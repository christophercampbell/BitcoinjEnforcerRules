package uk.co.froot.maven.enforcer;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.factory.ArtifactFactory;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.enforcer.rule.api.EnforcerRule;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.enforcer.rule.api.EnforcerRuleHelper;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.codehaus.plexus.util.FileUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.stream.Collectors;

/**
 * <p>Enforcer rule to provide the following to build process:</p>
 * <ul>
 * <li>Checking of hashes against an expected list</li>
 * </ul>
 *
 * @since 0.0.1 
 */
public class DigestRule implements EnforcerRule {

    // Injected by Enforcer plugin
    private String[] urns = null;
    private boolean buildSnapshot = false;
    private int concurrency = 4;

    // Various common references provided by Enforcer Helper

    private ArtifactRepository localRepository = null;
    private MavenProject mavenProject = null;
    private ArtifactFactory artifactFactory = null;
    private ArtifactResolver resolver = null;
    private Log log = null;
    private ForkJoinPool forkJoinPool = null;


    public String getCacheId() {
        return "id"; // This is not cacheable
    }

    public boolean isCacheable() {
        return false;
    }

    public boolean isResultValid(EnforcerRule arg0) {
        return false;
    }

    @SuppressWarnings("deprecation")
    public void execute(EnforcerRuleHelper helper) throws EnforcerRuleException {

        log = helper.getLog();

        log.info("Applying DigestRule");

        try {

            mavenProject = (MavenProject) helper.evaluate("${project}");

            // Get the local repository
            localRepository = (ArtifactRepository) helper.evaluate("${localRepository}");

            // Due to backwards compatibility issues the deprecated interface must be used here
            artifactFactory = (ArtifactFactory) helper.getComponent(ArtifactFactory.class);

            // Get the artifact resolver
            resolver = (ArtifactResolver) helper.getComponent(ArtifactResolver.class);

            log.info("Digester concurrency: " + concurrency);
            forkJoinPool = new ForkJoinPool(concurrency);

            // Build the snapshot first
            if (buildSnapshot) {
                buildSnapshot(mavenProject, log);
            }

            // Check for missing URNs (OK if we're just making a snapshot)
            if (urns == null && !buildSnapshot) {
                throw new EnforcerRuleException("Failing because there are no URNs in the <configuration> section. See the README for help.");
            }

            // Must be OK to verify
            verifyDependencies();

        } catch (IOException e) {
            throw new EnforcerRuleException("Unable to read file: " + e.getLocalizedMessage(), e);
        } catch (ExpressionEvaluationException e) {
            throw new EnforcerRuleException("Unable to lookup an expression: " + e.getLocalizedMessage(), e);
        } catch (ComponentLookupException e) {
            throw new EnforcerRuleException("Unable to look up a component: " + e.getLocalizedMessage(), e);
        } finally {
            if (forkJoinPool != null) {
                forkJoinPool.shutdown();
            }
        }
    }

    /**
     * @param project The project
     * @param log     The project log
     * @throws IOException           If something goes wrong
     * @throws EnforcerRuleException If something goes wrong
     */
    private void buildSnapshot(MavenProject project, Log log) throws IOException, EnforcerRuleException {

        log.info("Building snapshot whitelist of all current artifacts");

        List<Artifact> checklist = new ArrayList<Artifact>();
        checklist.addAll(project.getArtifacts());
        checklist.addAll(project.getPluginArtifacts());
        checklist.addAll(project.getExtensionArtifacts());

        try {

            List<ForkJoinTask<String>> tasks = checklist.stream()
                    .map(urn -> forkJoinPool.submit(() -> checkArtifact(urn)))
                    .collect(Collectors.toList());

            List<String> whitelist = tasks.stream()
                    .map(ForkJoinTask::join)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            // Provide the list in a natural order
            Collections.sort(whitelist);

            log.info("List of verified artifacts. If you are confident in the integrity of your repository you can use the list below:");
            log.info("<urns>");
            for (String urn : whitelist) {
                log.info("  <urn>" + urn + "</urn>");
            }
            log.info("</urns>");

        } catch (Exception e) {
            throw new EnforcerRuleException("Failed verifying artifacts.", e);
        }
    }

    /**
     * Check the digest of the resolved artifact against the published digest.
     *
     * @param artifact
     * @return the artifact urn if valid, null if invalid
     */
    private String checkArtifact(Artifact artifact) {
        try {
            String artifactUrn = String.format("%s:%s:%s:%s:%s:%s",
                    artifact.getGroupId(),
                    artifact.getArtifactId(),
                    artifact.getVersion(),
                    artifact.getType(),
                    artifact.getClassifier(),
                    artifact.getScope()
            );

            log.debug("Examining artifact URN: " + artifactUrn);

            resolveArtifact(artifact);

            // Read in the signature file (if it exists)
            File artifactFile = artifact.getFile();
            if (artifactFile == null) {
                log.error("Artifact " + artifactUrn + " UNVERIFIED (could not be resolved).");
                return null;
            }
            if (!artifactFile.exists()) {
                log.warn("Artifact " + artifactUrn + " UNVERIFIED (file missing in repo).");
                return null;
            }

            // Reference the SHA1
            File digestFile = new File(artifactFile.getAbsoluteFile() + ".sha1");

            // Read the SHA1
            String digestExpected = null;
            if (digestFile.exists()) {
                // SHA1 is 40 characters in hex
                digestExpected = FileUtils.fileRead(digestFile).substring(0, 40);
                log.debug("Found SHA-1: " + digestExpected);
            }

            // Generate actual
            String digestActual = digest(artifact.getFile());

            if (digestExpected != null) {
                if (!digestExpected.equals(digestActual)) {
                    log.error("Artifact " + artifactUrn + " FAILED SHA-1 verification. Expected='" + digestExpected + "' Actual='" + digestActual + "'");
                    return null;
                } else {
                    log.debug("Artifact " + artifactUrn + " PASSED SHA-1 verification.");
                    return artifactUrn + ":" + digestActual;
                }
            } else {
                log.warn("Artifact " + artifactUrn + " UNVERIFIED SHA-1 (missing in repo).");
                return null;
            }

        } catch (IOException | EnforcerRuleException e) {
            log.error("Error checking artifact ", e);
            return null;
        }
    }

    /**
     * <p>Handles the process of verifying the dependencies listed</p>
     *
     * @throws EnforcerRuleException If something goes wrong
     */
    private void verifyDependencies() throws EnforcerRuleException {
        log.info("Verifying dependencies");

        try {

            List<ForkJoinTask<Boolean>> tasks = Arrays.stream(urns).map(urn -> forkJoinPool.submit(() -> checkUrn(urn))).collect(Collectors.toList());

            List<Boolean> results = tasks.stream().map(ForkJoinTask::join).collect(Collectors.toList());

            // If any return false, fail verification
            if (results.size() > 0 && results.stream().filter(r -> !r.booleanValue()).findFirst().isPresent()) {
                throw new EnforcerRuleException("At least one artifact has not met expectations. You should manually verify the integrity of the affected artifacts against trusted sources.");
            }
        } catch (Exception e) {
            throw new EnforcerRuleException("Failed verifying artifacts.", e);
        }
    }

    /**
     * Check the digest of resolved artifact against the supplied digest in the urn.
     *
     * @param urn
     * @return true if the urn resolves validly, false if it fails
     */
    private boolean checkUrn(String urn) {
        log.info("Verifying URN: " + urn);

        // Decode it into artifact co-ordinates
        String[] coordinates = urn.split(":");
        if (coordinates.length != 7) {
            log.error("Failing because URN '" + urn + "' is not in format 'groupId:artifactId:version:type:classifier:scope:hash'");
            return false;
        }

        // Extract the artifact co-ordinates from the URN
        String groupId = coordinates[0];
        String artifactId = coordinates[1];
        String version = coordinates[2];
        String type = coordinates[3];
        String classifier = "null".equalsIgnoreCase(coordinates[4]) ? null : coordinates[4];
        String scope = coordinates[5];
        String hash = coordinates[6];

        VersionRange versionRange = VersionRange.createFromVersion(version);
        Artifact artifact = artifactFactory.createDependencyArtifact(groupId, artifactId, versionRange, type, classifier, scope);

        try {
            resolveArtifact(artifact);
            String actual = digest(artifact.getFile());
            if (!actual.equals(hash)) {
                log.error("*** CRITICAL FAILURE *** Artifact " + urn + " does not match. Possible dependency-chain attack. Expected='" + hash + "' Actual='" + actual + "'");
                return false;
            }
            return true;
        } catch (EnforcerRuleException e) {
            log.error("URN " + urn + " failed", e);
            return false;
        }
    }

    /**
     * @param artifact The unresolved artifact
     * @throws EnforcerRuleException If something goes wrong
     */
    private void resolveArtifact(Artifact artifact) throws EnforcerRuleException {
        try {
            resolver.resolve(artifact, mavenProject.getRemoteArtifactRepositories(), localRepository);
        } catch (ArtifactResolutionException e) {
            throw new EnforcerRuleException("Failing due to artifact resolution: " + e.getLocalizedMessage(), e);
        } catch (ArtifactNotFoundException e) {
            throw new EnforcerRuleException("Failing due to artifact not found: " + e.getLocalizedMessage(), e);
        }
    }

    /**
     * @param file The file to digest
     * @return The hex version of the digest
     * @throws EnforcerRuleException If something goes wrong
     */
    private String digest(final File file) throws EnforcerRuleException {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            try (final FileInputStream fis = new FileInputStream(file);
                 final DigestInputStream dis = new DigestInputStream(fis, messageDigest)) {
                while (dis.read() != -1) {
                    // Read fully to get digest
                }
            }
            return byteToHex(messageDigest.digest());
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new EnforcerRuleException("Unable to digest " + e.getLocalizedMessage(), e);
        }
    }

    /**
     * @param digest The digest of the message
     * @return The hex version
     */
    private static String byteToHex(final byte[] digest) {
        Formatter formatter = new Formatter();
        for (byte b : digest) {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }

}
