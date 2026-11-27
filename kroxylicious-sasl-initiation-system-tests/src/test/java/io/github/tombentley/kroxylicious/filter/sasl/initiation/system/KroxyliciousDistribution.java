/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

/**
 * Resolves, verifies and unpacks the Kroxylicious binary distribution used by the system tests.
 * <p>
 * By default the pinned release artifact is downloaded from GitHub, verified against a SHA-256 checksum and unpacked
 * into {@code target/kroxylicious}. A locally supplied distribution can be used instead by setting
 * {@code -Dkroxylicious.distribution=/path/to/directory-or-tar.gz}.
 * </p>
 */
final class KroxyliciousDistribution {

    private static final String DEFAULT_VERSION = "0.26.0";
    private static final String DEFAULT_SHA256 = "7231383db9bb72434a734c0658b1daf5d24898be82c632e11ffafed6ed436d9c";
    private static final String DISTRIBUTION_PROPERTY = "kroxylicious.distribution";
    private static final String CHECKSUM_PROPERTY = "kroxylicious.distribution.sha256";
    private static final String VERSION_PROPERTY = "kroxylicious.version";
    private static final String START_SCRIPT = "bin/kroxylicious-start.sh";

    private final Path home;
    private final Path pluginDirectory;
    private final Path cliAllJar;

    private KroxyliciousDistribution(Path home, Path pluginDirectory, Path cliAllJar) {
        this.home = home;
        this.pluginDirectory = pluginDirectory;
        this.cliAllJar = cliAllJar;
    }

    /**
     * Prepares a distribution and copies the built plugin jars into its classpath-plugins directory.
     *
     * @return the prepared distribution
     * @throws IOException if the distribution cannot be downloaded, verified or unpacked
     * @throws InterruptedException if the download is interrupted
     */
    static KroxyliciousDistribution prepare() throws IOException, InterruptedException {
        Path workDirectory = Path.of(System.getProperty("sasl.system.test.work.dir", "target"))
                .toAbsolutePath()
                .normalize();
        Path home;
        String customDistribution = property(DISTRIBUTION_PROPERTY);
        if (customDistribution != null) {
            Path customPath = Path.of(customDistribution).toAbsolutePath().normalize();
            if (Files.isDirectory(customPath)) {
                home = customPath;
                requireDistribution(home);
            }
            else if (Files.isRegularFile(customPath)) {
                verifyChecksumIfConfigured(customPath);
                home = workDirectory.resolve("kroxylicious");
                extract(customPath, home);
            }
            else {
                throw new IllegalStateException(
                        "The " + DISTRIBUTION_PROPERTY + " path is neither a directory nor a tar.gz file: " + customPath);
            }
        }
        else {
            home = workDirectory.resolve("kroxylicious");
            String version = propertyOrDefault(VERSION_PROPERTY, DEFAULT_VERSION);
            String checksum = checksumFor(version);
            Path versionMarker = home.resolve(".distribution-version");
            if (Files.isRegularFile(home.resolve(START_SCRIPT))
                    && Files.isRegularFile(versionMarker)
                    && version.equals(Files.readString(versionMarker).trim())) {
                // The extracted distribution matches the configured version; reuse it.
            }
            else {
                Path archive = download(workDirectory, version, checksum);
                extract(archive, home);
                Files.writeString(versionMarker, version + System.lineSeparator());
            }
        }

        Path pluginDirectory = home.resolve("classpath-plugins").resolve("sasl-initiation");
        installPlugins(pluginDirectory);
        return new KroxyliciousDistribution(home, pluginDirectory, requiredFile("sasl.initiation.cli.all.jar"));
    }

    /**
     * Returns the distribution root.
     *
     * @return the directory containing {@code bin/}, {@code libs/} and {@code classpath-plugins/}
     */
    Path home() {
        return home;
    }

    /**
     * Returns the directory containing the plugin jars.
     *
     * @return the {@code classpath-plugins/sasl-initiation} directory
     */
    Path pluginDirectory() {
        return pluginDirectory;
    }

    /**
     * Returns the shaded CLI jar used to create the credential store.
     *
     * @return the CLI jar with Picocli and the credential classes shaded in
     */
    Path cliAllJar() {
        return cliAllJar;
    }

    private static String checksumFor(String version) {
        String configured = property(CHECKSUM_PROPERTY);
        if (configured != null) {
            return configured;
        }
        if (DEFAULT_VERSION.equals(version)) {
            return DEFAULT_SHA256;
        }
        throw new IllegalStateException("No SHA-256 checksum is configured for Kroxylicious " + version
                + ". Set -D" + CHECKSUM_PROPERTY + "=<sha256> or use -D" + DISTRIBUTION_PROPERTY + "=<local path>.");
    }

    private static Path download(Path workDirectory, String version, String checksum) throws IOException, InterruptedException {
        Path cacheDirectory = workDirectory.resolve("distributions");
        Files.createDirectories(cacheDirectory);
        Path archive = cacheDirectory.resolve("kroxylicious-app-" + version + "-bin.tar.gz");
        if (Files.isRegularFile(archive) && checksumMatches(archive, checksum)) {
            return archive;
        }
        Files.deleteIfExists(archive);

        URI uri = URI.create("https://github.com/kroxylicious/kroxylicious/releases/download/v" + version
                + "/kroxylicious-app-" + version + "-bin.tar.gz");
        Path temporary = Files.createTempFile(cacheDirectory, "kroxylicious-app-" + version + "-", ".tar.gz.part");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofMinutes(10))
                .GET()
                .build();
        try (HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(30))
                .build()) {
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream input = response.body()) {
                if (response.statusCode() != 200) {
                    throw new IOException("Failed to download " + uri + ": HTTP " + response.statusCode());
                }
                Files.copy(input, temporary, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        catch (IOException e) {
            deleteQuietly(temporary);
            throw e;
        }
        if (!checksumMatches(temporary, checksum)) {
            String actual = sha256(temporary);
            deleteQuietly(temporary);
            throw new IOException("Checksum mismatch for " + uri + ": expected " + checksum + " but was " + actual);
        }
        moveIntoPlace(temporary, archive);
        return archive;
    }

    private static void verifyChecksumIfConfigured(Path archive) throws IOException {
        String checksum = property(CHECKSUM_PROPERTY);
        if (checksum != null && !checksumMatches(archive, checksum)) {
            throw new IOException("Checksum mismatch for " + archive + ": expected " + checksum
                    + " but was " + sha256(archive));
        }
    }

    private static void extract(Path archive, Path home) throws IOException {
        String root = distributionRoot(archive);
        deleteRecursively(home);
        Files.createDirectories(home);
        try (InputStream file = Files.newInputStream(archive);
                GZIPInputStream gzip = new GZIPInputStream(file);
                TarArchiveInputStream tar = new TarArchiveInputStream(gzip)) {
            TarArchiveEntry entry;
            while ((entry = tar.getNextEntry()) != null) {
                String name = normalizeEntryName(entry.getName());
                if (root != null && name.startsWith(root + "/")) {
                    name = name.substring(root.length() + 1);
                }
                if (name.isEmpty()) {
                    continue;
                }
                Path target = home.resolve(name).normalize();
                if (!target.startsWith(home)) {
                    throw new IOException("Archive entry escapes the extraction directory: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                }
                else {
                    Path parent = target.getParent();
                    if (parent != null) {
                        Files.createDirectories(parent);
                    }
                    Files.copy(tar, target, StandardCopyOption.REPLACE_EXISTING);
                    setMode(target, entry.getMode());
                }
            }
        }
        requireDistribution(home);
        ensureBinariesExecutable(home.resolve("bin"));
    }

    private static String distributionRoot(Path archive) throws IOException {
        try (InputStream file = Files.newInputStream(archive);
                GZIPInputStream gzip = new GZIPInputStream(file);
                TarArchiveInputStream tar = new TarArchiveInputStream(gzip)) {
            TarArchiveEntry entry;
            while ((entry = tar.getNextEntry()) != null) {
                String name = normalizeEntryName(entry.getName());
                int index = name.indexOf("/bin/kroxylicious-start.sh");
                if (index > 0) {
                    return name.substring(0, index);
                }
                if (name.equals("bin/kroxylicious-start.sh")) {
                    return null;
                }
            }
        }
        throw new IOException("The archive does not contain " + START_SCRIPT + ": " + archive);
    }

    private static String normalizeEntryName(String name) {
        String normalized = name;
        while (normalized.startsWith("./")) {
            normalized = normalized.substring(2);
        }
        return normalized;
    }

    private static void installPlugins(Path pluginDirectory) throws IOException {
        Files.createDirectories(pluginDirectory);
        try (Stream<Path> existing = Files.list(pluginDirectory)) {
            for (Path path : existing.filter(Files::isRegularFile).toList()) {
                if (path.getFileName().toString().endsWith(".jar")) {
                    Files.deleteIfExists(path);
                }
            }
        }
        copyJar(requiredFile("sasl.initiation.filter.jar"), pluginDirectory);
        copyJar(requiredFile("sasl.initiation.credentials.jar"), pluginDirectory);
        copyJar(requiredFile("sasl.initiation.cli.jar"), pluginDirectory);
    }

    private static void copyJar(Path source, Path pluginDirectory) throws IOException {
        Files.copy(source, pluginDirectory.resolve(source.getFileName()), StandardCopyOption.REPLACE_EXISTING);
    }

    private static Path requiredFile(String propertyName) {
        String value = property(propertyName);
        if (value == null) {
            throw new IllegalStateException("System property " + propertyName
                    + " is not set; run the system tests through Maven with -Psystem-tests");
        }
        Path path = Path.of(value).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("The file configured by " + propertyName + " does not exist: " + path);
        }
        return path;
    }

    private static String property(String key) {
        String value = System.getProperty(key);
        return value == null || value.isBlank() ? null : value;
    }

    private static String propertyOrDefault(String key, String defaultValue) {
        String value = property(key);
        return value == null ? defaultValue : value;
    }

    private static boolean checksumMatches(Path file, String expected) {
        if (!Files.isRegularFile(file)) {
            return false;
        }
        return sha256(file).equalsIgnoreCase(expected);
    }

    private static String sha256(Path file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(file)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
        catch (IOException e) {
            throw new IllegalStateException("Failed to compute the SHA-256 checksum of " + file, e);
        }
    }

    private static void moveIntoPlace(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            for (Path entry : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(entry);
            }
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        }
        catch (IOException e) {
            // Best-effort cleanup; the original failure is more useful.
        }
    }

    private static void requireDistribution(Path home) throws IOException {
        if (!Files.isRegularFile(home.resolve(START_SCRIPT))) {
            throw new IOException("Not a Kroxylicious distribution (missing " + START_SCRIPT + "): " + home);
        }
    }

    private static void ensureBinariesExecutable(Path binDirectory) throws IOException {
        if (!Files.isDirectory(binDirectory)) {
            return;
        }
        try (Stream<Path> files = Files.list(binDirectory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                if (file.getFileName().toString().endsWith(".sh")) {
                    try {
                        Set<PosixFilePermission> permissions = EnumSet.noneOf(PosixFilePermission.class);
                        permissions.addAll(Files.getPosixFilePermissions(file));
                        permissions.add(PosixFilePermission.OWNER_EXECUTE);
                        permissions.add(PosixFilePermission.GROUP_EXECUTE);
                        permissions.add(PosixFilePermission.OTHERS_EXECUTE);
                        Files.setPosixFilePermissions(file, permissions);
                    }
                    catch (UnsupportedOperationException e) {
                        // Non-POSIX file system: the launcher uses the JVM directly in that environment.
                    }
                }
            }
        }
    }

    private static void setMode(Path path, int mode) {
        if (mode == 0) {
            return;
        }
        try {
            Files.setPosixFilePermissions(path, toPosixPermissions(mode));
        }
        catch (UnsupportedOperationException | IOException e) {
            // Preserving the archive mode is best effort on non-POSIX file systems.
        }
    }

    private static Set<PosixFilePermission> toPosixPermissions(int mode) {
        Set<PosixFilePermission> permissions = EnumSet.noneOf(PosixFilePermission.class);
        addPermission(permissions, mode, 0400, PosixFilePermission.OWNER_READ);
        addPermission(permissions, mode, 0200, PosixFilePermission.OWNER_WRITE);
        addPermission(permissions, mode, 0100, PosixFilePermission.OWNER_EXECUTE);
        addPermission(permissions, mode, 0040, PosixFilePermission.GROUP_READ);
        addPermission(permissions, mode, 0020, PosixFilePermission.GROUP_WRITE);
        addPermission(permissions, mode, 0010, PosixFilePermission.GROUP_EXECUTE);
        addPermission(permissions, mode, 0004, PosixFilePermission.OTHERS_READ);
        addPermission(permissions, mode, 0002, PosixFilePermission.OTHERS_WRITE);
        addPermission(permissions, mode, 0001, PosixFilePermission.OTHERS_EXECUTE);
        return permissions;
    }

    private static void addPermission(Set<PosixFilePermission> permissions, int mode, int mask, PosixFilePermission permission) {
        if ((mode & mask) != 0) {
            permissions.add(permission);
        }
    }
}
