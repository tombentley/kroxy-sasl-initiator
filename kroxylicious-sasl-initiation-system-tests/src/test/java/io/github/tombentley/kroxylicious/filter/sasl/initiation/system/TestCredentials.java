/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Creates a PKCS12 initiation credential store with the packaged CLI.
 */
final class TestCredentials {

    private static final String CLI_MAIN_CLASS = "io.github.tombentley.kroxylicious.filter.sasl.initiation.cli.SaslInitiationCredentialTool";
    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

    private final Path storeFile;
    private final Path storePasswordFile;

    private TestCredentials(Path storeFile, Path storePasswordFile) {
        this.storeFile = storeFile;
        this.storePasswordFile = storePasswordFile;
    }

    /**
     * Creates a store containing one password credential for the fixed identity.
     *
     * @param directory the test working directory
     * @param distribution the prepared Kroxylicious distribution
     * @param subject the credential lookup subject
     * @param username the broker username
     * @param password the broker password
     * @param storePassword the PKCS12 store password
     * @return the store paths
     * @throws IOException if a file cannot be written
     * @throws InterruptedException if the CLI process is interrupted
     */
    static TestCredentials create(Path directory,
                                  KroxyliciousDistribution distribution,
                                  String subject,
                                  String username,
                                  String password,
                                  String storePassword)
            throws IOException, InterruptedException {
        Files.createDirectories(directory);
        Path credentialsDirectory = Files.createTempDirectory(directory, "credentials-");
        Path storeFile = credentialsDirectory.resolve("credentials.p12");
        Path storePasswordFile = credentialsDirectory.resolve("credentials.password");
        Path brokerPasswordFile = credentialsDirectory.resolve("broker.password");

        writeSecret(storePasswordFile, storePassword);
        writeSecret(brokerPasswordFile, password);

        runCli(credentialsDirectory, distribution,
                "create",
                "--file", storeFile.toString(),
                "--store-password-file", storePasswordFile.toString());
        runCli(credentialsDirectory, distribution,
                "add-password",
                "--file", storeFile.toString(),
                "--subject", subject,
                "--username", username,
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", brokerPasswordFile.toString());
        setOwnerOnly(storeFile);
        return new TestCredentials(storeFile, storePasswordFile);
    }

    /**
     * Returns the PKCS12 store.
     *
     * @return the store file
     */
    Path storeFile() {
        return storeFile;
    }

    /**
     * Returns the file containing the store password.
     *
     * @return the password file
     */
    Path storePasswordFile() {
        return storePasswordFile;
    }

    private static void runCli(Path directory,
                               KroxyliciousDistribution distribution,
                               String... arguments)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        command.add("-cp");
        command.add(classpath(distribution));
        command.add(CLI_MAIN_CLASS);
        command.addAll(List.of(arguments));

        Path log = directory.resolve("cli.log");
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.redirectOutput(log.toFile());
        Process process = builder.start();
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("The credential CLI did not finish within 60 seconds");
        }
        if (process.exitValue() != 0) {
            String output = Files.isRegularFile(log) ? Files.readString(log, StandardCharsets.UTF_8) : "";
            throw new IllegalStateException("The credential CLI failed with exit code " + process.exitValue()
                    + System.lineSeparator() + output);
        }
    }

    private static String classpath(KroxyliciousDistribution distribution) throws IOException {
        List<String> entries = new ArrayList<>();
        Path libs = distribution.home().resolve("libs");
        try (Stream<Path> files = Files.list(libs)) {
            files.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .sorted()
                    .forEach(path -> entries.add(path.toString()));
        }
        entries.add(distribution.cliAllJar().toString());
        return String.join(File.pathSeparator, entries);
    }

    private static String javaExecutable() {
        String executable = System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java";
        return Path.of(System.getProperty("java.home"), "bin", executable).toString();
    }

    private static void writeSecret(Path file, String secret) throws IOException {
        Files.writeString(file, secret + System.lineSeparator(), StandardCharsets.UTF_8);
        setOwnerOnly(file);
    }

    private static void setOwnerOnly(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, OWNER_ONLY);
        }
        catch (UnsupportedOperationException e) {
            // Non-POSIX file system: the permission check is disabled by the filter in that environment.
        }
    }
}
