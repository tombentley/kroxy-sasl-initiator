/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * A packaged Kroxylicious proxy running as a subprocess.
 */
final class PackagedProxy implements AutoCloseable {

    private static final Duration STARTUP_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration SHUTDOWN_TIMEOUT = Duration.ofSeconds(30);

    private final Process process;
    private final int port;
    private final Path standardOutput;
    private final Path standardError;

    private PackagedProxy(Process process, int port, Path standardOutput, Path standardError) {
        this.process = process;
        this.port = port;
        this.standardOutput = standardOutput;
        this.standardError = standardError;
    }

    /**
     * Starts the packaged proxy.
     *
     * @param distribution the prepared distribution
     * @param directory the working directory for the config and logs
     * @param mechanism the broker-facing SASL mechanism
     * @param subject the fixed credential subject
     * @param credentials the credential store
     * @param upstreamBootstrapServers the Kafka broker bootstrap address
     * @return the running proxy
     * @throws IOException if the config or process cannot be created
     */
    static PackagedProxy start(KroxyliciousDistribution distribution,
                               Path directory,
                               String mechanism,
                               String subject,
                               TestCredentials credentials,
                               String upstreamBootstrapServers)
            throws IOException {
        Files.createDirectories(directory);
        Path proxyDirectory = Files.createTempDirectory(directory, "proxy-");
        int port = freePort();
        Path config = proxyDirectory.resolve("proxy.yaml");
        Files.writeString(config, configuration(mechanism, subject, credentials, upstreamBootstrapServers, port),
                StandardCharsets.UTF_8);

        Path logging = proxyDirectory.resolve("log4j2-system-test.yaml");
        Files.writeString(logging, loggingConfiguration(), StandardCharsets.UTF_8);

        Path standardOutput = proxyDirectory.resolve("proxy.stdout.log");
        Path standardError = proxyDirectory.resolve("proxy.stderr.log");
        ProcessBuilder builder = new ProcessBuilder(
                distribution.home().resolve("bin/kroxylicious-start.sh").toString(),
                "--config", config.toString());
        builder.directory(proxyDirectory.toFile());
        builder.environment().put("KROXYLICIOUS_LOGGING_OPTIONS",
                "-Dlog4j2.configurationFile=" + logging.toAbsolutePath());
        builder.environment().put("KROXYLICIOUS_LOG_FORMAT", "text");
        builder.redirectOutput(standardOutput.toFile());
        builder.redirectError(standardError.toFile());

        Process process = builder.start();
        PackagedProxy proxy = new PackagedProxy(process, port, standardOutput, standardError);
        try {
            proxy.awaitReady();
            return proxy;
        }
        catch (RuntimeException | Error e) {
            proxy.close();
            throw e;
        }
    }

    /**
     * Returns the proxy bootstrap address.
     *
     * @return {@code localhost:<port>}
     */
    String bootstrapServers() {
        return "localhost:" + port;
    }

    /**
     * Returns the captured stdout and stderr.
     *
     * @return the combined process output
     */
    String log() {
        return "----- stdout -----" + System.lineSeparator()
                + read(standardOutput)
                + "----- stderr -----" + System.lineSeparator()
                + read(standardError);
    }

    @Override
    public void close() {
        if (!process.isAlive()) {
            return;
        }
        process.destroy();
        try {
            if (!process.waitFor(SHUTDOWN_TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor(SHUTDOWN_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            }
        }
        catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    private void awaitReady() {
        long deadline = System.nanoTime() + STARTUP_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new IllegalStateException("The packaged proxy exited before opening its bootstrap port"
                        + System.lineSeparator() + log());
            }
            if (isPortOpen()) {
                return;
            }
            try {
                Thread.sleep(200);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for the packaged proxy", e);
            }
        }
        throw new IllegalStateException("The packaged proxy did not open " + bootstrapServers()
                + " within " + STARTUP_TIMEOUT + System.lineSeparator() + log());
    }

    private boolean isPortOpen() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 250);
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static String configuration(String mechanism,
                                        String subject,
                                        TestCredentials credentials,
                                        String upstreamBootstrapServers,
                                        int port) {
        return """
                management:
                  endpoints:
                    prometheus: {}
                filterDefinitions:
                  - name: sasl-initiation
                    type: SaslInitiation
                    config:
                      mechanism: %s
                      identity:
                        mode: fixed
                        key: %s
                      keyStore:
                        file: %s
                        filePassword:
                          passwordFile: %s
                clusterDefinitions:
                  - name: kafka
                    bootstrapServers: %s
                virtualClusters:
                  - name: demo
                    target:
                      cluster: kafka
                    filters:
                      - sasl-initiation
                    gateways:
                      - name: default
                        portIdentifiesNode:
                          bootstrapAddress: localhost:%d
                    logNetwork: false
                    logFrames: false
                """.formatted(mechanism, subject, credentials.storeFile(), credentials.storePasswordFile(),
                upstreamBootstrapServers, port);
    }

    private static String loggingConfiguration() {
        return """
                ---
                Configuration:
                  status: WARN
                  shutdownHook: disable
                  name: SaslInitiationSystemTests
                  Appenders:
                    Console:
                      name: STDOUT
                      target: SYSTEM_OUT
                      PatternLayout:
                        pattern: "%d{yyyy-MM-dd HH:mm:ss} %-5p <%t> %c{2.} - %m%n"
                  Loggers:
                    Root:
                      level: INFO
                      additivity: false
                      AppenderRef:
                        - ref: STDOUT
                    Logger:
                      - name: io.github.tombentley
                        level: DEBUG
                        additivity: false
                        AppenderRef:
                          - ref: STDOUT
                      - name: io.kroxylicious
                        level: INFO
                        additivity: false
                        AppenderRef:
                          - ref: STDOUT
                """;
    }

    private static String read(Path file) {
        try {
            return Files.isRegularFile(file) ? Files.readString(file, StandardCharsets.UTF_8) : "";
        }
        catch (IOException e) {
            return "<unable to read " + file + ": " + e.getMessage() + ">" + System.lineSeparator();
        }
    }
}
