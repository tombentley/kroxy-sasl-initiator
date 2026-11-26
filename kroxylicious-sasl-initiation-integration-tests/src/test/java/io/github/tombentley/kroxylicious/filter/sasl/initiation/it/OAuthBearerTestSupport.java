/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Shared fixtures for the Docker-backed OAUTHBEARER integration tests.
 * <p>
 * The mock OAuth/OIDC server is exposed on a fixed port because the in-VM Kafka broker's JWKS URL is configured from a
 * constant. The in-VM broker and client share this JVM, so all OAuth URLs must also be added to Kafka's
 * {@code org.apache.kafka.sasl.oauthbearer.allowed.urls} system property.
 * </p>
 */
final class OAuthBearerTestSupport {

    static final int OAUTH_SERVER_PORT = 28089;
    static final String JWKS_ENDPOINT_URL = "http://localhost:" + OAUTH_SERVER_PORT + "/default/jwks";
    static final String TOKEN_ENDPOINT_URL = "http://localhost:" + OAUTH_SERVER_PORT + "/default/token";
    static final String EXPECTED_AUDIENCE = "default";
    static final String EXPECTED_ISSUER = "http://localhost:" + OAUTH_SERVER_PORT + "/default";
    static final String ALLOWED_URLS_PROPERTY = "org.apache.kafka.sasl.oauthbearer.allowed.urls";

    private static final String OAUTH_SERVER_IMAGE = "ghcr.io/navikt/mock-oauth2-server:5.0.2";

    /**
     * A token that is long since expired. It is a public test fixture, not a secret; it is signed by the mock server's
     * default key so that the failure exercised by the test is expiry rather than an unknown key.
     */
    static final String LONG_SINCE_EXPIRED_TOKEN = "eyJraWQiOiJkZWZhdWx0IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ."
            + "eyJzdWIiOiJjbGllbnRJZElnbm9yZSIsImF1ZCI6ImRlZmF1bHQiLCJuYmYiOjE3MjA3MjIyOTAsImF6cCI6ImNsaWVudElkSWdub3JlIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDoyODA4OS9kZWZhdWx0IiwiZXhwIjoxNzIwNzI1ODkwLCJpYXQiOjE3MjA3MjIyOTAsImp0aSI6IjE0MGZjMmFhLWRjZmQtNDE1Mi05MWJmLWQyMDZiM2M1MzAxZiIsInRpZCI6ImRlZmF1bHQifQ."
            + "I4LUI4Lp6XwUzD-UN2LDRfiNPCvhHDQJVH_LCE4gkuY5UxrRMJ8H3C9408zmjGPRChWmKU4aRIy8rtSPbfRmDLenoM91dr1mDy8B01TZohEOACnAxBSvsN73-cNUUvaRzZmMeUkGbmgEtGhqZ2d3MELe7bm0fEyuNRyM9fv-AahGm551hchMe3bzeYjbcBKuatKYoiHuPTX_HuNF4AAwI_vz_lYzHliKDmPRJwpsaMUaCtsfUKbSzpRPe6X2FWWkkgOLtCD-W14sp3r8z2KrHryH_ILz2MtPvIlvmkJE8U0CRaVyQ-6L2sL-iUdXoUGTHmV384X2R-cy5gKFhN3Ibg";

    private OAuthBearerTestSupport() {
    }

    static String baseAllowedUrls() {
        return JWKS_ENDPOINT_URL + "," + TOKEN_ENDPOINT_URL;
    }

    static void allowUrl(URI url) {
        String value = url.toString();
        synchronized (OAuthBearerTestSupport.class) {
            String current = System.getProperty(ALLOWED_URLS_PROPERTY);
            if (current == null || current.isBlank()) {
                System.setProperty(ALLOWED_URLS_PROPERTY, value);
            }
            else if (!Arrays.asList(current.split(",")).contains(value)) {
                System.setProperty(ALLOWED_URLS_PROPERTY, current + "," + value);
            }
        }
    }

    static OauthServerContainer startOauthServer() {
        OauthServerContainer container = new OauthServerContainer();
        container.setWaitStrategy(new LogMessageWaitStrategy().withRegEx(".*started server on address.*"));
        container.addFixedExposedPort(OAUTH_SERVER_PORT, OAUTH_SERVER_PORT);
        container.withEnv("SERVER_PORT", Integer.toString(OAUTH_SERVER_PORT));
        container.withEnv("LOG_LEVEL", "DEBUG");
        container.start();
        return container;
    }

    static String fetchAccessToken(String clientId, String clientSecret) throws Exception {
        String body = "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_ENDPOINT_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("The mock OAuth server returned HTTP " + response.statusCode());
            }
            JsonNode json = new ObjectMapper().readTree(response.body());
            JsonNode accessToken = json.get("access_token");
            if (accessToken == null || accessToken.asText().isBlank()) {
                throw new IllegalStateException("The mock OAuth server returned no access token");
            }
            return accessToken.asText();
        }
    }

    static Path writeTokenFile(Path file, String token) throws Exception {
        Files.writeString(file, token, StandardCharsets.UTF_8);
        setOwnerOnly(file);
        return file;
    }

    static Path writeOAuthStore(Path file, String storePassword, OAuthEntry... entries) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = storePassword.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
        try {
            keyStore.load(null, password);
            for (OAuthEntry entry : entries) {
                String json = """
                        {"version":1,"subject":"%s","oauthBearer":{"clientId":"%s","clientSecret":"%s","expectedSubject":"%s"}}
                        """.formatted(escape(entry.subject()), escape(entry.clientId()), escape(entry.clientSecret()),
                        escape(entry.expectedSubject()));
                keyStore.setEntry(alias(entry.subject()),
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(json.getBytes(StandardCharsets.UTF_8), "AES")),
                        protection);
            }
            try (OutputStream output = Files.newOutputStream(file)) {
                keyStore.store(output, password);
            }
            setOwnerOnly(file);
            return file;
        }
        finally {
            protection.destroy();
            Arrays.fill(password, '\0');
        }
    }

    static Path writePasswordStore(Path file, String storePassword, PasswordEntry... entries) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = storePassword.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
        try {
            keyStore.load(null, password);
            for (PasswordEntry entry : entries) {
                String json = """
                        {"version":1,"subject":"%s","username":"%s","password":"%s"}
                        """.formatted(escape(entry.subject()), escape(entry.username()), escape(entry.password()));
                keyStore.setEntry(alias(entry.subject()),
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(json.getBytes(StandardCharsets.UTF_8), "AES")),
                        protection);
            }
            try (OutputStream output = Files.newOutputStream(file)) {
                keyStore.store(output, password);
            }
            setOwnerOnly(file);
            return file;
        }
        finally {
            protection.destroy();
            Arrays.fill(password, '\0');
        }
    }

    static Path writePasswordFile(Path file, String password) throws Exception {
        Files.writeString(file, password, StandardCharsets.UTF_8);
        setOwnerOnly(file);
        return file;
    }

    static CapturedLogs captureLogs() {
        return CapturedLogs.start();
    }

    private static void setOwnerOnly(Path file) throws Exception {
        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(file, ownerOnly);
        }
        catch (UnsupportedOperationException e) {
            // Non-POSIX file system: nothing to set.
        }
    }

    private static String alias(String subject) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(subject.getBytes(StandardCharsets.UTF_8)));
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    record OAuthEntry(String subject, String clientId, String clientSecret, String expectedSubject) {}

    record PasswordEntry(String subject, String username, String password) {}

    static final class OauthServerContainer extends GenericContainer<OauthServerContainer> {

        private OauthServerContainer() {
            super(DockerImageName.parse(OAUTH_SERVER_IMAGE));
        }

        @Override
        protected void addFixedExposedPort(int hostPort, int containerPort) {
            super.addFixedExposedPort(hostPort, containerPort);
        }
    }

    /**
     * Captures proxy logs for the duration of a test so that secrets and tokens can be asserted absent.
     */
    static final class CapturedLogs implements AutoCloseable {

        private final LoggerContext loggerContext;
        private final LoggerConfig rootLoggerConfig;
        private final Level previousLevel;
        private final CapturingAppender appender;

        private CapturedLogs(LoggerContext loggerContext,
                             LoggerConfig rootLoggerConfig,
                             Level previousLevel,
                             CapturingAppender appender) {
            this.loggerContext = loggerContext;
            this.rootLoggerConfig = rootLoggerConfig;
            this.previousLevel = previousLevel;
            this.appender = appender;
        }

        static CapturedLogs start() {
            CapturingAppender appender = new CapturingAppender();
            appender.start();
            LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
            Configuration configuration = loggerContext.getConfiguration();
            LoggerConfig rootLoggerConfig = configuration.getRootLogger();
            Level previousLevel = rootLoggerConfig.getLevel();
            rootLoggerConfig.addAppender(appender, Level.DEBUG, null);
            rootLoggerConfig.setLevel(Level.DEBUG);
            loggerContext.updateLoggers();
            return new CapturedLogs(loggerContext, rootLoggerConfig, previousLevel, appender);
        }

        String text() {
            return appender.text();
        }

        @Override
        public void close() {
            rootLoggerConfig.removeAppender(appender.getName());
            rootLoggerConfig.setLevel(previousLevel);
            loggerContext.updateLoggers();
            appender.stop();
        }
    }

    private static final class CapturingAppender extends AbstractAppender {

        private final StringBuilder text = new StringBuilder();

        private CapturingAppender() {
            super("oauth-it-capture", null, null, false, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(LogEvent event) {
            text.append(event.getMessage().getFormattedMessage()).append('\n');
            if (event.getThrown() != null) {
                text.append(event.getThrown()).append('\n');
            }
        }

        private String text() {
            return text.toString();
        }
    }
}
