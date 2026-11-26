/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation;

import io.kroxylicious.proxy.config.ConfigurationBuilder;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real-Kafka integration tests for subject-derived broker identities.
 * <p>
 * A test-only {@link FixedSubjectFilter} publishes the downstream subject before {@code SaslInitiation} runs. This
 * isolates subject-mode credential selection from client-side SASL termination, which has its own composition tests.
 * </p>
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslSubjectInitiationIT {

    private static final String STORE_PASSWORD = "subject-initiation-store-password";
    private static final String ALICE_SUBJECT = "alice";
    private static final String ALICE_BROKER_USERNAME = "svc-alice";
    private static final String ALICE_BROKER_PASSWORD = "svc-alice-password";
    private static final String BOB_SUBJECT = "bob";
    private static final String BOB_BROKER_USERNAME = "svc-bob";
    private static final String BOB_BROKER_PASSWORD = "svc-bob-password";
    private static final String MISSING_SUBJECT = "carol";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final Map<String, Object> FAILING_PRODUCER_CONFIGURATION = Map.of(
            ProducerConfig.MAX_BLOCK_MS_CONFIG, 10_000,
            ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10_000,
            ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5_000);

    @TempDir
    Path tempDir;

    @Test
    void shouldAuthenticateWithTheBrokerUsernameMappedFromTheSubject(
                                                                     @SaslMechanism(value = "PLAIN", principals = {
                                                                             @SaslMechanism.Principal(user = ALICE_BROKER_USERNAME, password = ALICE_BROKER_PASSWORD),
                                                                             @SaslMechanism.Principal(user = BOB_BROKER_USERNAME, password = BOB_BROKER_PASSWORD) }) KafkaCluster cluster,
                                                                     Topic topic)
            throws Exception {
        Path storeFile = writeCredentialStore(
                new StoredEntry(ALICE_SUBJECT, ALICE_BROKER_USERNAME, ALICE_BROKER_PASSWORD),
                new StoredEntry(BOB_SUBJECT, BOB_BROKER_USERNAME, BOB_BROKER_PASSWORD));
        var fixedSubject = fixedSubjectDefinition(ALICE_SUBJECT);
        var initiation = subjectInitiationDefinition(storeFile);

        try (var tester = kroxyliciousTester(proxyConfiguration(cluster, fixedSubject, initiation));
                var producer = tester.producer()) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .succeedsWithin(TIMEOUT);
        }
    }

    @Test
    void shouldSelectTheEntryForThePublishedSubject(
                                                    @SaslMechanism(value = "PLAIN", principals = {
                                                            @SaslMechanism.Principal(user = ALICE_BROKER_USERNAME, password = ALICE_BROKER_PASSWORD),
                                                            @SaslMechanism.Principal(user = BOB_BROKER_USERNAME, password = BOB_BROKER_PASSWORD) }) KafkaCluster cluster,
                                                    Topic topic)
            throws Exception {
        Path storeFile = writeCredentialStore(
                new StoredEntry(ALICE_SUBJECT, ALICE_BROKER_USERNAME, ALICE_BROKER_PASSWORD),
                new StoredEntry(BOB_SUBJECT, BOB_BROKER_USERNAME, BOB_BROKER_PASSWORD));
        var fixedSubject = fixedSubjectDefinition(BOB_SUBJECT);
        var initiation = subjectInitiationDefinition(storeFile);

        try (var tester = kroxyliciousTester(proxyConfiguration(cluster, fixedSubject, initiation));
                var producer = tester.producer()) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .succeedsWithin(TIMEOUT);
        }
    }

    @Test
    void shouldFailClosedWhenTheSubjectHasNoCredential(
                                                       @SaslMechanism(value = "PLAIN", principals = {
                                                               @SaslMechanism.Principal(user = ALICE_BROKER_USERNAME, password = ALICE_BROKER_PASSWORD) }) KafkaCluster cluster,
                                                       Topic topic)
            throws Exception {
        Path storeFile = writeCredentialStore(
                new StoredEntry(ALICE_SUBJECT, ALICE_BROKER_USERNAME, ALICE_BROKER_PASSWORD));
        var fixedSubject = fixedSubjectDefinition(MISSING_SUBJECT);
        var initiation = subjectInitiationDefinition(storeFile);

        try (var tester = kroxyliciousTester(proxyConfiguration(cluster, fixedSubject, initiation));
                var producer = tester.producer(FAILING_PRODUCER_CONFIGURATION)) {
            assertThatThrownBy(() -> producer.send(new ProducerRecord<>(topic.name(), "key", "value"))
                    .get(30, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class);
        }
    }

    @Test
    void shouldFailClosedWhenTheBrokerRejectsTheMappedUsername(
                                                               @SaslMechanism(value = "PLAIN", principals = {
                                                                       @SaslMechanism.Principal(user = ALICE_BROKER_USERNAME, password = ALICE_BROKER_PASSWORD) }) KafkaCluster cluster,
                                                               Topic topic)
            throws Exception {
        Path storeFile = writeCredentialStore(
                new StoredEntry(ALICE_SUBJECT, ALICE_BROKER_USERNAME, "wrong-password"));
        var fixedSubject = fixedSubjectDefinition(ALICE_SUBJECT);
        var initiation = subjectInitiationDefinition(storeFile);

        try (var tester = kroxyliciousTester(proxyConfiguration(cluster, fixedSubject, initiation));
                var producer = tester.producer(FAILING_PRODUCER_CONFIGURATION)) {
            assertThatThrownBy(() -> producer.send(new ProducerRecord<>(topic.name(), "key", "value"))
                    .get(30, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class);
        }
    }

    @Test
    void shouldFailClosedForAnAnonymousClientInSubjectMode(
                                                           @SaslMechanism(value = "PLAIN", principals = {
                                                                   @SaslMechanism.Principal(user = ALICE_BROKER_USERNAME, password = ALICE_BROKER_PASSWORD) }) KafkaCluster cluster,
                                                           Topic topic)
            throws Exception {
        Path storeFile = writeCredentialStore(
                new StoredEntry(ALICE_SUBJECT, ALICE_BROKER_USERNAME, ALICE_BROKER_PASSWORD));
        var initiation = subjectInitiationDefinition(storeFile);
        var proxyConfiguration = proxy(cluster);
        proxyConfiguration.addToFilterDefinitions(initiation);
        proxyConfiguration.addToDefaultFilters(initiation.name());

        try (var tester = kroxyliciousTester(proxyConfiguration);
                var producer = tester.producer(FAILING_PRODUCER_CONFIGURATION)) {
            assertThatThrownBy(() -> producer.send(new ProducerRecord<>(topic.name(), "key", "value"))
                    .get(30, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class);
        }
    }

    private static ConfigurationBuilder proxyConfiguration(KafkaCluster cluster,
                                                           NamedFilterDefinition fixedSubject,
                                                           NamedFilterDefinition initiation) {
        var proxyConfiguration = proxy(cluster);
        proxyConfiguration.addToFilterDefinitions(fixedSubject, initiation);
        proxyConfiguration.addToDefaultFilters(fixedSubject.name(), initiation.name());
        return proxyConfiguration;
    }

    private NamedFilterDefinition fixedSubjectDefinition(String subject) {
        return new NamedFilterDefinitionBuilder("fixed-subject", FixedSubjectFilter.class.getName())
                .withConfig(Map.of("subject", subject))
                .build();
    }

    private NamedFilterDefinition subjectInitiationDefinition(Path storeFile) throws Exception {
        Path passwordFile = tempDir.resolve("credentials.password");
        Files.writeString(passwordFile, STORE_PASSWORD, StandardCharsets.UTF_8);
        setOwnerOnly(passwordFile);

        return new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", "PLAIN",
                        "identity", Map.of("mode", "subject"),
                        "keyStore", Map.of(
                                "file", storeFile.toString(),
                                "filePassword", Map.of("passwordFile", passwordFile.toString()))))
                .build();
    }

    private Path writeCredentialStore(StoredEntry... entries) throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] storePassword = STORE_PASSWORD.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        try {
            keyStore.load(null, storePassword);
            for (StoredEntry entry : entries) {
                String json = """
                        {"version":1,"subject":"%s","username":"%s","password":"%s"}
                        """.formatted(entry.subject(), entry.username(), entry.password());
                keyStore.setEntry(alias(entry.subject()),
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(json.getBytes(StandardCharsets.UTF_8), "AES")),
                        protection);
            }
            try (OutputStream output = Files.newOutputStream(file)) {
                keyStore.store(output, storePassword);
            }
            setOwnerOnly(file);
            return file;
        }
        finally {
            protection.destroy();
            Arrays.fill(storePassword, '\0');
        }
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

    private record StoredEntry(String subject, String username, String password) {}
}
