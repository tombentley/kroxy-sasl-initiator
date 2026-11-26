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
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.errors.UnsupportedSaslMechanismException;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.message.DescribeClusterRequestData;
import org.apache.kafka.common.message.DescribeClusterResponseData;
import org.apache.kafka.common.message.SaslHandshakeRequestData;
import org.apache.kafka.common.message.SaslHandshakeResponseData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.protocol.Errors;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation;

import io.kroxylicious.filter.sasl.termination.SaslTermination;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.scram.credentialstore.file.ScramCredentialFileManager;
import io.kroxylicious.scram.credentialstore.file.ScramCredentialFileService;
import io.kroxylicious.testing.integration.Request;
import io.kroxylicious.testing.integration.client.KafkaClient;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousTester;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Shared fixtures and assertions for the client-authentication composition tests.
 */
final class CompositionTestSupport {

    static final String TERMINATION_STORE_PASSWORD = "termination-client-store-password";
    static final String INITIATION_STORE_PASSWORD = "initiation-upstream-store-password";
    static final Duration TIMEOUT = Duration.ofSeconds(20);
    static final Duration CLOSE_TIMEOUT = Duration.ofSeconds(10);

    private static final Map<String, Object> FAILING_PRODUCER_CONFIGURATION = Map.of(
            ProducerConfig.MAX_BLOCK_MS_CONFIG, 10_000,
            ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10_000,
            ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5_000);

    private CompositionTestSupport() {
    }

    static Path writePasswordFile(Path file, String password) throws Exception {
        Files.writeString(file, password, StandardCharsets.UTF_8);
        setOwnerOnly(file);
        return file;
    }

    static Path writeInitiationStore(Path file, Credential... entries) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] storePassword = INITIATION_STORE_PASSWORD.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        try {
            keyStore.load(null, storePassword);
            for (Credential entry : entries) {
                keyStore.setEntry(alias(entry.subject()),
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(entry.toJson().getBytes(StandardCharsets.UTF_8), "AES")),
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

    static Path writeTerminationStore(Path file, Credential... entries) {
        ScramCredentialFileManager manager = new ScramCredentialFileManager();
        manager.createKeyStore(file, TERMINATION_STORE_PASSWORD);
        for (Credential entry : entries) {
            manager.addUser(file, TERMINATION_STORE_PASSWORD, entry.subject(), entry.password(), ScramMechanism.SCRAM_SHA_256);
        }
        return file;
    }

    static NamedFilterDefinition terminationDefinition(String name, Path store, Path passwordFile) {
        return new NamedFilterDefinitionBuilder(name, SaslTermination.class.getName())
                .withConfig("mechanisms", List.of(
                        Map.of(
                                "mechanism", "SCRAM-SHA-256",
                                "credentialStore", ScramCredentialFileService.class.getName(),
                                "credentialStoreConfig", Map.of(
                                        "file", store.toString(),
                                        "filePassword", Map.of("passwordFile", passwordFile.toString())))))
                .build();
    }

    static NamedFilterDefinition fixedInitiationDefinition(String name,
                                                           String mechanism,
                                                           String key,
                                                           Path store,
                                                           Path passwordFile) {
        return initiationDefinition(name, mechanism,
                Map.of("mode", "fixed", "key", key),
                store, passwordFile);
    }

    static NamedFilterDefinition subjectInitiationDefinition(String name,
                                                             String mechanism,
                                                             Path store,
                                                             Path passwordFile) {
        return initiationDefinition(name, mechanism,
                Map.of("mode", "subject"),
                store, passwordFile);
    }

    private static NamedFilterDefinition initiationDefinition(String name,
                                                              String mechanism,
                                                              Map<String, Object> identity,
                                                              Path store,
                                                              Path passwordFile) {
        return new NamedFilterDefinitionBuilder(name, SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", mechanism,
                        "identity", identity,
                        "keyStore", Map.of(
                                "file", store.toString(),
                                "filePassword", Map.of("passwordFile", passwordFile.toString()))))
                .build();
    }

    static Map<String, Object> scramClientConfiguration(String username, String password) {
        String jaasConfig = String.format(
                "org.apache.kafka.common.security.scram.ScramLoginModule required username=\"%s\" password=\"%s\";",
                username, password);

        return new HashMap<>(Map.of(
                CommonClientConfigs.CLIENT_ID_CONFIG, "composition-scram-client",
                CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT",
                SaslConfigs.SASL_MECHANISM, "SCRAM-SHA-256",
                SaslConfigs.SASL_JAAS_CONFIG, jaasConfig));
    }

    static void assertProduceAndConsume(KroxyliciousTester tester,
                                        Topic topic,
                                        Map<String, Object> clientConfiguration,
                                        String consumerGroup,
                                        String expectedDownstreamSubject,
                                        String expectedUpstreamMechanism,
                                        String expectedUpstreamAuthorizationId) {
        Map<String, Object> consumerConfiguration = new HashMap<>(clientConfiguration);
        consumerConfiguration.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        consumerConfiguration.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        try (var producer = tester.producer(clientConfiguration);
                var consumer = tester.consumer(consumerConfiguration)) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .succeedsWithin(TIMEOUT);

            consumer.subscribe(List.of(topic.name()));

            assertThat(consumer.poll(TIMEOUT).records(topic.name()))
                    .singleElement()
                    .satisfies(record -> {
                        assertThat(record.key()).isEqualTo("key");
                        assertThat(record.value()).isEqualTo("value");
                        assertThat(headerValue(record, CompositionObserverFilter.DOWNSTREAM_SUBJECT_HEADER))
                                .isEqualTo(expectedDownstreamSubject);
                        assertThat(headerValue(record, CompositionObserverFilter.UPSTREAM_MECHANISM_HEADER))
                                .isEqualTo(expectedUpstreamMechanism);
                        assertThat(headerValue(record, CompositionObserverFilter.UPSTREAM_AUTHORIZATION_ID_HEADER))
                                .isEqualTo(expectedUpstreamAuthorizationId);
                    });
        }
    }

    static void assertDirectClientSaslRejected(KroxyliciousTester tester, Topic topic, Map<String, Object> clientConfiguration) {
        Map<String, Object> failingConfiguration = new HashMap<>(clientConfiguration);
        failingConfiguration.putAll(FAILING_PRODUCER_CONFIGURATION);

        try (var producer = tester.producer(failingConfiguration)) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .failsWithin(30, TimeUnit.SECONDS)
                    .withThrowableOfType(ExecutionException.class)
                    .withCauseExactlyInstanceOf(UnsupportedSaslMechanismException.class);
        }

        try (KafkaClient client = tester.simpleTestClient()) {
            SaslHandshakeResponseData response = sendSaslHandshake(client, "SCRAM-SHA-256");
            assertThat(Errors.forCode(response.errorCode())).isEqualTo(Errors.UNSUPPORTED_SASL_MECHANISM);
            assertThat(response.mechanisms()).isEmpty();
            await().atMost(CLOSE_TIMEOUT).untilAsserted(() -> assertThat(client.isOpen()).isFalse());
        }
    }

    static void assertAnonymousSubjectModeFailsGenerically(KroxyliciousTester tester) {
        try (KafkaClient client = tester.simpleTestClient()) {
            DescribeClusterResponseData response = (DescribeClusterResponseData) client.getSync(
                    new Request(ApiKeys.DESCRIBE_CLUSTER,
                            ApiKeys.DESCRIBE_CLUSTER.latestVersion(),
                            "anonymous-subject-mode",
                            new DescribeClusterRequestData()))
                    .payload()
                    .message();

            assertThat(Errors.forCode(response.errorCode())).isEqualTo(Errors.UNKNOWN_SERVER_ERROR);
            assertThat(response.errorMessage()).isNullOrEmpty();
            await().atMost(CLOSE_TIMEOUT).untilAsserted(() -> assertThat(client.isOpen()).isFalse());
        }
    }

    private static SaslHandshakeResponseData sendSaslHandshake(KafkaClient client, String mechanism) {
        return (SaslHandshakeResponseData) client.getSync(
                new Request(ApiKeys.SASL_HANDSHAKE,
                        ApiKeys.SASL_HANDSHAKE.latestVersion(),
                        "direct-client-sasl",
                        new SaslHandshakeRequestData().setMechanism(mechanism)))
                .payload()
                .message();
    }

    private static String headerValue(ConsumerRecord<?, ?> record, String key) {
        Header header = record.headers().lastHeader(key);
        return header == null ? null : new String(header.value(), StandardCharsets.UTF_8);
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

    record Credential(String subject, String username, String password) {

        String toJson() {
            return """
                    {"version":1,"subject":"%s","username":"%s","password":"%s"}
                    """.formatted(subject, username, password);
        }
    }
}
