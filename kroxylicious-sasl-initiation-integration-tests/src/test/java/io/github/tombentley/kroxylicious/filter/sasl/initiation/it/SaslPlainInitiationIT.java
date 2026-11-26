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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.Serdes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation;

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
 * Real-Kafka integration tests for PLAIN SASL initiation with a fixed proxy identity.
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslPlainInitiationIT {

    private static final String STORE_PASSWORD = "plain-initiation-store-password";
    private static final String BROKER_USERNAME = "broker-alice";
    private static final String BROKER_PASSWORD = "broker-alice-password";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final Map<String, Object> FAILING_PRODUCER_CONFIGURATION = Map.of(
            ProducerConfig.MAX_BLOCK_MS_CONFIG, 10_000,
            ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10_000,
            ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5_000);

    @TempDir
    Path tempDir;

    @Test
    void shouldProduceAndConsumeThroughPlainInitiation(
                                                       @SaslMechanism(value = "PLAIN", principals = {
                                                               @SaslMechanism.Principal(user = BROKER_USERNAME, password = BROKER_PASSWORD) }) KafkaCluster cluster,
                                                       Topic topic)
            throws Exception {
        var filterDefinition = filterDefinition("PLAIN", BROKER_USERNAME, BROKER_PASSWORD);
        var proxyConfiguration = proxy(cluster);
        proxyConfiguration.addToFilterDefinitions(filterDefinition);
        proxyConfiguration.addToDefaultFilters(filterDefinition.name());

        Map<String, Object> consumerConfiguration = Map.of(
                ConsumerConfig.GROUP_ID_CONFIG, "sasl-plain-initiation-group",
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        try (var tester = kroxyliciousTester(proxyConfiguration);
                var producer = tester.producer();
                var consumer = tester.consumer(Serdes.String(), Serdes.String(), consumerConfiguration)) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .succeedsWithin(TIMEOUT);

            consumer.subscribe(List.of(topic.name()));

            assertThat(consumer.poll(TIMEOUT).records(topic.name()))
                    .singleElement()
                    .extracting(ConsumerRecord::key, ConsumerRecord::value)
                    .containsExactly("key", "value");
        }
    }

    @Test
    void shouldFailClosedForAWrongPassword(
                                           @SaslMechanism(value = "PLAIN", principals = {
                                                   @SaslMechanism.Principal(user = BROKER_USERNAME, password = BROKER_PASSWORD) }) KafkaCluster cluster,
                                           Topic topic)
            throws Exception {
        var filterDefinition = filterDefinition("PLAIN", BROKER_USERNAME, "wrong-password");
        var proxyConfiguration = proxy(cluster);
        proxyConfiguration.addToFilterDefinitions(filterDefinition);
        proxyConfiguration.addToDefaultFilters(filterDefinition.name());

        try (var tester = kroxyliciousTester(proxyConfiguration);
                var producer = tester.producer(FAILING_PRODUCER_CONFIGURATION)) {
            assertThatThrownBy(() -> producer.send(new ProducerRecord<>(topic.name(), "key", "value"))
                    .get(30, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class);
        }
    }

    @Test
    void shouldFailClosedWhenTheBrokerRejectsTheConfiguredMechanism(
                                                                    @SaslMechanism(value = "PLAIN", principals = {
                                                                            @SaslMechanism.Principal(user = BROKER_USERNAME, password = BROKER_PASSWORD) }) KafkaCluster cluster,
                                                                    Topic topic)
            throws Exception {
        var filterDefinition = filterDefinition("SCRAM-SHA-256", BROKER_USERNAME, BROKER_PASSWORD);
        var proxyConfiguration = proxy(cluster);
        proxyConfiguration.addToFilterDefinitions(filterDefinition);
        proxyConfiguration.addToDefaultFilters(filterDefinition.name());

        try (var tester = kroxyliciousTester(proxyConfiguration);
                var producer = tester.producer(FAILING_PRODUCER_CONFIGURATION)) {
            assertThatThrownBy(() -> producer.send(new ProducerRecord<>(topic.name(), "key", "value"))
                    .get(30, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class);
        }
    }

    private NamedFilterDefinition filterDefinition(String mechanism, String username, String password) throws Exception {
        Path storeFile = tempDir.resolve("credentials-" + mechanism + ".p12");
        writeCredentialStore(storeFile, "alice", username, password);
        Path passwordFile = tempDir.resolve("credentials-" + mechanism + ".password");
        Files.writeString(passwordFile, STORE_PASSWORD, StandardCharsets.UTF_8);
        setOwnerOnly(passwordFile);

        return new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", mechanism,
                        "identity", Map.of("mode", "fixed", "key", "alice"),
                        "keyStore", Map.of(
                                "file", storeFile.toString(),
                                "filePassword", Map.of("passwordFile", passwordFile.toString()))))
                .build();
    }

    private static void writeCredentialStore(Path file, String subject, String username, String password) throws Exception {
        String json = """
                {"version":1,"subject":"%s","username":"%s","password":"%s"}
                """.formatted(subject, username, password);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] storePassword = STORE_PASSWORD.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        try {
            keyStore.load(null, storePassword);
            keyStore.setEntry(alias(subject),
                    new KeyStore.SecretKeyEntry(new SecretKeySpec(json.getBytes(StandardCharsets.UTF_8), "AES")),
                    protection);
            try (OutputStream output = Files.newOutputStream(file)) {
                keyStore.store(output, storePassword);
            }
            setOwnerOnly(file);
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
}
