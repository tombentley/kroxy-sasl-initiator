/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

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

import javax.crypto.spec.SecretKeySpec;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.Serdes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;

import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.BrokerCluster;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end smoke test for the bootstrap SASL initiation plugin.
 * <p>
 * The filter is currently a pass-through: this test proves that plugin discovery, configuration, KeyStore loading and
 * the proxy/test harness work against a real Kafka cluster.
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationSmokeIT {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final String STORE_PASSWORD = "smoke-store-password";
    private static final Map<String, Object> CONSUMER_CONFIGURATION = Map.of(
            ConsumerConfig.GROUP_ID_CONFIG, "sasl-initiation-smoke-test-group",
            ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

    @TempDir
    Path tempDir;

    @Test
    void shouldProduceAndConsumeThroughTheNoOpFilter(@BrokerCluster KafkaCluster cluster, Topic topic) throws Exception {
        Path storeFile = writeCredentialStore(tempDir.resolve("credentials.p12"), "alice");
        Path passwordFile = tempDir.resolve("credentials.password");
        Files.writeString(passwordFile, STORE_PASSWORD, StandardCharsets.UTF_8);
        setOwnerOnly(passwordFile);

        var filterDefinition = new NamedFilterDefinitionBuilder(
                "sasl-initiation", SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", "PLAIN",
                        "identity", Map.of("mode", "fixed", "key", "alice"),
                        "keyStore", Map.of(
                                "file", storeFile.toString(),
                                "filePassword", Map.of("passwordFile", passwordFile.toString()))))
                .build();

        var proxyConfiguration = proxy(cluster);
        proxyConfiguration.addToFilterDefinitions(filterDefinition);
        proxyConfiguration.addToDefaultFilters(filterDefinition.name());

        try (var tester = kroxyliciousTester(proxyConfiguration);
                var producer = tester.producer();
                var consumer = tester.consumer(Serdes.String(), Serdes.String(), CONSUMER_CONFIGURATION)) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .succeedsWithin(TIMEOUT);

            consumer.subscribe(List.of(topic.name()));

            assertThat(consumer.poll(TIMEOUT).records(topic.name()))
                    .singleElement()
                    .extracting(ConsumerRecord::key, ConsumerRecord::value)
                    .containsExactly("key", "value");
        }
    }

    private static Path writeCredentialStore(Path file, String subject) throws Exception {
        String json = """
                {"version":1,"subject":"%s","username":"broker-%s","password":"broker-password"}
                """.formatted(subject, subject);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STORE_PASSWORD.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
        try {
            keyStore.load(null, password);
            keyStore.setEntry(alias(subject),
                    new KeyStore.SecretKeyEntry(new SecretKeySpec(json.getBytes(StandardCharsets.UTF_8), "AES")),
                    protection);
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
