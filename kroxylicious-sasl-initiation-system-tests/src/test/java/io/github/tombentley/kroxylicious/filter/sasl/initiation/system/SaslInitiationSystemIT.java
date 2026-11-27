/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Black-box system tests for the packaged SASL initiation plugin.
 * <p>
 * Each test starts the released Kroxylicious distribution as a subprocess with the built plugin on its
 * {@code classpath-plugins} path, a CLI-generated PKCS12 store, and a Testcontainers Kafka broker with a
 * SASL_PLAINTEXT listener. The clients talk only to the proxy, never directly to the broker.
 * </p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Timeout(value = 10, unit = TimeUnit.MINUTES)
class SaslInitiationSystemIT {

    private static final String STORE_PASSWORD = "system-test-store-password";
    private static final String SUBJECT = "proxy-service";
    private static final String PLAIN_MECHANISM = "PLAIN";
    private static final String SCRAM_MECHANISM = "SCRAM-SHA-256";
    private static final String DEFAULT_KAFKA_VERSION = "4.3.2";

    @TempDir(cleanup = CleanupMode.ON_SUCCESS)
    Path tempDirectory;

    private SaslKafkaContainer kafka;
    private KroxyliciousDistribution distribution;

    @BeforeAll
    void startKafkaAndPrepareDistribution() throws Exception {
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker is required for the packaged-proxy system tests");
        distribution = KroxyliciousDistribution.prepare();
        kafka = new SaslKafkaContainer(kafkaImage());
        kafka.start();
        kafka.createScramUser(SaslKafkaContainer.SCRAM_USER, SaslKafkaContainer.SCRAM_PASSWORD);
    }

    @AfterAll
    void stopKafka() {
        if (kafka != null) {
            kafka.stop();
        }
    }

    @Test
    void shouldProduceAndConsumeThroughTheProxyWithFixedPlainIdentity() throws Exception {
        assertProduceAndConsume(PLAIN_MECHANISM,
                SaslKafkaContainer.PLAIN_USER,
                SaslKafkaContainer.PLAIN_PASSWORD,
                Map.of("plain-key", "plain-value"));
    }

    @Test
    void shouldProduceAndConsumeThroughTheProxyWithFixedScramSha256Identity() throws Exception {
        assertProduceAndConsume(SCRAM_MECHANISM,
                SaslKafkaContainer.SCRAM_USER,
                SaslKafkaContainer.SCRAM_PASSWORD,
                Map.of("scram-key", "scram-value"));
    }

    @Test
    void shouldProduceAndConsumeMultipleRecordsThroughTheProxy() throws Exception {
        Map<String, String> records = new LinkedHashMap<>();
        for (int i = 0; i < 5; i++) {
            records.put("key-" + i, "value-" + i);
        }
        assertProduceAndConsume(PLAIN_MECHANISM,
                SaslKafkaContainer.PLAIN_USER,
                SaslKafkaContainer.PLAIN_PASSWORD,
                records);
    }

    @Test
    void shouldNotLeakSecretsIntoProxyLogs() throws Exception {
        String plainLog = runAndCaptureLog(PLAIN_MECHANISM,
                SaslKafkaContainer.PLAIN_USER,
                SaslKafkaContainer.PLAIN_PASSWORD,
                "proxy-logs-plain");
        String scramLog = runAndCaptureLog(SCRAM_MECHANISM,
                SaslKafkaContainer.SCRAM_USER,
                SaslKafkaContainer.SCRAM_PASSWORD,
                "proxy-logs-scram");

        assertThat(plainLog)
                .as("PLAIN proxy log")
                .contains("Loaded SASL initiation credentials")
                .contains("Kroxylicious is started")
                .doesNotContain(STORE_PASSWORD)
                .doesNotContain(SaslKafkaContainer.PLAIN_PASSWORD);
        assertThat(scramLog)
                .as("SCRAM proxy log")
                .contains("Loaded SASL initiation credentials")
                .contains("Kroxylicious is started")
                .doesNotContain(STORE_PASSWORD)
                .doesNotContain(SaslKafkaContainer.SCRAM_PASSWORD);
        assertThat(plainLog + scramLog)
                .as("all proxy logs")
                .doesNotContain(STORE_PASSWORD)
                .doesNotContain(SaslKafkaContainer.PLAIN_PASSWORD)
                .doesNotContain(SaslKafkaContainer.SCRAM_PASSWORD);
    }

    private void assertProduceAndConsume(String mechanism,
                                         String username,
                                         String password,
                                         Map<String, String> records)
            throws Exception {
        String topic = topicName(mechanism);
        TestCredentials credentials = TestCredentials.create(tempDirectory, distribution, SUBJECT, username, password,
                STORE_PASSWORD);
        PackagedProxy proxy = PackagedProxy.start(distribution, tempDirectory, mechanism, SUBJECT, credentials,
                kafka.bootstrapServers());
        try {
            KafkaClientSupport.createTopic(proxy.bootstrapServers(), topic);
            KafkaClientSupport.produceAndConsume(proxy.bootstrapServers(), topic, records);
        }
        catch (Exception e) {
            closeAfterFailure(proxy, e);
        }
        proxy.close();
        assertThat(proxy.log())
                .as("proxy log for " + mechanism)
                .doesNotContain(STORE_PASSWORD)
                .doesNotContain(password);
    }

    private String runAndCaptureLog(String mechanism, String username, String password, String topicPrefix) throws Exception {
        String topic = topicName(topicPrefix);
        TestCredentials credentials = TestCredentials.create(tempDirectory, distribution, SUBJECT, username, password,
                STORE_PASSWORD);
        PackagedProxy proxy = PackagedProxy.start(distribution, tempDirectory, mechanism, SUBJECT, credentials,
                kafka.bootstrapServers());
        try {
            KafkaClientSupport.createTopic(proxy.bootstrapServers(), topic);
            KafkaClientSupport.produceAndConsume(proxy.bootstrapServers(), topic, Map.of("key", "value"));
        }
        catch (Exception e) {
            closeAfterFailure(proxy, e);
        }
        proxy.close();
        return proxy.log();
    }

    private static void closeAfterFailure(PackagedProxy proxy, Exception failure) {
        proxy.close();
        throw new IllegalStateException("The system test failed; proxy output follows:"
                + System.lineSeparator() + proxy.log(), failure);
    }

    private static String topicName(String prefix) {
        return "system-it-" + prefix + "-" + UUID.randomUUID();
    }

    private static DockerImageName kafkaImage() {
        String image = System.getProperty("kafka.container.image");
        if (image != null && !image.isBlank()) {
            return DockerImageName.parse(image);
        }
        String version = System.getProperty("kafka.container.version", DEFAULT_KAFKA_VERSION);
        return DockerImageName.parse("apache/kafka:" + version);
    }
}
