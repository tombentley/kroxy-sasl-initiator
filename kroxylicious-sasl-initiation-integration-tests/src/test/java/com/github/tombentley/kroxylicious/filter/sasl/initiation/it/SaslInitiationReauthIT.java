/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;

import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.BrokerConfig;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.INITIATION_STORE_PASSWORD;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.TIMEOUT;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.fixedInitiationDefinition;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeInitiationStore;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writePasswordFile;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Real-Kafka KIP-368 reauthentication tests.
 * <p>
 * The broker advertises a five-second reauthentication window. A producer keeps the proxied connection busy across more
 * than two such windows. Reauthentication must be invisible to the Kafka client while the proxy logs each exchange.
 * Metrics are deliberately not asserted here; they arrive in a later commit.
 * </p>
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationReauthIT {

    private static final String BROKER_USERNAME = "reauth-broker-alice";
    private static final String BROKER_PASSWORD = "reauth-broker-alice-password";
    private static final String FIXED_KEY = "reauth-proxy-service";
    private static final String REAUTH_MS = "5000";
    private static final Duration ACTIVITY_DURATION = Duration.ofSeconds(12);
    private static final Duration SEND_INTERVAL = Duration.ofMillis(250);
    private static final Map<String, Object> PRODUCER_CONFIGURATION = Map.of(
            ProducerConfig.ACKS_CONFIG, "all",
            ProducerConfig.LINGER_MS_CONFIG, 0);

    @TempDir
    Path tempDir;

    @Test
    void shouldReauthenticateTransparentlyAgainstARealBroker(
                                                             @SaslMechanism(value = "SCRAM-SHA-256", principals = {
                                                                     @SaslMechanism.Principal(user = BROKER_USERNAME, password = BROKER_PASSWORD) }) @BrokerConfig(name = "connections.max.reauth.ms", value = REAUTH_MS) KafkaCluster cluster,
                                                             Topic topic)
            throws Exception {
        Path store = writeInitiationStore(tempDir.resolve("reauth-credentials.p12"),
                new CompositionTestSupport.Credential(FIXED_KEY, BROKER_USERNAME, BROKER_PASSWORD));
        Path passwordFile = writePasswordFile(tempDir.resolve("reauth-credentials.password"), INITIATION_STORE_PASSWORD);
        var initiation = fixedInitiationDefinition("sasl-initiation", "SCRAM-SHA-256", FIXED_KEY, store, passwordFile);
        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var logs = OAuthBearerTestSupport.captureLogs();
                var tester = kroxyliciousTester(config);
                var producer = tester.producer(PRODUCER_CONFIGURATION)) {
            long deadline = System.nanoTime() + ACTIVITY_DURATION.toNanos();
            int sequence = 0;
            while (System.nanoTime() < deadline) {
                assertThat(producer.send(new ProducerRecord<>(topic.name(), "key-" + sequence, "value-" + sequence)))
                        .succeedsWithin(TIMEOUT);
                sequence++;
                TimeUnit.MILLISECONDS.sleep(SEND_INTERVAL.toMillis());
            }
            assertThat(sequence).isGreaterThan(20);

            await().atMost(Duration.ofSeconds(10))
                    .untilAsserted(() -> assertThat(logs.text())
                            .contains("Starting KIP-368 SASL reauthentication")
                            .contains("KIP-368 SASL reauthentication succeeded"));
        }
    }
}
