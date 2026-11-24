/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.Serdes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

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
 * The filter is currently a pass-through: this test proves that plugin discovery, configuration and the
 * proxy/test harness work against a real Kafka cluster.
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationSmokeIT {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final Map<String, Object> CONSUMER_CONFIGURATION = Map.of(
            ConsumerConfig.GROUP_ID_CONFIG, "sasl-initiation-smoke-test-group",
            ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

    @Test
    void shouldProduceAndConsumeThroughTheNoOpFilter(@BrokerCluster KafkaCluster cluster, Topic topic) {
        var filterDefinition = new NamedFilterDefinitionBuilder(
                "sasl-initiation", SaslInitiation.class.getName())
                .withConfig("mechanism", "PLAIN")
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
}
