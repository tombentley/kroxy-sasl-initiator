/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Kafka clients used by the system tests.
 */
final class KafkaClientSupport {

    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(30);

    private KafkaClientSupport() {
    }

    /**
     * Waits for the proxy to become usable and creates a single-partition topic.
     *
     * @param bootstrapServers the proxy bootstrap address
     * @param topic the topic to create
     * @throws Exception if the cluster never becomes ready or the topic cannot be created
     */
    static void createTopic(String bootstrapServers, String topic) throws Exception {
        try (AdminClient admin = AdminClient.create(adminProperties(bootstrapServers))) {
            await().atMost(Duration.ofSeconds(60))
                    .pollInterval(Duration.ofMillis(500))
                    .ignoreExceptions()
                    .untilAsserted(() -> assertThat(admin.describeCluster()
                            .clusterId()
                            .get(10, TimeUnit.SECONDS)).isNotBlank());
            admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1)))
                    .all()
                    .get(CLIENT_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        }
    }

    /**
     * Produces the given records through the proxy and consumes them back through the proxy.
     *
     * @param bootstrapServers the proxy bootstrap address
     * @param topic the topic
     * @param expected the expected key/value records
     * @throws Exception if producing or consuming fails
     */
    static void produceAndConsume(String bootstrapServers, String topic, Map<String, String> expected) throws Exception {
        Map<String, String> records = new LinkedHashMap<>(expected);

        Properties producerConfiguration = new Properties();
        producerConfiguration.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        producerConfiguration.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerConfiguration.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerConfiguration.put(ProducerConfig.ACKS_CONFIG, "all");
        producerConfiguration.put(ProducerConfig.RETRIES_CONFIG, 3);
        producerConfiguration.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 30_000);
        producerConfiguration.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 10_000);
        producerConfiguration.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 30_000);
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(producerConfiguration)) {
            for (Map.Entry<String, String> entry : records.entrySet()) {
                producer.send(new ProducerRecord<>(topic, entry.getKey(), entry.getValue()))
                        .get(CLIENT_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            }
        }

        Properties consumerConfiguration = new Properties();
        consumerConfiguration.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        consumerConfiguration.put(ConsumerConfig.GROUP_ID_CONFIG, "system-test-" + UUID.randomUUID());
        consumerConfiguration.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        consumerConfiguration.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        consumerConfiguration.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        consumerConfiguration.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        consumerConfiguration.put(ConsumerConfig.REQUEST_TIMEOUT_MS_CONFIG, 10_000);
        consumerConfiguration.put(ConsumerConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, 20_000);

        Map<String, String> actual = new LinkedHashMap<>();
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerConfiguration)) {
            consumer.subscribe(List.of(topic));
            long deadline = System.nanoTime() + CLIENT_TIMEOUT.toNanos();
            while (actual.size() < records.size() && System.nanoTime() < deadline) {
                for (ConsumerRecord<String, String> record : consumer.poll(Duration.ofMillis(500))) {
                    actual.put(record.key(), record.value());
                }
            }
        }
        assertThat(actual).isEqualTo(records);
    }

    private static Properties adminProperties(String bootstrapServers) {
        Properties properties = new Properties();
        properties.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        properties.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, 10_000);
        properties.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, 20_000);
        properties.put(AdminClientConfig.RETRIES_CONFIG, 3);
        return properties;
    }
}
