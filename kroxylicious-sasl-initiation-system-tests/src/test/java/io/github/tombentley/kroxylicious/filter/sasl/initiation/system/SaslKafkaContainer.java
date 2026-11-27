/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

import com.github.dockerjava.api.command.InspectContainerResponse;

/**
 * A single-node KRaft Kafka broker with a SASL_PLAINTEXT listener.
 * <p>
 * The broker accepts both {@code PLAIN} and {@code SCRAM-SHA-256} on the same listener. The PLAIN user is configured
 * through the listener JAAS configuration; the SCRAM user is added to the metadata log after the broker starts. The
 * inter-broker and controller listeners use PLAINTEXT so that the test configuration remains small.
 * </p>
 */
final class SaslKafkaContainer extends GenericContainer<SaslKafkaContainer> {

    static final String PLAIN_USER = "plainuser";
    static final String PLAIN_PASSWORD = "plain-user-broker-password";
    static final String SCRAM_USER = "scramuser";
    static final String SCRAM_PASSWORD = "scram-user-client-secret";

    private static final int SASL_PORT = 9092;
    private static final int BROKER_PORT = 9093;
    private static final int CONTROLLER_PORT = 9094;
    private static final String CLUSTER_ID = "4L6g3nShT-eMCtK--X86sw";
    private static final String STARTER_SCRIPT = "/tmp/sasl-initiation-kafka-start.sh";
    private static final String JAAS_FILE = "/etc/kafka/docker/kafka_server_jaas.conf";

    SaslKafkaContainer(DockerImageName dockerImageName) {
        super(dockerImageName);

        withExposedPorts(SASL_PORT);
        withEnv("CLUSTER_ID", CLUSTER_ID);
        withEnv("KAFKA_NODE_ID", "1");
        withEnv("KAFKA_PROCESS_ROLES", "broker,controller");
        withEnv("KAFKA_CONTROLLER_LISTENER_NAMES", "CONTROLLER");
        withEnv("KAFKA_CONTROLLER_QUORUM_VOTERS", "1@localhost:" + CONTROLLER_PORT);
        withEnv("KAFKA_LISTENERS",
                "SASL_PLAINTEXT://0.0.0.0:" + SASL_PORT
                        + ",BROKER://0.0.0.0:" + BROKER_PORT
                        + ",CONTROLLER://0.0.0.0:" + CONTROLLER_PORT);
        withEnv("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP",
                "SASL_PLAINTEXT:SASL_PLAINTEXT,BROKER:PLAINTEXT,CONTROLLER:PLAINTEXT");
        withEnv("KAFKA_INTER_BROKER_LISTENER_NAME", "BROKER");
        withEnv("KAFKA_SASL_ENABLED_MECHANISMS", "PLAIN,SCRAM-SHA-256");

        // Kafka's docker wrapper maps double underscores back to a single underscore in the property name.
        // This variable therefore becomes listener.name.sasl_plaintext.plain.sasl.jaas.config.
        withEnv("KAFKA_LISTENER_NAME_SASL__PLAINTEXT_PLAIN_SASL_JAAS_CONFIG",
                "org.apache.kafka.common.security.plain.PlainLoginModule required user_"
                        + PLAIN_USER + "=\"" + PLAIN_PASSWORD + "\";");

        // ScramLoginModule's static initializer registers the SCRAM SASL server provider. Without a JAAS
        // context that references it, Kafka cannot create a ScramSaslServer and closes the connection during
        // the handshake. Triple underscores encode the hyphens in `scram-sha-256`.
        withEnv("KAFKA_LISTENER_NAME_SASL__PLAINTEXT_SCRAM___SHA___256_SASL_JAAS_CONFIG",
                "org.apache.kafka.common.security.scram.ScramLoginModule required;");

        // The official image requires KAFKA_OPTS when a SASL listener is advertised. The listener-specific
        // configuration above is what Kafka actually uses for PLAIN; this file satisfies the image's check and
        // provides the same user for any code path that falls back to the global KafkaServer section.
        withEnv("KAFKA_OPTS", "-Djava.security.auth.login.config=" + JAAS_FILE);

        withEnv("KAFKA_AUTO_CREATE_TOPICS_ENABLE", "false");
        withEnv("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR", "1");
        withEnv("KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR", "1");
        withEnv("KAFKA_TRANSACTION_STATE_LOG_MIN_ISR", "1");
        withEnv("KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS", "0");

        withCommand("sh", "-c", "while [ ! -f " + STARTER_SCRIPT + " ]; do sleep 0.1; done; " + STARTER_SCRIPT);
        waitingFor(Wait.forLogMessage(".*Kafka Server started.*", 1));
        withStartupTimeout(Duration.ofMinutes(3));
    }

    @Override
    protected void containerIsStarting(InspectContainerResponse containerInfo) {
        // The mapped port is only known once the container has started. KafkaContainer in Testcontainers uses the same
        // starter-script technique to publish a dynamically allocated host port.
        String advertisedListeners = "SASL_PLAINTEXT://" + getHost() + ":" + getMappedPort(SASL_PORT)
                + ",BROKER://" + containerInfo.getConfig().getHostName() + ":" + BROKER_PORT;
        String starter = "#!/bin/bash\n"
                + "set -e\n"
                + "export KAFKA_ADVERTISED_LISTENERS='" + advertisedListeners + "'\n"
                + "exec /etc/kafka/docker/run\n";
        copyFileToContainer(Transferable.of(jaasConfiguration(), 0644), JAAS_FILE);
        copyFileToContainer(Transferable.of(starter, 0777), STARTER_SCRIPT);
    }

    /**
     * Returns the SASL_PLAINTEXT bootstrap address reachable from the host.
     *
     * @return the bootstrap servers
     */
    String bootstrapServers() {
        return getHost() + ":" + getMappedPort(SASL_PORT);
    }

    /**
     * Adds or replaces a SCRAM-SHA-256 credential in the broker metadata.
     *
     * @param username the SCRAM username
     * @param password the SCRAM password
     * @throws Exception if the credential cannot be added before the timeout
     */
    void createScramUser(String username, String password) throws Exception {
        Exception lastFailure = null;
        for (int attempt = 0; attempt < 30; attempt++) {
            var result = execInContainer(
                    "/opt/kafka/bin/kafka-configs.sh",
                    "--bootstrap-server", "localhost:" + BROKER_PORT,
                    "--alter",
                    "--add-config", "SCRAM-SHA-256=[iterations=4096,password=" + password + "]",
                    "--entity-type", "users",
                    "--entity-name", username);
            if (result.getExitCode() == 0) {
                return;
            }
            lastFailure = new IllegalStateException(
                    "Failed to create SCRAM user '" + username + "': "
                            + sanitize(result.getStdout() + result.getStderr(), password));
            Thread.sleep(1_000);
        }
        throw lastFailure;
    }

    private static String jaasConfiguration() {
        return "KafkaServer {\n"
                + "  org.apache.kafka.common.security.plain.PlainLoginModule required\n"
                + "  user_" + PLAIN_USER + "=\"" + PLAIN_PASSWORD + "\";\n"
                + "};\n";
    }

    private static String sanitize(String text, String secret) {
        return text.replace(secret, "***");
    }
}
