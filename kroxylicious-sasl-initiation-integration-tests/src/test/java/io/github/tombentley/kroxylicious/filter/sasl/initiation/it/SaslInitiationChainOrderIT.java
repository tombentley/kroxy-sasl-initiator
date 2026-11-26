/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.Credential;

import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.INITIATION_STORE_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.TERMINATION_STORE_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.assertDirectClientSaslRejected;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.fixedInitiationDefinition;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.scramClientConfiguration;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.terminationDefinition;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeInitiationStore;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writePasswordFile;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeTerminationStore;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;

/**
 * Integration tests for the unsafe client-SASL configurations that {@code SaslInitiation} must reject.
 * <p>
 * Client-facing SASL must be terminated <em>before</em> {@code SaslInitiation}. If a client's SASL frames reach the
 * initiator, either because no termination filter is configured or because the chain is misordered, the initiator
 * rejects the handshake with {@code UNSUPPORTED_SASL_MECHANISM} and closes the connection. No broker detail or SASL
 * payload is returned.
 * </p>
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationChainOrderIT {

    private static final String ALICE = "alice";
    private static final String ALICE_CLIENT_PASSWORD = "alice-client-password-123";

    @TempDir
    Path tempDir;

    @Test
    void shouldRejectClientSaslWhenNoTerminationFilterIsConfigured(
                                                                   @SaslMechanism(value = "PLAIN", principals = {
                                                                           @SaslMechanism.Principal(user = "svc-plain", password = "svc-plain-password-123") }) KafkaCluster cluster,
                                                                   Topic topic)
            throws Exception {
        Path initiationStore = writeInitiationStore(tempDir.resolve("initiation-credentials.p12"),
                new Credential("proxy-service", "svc-plain", "svc-plain-password-123"));
        Path initiationPassword = writePasswordFile(tempDir.resolve("initiation-credentials.password"), INITIATION_STORE_PASSWORD);
        var initiation = fixedInitiationDefinition("sasl-initiation", "PLAIN", "proxy-service",
                initiationStore, initiationPassword);

        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var tester = kroxyliciousTester(config)) {
            assertDirectClientSaslRejected(tester, topic, scramClientConfiguration(ALICE, ALICE_CLIENT_PASSWORD));
        }
    }

    @Test
    void shouldRejectClientSaslWhenTheChainIsMisordered(
                                                        @SaslMechanism(value = "PLAIN", principals = {
                                                                @SaslMechanism.Principal(user = "svc-plain", password = "svc-plain-password-123") }) KafkaCluster cluster,
                                                        Topic topic)
            throws Exception {
        Path initiationStore = writeInitiationStore(tempDir.resolve("initiation-credentials.p12"),
                new Credential("proxy-service", "svc-plain", "svc-plain-password-123"));
        Path initiationPassword = writePasswordFile(tempDir.resolve("initiation-credentials.password"), INITIATION_STORE_PASSWORD);
        var initiation = fixedInitiationDefinition("sasl-initiation", "PLAIN", "proxy-service",
                initiationStore, initiationPassword);

        Path terminationStore = writeTerminationStore(tempDir.resolve("termination-credentials.p12"),
                new Credential(ALICE, ALICE, ALICE_CLIENT_PASSWORD));
        Path terminationPassword = writePasswordFile(tempDir.resolve("termination-credentials.password"), TERMINATION_STORE_PASSWORD);
        var termination = terminationDefinition("sasl-termination", terminationStore, terminationPassword);

        // Misconfiguration: SaslInitiation is before SaslTermination, so the initiator sees the client's SASL frames.
        var config = proxy(cluster)
                .addToFilterDefinitions(initiation, termination)
                .addToDefaultFilters(initiation.name(), termination.name());

        try (var tester = kroxyliciousTester(config)) {
            assertDirectClientSaslRejected(tester, topic, scramClientConfiguration(ALICE, ALICE_CLIENT_PASSWORD));
        }
    }
}
