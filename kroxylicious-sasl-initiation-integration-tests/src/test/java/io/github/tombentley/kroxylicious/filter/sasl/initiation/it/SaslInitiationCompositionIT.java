/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.common.config.SslConfigs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.Credential;

import io.kroxylicious.proxy.authentication.UserFactory;
import io.kroxylicious.proxy.config.tls.TlsClientAuth;
import io.kroxylicious.testing.integration.config.TransportSubjectBuilderDefinitionBuilder;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.KeytoolCertificateGenerator;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.common.Tls;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.INITIATION_STORE_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.TERMINATION_STORE_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.assertAnonymousSubjectModeFailsGenerically;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.assertProduceAndConsume;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.fixedInitiationDefinition;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.scramClientConfiguration;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.subjectInitiationDefinition;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.terminationDefinition;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeInitiationStore;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writePasswordFile;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeTerminationStore;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.DEFAULT_CLUSTER_DEF_NAME;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.DEFAULT_CLUSTER_TARGET;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.OS_ASSIGNED_BOOTSTRAP;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.baseConfigurationBuilder;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.defaultPortIdentifiesNodeGatewayBuilder;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.newBuilder;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real-Kafka integration tests proving that {@code SaslInitiation} composes with client-facing authentication.
 * <p>
 * Every successful scenario uses two separate PKCS12 files: one SCRAM credential store owned by
 * {@code SaslTermination}, and one password-credential store owned by {@code SaslInitiation}. This verifies D17
 * (dedicated credential stores) rather than silently sharing client and broker credentials.
 * </p>
 * <p>
 * A test-only {@link CompositionObserverFilter} is placed after {@code SaslInitiation}, closest to the broker. It
 * records the mechanism and authorization id used by the initiator and adds them, together with the downstream subject,
 * to produced records. The assertions therefore verify the identity the broker actually authenticated, not just that a
 * produce happened to succeed.
 * </p>
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationCompositionIT {

    private static final String ALICE = "alice";
    private static final String ALICE_CLIENT_PASSWORD = "alice-client-password-123";
    private static final String ALICE_SUBJECT = "Subject[principals=[User[name=alice]]]";
    private static final String ANONYMOUS_SUBJECT = "Subject[principals=[]]";

    @TempDir
    Path tempDir;

    @Test
    void shouldTerminateScramClientThenInitiatePlainUpstreamWithADifferentIdentity(
                                                                                   @SaslMechanism(value = "PLAIN", principals = {
                                                                                           @SaslMechanism.Principal(user = "svc-plain", password = "svc-plain-password-123") }) KafkaCluster cluster,
                                                                                   Topic topic)
            throws Exception {
        Stores stores = stores(
                List.of(new Credential(ALICE, ALICE, ALICE_CLIENT_PASSWORD)),
                List.of(new Credential("proxy-service", "svc-plain", "svc-plain-password-123")));
        var termination = terminationDefinition("sasl-termination", stores.terminationStore(), stores.terminationPassword());
        var initiation = fixedInitiationDefinition("sasl-initiation", "PLAIN", "proxy-service",
                stores.initiationStore(), stores.initiationPassword());
        var observer = CompositionObserverFilter.definition("composition-observer");

        var config = proxy(cluster)
                .addToFilterDefinitions(termination, initiation, observer)
                .addToDefaultFilters(termination.name(), initiation.name(), observer.name());

        try (var tester = kroxyliciousTester(config)) {
            assertProduceAndConsume(tester, topic,
                    scramClientConfiguration(ALICE, ALICE_CLIENT_PASSWORD),
                    "composition-plain-upstream",
                    ALICE_SUBJECT,
                    "PLAIN",
                    "svc-plain");
        }
    }

    @Test
    void shouldTerminateScramClientThenTranslateToScramSha512Upstream(
                                                                      @SaslMechanism(value = "SCRAM-SHA-512", principals = {
                                                                              @SaslMechanism.Principal(user = "svc-translation", password = "svc-translation-password-123") }) KafkaCluster cluster,
                                                                      Topic topic)
            throws Exception {
        Stores stores = stores(
                List.of(new Credential(ALICE, ALICE, ALICE_CLIENT_PASSWORD)),
                List.of(new Credential("proxy-service", "svc-translation", "svc-translation-password-123")));
        var termination = terminationDefinition("sasl-termination", stores.terminationStore(), stores.terminationPassword());
        var initiation = fixedInitiationDefinition("sasl-initiation", "SCRAM-SHA-512", "proxy-service",
                stores.initiationStore(), stores.initiationPassword());
        var observer = CompositionObserverFilter.definition("composition-observer");

        var config = proxy(cluster)
                .addToFilterDefinitions(termination, initiation, observer)
                .addToDefaultFilters(termination.name(), initiation.name(), observer.name());

        try (var tester = kroxyliciousTester(config)) {
            assertProduceAndConsume(tester, topic,
                    scramClientConfiguration(ALICE, ALICE_CLIENT_PASSWORD),
                    "composition-scram-translation",
                    ALICE_SUBJECT,
                    "SCRAM-SHA-512",
                    "svc-translation");
        }
    }

    @Test
    void shouldMapTheTerminatedUserToAPerUserUpstreamIdentity(
                                                              @SaslMechanism(value = "PLAIN", principals = {
                                                                      @SaslMechanism.Principal(user = "svc-alice", password = "svc-alice-password-123") }) KafkaCluster cluster,
                                                              Topic topic)
            throws Exception {
        Stores stores = stores(
                List.of(new Credential(ALICE, ALICE, ALICE_CLIENT_PASSWORD)),
                List.of(new Credential(ALICE, "svc-alice", "svc-alice-password-123")));
        var termination = terminationDefinition("sasl-termination", stores.terminationStore(), stores.terminationPassword());
        var initiation = subjectInitiationDefinition("sasl-initiation", "PLAIN",
                stores.initiationStore(), stores.initiationPassword());
        var observer = CompositionObserverFilter.definition("composition-observer");

        var config = proxy(cluster)
                .addToFilterDefinitions(termination, initiation, observer)
                .addToDefaultFilters(termination.name(), initiation.name(), observer.name());

        try (var tester = kroxyliciousTester(config)) {
            assertProduceAndConsume(tester, topic,
                    scramClientConfiguration(ALICE, ALICE_CLIENT_PASSWORD),
                    "composition-mapped-identity",
                    ALICE_SUBJECT,
                    "PLAIN",
                    "svc-alice");
        }
    }

    @Test
    void shouldComposeMutualTlsClientWithScramInitiation(
                                                         @SaslMechanism(value = "SCRAM-SHA-512", principals = {
                                                                 @SaslMechanism.Principal(user = "svc-mtls", password = "svc-mtls-password-123") }) @Tls KafkaCluster cluster,
                                                         Topic topic)
            throws Exception {
        KeytoolCertificateGenerator downstreamCertificateGenerator = new KeytoolCertificateGenerator();
        downstreamCertificateGenerator.generateSelfSignedCertificateEntry("test@kroxylicious.io", "localhost", "KI",
                "kroxylicious.io", null, null, "US");
        Path clientTrustStore = tempDir.resolve("client.truststore.p12");
        downstreamCertificateGenerator.generateTrustStore(downstreamCertificateGenerator.getCertFilePath(), "client",
                clientTrustStore.toString());

        KeytoolCertificateGenerator clientCertificateGenerator = new KeytoolCertificateGenerator();
        clientCertificateGenerator.generateSelfSignedCertificateEntry("clientTest@kroxylicious.io", "client", "Dev",
                "kroxylicious.io", null, null, "US");
        Path proxyTrustStore = tempDir.resolve("proxy.truststore.p12");
        clientCertificateGenerator.generateTrustStore(clientCertificateGenerator.getCertFilePath(), "proxy",
                proxyTrustStore.toString());

        Stores stores = stores(List.of(), List.of(new Credential("client", "svc-mtls", "svc-mtls-password-123")));
        var initiation = subjectInitiationDefinition("sasl-initiation", "SCRAM-SHA-512",
                stores.initiationStore(), stores.initiationPassword());
        var observer = CompositionObserverFilter.definition("composition-observer");

        var subjectBuilder = new TransportSubjectBuilderDefinitionBuilder("DefaultTransportSubjectBuilderService")
                .withConfig(Map.of("addPrincipals", List.of(Map.of(
                        "from", "clientTlsSanDnsName",
                        "principalFactory", UserFactory.class.getName()))))
                .build();

        Map<String, Object> brokerClientConfiguration = cluster.getKafkaClientConfiguration();
        var config = baseConfigurationBuilder()
                .addToFilterDefinitions(initiation, observer)
                .addToDefaultFilters(initiation.name(), observer.name())
                .addNewClusterDefinition()
                .withName(DEFAULT_CLUSTER_DEF_NAME)
                .withBootstrapServers(cluster.getBootstrapServers())
                .withNewTls()
                .withNewTrustStoreTrust()
                .withStoreFile((String) brokerClientConfiguration.get(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG))
                .withNewInlinePasswordStoreProvider((String) brokerClientConfiguration.get(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG))
                .endTrustStoreTrust()
                .endTls()
                .endClusterDefinition()
                .addNewVirtualCluster()
                .withName("demo")
                .withTarget(DEFAULT_CLUSTER_TARGET)
                .withSubjectBuilder(subjectBuilder)
                .addToGateways(defaultPortIdentifiesNodeGatewayBuilder(OS_ASSIGNED_BOOTSTRAP)
                        .withNewTls()
                        .withNewKeyStoreKey()
                        .withStoreFile(downstreamCertificateGenerator.getKeyStoreLocation())
                        .withNewInlinePasswordStoreProvider(downstreamCertificateGenerator.getPassword())
                        .endKeyStoreKey()
                        .withNewTrustStoreTrust()
                        .withNewServerOptionsTrust()
                        .withClientAuth(TlsClientAuth.REQUIRED)
                        .endServerOptionsTrust()
                        .withStoreFile(proxyTrustStore.toString())
                        .withNewInlinePasswordStoreProvider(clientCertificateGenerator.getPassword())
                        .endTrustStoreTrust()
                        .endTls()
                        .build())
                .endVirtualCluster();

        Map<String, Object> clientConfiguration = Map.of(
                SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, clientCertificateGenerator.getKeyStoreLocation(),
                SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, clientCertificateGenerator.getPassword(),
                SslConfigs.SSL_KEY_PASSWORD_CONFIG, clientCertificateGenerator.getPassword());

        try (var tester = newBuilder(config)
                .setTrustStoreLocation(clientTrustStore.toString())
                .setTrustStorePassword(downstreamCertificateGenerator.getPassword())
                .createDefaultKroxyliciousTester()) {
            assertProduceAndConsume(tester, topic,
                    clientConfiguration,
                    "composition-mtls",
                    "Subject[principals=[User[name=client]]]",
                    "SCRAM-SHA-512",
                    "svc-mtls");
        }
    }

    @Test
    void shouldComposeAnAnonymousClientWithAFixedUpstreamIdentity(
                                                                  @SaslMechanism(value = "SCRAM-SHA-256", principals = {
                                                                          @SaslMechanism.Principal(user = "svc-anonymous", password = "svc-anonymous-password-123") }) KafkaCluster cluster,
                                                                  Topic topic)
            throws Exception {
        Stores stores = stores(List.of(),
                List.of(new Credential("proxy-service", "svc-anonymous", "svc-anonymous-password-123")));
        var initiation = fixedInitiationDefinition("sasl-initiation", "SCRAM-SHA-256", "proxy-service",
                stores.initiationStore(), stores.initiationPassword());
        var observer = CompositionObserverFilter.definition("composition-observer");

        var config = proxy(cluster)
                .addToFilterDefinitions(initiation, observer)
                .addToDefaultFilters(initiation.name(), observer.name());

        try (var tester = kroxyliciousTester(config)) {
            assertProduceAndConsume(tester, topic,
                    Map.of(CommonClientConfigs.CLIENT_ID_CONFIG, "composition-anonymous-client"),
                    "composition-anonymous",
                    ANONYMOUS_SUBJECT,
                    "SCRAM-SHA-256",
                    "svc-anonymous");
        }
    }

    @Test
    void shouldFailGenericallyWhenAnAnonymousClientUsesSubjectMode(
                                                                   @SaslMechanism(value = "PLAIN", principals = {
                                                                           @SaslMechanism.Principal(user = "svc-alice", password = "svc-alice-password-123") }) KafkaCluster cluster)
            throws Exception {
        Stores stores = stores(List.of(), List.of(new Credential(ALICE, "svc-alice", "svc-alice-password-123")));
        var initiation = subjectInitiationDefinition("sasl-initiation", "PLAIN",
                stores.initiationStore(), stores.initiationPassword());

        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var tester = kroxyliciousTester(config)) {
            assertAnonymousSubjectModeFailsGenerically(tester);
        }
    }

    private Stores stores(List<Credential> terminationCredentials, List<Credential> initiationCredentials) throws Exception {
        Path terminationStore = tempDir.resolve("termination-credentials.p12");
        Path terminationPassword = writePasswordFile(tempDir.resolve("termination-credentials.password"), TERMINATION_STORE_PASSWORD);
        if (!terminationCredentials.isEmpty()) {
            writeTerminationStore(terminationStore, terminationCredentials.toArray(Credential[]::new));
        }

        Path initiationStore = tempDir.resolve("initiation-credentials.p12");
        Path initiationPassword = writePasswordFile(tempDir.resolve("initiation-credentials.password"), INITIATION_STORE_PASSWORD);
        writeInitiationStore(initiationStore, initiationCredentials.toArray(Credential[]::new));

        if (!terminationCredentials.isEmpty()) {
            assertThat(terminationStore).exists();
            assertThat(initiationStore).exists();
            assertThat(terminationStore).isNotEqualTo(initiationStore);
            assertThat(TERMINATION_STORE_PASSWORD).isNotEqualTo(INITIATION_STORE_PASSWORD);
        }
        return new Stores(terminationStore, terminationPassword, initiationStore, initiationPassword);
    }

    private record Stores(Path terminationStore, Path terminationPassword, Path initiationStore, Path initiationPassword) {}
}
