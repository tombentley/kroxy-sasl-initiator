/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.Serdes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.RouteInitiationObserverFilter.ConnectionObservation;

import io.kroxylicious.proxy.config.ClusterDefinition;
import io.kroxylicious.proxy.config.ConfigurationBuilder;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.proxy.config.RouteDefinition;
import io.kroxylicious.proxy.config.RouteTarget;
import io.kroxylicious.proxy.config.RouterDefinition;
import io.kroxylicious.proxy.config.VirtualClusterBuilder;
import io.kroxylicious.proxy.internal.config.Feature;
import io.kroxylicious.proxy.internal.config.Features;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousTester;
import io.kroxylicious.testing.integration.tester.KroxyliciousTesters;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.INITIATION_STORE_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.fixedInitiationDefinition;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.baseConfigurationBuilder;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.defaultPortIdentifiesNodeGatewayBuilder;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real-Kafka integration tests for per-route {@code SaslInitiation} placement.
 * <p>
 * Under routing, the initiator belongs on each leaf route's filter chain, closest to that route's upstream cluster. A
 * client connection can fan out to several routes; each route then has its own filter definition, KeyStore, filter
 * instance and upstream SASL state. The downstream client subject remains visible to route filters and is never changed
 * by initiation.
 * </p>
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationRoutingIT {

    private static final Features ROUTING_ENABLED = Features.builder().enable(Feature.ROUTING).build();
    private static final String VIRTUAL_CLUSTER = "demo";
    private static final String CLUSTER_A = "cluster-a";
    private static final String CLUSTER_B = "cluster-b";
    private static final String ROUTER = "fan-out-router";
    private static final String ROUTE_A = "route-a";
    private static final String ROUTE_B = "route-b";
    private static final String CLIENT_SUBJECT_NAME = "client-alice";
    private static final String CLIENT_SUBJECT = "Subject[principals=[User[name=" + CLIENT_SUBJECT_NAME + "]]]";
    private static final String ROUTE_A_KEY = "route-a-key";
    private static final String ROUTE_A_UPSTREAM = "upstream-route-a";
    private static final String ROUTE_A_PASSWORD = "upstream-route-a-password";
    private static final String ROUTE_B_KEY = "route-b-key";
    private static final String ROUTE_B_UPSTREAM = "upstream-route-b";
    private static final String ROUTE_B_PASSWORD = "upstream-route-b-password";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    @TempDir
    Path tempDir;

    @Test
    void shouldAuthenticateEachLeafRouteWithItsOwnCredentialsAndPreserveTheClientSubject(
                                                                                         @SaslMechanism(value = "PLAIN", principals = {
                                                                                                 @SaslMechanism.Principal(user = ROUTE_A_UPSTREAM, password = ROUTE_A_PASSWORD) }) KafkaCluster clusterA,
                                                                                         @SaslMechanism(value = "PLAIN", principals = {
                                                                                                 @SaslMechanism.Principal(user = ROUTE_B_UPSTREAM, password = ROUTE_B_PASSWORD) }) KafkaCluster clusterB)
            throws Exception {
        RouteInitiationObserverFilter.register(ROUTE_A);
        RouteInitiationObserverFilter.register(ROUTE_B);
        try {
            Path routeAStore = CompositionTestSupport.writeInitiationStore(
                    tempDir.resolve("route-a-initiation.p12"),
                    new CompositionTestSupport.Credential(ROUTE_A_KEY, ROUTE_A_UPSTREAM, ROUTE_A_PASSWORD));
            Path routeAStorePassword = CompositionTestSupport.writePasswordFile(
                    tempDir.resolve("route-a-initiation.password"), INITIATION_STORE_PASSWORD);
            Path routeBStore = CompositionTestSupport.writeInitiationStore(
                    tempDir.resolve("route-b-initiation.p12"),
                    new CompositionTestSupport.Credential(ROUTE_B_KEY, ROUTE_B_UPSTREAM, ROUTE_B_PASSWORD));
            Path routeBStorePassword = CompositionTestSupport.writePasswordFile(
                    tempDir.resolve("route-b-initiation.password"), INITIATION_STORE_PASSWORD);

            var initiationA = fixedInitiationDefinition("sasl-initiation-route-a", "PLAIN", ROUTE_A_KEY,
                    routeAStore, routeAStorePassword);
            var initiationB = fixedInitiationDefinition("sasl-initiation-route-b", "PLAIN", ROUTE_B_KEY,
                    routeBStore, routeBStorePassword);
            var observerA = RouteInitiationObserverFilter.definition("route-observer-a", ROUTE_A);
            var observerB = RouteInitiationObserverFilter.definition("route-observer-b", ROUTE_B);
            var fixedSubject = new NamedFilterDefinitionBuilder("fixed-subject", FixedSubjectFilter.class.getName())
                    .withConfig(Map.of("subject", CLIENT_SUBJECT_NAME))
                    .build();

            var config = routingConfiguration(clusterA, clusterB,
                    List.of(fixedSubject, initiationA, observerA, initiationB, observerB),
                    List.of(routeA(initiationA, observerA), routeB(initiationB, observerB)),
                    List.of(fixedSubject.name()));
            String topicName = "sasl-initiation-routing-" + UUID.randomUUID();

            try (var tester = routingTester(config);
                    var admin = tester.admin();
                    var producer = tester.producer();
                    var consumer = tester.consumer(Serdes.String(), Serdes.String(), Map.of(
                            ConsumerConfig.GROUP_ID_CONFIG, "sasl-initiation-routing-group",
                            ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest"))) {
                admin.createTopics(List.of(new NewTopic(topicName, 1, (short) 1)))
                        .all()
                        .get(10, TimeUnit.SECONDS);

                assertThat(producer.send(new ProducerRecord<>(topicName, "key", "value")))
                        .succeedsWithin(TIMEOUT);

                consumer.subscribe(List.of(topicName));

                assertThat(consumer.poll(TIMEOUT).records(topicName))
                        .singleElement()
                        .extracting(ConsumerRecord::key, ConsumerRecord::value)
                        .containsExactly("key", "value");
            }

            // A client connection has a route filter instance for every route, even if that connection never routes
            // traffic down a particular route. Only connections that actually sent a non-ApiVersions request down the
            // route can have authenticated that route's upstream.
            List<ConnectionObservation> observationsA = routedConnections(RouteInitiationObserverFilter.observations(ROUTE_A));
            List<ConnectionObservation> observationsB = routedConnections(RouteInitiationObserverFilter.observations(ROUTE_B));

            assertRouteAuthenticated(observationsA, ROUTE_A_UPSTREAM);
            assertRouteAuthenticated(observationsB, ROUTE_B_UPSTREAM);

            Set<String> sessionsA = observationsA.stream()
                    .map(ConnectionObservation::sessionId)
                    .collect(Collectors.toSet());
            Set<String> sessionsB = observationsB.stream()
                    .map(ConnectionObservation::sessionId)
                    .collect(Collectors.toSet());
            Set<String> sharedSessions = new HashSet<>(sessionsA);
            sharedSessions.retainAll(sessionsB);
            assertThat(sharedSessions).isNotEmpty();

            Set<Integer> instancesA = observationsA.stream()
                    .map(ConnectionObservation::instanceId)
                    .collect(Collectors.toSet());
            Set<Integer> instancesB = observationsB.stream()
                    .map(ConnectionObservation::instanceId)
                    .collect(Collectors.toSet());
            assertThat(instancesA).doesNotContainAnyElementsOf(instancesB);
        }
        finally {
            RouteInitiationObserverFilter.unregister(ROUTE_A);
            RouteInitiationObserverFilter.unregister(ROUTE_B);
        }
    }

    /**
     * A virtual-cluster-level initiator runs before the router selects a target.
     * <p>
     * This test documents why that placement is not supported: the initiator's own SASL frames are routed by the
     * router just like any other request, so only the route selected for those frames (the router's default/static
     * route) gets authenticated. A second leaf route used by the same client connection receives no SASL handshake at
     * all. The correct placement is a separate initiator on every leaf route, as exercised by the test above.
     * </p>
     * <p>
     * Route B uses a plaintext broker so the test can complete without relying on a broker-side SASL failure; the
     * assertion is about where the initiator's handshake goes, not about the second broker rejecting a request.
     * </p>
     */
    @Test
    void shouldShowThatAVirtualClusterLevelInitiatorDoesNotAuthenticateEveryLeafRoute(
                                                                                      @SaslMechanism(value = "PLAIN", principals = {
                                                                                              @SaslMechanism.Principal(user = ROUTE_A_UPSTREAM, password = ROUTE_A_PASSWORD) }) KafkaCluster clusterA,
                                                                                      KafkaCluster clusterB)
            throws Exception {
        RouteInitiationObserverFilter.register(ROUTE_A);
        RouteInitiationObserverFilter.register(ROUTE_B);
        try {
            Path store = CompositionTestSupport.writeInitiationStore(
                    tempDir.resolve("vc-initiation.p12"),
                    new CompositionTestSupport.Credential(ROUTE_A_KEY, ROUTE_A_UPSTREAM, ROUTE_A_PASSWORD));
            Path storePassword = CompositionTestSupport.writePasswordFile(
                    tempDir.resolve("vc-initiation.password"), INITIATION_STORE_PASSWORD);
            var virtualClusterInitiation = fixedInitiationDefinition("sasl-initiation-virtual-cluster", "PLAIN", ROUTE_A_KEY,
                    store, storePassword);
            var observerA = RouteInitiationObserverFilter.definition("route-observer-a", ROUTE_A);
            var observerB = RouteInitiationObserverFilter.definition("route-observer-b", ROUTE_B);

            var config = routingConfiguration(clusterA, clusterB,
                    List.of(virtualClusterInitiation, observerA, observerB),
                    List.of(routeA(observerA), routeB(observerB)),
                    List.of(virtualClusterInitiation.name()));
            String topicName = "sasl-initiation-virtual-cluster-routing-" + UUID.randomUUID();

            try (var tester = routingTester(config);
                    var admin = tester.admin();
                    var producer = tester.producer();
                    var consumer = tester.consumer(Serdes.String(), Serdes.String(), Map.of(
                            ConsumerConfig.GROUP_ID_CONFIG, "sasl-initiation-virtual-cluster-routing-group",
                            ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest"))) {
                admin.createTopics(List.of(new NewTopic(topicName, 1, (short) 1)))
                        .all()
                        .get(10, TimeUnit.SECONDS);

                assertThat(producer.send(new ProducerRecord<>(topicName, "key", "value")))
                        .succeedsWithin(TIMEOUT);

                consumer.subscribe(List.of(topicName));

                assertThat(consumer.poll(TIMEOUT).records(topicName))
                        .singleElement()
                        .extracting(ConsumerRecord::key, ConsumerRecord::value)
                        .containsExactly("key", "value");
            }

            List<ConnectionObservation> observationsA = routedConnections(RouteInitiationObserverFilter.observations(ROUTE_A));
            List<ConnectionObservation> observationsB = routedConnections(RouteInitiationObserverFilter.observations(ROUTE_B));

            assertThat(observationsA)
                    .isNotEmpty()
                    .allSatisfy(observation -> {
                        assertThat(observation.handshakes()).isEqualTo(1);
                        assertThat(observation.authorizationId()).isEqualTo(ROUTE_A_UPSTREAM);
                    });
            assertThat(observationsB)
                    .isNotEmpty()
                    .allSatisfy(observation -> assertThat(observation.handshakes()).isZero());
        }
        finally {
            RouteInitiationObserverFilter.unregister(ROUTE_A);
            RouteInitiationObserverFilter.unregister(ROUTE_B);
        }
    }

    private static List<ConnectionObservation> routedConnections(List<ConnectionObservation> observations) {
        return observations.stream()
                .filter(observation -> !observation.subjects().isEmpty())
                .toList();
    }

    private static void assertRouteAuthenticated(List<ConnectionObservation> observations, String expectedUpstreamIdentity) {
        assertThat(observations)
                .isNotEmpty()
                .allSatisfy(observation -> {
                    assertThat(observation.handshakes()).isEqualTo(1);
                    assertThat(observation.authenticateRequests()).isPositive();
                    assertThat(observation.mechanism()).isEqualTo("PLAIN");
                    assertThat(observation.authorizationId()).isEqualTo(expectedUpstreamIdentity);
                    assertThat(observation.subjects()).containsExactly(CLIENT_SUBJECT);
                });
    }

    private static RouteDefinition routeA(NamedFilterDefinition... filters) {
        return route(ROUTE_A, 0, CLUSTER_A, filters);
    }

    private static RouteDefinition routeB(NamedFilterDefinition... filters) {
        return route(ROUTE_B, 1, CLUSTER_B, filters);
    }

    private static RouteDefinition route(String name, int id, String clusterName, NamedFilterDefinition... filters) {
        List<String> filterNames = java.util.Arrays.stream(filters).map(NamedFilterDefinition::name).toList();
        return new RouteDefinition(name, id, filterNames, new RouteTarget(clusterName, null));
    }

    private static ConfigurationBuilder routingConfiguration(KafkaCluster clusterA,
                                                             KafkaCluster clusterB,
                                                             List<NamedFilterDefinition> filterDefinitions,
                                                             List<RouteDefinition> routes,
                                                             List<String> virtualClusterFilters) {
        var clusterDefinitionA = new ClusterDefinition(CLUSTER_A, clusterA.getBootstrapServers(), null);
        var clusterDefinitionB = new ClusterDefinition(CLUSTER_B, clusterB.getBootstrapServers(), null);
        var routerConfig = new FanOutRouterFactory.Config(List.of(ROUTE_A, ROUTE_B), "METADATA");
        var routerDefinition = new RouterDefinition(ROUTER, FanOutRouterFactory.class.getName(), routerConfig, routes);
        var virtualCluster = new VirtualClusterBuilder()
                .withName(VIRTUAL_CLUSTER)
                .withTarget(new RouteTarget(null, ROUTER))
                .withFilters(virtualClusterFilters)
                .addToGateways(defaultPortIdentifiesNodeGatewayBuilder("localhost:0").build())
                .build();
        return baseConfigurationBuilder()
                .addToClusterDefinitions(clusterDefinitionA, clusterDefinitionB)
                .addAllToFilterDefinitions(filterDefinitions)
                .addToRouterDefinitions(routerDefinition)
                .addToVirtualClusters(virtualCluster);
    }

    private static KroxyliciousTester routingTester(ConfigurationBuilder config) {
        return KroxyliciousTesters.newBuilder(config)
                .setFeatures(ROUTING_ENABLED)
                .createDefaultKroxyliciousTester();
    }
}
