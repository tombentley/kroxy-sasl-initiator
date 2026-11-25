/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.it.RouteInitiationObserverFilter.Config;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateRequestData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilter;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;

/**
 * A test-only observer placed after {@code SaslInitiation} on a leaf route.
 * <p>
 * It records, per route filter instance, the upstream SASL mechanism and authorization id injected by
 * {@code SaslInitiation}, the number of handshakes, and the downstream client subject visible to the route. The test can
 * therefore prove that two routes authenticated independently and that the client subject was readable and unchanged.
 * </p>
 * <p>
 * <strong>This filter is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class RouteInitiationObserverFilter implements FilterFactory<Config, Config> {

    private static final Map<String, Recorder> RECORDERS = new ConcurrentHashMap<>();

    /**
     * Configuration for the observer.
     *
     * @param name the name of the recorder registered by the test
     */
    public record Config(String name) {

        /**
         * Validates the configuration.
         */
        public Config {
            name = Objects.requireNonNull(name, "name");
            if (name.isBlank()) {
                throw new IllegalArgumentException("name must not be blank");
            }
        }
    }

    /**
     * Registers a fresh recorder for a route.
     *
     * @param name the recorder name
     * @return the recorder
     */
    public static Recorder register(String name) {
        Recorder recorder = new Recorder();
        RECORDERS.put(name, recorder);
        return recorder;
    }

    /**
     * Removes a recorder registered by a test.
     *
     * @param name the recorder name
     */
    public static void unregister(String name) {
        RECORDERS.remove(name);
    }

    /**
     * Returns the observations recorded for a route.
     *
     * @param name the recorder name
     * @return the observed route connections
     */
    public static List<ConnectionObservation> observations(String name) {
        return recorder(name).observations();
    }

    /**
     * Creates a named filter definition for this observer.
     *
     * @param filterName the filter definition name
     * @param recorderName the recorder name registered by the test
     * @return the filter definition
     */
    public static NamedFilterDefinition definition(String filterName, String recorderName) {
        return new NamedFilterDefinitionBuilder(filterName, RouteInitiationObserverFilter.class.getName())
                .withConfig(Map.of("name", recorderName))
                .build();
    }

    private static Recorder recorder(String name) {
        Recorder recorder = RECORDERS.get(name);
        if (recorder == null) {
            throw new IllegalStateException("No route observer registered for " + name);
        }
        return recorder;
    }

    /**
     * Default constructor used by the runtime.
     */
    public RouteInitiationObserverFilter() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(FilterFactoryContext context, Config config) throws PluginConfigurationException {
        return Objects.requireNonNull(config, "config");
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Config config) {
        ConnectionObservation observation = new ConnectionObservation();
        recorder(config.name()).add(observation);
        return new ObservingFilter(observation);
    }

    /**
     * Holds all observations for one route in one test.
     */
    public static final class Recorder {

        private final List<ConnectionObservation> observations = new CopyOnWriteArrayList<>();

        private Recorder() {
        }

        private void add(ConnectionObservation observation) {
            observations.add(observation);
        }

        /**
         * Returns a snapshot of the observations.
         *
         * @return the observations
         */
        public List<ConnectionObservation> observations() {
            return List.copyOf(observations);
        }
    }

    /**
     * Records the upstream SASL exchange and downstream subject seen by one route filter instance.
     */
    public static final class ConnectionObservation {

        private final int instanceId = System.identityHashCode(this);
        private final AtomicInteger handshakes = new AtomicInteger();
        private final AtomicInteger authenticateRequests = new AtomicInteger();
        private final Set<String> subjects = ConcurrentHashMap.newKeySet();
        private volatile String sessionId = "";
        private volatile String mechanism = "";
        private volatile String authorizationId = "";

        private ConnectionObservation() {
        }

        /**
         * Returns an identity for this route filter instance.
         *
         * @return the instance identity
         */
        public int instanceId() {
            return instanceId;
        }

        /**
         * Returns the proxy session id of the downstream client connection.
         *
         * @return the session id, or an empty string before the first request
         */
        public String sessionId() {
            return sessionId;
        }

        /**
         * Returns the upstream SASL mechanism observed in the handshake.
         *
         * @return the mechanism, or an empty string before the handshake
         */
        public String mechanism() {
            return mechanism;
        }

        /**
         * Returns the upstream authorization id parsed from the SASL authenticate token.
         *
         * @return the authorization id, or an empty string before it is observed
         */
        public String authorizationId() {
            return authorizationId;
        }

        /**
         * Returns the number of upstream SASL handshakes observed by this route filter instance.
         *
         * @return the handshake count
         */
        public int handshakes() {
            return handshakes.get();
        }

        /**
         * Returns the number of upstream SASL authenticate requests observed by this route filter instance.
         *
         * @return the authenticate request count
         */
        public int authenticateRequests() {
            return authenticateRequests.get();
        }

        /**
         * Returns the downstream client subjects observed on non-ApiVersions requests.
         *
         * @return the observed subject strings
         */
        public Set<String> subjects() {
            return Set.copyOf(subjects);
        }
    }

    private static final class ObservingFilter implements RequestFilter {

        private final ConnectionObservation observation;

        private ObservingFilter(ConnectionObservation observation) {
            this.observation = observation;
        }

        @Override
        public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                              short apiVersion,
                                                              RequestHeaderData header,
                                                              ApiMessage request,
                                                              FilterContext context) {
            observation.sessionId = context.sessionId();
            if (apiKey != ApiKeys.API_VERSIONS) {
                observation.subjects.add(context.authenticatedSubject().toString());
            }
            switch (apiKey) {
                case SASL_HANDSHAKE -> {
                    observation.handshakes.incrementAndGet();
                    observation.mechanism = ((SaslHandshakeRequestData) request).mechanism();
                }
                case SASL_AUTHENTICATE -> {
                    observation.authenticateRequests.incrementAndGet();
                    String parsedAuthorizationId = plainAuthorizationId(((SaslAuthenticateRequestData) request).authBytes());
                    if (!parsedAuthorizationId.isEmpty()) {
                        observation.authorizationId = parsedAuthorizationId;
                    }
                }
                default -> {
                    // Nothing to observe.
                }
            }
            return context.forwardRequest(header, request);
        }

        private static String plainAuthorizationId(byte[] authBytes) {
            if (authBytes == null || authBytes.length == 0) {
                return "";
            }
            String[] parts = new String(authBytes, StandardCharsets.UTF_8).split("\u0000", -1);
            return parts.length > 1 ? parts[1] : "";
        }
    }
}
