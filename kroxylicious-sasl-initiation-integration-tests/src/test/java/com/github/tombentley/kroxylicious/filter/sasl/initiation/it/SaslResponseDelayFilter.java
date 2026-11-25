/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.it.SaslResponseDelayFilter.Config;

import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateResponseData;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.FilterDispatchExecutor;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.ResponseFilterResult;
import io.kroxylicious.proxy.filter.SaslAuthenticateResponseFilter;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;

/**
 * A test-only filter that holds one upstream {@code SaslAuthenticate} response until the test releases it.
 * <p>
 * It is placed downstream of {@code SaslInitiation}, closest to the broker, so the initiator sees the broker's SASL
 * exchange as slow. The test can then pipeline client requests while authentication or reauthentication is in
 * progress and verify ordering and boundedness without relying on a real broker's timing.
 * </p>
 * <p>
 * <strong>This filter is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class SaslResponseDelayFilter implements FilterFactory<Config, Config> {

    private static final Map<String, Gate> GATES = new ConcurrentHashMap<>();

    /**
     * Configuration for the test filter.
     *
     * @param name the name of the gate registered by the test
     * @param delayOrdinal the one-based ordinal of the {@code SaslAuthenticate} response to delay; zero disables delay
     */
    public record Config(String name, int delayOrdinal) {

        /**
         * Validates the configuration.
         */
        public Config {
            name = Objects.requireNonNull(name, "name");
            if (name.isBlank()) {
                throw new IllegalArgumentException("name must not be blank");
            }
            if (delayOrdinal < 0) {
                throw new IllegalArgumentException("delayOrdinal must not be negative");
            }
        }
    }

    /**
     * A gate that lets a test release a delayed {@code SaslAuthenticate} response.
     */
    public static final class Gate {

        private final CompletableFuture<Void> blocked = new CompletableFuture<>();
        private final CompletableFuture<Void> released = new CompletableFuture<>();

        private Gate() {
        }

        private void markBlocked() {
            blocked.complete(null);
        }

        /**
         * Waits until a response has reached the gate.
         *
         * @param timeout the maximum time to wait
         * @return {@code true} when a response was blocked, otherwise {@code false}
         * @throws InterruptedException if the thread is interrupted while waiting
         */
        public boolean awaitBlocked(Duration timeout) throws InterruptedException {
            try {
                blocked.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
                return true;
            }
            catch (java.util.concurrent.ExecutionException e) {
                return false;
            }
            catch (java.util.concurrent.TimeoutException e) {
                return false;
            }
        }

        /**
         * Releases the delayed response.
         */
        public void release() {
            released.complete(null);
        }

        private CompletionStage<Void> released() {
            return released;
        }
    }

    /**
     * Registers a gate for a test. Replace any stale gate with the same name.
     *
     * @param name the gate name
     * @return the gate
     */
    public static Gate register(String name) {
        Gate gate = new Gate();
        GATES.put(name, gate);
        return gate;
    }

    /**
     * Removes a gate registered by a test.
     *
     * @param name the gate name
     */
    public static void unregister(String name) {
        GATES.remove(name);
    }

    /**
     * Creates a named filter definition for this delay filter.
     *
     * @param name the filter definition name
     * @param gateName the gate name registered by the test
     * @param delayOrdinal the one-based ordinal of the response to delay
     * @return the filter definition
     */
    public static NamedFilterDefinition definition(String name, String gateName, int delayOrdinal) {
        return new NamedFilterDefinitionBuilder(name, SaslResponseDelayFilter.class.getName())
                .withConfig(Map.of(
                        "name", gateName,
                        "delayOrdinal", delayOrdinal))
                .build();
    }

    /**
     * Default constructor used by the runtime.
     */
    public SaslResponseDelayFilter() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(FilterFactoryContext context, Config config) throws PluginConfigurationException {
        return Objects.requireNonNull(config, "config");
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Config config) {
        return new DelayingFilter(config, context.filterDispatchExecutor());
    }

    private static final class DelayingFilter implements SaslAuthenticateResponseFilter {

        private final Config config;
        private final FilterDispatchExecutor executor;
        private final AtomicInteger authenticateResponses = new AtomicInteger();

        private DelayingFilter(Config config, FilterDispatchExecutor executor) {
            this.config = config;
            this.executor = executor;
        }

        @Override
        public CompletionStage<ResponseFilterResult> onSaslAuthenticateResponse(short apiVersion,
                                                                                ResponseHeaderData header,
                                                                                SaslAuthenticateResponseData response,
                                                                                FilterContext context) {
            Gate gate = GATES.get(config.name());
            if (gate == null || config.delayOrdinal() == 0
                    || authenticateResponses.incrementAndGet() != config.delayOrdinal()) {
                return context.forwardResponse(header, response);
            }
            gate.markBlocked();
            return executor.completeOnFilterDispatchThread(gate.released())
                    .thenCompose(ignored -> context.forwardResponse(header, response));
        }
    }
}
