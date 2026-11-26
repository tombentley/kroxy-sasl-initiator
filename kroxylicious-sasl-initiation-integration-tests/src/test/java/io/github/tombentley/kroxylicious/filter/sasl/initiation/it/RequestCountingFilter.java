/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.RequestCountingFilter.Config;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
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
 * A test-only filter that counts business requests dispatched into the downstream end of a filter chain.
 * <p>
 * It sits before {@code SaslInitiation} and increments a shared counter whenever a non-{@code ApiVersions} request
 * reaches the chain. Because the runtime invokes filters one request at a time on a connection, a bounded count while
 * authentication is deferred proves that the filter chain is not accumulating a per-connection request backlog.
 * </p>
 * <p>
 * <strong>This filter is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class RequestCountingFilter implements FilterFactory<Config, Config> {

    private static final Map<String, AtomicInteger> COUNTERS = new ConcurrentHashMap<>();

    /**
     * Configuration for the test filter.
     *
     * @param name the counter name
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
     * Creates a named filter definition for this counter.
     *
     * @param name the filter definition name
     * @param counterName the counter name
     * @return the filter definition
     */
    public static NamedFilterDefinition definition(String name, String counterName) {
        return new NamedFilterDefinitionBuilder(name, RequestCountingFilter.class.getName())
                .withConfig(Map.of("name", counterName))
                .build();
    }

    /**
     * Registers and clears a counter for a test.
     *
     * @param name the counter name
     * @return the counter
     */
    public static AtomicInteger register(String name) {
        AtomicInteger counter = new AtomicInteger();
        COUNTERS.put(name, counter);
        return counter;
    }

    /**
     * Returns the counter registered for a test.
     *
     * @param name the counter name
     * @return the counter
     */
    public static AtomicInteger counter(String name) {
        AtomicInteger counter = COUNTERS.get(name);
        if (counter == null) {
            throw new IllegalStateException("No counter registered for " + name);
        }
        return counter;
    }

    /**
     * Removes a counter registered by a test.
     *
     * @param name the counter name
     */
    public static void unregister(String name) {
        COUNTERS.remove(name);
    }

    /**
     * Default constructor used by the runtime.
     */
    public RequestCountingFilter() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(FilterFactoryContext context, Config config) throws PluginConfigurationException {
        return Objects.requireNonNull(config, "config");
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Config config) {
        return new CountingFilter(config.name());
    }

    private static final class CountingFilter implements RequestFilter {

        private final String name;

        private CountingFilter(String name) {
            this.name = name;
        }

        @Override
        public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                              short apiVersion,
                                                              RequestHeaderData header,
                                                              ApiMessage request,
                                                              FilterContext context) {
            if (apiKey != ApiKeys.API_VERSIONS) {
                counter(name).incrementAndGet();
            }
            return context.forwardRequest(header, request);
        }
    }
}
