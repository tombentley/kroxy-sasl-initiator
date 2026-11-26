/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.PassThroughRouterFactory.Config;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.router.Router;
import io.kroxylicious.proxy.router.RouterContext;
import io.kroxylicious.proxy.router.RouterFactory;
import io.kroxylicious.proxy.router.RouterFactoryContext;
import io.kroxylicious.proxy.router.RouterResponse;

/**
 * A test-only router that statically forwards every request to a single named route.
 * <p>
 * This is adapted from Kroxylicious's {@code PassThroughRouterFactory} test plugin. It exists so routing integration
 * tests can exercise leaf-route filter chains without depending on a production router implementation.
 * </p>
 * <p>
 * <strong>This router is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class PassThroughRouterFactory implements RouterFactory<Config, Config> {

    /**
     * Configuration for the pass-through router.
     *
     * @param route the route to which every request is forwarded
     */
    public record Config(String route) {

        /**
         * Validates the configuration.
         */
        public Config {
            route = Objects.requireNonNull(route, "route");
            if (route.isBlank()) {
                throw new IllegalArgumentException("route must not be blank");
            }
        }
    }

    private Map<ApiKeys, String> staticRoutes;

    /**
     * Default constructor used by the runtime.
     */
    public PassThroughRouterFactory() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(RouterFactoryContext context, Config config) {
        // Several routes in the routing tests intentionally point at the same Kafka cluster.
        context.allowSharedClusterTargets();
        staticRoutes = Arrays.stream(ApiKeys.values())
                .collect(Collectors.toUnmodifiableMap(apiKey -> apiKey, apiKey -> config.route()));
        return config;
    }

    @Override
    public Router createRouter(RouterFactoryContext context, Config config) {
        return new Router() {
            @Override
            public CompletionStage<RouterResponse> onRequest(ApiKeys apiKey,
                                                             short apiVersion,
                                                             RequestHeaderData header,
                                                             ApiMessage request,
                                                             RouterContext routerContext) {
                throw new IllegalStateException("all RPCs should be statically routed, onRequest invoked unexpectedly");
            }

            @Override
            public Map<ApiKeys, String> staticRoutes() {
                return staticRoutes;
            }
        };
    }
}
