/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.FanOutRouterFactory.Config;

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
 * A test-only router that fans one dynamically-routed API key out to every configured route and statically routes all
 * other API keys to the first route.
 * <p>
 * This is adapted from Kroxylicious's {@code FanOutRouterFactory} test plugin. The routing integration tests use it to
 * make a single client connection open an upstream connection to two leaf routes, so each route's own
 * {@code SaslInitiation} filter must authenticate independently.
 * </p>
 * <p>
 * <strong>This router is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class FanOutRouterFactory implements RouterFactory<Config, Config> {

    /**
     * Configuration for the fan-out router.
     *
     * @param routes the leaf routes to fan the dynamic API key out to, in order; the first route also handles every
     *            statically-routed API key
     * @param dynamicApiKey the name of the {@link ApiKeys} constant that is fanned out
     */
    public record Config(List<String> routes, String dynamicApiKey) {

        /**
         * Validates the configuration.
         */
        public Config {
            routes = List.copyOf(Objects.requireNonNull(routes, "routes"));
            if (routes.isEmpty()) {
                throw new IllegalArgumentException("routes must not be empty");
            }
            for (String route : routes) {
                if (route == null || route.isBlank()) {
                    throw new IllegalArgumentException("routes must not contain a null or blank name");
                }
            }
            dynamicApiKey = Objects.requireNonNull(dynamicApiKey, "dynamicApiKey");
            try {
                ApiKeys.valueOf(dynamicApiKey);
            }
            catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("dynamicApiKey is not a Kafka API key: " + dynamicApiKey, e);
            }
        }
    }

    /**
     * Default constructor used by the runtime.
     */
    public FanOutRouterFactory() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(RouterFactoryContext context, Config config) {
        // Several routes in the routing tests intentionally point at the same Kafka cluster.
        context.allowSharedClusterTargets();
        return config;
    }

    @Override
    public Router createRouter(RouterFactoryContext context, Config config) {
        ApiKeys dynamicApiKey = ApiKeys.valueOf(config.dynamicApiKey());
        String defaultRoute = config.routes().getFirst();
        Map<ApiKeys, String> staticRoutes = Arrays.stream(ApiKeys.values())
                .filter(apiKey -> apiKey != dynamicApiKey)
                .collect(Collectors.toUnmodifiableMap(apiKey -> apiKey, apiKey -> defaultRoute));

        return new Router() {
            @Override
            public CompletionStage<RouterResponse> onRequest(ApiKeys apiKey,
                                                             short apiVersion,
                                                             RequestHeaderData header,
                                                             ApiMessage request,
                                                             RouterContext routerContext) {
                List<CompletableFuture<ApiMessage>> stages = config.routes().stream()
                        .map(route -> routerContext.sendRequest(
                                routerContext.anyNode(route),
                                header.duplicate(),
                                (ApiMessage) request.duplicate())
                                .toCompletableFuture())
                        .toList();
                return CompletableFuture.allOf(stages.toArray(new CompletableFuture[0]))
                        .thenCompose(ignored -> routerContext.respondWith(stages.getFirst().getNow(null)).completed());
            }

            @Override
            public Map<ApiKeys, String> staticRoutes() {
                return staticRoutes;
            }
        };
    }
}
