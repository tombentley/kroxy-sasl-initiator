/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.SubjectSwitcherFilter.Config;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
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
 * A test-only filter that publishes a downstream {@link Subject} and then, after a configured number of requests,
 * announces a different subject with {@link FilterContext#clientSaslAuthenticationSuccess(String, Subject)}.
 * <p>
 * It is used to prove that subject-mode {@code SaslInitiation} fails closed when the downstream subject changes after
 * upstream authentication, while fixed mode continues to use the shared identity. The switch is announced from the
 * downstream side of {@code SaslInitiation}, so the initiator sees the new subject on the same request.
 * </p>
 * <p>
 * <strong>This filter is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class SubjectSwitcherFilter implements FilterFactory<Config, Config> {

    /**
     * Configuration for the test filter.
     *
     * @param initialSubject the subject published on the first non-SASL request
     * @param subjectAfterSwitch the subject published after {@code requestsBeforeSwitch} non-SASL requests
     * @param requestsBeforeSwitch the number of non-SASL requests forwarded with the initial subject; must be at least
     *            one so that initial authentication has a subject
     * @param mechanism the client authentication mechanism name reported to the runtime
     */
    public record Config(String initialSubject, String subjectAfterSwitch, int requestsBeforeSwitch, String mechanism) {

        /**
         * Validates the configuration.
         */
        public Config {
            initialSubject = Objects.requireNonNull(initialSubject, "initialSubject");
            subjectAfterSwitch = Objects.requireNonNull(subjectAfterSwitch, "subjectAfterSwitch");
            if (initialSubject.isBlank()) {
                throw new IllegalArgumentException("initialSubject must not be blank");
            }
            if (subjectAfterSwitch.isBlank()) {
                throw new IllegalArgumentException("subjectAfterSwitch must not be blank");
            }
            if (requestsBeforeSwitch < 1) {
                throw new IllegalArgumentException("requestsBeforeSwitch must be at least 1");
            }
            if (mechanism == null || mechanism.isBlank()) {
                mechanism = "PLAIN";
            }
        }
    }

    /**
     * Creates a named filter definition for this switcher.
     *
     * @param name the filter definition name
     * @param initialSubject the initial subject
     * @param subjectAfterSwitch the subject to publish after the switch
     * @param requestsBeforeSwitch the number of requests to forward with the initial subject
     * @return the filter definition
     */
    public static NamedFilterDefinition definition(String name,
                                                   String initialSubject,
                                                   String subjectAfterSwitch,
                                                   int requestsBeforeSwitch) {
        return new NamedFilterDefinitionBuilder(name, SubjectSwitcherFilter.class.getName())
                .withConfig(Map.of(
                        "initialSubject", initialSubject,
                        "subjectAfterSwitch", subjectAfterSwitch,
                        "requestsBeforeSwitch", requestsBeforeSwitch))
                .build();
    }

    /**
     * Default constructor used by the runtime.
     */
    public SubjectSwitcherFilter() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(FilterFactoryContext context, Config config) throws PluginConfigurationException {
        return Objects.requireNonNull(config, "config");
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Config config) {
        return new SwitchingFilter(config);
    }

    private static final class SwitchingFilter implements RequestFilter {

        private final Config config;
        private int requestsWithInitialSubject;
        private boolean switched;

        private SwitchingFilter(Config config) {
            this.config = config;
        }

        @Override
        public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                              short apiVersion,
                                                              RequestHeaderData header,
                                                              ApiMessage request,
                                                              FilterContext context) {
            if (isBusinessRequest(apiKey)) {
                publishSubject(context);
            }
            return context.forwardRequest(header, request);
        }

        private void publishSubject(FilterContext context) {
            if (!switched && requestsWithInitialSubject < config.requestsBeforeSwitch()) {
                requestsWithInitialSubject++;
                context.clientSaslAuthenticationSuccess(config.mechanism(), subject(config.initialSubject()));
                return;
            }
            switched = true;
            context.clientSaslAuthenticationSuccess(config.mechanism(), subject(config.subjectAfterSwitch()));
        }

        private static boolean isBusinessRequest(ApiKeys apiKey) {
            return apiKey != ApiKeys.API_VERSIONS
                    && apiKey != ApiKeys.SASL_HANDSHAKE
                    && apiKey != ApiKeys.SASL_AUTHENTICATE;
        }

        private static Subject subject(String name) {
            return new Subject(new User(name));
        }
    }
}
