/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.util.Objects;
import java.util.concurrent.CompletionStage;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.it.FixedSubjectFilter.Config;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilter;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;

/**
 * A test-only filter that announces a fixed downstream {@link Subject} before {@code SaslInitiation} runs.
 * <p>
 * It exists so subject-identity integration tests can exercise the filter against a real broker without depending on
 * client-side SASL termination (which is covered separately by the composition tests).
 * </p>
 */
@Plugin(configType = Config.class)
public class FixedSubjectFilter implements FilterFactory<Config, Config> {

    /**
     * Configuration for the test filter.
     *
     * @param subject the fixed subject name to publish
     * @param mechanism the client authentication mechanism name reported to the runtime
     */
    public record Config(String subject, String mechanism) {

        /**
         * Validates the configuration.
         */
        public Config {
            subject = Objects.requireNonNull(subject, "subject");
            if (subject.isBlank()) {
                throw new IllegalArgumentException("subject must not be blank");
            }
            if (mechanism == null || mechanism.isBlank()) {
                mechanism = "PLAIN";
            }
        }

        /**
         * Creates a configuration using the default mechanism name.
         *
         * @param subject the fixed subject name
         */
        public Config(String subject) {
            this(subject, "PLAIN");
        }
    }

    /**
     * Default constructor used by the runtime.
     */
    public FixedSubjectFilter() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(FilterFactoryContext context, Config config) throws PluginConfigurationException {
        return Objects.requireNonNull(config, "config");
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Config config) {
        return new SubjectPublishingFilter(config);
    }

    private static final class SubjectPublishingFilter implements RequestFilter {

        private final Config config;
        private boolean published;

        private SubjectPublishingFilter(Config config) {
            this.config = config;
        }

        @Override
        public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                              short apiVersion,
                                                              RequestHeaderData header,
                                                              ApiMessage request,
                                                              FilterContext context) {
            if (!published && apiKey != ApiKeys.API_VERSIONS
                    && apiKey != ApiKeys.SASL_HANDSHAKE
                    && apiKey != ApiKeys.SASL_AUTHENTICATE) {
                context.clientSaslAuthenticationSuccess(config.mechanism(), new Subject(new User(config.subject())));
                published = true;
            }
            return context.forwardRequest(header, request);
        }
    }
}
