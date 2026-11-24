/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Configuration for the {@code SaslInitiation} filter.
 * <p>
 * This bootstrap version only carries the SASL mechanism name. Credential, identity and reauthentication
 * configuration is added by later commits.
 *
 * @param mechanism the IANA SASL mechanism name to use when authenticating to the broker; must be non-empty
 */
public record SaslInitiationConfig(
                                   @JsonProperty(required = true) String mechanism) {

    /**
     * Validates the configuration.
     */
    public SaslInitiationConfig {
        if (mechanism == null || mechanism.isBlank()) {
            throw new IllegalArgumentException("mechanism must not be null or empty");
        }
    }
}
