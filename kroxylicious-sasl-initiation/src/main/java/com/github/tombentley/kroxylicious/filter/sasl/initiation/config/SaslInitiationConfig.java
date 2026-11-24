/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import com.fasterxml.jackson.annotation.JsonProperty;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Configuration for the {@code SaslInitiation} filter.
 * <p>
 * The schema uses nested groups for identity, KeyStore and reauthentication settings. All secrets in configuration are
 * represented by {@link io.kroxylicious.proxy.config.secret.PasswordProvider}; broker passwords live in the KeyStore,
 * never in this configuration.
 * </p>
 *
 * @param mechanism the SASL mechanism used to authenticate to the broker
 * @param identity how the credential lookup key is selected
 * @param keyStore the PKCS12 credential store; required for all mechanisms supported by this commit
 * @param reauth reauthentication timing; optional, defaulting to a window factor of 0.8
 */
public record SaslInitiationConfig(
                                   @JsonProperty(required = true) Mechanism mechanism,
                                   @JsonProperty(required = true) IdentityConfig identity,
                                   @JsonProperty(required = true) KeyStoreConfig keyStore,
                                   @Nullable ReauthConfig reauth) {

    /**
     * Creates a configuration with the default reauthentication settings.
     *
     * @param mechanism the SASL mechanism
     * @param identity the identity configuration
     * @param keyStore the KeyStore configuration
     */
    public SaslInitiationConfig(Mechanism mechanism, IdentityConfig identity, KeyStoreConfig keyStore) {
        this(mechanism, identity, keyStore, null);
    }

    /**
     * Validates the configuration, including combinations of fields that are only meaningful together.
     */
    public SaslInitiationConfig {
        if (mechanism == null) {
            throw new IllegalArgumentException("mechanism is required and must be one of PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512");
        }
        if (identity == null) {
            throw new IllegalArgumentException("identity is required and must contain a mode");
        }
        if (keyStore == null) {
            throw new IllegalArgumentException(
                    "keyStore is required for mechanism " + mechanism.mechanismName()
                            + "; configure keyStore.file and keyStore.filePassword");
        }
        if (reauth == null) {
            reauth = new ReauthConfig();
        }
        if (identity.mode() == IdentityMode.FIXED) {
            if (identity.key() == null || identity.key().isBlank()) {
                throw new IllegalArgumentException(
                        "identity.key is required in fixed mode when a keyStore is configured; set identity.key to the "
                                + "credential lookup key");
            }
        }
    }
}
