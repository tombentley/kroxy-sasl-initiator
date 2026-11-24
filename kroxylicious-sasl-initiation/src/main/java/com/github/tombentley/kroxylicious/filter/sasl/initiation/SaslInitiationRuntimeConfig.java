/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Objects;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelector;

/**
 * Immutable initialization data produced once per virtual cluster by {@link SaslInitiation#initialize}.
 * <p>
 * It contains the validated configuration, the loaded credential store and the identity selector. The store is loaded
 * and validated during initialization so configuration errors fail at startup rather than on the first client
 * connection.
 * </p>
 *
 * @param config the validated plugin configuration
 * @param credentialStore the loaded credential store
 * @param identitySelector the selector that maps a request to a credential lookup key
 * @param credentialResolver the resolver that maps a lookup key to a validated stored credential
 */
public record SaslInitiationRuntimeConfig(
                                          SaslInitiationConfig config,
                                          KeyStoreCredentialStore credentialStore,
                                          IdentitySelector identitySelector,
                                          CredentialResolver credentialResolver) {

    /**
     * Creates a runtime configuration using a resolver backed by the supplied store.
     *
     * @param config the validated plugin configuration
     * @param credentialStore the loaded credential store
     * @param identitySelector the identity selector
     */
    public SaslInitiationRuntimeConfig(SaslInitiationConfig config,
                                       KeyStoreCredentialStore credentialStore,
                                       IdentitySelector identitySelector) {
        this(config, credentialStore, identitySelector, new CredentialResolver(credentialStore));
    }

    /**
     * Validates the runtime configuration.
     */
    public SaslInitiationRuntimeConfig {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(credentialStore, "credentialStore");
        Objects.requireNonNull(identitySelector, "identitySelector");
        Objects.requireNonNull(credentialResolver, "credentialResolver");
    }
}
