/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Objects;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelector;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.oauth.OAuthTokenService;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Immutable initialization data produced once per virtual cluster by {@link SaslInitiation#initialize}.
 * <p>
 * It contains the validated configuration, the loaded credential store, the identity selector and, for OAUTHBEARER,
 * the shared token service. The store is loaded and validated during initialization so configuration errors fail at
 * startup rather than on the first client connection.
 * </p>
 *
 * @param config the validated plugin configuration
 * @param credentialStore the loaded credential store, or {@code null} for a fixed OAuth token file
 * @param identitySelector the selector that maps a request to a credential lookup key
 * @param credentialResolver the resolver that maps a lookup key to a validated stored credential
 * @param oauthTokenService the shared OAuth token service, or {@code null} for password mechanisms
 */
public record SaslInitiationRuntimeConfig(
                                          SaslInitiationConfig config,
                                          @Nullable KeyStoreCredentialStore credentialStore,
                                          IdentitySelector identitySelector,
                                          CredentialResolver credentialResolver,
                                          @Nullable OAuthTokenService oauthTokenService) {

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
        this(config, credentialStore, identitySelector, new CredentialResolver(credentialStore), null);
    }

    /**
     * Creates a runtime configuration without an OAuth token service.
     *
     * @param config the validated plugin configuration
     * @param credentialStore the loaded credential store
     * @param identitySelector the identity selector
     * @param credentialResolver the credential resolver
     */
    public SaslInitiationRuntimeConfig(SaslInitiationConfig config,
                                       KeyStoreCredentialStore credentialStore,
                                       IdentitySelector identitySelector,
                                       CredentialResolver credentialResolver) {
        this(config, credentialStore, identitySelector, credentialResolver, null);
    }

    /**
     * Validates the runtime configuration.
     */
    public SaslInitiationRuntimeConfig {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(identitySelector, "identitySelector");
        Objects.requireNonNull(credentialResolver, "credentialResolver");
    }
}
