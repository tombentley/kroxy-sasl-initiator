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
 * The schema uses nested groups for identity, KeyStore, OAuth bearer and reauthentication settings. All secrets in
 * configuration are represented by {@link io.kroxylicious.proxy.config.secret.PasswordProvider}; broker passwords and
 * OAuth client secrets live in the KeyStore, never in this configuration.
 * </p>
 *
 * @param mechanism the SASL mechanism used to authenticate to the broker
 * @param identity how the credential lookup key is selected
 * @param keyStore the PKCS12 credential store; required except for fixed-identity OAUTHBEARER with a token file
 * @param oauthBearer the OAuth bearer settings; required exactly for {@link Mechanism#OAUTHBEARER}
 * @param reauth reauthentication timing; optional, defaulting to a window factor of 0.8
 */
public record SaslInitiationConfig(
                                   @JsonProperty(required = true) Mechanism mechanism,
                                   @JsonProperty(required = true) IdentityConfig identity,
                                   @Nullable KeyStoreConfig keyStore,
                                   @Nullable OAuthBearerConfig oauthBearer,
                                   @Nullable ReauthConfig reauth) {

    /**
     * Creates a configuration without OAuth settings and with the default reauthentication settings.
     *
     * @param mechanism the SASL mechanism
     * @param identity the identity configuration
     * @param keyStore the KeyStore configuration
     */
    public SaslInitiationConfig(Mechanism mechanism, IdentityConfig identity, KeyStoreConfig keyStore) {
        this(mechanism, identity, keyStore, null, null);
    }

    /**
     * Creates a configuration without OAuth settings.
     *
     * @param mechanism the SASL mechanism
     * @param identity the identity configuration
     * @param keyStore the KeyStore configuration
     * @param reauth the reauthentication configuration
     */
    public SaslInitiationConfig(Mechanism mechanism, IdentityConfig identity, KeyStoreConfig keyStore, ReauthConfig reauth) {
        this(mechanism, identity, keyStore, null, reauth);
    }

    /**
     * Creates a configuration with the default reauthentication settings.
     *
     * @param mechanism the SASL mechanism
     * @param identity the identity configuration
     * @param keyStore the KeyStore configuration, or {@code null} for a fixed OAuth token file
     * @param oauthBearer the OAuth bearer configuration
     */
    public SaslInitiationConfig(Mechanism mechanism,
                                IdentityConfig identity,
                                @Nullable KeyStoreConfig keyStore,
                                OAuthBearerConfig oauthBearer) {
        this(mechanism, identity, keyStore, oauthBearer, null);
    }

    /**
     * Validates the configuration, including combinations of fields that are only meaningful together.
     */
    public SaslInitiationConfig {
        if (mechanism == null) {
            throw new IllegalArgumentException(
                    "mechanism is required and must be one of PLAIN, SCRAM-SHA-256, SCRAM-SHA-512 or OAUTHBEARER");
        }
        if (identity == null) {
            throw new IllegalArgumentException("identity is required and must contain a mode");
        }

        boolean oauthBearerMechanism = mechanism == Mechanism.OAUTHBEARER;
        if (oauthBearerMechanism && oauthBearer == null) {
            throw new IllegalArgumentException(
                    "oauthBearer is required for mechanism OAUTHBEARER; configure oauthBearer.tokenEndpointUrl");
        }
        if (!oauthBearerMechanism && oauthBearer != null) {
            throw new IllegalArgumentException(
                    "oauthBearer is only valid for mechanism OAUTHBEARER; remove it or change the configured mechanism");
        }

        boolean fixedFileToken = oauthBearerMechanism
                && identity.mode() == IdentityMode.FIXED
                && oauthBearer.isFileTokenEndpoint();
        if (oauthBearerMechanism && identity.mode() == IdentityMode.SUBJECT && oauthBearer.isFileTokenEndpoint()) {
            throw new IllegalArgumentException(
                    "oauthBearer.tokenEndpointUrl must be an HTTP(S) token endpoint in subject mode; token files are only "
                            + "valid with a fixed identity");
        }
        if (fixedFileToken) {
            if (keyStore != null) {
                throw new IllegalArgumentException(
                        "keyStore is not used for fixed-identity OAUTHBEARER with a file token endpoint; remove keyStore");
            }
        }
        else if (keyStore == null) {
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
                        "identity.key is required in fixed mode; set identity.key to the credential lookup key");
            }
        }
    }
}
