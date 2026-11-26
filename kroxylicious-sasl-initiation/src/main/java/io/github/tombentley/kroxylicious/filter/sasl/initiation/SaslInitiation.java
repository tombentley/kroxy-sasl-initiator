/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.FixedIdentitySelector;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelector;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.SubjectIdentitySelector;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.oauth.OAuthTokenService;

import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterDispatchExecutor;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import io.kroxylicious.proxy.plugin.Plugins;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A {@link FilterFactory} for the {@link SaslInitiationFilter}.
 * <p>
 * Initialization validates the full configuration, loads and validates the PKCS12 credential store, checks that a
 * fixed identity key exists, builds the identity selector and, for OAUTHBEARER, creates the shared token service.
 * Failures therefore happen at startup, before any client connection. Each connection gets its own filter instance and
 * SASL exchange state.
 * </p>
 */
@Plugin(configType = SaslInitiationConfig.class)
public class SaslInitiation implements FilterFactory<SaslInitiationConfig, SaslInitiationRuntimeConfig> {

    /**
     * Default constructor used by the runtime.
     */
    public SaslInitiation() {
        // Intentionally empty.
    }

    @Override
    public SaslInitiationRuntimeConfig initialize(FilterFactoryContext context, SaslInitiationConfig config) {
        SaslInitiationConfig validated = Plugins.requireConfig(this, config);
        KeyStoreCredentialStore credentialStore = null;
        OAuthTokenService oauthTokenService = null;
        try {
            boolean oauthBearerMechanism = validated.mechanism() == Mechanism.OAUTHBEARER;
            boolean fixedFileToken = oauthBearerMechanism
                    && validated.identity().mode() == IdentityMode.FIXED
                    && validated.oauthBearer().isFileTokenEndpoint();
            if (!fixedFileToken) {
                CredentialKind credentialKind = validated.mechanism().credentialKind();
                credentialStore = KeyStoreCredentialStore.load(
                        Path.of(validated.keyStore().file()),
                        validated.keyStore().filePassword(),
                        credentialKind);
            }

            IdentitySelector identitySelector = buildIdentitySelector(validated);
            CredentialResolver credentialResolver = credentialStore == null
                    ? CredentialResolver.empty()
                    : new CredentialResolver(credentialStore);
            if (validated.identity().mode() == IdentityMode.FIXED && credentialStore != null) {
                // Fail at startup, not when the first client arrives, if the fixed key is not in the store.
                credentialStore.require(validated.identity().key());
            }
            if (oauthBearerMechanism) {
                oauthTokenService = new OAuthTokenService(
                        validated.oauthBearer(), validated.identity().mode(), credentialStore);
            }
            return new SaslInitiationRuntimeConfig(
                    validated, credentialStore, identitySelector, credentialResolver, oauthTokenService);
        }
        catch (RuntimeException e) {
            if (oauthTokenService != null) {
                oauthTokenService.close();
            }
            if (credentialStore != null) {
                credentialStore.close();
            }
            throw configurationException(e);
        }
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, SaslInitiationRuntimeConfig configuration) {
        SaslInitiationRuntimeConfig validated = Plugins.requireConfig(this, configuration);
        FilterDispatchExecutor filterDispatchExecutor = context == null ? null : context.filterDispatchExecutor();
        return new SaslInitiationFilter(validated, filterDispatchExecutor);
    }

    @Override
    public void close(@NonNull SaslInitiationRuntimeConfig initializationData) {
        if (initializationData.oauthTokenService() != null) {
            initializationData.oauthTokenService().close();
        }
        if (initializationData.credentialStore() != null) {
            initializationData.credentialStore().close();
        }
    }

    private static IdentitySelector buildIdentitySelector(SaslInitiationConfig config) {
        return switch (config.identity().mode()) {
            case FIXED -> new FixedIdentitySelector(config.identity().key());
            case SUBJECT -> new SubjectIdentitySelector(config.identity().principalClass());
        };
    }

    private static PluginConfigurationException configurationException(RuntimeException e) {
        if (e instanceof PluginConfigurationException pluginConfigurationException) {
            return pluginConfigurationException;
        }
        String detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        return new PluginConfigurationException("Invalid SaslInitiation configuration: " + detail, e);
    }
}
