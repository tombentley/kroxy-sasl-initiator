/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.FixedIdentitySelector;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelector;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.SubjectIdentitySelector;

import io.kroxylicious.proxy.filter.Filter;
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
 * fixed identity key exists, and builds the identity selector. Failures therefore happen at startup, before any client
 * connection. Each connection gets its own filter instance and SASL exchange state.
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
        final KeyStoreCredentialStore credentialStore;
        try {
            CredentialKind credentialKind = validated.mechanism().credentialKind();
            credentialStore = KeyStoreCredentialStore.load(
                    Path.of(validated.keyStore().file()),
                    validated.keyStore().filePassword(),
                    credentialKind);
        }
        catch (RuntimeException e) {
            throw configurationException(e);
        }

        try {
            IdentitySelector identitySelector = buildIdentitySelector(validated);
            if (validated.identity().mode() == IdentityMode.FIXED) {
                // Fail at startup, not when the first client arrives, if the fixed key is not in the store.
                credentialStore.require(validated.identity().key());
            }
            return new SaslInitiationRuntimeConfig(validated, credentialStore, identitySelector);
        }
        catch (RuntimeException e) {
            credentialStore.close();
            throw configurationException(e);
        }
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, SaslInitiationRuntimeConfig configuration) {
        SaslInitiationRuntimeConfig validated = Plugins.requireConfig(this, configuration);
        return new SaslInitiationFilter(validated);
    }

    @Override
    public void close(@NonNull SaslInitiationRuntimeConfig initializationData) {
        initializationData.credentialStore().close();
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
