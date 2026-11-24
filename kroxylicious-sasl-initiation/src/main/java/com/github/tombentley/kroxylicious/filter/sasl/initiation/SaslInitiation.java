/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.Plugins;

/**
 * A {@link FilterFactory} for the {@link SaslInitiationFilter}.
 * <p>
 * At this stage the filter is a pass-through placeholder. Later commits add credential storage, identity
 * selection and the Kafka SASL protocol state machine.
 */
@Plugin(configType = SaslInitiationConfig.class)
public class SaslInitiation implements FilterFactory<SaslInitiationConfig, SaslInitiationConfig> {

    /**
     * Default constructor used by the runtime.
     */
    public SaslInitiation() {
        // Intentionally empty.
    }

    @Override
    public SaslInitiationConfig initialize(FilterFactoryContext context, SaslInitiationConfig config) {
        return Plugins.requireConfig(this, config);
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, SaslInitiationConfig configuration) {
        return new SaslInitiationFilter(configuration);
    }
}
