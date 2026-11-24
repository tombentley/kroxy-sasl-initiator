/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.time.Duration;
import java.util.List;
import java.util.ServiceLoader;

import org.junit.jupiter.api.Test;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.kafka.common.message.ApiVersionsRequestData;
import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class SaslInitiationTest {

    private final SaslInitiation factory = new SaslInitiation();
    private final SaslInitiationConfig config = new SaslInitiationConfig("PLAIN");

    @Test
    void shouldBeDiscoverableByServiceLoader() {
        List<Class<? extends FilterFactory>> providers = ServiceLoader.load(FilterFactory.class)
                .stream()
                .map(ServiceLoader.Provider::type)
                .toList();

        assertThat(providers).contains(SaslInitiation.class);
    }

    @Test
    void shouldRejectNullOrBlankMechanism() {
        assertThatThrownBy(() -> new SaslInitiationConfig(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("mechanism");
        assertThatThrownBy(() -> new SaslInitiationConfig(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("mechanism");
        assertThatThrownBy(() -> new SaslInitiationConfig("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("mechanism");
    }

    @Test
    void shouldInitializeAndCreateFilter() {
        FilterFactoryContext context = mock(FilterFactoryContext.class);

        SaslInitiationConfig initialized = factory.initialize(context, config);
        Filter filter = factory.createFilter(context, initialized);

        assertThat(initialized).isSameAs(config);
        assertThat(filter).isInstanceOf(SaslInitiationFilter.class);
    }

    @Test
    void shouldForwardRequestUnchanged() {
        RequestHeaderData header = new RequestHeaderData();
        ApiVersionsRequestData request = new ApiVersionsRequestData();
        MockFilterContext context = MockFilterContext.builder(header, request).build();
        SaslInitiationFilter filter = new SaslInitiationFilter(config);

        assertThat(filter.onRequest(ApiKeys.API_VERSIONS, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasHeaderEqualTo(header)
                        .hasMessageEqualTo(request));
    }

    @Test
    void shouldForwardResponseUnchanged() {
        ResponseHeaderData header = new ResponseHeaderData();
        ApiVersionsResponseData response = new ApiVersionsResponseData();
        MockFilterContext context = MockFilterContext.builder(header, response).build();
        SaslInitiationFilter filter = new SaslInitiationFilter(config);

        assertThat(filter.onResponse(ApiKeys.API_VERSIONS, (short) 0, header, response, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardResponse()
                        .hasHeaderEqualTo(header)
                        .hasMessageEqualTo(response));
    }
}
