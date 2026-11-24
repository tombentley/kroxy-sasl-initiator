/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;

/**
 * Builds headers for requests the filter sends to the broker.
 * <p>
 * The client ID is fixed and deliberately not configurable. Filter-originated requests should be recognisable as proxy
 * activity rather than masquerading as the downstream client.
 * </p>
 */
final class RequestHeaderFactory {

    /**
     * The client ID used for all filter-originated requests.
     */
    static final String CLIENT_ID = "kroxylicious-sasl-initiation";

    private RequestHeaderFactory() {
    }

    /**
     * Creates a request header for a filter-originated request.
     *
     * @param apiKey the request API key
     * @param apiVersion the request API version
     * @return the request header
     */
    static RequestHeaderData forRequest(ApiKeys apiKey, short apiVersion) {
        return new RequestHeaderData()
                .setRequestApiKey(apiKey.id)
                .setRequestApiVersion(apiVersion)
                .setClientId(CLIENT_ID);
    }
}
