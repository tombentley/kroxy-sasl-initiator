/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

/**
 * The explicit state machine of a single upstream connection's SASL initiation exchange.
 * <p>
 * The state is always changed on the connection's filter-dispatch thread. A filter instance is per connection, so no
 * state is shared between clients.
 * </p>
 */
public enum SaslExchangeState {

    /**
     * No client request that requires upstream authentication has been seen yet.
     */
    AWAITING_TRIGGER,

    /**
     * The filter is running its internal ApiVersions/SaslHandshake/SaslAuthenticate exchange.
     */
    AUTHENTICATING,

    /**
     * The proxy has successfully authenticated to the upstream broker.
     */
    AUTHENTICATED,

    /**
     * Authentication failed or a client attempted to pass a SASL frame through the proxy. The connection must close.
     */
    FAILED
}
