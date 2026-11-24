/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Objects;
import java.util.concurrent.CompletionStage;

/**
 * The explicit state machine of a single upstream connection's SASL initiation exchange.
 * <p>
 * The state is always changed on the connection's filter-dispatch thread. A filter instance is per connection, so no
 * state is shared between clients.
 * </p>
 * <p>
 * Each state carries only the data that is meaningful while the connection is in that state. This makes it impossible
 * to observe, for example, a session lifetime before authentication has succeeded, or an authentication stage in any
 * state other than {@link Authenticating}.
 * </p>
 */
sealed interface SaslExchangeState
        permits SaslExchangeState.AwaitingTrigger,
        SaslExchangeState.Authenticating,
        SaslExchangeState.Authenticated,
        SaslExchangeState.Failed {

    /**
     * No client request that requires upstream authentication has been seen yet.
     */
    record AwaitingTrigger() implements SaslExchangeState {}

    /**
     * The filter is running its internal ApiVersions/SaslHandshake/SaslAuthenticate exchange.
     *
     * @param stage the stage that completes once the exchange has finished and the state has been updated
     */
    record Authenticating(CompletionStage<AuthenticationResult> stage) implements SaslExchangeState {

        /**
         * Validates the state.
         */
        public Authenticating {
            Objects.requireNonNull(stage, "stage");
        }
    }

    /**
     * The proxy has successfully authenticated to the upstream broker.
     *
     * @param sessionLifetimeMs the broker-reported session lifetime, or zero if the broker did not report one
     */
    record Authenticated(long sessionLifetimeMs) implements SaslExchangeState {}

    /**
     * Authentication failed or a client attempted to pass a SASL frame through the proxy. The connection must close.
     */
    record Failed() implements SaslExchangeState {}

    /**
     * The result of an authentication attempt.
     *
     * @param authenticated whether authentication succeeded
     * @param sessionLifetimeMs the broker-reported session lifetime, meaningful only when {@code authenticated} is true
     */
    record AuthenticationResult(boolean authenticated, long sessionLifetimeMs) {

        /**
         * Returns a successful result.
         *
         * @param sessionLifetimeMs the broker-reported session lifetime
         * @return the result
         */
        static AuthenticationResult success(long sessionLifetimeMs) {
            return new AuthenticationResult(true, sessionLifetimeMs);
        }

        /**
         * Returns a failed result.
         *
         * @return the result
         */
        static AuthenticationResult failure() {
            return new AuthenticationResult(false, 0);
        }
    }
}
