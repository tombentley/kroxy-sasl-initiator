/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Objects;
import java.util.concurrent.CompletionStage;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySnapshot;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * The explicit state machine of a single upstream connection's SASL initiation exchange.
 * <p>
 * The state is always changed on the connection's filter-dispatch thread. A filter instance is per connection, so no
 * state is shared between clients.
 * </p>
 * <p>
 * Each state carries only the data that is meaningful while the connection is in that state. This makes it impossible
 * to observe, for example, a session lifetime before authentication has succeeded, or an authentication stage in any
 * state other than {@link Authenticating} or {@link Reauthenticating}.
 * </p>
 */
sealed interface SaslExchangeState
        permits SaslExchangeState.AwaitingTrigger,
        SaslExchangeState.Authenticating,
        SaslExchangeState.Authenticated,
        SaslExchangeState.Reauthenticating,
        SaslExchangeState.Failed {

    /**
     * No client request that requires upstream authentication has been seen yet.
     */
    record AwaitingTrigger() implements SaslExchangeState {}

    /**
     * The filter is running its initial ApiVersions/SaslHandshake/SaslAuthenticate exchange.
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
     * @param apiVersions the SASL API versions used for the authenticated session, reused for reauthentication
     * @param identity the identity and credential lookup key used for the authenticated session
     * @param tokenExpiresAtMs the OAuth token expiry instant, or {@code null} for password mechanisms
     */
    record Authenticated(long sessionLifetimeMs,
                         SaslApiVersions apiVersions,
                         IdentitySnapshot identity,
                         @Nullable Long tokenExpiresAtMs)
            implements SaslExchangeState {

        /**
         * Validates the state.
         */
        public Authenticated {
            Objects.requireNonNull(apiVersions, "apiVersions");
            Objects.requireNonNull(identity, "identity");
        }
    }

    /**
     * The filter is reauthenticating the existing upstream session with the same identity.
     *
     * @param stage the stage that completes once the exchange has finished and the state has been updated
     */
    record Reauthenticating(CompletionStage<AuthenticationResult> stage) implements SaslExchangeState {

        /**
         * Validates the state.
         */
        public Reauthenticating {
            Objects.requireNonNull(stage, "stage");
        }
    }

    /**
     * Authentication failed or a client attempted to pass a SASL frame through the proxy. The connection must close.
     */
    record Failed() implements SaslExchangeState {}

    /**
     * The result of an authentication attempt.
     *
     * @param authenticated whether authentication succeeded
     * @param sessionLifetimeMs the broker-reported session lifetime, meaningful only when {@code authenticated} is true
     * @param apiVersions the SASL API versions used, meaningful only when {@code authenticated} is true
     * @param identity the selected identity, meaningful only when {@code authenticated} is true
     * @param tokenExpiresAtMs the OAuth token expiry instant, or {@code null} for password mechanisms
     */
    record AuthenticationResult(boolean authenticated,
                                long sessionLifetimeMs,
                                @Nullable SaslApiVersions apiVersions,
                                @Nullable IdentitySnapshot identity,
                                @Nullable Long tokenExpiresAtMs) {

        /**
         * Validates the result.
         */
        public AuthenticationResult {
            if (authenticated) {
                Objects.requireNonNull(apiVersions, "apiVersions");
                Objects.requireNonNull(identity, "identity");
            }
        }

        /**
         * Returns a successful result.
         *
         * @param sessionLifetimeMs the broker-reported session lifetime
         * @param apiVersions the SASL API versions used
         * @param identity the selected identity
         * @param tokenExpiresAtMs the OAuth token expiry instant, or {@code null} for password mechanisms
         * @return the result
         */
        static AuthenticationResult success(long sessionLifetimeMs,
                                            SaslApiVersions apiVersions,
                                            IdentitySnapshot identity,
                                            @Nullable Long tokenExpiresAtMs) {
            return new AuthenticationResult(true, sessionLifetimeMs, apiVersions, identity, tokenExpiresAtMs);
        }

        /**
         * Returns a failed result.
         *
         * @return the result
         */
        static AuthenticationResult failure() {
            return new AuthenticationResult(false, 0, null, null, null);
        }
    }
}
