/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;

/**
 * Supplies an already retrieved and validated OAuth bearer token to Kafka's OAUTHBEARER SASL client.
 * <p>
 * The token is obtained before this handler is used, on a worker thread, so handling the SASL callback performs no
 * network or file I/O on the filter-dispatch thread. No SASL extensions are sent.
 * </p>
 */
final class OAuthBearerSaslClientCallbackHandler implements AuthenticateCallbackHandler {

    private final OAuthBearerToken token;

    /**
     * Creates a callback handler for one exchange.
     *
     * @param token the validated token for the exchange
     */
    OAuthBearerSaslClientCallbackHandler(OAuthBearerToken token) {
        this.token = Objects.requireNonNull(token, "token");
    }

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        // The token is supplied at construction; no configuration is needed.
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback tokenCallback) {
                tokenCallback.token(token);
            }
            else if (callback instanceof SaslExtensionsCallback extensionsCallback) {
                extensionsCallback.extensions(SaslExtensions.empty());
            }
            else {
                throw new UnsupportedCallbackException(callback, "Unsupported SASL callback for OAUTHBEARER");
            }
        }
    }

    @Override
    public void close() {
        // The token is not owned by this handler.
    }
}
