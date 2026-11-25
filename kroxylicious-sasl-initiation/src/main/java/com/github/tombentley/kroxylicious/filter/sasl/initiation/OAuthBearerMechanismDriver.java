/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerSaslClientProvider;

/**
 * A mechanism driver for SASL/OAUTHBEARER, using Kafka's SASL client implementation.
 * <p>
 * Token retrieval and validation happen before this driver is used. The supplied callback handler returns the
 * pre-validated token; the challenge/response state machine remains mechanism agnostic.
 * </p>
 */
final class OAuthBearerMechanismDriver implements MechanismDriver {

    private static final String MECHANISM = "OAUTHBEARER";

    static {
        OAuthBearerSaslClientProvider.initialize();
    }

    @Override
    public SaslClient createSaslClient(CallbackHandler callbackHandler) throws SaslException {
        SaslClient client = Sasl.createSaslClient(
                new String[]{ MECHANISM },
                null,
                null,
                "localhost",
                Map.of(),
                callbackHandler);
        if (client == null) {
            throw new SaslException("No SASL client implementation is available for " + MECHANISM);
        }
        return client;
    }
}
