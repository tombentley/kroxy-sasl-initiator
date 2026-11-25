/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

/**
 * Creates the mechanism-specific {@link SaslClient} used by the generic challenge/response exchange.
 * <p>
 * The exchange loop and Kafka {@code SaslAuthenticate} framing are mechanism agnostic. Mechanism-specific callbacks and
 * SASL client construction are confined to implementations of this interface.
 * </p>
 */
interface MechanismDriver {

    /**
     * Creates a SASL client for one authentication exchange.
     *
     * @param callbackHandler the callback handler that supplies mechanism-specific callbacks
     * @return a new SASL client
     * @throws SaslException if the client cannot be created
     */
    SaslClient createSaslClient(CallbackHandler callbackHandler) throws SaslException;
}
