/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Map;
import java.util.Objects;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;

/**
 * A mechanism driver for SASL mechanisms that use the JDK's password-based client implementations.
 * <p>
 * This commit implements PLAIN. SCRAM is added by the next commit without changing the exchange state machine.
 * </p>
 */
final class PasswordMechanismDriver implements MechanismDriver {

    private final Mechanism mechanism;

    /**
     * Creates a password mechanism driver.
     *
     * @param mechanism the configured mechanism
     */
    PasswordMechanismDriver(Mechanism mechanism) {
        this.mechanism = Objects.requireNonNull(mechanism, "mechanism");
    }

    @Override
    public SaslClient createSaslClient(PasswordCredential credential, CallbackHandler callbackHandler) throws SaslException {
        if (mechanism != Mechanism.PLAIN) {
            throw new SaslException("SASL mechanism " + mechanism.mechanismName() + " is not implemented by this version");
        }
        Map<String, Object> configs = Map.of();
        SaslClient client = Sasl.createSaslClient(
                new String[]{ Mechanism.PLAIN.mechanismName() },
                null,
                null,
                "localhost",
                configs,
                callbackHandler);
        if (client == null) {
            throw new SaslException("No SASL client implementation is available for " + mechanism.mechanismName());
        }
        return client;
    }
}
