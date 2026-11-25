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

import org.apache.kafka.common.security.scram.internals.ScramSaslClientProvider;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;

/**
 * A mechanism driver for SASL mechanisms that use the JDK's or Kafka's password-based client implementations.
 * <p>
 * PLAIN is provided by the JDK. SCRAM-SHA-256 and SCRAM-SHA-512 are provided by Kafka, so the Kafka
 * {@link ScramSaslClientProvider} must be registered before creating those clients. The challenge/response state
 * machine remains mechanism agnostic.
 * </p>
 */
final class PasswordMechanismDriver implements MechanismDriver {

    static {
        // Registers the Kafka SCRAM SASL client factories. The JDK does not provide SCRAM.
        ScramSaslClientProvider.initialize();
    }

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
    public SaslClient createSaslClient(CallbackHandler callbackHandler) throws SaslException {
        Map<String, Object> configs = Map.of();
        SaslClient client = Sasl.createSaslClient(
                new String[]{ mechanism.mechanismName() },
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
