/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import java.util.Arrays;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;

/**
 * The SASL mechanism the filter uses to authenticate to the upstream broker.
 * <p>
 * The enum constant names are Java-friendly, while {@link #mechanismName()} is the IANA mechanism name used in
 * configuration. OAUTHBEARER is deliberately absent from this commit; it is added with its dedicated configuration
 * group later.
 * </p>
 */
public enum Mechanism {

    /**
     * SASL PLAIN.
     */
    PLAIN("PLAIN", CredentialKind.PASSWORD),

    /**
     * SCRAM using SHA-256.
     */
    SCRAM_SHA_256("SCRAM-SHA-256", CredentialKind.PASSWORD),

    /**
     * SCRAM using SHA-512.
     */
    SCRAM_SHA_512("SCRAM-SHA-512", CredentialKind.PASSWORD);

    private final String mechanismName;
    private final CredentialKind credentialKind;

    Mechanism(String mechanismName, CredentialKind credentialKind) {
        this.mechanismName = mechanismName;
        this.credentialKind = credentialKind;
    }

    /**
     * Returns the IANA mechanism name used in configuration.
     *
     * @return the mechanism name
     */
    @JsonValue
    public String mechanismName() {
        return mechanismName;
    }

    /**
     * Returns the kind of credential this mechanism consumes.
     *
     * @return the credential kind
     */
    public CredentialKind credentialKind() {
        return credentialKind;
    }

    /**
     * Parses an IANA SASL mechanism name from configuration.
     *
     * @param value the configured mechanism name
     * @return the matching mechanism
     * @throws IllegalArgumentException if the value is null, blank or not one of the supported mechanisms
     */
    @JsonCreator
    public static Mechanism fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("mechanism is required and must be one of " + supportedMechanisms());
        }
        for (Mechanism mechanism : values()) {
            if (mechanism.mechanismName.equals(value)) {
                return mechanism;
            }
        }
        throw new IllegalArgumentException("Unsupported mechanism '" + value + "'; expected one of " + supportedMechanisms());
    }

    private static String supportedMechanisms() {
        return Arrays.stream(values())
                .map(Mechanism::mechanismName)
                .collect(Collectors.joining(", ", "[", "]"));
    }

    @Override
    public String toString() {
        return mechanismName;
    }
}
