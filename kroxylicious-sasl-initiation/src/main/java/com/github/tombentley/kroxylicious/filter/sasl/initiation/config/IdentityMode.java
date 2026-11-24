/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Selects how the filter determines the credential lookup key for a connection.
 */
public enum IdentityMode {

    /**
     * Use the key configured in {@link IdentityConfig#key()}.
     */
    FIXED("fixed"),

    /**
     * Use a principal from the authenticated downstream subject at request time.
     */
    SUBJECT("subject");

    private final String jsonName;

    IdentityMode(String jsonName) {
        this.jsonName = jsonName;
    }

    /**
     * Returns the lower-case name used in configuration.
     *
     * @return the configuration name
     */
    @JsonValue
    public String jsonName() {
        return jsonName;
    }

    /**
     * Parses an identity mode from configuration.
     *
     * @param value the configured mode
     * @return the matching identity mode
     * @throws IllegalArgumentException if the value is null, blank or unsupported
     */
    @JsonCreator
    public static IdentityMode fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("identity.mode is required and must be 'fixed' or 'subject'");
        }
        for (IdentityMode mode : values()) {
            if (mode.jsonName.equals(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unsupported identity mode '" + value + "'; expected 'fixed' or 'subject'");
    }
}
