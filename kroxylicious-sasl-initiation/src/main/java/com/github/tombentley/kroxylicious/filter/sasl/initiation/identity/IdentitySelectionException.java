/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

/**
 * Thrown when the configured identity cannot be selected from the current request context.
 * <p>
 * This is always a fail-closed condition: the filter must not fall back to a different identity. Messages are safe to
 * log and never contain credentials or passwords.
 * </p>
 */
public class IdentitySelectionException extends IllegalStateException {

    /**
     * Creates an exception with the given failure message.
     *
     * @param message description of the failure
     */
    public IdentitySelectionException(String message) {
        super(message);
    }

    /**
     * Creates an exception with the given failure message and cause.
     *
     * @param message description of the failure
     * @param cause the underlying cause
     */
    public IdentitySelectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
