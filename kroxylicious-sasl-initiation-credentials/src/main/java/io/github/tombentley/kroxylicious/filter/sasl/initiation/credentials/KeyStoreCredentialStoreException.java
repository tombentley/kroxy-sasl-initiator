/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

/**
 * Thrown when a credential KeyStore cannot be loaded or contains an invalid entry.
 * <p>
 * Messages are intended to be actionable and must never contain passwords, client secrets, token values or KeyStore
 * password material. Paths, subjects, aliases and field names are not secrets and may appear in messages.
 * </p>
 */
public class KeyStoreCredentialStoreException extends RuntimeException {

    /**
     * Creates an exception with the given failure message.
     *
     * @param message description of the failure; must not contain secret material
     */
    public KeyStoreCredentialStoreException(String message) {
        super(message);
    }

    /**
     * Creates an exception with the given failure message and cause.
     *
     * @param message description of the failure; must not contain secret material
     * @param cause the underlying cause
     */
    public KeyStoreCredentialStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
