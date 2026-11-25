/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.util.Objects;

/**
 * One credential together with the subject it was stored for.
 * <p>
 * The subject is the credential's lookup key. It is carried separately from the runtime credential so callers can
 * verify that a lookup result really belongs to the key they requested. The runtime credential never exposes secrets
 * through {@link Object#toString()}; this record does not either.
 * </p>
 *
 * @param subject the subject (lookup key) the credential is stored for
 * @param credential the runtime credential
 */
public record StoredCredential(String subject, Credential credential) {

    /**
     * Validates the stored credential.
     */
    public StoredCredential {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("credential subject must not be blank");
        }
        credential = Objects.requireNonNull(credential, "credential");
    }

    @Override
    public String toString() {
        return "StoredCredential[subject=" + subject + ", credential=" + credential + "]";
    }
}
