/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Shared validation helpers for credential model types. Messages name fields but never include field values that may
 * be secret.
 */
final class CredentialValidation {

    private CredentialValidation() {
    }

    static int requireVersion(int version) {
        if (version != CredentialEntry.CURRENT_VERSION) {
            throw new IllegalArgumentException("Unsupported credential entry version " + version
                    + "; version " + CredentialEntry.CURRENT_VERSION + " is required");
        }
        return version;
    }

    static String requireNonBlank(@Nullable String value, String field) {
        if (value == null) {
            throw new NullPointerException("Credential entry field '" + field + "' must not be null");
        }
        if (value.isBlank()) {
            throw new IllegalArgumentException("Credential entry field '" + field + "' must not be blank");
        }
        return value;
    }

    static String requireNonEmpty(@Nullable String value, String field) {
        if (value == null) {
            throw new NullPointerException("Credential entry field '" + field + "' must not be null");
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Credential entry field '" + field + "' must not be empty");
        }
        return value;
    }

    static String requireSecret(@Nullable String value, String field) {
        return requireNonEmpty(value, field);
    }
}
