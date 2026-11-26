/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.util.Objects;

/**
 * A broker username and password, used by PLAIN and SCRAM.
 *
 * @param username the broker authentication id; may differ from the store subject
 * @param password the broker password
 */
public record PasswordCredential(String username, DestroyableSecret password) implements Credential {

    /**
     * Creates a password credential.
     *
     * @param username the broker authentication id
     * @param password the broker password
     */
    public PasswordCredential {
        username = CredentialValidation.requireNonBlank(username, "username");
        password = Objects.requireNonNull(password, "password");
    }

    @Override
    public void destroy() {
        password.destroy();
    }

    @Override
    public String toString() {
        return "PasswordCredential[username=" + username + ", password=REDACTED]";
    }
}
