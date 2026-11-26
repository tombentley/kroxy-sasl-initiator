/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

/**
 * A version 1 password credential entry.
 *
 * @param version the schema version; must be {@value CredentialEntry#CURRENT_VERSION}
 * @param subject the lookup key the entry is intended for
 * @param username the broker authentication id
 * @param password the broker password
 */
public record PasswordCredentialEntry(int version, String subject, String username, String password) implements CredentialEntry {

    /**
     * Creates a password credential entry.
     *
     * @param version the schema version
     * @param subject the lookup key
     * @param username the broker authentication id
     * @param password the broker password
     */
    public PasswordCredentialEntry {
        version = CredentialValidation.requireVersion(version);
        subject = CredentialValidation.requireNonBlank(subject, "subject");
        username = CredentialValidation.requireNonBlank(username, "username");
        password = CredentialValidation.requireSecret(password, "password");
    }

    @Override
    public CredentialKind kind() {
        return CredentialKind.PASSWORD;
    }

    @Override
    public Credential toCredential() {
        return new PasswordCredential(username, DestroyableSecret.of(password));
    }

    @Override
    public String toString() {
        return "PasswordCredentialEntry[version=" + version
                + ", subject=" + subject
                + ", username=" + username
                + ", password=REDACTED]";
    }
}
