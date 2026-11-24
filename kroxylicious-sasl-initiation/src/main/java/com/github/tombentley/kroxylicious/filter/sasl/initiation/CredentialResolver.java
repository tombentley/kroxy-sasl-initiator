/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.Credential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.StoredCredential;

/**
 * Resolves a credential lookup key to a stored credential.
 * <p>
 * The credential store is an allow-list: the lookup key selects exactly one entry. A missing entry, an entry of the
 * wrong credential kind, or an entry whose stored subject does not equal the lookup key all fail closed. This prevents
 * a subject from selecting a credential that was stored for a different subject, even if a store implementation or a
 * future store format ever returns such an entry.
 * </p>
 * <p>
 * Exception messages are safe to log: they name subjects and credential kinds, never passwords, tokens or payloads.
 * </p>
 */
public final class CredentialResolver {

    private final Function<String, Optional<StoredCredential>> lookup;

    /**
     * Creates a resolver backed by the loaded credential store.
     *
     * @param store the credential store
     */
    public CredentialResolver(KeyStoreCredentialStore store) {
        this(Objects.requireNonNull(store, "store")::findStored);
    }

    CredentialResolver(Function<String, Optional<StoredCredential>> lookup) {
        this.lookup = Objects.requireNonNull(lookup, "lookup");
    }

    /**
     * Resolves the credential for a lookup key.
     *
     * @param lookupKey the subject lookup key
     * @param expectedKind the credential kind required by the configured mechanism
     * @return the credential and its stored subject
     * @throws CredentialResolutionException if the entry is missing, has the wrong kind, or belongs to another subject
     */
    public ResolvedCredential resolve(String lookupKey, CredentialKind expectedKind) {
        if (lookupKey == null || lookupKey.isBlank()) {
            throw new CredentialResolutionException("The credential lookup key must not be blank");
        }
        Objects.requireNonNull(expectedKind, "expectedKind");

        StoredCredential stored = lookup.apply(lookupKey)
                .orElseThrow(() -> new CredentialResolutionException(
                        "No " + expectedKind + " credential is configured for the selected identity"));
        if (!lookupKey.equals(stored.subject())) {
            throw new CredentialResolutionException(
                    "The resolved credential belongs to a different subject than the selected identity");
        }
        CredentialKind actualKind = kindOf(stored.credential());
        if (actualKind != expectedKind) {
            throw new CredentialResolutionException(
                    "The resolved credential is " + actualKind + " but the configured mechanism requires " + expectedKind);
        }
        return new ResolvedCredential(stored.subject(), stored.credential());
    }

    private static CredentialKind kindOf(Credential credential) {
        if (credential instanceof PasswordCredential) {
            return CredentialKind.PASSWORD;
        }
        if (credential instanceof OAuthClientCredential) {
            return CredentialKind.OAUTH;
        }
        throw new CredentialResolutionException("The resolved credential has an unsupported type");
    }

    /**
     * A credential and the subject it was resolved for.
     *
     * @param subject the stored subject, which equals the lookup key
     * @param credential the runtime credential
     */
    public record ResolvedCredential(String subject, Credential credential) {

        /**
         * Validates the resolved credential.
         */
        public ResolvedCredential {
            if (subject == null || subject.isBlank()) {
                throw new IllegalArgumentException("resolved credential subject must not be blank");
            }
            Objects.requireNonNull(credential, "credential");
        }
    }

    /**
     * Thrown when a credential cannot be resolved for an identity.
     * <p>
     * This is always a fail-closed condition. Messages never contain secrets.
     * </p>
     */
    public static final class CredentialResolutionException extends RuntimeException {

        /**
         * Creates an exception with the given failure message.
         *
         * @param message description of the failure
         */
        public CredentialResolutionException(String message) {
            super(message);
        }
    }
}
