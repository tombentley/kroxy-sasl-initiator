/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.util.Objects;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A version 1 OAuth client credential entry.
 *
 * @param version the schema version; must be {@value CredentialEntry#CURRENT_VERSION}
 * @param subject the lookup key the entry is intended for
 * @param oauthBearer the OAuth client credential details
 */
public record OAuthCredentialEntry(int version, String subject, OAuthBearer oauthBearer) implements CredentialEntry {

    /**
     * Creates an OAuth credential entry.
     *
     * @param version the schema version
     * @param subject the lookup key
     * @param oauthBearer the OAuth client credential details
     */
    public OAuthCredentialEntry {
        version = CredentialValidation.requireVersion(version);
        subject = CredentialValidation.requireNonBlank(subject, "subject");
        oauthBearer = Objects.requireNonNull(oauthBearer, "oauthBearer");
        if (oauthBearer.expectedSubject() == null) {
            oauthBearer = new OAuthBearer(oauthBearer.clientId(), oauthBearer.clientSecret(), subject);
        }
    }

    @Override
    public CredentialKind kind() {
        return CredentialKind.OAUTH;
    }

    @Override
    public Credential toCredential() {
        return new OAuthClientCredential(oauthBearer.clientId(),
                DestroyableSecret.of(oauthBearer.clientSecret()),
                oauthBearer.expectedSubject());
    }

    @Override
    public String toString() {
        return "OAuthCredentialEntry[version=" + version
                + ", subject=" + subject
                + ", oauthBearer=" + oauthBearer + "]";
    }

    /**
     * The OAuth client credential details stored inside an {@link OAuthCredentialEntry}.
     *
     * @param clientId the OAuth client id
     * @param clientSecret the OAuth client secret
     * @param expectedSubject the expected token subject; if absent in JSON, defaults to the entry subject
     */
    public record OAuthBearer(String clientId, String clientSecret, @Nullable String expectedSubject) {

        /**
         * Creates OAuth bearer details.
         *
         * @param clientId the OAuth client id
         * @param clientSecret the OAuth client secret
         * @param expectedSubject the expected token subject, or {@code null} to default it to the entry subject
         */
        public OAuthBearer {
            clientId = CredentialValidation.requireNonBlank(clientId, "clientId");
            clientSecret = CredentialValidation.requireSecret(clientSecret, "clientSecret");
            if (expectedSubject != null) {
                expectedSubject = CredentialValidation.requireNonBlank(expectedSubject, "expectedSubject");
            }
        }

        @Override
        public String toString() {
            return "OAuthBearer[clientId=" + clientId
                    + ", clientSecret=REDACTED, expectedSubject=" + expectedSubject + "]";
        }
    }
}
