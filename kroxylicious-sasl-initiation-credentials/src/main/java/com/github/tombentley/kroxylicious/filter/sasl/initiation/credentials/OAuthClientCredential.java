/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.util.Objects;

/**
 * An OAuth client credential and the subject the retrieved token is expected to carry.
 *
 * @param clientId the OAuth client id
 * @param clientSecret the OAuth client secret
 * @param expectedSubject the token subject claim value the proxy verifies
 */
public record OAuthClientCredential(String clientId, DestroyableSecret clientSecret, String expectedSubject) implements Credential {

    /**
     * Creates an OAuth client credential.
     *
     * @param clientId the OAuth client id
     * @param clientSecret the OAuth client secret
     * @param expectedSubject the expected token subject
     */
    public OAuthClientCredential {
        clientId = CredentialValidation.requireNonBlank(clientId, "clientId");
        clientSecret = Objects.requireNonNull(clientSecret, "clientSecret");
        expectedSubject = CredentialValidation.requireNonBlank(expectedSubject, "expectedSubject");
    }

    @Override
    public void destroy() {
        clientSecret.destroy();
    }

    @Override
    public String toString() {
        return "OAuthClientCredential[clientId=" + clientId
                + ", clientSecret=REDACTED, expectedSubject=" + expectedSubject + "]";
    }
}
