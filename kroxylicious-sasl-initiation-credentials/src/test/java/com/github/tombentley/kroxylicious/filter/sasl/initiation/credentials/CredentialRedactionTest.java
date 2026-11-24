/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CredentialRedactionTest {

    @Test
    void passwordCredentialToStringRedactsPassword() {
        String secretValue = "password-to-redact";
        PasswordCredential credential = new PasswordCredential("broker-alice", DestroyableSecret.of(secretValue.toCharArray()));
        try {
            assertFalse(credential.toString().contains(secretValue), "PasswordCredential.toString leaked the password");
            assertThat(credential.toString()).contains("REDACTED");
        }
        finally {
            credential.destroy();
        }
    }

    @Test
    void oauthClientCredentialToStringRedactsClientSecret() {
        String secretValue = "client-secret-to-redact";
        OAuthClientCredential credential = new OAuthClientCredential("client-id", DestroyableSecret.of(secretValue.toCharArray()), "alice");
        try {
            assertFalse(credential.toString().contains(secretValue), "OAuthClientCredential.toString leaked the client secret");
            assertThat(credential.toString()).contains("REDACTED");
        }
        finally {
            credential.destroy();
        }
    }

    @Test
    void passwordEntryToStringRedactsPassword() {
        String secretValue = "entry-password-to-redact";
        PasswordCredentialEntry entry = new PasswordCredentialEntry(1, "alice", "broker-alice", secretValue);

        assertFalse(entry.toString().contains(secretValue), "PasswordCredentialEntry.toString leaked the password");
        assertThat(entry.toString()).contains("REDACTED");
    }

    @Test
    void oauthEntryToStringRedactsClientSecret() {
        String secretValue = "entry-client-secret-to-redact";
        OAuthCredentialEntry entry = new OAuthCredentialEntry(1, "alice",
                new OAuthCredentialEntry.OAuthBearer("client-id", secretValue, "alice"));

        assertFalse(entry.toString().contains(secretValue), "OAuthCredentialEntry.toString leaked the client secret");
        assertThat(entry.toString()).contains("REDACTED");
    }

    @Test
    void credentialDestroyIsIdempotentAndDestroysSecrets() {
        DestroyableSecret secret = DestroyableSecret.of("secret".toCharArray());
        PasswordCredential credential = new PasswordCredential("broker-alice", secret);

        credential.destroy();
        credential.close();

        assertThat(secret.isDestroyed()).isTrue();
    }

    @Test
    void oauthCredentialExpectedSubjectDefaultsInEntry() {
        OAuthCredentialEntry entry = new OAuthCredentialEntry(1, "alice",
                new OAuthCredentialEntry.OAuthBearer("client-id", "client-secret", null));

        assertThat(entry.oauthBearer().expectedSubject()).isEqualTo("alice");
    }
}
