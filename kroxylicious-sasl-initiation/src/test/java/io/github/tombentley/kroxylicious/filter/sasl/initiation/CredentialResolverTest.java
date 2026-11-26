/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.CredentialResolver.CredentialResolutionException;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.StoredCredential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialResolverTest {

    private static final String PASSWORD = "broker-password";

    @Test
    void resolvesTheEntryForTheLookupKey() {
        PasswordCredential credential = passwordCredential("svc-alice");
        CredentialResolver resolver = new CredentialResolver(
                key -> Optional.of(new StoredCredential("alice", credential)));

        CredentialResolver.ResolvedCredential resolved = resolver.resolve("alice", CredentialKind.PASSWORD);

        assertThat(resolved.subject()).isEqualTo("alice");
        assertThat(resolved.credential()).isSameAs(credential);
    }

    @Test
    void failsClosedWhenTheEntryIsMissing() {
        CredentialResolver resolver = new CredentialResolver(key -> Optional.empty());

        assertThatThrownBy(() -> resolver.resolve("alice", CredentialKind.PASSWORD))
                .isInstanceOf(CredentialResolutionException.class)
                .hasMessageContaining("No PASSWORD credential");
    }

    @Test
    void failsClosedWhenTheEntrySubjectDoesNotMatchTheLookupKey() {
        CredentialResolver resolver = new CredentialResolver(
                key -> Optional.of(new StoredCredential("bob", passwordCredential("svc-bob"))));

        assertThatThrownBy(() -> resolver.resolve("alice", CredentialKind.PASSWORD))
                .isInstanceOf(CredentialResolutionException.class)
                .hasMessageContaining("different subject");
    }

    @Test
    void failsClosedWhenTheEntryHasTheWrongKind() {
        OAuthClientCredential oauthCredential = new OAuthClientCredential(
                "alice-client",
                DestroyableSecret.of("client-secret"),
                "alice");
        CredentialResolver resolver = new CredentialResolver(
                key -> Optional.of(new StoredCredential("alice", oauthCredential)));

        assertThatThrownBy(() -> resolver.resolve("alice", CredentialKind.PASSWORD))
                .isInstanceOf(CredentialResolutionException.class)
                .hasMessageContaining("OAUTH")
                .hasMessageContaining("PASSWORD");
        oauthCredential.destroy();
    }

    @Test
    void rejectsABlankLookupKey() {
        CredentialResolver resolver = new CredentialResolver(key -> Optional.empty());

        assertThatThrownBy(() -> resolver.resolve(" ", CredentialKind.PASSWORD))
                .isInstanceOf(CredentialResolutionException.class)
                .hasMessageContaining("must not be blank");
    }

    private static PasswordCredential passwordCredential(String username) {
        return new PasswordCredential(username, DestroyableSecret.of(PASSWORD));
    }
}
