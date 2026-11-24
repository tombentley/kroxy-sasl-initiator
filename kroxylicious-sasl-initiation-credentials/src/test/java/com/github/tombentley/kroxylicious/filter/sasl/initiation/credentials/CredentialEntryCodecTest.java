/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialEntryCodecTest {

    private static final String PASSWORD_SECRET = "correct horse battery staple";
    private static final String CLIENT_SECRET = "oauth-client-secret";

    @Test
    void decodesPasswordVariant() {
        String json = """
                {"version":1,"subject":"alice","username":"broker-alice","password":"%s"}
                """.formatted(PASSWORD_SECRET);

        CredentialEntry decoded = CredentialEntryCodec.decode(json);

        assertThat(decoded).isInstanceOf(PasswordCredentialEntry.class);
        PasswordCredentialEntry entry = (PasswordCredentialEntry) decoded;
        assertThat(entry.version()).isEqualTo(1);
        assertThat(entry.subject()).isEqualTo("alice");
        assertThat(entry.username()).isEqualTo("broker-alice");
        assertThat(entry.kind()).isEqualTo(CredentialKind.PASSWORD);
        SecretAssertions.assertStringSecretEqual(entry.password(), PASSWORD_SECRET);
    }

    @Test
    void decodesOAuthVariant() {
        String json = """
                {"version":1,"subject":"alice","oauthBearer":{"clientId":"alice-client","clientSecret":"%s","expectedSubject":"mapped-alice"}}
                """.formatted(CLIENT_SECRET);

        CredentialEntry decoded = CredentialEntryCodec.decode(json);

        assertThat(decoded).isInstanceOf(OAuthCredentialEntry.class);
        OAuthCredentialEntry entry = (OAuthCredentialEntry) decoded;
        assertThat(entry.version()).isEqualTo(1);
        assertThat(entry.subject()).isEqualTo("alice");
        assertThat(entry.kind()).isEqualTo(CredentialKind.OAUTH);
        assertThat(entry.oauthBearer().clientId()).isEqualTo("alice-client");
        SecretAssertions.assertStringSecretEqual(entry.oauthBearer().clientSecret(), CLIENT_SECRET);
        assertThat(entry.oauthBearer().expectedSubject()).isEqualTo("mapped-alice");
    }

    @Test
    void defaultsMissingOAuthExpectedSubjectToSubject() {
        String json = """
                {"version":1,"subject":"alice","oauthBearer":{"clientId":"alice-client","clientSecret":"%s"}}
                """.formatted(CLIENT_SECRET);

        OAuthCredentialEntry entry = (OAuthCredentialEntry) CredentialEntryCodec.decode(json);

        assertThat(entry.oauthBearer().expectedSubject()).isEqualTo("alice");
    }

    @Test
    void encodesPasswordVariantRoundTrip() {
        PasswordCredentialEntry original = new PasswordCredentialEntry(1, "alice", "broker-alice", PASSWORD_SECRET);

        byte[] encoded = CredentialEntryCodec.encode(original);
        PasswordCredentialEntry decoded = (PasswordCredentialEntry) CredentialEntryCodec.decode(encoded);

        assertThat(encoded).isNotEmpty();
        assertThat(decoded.version()).isEqualTo(original.version());
        assertThat(decoded.subject()).isEqualTo(original.subject());
        assertThat(decoded.username()).isEqualTo(original.username());
        SecretAssertions.assertStringSecretEqual(decoded.password(), PASSWORD_SECRET);
    }

    @Test
    void encodesOAuthVariantRoundTrip() {
        OAuthCredentialEntry original = new OAuthCredentialEntry(1, "alice",
                new OAuthCredentialEntry.OAuthBearer("alice-client", CLIENT_SECRET, "mapped-alice"));

        byte[] encoded = CredentialEntryCodec.encode(original);
        OAuthCredentialEntry decoded = (OAuthCredentialEntry) CredentialEntryCodec.decode(encoded);

        assertThat(encoded).isNotEmpty();
        assertThat(decoded.subject()).isEqualTo(original.subject());
        assertThat(decoded.oauthBearer().clientId()).isEqualTo("alice-client");
        SecretAssertions.assertStringSecretEqual(decoded.oauthBearer().clientSecret(), CLIENT_SECRET);
        assertThat(decoded.oauthBearer().expectedSubject()).isEqualTo("mapped-alice");
    }

    @Test
    void encodedJsonIsUtf8() {
        PasswordCredentialEntry original = new PasswordCredentialEntry(1, "Ålice", "Ålice", PASSWORD_SECRET);

        byte[] encoded = CredentialEntryCodec.encode(original);
        String json = new String(encoded, StandardCharsets.UTF_8);

        assertTrue(json.contains("\"subject\":\"Ålice\""), "encoded JSON does not contain the expected non-ASCII subject");
        CredentialEntry decoded = CredentialEntryCodec.decode(encoded);
        assertThat(decoded.subject()).isEqualTo("Ålice");
    }

    @ParameterizedTest
    @MethodSource("invalidEntries")
    void rejectsInvalidEntries(String json, String expectedMessageFragment) {
        KeyStoreCredentialStoreException exception = assertThrows(KeyStoreCredentialStoreException.class,
                () -> CredentialEntryCodec.decode(json));

        assertThat(exception.getMessage()).contains(expectedMessageFragment);
        assertThat(exception).hasNoCause();
        assertFalse(exception.getMessage().contains(PASSWORD_SECRET), "exception message leaked a secret");
        assertFalse(exception.getMessage().contains(CLIENT_SECRET), "exception message leaked a secret");
    }

    @Test
    void doesNotLeakMalformedJsonContent() {
        String secretValue = "secret-in-malformed-json";
        String json = "{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\"" + secretValue + "\"";

        KeyStoreCredentialStoreException exception = assertThrows(KeyStoreCredentialStoreException.class,
                () -> CredentialEntryCodec.decode(json));

        assertFalse(exception.getMessage().contains(secretValue), "exception message leaked malformed JSON content");
        assertThat(exception).hasNoCause();
    }

    @Test
    void doesNotLeakWronglyTypedSecretValue() {
        String secretValue = "secret-in-wrong-type";
        String json = "{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":{\"value\":\""
                + secretValue + "\"}}";

        KeyStoreCredentialStoreException exception = assertThrows(KeyStoreCredentialStoreException.class,
                () -> CredentialEntryCodec.decode(json));

        assertFalse(exception.getMessage().contains(secretValue), "exception message leaked a field value");
        assertThat(exception).hasNoCause();
    }

    @Test
    void doesNotLeakUnknownFieldValue() {
        String secretValue = "secret-in-unknown-field";
        String json = "{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\""
                + PASSWORD_SECRET + "\",\"unexpected\":\"" + secretValue + "\"}";

        KeyStoreCredentialStoreException exception = assertThrows(KeyStoreCredentialStoreException.class,
                () -> CredentialEntryCodec.decode(json));

        assertThat(exception.getMessage()).contains("unknown field 'unexpected'");
        assertFalse(exception.getMessage().contains(secretValue), "exception message leaked an unknown field value");
        assertThat(exception).hasNoCause();
    }

    @Test
    void rejectsNullBytes() {
        assertThatThrownBy(() -> CredentialEntryCodec.decode((byte[]) null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsNullEntryOnEncode() {
        assertThatThrownBy(() -> CredentialEntryCodec.encode(null))
                .isInstanceOf(NullPointerException.class);
    }

    private static Stream<Arguments> invalidEntries() {
        return Stream.of(
                Arguments.of("", "Malformed credential entry JSON"),
                Arguments.of("not json", "Malformed credential entry JSON"),
                Arguments.of("{}", "version"),
                Arguments.of("[]", "must be an object"),
                Arguments.of("null", "must be an object"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\"}", "password"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}", "username"),
                Arguments.of("{\"version\":1,\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}", "subject"),
                Arguments.of("{\"version\":1,\"subject\":null,\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}", "subject"),
                Arguments.of("{\"version\":1,\"subject\":\"\",\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}", "subject"),
                Arguments.of("{\"version\":1,\"subject\":\"   \",\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}", "subject"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":null}", "password"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\"\"}", "password"),
                Arguments.of("{\"version\":null,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}",
                        "version"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":null,\"password\":\"" + PASSWORD_SECRET + "\"}", "username"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"\",\"password\":\"" + PASSWORD_SECRET + "\"}", "username"),
                Arguments.of("{\"version\":2,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}",
                        "Unsupported credential entry version 2"),
                Arguments.of("{\"version\":\"1\",\"subject\":\"alice\",\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}",
                        "must be an integer"),
                Arguments.of("{\"version\":1.0,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}",
                        "must be an integer"),
                Arguments.of("{\"version\":1,\"subject\":42,\"username\":\"alice\",\"password\":\"" + PASSWORD_SECRET + "\"}",
                        "must be a string"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\""
                        + PASSWORD_SECRET + "\",\"extra\":\"x\"}", "unknown field 'extra'"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\""
                        + PASSWORD_SECRET + "\",\"oauthBearer\":{}}", "unknown field 'username'"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":\"not-an-object\"}", "oauthBearer"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":null}", "oauthBearer"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientSecret\":\""
                        + CLIENT_SECRET + "\"}}", "clientId"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"client\"}}", "clientSecret"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"client\",\"clientSecret\":null}}", "clientSecret"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"\",\"clientSecret\":\""
                        + CLIENT_SECRET + "\"}}", "clientId"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"client\",\"clientSecret\":\""
                        + CLIENT_SECRET + "\",\"expectedSubject\":null}}", "expectedSubject"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"client\",\"clientSecret\":\""
                        + CLIENT_SECRET + "\",\"expectedSubject\":\"\"}}", "expectedSubject"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"client\",\"clientSecret\":\""
                        + CLIENT_SECRET + "\",\"expectedSubject\":\"   \"}}", "expectedSubject"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"oauthBearer\":{\"clientId\":\"client\",\"clientSecret\":\""
                        + CLIENT_SECRET + "\",\"nested\":\"x\"}}", "unknown field 'nested'"),
                Arguments.of("{\"version\":1,\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\""
                        + PASSWORD_SECRET + "\"}", "Malformed credential entry JSON"),
                Arguments.of("{\"version\":1,\"subject\":\"alice\",\"username\":\"alice\",\"password\":\""
                        + PASSWORD_SECRET + "\"} {}", "Malformed credential entry JSON"));
    }
}
