/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import io.kroxylicious.proxy.config.secret.FilePassword;
import io.kroxylicious.testing.certificate.CertificateGenerator;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.CLIENT_SECRET;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.PASSWORD_SECRET;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.STORE_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.alias;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.oauthEntryJson;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.passwordEntryJson;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreTestSupport.passwordProvider;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertFalse;

class KeyStoreCredentialStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void loadsPasswordEntriesAndIsImmutable() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET));
        entries.put(alias("bob"), passwordEntryJson("bob", "broker-bob", "bob-password"));
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD, entries);

        try (KeyStoreCredentialStore store = KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD)) {
            assertThat(store.size()).isEqualTo(2);
            assertThat(store.kind()).isEqualTo(CredentialKind.PASSWORD);
            assertThat(store.credentials()).containsOnlyKeys("alice", "bob");

            Credential alice = store.require("alice");
            assertThat(alice).isInstanceOf(PasswordCredential.class);
            PasswordCredential passwordCredential = (PasswordCredential) alice;
            assertThat(passwordCredential.username()).isEqualTo("broker-alice");
            SecretAssertions.assertCharsEqual(passwordCredential.password(), PASSWORD_SECRET);
            assertThat(store.find("bob")).isPresent();
            assertThat(store.find("missing")).isEmpty();

            assertThatThrownBy(() -> store.credentials().clear())
                    .isInstanceOf(UnsupportedOperationException.class);
            assertFalse(store.toString().contains(PASSWORD_SECRET), "store toString leaked a password");
        }
    }

    @Test
    void loadsOAuthEntryAndDefaultsExpectedSubject() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), KeyStoreTestSupport.rawOAuthEntryJsonWithoutExpectedSubject("alice", "alice-client", CLIENT_SECRET)));

        try (KeyStoreCredentialStore store = KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.OAUTH)) {
            Credential credential = store.require("alice");
            assertThat(credential).isInstanceOf(OAuthClientCredential.class);
            OAuthClientCredential oauthCredential = (OAuthClientCredential) credential;
            assertThat(oauthCredential.clientId()).isEqualTo("alice-client");
            assertThat(oauthCredential.expectedSubject()).isEqualTo("alice");
            SecretAssertions.assertCharsEqual(oauthCredential.clientSecret(), CLIENT_SECRET);
        }
    }

    @Test
    void requireFailsForMissingKey() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));

        try (KeyStoreCredentialStore store = KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD)) {
            assertThatThrownBy(() -> store.require("nobody"))
                    .isInstanceOf(KeyStoreCredentialStoreException.class)
                    .hasMessageContaining("nobody")
                    .satisfies(exception -> assertFalse(exception.getMessage().contains(PASSWORD_SECRET),
                            "exception message leaked a password"));
        }
    }

    @Test
    void closeDestroysCredentialSecrets() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));

        KeyStoreCredentialStore store = KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD);
        PasswordCredential credential = (PasswordCredential) store.require("alice");
        DestroyableSecret secret = credential.password();
        try {
            store.close();
            store.close();

            assertThat(secret.isDestroyed()).isTrue();
            assertThatThrownBy(secret::chars).isInstanceOf(IllegalStateException.class);
        }
        finally {
            store.close();
        }
    }

    @Test
    void rejectsWrongStorePassword() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider("wrong-password"), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("PKCS12")
                .satisfies(exception -> {
                    assertFalse(exception.getMessage().contains(STORE_PASSWORD), "exception message leaked the store password");
                    assertFalse(exception.getMessage().contains(PASSWORD_SECRET), "exception message leaked an entry password");
                });
    }

    @Test
    void rejectsMissingFile() {
        Path file = tempDir.resolve("missing.p12");

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void rejectsCorruptFile() throws Exception {
        Path file = tempDir.resolve("corrupt.p12");
        Files.write(file, new byte[]{ 0x30, 0x03, 0x01, 0x02 });
        KeyStoreTestSupport.setOwnerOnly(file);

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("Failed to load the PKCS12 credential KeyStore");
    }

    @Test
    void rejectsNonPkcs12File() throws Exception {
        Path file = tempDir.resolve("credentials.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] password = STORE_PASSWORD.toCharArray();
        try {
            keyStore.load(null, password);
            KeyStoreTestSupport.writeStore(keyStore, file, password);
        }
        finally {
            Arrays.fill(password, '\0');
        }

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("not a PKCS12 file");
    }

    @Test
    void rejectsCertificateEntry() throws Exception {
        Path file = tempDir.resolve("certificate.p12");
        writeCertificateStore(file);

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("not a secret key entry");
    }

    @Test
    void rejectsPrivateKeyEntry() throws Exception {
        Path file = tempDir.resolve("private-key.p12");
        KeyPair keyPair = CertificateGenerator.generateRsaKeyPair();
        X509Certificate certificate = CertificateGenerator.generateSelfSignedX509Certificate(keyPair);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STORE_PASSWORD.toCharArray();
        try {
            keyStore.load(null, password);
            keyStore.setKeyEntry("private-key", keyPair.getPrivate(), password, new Certificate[]{ certificate });
            KeyStoreTestSupport.writeStore(keyStore, file, password);
        }
        finally {
            Arrays.fill(password, '\0');
        }

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("not a secret key entry");
    }

    @Test
    void rejectsAliasMismatch() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("bob"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("does not match the SHA-256 hash of its subject");
    }

    @Test
    void rejectsDuplicateSubjects() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET));
        entries.put(alias("bob"), passwordEntryJson("alice", "broker-alice-2", PASSWORD_SECRET));
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD, entries);

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("Duplicate subject 'alice'");
    }

    @Test
    void rejectsEmptyStore() throws Exception {
        Path file = tempDir.resolve("empty.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD, Map.of());

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsWrongCredentialKind() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), oauthEntryJson("alice", "alice-client", CLIENT_SECRET, "alice")));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("OAUTH")
                .hasMessageContaining("PASSWORD")
                .satisfies(exception -> assertFalse(exception.getMessage().contains(CLIENT_SECRET),
                        "exception message leaked a client secret"));
    }

    @Test
    void rejectsMalformedEntryJson() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), "not-json".getBytes(StandardCharsets.UTF_8)));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("Invalid credential entry for alias")
                .hasMessageContaining("Malformed credential entry JSON");
    }

    @Test
    void rejectsEntryWithUnknownField() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        byte[] json = ("{\"version\":1,\"subject\":\"alice\",\"username\":\"broker-alice\",\"password\":\""
                + PASSWORD_SECRET + "\",\"extra\":\"x\"}").getBytes(StandardCharsets.UTF_8);
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD, Map.of(alias("alice"), json));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("Invalid credential entry for alias")
                .hasMessageContaining("unknown field 'extra'")
                .satisfies(exception -> assertFalse(exception.getMessage().contains(PASSWORD_SECRET),
                        "exception message leaked a password"));
    }

    @Test
    void rejectsMissingEntryPasswordFile() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));
        FilePassword passwordProvider = new FilePassword(tempDir.resolve("missing.password").toString());

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider, CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("Failed to obtain the KeyStore password");
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void rejectsGroupReadableStoreFile() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, passwordProvider(STORE_PASSWORD), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining(file.toString())
                .hasMessageContaining("insecure permissions")
                .satisfies(exception -> assertFalse(exception.getMessage().contains(STORE_PASSWORD),
                        "exception message leaked the store password"));
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void acceptsOwnerOnlyPasswordFile() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));
        Path passwordFile = tempDir.resolve("store.password");
        Files.writeString(passwordFile, STORE_PASSWORD);
        KeyStoreTestSupport.setOwnerOnly(passwordFile);

        try (KeyStoreCredentialStore store = KeyStoreCredentialStore.load(file, new FilePassword(passwordFile.toString()), CredentialKind.PASSWORD)) {
            assertThat(store.size()).isEqualTo(1);
        }
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void rejectsGroupReadablePasswordFile() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        KeyStoreTestSupport.writeStore(file, STORE_PASSWORD,
                Map.of(alias("alice"), passwordEntryJson("alice", "broker-alice", PASSWORD_SECRET)));
        Path passwordFile = tempDir.resolve("store.password");
        Files.writeString(passwordFile, STORE_PASSWORD);
        Files.setPosixFilePermissions(passwordFile, PosixFilePermissions.fromString("rw-r--r--"));

        assertThatThrownBy(() -> KeyStoreCredentialStore.load(file, new FilePassword(passwordFile.toString()), CredentialKind.PASSWORD))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining(passwordFile.toString())
                .hasMessageContaining("insecure permissions")
                .satisfies(exception -> assertFalse(exception.getMessage().contains(STORE_PASSWORD),
                        "exception message leaked the store password"));
    }

    private void writeCertificateStore(Path file) throws Exception {
        KeyPair keyPair = CertificateGenerator.generateRsaKeyPair();
        X509Certificate certificate = CertificateGenerator.generateSelfSignedX509Certificate(keyPair);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STORE_PASSWORD.toCharArray();
        try {
            keyStore.load(null, password);
            keyStore.setCertificateEntry("certificate", certificate);
            KeyStoreTestSupport.writeStore(keyStore, file, password);
        }
        finally {
            Arrays.fill(password, '\0');
        }
    }
}
