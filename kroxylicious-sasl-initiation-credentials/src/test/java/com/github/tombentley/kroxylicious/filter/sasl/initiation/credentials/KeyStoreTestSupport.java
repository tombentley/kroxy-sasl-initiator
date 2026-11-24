/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import io.kroxylicious.proxy.config.secret.PasswordProvider;

/**
 * Test helpers for creating PKCS12 credential stores.
 */
final class KeyStoreTestSupport {

    static final String STORE_PASSWORD = "test-store-password";
    static final String PASSWORD_SECRET = "test-broker-password";
    static final String CLIENT_SECRET = "test-oauth-client-secret";

    private KeyStoreTestSupport() {
    }

    static PasswordProvider passwordProvider(String password) {
        return () -> password;
    }

    static byte[] passwordEntryJson(String subject, String username, String password) {
        return CredentialEntryCodec.encode(new PasswordCredentialEntry(1, subject, username, password));
    }

    static byte[] oauthEntryJson(String subject, String clientId, String clientSecret, String expectedSubject) {
        return CredentialEntryCodec.encode(new OAuthCredentialEntry(1, subject,
                new OAuthCredentialEntry.OAuthBearer(clientId, clientSecret, expectedSubject)));
    }

    static byte[] rawOAuthEntryJsonWithoutExpectedSubject(String subject, String clientId, String clientSecret) {
        return ("{\"version\":1,\"subject\":\"" + subject + "\",\"oauthBearer\":{\"clientId\":\"" + clientId
                + "\",\"clientSecret\":\"" + clientSecret + "\"}}").getBytes(StandardCharsets.UTF_8);
    }

    static void writeStore(Path file, String password, Map<String, byte[]> entries) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] passwordChars = password.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(passwordChars);
        try {
            keyStore.load(null, passwordChars);
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                keyStore.setEntry(entry.getKey(),
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(entry.getValue(), "AES")),
                        protection);
            }
            writeStore(keyStore, file, passwordChars);
        }
        finally {
            protection.destroy();
            Arrays.fill(passwordChars, '\0');
        }
    }

    static void writeStore(KeyStore keyStore, Path file, char[] password) throws Exception {
        if (Files.exists(file)) {
            Files.delete(file);
        }
        try (OutputStream output = Files.newOutputStream(file)) {
            keyStore.store(output, password);
        }
        setOwnerOnly(file);
    }

    static void setOwnerOnly(Path file) {
        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(file, ownerOnly);
        }
        catch (UnsupportedOperationException e) {
            // Non-POSIX file system: nothing to set.
        }
        catch (Exception e) {
            throw new IllegalStateException("Failed to set owner-only permissions on " + file, e);
        }
    }

    static String alias(String subject) {
        return SubjectAlias.hash(subject);
    }
}
