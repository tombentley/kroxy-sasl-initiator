/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

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

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntryCodec;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.SubjectAlias;

import io.kroxylicious.proxy.config.secret.PasswordProvider;

/**
 * Test helpers for creating PKCS12 credential stores.
 */
final class TestStores {

    static final String STORE_PASSWORD = "test-store-password";
    static final String BROKER_PASSWORD = "test-broker-password";

    private TestStores() {
    }

    static PasswordProvider passwordProvider(String password) {
        return () -> password;
    }

    static byte[] passwordEntryJson(String subject, String username, String password) {
        return CredentialEntryCodec.encode(new PasswordCredentialEntry(1, subject, username, password));
    }

    static void writePasswordStore(Path file, String... subjects) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STORE_PASSWORD.toCharArray();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
        try {
            keyStore.load(null, password);
            for (String subject : subjects) {
                byte[] json = passwordEntryJson(subject, "broker-" + subject, BROKER_PASSWORD);
                keyStore.setEntry(SubjectAlias.hash(subject),
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(json, "AES")),
                        protection);
                Arrays.fill(json, (byte) 0);
            }
            writeStore(keyStore, file, password);
        }
        finally {
            protection.destroy();
            Arrays.fill(password, '\0');
        }
    }

    static void writeRawStore(Path file, Map<String, byte[]> entries, String password) throws Exception {
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

    static byte[] rawJson(String subject, String username, String password) {
        return ("{\"version\":1,\"subject\":\"" + subject + "\",\"username\":\"" + username + "\",\"password\":\""
                + password + "\"}").getBytes(StandardCharsets.UTF_8);
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
}
