/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntryCodec;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStorePermissions;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.SubjectAlias;

/**
 * Low-level PKCS12 file operations used by the CLI.
 * <p>
 * The CLI needs to mutate the store, while the production credential store is deliberately immutable and requires every
 * entry to have the same credential kind. This helper therefore works with the credential model and codec from the
 * credentials module directly. It preserves the same PKCS12 representation, alias scheme and owner-only permission
 * policy, so stores written by the tool are accepted by
 * {@link com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore}.
 * </p>
 */
final class KeyStoreFile {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_ALGORITHM = "AES";

    private KeyStoreFile() {
    }

    /**
     * Loads an existing PKCS12 store, enforcing the same readability, permission and format checks as the production
     * store.
     *
     * @param file the store file
     * @param password the store password
     * @return the loaded KeyStore
     */
    static KeyStore load(Path file, char[] password) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(password, "password");
        requireReadable(file);
        requirePkcs12Header(file);
        KeyStorePermissions.check(file);
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream input = Files.newInputStream(file)) {
                keyStore.load(input, password);
            }
            return keyStore;
        }
        catch (IOException e) {
            throw new CliException("Failed to load the credential store at " + file
                    + "; the file may not be a PKCS12 store or the store password may be incorrect", e);
        }
        catch (GeneralSecurityException e) {
            throw new CliException("Failed to read the credential store at " + file, e);
        }
    }

    /**
     * Creates a new, empty PKCS12 store with owner-only permissions.
     *
     * @param file the file to create
     * @param password the store password
     */
    static void createEmpty(Path file, char[] password) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(password, "password");
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new CliException("Credential store already exists: " + file);
        }
        Path parent = file.toAbsolutePath().getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new CliException("The parent directory of the credential store does not exist: " + file);
        }

        boolean created = false;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, password);
            KeyStorePermissions.createOwnerOnly(file);
            created = true;
            try (OutputStream output = Files.newOutputStream(file)) {
                keyStore.store(output, password);
            }
            KeyStorePermissions.setOwnerOnly(file);
        }
        catch (FileAlreadyExistsException e) {
            throw new CliException("Credential store already exists: " + file, e);
        }
        catch (IOException e) {
            if (created) {
                deleteQuietly(file);
            }
            throw new CliException("Failed to create the credential store at " + file, e);
        }
        catch (GeneralSecurityException e) {
            if (created) {
                deleteQuietly(file);
            }
            throw new CliException("Failed to create the credential store at " + file, e);
        }
    }

    /**
     * Replaces an existing store atomically using a temporary owner-only file in the same directory.
     *
     * @param file the store file to replace
     * @param keyStore the complete updated store
     * @param password the store password
     */
    static void save(Path file, KeyStore keyStore, char[] password) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(keyStore, "keyStore");
        Objects.requireNonNull(password, "password");
        Path absolute = file.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new CliException("Cannot determine the parent directory of the credential store: " + file);
        }

        Path temporary = null;
        try {
            temporary = KeyStorePermissions.createTempFileOwnerOnly(parent, ".sasl-initiation-credentials", ".tmp");
            try (OutputStream output = Files.newOutputStream(temporary)) {
                keyStore.store(output, password);
            }
            KeyStorePermissions.setOwnerOnly(temporary);
            moveIntoPlace(temporary, absolute);
            temporary = null;
        }
        catch (IOException e) {
            throw new CliException("Failed to write the credential store at " + file, e);
        }
        catch (GeneralSecurityException e) {
            throw new CliException("Failed to write the credential store at " + file, e);
        }
        finally {
            if (temporary != null) {
                deleteQuietly(temporary);
            }
        }
    }

    private static void moveIntoPlace(Path temporary, Path target) throws IOException {
        try {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Decodes a credential entry from a KeyStore alias.
     *
     * @param keyStore the KeyStore
     * @param alias the alias
     * @param protection the password protection
     * @return the decoded entry
     */
    static CredentialEntry readEntry(KeyStore keyStore, String alias, KeyStore.PasswordProtection protection) {
        try {
            if (!keyStore.isKeyEntry(alias)) {
                throw new CliException("The credential store contains a non-secret entry; only password and OAuth credentials are supported");
            }
            KeyStore.Entry keyStoreEntry = keyStore.getEntry(alias, protection);
            if (!(keyStoreEntry instanceof KeyStore.SecretKeyEntry secretKeyEntry)) {
                throw new CliException("The credential store contains a non-secret entry; only password and OAuth credentials are supported");
            }
            SecretKey secretKey = secretKeyEntry.getSecretKey();
            byte[] encoded = secretKey == null ? null : secretKey.getEncoded();
            if (encoded == null) {
                throw new CliException("A credential entry contains no encoded key material");
            }
            try {
                return CredentialEntryCodec.decode(encoded);
            }
            finally {
                Arrays.fill(encoded, (byte) 0);
            }
        }
        catch (GeneralSecurityException e) {
            throw new CliException("Failed to read a credential entry", e);
        }
    }

    /**
     * Adds or replaces the credential entry for the entry's subject.
     *
     * @param keyStore the KeyStore
     * @param entry the credential entry
     * @param protection the password protection
     */
    static void putEntry(KeyStore keyStore, CredentialEntry entry, KeyStore.PasswordProtection protection) {
        byte[] encoded = CredentialEntryCodec.encode(entry);
        try {
            String alias = SubjectAlias.hash(entry.subject());
            keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeySpec(encoded, KEY_ALGORITHM)), protection);
        }
        catch (GeneralSecurityException e) {
            throw new CliException("Failed to add the credential entry for subject '" + entry.subject() + "'", e);
        }
        finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static void requireReadable(Path file) {
        if (!Files.exists(file)) {
            throw new CliException("Credential store file not found: " + file);
        }
        if (!Files.isRegularFile(file)) {
            throw new CliException("Credential store path is not a regular file: " + file);
        }
        if (!Files.isReadable(file)) {
            throw new CliException("Credential store file is not readable: " + file);
        }
    }

    private static void requirePkcs12Header(Path file) {
        try (InputStream input = Files.newInputStream(file)) {
            int firstByte = input.read();
            if (firstByte != 0x30) {
                throw new CliException("The credential store at " + file + " is not a PKCS12 file; PKCS12 is required");
            }
        }
        catch (IOException e) {
            throw new CliException("Failed to read the credential store at " + file, e);
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        }
        catch (IOException e) {
            // Best effort cleanup; the original failure is more useful.
        }
    }
}
