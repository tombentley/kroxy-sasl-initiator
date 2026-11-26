/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.kroxylicious.proxy.config.secret.FilePassword;
import io.kroxylicious.proxy.config.secret.PasswordProvider;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * An immutable in-memory credential store loaded from a PKCS12 KeyStore.
 * <p>
 * The KeyStore contains one {@link KeyStore.SecretKeyEntry} per identity. The alias is
 * {@link SubjectAlias#hash(String) hash(subject)}, and the entry payload is the UTF-8 JSON described by
 * {@link CredentialEntry}. The same password protects the KeyStore and each entry. Loading validates the whole file
 * before publishing any credential: entry type, JSON schema, alias/subject agreement, expected credential kind,
 * duplicate subjects and an empty store all fail closed. No partial store is returned.
 * </p>
 * <p>
 * The store password is converted to a {@code char[]}, used for the load, and zeroized afterwards. Entry secrets are
 * wrapped in {@link DestroyableSecret}. Immutable strings and library-internal copies remain an accepted residual heap
 * risk; see the package documentation.
 * </p>
 * <p>
 * Instances are immutable and safe to share between threads. The secret material inside the returned credentials is
 * owned by the store; {@link #close()} destroys it. Do not use a store after closing it.
 * </p>
 */
public final class KeyStoreCredentialStore implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreCredentialStore.class);

    private static final String KEYSTORE_TYPE = "PKCS12";

    private final Map<String, StoredCredential> credentials;
    private final Map<String, Credential> credentialView;
    private final CredentialKind kind;
    private final Path file;

    private KeyStoreCredentialStore(Map<String, StoredCredential> credentials, CredentialKind kind, Path file) {
        this.credentials = Collections.unmodifiableMap(new LinkedHashMap<>(credentials));
        Map<String, Credential> view = new LinkedHashMap<>();
        this.credentials.forEach((subject, stored) -> view.put(subject, stored.credential()));
        this.credentialView = Collections.unmodifiableMap(view);
        this.kind = kind;
        this.file = file;
    }

    /**
     * Loads and validates a PKCS12 credential store.
     *
     * @param file the PKCS12 file
     * @param filePassword the password provider for the store and its entries
     * @param expectedKind the credential kind every entry must have
     * @return the loaded immutable store
     * @throws KeyStoreCredentialStoreException if the file is missing, unreadable, not PKCS12, has insecure
     *             permissions, has an incorrect password, or contains an invalid entry
     */
    @SuppressFBWarnings(value = "RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE", justification = "PasswordProvider is implemented by users; keep the defensive null check")
    public static KeyStoreCredentialStore load(Path file, PasswordProvider filePassword, CredentialKind expectedKind) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(filePassword, "filePassword");
        Objects.requireNonNull(expectedKind, "expectedKind");

        requireReadable(file);
        checkPermissions(file, filePassword);
        requirePkcs12Header(file);

        String providedPassword;
        try {
            providedPassword = filePassword.getProvidedPassword();
        }
        catch (RuntimeException e) {
            throw new KeyStoreCredentialStoreException("Failed to obtain the KeyStore password for " + file, e);
        }
        if (providedPassword == null || providedPassword.isEmpty()) {
            throw new KeyStoreCredentialStoreException("The KeyStore password for " + file + " must not be null or empty");
        }

        char[] storePassword = providedPassword.toCharArray();
        KeyStore.PasswordProtection protection = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream input = Files.newInputStream(file)) {
                keyStore.load(input, storePassword);
            }

            protection = new KeyStore.PasswordProtection(storePassword);
            List<DecodedEntry> entries = decodeEntries(keyStore, protection, expectedKind);
            rejectDuplicateSubjects(entries);
            Map<String, StoredCredential> loaded = buildCredentials(entries);
            LOGGER.atInfo()
                    .addKeyValue("file", file)
                    .addKeyValue("credentialKind", expectedKind)
                    .addKeyValue("entryCount", loaded.size())
                    .log("Loaded SASL initiation credentials");
            return new KeyStoreCredentialStore(loaded, expectedKind, file);
        }
        catch (KeyStoreCredentialStoreException e) {
            throw e;
        }
        catch (IOException e) {
            throw new KeyStoreCredentialStoreException(
                    "Failed to load the PKCS12 credential KeyStore at " + file
                            + "; the file may not be a PKCS12 KeyStore or the password may be incorrect",
                    e);
        }
        catch (GeneralSecurityException e) {
            throw new KeyStoreCredentialStoreException("Failed to read the credential KeyStore at " + file, e);
        }
        finally {
            if (protection != null) {
                try {
                    protection.destroy();
                }
                catch (DestroyFailedException e) {
                    // Best-effort: the store password buffer is zeroed below regardless.
                }
            }
            Arrays.fill(storePassword, '\0');
        }
    }

    /**
     * Returns an unmodifiable view of the loaded credentials, keyed by subject.
     *
     * @return the credentials keyed by subject
     */
    public Map<String, Credential> credentials() {
        return credentialView;
    }

    /**
     * Returns the credential kind this store was validated against.
     *
     * @return the expected credential kind
     */
    public CredentialKind kind() {
        return kind;
    }

    /**
     * Returns the number of loaded entries.
     *
     * @return the number of entries
     */
    public int size() {
        return credentials.size();
    }

    /**
     * Finds a credential by subject.
     *
     * @param key the subject lookup key
     * @return the credential, or empty if no entry exists
     */
    public Optional<Credential> find(String key) {
        return findStored(key).map(StoredCredential::credential);
    }

    /**
     * Finds a credential and its stored subject by subject.
     *
     * @param key the subject lookup key
     * @return the stored credential, or empty if no entry exists
     */
    public Optional<StoredCredential> findStored(String key) {
        Objects.requireNonNull(key, "key");
        return Optional.ofNullable(credentials.get(key));
    }

    /**
     * Returns a credential by subject, failing if it is absent. This is the fail-closed lookup used by fixed-identity
     * mode.
     *
     * @param key the subject lookup key
     * @return the credential
     * @throws KeyStoreCredentialStoreException if no entry exists for the key
     */
    public Credential require(String key) {
        return requireStored(key).credential();
    }

    /**
     * Returns a credential and its stored subject by subject, failing if it is absent.
     *
     * @param key the subject lookup key
     * @return the stored credential
     * @throws KeyStoreCredentialStoreException if no entry exists for the key
     */
    public StoredCredential requireStored(String key) {
        Objects.requireNonNull(key, "key");
        StoredCredential stored = credentials.get(key);
        if (stored == null) {
            throw new KeyStoreCredentialStoreException(
                    "No " + kind + " credential is configured for key '" + key + "' in " + file
                            + "; add the entry or correct the configured identity key");
        }
        return stored;
    }

    /**
     * Destroys the secret material held by all credentials in this store. Calling this method more than once has no
     * additional effect.
     */
    @Override
    public void close() {
        credentials.values().forEach(stored -> stored.credential().destroy());
    }

    @Override
    public String toString() {
        return "KeyStoreCredentialStore[file=" + file + ", kind=" + kind + ", entries=" + credentials.size() + "]";
    }

    private static void requireReadable(Path file) {
        if (!Files.exists(file)) {
            throw new KeyStoreCredentialStoreException("Credential KeyStore file not found: " + file);
        }
        if (!Files.isRegularFile(file)) {
            throw new KeyStoreCredentialStoreException("Credential KeyStore path is not a regular file: " + file);
        }
        if (!Files.isReadable(file)) {
            throw new KeyStoreCredentialStoreException("Credential KeyStore file is not readable: " + file);
        }
    }

    private static void checkPermissions(Path file, PasswordProvider filePassword) {
        KeyStorePermissions.check(file);
        if (filePassword instanceof FilePassword passwordFile) {
            KeyStorePermissions.check(Path.of(passwordFile.passwordFile()));
        }
    }

    private static void requirePkcs12Header(Path file) {
        try (InputStream input = Files.newInputStream(file)) {
            int firstByte = input.read();
            if (firstByte != 0x30) {
                throw new KeyStoreCredentialStoreException(
                        "The credential KeyStore at " + file + " is not a PKCS12 file; PKCS12 is required");
            }
        }
        catch (IOException e) {
            throw new KeyStoreCredentialStoreException("Failed to read the credential KeyStore at " + file, e);
        }
    }

    private static List<DecodedEntry> decodeEntries(KeyStore keyStore, KeyStore.PasswordProtection protection, CredentialKind expectedKind)
            throws GeneralSecurityException {
        if (keyStore.size() == 0) {
            throw new KeyStoreCredentialStoreException("The credential KeyStore is empty; it must contain at least one entry");
        }

        List<DecodedEntry> entries = new ArrayList<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            entries.add(decodeEntry(keyStore, alias, protection, expectedKind));
        }
        if (entries.isEmpty()) {
            throw new KeyStoreCredentialStoreException("The credential KeyStore is empty; it must contain at least one entry");
        }
        return entries;
    }

    private static DecodedEntry decodeEntry(KeyStore keyStore, String alias, KeyStore.PasswordProtection protection, CredentialKind expectedKind)
            throws GeneralSecurityException {
        if (!keyStore.isKeyEntry(alias)) {
            throw new KeyStoreCredentialStoreException(
                    "KeyStore alias '" + alias + "' is not a secret key entry; only SecretKeyEntry entries are supported");
        }
        KeyStore.Entry keyStoreEntry = keyStore.getEntry(alias, protection);
        if (!(keyStoreEntry instanceof KeyStore.SecretKeyEntry secretKeyEntry)) {
            throw new KeyStoreCredentialStoreException(
                    "KeyStore alias '" + alias + "' is not a secret key entry; only SecretKeyEntry entries are supported");
        }
        SecretKey secretKey = secretKeyEntry.getSecretKey();
        if (secretKey == null) {
            throw new KeyStoreCredentialStoreException("KeyStore alias '" + alias + "' contains no secret key material");
        }
        byte[] encoded = secretKey.getEncoded();
        if (encoded == null) {
            throw new KeyStoreCredentialStoreException("KeyStore alias '" + alias + "' contains no encoded secret key material");
        }

        final CredentialEntry entry;
        try {
            entry = CredentialEntryCodec.decode(encoded);
        }
        catch (KeyStoreCredentialStoreException e) {
            throw new KeyStoreCredentialStoreException("Invalid credential entry for alias '" + alias + "': " + e.getMessage());
        }
        finally {
            Arrays.fill(encoded, (byte) 0);
        }

        if (entry.kind() != expectedKind) {
            throw new KeyStoreCredentialStoreException(
                    "Credential entry for subject '" + entry.subject() + "' is " + entry.kind()
                            + " but the store was loaded expecting " + expectedKind + " credentials");
        }
        return new DecodedEntry(alias, entry);
    }

    private static void rejectDuplicateSubjects(List<DecodedEntry> entries) {
        Map<String, String> aliasesBySubject = new LinkedHashMap<>();
        for (DecodedEntry entry : entries) {
            String previousAlias = aliasesBySubject.putIfAbsent(entry.entry().subject(), entry.alias());
            if (previousAlias != null) {
                throw new KeyStoreCredentialStoreException(
                        "Duplicate subject '" + entry.entry().subject() + "' in the credential KeyStore: aliases '"
                                + previousAlias + "' and '" + entry.alias() + "' both claim the same subject");
            }
        }
    }

    private static Map<String, StoredCredential> buildCredentials(List<DecodedEntry> entries) {
        Map<String, StoredCredential> loaded = new LinkedHashMap<>();
        boolean complete = false;
        try {
            for (DecodedEntry decoded : entries) {
                String expectedAlias = SubjectAlias.hash(decoded.entry().subject());
                if (!expectedAlias.equals(decoded.alias())) {
                    throw new KeyStoreCredentialStoreException(
                            "KeyStore alias '" + decoded.alias() + "' does not match the SHA-256 hash of its subject; expected '"
                                    + expectedAlias + "'. The KeyStore may be corrupted or created by an incompatible tool.");
                }
                loaded.put(decoded.entry().subject(),
                        new StoredCredential(decoded.entry().subject(), decoded.entry().toCredential()));
            }
            complete = true;
            return loaded;
        }
        finally {
            if (!complete) {
                loaded.values().forEach(stored -> stored.credential().destroy());
            }
        }
    }

    private record DecodedEntry(String alias, CredentialEntry entry) {}
}
