/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.security.auth.DestroyFailedException;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntry;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.SubjectAlias;

/**
 * Shared add/update/remove operations for the CLI commands.
 */
final class CredentialStoreMutations {

    private CredentialStoreMutations() {
    }

    /**
     * Adds or updates one credential entry.
     *
     * @param file the credential store
     * @param storePassword the store password
     * @param secret the entry secret
     * @param subject the subject
     * @param mustExist whether the subject must already exist (update) or must be absent (add)
     * @param entryFactory creates the entry from the secret text
     * @return whether an existing entry was updated
     */
    static boolean put(Path file, char[] storePassword, char[] secret, String subject, boolean mustExist,
                       EntryFactory entryFactory) {
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        try {
            KeyStore keyStore = KeyStoreFile.load(file, storePassword);
            boolean exists = keyStore.containsAlias(SubjectAlias.hash(subject));
            if (mustExist && !exists) {
                throw new CliException("No credential exists for subject '" + subject + "'");
            }
            if (!mustExist && exists) {
                throw new CliException("A credential already exists for subject '" + subject + "'");
            }
            CredentialEntry entry = entryFactory.create(new String(secret));
            KeyStoreFile.putEntry(keyStore, entry, protection);
            KeyStoreFile.save(file, keyStore, storePassword);
            return exists;
        }
        catch (GeneralSecurityException e) {
            throw new CliException("Failed to update the credential store at " + file, e);
        }
        finally {
            destroy(protection);
        }
    }

    /**
     * Removes one credential entry.
     *
     * @param file the credential store
     * @param storePassword the store password
     * @param subject the subject to remove
     */
    static void remove(Path file, char[] storePassword, String subject) {
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        try {
            KeyStore keyStore = KeyStoreFile.load(file, storePassword);
            String alias = SubjectAlias.hash(subject);
            if (!keyStore.containsAlias(alias)) {
                throw new CliException("No credential exists for subject '" + subject + "'");
            }
            keyStore.deleteEntry(alias);
            KeyStoreFile.save(file, keyStore, storePassword);
        }
        catch (GeneralSecurityException e) {
            throw new CliException("Failed to update the credential store at " + file, e);
        }
        finally {
            destroy(protection);
        }
    }

    private static void destroy(KeyStore.PasswordProtection protection) {
        try {
            protection.destroy();
        }
        catch (DestroyFailedException e) {
            // Best effort; callers also zero the underlying array.
        }
    }

    /**
     * Creates a credential entry from the secret text.
     */
    @FunctionalInterface
    interface EntryFactory {

        /**
         * Creates an entry.
         *
         * @param secret the secret text
         * @return the credential entry
         */
        CredentialEntry create(String secret);
    }
}
