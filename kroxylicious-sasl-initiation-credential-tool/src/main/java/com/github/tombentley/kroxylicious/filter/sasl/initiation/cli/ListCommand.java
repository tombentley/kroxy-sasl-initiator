/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.DestroyFailedException;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthCredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.SubjectAlias;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

/**
 * Lists the non-secret metadata of the stored credentials.
 */
@Command(name = "list", mixinStandardHelpOptions = true, description = "List subjects, credential types and the broker username or expected OAuth subject. "
        + "Passwords, client secrets, aliases and entry payloads are never printed.")
final class ListCommand extends AbstractCommand {

    @Mixin
    FileOptions fileOptions;

    @Mixin
    InsecureOptions insecureOptions;

    @Mixin
    StorePasswordOptions storePasswordOptions;

    @Override
    protected int execute() throws GeneralSecurityException {
        boolean allowPasswordArgument = insecureOptions.insecureAllowPasswordArgument;
        storePasswordOptions.validate(allowPasswordArgument);
        char[] storePassword = storePasswordOptions.resolve(allowPasswordArgument);
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        try {
            KeyStore keyStore = KeyStoreFile.load(fileOptions.file, storePassword);
            List<Row> rows = new ArrayList<>();
            Set<String> subjects = new HashSet<>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                CredentialEntry entry = KeyStoreFile.readEntry(keyStore, alias, protection);
                if (!SubjectAlias.hash(entry.subject()).equals(alias)) {
                    throw new CliException("Credential entry for subject '" + entry.subject()
                            + "' has an invalid alias; the credential store may be corrupted or was created by an incompatible tool");
                }
                if (!subjects.add(entry.subject())) {
                    throw new CliException("Duplicate subject '" + entry.subject() + "' in the credential store");
                }
                rows.add(row(entry));
            }
            rows.sort(Comparator.comparing(Row::subject));
            for (Row row : rows) {
                out().printf("subject=%s type=%s %s=%s%n", row.subject(), row.type(), row.detailName(), row.detail());
            }
            return CommandLine.ExitCode.OK;
        }
        finally {
            try {
                protection.destroy();
            }
            catch (DestroyFailedException e) {
                // Best effort; the underlying array is zeroed below.
            }
            Arrays.fill(storePassword, '\0');
        }
    }

    private static Row row(CredentialEntry entry) {
        if (entry instanceof PasswordCredentialEntry passwordEntry) {
            return new Row(passwordEntry.subject(), "PASSWORD", "username", passwordEntry.username());
        }
        if (entry instanceof OAuthCredentialEntry oauthEntry) {
            return new Row(oauthEntry.subject(), "OAUTH", "expectedSubject", oauthEntry.oauthBearer().expectedSubject());
        }
        return new Row(entry.subject(), entry.kind().name(), "detail", "");
    }

    private record Row(String subject, String type, String detailName, String detail) {}
}
