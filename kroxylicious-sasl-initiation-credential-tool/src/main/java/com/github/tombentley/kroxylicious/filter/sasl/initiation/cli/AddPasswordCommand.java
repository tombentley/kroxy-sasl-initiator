/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.util.Arrays;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredentialEntry;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * Adds a broker username and password entry.
 */
@Command(name = "add-password", mixinStandardHelpOptions = true, description = "Add a password credential. The subject must not already exist.")
final class AddPasswordCommand extends AbstractCommand {

    @Mixin
    FileOptions fileOptions;

    @Mixin
    InsecureOptions insecureOptions;

    @Mixin
    StorePasswordOptions storePasswordOptions;

    @Mixin
    EntrySecretOptions entrySecretOptions;

    @Option(names = "--subject", required = true, paramLabel = "<subject>", description = "The subject (lookup key) the credential is for.")
    String subject;

    @Option(names = "--username", required = true, paramLabel = "<username>", description = "The broker authentication username.")
    String username;

    @Override
    protected int execute() {
        String checkedSubject = subject;
        String checkedUsername = username;
        requireNonBlank(checkedSubject, "--subject");
        requireNonBlank(checkedUsername, "--username");

        boolean allowPasswordArgument = insecureOptions.insecureAllowPasswordArgument;
        storePasswordOptions.validate(allowPasswordArgument);
        entrySecretOptions.validate(allowPasswordArgument);
        char[] storePassword = storePasswordOptions.resolve(allowPasswordArgument);
        char[] secret = entrySecretOptions.resolve("password", "Enter the broker password: ", allowPasswordArgument);
        try {
            CredentialStoreMutations.put(fileOptions.file, storePassword, secret, checkedSubject, false,
                    plaintextPassword -> new PasswordCredentialEntry(CredentialEntry.CURRENT_VERSION, checkedSubject,
                            checkedUsername, plaintextPassword));
            out().println("Added PASSWORD credential for subject '" + checkedSubject + "'");
            return CommandLine.ExitCode.OK;
        }
        finally {
            Arrays.fill(storePassword, '\0');
            Arrays.fill(secret, '\0');
        }
    }
}
