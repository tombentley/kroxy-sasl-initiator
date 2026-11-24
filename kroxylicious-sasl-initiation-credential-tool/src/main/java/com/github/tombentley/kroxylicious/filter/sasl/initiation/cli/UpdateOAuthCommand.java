/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.util.Arrays;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthCredentialEntry;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * Replaces an existing OAuth client credential entry.
 */
@Command(name = "update-oauth", mixinStandardHelpOptions = true, description = "Update an OAuth client credential. The subject must already exist.")
final class UpdateOAuthCommand extends AbstractCommand {

    @Mixin
    FileOptions fileOptions;

    @Mixin
    InsecureOptions insecureOptions;

    @Mixin
    StorePasswordOptions storePasswordOptions;

    @Mixin
    EntrySecretOptions entrySecretOptions;

    @Option(names = "--subject", required = true, paramLabel = "<subject>", description = "The subject (lookup key) of the credential to update.")
    String subject;

    @Option(names = "--client-id", required = true, paramLabel = "<client-id>", description = "The OAuth client id.")
    String clientId;

    @Option(names = "--expected-subject", paramLabel = "<subject>", description = "The token subject claim value to verify. Defaults to the credential subject.")
    String expectedSubject;

    @Override
    protected int execute() {
        String checkedSubject = subject;
        String checkedClientId = clientId;
        requireNonBlank(checkedSubject, "--subject");
        requireNonBlank(checkedClientId, "--client-id");
        String checkedExpectedSubject = expectedSubject == null ? checkedSubject : expectedSubject;
        requireNonBlank(checkedExpectedSubject, "--expected-subject");

        boolean allowPasswordArgument = insecureOptions.insecureAllowPasswordArgument;
        storePasswordOptions.validate(allowPasswordArgument);
        entrySecretOptions.validate(allowPasswordArgument);
        char[] storePassword = storePasswordOptions.resolve(allowPasswordArgument);
        char[] secret = entrySecretOptions.resolve("client secret", "Enter the new OAuth client secret: ", allowPasswordArgument);
        try {
            CredentialStoreMutations.put(fileOptions.file, storePassword, secret, checkedSubject, true,
                    clientSecret -> new OAuthCredentialEntry(CredentialEntry.CURRENT_VERSION, checkedSubject,
                            new OAuthCredentialEntry.OAuthBearer(checkedClientId, clientSecret, checkedExpectedSubject)));
            out().println("Updated OAUTH credential for subject '" + checkedSubject + "'");
            return CommandLine.ExitCode.OK;
        }
        finally {
            Arrays.fill(storePassword, '\0');
            Arrays.fill(secret, '\0');
        }
    }
}
