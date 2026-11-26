/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.util.Arrays;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntry;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthCredentialEntry;

import edu.umd.cs.findbugs.annotations.Nullable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * Adds an OAuth client credential entry.
 */
@Command(name = "add-oauth", mixinStandardHelpOptions = true, description = "Add an OAuth client credential. The subject must not already exist.")
final class AddOAuthCommand extends AbstractCommand {

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

    @Option(names = "--client-id", required = true, paramLabel = "<client-id>", description = "The OAuth client id.")
    String clientId;

    @Option(names = "--expected-subject", paramLabel = "<subject>", description = "The token subject claim value to verify. Defaults to the credential subject.")
    @Nullable
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
        char[] secret = entrySecretOptions.resolve("client secret", "Enter the OAuth client secret: ", allowPasswordArgument);
        try {
            CredentialStoreMutations.put(fileOptions.file, storePassword, secret, checkedSubject, false,
                    clientSecret -> new OAuthCredentialEntry(CredentialEntry.CURRENT_VERSION, checkedSubject,
                            new OAuthCredentialEntry.OAuthBearer(checkedClientId, clientSecret, checkedExpectedSubject)));
            out().println("Added OAUTH credential for subject '" + checkedSubject + "'");
            return CommandLine.ExitCode.OK;
        }
        finally {
            Arrays.fill(storePassword, '\0');
            Arrays.fill(secret, '\0');
        }
    }
}
