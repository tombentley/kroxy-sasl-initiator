/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.util.Arrays;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

/**
 * Removes one credential entry.
 */
@Command(name = "remove", mixinStandardHelpOptions = true, description = "Remove the credential for a subject. The subject must exist.")
final class RemoveCommand extends AbstractCommand {

    @Mixin
    FileOptions fileOptions;

    @Mixin
    InsecureOptions insecureOptions;

    @Mixin
    StorePasswordOptions storePasswordOptions;

    @Option(names = "--subject", required = true, paramLabel = "<subject>", description = "The subject (lookup key) of the credential to remove.")
    String subject;

    @Override
    protected int execute() {
        String checkedSubject = subject;
        requireNonBlank(checkedSubject, "--subject");

        boolean allowPasswordArgument = insecureOptions.insecureAllowPasswordArgument;
        storePasswordOptions.validate(allowPasswordArgument);
        char[] storePassword = storePasswordOptions.resolve(allowPasswordArgument);
        try {
            CredentialStoreMutations.remove(fileOptions.file, storePassword, checkedSubject);
            out().println("Removed credential for subject '" + checkedSubject + "'");
            return CommandLine.ExitCode.OK;
        }
        finally {
            Arrays.fill(storePassword, '\0');
        }
    }
}
