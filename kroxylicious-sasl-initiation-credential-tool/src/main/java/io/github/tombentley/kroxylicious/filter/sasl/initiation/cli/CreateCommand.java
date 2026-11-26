/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

/**
 * Creates a new empty credential store.
 */
@Command(name = "create", mixinStandardHelpOptions = true, description = "Create a new empty PKCS12 credential store. The file must not already exist.")
final class CreateCommand extends AbstractCommand {

    @Mixin
    FileOptions fileOptions;

    @Mixin
    InsecureOptions insecureOptions;

    @Mixin
    StorePasswordOptions storePasswordOptions;

    @Override
    protected int execute() {
        Path file = fileOptions.file;
        if (Files.exists(file)) {
            throw new CliException("Credential store already exists: " + file);
        }
        storePasswordOptions.validate(insecureOptions.insecureAllowPasswordArgument);
        char[] password = storePasswordOptions.resolve(insecureOptions.insecureAllowPasswordArgument);
        try {
            KeyStoreFile.createEmpty(file, password);
            out().println("Created credential store " + file);
            return CommandLine.ExitCode.OK;
        }
        finally {
            Arrays.fill(password, '\0');
        }
    }
}
