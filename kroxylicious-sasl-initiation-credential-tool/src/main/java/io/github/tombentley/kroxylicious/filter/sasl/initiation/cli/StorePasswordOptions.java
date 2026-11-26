/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.nio.file.Path;

import edu.umd.cs.findbugs.annotations.Nullable;
import picocli.CommandLine.Option;

/**
 * Options for obtaining the PKCS12 store password.
 */
final class StorePasswordOptions {

    @Option(names = "--store-password-file", paramLabel = "<path>", description = "Read the store password from the first line of the given file.")
    @Nullable
    Path storePasswordFile;

    @Option(names = "--store-password-stdin", description = "Read the store password from the first line of standard input.")
    boolean storePasswordStdin;

    @Option(names = "--store-password", paramLabel = "<password>", description = "Pass the store password as an argument. Requires --insecure-allow-password-argument. "
            + "SECURITY WARNING: command-line arguments are exposed in process listings and shell history.")
    @Nullable
    String storePassword;

    void validate(boolean allowPasswordArgument) {
        SecretInput.validate("--store-password-file", storePasswordFile,
                "--store-password-stdin", storePasswordStdin,
                "--store-password", storePassword,
                allowPasswordArgument);
    }

    char[] resolve(boolean allowPasswordArgument) {
        return SecretInput.read("store password",
                "--store-password-file", storePasswordFile,
                "--store-password-stdin", storePasswordStdin,
                "--store-password", storePassword,
                allowPasswordArgument,
                "Enter the credential store password: ");
    }
}
