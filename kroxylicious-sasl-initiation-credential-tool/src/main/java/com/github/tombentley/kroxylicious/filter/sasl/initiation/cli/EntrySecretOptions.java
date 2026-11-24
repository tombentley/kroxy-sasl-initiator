/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.nio.file.Path;

import edu.umd.cs.findbugs.annotations.Nullable;
import picocli.CommandLine.Option;

/**
 * Options for obtaining an entry secret (a broker password or an OAuth client secret).
 */
final class EntrySecretOptions {

    @Option(names = { "--password-file", "--client-secret-file" }, paramLabel = "<path>", description = "Read the secret from the first line of the given file.")
    @Nullable
    Path passwordFile;

    @Option(names = { "--password-stdin", "--client-secret-stdin" }, description = "Read the secret from the first line of standard input.")
    boolean passwordStdin;

    @Option(names = { "--password",
            "--client-secret" }, paramLabel = "<secret>", description = "Pass the secret as an argument. Requires --insecure-allow-password-argument. "
                    + "SECURITY WARNING: command-line arguments are exposed in process listings and shell history.")
    @Nullable
    String password;

    void validate(boolean allowPasswordArgument) {
        SecretInput.validate("--password-file/--client-secret-file", passwordFile,
                "--password-stdin/--client-secret-stdin", passwordStdin,
                "--password/--client-secret", password,
                allowPasswordArgument);
    }

    char[] resolve(String label, String prompt, boolean allowPasswordArgument) {
        return SecretInput.read(label,
                "--password-file/--client-secret-file", passwordFile,
                "--password-stdin/--client-secret-stdin", passwordStdin,
                "--password/--client-secret", password,
                allowPasswordArgument,
                prompt);
    }
}
