/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import picocli.CommandLine.Option;

/**
 * The explicit acknowledgement required before a secret may be supplied as a command-line argument.
 */
final class InsecureOptions {

    @Option(names = "--insecure-allow-password-argument", description = "Explicitly allow secrets to be passed with --password or --store-password. "
            + "SECURITY WARNING: command-line arguments are visible to other users in process listings, "
            + "may be retained in shell history and may be captured by process accounting or logs.")
    boolean insecureAllowPasswordArgument;
}
