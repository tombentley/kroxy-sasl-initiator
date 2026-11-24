/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.nio.file.Path;

import picocli.CommandLine.Option;

/**
 * Common options identifying the credential store file.
 */
final class FileOptions {

    @Option(names = "--file", required = true, paramLabel = "<path>", description = "Path to the PKCS12 credential store.")
    Path file;
}
