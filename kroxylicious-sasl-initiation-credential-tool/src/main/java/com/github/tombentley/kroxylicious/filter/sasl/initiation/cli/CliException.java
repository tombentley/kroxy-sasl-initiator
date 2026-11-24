/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

/**
 * A failure that should be reported to the user as a concise error message.
 * <p>
 * Messages are printed to standard error and must never contain passwords, client secrets, store passwords, entry
 * payloads or KeyStore aliases.
 * </p>
 */
final class CliException extends RuntimeException {

    CliException(String message) {
        super(message);
    }

    CliException(String message, Throwable cause) {
        super(message, cause);
    }
}
