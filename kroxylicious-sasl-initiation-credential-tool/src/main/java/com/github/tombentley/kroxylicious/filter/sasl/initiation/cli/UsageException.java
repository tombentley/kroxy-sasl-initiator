/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

/**
 * A command-line usage failure, such as requesting an insecure option without its explicit gate.
 */
final class UsageException extends RuntimeException {

    UsageException(String message) {
        super(message);
    }
}
