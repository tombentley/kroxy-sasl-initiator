/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A sanitized failure from the upstream SASL initiation exchange.
 * <p>
 * Messages in this exception are safe to log and never contain broker error text, SASL payloads, usernames or secrets.
 * </p>
 */
final class SaslExchangeException extends RuntimeException {

    private final short brokerErrorCode;

    /**
     * Creates a failure without a broker error code.
     *
     * @param message a sanitized description
     */
    SaslExchangeException(String message) {
        this(message, null, (short) -1);
    }

    /**
     * Creates a failure with a cause.
     *
     * @param message a sanitized description
     * @param cause the underlying cause, which is not exposed to the client
     */
    SaslExchangeException(String message, @Nullable Throwable cause) {
        this(message, cause, (short) -1);
    }

    /**
     * Creates a failure caused by a broker error response.
     *
     * @param message a sanitized description
     * @param brokerErrorCode the broker's error code
     */
    SaslExchangeException(String message, short brokerErrorCode) {
        this(message, null, brokerErrorCode);
    }

    private SaslExchangeException(String message, @Nullable Throwable cause, short brokerErrorCode) {
        super(message, cause);
        this.brokerErrorCode = brokerErrorCode;
    }

    /**
     * Returns the broker error code, or {@code -1} when the failure was not caused by a broker error response.
     *
     * @return the broker error code
     */
    short brokerErrorCode() {
        return brokerErrorCode;
    }
}
