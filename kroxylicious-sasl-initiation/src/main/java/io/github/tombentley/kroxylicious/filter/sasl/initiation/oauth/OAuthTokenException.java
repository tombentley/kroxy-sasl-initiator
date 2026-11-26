/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.oauth;

/**
 * A sanitized failure to obtain or validate an OAuth bearer token.
 * <p>
 * The message is safe to log: it never contains the token, an OAuth client secret or the text of an underlying
 * retriever/validator exception. Deliberately no cause is retained, because third-party exception messages can
 * include token values or request details.
 * </p>
 */
public final class OAuthTokenException extends RuntimeException {

    /**
     * Creates a sanitized token failure.
     *
     * @param message a description that contains no secret material
     */
    OAuthTokenException(String message) {
        super(message);
    }
}
