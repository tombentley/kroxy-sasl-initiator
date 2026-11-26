/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

/**
 * A credential used by a SASL initiation mechanism.
 * <p>
 * A credential owns the secret wrapper returned by its accessor. Call {@link #destroy()} (or {@link #close()}) when
 * the credential is no longer needed; both are idempotent. Implementations must never include secret material in
 * {@link Object#toString()}.
 * </p>
 */
public sealed interface Credential extends AutoCloseable permits PasswordCredential, OAuthClientCredential {

    /**
     * Destroys the secret material held by this credential. Calling this method more than once has no additional
     * effect.
     */
    void destroy();

    @Override
    default void close() {
        destroy();
    }
}
