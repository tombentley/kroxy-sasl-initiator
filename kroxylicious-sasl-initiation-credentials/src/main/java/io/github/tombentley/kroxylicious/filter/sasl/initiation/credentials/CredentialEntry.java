/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

/**
 * The versioned model of one JSON credential entry stored in the KeyStore.
 * <p>
 * Version 1 has two shapes:
 * </p>
 * <pre>{@code
 * {"version":1,"subject":"alice","username":"alice","password":"..."}
 * }</pre>
 * <pre>{@code
 * {"version":1,"subject":"alice","oauthBearer":{"clientId":"...","clientSecret":"...","expectedSubject":"alice"}}
 * }</pre>
 * <p>
 * Both shapes are represented by this sealed interface. Use {@link CredentialEntryCodec} to encode and decode the JSON.
 * </p>
 * <p>
 * The model holds secrets as {@link String} values because that is how JSON text is normally represented. This means
 * the immutable strings remain on the heap even after {@link #toCredential()} has copied them into a
 * {@link DestroyableSecret}; it is an accepted residual risk. Do not include these values in logs, exceptions or
 * {@link Object#toString()} output.
 * </p>
 */
public sealed interface CredentialEntry permits PasswordCredentialEntry, OAuthCredentialEntry {

    /**
     * The only schema version understood by this implementation.
     */
    int CURRENT_VERSION = 1;

    /**
     * Returns the schema version of this entry.
     *
     * @return the schema version, always {@value #CURRENT_VERSION} for valid entries
     */
    int version();

    /**
     * Returns the subject (lookup key) the entry is intended for.
     *
     * @return the subject
     */
    String subject();

    /**
     * Returns the credential kind represented by this entry.
     *
     * @return the credential kind
     */
    CredentialKind kind();

    /**
     * Creates a runtime credential from this entry. Secret values are copied into {@link DestroyableSecret} instances.
     * The returned credential owns its own secret material and should be destroyed when no longer needed.
     *
     * @return a runtime credential
     */
    Credential toCredential();
}
