/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Credential storage and secret handling for the SASL initiation filter.
 * <p>
 * Credentials are stored in a PKCS12 KeyStore, one {@link java.security.KeyStore.SecretKeyEntry} per identity. The
 * entry alias is the lowercase hexadecimal SHA-256 digest of the UTF-8 subject, and the entry payload is a versioned
 * JSON document. See {@link com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialEntryCodec} for the v1 schema
 * and {@link com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore} for loading and validation.
 * </p>
 * <p>
 * Secrets are wrapped in {@link com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret} where practical.
 * This reduces avoidable copies and allows deterministic zeroization of those buffers, but it does not eliminate the
 * residual risk of secret material in the JVM heap: the KeyStore JSON is decoded through Jackson, {@link String}
 * instances are immutable, and Kafka/JVM internals make further copies. Do not interpret zeroization as a complete
 * memory-protection guarantee.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
