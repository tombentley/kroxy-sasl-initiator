/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * OAuth bearer token retrieval, validation and caching for SASL initiation.
 * <p>
 * Token retrieval is blocking and always runs on a dedicated worker executor. Retrieved tokens are cached per identity
 * in a bounded cache that refreshes before expiry, and validation failures are reported with sanitized exceptions that
 * never contain the token or an OAuth client secret.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package io.github.tombentley.kroxylicious.filter.sasl.initiation.oauth;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
