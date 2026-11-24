/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Identity selection for the SASL initiation filter.
 * <p>
 * Fixed and subject identity modes are supported with no fallback. The deprecated proxy authentication subject API is
 * isolated in {@link com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentityAdapter}; the rest of
 * the filter consumes immutable {@link com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySnapshot}
 * values.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package com.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
