/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * The SASL initiation filter and its protocol handling.
 * <p>
 * The filter authenticates the proxy to the upstream broker on behalf of the downstream client. It never impersonates a
 * client authentication outcome; downstream authentication belongs to a separate filter such as
 * {@code SaslTermination}.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
