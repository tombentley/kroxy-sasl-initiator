/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Configuration model for the SASL initiation filter.
 * <p>
 * Configuration records validate their inputs in compact constructors. Values that are optional in the plugin
 * configuration are represented by {@link java.util.Optional} or defaulted during validation rather than leaking a
 * {@code null} into the running filter.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package io.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
