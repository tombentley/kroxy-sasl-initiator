/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Black-box system tests for the packaged SASL initiation plugin.
 * <p>
 * These tests start a Testcontainers Kafka broker and the released Kroxylicious distribution as a subprocess. They do
 * not link against the production filter classes: the only production artifacts involved are the jars copied into the
 * distribution's {@code classpath-plugins} directory.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package io.github.tombentley.kroxylicious.filter.sasl.initiation.system;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
