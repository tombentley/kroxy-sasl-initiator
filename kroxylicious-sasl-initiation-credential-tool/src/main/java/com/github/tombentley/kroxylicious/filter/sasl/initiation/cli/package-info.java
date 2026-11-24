/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Command line tooling for managing SASL initiation credentials.
 * <p>
 * The tool manipulates the versioned PKCS12 credential store used by the filter. It never prints passwords, client
 * secrets, KeyStore aliases or raw entry bytes.
 * </p>
 */
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
@SuppressFBWarnings(value = "NP_NONNULL_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR", justification = "Command fields are populated by picocli before the command runs")
package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
