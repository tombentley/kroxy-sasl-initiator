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
package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;
