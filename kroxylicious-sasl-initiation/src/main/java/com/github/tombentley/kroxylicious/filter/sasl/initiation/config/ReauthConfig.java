/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

/**
 * Reauthentication timing configuration.
 *
 * @param windowFactor the fraction of the effective session lifetime at which reauthentication is attempted; defaults
 *            to {@value #DEFAULT_WINDOW_FACTOR}
 */
public record ReauthConfig(Double windowFactor) {

    /**
     * The default reauthentication window factor.
     */
    public static final double DEFAULT_WINDOW_FACTOR = 0.8;

    /**
     * The smallest permitted reauthentication window factor.
     */
    public static final double MIN_WINDOW_FACTOR = 0.5;

    /**
     * The largest permitted reauthentication window factor.
     */
    public static final double MAX_WINDOW_FACTOR = 0.95;

    /**
     * Creates a reauthentication configuration using the default window factor.
     */
    public ReauthConfig() {
        this(DEFAULT_WINDOW_FACTOR);
    }

    /**
     * Validates the reauthentication configuration.
     */
    public ReauthConfig {
        if (windowFactor == null) {
            windowFactor = DEFAULT_WINDOW_FACTOR;
        }
        if (!Double.isFinite(windowFactor) || windowFactor < MIN_WINDOW_FACTOR || windowFactor > MAX_WINDOW_FACTOR) {
            throw new IllegalArgumentException(
                    "reauth.windowFactor must be between " + MIN_WINDOW_FACTOR + " and " + MAX_WINDOW_FACTOR
                            + " inclusive; configured value was " + windowFactor);
        }
    }
}
