/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import io.kroxylicious.proxy.filter.FilterContext;

/**
 * An identity selector that always returns a configured lookup key.
 * <p>
 * The downstream subject is intentionally ignored. Fixed identity is shared by every connection using the filter
 * instance and does not change if the client's subject changes.
 * </p>
 */
public final class FixedIdentitySelector implements IdentitySelector {

    private final String key;

    /**
     * Creates a fixed identity selector.
     *
     * @param key the credential lookup key
     */
    public FixedIdentitySelector(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("fixed identity key must not be blank");
        }
        this.key = key;
    }

    /**
     * Returns the configured lookup key.
     *
     * @return the lookup key
     */
    public String key() {
        return key;
    }

    @Override
    public IdentitySnapshot select(FilterContext context) {
        return IdentitySnapshot.forKey(key);
    }
}
