/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import io.kroxylicious.proxy.filter.FilterContext;

/**
 * Selects the credential lookup key and identity snapshot for a request.
 * <p>
 * Implementations are shared across connections and must be thread-safe. Implementations that depend on the
 * downstream subject must read it from the supplied {@link FilterContext} on every call; they must not cache a subject
 * across requests.
 * </p>
 */
public interface IdentitySelector {

    /**
     * Selects the identity for the current request.
     *
     * @param context the current request context
     * @return the identity snapshot
     * @throws IdentitySelectionException if the configured identity cannot be selected
     */
    IdentitySnapshot select(FilterContext context);

    /**
     * Selects the identity for the current request.
     *
     * @param context the current request context
     * @return the identity snapshot
     * @throws IdentitySelectionException if the configured identity cannot be selected
     */
    default IdentitySnapshot selectIdentity(FilterContext context) {
        return select(context);
    }
}
