/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import java.util.Objects;

import io.kroxylicious.identity.Principal;
import io.kroxylicious.identity.SingularPrincipals;
import io.kroxylicious.proxy.filter.FilterContext;

/**
 * An identity selector that derives the lookup key from the current downstream subject.
 * <p>
 * The subject is read at request time. There is no fixed fallback: anonymous subjects, subjects without a principal of
 * the configured type, and subjects with multiple principals of that type all fail closed.
 * </p>
 */
public final class SubjectIdentitySelector implements IdentitySelector {

    private final Class<? extends Principal> principalType;
    private final IdentityAdapter adapter;

    /**
     * Creates a subject identity selector.
     *
     * @param principalType the singular principal type whose name is the lookup key
     */
    public SubjectIdentitySelector(Class<? extends Principal> principalType) {
        this(principalType, new IdentityAdapter());
    }

    /**
     * Creates a subject identity selector using the supplied adapter.
     *
     * @param principalType the singular principal type whose name is the lookup key
     * @param adapter the adapter used to read the request subject
     */
    public SubjectIdentitySelector(Class<? extends Principal> principalType, IdentityAdapter adapter) {
        this.principalType = Objects.requireNonNull(principalType, "principalType");
        this.adapter = Objects.requireNonNull(adapter, "adapter");
        if (!SingularPrincipals.isSingular(principalType)) {
            throw new IllegalArgumentException(
                    "principal type " + principalType.getName() + " is not a singular principal type");
        }
    }

    /**
     * Returns the configured principal type.
     *
     * @return the principal type
     */
    public Class<? extends Principal> principalType() {
        return principalType;
    }

    @Override
    public IdentitySnapshot select(FilterContext context) {
        return adapter.snapshot(context, principalType);
    }
}
