/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

/**
 * An immutable principal type/name pair captured from an authenticated subject.
 * <p>
 * The type is the principal implementation's fully-qualified class name. The pair deliberately does not retain the
 * principal or subject object, which keeps deprecated identity API types out of cached state and makes snapshots safe
 * to compare across requests.
 * </p>
 *
 * @param type the principal implementation's fully-qualified class name
 * @param name the principal name
 */
public record PrincipalIdentity(String type, String name) {

    /**
     * Validates the principal identity.
     */
    public PrincipalIdentity {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("principal type must not be blank");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("principal name must not be blank");
        }
    }

    /**
     * Returns the principal implementation's fully-qualified class name.
     *
     * @return the principal type
     */
    public String principalType() {
        return type;
    }

    /**
     * Returns the principal name.
     *
     * @return the principal name
     */
    public String principalName() {
        return name;
    }
}
