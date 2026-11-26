/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.kroxylicious.identity.Principal;
import io.kroxylicious.identity.SingularPrincipals;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * The identity selection part of the filter configuration.
 *
 * @param mode how the credential lookup key is selected
 * @param key the fixed lookup key; required in fixed mode and forbidden in subject mode
 * @param principalType the fully-qualified singular principal type used in subject mode; defaults to
 *            {@value #DEFAULT_PRINCIPAL_TYPE}
 */
public record IdentityConfig(
                             @JsonProperty(required = true) IdentityMode mode,
                             @Nullable String key,
                             @Nullable String principalType) {

    /**
     * The default principal type used in subject mode.
     */
    public static final String DEFAULT_PRINCIPAL_TYPE = "io.kroxylicious.proxy.authentication.User";

    /**
     * Creates an identity configuration with the default subject principal type.
     *
     * @param mode the identity mode
     * @param key the fixed lookup key
     */
    public IdentityConfig(IdentityMode mode, String key) {
        this(mode, key, null);
    }

    /**
     * Validates the identity configuration.
     */
    public IdentityConfig {
        if (mode == null) {
            throw new IllegalArgumentException("identity.mode is required and must be 'fixed' or 'subject'");
        }
        if (mode == IdentityMode.FIXED) {
            if (key != null && key.isBlank()) {
                throw new IllegalArgumentException("identity.key must not be blank when configured");
            }
            if (principalType != null && !principalType.isBlank()) {
                throw new IllegalArgumentException(
                        "identity.principalType is only valid in subject mode; remove it or set identity.mode to 'subject'");
            }
            principalType = null;
        }
        else {
            if (key != null) {
                throw new IllegalArgumentException(
                        "identity.key is not valid in subject mode; use identity.principalType to choose the lookup principal");
            }
            if (principalType == null || principalType.isBlank()) {
                principalType = DEFAULT_PRINCIPAL_TYPE;
            }
            principalType = resolvePrincipalType(principalType).getName();
        }
    }

    /**
     * Resolves and validates the configured principal type.
     *
     * @param className the fully-qualified principal class name
     * @return the resolved principal class
     * @throws IllegalArgumentException if the class is missing, is not a principal, or is not singular
     */
    public static Class<? extends Principal> resolvePrincipalType(@Nullable String className) {
        if (className == null || className.isBlank()) {
            throw new IllegalArgumentException("identity.principalType must not be blank in subject mode");
        }
        final Class<?> loaded;
        try {
            loaded = Class.forName(className);
        }
        catch (ClassNotFoundException e) {
            throw new IllegalArgumentException(
                    "identity.principalType '" + className + "' was not found on the classpath", e);
        }
        if (!Principal.class.isAssignableFrom(loaded)) {
            throw new IllegalArgumentException(
                    "identity.principalType '" + className + "' does not implement " + Principal.class.getName());
        }
        if (!SingularPrincipals.isSingular(loaded)) {
            throw new IllegalArgumentException(
                    "identity.principalType '" + className + "' is not a singular principal type; annotate it with "
                            + SingularPrincipals.class.getPackageName() + ".SingularPrincipal (or @Unique)");
        }
        return loaded.asSubclass(Principal.class);
    }

    /**
     * Resolves the configured principal type. The type was already validated by the canonical constructor.
     *
     * @return the resolved principal class
     */
    public Class<? extends Principal> principalClass() {
        if (principalType == null) {
            throw new IllegalStateException("identity.principalType is not configured; it is required in subject mode");
        }
        return resolvePrincipalType(principalType);
    }
}
