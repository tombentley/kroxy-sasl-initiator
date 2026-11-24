/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import io.kroxylicious.identity.Identity;
import io.kroxylicious.identity.Principal;
import io.kroxylicious.proxy.filter.FilterContext;

/**
 * Adapts the deprecated proxy authentication subject API into the filter's immutable {@link IdentitySnapshot}.
 * <p>
 * All use of {@link FilterContext#authenticatedSubject()} and the deprecated
 * {@code io.kroxylicious.proxy.authentication.Subject}/{@code User} types is confined to this class. The rest of the
 * filter works with {@link Principal} and {@link IdentitySnapshot}, so the 1.0 identity API migration stays local.
 * </p>
 * <p>
 * A snapshot is always taken from the supplied request context; this class never caches a subject across requests.
 * Selection fails closed if the subject is anonymous or if the configured principal type is absent.
 * </p>
 * <p>
 * The principal type must be a {@linkplain io.kroxylicious.identity.SingularPrincipals#isSingular(Class) singular}
 * principal type. That is validated when the identity configuration is resolved, and identity implementations enforce
 * at most one principal of such a type, so no ambiguity check is needed per request.
 * </p>
 */
public final class IdentityAdapter {

    private static final Comparator<PrincipalIdentity> PRINCIPAL_ORDER = Comparator
            .comparing(PrincipalIdentity::type)
            .thenComparing(PrincipalIdentity::name);

    /**
     * Creates an identity adapter.
     */
    public IdentityAdapter() {
        // Intentionally empty.
    }

    /**
     * Takes a snapshot of the request's current authenticated subject.
     * <p>
     * This method reads {@link FilterContext#authenticatedSubject()} at call time. Callers must invoke it per request;
     * a snapshot must not be reused as a substitute for re-reading the subject.
     * </p>
     *
     * @param context the current request context
     * @param principalType the singular principal type whose name is used as the lookup key
     * @return the identity snapshot
     * @throws IdentitySelectionException if the subject is anonymous or missing the principal type
     */
    @SuppressWarnings({ "deprecation", "removal", "java:S5738" })
    public IdentitySnapshot snapshot(FilterContext context, Class<? extends Principal> principalType) {
        Objects.requireNonNull(context, "context");
        return snapshot(context.authenticatedSubject(), principalType);
    }

    /**
     * Takes a snapshot of the given identity.
     *
     * @param identity the authenticated identity
     * @param principalType the singular principal type whose name is used as the lookup key
     * @return the identity snapshot
     * @throws IdentitySelectionException if the identity is anonymous or missing the principal type
     */
    public IdentitySnapshot snapshot(Identity identity, Class<? extends Principal> principalType) {
        Objects.requireNonNull(principalType, "principalType");
        if (identity == null) {
            throw new IdentitySelectionException(
                    "No authenticated subject is available; subject identity mode requires an authenticated client");
        }

        Set<? extends Principal> allPrincipals = identity.principals();
        if (allPrincipals.isEmpty()) {
            throw new IdentitySelectionException(
                    "The authenticated subject is anonymous; subject identity mode requires an authenticated client");
        }

        // The principal type is singular, which was validated when the configuration was resolved, so a valid subject
        // cannot contain more than one principal of this type.
        Principal selected = allPrincipals.stream()
                .filter(principalType::isInstance)
                .findFirst()
                .orElseThrow(() -> new IdentitySelectionException(
                        "The authenticated subject " + identity + " has no principal of type " + principalType.getName()
                                + "; configure identity.principalType to a singular principal type guaranteed to be present in the authenticated subject"));
        String lookupKey = selected.name();
        if (lookupKey == null || lookupKey.isBlank()) {
            throw new IdentitySelectionException(
                    "The selected principal of type " + principalType.getName() + " has a blank name");
        }

        Set<PrincipalIdentity> captured = new LinkedHashSet<>();
        for (Principal principal : allPrincipals) {
            String name = principal.name();
            if (name == null || name.isBlank()) {
                throw new IdentitySelectionException(
                        "The authenticated subject contains a principal of type " + principal.getClass().getName()
                                + " with a blank name");
            }
            captured.add(new PrincipalIdentity(principal.getClass().getName(), name));
        }
        Set<PrincipalIdentity> ordered = captured.stream()
                .sorted(PRINCIPAL_ORDER)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return new IdentitySnapshot(lookupKey, ordered);
    }
}
