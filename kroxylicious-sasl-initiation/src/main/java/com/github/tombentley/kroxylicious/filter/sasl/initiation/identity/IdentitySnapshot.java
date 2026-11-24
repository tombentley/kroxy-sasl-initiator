/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * An immutable snapshot of the identity selected for a connection.
 * <p>
 * The lookup key selects the KeyStore entry. The principal set is a stable, immutable representation of all principals
 * present in the downstream subject when the snapshot was taken; it can be retained after the request callback to
 * detect a later identity change without retaining the deprecated subject object.
 * </p>
 *
 * @param lookupKey the credential lookup key
 * @param principals the principal type/name pairs captured with the identity
 */
public record IdentitySnapshot(String lookupKey, Set<PrincipalIdentity> principals) {

    /**
     * Validates and defensively copies the snapshot.
     */
    public IdentitySnapshot {
        if (lookupKey == null || lookupKey.isBlank()) {
            throw new IllegalArgumentException("identity lookup key must not be blank");
        }
        principals = Collections.unmodifiableSet(new LinkedHashSet<>(
                Objects.requireNonNull(principals, "principals")));
    }

    /**
     * Creates a snapshot for a fixed identity, which has no downstream principal set.
     *
     * @param lookupKey the credential lookup key
     * @return a snapshot with no principals
     */
    public static IdentitySnapshot forKey(String lookupKey) {
        return new IdentitySnapshot(lookupKey, Set.of());
    }

    /**
     * Creates a fixed-identity snapshot with no principal set.
     *
     * @param lookupKey the credential lookup key
     */
    public IdentitySnapshot(String lookupKey) {
        this(lookupKey, Set.of());
    }

    /**
     * Reports whether this snapshot differs from a previous snapshot. This is equivalent to negating record equality
     * and is provided to make subject-change checks read naturally.
     *
     * @param previous the previous snapshot, or {@code null} if there was none
     * @return {@code true} if the previous snapshot is absent or different
     */
    public boolean hasChangedFrom(IdentitySnapshot previous) {
        return !equals(previous);
    }

    /**
     * Reports whether this snapshot has the same identity as another snapshot.
     *
     * @param other the other snapshot, or {@code null}
     * @return {@code true} if both snapshots are equal
     */
    public boolean sameIdentityAs(IdentitySnapshot other) {
        return equals(other);
    }
}
