/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.identity;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.kroxylicious.proxy.filter.FilterContext;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Detects a change in the downstream identity after upstream authentication.
 * <p>
 * In subject mode the guard remembers the immutable {@link IdentitySnapshot} selected at the authentication trigger and
 * compares it with the subject read from every later request. Any change, including a change to an anonymous subject,
 * fails closed. It never reauthenticates as the new identity.
 * </p>
 * <p>
 * In fixed mode the guard is disabled: the configured identity is shared and is intentionally independent of the
 * client subject.
 * </p>
 * <p>
 * Instances are per connection and are only used on the connection's filter-dispatch thread.
 * </p>
 */
public final class IdentityGuard {

    private static final Logger LOGGER = LoggerFactory.getLogger(IdentityGuard.class);

    private final @Nullable IdentitySelector selector;
    private @Nullable IdentitySnapshot expected;

    private IdentityGuard(@Nullable IdentitySelector selector) {
        this.selector = selector;
    }

    /**
     * Returns a guard that does nothing. Used by fixed identity mode.
     *
     * @return a disabled guard
     */
    public static IdentityGuard disabled() {
        return new IdentityGuard(null);
    }

    /**
     * Returns a guard that verifies the downstream subject against the snapshot taken at the trigger point.
     *
     * @param selector the subject identity selector
     * @return an enabled guard
     */
    public static IdentityGuard forSubject(IdentitySelector selector) {
        return new IdentityGuard(Objects.requireNonNull(selector, "selector"));
    }

    /**
     * Reports whether this guard checks the downstream subject.
     *
     * @return {@code true} in subject mode
     */
    public boolean isEnabled() {
        return selector != null;
    }

    /**
     * Records the identity selected at the trigger point.
     *
     * @param identity the identity used to look up the broker credential
     */
    public void expect(IdentitySnapshot identity) {
        if (selector == null) {
            return;
        }
        expected = Objects.requireNonNull(identity, "identity");
    }

    /**
     * Reads the current downstream identity and verifies that it has not changed from the expected snapshot.
     *
     * @param context the current request context
     * @throws IdentitySelectionException if the subject is no longer eligible or has changed
     */
    public void verify(FilterContext context) {
        IdentitySelector currentSelector = selector;
        if (currentSelector == null) {
            return;
        }
        IdentitySnapshot snapshot = expected;
        if (snapshot == null) {
            throw new IdentitySelectionException(
                    "No identity snapshot has been recorded; refusing to continue after upstream authentication");
        }
        IdentitySnapshot current = currentSelector.select(context);
        if (current.hasChangedFrom(snapshot)) {
            LOGGER.atWarn()
                    .addKeyValue("previousSubject", snapshot.lookupKey())
                    .addKeyValue("currentSubject", current.lookupKey())
                    .log("The downstream subject changed after SASL authentication; closing the connection");
            throw new IdentitySelectionException(
                    "The downstream subject changed after SASL authentication; refusing to continue");
        }
    }
}
