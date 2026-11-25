/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.oauth;

import java.util.Set;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An immutable {@link OAuthBearerToken} whose string form redacts the token value.
 * <p>
 * Kafka's own token implementations include the bearer token in {@link Object#toString()}. Wrapping the validated
 * token before it is cached or passed around prevents accidental disclosure through logs or exception messages.
 * </p>
 */
final class RedactedOAuthBearerToken implements OAuthBearerToken {

    private final String value;
    private final Set<String> scope;
    private final long lifetimeMs;
    private final String principalName;
    private final @Nullable Long startTimeMs;

    RedactedOAuthBearerToken(OAuthBearerToken token) {
        this.value = token.value();
        this.scope = Set.copyOf(token.scope());
        this.lifetimeMs = token.lifetimeMs();
        this.principalName = token.principalName();
        this.startTimeMs = token.startTimeMs();
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public Set<String> scope() {
        return scope;
    }

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public @Nullable Long startTimeMs() {
        return startTimeMs;
    }

    @Override
    public String toString() {
        return "OAuthBearerToken[principalName=" + principalName
                + ", lifetimeMs=" + lifetimeMs
                + ", scope=" + scope
                + ", token=REDACTED]";
    }
}
