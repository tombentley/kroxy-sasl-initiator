/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.oauth;

import java.time.Clock;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

/**
 * A bounded, expiring, single-flight cache of validated OAuth bearer tokens.
 * <p>
 * A cache entry is reused until its refresh instant, which is a safety margin before the token's expiry. Concurrent
 * requests for the same lookup key share one retrieval. The cache never grows beyond {@value #MAX_ENTRIES} entries:
 * expired entries are removed first, and the oldest remaining entry is evicted when necessary.
 * </p>
 * <p>
 * Retrieval runs on the supplied executor; callers must not use {@link #get(String, TokenLoader)} from a thread that
 * is not allowed to block. This class never includes token values in its string form.
 * </p>
 */
final class OAuthTokenCache implements AutoCloseable {

    static final int MAX_ENTRIES = 1024;

    private static final long MAX_SAFETY_MARGIN_MS = 60_000L;

    /**
     * Loads a token. Implementations may block.
     */
    @FunctionalInterface
    interface TokenLoader {
        OAuthBearerToken load();
    }

    private final Clock clock;
    private final Executor executor;
    private final Map<String, CachedToken> tokens = new LinkedHashMap<>();
    private final Map<String, CompletableFuture<OAuthBearerToken>> inFlight = new HashMap<>();
    private boolean closed;

    OAuthTokenCache(Clock clock, Executor executor) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.executor = Objects.requireNonNull(executor, "executor");
    }

    /**
     * Returns a cached token, or retrieves one on the worker executor.
     *
     * @param lookupKey the cache key
     * @param loader the blocking token loader
     * @return a stage completed with the token
     */
    CompletionStage<OAuthBearerToken> get(String lookupKey, TokenLoader loader) {
        Objects.requireNonNull(lookupKey, "lookupKey");
        Objects.requireNonNull(loader, "loader");

        final CompletableFuture<OAuthBearerToken> result;
        synchronized (this) {
            if (closed) {
                return CompletableFuture.failedFuture(new OAuthTokenException(
                        "The OAuth token service is closed"));
            }
            long now = clock.millis();
            CachedToken cached = tokens.get(lookupKey);
            if (cached != null) {
                if (cached.expiresAtMs() <= now) {
                    tokens.remove(lookupKey);
                }
                else if (now < cached.refreshAtMs()) {
                    return CompletableFuture.completedFuture(cached.token());
                }
            }

            CompletableFuture<OAuthBearerToken> existing = inFlight.get(lookupKey);
            if (existing != null) {
                return existing;
            }

            result = new CompletableFuture<>();
            inFlight.put(lookupKey, result);
        }

        try {
            executor.execute(() -> load(lookupKey, loader, result));
        }
        catch (RuntimeException e) {
            synchronized (this) {
                inFlight.remove(lookupKey, result);
            }
            result.completeExceptionally(new OAuthTokenException("The OAuth token worker could not be scheduled"));
        }
        return result;
    }

    /**
     * Returns the number of cached, unexpired entries. Intended for tests.
     *
     * @return the number of cache entries
     */
    synchronized int size() {
        removeExpired(clock.millis());
        return tokens.size();
    }

    private void load(String lookupKey, TokenLoader loader, CompletableFuture<OAuthBearerToken> result) {
        synchronized (this) {
            if (closed) {
                result.completeExceptionally(new OAuthTokenException("The OAuth token service is closed"));
                inFlight.remove(lookupKey, result);
                return;
            }
        }
        try {
            OAuthBearerToken token = loader.load();
            if (token == null) {
                throw new OAuthTokenException("The OAuth token source returned no token");
            }
            synchronized (this) {
                if (closed) {
                    result.completeExceptionally(new OAuthTokenException("The OAuth token service is closed"));
                    return;
                }
                long now = clock.millis();
                CachedToken entry = new CachedToken(token, now);
                tokens.put(lookupKey, entry);
                removeExpired(now);
                evictOldestUntilBounded();
            }
            result.complete(token);
        }
        catch (RuntimeException e) {
            result.completeExceptionally(sanitize(e));
        }
        finally {
            synchronized (this) {
                inFlight.remove(lookupKey, result);
            }
        }
    }

    private void removeExpired(long now) {
        tokens.entrySet().removeIf(entry -> entry.getValue().expiresAtMs() <= now);
    }

    private void evictOldestUntilBounded() {
        Iterator<String> keys = tokens.keySet().iterator();
        while (tokens.size() > MAX_ENTRIES && keys.hasNext()) {
            keys.next();
            keys.remove();
        }
    }

    private static RuntimeException sanitize(RuntimeException error) {
        if (error instanceof OAuthTokenException) {
            return error;
        }
        return new OAuthTokenException("OAuth token retrieval or validation failed");
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        tokens.clear();
        OAuthTokenException closedFailure = new OAuthTokenException("The OAuth token service is closed");
        inFlight.values().forEach(future -> future.completeExceptionally(closedFailure));
        inFlight.clear();
    }

    @Override
    public String toString() {
        return "OAuthTokenCache[size=" + size() + ", closed=" + isClosed() + "]";
    }

    private synchronized boolean isClosed() {
        return closed;
    }

    private record CachedToken(OAuthBearerToken token, long refreshAtMs, long expiresAtMs) {

        CachedToken {
            Objects.requireNonNull(token, "token");
        }

        CachedToken(OAuthBearerToken token, long nowMs) {
            this(token, refreshAt(token.lifetimeMs(), nowMs), token.lifetimeMs());
        }

        private static long refreshAt(long expiresAtMs, long nowMs) {
            long remaining = Math.max(0L, expiresAtMs - nowMs);
            long safetyMargin = Math.min(MAX_SAFETY_MARGIN_MS, remaining / 10L);
            return expiresAtMs - safetyMargin;
        }

        @Override
        public String toString() {
            return "CachedToken[token=REDACTED, refreshAtMs=" + refreshAtMs + ", expiresAtMs=" + expiresAtMs + "]";
        }
    }
}
