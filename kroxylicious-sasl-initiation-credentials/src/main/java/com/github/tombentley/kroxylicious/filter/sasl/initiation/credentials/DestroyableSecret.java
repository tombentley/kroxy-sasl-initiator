/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.util.Arrays;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A secret held in a mutable {@code char[]} or {@code byte[]} that can be zeroized deterministically.
 * <p>
 * The factory methods take ownership of the supplied array. The caller must not keep or use the array after handing
 * it to this class; doing so would bypass the zeroization performed by {@link #destroy()}.
 * </p>
 * <p>
 * Destroying is idempotent. Accessors return defensive copies so callers cannot accidentally retain a reference to the
 * internally owned buffer. This class never includes secret material in {@link #toString()}.
 * </p>
 * <p>
 * Zeroization is best effort: the JVM, Jackson, Kafka and other libraries may have made additional copies that this
 * class cannot reach. See the package documentation for the residual heap risk.
 * </p>
 */
public final class DestroyableSecret implements AutoCloseable {

    private static final String REDACTED = "REDACTED";

    private final Object lock = new Object();
    private @Nullable char[] chars;
    private @Nullable byte[] bytes;
    private boolean destroyed;

    private DestroyableSecret(char[] chars) {
        this.chars = chars;
    }

    private DestroyableSecret(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Creates a secret that owns the given character array.
     *
     * @param secret the secret material; ownership transfers to the returned object
     * @return a new destroyable secret
     */
    public static DestroyableSecret of(char[] secret) {
        return new DestroyableSecret(Objects.requireNonNull(secret, "secret"));
    }

    /**
     * Creates a secret that owns the given byte array.
     *
     * @param secret the secret material; ownership transfers to the returned object
     * @return a new destroyable secret
     */
    public static DestroyableSecret of(byte[] secret) {
        return new DestroyableSecret(Objects.requireNonNull(secret, "secret"));
    }

    /**
     * Creates a secret by copying the characters of the given string. The immutable string remains on the heap and
     * cannot be zeroized; callers should prefer the array-based factories when they control the source.
     *
     * @param secret the secret string
     * @return a new destroyable secret
     */
    public static DestroyableSecret of(String secret) {
        Objects.requireNonNull(secret, "secret");
        return new DestroyableSecret(secret.toCharArray());
    }

    /**
     * Returns a copy of the character secret.
     *
     * @return a defensive copy of the secret characters
     * @throws IllegalStateException if the secret has been destroyed or holds byte material
     */
    public char[] chars() {
        synchronized (lock) {
            if (destroyed) {
                throw new IllegalStateException("Secret has already been destroyed");
            }
            if (chars == null) {
                throw new IllegalStateException("Secret does not contain character data");
            }
            return chars.clone();
        }
    }

    /**
     * Returns a copy of the byte secret.
     *
     * @return a defensive copy of the secret bytes
     * @throws IllegalStateException if the secret has been destroyed or holds character material
     */
    public byte[] bytes() {
        synchronized (lock) {
            if (destroyed) {
                throw new IllegalStateException("Secret has already been destroyed");
            }
            if (bytes == null) {
                throw new IllegalStateException("Secret does not contain byte data");
            }
            return bytes.clone();
        }
    }

    /**
     * Returns the length of the secret material.
     *
     * @return the number of characters or bytes
     */
    public int length() {
        synchronized (lock) {
            if (destroyed) {
                return 0;
            }
            return chars != null ? chars.length : bytes.length;
        }
    }

    /**
     * Reports whether this secret has been destroyed.
     *
     * @return {@code true} if the material has been zeroized
     */
    public boolean isDestroyed() {
        synchronized (lock) {
            return destroyed;
        }
    }

    /**
     * Zeroizes the secret material. Calling this method more than once has no additional effect.
     */
    public void destroy() {
        synchronized (lock) {
            if (destroyed) {
                return;
            }
            if (chars != null) {
                Arrays.fill(chars, '\0');
            }
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
            chars = null;
            bytes = null;
            destroyed = true;
        }
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public String toString() {
        return "DestroyableSecret[" + REDACTED + "]";
    }
}
