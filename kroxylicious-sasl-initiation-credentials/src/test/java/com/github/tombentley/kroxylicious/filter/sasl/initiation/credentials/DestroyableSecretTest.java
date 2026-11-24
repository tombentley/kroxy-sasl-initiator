/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DestroyableSecretTest {

    @Test
    void zeroizesCharacterMaterial() {
        char[] material = "super-secret-password".toCharArray();
        DestroyableSecret secret = DestroyableSecret.of(material);

        SecretAssertions.assertCharsEqual(secret, "super-secret-password");
        secret.destroy();

        assertThat(material).containsOnly('\0');
        assertThat(secret.isDestroyed()).isTrue();
    }

    @Test
    void zeroizesByteMaterial() {
        byte[] material = "super-secret-password".getBytes(StandardCharsets.UTF_8);
        DestroyableSecret secret = DestroyableSecret.of(material);

        SecretAssertions.assertBytesEqual(secret, "super-secret-password".getBytes(StandardCharsets.UTF_8));
        secret.destroy();

        assertThat(material).containsOnly((byte) 0);
        assertThat(secret.isDestroyed()).isTrue();
    }

    @Test
    void destroyingIsIdempotent() {
        DestroyableSecret secret = DestroyableSecret.of("secret".toCharArray());

        secret.destroy();
        secret.destroy();

        assertThat(secret.isDestroyed()).isTrue();
    }

    @Test
    void accessorsReturnDefensiveCopies() {
        DestroyableSecret secret = DestroyableSecret.of("secret".toCharArray());

        char[] first = secret.chars();
        first[0] = 'X';
        char[] second = secret.chars();
        try {
            assertTrue(Arrays.equals("secret".toCharArray(), second), "secret content was modified through an accessor copy");
        }
        finally {
            Arrays.fill(first, '\0');
            Arrays.fill(second, '\0');
        }
    }

    @Test
    void rejectsAccessAfterDestroy() {
        DestroyableSecret secret = DestroyableSecret.of("secret".toCharArray());
        secret.destroy();

        assertThatThrownBy(secret::chars).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(secret::bytes).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsWrongMaterialType() {
        DestroyableSecret characters = DestroyableSecret.of("secret".toCharArray());
        DestroyableSecret bytes = DestroyableSecret.of(new byte[]{ 1, 2, 3 });

        assertThatThrownBy(characters::bytes).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(bytes::chars).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void closeDestroys() {
        char[] material = "secret".toCharArray();
        try (DestroyableSecret secret = DestroyableSecret.of(material)) {
            assertThat(secret.isDestroyed()).isFalse();
        }

        assertThat(material).containsOnly('\0');
    }

    @Test
    void toStringNeverContainsTheSecret() {
        String secretValue = "toString-must-not-show-this";
        DestroyableSecret secret = DestroyableSecret.of(secretValue.toCharArray());
        try {
            assertFalse(secret.toString().contains(secretValue), "toString leaked the secret");
            assertThat(secret.toString()).contains("REDACTED");
        }
        finally {
            secret.destroy();
        }
    }
}
