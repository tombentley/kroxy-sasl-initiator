/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Assertion helpers that compare secret material without including it in failure messages.
 */
final class SecretAssertions {

    private SecretAssertions() {
    }

    static void assertCharsEqual(DestroyableSecret secret, String expected) {
        char[] actual = secret.chars();
        char[] expectedChars = expected.toCharArray();
        try {
            assertTrue(Arrays.equals(actual, expectedChars), "secret character content does not match");
        }
        finally {
            Arrays.fill(actual, '\0');
            Arrays.fill(expectedChars, '\0');
        }
    }

    static void assertBytesEqual(DestroyableSecret secret, byte[] expected) {
        byte[] actual = secret.bytes();
        try {
            assertTrue(Arrays.equals(actual, expected), "secret byte content does not match");
        }
        finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    static void assertStringSecretEqual(String actual, String expected) {
        assertTrue(expected.equals(actual), "secret string content does not match");
    }
}
