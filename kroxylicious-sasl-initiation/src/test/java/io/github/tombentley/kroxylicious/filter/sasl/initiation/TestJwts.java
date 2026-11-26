/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Creates unsecured JWT strings for OAUTHBEARER protocol tests. Kafka's client-side validator only decodes the token;
 * the test fake broker performs the real validation callback.
 */
final class TestJwts {

    private TestJwts() {
    }

    static String validToken(String subject) {
        return validToken(subject, 3_600_000L);
    }

    static String validToken(String subject, long lifetimeMillis) {
        long nowSeconds = System.currentTimeMillis() / 1000L;
        long expirySeconds = nowSeconds + Math.max(1L, lifetimeMillis / 1000L);
        String header = "{\"alg\":\"none\"}";
        String payload = "{\"sub\":\"" + subject + "\",\"iat\":" + nowSeconds
                + ",\"exp\":" + expirySeconds + ",\"scope\":\"kafka\"}";
        return encode(header) + "." + encode(payload) + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString("signature".getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
