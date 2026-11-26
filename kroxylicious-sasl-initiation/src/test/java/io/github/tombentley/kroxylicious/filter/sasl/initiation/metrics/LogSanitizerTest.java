/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.metrics;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LogSanitizerTest {

    @Test
    void stripsCarriageReturnsAndLineFeeds() {
        assertThat(LogSanitizer.sanitize("first\r\nsecond\nthird\rfourth"))
                .isEqualTo("first  second third fourth");
    }

    @Test
    void stripsOtherControlCharacters() {
        assertThat(LogSanitizer.sanitize("before\u0000after\u0007tab\there"))
                .isEqualTo("beforeaftertabhere");
    }

    @Test
    void preservesOrdinaryText() {
        assertThat(LogSanitizer.sanitize("The broker rejected the SASL handshake"))
                .isEqualTo("The broker rejected the SASL handshake");
    }

    @Test
    void truncatesLongMessages() {
        String message = "x".repeat(LogSanitizer.MAX_MESSAGE_LENGTH + 50);

        String sanitized = LogSanitizer.sanitize(message);

        assertThat(sanitized).hasSize(LogSanitizer.MAX_MESSAGE_LENGTH);
        assertThat(sanitized).endsWith("...");
    }

    @Test
    void returnsAnEmptyStringForNullAndEmptyMessages() {
        assertThat(LogSanitizer.sanitize(null)).isEmpty();
        assertThat(LogSanitizer.sanitize("")).isEmpty();
    }
}
