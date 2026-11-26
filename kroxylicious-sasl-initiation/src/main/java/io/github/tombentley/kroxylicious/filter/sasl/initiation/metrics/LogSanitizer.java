/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.metrics;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Sanitizes exception and diagnostic messages before they are written to a log.
 * <p>
 * The sanitizer strips line breaks and other control characters so that a message cannot forge additional log lines,
 * and caps the length so that a broken upstream cannot flood the log. It deliberately cannot detect secrets: callers
 * must only pass messages that are known not to contain passwords, client secrets, bearer tokens, SASL auth bytes or
 * raw broker error payloads. The filter only passes its own sanitized {@code SaslExchangeException} descriptions
 * through this class; broker error text and SASL payloads are never logged.
 * </p>
 */
public final class LogSanitizer {

    /**
     * The maximum number of characters retained from a message.
     */
    public static final int MAX_MESSAGE_LENGTH = 256;

    private static final String TRUNCATED = "...";

    private LogSanitizer() {
        // Utility class.
    }

    /**
     * Strips control characters, normalizes line breaks and truncates a message.
     *
     * @param message the message to sanitize; may be {@code null}
     * @return the sanitized message, never {@code null}
     */
    public static String sanitize(@Nullable String message) {
        if (message == null || message.isEmpty()) {
            return "";
        }
        int limit = Math.min(message.length(), MAX_MESSAGE_LENGTH);
        StringBuilder sanitized = new StringBuilder(limit);
        for (int i = 0; i < limit; i++) {
            char character = message.charAt(i);
            if (character == '\r' || character == '\n') {
                sanitized.append(' ');
            }
            else if (!Character.isISOControl(character)) {
                sanitized.append(character);
            }
        }
        if (message.length() > MAX_MESSAGE_LENGTH) {
            int keep = Math.max(0, MAX_MESSAGE_LENGTH - TRUNCATED.length());
            if (sanitized.length() > keep) {
                sanitized.setLength(keep);
            }
            sanitized.append(TRUNCATED);
        }
        return sanitized.toString();
    }
}
