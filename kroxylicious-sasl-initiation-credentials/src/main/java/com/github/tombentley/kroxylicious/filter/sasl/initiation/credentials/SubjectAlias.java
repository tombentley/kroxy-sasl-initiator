/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Computes KeyStore aliases from credential subjects.
 * <p>
 * The alias is the lowercase hexadecimal SHA-256 digest of the UTF-8 subject. Hashing the subject rather than using it
 * directly avoids KeyStore alias case-folding and character restrictions. The original subject is stored inside the
 * entry JSON so the alias can be validated when the entry is loaded.
 * </p>
 */
public final class SubjectAlias {

    private SubjectAlias() {
    }

    /**
     * Computes the KeyStore alias for the given subject.
     *
     * @param subject the lookup key
     * @return the lowercase hexadecimal SHA-256 digest of the UTF-8 subject
     */
    public static String hash(String subject) {
        Objects.requireNonNull(subject, "subject");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(subject.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available in this JVM", e);
        }
    }
}
