/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SubjectAliasTest {

    @Test
    void hashesKnownVectors() {
        assertThat(SubjectAlias.hash("alice"))
                .isEqualTo("2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90");
        assertThat(SubjectAlias.hash(""))
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    @Test
    void hashesUtf8Subjects() {
        assertThat(SubjectAlias.hash("Ålice-用户"))
                .isEqualTo("866b65762e747bf51d9d8f71d704a3f9ae73d43db52f3176f35640e149a501e6");
    }

    @Test
    void isCaseSensitive() {
        assertThat(SubjectAlias.hash("alice")).isNotEqualTo(SubjectAlias.hash("Alice"));
    }

    @Test
    void producesLowercaseHexOnly() {
        assertThat(SubjectAlias.hash("some subject")).matches("[0-9a-f]{64}");
    }

    @Test
    void rejectsNullSubject() {
        assertThatThrownBy(() -> SubjectAlias.hash(null))
                .isInstanceOf(NullPointerException.class);
    }
}
