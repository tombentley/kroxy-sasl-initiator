/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.apache.kafka.common.security.scram.ScramExtensionsCallback;
import org.junit.jupiter.api.Test;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;

import static org.assertj.core.api.Assertions.assertThat;

class SaslClientCallbackHandlerTest {

    @Test
    void suppliesNamePasswordAndEmptyScramExtensions() throws Exception {
        PasswordCredential credential = credential();
        try (SaslClientCallbackHandler handler = new SaslClientCallbackHandler(credential)) {
            NameCallback nameCallback = new NameCallback("name");
            PasswordCallback passwordCallback = new PasswordCallback("password", false);
            ScramExtensionsCallback extensionsCallback = new ScramExtensionsCallback();

            handler.handle(new Callback[]{ nameCallback, passwordCallback, extensionsCallback });

            assertThat(nameCallback.getName()).isEqualTo(credential.username());
            assertThat(passwordCallback.getPassword()).containsExactly('s', 'e', 'c', 'r', 'e', 't');
            assertThat(extensionsCallback.extensions()).isEmpty();
        }
        finally {
            credential.destroy();
        }
    }

    @Test
    void acceptsCallbacksWithoutScramExtensions() throws Exception {
        PasswordCredential credential = credential();
        try (SaslClientCallbackHandler handler = new SaslClientCallbackHandler(credential)) {
            NameCallback nameCallback = new NameCallback("name");
            PasswordCallback passwordCallback = new PasswordCallback("password", false);

            handler.handle(new Callback[]{ nameCallback, passwordCallback });

            assertThat(nameCallback.getName()).isEqualTo(credential.username());
            assertThat(passwordCallback.getPassword()).containsExactly('s', 'e', 'c', 'r', 'e', 't');
        }
        finally {
            credential.destroy();
        }
    }

    private static PasswordCredential credential() {
        return new PasswordCredential("broker-alice", DestroyableSecret.of("secret"));
    }
}
