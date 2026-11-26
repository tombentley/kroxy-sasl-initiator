/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.kafka.common.security.scram.ScramExtensionsCallback;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;

/**
 * Supplies the broker username, password and SCRAM extensions to the SASL client for password-based mechanisms.
 * <p>
 * Password arrays handed to the SASL client are kept only for the lifetime of one exchange and zeroized by
 * {@link #close()}. The credential itself is also destroyed by the owning exchange.
 * </p>
 */
final class SaslClientCallbackHandler implements CallbackHandler, AutoCloseable {

    private final PasswordCredential credential;
    private final List<char[]> passwordCopies = new ArrayList<>();

    /**
     * Creates a callback handler for one exchange.
     *
     * @param credential the credential for the exchange
     */
    SaslClientCallbackHandler(PasswordCredential credential) {
        this.credential = credential;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback nameCallback) {
                nameCallback.setName(credential.username());
            }
            else if (callback instanceof PasswordCallback passwordCallback) {
                char[] password = credential.password().chars();
                passwordCopies.add(password);
                passwordCallback.setPassword(password);
            }
            else if (callback instanceof ScramExtensionsCallback scramExtensionsCallback) {
                // This filter does not use SCRAM extensions, so authenticate without any. Kafka's SCRAM client
                // requires a non-null map when the callback is handled.
                scramExtensionsCallback.extensions(Map.of());
            }
            else {
                throw new UnsupportedCallbackException(callback,
                        "Unsupported SASL callback for " + credential.username());
            }
        }
    }

    @Override
    public void close() {
        for (char[] password : passwordCopies) {
            Arrays.fill(password, '\0');
        }
        passwordCopies.clear();
    }
}
