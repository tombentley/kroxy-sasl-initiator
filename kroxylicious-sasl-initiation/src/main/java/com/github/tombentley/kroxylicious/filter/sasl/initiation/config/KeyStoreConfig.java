/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import java.nio.file.Path;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.kroxylicious.proxy.config.secret.PasswordProvider;

/**
 * Configuration of the PKCS12 credential KeyStore.
 *
 * @param file the KeyStore file path
 * @param filePassword the provider for the KeyStore password
 */
public record KeyStoreConfig(
                             @JsonProperty(required = true) String file,
                             @JsonProperty(required = true) PasswordProvider filePassword) {

    /**
     * Validates the KeyStore configuration.
     */
    public KeyStoreConfig {
        if (file == null || file.isBlank()) {
            throw new IllegalArgumentException("keyStore.file is required when keyStore is configured");
        }
        if (filePassword == null) {
            throw new IllegalArgumentException("keyStore.filePassword is required when keyStore is configured");
        }
    }

    /**
     * Creates a KeyStore configuration from a path.
     *
     * @param file the KeyStore file path
     * @param filePassword the provider for the KeyStore password
     * @return a KeyStore configuration
     */
    public static KeyStoreConfig of(Path file, PasswordProvider filePassword) {
        return new KeyStoreConfig(file == null ? null : file.toString(), filePassword);
    }

    /**
     * Returns the configured file as a path.
     *
     * @return the KeyStore file path
     */
    public Path path() {
        return Path.of(file);
    }

    @Override
    public String toString() {
        return "KeyStoreConfig[file=" + file + ", filePassword=REDACTED]";
    }
}
