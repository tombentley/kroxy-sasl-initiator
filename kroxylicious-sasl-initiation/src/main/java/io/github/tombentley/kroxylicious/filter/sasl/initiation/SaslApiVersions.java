/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Optional;

import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.Errors;

/**
 * The SASL API versions negotiated from an ApiVersions response.
 * <p>
 * The selected version is the lower of the broker's maximum version and the version supported by this client. Both
 * handshake and authenticate must be at least version 1; the older versions do not carry the modern SASL framing or the
 * session lifetime.
 * </p>
 *
 * @param handshakeVersion the SaslHandshake request version
 * @param authenticateVersion the SaslAuthenticate request version
 */
record SaslApiVersions(short handshakeVersion, short authenticateVersion) {

    private static final short MINIMUM_SASL_VERSION = 1;

    /**
     * Extracts usable SASL API versions from an ApiVersions response.
     *
     * @param response the response to inspect
     * @return the selected versions, or empty if the response is an error or lacks usable SASL entries
     */
    static Optional<SaslApiVersions> from(ApiVersionsResponseData response) {
        if (Errors.forCode(response.errorCode()) != Errors.NONE) {
            return Optional.empty();
        }
        ApiVersionsResponseData.ApiVersion handshake = response.apiKeys().find(ApiKeys.SASL_HANDSHAKE.id);
        ApiVersionsResponseData.ApiVersion authenticate = response.apiKeys().find(ApiKeys.SASL_AUTHENTICATE.id);
        if (handshake == null || authenticate == null) {
            return Optional.empty();
        }
        short selectedHandshake = selectVersion(handshake, ApiKeys.SASL_HANDSHAKE);
        short selectedAuthenticate = selectVersion(authenticate, ApiKeys.SASL_AUTHENTICATE);
        if (selectedHandshake < MINIMUM_SASL_VERSION || selectedAuthenticate < MINIMUM_SASL_VERSION) {
            return Optional.empty();
        }
        return Optional.of(new SaslApiVersions(selectedHandshake, selectedAuthenticate));
    }

    private static short selectVersion(ApiVersionsResponseData.ApiVersion brokerVersion, ApiKeys apiKey) {
        return (short) Math.min(brokerVersion.maxVersion(), apiKey.latestVersion());
    }
}
