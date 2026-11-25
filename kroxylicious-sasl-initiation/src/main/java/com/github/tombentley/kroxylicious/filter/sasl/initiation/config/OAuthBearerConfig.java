/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

import org.apache.kafka.common.security.oauthbearer.JwtRetriever;

import com.fasterxml.jackson.annotation.JsonProperty;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Configuration of the OAuth bearer token source.
 * <p>
 * A {@code file:} URL selects a static token file and is only valid with a fixed identity. An {@code http:} or
 * {@code https:} URL selects a token endpoint that is used with the OAuth client credentials from the KeyStore.
 * </p>
 *
 * @param tokenEndpointUrl the token endpoint or token file URL
 * @param scope the optional OAuth scope to request
 * @param jwtRetriever the optional fully-qualified {@link JwtRetriever} class; defaults to
 *            {@value #DEFAULT_JWT_RETRIEVER}
 * @param subjectClaimName the optional claim holding the token subject; defaults to
 *            {@value #DEFAULT_SUBJECT_CLAIM_NAME}
 */
public record OAuthBearerConfig(
                                @JsonProperty(required = true) String tokenEndpointUrl,
                                @Nullable String scope,
                                @Nullable String jwtRetriever,
                                @Nullable String subjectClaimName) {

    /**
     * The default claim that holds the token subject.
     */
    public static final String DEFAULT_SUBJECT_CLAIM_NAME = "sub";

    /**
     * The default Kafka JWT retriever class. It selects the concrete retriever from the endpoint URL.
     */
    public static final String DEFAULT_JWT_RETRIEVER = "org.apache.kafka.common.security.oauthbearer.DefaultJwtRetriever";

    /**
     * Creates an OAuth bearer configuration with the default retriever and subject claim.
     *
     * @param tokenEndpointUrl the token endpoint or token file URL
     * @param scope the optional OAuth scope
     */
    public OAuthBearerConfig(String tokenEndpointUrl, @Nullable String scope) {
        this(tokenEndpointUrl, scope, null, null);
    }

    /**
     * Validates the OAuth bearer configuration.
     */
    public OAuthBearerConfig {
        if (tokenEndpointUrl == null || tokenEndpointUrl.isBlank()) {
            throw new IllegalArgumentException("oauthBearer.tokenEndpointUrl is required for mechanism OAUTHBEARER");
        }
        URI endpoint = parseEndpoint(tokenEndpointUrl);
        String scheme = endpoint.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("file") && !scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException(
                    "oauthBearer.tokenEndpointUrl must use the file, http or https scheme; configured scheme was '"
                            + endpoint.getScheme() + "'");
        }
        if (scheme.equals("file") && (endpoint.getPath() == null || endpoint.getPath().isBlank())) {
            throw new IllegalArgumentException("oauthBearer.tokenEndpointUrl must name a file when using the file scheme");
        }
        if ((scheme.equals("http") || scheme.equals("https")) && endpoint.getHost() == null) {
            throw new IllegalArgumentException("oauthBearer.tokenEndpointUrl must include a host when using HTTP(S)");
        }
        tokenEndpointUrl = endpoint.toString();

        if (scope != null && scope.isBlank()) {
            throw new IllegalArgumentException("oauthBearer.scope must not be blank when configured");
        }
        if (jwtRetriever == null || jwtRetriever.isBlank()) {
            jwtRetriever = DEFAULT_JWT_RETRIEVER;
        }
        else {
            resolveRetrieverClass(jwtRetriever);
        }
        if (subjectClaimName == null) {
            subjectClaimName = DEFAULT_SUBJECT_CLAIM_NAME;
        }
        else if (subjectClaimName.isBlank()) {
            throw new IllegalArgumentException("oauthBearer.subjectClaimName must not be blank when configured");
        }
    }

    /**
     * Returns whether the configured endpoint is a static token file.
     *
     * @return {@code true} for a {@code file:} endpoint
     */
    public boolean isFileTokenEndpoint() {
        return endpointUri().getScheme().equalsIgnoreCase("file");
    }

    /**
     * Returns the configured endpoint as a URI.
     *
     * @return the endpoint URI
     */
    public URI endpointUri() {
        return parseEndpoint(tokenEndpointUrl);
    }

    /**
     * Returns the configured JWT retriever class, which was validated by the canonical constructor.
     *
     * @return the retriever class
     */
    public Class<? extends JwtRetriever> jwtRetrieverClass() {
        return resolveRetrieverClass(jwtRetriever);
    }

    private static URI parseEndpoint(String value) {
        final URI endpoint;
        try {
            endpoint = new URI(value.trim());
        }
        catch (URISyntaxException e) {
            throw new IllegalArgumentException("oauthBearer.tokenEndpointUrl is not a valid URI", e);
        }
        if (endpoint.getScheme() == null || endpoint.getScheme().isBlank()) {
            throw new IllegalArgumentException("oauthBearer.tokenEndpointUrl must include a file, http or https scheme");
        }
        return endpoint;
    }

    private static Class<? extends JwtRetriever> resolveRetrieverClass(String className) {
        final Class<?> loaded;
        try {
            loaded = Class.forName(className);
        }
        catch (ClassNotFoundException e) {
            throw new IllegalArgumentException(
                    "oauthBearer.jwtRetriever '" + className + "' was not found on the classpath", e);
        }
        if (!JwtRetriever.class.isAssignableFrom(loaded)) {
            throw new IllegalArgumentException(
                    "oauthBearer.jwtRetriever '" + className + "' does not implement " + JwtRetriever.class.getName());
        }
        return loaded.asSubclass(JwtRetriever.class);
    }
}
