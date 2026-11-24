/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.plain.internals.PlainSaslServer;
import org.apache.kafka.common.security.plain.internals.PlainSaslServerProvider;

import io.kroxylicious.kafka.common.message.ApiVersionsRequestData;
import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateRequestData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateResponseData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.message.SaslHandshakeResponseData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import edu.umd.cs.findbugs.annotations.Nullable;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.BROKER_PASSWORD;

/**
 * A small fake broker for protocol tests. It answers ApiVersions, SaslHandshake and SaslAuthenticate, using Kafka's
 * {@link PlainSaslServer} for the actual PLAIN challenge/response.
 */
final class FakeSaslBroker implements MockFilterContext.SendRequestHandler {

    static final String BROKER_USERNAME = "broker-alice";

    private String username = BROKER_USERNAME;
    private String password = BROKER_PASSWORD;
    private Set<String> enabledMechanisms = Set.of(PlainSaslServer.PLAIN_MECHANISM);
    private short handshakeMaxVersion = ApiKeys.SASL_HANDSHAKE.latestVersion();
    private short authenticateMaxVersion = ApiKeys.SASL_AUTHENTICATE.latestVersion();
    private boolean includeSaslApiVersions = true;
    private long sessionLifetimeMs;
    private boolean unexpectedTokenAfterCompletion;
    private @Nullable RuntimeException sendRequestFailure;
    private @Nullable CompletableFuture<ApiMessage> pendingHandshake;
    private @Nullable String pendingHandshakeMechanism;

    private final List<CapturedRequest> capturedRequests = new ArrayList<>();
    private @Nullable SaslServer saslServer;

    /**
     * Creates a fake broker that accepts the default test credential and PLAIN.
     */
    FakeSaslBroker() {
        PlainSaslServerProvider.initialize();
    }

    FakeSaslBroker withCredentials(String username, String password) {
        this.username = username;
        this.password = password;
        this.saslServer = null;
        return this;
    }

    FakeSaslBroker withEnabledMechanisms(String... mechanisms) {
        this.enabledMechanisms = new LinkedHashSet<>(Arrays.asList(mechanisms));
        return this;
    }

    FakeSaslBroker withSaslVersions(short handshakeMaxVersion, short authenticateMaxVersion) {
        this.handshakeMaxVersion = handshakeMaxVersion;
        this.authenticateMaxVersion = authenticateMaxVersion;
        return this;
    }

    FakeSaslBroker withoutSaslApiVersions() {
        this.includeSaslApiVersions = false;
        return this;
    }

    FakeSaslBroker withSessionLifetimeMs(long sessionLifetimeMs) {
        this.sessionLifetimeMs = sessionLifetimeMs;
        return this;
    }

    FakeSaslBroker withUnexpectedTokenAfterCompletion() {
        this.unexpectedTokenAfterCompletion = true;
        return this;
    }

    FakeSaslBroker withSendRequestFailure(RuntimeException failure) {
        this.sendRequestFailure = failure;
        return this;
    }

    FakeSaslBroker withPendingHandshake() {
        this.pendingHandshake = new CompletableFuture<>();
        return this;
    }

    void completePendingHandshake() {
        CompletableFuture<ApiMessage> handshake = pendingHandshake;
        if (handshake == null) {
            throw new IllegalStateException("No pending handshake");
        }
        handshake.complete(handshakeResponse(pendingHandshakeMechanism));
        pendingHandshake = null;
        pendingHandshakeMechanism = null;
    }

    List<CapturedRequest> capturedRequests() {
        return List.copyOf(capturedRequests);
    }

    @Override
    public CompletionStage<? extends ApiMessage> handle(RequestHeaderData header, ApiMessage request) {
        capturedRequests.add(new CapturedRequest(header, request));
        RuntimeException failure = sendRequestFailure;
        if (failure != null) {
            return CompletableFuture.failedFuture(failure);
        }
        if (request instanceof ApiVersionsRequestData) {
            return CompletableFuture.completedFuture(configuredApiVersionsResponse());
        }
        if (request instanceof SaslHandshakeRequestData handshake) {
            if (pendingHandshake != null) {
                pendingHandshakeMechanism = handshake.mechanism();
                return pendingHandshake;
            }
            return CompletableFuture.completedFuture(handshakeResponse(handshake.mechanism()));
        }
        if (request instanceof SaslAuthenticateRequestData authenticate) {
            return CompletableFuture.completedFuture(authenticateResponse(authenticate.authBytes()));
        }
        return CompletableFuture.failedFuture(new IllegalArgumentException("Unexpected request " + request.getClass().getName()));
    }

    private SaslHandshakeResponseData handshakeResponse(@Nullable String requestedMechanism) {
        if (requestedMechanism == null || !enabledMechanisms.contains(requestedMechanism)) {
            return new SaslHandshakeResponseData()
                    .setErrorCode(Errors.UNSUPPORTED_SASL_MECHANISM.code())
                    .setMechanisms(new ArrayList<>(enabledMechanisms));
        }
        saslServer = new PlainSaslServer(callbackHandler());
        return new SaslHandshakeResponseData()
                .setErrorCode(Errors.NONE.code())
                .setMechanisms(new ArrayList<>(enabledMechanisms));
    }

    private SaslAuthenticateResponseData authenticateResponse(byte[] authBytes) {
        SaslServer server = saslServer;
        if (server == null) {
            return new SaslAuthenticateResponseData()
                    .setErrorCode(Errors.ILLEGAL_SASL_STATE.code())
                    .setErrorMessage("no handshake")
                    .setAuthBytes(new byte[0]);
        }
        try {
            byte[] challenge = authBytes == null ? new byte[0] : authBytes;
            byte[] response = server.evaluateResponse(challenge);
            byte[] responseAuthBytes = response == null ? new byte[0] : response;
            if (unexpectedTokenAfterCompletion && server.isComplete() && responseAuthBytes.length == 0) {
                responseAuthBytes = new byte[]{ 1 };
            }
            return new SaslAuthenticateResponseData()
                    .setErrorCode(Errors.NONE.code())
                    .setAuthBytes(responseAuthBytes)
                    .setSessionLifetimeMs(sessionLifetimeMs);
        }
        catch (SaslException e) {
            return new SaslAuthenticateResponseData()
                    .setErrorCode(Errors.SASL_AUTHENTICATION_FAILED.code())
                    .setErrorMessage("broker-only diagnostic text")
                    .setAuthBytes(new byte[0]);
        }
    }

    private CallbackHandler callbackHandler() {
        return callbacks -> {
            String presentedUsername = null;
            PlainAuthenticateCallback authenticateCallback = null;
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback nameCallback) {
                    presentedUsername = nameCallback.getDefaultName();
                }
                else if (callback instanceof PlainAuthenticateCallback plainCallback) {
                    authenticateCallback = plainCallback;
                }
            }
            if (authenticateCallback != null) {
                boolean authenticated = username.equals(presentedUsername)
                        && Arrays.equals(password.toCharArray(), authenticateCallback.password());
                authenticateCallback.authenticated(authenticated);
            }
        };
    }

    static ApiVersionsResponseData apiVersionsResponse() {
        return apiVersionsResponse(ApiKeys.SASL_HANDSHAKE.latestVersion(), ApiKeys.SASL_AUTHENTICATE.latestVersion());
    }

    static ApiVersionsResponseData apiVersionsResponse(short handshakeMaxVersion, short authenticateMaxVersion) {
        ApiVersionsResponseData response = apiVersionsResponse(true);
        response.apiKeys().find(ApiKeys.SASL_HANDSHAKE.id).setMaxVersion(handshakeMaxVersion);
        response.apiKeys().find(ApiKeys.SASL_AUTHENTICATE.id).setMaxVersion(authenticateMaxVersion);
        return response;
    }

    static ApiVersionsResponseData apiVersionsResponseWithoutSaslEntries() {
        return apiVersionsResponse(false);
    }

    private static ApiVersionsResponseData apiVersionsResponse(boolean includeSaslEntries) {
        ApiVersionsResponseData response = new ApiVersionsResponseData().setErrorCode(Errors.NONE.code());
        if (includeSaslEntries) {
            response.apiKeys().add(new ApiVersionsResponseData.ApiVersion()
                    .setApiKey(ApiKeys.SASL_HANDSHAKE.id)
                    .setMinVersion(ApiKeys.SASL_HANDSHAKE.oldestVersion())
                    .setMaxVersion(ApiKeys.SASL_HANDSHAKE.latestVersion()));
            response.apiKeys().add(new ApiVersionsResponseData.ApiVersion()
                    .setApiKey(ApiKeys.SASL_AUTHENTICATE.id)
                    .setMinVersion(ApiKeys.SASL_AUTHENTICATE.oldestVersion())
                    .setMaxVersion(ApiKeys.SASL_AUTHENTICATE.latestVersion()));
        }
        return response;
    }

    private ApiVersionsResponseData configuredApiVersionsResponse() {
        ApiVersionsResponseData response = apiVersionsResponse(includeSaslApiVersions);
        if (includeSaslApiVersions) {
            response.apiKeys().find(ApiKeys.SASL_HANDSHAKE.id).setMaxVersion(handshakeMaxVersion);
            response.apiKeys().find(ApiKeys.SASL_AUTHENTICATE.id).setMaxVersion(authenticateMaxVersion);
        }
        return response;
    }

    /**
     * A request captured by the fake broker.
     *
     * @param header the request header
     * @param request the request body
     */
    record CapturedRequest(RequestHeaderData header, ApiMessage request) {}
}
