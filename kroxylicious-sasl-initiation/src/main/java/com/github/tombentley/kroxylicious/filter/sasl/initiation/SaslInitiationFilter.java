/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.Credential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelector;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySnapshot;

import io.kroxylicious.kafka.common.message.ApiVersionsRequestData;
import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateRequestData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateResponseData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.message.SaslHandshakeResponseData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.filter.ApiVersionsResponseFilter;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.RequestFilter;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.filter.ResponseFilterResult;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Authenticates the proxy to the upstream broker using SASL initiation.
 * <p>
 * The filter forwards the client's ApiVersions exchange unchanged so that clients which terminate SASL at the proxy can
 * complete their own negotiation. It initiates upstream authentication on the first non-ApiVersions request and then
 * forwards that request. Later requests are intercepted as well so subject changes and reauthentication can be observed,
 * but this commit only implements initial authentication.
 * </p>
 * <p>
 * Failure is reported to the client as a generic {@link Errors#UNKNOWN_SERVER_ERROR} followed by connection close. Broker
 * error text and SASL payloads are never forwarded. A client that sends SASL frames through this filter has bypassed or
 * misordered the client-facing authentication filter, so those frames are rejected with a SASL-specific error.
 * </p>
 */
class SaslInitiationFilter implements RequestFilter, ApiVersionsResponseFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaslInitiationFilter.class);
    private static final byte[] EMPTY_BYTES = new byte[0];

    private final SaslInitiationConfig config;
    private final KeyStoreCredentialStore credentialStore;
    private final IdentitySelector identitySelector;
    private final MechanismDriver mechanismDriver;

    private SaslExchangeState state = SaslExchangeState.AWAITING_TRIGGER;
    private @Nullable SaslApiVersions cachedApiVersions;
    private @Nullable CompletionStage<Boolean> authenticationStage;
    private long sessionLifetimeMs;

    /**
     * Creates a per-connection filter.
     *
     * @param runtimeConfig the shared runtime configuration
     */
    SaslInitiationFilter(SaslInitiationRuntimeConfig runtimeConfig) {
        this.config = runtimeConfig.config();
        this.credentialStore = runtimeConfig.credentialStore();
        this.identitySelector = runtimeConfig.identitySelector();
        this.mechanismDriver = new PasswordMechanismDriver(config.mechanism());
    }

    @Override
    public boolean shouldHandleRequest(ApiKeys apiKey, short apiVersion) {
        return true;
    }

    @Override
    public boolean shouldHandleApiVersionsResponse(short apiVersion) {
        return true;
    }

    @Override
    public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                          short apiVersion,
                                                          RequestHeaderData header,
                                                          ApiMessage request,
                                                          FilterContext context) {
        if (apiKey == ApiKeys.SASL_HANDSHAKE) {
            return rejectClientSaslFrame(context, header, request, Errors.UNSUPPORTED_SASL_MECHANISM);
        }
        if (apiKey == ApiKeys.SASL_AUTHENTICATE) {
            return rejectClientSaslFrame(context, header, request, Errors.ILLEGAL_SASL_STATE);
        }

        return switch (state) {
            case AWAITING_TRIGGER -> {
                if (apiKey == ApiKeys.API_VERSIONS) {
                    yield context.forwardRequest(header, request);
                }
                yield startAuthentication(context, header, request);
            }
            case AUTHENTICATING -> {
                CompletionStage<Boolean> stage = authenticationStage;
                if (stage == null) {
                    yield failureResult(context, header, request);
                }
                yield stage.thenCompose(success -> success
                        ? context.forwardRequest(header, request)
                        : failureResult(context, header, request));
            }
            case AUTHENTICATED -> context.forwardRequest(header, request);
            case FAILED -> failureResult(context, header, request);
        };
    }

    @Override
    public CompletionStage<ResponseFilterResult> onApiVersionsResponse(short apiVersion,
                                                                       ResponseHeaderData header,
                                                                       ApiVersionsResponseData response,
                                                                       FilterContext context) {
        if (state == SaslExchangeState.AWAITING_TRIGGER) {
            Optional<SaslApiVersions> versions = SaslApiVersions.from(response);
            versions.ifPresent(value -> cachedApiVersions = value);
        }
        return context.forwardResponse(header, response);
    }

    /**
     * Returns the current protocol state. Package-private for protocol tests.
     *
     * @return the state
     */
    SaslExchangeState state() {
        return state;
    }

    /**
     * Returns the broker-reported session lifetime from the last successful authentication response.
     *
     * @return the session lifetime in milliseconds, or zero if the broker did not report one
     */
    long sessionLifetimeMs() {
        return sessionLifetimeMs;
    }

    private CompletionStage<RequestFilterResult> rejectClientSaslFrame(FilterContext context,
                                                                       RequestHeaderData header,
                                                                       ApiMessage request,
                                                                       Errors error) {
        LOGGER.atWarn()
                .addKeyValue("errorCode", error.code())
                .log("Rejecting client-originated SASL frame; client SASL must be terminated before SaslInitiation");
        state = SaslExchangeState.FAILED;
        return context.requestFilterResultBuilder()
                .errorResponse(header, request, error)
                .withCloseConnection()
                .completed();
    }

    private CompletionStage<RequestFilterResult> startAuthentication(FilterContext context,
                                                                     RequestHeaderData header,
                                                                     ApiMessage request) {
        state = SaslExchangeState.AUTHENTICATING;
        final CompletionStage<Boolean> stage;
        try {
            stage = authenticate(context);
        }
        catch (RuntimeException e) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("errorType", e.getClass().getSimpleName())
                    .log("SASL initiation failed before starting the exchange");
            state = SaslExchangeState.FAILED;
            return failureResult(context, header, request);
        }
        authenticationStage = stage;
        return stage.thenCompose(success -> success
                ? context.forwardRequest(header, request)
                : failureResult(context, header, request));
    }

    private CompletionStage<Boolean> authenticate(FilterContext context) {
        final PasswordCredential credential;
        try {
            IdentitySnapshot identity = identitySelector.select(context);
            Credential selected = credentialStore.require(identity.lookupKey());
            if (!(selected instanceof PasswordCredential passwordCredential)) {
                throw new SaslExchangeException("The selected credential is not usable by the configured mechanism");
            }
            credential = passwordCredential;
        }
        catch (RuntimeException e) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("errorType", e.getClass().getSimpleName())
                    .log("SASL initiation could not select a usable broker credential");
            state = SaslExchangeState.FAILED;
            return CompletableFuture.completedFuture(false);
        }

        CompletionStage<Boolean> stage = resolveApiVersions(context)
                .thenCompose(versions -> sendHandshake(context, versions))
                .thenCompose(versions -> performExchange(context, credential, versions).thenApply(ignored -> true));

        return stage.handle((success, error) -> {
            boolean authenticated = error == null && Boolean.TRUE.equals(success);
            if (!authenticated && error != null) {
                logExchangeFailure(error);
            }
            if (state == SaslExchangeState.AUTHENTICATING) {
                state = authenticated ? SaslExchangeState.AUTHENTICATED : SaslExchangeState.FAILED;
            }
            return authenticated;
        });
    }

    private CompletionStage<SaslApiVersions> resolveApiVersions(FilterContext context) {
        SaslApiVersions cached = cachedApiVersions;
        if (cached != null) {
            return CompletableFuture.completedFuture(cached);
        }
        ApiVersionsRequestData request = new ApiVersionsRequestData();
        return context.<ApiVersionsResponseData> sendRequest(
                RequestHeaderFactory.forRequest(ApiKeys.API_VERSIONS, (short) 0),
                request)
                .thenCompose(response -> {
                    Optional<SaslApiVersions> versions = SaslApiVersions.from(Objects.requireNonNull(response,
                            "ApiVersions response"));
                    if (versions.isEmpty()) {
                        LOGGER.atWarn()
                                .addKeyValue("mechanism", config.mechanism())
                                .log("The broker ApiVersions response has no usable SASL handshake/authenticate entries");
                        return CompletableFuture.failedFuture(new SaslExchangeException(
                                "The broker does not advertise usable SASL API versions"));
                    }
                    return CompletableFuture.completedFuture(versions.get());
                });
    }

    private CompletionStage<SaslApiVersions> sendHandshake(FilterContext context, SaslApiVersions versions) {
        SaslHandshakeRequestData request = new SaslHandshakeRequestData()
                .setMechanism(config.mechanism().mechanismName());
        return context.<SaslHandshakeResponseData> sendRequest(
                RequestHeaderFactory.forRequest(ApiKeys.SASL_HANDSHAKE, versions.handshakeVersion()),
                request)
                .thenCompose(response -> {
                    Errors error = Errors.forCode(response.errorCode());
                    if (error != Errors.NONE) {
                        LOGGER.atWarn()
                                .addKeyValue("mechanism", config.mechanism())
                                .addKeyValue("brokerErrorCode", error.code())
                                .addKeyValue("enabledMechanisms", String.join(",", response.mechanisms()))
                                .log("The broker rejected the SASL handshake");
                        return CompletableFuture.failedFuture(new SaslExchangeException(
                                "The broker rejected the SASL handshake", error.code()));
                    }
                    return CompletableFuture.completedFuture(versions);
                });
    }

    private CompletionStage<Void> performExchange(FilterContext context,
                                                  PasswordCredential storedCredential,
                                                  SaslApiVersions versions) {
        PasswordCredential exchangeCredential = new PasswordCredential(
                storedCredential.username(),
                DestroyableSecret.of(storedCredential.password().chars()));
        SaslClientCallbackHandler callbackHandler = new SaslClientCallbackHandler(exchangeCredential);
        final SaslClient client;
        try {
            client = mechanismDriver.createSaslClient(exchangeCredential, callbackHandler);
        }
        catch (SaslException | RuntimeException e) {
            closeExchange(null, callbackHandler, exchangeCredential);
            return CompletableFuture.failedFuture(new SaslExchangeException("Could not create the SASL client", e));
        }

        CompletionStage<Void> exchange;
        try {
            byte[] initialToken = client.hasInitialResponse()
                    ? client.evaluateChallenge(EMPTY_BYTES)
                    : EMPTY_BYTES;
            exchange = sendAuthenticate(context, client, versions, initialToken == null ? EMPTY_BYTES : initialToken);
        }
        catch (SaslException | RuntimeException e) {
            closeExchange(client, callbackHandler, exchangeCredential);
            exchange = CompletableFuture.failedFuture(new SaslExchangeException("The SASL client rejected the initial challenge", e));
        }
        return exchange.whenComplete((ignored, error) -> closeExchange(client, callbackHandler, exchangeCredential));
    }

    private CompletionStage<Void> sendAuthenticate(FilterContext context,
                                                   SaslClient client,
                                                   SaslApiVersions versions,
                                                   byte[] token) {
        SaslAuthenticateRequestData request = new SaslAuthenticateRequestData().setAuthBytes(token);
        return context.<SaslAuthenticateResponseData> sendRequest(
                RequestHeaderFactory.forRequest(ApiKeys.SASL_AUTHENTICATE, versions.authenticateVersion()),
                request)
                .thenCompose(response -> {
                    Errors error = Errors.forCode(response.errorCode());
                    if (error != Errors.NONE) {
                        LOGGER.atWarn()
                                .addKeyValue("mechanism", config.mechanism())
                                .addKeyValue("brokerErrorCode", error.code())
                                .log("The broker rejected SASL authentication");
                        return CompletableFuture.failedFuture(new SaslExchangeException(
                                "The broker rejected SASL authentication", error.code()));
                    }
                    sessionLifetimeMs = response.sessionLifetimeMs();
                    byte[] serverToken = response.authBytes() == null ? EMPTY_BYTES : response.authBytes();
                    if (client.isComplete()) {
                        if (serverToken.length > 0) {
                            return CompletableFuture.failedFuture(new SaslExchangeException(
                                    "The broker sent unexpected SASL data after authentication completed"));
                        }
                        return CompletableFuture.completedFuture(null);
                    }
                    final byte[] nextToken;
                    try {
                        nextToken = client.evaluateChallenge(serverToken);
                    }
                    catch (SaslException e) {
                        return CompletableFuture.failedFuture(new SaslExchangeException(
                                "The SASL client rejected the broker challenge", e));
                    }
                    if (nextToken == null && client.isComplete()) {
                        // SCRAM consumes the broker's final server message and must not send another token.
                        return CompletableFuture.completedFuture(null);
                    }
                    return sendAuthenticate(context, client, versions, nextToken == null ? EMPTY_BYTES : nextToken);
                });
    }

    private CompletionStage<RequestFilterResult> failureResult(FilterContext context,
                                                               RequestHeaderData header,
                                                               ApiMessage request) {
        return context.requestFilterResultBuilder()
                .errorResponse(header, request, Errors.UNKNOWN_SERVER_ERROR)
                .withCloseConnection()
                .completed();
    }

    private static void closeExchange(@Nullable SaslClient client,
                                      SaslClientCallbackHandler callbackHandler,
                                      PasswordCredential credential) {
        if (client != null) {
            try {
                client.dispose();
            }
            catch (SaslException e) {
                // Best effort: authentication has already completed or failed.
            }
        }
        callbackHandler.close();
        credential.destroy();
    }

    private static void logExchangeFailure(Throwable error) {
        if (error instanceof SaslExchangeException saslExchangeException) {
            LOGGER.atWarn()
                    .addKeyValue("errorType", error.getClass().getSimpleName())
                    .addKeyValue("brokerErrorCode", saslExchangeException.brokerErrorCode())
                    .log("SASL initiation failed");
        }
        else {
            LOGGER.atWarn()
                    .addKeyValue("errorType", error.getClass().getSimpleName())
                    .log("SASL initiation failed");
        }
        if (error.getCause() != null) {
            LOGGER.atDebug()
                    .setCause(error.getCause())
                    .log("SASL initiation failure detail");
        }
    }

}
