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

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentityGuard;
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
    private final CredentialResolver credentialResolver;
    private final IdentitySelector identitySelector;
    private final IdentityGuard identityGuard;
    private final MechanismDriver mechanismDriver;

    private SaslExchangeState state = new SaslExchangeState.AwaitingTrigger();
    private boolean forwardedInitialApiVersions;
    private @Nullable SaslApiVersions cachedApiVersions;

    /**
     * Creates a per-connection filter.
     *
     * @param runtimeConfig the shared runtime configuration
     */
    SaslInitiationFilter(SaslInitiationRuntimeConfig runtimeConfig) {
        this.config = runtimeConfig.config();
        this.credentialResolver = runtimeConfig.credentialResolver();
        this.identitySelector = runtimeConfig.identitySelector();
        this.identityGuard = config.identity().mode() == IdentityMode.SUBJECT
                ? IdentityGuard.forSubject(identitySelector)
                : IdentityGuard.disabled();
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
            case SaslExchangeState.AwaitingTrigger ignored -> {
                if (apiKey == ApiKeys.API_VERSIONS && !forwardedInitialApiVersions) {
                    // A Java Kafka client using SASL sends ApiVersions twice: SaslClientAuthenticator sends v0
                    // before the client's SaslHandshake to negotiate SASL API versions, and NetworkClient sends
                    // another after the client's SASL exchange completes, before sending business requests.
                    //
                    // Without a SaslTermination filter the client's SaslHandshake/SaslAuthenticate reach the broker,
                    // so the broker completes SASL and accepts the second ApiVersions request. With SaslTermination,
                    // the termination filter answers the client's SASL frames and the broker never sees them. If this
                    // filter forwarded both ApiVersions requests, the broker would still be in HANDSHAKE_REQUEST
                    // after the first one and would reject the second as unexpected during SASL authentication.
                    //
                    // Forward only the first ApiVersions exchange before initiation. Treat any later ApiVersions
                    // request as the trigger: authenticate the proxy to the broker first, then forward that request
                    // after the broker's SASL exchange has completed.
                    forwardedInitialApiVersions = true;
                    yield context.forwardRequest(header, request);
                }
                yield startAuthentication(context, header, request);
            }
            case SaslExchangeState.Authenticating authenticating -> authenticating.stage()
                    .thenCompose(result -> result.authenticated()
                            ? forwardWithIdentityCheck(context, header, request)
                            : failureResult(context, header, request));
            case SaslExchangeState.Authenticated ignored -> forwardWithIdentityCheck(context, header, request);
            case SaslExchangeState.Failed ignored -> failureResult(context, header, request);
        };
    }

    @Override
    public CompletionStage<ResponseFilterResult> onApiVersionsResponse(short apiVersion,
                                                                       ResponseHeaderData header,
                                                                       ApiVersionsResponseData response,
                                                                       FilterContext context) {
        if (state instanceof SaslExchangeState.AwaitingTrigger) {
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

    private CompletionStage<RequestFilterResult> rejectClientSaslFrame(FilterContext context,
                                                                       RequestHeaderData header,
                                                                       ApiMessage request,
                                                                       Errors error) {
        LOGGER.atWarn()
                .addKeyValue("errorCode", error.code())
                .log("Rejecting client-originated SASL frame; client SASL must be terminated before SaslInitiation");
        state = new SaslExchangeState.Failed();
        return context.requestFilterResultBuilder()
                .errorResponse(header, request, error)
                .withCloseConnection()
                .completed();
    }

    private CompletionStage<RequestFilterResult> startAuthentication(FilterContext context,
                                                                     RequestHeaderData header,
                                                                     ApiMessage request) {
        final CompletionStage<SaslExchangeState.AuthenticationResult> exchange;
        try {
            exchange = authenticate(context);
        }
        catch (RuntimeException e) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("errorType", e.getClass().getSimpleName())
                    .log("SASL initiation failed before starting the exchange");
            state = new SaslExchangeState.Failed();
            return failureResult(context, header, request);
        }

        CompletableFuture<SaslExchangeState.AuthenticationResult> stage = new CompletableFuture<>();
        SaslExchangeState.Authenticating authenticating = new SaslExchangeState.Authenticating(stage);
        state = authenticating;
        exchange.whenComplete((result, error) -> {
            if (error != null) {
                logExchangeFailure(error);
            }
            SaslExchangeState.AuthenticationResult outcome = error == null && result != null
                    ? result
                    : SaslExchangeState.AuthenticationResult.failure();
            if (state == authenticating) {
                state = outcome.authenticated()
                        ? new SaslExchangeState.Authenticated(outcome.sessionLifetimeMs())
                        : new SaslExchangeState.Failed();
            }
            stage.complete(outcome);
        });

        return stage.thenCompose(result -> result.authenticated()
                ? forwardWithIdentityCheck(context, header, request)
                : failureResult(context, header, request));
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> authenticate(FilterContext context) {
        final IdentitySnapshot identity;
        final PasswordCredential credential;
        try {
            identity = identitySelector.select(context);
            identityGuard.expect(identity);
            CredentialResolver.ResolvedCredential resolved = credentialResolver.resolve(
                    identity.lookupKey(),
                    config.mechanism().credentialKind());
            if (!(resolved.credential() instanceof PasswordCredential passwordCredential)) {
                throw new CredentialResolver.CredentialResolutionException(
                        "The selected credential is not usable by the configured mechanism");
            }
            credential = passwordCredential;
        }
        catch (RuntimeException e) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("errorType", e.getClass().getSimpleName())
                    .log("SASL initiation could not select a usable broker credential");
            LOGGER.atDebug()
                    .setCause(e)
                    .log("SASL initiation identity/credential selection detail");
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        final String subject = identity.lookupKey();
        final String brokerUsername = credential.username();
        LOGGER.atDebug()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("subject", subject)
                .addKeyValue("brokerUsername", brokerUsername)
                .log("Selected the broker credential for SASL initiation");

        CompletionStage<Long> exchange = resolveApiVersions(context)
                .thenCompose(versions -> sendHandshake(context, versions))
                .thenCompose(versions -> performExchange(context, credential, versions));

        return exchange.handle((sessionLifetimeMs, error) -> {
            if (error != null) {
                logExchangeFailure(error);
                return SaslExchangeState.AuthenticationResult.failure();
            }
            try {
                // The subject may have changed while the upstream exchange was in flight. Re-read it before treating
                // the connection as authenticated; never retry as the new identity.
                identityGuard.verify(context);
            }
            catch (RuntimeException e) {
                logSubjectChangeFailure(e);
                return SaslExchangeState.AuthenticationResult.failure();
            }
            LOGGER.atInfo()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("subject", subject)
                    .addKeyValue("brokerUsername", brokerUsername)
                    .log("SASL initiation authenticated the upstream connection");
            return SaslExchangeState.AuthenticationResult.success(
                    Objects.requireNonNull(sessionLifetimeMs, "sessionLifetimeMs"));
        });
    }

    private CompletionStage<RequestFilterResult> forwardWithIdentityCheck(FilterContext context,
                                                                          RequestHeaderData header,
                                                                          ApiMessage request) {
        try {
            identityGuard.verify(context);
        }
        catch (RuntimeException e) {
            logSubjectChangeFailure(e);
            state = new SaslExchangeState.Failed();
            return failureResult(context, header, request);
        }
        return context.forwardRequest(header, request);
    }

    private void logSubjectChangeFailure(Throwable error) {
        LOGGER.atWarn()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("errorType", error.getClass().getSimpleName())
                .log("The downstream subject is no longer valid for this authenticated upstream connection");
        LOGGER.atDebug()
                .setCause(error)
                .log("Downstream subject change detail");
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

    private CompletionStage<Long> performExchange(FilterContext context,
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

        CompletionStage<Long> exchange;
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

    private CompletionStage<Long> sendAuthenticate(FilterContext context,
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
                    long sessionLifetimeMs = response.sessionLifetimeMs();
                    byte[] serverToken = response.authBytes() == null ? EMPTY_BYTES : response.authBytes();
                    if (client.isComplete()) {
                        if (serverToken.length > 0) {
                            return CompletableFuture.failedFuture(new SaslExchangeException(
                                    "The broker sent unexpected SASL data after authentication completed"));
                        }
                        return CompletableFuture.completedFuture(sessionLifetimeMs);
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
                        return CompletableFuture.completedFuture(sessionLifetimeMs);
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
