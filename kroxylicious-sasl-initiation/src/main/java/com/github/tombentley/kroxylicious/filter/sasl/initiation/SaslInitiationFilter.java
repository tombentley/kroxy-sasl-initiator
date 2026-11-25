/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentityGuard;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySelector;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.identity.IdentitySnapshot;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.oauth.OAuthTokenService;

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
import io.kroxylicious.proxy.filter.FilterDispatchExecutor;
import io.kroxylicious.proxy.filter.RequestFilter;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.filter.ResponseFilterResult;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Authenticates the proxy to the upstream broker using SASL initiation.
 * <p>
 * The filter forwards the client's ApiVersions exchange unchanged so that clients which terminate SASL at the proxy can
 * complete their own negotiation. It initiates upstream authentication on the first non-ApiVersions request and then
 * forwards that request. Later requests are intercepted as well so subject changes and reauthentication can be observed.
 * </p>
 * <p>
 * KIP-368 reauthentication is proactive and lazy at the request boundary: a one-shot task on the connection's
 * filter-dispatch executor marks reauthentication due at a jittered fraction of the effective session lifetime, and the
 * next request performs the exchange before it is forwarded. Reauthentication never changes identity and never sends
 * ApiVersions again.
 * </p>
 * <p>
 * Failure is reported to the client as a generic {@link Errors#UNKNOWN_SERVER_ERROR} followed by connection close. Broker
 * error text and SASL payloads are never forwarded. A client that sends SASL frames through this filter has bypassed or
 * misordered the client-facing authentication filter, so those frames are rejected with a SASL-specific error.
 * </p>
 */
final class SaslInitiationFilter implements RequestFilter, ApiVersionsResponseFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaslInitiationFilter.class);
    private static final byte[] EMPTY_BYTES = new byte[0];

    private final SaslInitiationConfig config;
    private final CredentialResolver credentialResolver;
    private final IdentitySelector identitySelector;
    private final IdentityGuard identityGuard;
    private final @Nullable OAuthTokenService oauthTokenService;
    private final @Nullable FilterDispatchExecutor filterDispatchExecutor;
    private final ReauthScheduler reauthScheduler;
    private final Clock clock;

    private SaslExchangeState state = new SaslExchangeState.AwaitingTrigger();
    private boolean forwardedInitialApiVersions;
    private @Nullable SaslApiVersions cachedApiVersions;
    private @Nullable ReauthScheduler.Deadline reauthDeadline;
    private @Nullable ReauthScheduler.Cancellable reauthTask;
    private boolean reauthDue;
    private long reauthGeneration;

    /**
     * Creates a per-connection filter using an executor that completes work inline. Production code must use
     * {@link #SaslInitiationFilter(SaslInitiationRuntimeConfig, FilterDispatchExecutor)} so OAuth token retrieval can
     * return to the connection's filter-dispatch thread.
     *
     * @param runtimeConfig the shared runtime configuration
     */
    SaslInitiationFilter(SaslInitiationRuntimeConfig runtimeConfig) {
        this(runtimeConfig, null);
    }

    /**
     * Creates a per-connection filter.
     *
     * @param runtimeConfig the shared runtime configuration
     * @param filterDispatchExecutor the connection's filter-dispatch executor, or {@code null} in tests that do not use
     *            OAuth
     */
    SaslInitiationFilter(SaslInitiationRuntimeConfig runtimeConfig, @Nullable FilterDispatchExecutor filterDispatchExecutor) {
        this(runtimeConfig, filterDispatchExecutor, schedulerFor(runtimeConfig, filterDispatchExecutor));
    }

    /**
     * Creates a per-connection filter with an explicit reauthentication scheduler. Intended for tests that need a
     * mutable clock and a controllable task scheduler.
     *
     * @param runtimeConfig the shared runtime configuration
     * @param filterDispatchExecutor the connection's filter-dispatch executor, or {@code null}
     * @param reauthScheduler the reauthentication scheduler
     */
    SaslInitiationFilter(SaslInitiationRuntimeConfig runtimeConfig,
                         @Nullable FilterDispatchExecutor filterDispatchExecutor,
                         ReauthScheduler reauthScheduler) {
        this.config = runtimeConfig.config();
        this.credentialResolver = runtimeConfig.credentialResolver();
        this.identitySelector = runtimeConfig.identitySelector();
        this.oauthTokenService = runtimeConfig.oauthTokenService();
        this.filterDispatchExecutor = filterDispatchExecutor;
        this.reauthScheduler = Objects.requireNonNull(reauthScheduler, "reauthScheduler");
        this.clock = reauthScheduler.clock();
        this.identityGuard = config.identity().mode() == IdentityMode.SUBJECT
                ? IdentityGuard.forSubject(identitySelector)
                : IdentityGuard.disabled();
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
            case SaslExchangeState.Authenticated authenticated -> handleAuthenticated(context, header, request, authenticated);
            case SaslExchangeState.Reauthenticating reauthenticating -> reauthenticating.stage()
                    .thenCompose(result -> result.authenticated()
                            ? forwardWithIdentityCheck(context, header, request)
                            : failureResult(context, header, request));
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

    private static ReauthScheduler schedulerFor(SaslInitiationRuntimeConfig runtimeConfig,
                                                @Nullable FilterDispatchExecutor filterDispatchExecutor) {
        double windowFactor = runtimeConfig.config().reauth().windowFactor();
        return filterDispatchExecutor == null
                ? ReauthScheduler.withoutTaskScheduling(Clock.systemUTC(), windowFactor)
                : ReauthScheduler.onFilterDispatchExecutor(filterDispatchExecutor, Clock.systemUTC(), windowFactor);
    }

    private CompletionStage<RequestFilterResult> rejectClientSaslFrame(FilterContext context,
                                                                       RequestHeaderData header,
                                                                       ApiMessage request,
                                                                       Errors error) {
        LOGGER.atWarn()
                .addKeyValue("errorCode", error.code())
                .log("Rejecting client-originated SASL frame; client SASL must be terminated before SaslInitiation");
        failClosed();
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
                if (outcome.authenticated()) {
                    state = new SaslExchangeState.Authenticated(
                            outcome.sessionLifetimeMs(),
                            Objects.requireNonNull(outcome.apiVersions(), "apiVersions"),
                            Objects.requireNonNull(outcome.identity(), "identity"),
                            outcome.tokenExpiresAtMs());
                    if (!armReauth(outcome, context)) {
                        state = new SaslExchangeState.Failed();
                        outcome = SaslExchangeState.AuthenticationResult.failure();
                    }
                }
                else {
                    state = new SaslExchangeState.Failed();
                }
            }
            stage.complete(outcome);
        });

        return stage.thenCompose(result -> result.authenticated()
                ? forwardWithIdentityCheck(context, header, request)
                : failureResult(context, header, request));
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> authenticate(FilterContext context) {
        final IdentitySnapshot identity;
        try {
            identity = identitySelector.select(context);
            identityGuard.expect(identity);
        }
        catch (RuntimeException e) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("errorType", e.getClass().getSimpleName())
                    .log("SASL initiation could not select a broker identity");
            LOGGER.atDebug()
                    .setCause(e)
                    .log("SASL initiation identity selection detail");
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        return config.mechanism() == Mechanism.OAUTHBEARER
                ? authenticateOAuthBearer(context, identity)
                : authenticatePassword(context, identity);
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> authenticatePassword(FilterContext context,
                                                                                         IdentitySnapshot identity) {
        final PasswordCredential credential;
        try {
            credential = resolvePasswordCredential(identity.lookupKey());
        }
        catch (RuntimeException e) {
            logCredentialSelectionFailure(e);
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        final String subject = identity.lookupKey();
        final String brokerUsername = credential.username();
        LOGGER.atDebug()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("subject", subject)
                .addKeyValue("brokerUsername", brokerUsername)
                .log("Selected the broker credential for SASL initiation");

        return resolveApiVersions(context)
                .thenCompose(versions -> completeExchange(context, identity, subject, brokerUsername, versions, null,
                        performPasswordExchange(context, credential, versions)));
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> authenticateOAuthBearer(FilterContext context,
                                                                                            IdentitySnapshot identity) {
        final OAuthTokenService tokenService = oauthTokenService;
        if (tokenService == null) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .log("SASL initiation has no OAuth token service configured");
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        final @Nullable OAuthClientCredential credential;
        try {
            credential = selectOAuthCredential(identity);
        }
        catch (RuntimeException e) {
            logCredentialSelectionFailure(e);
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        final String subject = identity.lookupKey();
        final String tokenPrincipal = credential == null ? subject : credential.expectedSubject();
        LOGGER.atDebug()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("subject", subject)
                .addKeyValue("tokenPrincipal", tokenPrincipal)
                .log("Selected the OAuth token source for SASL initiation");

        CompletionStage<OAuthBearerToken> tokenStage = tokenService.token(subject, credential);
        CompletionStage<OAuthBearerToken> dispatchStage = filterDispatchExecutor == null
                ? tokenStage
                : filterDispatchExecutor.completeOnFilterDispatchThread(tokenStage);

        return dispatchStage.thenCompose(token -> resolveApiVersions(context)
                .thenCompose(versions -> completeExchange(context, identity, subject, tokenPrincipal, versions,
                        token.lifetimeMs(), performOAuthBearerExchange(context, token, versions))));
    }

    private PasswordCredential resolvePasswordCredential(String lookupKey) {
        CredentialResolver.ResolvedCredential resolved = credentialResolver.resolve(
                lookupKey,
                config.mechanism().credentialKind());
        if (!(resolved.credential() instanceof PasswordCredential passwordCredential)) {
            throw new CredentialResolver.CredentialResolutionException(
                    "The selected credential is not usable by the configured mechanism");
        }
        return passwordCredential;
    }

    private @Nullable OAuthClientCredential selectOAuthCredential(IdentitySnapshot identity) {
        OAuthTokenService tokenService = Objects.requireNonNull(oauthTokenService, "oauthTokenService");
        if (tokenService.usesStaticTokenFile()) {
            return null;
        }
        CredentialResolver.ResolvedCredential resolved = credentialResolver.resolve(
                identity.lookupKey(),
                CredentialKind.OAUTH);
        if (!(resolved.credential() instanceof OAuthClientCredential oauthCredential)) {
            throw new CredentialResolver.CredentialResolutionException(
                    "The selected credential is not usable by the configured mechanism");
        }
        return oauthCredential;
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> completeExchange(FilterContext context,
                                                                                     IdentitySnapshot identity,
                                                                                     String subject,
                                                                                     String brokerIdentity,
                                                                                     SaslApiVersions versions,
                                                                                     @Nullable Long tokenExpiresAtMs,
                                                                                     CompletionStage<Long> exchange) {
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
                    .addKeyValue("brokerIdentity", brokerIdentity)
                    .log("SASL initiation authenticated the upstream connection");
            return SaslExchangeState.AuthenticationResult.success(
                    Objects.requireNonNull(sessionLifetimeMs, "sessionLifetimeMs"),
                    versions,
                    identity,
                    tokenExpiresAtMs);
        });
    }

    private CompletionStage<RequestFilterResult> handleAuthenticated(FilterContext context,
                                                                     RequestHeaderData header,
                                                                     ApiMessage request,
                                                                     SaslExchangeState.Authenticated authenticated) {
        ReauthScheduler.Deadline deadline = reauthDeadline;
        long now = clock.millis();
        if (deadline != null && deadline.isHardDeadlineReached(now)) {
            logReauthFailure(context, "hard-deadline", null);
            failClosed();
            return failureResult(context, header, request);
        }
        if (deadline != null && (reauthDue || deadline.isDue(now))) {
            return startReauthentication(context, header, request, authenticated);
        }
        return forwardWithIdentityCheck(context, header, request);
    }

    private CompletionStage<RequestFilterResult> startReauthentication(FilterContext context,
                                                                       RequestHeaderData header,
                                                                       ApiMessage request,
                                                                       SaslExchangeState.Authenticated authenticated) {
        reauthDue = false;
        cancelReauthTask();
        LOGGER.atInfo()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("virtualCluster", context.getVirtualClusterName())
                .addKeyValue("sessionId", context.sessionId())
                .log("Starting KIP-368 SASL reauthentication");

        final CompletionStage<SaslExchangeState.AuthenticationResult> exchange;
        try {
            exchange = reauthenticate(context, authenticated);
        }
        catch (RuntimeException e) {
            logReauthFailure(context, "reauth-start", e);
            failClosed();
            return failureResult(context, header, request);
        }

        CompletableFuture<SaslExchangeState.AuthenticationResult> stage = new CompletableFuture<>();
        SaslExchangeState.Reauthenticating reauthenticating = new SaslExchangeState.Reauthenticating(stage);
        state = reauthenticating;
        exchange.whenComplete((result, error) -> {
            if (error != null) {
                logExchangeFailure(error);
            }
            SaslExchangeState.AuthenticationResult outcome = error == null && result != null
                    ? result
                    : SaslExchangeState.AuthenticationResult.failure();
            if (state == reauthenticating && outcome.authenticated()) {
                state = new SaslExchangeState.Authenticated(
                        outcome.sessionLifetimeMs(),
                        Objects.requireNonNull(outcome.apiVersions(), "apiVersions"),
                        Objects.requireNonNull(outcome.identity(), "identity"),
                        outcome.tokenExpiresAtMs());
                if (armReauth(outcome, context)) {
                    logReauthSuccess(context, outcome);
                }
                else {
                    state = new SaslExchangeState.Failed();
                    outcome = SaslExchangeState.AuthenticationResult.failure();
                }
            }
            else if (state == reauthenticating) {
                state = new SaslExchangeState.Failed();
                logReauthFailure(context, "reauth-exchange", error);
            }
            else {
                outcome = SaslExchangeState.AuthenticationResult.failure();
            }
            stage.complete(outcome);
        });

        return stage.thenCompose(result -> result.authenticated()
                ? forwardWithIdentityCheck(context, header, request)
                : failureResult(context, header, request));
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> reauthenticate(FilterContext context,
                                                                                   SaslExchangeState.Authenticated authenticated) {
        ReauthScheduler.Deadline deadline = reauthDeadline;
        if (deadline == null || deadline.isHardDeadlineReached(clock.millis())) {
            logReauthFailure(context, "hard-deadline", null);
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }
        try {
            identityGuard.verify(context);
        }
        catch (RuntimeException e) {
            logSubjectChangeFailure(e);
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        CompletionStage<SaslExchangeState.AuthenticationResult> exchange = config.mechanism() == Mechanism.OAUTHBEARER
                ? reauthenticateOAuthBearer(context, authenticated)
                : reauthenticatePassword(context, authenticated);

        return exchange.handle((result, error) -> {
            if (error != null) {
                logExchangeFailure(error);
                return SaslExchangeState.AuthenticationResult.failure();
            }
            try {
                // The subject may have changed while reauthentication was in flight. Never continue as the new
                // identity, and never retry.
                identityGuard.verify(context);
            }
            catch (RuntimeException e) {
                logSubjectChangeFailure(e);
                return SaslExchangeState.AuthenticationResult.failure();
            }
            if (deadline.isHardDeadlineReached(clock.millis())) {
                logReauthFailure(context, "hard-deadline", null);
                return SaslExchangeState.AuthenticationResult.failure();
            }
            return result == null ? SaslExchangeState.AuthenticationResult.failure() : result;
        });
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> reauthenticatePassword(FilterContext context,
                                                                                           SaslExchangeState.Authenticated authenticated) {
        final PasswordCredential credential;
        try {
            credential = resolvePasswordCredential(authenticated.identity().lookupKey());
        }
        catch (RuntimeException e) {
            logCredentialSelectionFailure(e);
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        return performPasswordExchange(context, credential, authenticated.apiVersions())
                .thenApply(sessionLifetimeMs -> SaslExchangeState.AuthenticationResult.success(
                        sessionLifetimeMs,
                        authenticated.apiVersions(),
                        authenticated.identity(),
                        null));
    }

    private CompletionStage<SaslExchangeState.AuthenticationResult> reauthenticateOAuthBearer(FilterContext context,
                                                                                              SaslExchangeState.Authenticated authenticated) {
        final OAuthTokenService tokenService = oauthTokenService;
        if (tokenService == null) {
            LOGGER.atWarn()
                    .addKeyValue("mechanism", config.mechanism())
                    .log("SASL initiation has no OAuth token service configured for reauthentication");
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        final @Nullable OAuthClientCredential credential;
        try {
            credential = selectOAuthCredential(authenticated.identity());
        }
        catch (RuntimeException e) {
            logCredentialSelectionFailure(e);
            return CompletableFuture.completedFuture(SaslExchangeState.AuthenticationResult.failure());
        }

        CompletionStage<OAuthBearerToken> tokenStage = tokenService.token(authenticated.identity().lookupKey(), credential);
        CompletionStage<OAuthBearerToken> dispatchStage = filterDispatchExecutor == null
                ? tokenStage
                : filterDispatchExecutor.completeOnFilterDispatchThread(tokenStage);

        return dispatchStage.thenCompose(token -> performOAuthBearerExchange(context, token, authenticated.apiVersions())
                .thenApply(sessionLifetimeMs -> SaslExchangeState.AuthenticationResult.success(
                        sessionLifetimeMs,
                        authenticated.apiVersions(),
                        authenticated.identity(),
                        token.lifetimeMs())));
    }

    private boolean armReauth(SaslExchangeState.AuthenticationResult result, FilterContext context) {
        cancelReauthTask();
        reauthDue = false;
        long generation = ++reauthGeneration;
        final Optional<ReauthScheduler.Schedule> schedule;
        try {
            schedule = reauthScheduler.arm(
                    result.sessionLifetimeMs(),
                    result.tokenExpiresAtMs(),
                    () -> {
                        if (generation == reauthGeneration) {
                            reauthDue = true;
                        }
                    });
        }
        catch (RuntimeException e) {
            logReauthFailure(context, "scheduling", e);
            cancelReauthTask();
            reauthDeadline = null;
            return false;
        }
        if (schedule.isPresent()) {
            ReauthScheduler.Deadline deadline = schedule.get().deadline();
            reauthDeadline = deadline;
            reauthTask = schedule.get().cancellation();
            LOGGER.atDebug()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("virtualCluster", context.getVirtualClusterName())
                    .addKeyValue("sessionId", context.sessionId())
                    .addKeyValue("reauthAtMs", deadline.reauthAtMs())
                    .addKeyValue("hardDeadlineMs", deadline.hardDeadlineMs())
                    .log("Armed KIP-368 SASL reauthentication");
        }
        else {
            reauthDeadline = null;
            reauthTask = null;
            LOGGER.atDebug()
                    .addKeyValue("mechanism", config.mechanism())
                    .addKeyValue("virtualCluster", context.getVirtualClusterName())
                    .addKeyValue("sessionId", context.sessionId())
                    .log("No positive SASL session lifetime; KIP-368 reauthentication will not be scheduled");
        }
        return true;
    }

    private void cancelReauthTask() {
        ReauthScheduler.Cancellable task = reauthTask;
        if (task != null) {
            task.cancel();
            reauthTask = null;
        }
    }

    private void failClosed() {
        cancelReauthTask();
        reauthDeadline = null;
        reauthDue = false;
        state = new SaslExchangeState.Failed();
    }

    private void logCredentialSelectionFailure(RuntimeException e) {
        LOGGER.atWarn()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("errorType", e.getClass().getSimpleName())
                .log("SASL initiation could not select a usable broker credential");
        LOGGER.atDebug()
                .setCause(e)
                .log("SASL initiation identity/credential selection detail");
    }

    private CompletionStage<RequestFilterResult> forwardWithIdentityCheck(FilterContext context,
                                                                          RequestHeaderData header,
                                                                          ApiMessage request) {
        try {
            identityGuard.verify(context);
        }
        catch (RuntimeException e) {
            logSubjectChangeFailure(e);
            failClosed();
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

    private void logReauthSuccess(FilterContext context, SaslExchangeState.AuthenticationResult result) {
        LOGGER.atInfo()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("virtualCluster", context.getVirtualClusterName())
                .addKeyValue("sessionId", context.sessionId())
                .addKeyValue("sessionLifetimeMs", result.sessionLifetimeMs())
                .log("KIP-368 SASL reauthentication succeeded");
    }

    private void logReauthFailure(FilterContext context, String reason, @Nullable Throwable error) {
        var event = LOGGER.atWarn()
                .addKeyValue("mechanism", config.mechanism())
                .addKeyValue("virtualCluster", context.getVirtualClusterName())
                .addKeyValue("sessionId", context.sessionId())
                .addKeyValue("errorCode", Errors.UNKNOWN_SERVER_ERROR.code())
                .addKeyValue("reason", reason);
        if (error instanceof SaslExchangeException saslExchangeException) {
            event = event.addKeyValue("brokerErrorCode", saslExchangeException.brokerErrorCode());
        }
        if (error != null) {
            event = event.addKeyValue("errorType", error.getClass().getSimpleName());
        }
        event.log("KIP-368 SASL reauthentication failed");
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

    private CompletionStage<Long> performPasswordExchange(FilterContext context,
                                                          PasswordCredential storedCredential,
                                                          SaslApiVersions versions) {
        return sendHandshake(context, versions)
                .thenCompose(handshakeVersions -> performPasswordClientExchange(context, storedCredential, handshakeVersions));
    }

    private CompletionStage<Long> performPasswordClientExchange(FilterContext context,
                                                                PasswordCredential storedCredential,
                                                                SaslApiVersions versions) {
        PasswordCredential exchangeCredential = new PasswordCredential(
                storedCredential.username(),
                DestroyableSecret.of(storedCredential.password().chars()));
        SaslClientCallbackHandler callbackHandler = new SaslClientCallbackHandler(exchangeCredential);
        final SaslClient client;
        try {
            client = new PasswordMechanismDriver(config.mechanism()).createSaslClient(callbackHandler);
        }
        catch (SaslException | RuntimeException e) {
            closeExchange(null, callbackHandler, exchangeCredential);
            return CompletableFuture.failedFuture(new SaslExchangeException("Could not create the SASL client", e));
        }
        return startExchange(context, client, versions)
                .whenComplete((ignored, error) -> closeExchange(client, callbackHandler, exchangeCredential));
    }

    private CompletionStage<Long> performOAuthBearerExchange(FilterContext context,
                                                             OAuthBearerToken token,
                                                             SaslApiVersions versions) {
        return sendHandshake(context, versions)
                .thenCompose(handshakeVersions -> performOAuthBearerClientExchange(context, token, handshakeVersions));
    }

    private CompletionStage<Long> performOAuthBearerClientExchange(FilterContext context,
                                                                   OAuthBearerToken token,
                                                                   SaslApiVersions versions) {
        OAuthBearerSaslClientCallbackHandler callbackHandler = new OAuthBearerSaslClientCallbackHandler(token);
        final SaslClient client;
        try {
            client = new OAuthBearerMechanismDriver().createSaslClient(callbackHandler);
        }
        catch (SaslException | RuntimeException e) {
            callbackHandler.close();
            return CompletableFuture.failedFuture(new SaslExchangeException("Could not create the SASL client", e));
        }
        return startExchange(context, client, versions)
                .whenComplete((ignored, error) -> closeExchange(client, callbackHandler));
    }

    private CompletionStage<Long> startExchange(FilterContext context, SaslClient client, SaslApiVersions versions) {
        try {
            byte[] initialToken = client.hasInitialResponse()
                    ? client.evaluateChallenge(EMPTY_BYTES)
                    : EMPTY_BYTES;
            return sendAuthenticate(context, client, versions, initialToken == null ? EMPTY_BYTES : initialToken);
        }
        catch (SaslException | RuntimeException e) {
            return CompletableFuture.failedFuture(new SaslExchangeException(
                    "The SASL client rejected the initial challenge", e));
        }
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
                        // SCRAM and OAUTHBEARER consume the broker's final server message and send no further token.
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
        closeClient(client);
        callbackHandler.close();
        credential.destroy();
    }

    private static void closeExchange(@Nullable SaslClient client, OAuthBearerSaslClientCallbackHandler callbackHandler) {
        closeClient(client);
        callbackHandler.close();
    }

    private static void closeClient(@Nullable SaslClient client) {
        if (client != null) {
            try {
                client.dispose();
            }
            catch (SaslException e) {
                // Best effort: authentication has already completed or failed.
            }
        }
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
