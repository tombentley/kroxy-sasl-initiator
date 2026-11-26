/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.StoredCredential;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.FixedIdentitySelector;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.oauth.OAuthTokenService;

import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Protocol-level KIP-368 reauthentication tests with a mutable clock and a controllable task scheduler.
 */
@SuppressWarnings({ "deprecation", "removal", "java:S5738" })
class SaslInitiationReauthTest {

    private static final double WINDOW_FACTOR = 0.8;

    @TempDir
    Path tempDir;

    private MutableClock clock;
    private RecordingTaskScheduler taskScheduler;
    private Path storeFile;

    @BeforeEach
    void setUp() throws Exception {
        clock = new MutableClock(Instant.ofEpochMilli(System.currentTimeMillis()));
        taskScheduler = new RecordingTaskScheduler();
        storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice", "bob");
    }

    @Test
    void forwardsBeforeTheReauthenticationDeadlineWithoutReauthenticating() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        MockFilterContext initialContext = authenticate(filter, broker);
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(broker.capturedRequests()).hasSize(3);
        assertThat(taskScheduler.scheduled()).hasSize(1);
        assertThat(taskScheduler.lastScheduled().delayMillis()).isEqualTo(8_000);

        clock.advance(Duration.ofMillis(7_999));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(broker.capturedRequests()).hasSize(3);
        assertThat(taskScheduler.scheduled()).hasSize(1);
        assertThat(initialContext.clientSaslGestureInvocations()).isEmpty();
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void theScheduledTaskOnlyMarksReauthenticationDue() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);

        clock.advance(Duration.ofMillis(8_000));
        taskScheduler.runLast();

        assertThat(broker.capturedRequests()).hasSize(3);

        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
        assertThat(taskScheduler.scheduled()).hasSize(2);
    }

    @Test
    void reauthenticatesOnTheFirstRequestAtTheDeadline() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void updatesTheSessionLifetimeAndReschedulesAfterSuccessfulReauthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeSequence(10_000, 20_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);
        RecordingTaskScheduler.ScheduledTask initialTask = taskScheduler.lastScheduled();
        assertThat(initialTask.delayMillis()).isEqualTo(8_000);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(filter.state())
                .isInstanceOfSatisfying(SaslExchangeState.Authenticated.class,
                        authenticated -> assertThat(authenticated.sessionLifetimeMs()).isEqualTo(20_000));
        assertThat(taskScheduler.isCancelled(initialTask)).isTrue();
        assertThat(taskScheduler.scheduled()).hasSize(2);
        assertThat(taskScheduler.lastScheduled().delayMillis()).isEqualTo(16_000);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void doesNotScheduleWhenNeitherTheBrokerNorATokenReportsALifetime() {
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);

        assertThat(taskScheduler.scheduled()).isEmpty();

        clock.advance(Duration.ofDays(1));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedWhenReauthenticationCannotBeScheduled() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        ReauthScheduler failingScheduler = ReauthScheduler.with(clock, WINDOW_FACTOR, (task, delayMillis) -> {
            throw new IllegalStateException("scheduler closed");
        }, () -> 0.0);
        SaslInitiationFilter filter = new SaslInitiationFilter(
                runtime(Mechanism.PLAIN, IdentityMode.FIXED, "alice"), null, failingScheduler);

        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void reusesTheNegotiatedApiVersionsWithoutSendingApiVersionsDuringReauthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");

        ResponseHeaderData responseHeader = new ResponseHeaderData();
        ApiVersionsResponseData response = FakeSaslBroker.apiVersionsResponse((short) 1, (short) 1);
        MockFilterContext responseContext = MockFilterContext.builder(responseHeader, response).build();
        assertThat(filter.onApiVersionsResponse((short) 0, responseHeader, response, responseContext))
                .succeedsWithin(Duration.ZERO);

        authenticate(filter, broker);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.header().requestApiVersion())
                .containsOnly((short) 1);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void usesAFreshScramClientForReauthentication() {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withEnabledMechanisms(Mechanism.SCRAM_SHA_256.mechanismName())
                .withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.SCRAM_SHA_256, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE, ApiKeys.SASL_AUTHENTICATE);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(capturedApiKeys(broker).subList(4, 7)).doesNotContain(ApiKeys.API_VERSIONS);
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedAndDoesNotRetryWhenReauthenticationFails() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);
        broker.withEnabledMechanisms(Mechanism.SCRAM_SHA_256.mechanismName());

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE, ApiKeys.SASL_HANDSHAKE);

        RequestHeaderData retryHeader = header();
        MetadataRequestData retryRequest = new MetadataRequestData();
        MockFilterContext retryContext = context(retryHeader, retryRequest, broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, retryHeader, retryRequest, retryContext));

        assertThat(capturedApiKeys(broker)).hasSize(4);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
        assertThat(retryContext.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedWhenTheCredentialDisappearsBeforeReauthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationRuntimeConfig base = runtime(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        AtomicInteger resolutions = new AtomicInteger();
        CredentialResolver disappearing = new CredentialResolver(key -> {
            if (resolutions.getAndIncrement() > 0) {
                return Optional.empty();
            }
            CredentialResolver.ResolvedCredential resolved = base.credentialResolver().resolve(key, CredentialKind.PASSWORD);
            return Optional.of(new StoredCredential(resolved.subject(), resolved.credential()));
        });
        SaslInitiationRuntimeConfig runtime = new SaslInitiationRuntimeConfig(
                base.config(), base.credentialStore(), base.identitySelector(), disappearing);
        SaslInitiationFilter filter = new SaslInitiationFilter(runtime, null, scheduler());
        authenticate(filter, broker);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedWithoutStartingReauthenticationAfterTheHardDeadline() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);

        clock.advance(Duration.ofMillis(10_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedWhenTheHardDeadlineIsReachedWhileReauthenticationIsInFlight() {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withSessionLifetimeMs(10_000)
                .withPendingHandshakeOn(2);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        CompletionStage<RequestFilterResult> stage = filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context);
        assertThat(stage.toCompletableFuture().isDone()).isFalse();

        clock.advance(Duration.ofMillis(2_000));
        broker.completePendingHandshake();

        assertFailure(stage);
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).contains(
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedWhenTheSubjectChangesBeforeReauthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.SUBJECT, null);
        authenticate(filter, broker, new Subject(new User("alice")));

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("bob")), broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedWhenTheSubjectChangesDuringReauthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.SUBJECT, null);
        authenticate(filter, broker, new Subject(new User("alice")));

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext delegate = context(header, request, new Subject(new User("alice")), broker);
        FilterContext changingContext = mock(FilterContext.class, delegatesTo(delegate));
        doReturn(new Subject(new User("alice")), new Subject(new User("bob")))
                .when(changingContext).authenticatedSubject();

        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, changingContext));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(delegate.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void refreshesTheOAuthTokenBeforeReauthentication() {
        OAuthBearerToken firstToken = oauthToken("token-one", clock.millis() + 10_000);
        OAuthBearerToken refreshedToken = oauthToken("token-two", clock.millis() + 60_000);
        OAuthTokenService tokenService = mock(OAuthTokenService.class);
        when(tokenService.usesStaticTokenFile()).thenReturn(true);
        when(tokenService.token(eq("proxy-service"), isNull()))
                .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(firstToken))
                .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(refreshedToken));

        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                null,
                new OAuthBearerConfig("file:/unused-token", "kafka"));
        SaslInitiationRuntimeConfig runtime = new SaslInitiationRuntimeConfig(
                config, null, new FixedIdentitySelector("proxy-service"), CredentialResolver.empty(), tokenService);
        SaslInitiationFilter filter = new SaslInitiationFilter(runtime, null, scheduler());
        FakeSaslBroker broker = new FakeSaslBroker()
                .withEnabledMechanisms(Mechanism.OAUTHBEARER.mechanismName())
                .withOAuthBearerToken(firstToken)
                .withSessionLifetimeMs(60_000);
        authenticate(filter, broker);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);

        broker.withOAuthBearerToken(refreshedToken);
        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);

        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        verify(tokenService, times(2)).token(eq("proxy-service"), isNull());
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void chainsRequestsDuringReauthenticationAndForwardsThemAfterSuccess() {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withSessionLifetimeMs(10_000)
                .withPendingHandshakeOn(2);
        SaslInitiationFilter filter = passwordFilter(Mechanism.PLAIN, IdentityMode.FIXED, "alice");
        authenticate(filter, broker);

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData firstHeader = header();
        MetadataRequestData firstRequest = new MetadataRequestData();
        MockFilterContext firstContext = context(firstHeader, firstRequest, broker);
        List<ApiMessage> forwarded = new ArrayList<>();
        FilterContext firstRecorder = recordingContext(firstContext, forwarded);
        CompletionStage<RequestFilterResult> first = filter.onRequest(
                ApiKeys.METADATA, (short) 0, firstHeader, firstRequest, firstRecorder);
        assertThat(first.toCompletableFuture().isDone()).isFalse();
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Reauthenticating.class);

        RequestHeaderData secondHeader = header();
        MetadataRequestData secondRequest = new MetadataRequestData();
        MockFilterContext secondContext = context(secondHeader, secondRequest, broker);
        FilterContext secondRecorder = recordingContext(secondContext, forwarded);
        CompletionStage<RequestFilterResult> second = filter.onRequest(
                ApiKeys.METADATA, (short) 0, secondHeader, secondRequest, secondRecorder);
        assertThat(first.toCompletableFuture().isDone()).isFalse();
        assertThat(second.toCompletableFuture().isDone()).isFalse();
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE, ApiKeys.SASL_HANDSHAKE);
        assertThat(forwarded).isEmpty();

        broker.completePendingHandshake();

        assertForward(first, firstRequest);
        assertForward(second, secondRequest);
        assertThat(forwarded).containsExactly(firstRequest, secondRequest);
        assertThat(capturedApiKeys(broker)).containsExactly(
                ApiKeys.API_VERSIONS, ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE,
                ApiKeys.SASL_HANDSHAKE, ApiKeys.SASL_AUTHENTICATE);
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(firstContext.clientSaslGestureInvocations()).isEmpty();
        assertThat(secondContext.clientSaslGestureInvocations()).isEmpty();
    }

    private static FilterContext recordingContext(MockFilterContext delegate, List<ApiMessage> forwarded) {
        FilterContext context = mock(FilterContext.class, delegatesTo(delegate));
        try {
            doAnswer(invocation -> {
                forwarded.add(invocation.getArgument(1));
                return delegate.forwardRequest(invocation.getArgument(0), invocation.getArgument(1));
            }).when(context).forwardRequest(any(RequestHeaderData.class), any(ApiMessage.class));
        }
        catch (Throwable t) {
            throw new IllegalStateException(t);
        }
        return context;
    }

    private MockFilterContext authenticate(SaslInitiationFilter filter, FakeSaslBroker broker) {
        return authenticate(filter, broker, Subject.anonymous());
    }

    private MockFilterContext authenticate(SaslInitiationFilter filter, FakeSaslBroker broker, Subject subject) {
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, subject, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context), request);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
        return context;
    }

    private SaslInitiationFilter passwordFilter(Mechanism mechanism, IdentityMode mode, String key) {
        return new SaslInitiationFilter(runtime(mechanism, mode, key), null, scheduler());
    }

    private SaslInitiationRuntimeConfig runtime(Mechanism mechanism, IdentityMode mode, String key) {
        SaslInitiationConfig config = new SaslInitiationConfig(
                mechanism,
                new IdentityConfig(mode, key),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)));
        return new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
    }

    private ReauthScheduler scheduler() {
        return ReauthScheduler.with(clock, WINDOW_FACTOR, taskScheduler, () -> 0.0);
    }

    private static OAuthBearerToken oauthToken(String value, long expiresAtMs) {
        return new BasicOAuthBearerToken(value, Set.of("kafka"), expiresAtMs, "alice", expiresAtMs - 60_000);
    }

    private static void assertForward(CompletionStage<RequestFilterResult> stage, ApiMessage request) {
        assertThat(stage)
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasMessageEqualTo(request));
    }

    private static void assertFailure(CompletionStage<RequestFilterResult> stage) {
        assertThat(stage)
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));
    }

    private static List<ApiKeys> capturedApiKeys(FakeSaslBroker broker) {
        return broker.capturedRequests().stream()
                .map(captured -> ApiKeys.forId(captured.request().apiKey()))
                .toList();
    }

    private static MockFilterContext context(RequestHeaderData header, ApiMessage request, FakeSaslBroker broker) {
        return context(header, request, Subject.anonymous(), broker);
    }

    private static MockFilterContext context(RequestHeaderData header,
                                             ApiMessage request,
                                             Subject subject,
                                             FakeSaslBroker broker) {
        return MockFilterContext.builder(header, request)
                .withAuthenticatedSubject(subject)
                .withSendRequestHandler(broker)
                .build();
    }

    private static RequestHeaderData header() {
        return new RequestHeaderData()
                .setRequestApiKey(ApiKeys.METADATA.id)
                .setRequestApiVersion((short) 0);
    }
}
