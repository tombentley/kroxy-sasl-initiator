/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.kafka.common.message.ApiVersionsRequestData;
import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateRequestData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SaslInitiationFilterTest {

    @TempDir
    Path tempDir;

    private Path storeFile;

    @BeforeEach
    void createStore() throws Exception {
        storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
    }

    @Test
    void authenticatesOnFirstBusinessRequestAfterClientApiVersions() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(5000);
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);
        assertThat(filter.state()).isEqualTo(SaslExchangeState.AWAITING_TRIGGER);

        RequestHeaderData apiVersionsHeader = header(ApiKeys.API_VERSIONS);
        ApiVersionsRequestData apiVersionsRequest = new ApiVersionsRequestData();
        MockFilterContext apiVersionsContext = context(apiVersionsHeader, apiVersionsRequest);
        assertThat(filter.onRequest(ApiKeys.API_VERSIONS, (short) 0, apiVersionsHeader, apiVersionsRequest, apiVersionsContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasHeaderEqualTo(apiVersionsHeader)
                        .hasMessageEqualTo(apiVersionsRequest));
        assertThat(filter.state()).isEqualTo(SaslExchangeState.AWAITING_TRIGGER);

        ResponseHeaderData responseHeader = new ResponseHeaderData();
        ApiVersionsResponseData response = FakeSaslBroker.apiVersionsResponse();
        MockFilterContext responseContext = context(responseHeader, response);
        assertThat(filter.onApiVersionsResponse((short) 0, responseHeader, response, responseContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardResponse()
                        .hasHeaderEqualTo(responseHeader)
                        .hasMessageEqualTo(response));
        assertThat(filter.state()).isEqualTo(SaslExchangeState.AWAITING_TRIGGER);

        RequestHeaderData businessHeader = header(ApiKeys.METADATA);
        MetadataRequestData businessRequest = new MetadataRequestData();
        MockFilterContext businessContext = context(businessHeader, businessRequest, broker);
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, businessHeader, businessRequest, businessContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasHeaderEqualTo(businessHeader)
                        .hasMessageEqualTo(businessRequest));

        assertThat(filter.state()).isEqualTo(SaslExchangeState.AUTHENTICATED);
        assertThat(filter.sessionLifetimeMs()).isEqualTo(5000);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
        assertThat(businessContext.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void sendsItsOwnV0ApiVersionsWhenTheClientDidNot() {
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        RequestHeaderData businessHeader = header(ApiKeys.METADATA);
        MetadataRequestData businessRequest = new MetadataRequestData();
        MockFilterContext context = context(businessHeader, businessRequest, broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, businessHeader, businessRequest, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        List<FakeSaslBroker.CapturedRequest> requests = broker.capturedRequests();
        assertThat(requests).hasSize(3);
        assertThat(requests.get(0).request()).isInstanceOf(ApiVersionsRequestData.class);
        assertThat(requests.get(0).header().requestApiVersion()).isZero();
        assertThat(requests.get(0).header().clientId()).isEqualTo(RequestHeaderFactory.CLIENT_ID);
        assertThat(requests.get(1).request()).isInstanceOf(SaslHandshakeRequestData.class);
        assertThat(requests.get(2).request()).isInstanceOf(SaslAuthenticateRequestData.class);
        assertThat(filter.state()).isEqualTo(SaslExchangeState.AUTHENTICATED);
    }

    @Test
    void usesTheCachedApiVersionsWithoutSendingAnotherRequest() {
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        ResponseHeaderData responseHeader = new ResponseHeaderData();
        ApiVersionsResponseData response = FakeSaslBroker.apiVersionsResponse((short) 1, (short) 1);
        assertThat(filter.onApiVersionsResponse((short) 0, responseHeader, response, context(responseHeader, response)))
                .succeedsWithin(Duration.ZERO);

        RequestHeaderData businessHeader = header(ApiKeys.METADATA);
        MetadataRequestData businessRequest = new MetadataRequestData();
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, businessHeader, businessRequest,
                context(businessHeader, businessRequest, broker)))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
        assertThat(broker.capturedRequests().get(0).header().requestApiVersion()).isEqualTo((short) 1);
        assertThat(broker.capturedRequests().get(1).header().requestApiVersion()).isEqualTo((short) 1);
    }

    @Test
    void fallsBackToItsOwnApiVersionsWhenTheCachedResponseHasNoSaslEntries() {
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        ResponseHeaderData responseHeader = new ResponseHeaderData();
        ApiVersionsResponseData response = FakeSaslBroker.apiVersionsResponseWithoutSaslEntries();
        assertThat(filter.onApiVersionsResponse((short) 0, responseHeader, response, context(responseHeader, response)))
                .succeedsWithin(Duration.ZERO);

        RequestHeaderData businessHeader = header(ApiKeys.METADATA);
        MetadataRequestData businessRequest = new MetadataRequestData();
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, businessHeader, businessRequest,
                context(businessHeader, businessRequest, broker)))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
    }

    @Test
    void failsClosedWhenItsOwnApiVersionsResponseHasNoSaslEntries() {
        FakeSaslBroker broker = new FakeSaslBroker().withoutSaslApiVersions();
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        assertAuthenticationFailure(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id);
    }

    @Test
    void failsClosedWhenTheBrokerRejectsTheHandshake() {
        FakeSaslBroker broker = new FakeSaslBroker().withEnabledMechanisms("SCRAM-SHA-256");
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        assertAuthenticationFailure(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id);
    }

    @Test
    void failsClosedWhenTheBrokerRejectsAuthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withCredentials(FakeSaslBroker.BROKER_USERNAME, "wrong-password");
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        assertAuthenticationFailure(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
    }

    @Test
    void failsClosedWhenSendRequestCompletesExceptionally() {
        FakeSaslBroker broker = new FakeSaslBroker().withSendRequestFailure(new IllegalStateException("boom"));
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        assertAuthenticationFailure(filter, broker);
    }

    @ParameterizedTest
    @MethodSource("clientSaslFrames")
    void rejectsClientOriginatedSaslFrames(ApiKeys apiKey, ApiMessage request, Errors expectedError) {
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);
        RequestHeaderData header = header(apiKey);

        assertThat(filter.onRequest(apiKey, (short) 0, header, request, context(header, request)))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(expectedError));

        assertThat(filter.state()).isEqualTo(SaslExchangeState.FAILED);
    }

    @Test
    void doesNotForwardRequestsArrivingDuringAuthenticationUntilTheExchangeCompletes() {
        FakeSaslBroker broker = new FakeSaslBroker().withPendingHandshake();
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        RequestHeaderData firstHeader = header(ApiKeys.METADATA);
        MetadataRequestData firstRequest = new MetadataRequestData();
        MockFilterContext firstContext = context(firstHeader, firstRequest, broker);
        CompletionStage<RequestFilterResult> first = filter.onRequest(ApiKeys.METADATA, (short) 0, firstHeader, firstRequest,
                firstContext);
        assertThat(first.toCompletableFuture().isDone()).isFalse();
        assertThat(filter.state()).isEqualTo(SaslExchangeState.AUTHENTICATING);

        RequestHeaderData secondHeader = header(ApiKeys.METADATA);
        MetadataRequestData secondRequest = new MetadataRequestData();
        MockFilterContext secondContext = context(secondHeader, secondRequest, broker);
        CompletionStage<RequestFilterResult> second = filter.onRequest(ApiKeys.METADATA, (short) 0, secondHeader, secondRequest,
                secondContext);
        assertThat(first.toCompletableFuture().isDone()).isFalse();
        assertThat(second.toCompletableFuture().isDone()).isFalse();

        broker.completePendingHandshake();

        assertThat(first).succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasMessageEqualTo(firstRequest));
        assertThat(second).succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasMessageEqualTo(secondRequest));
        assertThat(filter.state()).isEqualTo(SaslExchangeState.AUTHENTICATED);
    }

    @Test
    void reportsAnUnexpectedBrokerTokenAfterTheClientCompletedAsAProtocolError() {
        FakeSaslBroker broker = new FakeSaslBroker().withUnexpectedTokenAfterCompletion();
        SaslInitiationFilter filter = filter(Mechanism.PLAIN);

        assertAuthenticationFailure(filter, broker);
    }

    @Test
    void failsClosedAndMarksTheStateFailedWhenSubjectModeHasNoEligibleSubject() {
        SaslInitiationFilter filter = filter(Mechanism.PLAIN, IdentityMode.SUBJECT, null);

        RequestHeaderData header = header(ApiKeys.METADATA);
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = MockFilterContext.builder(header, request)
                .withAuthenticatedSubject(Subject.anonymous())
                .build();

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));

        assertThat(filter.state()).isEqualTo(SaslExchangeState.FAILED);
    }

    private void assertAuthenticationFailure(SaslInitiationFilter filter, FakeSaslBroker broker) {
        RequestHeaderData header = header(ApiKeys.METADATA);
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));

        assertThat(filter.state()).isEqualTo(SaslExchangeState.FAILED);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    private SaslInitiationFilter filter(Mechanism mechanism) {
        return filter(mechanism, IdentityMode.FIXED, "alice");
    }

    private SaslInitiationFilter filter(Mechanism mechanism, IdentityMode mode, String key) {
        SaslInitiationConfig config = new SaslInitiationConfig(
                mechanism,
                new IdentityConfig(mode, key),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)));
        SaslInitiationRuntimeConfig runtime = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
        return new SaslInitiationFilter(runtime);
    }

    private static MockFilterContext context(RequestHeaderData header, ApiMessage request) {
        return MockFilterContext.builder(header, request).build();
    }

    private static MockFilterContext context(ResponseHeaderData header, ApiMessage response) {
        return MockFilterContext.builder(header, response).build();
    }

    private static MockFilterContext context(RequestHeaderData header, ApiMessage request, FakeSaslBroker broker) {
        return MockFilterContext.builder(header, request)
                .withSendRequestHandler(broker)
                .build();
    }

    private static RequestHeaderData header(ApiKeys apiKey) {
        return new RequestHeaderData()
                .setRequestApiKey(apiKey.id)
                .setRequestApiVersion((short) 0);
    }

    private static Stream<Arguments> clientSaslFrames() {
        return Stream.of(
                Arguments.of(ApiKeys.SASL_HANDSHAKE, new SaslHandshakeRequestData(), Errors.UNSUPPORTED_SASL_MECHANISM),
                Arguments.of(ApiKeys.SASL_AUTHENTICATE, new SaslAuthenticateRequestData(), Errors.ILLEGAL_SASL_STATE));
    }
}
