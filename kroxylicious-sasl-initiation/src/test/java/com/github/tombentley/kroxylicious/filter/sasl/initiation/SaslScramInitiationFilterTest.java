/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Protocol-level tests for SCRAM-SHA-256 and SCRAM-SHA-512 using Kafka's SCRAM server implementation and the same
 * filter exchange path as PLAIN.
 */
class SaslScramInitiationFilterTest {

    @TempDir
    Path tempDir;

    private Path storeFile;

    @BeforeEach
    void createStore() throws Exception {
        storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
    }

    @ParameterizedTest
    @MethodSource("scramMechanisms")
    void authenticatesAndConsumesTheFinalScramServerMessage(Mechanism mechanism) {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withEnabledMechanisms(mechanism.mechanismName())
                .withSessionLifetimeMs(5000);
        SaslInitiationFilter filter = filter(mechanism);

        RequestHeaderData header = header(ApiKeys.METADATA);
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasHeaderEqualTo(header)
                        .hasMessageEqualTo(request));

        assertThat(filter.state()).isEqualTo(SaslExchangeState.AUTHENTICATED);
        assertThat(filter.sessionLifetimeMs()).isEqualTo(5000);
        List<FakeSaslBroker.CapturedRequest> requests = broker.capturedRequests();
        assertThat(requests)
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(
                        ApiKeys.API_VERSIONS.id,
                        ApiKeys.SASL_HANDSHAKE.id,
                        ApiKeys.SASL_AUTHENTICATE.id,
                        ApiKeys.SASL_AUTHENTICATE.id);
        assertThat(requests.get(1).request()).isInstanceOf(SaslHandshakeRequestData.class);
        assertThat(((SaslHandshakeRequestData) requests.get(1).request()).mechanism())
                .isEqualTo(mechanism.mechanismName());
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("scramMechanisms")
    void failsClosedForAWrongPassword(Mechanism mechanism) {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withEnabledMechanisms(mechanism.mechanismName())
                .withCredentials(FakeSaslBroker.BROKER_USERNAME, "not-the-stored-password");
        SaslInitiationFilter filter = filter(mechanism);

        assertAuthenticationFailure(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(
                        ApiKeys.API_VERSIONS.id,
                        ApiKeys.SASL_HANDSHAKE.id,
                        ApiKeys.SASL_AUTHENTICATE.id,
                        ApiKeys.SASL_AUTHENTICATE.id);
    }

    @ParameterizedTest
    @MethodSource("scramMechanisms")
    void failsClosedForAnUnknownUser(Mechanism mechanism) {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withEnabledMechanisms(mechanism.mechanismName())
                .withCredentials("someone-else", TestStores.BROKER_PASSWORD);
        SaslInitiationFilter filter = filter(mechanism);

        assertAuthenticationFailure(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(
                        ApiKeys.API_VERSIONS.id,
                        ApiKeys.SASL_HANDSHAKE.id,
                        ApiKeys.SASL_AUTHENTICATE.id);
    }

    @ParameterizedTest
    @MethodSource("scramMechanisms")
    void failsClosedWhenTheBrokerDoesNotEnableTheConfiguredMechanism(Mechanism mechanism) {
        FakeSaslBroker broker = new FakeSaslBroker().withEnabledMechanisms("PLAIN");
        SaslInitiationFilter filter = filter(mechanism);

        assertAuthenticationFailure(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id);
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
        SaslInitiationConfig config = new SaslInitiationConfig(
                mechanism,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)));
        SaslInitiationRuntimeConfig runtime = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
        return new SaslInitiationFilter(runtime);
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

    private static Stream<Mechanism> scramMechanisms() {
        return Stream.of(Mechanism.SCRAM_SHA_256, Mechanism.SCRAM_SHA_512);
    }
}
