/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import org.apache.kafka.common.message.ApiVersionsRequestData;
import org.apache.kafka.common.message.ApiVersionsResponseData;
import org.apache.kafka.common.message.MetadataRequestData;
import org.apache.kafka.common.message.MetadataResponseData;
import org.apache.kafka.common.message.SaslAuthenticateResponseData;
import org.apache.kafka.common.message.SaslHandshakeResponseData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.protocol.Errors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation;

import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.testing.integration.Request;
import io.kroxylicious.testing.integration.Response;
import io.kroxylicious.testing.integration.ResponsePayload;
import io.kroxylicious.testing.integration.client.KafkaClient;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.MockServerKroxyliciousTester;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.INITIATION_STORE_PASSWORD;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeInitiationStore;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writePasswordFile;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.mockKafkaKroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Protocol-level integration tests for pipelining and backpressure during authentication and reauthentication.
 * <p>
 * A raw {@link KafkaClient} pipelines many metadata requests. A test-only {@link SaslResponseDelayFilter} holds the
 * upstream {@code SaslAuthenticate} response, so the proxy stays in the deferred-stage path while the requests are
 * queued. The mock broker records what actually reached it: no business request may overtake authentication, requests
 * must arrive in order, and {@link RequestCountingFilter} must observe only the in-flight request rather than a
 * filter-level backlog.
 * </p>
 */
class SaslInitiationPipeliningIT {

    private static final String FIXED_KEY = "pipeline-proxy-service";
    private static final int PIPELINED_REQUESTS = 400;
    private static final int TOPICS_PER_REQUEST = 160;
    private static final Duration WAIT = Duration.ofSeconds(20);

    @TempDir
    Path tempDir;

    @Test
    void shouldNotForwardPipelinedRequestsBeforeInitialAuthenticationCompletes() throws Exception {
        String counterName = "pipeline-initial-counter";
        String gateName = "pipeline-initial-gate";
        AtomicInteger counter = RequestCountingFilter.register(counterName);
        SaslResponseDelayFilter.Gate gate = SaslResponseDelayFilter.register(gateName);
        try (MockServerKroxyliciousTester tester = startTester("PLAIN", 0.8, 0L, 1, counterName, gateName);
                KafkaClient client = tester.simpleTestClient()) {
            addMockResponses(tester, 0L);

            Response versions = client.getSync(apiVersionsRequest("pipeline-bootstrap"));
            assertThat(Errors.forCode(((ApiVersionsResponseData) versions.payload().message()).errorCode()))
                    .isEqualTo(Errors.NONE);
            counter.set(0);

            // Trigger authentication with a single request, then wait until its upstream SaslAuthenticate response is
            // held by the gate. Waiting first makes the in-flight count deterministic: pipelining the remaining
            // requests before the deferred stage is established races with the runtime's read batch.
            CompletableFuture<Response> trigger = client.get(metadataRequest("pipeline-trigger"));
            assertThat(gate.awaitBlocked(WAIT)).isTrue();
            assertThat(counter.get()).isEqualTo(1);
            assertThat(tester.getRequestsForApiKey(ApiKeys.METADATA)).isEmpty();

            List<CompletableFuture<Response>> responses = new ArrayList<>();
            responses.add(trigger);
            responses.addAll(pipeline(client, "pipeline"));
            assertThat(counter.get()).isEqualTo(1);
            assertThat(tester.getRequestsForApiKey(ApiKeys.METADATA)).isEmpty();

            gate.release();
            CompletableFuture.allOf(responses.toArray(CompletableFuture[]::new)).get(WAIT.toSeconds(), TimeUnit.SECONDS);

            assertThat(counter.get()).isEqualTo(PIPELINED_REQUESTS + 1);
            assertOrderedMetadataRequests(tester, "pipeline");
        }
        finally {
            SaslResponseDelayFilter.unregister(gateName);
            RequestCountingFilter.unregister(counterName);
        }
    }

    @Test
    void shouldNotForwardPipelinedRequestsBeforeReauthenticationCompletes() throws Exception {
        String counterName = "pipeline-reauth-counter";
        String gateName = "pipeline-reauth-gate";
        AtomicInteger counter = RequestCountingFilter.register(counterName);
        SaslResponseDelayFilter.Gate gate = SaslResponseDelayFilter.register(gateName);
        try (MockServerKroxyliciousTester tester = startTester("PLAIN", 0.5, 4_000L, 2, counterName, gateName);
                KafkaClient client = tester.simpleTestClient()) {
            addMockResponses(tester, 4_000L);

            Response versions = client.getSync(apiVersionsRequest("reauth-bootstrap"));
            assertThat(Errors.forCode(((ApiVersionsResponseData) versions.payload().message()).errorCode()))
                    .isEqualTo(Errors.NONE);
            client.getSync(metadataRequest("reauth-initial")).payload().message();
            counter.set(0);

            TimeUnit.MILLISECONDS.sleep(2_400);

            CompletableFuture<Response> trigger = client.get(metadataRequest("reauth-trigger"));
            assertThat(gate.awaitBlocked(WAIT)).isTrue();
            assertThat(counter.get()).isEqualTo(1);
            assertThat(tester.getRequestsForApiKey(ApiKeys.METADATA)).hasSize(1);

            List<CompletableFuture<Response>> responses = new ArrayList<>();
            responses.add(trigger);
            responses.addAll(pipeline(client, "reauth"));
            assertThat(counter.get()).isEqualTo(1);
            assertThat(tester.getRequestsForApiKey(ApiKeys.METADATA)).hasSize(1);

            gate.release();
            CompletableFuture.allOf(responses.toArray(CompletableFuture[]::new)).get(WAIT.toSeconds(), TimeUnit.SECONDS);

            assertThat(counter.get()).isEqualTo(PIPELINED_REQUESTS + 1);
            assertOrderedMetadataRequests(tester, "reauth");
            assertThat(tester.getRequestsForApiKey(ApiKeys.METADATA))
                    .first()
                    .extracting(Request::clientIdHeader)
                    .isEqualTo("reauth-initial");
        }
        finally {
            SaslResponseDelayFilter.unregister(gateName);
            RequestCountingFilter.unregister(counterName);
        }
    }

    private MockServerKroxyliciousTester startTester(String mechanism,
                                                     double windowFactor,
                                                     long sessionLifetimeMs,
                                                     int delayOrdinal,
                                                     String counterName,
                                                     String gateName)
            throws Exception {
        Path store = writeInitiationStore(tempDir.resolve("pipeline-credentials.p12"),
                new CompositionTestSupport.Credential(FIXED_KEY, "pipeline-broker", "pipeline-broker-password"));
        Path passwordFile = writePasswordFile(tempDir.resolve("pipeline-credentials.password"), INITIATION_STORE_PASSWORD);
        NamedFilterDefinition counting = RequestCountingFilter.definition("request-counter", counterName);
        NamedFilterDefinition initiation = initiationDefinition(mechanism, windowFactor, sessionLifetimeMs, store, passwordFile);
        NamedFilterDefinition delay = SaslResponseDelayFilter.definition("sasl-response-delay", gateName, delayOrdinal);

        return mockKafkaKroxyliciousTester(bootstrap -> proxy(bootstrap)
                .addToFilterDefinitions(counting, initiation, delay)
                .addToDefaultFilters(counting.name(), initiation.name(), delay.name()));
    }

    private NamedFilterDefinition initiationDefinition(String mechanism,
                                                       double windowFactor,
                                                       long sessionLifetimeMs,
                                                       Path store,
                                                       Path passwordFile) {
        Map<String, Object> config;
        if (sessionLifetimeMs > 0) {
            config = Map.of(
                    "mechanism", mechanism,
                    "identity", Map.of("mode", "fixed", "key", FIXED_KEY),
                    "keyStore", Map.of(
                            "file", store.toString(),
                            "filePassword", Map.of("passwordFile", passwordFile.toString())),
                    "reauth", Map.of("windowFactor", windowFactor));
        }
        else {
            config = Map.of(
                    "mechanism", mechanism,
                    "identity", Map.of("mode", "fixed", "key", FIXED_KEY),
                    "keyStore", Map.of(
                            "file", store.toString(),
                            "filePassword", Map.of("passwordFile", passwordFile.toString())));
        }
        return new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(config)
                .build();
    }

    private static void addMockResponses(MockServerKroxyliciousTester tester, long sessionLifetimeMs) {
        tester.addMockResponseForApiKey(new ResponsePayload(ApiKeys.API_VERSIONS, (short) 0,
                apiVersionsResponse(), (short) 0));
        tester.addMockResponseForApiKey(new ResponsePayload(ApiKeys.SASL_HANDSHAKE, (short) 1,
                new SaslHandshakeResponseData()
                        .setErrorCode(Errors.NONE.code())
                        .setMechanisms(List.of("PLAIN")),
                (short) 1));
        tester.addMockResponseForApiKey(new ResponsePayload(ApiKeys.SASL_AUTHENTICATE, (short) 2,
                new SaslAuthenticateResponseData()
                        .setErrorCode(Errors.NONE.code())
                        .setAuthBytes(new byte[0])
                        .setSessionLifetimeMs(sessionLifetimeMs),
                (short) 2));
        tester.addMockResponseForApiKey(new ResponsePayload(ApiKeys.METADATA, (short) 0,
                new MetadataResponseData(), (short) 0));
    }

    private static ApiVersionsResponseData apiVersionsResponse() {
        ApiVersionsResponseData response = new ApiVersionsResponseData().setErrorCode(Errors.NONE.code());
        response.apiKeys().add(new ApiVersionsResponseData.ApiVersion()
                .setApiKey(ApiKeys.SASL_HANDSHAKE.id)
                .setMinVersion(ApiKeys.SASL_HANDSHAKE.oldestVersion())
                .setMaxVersion(ApiKeys.SASL_HANDSHAKE.latestVersion()));
        response.apiKeys().add(new ApiVersionsResponseData.ApiVersion()
                .setApiKey(ApiKeys.SASL_AUTHENTICATE.id)
                .setMinVersion(ApiKeys.SASL_AUTHENTICATE.oldestVersion())
                .setMaxVersion(ApiKeys.SASL_AUTHENTICATE.latestVersion()));
        return response;
    }

    private static Request apiVersionsRequest(String clientId) {
        return new Request(ApiKeys.API_VERSIONS, (short) 0, clientId, new ApiVersionsRequestData());
    }

    private static Request metadataRequest(String clientId) {
        return new Request(ApiKeys.METADATA, (short) 0, clientId, metadataBody(clientId));
    }

    private static MetadataRequestData metadataBody(String clientId) {
        MetadataRequestData request = new MetadataRequestData();
        for (int topic = 0; topic < TOPICS_PER_REQUEST; topic++) {
            request.topics().add(new MetadataRequestData.MetadataRequestTopic()
                    .setName("pipeline-topic-" + clientId + "-" + topic));
        }
        return request;
    }

    private static List<CompletableFuture<Response>> pipeline(KafkaClient client, String prefix) {
        return IntStream.range(0, PIPELINED_REQUESTS)
                .mapToObj(index -> client.get(metadataRequest(prefix + "-" + index)))
                .toList();
    }

    private static void assertOrderedMetadataRequests(MockServerKroxyliciousTester tester, String prefix) {
        List<Request> metadataRequests = tester.getRequestsForApiKey(ApiKeys.METADATA);
        assertThat(metadataRequests).hasSize(PIPELINED_REQUESTS + ("reauth".equals(prefix) ? 2 : 1));
        assertThat(metadataRequests)
                .extracting(Request::clientIdHeader)
                .containsExactlyElementsOf(expectedClientIds(prefix));
    }

    private static List<String> expectedClientIds(String prefix) {
        List<String> clientIds = new ArrayList<>();
        if ("reauth".equals(prefix)) {
            clientIds.add("reauth-initial");
        }
        clientIds.add(prefix + "-trigger");
        IntStream.range(0, PIPELINED_REQUESTS).mapToObj(index -> prefix + "-" + index).forEach(clientIds::add);
        return clientIds;
    }
}
