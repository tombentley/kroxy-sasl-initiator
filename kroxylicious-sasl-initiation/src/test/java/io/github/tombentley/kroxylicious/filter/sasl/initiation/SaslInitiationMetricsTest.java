/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.metrics.SaslInitiationMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies the metrics recorded by the SASL initiation filter.
 * <p>
 * Each test installs a fresh {@link SimpleMeterRegistry} in Micrometer's global registry so that assertions see only the
 * meters created by that test.
 * </p>
 */
class SaslInitiationMetricsTest {

    private static final double WINDOW_FACTOR = 0.8;
    private static final Set<String> ALLOWED_TAG_KEYS = Set.of(
            SaslInitiationMetrics.MECHANISM_TAG,
            SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG,
            SaslInitiationMetrics.OUTCOME_TAG,
            SaslInitiationMetrics.REASON_TAG);

    @TempDir
    Path tempDir;

    private Path storeFile;
    private SimpleMeterRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        Metrics.globalRegistry.clear();
        registry = new SimpleMeterRegistry();
        Metrics.globalRegistry.add(registry);
        storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
    }

    @AfterEach
    void tearDown() {
        Metrics.globalRegistry.remove(registry);
        registry.close();
        Metrics.globalRegistry.clear();
    }

    @Test
    void recordsSuccessfulInitialAuthentication() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(5000);
        SaslInitiationFilter filter = filter();
        String virtualCluster = "vc-metrics-success";
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, virtualCluster, "session-success", broker);

        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(counter(SaslInitiationMetrics.AUTH_ATTEMPTS_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster,
                SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_SUCCESS)).isEqualTo(1.0);
        assertThat(timerCount(SaslInitiationMetrics.AUTH_DURATION_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster)).isEqualTo(1);
        assertThat(registry.find(SaslInitiationMetrics.CONNECTION_CLOSED_METRIC).counter()).isNull();
    }

    @Test
    void recordsFailedInitialAuthenticationAndConnectionClose() {
        FakeSaslBroker broker = new FakeSaslBroker()
                .withCredentials(FakeSaslBroker.BROKER_USERNAME, "the-wrong-password");
        SaslInitiationFilter filter = filter();
        String virtualCluster = "vc-metrics-failure";
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, virtualCluster, "session-failure", broker);

        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(counter(SaslInitiationMetrics.AUTH_ATTEMPTS_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster,
                SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_FAILURE)).isEqualTo(1.0);
        assertThat(timerCount(SaslInitiationMetrics.AUTH_DURATION_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster)).isEqualTo(1);
        assertThat(counter(SaslInitiationMetrics.CONNECTION_CLOSED_METRIC,
                SaslInitiationMetrics.REASON_TAG, "auth-failure")).isEqualTo(1.0);
    }

    @Test
    void recordsSuccessfulReauthentication() {
        MutableClock clock = new MutableClock(Instant.ofEpochMilli(System.currentTimeMillis()));
        RecordingTaskScheduler taskScheduler = new RecordingTaskScheduler();
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = filter(clock, taskScheduler);
        String virtualCluster = "vc-metrics-reauth-success";
        authenticate(filter, broker, virtualCluster, "session-reauth-success-1");

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, virtualCluster, "session-reauth-success-2", broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(counter(SaslInitiationMetrics.AUTH_ATTEMPTS_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster,
                SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_SUCCESS)).isEqualTo(1.0);
        assertThat(counter(SaslInitiationMetrics.REAUTH_ATTEMPTS_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster,
                SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_SUCCESS)).isEqualTo(1.0);
        assertThat(timerCount(SaslInitiationMetrics.REAUTH_DURATION_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster)).isEqualTo(1);
    }

    @Test
    void recordsFailedReauthenticationAndConnectionClose() {
        MutableClock clock = new MutableClock(Instant.ofEpochMilli(System.currentTimeMillis()));
        RecordingTaskScheduler taskScheduler = new RecordingTaskScheduler();
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(10_000);
        SaslInitiationFilter filter = filter(clock, taskScheduler);
        String virtualCluster = "vc-metrics-reauth-failure";
        authenticate(filter, broker, virtualCluster, "session-reauth-failure-1");
        broker.withEnabledMechanisms(Mechanism.SCRAM_SHA_256.mechanismName());

        clock.advance(Duration.ofMillis(8_000));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, virtualCluster, "session-reauth-failure-2", broker);
        assertFailure(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(counter(SaslInitiationMetrics.REAUTH_ATTEMPTS_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster,
                SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_FAILURE)).isEqualTo(1.0);
        assertThat(timerCount(SaslInitiationMetrics.REAUTH_DURATION_METRIC,
                SaslInitiationMetrics.MECHANISM_TAG, "PLAIN",
                SaslInitiationMetrics.VIRTUAL_CLUSTER_TAG, virtualCluster)).isEqualTo(1);
        assertThat(counter(SaslInitiationMetrics.CONNECTION_CLOSED_METRIC,
                SaslInitiationMetrics.REASON_TAG, "reauth-failure")).isEqualTo(1.0);
    }

    @Test
    void doesNotUseIdentityValuesAsMetricTags() {
        FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(5000);
        SaslInitiationFilter filter = filter();
        String virtualCluster = "vc-metrics-tags";
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, virtualCluster, "session-tags", broker);

        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

        assertThat(registry.getMeters()).isNotEmpty();
        assertThat(registry.getMeters()).allSatisfy(meter -> {
            assertThat(meter.getId().getTags()).extracting(tag -> tag.getKey())
                    .isSubsetOf(ALLOWED_TAG_KEYS);
            assertThat(meter.getId().getTags()).extracting(tag -> tag.getKey())
                    .doesNotContain("subject", "username", "brokerUsername", "brokerIdentity", "sessionId");
        });
    }

    private SaslInitiationFilter filter() {
        return new SaslInitiationFilter(runtime());
    }

    private SaslInitiationFilter filter(MutableClock clock, RecordingTaskScheduler taskScheduler) {
        return new SaslInitiationFilter(runtime(), null,
                ReauthScheduler.with(clock, WINDOW_FACTOR, taskScheduler, () -> 0.0));
    }

    private SaslInitiationRuntimeConfig runtime() {
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.PLAIN,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)));
        return new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
    }

    private MockFilterContext authenticate(SaslInitiationFilter filter,
                                           FakeSaslBroker broker,
                                           String virtualCluster,
                                           String sessionId) {
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, virtualCluster, sessionId, broker);
        assertForward(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));
        return context;
    }

    private double counter(String name, String... tags) {
        Counter counter = registry.find(name).tags(tags).counter();
        assertThat(counter).as("counter %s with tags %s", name, Arrays.toString(tags)).isNotNull();
        return counter.count();
    }

    private long timerCount(String name, String... tags) {
        Timer timer = registry.find(name).tags(tags).timer();
        assertThat(timer).as("timer %s with tags %s", name, Arrays.toString(tags)).isNotNull();
        return timer.count();
    }

    private static void assertForward(java.util.concurrent.CompletionStage<RequestFilterResult> stage) {
        assertThat(stage)
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());
    }

    private static void assertFailure(java.util.concurrent.CompletionStage<RequestFilterResult> stage) {
        assertThat(stage)
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));
    }

    private static MockFilterContext context(RequestHeaderData header,
                                             ApiMessage request,
                                             String virtualCluster,
                                             String sessionId,
                                             FakeSaslBroker broker) {
        return MockFilterContext.builder(header, request)
                .withVirtualClusterName(virtualCluster)
                .withSessionId(sessionId)
                .withSendRequestHandler(broker)
                .build();
    }

    private static RequestHeaderData header() {
        return new RequestHeaderData()
                .setRequestApiKey(ApiKeys.METADATA.id)
                .setRequestApiVersion((short) 0);
    }
}
