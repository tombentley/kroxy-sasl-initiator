/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.kafka.common.security.oauthbearer.JwtRetriever;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.OAuthEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.proxy.filter.FilterDispatchExecutor;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Proves that a blocking OAuth token retrieval does not run on, or block, the connection's filter-dispatch thread.
 */
public class SaslOAuthBearerBlockingRetrieverTest {

    @TempDir
    Path tempDir;

    @Test
    void doesNotBlockTheFilterDispatchThreadWhileRetrievingAToken() throws Exception {
        BlockingJwtRetriever.reset();
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new OAuthEntry("proxy-service", "alice-client", "client-secret", "alice"));
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)),
                new OAuthBearerConfig("https://idp.example.com/token", "kafka", BlockingJwtRetriever.class.getName(), null));
        SaslInitiationRuntimeConfig runtime = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);

        ExecutorService dispatchThread = Executors.newSingleThreadExecutor(runnable -> new Thread(runnable, "filter-dispatch"));
        try {
            FilterDispatchExecutor dispatchExecutor = dispatchExecutor(dispatchThread);
            SaslInitiationFilter filter = new SaslInitiationFilter(runtime, dispatchExecutor);
            FakeSaslBroker broker = broker();
            RequestHeaderData header = new RequestHeaderData()
                    .setRequestApiKey(ApiKeys.METADATA.id)
                    .setRequestApiVersion((short) 0);
            MetadataRequestData request = new MetadataRequestData();
            MockFilterContext context = MockFilterContext.builder(header, request)
                    .withSendRequestHandler(broker)
                    .build();

            Future<CompletionStage<RequestFilterResult>> submitted = dispatchThread.submit(
                    () -> filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context));

            assertThat(BlockingJwtRetriever.enter.await(5, TimeUnit.SECONDS)).isTrue();
            CompletionStage<RequestFilterResult> resultStage = submitted.get(5, TimeUnit.SECONDS);
            assertThat(resultStage.toCompletableFuture().isDone()).isFalse();
            assertThat(BlockingJwtRetriever.retrievalThread.get()).isNotEqualTo("filter-dispatch");

            // The dispatch thread is free to do other work while retrieval is blocked in the fake retriever.
            Future<String> marker = dispatchThread.submit(() -> "dispatch-thread-was-free");
            assertThat(marker.get(2, TimeUnit.SECONDS)).isEqualTo("dispatch-thread-was-free");

            BlockingJwtRetriever.release.countDown();

            assertThat(resultStage).succeedsWithin(Duration.ofSeconds(5))
                    .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());
            assertThat(filter.state())
                    .isInstanceOfSatisfying(SaslExchangeState.Authenticated.class,
                            authenticated -> assertThat(authenticated.sessionLifetimeMs()).isEqualTo(5000));
        }
        finally {
            BlockingJwtRetriever.release.countDown();
            runtime.oauthTokenService().close();
            runtime.credentialStore().close();
            dispatchThread.shutdownNow();
        }
    }

    private static FakeSaslBroker broker() {
        OAuthBearerToken token = new BasicOAuthBearerToken(
                BlockingJwtRetriever.TOKEN,
                Set.of("kafka"),
                System.currentTimeMillis() + 3_600_000L,
                "alice",
                System.currentTimeMillis());
        return new FakeSaslBroker()
                .withEnabledMechanisms("OAUTHBEARER")
                .withOAuthBearerToken(token)
                .withSessionLifetimeMs(5000);
    }

    private static FilterDispatchExecutor dispatchExecutor(ExecutorService dispatchThread) {
        FilterDispatchExecutor executor = mock(FilterDispatchExecutor.class);
        when(executor.isInFilterDispatchThread())
                .thenAnswer(invocation -> Thread.currentThread().getName().equals("filter-dispatch"));
        when(executor.completeOnFilterDispatchThread(any())).thenAnswer(invocation -> {
            CompletionStage<?> input = invocation.getArgument(0);
            CompletableFuture<Object> output = new CompletableFuture<>();
            input.whenComplete((value, error) -> dispatchThread.execute(() -> {
                if (error != null) {
                    output.completeExceptionally(error);
                }
                else {
                    output.complete(value);
                }
            }));
            return output;
        });
        return executor;
    }

    /**
     * A retriever that blocks until the test releases it.
     */
    public static class BlockingJwtRetriever implements JwtRetriever {

        static final String TOKEN = TestJwts.validToken("alice");
        static final AtomicReference<String> retrievalThread = new AtomicReference<>();
        static volatile CountDownLatch enter;
        static volatile CountDownLatch release;

        static void reset() {
            retrievalThread.set(null);
            enter = new CountDownLatch(1);
            release = new CountDownLatch(1);
        }

        @Override
        public String retrieve() {
            retrievalThread.set(Thread.currentThread().getName());
            enter.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while blocking the test retriever");
            }
            return TOKEN;
        }
    }
}
