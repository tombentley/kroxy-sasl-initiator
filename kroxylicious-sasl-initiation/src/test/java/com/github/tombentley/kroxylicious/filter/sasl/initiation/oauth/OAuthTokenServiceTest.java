/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.oauth;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.security.oauthbearer.JwtRetriever;
import org.apache.kafka.common.security.oauthbearer.JwtRetrieverException;
import org.apache.kafka.common.security.oauthbearer.JwtValidator;
import org.apache.kafka.common.security.oauthbearer.JwtValidatorException;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.metrics.SaslInitiationMetrics;

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuthTokenServiceTest {

    private static final String CLIENT_ID = "alice-client";
    private static final String CLIENT_SECRET = "super-secret-client-secret";
    private static final String TOKEN_VALUE = "header.payload.signature";
    private static final String EXPECTED_SUBJECT = "alice";

    private final MutableClock clock = new MutableClock(1_000_000L);
    private SimpleMeterRegistry registry;

    @BeforeEach
    void setUpMetrics() {
        Metrics.globalRegistry.clear();
        registry = new SimpleMeterRegistry();
        Metrics.globalRegistry.add(registry);
    }

    @AfterEach
    void tearDownMetrics() {
        Metrics.globalRegistry.remove(registry);
        registry.close();
        Metrics.globalRegistry.clear();
    }

    @Test
    void returnsACachedTokenForTheSameIdentity() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            OAuthBearerToken first = service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            OAuthBearerToken second = service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();

            assertThat(second.value()).isEqualTo(first.value());
            assertThat(retriever.retrieveCount).hasValue(1);
            assertThat(validator.validateCount).hasValue(1);
            assertThat(service.cachedTokenCount()).isEqualTo(1);
        }
    }

    @Test
    void refreshesAnExpiredToken() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 10_000, 2);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            clock.advanceMillis(10_000);
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            assertThat(retriever.retrieveCount).hasValue(2);
        }
    }

    @Test
    void refreshesBeforeExpiryUsingTheSafetyMargin() {
        // A 5 minute token refreshes 30 seconds (10%) before expiry.
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 300_000, 2);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            clock.advanceMillis(269_999);
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            assertThat(retriever.retrieveCount).hasValue(1);

            clock.advanceMillis(1);
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            assertThat(retriever.retrieveCount).hasValue(2);
        }
    }

    @Test
    void usesAtMostSixtySecondsOfSafetyMarginForLongLivedTokens() {
        // A 1 hour token refreshes 60 seconds before expiry.
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 3_600_000, 2);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            clock.advanceMillis(3_539_999);
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            assertThat(retriever.retrieveCount).hasValue(1);

            clock.advanceMillis(1);
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            assertThat(retriever.retrieveCount).hasValue(2);
        }
    }

    @Test
    void boundsTheNumberOfCachedTokens() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 3_600_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            for (int i = 0; i < OAuthTokenCache.MAX_ENTRIES + 25; i++) {
                service.token("subject-" + i, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            }

            assertThat(service.cachedTokenCount()).isEqualTo(OAuthTokenCache.MAX_ENTRIES);
        }
    }

    @Test
    void removesExpiredEntriesWhenTheCacheGrows() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 1_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            for (int i = 0; i < 10; i++) {
                service.token("subject-" + i, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
            }
            clock.advanceMillis(1_000);
            service.token("new-subject", credential(EXPECTED_SUBJECT)).toCompletableFuture().join();

            assertThat(service.cachedTokenCount()).isEqualTo(1);
        }
    }

    @Test
    void performsOnlyOneRetrievalForConcurrentRequests() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        retriever.entered = entered;
        retriever.release = release;
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, null)) {
            CompletionStage<OAuthBearerToken> first = service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();

            CompletionStage<OAuthBearerToken> second = service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT));
            assertThat(retriever.retrieveCount).hasValue(1);
            assertThat(second.toCompletableFuture().isDone()).isFalse();

            release.countDown();
            assertThat(first.toCompletableFuture().get(5, TimeUnit.SECONDS).value()).isEqualTo(TOKEN_VALUE);
            assertThat(second.toCompletableFuture().get(5, TimeUnit.SECONDS).value()).isEqualTo(TOKEN_VALUE);
            assertThat(retriever.retrieveCount).hasValue(1);
        }
    }

    @Test
    void rejectsATokenWhoseSubjectDoesNotMatchTheExpectedSubject() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, "someone-else", 60_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            assertThatThrownBy(() -> service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join())
                    .hasRootCauseInstanceOf(OAuthTokenException.class)
                    .hasMessageContaining("subject")
                    .satisfies(error -> assertThat(error.getMessage()).doesNotContain(CLIENT_SECRET, TOKEN_VALUE));
        }
    }

    @Test
    void failsClosedWhenTheRetrieverFails() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        retriever.retrievalFailure = new JwtRetrieverException("failed with secret " + CLIENT_SECRET);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            assertThatThrownBy(() -> service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join())
                    .hasRootCauseInstanceOf(OAuthTokenException.class)
                    .hasMessageContaining("retrieval failed")
                    .satisfies(error -> assertThat(error.getMessage()).doesNotContain(CLIENT_SECRET, TOKEN_VALUE));
        }
    }

    @Test
    void failsClosedWhenTheValidatorFails() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        validator.validationFailure = new JwtValidatorException("invalid token " + TOKEN_VALUE);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            assertThatThrownBy(() -> service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join())
                    .hasRootCauseInstanceOf(OAuthTokenException.class)
                    .hasMessageContaining("validation failed")
                    .satisfies(error -> assertThat(error.getMessage()).doesNotContain(CLIENT_SECRET, TOKEN_VALUE));
        }
    }

    @Test
    void recordsSuccessfulTokenRetrievalDuration() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();
        }

        Timer success = registry.find(SaslInitiationMetrics.TOKEN_RETRIEVAL_DURATION_METRIC)
                .tag(SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_SUCCESS)
                .timer();
        assertThat(success).isNotNull();
        assertThat(success.count()).isEqualTo(1);
        assertThat(registry.find(SaslInitiationMetrics.TOKEN_RETRIEVAL_DURATION_METRIC)
                .tag(SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_FAILURE)
                .timer()).isNull();
        assertThat(registry.getMeters()).allSatisfy(meter -> assertThat(meter.getId().getTags())
                .extracting(tag -> tag.getKey())
                .isSubsetOf(java.util.Set.of(SaslInitiationMetrics.OUTCOME_TAG)));
    }

    @Test
    void recordsFailedTokenRetrievalDuration() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        retriever.retrievalFailure = new JwtRetrieverException("failed with secret " + CLIENT_SECRET);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            assertThatThrownBy(() -> service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join())
                    .hasRootCauseInstanceOf(OAuthTokenException.class);
        }

        Timer failure = registry.find(SaslInitiationMetrics.TOKEN_RETRIEVAL_DURATION_METRIC)
                .tag(SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_FAILURE)
                .timer();
        assertThat(failure).isNotNull();
        assertThat(failure.count()).isEqualTo(1);
        assertThat(registry.find(SaslInitiationMetrics.TOKEN_RETRIEVAL_DURATION_METRIC)
                .tag(SaslInitiationMetrics.OUTCOME_TAG, SaslInitiationMetrics.OUTCOME_SUCCESS)
                .timer()).isNull();
    }

    @Test
    void closesRetrieversValidatorsAndTheCache() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        OAuthTokenService service = service(retriever, validator, Runnable::run);
        service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();

        service.close();
        service.close();

        assertThat(retriever.closeCount).hasValue(1);
        assertThat(validator.closeCount).hasValue(1);
        assertThat(service.cachedTokenCount()).isZero();
        assertThatThrownBy(() -> service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join())
                .hasRootCauseInstanceOf(OAuthTokenException.class)
                .hasMessageContaining("closed");
    }

    @Test
    void buildsTheKafkaConfigurationAndJaasEntries() {
        try (OAuthClientCredential credential = oauthCredential(EXPECTED_SUBJECT)) {
            OAuthBearerConfig config = new OAuthBearerConfig(
                    "https://idp.example.com/token", "kafka", null, "preferred_username");

            Map<String, Object> kafkaConfigs = OAuthTokenService.buildKafkaConfigs(config, credential);

            assertThat(kafkaConfigs)
                    .containsEntry(SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL, "https://idp.example.com/token")
                    .containsEntry(SaslConfigs.SASL_OAUTHBEARER_SCOPE, "kafka")
                    .containsEntry(SaslConfigs.SASL_OAUTHBEARER_SUB_CLAIM_NAME, "preferred_username")
                    // HttpJwtRetriever requires these, and would otherwise fail to configure.
                    .containsEntry(SaslConfigs.SASL_LOGIN_RETRY_BACKOFF_MS,
                            SaslConfigs.DEFAULT_SASL_LOGIN_RETRY_BACKOFF_MS)
                    .containsEntry(SaslConfigs.SASL_LOGIN_RETRY_BACKOFF_MAX_MS,
                            SaslConfigs.DEFAULT_SASL_LOGIN_RETRY_BACKOFF_MAX_MS)
                    .containsEntry(SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_ID)
                    .containsEntry(SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_SECRET,
                            new Password(CLIENT_SECRET));
            assertThat(kafkaConfigs.toString()).doesNotContain(CLIENT_SECRET);
        }
    }

    @Test
    void doesNotExposeSecretsInStringForms() {
        FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
        FakeValidator validator = new FakeValidator(retriever);
        try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
            OAuthBearerToken token = service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join();

            assertThat(service.toString()).doesNotContain(CLIENT_SECRET, TOKEN_VALUE);
            assertThat(token.toString()).doesNotContain(CLIENT_SECRET, TOKEN_VALUE);
            assertThat(token.toString()).contains("REDACTED");
        }
    }

    @Test
    void doesNotLogTokensOrClientSecrets() {
        CapturingAppender appender = new CapturingAppender();
        appender.start();
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = loggerContext.getConfiguration();
        LoggerConfig loggerConfig = configuration.getLoggerConfig(OAuthTokenService.class.getName());
        Level previousLevel = loggerConfig.getLevel();
        loggerConfig.addAppender(appender, Level.DEBUG, null);
        loggerConfig.setLevel(Level.DEBUG);
        loggerContext.updateLoggers();
        try {
            FakeRetriever retriever = new FakeRetriever(clock, TOKEN_VALUE, EXPECTED_SUBJECT, 60_000, 1);
            retriever.retrievalFailure = new JwtRetrieverException(
                    "retriever failed with client secret " + CLIENT_SECRET + " and token " + TOKEN_VALUE);
            FakeValidator validator = new FakeValidator(retriever);
            try (OAuthTokenService service = service(retriever, validator, Runnable::run)) {
                assertThatThrownBy(() -> service.token(EXPECTED_SUBJECT, credential(EXPECTED_SUBJECT)).toCompletableFuture().join())
                        .hasRootCauseInstanceOf(OAuthTokenException.class);
            }

            assertThat(appender.text()).isNotBlank();
            assertThat(appender.text()).doesNotContain(CLIENT_SECRET, TOKEN_VALUE);
        }
        finally {
            loggerConfig.removeAppender(appender.getName());
            loggerConfig.setLevel(previousLevel);
            loggerContext.updateLoggers();
            appender.stop();
        }
    }

    private OAuthTokenService service(JwtRetriever retriever, JwtValidator validator, Executor executor) {
        OAuthBearerConfig config = new OAuthBearerConfig("https://idp.example.com/token", null);
        return new OAuthTokenService(
                config,
                IdentityMode.FIXED,
                null,
                clock,
                executor,
                (lookupKey, credential) -> new OAuthTokenService.JwtComponents(retriever, validator));
    }

    private static OAuthClientCredential credential(String expectedSubject) {
        return oauthCredential(expectedSubject);
    }

    private static OAuthClientCredential oauthCredential(String expectedSubject) {
        return new OAuthClientCredential(CLIENT_ID, DestroyableSecret.of(CLIENT_SECRET), expectedSubject);
    }

    private static final class FakeRetriever implements JwtRetriever {

        private final MutableClock clock;
        private final String tokenValue;
        private final String principalName;
        private final long lifetimeMillis;
        private final int distinctTokens;
        private final AtomicInteger retrieveCount = new AtomicInteger();
        private final AtomicInteger closeCount = new AtomicInteger();
        private volatile CountDownLatch entered;
        private volatile CountDownLatch release;
        private volatile RuntimeException retrievalFailure;

        private FakeRetriever(MutableClock clock,
                              String tokenValue,
                              String principalName,
                              long lifetimeMillis,
                              int distinctTokens) {
            this.clock = clock;
            this.tokenValue = tokenValue;
            this.principalName = principalName;
            this.lifetimeMillis = lifetimeMillis;
            this.distinctTokens = distinctTokens;
        }

        @Override
        public String retrieve() {
            int count = retrieveCount.incrementAndGet();
            if (entered != null) {
                entered.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new JwtRetrieverException(e);
                }
            }
            if (retrievalFailure != null) {
                throw retrievalFailure;
            }
            String value = count == 1 || distinctTokens == 1 ? tokenValue : tokenValue + "-" + count;
            return value;
        }

        @Override
        public void close() {
            closeCount.incrementAndGet();
        }
    }

    private static final class FakeValidator implements JwtValidator {

        private final FakeRetriever retriever;
        private final AtomicInteger validateCount = new AtomicInteger();
        private final AtomicInteger closeCount = new AtomicInteger();
        private volatile RuntimeException validationFailure;

        private FakeValidator(FakeRetriever retriever) {
            this.retriever = retriever;
        }

        @Override
        public OAuthBearerToken validate(String accessToken) {
            validateCount.incrementAndGet();
            if (validationFailure != null) {
                throw validationFailure;
            }
            return new BasicOAuthBearerToken(
                    accessToken,
                    Set.of("kafka"),
                    retriever.clock.millis() + retriever.lifetimeMillis,
                    retriever.principalName,
                    retriever.clock.millis());
        }

        @Override
        public void close() {
            closeCount.incrementAndGet();
        }
    }

    private static final class CapturingAppender extends AbstractAppender {

        private final StringBuilder text = new StringBuilder();

        private CapturingAppender() {
            super("oauth-token-service-capture", null, null, false, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(LogEvent event) {
            text.append(event.getMessage().getFormattedMessage()).append('\n');
            if (event.getThrown() != null) {
                text.append(event.getThrown()).append('\n');
            }
        }

        private String text() {
            return text.toString();
        }
    }

    private static final class MutableClock extends Clock {

        private final AtomicLong millis;

        private MutableClock(long initialMillis) {
            this.millis = new AtomicLong(initialMillis);
        }

        void advanceMillis(long durationMillis) {
            millis.addAndGet(durationMillis);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis());
        }

        @Override
        public long millis() {
            return millis.get();
        }
    }
}
