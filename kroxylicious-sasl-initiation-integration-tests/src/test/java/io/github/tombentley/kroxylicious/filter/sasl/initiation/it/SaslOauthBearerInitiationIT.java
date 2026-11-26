/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.message.DescribeClusterRequestData;
import org.apache.kafka.common.message.DescribeClusterResponseData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.protocol.Errors;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.serialization.Serdes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.OAuthEntry;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.PasswordEntry;

import io.kroxylicious.filter.sasl.termination.SaslTermination;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.testing.integration.Request;
import io.kroxylicious.testing.integration.client.KafkaClient;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousTester;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.BrokerConfig;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.EXPECTED_AUDIENCE;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.EXPECTED_ISSUER;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.JWKS_ENDPOINT_URL;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.LONG_SINCE_EXPIRED_TOKEN;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.TOKEN_ENDPOINT_URL;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.allowUrl;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.captureLogs;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.fetchAccessToken;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.writeOAuthStore;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.writePasswordFile;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.writePasswordStore;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.it.OAuthBearerTestSupport.writeTokenFile;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * Real-Kafka integration tests for OAUTHBEARER SASL initiation, backed by a mock OAuth/OIDC server container.
 * <p>
 * These tests are Docker-gated. They cover fixed token-file and client-credentials identities, subject-derived OAuth
 * client credentials, expected-subject verification, expired tokens, log redaction and composition with client-side
 * OAUTHBEARER termination.
 * </p>
 */
@Tag("docker")
@EnabledIf(value = "isDockerAvailable", disabledReason = "docker unavailable")
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslOauthBearerInitiationIT {

    private static final String STORE_PASSWORD = "oauth-initiation-store-password";
    private static final String CLIENT_ID = "proxy-service-client";
    private static final String CLIENT_SECRET = "proxy-service-client-secret-9f8e7d6c";
    private static final String ALICE_SUBJECT = "alice";
    private static final String ALICE_CLIENT_ID = "alice-client";
    private static final String ALICE_CLIENT_SECRET = "alice-client-secret-1a2b3c4d";
    private static final String BOB_SUBJECT = "bob";
    private static final String BOB_CLIENT_ID = "bob-client";
    private static final String BOB_CLIENT_SECRET = "bob-client-secret-5e6f7a8b";
    private static final String BROKER_USERNAME = "svc-initiation";
    private static final String BROKER_PASSWORD = "svc-initiation-password-123";
    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final Duration CLOSE_TIMEOUT = Duration.ofSeconds(10);
    private static final Map<String, Object> FAILING_PRODUCER_CONFIGURATION = Map.of(
            ProducerConfig.MAX_BLOCK_MS_CONFIG, 10_000,
            ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10_000,
            ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5_000);

    private static OAuthBearerTestSupport.OauthServerContainer oauthServer;
    private static String previousAllowedUrls;

    @TempDir
    Path tempDir;

    @BeforeAll
    static void startOauthServer() {
        previousAllowedUrls = System.getProperty(OAuthBearerTestSupport.ALLOWED_URLS_PROPERTY);
        System.setProperty(OAuthBearerTestSupport.ALLOWED_URLS_PROPERTY, OAuthBearerTestSupport.baseAllowedUrls());
        oauthServer = OAuthBearerTestSupport.startOauthServer();
    }

    @AfterAll
    static void stopOauthServer() {
        if (oauthServer != null) {
            oauthServer.close();
        }
        if (previousAllowedUrls == null) {
            System.clearProperty(OAuthBearerTestSupport.ALLOWED_URLS_PROPERTY);
        }
        else {
            System.setProperty(OAuthBearerTestSupport.ALLOWED_URLS_PROPERTY, previousAllowedUrls);
        }
    }

    static boolean isDockerAvailable() {
        return DockerClientFactory.instance().isDockerAvailable();
    }

    @Test
    void shouldAuthenticateWithFixedIdentityAndATokenFile(
                                                          @SaslMechanism(value = "OAUTHBEARER") @BrokerConfig(name = "listener.name.external.oauthbearer.sasl.server.callback.handler.class", value = "org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwt.validator.class", value = "org.apache.kafka.common.security.oauthbearer.BrokerJwtValidator") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwks.endpoint.url", value = JWKS_ENDPOINT_URL) @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.expected.audience", value = EXPECTED_AUDIENCE) KafkaCluster cluster,
                                                          Topic topic)
            throws Exception {
        String token = fetchAccessToken(CLIENT_ID, CLIENT_SECRET);
        Path tokenFile = writeTokenFile(tempDir.resolve("token.jwt"), token);
        allowUrl(tokenFile.toUri());

        var initiation = tokenFileDefinition(tokenFile);
        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var logs = captureLogs()) {
            try (var tester = kroxyliciousTester(config);
                    var producer = tester.producer();
                    var consumer = tester.consumer(Serdes.String(), Serdes.String(), consumerConfiguration("oauth-file-token-group"))) {
                assertProduceAndConsume(producer, consumer, topic);
            }
            assertThat(logs.text()).doesNotContain(token, CLIENT_SECRET);
        }
    }

    @Test
    void shouldAuthenticateWithFixedIdentityAndClientCredentials(
                                                                 @SaslMechanism(value = "OAUTHBEARER") @BrokerConfig(name = "listener.name.external.oauthbearer.sasl.server.callback.handler.class", value = "org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwt.validator.class", value = "org.apache.kafka.common.security.oauthbearer.BrokerJwtValidator") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwks.endpoint.url", value = JWKS_ENDPOINT_URL) @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.expected.audience", value = EXPECTED_AUDIENCE) KafkaCluster cluster,
                                                                 Topic topic)
            throws Exception {
        Path store = writeOAuthStore(tempDir.resolve("fixed-oauth.p12"), STORE_PASSWORD,
                new OAuthEntry("proxy-service", CLIENT_ID, CLIENT_SECRET, CLIENT_ID));
        var initiation = oauthStoreDefinition(Map.of("mode", "fixed", "key", "proxy-service"), store);
        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var logs = captureLogs()) {
            try (var tester = kroxyliciousTester(config);
                    var producer = tester.producer();
                    var consumer = tester.consumer(Serdes.String(), Serdes.String(), consumerConfiguration("oauth-client-credentials-group"))) {
                assertProduceAndConsume(producer, consumer, topic);
            }
            assertThat(logs.text()).doesNotContain(CLIENT_SECRET);
        }
    }

    @Test
    void shouldSelectPerSubjectOAuthClientCredentials(
                                                      @SaslMechanism(value = "OAUTHBEARER") @BrokerConfig(name = "listener.name.external.oauthbearer.sasl.server.callback.handler.class", value = "org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwt.validator.class", value = "org.apache.kafka.common.security.oauthbearer.BrokerJwtValidator") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwks.endpoint.url", value = JWKS_ENDPOINT_URL) @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.expected.audience", value = EXPECTED_AUDIENCE) KafkaCluster cluster,
                                                      Topic topic)
            throws Exception {
        Path store = writeOAuthStore(tempDir.resolve("subject-oauth.p12"), STORE_PASSWORD,
                new OAuthEntry(ALICE_SUBJECT, ALICE_CLIENT_ID, ALICE_CLIENT_SECRET, ALICE_CLIENT_ID),
                new OAuthEntry(BOB_SUBJECT, BOB_CLIENT_ID, BOB_CLIENT_SECRET, BOB_CLIENT_ID));
        var fixedSubject = new NamedFilterDefinitionBuilder("fixed-subject", FixedSubjectFilter.class.getName())
                .withConfig(Map.of("subject", ALICE_SUBJECT))
                .build();
        var initiation = oauthStoreDefinition(Map.of("mode", "subject"), store);
        var observer = CompositionObserverFilter.definition("oauth-observer");

        var config = proxy(cluster)
                .addToFilterDefinitions(fixedSubject, initiation, observer)
                .addToDefaultFilters(fixedSubject.name(), initiation.name(), observer.name());

        try (var tester = kroxyliciousTester(config);
                var producer = tester.producer();
                var consumer = tester.consumer(Serdes.String(), Serdes.String(), consumerConfiguration("oauth-subject-group"))) {
            assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                    .succeedsWithin(TIMEOUT);

            consumer.subscribe(List.of(topic.name()));

            assertThat(consumer.poll(TIMEOUT).records(topic.name()))
                    .singleElement()
                    .satisfies(record -> {
                        assertThat(record.key()).isEqualTo("key");
                        assertThat(record.value()).isEqualTo("value");
                        assertThat(headerValue(record, CompositionObserverFilter.UPSTREAM_MECHANISM_HEADER))
                                .isEqualTo("OAUTHBEARER");
                        assertThat(headerValue(record, CompositionObserverFilter.UPSTREAM_OAUTH_SUBJECT_HEADER))
                                .isEqualTo(ALICE_CLIENT_ID);
                    });
        }
    }

    @Test
    void shouldFailGenericallyWhenTheExpectedSubjectDoesNotMatch(
                                                                 @SaslMechanism(value = "OAUTHBEARER") @BrokerConfig(name = "listener.name.external.oauthbearer.sasl.server.callback.handler.class", value = "org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwt.validator.class", value = "org.apache.kafka.common.security.oauthbearer.BrokerJwtValidator") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwks.endpoint.url", value = JWKS_ENDPOINT_URL) @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.expected.audience", value = EXPECTED_AUDIENCE) KafkaCluster cluster)
            throws Exception {
        Path store = writeOAuthStore(tempDir.resolve("wrong-subject-oauth.p12"), STORE_PASSWORD,
                new OAuthEntry("proxy-service", CLIENT_ID, CLIENT_SECRET, "someone-else"));
        var initiation = oauthStoreDefinition(Map.of("mode", "fixed", "key", "proxy-service"), store);
        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var tester = kroxyliciousTester(config)) {
            assertGenericFailureAndClose(tester);
        }
    }

    @Test
    void shouldFailClosedForAnExpiredTokenWithoutLoggingIt(
                                                           @SaslMechanism(value = "OAUTHBEARER") @BrokerConfig(name = "listener.name.external.oauthbearer.sasl.server.callback.handler.class", value = "org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallbackHandler") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwt.validator.class", value = "org.apache.kafka.common.security.oauthbearer.BrokerJwtValidator") @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.jwks.endpoint.url", value = JWKS_ENDPOINT_URL) @BrokerConfig(name = "listener.name.external.sasl.oauthbearer.expected.audience", value = EXPECTED_AUDIENCE) KafkaCluster cluster)
            throws Exception {
        Path tokenFile = writeTokenFile(tempDir.resolve("expired.jwt"), LONG_SINCE_EXPIRED_TOKEN);
        allowUrl(tokenFile.toUri());
        var initiation = tokenFileDefinition(tokenFile);
        var config = proxy(cluster)
                .addToFilterDefinitions(initiation)
                .addToDefaultFilters(initiation.name());

        try (var logs = captureLogs()) {
            try (var tester = kroxyliciousTester(config)) {
                assertGenericFailureAndClose(tester);
            }
            assertThat(logs.text()).doesNotContain(LONG_SINCE_EXPIRED_TOKEN);
        }
    }

    @Test
    void shouldComposeOAuthTerminationWithScramInitiation(
                                                          @SaslMechanism(value = "SCRAM-SHA-256", principals = {
                                                                  @SaslMechanism.Principal(user = BROKER_USERNAME, password = BROKER_PASSWORD) }) KafkaCluster cluster,
                                                          Topic topic)
            throws Exception {
        Path initiationStore = writePasswordStore(tempDir.resolve("composition-initiation.p12"), STORE_PASSWORD,
                new PasswordEntry("proxy-service", BROKER_USERNAME, BROKER_PASSWORD));
        Path initiationPassword = writePasswordFile(tempDir.resolve("composition-initiation.password"), STORE_PASSWORD);
        var initiation = passwordDefinition(initiationStore, initiationPassword);
        var termination = terminationDefinition();

        var config = proxy(cluster)
                .addToFilterDefinitions(termination, initiation)
                .addToDefaultFilters(termination.name(), initiation.name());

        Map<String, Object> producerConfiguration = oauthClientConfiguration(CLIENT_ID, CLIENT_SECRET);
        producerConfiguration.put(CommonClientConfigs.CLIENT_ID_CONFIG, "oauth-termination-producer");
        Map<String, Object> consumerConfiguration = oauthClientConfiguration(CLIENT_ID, CLIENT_SECRET);
        consumerConfiguration.put(CommonClientConfigs.CLIENT_ID_CONFIG, "oauth-termination-consumer");
        consumerConfiguration.put(ConsumerConfig.GROUP_ID_CONFIG, "oauth-termination-group");
        consumerConfiguration.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        try (var tester = kroxyliciousTester(config);
                var producer = tester.producer(producerConfiguration);
                var consumer = tester.consumer(consumerConfiguration)) {
            assertProduceAndConsume(producer, consumer, topic);
        }
    }

    @Test
    void shouldFailClosedForAWrongBrokerCredentialDuringOAuthComposition(
                                                                         @SaslMechanism(value = "SCRAM-SHA-256", principals = {
                                                                                 @SaslMechanism.Principal(user = BROKER_USERNAME, password = BROKER_PASSWORD) }) KafkaCluster cluster,
                                                                         Topic topic)
            throws Exception {
        Path initiationStore = writePasswordStore(tempDir.resolve("composition-wrong-password.p12"), STORE_PASSWORD,
                new PasswordEntry("proxy-service", BROKER_USERNAME, "wrong-password"));
        Path initiationPassword = writePasswordFile(tempDir.resolve("composition-wrong-password.password"), STORE_PASSWORD);
        var initiation = passwordDefinition(initiationStore, initiationPassword);
        var termination = terminationDefinition();

        var config = proxy(cluster)
                .addToFilterDefinitions(termination, initiation)
                .addToDefaultFilters(termination.name(), initiation.name());

        Map<String, Object> producerConfiguration = new HashMap<>(oauthClientConfiguration(CLIENT_ID, CLIENT_SECRET));
        producerConfiguration.putAll(FAILING_PRODUCER_CONFIGURATION);

        try (var tester = kroxyliciousTester(config);
                var producer = tester.producer(producerConfiguration)) {
            assertThatThrownBy(() -> producer.send(new ProducerRecord<>(topic.name(), "key", "value"))
                    .get(30, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class);
        }
    }

    private NamedFilterDefinition tokenFileDefinition(Path tokenFile) {
        return new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", "OAUTHBEARER",
                        "identity", Map.of("mode", "fixed", "key", "proxy-service"),
                        "oauthBearer", Map.of("tokenEndpointUrl", tokenFile.toUri().toString())))
                .build();
    }

    private NamedFilterDefinition oauthStoreDefinition(Map<String, Object> identity, Path store) throws Exception {
        Path passwordFile = writePasswordFile(tempDir.resolve("oauth-store.password"), STORE_PASSWORD);
        return new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", "OAUTHBEARER",
                        "identity", identity,
                        "keyStore", Map.of(
                                "file", store.toString(),
                                "filePassword", Map.of("passwordFile", passwordFile.toString())),
                        "oauthBearer", Map.of("tokenEndpointUrl", TOKEN_ENDPOINT_URL)))
                .build();
    }

    private NamedFilterDefinition passwordDefinition(Path store, Path passwordFile) {
        return new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(Map.of(
                        "mechanism", "SCRAM-SHA-256",
                        "identity", Map.of("mode", "fixed", "key", "proxy-service"),
                        "keyStore", Map.of(
                                "file", store.toString(),
                                "filePassword", Map.of("passwordFile", passwordFile.toString()))))
                .build();
    }

    private static NamedFilterDefinition terminationDefinition() {
        return new NamedFilterDefinitionBuilder("sasl-termination", SaslTermination.class.getName())
                .withConfig("mechanisms", List.of(
                        Map.of(
                                "mechanism", "OAUTHBEARER",
                                "jwksEndpointUrl", JWKS_ENDPOINT_URL,
                                "expectedAudience", EXPECTED_AUDIENCE,
                                "expectedIssuer", EXPECTED_ISSUER)))
                .build();
    }

    private static Map<String, Object> oauthClientConfiguration(String clientId, String clientSecret) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, SecurityProtocol.SASL_PLAINTEXT.name());
        configuration.put(SaslConfigs.SASL_MECHANISM, OAuthBearerLoginModule.OAUTHBEARER_MECHANISM);
        configuration.put(SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL, TOKEN_ENDPOINT_URL);
        configuration.put(SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS, OAuthBearerLoginCallbackHandler.class.getCanonicalName());
        configuration.put(SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_ID, clientId);
        configuration.put(SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_SECRET, clientSecret);
        configuration.put(SaslConfigs.SASL_JAAS_CONFIG,
                "%s required;".formatted(OAuthBearerLoginModule.class.getName()));
        return configuration;
    }

    private static Map<String, Object> consumerConfiguration(String groupId) {
        return Map.of(
                ConsumerConfig.GROUP_ID_CONFIG, groupId,
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    }

    private static void assertProduceAndConsume(org.apache.kafka.clients.producer.Producer<String, String> producer,
                                                org.apache.kafka.clients.consumer.Consumer<String, String> consumer,
                                                Topic topic) {
        assertThat(producer.send(new ProducerRecord<>(topic.name(), "key", "value")))
                .succeedsWithin(TIMEOUT);

        consumer.subscribe(List.of(topic.name()));

        assertThat(consumer.poll(TIMEOUT).records(topic.name()))
                .singleElement()
                .extracting(ConsumerRecord::key, ConsumerRecord::value)
                .containsExactly("key", "value");
    }

    private static void assertGenericFailureAndClose(KroxyliciousTester tester) {
        try (KafkaClient client = tester.simpleTestClient()) {
            DescribeClusterResponseData response = (DescribeClusterResponseData) client.getSync(
                    new Request(ApiKeys.DESCRIBE_CLUSTER,
                            ApiKeys.DESCRIBE_CLUSTER.latestVersion(),
                            "oauth-failure",
                            new DescribeClusterRequestData()))
                    .payload()
                    .message();

            assertThat(Errors.forCode(response.errorCode())).isEqualTo(Errors.UNKNOWN_SERVER_ERROR);
            assertThat(response.errorMessage()).isNullOrEmpty();
            await().atMost(CLOSE_TIMEOUT).untilAsserted(() -> assertThat(client.isOpen()).isFalse());
        }
    }

    private static String headerValue(ConsumerRecord<?, ?> record, String key) {
        Header header = record.headers().lastHeader(key);
        return header == null ? null : new String(header.value(), StandardCharsets.UTF_8);
    }
}
