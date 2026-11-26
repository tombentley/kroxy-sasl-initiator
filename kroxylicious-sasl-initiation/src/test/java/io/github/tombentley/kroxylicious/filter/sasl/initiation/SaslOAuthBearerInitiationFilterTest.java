/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.apache.kafka.common.security.oauthbearer.JwtRetriever;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.OAuthEntry;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.filter.FilterDispatchExecutor;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Protocol-level OAUTHBEARER tests using Kafka's client and server SASL implementations.
 */
public class SaslOAuthBearerInitiationFilterTest {

    private static final String ALLOWED_URLS_PROPERTY = "org.apache.kafka.sasl.oauthbearer.allowed.urls";

    @TempDir
    Path tempDir;

    @Test
    void authenticatesWithAFixedTokenFile() throws Exception {
        String tokenValue = TestJwts.validToken("alice");
        Path tokenFile = tempDir.resolve("token.jwt");
        Files.writeString(tokenFile, tokenValue);

        withAllowedUrl("file:" + tokenFile, () -> {
            FakeSaslBroker broker = oauthBroker(tokenValue, "alice");
            SaslInitiationConfig config = new SaslInitiationConfig(
                    Mechanism.OAUTHBEARER,
                    new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                    null,
                    new OAuthBearerConfig("file:" + tokenFile, "kafka"));
            SaslInitiationFilter filter = filter(config, directExecutor());

            assertAuthenticationSucceeds(filter, broker);
        });
    }

    @Test
    void authenticatesWithFixedHttpClientCredentials() throws Exception {
        String tokenValue = tokenFor("alice");
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new OAuthEntry("proxy-service", "alice-client", "client-secret", "alice"));
        FakeSaslBroker broker = oauthBroker(tokenValue, "alice");
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                keyStore(storeFile),
                oauthBearer("https://idp.example.com/token"));
        SaslInitiationFilter filter = filter(config, directExecutor());

        assertAuthenticationSucceeds(filter, broker);
    }

    @Test
    void authenticatesWithASubjectModeOAuthEntry() throws Exception {
        String tokenValue = tokenFor("alice");
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new OAuthEntry("alice", "alice-client", "client-secret", "alice"));
        FakeSaslBroker broker = oauthBroker(tokenValue, "alice");
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.SUBJECT, null),
                keyStore(storeFile),
                oauthBearer("https://idp.example.com/token"));
        SaslInitiationFilter filter = filter(config, directExecutor());

        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("alice")), broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ofSeconds(5))
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void failsClosedForAWrongExpectedSubject() throws Exception {
        String tokenValue = tokenFor("alice");
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new OAuthEntry("proxy-service", "alice-client", "client-secret", "bob"));
        FakeSaslBroker broker = oauthBroker(tokenValue, "alice");
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                keyStore(storeFile),
                oauthBearer("https://idp.example.com/token"));
        SaslInitiationFilter filter = filter(config, directExecutor());

        assertAuthenticationFails(filter, broker);
        assertThat(broker.capturedRequests()).isEmpty();
    }

    @Test
    void failsClosedForASubjectModeEntryWithAWrongExpectedSubject() throws Exception {
        String tokenValue = tokenFor("bob");
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new OAuthEntry("alice", "alice-client", "client-secret", "alice"));
        FakeSaslBroker broker = oauthBroker(tokenValue, "bob");
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.SUBJECT, null),
                keyStore(storeFile),
                oauthBearer("https://idp.example.com/token"));
        SaslInitiationFilter filter = filter(config, directExecutor());

        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("alice")), broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ofSeconds(5))
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));
        assertThat(broker.capturedRequests()).isEmpty();
    }

    @Test
    void failsClosedWhenTheBrokerRejectsTheToken() throws Exception {
        tokenFor("alice");
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new OAuthEntry("proxy-service", "alice-client", "client-secret", "alice"));
        FakeSaslBroker broker = oauthBroker(TestJwts.validToken("someone-else"), "someone-else");
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                keyStore(storeFile),
                oauthBearer("https://idp.example.com/token"));
        SaslInitiationFilter filter = filter(config, directExecutor());

        assertAuthenticationFails(filter, broker);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(
                        ApiKeys.API_VERSIONS.id,
                        ApiKeys.SASL_HANDSHAKE.id,
                        ApiKeys.SASL_AUTHENTICATE.id,
                        ApiKeys.SASL_AUTHENTICATE.id);
    }

    private void assertAuthenticationSucceeds(SaslInitiationFilter filter, FakeSaslBroker broker) {
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, Subject.anonymous(), broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ofSeconds(5))
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasHeaderEqualTo(header)
                        .hasMessageEqualTo(request));

        assertThat(filter.state())
                .isInstanceOfSatisfying(SaslExchangeState.Authenticated.class,
                        authenticated -> assertThat(authenticated.sessionLifetimeMs()).isEqualTo(5000));
        List<FakeSaslBroker.CapturedRequest> requests = broker.capturedRequests();
        assertThat(requests)
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
        assertThat(requests.get(1).request()).isInstanceOf(SaslHandshakeRequestData.class);
        assertThat(((SaslHandshakeRequestData) requests.get(1).request()).mechanism()).isEqualTo("OAUTHBEARER");
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    private void assertAuthenticationFails(SaslInitiationFilter filter, FakeSaslBroker broker) {
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, Subject.anonymous(), broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ofSeconds(5))
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    private SaslInitiationFilter filter(SaslInitiationConfig config, FilterDispatchExecutor executor) {
        SaslInitiationRuntimeConfig runtime = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
        return new SaslInitiationFilter(runtime, executor);
    }

    private static FakeSaslBroker oauthBroker(String tokenValue, String principalName) {
        OAuthBearerToken token = new BasicOAuthBearerToken(
                tokenValue,
                Set.of("kafka"),
                System.currentTimeMillis() + 3_600_000L,
                principalName,
                System.currentTimeMillis());
        return new FakeSaslBroker()
                .withEnabledMechanisms("OAUTHBEARER")
                .withOAuthBearerToken(token)
                .withSessionLifetimeMs(5000);
    }

    private static KeyStoreConfig keyStore(Path storeFile) {
        return new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD));
    }

    private static OAuthBearerConfig oauthBearer(String tokenEndpointUrl) {
        return new OAuthBearerConfig(tokenEndpointUrl, "kafka", StaticJwtRetriever.class.getName(), null);
    }

    private static String tokenFor(String subject) {
        String token = TestJwts.validToken(subject);
        StaticJwtRetriever.token = token;
        return token;
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

    private static FilterDispatchExecutor directExecutor() {
        FilterDispatchExecutor executor = mock(FilterDispatchExecutor.class);
        when(executor.completeOnFilterDispatchThread(any())).thenAnswer(invocation -> invocation.getArgument(0));
        return executor;
    }

    private static void withAllowedUrl(String url, ThrowingRunnable action) throws Exception {
        String previous = System.getProperty(ALLOWED_URLS_PROPERTY);
        System.setProperty(ALLOWED_URLS_PROPERTY, url);
        try {
            action.run();
        }
        finally {
            if (previous == null) {
                System.clearProperty(ALLOWED_URLS_PROPERTY);
            }
            else {
                System.setProperty(ALLOWED_URLS_PROPERTY, previous);
            }
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /**
     * A retriever that avoids a real token endpoint in protocol tests. The token is still decoded and validated by
     * Kafka's normal client validator.
     */
    public static class StaticJwtRetriever implements JwtRetriever {

        static volatile String token = TestJwts.validToken("alice");

        @Override
        public String retrieve() {
            return token;
        }
    }
}
