/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.PasswordEntry;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.StoredCredential;

import io.kroxylicious.identity.SingularPrincipal;
import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.authentication.Principal;
import io.kroxylicious.proxy.authentication.Subject;
import io.kroxylicious.proxy.authentication.User;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.BROKER_PASSWORD;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Protocol-level tests for subject-derived broker identities.
 */
@SuppressWarnings({ "deprecation", "removal", "java:S5738" })
class SaslInitiationSubjectIdentityTest {

    @TempDir
    Path tempDir;

    @Test
    void subjectSelectsTheMatchingCredentialEntry() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice", "bob");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, User.class);
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("alice")), broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void subjectMapsToADifferentStoredBrokerUsername() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, new PasswordEntry("alice", "svc-alice", BROKER_PASSWORD));
        FakeSaslBroker broker = new FakeSaslBroker().withCredentials("svc-alice", BROKER_PASSWORD);
        SaslInitiationFilter filter = subjectFilter(storeFile, User.class);
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("alice")), broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
    }

    @Test
    void anonymousSubjectFailsClosed() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, User.class);
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, Subject.anonymous(), broker);

        assertFailure(filter, header, request, context);
        assertThat(broker.capturedRequests()).isEmpty();
        assertThat(context.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void absentConfiguredPrincipalFailsClosed() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, CustomPrincipal.class);
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("alice")), broker);

        assertFailure(filter, header, request, context);
        assertThat(broker.capturedRequests()).isEmpty();
    }

    @Test
    void ambiguousCustomPrincipalFailsClosed() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, CustomPrincipal.class);
        Subject ambiguous = mock(Subject.class);
        when(ambiguous.principals()).thenReturn(Set.of(
                new CustomPrincipal("first"),
                new CustomPrincipal("second")));
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, ambiguous, broker);

        assertFailure(filter, header, request, context);
        assertThat(broker.capturedRequests()).isEmpty();
    }

    @Test
    void customPrincipalSelectsItsOwnEntry() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, new PasswordEntry("custom-alice", "broker-custom-alice", BROKER_PASSWORD));
        FakeSaslBroker broker = new FakeSaslBroker().withCredentials("broker-custom-alice", BROKER_PASSWORD);
        SaslInitiationFilter filter = subjectFilter(storeFile, CustomPrincipal.class);
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        Subject subject = new Subject(Set.of(new User("alice"), new CustomPrincipal("custom-alice")));
        MockFilterContext context = context(header, request, subject, broker);

        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
    }

    @Test
    void missingEntryFailsClosedWithoutContactingTheBroker() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, User.class);
        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext context = context(header, request, new Subject(new User("bob")), broker);

        assertFailure(filter, header, request, context);
        assertThat(broker.capturedRequests()).isEmpty();
    }

    @Test
    void entryWhoseSubjectDoesNotMatchTheLookupKeyFailsClosed() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationConfig config = config(storeFile, IdentityMode.SUBJECT, null, User.class);
        SaslInitiationRuntimeConfig base = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
        PasswordCredential mismatchedCredential = new PasswordCredential(FakeSaslBroker.BROKER_USERNAME,
                DestroyableSecret.of(BROKER_PASSWORD));
        CredentialResolver resolver = new CredentialResolver(
                lookupKey -> Optional.of(new StoredCredential("bob", mismatchedCredential)));
        SaslInitiationRuntimeConfig runtime = new SaslInitiationRuntimeConfig(
                base.config(), base.credentialStore(), base.identitySelector(), resolver);
        try {
            SaslInitiationFilter filter = new SaslInitiationFilter(runtime);
            RequestHeaderData header = header();
            MetadataRequestData request = new MetadataRequestData();
            MockFilterContext context = context(header, request, new Subject(new User("alice")), broker);

            assertFailure(filter, header, request, context);
            assertThat(broker.capturedRequests()).isEmpty();
        }
        finally {
            mismatchedCredential.destroy();
            base.credentialStore().close();
        }
    }

    @Test
    void subjectChangeAfterAuthenticationFailsClosedOnTheNextRequest() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice", "bob");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, User.class);

        RequestHeaderData firstHeader = header();
        MetadataRequestData firstRequest = new MetadataRequestData();
        MockFilterContext firstContext = context(firstHeader, firstRequest, new Subject(new User("alice")), broker);
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, firstHeader, firstRequest, firstContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        int requestsAfterAuthentication = broker.capturedRequests().size();

        RequestHeaderData secondHeader = header();
        MetadataRequestData secondRequest = new MetadataRequestData();
        MockFilterContext secondContext = context(secondHeader, secondRequest, new Subject(new User("bob")), broker);
        assertFailure(filter, secondHeader, secondRequest, secondContext);

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(broker.capturedRequests()).hasSize(requestsAfterAuthentication);
        assertThat(secondContext.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void subjectChangeDuringAuthenticationFailsClosed() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice", "bob");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = subjectFilter(storeFile, User.class);

        RequestHeaderData header = header();
        MetadataRequestData request = new MetadataRequestData();
        MockFilterContext delegate = context(header, request, new Subject(new User("alice")), broker);
        FilterContext changingContext = mock(FilterContext.class, delegatesTo(delegate));
        doReturn(new Subject(new User("alice")), new Subject(new User("bob")))
                .when(changingContext).authenticatedSubject();

        assertFailure(filter, header, request, changingContext);

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
        assertThat(broker.capturedRequests())
                .extracting(captured -> captured.request().apiKey())
                .containsExactly(ApiKeys.API_VERSIONS.id, ApiKeys.SASL_HANDSHAKE.id, ApiKeys.SASL_AUTHENTICATE.id);
        assertThat(delegate.clientSaslGestureInvocations()).isEmpty();
    }

    @Test
    void fixedModeIgnoresSubjectChanges() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        FakeSaslBroker broker = new FakeSaslBroker();
        SaslInitiationFilter filter = filter(storeFile, IdentityMode.FIXED, "alice", User.class);

        RequestHeaderData firstHeader = header();
        MetadataRequestData firstRequest = new MetadataRequestData();
        MockFilterContext firstContext = context(firstHeader, firstRequest, new Subject(new User("alice")), broker);
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, firstHeader, firstRequest, firstContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());

        RequestHeaderData secondHeader = header();
        MetadataRequestData secondRequest = new MetadataRequestData();
        MockFilterContext secondContext = context(secondHeader, secondRequest, new Subject(new User("bob")), broker);
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, secondHeader, secondRequest, secondContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasMessageEqualTo(secondRequest));

        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Authenticated.class);
        assertThat(firstContext.clientSaslGestureInvocations()).isEmpty();
        assertThat(secondContext.clientSaslGestureInvocations()).isEmpty();
    }

    private void assertFailure(SaslInitiationFilter filter,
                               RequestHeaderData header,
                               ApiMessage request,
                               FilterContext context) {
        assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isErrorResponse()
                        .isCloseConnection()
                        .errorResponse()
                        .hasError(Errors.UNKNOWN_SERVER_ERROR));
        assertThat(filter.state()).isInstanceOf(SaslExchangeState.Failed.class);
    }

    private SaslInitiationFilter subjectFilter(Path storeFile,
                                               Class<? extends Principal> principalType) {
        return filter(storeFile, IdentityMode.SUBJECT, null, principalType);
    }

    private SaslInitiationFilter filter(Path storeFile,
                                        IdentityMode mode,
                                        String key,
                                        Class<? extends Principal> principalType) {
        SaslInitiationConfig config = config(storeFile, mode, key, principalType);
        SaslInitiationRuntimeConfig runtime = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
        return new SaslInitiationFilter(runtime);
    }

    private static SaslInitiationConfig config(Path storeFile,
                                               IdentityMode mode,
                                               String key,
                                               Class<? extends Principal> principalType) {
        IdentityConfig identity = mode == IdentityMode.SUBJECT
                ? new IdentityConfig(mode, key, principalType.getName())
                : new IdentityConfig(mode, key);
        return new SaslInitiationConfig(
                Mechanism.PLAIN,
                identity,
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)));
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

    @SingularPrincipal
    public record CustomPrincipal(String name) implements Principal {}
}
