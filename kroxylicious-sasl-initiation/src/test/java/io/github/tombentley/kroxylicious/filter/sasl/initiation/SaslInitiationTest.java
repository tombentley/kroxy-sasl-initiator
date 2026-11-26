/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.ReauthConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStorePermissions;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.SubjectAlias;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.FixedIdentitySelector;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.identity.SubjectIdentitySelector;

import io.kroxylicious.kafka.common.message.ApiVersionsRequestData;
import io.kroxylicious.kafka.common.message.ApiVersionsResponseData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.BROKER_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class SaslInitiationTest {

    @TempDir
    Path tempDir;

    private final SaslInitiation factory = new SaslInitiation();
    private final FilterFactoryContext context = mock(FilterFactoryContext.class);

    @Test
    void shouldBeDiscoverableByServiceLoader() {
        List<Class<? extends FilterFactory>> providers = ServiceLoader.load(FilterFactory.class)
                .stream()
                .map(ServiceLoader.Provider::type)
                .toList();

        assertThat(providers).contains(SaslInitiation.class);
    }

    @Test
    void initializesFixedIdentityWithRealStore() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice", "bob");
        SaslInitiationConfig config = config(Mechanism.SCRAM_SHA_256, IdentityMode.FIXED, "alice", storeFile, 0.8);

        SaslInitiationRuntimeConfig runtime = factory.initialize(context, config);
        try {
            assertThat(runtime.config()).isSameAs(config);
            assertThat(runtime.identitySelector()).isInstanceOf(FixedIdentitySelector.class);
            assertThat(((FixedIdentitySelector) runtime.identitySelector()).key()).isEqualTo("alice");
            assertThat(runtime.credentialStore().size()).isEqualTo(2);
            assertThat(runtime.credentialStore().find("alice")).isPresent();

            Filter filter = factory.createFilter(context, runtime);
            assertThat(filter).isInstanceOf(SaslInitiationFilter.class);
        }
        finally {
            factory.close(runtime);
        }

        assertThat(runtime.credentialStore().credentials().get("alice").toString())
                .doesNotContain(BROKER_PASSWORD);
    }

    @Test
    void initializesSubjectIdentityWithRealStore() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        SaslInitiationConfig config = config(Mechanism.PLAIN, IdentityMode.SUBJECT, null, storeFile, 0.9);

        SaslInitiationRuntimeConfig runtime = factory.initialize(context, config);
        try {
            assertThat(runtime.identitySelector()).isInstanceOf(SubjectIdentitySelector.class);
            assertThat(((SubjectIdentitySelector) runtime.identitySelector()).principalType())
                    .isEqualTo(IdentityConfig.resolvePrincipalType(IdentityConfig.DEFAULT_PRINCIPAL_TYPE));
            assertThat(runtime.config().reauth().windowFactor()).isEqualTo(0.9);
        }
        finally {
            factory.close(runtime);
        }
    }

    @Test
    void failsInitializationWhenStoreFileIsMissing() {
        SaslInitiationConfig config = config(Mechanism.PLAIN, IdentityMode.FIXED, "alice",
                tempDir.resolve("missing.p12"), 0.8);

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("not found")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(STORE_PASSWORD));
    }

    @Test
    void failsInitializationWhenFixedKeyIsMissing() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "bob");
        SaslInitiationConfig config = config(Mechanism.SCRAM_SHA_256, IdentityMode.FIXED, "alice", storeFile, 0.8);

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("No PASSWORD credential")
                .hasMessageContaining("alice");
    }

    @Test
    void failsInitializationWhenStoreContainsWrongEntryType() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        String oauthJson = """
                {"version":1,"subject":"alice","oauthBearer":{"clientId":"alice-client","clientSecret":"client-secret"}}
                """;
        TestStores.writeRawStore(storeFile,
                Map.of(SubjectAlias.hash("alice"), oauthJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                STORE_PASSWORD);
        SaslInitiationConfig config = config(Mechanism.PLAIN, IdentityMode.FIXED, "alice", storeFile, 0.8);

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("OAUTH")
                .hasMessageContaining("PASSWORD");
    }

    @Test
    void failsInitializationWhenStoreEntryIsMalformed() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writeRawStore(storeFile,
                Map.of(SubjectAlias.hash("alice"), "not-json".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                STORE_PASSWORD);
        SaslInitiationConfig config = config(Mechanism.PLAIN, IdentityMode.FIXED, "alice", storeFile, 0.8);

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("Invalid credential entry");
    }

    @Test
    void failsInitializationWhenStoreEntryAliasDoesNotMatchSubject() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writeRawStore(storeFile,
                Map.of(SubjectAlias.hash("bob"), TestStores.rawJson("alice", "broker-alice", BROKER_PASSWORD)),
                STORE_PASSWORD);
        SaslInitiationConfig config = config(Mechanism.PLAIN, IdentityMode.FIXED, "alice", storeFile, 0.8);

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("does not match the SHA-256 hash");
    }

    @Test
    void failsInitializationWhenStorePermissionsAreInsecure() throws Exception {
        Assumptions.assumeFalse("true".equalsIgnoreCase(System.getenv(KeyStorePermissions.ALLOW_INSECURE_PERMISSIONS_ENV_VAR)),
                "Permission checks are explicitly disabled by the environment");
        Assumptions.assumeTrue(Files.getFileAttributeView(tempDir, PosixFileAttributeView.class) != null,
                "POSIX permissions are not available");

        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        Files.setPosixFilePermissions(storeFile, PosixFilePermissions.fromString("rw-r--r--"));
        SaslInitiationConfig config = config(Mechanism.PLAIN, IdentityMode.FIXED, "alice", storeFile, 0.8);

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("insecure permissions")
                .hasMessageContaining(KeyStorePermissions.ALLOW_INSECURE_PERMISSIONS_ENV_VAR);
    }

    @Test
    void shouldForwardApiVersionsRequestUnchanged() throws Exception {
        Path storeFile = tempDir.resolve("forwarding.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        RequestHeaderData header = new RequestHeaderData();
        ApiVersionsRequestData request = new ApiVersionsRequestData();
        MockFilterContext filterContext = MockFilterContext.builder(header, request).build();
        SaslInitiationFilter filter = filter(config(Mechanism.PLAIN, IdentityMode.FIXED, "alice", storeFile, 0.8));

        assertThat(filter.onRequest(ApiKeys.API_VERSIONS, (short) 0, header, request, filterContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardRequest()
                        .hasHeaderEqualTo(header)
                        .hasMessageEqualTo(request));
    }

    @Test
    void shouldForwardApiVersionsResponseUnchanged() throws Exception {
        Path storeFile = tempDir.resolve("forwarding-response.p12");
        TestStores.writePasswordStore(storeFile, "alice");
        ResponseHeaderData header = new ResponseHeaderData();
        ApiVersionsResponseData response = new ApiVersionsResponseData();
        MockFilterContext filterContext = MockFilterContext.builder(header, response).build();
        SaslInitiationFilter filter = filter(config(Mechanism.PLAIN, IdentityMode.FIXED, "alice", storeFile, 0.8));

        assertThat(filter.onApiVersionsResponse((short) 0, header, response, filterContext))
                .succeedsWithin(Duration.ZERO)
                .satisfies(result -> MockFilterContextAssert.assertThat(result)
                        .isForwardResponse()
                        .hasHeaderEqualTo(header)
                        .hasMessageEqualTo(response));
    }

    @Test
    void initializesOAuthSubjectModeWithRealStore() throws Exception {
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile,
                new TestStores.OAuthEntry("alice", "alice-client", "client-secret", null));
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.SUBJECT, null),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)),
                new OAuthBearerConfig("https://idp.example.com/token", "kafka"));

        SaslInitiationRuntimeConfig runtime = factory.initialize(context, config);
        try {
            assertThat(runtime.credentialStore()).isNotNull();
            assertThat(runtime.credentialStore().kind()).isEqualTo(CredentialKind.OAUTH);
            assertThat(runtime.oauthTokenService()).isNotNull();
            assertThat(runtime.oauthTokenService().usesStaticTokenFile()).isFalse();
            assertThat(runtime.credentialStore().require("alice"))
                    .isInstanceOfSatisfying(OAuthClientCredential.class,
                            credential -> assertThat(credential.expectedSubject()).isEqualTo("alice"));
        }
        finally {
            factory.close(runtime);
        }
    }

    @Test
    void initializesOAuthFixedTokenFileWithoutAKeyStore() {
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                null,
                new OAuthBearerConfig("file:/etc/kroxylicious/token.jwt", null));

        SaslInitiationRuntimeConfig runtime = factory.initialize(context, config);
        try {
            assertThat(runtime.credentialStore()).isNull();
            assertThat(runtime.oauthTokenService()).isNotNull();
            assertThat(runtime.oauthTokenService().usesStaticTokenFile()).isTrue();
        }
        finally {
            factory.close(runtime);
        }
    }

    @Test
    void failsInitializationWhenOAuthStoreContainsPasswordEntries() throws Exception {
        Path storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "proxy-service");
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "proxy-service"),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)),
                new OAuthBearerConfig("https://idp.example.com/token", null));

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("PASSWORD")
                .hasMessageContaining("OAUTH");
    }

    @Test
    void failsInitializationWhenTheFixedOAuthKeyIsMissing() throws Exception {
        Path storeFile = tempDir.resolve("oauth.p12");
        TestStores.writeOAuthStore(storeFile, new TestStores.OAuthEntry("bob", "bob-client", "client-secret", "bob"));
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)),
                new OAuthBearerConfig("https://idp.example.com/token", null));

        assertThatThrownBy(() -> factory.initialize(context, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("No OAUTH credential")
                .hasMessageContaining("alice");
    }

    private static SaslInitiationConfig config(Mechanism mechanism,
                                               IdentityMode mode,
                                               String key,
                                               Path storeFile,
                                               double windowFactor) {
        return new SaslInitiationConfig(
                mechanism,
                new IdentityConfig(mode, key),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)),
                new ReauthConfig(windowFactor));
    }

    private SaslInitiationFilter filter(SaslInitiationConfig config) {
        SaslInitiationRuntimeConfig runtime = factory.initialize(context, config);
        return (SaslInitiationFilter) factory.createFilter(context, runtime);
    }
}
