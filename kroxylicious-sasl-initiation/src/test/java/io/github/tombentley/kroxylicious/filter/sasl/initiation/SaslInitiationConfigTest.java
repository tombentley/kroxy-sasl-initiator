/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import org.apache.kafka.common.security.oauthbearer.JwtRetriever;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.ReauthConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.identity.Principal;
import io.kroxylicious.identity.SingularPrincipal;
import io.kroxylicious.proxy.config.secret.FilePassword;
import io.kroxylicious.proxy.config.secret.InlinePassword;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SaslInitiationConfigTest {

    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());

    @Test
    void parsesFixedConfigurationAndDefaultsReauth() throws Exception {
        String yamlConfig = """
                mechanism: SCRAM-SHA-256
                identity:
                  mode: fixed
                  key: proxy-service
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
                """;

        SaslInitiationConfig config = yaml.readValue(yamlConfig, SaslInitiationConfig.class);

        assertThat(config.mechanism()).isEqualTo(Mechanism.SCRAM_SHA_256);
        assertThat(config.identity().mode()).isEqualTo(IdentityMode.FIXED);
        assertThat(config.identity().key()).isEqualTo("proxy-service");
        assertThat(config.identity().principalType()).isNull();
        assertThat(config.keyStore().file()).isEqualTo("/etc/kroxylicious/sasl-initiation.p12");
        assertThat(config.keyStore().filePassword()).isInstanceOf(FilePassword.class);
        assertThat(config.reauth().windowFactor()).isEqualTo(ReauthConfig.DEFAULT_WINDOW_FACTOR);
    }

    @Test
    void parsesSubjectConfigurationWithDefaultPrincipalType() throws Exception {
        String yamlConfig = """
                mechanism: PLAIN
                identity:
                  mode: subject
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                reauth:
                  windowFactor: 0.9
                """;

        SaslInitiationConfig config = yaml.readValue(yamlConfig, SaslInitiationConfig.class);

        assertThat(config.mechanism()).isEqualTo(Mechanism.PLAIN);
        assertThat(config.identity().mode()).isEqualTo(IdentityMode.SUBJECT);
        assertThat(config.identity().key()).isNull();
        assertThat(config.identity().principalType()).isEqualTo(IdentityConfig.DEFAULT_PRINCIPAL_TYPE);
        assertThat(config.identity().principalClass().getName()).isEqualTo(IdentityConfig.DEFAULT_PRINCIPAL_TYPE);
        assertThat(config.keyStore().filePassword()).isInstanceOf(InlinePassword.class);
        assertThat(config.reauth().windowFactor()).isEqualTo(0.9);
    }

    @Test
    void parsesCustomSingularPrincipalType() throws Exception {
        String yamlConfig = """
                mechanism: SCRAM-SHA-512
                identity:
                  mode: subject
                  principalType: %s
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                """.formatted(CustomPrincipal.class.getName());

        SaslInitiationConfig config = yaml.readValue(yamlConfig, SaslInitiationConfig.class);

        assertThat(config.identity().principalClass()).isEqualTo(CustomPrincipal.class);
    }

    @Test
    void parsesAllSupportedMechanisms() throws Exception {
        for (Mechanism mechanism : Mechanism.values()) {
            String yamlConfig;
            if (mechanism == Mechanism.OAUTHBEARER) {
                yamlConfig = """
                        mechanism: %s
                        identity:
                          mode: fixed
                          key: alice
                        oauthBearer:
                          tokenEndpointUrl: file:/etc/kroxylicious/token.jwt
                        """.formatted(mechanism.mechanismName());
            }
            else {
                yamlConfig = """
                        mechanism: %s
                        identity:
                          mode: fixed
                          key: alice
                        keyStore:
                          file: /etc/kroxylicious/sasl-initiation.p12
                          filePassword:
                            password: store-password
                        """.formatted(mechanism.mechanismName());
            }

            assertThat(yaml.readValue(yamlConfig, SaslInitiationConfig.class).mechanism()).isEqualTo(mechanism);
        }
    }

    @Test
    void rejectsMissingMechanism() {
        assertThatThrownBy(() -> new SaslInitiationConfig(null, new IdentityConfig(IdentityMode.FIXED, "alice"), keyStore()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("mechanism");
    }

    @Test
    void rejectsMissingMechanismInYaml() {
        String yamlConfig = """
                identity:
                  mode: fixed
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                """;

        assertThatThrownBy(() -> yaml.readValue(yamlConfig, SaslInitiationConfig.class))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("mechanism");
    }

    @Test
    void rejectsUnknownMechanism() {
        assertThatThrownBy(() -> Mechanism.fromString("GSSAPI"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported mechanism")
                .hasMessageContaining("PLAIN")
                .hasMessageContaining("OAUTHBEARER");

        String yamlConfig = """
                mechanism: GSSAPI
                identity:
                  mode: fixed
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                """;
        assertThatThrownBy(() -> yaml.readValue(yamlConfig, SaslInitiationConfig.class))
                .hasMessageContaining("GSSAPI");
    }

    @Test
    void rejectsWrongIdentityMode() {
        assertThatThrownBy(() -> IdentityMode.fromString("fallback"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported identity mode")
                .hasMessageContaining("fixed")
                .hasMessageContaining("subject");

        String yamlConfig = """
                mechanism: PLAIN
                identity:
                  mode: fallback
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                """;
        assertThatThrownBy(() -> yaml.readValue(yamlConfig, SaslInitiationConfig.class))
                .hasMessageContaining("fallback");
    }

    @Test
    void rejectsMissingIdentity() {
        assertThatThrownBy(() -> new SaslInitiationConfig(Mechanism.PLAIN, null, keyStore()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity");
    }

    @Test
    void rejectsMissingRequiredFieldsInYaml() {
        String missingMode = """
                mechanism: PLAIN
                identity:
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                """;
        assertThatThrownBy(() -> yaml.readValue(missingMode, SaslInitiationConfig.class))
                .hasMessageContaining("mode");

        String missingPassword = """
                mechanism: PLAIN
                identity:
                  mode: fixed
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                """;
        assertThatThrownBy(() -> yaml.readValue(missingPassword, SaslInitiationConfig.class))
                .hasMessageContaining("filePassword");

        String unknownField = """
                mechanism: PLAIN
                identity:
                  mode: fixed
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                oauthBearer:
                  tokenEndpointUrl: https://idp.example.com/token
                """;
        assertThatThrownBy(() -> yaml.readValue(unknownField, SaslInitiationConfig.class))
                .hasMessageContaining("oauthBearer");
    }

    @Test
    void rejectsKeyInSubjectMode() {
        assertThatThrownBy(() -> new IdentityConfig(IdentityMode.SUBJECT, "alice", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity.key")
                .hasMessageContaining("subject mode");
    }

    @Test
    void rejectsPrincipalTypeInFixedMode() {
        assertThatThrownBy(() -> new IdentityConfig(IdentityMode.FIXED, "alice", CustomPrincipal.class.getName()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("principalType")
                .hasMessageContaining("subject mode");
    }

    @Test
    void rejectsMissingFixedKey() {
        assertThatThrownBy(() -> new SaslInitiationConfig(Mechanism.PLAIN, new IdentityConfig(IdentityMode.FIXED, null), keyStore()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity.key is required");
        assertThatThrownBy(() -> new SaslInitiationConfig(Mechanism.PLAIN, new IdentityConfig(IdentityMode.FIXED, "  "), keyStore()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity.key");
    }

    @Test
    void rejectsMissingKeyStore() {
        assertThatThrownBy(() -> new SaslInitiationConfig(Mechanism.SCRAM_SHA_256,
                new IdentityConfig(IdentityMode.FIXED, "alice"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore is required")
                .hasMessageContaining("SCRAM-SHA-256");
    }

    @Test
    void rejectsMissingKeyStoreFields() {
        assertThatThrownBy(() -> new KeyStoreConfig(null, new InlinePassword("x")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore.file");
        assertThatThrownBy(() -> new KeyStoreConfig(" ", new InlinePassword("x")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore.file");
        assertThatThrownBy(() -> new KeyStoreConfig("/tmp/store.p12", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore.filePassword");
    }

    @Test
    void validatesWindowFactor() {
        assertThat(new ReauthConfig().windowFactor()).isEqualTo(ReauthConfig.DEFAULT_WINDOW_FACTOR);
        assertThat(new ReauthConfig(null).windowFactor()).isEqualTo(ReauthConfig.DEFAULT_WINDOW_FACTOR);
        assertThat(new ReauthConfig(0.5).windowFactor()).isEqualTo(0.5);
        assertThat(new ReauthConfig(0.95).windowFactor()).isEqualTo(0.95);

        assertThatThrownBy(() -> new ReauthConfig(0.49))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reauth.windowFactor");
        assertThatThrownBy(() -> new ReauthConfig(0.96))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reauth.windowFactor");
        assertThatThrownBy(() -> new ReauthConfig(Double.NaN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reauth.windowFactor");
        assertThatThrownBy(() -> new ReauthConfig(Double.POSITIVE_INFINITY))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reauth.windowFactor");
    }

    @Test
    void rejectsInvalidWindowFactorInYaml() {
        String yamlConfig = """
                mechanism: PLAIN
                identity:
                  mode: fixed
                  key: alice
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                reauth:
                  windowFactor: 0.3
                """;

        assertThatThrownBy(() -> yaml.readValue(yamlConfig, SaslInitiationConfig.class))
                .hasMessageContaining("windowFactor");
    }

    @Test
    void rejectsMissingPrincipalTypeClass() {
        assertThatThrownBy(() -> IdentityConfig.resolvePrincipalType("does.not.Exist"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("was not found");
    }

    @Test
    void rejectsPrincipalTypeThatIsNotAPrincipal() {
        assertThatThrownBy(() -> IdentityConfig.resolvePrincipalType(String.class.getName()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not implement");
    }

    @Test
    void rejectsNonSingularPrincipalType() {
        assertThatThrownBy(() -> IdentityConfig.resolvePrincipalType(NotSingularPrincipal.class.getName()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a singular principal type");
        assertThatThrownBy(() -> new IdentityConfig(IdentityMode.SUBJECT, null, NotSingularPrincipal.class.getName()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a singular principal type");
    }

    @Test
    void parsesOAuthBearerFixedFileConfigurationWithoutKeyStore() throws Exception {
        String yamlConfig = """
                mechanism: OAUTHBEARER
                identity:
                  mode: fixed
                  key: proxy-service
                oauthBearer:
                  tokenEndpointUrl: file:/etc/kroxylicious/token.jwt
                  scope: kafka
                """;

        SaslInitiationConfig config = yaml.readValue(yamlConfig, SaslInitiationConfig.class);

        assertThat(config.mechanism()).isEqualTo(Mechanism.OAUTHBEARER);
        assertThat(config.keyStore()).isNull();
        assertThat(config.oauthBearer().tokenEndpointUrl()).isEqualTo("file:/etc/kroxylicious/token.jwt");
        assertThat(config.oauthBearer().scope()).isEqualTo("kafka");
        assertThat(config.oauthBearer().jwtRetriever()).isEqualTo(OAuthBearerConfig.DEFAULT_JWT_RETRIEVER);
        assertThat(config.oauthBearer().subjectClaimName()).isEqualTo("sub");
    }

    @Test
    void parsesOAuthBearerFixedHttpConfigurationWithKeyStore() throws Exception {
        String yamlConfig = """
                mechanism: OAUTHBEARER
                identity:
                  mode: fixed
                  key: proxy-service
                keyStore:
                  file: /etc/kroxylicious/sasl-initiation.p12
                  filePassword:
                    password: store-password
                oauthBearer:
                  tokenEndpointUrl: https://idp.example.com/token
                  subjectClaimName: preferred_username
                """;

        SaslInitiationConfig config = yaml.readValue(yamlConfig, SaslInitiationConfig.class);

        assertThat(config.keyStore()).isNotNull();
        assertThat(config.oauthBearer().subjectClaimName()).isEqualTo("preferred_username");
    }

    @Test
    void rejectsOAuthBearerMissingConfigurationGroup() {
        assertThatThrownBy(() -> new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("oauthBearer is required");
    }

    @Test
    void rejectsOAuthBearerGroupForOtherMechanisms() {
        assertThatThrownBy(() -> new SaslInitiationConfig(
                Mechanism.PLAIN,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                keyStore(),
                new OAuthBearerConfig("file:/tmp/token.jwt", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("oauthBearer is only valid");
    }

    @Test
    void requiresKeyStoreForOAuthBearerSubjectMode() {
        assertThatThrownBy(() -> new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.SUBJECT, null),
                null,
                new OAuthBearerConfig("https://idp.example.com/token", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore is required");
    }

    @Test
    void rejectsOAuthBearerTokenFileInSubjectMode() {
        assertThatThrownBy(() -> new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.SUBJECT, null),
                keyStore(),
                new OAuthBearerConfig("file:/tmp/token.jwt", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("token files are only valid with a fixed identity");
    }

    @Test
    void requiresKeyStoreForOAuthBearerFixedHttpClientCredentials() {
        assertThatThrownBy(() -> new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                null,
                new OAuthBearerConfig("https://idp.example.com/token", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore is required");
    }

    @Test
    void rejectsKeyStoreForOAuthBearerFixedFileToken() {
        assertThatThrownBy(() -> new SaslInitiationConfig(
                Mechanism.OAUTHBEARER,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                keyStore(),
                new OAuthBearerConfig("file:/tmp/token.jwt", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStore is not used");
    }

    @Test
    void validatesOAuthBearerTokenEndpointUrl() {
        assertThatThrownBy(() -> new OAuthBearerConfig(null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tokenEndpointUrl is required");
        assertThatThrownBy(() -> new OAuthBearerConfig(" ", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tokenEndpointUrl is required");
        assertThatThrownBy(() -> new OAuthBearerConfig("ftp://idp.example.com/token", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("file, http or https");
        assertThatThrownBy(() -> new OAuthBearerConfig("not a uri", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI");
        assertThatThrownBy(() -> new OAuthBearerConfig("file:", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI");
        assertThatThrownBy(() -> new OAuthBearerConfig("https://", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI");
        assertThat(new OAuthBearerConfig("HTTP://idp.example.com/token", null).isFileTokenEndpoint()).isFalse();
        assertThat(new OAuthBearerConfig("FILE:/tmp/token.jwt", null).isFileTokenEndpoint()).isTrue();
    }

    @Test
    void validatesOAuthBearerRetrieverAndSubjectClaimName() {
        assertThatThrownBy(() -> new OAuthBearerConfig("file:/tmp/token.jwt", null, "does.not.Exist", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("was not found");
        assertThatThrownBy(() -> new OAuthBearerConfig("file:/tmp/token.jwt", null, String.class.getName(), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not implement");
        assertThatThrownBy(() -> new OAuthBearerConfig("file:/tmp/token.jwt", null, TestJwtRetriever.class.getName(), " "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("subjectClaimName must not be blank");
        assertThatThrownBy(() -> new OAuthBearerConfig("file:/tmp/token.jwt", " ", null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("scope must not be blank");

        OAuthBearerConfig config = new OAuthBearerConfig("file:/tmp/token.jwt", null, TestJwtRetriever.class.getName(), null);
        assertThat(config.jwtRetrieverClass()).isEqualTo(TestJwtRetriever.class);
        assertThat(config.subjectClaimName()).isEqualTo("sub");
    }

    @Test
    void configToStringDoesNotContainInlinePassword() {
        SaslInitiationConfig config = new SaslInitiationConfig(Mechanism.PLAIN,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                new KeyStoreConfig("/tmp/store.p12", new InlinePassword("super-secret")));

        assertThat(config.toString()).doesNotContain("super-secret");
    }

    @Test
    void keyStoreConfigToStringRedactsPasswordProvider() {
        KeyStoreConfig config = new KeyStoreConfig("/tmp/store.p12", new InlinePassword("super-secret"));

        assertThat(config.toString())
                .doesNotContain("super-secret")
                .contains("filePassword=REDACTED");
    }

    private static KeyStoreConfig keyStore() {
        return new KeyStoreConfig("/tmp/store.p12", new InlinePassword("store-password"));
    }

    @SingularPrincipal
    public record CustomPrincipal(String name) implements Principal {}

    public record NotSingularPrincipal(String name) implements Principal {}

    public static class TestJwtRetriever implements JwtRetriever {

        @Override
        public String retrieve() {
            return "unused";
        }
    }
}
