/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.oauth;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.security.auth.login.AppConfigurationEntry;

import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.security.oauthbearer.DefaultJwtValidator;
import org.apache.kafka.common.security.oauthbearer.JwtRetriever;
import org.apache.kafka.common.security.oauthbearer.JwtValidator;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.config.OAuthBearerConfig;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.metrics.SaslInitiationMetrics;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Retrieves, validates and caches OAuth bearer tokens for one filter factory.
 * <p>
 * Token retrieval and validation are blocking operations and always run on a dedicated worker executor, never on the
 * connection's filter-dispatch thread. Callers must switch back to the filter-dispatch thread before mutating filter
 * state; see {@link io.kroxylicious.proxy.filter.FilterDispatchExecutor#completeOnFilterDispatchThread(CompletionStage)}.
 * </p>
 * <p>
 * For fixed-identity token files the file is trusted and no KeyStore entry is used. For fixed HTTP client credentials
 * and for subject mode, the KeyStore entry supplies the OAuth client id and secret, and the retrieved token's principal
 * name must equal the entry's expected subject.
 * </p>
 */
public final class OAuthTokenService implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthTokenService.class);

    private static final String SASL_MECHANISM = "OAUTHBEARER";

    private final OAuthBearerConfig oauthBearer;
    private final IdentityMode identityMode;
    private final JwtComponentsFactory componentsFactory;
    private final Map<String, JwtComponents> components = new ConcurrentHashMap<>();
    private final OAuthTokenCache cache;
    private final @Nullable ExecutorService ownedExecutor;
    private volatile boolean closed;

    /**
     * Creates a token service for one factory initialization.
     *
     * @param oauthBearer the OAuth bearer configuration
     * @param identityMode the identity mode
     * @param credentialStore the credential store, or {@code null} for a fixed token file
     */
    public OAuthTokenService(OAuthBearerConfig oauthBearer,
                             IdentityMode identityMode,
                             @Nullable KeyStoreCredentialStore credentialStore) {
        this(oauthBearer, identityMode, credentialStore, Clock.systemUTC(), null, null);
    }

    OAuthTokenService(OAuthBearerConfig oauthBearer,
                      IdentityMode identityMode,
                      @Nullable KeyStoreCredentialStore credentialStore,
                      Clock clock,
                      @Nullable Executor executor,
                      @Nullable JwtComponentsFactory componentsFactory) {
        this.oauthBearer = Objects.requireNonNull(oauthBearer, "oauthBearer");
        this.identityMode = Objects.requireNonNull(identityMode, "identityMode");
        if (executor == null) {
            ExecutorService virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor();
            this.ownedExecutor = virtualThreadExecutor;
            this.cache = new OAuthTokenCache(clock, virtualThreadExecutor);
        }
        else {
            this.ownedExecutor = null;
            this.cache = new OAuthTokenCache(clock, executor);
        }
        this.componentsFactory = componentsFactory == null
                ? (key, credential) -> createComponents(oauthBearer, credential)
                : componentsFactory;
    }

    /**
     * Returns a validated token for an identity.
     *
     * @param lookupKey the identity lookup key, also used as the cache key
     * @param credential the OAuth client credential, or {@code null} for a fixed token file
     * @return a stage completed with a token, off the calling filter-dispatch thread
     */
    public CompletionStage<OAuthBearerToken> token(String lookupKey, @Nullable OAuthClientCredential credential) {
        if (lookupKey == null || lookupKey.isBlank()) {
            return CompletableFuture.failedFuture(
                    new OAuthTokenException("The OAuth identity lookup key must not be blank"));
        }
        if (closed) {
            return CompletableFuture.failedFuture(
                    new OAuthTokenException("The OAuth token service is closed"));
        }
        return cache.get(lookupKey, () -> loadToken(lookupKey, credential));
    }

    private OAuthBearerToken loadToken(String lookupKey, @Nullable OAuthClientCredential credential) {
        long startedNanos = System.nanoTime();
        boolean success = false;
        try {
            JwtComponents component = components.computeIfAbsent(lookupKey,
                    key -> componentsFactory.create(key, credential));
            if (closed) {
                components.remove(lookupKey, component);
                component.close();
                throw new OAuthTokenException("The OAuth token service is closed");
            }
            String serializedToken;
            try {
                serializedToken = component.retriever().retrieve();
            }
            catch (RuntimeException e) {
                LOGGER.atWarn()
                        .addKeyValue("stage", "retrieval")
                        .addKeyValue("errorType", e.getClass().getSimpleName())
                        .log("OAuth token retrieval failed");
                throw new OAuthTokenException("OAuth token retrieval failed");
            }

            final OAuthBearerToken token;
            try {
                token = component.validator().validate(serializedToken);
            }
            catch (RuntimeException e) {
                LOGGER.atWarn()
                        .addKeyValue("stage", "validation")
                        .addKeyValue("errorType", e.getClass().getSimpleName())
                        .log("OAuth token validation failed");
                throw new OAuthTokenException("OAuth token validation failed");
            }
            if (token == null) {
                throw new OAuthTokenException("OAuth token validation returned no token");
            }
            if (credential != null && !credential.expectedSubject().equals(token.principalName())) {
                LOGGER.atWarn()
                        .addKeyValue("stage", "subject")
                        .log("The retrieved OAuth token subject does not match the expected subject");
                throw new OAuthTokenException("The retrieved OAuth token subject does not match the expected subject");
            }
            success = true;
            return new RedactedOAuthBearerToken(token);
        }
        finally {
            SaslInitiationMetrics.recordTokenRetrieval(success, Duration.ofNanos(System.nanoTime() - startedNanos));
        }
    }

    /**
     * Returns whether this service uses a static token file.
     *
     * @return {@code true} for a fixed-identity file token endpoint
     */
    public boolean usesStaticTokenFile() {
        return identityMode == IdentityMode.FIXED && oauthBearer.isFileTokenEndpoint();
    }

    /**
     * Returns the number of cached tokens. Intended for tests.
     *
     * @return the cache size
     */
    int cachedTokenCount() {
        return cache.size();
    }

    Map<String, Object> kafkaConfigs(@Nullable OAuthClientCredential credential) {
        return buildKafkaConfigs(oauthBearer, credential);
    }

    private static JwtComponents createComponents(OAuthBearerConfig oauthBearerConfig,
                                                  @Nullable OAuthClientCredential credential) {
        Map<String, Object> configs = buildKafkaConfigs(oauthBearerConfig, credential);
        List<AppConfigurationEntry> jaasEntries = List.of(new AppConfigurationEntry(
                OAuthBearerLoginModule.class.getName(),
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                Map.of()));

        final JwtRetriever retriever;
        try {
            retriever = oauthBearerConfig.jwtRetrieverClass().getDeclaredConstructor().newInstance();
            retriever.configure(configs, SASL_MECHANISM, jaasEntries);
        }
        catch (ReflectiveOperationException | RuntimeException e) {
            throw new OAuthTokenException("Could not create the configured OAuth token retriever");
        }

        final JwtValidator validator;
        try {
            validator = new DefaultJwtValidator();
            validator.configure(configs, SASL_MECHANISM, jaasEntries);
        }
        catch (RuntimeException e) {
            closeQuietly(retriever);
            throw new OAuthTokenException("Could not create the OAuth token validator");
        }
        return new JwtComponents(retriever, validator);
    }

    static Map<String, Object> buildKafkaConfigs(OAuthBearerConfig oauthBearerConfig,
                                                 @Nullable OAuthClientCredential credential) {
        Map<String, Object> configs = new HashMap<>();
        configs.put(SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL, oauthBearerConfig.tokenEndpointUrl());
        configs.put(SaslConfigs.SASL_OAUTHBEARER_SUB_CLAIM_NAME, oauthBearerConfig.subjectClaimName());
        // Kafka's ClientJwtValidator requires the scope claim name to be present even when using the default.
        configs.put(SaslConfigs.SASL_OAUTHBEARER_SCOPE_CLAIM_NAME,
                SaslConfigs.DEFAULT_SASL_OAUTHBEARER_SCOPE_CLAIM_NAME);
        // Kafka's HttpJwtRetriever requires these login retry settings. They normally come from KafkaConfig
        // defaults, but the retriever is configured from this bare map rather than a KafkaConfig.
        configs.put(SaslConfigs.SASL_LOGIN_RETRY_BACKOFF_MS,
                SaslConfigs.DEFAULT_SASL_LOGIN_RETRY_BACKOFF_MS);
        configs.put(SaslConfigs.SASL_LOGIN_RETRY_BACKOFF_MAX_MS,
                SaslConfigs.DEFAULT_SASL_LOGIN_RETRY_BACKOFF_MAX_MS);
        if (oauthBearerConfig.scope() != null) {
            configs.put(SaslConfigs.SASL_OAUTHBEARER_SCOPE, oauthBearerConfig.scope());
        }
        if (credential != null) {
            configs.put(SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_ID, credential.clientId());
            configs.put(SaslConfigs.SASL_OAUTHBEARER_CLIENT_CREDENTIALS_CLIENT_SECRET,
                    new Password(new String(credential.clientSecret().chars())));
        }
        return Map.copyOf(configs);
    }

    /**
     * Stops the worker executor and closes all retrievers, validators and cached tokens.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        cache.close();
        List<JwtComponents> toClose = new ArrayList<>(components.values());
        components.clear();
        toClose.forEach(JwtComponents::close);
        if (ownedExecutor != null) {
            ownedExecutor.shutdownNow();
        }
    }

    private static void closeQuietly(AutoCloseable closeable) {
        try {
            closeable.close();
        }
        catch (Exception e) {
            LOGGER.atDebug()
                    .addKeyValue("errorType", e.getClass().getSimpleName())
                    .log("Failed to close an OAuth token component");
        }
    }

    @Override
    public String toString() {
        return "OAuthTokenService[identityMode=" + identityMode
                + ", tokenEndpointUrl=" + oauthBearer.tokenEndpointUrl()
                + ", cachedTokens=" + cache.size()
                + ", closed=" + closed + "]";
    }

    /**
     * Creates the retriever/validator pair for one identity.
     */
    @FunctionalInterface
    interface JwtComponentsFactory {
        JwtComponents create(String lookupKey, @Nullable OAuthClientCredential credential);
    }

    /**
     * A retriever and validator configured for one identity.
     *
     * @param retriever the JWT retriever
     * @param validator the JWT validator
     */
    record JwtComponents(JwtRetriever retriever, JwtValidator validator) implements AutoCloseable {

        JwtComponents {
            Objects.requireNonNull(retriever, "retriever");
            Objects.requireNonNull(validator, "validator");
        }

        @Override
        public void close() {
            closeQuietly(retriever);
            closeQuietly(validator);
        }

        @Override
        public String toString() {
            return "JwtComponents[retriever=" + retriever.getClass().getName()
                    + ", validator=" + validator.getClass().getName() + "]";
        }
    }
}
