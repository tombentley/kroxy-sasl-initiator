/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.nio.file.Path;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.util.ReadOnlyStringMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.IdentityMode;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.KeyStoreConfig;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.Mechanism;
import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import io.kroxylicious.kafka.common.message.MetadataRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;

import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.BROKER_PASSWORD;
import static io.github.tombentley.kroxylicious.filter.sasl.initiation.TestStores.STORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies that the filter's structured logs contain the fields operators need and never contain secrets or raw broker
 * error text.
 */
class SaslInitiationLoggingTest {

    @TempDir
    Path tempDir;

    private Path storeFile;

    @BeforeEach
    void createStore() throws Exception {
        storeFile = tempDir.resolve("credentials.p12");
        TestStores.writePasswordStore(storeFile, "alice");
    }

    @Test
    void successfulAuthenticationLogsStructuredFieldsWithoutSecrets() {
        CapturingAppender appender = attach();
        try {
            FakeSaslBroker broker = new FakeSaslBroker().withSessionLifetimeMs(5000);
            SaslInitiationFilter filter = filter();
            RequestHeaderData header = header();
            MetadataRequestData request = new MetadataRequestData();
            MockFilterContext context = context(header, request, "session-success", "vc-logs-success", broker);

            assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                    .succeedsWithin(java.time.Duration.ZERO)
                    .satisfies(result -> MockFilterContextAssert.assertThat(result).isForwardRequest());
        }
        finally {
            detach(appender);
        }

        String logs = appender.text();
        assertThat(logs).contains(
                "sessionId=session-success",
                "virtualCluster=vc-logs-success",
                "mechanism=PLAIN",
                "outcome=success",
                "reauth=false",
                "subject=alice",
                "brokerUsername=broker-alice");
        assertThat(logs).doesNotContain(BROKER_PASSWORD, STORE_PASSWORD);
    }

    @Test
    void failedAuthenticationLogsStructuredFieldsWithoutSecretsOrBrokerText() {
        CapturingAppender appender = attach();
        try {
            FakeSaslBroker broker = new FakeSaslBroker()
                    .withCredentials(FakeSaslBroker.BROKER_USERNAME, "the-wrong-password");
            SaslInitiationFilter filter = filter();
            RequestHeaderData header = header();
            MetadataRequestData request = new MetadataRequestData();
            MockFilterContext context = context(header, request, "session-failure", "vc-logs-failure", broker);

            assertThat(filter.onRequest(ApiKeys.METADATA, (short) 0, header, request, context))
                    .succeedsWithin(java.time.Duration.ZERO)
                    .satisfies(result -> MockFilterContextAssert.assertThat(result)
                            .isErrorResponse()
                            .isCloseConnection()
                            .errorResponse()
                            .hasError(Errors.UNKNOWN_SERVER_ERROR));
        }
        finally {
            detach(appender);
        }

        String logs = appender.text();
        assertThat(logs).contains(
                "sessionId=session-failure",
                "virtualCluster=vc-logs-failure",
                "mechanism=PLAIN",
                "outcome=failure",
                "reauth=false",
                "errorCode=-1");
        assertThat(logs).doesNotContain(BROKER_PASSWORD, STORE_PASSWORD, "the-wrong-password",
                "broker-only diagnostic text");
    }

    private SaslInitiationFilter filter() {
        SaslInitiationConfig config = new SaslInitiationConfig(
                Mechanism.PLAIN,
                new IdentityConfig(IdentityMode.FIXED, "alice"),
                new KeyStoreConfig(storeFile.toString(), TestStores.passwordProvider(STORE_PASSWORD)));
        SaslInitiationRuntimeConfig runtime = new SaslInitiation().initialize(mock(FilterFactoryContext.class), config);
        return new SaslInitiationFilter(runtime);
    }

    private static MockFilterContext context(RequestHeaderData header,
                                             MetadataRequestData request,
                                             String sessionId,
                                             String virtualCluster,
                                             FakeSaslBroker broker) {
        return MockFilterContext.builder(header, request)
                .withSessionId(sessionId)
                .withVirtualClusterName(virtualCluster)
                .withSendRequestHandler(broker)
                .build();
    }

    private static RequestHeaderData header() {
        return new RequestHeaderData()
                .setRequestApiKey(ApiKeys.METADATA.id)
                .setRequestApiVersion((short) 0);
    }

    private static CapturingAppender attach() {
        CapturingAppender appender = new CapturingAppender();
        appender.start();
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = loggerContext.getConfiguration();
        LoggerConfig loggerConfig = configuration.getLoggerConfig(SaslInitiationFilter.class.getName());
        loggerConfig.addAppender(appender, Level.DEBUG, null);
        loggerConfig.setLevel(Level.DEBUG);
        loggerContext.updateLoggers();
        return appender;
    }

    private static void detach(CapturingAppender appender) {
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = loggerContext.getConfiguration();
        LoggerConfig loggerConfig = configuration.getLoggerConfig(SaslInitiationFilter.class.getName());
        loggerConfig.removeAppender(appender.getName());
        loggerContext.updateLoggers();
        appender.stop();
    }

    private static final class CapturingAppender extends AbstractAppender {

        private final StringBuilder text = new StringBuilder();

        private CapturingAppender() {
            super("sasl-initiation-log-capture", null, null, false, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(LogEvent event) {
            StringBuilder line = new StringBuilder();
            line.append(event.getLevel()).append(' ');
            ReadOnlyStringMap contextData = event.getContextData();
            if (contextData != null) {
                contextData.forEach((key, value) -> line.append(key).append('=').append(value).append(' '));
            }
            line.append(event.getMessage().getFormattedMessage());
            if (event.getThrown() != null) {
                line.append(' ').append(event.getThrown().getClass().getName());
            }
            text.append(line).append('\n');
        }

        private String text() {
            return text.toString();
        }
    }
}
