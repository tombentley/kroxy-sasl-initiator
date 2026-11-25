/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.file.Path;

import org.apache.kafka.common.message.DescribeClusterRequestData;
import org.apache.kafka.common.message.DescribeClusterResponseData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.protocol.Errors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;

import io.kroxylicious.proxy.config.ConfigurationBuilder;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.testing.integration.Request;
import io.kroxylicious.testing.integration.client.KafkaClient;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.SaslMechanism;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;

import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.INITIATION_STORE_PASSWORD;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.fixedInitiationDefinition;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.subjectInitiationDefinition;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writeInitiationStore;
import static com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionTestSupport.writePasswordFile;
import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Real-Kafka tests for a downstream subject change after upstream authentication.
 * <p>
 * A test-only {@link SubjectSwitcherFilter} publishes the initial subject and later announces a different one. In
 * subject mode {@code SaslInitiation} must fail closed with a generic error; in fixed mode it must continue using the
 * shared identity and leave the connection usable.
 * </p>
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SaslInitiationSubjectChangeIT {

    private static final String INITIAL_SUBJECT = "alice";
    private static final String SWITCHED_SUBJECT = "bob";
    private static final String FIXED_KEY = "proxy-service";
    private static final String ALICE_BROKER_USERNAME = "svc-alice";
    private static final String ALICE_BROKER_PASSWORD = "svc-alice-password";
    private static final String BOB_BROKER_USERNAME = "svc-bob";
    private static final String BOB_BROKER_PASSWORD = "svc-bob-password";
    private static final String FIXED_BROKER_USERNAME = "svc-fixed";
    private static final String FIXED_BROKER_PASSWORD = "svc-fixed-password";

    @TempDir
    Path tempDir;

    @Test
    void subjectModeShouldFailGenericallyAndCloseWhenTheSubjectChanges(
                                                                       @SaslMechanism(value = "PLAIN", principals = {
                                                                               @SaslMechanism.Principal(user = ALICE_BROKER_USERNAME, password = ALICE_BROKER_PASSWORD),
                                                                               @SaslMechanism.Principal(user = BOB_BROKER_USERNAME, password = BOB_BROKER_PASSWORD) }) KafkaCluster cluster)
            throws Exception {
        Path store = writeInitiationStore(tempDir.resolve("subject-change.p12"),
                new CompositionTestSupport.Credential(INITIAL_SUBJECT, ALICE_BROKER_USERNAME, ALICE_BROKER_PASSWORD),
                new CompositionTestSupport.Credential(SWITCHED_SUBJECT, BOB_BROKER_USERNAME, BOB_BROKER_PASSWORD));
        Path passwordFile = writePasswordFile(tempDir.resolve("subject-change.password"), INITIATION_STORE_PASSWORD);
        var switcher = SubjectSwitcherFilter.definition("subject-switcher", INITIAL_SUBJECT, SWITCHED_SUBJECT, 1);
        var initiation = subjectInitiationDefinition("sasl-initiation", "PLAIN", store, passwordFile);

        try (var tester = kroxyliciousTester(configuration(cluster, switcher, initiation));
                KafkaClient client = tester.simpleTestClient()) {
            assertThat(Errors.forCode(describeCluster(client, "subject-change-initial").errorCode()))
                    .isEqualTo(Errors.NONE);

            DescribeClusterResponseData switched = describeCluster(client, "subject-change-switched");
            assertThat(Errors.forCode(switched.errorCode())).isEqualTo(Errors.UNKNOWN_SERVER_ERROR);
            assertThat(switched.errorMessage()).isNullOrEmpty();

            await().atMost(CompositionTestSupport.CLOSE_TIMEOUT)
                    .untilAsserted(() -> assertThat(client.isOpen()).isFalse());
        }
    }

    @Test
    void fixedModeShouldKeepUsingTheSharedIdentityWhenTheSubjectChanges(
                                                                        @SaslMechanism(value = "PLAIN", principals = {
                                                                                @SaslMechanism.Principal(user = FIXED_BROKER_USERNAME, password = FIXED_BROKER_PASSWORD) }) KafkaCluster cluster)
            throws Exception {
        Path store = writeInitiationStore(tempDir.resolve("fixed-subject-change.p12"),
                new CompositionTestSupport.Credential(FIXED_KEY, FIXED_BROKER_USERNAME, FIXED_BROKER_PASSWORD));
        Path passwordFile = writePasswordFile(tempDir.resolve("fixed-subject-change.password"), INITIATION_STORE_PASSWORD);
        var switcher = SubjectSwitcherFilter.definition("subject-switcher", INITIAL_SUBJECT, SWITCHED_SUBJECT, 1);
        var initiation = fixedInitiationDefinition("sasl-initiation", "PLAIN", FIXED_KEY, store, passwordFile);

        try (var tester = kroxyliciousTester(configuration(cluster, switcher, initiation));
                KafkaClient client = tester.simpleTestClient()) {
            assertThat(Errors.forCode(describeCluster(client, "fixed-subject-initial").errorCode()))
                    .isEqualTo(Errors.NONE);
            assertThat(Errors.forCode(describeCluster(client, "fixed-subject-switched").errorCode()))
                    .isEqualTo(Errors.NONE);
            assertThat(Errors.forCode(describeCluster(client, "fixed-subject-after-switch").errorCode()))
                    .isEqualTo(Errors.NONE);
            assertThat(client.isOpen()).isTrue();
        }
    }

    private static ConfigurationBuilder configuration(KafkaCluster cluster,
                                                      NamedFilterDefinition switcher,
                                                      NamedFilterDefinition initiation) {
        return proxy(cluster)
                .addToFilterDefinitions(switcher, initiation)
                .addToDefaultFilters(switcher.name(), initiation.name());
    }

    private static DescribeClusterResponseData describeCluster(KafkaClient client, String clientId) {
        return (DescribeClusterResponseData) client.getSync(
                new Request(ApiKeys.DESCRIBE_CLUSTER,
                        ApiKeys.DESCRIBE_CLUSTER.latestVersion(),
                        clientId,
                        new DescribeClusterRequestData()))
                .payload()
                .message();
    }
}
