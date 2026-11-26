/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.metrics;

import java.time.Duration;
import java.util.Objects;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;

/**
 * Micrometer metrics for the SASL initiation filter.
 * <p>
 * Meters are registered with {@link Metrics#globalRegistry}, following the conventions of the SASL termination filter.
 * Tags are deliberately bounded: mechanism, virtual cluster, outcome and a small set of connection-close reasons.
 * Subject names, broker usernames and other identity values are never used as tags because they would create
 * unbounded cardinality and expose identity information through the metrics endpoint.
 * </p>
 */
public final class SaslInitiationMetrics {

    /**
     * Number of SASL initiation authentication attempts.
     */
    public static final String AUTH_ATTEMPTS_METRIC = "kroxylicious_filter_sasl_initiation_auth_attempts_total";

    /**
     * Duration of SASL initiation authentication attempts.
     */
    public static final String AUTH_DURATION_METRIC = "kroxylicious_filter_sasl_initiation_auth_duration_seconds";

    /**
     * Number of KIP-368 reauthentication attempts.
     */
    public static final String REAUTH_ATTEMPTS_METRIC = "kroxylicious_filter_sasl_initiation_reauth_attempts_total";

    /**
     * Duration of KIP-368 reauthentication attempts.
     */
    public static final String REAUTH_DURATION_METRIC = "kroxylicious_filter_sasl_initiation_reauth_duration_seconds";

    /**
     * Duration of OAuth bearer token retrieval and validation.
     */
    public static final String TOKEN_RETRIEVAL_DURATION_METRIC = "kroxylicious_filter_sasl_initiation_token_retrieval_duration_seconds";

    /**
     * Number of connections closed by the filter.
     */
    public static final String CONNECTION_CLOSED_METRIC = "kroxylicious_filter_sasl_initiation_connection_closed_total";

    /**
     * The mechanism tag.
     */
    public static final String MECHANISM_TAG = "mechanism";

    /**
     * The virtual cluster tag.
     */
    public static final String VIRTUAL_CLUSTER_TAG = "virtual_cluster";

    /**
     * The outcome tag.
     */
    public static final String OUTCOME_TAG = "outcome";

    /**
     * The connection-close reason tag.
     */
    public static final String REASON_TAG = "reason";

    /**
     * The successful outcome value.
     */
    public static final String OUTCOME_SUCCESS = "success";

    /**
     * The failed outcome value.
     */
    public static final String OUTCOME_FAILURE = "failure";

    private SaslInitiationMetrics() {
        // Utility class.
    }

    /**
     * Records one initial authentication attempt.
     *
     * @param mechanism the SASL mechanism name
     * @param virtualCluster the virtual cluster name
     * @param success whether the attempt succeeded
     */
    public static void recordAuthAttempt(String mechanism, String virtualCluster, boolean success) {
        Counter.builder(AUTH_ATTEMPTS_METRIC)
                .description("SASL initiation authentication attempts by mechanism, virtual cluster and outcome.")
                .tag(MECHANISM_TAG, Objects.requireNonNull(mechanism, "mechanism"))
                .tag(VIRTUAL_CLUSTER_TAG, Objects.requireNonNull(virtualCluster, "virtualCluster"))
                .tag(OUTCOME_TAG, outcome(success))
                .register(Metrics.globalRegistry)
                .increment();
    }

    /**
     * Records the duration of one initial authentication attempt.
     *
     * @param mechanism the SASL mechanism name
     * @param virtualCluster the virtual cluster name
     * @param duration the attempt duration
     */
    public static void recordAuthDuration(String mechanism, String virtualCluster, Duration duration) {
        Timer.builder(AUTH_DURATION_METRIC)
                .description("Duration of SASL initiation authentication attempts, including API negotiation, "
                        + "SASL handshake and challenge/response rounds.")
                .tag(MECHANISM_TAG, Objects.requireNonNull(mechanism, "mechanism"))
                .tag(VIRTUAL_CLUSTER_TAG, Objects.requireNonNull(virtualCluster, "virtualCluster"))
                .register(Metrics.globalRegistry)
                .record(nonNegative(duration));
    }

    /**
     * Records one KIP-368 reauthentication attempt.
     *
     * @param mechanism the SASL mechanism name
     * @param virtualCluster the virtual cluster name
     * @param success whether the attempt succeeded
     */
    public static void recordReauthAttempt(String mechanism, String virtualCluster, boolean success) {
        Counter.builder(REAUTH_ATTEMPTS_METRIC)
                .description("SASL initiation KIP-368 reauthentication attempts by mechanism, virtual cluster and outcome.")
                .tag(MECHANISM_TAG, Objects.requireNonNull(mechanism, "mechanism"))
                .tag(VIRTUAL_CLUSTER_TAG, Objects.requireNonNull(virtualCluster, "virtualCluster"))
                .tag(OUTCOME_TAG, outcome(success))
                .register(Metrics.globalRegistry)
                .increment();
    }

    /**
     * Records the duration of one KIP-368 reauthentication attempt.
     *
     * @param mechanism the SASL mechanism name
     * @param virtualCluster the virtual cluster name
     * @param duration the attempt duration
     */
    public static void recordReauthDuration(String mechanism, String virtualCluster, Duration duration) {
        Timer.builder(REAUTH_DURATION_METRIC)
                .description("Duration of SASL initiation KIP-368 reauthentication attempts.")
                .tag(MECHANISM_TAG, Objects.requireNonNull(mechanism, "mechanism"))
                .tag(VIRTUAL_CLUSTER_TAG, Objects.requireNonNull(virtualCluster, "virtualCluster"))
                .register(Metrics.globalRegistry)
                .record(nonNegative(duration));
    }

    /**
     * Records the duration of one OAuth bearer token retrieval attempt.
     *
     * @param success whether retrieval and validation succeeded
     * @param duration the attempt duration
     */
    public static void recordTokenRetrieval(boolean success, Duration duration) {
        Timer.builder(TOKEN_RETRIEVAL_DURATION_METRIC)
                .description("Duration of OAuth bearer token retrieval and validation by outcome.")
                .tag(OUTCOME_TAG, outcome(success))
                .register(Metrics.globalRegistry)
                .record(nonNegative(duration));
    }

    /**
     * Records one connection closed by the filter.
     *
     * @param reason a bounded reason such as {@code auth-failure}, {@code reauth-failure} or {@code subject-change}
     */
    public static void recordConnectionClosed(String reason) {
        Counter.builder(CONNECTION_CLOSED_METRIC)
                .description("Connections closed by SASL initiation by bounded reason.")
                .tag(REASON_TAG, Objects.requireNonNull(reason, "reason"))
                .register(Metrics.globalRegistry)
                .increment();
    }

    private static String outcome(boolean success) {
        return success ? OUTCOME_SUCCESS : OUTCOME_FAILURE;
    }

    private static Duration nonNegative(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        return duration.isNegative() ? Duration.ZERO : duration;
    }
}
