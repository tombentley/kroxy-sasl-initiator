/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReauthSchedulerTest {

    private static final long NOW_MS = 1_000_000L;

    private final MutableClock clock = new MutableClock(Instant.ofEpochMilli(NOW_MS));
    private final RecordingTaskScheduler taskScheduler = new RecordingTaskScheduler();

    @Test
    void usesTheBrokerSessionLifetime() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        ReauthScheduler.Deadline deadline = scheduler.deadline(10_000, null).orElseThrow();

        assertThat(deadline.reauthAtMs()).isEqualTo(NOW_MS + 8_000);
        assertThat(deadline.hardDeadlineMs()).isEqualTo(NOW_MS + 10_000);
    }

    @Test
    void usesTheTokenRemainingLifetime() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        ReauthScheduler.Deadline deadline = scheduler.deadline(0, NOW_MS + 6_000).orElseThrow();

        assertThat(deadline.reauthAtMs()).isEqualTo(NOW_MS + 4_800);
        assertThat(deadline.hardDeadlineMs()).isEqualTo(NOW_MS + 6_000);
    }

    @Test
    void usesTheSmallerOfBrokerAndTokenLifetimes() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        ReauthScheduler.Deadline tokenIsEarlier = scheduler.deadline(10_000, NOW_MS + 6_000).orElseThrow();
        ReauthScheduler.Deadline brokerIsEarlier = scheduler.deadline(5_000, NOW_MS + 6_000).orElseThrow();

        assertThat(tokenIsEarlier.hardDeadlineMs()).isEqualTo(NOW_MS + 6_000);
        assertThat(tokenIsEarlier.reauthAtMs()).isEqualTo(NOW_MS + 4_800);
        assertThat(brokerIsEarlier.hardDeadlineMs()).isEqualTo(NOW_MS + 5_000);
        assertThat(brokerIsEarlier.reauthAtMs()).isEqualTo(NOW_MS + 4_000);
    }

    @Test
    void ignoresAnExpiredTokenWhenTheBrokerReportsALifetime() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        ReauthScheduler.Deadline deadline = scheduler.deadline(10_000, NOW_MS - 1).orElseThrow();

        assertThat(deadline.hardDeadlineMs()).isEqualTo(NOW_MS + 10_000);
    }

    @Test
    void doesNotProduceADeadlineWithoutALifetime() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        assertThat(scheduler.deadline(0, null)).isEmpty();
        assertThat(scheduler.deadline(-1, null)).isEmpty();
        assertThat(scheduler.deadline(0, NOW_MS)).isEmpty();
        assertThat(scheduler.deadline(0, NOW_MS - 1)).isEmpty();
    }

    @Test
    void appliesTheConfiguredWindowFactor() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        assertThat(scheduler.deadline(10_000, null).orElseThrow().reauthAtMs())
                .isEqualTo(NOW_MS + 8_000);
    }

    @Test
    void appliesNegativeAndPositiveJitter() {
        ReauthScheduler negative = scheduler(0.8, -0.05);
        ReauthScheduler positive = scheduler(0.8, 0.05);

        assertThat(negative.deadline(10_000, null).orElseThrow().reauthAtMs())
                .isEqualTo(NOW_MS + 7_500);
        assertThat(positive.deadline(10_000, null).orElseThrow().reauthAtMs())
                .isEqualTo(NOW_MS + 8_500);
    }

    @Test
    void clampsTheJitteredFactorToThePermittedWindow() {
        ReauthScheduler belowMinimum = scheduler(0.5, -0.05);
        ReauthScheduler aboveMaximum = scheduler(0.95, 0.05);

        assertThat(belowMinimum.deadline(10_000, null).orElseThrow().reauthAtMs())
                .isEqualTo(NOW_MS + 5_000);
        assertThat(aboveMaximum.deadline(10_000, null).orElseThrow().reauthAtMs())
                .isEqualTo(NOW_MS + 9_500);
    }

    @Test
    void armsAOneShotTaskAtTheJitteredDelay() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);
        boolean[] due = { false };

        ReauthScheduler.Schedule schedule = scheduler.arm(10_000, null, () -> due[0] = true).orElseThrow();

        assertThat(schedule.deadline().reauthAtMs()).isEqualTo(NOW_MS + 8_000);
        assertThat(taskScheduler.scheduled()).hasSize(1);
        assertThat(taskScheduler.lastScheduled().delayMillis()).isEqualTo(8_000);
        assertThat(due[0]).isFalse();

        clock.advance(Duration.ofMillis(8_000));
        taskScheduler.runLast();

        assertThat(due[0]).isTrue();
        assertThat(schedule.deadline().isDue(clock.millis())).isTrue();
        assertThat(schedule.deadline().isHardDeadlineReached(clock.millis())).isFalse();
    }

    @Test
    void doesNotScheduleWithoutALifetime() {
        ReauthScheduler scheduler = scheduler(0.8, 0.0);

        assertThat(scheduler.arm(0, null, () -> {
        })).isEmpty();
        assertThat(taskScheduler.scheduled()).isEmpty();
    }

    @Test
    void reportsTheHardDeadlineWhenTheEffectiveLifetimeElapses() {
        ReauthScheduler.Deadline deadline = scheduler(0.8, 0.0).deadline(10_000, null).orElseThrow();

        clock.advance(Duration.ofMillis(9_999));
        assertThat(deadline.isHardDeadlineReached(clock.millis())).isFalse();

        clock.advance(Duration.ofMillis(1));
        assertThat(deadline.isHardDeadlineReached(clock.millis())).isTrue();
    }

    private ReauthScheduler scheduler(double windowFactor, double jitter) {
        return ReauthScheduler.with(clock, windowFactor, taskScheduler, () -> jitter);
    }
}
