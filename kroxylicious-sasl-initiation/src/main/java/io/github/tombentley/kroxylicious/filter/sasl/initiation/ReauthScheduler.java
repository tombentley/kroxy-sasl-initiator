/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.function.DoubleSupplier;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.ReauthConfig;

import io.kroxylicious.proxy.filter.FilterDispatchExecutor;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Computes KIP-368 reauthentication deadlines and arms a single one-shot task for a connection.
 * <p>
 * The effective lifetime is the smaller of a positive broker-reported {@code sessionLifetimeMs} and the remaining
 * lifetime of an OAuth bearer token. When neither is available, no deadline is produced and no task is scheduled.
 * </p>
 * <p>
 * The task only records that reauthentication is due. It performs no I/O and does not touch the broker; the exchange is
 * started from the next request boundary on the connection's filter-dispatch thread.
 * </p>
 * <p>
 * Instances are per connection. The supplied clock and task scheduler make the timing deterministic in unit tests.
 * </p>
 */
final class ReauthScheduler {

    /**
     * The maximum absolute jitter added to the configured window factor.
     */
    static final double JITTER_RANGE = 0.05;

    /**
     * Schedules a one-shot task and returns a handle that can cancel it.
     */
    @FunctionalInterface
    interface TaskScheduler {

        /**
         * Schedules a task.
         *
         * @param task the task
         * @param delayMillis the delay in milliseconds, which is never negative
         * @return a handle that cancels the task
         */
        Cancellable schedule(Runnable task, long delayMillis);
    }

    /**
     * A cancellation handle for a scheduled task.
     */
    @FunctionalInterface
    interface Cancellable {

        /**
         * A handle that has nothing to cancel.
         */
        Cancellable NONE = () -> {
        };

        /**
         * Cancels the task if it has not run yet.
         */
        void cancel();
    }

    /**
     * An armed reauthentication deadline.
     *
     * @param reauthAtMs the filtered-clock instant at which reauthentication should start on the next request
     * @param hardDeadlineMs the filtered-clock instant after which the connection must fail closed
     */
    record Deadline(long reauthAtMs, long hardDeadlineMs) {

        /**
         * Reports whether reauthentication is due at the given instant.
         *
         * @param nowMs the current filtered-clock instant
         * @return {@code true} when {@code nowMs} is at or after the reauthentication instant
         */
        boolean isDue(long nowMs) {
            return nowMs >= reauthAtMs;
        }

        /**
         * Reports whether the effective lifetime has elapsed.
         *
         * @param nowMs the current filtered-clock instant
         * @return {@code true} when {@code nowMs} is at or after the hard deadline
         */
        boolean isHardDeadlineReached(long nowMs) {
            return nowMs >= hardDeadlineMs;
        }
    }

    /**
     * An armed deadline and the task that marks it due.
     *
     * @param deadline the deadline
     * @param cancellation the task cancellation handle
     */
    record Schedule(Deadline deadline, Cancellable cancellation) {

        /**
         * Validates the schedule.
         */
        public Schedule {
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(cancellation, "cancellation");
        }
    }

    private final Clock clock;
    private final double windowFactor;
    private final @Nullable TaskScheduler taskScheduler;
    private final DoubleSupplier jitter;

    private ReauthScheduler(Clock clock,
                            double windowFactor,
                            @Nullable TaskScheduler taskScheduler,
                            DoubleSupplier jitter) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.windowFactor = windowFactor;
        this.taskScheduler = taskScheduler;
        this.jitter = Objects.requireNonNull(jitter, "jitter");
    }

    /**
     * Creates a scheduler that computes deadlines but never schedules a task. Used in tests that do not exercise
     * scheduling and when no filter-dispatch executor is available.
     *
     * @param clock the clock
     * @param windowFactor the configured reauthentication window factor
     * @return a scheduler without a task scheduler
     */
    static ReauthScheduler withoutTaskScheduling(Clock clock, double windowFactor) {
        return new ReauthScheduler(clock, windowFactor, null, defaultJitter());
    }

    /**
     * Creates a scheduler that arms tasks on the connection's filter-dispatch executor.
     *
     * @param executor the connection's filter-dispatch executor
     * @param clock the clock
     * @param windowFactor the configured reauthentication window factor
     * @return a scheduler that arms tasks on the executor
     */
    static ReauthScheduler onFilterDispatchExecutor(FilterDispatchExecutor executor,
                                                    Clock clock,
                                                    double windowFactor) {
        Objects.requireNonNull(executor, "executor");
        return with(clock, windowFactor, (task, delayMillis) -> {
            ScheduledFuture<?> future = executor.schedule(task, delayMillis, TimeUnit.MILLISECONDS);
            return () -> future.cancel(false);
        }, defaultJitter());
    }

    /**
     * Creates a scheduler with explicit scheduling and jitter sources. Intended for tests.
     *
     * @param clock the clock
     * @param windowFactor the configured reauthentication window factor
     * @param taskScheduler the task scheduler, or {@code null} to compute deadlines without scheduling
     * @param jitter a supplier of values in {@code [-0.05, +0.05]}
     * @return a scheduler
     */
    static ReauthScheduler with(Clock clock,
                                double windowFactor,
                                @Nullable TaskScheduler taskScheduler,
                                DoubleSupplier jitter) {
        return new ReauthScheduler(clock, windowFactor, taskScheduler, jitter);
    }

    /**
     * Returns the clock used by this scheduler. The filter uses the same clock for hard-deadline checks.
     *
     * @return the clock
     */
    Clock clock() {
        return clock;
    }

    /**
     * Computes the reauthentication deadline for a newly authenticated session.
     *
     * @param brokerSessionLifetimeMs the broker-reported session lifetime; zero or negative means absent
     * @param tokenExpiresAtMs the OAuth token expiry instant, or {@code null} for password mechanisms
     * @return the deadline, or empty when there is no positive lifetime
     */
    Optional<Deadline> deadline(long brokerSessionLifetimeMs, @Nullable Long tokenExpiresAtMs) {
        return deadline(clock.millis(), brokerSessionLifetimeMs, tokenExpiresAtMs);
    }

    /**
     * Computes a deadline and arms the one-shot task when a lifetime is available.
     *
     * @param brokerSessionLifetimeMs the broker-reported session lifetime; zero or negative means absent
     * @param tokenExpiresAtMs the OAuth token expiry instant, or {@code null} for password mechanisms
     * @param onDue the task that records that reauthentication is due
     * @return the armed deadline, or empty when there is no positive lifetime
     */
    Optional<Schedule> arm(long brokerSessionLifetimeMs, @Nullable Long tokenExpiresAtMs, Runnable onDue) {
        Objects.requireNonNull(onDue, "onDue");
        long now = clock.millis();
        Optional<Deadline> deadline = deadline(now, brokerSessionLifetimeMs, tokenExpiresAtMs);
        if (deadline.isEmpty()) {
            return Optional.empty();
        }
        Deadline value = deadline.get();
        Cancellable cancellation = taskScheduler == null
                ? Cancellable.NONE
                : taskScheduler.schedule(onDue, Math.max(0L, value.reauthAtMs() - now));
        return Optional.of(new Schedule(value, cancellation));
    }

    private Optional<Deadline> deadline(long nowMs, long brokerSessionLifetimeMs, @Nullable Long tokenExpiresAtMs) {
        long effectiveLifetimeMs = effectiveLifetimeMs(nowMs, brokerSessionLifetimeMs, tokenExpiresAtMs);
        if (effectiveLifetimeMs <= 0) {
            return Optional.empty();
        }
        double jitteredFactor = Math.max(ReauthConfig.MIN_WINDOW_FACTOR,
                Math.min(ReauthConfig.MAX_WINDOW_FACTOR, windowFactor + jitter.getAsDouble()));
        long reauthDelayMs = Math.round(effectiveLifetimeMs * jitteredFactor);
        return Optional.of(new Deadline(
                saturatedAdd(nowMs, reauthDelayMs),
                saturatedAdd(nowMs, effectiveLifetimeMs)));
    }

    private static long effectiveLifetimeMs(long nowMs,
                                            long brokerSessionLifetimeMs,
                                            @Nullable Long tokenExpiresAtMs) {
        long effectiveLifetimeMs = brokerSessionLifetimeMs > 0 ? brokerSessionLifetimeMs : Long.MAX_VALUE;
        if (tokenExpiresAtMs != null) {
            long tokenRemainingMs = tokenExpiresAtMs - nowMs;
            if (tokenRemainingMs > 0) {
                effectiveLifetimeMs = Math.min(effectiveLifetimeMs, tokenRemainingMs);
            }
        }
        return effectiveLifetimeMs == Long.MAX_VALUE ? 0 : effectiveLifetimeMs;
    }

    private static long saturatedAdd(long left, long right) {
        long result = left + right;
        if (((left ^ result) & (right ^ result)) < 0) {
            return Long.MAX_VALUE;
        }
        return result;
    }

    private static DoubleSupplier defaultJitter() {
        return () -> ThreadLocalRandom.current().nextDouble(-JITTER_RANGE, JITTER_RANGE);
    }
}
