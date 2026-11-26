/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.util.ArrayList;
import java.util.List;

/**
 * A controllable task scheduler for reauthentication timing tests.
 */
final class RecordingTaskScheduler implements ReauthScheduler.TaskScheduler {

    /**
     * A scheduled task.
     *
     * @param task the task
     * @param delayMillis the delay
     */
    record ScheduledTask(Runnable task, long delayMillis) {}

    private final List<ScheduledTask> scheduled = new ArrayList<>();
    private final List<ScheduledTask> cancelled = new ArrayList<>();

    @Override
    public ReauthScheduler.Cancellable schedule(Runnable task, long delayMillis) {
        ScheduledTask scheduledTask = new ScheduledTask(task, delayMillis);
        scheduled.add(scheduledTask);
        return () -> cancelled.add(scheduledTask);
    }

    List<ScheduledTask> scheduled() {
        return List.copyOf(scheduled);
    }

    ScheduledTask lastScheduled() {
        if (scheduled.isEmpty()) {
            throw new IllegalStateException("No task has been scheduled");
        }
        return scheduled.get(scheduled.size() - 1);
    }

    boolean isCancelled(ScheduledTask task) {
        return cancelled.contains(task);
    }

    void runLast() {
        lastScheduled().task().run();
    }
}
