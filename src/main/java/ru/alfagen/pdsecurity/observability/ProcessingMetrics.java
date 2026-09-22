package ru.alfagen.pdsecurity.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import ru.alfagen.pdsecurity.detect.EntityType;

import java.util.concurrent.TimeUnit;

/**
 * Central metrics facade. Labels are limited to known {@code system},
 * {@code operation}, {@code status}, {@code type}, {@code stage} values; no
 * payload ids, tokens, names or exception messages are ever recorded.
 */
public final class ProcessingMetrics {

    private final MeterRegistry registry;

    public ProcessingMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public void event(String system, String operation, String status) {
        Counter.builder("pd.event")
                .tag("system", system)
                .tag("operation", operation)
                .tag("status", status)
                .register(registry)
                .increment();
    }

    public void detected(EntityType type, int count) {
        Counter.builder("pd.detected")
                .tag("type", type.name())
                .register(registry)
                .increment(count);
    }

    public void recordStage(String stage, long nanos) {
        Timer.builder("pd.stage")
                .tag("stage", stage)
                .register(registry)
                .record(nanos, TimeUnit.NANOSECONDS);
    }

    public void recordLatency(long nanos) {
        Timer.builder("pd.http.latency")
                .register(registry)
                .record(nanos, TimeUnit.NANOSECONDS);
    }

    public void recordTokens(long count) {
        Counter.builder("pd.input_tokens_total")
                .tag("tokenizer", "cl100k_base")
                .register(registry)
                .increment(count);
    }

    public void recordStoreSize(int active, int tombstones) {
        registry.gauge("pd.store.active", active);
        registry.gauge("pd.store.tombstones", tombstones);
    }
}