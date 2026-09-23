package ru.alfagen.pdsecurity.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import ru.alfagen.pdsecurity.detect.EntityType;

import io.micrometer.core.instrument.distribution.HistogramSnapshot;
import io.micrometer.core.instrument.distribution.ValueAtPercentile;

import java.util.LinkedHashMap;
import java.util.Map;
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
        latencyTimer().record(nanos, TimeUnit.NANOSECONDS);
    }

    private Timer latencyTimer() {
        return Timer.builder("pd.http.latency")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);
    }

    /**
     * Снимок для демонстрационной страницы: агрегаты, которые уже собираются
     * для Prometheus. Значений персональных данных здесь нет по построению —
     * только счётчики и перцентили.
     */
    public Map<String, Object> snapshot() {
        Timer latency = latencyTimer();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("requests", latency.count());
        out.put("latencyMeanMicros", Math.round(latency.mean(TimeUnit.MICROSECONDS)));
        out.put("latencyMaxMicros", Math.round(latency.max(TimeUnit.MICROSECONDS)));
        HistogramSnapshot histogram = latency.takeSnapshot();
        Map<String, Long> percentiles = new LinkedHashMap<>();
        for (ValueAtPercentile v : histogram.percentileValues()) {
            percentiles.put("p" + Math.round(v.percentile() * 100),
                    Math.round(v.value(TimeUnit.MICROSECONDS)));
        }
        out.put("latencyPercentilesMicros", percentiles);

        Map<String, Long> detected = new LinkedHashMap<>();
        registry.find("pd.detected").counters().stream()
                .filter(c -> c.count() > 0)
                .forEach(c -> detected.merge(c.getId().getTag("type"), (long) c.count(), Long::sum));
        out.put("detectedByType", detected);

        Map<String, Long> events = new LinkedHashMap<>();
        registry.find("pd.event").counters().stream()
                .filter(c -> c.count() > 0)
                .forEach(c -> events.merge(c.getId().getTag("status"), (long) c.count(), Long::sum));
        out.put("eventsByStatus", events);

        Counter tokens = registry.find("pd.input_tokens_total").counter();
        out.put("inputTokens", tokens == null ? 0L : (long) tokens.count());
        return out;
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