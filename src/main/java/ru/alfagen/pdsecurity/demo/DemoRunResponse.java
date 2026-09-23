package ru.alfagen.pdsecurity.demo;

import java.util.List;
import java.util.Map;

/**
 * Everything the demo page shows: the four stages of the round trip, what the
 * module detected and how long each stage took.
 *
 * @param original    what the reviewer typed
 * @param masked      what actually left the protected perimeter
 * @param llmResponse what the model answered, still masked
 * @param restored    what the consumer system finally receives
 * @param detected    detected types and their counts, the same map that goes to the log
 * @param spans       masked fragments, for highlighting on the page
 * @param timings     stage durations in milliseconds
 * @param llmMode     which model answered: mock or alfagen
 * @param strategy    mask strategy actually applied
 * @param system      consumer system whose policy was used
 * @param policyTypes число типов ПД, которые маскирует политика этой системы
 * @param notCovered  типы, найденные в тексте, но не входящие в перечень системы
 * @param note        optional human-readable note, e.g. why the model was unavailable
 */
public record DemoRunResponse(
        String original,
        String masked,
        String llmResponse,
        String restored,
        Map<String, Integer> detected,
        List<String> spans,
        Map<String, Long> timings,
        String llmMode,
        String strategy,
        String system,
        int policyTypes,
        List<String> notCovered,
        String note) {
}
