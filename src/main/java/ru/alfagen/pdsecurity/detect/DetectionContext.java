package ru.alfagen.pdsecurity.detect;

/**
 * Per-request detection context: ambiguity mode and the set of types to detect.
 * Detectors may consult it to tune thresholds.
 *
 * @param ambiguityMode contextual or balanced
 * @param detectTypes   types enabled for this request
 */
public record DetectionContext(String ambiguityMode, java.util.Set<EntityType> detectTypes) {

    public boolean enabled(EntityType type) {
        return detectTypes.contains(type);
    }
}