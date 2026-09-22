package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DefaultDetectionEngine;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A failing detector must not fail the request; the others still run.
 */
class DetectorFaultIsolationTest {

    @Test
    void failingDetectorIsExcluded() {
        Detector failing = new Detector() {
            @Override
            public EntityType type() {
                return EntityType.EMAIL;
            }

            @Override
            public List<Candidate> detect(SourceText source, DetectionContext context) {
                throw new RuntimeException("boom");
            }
        };
        Detector working = new Detector() {
            @Override
            public EntityType type() {
                return EntityType.PHONE;
            }

            @Override
            public List<Candidate> detect(SourceText source, DetectionContext context) {
                return List.of();
            }
        };
        ProcessingMetrics metrics = new ProcessingMetrics(new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        DefaultDetectionEngine engine = new DefaultDetectionEngine(List.of(failing, working), metrics);
        DetectionContext ctx = new DetectionContext("balanced", EnumSet.allOf(EntityType.class));
        assertEquals(0, engine.detect(new SourceText("text"), ctx).size());
    }
}