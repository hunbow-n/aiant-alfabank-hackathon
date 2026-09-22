package ru.alfagen.pdsecurity.detect;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs enabled detectors and isolates failures: an exception in one detector
 * excludes that detector from this pass, records the fact in metrics, and lets
 * the others proceed normally. The request still succeeds.
 */
public final class DefaultDetectionEngine implements DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DefaultDetectionEngine.class);

    private final List<Detector> detectors;
    private final ProcessingMetrics metrics;

    public DefaultDetectionEngine(List<Detector> detectors, ProcessingMetrics metrics) {
        this.detectors = List.copyOf(detectors);
        this.metrics = metrics;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> all = new ArrayList<>();
        for (Detector d : detectors) {
            if (!context.enabled(d.type())) {
                continue;
            }
            try {
                List<Candidate> found = d.detect(source, context);
                all.addAll(found);
                metrics.detected(d.type(), found.size());
            } catch (RuntimeException e) {
                metrics.event("benchmark", "detect", "failed");
                log.warn("detector {} excluded for this pass", d.type());
            }
        }
        return all;
    }
}