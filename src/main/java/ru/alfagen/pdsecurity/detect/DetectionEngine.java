package ru.alfagen.pdsecurity.detect;

import ru.alfagen.pdsecurity.text.SourceText;

import java.util.List;

/**
 * Runs the enabled detectors over a source and collects candidates. A failure
 * in one detector must not fail the request.
 */
public interface DetectionEngine {

    List<Candidate> detect(SourceText source, DetectionContext context);
}