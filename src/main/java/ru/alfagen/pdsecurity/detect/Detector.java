package ru.alfagen.pdsecurity.detect;

import ru.alfagen.pdsecurity.text.SourceText;

import java.util.List;

/**
 * A detector finds candidates of one entity type in a source text. Detectors
 * never modify the input and return only ranges in source coordinates.
 */
public interface Detector {

    EntityType type();

    List<Candidate> detect(SourceText source, DetectionContext context);
}