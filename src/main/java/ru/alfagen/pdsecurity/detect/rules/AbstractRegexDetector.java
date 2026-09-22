package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Base class for regex-based detectors. Subclasses provide a compiled pattern
 * and a factory that turns a match into a candidate. All patterns are
 * {@code static final}.
 */
public abstract class AbstractRegexDetector implements Detector {

    private final EntityType type;
    private final Pattern pattern;

    protected AbstractRegexDetector(EntityType type, Pattern pattern) {
        this.type = type;
        this.pattern = pattern;
    }

    @Override
    public EntityType type() {
        return type;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = pattern.matcher(source.value());
        while (m.find()) {
            Candidate c = build(source, m);
            if (c != null) {
                out.add(c);
            }
        }
        return out;
    }

    /**
     * Build a candidate from a match, or return null to skip it.
     */
    protected abstract Candidate build(SourceText source, Matcher m);

    protected Candidate single(EntityType type, Matcher m, double confidence, int priority, String evidence) {
        SourceRange range = new SourceRange(m.start(), m.end());
        return new Candidate("e" + m.start(), type, List.of(range), confidence, priority, evidence, null);
    }
}