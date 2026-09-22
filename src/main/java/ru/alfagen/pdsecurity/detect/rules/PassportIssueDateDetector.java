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
 * Detects passport issue dates following "дата выдачи", "выдан", "выдана" in a
 * passport context. A birth date or delivery date nearby is not masked.
 */
public final class PassportIssueDateDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(дата\\s+выдачи|выдан|выдана)\\s*[:\\s-]*");

    private final DateParser dateParser = new DateParser();

    @Override
    public EntityType type() {
        return EntityType.PASSPORT_ISSUE_DATE;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            DateParser.ParsedDate d = dateParser.find(source.value(), m.end());
            if (d != null && d.plausible()) {
                out.add(new Candidate("pid-" + m.start(), EntityType.PASSPORT_ISSUE_DATE,
                        List.of(new SourceRange(d.start(), d.end())), 0.85, 100, "issue-date-label", null));
            }
        }
        return out;
    }
}