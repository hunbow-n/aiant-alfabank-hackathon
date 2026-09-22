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
 * Detects birth places following "место рождения" or "родился в". Captures the
 * place up to a field boundary (comma, newline, or a known next-field label).
 */
public final class BirthPlaceDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(место\\s+рождения|родился\\s+в|родилась\\s+в)\\s*[:\\s-]*");

    private static final Pattern BOUNDARY = Pattern.compile(
            "(?iu)(,|\\n|;|дата|паспорт|гражданство|адрес|телефон|email|\\b\\d{2}\\.\\d{2}\\.\\d{4})");

    @Override
    public EntityType type() {
        return EntityType.BIRTH_PLACE;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            int start = m.end();
            Matcher b = BOUNDARY.matcher(source.value());
            int end = source.length();
            if (b.find(start)) {
                end = b.start();
            }
            if (end > start) {
                out.add(new Candidate("bp-" + m.start(), EntityType.BIRTH_PLACE,
                        List.of(new SourceRange(start, end)), 0.85, 100, "birth-place-label", null));
            }
        }
        return out;
    }
}