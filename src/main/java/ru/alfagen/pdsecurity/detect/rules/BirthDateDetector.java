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
 * Detects birth dates following "дата рождения", "родился", "д.р.", "г.р.".
 * A date without such a label (e.g. a meeting date) is not masked.
 */
public final class BirthDateDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(дата\\s+рождения|родился|родилась|д\\.р\\.|г\\.р\\.)\\s*[:\\s-]*");

    private final DateParser dateParser = new DateParser();

    @Override
    public EntityType type() {
        return EntityType.BIRTH_DATE;
    }

    /** Значение должно стоять рядом с меткой: дальше по тексту это уже другая дата. */
    private static final int MAX_LABEL_DISTANCE = 40;

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            DateParser.ParsedDate d = dateParser.find(source.value(), m.end());
            if (d != null && d.plausible() && d.start() - m.end() <= MAX_LABEL_DISTANCE) {
                out.add(new Candidate("bd-" + m.start(), EntityType.BIRTH_DATE,
                        List.of(new SourceRange(d.start(), d.end())), 0.9, 105, "birth-date-label", null));
            }
        }
        return out;
    }
}