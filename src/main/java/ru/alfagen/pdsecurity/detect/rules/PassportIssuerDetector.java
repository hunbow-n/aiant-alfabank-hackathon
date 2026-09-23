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
 * Detects passport issuing authority: a field label followed by МВД/УФМС/ОВД/ТП/ГУ
 * and the long authority name, stopping at a date, code or next field.
 */
public final class PassportIssuerDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(кем\\s+выдан|орган\\s+выдачи|выдан)\\s*[:\\s-]*");

    private static final String ABBREVIATIONS = "о?уфмс|мвд|овд|офмс|фмс|тп|гу\\s+мвд";
    private static final String FULL_NAMES =
            "отдел(?:ом)?\\s+внутренних\\s+дел|управление\\s+внутренних\\s+дел";

    private static final Pattern AUTHORITY = Pattern.compile(
            "(?iu)(" + ABBREVIATIONS + "|" + FULL_NAMES + ")");

    private static final Pattern STOP = Pattern.compile(
            "(?iu)(\\d{2}\\.\\d{2}\\.\\d{4}|код\\s+подразделения|дата\\s+выдачи|\\n)");

    @Override
    public EntityType type() {
        return EntityType.PASSPORT_ISSUER;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            Matcher a = AUTHORITY.matcher(source.value());
            if (!a.find(m.end())) {
                continue;
            }
            int start = a.start();
            Matcher s = STOP.matcher(source.value());
            int end = source.length();
            if (s.find(a.end())) {
                end = s.start();
            }
            // Пробелы перед следующим полем в название органа не входят.
            while (end > start && Character.isWhitespace(source.charAt(end - 1))) {
                end--;
            }
            if (end > start) {
                out.add(new Candidate("iss-" + m.start(), EntityType.PASSPORT_ISSUER,
                        List.of(new SourceRange(start, end)), 0.85, 100, "issuer-label", null));
            }
        }
        return out;
    }
}