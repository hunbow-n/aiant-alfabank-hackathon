package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects Russian passports: series 2+2 digits and number 6 digits. Requires
 * either a passport label ("серия", "номер", "паспорт", "№") or word boundaries
 * around the whole form, so a longer digit sequence (card, INN) is not matched.
 * Series and number are separate ranges of one composite entity so the labels
 * and surrounding spaces are preserved.
 */
public final class PassportDetector extends AbstractRegexDetector {

    private static final Pattern PASSPORT = Pattern.compile(
            "(?iu)(?:(?:серия|паспорт)\\s*)?(?<![\\d])(\\d{2}\\s?\\d{2})\\s*(?:номер\\s*)?(\\d{6})(?![\\d])");

    public PassportDetector() {
        super(EntityType.PASSPORT, PASSPORT);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        String series = m.group(1);
        String number = m.group(2);
        int seriesStart = m.start(1);
        int numberStart = m.start(2);
        int numberEnd = m.end(2);

        List<SourceRange> ranges = new ArrayList<>();
        ranges.add(new SourceRange(seriesStart, seriesStart + series.length()));
        ranges.add(new SourceRange(numberStart, numberEnd));

        String entityId = "passport-" + m.start();
        return new Candidate(entityId, EntityType.PASSPORT, ranges, 0.9, 85,
                "passport-format", null);
    }
}