package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects dates written in words, e.g. "двенадцатого марта тысяча девятьсот
 * девяностого года". The day is a Russian ordinal in genitive, the month is a
 * genitive month name, and the year is a cardinal in genitive followed by
 * "года". Only dates following a birth/issue label are masked.
 */
public final class DateWordsDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(дата\\s+рождения|родился|родилась|дата\\s+выдачи|выдан|выдана)\\s*[:\\s-]*");

    private static final Map<String, Integer> MONTHS = Map.ofEntries(
            Map.entry("января", 1), Map.entry("февраля", 2), Map.entry("марта", 3),
            Map.entry("апреля", 4), Map.entry("мая", 5), Map.entry("июня", 6),
            Map.entry("июля", 7), Map.entry("августа", 8), Map.entry("сентября", 9),
            Map.entry("октября", 10), Map.entry("ноября", 11), Map.entry("декабря", 12));

    private static final Pattern DATE_WORDS = Pattern.compile(
            "(?iu)([а-яё]+(?:\s+[а-яё]+){0,3})\s+(" + String.join("|", MONTHS.keySet()) + ")"
                    + "\s+([а-яё]+(?:\s+[а-яё]+){0,4})\s+года");


    @Override
    public EntityType type() {
        return EntityType.BIRTH_DATE;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            Matcher d = DATE_WORDS.matcher(source.value());
            if (d.find(m.end()) && d.start() == m.end()) {
                String day = d.group(1);
                String month = d.group(2);
                String year = d.group(3);
                if (MONTHS.containsKey(month.toLowerCase()) && plausibleDay(day) && plausibleYear(year)) {
                    out.add(new Candidate("bdw-" + m.start(), EntityType.BIRTH_DATE,
                            List.of(new SourceRange(d.start(), d.end())), 0.9, 105, "birth-date-words", null));
                }
            }
        }
        return out;
    }

    private boolean plausibleDay(String dayWords) {
        Integer day = NumberWords.parseOrdinal(dayWords);
        return day != null && day >= 1 && day <= 31;
    }

    private boolean plausibleYear(String yearWords) {
        Integer year = NumberWords.parseCardinal(yearWords);
        return year != null && year >= 1900 && year <= 2100;
    }
}