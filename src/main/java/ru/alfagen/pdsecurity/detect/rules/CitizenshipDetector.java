package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects citizenship following "гражданство", "гражданин/гражданка" or a
 * country dictionary. "Сбербанк России" or a tourist destination is not
 * citizenship.
 */
public final class CitizenshipDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(гражданство|гражданин|гражданка)\\s*[:\\s-]*");

    private static final Pattern WORD = Pattern.compile("(?iuU)[а-яё]+");

    private static final Set<String> COUNTRIES = Set.of(
            "россия", "рф", "казахстан", "беларусь", "украина", "германия", "франция", "сша",
            "китай", "индия", "италия", "испания", "польша", "грузия", "армения", "азербайджан",
            "узбекистан", "таджикистан", "киргизия", "молдова", "латвия", "литва", "эстония",
            "финляндия", "швеция", "норвегия", "дания", "нидерланды", "бельгия", "австрия",
            "швейцария", "чехия", "словакия", "венгрия", "румыния", "болгария", "сербия",
            "греция", "турция", "израиль", "япония", "корея", "вьетнам", "тайланд", "бразилия",
            "аргентина", "мексика", "канада", "австралия");

    @Override
    public EntityType type() {
        return EntityType.CITIZENSHIP;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            Matcher c = WORD.matcher(source.value());
            if (c.find(m.end()) && c.start() == m.end()
                    && COUNTRIES.contains(c.group().toLowerCase(Locale.ROOT))) {
                out.add(new Candidate("cit-" + m.start(), EntityType.CITIZENSHIP,
                        List.of(new SourceRange(c.start(), c.end())), 0.9, 100, "citizenship-label", null));
            }
        }
        return out;
    }
}