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
 * Detects addresses: a field label ("адрес", "проживает", "зарегистрирован")
 * followed by a bounded sequence of address components, and standalone
 * components ("ул. Тверская", "дом 28", "индекс 125009", "г. Москва"). The
 * value stops at a sentence boundary or a transition to non-address text, so
 * trailing clauses ("Позвоните завтра") are not captured. A bank branch address
 * is not a client address.
 */
public final class AddressDetector implements Detector {

    // Toponym must start with an uppercase letter so lowercase words like
    // "адресу" are not consumed as address components. The (?U) flag makes \b
    // Unicode-aware; labels are made case-insensitive via inline (?i:...).
    private static final String TOPONYM = "[А-ЯЁ][а-яё]+(?:-[А-Яа-яё]+){0,3}";

    private static final String HOUSE_NUM = "\\d+[А-Яа-яё/]*";

    private static final String CITY_LABEL = "(?i:г\\.|город)";

    private static final String STREET_LABEL = "(?i:ул\\.|улица|проспект|пр-т|пер\\.|ш\\.)";

    private static final String HOUSE_LABEL = "(?i:д\\.|дом)";

    private static final String UNIT_LABEL = "(?i:корп\\.|стр\\.|кв\\.|квартира)";

    private static final String INDEX = "\\d{6}";
    private static final String INDEX_LABEL = "(?i:индекс)\\b";
    private static final int MAX_COMPONENTS = 8;

    private static final String SEPARATOR = "[:\\s\\-—–]*";

    private static final String ADDRESS_WORD = "адрес(?:\\s+проживания|\\s+регистрации)?";
    private static final String LIVES_AT = "(?:проживает|зарегистрирован)\\s+по(?:\\s+адресу)?";

    private static final Pattern LABEL = Pattern.compile(
            "(?iuU)(?:" + ADDRESS_WORD + "|" + LIVES_AT + ")\\b" + SEPARATOR);

    private static final Pattern COMPONENT = Pattern.compile(
            "(?U)(?:" + CITY_LABEL + "\\s*" + TOPONYM
                    + "|" + STREET_LABEL + "\\s*" + TOPONYM
                    + "|" + HOUSE_LABEL + "\\s*" + HOUSE_NUM
                    + "|" + UNIT_LABEL + "\\s*\\d+"
                    + "|" + INDEX
                    + "|" + TOPONYM + ")");

    private static final String ANY_LABEL =
            INDEX_LABEL + "|" + CITY_LABEL + "|" + STREET_LABEL + "|" + HOUSE_LABEL + "|" + UNIT_LABEL;

    private static final Pattern COMPONENT_LABEL = Pattern.compile(
            "(?U)(?:" + ANY_LABEL + ")" + SEPARATOR + "(" + TOPONYM + "|" + HOUSE_NUM + ")");

    private static final Pattern PUBLIC_CONTEXT = Pattern.compile(
            "(?iuU)(отделение\\s+банка|офис\\s+банка|банк\\s+по\\s+адресу|адрес\\s+отделения|адрес\\s+банка)");

    @Override
    public EntityType type() {
        return EntityType.ADDRESS;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            if (hasPublicContext(source, m.start(), m.end())) {
                continue;
            }
            int end = scanAddressEnd(source, m.end());
            if (end > m.end()) {
                out.add(new Candidate("addr-" + m.start(), EntityType.ADDRESS,
                        List.of(new SourceRange(m.end(), end)), 0.85, 100, "address-label", null));
            }
        }
        Matcher c = COMPONENT_LABEL.matcher(source.value());
        while (c.find()) {
            if (hasPublicContext(source, c.start(), c.end())) {
                continue;
            }
            out.add(new Candidate("addrcomp-" + c.start(), EntityType.ADDRESS,
                    List.of(new SourceRange(c.start(1), c.end(1))), 0.7, 70, "address-component", null));
        }
        return out;
    }

    /**
     * Scan forward from the label end, consuming address components separated by
     * commas/spaces. Stops at a sentence boundary (period followed by a capital
     * letter or end), a newline, or after a bounded number of components.
     */
    private int scanAddressEnd(SourceText source, int from) {
        String text = source.value();
        int pos = from;
        int lastComponentEnd = from;
        boolean more = true;
        for (int components = 0; components < MAX_COMPONENTS && more; components++) {
            Matcher comp = COMPONENT.matcher(text);
            more = comp.find(pos) && comp.start() == pos;
            if (more) {
                lastComponentEnd = comp.end();
                int next = afterSeparators(text, comp.end());
                more = next >= 0;
                pos = more ? next : pos;
            }
        }
        // Возвращаем конец последнего компонента: разделители за ним в адрес не входят.
        return lastComponentEnd;
    }

    /**
     * Skips commas and spaces after a component and returns the position of the
     * next component, or -1 when the address ends here: a sentence boundary
     * (period followed by a capital letter or end of text) or a line break.
     */
    private int afterSeparators(String text, int from) {
        int sep = from;
        while (sep < text.length() && (text.charAt(sep) == ',' || text.charAt(sep) == ' ')) {
            sep++;
        }
        if (sep >= text.length() || text.charAt(sep) == '\n') {
            return -1;
        }
        if (text.charAt(sep) != '.') {
            return sep;
        }
        // A period either ends the sentence or belongs to an abbreviation (г., ул.).
        int after = sep + 1;
        while (after < text.length() && text.charAt(after) == ' ') {
            after++;
        }
        return after >= text.length() || Character.isUpperCase(text.charAt(after)) ? -1 : sep + 1;
    }

    private boolean hasPublicContext(SourceText source, int start, int end) {
        int from = Math.max(0, start - 60);
        int to = Math.min(source.length(), end + 60);
        String around = source.value().substring(from, to);
        return PUBLIC_CONTEXT.matcher(around).find();
    }
}