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

    private static final Pattern LABEL = Pattern.compile(
            "(?iuU)(адрес\\s+проживания|адрес\\s+регистрации|проживает\\s+по\\s+адресу|зарегистрирован\\s+по\\s+адресу"
                    + "|адрес|проживает\\s+по|зарегистрирован\\s+по)\\b"
                    + "\\s*[:\\s\\-—–]*");

    // Toponym must start with an uppercase letter so lowercase words like
    // "адресу" are not consumed as address components. The (?U) flag makes \b
    // Unicode-aware; labels are made case-insensitive via inline (?i:...).
    private static final String TOPONYM = "[А-ЯЁ][а-яё]+(?:-[А-Яа-яё]+)*";
    private static final String HOUSE_NUM = "\\d+[А-Яа-яё/]*";

    private static final Pattern COMPONENT = Pattern.compile(
            "(?U)(?:(?i:г\\.)\\s*" + TOPONYM
                    + "|(?i:город)\\s*" + TOPONYM
                    + "|(?i:ул\\.)\\s*" + TOPONYM
                    + "|(?i:улица)\\s*" + TOPONYM
                    + "|(?i:проспект)\\s*" + TOPONYM
                    + "|(?i:пр-т)\\s*" + TOPONYM
                    + "|(?i:пер\\.)\\s*" + TOPONYM
                    + "|(?i:ш\\.)\\s*" + TOPONYM
                    + "|(?i:д\\.)\\s*" + HOUSE_NUM
                    + "|(?i:дом)\\s*" + HOUSE_NUM
                    + "|(?i:корп\\.)\\s*\\d+"
                    + "|(?i:стр\\.)\\s*\\d+"
                    + "|(?i:кв\\.)\\s*\\d+"
                    + "|(?i:квартира)\\s*\\d+"
                    + "|\\d{6}"
                    + "|" + TOPONYM + ")");

    private static final Pattern COMPONENT_LABEL = Pattern.compile(
            "(?U)(?:(?i:индекс|город|улица|дом|корпус|строение|квартира|проспект)\\b"
                    + "|(?i:ул\\.|кв\\.|г\\.|д\\.|пр-т|пер\\.|ш\\.))"
                    + "\\s*[:\\s\\-—–]*(" + TOPONYM + "|" + HOUSE_NUM + ")");

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
        int components = 0;
        while (components < 8) {
            Matcher comp = COMPONENT.matcher(text);
            if (!comp.find(pos) || comp.start() != pos) {
                break;
            }
            pos = comp.end();
            components++;
            // Skip separators: commas and spaces.
            int sep = pos;
            while (sep < text.length() && (text.charAt(sep) == ',' || text.charAt(sep) == ' ')) {
                sep++;
            }
            // Stop at a period followed by a capital letter (new sentence) or end.
            if (sep < text.length() && text.charAt(sep) == '.') {
                int after = sep + 1;
                while (after < text.length() && text.charAt(after) == ' ') {
                    after++;
                }
                if (after >= text.length() || Character.isUpperCase(text.charAt(after))) {
                    break;
                }
                // Period inside abbreviation (г., ул.) — continue.
                pos = sep + 1;
                continue;
            }
            if (sep >= text.length() || text.charAt(sep) == '\n') {
                break;
            }
            pos = sep;
        }
        return pos;
    }

    private boolean hasPublicContext(SourceText source, int start, int end) {
        int from = Math.max(0, start - 60);
        int to = Math.min(source.length(), end + 60);
        String around = source.value().substring(from, to);
        return PUBLIC_CONTEXT.matcher(around).find();
    }
}