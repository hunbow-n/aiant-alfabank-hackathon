package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects SNILS (СНИЛС): 11 digits in the form XXX-XXX-XXX YY with a valid
 * checksum. The checksum is the last two digits computed from the first nine.
 */
public final class SnilsDetector extends AbstractRegexDetector {

    private static final Pattern SNILS = Pattern.compile(
            "(?<![\\d])(\\d{3}-\\d{3}-\\d{3}\\s\\d{2})(?![\\d])");

    public SnilsDetector() {
        super(EntityType.PASSPORT, SNILS);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        String digits = m.group(1).replaceAll("[^\\d]", "");
        boolean valid = isValidSnils(digits);
        double confidence = valid ? 0.9 : 0.4;
        return single(EntityType.PASSPORT, m, confidence, valid ? 80 : 40,
                valid ? "snils-valid" : "snils-format");
    }

    static boolean isValidSnils(String digits) {
        if (digits.length() != 11) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            sum += (digits.charAt(i) - '0') * (9 - i);
        }
        int control;
        if (sum < 100) {
            control = sum;
        } else if (sum == 100 || sum == 101) {
            control = 0;
        } else {
            control = sum % 101;
            if (control == 100) {
                control = 0;
            }
        }
        return control == Integer.parseInt(digits.substring(9));
    }
}