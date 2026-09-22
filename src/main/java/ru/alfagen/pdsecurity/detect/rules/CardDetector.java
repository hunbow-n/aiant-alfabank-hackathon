package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects bank card numbers (13-19 digits) with Luhn validation and optional
 * grouping by spaces. A valid Luhn sum raises confidence.
 */
public final class CardDetector extends AbstractRegexDetector {

    private static final Pattern CARD = Pattern.compile(
            "(?<![\\d])(\\d{4}[ ]?\\d{4}[ ]?\\d{4}[ ]?\\d{4}|\\d{4}[ ]?\\d{4}[ ]?\\d{4}[ ]?\\d{3}|\\d{13,19})(?![\\d])");

    public CardDetector() {
        super(EntityType.CARD, CARD);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        String digits = m.group(1).replace(" ", "");
        boolean luhn = isLuhn(digits);
        double confidence = luhn ? 0.9 : 0.4;
        return single(EntityType.CARD, m, confidence, luhn ? 80 : 40, luhn ? "card-luhn" : "card-format");
    }

    static boolean isLuhn(String digits) {
        int sum = 0;
        boolean alt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (alt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            alt = !alt;
        }
        return sum % 10 == 0;
    }
}