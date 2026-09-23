package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects CVV/CVC codes: 3 digits (or 4 with an explicit matching context)
 * following a CVV/CVC/"код на обороте" label. Bare three digits without a
 * label are not masked.
 */
public final class CvvDetector extends AbstractRegexDetector {

    private static final Pattern CVV = Pattern.compile(
            "(?iu)(?:cvv|cvc|код\\s+на\\s+обороте|код\\s+проверки)[:\\s-]*(\\d{3,4})");

    public CvvDetector() {
        super(EntityType.CVV, CVV);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        String digits = m.group(1);
        if (digits.length() == 4) {
            return null; // 4-digit only with explicit context handled by PIN
        }
        return single(EntityType.CVV, m, 0.95, 110, "cvv-label");
    }
}