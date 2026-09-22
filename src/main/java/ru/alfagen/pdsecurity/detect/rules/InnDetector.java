package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects INN (10 or 12 digits) with checksum validation. A valid checksum
 * raises confidence; without context an invalid checksum drops below threshold.
 */
public final class InnDetector extends AbstractRegexDetector {

    private static final Pattern INN = Pattern.compile("(?<![\\d])(\\d{10}|\\d{12})(?![\\d])");

    public InnDetector() {
        super(EntityType.INN, INN);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        String digits = m.group(1);
        boolean valid = isValidInn(digits);
        double confidence = valid ? 0.9 : 0.4;
        return single(EntityType.INN, m, confidence, valid ? 80 : 40, valid ? "inn-valid" : "inn-format");
    }

    static boolean isValidInn(String inn) {
        if (inn.length() == 10) {
            return checksum(inn, new int[]{2, 4, 10, 3, 5, 9, 4, 6, 8}) == inn.charAt(9) - '0';
        }
        if (inn.length() == 12) {
            int c1 = checksum(inn, new int[]{7, 2, 4, 10, 3, 5, 9, 4, 6, 8});
            int c2 = checksum(inn, new int[]{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8});
            return c1 == inn.charAt(10) - '0' && c2 == inn.charAt(11) - '0';
        }
        return false;
    }

    private static int checksum(String inn, int[] weights) {
        int sum = 0;
        for (int i = 0; i < weights.length; i++) {
            sum += (inn.charAt(i) - '0') * weights[i];
        }
        return sum % 11 % 10;
    }
}