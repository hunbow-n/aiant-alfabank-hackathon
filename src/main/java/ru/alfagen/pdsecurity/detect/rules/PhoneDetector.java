package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects phone numbers: +7/8, optional country code, brackets, dashes, spaces.
 * A leading + or 8 and 10-11 digits with separators is required so a substring
 * of a longer number or a plain date is not matched.
 */
public final class PhoneDetector extends AbstractRegexDetector {

    private static final Pattern PHONE = Pattern.compile(
            "(?<![\\d])(?:\\+7|8|\\+\\d{1,3})[\\s(.-]*\\d{3}[\\s).-]*\\d{3}[\\s.-]*\\d{2}[\\s.-]*\\d{2}(?![\\d])");

    public PhoneDetector() {
        super(EntityType.PHONE, PHONE);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        return single(EntityType.PHONE, m, 0.95, 90, "phone-format");
    }
}