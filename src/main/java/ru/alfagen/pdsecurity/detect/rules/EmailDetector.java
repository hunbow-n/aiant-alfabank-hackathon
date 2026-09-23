package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects email addresses. A practical {@code local@domain} pattern without a
 * full RFC parser. A sentence dot right after the address is not part of it:
 * the domain stops at the last alphabetic label.
 */
public final class EmailDetector extends AbstractRegexDetector {

    private static final Pattern EMAIL = Pattern.compile(
            "(?<![\\w.+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,})(?![\\w+-])");

    public EmailDetector() {
        super(EntityType.EMAIL, EMAIL);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        return single(EntityType.EMAIL, m, 0.99, 100, "email-format");
    }
}