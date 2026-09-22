package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects PIN codes: usually 4 digits, other lengths only with an explicit
 * "ПИН"/"PIN"/"пин-код" label. A bare year or postal index is not masked.
 */
public final class PinDetector extends AbstractRegexDetector {

    private static final Pattern PIN = Pattern.compile(
            "(?iu)(?:пин-код|пин|pin)\\s*[:\\s-]*\\s*(\\d{4,6})");

    public PinDetector() {
        super(EntityType.PIN, PIN);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        return single(EntityType.PIN, m, 0.95, 110, "pin-label");
    }
}