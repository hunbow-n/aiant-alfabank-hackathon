package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects driver's licenses: digital forms and common old forms with letters,
 * preceded by "ВУ"/"права"/"водительское удостоверение". "права доступа" is
 * not a license. The label is mandatory, so a match outranks the bare
 * passport digit shape, which looks identical.
 */
public final class DriverLicenseDetector extends AbstractRegexDetector {

    private static final String LABELS = "(?iu)(?:водительское\\s+удостоверение|удостоверение\\s+водителя|права|ву)";
    private static final String NUMBER = "\\d{2}\\s?\\d{2}\\s?\\d{6}|\\d{2}\\s?[А-ЯЁ]{2}\\s?\\d{6}";

    private static final Pattern LICENSE = Pattern.compile(
            LABELS + "[:\\s-]*(" + NUMBER + ")");

    public DriverLicenseDetector() {
        super(EntityType.DRIVER_LICENSE, LICENSE);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        return single(EntityType.DRIVER_LICENSE, m, 0.95, 95, "license-format");
    }
}