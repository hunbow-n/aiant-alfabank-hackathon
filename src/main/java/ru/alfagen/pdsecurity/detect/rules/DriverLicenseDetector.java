package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects driver's licenses: digital forms and common old forms with letters,
 * preceded by "ВУ"/"права"/"водительское удостоверение". "права доступа" is
 * not a license.
 */
public final class DriverLicenseDetector extends AbstractRegexDetector {

    private static final Pattern LICENSE = Pattern.compile(
            "(?iu)(?:водительское\\s+удостоверение|удостоверение\\s+водителя|права|ву)\\s*[:\\s-]*\\s*"
                    + "([0-9]{10}|[0-9]{2}\\s?[А-ЯЁ]{2}\\s?[0-9]{6})");

    public DriverLicenseDetector() {
        super(EntityType.DRIVER_LICENSE, LICENSE);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        return single(EntityType.DRIVER_LICENSE, m, 0.9, 85, "license-format");
    }
}