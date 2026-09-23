package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects passport department codes: 3-3 digits following a field label such
 * as "код подразделения". A bare 3-3 number without a label is not masked.
 */
public final class DepartmentCodeDetector extends AbstractRegexDetector {

    private static final Pattern CODE = Pattern.compile(
            "(?iu)(?:код\\s+подразделения|код\\s+подразд\\.)[:\\s-]*(\\d{3}-\\d{3}|\\d{3}\\s\\d{3})");

    public DepartmentCodeDetector() {
        super(EntityType.DEPARTMENT_CODE, CODE);
    }

    @Override
    protected Candidate build(SourceText source, Matcher m) {
        return single(EntityType.DEPARTMENT_CODE, m, 0.95, 110, "dept-code-label");
    }
}