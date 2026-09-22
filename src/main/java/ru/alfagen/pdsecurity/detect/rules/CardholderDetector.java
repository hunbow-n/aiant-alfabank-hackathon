package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects cardholder names following "имя держателя"/"cardholder" in a banking
 * field. A company or shop name is not a cardholder.
 */
public final class CardholderDetector implements Detector {

    private static final Pattern LABEL = Pattern.compile(
            "(?iu)(имя\\s+держателя|cardholder|держатель\\s+карты)\\s*[:\\s-]*");

    private static final Pattern NAME = Pattern.compile(
            "([A-ZА-ЯЁ][A-ZА-ЯЁ\\s.-]{2,40})");

    @Override
    public EntityType type() {
        return EntityType.CARDHOLDER;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        Matcher m = LABEL.matcher(source.value());
        while (m.find()) {
            Matcher n = NAME.matcher(source.value());
            if (n.find(m.end()) && n.start() == m.end()) {
                out.add(new Candidate("ch-" + m.start(), EntityType.CARDHOLDER,
                        List.of(new SourceRange(n.start(), n.end())), 0.9, 105, "cardholder-label", null));
            }
        }
        return out;
    }
}