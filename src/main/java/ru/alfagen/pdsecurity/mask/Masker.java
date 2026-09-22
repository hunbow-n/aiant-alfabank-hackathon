package ru.alfagen.pdsecurity.mask;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.resolve.Replacement;
import ru.alfagen.pdsecurity.resolve.ReplacementPlan;
import ru.alfagen.pdsecurity.text.SourceRange;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Applies a mask strategy to a resolved, non-overlapping candidate list in a
 * single pass over the source using a {@link StringBuilder}. Each candidate is
 * flattened into one replacement per range, so composite entities (passport
 * series + number, etc.) are fully masked. Complexity is O(n + k log k).
 */
public final class Masker {

    private final MaskStrategy strategy;

    public Masker(MaskStrategy strategy) {
        this.strategy = strategy;
    }

    public String render(String source, List<Candidate> candidates) {
        List<Replacement> replacements = flatten(source, candidates);
        return apply(source, new ReplacementPlan(replacements));
    }

    private List<Replacement> flatten(String source, List<Candidate> candidates) {
        List<Replacement> out = new ArrayList<>();
        for (Candidate c : candidates) {
            for (SourceRange range : c.ranges()) {
                out.add(new Replacement(range, strategy.render(range, source, c.type()), c.entityId(), c.type()));
            }
        }
        out.sort(Comparator.comparingInt(r -> r.originalRange().startInclusive()));
        return out;
    }

    private String apply(String source, ReplacementPlan plan) {
        StringBuilder sb = new StringBuilder(source.length());
        int cursor = 0;
        for (Replacement r : plan.replacements()) {
            SourceRange range = r.originalRange();
            if (range.startInclusive() < cursor) {
                continue; // defensive: skip overlapping leftovers
            }
            sb.append(source, cursor, range.startInclusive());
            sb.append(r.replacement());
            cursor = range.endExclusive();
        }
        sb.append(source, cursor, source.length());
        return sb.toString();
    }
}