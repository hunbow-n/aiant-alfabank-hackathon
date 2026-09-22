package ru.alfagen.pdsecurity.detect;

import ru.alfagen.pdsecurity.text.SourceRange;

import java.util.List;

/**
 * A detected personal-data mention. A candidate may cover several disjoint
 * ranges (e.g. passport series and number groups) that belong to one entity.
 *
 * @param entityId        stable id linking the parts of one composite document
 * @param type            detected entity type
 * @param ranges          non-empty, non-overlapping ranges in source coordinates
 * @param confidence      [0..1] detector confidence
 * @param priority        resolution priority (explicit field label &gt; format heuristic)
 * @param evidence        short human-readable reason (never logged raw)
 * @param contextGroupId  id of the field/group the mention belongs to, if any
 */
public record Candidate(
        String entityId,
        EntityType type,
        List<SourceRange> ranges,
        double confidence,
        int priority,
        String evidence,
        String contextGroupId) {

    public Candidate {
        ranges = List.copyOf(ranges);
        if (ranges.isEmpty()) {
            throw new IllegalArgumentException("candidate must have at least one range");
        }
    }

    public SourceRange firstRange() {
        return ranges.get(0);
    }
}