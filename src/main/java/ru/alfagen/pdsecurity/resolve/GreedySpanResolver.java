package ru.alfagen.pdsecurity.resolve;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.text.SourceRange;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Deterministic greedy resolver. Candidates are sorted by priority (desc),
 * confidence (desc), total length (desc), then a stable tie-break on start,
 * end and type. Non-overlapping candidates are kept; overlapping ones are
 * dropped. The result is ordered by start index for single-pass rendering.
 *
 * <p>Overlap checks use a {@link TreeMap} of selected ranges for O(log n)
 * lookups instead of scanning all selected candidates, keeping the resolver
 * near O(n log n) even on texts with tens of thousands of candidates.
 */
public final class GreedySpanResolver implements SpanResolver {

    @Override
    public List<Candidate> resolve(String source, List<Candidate> candidates) {
        List<Candidate> sorted = new ArrayList<>(candidates);
        sorted.sort(Comparator
                .comparingInt(Candidate::priority).reversed()
                .thenComparingDouble(Candidate::confidence).reversed()
                .thenComparingInt(this::totalLength).reversed()
                .thenComparingInt(c -> c.firstRange().startInclusive())
                .thenComparingInt(c -> c.firstRange().endExclusive())
                .thenComparing(c -> c.type().name()));

        TreeMap<Integer, Integer> occupied = new TreeMap<>();
        List<Candidate> selected = new ArrayList<>();
        for (Candidate c : sorted) {
            if (!overlapsAny(occupied, c)) {
                selected.add(c);
                for (SourceRange r : c.ranges()) {
                    occupied.put(r.startInclusive(), r.endExclusive());
                }
            }
        }
        selected.sort(Comparator.comparingInt(c -> c.firstRange().startInclusive()));
        return selected;
    }

    private boolean overlapsAny(TreeMap<Integer, Integer> occupied, Candidate c) {
        for (SourceRange b : c.ranges()) {
            // The selected range with the largest start <= b.end could overlap.
            Map.Entry<Integer, Integer> floor = occupied.floorEntry(b.endExclusive() - 1);
            if (floor != null && floor.getValue() > b.startInclusive()) {
                return true;
            }
            // The selected range with the smallest start >= b.start could overlap.
            Map.Entry<Integer, Integer> ceil = occupied.ceilingEntry(b.startInclusive());
            if (ceil != null && ceil.getKey() < b.endExclusive()) {
                return true;
            }
        }
        return false;
    }

    private int totalLength(Candidate c) {
        int sum = 0;
        for (SourceRange r : c.ranges()) {
            sum += r.length();
        }
        return sum;
    }
}