package ru.alfagen.pdsecurity.resolve;

import java.util.List;

/**
 * An ordered, non-overlapping set of replacements to apply to a source text in
 * a single pass.
 *
 * @param replacements sorted by start index, non-overlapping
 */
public record ReplacementPlan(List<Replacement> replacements) {

    public ReplacementPlan {
        replacements = List.copyOf(replacements);
    }

    public boolean isEmpty() {
        return replacements.isEmpty();
    }
}