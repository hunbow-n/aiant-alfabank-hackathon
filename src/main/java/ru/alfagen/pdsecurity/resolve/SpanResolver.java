package ru.alfagen.pdsecurity.resolve;

import ru.alfagen.pdsecurity.detect.Candidate;

import java.util.List;

/**
 * Resolves overlapping candidates into a non-overlapping, deterministically
 * ordered selection. The greedy resolver sorts by priority, then confidence,
 * then length, then a stable tie-break, and keeps non-overlapping candidates.
 */
public interface SpanResolver {

    List<Candidate> resolve(String source, List<Candidate> candidates);
}