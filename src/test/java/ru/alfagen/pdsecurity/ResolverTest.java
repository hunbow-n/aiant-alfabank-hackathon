package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.resolve.GreedySpanResolver;
import ru.alfagen.pdsecurity.text.SourceRange;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Resolver tests: overlapping candidates are resolved deterministically and
 * non-overlapping ones are preserved.
 */
class ResolverTest {

    private final GreedySpanResolver resolver = new GreedySpanResolver();

    @Test
    void overlappingKeepsHigherPriority() {
        Candidate low = new Candidate("a", EntityType.PHONE, List.of(new SourceRange(0, 12)), 0.9, 40, "low", null);
        Candidate high = new Candidate("b", EntityType.PASSPORT, List.of(new SourceRange(0, 12)), 0.9, 85, "high", null);
        List<Candidate> resolved = resolver.resolve("012345678901", List.of(low, high));
        assertEquals(1, resolved.size());
        assertEquals(EntityType.PASSPORT, resolved.get(0).type());
    }

    @Test
    void nonOverlappingBothKept() {
        Candidate a = new Candidate("a", EntityType.EMAIL, List.of(new SourceRange(0, 10)), 0.9, 100, "a", null);
        Candidate b = new Candidate("b", EntityType.PHONE, List.of(new SourceRange(20, 30)), 0.9, 90, "b", null);
        List<Candidate> resolved = resolver.resolve("0123456789 0123456789", List.of(a, b));
        assertEquals(2, resolved.size());
    }

    @Test
    void compositePassportRanges() {
        Candidate passport = new Candidate("p", EntityType.PASSPORT,
                List.of(new SourceRange(0, 4), new SourceRange(5, 11)), 0.9, 85, "passport", null);
        Candidate overlapping = new Candidate("o", EntityType.PHONE,
                List.of(new SourceRange(3, 11)), 0.9, 40, "phone", null);
        List<Candidate> resolved = resolver.resolve("4509 123456", List.of(passport, overlapping));
        assertEquals(1, resolved.size());
        assertEquals(EntityType.PASSPORT, resolved.get(0).type());
    }
}