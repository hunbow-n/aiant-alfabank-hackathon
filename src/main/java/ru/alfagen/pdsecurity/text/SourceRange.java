package ru.alfagen.pdsecurity.text;

/**
 * A half-open range {@code [startInclusive, endExclusive)} of UTF-16 indices
 * into the original Java {@code String}. Ranges are always valid against the
 * source text and never split a surrogate pair.
 *
 * @param startInclusive first UTF-16 code unit (inclusive)
 * @param endExclusive   first UTF-16 code unit after the range (exclusive)
 */
public record SourceRange(int startInclusive, int endExclusive) {

    public SourceRange {
        if (startInclusive < 0 || endExclusive < startInclusive) {
            throw new IllegalArgumentException("invalid range [" + startInclusive + "," + endExclusive + ")");
        }
    }

    public int length() {
        return endExclusive - startInclusive;
    }

    public boolean isEmpty() {
        return startInclusive == endExclusive;
    }

    public boolean overlaps(SourceRange other) {
        return this.startInclusive < other.endExclusive && other.startInclusive < this.endExclusive;
    }

    public boolean contains(SourceRange other) {
        return this.startInclusive <= other.startInclusive && other.endExclusive <= this.endExclusive;
    }
}