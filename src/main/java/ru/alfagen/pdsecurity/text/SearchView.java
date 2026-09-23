package ru.alfagen.pdsecurity.text;


/**
 * A normalized, searchable view of the source text that can map a match back
 * to original ranges. Used by detectors that need case/ё-insensitive matching
 * while producing ranges valid in the original string.
 */
public final class SearchView {

    private final String source;
    private final String normalized;
    private final int[] originalIndex; // normalized index -> original index

    private SearchView(String source, String normalized, int[] originalIndex) {
        this.source = source;
        this.normalized = normalized;
        this.originalIndex = originalIndex;
    }

    public static SearchView of(String source) {
        StringBuilder sb = new StringBuilder(source.length());
        int[] map = new int[source.length()];
        int j = 0;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char n = TextTokenizer.normalize(String.valueOf(c)).charAt(0);
            sb.append(n);
            map[j++] = i;
        }
        int[] trimmed = new int[j];
        System.arraycopy(map, 0, trimmed, 0, j);
        return new SearchView(source, sb.toString(), trimmed);
    }

    public String normalized() {
        return normalized;
    }

    /**
     * Map a normalized index back to the original index.
     */
    public int originalIndex(int normalizedIndex) {
        return originalIndex[normalizedIndex];
    }

    /**
     * Map a normalized range back to an original range.
     */
    public SourceRange originalRange(int start, int end) {
        return new SourceRange(originalIndex[start], originalIndex[end - 1] + 1);
    }

    public int indexOf(String needle, int from) {
        return normalized.indexOf(needle, from);
    }

    public String source() {
        return source;
    }
}