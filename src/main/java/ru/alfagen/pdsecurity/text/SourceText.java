package ru.alfagen.pdsecurity.text;

/**
 * Immutable wrapper around the original source string. The source is never
 * modified in place; all detection and masking operate on ranges into it.
 */
public record SourceText(String value) {

    public int length() {
        return value.length();
    }

    public String substring(SourceRange range) {
        return value.substring(range.startInclusive(), range.endExclusive());
    }

    public char charAt(int index) {
        return value.charAt(index);
    }
}