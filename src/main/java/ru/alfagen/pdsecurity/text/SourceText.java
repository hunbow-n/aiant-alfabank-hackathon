package ru.alfagen.pdsecurity.text;

/**
 * Immutable wrapper around the original source string. The source is never
 * modified in place; all detection and masking operate on ranges into it.
 */
public final class SourceText {

    private final String value;

    public SourceText(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

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