package ru.alfagen.pdsecurity.text;

/**
 * A token with its original UTF-16 range and a normalized search value.
 *
 * @param normalizedValue case-folded, ё→е normalized value used for matching
 * @param originalRange   range in the original source
 */
public record SearchToken(String normalizedValue, SourceRange originalRange) {
}