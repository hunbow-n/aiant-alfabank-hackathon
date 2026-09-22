package ru.alfagen.pdsecurity.text;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Splits the source into search tokens with original ranges. Tokens are
 * maximal runs of letters/digits; punctuation and whitespace become separators
 * but their ranges are preserved so detectors can reconstruct spans.
 */
public final class TextTokenizer {

    public List<SearchToken> tokenize(String source) {
        List<SearchToken> tokens = new ArrayList<>();
        int i = 0;
        int n = source.length();
        while (i < n) {
            int start = i;
            while (i < n && isTokenChar(source.charAt(i))) {
                i++;
            }
            if (i > start) {
                tokens.add(new SearchToken(normalize(source.substring(start, i)),
                        new SourceRange(start, i)));
            } else {
                i++;
            }
        }
        return tokens;
    }

    private boolean isTokenChar(char c) {
        return Character.isLetterOrDigit(c);
    }

    /**
     * Case-fold to ROOT locale and map ё→е for search matching. The original
     * text is never replaced by this value.
     */
    public static String normalize(String value) {
        return value.toLowerCase(Locale.ROOT).replace('ё', 'е');
    }
}