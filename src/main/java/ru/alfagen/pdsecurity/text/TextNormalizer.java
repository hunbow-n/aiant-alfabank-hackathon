package ru.alfagen.pdsecurity.text;

import java.util.ArrayList;
import java.util.List;

/**
 * NFKC normalization with a range map back to the original UTF-16 string.
 * Combining characters and expansions require mapping both the start and end
 * of each normalized code point to its original range.
 */
public final class TextNormalizer {

    /**
     * A normalized character mapped to its original range.
     */
    public record MappedChar(char normalized, SourceRange originalRange) {
    }

    /**
     * Normalize the source and produce a list of mapped characters. Surrogate
     * pairs are kept intact (each supplementary code point maps to its full
     * two-char range).
     */
    public List<MappedChar> normalizeMapped(String source) {
        List<MappedChar> out = new ArrayList<>();
        int i = 0;
        int n = source.length();
        while (i < n) {
            int cp = source.codePointAt(i);
            int cpLen = Character.charCount(cp);
            String orig = source.substring(i, i + cpLen);
            String norm = java.text.Normalizer.normalize(orig, java.text.Normalizer.Form.NFKC);
            SourceRange range = new SourceRange(i, i + cpLen);
            if (norm.isEmpty()) {
                // Decomposed away (e.g. some marks); skip but keep range.
            } else {
                for (int k = 0; k < norm.length(); k++) {
                    out.add(new MappedChar(norm.charAt(k), range));
                }
            }
            i += cpLen;
        }
        return out;
    }
}