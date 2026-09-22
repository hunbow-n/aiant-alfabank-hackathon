package ru.alfagen.pdsecurity.mask;

import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;

/**
 * Star masking: hides meaningful characters of a value while preserving
 * structural internal separators (spaces, dots, hyphens inside groups). Email
 * is hidden entirely so no domain is left. Each meaningful code point becomes
 * one star; a supplementary code point becomes two stars to preserve UTF-16
 * length. Text outside the range is untouched.
 */
public final class StarMask implements MaskStrategy {

    @Override
    public String render(SourceRange range, String source, EntityType type) {
        boolean hideAll = type == EntityType.EMAIL;
        StringBuilder sb = new StringBuilder(range.length());
        int i = range.startInclusive();
        int end = range.endExclusive();
        while (i < end) {
            char c = source.charAt(i);
            if (!hideAll && isStructural(c)) {
                sb.append(c);
                i++;
            } else if (Character.isHighSurrogate(c) && i + 1 < end && Character.isLowSurrogate(source.charAt(i + 1))) {
                sb.append("**");
                i += 2;
            } else {
                sb.append('*');
                i++;
            }
        }
        return sb.toString();
    }

    private boolean isStructural(char c) {
        return c == ' ' || c == '.' || c == '-' || c == '/' || c == '(' || c == ')' || c == '+';
    }
}