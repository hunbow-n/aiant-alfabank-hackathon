package ru.alfagen.pdsecurity.mask;

import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;

/**
 * Renders replacement text for a single source range. Implementations must
 * preserve the UTF-16 length of the range (a supplementary code point becomes
 * two stars) and never split a surrogate pair.
 */
public interface MaskStrategy {

    /**
     * Produce the replacement text for one range. The returned string is
     * substituted for the range in the source.
     */
    String render(SourceRange range, String source, EntityType type);
}