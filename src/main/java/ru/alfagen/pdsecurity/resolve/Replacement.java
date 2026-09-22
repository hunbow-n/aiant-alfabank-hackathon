package ru.alfagen.pdsecurity.resolve;

import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;

/**
 * A single resolved replacement: the source range to replace and the text to
 * put in its place. Ranges in a plan are sorted and non-overlapping.
 *
 * @param originalRange source range in original coordinates
 * @param replacement   replacement text
 * @param entityId      owning entity id
 * @param type          entity type
 */
public record Replacement(SourceRange originalRange, String replacement, String entityId, EntityType type) {
}