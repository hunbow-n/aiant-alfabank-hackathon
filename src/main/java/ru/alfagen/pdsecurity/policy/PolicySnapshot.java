package ru.alfagen.pdsecurity.policy;

import ru.alfagen.pdsecurity.detect.EntityType;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Immutable policy snapshot for one system. A single request works with one
 * snapshot for its whole lifetime.
 *
 * @param version        policy version
 * @param namespace      storage namespace
 * @param enabled        whether the system is enabled
 * @param detectTypes    types to detect
 * @param maskTypes      types to mask
 * @param demask         whether restoration is allowed
 * @param ambiguityMode  contextual or balanced
 * @param strategy       mask strategy name (star/token/synthetic)
 * @param activeTtl      active session TTL
 * @param tombstoneTtl   tombstone TTL
 * @param comboRules     combination rules
 */
public record PolicySnapshot(
        long version,
        String namespace,
        boolean enabled,
        Set<EntityType> detectTypes,
        Set<EntityType> maskTypes,
        boolean demask,
        String ambiguityMode,
        String strategy,
        Duration activeTtl,
        Duration tombstoneTtl,
        List<ComboRule> comboRules) {

    public boolean detects(EntityType type) {
        return detectTypes.contains(type);
    }

    public boolean masks(EntityType type) {
        return maskTypes.contains(type);
    }
}