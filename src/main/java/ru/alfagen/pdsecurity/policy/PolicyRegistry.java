package ru.alfagen.pdsecurity.policy;

import ru.alfagen.pdsecurity.detect.EntityType;

import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds and validates immutable policy snapshots from configuration. The
 * benchmark namespace is always present and reserved. Validation rejects
 * configurations where mask types or combo prerequisites are not detectable.
 */
public final class PolicyRegistry {

    private final Map<String, PolicySnapshot> snapshots = new LinkedHashMap<>();

    public PolicyRegistry(PolicyProperties props) {
        build(props);
    }

    private void build(PolicyProperties props) {
        snapshots.clear();
        PolicyProperties.Benchmark b = props.getBenchmark();
        snapshots.put("benchmark", new PolicySnapshot(
                props.getVersion(),
                b.getNamespace(),
                b.isEnabled(),
                parseTypes(b.getDetectTypes()),
                parseTypes(b.getMaskTypes()),
                b.isDemask(),
                b.getAmbiguityMode(),
                b.getStrategy(),
                Duration.parse("PT" + normalizeTtl(b.getActiveTtl())),
                Duration.parse("PT" + normalizeTtl(b.getTombstoneTtl())),
                List.of()));

        for (Map.Entry<String, PolicyProperties.SystemConfig> e : props.getSystems().entrySet()) {
            PolicyProperties.SystemConfig c = e.getValue();
            Set<EntityType> detect = parseTypes(c.getDetectTypes());
            Set<EntityType> mask = parseTypes(c.getMaskTypes());
            validate(detect, mask, c.getComboRules());
            snapshots.put(e.getKey(), new PolicySnapshot(
                    props.getVersion(),
                    e.getKey(),
                    c.isEnabled(),
                    detect,
                    mask,
                    c.isDemask(),
                    c.getAmbiguityMode(),
                    c.getStrategy(),
                    Duration.parse("PT" + normalizeTtl(b.getActiveTtl())),
                    Duration.parse("PT" + normalizeTtl(b.getTombstoneTtl())),
                    parseCombo(c.getComboRules())));
        }
    }

    public PolicySnapshot get(String systemId) {
        return snapshots.get(systemId);
    }

    public PolicySnapshot benchmark() {
        return snapshots.get("benchmark");
    }

    private void validate(Set<EntityType> detect, Set<EntityType> mask, List<PolicyProperties.ComboRuleConfig> combos) {
        for (EntityType t : mask) {
            if (!detect.contains(t)) {
                throw new IllegalArgumentException("mask type " + t + " not in detect types");
            }
        }
        for (PolicyProperties.ComboRuleConfig combo : combos) {
            for (String req : combo.getRequireTypes()) {
                if (!detect.contains(EntityType.valueOf(req))) {
                    throw new IllegalArgumentException("combo prerequisite " + req + " not detectable");
                }
            }
        }
    }

    private List<ComboRule> parseCombo(List<PolicyProperties.ComboRuleConfig> combos) {
        List<ComboRule> rules = new ArrayList<>();
        for (PolicyProperties.ComboRuleConfig c : combos) {
            rules.add(new ComboRule(
                    parseTypes(c.getTargetTypes()).stream().toList(),
                    parseTypes(c.getRequireTypes()).stream().toList(),
                    c.getScope()));
        }
        return rules;
    }

    private Set<EntityType> parseTypes(List<String> names) {
        if (names == null || names.isEmpty() || names.contains("ALL")) {
            return EnumSet.allOf(EntityType.class);
        }
        Set<EntityType> set = EnumSet.noneOf(EntityType.class);
        for (String n : names) {
            set.add(EntityType.valueOf(n));
        }
        return set;
    }

    private String normalizeTtl(String ttl) {
        if (ttl.endsWith("m")) {
            return ttl.substring(0, ttl.length() - 1) + "M";
        }
        return ttl;
    }
}