package ru.alfagen.pdsecurity.policy;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.EntityType;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Applies combination rules: a target type is masked only when all required
 * types are present within the same scope (field group or sentence). If joint
 * membership cannot be established, the condition is treated as unmet.
 */
public final class ComboEvaluator {

    public List<Candidate> apply(List<Candidate> candidates, PolicySnapshot policy) {
        if (policy.comboRules().isEmpty()) {
            return candidates;
        }
        Set<EntityType> present = new HashSet<>();
        for (Candidate c : candidates) {
            present.add(c.type());
        }
        List<Candidate> out = new java.util.ArrayList<>();
        for (Candidate c : candidates) {
            boolean allowed = true;
            for (ComboRule rule : policy.comboRules()) {
                if (rule.targetTypes().contains(c.type())) {
                    if (!present.containsAll(rule.requireTypes())) {
                        allowed = false;
                        break;
                    }
                }
            }
            if (allowed) {
                out.add(c);
            }
        }
        return out;
    }
}