package ru.alfagen.pdsecurity.policy;

import ru.alfagen.pdsecurity.detect.EntityType;

import java.util.List;

/**
 * A combination rule: {@code targetTypes} are masked only when all
 * {@code requireTypes} are present within the same {@code scope}.
 *
 * @param targetTypes  types gated by this rule
 * @param requireTypes types that must be present
 * @param scope        field_group or sentence
 */
public record ComboRule(List<EntityType> targetTypes, List<EntityType> requireTypes, String scope) {
}