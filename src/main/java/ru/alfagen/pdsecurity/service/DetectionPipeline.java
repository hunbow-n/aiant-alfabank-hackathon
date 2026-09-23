package ru.alfagen.pdsecurity.service;

import ru.alfagen.pdsecurity.detect.DetectionEngine;
import ru.alfagen.pdsecurity.policy.ComboEvaluator;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;
import ru.alfagen.pdsecurity.resolve.SpanResolver;

/**
 * Collaborators that turn a source text into a resolved set of candidates:
 * detection, conflict resolution and the policy that governs both.
 *
 * @param engine         runs the detectors
 * @param resolver       resolves overlapping candidates
 * @param comboEvaluator applies conditional combination rules
 * @param policies       immutable policy snapshots per system
 */
public record DetectionPipeline(DetectionEngine engine, SpanResolver resolver,
                                ComboEvaluator comboEvaluator, PolicyRegistry policies) {
}
