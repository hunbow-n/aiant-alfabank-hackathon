package ru.alfagen.pdsecurity.service;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.DetectionEngine;
import ru.alfagen.pdsecurity.mask.Masker;
import ru.alfagen.pdsecurity.mask.MaskStrategy;
import ru.alfagen.pdsecurity.mask.StarMask;
import ru.alfagen.pdsecurity.mask.TokenMask;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.observability.TokenCounter;
import ru.alfagen.pdsecurity.policy.ComboEvaluator;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;
import ru.alfagen.pdsecurity.policy.PolicySnapshot;
import ru.alfagen.pdsecurity.resolve.SpanResolver;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;
import ru.alfagen.pdsecurity.session.StoredSession;
import ru.alfagen.pdsecurity.text.SourceText;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Consumer-facing mask/unmask service. Direction is explicit by path; each
 * system has its own policy and storage namespace.
 */
public final class ConsumerService {

    private final SessionStore store;
    private final SessionCipher cipher;
    private final Fingerprint fingerprint;
    private final DetectionEngine engine;
    private final SpanResolver resolver;
    private final ComboEvaluator comboEvaluator;
    private final PolicyRegistry policies;
    private final ProcessingMetrics metrics;
    private final TokenCounter tokenCounter;
    private final ExecutorService tokenExecutor;

    public ConsumerService(SessionSupport session, DetectionPipeline pipeline,
                           ProcessingMetrics metrics, TokenCounter tokenCounter) {
        this.store = session.store();
        this.cipher = session.cipher();
        this.fingerprint = session.fingerprint();
        this.engine = pipeline.engine();
        this.resolver = pipeline.resolver();
        this.comboEvaluator = pipeline.comboEvaluator();
        this.policies = pipeline.policies();
        this.metrics = metrics;
        this.tokenCounter = tokenCounter;
        this.tokenExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "token-counter");
            t.setDaemon(true);
            return t;
        });
    }

    public String mask(String systemId, String payload, String payloadId) {
        PolicySnapshot policy = policies.get(systemId);
        if (policy == null || !policy.enabled()) {
            throw new ForbiddenException();
        }
        String key = key(policy.namespace(), payloadId);
        byte[] fp = fingerprint.of(payload);

        StoredSession existing = store.get(key).orElse(null);
        if (existing != null) {
            if (Fingerprint.constantTimeEquals(existing.fingerprint(), fp)) {
                return existing.masked();
            }
            throw new ConflictException();
        }

        if (!store.tryAcquire()) {
            throw new CapacityException();
        }
        List<Candidate> candidates = engine.detect(new SourceText(payload),
                new DetectionContext(policy.ambiguityMode(), policy.detectTypes()));
        candidates = comboEvaluator.apply(candidates, policy);
        List<Candidate> resolved = resolver.resolve(payload, candidates);
        MaskStrategy strategy = strategyFor(policy.strategy());
        String masked = new Masker(strategy).render(payload, resolved);

        StoredSession entry = new StoredSession(
                policy.version(),
                Instant.now(),
                policy.demask(),
                masked,
                fp,
                policy.demask() ? cipher.encrypt(payload) : new byte[0],
                strategy instanceof TokenMask tm ? serialize(tm.tokenTable()) : null,
                null);

        StoredSession winner = store.putIfAbsent(key, entry);
        if (winner != entry) {
            store.release();
            if (Fingerprint.constantTimeEquals(winner.fingerprint(), fp)) {
                return winner.masked();
            }
            throw new ConflictException();
        }
        metrics.event(systemId, "mask", "ok");
        countTokensAsync(payload);
        return masked;
    }

    private void countTokensAsync(String payload) {
        tokenExecutor.submit(() -> {
            try {
                metrics.recordTokens(tokenCounter.count(payload));
            } catch (RuntimeException e) {
                // Best-effort, off the critical path.
            }
        });
    }

    public String unmask(String systemId, String payload, String payloadId) {
        PolicySnapshot policy = policies.get(systemId);
        if (policy == null || !policy.enabled()) {
            throw new ForbiddenException();
        }
        if (!policy.demask()) {
            throw new ForbiddenException();
        }
        String key = key(policy.namespace(), payloadId);
        StoredSession existing = store.get(key).orElse(null);
        if (existing == null) {
            throw new ExpiredException();
        }
        if (!existing.restorable()) {
            throw new ForbiddenException();
        }
        if (!existing.masked().equals(payload)) {
            throw new ConflictException();
        }
        store.markCompleted(key);
        metrics.event(systemId, "unmask", "ok");
        return cipher.decrypt(existing.encryptedOriginal());
    }

    private MaskStrategy strategyFor(String name) {
        return switch (name) {
            case "token" -> new TokenMask();
            default -> new StarMask();
        };
    }

    private byte[] serialize(Map<String, String> table) {
        StringBuilder sb = new StringBuilder();
        table.forEach((k, v) -> sb.append(k).append('\u0001').append(v).append('\u0002'));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String key(String namespace, String payloadId) {
        return namespace + ":" + java.util.HexFormat.of().formatHex(fingerprint.of(payloadId));
    }
}