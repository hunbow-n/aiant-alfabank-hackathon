package ru.alfagen.pdsecurity.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.DetectionEngine;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.mask.Masker;
import ru.alfagen.pdsecurity.mask.MaskStrategy;
import ru.alfagen.pdsecurity.mask.StarMask;
import ru.alfagen.pdsecurity.mask.TokenMask;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.observability.SafeLog;
import ru.alfagen.pdsecurity.observability.TokenCounter;
import ru.alfagen.pdsecurity.policy.ComboEvaluator;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;
import ru.alfagen.pdsecurity.policy.PolicySnapshot;
import ru.alfagen.pdsecurity.resolve.GreedySpanResolver;
import ru.alfagen.pdsecurity.resolve.SpanResolver;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;
import ru.alfagen.pdsecurity.session.StoredSession;
import ru.alfagen.pdsecurity.session.Tombstone;
import ru.alfagen.pdsecurity.text.SourceText;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Implements the /process state machine: MASK, MASK_RETRY, DEMASK, CONFLICT,
 * EXPIRED. Expensive detection runs before any critical section; state writes
 * are atomic via {@link SessionStore#putIfAbsent}. The benchmark namespace is
 * always used for /process.
 */
public final class ProcessService {

    private static final Logger log = LoggerFactory.getLogger(ProcessService.class);

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

    public ProcessService(SessionStore store, SessionCipher cipher, Fingerprint fingerprint,
                          DetectionEngine engine, SpanResolver resolver, ComboEvaluator comboEvaluator,
                          PolicyRegistry policies, ProcessingMetrics metrics, TokenCounter tokenCounter) {
        this.store = store;
        this.cipher = cipher;
        this.fingerprint = fingerprint;
        this.engine = engine;
        this.resolver = resolver;
        this.comboEvaluator = comboEvaluator;
        this.policies = policies;
        this.metrics = metrics;
        this.tokenCounter = tokenCounter;
        this.tokenExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "token-counter");
            t.setDaemon(true);
            return t;
        });
    }

    public ProcessResult process(String payload, String payloadId) {
        long start = System.nanoTime();
        PolicySnapshot policy = policies.benchmark();
        String key = key(policy.namespace(), payloadId);
        byte[] fp = fingerprint.of(payload);

        StoredSession existing = store.get(key).orElse(null);
        if (existing != null) {
            ProcessResult r = classify(existing, payload, fp, key, policy);
            metrics.recordLatency(System.nanoTime() - start);
            return r;
        }

        Tombstone tomb = store.getTombstone(key).orElse(null);
        if (tomb != null && Fingerprint.constantTimeEquals(tomb.maskFingerprint(), fingerprint.of(payload))) {
            metrics.event("benchmark", "process", "expired");
            metrics.recordLatency(System.nanoTime() - start);
            throw new ExpiredException();
        }

        if (!store.tryAcquire()) {
            metrics.event("benchmark", "process", "rejected");
            metrics.recordLatency(System.nanoTime() - start);
            throw new CapacityException();
        }
        try {
            List<Candidate> candidates = engine.detect(new SourceText(payload),
                    new DetectionContext(policy.ambiguityMode(), policy.detectTypes()));
            candidates = comboEvaluator.apply(candidates, policy);
            List<Candidate> resolved = resolver.resolve(payload, candidates);
            MaskStrategy strategy = strategyFor(policy.strategy());
            String masked = new Masker(strategy).render(payload, resolved);

            log.info("op=MASK payloadIdHash={} len={} types={} latencyMs={}",
                    SafeLog.hash(payloadId), payload.length(), typeCounts(candidates),
                    (System.nanoTime() - start) / 1_000_000);

            StoredSession entry = new StoredSession(
                    policy.version(),
                    Instant.now(),
                    policy.demask(),
                    masked,
                    fp,
                    cipher.encrypt(payload),
                    strategy instanceof TokenMask tm ? serialize(tm.tokenTable()) : null,
                    null);

            StoredSession winner = store.putIfAbsent(key, entry);
            if (winner != entry) {
                store.release();
                ProcessResult r = classify(winner, payload, fp, key, policy);
                metrics.recordLatency(System.nanoTime() - start);
                return r;
            }
            metrics.event("benchmark", "process", "masked");
            metrics.recordLatency(System.nanoTime() - start);
            countTokensAsync(payload);
            return new ProcessResult(masked, Operation.MASK);
        } finally {
            // The capacity permit is held for the lifetime of the session and
            // released by the sweep when the session expires. On the rejection
            // path above we never acquired, so nothing to release here.
        }
    }

    private ProcessResult classify(StoredSession entry, String payload, byte[] fp, String key, PolicySnapshot policy) {
        if (Fingerprint.constantTimeEquals(entry.fingerprint(), fp)) {
            metrics.event("benchmark", "process", "mask_retry");
            return new ProcessResult(entry.masked(), Operation.MASK_RETRY);
        }
        if (entry.masked().equals(payload)) {
            if (!entry.restorable()) {
                metrics.event("benchmark", "process", "forbidden");
                throw new ForbiddenException();
            }
            store.markCompleted(key);
            metrics.event("benchmark", "process", "restored");
            return new ProcessResult(cipher.decrypt(entry.encryptedOriginal()), Operation.DEMASK);
        }
        metrics.event("benchmark", "process", "conflict");
        throw new ConflictException();
    }

    private MaskStrategy strategyFor(String name) {
        return switch (name) {
            case "token" -> new TokenMask();
            default -> new StarMask();
        };
    }

    private Map<String, Integer> typeCounts(List<Candidate> candidates) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Candidate c : candidates) {
            counts.merge(c.type().name(), 1, Integer::sum);
        }
        return counts;
    }

    private void countTokensAsync(String payload) {
        tokenExecutor.submit(() -> {
            try {
                metrics.recordTokens(tokenCounter.count(payload));
            } catch (RuntimeException e) {
                // Token counting is best-effort and off the critical path.
            }
        });
    }

    private byte[] serialize(Map<String, String> table) {
        StringBuilder sb = new StringBuilder();
        table.forEach((k, v) -> sb.append(k).append('\u0001').append(v).append('\u0002'));
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String key(String namespace, String payloadId) {
        return namespace + ":" + java.util.HexFormat.of().formatHex(fingerprint.of(payloadId));
    }

    public enum Operation {
        MASK, MASK_RETRY, DEMASK
    }

    public record ProcessResult(String result, Operation operation) {
    }
}