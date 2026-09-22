package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import ru.alfagen.pdsecurity.detect.DefaultDetectionEngine;
import ru.alfagen.pdsecurity.detect.DetectionEngine;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.rules.EmailDetector;
import ru.alfagen.pdsecurity.detect.rules.PersonDetector;
import ru.alfagen.pdsecurity.detect.rules.PhoneDetector;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.observability.TokenCounter;
import ru.alfagen.pdsecurity.policy.ComboEvaluator;
import ru.alfagen.pdsecurity.policy.PolicyProperties;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;
import ru.alfagen.pdsecurity.resolve.GreedySpanResolver;
import ru.alfagen.pdsecurity.service.ProcessService;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.InMemorySessionStore;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Concurrent first request: many clients race on the same payload_id; the
 * winning mask must be stable and identical for all.
 */
class ConcurrentSessionTest {

    @Test
    void concurrentFirstRequestStableMask() throws Exception {
        Fingerprint fp = new Fingerprint();
        SessionStore store = new InMemorySessionStore(1000, Duration.ofMinutes(15), Duration.ofMinutes(5), fp, java.time.Instant::now);
        SessionCipher cipher = new SessionCipher();
        List<Detector> detectors = List.of(new PersonDetector(), new EmailDetector(), new PhoneDetector());
        ProcessingMetrics metrics = new ProcessingMetrics(new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        DetectionEngine engine = new DefaultDetectionEngine(detectors, metrics);
        PolicyRegistry policies = new PolicyRegistry(new PolicyProperties());
        ProcessService service = new ProcessService(store, cipher, fp, engine, new GreedySpanResolver(),
                new ComboEvaluator(), policies, metrics, new TokenCounter());

        String original = "Клиент Иванов Иван, email ivan@example.com";
        int threads = 200;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicReference<String> winner = new AtomicReference<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    ProcessService.ProcessResult r = service.process(original, "race-id");
                    winner.compareAndSet(null, r.result());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        pool.awaitTermination(30, TimeUnit.SECONDS);

        assertNotNull(winner.get());
        // The winner's mask must round-trip back to the original.
        ProcessService.ProcessResult demask = service.process(winner.get(), "race-id");
        assertEquals(original, demask.result());
    }
}