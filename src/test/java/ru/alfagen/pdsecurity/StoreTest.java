package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.InMemorySessionStore;
import ru.alfagen.pdsecurity.session.StoredSession;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Store tests: atomic first-writer-wins, capacity budget, TTL and sweep,
 * absence of eviction.
 */
class StoreTest {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));

    private InMemorySessionStore store(int max) {
        return new InMemorySessionStore(max, Duration.ofMinutes(15), Duration.ofMinutes(5),
                new Fingerprint(), now::get);
    }

    private StoredSession session(String masked) {
        return new StoredSession(1, now.get(), true, masked, new byte[]{1}, new byte[]{2}, null, null);
    }

    @Test
    void putIfAbsentFirstWriterWins() {
        InMemorySessionStore s = store(10);
        StoredSession a = session("mask-a");
        StoredSession b = session("mask-b");
        assertEquals(a, s.putIfAbsent("k", a));
        assertEquals(a, s.putIfAbsent("k", b));
        assertTrue(s.get("k").isPresent());
        assertEquals("mask-a", s.get("k").get().masked());
    }

    @Test
    void capacityExhaustedRejects() {
        InMemorySessionStore s = store(1);
        assertTrue(s.tryAcquire());
        assertFalse(s.tryAcquire());
    }

    @Test
    void ttlExpiryMovesToTombstone() {
        InMemorySessionStore s = store(10);
        s.putIfAbsent("k", session("mask"));
        now.set(now.get().plus(Duration.ofMinutes(16)));
        assertTrue(s.get("k").isEmpty());
        assertTrue(s.getTombstone("k").isPresent());
    }

    @Test
    void tombstoneExpires() {
        InMemorySessionStore s = store(10);
        s.putIfAbsent("k", session("mask"));
        now.set(now.get().plus(Duration.ofMinutes(16)));
        s.sweep();
        assertTrue(s.getTombstone("k").isPresent());
        now.set(now.get().plus(Duration.ofMinutes(6)));
        s.sweep();
        assertTrue(s.getTombstone("k").isEmpty());
    }
}