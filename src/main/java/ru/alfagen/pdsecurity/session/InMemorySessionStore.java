package ru.alfagen.pdsecurity.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-memory, non-evicting session store. Capacity is bounded by a
 * {@link Semaphore}; when exhausted, new work is rejected (429) rather than
 * evicting an active pair. Active sessions expire after {@code activeTtl};
 * expired sessions become tombstones that live for {@code tombstoneTtl}.
 *
 * <p>Expiry is checked against a monotonic clock on every read; a background
 * sweep removes expired records in batches without a global lock.
 */
public final class InMemorySessionStore implements SessionStore {

    private final ConcurrentHashMap<String, StoredSession> active = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Tombstone> tombstones = new ConcurrentHashMap<>();
    private final Semaphore capacity;
    private final AtomicInteger live = new AtomicInteger();
    private final Duration activeTtl;
    private final Duration tombstoneTtl;
    private final Fingerprint fingerprint;
    private final Clock clock;

    public interface Clock {
        Instant now();
    }

    public InMemorySessionStore(int maxEntries, Duration activeTtl, Duration tombstoneTtl,
                                Fingerprint fingerprint, Clock clock) {
        this.capacity = new Semaphore(maxEntries);
        this.activeTtl = activeTtl;
        this.tombstoneTtl = tombstoneTtl;
        this.fingerprint = fingerprint;
        this.clock = clock;
    }

    @Override
    public Optional<StoredSession> get(String key) {
        StoredSession s = active.get(key);
        if (s == null) {
            return Optional.empty();
        }
        if (isExpired(s.createdAt(), activeTtl)) {
            if (active.remove(key, s)) {
                tombstones.put(key, new Tombstone(fingerprint.of(s.masked()), false, clock.now()));
            }
            return Optional.empty();
        }
        return Optional.of(s);
    }

    @Override
    public Optional<Tombstone> getTombstone(String key) {
        Tombstone t = tombstones.get(key);
        if (t == null) {
            return Optional.empty();
        }
        if (isExpired(t.createdAt(), tombstoneTtl)) {
            tombstones.remove(key, t);
            live.decrementAndGet();
            return Optional.empty();
        }
        return Optional.of(t);
    }

    @Override
    public StoredSession putIfAbsent(String key, StoredSession session) {
        StoredSession winner = active.putIfAbsent(key, session);
        if (winner == null) {
            live.incrementAndGet();
            return session;
        }
        return winner;
    }

    @Override
    public void markCompleted(String key) {
        // Retained for retry; no state change needed beyond the record itself.
    }

    @Override
    public boolean tryAcquire() {
        return capacity.tryAcquire();
    }

    @Override
    public void release() {
        capacity.release();
    }

    @Override
    public int size() {
        return live.get();
    }

    @Override
    public void sweep() {
        Instant now = clock.now();
        active.forEach((key, s) -> {
            if (isExpired(s.createdAt(), activeTtl) && active.remove(key, s)) {
                tombstones.put(key, new Tombstone(fingerprint.of(s.masked()), false, now));
            }
        });
        tombstones.forEach((key, t) -> {
            if (isExpired(t.createdAt(), tombstoneTtl) && tombstones.remove(key, t)) {
                live.decrementAndGet();
            }
        });
    }

    private boolean isExpired(Instant createdAt, Duration ttl) {
        return createdAt.plus(ttl).isBefore(clock.now());
    }
}