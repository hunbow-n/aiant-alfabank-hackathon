package ru.alfagen.pdsecurity.session;

import java.util.Optional;

/**
 * Storage contract for session state. Implementations must be thread-safe,
 * non-evicting under memory pressure, and support atomic first-writer-wins
 * publication. Keys are opaque (namespace + HMAC of the caller id).
 */
public interface SessionStore {

    /**
     * Look up an active session by key. Expired entries are treated as absent.
     */
    Optional<StoredSession> get(String key);

    /**
     * Look up a tombstone by key. Expired tombstones are treated as absent.
     */
    Optional<Tombstone> getTombstone(String key);

    /**
     * Atomically publish a new session if the key is free. Returns the stored
     * winner: the argument if it won, otherwise the existing entry.
     */
    StoredSession putIfAbsent(String key, StoredSession session);

    /**
     * Mark a session as completed (demasked). The record is retained so a lost
     * response can be retried, but it is no longer considered active.
     */
    void markCompleted(String key);

    /**
     * Reserve one capacity permit for a new session. Returns false when the
     * budget is exhausted (caller should answer 429).
     */
    boolean tryAcquire();

    /**
     * Release a capacity permit (on rejection or when a session is removed).
     */
    void release();

    /**
     * Number of live (active + tombstone) records currently held.
     */
    int size();

    /**
     * Remove expired entries. Called periodically by a sweep.
     */
    void sweep();
}