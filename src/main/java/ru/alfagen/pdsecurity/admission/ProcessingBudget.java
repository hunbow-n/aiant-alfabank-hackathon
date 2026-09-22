package ru.alfagen.pdsecurity.admission;

import java.util.concurrent.Semaphore;

/**
 * Bounds the number of concurrent CPU-processing permits for new heavy masking
 * work. Reads and restores have a separate reserve. When exhausted, new work is
 * rejected with 429 rather than queued indefinitely.
 */
public final class ProcessingBudget {

    private final Semaphore permits;

    public ProcessingBudget(int permits) {
        this.permits = new Semaphore(permits);
    }

    public boolean tryAcquire() {
        return permits.tryAcquire();
    }

    public void release() {
        permits.release();
    }
}