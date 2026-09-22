package ru.alfagen.pdsecurity.service;

/**
 * Thrown when a known session has expired (tombstone) and a late unmask is
 * attempted. The lost original is never substituted with the supplied mask.
 */
public class ExpiredException extends RuntimeException {
    public ExpiredException() {
        super("expired");
    }
}