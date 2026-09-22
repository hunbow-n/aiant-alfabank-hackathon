package ru.alfagen.pdsecurity.service;

/**
 * Thrown when a payload_id is already active with a different payload.
 */
public class ConflictException extends RuntimeException {
    public ConflictException() {
        super("conflict");
    }
}