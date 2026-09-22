package ru.alfagen.pdsecurity.service;

/**
 * Thrown when there is no capacity to accept new work. Maps to 429.
 */
public class CapacityException extends RuntimeException {
    public CapacityException() {
        super("capacity");
    }
}