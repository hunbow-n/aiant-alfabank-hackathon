package ru.alfagen.pdsecurity.service;

/**
 * Thrown when restoration is attempted but demask is disabled for the session.
 * Maps to 403.
 */
public class ForbiddenException extends RuntimeException {
    public ForbiddenException() {
        super("forbidden");
    }
}