package ru.alfagen.pdsecurity.api;

/**
 * Safe error body. Never echoes the payload or any sensitive value.
 *
 * @param code    stable machine-readable error code
 * @param message short human-readable message without user data
 */
public record ApiError(String code, String message) {
}