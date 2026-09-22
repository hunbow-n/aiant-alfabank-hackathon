package ru.alfagen.pdsecurity.observability;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Helpers for logging without leaking sensitive values. Only hashes of
 * caller-supplied ids are ever logged, never the raw values.
 */
public final class SafeLog {

    private SafeLog() {
    }

    public static String hash(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", d[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "hash-error";
        }
    }
}