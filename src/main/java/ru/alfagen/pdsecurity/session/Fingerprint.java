package ru.alfagen.pdsecurity.session;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * HMAC-SHA-256 fingerprints. Used instead of {@code String.equals} on large
 * texts and to derive opaque storage keys from caller-supplied ids. The key is
 * ephemeral per process.
 */
public final class Fingerprint {

    private static final String HMAC = "HmacSHA256";
    private final byte[] key;

    public Fingerprint() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        this.key = k;
    }

    public byte[] of(String value) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }

    public byte[] of(byte[] value) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(value);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return java.security.MessageDigest.isEqual(a, b);
    }
}