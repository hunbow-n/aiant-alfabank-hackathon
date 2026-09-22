package ru.alfagen.pdsecurity.session;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM envelope for session payloads. A fresh 96-bit nonce is generated
 * per encryption; the tag is 128 bits. The key is ephemeral, created at startup
 * and never persisted or logged. Format: {@code base64(iv || ciphertext)}.
 */
public final class SessionCipher {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey key;
    private final SecureRandom random;

    public SessionCipher() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            this.key = kg.generateKey();
        } catch (Exception e) {
            throw new IllegalStateException("cannot initialise AES key", e);
        }
        this.random = new SecureRandom();
    }

    public byte[] encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encode(out);
        } catch (Exception e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    public String decrypt(byte[] envelope) {
        try {
            byte[] raw = Base64.getDecoder().decode(envelope);
            if (raw.length < IV_BYTES + 16) {
                throw new IllegalArgumentException("envelope too short");
            }
            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(raw, 0, iv, 0, IV_BYTES);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] pt = cipher.doFinal(raw, IV_BYTES, raw.length - IV_BYTES);
            return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("decryption failed", e);
        }
    }
}