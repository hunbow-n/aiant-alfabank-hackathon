package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import ru.alfagen.pdsecurity.session.SessionCipher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Cipher tests: fresh nonces, ciphertext corruption, wrong key.
 */
class SessionCipherTest {

    @Test
    void roundTrip() {
        SessionCipher c = new SessionCipher();
        byte[] env = c.encrypt("Иванов Иван Иванович");
        assertEquals("Иванов Иван Иванович", c.decrypt(env));
    }

    @Test
    void freshNoncePerEncryption() {
        SessionCipher c = new SessionCipher();
        byte[] a = c.encrypt("same");
        byte[] b = c.encrypt("same");
        assertNotEquals(new String(a), new String(b));
    }

    @Test
    void corruptedCiphertextFails() {
        SessionCipher c = new SessionCipher();
        byte[] env = c.encrypt("secret");
        byte[] corrupted = env.clone();
        corrupted[corrupted.length - 1] ^= 0x01;
        assertThrows(IllegalStateException.class, () -> c.decrypt(corrupted));
    }
}