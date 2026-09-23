package ru.alfagen.pdsecurity.service;

import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;

/**
 * Collaborators that own session state: the store itself, the cipher protecting
 * stored originals and the fingerprint used for constant-time comparison.
 *
 * @param store       correlation store
 * @param cipher      AES-GCM envelope for stored originals
 * @param fingerprint HMAC of payloads, used instead of comparing whole strings
 */
public record SessionSupport(SessionStore store, SessionCipher cipher, Fingerprint fingerprint) {
}
