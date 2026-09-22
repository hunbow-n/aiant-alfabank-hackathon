package ru.alfagen.pdsecurity.session;

import java.time.Instant;

/**
 * A short-lived marker left after an active session expires. Holds only the
 * HMAC of the previous mask and a flag indicating whether the original was
 * identical to the mask (so a late unmask can be answered honestly).
 *
 * @param maskFingerprint HMAC of the previous mask
 * @param originalEqualsMask whether original == masked
 * @param createdAt        creation instant
 */
public record Tombstone(byte[] maskFingerprint, boolean originalEqualsMask, Instant createdAt) {
}