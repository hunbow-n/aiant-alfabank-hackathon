package ru.alfagen.pdsecurity.session;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

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

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Tombstone(byte[] fp, boolean equalsMask, Instant created))) {
            return false;
        }
        return originalEqualsMask == equalsMask
                && Arrays.equals(maskFingerprint, fp)
                && Objects.equals(createdAt, created);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(maskFingerprint), originalEqualsMask, createdAt);
    }

    @Override
    public String toString() {
        return "Tombstone[originalEqualsMask=" + originalEqualsMask + ", createdAt=" + createdAt + "]";
    }
}