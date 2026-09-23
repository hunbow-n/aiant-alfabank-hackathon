package ru.alfagen.pdsecurity.session;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * An immutable active session record. The original payload is stored encrypted;
 * the fingerprint is an HMAC of the original used for constant-time comparison.
 *
 * @param policyVersion policy snapshot version that produced this session
 * @param createdAt      creation instant (monotonic clock)
 * @param restorable     whether the original can be restored (demask enabled)
 * @param masked         the mask returned to the caller
 * @param fingerprint    HMAC-SHA-256 of the original payload
 * @param encryptedOriginal AES-256-GCM envelope of the original payload
 * @param tokenTable     serialized token table for token strategy, else null
 * @param inputTokens    token count of the original (cl100k_base), may be null
 */
public record StoredSession(
        long policyVersion,
        Instant createdAt,
        boolean restorable,
        String masked,
        byte[] fingerprint,
        byte[] encryptedOriginal,
        byte[] tokenTable,
        Long inputTokens) {

    public StoredSession {
        if (fingerprint == null || fingerprint.length == 0) {
            throw new IllegalArgumentException("fingerprint required");
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof StoredSession(long version, Instant created, boolean restore, String mask,
                byte[] fp, byte[] encrypted, byte[] table, Long tokens))) {
            return false;
        }
        return policyVersion == version && restorable == restore
                && Objects.equals(createdAt, created) && Objects.equals(masked, mask)
                && Arrays.equals(fingerprint, fp)
                && Arrays.equals(encryptedOriginal, encrypted)
                && Arrays.equals(tokenTable, table)
                && Objects.equals(inputTokens, tokens);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policyVersion, createdAt, restorable, masked, Arrays.hashCode(fingerprint),
                Arrays.hashCode(encryptedOriginal), Arrays.hashCode(tokenTable), inputTokens);
    }

    /**
     * Deliberately omits every payload-derived field: a session must never be
     * printable into logs.
     */
    @Override
    public String toString() {
        return "StoredSession[policyVersion=" + policyVersion + ", createdAt=" + createdAt
                + ", restorable=" + restorable + "]";
    }
}