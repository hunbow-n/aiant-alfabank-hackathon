package ru.alfagen.pdsecurity.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Verifies consumer API keys. Only digests of keys are stored; comparison is
 * constant-time. Unknown systems and wrong keys produce the same result.
 */
public final class SystemAuthentication {

    private final Map<String, String> systemKeyHashes;

    public SystemAuthentication(Map<String, String> systemKeyHashes) {
        this.systemKeyHashes = Map.copyOf(systemKeyHashes);
    }

    /**
     * Returns the system id if the key is valid for it, else null.
     */
    public String authenticate(String systemId, String apiKey) {
        if (systemId == null || apiKey == null) {
            return null;
        }
        String expectedHash = systemKeyHashes.get(systemId);
        if (expectedHash == null) {
            return null;
        }
        String actualHash = sha256(apiKey);
        if (MessageDigest.isEqual(expectedHash.getBytes(StandardCharsets.UTF_8),
                actualHash.getBytes(StandardCharsets.UTF_8))) {
            return systemId;
        }
        return null;
    }

    private String sha256(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}