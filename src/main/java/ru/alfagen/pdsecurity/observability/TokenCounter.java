package ru.alfagen.pdsecurity.observability;

import com.knuddels.jtokkit.Encodings;
import com.knuddels.jtokkit.api.Encoding;
import com.knuddels.jtokkit.api.EncodingRegistry;
import com.knuddels.jtokkit.api.EncodingType;

/**
 * BPE token counter using the cl100k_base encoding. Counting is performed off
 * the critical path; the result is stored in the session and reused on retries.
 */
public final class TokenCounter {

    private final Encoding encoding;

    public TokenCounter() {
        EncodingRegistry registry = Encodings.newDefaultEncodingRegistry();
        this.encoding = registry.getEncoding(EncodingType.CL100K_BASE);
    }

    public long count(String text) {
        return encoding.countTokens(text);
    }
}