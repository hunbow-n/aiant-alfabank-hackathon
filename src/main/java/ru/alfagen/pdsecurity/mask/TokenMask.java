package ru.alfagen.pdsecurity.mask;

import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Token masking: replaces each range with {@code {{TYPE_n}}}, numbered per
 * type in order of appearance. Identical exact values of one type in a session
 * share one token. The token table maps token -> original value for restoration.
 */
public final class TokenMask implements MaskStrategy {

    private final Map<String, String> tokenTable = new LinkedHashMap<>();
    private final Map<String, Integer> counters = new LinkedHashMap<>();

    @Override
    public String render(SourceRange range, String source, EntityType type) {
        String value = source.substring(range.startInclusive(), range.endExclusive());
        return tokenFor(type.name(), value);
    }

    private String tokenFor(String type, String value) {
        String key = type + "\u0000" + value;
        String existing = tokenTable.get(key);
        if (existing != null) {
            return existing;
        }
        int n = counters.merge(type, 1, Integer::sum);
        String token = "{{" + type + "_" + n + "}}";
        tokenTable.put(key, token);
        return token;
    }

    public Map<String, String> tokenTable() {
        return Map.copyOf(tokenTable);
    }
}