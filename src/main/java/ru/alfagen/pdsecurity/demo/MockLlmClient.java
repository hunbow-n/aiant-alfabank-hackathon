package ru.alfagen.pdsecurity.demo;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline stand-in for a language model. It does not understand the text; it
 * imitates the one behaviour that matters for the demo — a model rearranges
 * words but copies placeholders verbatim, so restoration can be shown without
 * depending on an external service.
 */
public final class MockLlmClient implements LlmClient {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{[A-Z_]+_\\d+}}");

    @Override
    public String complete(String prompt, String instructions) {
        Set<String> placeholders = new LinkedHashSet<>();
        Matcher m = PLACEHOLDER.matcher(prompt);
        while (m.find()) {
            placeholders.add(m.group());
        }
        String quoted = prompt.length() > 220 ? prompt.substring(0, 220) + "…" : prompt;
        StringBuilder sb = new StringBuilder();
        if (placeholders.isEmpty()) {
            sb.append("Здравствуйте! Обращение принято в работу: «").append(quoted).append("»");
        } else {
            sb.append("Здравствуйте, ").append(placeholders.iterator().next()).append('!');
            sb.append(" Обращение принято в работу: «").append(quoted).append("»");
        }
        sb.append(" Мы свяжемся с вами по указанным контактам. Спасибо, что остаётесь с нами.");
        return sb.toString();
    }
}
