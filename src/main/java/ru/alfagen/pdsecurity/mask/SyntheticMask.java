package ru.alfagen.pdsecurity.mask;

import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SourceRange;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Replaces a value with plausible synthetic data of the same type, so the text
 * stays natural for a language model. The mapping is kept per session and is
 * reversible in the same way as {@link TokenMask}.
 *
 * <p>Synthetic values never collide with real ones by construction: names come
 * from a fixed fictional set, card numbers fail the Luhn check on purpose and
 * phone numbers use the reserved 555 range.
 */
public final class SyntheticMask implements MaskStrategy {

    private static final List<String> PERSONS = List.of(
            "Сергей Петров", "Мария Козлова", "Андрей Волков", "Елена Смирнова");
    private static final List<String> ADDRESSES = List.of(
            "г. Вымышленск, ул. Тестовая, д. 1", "г. Примерово, ул. Образцовая, д. 2");
    private static final List<String> PLACES = List.of("г. Вымышленск", "г. Примерово");

    private final Map<String, String> table = new LinkedHashMap<>();
    private int counter;

    @Override
    public String render(SourceRange range, String source, EntityType type) {
        String value = source.substring(range.startInclusive(), range.endExclusive());
        String existing = table.get(value);
        if (existing != null) {
            return existing;
        }
        String fake = generate(type, value);
        table.put(value, fake);
        counter++;
        return fake;
    }

    /**
     * Reverse mapping: synthetic value to the original one.
     */
    public Map<String, String> reverseTable() {
        Map<String, String> reverse = new LinkedHashMap<>();
        table.forEach((original, fake) -> reverse.put(fake, original));
        return Map.copyOf(reverse);
    }

    /**
     * Повторяет форму исходного значения: цифры заменяются фиктивными, а
     * пробелы и дефисы сохраняются, поэтому текст остаётся правдоподобным.
     */
    private String sameShape(String original, int seed) {
        StringBuilder sb = new StringBuilder(original.length());
        int digit = seed;
        for (int i = 0; i < original.length(); i++) {
            char c = original.charAt(i);
            if (Character.isDigit(c)) {
                sb.append((char) ('0' + (digit++ % 7)));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String generate(EntityType type, String original) {
        int n = counter;
        return switch (type) {
            case PERSON, CARDHOLDER -> PERSONS.get(n % PERSONS.size());
            case ADDRESS -> ADDRESSES.get(n % ADDRESSES.size());
            case BIRTH_PLACE -> PLACES.get(n % PLACES.size());
            case EMAIL -> "user" + (n + 1) + "@example.com";
            case PHONE -> "+7 495 555-" + String.format("%02d-%02d", n % 100, (n * 7) % 100);
            // Документы и номера: та же форма и длина, что у оригинала, но цифры фиктивные.
            case CARD, INN, PASSPORT, DRIVER_LICENSE, DEPARTMENT_CODE -> sameShape(original, n);
            case BIRTH_DATE, PASSPORT_ISSUE_DATE -> "01.01.2000";
            case CITIZENSHIP -> "Вымышляндия";
            case PASSPORT_ISSUER -> "ОВД Вымышленского района";
            case CVV -> "000";
            case PIN -> "0000";
        };
    }
}
