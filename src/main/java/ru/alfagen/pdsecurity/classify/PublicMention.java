package ru.alfagen.pdsecurity.classify;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Определяет публичное упоминание: «поэт Александр Пушкин» — это не персональные
 * данные клиента, как и место рождения такого человека. Проверка общая для всех
 * детекторов, которые опираются на имя человека.
 */
public final class PublicMention {

    /** Роль стоит перед именем, поэтому назад смотрим на короткое окно. */
    private static final int LOOKBEHIND = 40;

    private static final Pattern WORDS = Pattern.compile("(?iuU)[а-яё]+");

    private static final Set<String> ROLES = Set.of(
            "поэт", "писатель", "художник", "композитор", "учёный", "ученый",
            "президент", "министр", "актёр", "актер", "певец", "певица",
            "режиссёр", "режиссер", "полководец", "император");

    private PublicMention() {
    }

    /**
     * Есть ли перед позицией {@code at} слово, обозначающее публичную роль.
     */
    public static boolean precedes(String text, int at) {
        int from = Math.max(0, at - LOOKBEHIND);
        Matcher m = WORDS.matcher(text.substring(from, at));
        while (m.find()) {
            if (ROLES.contains(m.group().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }
}
