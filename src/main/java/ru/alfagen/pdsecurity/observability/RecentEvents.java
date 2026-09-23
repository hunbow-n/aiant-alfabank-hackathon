package ru.alfagen.pdsecurity.observability;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;

/**
 * Кольцевой буфер последних строк обработки — ровно тех, что уходят в лог.
 * Существует, чтобы проверяющий мог своими глазами убедиться: в журнале есть
 * типы и количества персональных данных, но нет ни одного значения.
 *
 * <p>Значения сюда физически не попадают: запись принимает только хэш
 * идентификатора, длину текста и карту «тип → количество».
 */
public final class RecentEvents {

    private static final int CAPACITY = 20;

    private final Deque<Entry> entries = new ArrayDeque<>(CAPACITY);

    /**
     * Одна строка журнала.
     *
     * @param at            момент обработки
     * @param operation     MASK, MASK_RETRY, DEMASK
     * @param payloadIdHash хэш идентификатора, сам идентификатор не хранится
     * @param length        длина исходного текста в символах
     * @param types         найденные типы и их количества
     * @param latencyMicros длительность обработки
     */
    public record Entry(Instant at, String operation, String payloadIdHash, int length,
                        Map<String, Integer> types, long latencyMicros) {
    }

    public synchronized void add(String operation, String payloadIdHash, int length,
                                 Map<String, Integer> types, long latencyMicros) {
        if (entries.size() == CAPACITY) {
            entries.removeFirst();
        }
        entries.addLast(new Entry(Instant.now(), operation, payloadIdHash, length,
                Map.copyOf(types), latencyMicros));
    }

    /**
     * Последние записи, новые сверху.
     */
    public synchronized List<Entry> recent() {
        return entries.stream().collect(
                java.util.stream.Collectors.collectingAndThen(
                        java.util.stream.Collectors.toList(),
                        list -> {
                            java.util.Collections.reverse(list);
                            return List.copyOf(list);
                        }));
    }
}
