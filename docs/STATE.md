# Состояние

## Запись

Ключ — `namespace + HMAC(indexKey, lengthPrefixed(systemId, payloadId))`. Сырого `payload_id`
в хранилище нет.

Активная запись (неизменяемая): `policyVersion`, `createdAt`, `restorable`, `masked`,
`fingerprint` исходника, token counts, безопасная статистика детекции. Полезная нагрузка
шифруется AES-256-GCM эфемерным ключом процесса: 96-битный nonce на каждую запись, тег 128 бит,
формат `base64(iv || ciphertext)`.

`fingerprint` — HMAC-SHA-256 от UTF-8 байтов исходника с ключом процесса. Сравнение payload
с оригиналом всегда идёт по fingerprint, никогда через `String.equals` на всём тексте.

## Жизненный цикл

- Active TTL — 15 минут от создания.
- После успешного демаскирования запись не удаляется сразу: потерянный ответ вызовет ретрай.
- По истечении active TTL запись заменяется tombstone: только HMAC прежней маски и признак
  `original == masked`. TTL tombstone — 5 минут.
- Срок проверяется по монотонному времени при каждом чтении.
- Фоновый sweep: период 5 с, порционно, без глобальной блокировки. Плюс ленивое удаление при `get`.

## Алгоритм `/process`

```text
process(payloadId, payload):
  fingerprint = HMAC(payload)
  entry = store.get(payloadId)
  если entry активна:
      если entry.fingerprint == fingerprint      -> MASK_RETRY: вернуть entry.masked
      если entry.masked == payload               -> DEMASK: вернуть decrypt(original)
      иначе                                      -> 409, ничего не перезаписывать
  если найден tombstone и HMAC(payload) == HMAC прежней маски -> 410
  spans = engine.detect(payload)                 # вне критической секции
  masked = masker.render(payload, spans)
  stored = store.putIfAbsent(newEntry)
  если stored != newEntry                        -> перечитать победителя
  если нет бюджета                               -> 429 + Retry-After
  вернуть masked
```

## Ёмкость и память

Ёмкость ограничена `Semaphore` на число записей плюс байтовый бюджет. Исчерпание -> 429, а не OOM
и не вытеснение. Разрешение освобождается при удалении записи и при переходе active -> tombstone.

## Границы честности

- В пределах TTL и живой JVM гарантируются точный round-trip, идемпотентность и отсутствие вытеснения.
- Падение JVM = потеря состояния. Этот профиль переживание падения не обещает.
- После удаления tombstone star-маска на неизвестном ID неотличима от нового текста.