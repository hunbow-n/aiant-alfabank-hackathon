# Тестирование

## Обязательные тесты

| Группа | Проверки |
|---|---|
| ContractTest | Строгие типы, missing/null, empty/whitespace, malformed JSON, UTF-8, media type |
| ProcessRoundTripTest | original->mask, ретрай original->та же маска, mask->original, текст без ПД дословно |
| ConcurrentSessionTest | 200 параллельных клиентов; один ID; неизменность победившей записи |
| StoreTest | Атомарная публикация, бюджет, TTL и sweep, отсутствие вытеснения |
| SessionCipherTest | Свежие nonce, порча ciphertext |
| DetectorFixturesTest | Позитивные, негативные фикстуры каждого из 17 типов |
| DetectorFaultIsolationTest | Падающий детектор не проваливает запрос |
| ResolverTest | Пересечения, составной паспорт, служебные слова |

TTL в unit-тестах проверяется управляемым монотонным временем, не ожиданием 15 минут.

## Запуск

```bash
mvn test
```