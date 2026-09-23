#!/usr/bin/env python3
"""
Приёмочная проверка развёрнутого pd-security.

Запуск:
    python3 check_deployed.py http://IP[:PORT]
    python3 check_deployed.py http://IP --quick     # без нагрузочной части

Проверяет то же, что проверялось на всех ревью: контракт, идемпотентность,
отсутствие утечек значений, ложные срабатывания, границы адреса, ФИО,
edge-cases round-trip, latency на больших текстах, throughput.

Датасет — синтетический, собран вручную по списку 17 типов ПД из ТЗ и по
примерам из Приложения A. Реальных персональных данных нет.
Эталонный датасет организаторов не публикуется (ответ #710), поэтому
проверка качества здесь — не оценка жюри, а регрессионный контроль.
"""

import json
import re
import sys
import time
import urllib.request
import urllib.error
import uuid
from concurrent.futures import ThreadPoolExecutor

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8099"
QUICK = "--quick" in sys.argv
URL = BASE + "/process"
TIMEOUT = 15

ok_count = 0
fail_count = 0


def call(payload, payload_id):
    """Один запрос к /process. Возвращает (http_status, result|error_text)."""
    body = json.dumps({"payload": payload, "payload_id": payload_id}).encode()
    req = urllib.request.Request(URL, body, {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.load(r).get("result")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:120]


def pair(text):
    """Маскирование + демаскирование одной строки. Возвращает (маска, round_trip_ok)."""
    pid = str(uuid.uuid4())
    s1, masked = call(text, pid)
    if s1 != 200:
        return None, False
    s2, back = call(masked, pid)
    return masked, (s2 == 200 and back == text)


def check(name, condition, detail=""):
    global ok_count, fail_count
    if condition:
        ok_count += 1
        print(f"  OK   {name}")
    else:
        fail_count += 1
        print(f"  FAIL {name}   {detail}")


print(f"=== Проверка {BASE}\n")

try:
    with urllib.request.urlopen(BASE + "/health", timeout=10) as r:
        print(f"  health: {r.status} {r.read().decode()[:60]}\n")
except Exception as e:  # noqa: BLE001 - хотим понятное сообщение вместо traceback
    print(f"  СЕРВИС НЕДОСТУПЕН: {e}")
    print("  Проверьте URL, открыт ли порт наружу и запущен ли контейнер.")
    sys.exit(2)

# ---------------------------------------------------------------- 1. Контракт
print("[1] Контракт и машина состояний")
pid = str(uuid.uuid4())
s, masked = call("Клиент Иванов Иван Иванович, паспорт 4509 123456", pid)
check("200 на валидный запрос", s == 200, f"статус {s}")
check("маска отличается от исходника", masked and "Иванов" not in masked)
s, retry = call("Клиент Иванов Иван Иванович, паспорт 4509 123456", pid)
check("ретрай маскирования возвращает ту же маску", retry == masked)
s, back = call(masked, pid)
check("демаскирование возвращает исходник",
      back == "Клиент Иванов Иван Иванович, паспорт 4509 123456")
s, _ = call("Совершенно другой текст", pid)
check("конфликт по payload_id -> 409", s == 409, f"статус {s}")
req = urllib.request.Request(URL, b'{"payload":"x"}', {"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=TIMEOUT)
    check("запрос без payload_id -> 4xx", False, "вернулось 200")
except urllib.error.HTTPError as e:
    check("запрос без payload_id -> 4xx", 400 <= e.code < 500, f"статус {e.code}")
    check("ответ об ошибке не содержит payload", "x" not in e.read().decode()[:200].replace('"', ""))

# ------------------------------------------------------- 2. Утечки значений
print("\n[2] Утечки: цифры исходника не должны оставаться в маске")
LEAKS = [
    ("паспорт 4509 123456", "паспорт"),
    ("карта 4276 3801 2345 6789", "карта"),
    ("ИНН 7707083893", "ИНН"),
    ("ВУ 99 12 345678", "ВУ"),
    ("тел +7 916 123-45-67", "телефон"),
    ("снилс 112-233-445 95", "СНИЛС"),
    ("cvv 123 к карте 4276380123456789", "CVV + карта"),
    ("д.р. 12.03.1990", "дата рождения"),
    ("код подразделения 770-123", "код подразделения"),
]
for text, label in LEAKS:
    masked, rt = pair(text)
    digits_left = re.sub(r"\D", "", masked or "")
    check(f"{label}: цифры скрыты", masked is not None and digits_left == "",
          f"осталось {digits_left!r} в {masked!r}")

# ------------------------------------------------------------- 3. ФИО
print("\n[3] ФИО во всех формах")
NAMES = [
    "Иванов Иван Иванович",
    "Петрову Сергею Алексеевичу",
    "иванов иван иванович",
    "Фамилия: Сидоров",
    "Иван Петров",
]
for text in NAMES:
    masked, rt = pair(text)
    check(f"{text!r} маскируется", masked and "*" in masked, f"-> {masked!r}")

# -------------------------------------------------------- 4. Адрес: две стороны
print("\n[4] Адрес: компоненты скрыты, хвост предложения цел")
ADDR_HIDE = ["ул. Тверская", "дом 28", "кв. 15", "индекс 125009", "город Москва"]
for text in ADDR_HIDE:
    masked, rt = pair(text)
    check(f"{text!r} маскируется", masked and "*" in masked, f"-> {masked!r}")

masked, _ = pair("Адрес: г. Москва, ул. Тверская, д. 7, кв. 15. Позвоните завтра.")
check("хвост предложения не съеден", masked and "Позвоните завтра" in masked, f"-> {masked!r}")
masked, _ = pair("Клиент проживает по адресу 125009 Москва Тверская 7, телефон уточняется")
check("текст после адреса цел", masked and "телефон уточняется" in masked, f"-> {masked!r}")
masked, _ = pair("адресу")
check("метка не режется по корню", masked == "адресу", f"-> {masked!r}")

# --------------------------------------------- 5. Ложные срабатывания
print("\n[5] Ложные срабатывания: текст без ПД не должен меняться")
CLEAN = [
    "Клиент оплатил покупку в магазине Пятёрочка на сумму 1500 рублей",
    "Кот сидит на окне, мороз на улице",
    "Договор 770-123 от 12.03.2024 подписан",
    "Встреча назначена на 15.04.2026 в офисе",
    "Сумма перевода 123456 рублей на счёт получателя",
    "Президент подписал указ о поддержке малого бизнеса",
]
for text in CLEAN:
    masked, _ = pair(text)
    check(f"не тронуто: {text[:40]!r}", masked == text, f"-> {masked!r}")

print("\n[5b] Примеры персональности из ТЗ")
masked, _ = pair("Поэт Александр Пушкин написал стихотворение")
check("публичная персона не маскируется", masked and "Пушкин" in masked, f"-> {masked!r}")
masked, _ = pair("Адрес отделения банка: г. Москва, ул. Каланчевская, д. 27")
check("адрес отделения банка не маскируется", masked and "Каланчевская" in masked, f"-> {masked!r}")

# ------------------------------------------------- 6. Round-trip edge cases
print("\n[6] Round-trip на пограничных входах")
EDGE = [
    "",
    "   ",
    "🙂 Иванов Иван Иванович 🙂",
    "строка\r\nс переносом Петров Иван",
    'кавычки "и" \\слеши\\ Иванов Иван Иванович',
    "Иванов Иван Иванович и Петров Пётр Петрович в одном тексте",
]
for text in EDGE:
    masked, rt = pair(text)
    check(f"round-trip {text[:32]!r}", rt, f"-> {masked!r}")

# ---------------------------------------------------- 7. Большие тексты
print("\n[7] Большие тексты (требование ТЗ: до 100 000 токенов)")
BASE_TEXT = ("Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 916 123-45-67, "
             "ivan@mail.ru, адрес: г. Москва, ул. Тверская, д. 7, кв. 15. ")
for mult, label in ((200, "~6k токенов"), (2000, "~60k токенов"), (4000, "~120k токенов")):
    text = BASE_TEXT * mult
    pid = str(uuid.uuid4())
    t0 = time.time()
    s1, masked = call(text, pid)
    d1 = (time.time() - t0) * 1000
    t0 = time.time()
    s2, back = call(masked, pid) if s1 == 200 else (0, None)
    d2 = (time.time() - t0) * 1000
    ok = s1 == 200 and back == text
    print(f"  {'OK  ' if ok else 'FAIL'} {label}: {len(text)} символов, "
          f"маскирование {d1:.0f} мс, демаскирование {d2:.0f} мс, round-trip {'ok' if ok else 'СЛОМАН'}")
    check(f"{label}: latency маскирования < 1000 мс", d1 < 1000, f"{d1:.0f} мс")
    globals()['ok_count' if ok else 'fail_count'] += 1

if QUICK:
    print(f"\n=== ИТОГ: OK {ok_count}, FAIL {fail_count} (нагрузочная часть пропущена)")
    sys.exit(1 if fail_count else 0)

# ------------------------------------------------------------- 8. Нагрузка
print("\n[8] Нагрузка (профиль проверяющей системы: пары mask+unmask)")
WORKERS = 50
PER_WORKER = 40
TEXT = "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 916 123-45-67, ivan@mail.ru"
latencies = []
errors = []
rt_fails = []


def worker(_):
    for _ in range(PER_WORKER):
        pid = str(uuid.uuid4())
        t0 = time.time()
        try:
            s1, masked = call(TEXT, pid)
            if s1 == 429:
                errors.append("429")
                continue
            s2, back = call(masked, pid)
            if back != TEXT:
                rt_fails.append(1)
        except Exception as e:  # noqa: BLE001 - диагностический сбор
            errors.append(type(e).__name__)
        latencies.append(time.time() - t0)


t0 = time.time()
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    list(pool.map(worker, range(WORKERS)))
wall = time.time() - t0
latencies.sort()
http_requests = WORKERS * PER_WORKER * 2
rps = http_requests / wall


def pct(p):
    return latencies[min(int(len(latencies) * p), len(latencies) - 1)] * 1000


print(f"  пар {WORKERS * PER_WORKER}, HTTP-запросов {http_requests}, время {wall:.1f} с")
print(f"  RPS {rps:.0f} | пара p50 {pct(0.5):.0f} мс, p95 {pct(0.95):.0f} мс, p99 {pct(0.99):.0f} мс")
print(f"  ошибок {len(errors)}, потерь round-trip {len(rt_fails)}")
check("RPS >= 1000 (требование ТЗ)", rps >= 1000, f"{rps:.0f}")
check("p99 пары < 1000 мс", pct(0.99) < 1000, f"{pct(0.99):.0f} мс")
check("нет ошибок под нагрузкой", not errors, f"{set(errors)}")
check("нет потерь round-trip", not rt_fails, f"{len(rt_fails)}")

print(f"\n=== ИТОГ: OK {ok_count}, FAIL {fail_count}")
sys.exit(1 if fail_count else 0)
