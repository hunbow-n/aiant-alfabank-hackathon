#!/usr/bin/env bash
# Smoke test against a running instance: mask, retry, unmask, health.
set -euo pipefail

BASE="${1:-http://localhost:8080}"

echo "==> health"
curl -fsS "$BASE/health"

echo
echo "==> mask"
MASKED=$(curl -fsS -X POST "$BASE/process" \
  -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент Иванов Иван, email ivan@example.com","payload_id":"smoke-1"}')
echo "$MASKED"

echo "==> retry original"
curl -fsS -X POST "$BASE/process" \
  -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент Иванов Иван, email ivan@example.com","payload_id":"smoke-1"}'
echo

echo "==> unmask"
RESULT=$(echo "$MASKED" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"])')
curl -fsS -X POST "$BASE/process" \
  -H 'Content-Type: application/json' \
  -d "{\"payload\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$RESULT"),\"payload_id\":\"smoke-1\"}"
echo

echo "==> OK"