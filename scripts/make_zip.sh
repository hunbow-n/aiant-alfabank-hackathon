#!/usr/bin/env bash
# Build a clean submission ZIP with an allowlist and clean-room verification.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/pd-security.zip}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Running tests"
(cd "$ROOT" && mvn -q test)

echo "==> Staging files by allowlist"
STAGE="$TMP/stage"
mkdir -p "$STAGE"
for item in pom.xml mvnw .mvn src docs scripts tools config ops Dockerfile compose.yaml \
            README.md AGENTS.md NOTICE THIRD_PARTY_NOTICES.md .gitignore .dockerignore; do
  if [ -e "$ROOT/$item" ]; then
    cp -R "$ROOT/$item" "$STAGE/"
  fi
done

echo "==> Removing accidental artifacts"
find "$STAGE" -type d \( -name target -o -name .git -o -name .idea -o -name node_modules \) -prune -exec rm -rf {} +
find "$STAGE" -type f \( -name '*.log' -o -name '*.zip' -o -name '.DS_Store' -o -name '*.jar' \) -delete

echo "==> Creating archive"
(cd "$STAGE" && zip -qr "$OUT" .)
echo "Archive: $OUT"
echo "Size: $(du -h "$OUT" | cut -f1)"
echo "SHA-256: $(shasum -a 256 "$OUT" | cut -d' ' -f1)"

echo "==> Clean-room verification"
VERIFY="$TMP/verify"
mkdir -p "$VERIFY"
(cd "$VERIFY" && unzip -q "$OUT")
test -f "$VERIFY/pom.xml" || { echo "FAIL: pom.xml not at root"; exit 1; }
if find "$VERIFY" -type d \( -name target -o -name .git -o -name .idea -o -name node_modules \) | grep -q .; then
  echo "FAIL: forbidden directory present"; exit 1
fi
if find "$VERIFY" -name '*.jar' | grep -q .; then
  echo "FAIL: jar present"; exit 1
fi
echo "==> Running tests from unpacked archive"
(cd "$VERIFY" && mvn -q test)
echo "==> OK: archive verified"