#!/usr/bin/env bash
#
# run.sh — create a virtualenv if needed, then start the mock on $PORT (default 9500).
#
#   ./run.sh          start the server
#   ./run.sh --test   run the test suite and exit
#
# Configuration is environment variables only (see app/config.py).
# Needs Python 3.11+; set PYTHON=/path/to/python3.11 if it is not on PATH.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VENV=".venv"
PY="$VENV/bin/python"

new_enough() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; }

find_python() {
  local candidate
  for candidate in "${PYTHON:-}" python3.13 python3.12 python3.11 python3; do
    [[ -n "$candidate" ]] && command -v "$candidate" >/dev/null 2>&1 || continue
    if new_enough "$candidate"; then command -v "$candidate"; return 0; fi
  done
  return 1
}

if [[ ! -x "$PY" ]] || ! new_enough "$PY"; then
  BASE_PY="$(find_python)" || {
    echo "The mock needs Python 3.11 or newer; found $(python3 --version 2>&1)." >&2
    echo "Install one, or set PYTHON=/path/to/python3.11." >&2
    exit 1
  }
  echo "==> Creating virtualenv with $("$BASE_PY" --version)"
  rm -rf "$VENV"
  "$BASE_PY" -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
fi

if ! "$PY" -c 'import fastapi, uvicorn, pydantic, jwt, cryptography, httpx, pytest' 2>/dev/null; then
  echo "==> Installing dependencies"
  "$VENV/bin/pip" install --quiet \
    "fastapi>=0.115" "uvicorn[standard]>=0.32" "pydantic>=2.9" \
    "pyjwt>=2.8" "cryptography>=42" "httpx>=0.27" "pytest>=8.3"
fi

case "${1:-}" in
  --test)
    exec "$VENV/bin/pytest" -q
    ;;
  "")
    exec "$VENV/bin/uvicorn" app.main:app \
      --host "${HOST:-0.0.0.0}" --port "${PORT:-9500}" --log-level "${LOG_LEVEL:-info}"
    ;;
  *)
    echo "Usage: ./run.sh [--test]" >&2
    exit 2
    ;;
esac
