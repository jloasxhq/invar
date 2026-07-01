#!/usr/bin/env bash
# Startup script: build (release) and run the forge-backend, loading .env if present.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo "Loading config from .env"
  set -a; . ./.env; set +a
else
  echo "No .env found (using built-in defaults; see .env.example)"
fi

echo "Building forge-backend (release)..."
cargo build --release -p forge-backend

BIN="target/release/forge-backend"
[ -f "${BIN}.exe" ] && BIN="${BIN}.exe"

echo "Starting: ${BIN}"
exec "./${BIN}"
