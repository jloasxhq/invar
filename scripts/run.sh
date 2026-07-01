#!/usr/bin/env bash
# Startup script: build (release) and run the HTTPS invar-backend, loading .env if
# present and auto-generating a self-signed dev cert when none is configured.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo "Loading config from .env"
  set -a; . ./.env; set +a
else
  echo "No .env found (using built-in defaults; see .env.example)"
fi

# HTTPS only: ensure a cert/key exist (generate a self-signed pair for dev).
if [ -z "${INVAR_TLS_CERT:-}" ] || [ ! -f "${INVAR_TLS_CERT:-/nonexistent}" ]; then
  echo "No TLS cert configured — generating a self-signed dev cert in .certs/"
  mkdir -p .certs
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 \
    -keyout .certs/key.pem -out .certs/cert.pem -days 365 -nodes -subj "/CN=localhost" >/dev/null 2>&1
  export INVAR_TLS_CERT=.certs/cert.pem INVAR_TLS_KEY=.certs/key.pem
fi

echo "Building invar-backend (release)..."
cargo build --release -p invar-backend

BIN="target/release/invar-backend"
[ -f "${BIN}.exe" ] && BIN="${BIN}.exe"

echo "Starting HTTPS backend: ${BIN}"
exec "./${BIN}"
