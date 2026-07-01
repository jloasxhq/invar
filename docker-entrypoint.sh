#!/bin/sh
# HTTPS-only entrypoint. If no cert is provided via FORGE_TLS_CERT/FORGE_TLS_KEY,
# generate a self-signed pair (fine for dev/alpha; mount real certs in production).
set -e

if [ -z "${FORGE_TLS_CERT:-}" ]; then
  if [ ! -f /etc/forge/tls/cert.pem ]; then
    echo "No TLS cert provided — generating a self-signed pair (mount real certs in production)"
    openssl req -x509 -newkey rsa:2048 \
      -keyout /etc/forge/tls/key.pem -out /etc/forge/tls/cert.pem \
      -days 365 -nodes -subj "/CN=stablecoin-forge" >/dev/null 2>&1
  fi
  export FORGE_TLS_CERT=/etc/forge/tls/cert.pem
  export FORGE_TLS_KEY=/etc/forge/tls/key.pem
fi

exec /usr/local/bin/forge-backend
