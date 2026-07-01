#!/bin/sh
# HTTPS-only entrypoint. If no cert is provided via INVAR_TLS_CERT/INVAR_TLS_KEY,
# generate a self-signed pair (fine for dev/alpha; mount real certs in production).
set -e

if [ -z "${INVAR_TLS_CERT:-}" ]; then
  if [ ! -f /etc/invar/tls/cert.pem ]; then
    echo "No TLS cert provided — generating a self-signed pair (mount real certs in production)"
    openssl req -x509 -newkey rsa:2048 \
      -keyout /etc/invar/tls/key.pem -out /etc/invar/tls/cert.pem \
      -days 365 -nodes -subj "/CN=invar" >/dev/null 2>&1
  fi
  export INVAR_TLS_CERT=/etc/invar/tls/cert.pem
  export INVAR_TLS_KEY=/etc/invar/tls/key.pem
fi

exec /usr/local/bin/invar-backend
