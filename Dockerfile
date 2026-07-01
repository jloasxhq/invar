# syntax=docker/dockerfile:1

# ---- build stage ----
FROM rust:1-slim-bookworm AS builder
# CARGO_FEATURES="pqc-tls" builds hybrid post-quantum TLS (X25519MLKEM768) via
# aws-lc-rs, which needs a C toolchain + cmake + Go + perl to compile AWS-LC.
ARG CARGO_FEATURES=""
WORKDIR /build

RUN if [ -n "$CARGO_FEATURES" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        cmake clang perl golang-go && rm -rf /var/lib/apt/lists/*; \
    fi

# Copy only what the Rust build needs (Go/web/docs excluded via .dockerignore).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY conformance ./conformance

RUN cargo build --release -p invar-backend ${CARGO_FEATURES:+--features "$CARGO_FEATURES"}

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin invar \
    && mkdir -p /etc/invar/tls && chown invar:invar /etc/invar/tls

COPY --from=builder /build/target/release/invar-backend /usr/local/bin/invar-backend
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER invar
# HTTPS-only and zero-trust (capability tokens required) by default.
ENV INVAR_BIND=0.0.0.0:8443 \
    INVAR_ADMIN=issuer \
    INVAR_REQUIRE_CAPS=true
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsSk https://127.0.0.1:8443/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
