//! forge-backend server entrypoint. **HTTPS only** (plaintext HTTP is not
//! supported) and **zero-trust by default** (capability tokens required). Configured
//! via environment variables; see `.env.example`.
//!
//! TLS uses rustls with the ring provider by default; building with `--features fips`
//! selects the CMVP-validated AWS-LC-FIPS provider (see `docs/FIPS-PQC.md`).

use std::net::SocketAddr;

use axum_server::tls_rustls::RustlsConfig;
use forge_backend::{router, AppState};
use forge_core::TokenConfig;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Install the process-wide rustls crypto provider. With `pqc-tls` or `fips` this is
/// aws-lc-rs, whose default key-exchange groups include the hybrid post-quantum
/// `X25519MLKEM768`; otherwise it is ring (classical, builds without cmake).
#[cfg(any(feature = "pqc-tls", feature = "fips"))]
fn install_crypto_provider() -> &'static str {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc-rs provider");
    "aws-lc-rs (hybrid X25519MLKEM768 available)"
}

#[cfg(not(any(feature = "pqc-tls", feature = "fips")))]
fn install_crypto_provider() -> &'static str {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install ring provider");
    "ring (classical)"
}

#[tokio::main]
async fn main() {
    let tls_provider = install_crypto_provider();

    let bind: SocketAddr = env_or("FORGE_BIND", "0.0.0.0:8443")
        .parse()
        .expect("FORGE_BIND must be host:port");
    let admin = env_or("FORGE_ADMIN", "issuer");
    let name = env_or("FORGE_TOKEN_NAME", "Generic USD");
    let symbol = env_or("FORGE_TOKEN_SYMBOL", "gUSD");
    let decimals: u8 = env_or("FORGE_TOKEN_DECIMALS", "2").parse().unwrap_or(2);

    // Zero-trust: capability tokens are REQUIRED by default. Opt out only for local
    // development by explicitly setting FORGE_REQUIRE_CAPS=false.
    let require_caps = env_or("FORGE_REQUIRE_CAPS", "true") != "false";

    // HTTPS only — no plaintext fallback.
    let cert = env_or("FORGE_TLS_CERT", "");
    let key = env_or("FORGE_TLS_KEY", "");
    if cert.is_empty() || key.is_empty() {
        panic!(
            "HTTPS-only: set FORGE_TLS_CERT and FORGE_TLS_KEY to PEM file paths. \
             Plaintext HTTP is not supported."
        );
    }

    let state = AppState::with_caps(
        TokenConfig::new(name, symbol, decimals),
        admin,
        require_caps,
    )
    .expect("init state");
    let app = router(state);

    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .unwrap_or_else(|e| panic!("load TLS cert/key ({cert}, {key}): {e}"));

    println!(
        "forge-backend HTTPS on https://{bind} (require_caps={require_caps}, tls={tls_provider})"
    );
    axum_server::bind_rustls(bind, tls)
        .serve(app.into_make_service())
        .await
        .expect("server");
}
