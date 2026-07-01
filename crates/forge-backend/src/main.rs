//! forge-backend server entrypoint.
//!
//! For a real deployment, run the Go build under `GODEBUG=fips140=on` for the
//! transport boundary and terminate PQC-hybrid TLS in front of this service; see
//! `docs/FIPS-PQC.md`.

use forge_backend::{router, AppState};
use forge_core::TokenConfig;

#[tokio::main]
async fn main() {
    let bind = std::env::var("FORGE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let admin = std::env::var("FORGE_ADMIN").unwrap_or_else(|_| "issuer".to_string());

    let state =
        AppState::new(TokenConfig::new("Generic USD", "gUSD", 2), admin).expect("init state");
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    println!("forge-backend listening on http://{bind}");
    axum::serve(listener, app).await.expect("server");
}
