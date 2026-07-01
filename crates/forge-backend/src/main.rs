//! forge-backend server entrypoint. Configured entirely via environment variables
//! (see `.env.example`). For the transport boundary, run the Go build under
//! `GODEBUG=fips140=on` and terminate PQC-hybrid TLS in front of this service; see
//! `docs/FIPS-PQC.md`.

use forge_backend::{router, AppState};
use forge_core::TokenConfig;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str) -> bool {
    matches!(
        env_or(key, "false").to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[tokio::main]
async fn main() {
    let bind = env_or("FORGE_BIND", "127.0.0.1:8080");
    let admin = env_or("FORGE_ADMIN", "issuer");
    let name = env_or("FORGE_TOKEN_NAME", "Generic USD");
    let symbol = env_or("FORGE_TOKEN_SYMBOL", "gUSD");
    let decimals: u8 = env_or("FORGE_TOKEN_DECIMALS", "2").parse().unwrap_or(2);
    let require_caps = env_bool("FORGE_REQUIRE_CAPS");

    let state = AppState::with_caps(
        TokenConfig::new(name, symbol, decimals),
        admin,
        require_caps,
    )
    .expect("init state");
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    println!("forge-backend listening on http://{bind} (require_caps={require_caps})");
    axum::serve(listener, app).await.expect("server");
}
