//! # invar-backend
//!
//! HTTPS REST API over the domain service, **zero-trust by default**: privileged
//! endpoints require a valid **ML-DSA-65 capability token** (`AuthCaller`), verified
//! against a pinned issuer key. TLS is mandatory (see `main.rs`); the `pqc-tls` build
//! adds hybrid post-quantum key exchange.
//!
//! State persists through the `LedgerPort` — set `INVAR_DB_PATH` for the durable
//! SQLite backend (balances, reserve, holds, and governance survive a restart).
//! Capability issuance can be externalized: set `INVAR_ISSUER_PUBKEY` for verify-only
//! mode (an external IdP holds the signing key; `/auth/token` is disabled). The
//! remaining stub is in-memory key custody (production uses an HSM/KMS via the
//! `CryptoProvider` seam — see `docs/ROADMAP.md`).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use invar_core::multisig::{MultisigController, MultisigPolicy, OperationRequest};
use invar_core::{
    AccountId, Allowance, Amount, CryptoProvider, InvarError, KycStatus, LedgerPort,
    ManualReserveOracle, Role, SigningKey, StablecoinService, TokenConfig, VerifyingKey,
};
use invar_crypto::FipsPqcProvider;
use invar_ledger_custodial::CustodialLedger;
use invar_ledger_sqlite::SqliteLedger;

pub type Ctrl = MultisigController<Ledger, FipsPqcProvider>;

/// Parse a role name from the API into a domain `Role`.
fn parse_role(s: &str) -> Option<Role> {
    Some(match s.to_ascii_lowercase().as_str() {
        "admin" => Role::Admin,
        "minter" => Role::Minter,
        "burner" => Role::Burner,
        "pauser" => Role::Pauser,
        "freezer" => Role::Freezer,
        "wiper" => Role::Wiper,
        "compliance" | "complianceofficer" => Role::ComplianceOfficer,
        "attestor" | "reserveattestor" => Role::ReserveAttestor,
        "deleter" => Role::Deleter,
        _ => return None,
    })
}

/// The ledger is a trait object so the backend can select a durable SQLite store
/// or the in-memory custodial ledger at runtime.
pub type Ledger = Arc<dyn LedgerPort>;
pub type Svc = StablecoinService<Ledger, FipsPqcProvider>;

#[derive(Clone)]
pub struct AppState {
    svc: Arc<Svc>,
    ctrl: Arc<Ctrl>,
    admin: AccountId,
    attestor_vk: VerifyingKey,
    attestor_sk: Arc<SigningKey>,
    oracle: Arc<ManualReserveOracle>,
    /// DEMO ONLY: multisig signer keypairs held in-process. In production these are
    /// external/HSM-held; the backend would only ever see detached signatures.
    signers: Arc<Vec<(VerifyingKey, SigningKey)>>,
    /// Pinned capability-issuer verifying key. The signing key is only held here in
    /// dev; in production (verify-only mode) an external IdP holds it and `issuer_sk`
    /// is `None`, so `/auth/token` issuance is disabled.
    issuer_vk: VerifyingKey,
    issuer_sk: Option<Arc<SigningKey>>,
    /// When true, privileged endpoints require a valid capability token; when false
    /// (dev default), a missing token falls back to the bootstrap admin.
    require_caps: bool,
}

impl AppState {
    /// Dev-mode state: privileged endpoints accept the bootstrap admin without a
    /// capability token.
    pub fn new(config: TokenConfig, admin: impl Into<String>) -> Result<Self, InvarError> {
        Self::with_caps(config, admin, false)
    }

    /// Build state (in-memory custodial ledger), optionally requiring capabilities.
    pub fn with_caps(
        config: TokenConfig,
        admin: impl Into<String>,
        require_caps: bool,
    ) -> Result<Self, InvarError> {
        Self::with_ledger(
            config,
            admin,
            require_caps,
            Arc::new(CustodialLedger::new()),
        )
    }

    /// Select the ledger from the environment: `INVAR_DB_PATH` → durable SQLite
    /// (persists balances, reserve, holds, and governance across restarts);
    /// otherwise the in-memory custodial ledger.
    pub fn from_env(
        config: TokenConfig,
        admin: impl Into<String>,
        require_caps: bool,
    ) -> Result<Self, InvarError> {
        let ledger: Ledger = match std::env::var("INVAR_DB_PATH") {
            Ok(p) if !p.is_empty() => Arc::new(SqliteLedger::open(&p)?),
            _ => Arc::new(CustodialLedger::new()),
        };
        let mut state = Self::with_ledger(config, admin, require_caps, ledger)?;
        // External-issuer (verify-only) mode: pin the IdP's public key and disable
        // the in-process /auth/token issuer. The IdP holds the signing key.
        if let Ok(hexpk) = std::env::var("INVAR_ISSUER_PUBKEY") {
            if !hexpk.is_empty() {
                let bytes = hex::decode(hexpk.trim())
                    .map_err(|e| InvarError::MalformedCapability(format!("issuer pubkey: {e}")))?;
                state.issuer_vk = VerifyingKey(bytes);
                state.issuer_sk = None;
            }
        }
        Ok(state)
    }

    /// Build state with a caller-provided ledger backend.
    pub fn with_ledger(
        config: TokenConfig,
        admin: impl Into<String>,
        require_caps: bool,
        ledger: Ledger,
    ) -> Result<Self, InvarError> {
        let admin = AccountId::new(admin);
        let svc = Arc::new(StablecoinService::new(
            config,
            ledger,
            FipsPqcProvider::new(),
            admin.clone(),
        )?);
        let (vk, sk) = svc.crypto().generate_keypair()?;

        // Executor account operated solely by the multisig controller.
        let executor = AccountId::new("__multisig_executor__");
        for role in [
            Role::Admin,
            Role::Minter,
            Role::Burner,
            Role::Wiper,
            Role::Pauser,
            Role::ReserveAttestor,
            Role::Rescuer,
        ] {
            svc.grant_role(&admin, &executor, role)?;
        }

        // 2-of-3 signer policy.
        let mut signers = Vec::new();
        for _ in 0..3 {
            signers.push(svc.crypto().generate_keypair()?);
        }
        let policy = MultisigPolicy::new(2, signers.iter().map(|(v, _)| v.clone()).collect());
        let ctrl = Arc::new(MultisigController::new(svc.clone(), executor, policy));

        let (issuer_vk, issuer_sk) = svc.crypto().generate_keypair()?;

        Ok(AppState {
            svc,
            ctrl,
            admin,
            attestor_vk: vk,
            attestor_sk: Arc::new(sk),
            oracle: Arc::new(ManualReserveOracle::new("custodian-api", Amount::ZERO)),
            signers: Arc::new(signers),
            issuer_vk,
            issuer_sk: Some(Arc::new(issuer_sk)),
            require_caps,
        })
    }
}

/// Authenticated caller derived from a capability token (or the dev-fallback admin).
pub struct AuthCaller {
    pub subject: AccountId,
    pub scopes: Vec<String>,
}

impl AuthCaller {
    /// Require the caller's capability to grant `scope`.
    fn require(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.iter().any(|s| s == "*" || s == scope) {
            Ok(())
        } else {
            Err(ApiError(InvarError::InsufficientScope(scope.to_string())))
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<AppState> for AuthCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(hv) = parts.headers.get("x-invar-capability") {
            let token = hv.to_str().map_err(|_| {
                ApiError(InvarError::MalformedCapability("non-ascii header".into()))
            })?;
            // Compact token: hex(capability-json) "." hex(signature).
            let (cap_hex, sig_hex) = token.split_once('.').ok_or_else(|| {
                ApiError(InvarError::MalformedCapability("expected cap.sig".into()))
            })?;
            let cap_bytes = hex::decode(cap_hex)
                .map_err(|_| ApiError(InvarError::MalformedCapability("invalid hex".into())))?;
            let capability: invar_core::Capability = serde_json::from_slice(&cap_bytes)
                .map_err(|e| ApiError(InvarError::MalformedCapability(e.to_string())))?;
            let sig_bytes = hex::decode(sig_hex)
                .map_err(|_| ApiError(InvarError::MalformedCapability("invalid hex".into())))?;
            let signed = invar_core::SignedCapability {
                capability,
                signature: invar_core::Signature(sig_bytes),
            };
            let cap = invar_core::capability::verify(
                state.svc.crypto(),
                &state.issuer_vk,
                &signed,
                now_unix(),
            )
            .map_err(ApiError)?;
            Ok(AuthCaller {
                subject: cap.subject.clone(),
                scopes: cap.scopes.clone(),
            })
        } else if state.require_caps {
            Err(ApiError(InvarError::Unauthorized(
                "capability token required".into(),
            )))
        } else {
            Ok(AuthCaller {
                subject: state.admin.clone(),
                scopes: vec!["*".to_string()],
            })
        }
    }
}

/// Map domain errors to HTTP responses.
pub struct ApiError(InvarError);
impl From<InvarError> for ApiError {
    fn from(e: InvarError) -> Self {
        ApiError(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use InvarError::*;
        let status = match &self.0 {
            Unauthorized(_) => StatusCode::FORBIDDEN,
            NotRegistered(_) | NotVerified(_) | AmountOverflow | InsufficientBalance
            | Serialization(_) => StatusCode::BAD_REQUEST,
            Frozen(_)
            | Paused
            | InvalidState(_)
            | TokenDeleted
            | HoldNotActive(_)
            | HoldExpired(_)
            | DuplicateApproval
            | AlreadyExecuted(_)
            | QuorumNotMet { .. } => StatusCode::CONFLICT,
            ReserveExceeded { .. } | AllowanceExceeded { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            UnknownSigner | InsufficientScope(_) => StatusCode::FORBIDDEN,
            CapabilityExpired => StatusCode::UNAUTHORIZED,
            BadSignature | MalformedCapability(_) => StatusCode::BAD_REQUEST,
            UnknownAccount(_) | HoldNotFound(_) | UnknownPendingOp(_) => StatusCode::NOT_FOUND,
            Crypto(_) | Ledger(_) | Oracle(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/token", post(issue_token))
        .route("/auth/pubkey", get(issuer_pubkey))
        .route("/token", get(token))
        .route("/accounts", post(register_account))
        .route("/accounts/:id", get(get_account))
        .route("/accounts/:id/kyc", post(set_kyc))
        .route("/accounts/:id/freeze", post(freeze))
        .route("/mint", post(mint))
        .route("/burn", post(burn))
        .route("/transfer", post(transfer))
        .route("/redeem", post(redeem))
        .route("/pause", post(pause))
        .route("/attest", post(attest))
        .route("/entries", get(entries))
        .route("/accounts/:id/roles/grant", post(grant_role))
        .route("/accounts/:id/roles/revoke", post(revoke_role))
        .route("/holds", get(list_holds).post(create_hold))
        .route("/holds/:id/execute", post(execute_hold))
        .route("/holds/:id/release", post(release_hold))
        .route("/token/metadata", post(set_metadata))
        .route("/token/delete", post(delete_token))
        .route("/reserve/oracle", post(set_oracle))
        .route("/reserve/sync", post(sync_reserve))
        .route("/rescue", post(rescue))
        .route("/accounts/:id/allowance", post(set_allowance))
        .route("/multisig/policy", get(multisig_policy))
        .route("/multisig", get(list_pending).post(propose))
        .route("/multisig/:id/approve", post(approve))
        .route("/multisig/:id/execute", post(execute))
        .with_state(state)
}

// ---- request/response bodies ----

#[derive(Deserialize)]
struct RegisterReq {
    id: String,
}
#[derive(Deserialize)]
struct KycReq {
    verified: bool,
}
#[derive(Deserialize)]
struct FreezeReq {
    frozen: bool,
}
#[derive(Deserialize)]
struct MintReq {
    to: String,
    amount: u128,
}
#[derive(Deserialize)]
struct TransferReq {
    from: String,
    to: String,
    amount: u128,
}
#[derive(Deserialize)]
struct RedeemReq {
    from: String,
    amount: u128,
}
#[derive(Deserialize)]
struct AttestReq {
    reserve: u128,
    custodian_ref: String,
}
#[derive(Serialize)]
struct TokenInfo {
    name: String,
    symbol: String,
    decimals: u8,
    total_supply: u128,
    attested_reserve: u128,
    paused: bool,
}
#[derive(Serialize)]
struct BalanceInfo {
    id: String,
    balance: u128,
}
#[derive(Deserialize)]
struct BurnReq {
    from: String,
    amount: u128,
}
#[derive(Deserialize)]
struct PauseReq {
    paused: bool,
}
#[derive(Deserialize)]
struct RoleReq {
    role: String,
}
#[derive(Deserialize)]
struct CreateHoldReq {
    from: String,
    amount: u128,
    #[serde(default)]
    beneficiary: Option<String>,
    #[serde(default)]
    expires_unix: u64,
}
#[derive(Deserialize)]
struct ExecuteHoldReq {
    #[serde(default)]
    target: Option<String>,
}
#[derive(Deserialize)]
struct MetadataReq {
    #[serde(default)]
    metadata: Option<String>,
}
#[derive(Deserialize)]
struct OracleReq {
    reserve: u128,
}
#[derive(Deserialize)]
struct RescueReq {
    to: String,
    amount: u128,
}
#[derive(Deserialize)]
struct AllowanceReq {
    #[serde(default)]
    unlimited: bool,
    #[serde(default)]
    amount: u128,
}
#[derive(Deserialize)]
struct ApproveReq {
    signer_index: usize,
}
#[derive(Deserialize)]
struct TokenReq {
    subject: String,
    scopes: Vec<String>,
    #[serde(default)]
    ttl_secs: u64,
}

// ---- handlers ----

async fn health() -> &'static str {
    "ok"
}

/// DEV issuance endpoint (stands in for an IdP). Issues an ML-DSA-signed capability
/// token; returns it hex-encoded for the `X-Invar-Capability` header.
/// The pinned capability-issuer verifying key and whether in-process issuance is on.
async fn issuer_pubkey(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "algorithm": "ML-DSA-65",
        "issuer_pubkey": hex::encode(&s.issuer_vk.0),
        "issuance_enabled": s.issuer_sk.is_some(),
    }))
}

async fn issue_token(
    State(s): State<AppState>,
    Json(req): Json<TokenReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let not_after = if req.ttl_secs == 0 {
        0
    } else {
        now_unix() + req.ttl_secs
    };
    // Verify-only mode: issuance is disabled; an external IdP mints capabilities.
    let issuer_sk = s.issuer_sk.as_ref().ok_or_else(|| {
        ApiError(InvarError::Unauthorized(
            "token issuance disabled (verify-only mode); mint capabilities at the external IdP"
                .into(),
        ))
    })?;
    let nonce = format!("{}:{}", now_unix(), req.subject);
    let cap = invar_core::capability::Capability::new(
        AccountId::new(req.subject),
        req.scopes,
        not_after,
        nonce,
    );
    let signed = invar_core::capability::issue(s.svc.crypto(), issuer_sk, cap).map_err(ApiError)?;
    // Compact token: hex(capability-json) "." hex(signature). Avoids serializing the
    // 3309-byte ML-DSA signature as a JSON number array (which bloated the header).
    let cap_json = serde_json::to_vec(&signed.capability)
        .map_err(|e| ApiError(InvarError::Serialization(e.to_string())))?;
    let token = format!(
        "{}.{}",
        hex::encode(&cap_json),
        hex::encode(&signed.signature.0)
    );
    Ok(Json(serde_json::json!({ "token": token })))
}

async fn token(State(s): State<AppState>) -> Result<Json<TokenInfo>, ApiError> {
    Ok(Json(TokenInfo {
        name: s.svc.config.name.clone(),
        symbol: s.svc.config.symbol.clone(),
        decimals: s.svc.config.decimals,
        total_supply: s.svc.total_supply()?.get(),
        attested_reserve: s.svc.attested_reserve()?.get(),
        paused: s.svc.is_paused(),
    }))
}

async fn register_account(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<RegisterReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("compliance")?;
    s.svc
        .register_account(&caller.subject, &AccountId::new(req.id))?;
    Ok(StatusCode::CREATED)
}

async fn get_account(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<BalanceInfo>, ApiError> {
    let acct = AccountId::new(id.clone());
    Ok(Json(BalanceInfo {
        id,
        balance: s.svc.balance_of(&acct)?.get(),
    }))
}

async fn set_kyc(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
    Json(req): Json<KycReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("compliance")?;
    let status = if req.verified {
        KycStatus::Verified
    } else {
        KycStatus::Revoked
    };
    s.svc
        .set_kyc(&caller.subject, &AccountId::new(id), status)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn freeze(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
    Json(req): Json<FreezeReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("freeze")?;
    s.svc
        .set_frozen(&caller.subject, &AccountId::new(id), req.frozen)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn mint(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<MintReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("mint")?;
    s.svc.mint(
        &caller.subject,
        &AccountId::new(req.to),
        Amount::new(req.amount),
    )?;
    Ok(StatusCode::OK)
}

async fn transfer(
    State(s): State<AppState>,
    Json(req): Json<TransferReq>,
) -> Result<StatusCode, ApiError> {
    let from = AccountId::new(req.from);
    s.svc.transfer(
        &from,
        &from,
        &AccountId::new(req.to),
        Amount::new(req.amount),
    )?;
    Ok(StatusCode::OK)
}

async fn redeem(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<RedeemReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("burn")?;
    s.svc.redeem(
        &caller.subject,
        &AccountId::new(req.from),
        Amount::new(req.amount),
    )?;
    Ok(StatusCode::OK)
}

async fn attest(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<AttestReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    caller.require("attest")?;
    let att = s.svc.attest_reserve(
        &caller.subject,
        &s.attestor_vk,
        &s.attestor_sk,
        Amount::new(req.reserve),
        &req.custodian_ref,
    )?;
    serde_json::to_value(&att)
        .map(Json)
        .map_err(|e| ApiError(InvarError::Serialization(e.to_string())))
}

async fn burn(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<BurnReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("burn")?;
    s.svc.burn(
        &caller.subject,
        &AccountId::new(req.from),
        Amount::new(req.amount),
    )?;
    Ok(StatusCode::OK)
}

async fn pause(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<PauseReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("pause")?;
    s.svc.set_paused(&caller.subject, req.paused)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn grant_role(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
    Json(req): Json<RoleReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("admin")?;
    let role = parse_role(&req.role).ok_or_else(|| {
        ApiError(InvarError::InvalidState(format!(
            "unknown role {}",
            req.role
        )))
    })?;
    s.svc
        .grant_role(&caller.subject, &AccountId::new(id), role)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_role(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
    Json(req): Json<RoleReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("admin")?;
    let role = parse_role(&req.role).ok_or_else(|| {
        ApiError(InvarError::InvalidState(format!(
            "unknown role {}",
            req.role
        )))
    })?;
    s.svc
        .revoke_role(&caller.subject, &AccountId::new(id), role)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_hold(
    State(s): State<AppState>,
    Json(req): Json<CreateHoldReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let from = AccountId::new(req.from);
    let beneficiary = req.beneficiary.map(AccountId::new);
    let hold = s.svc.create_hold(
        &from,
        &from,
        Amount::new(req.amount),
        beneficiary,
        req.expires_unix,
    )?;
    serde_json::to_value(hold)
        .map(Json)
        .map_err(|e| ApiError(InvarError::Serialization(e.to_string())))
}

async fn execute_hold(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ExecuteHoldReq>,
) -> Result<StatusCode, ApiError> {
    s.svc
        .execute_hold(&s.admin, &id, req.target.map(AccountId::new))?;
    Ok(StatusCode::OK)
}

async fn release_hold(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    s.svc.release_hold(&s.admin, &id)?;
    Ok(StatusCode::OK)
}

async fn list_holds(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let holds = s.svc.holds()?;
    serde_json::to_value(holds)
        .map(Json)
        .map_err(|e| ApiError(InvarError::Serialization(e.to_string())))
}

async fn set_metadata(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<MetadataReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("delete")?;
    s.svc.set_metadata(&caller.subject, req.metadata)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_token(
    State(s): State<AppState>,
    caller: AuthCaller,
) -> Result<StatusCode, ApiError> {
    caller.require("delete")?;
    s.svc.delete_token(&caller.subject)?;
    Ok(StatusCode::OK)
}

async fn set_oracle(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<OracleReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("attest")?;
    s.oracle.set(Amount::new(req.reserve));
    Ok(StatusCode::NO_CONTENT)
}

async fn sync_reserve(
    State(s): State<AppState>,
    caller: AuthCaller,
) -> Result<Json<serde_json::Value>, ApiError> {
    caller.require("attest")?;
    let r = s
        .svc
        .sync_reserve_from_oracle(&caller.subject, s.oracle.as_ref())?;
    Ok(Json(serde_json::json!({ "attested_reserve": r.get() })))
}

async fn rescue(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(req): Json<RescueReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("rescue")?;
    s.svc.rescue(
        &caller.subject,
        &AccountId::new(req.to),
        Amount::new(req.amount),
    )?;
    Ok(StatusCode::OK)
}

async fn set_allowance(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
    Json(req): Json<AllowanceReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("supply_admin")?;
    let allowance = if req.unlimited {
        Allowance::Unlimited
    } else {
        Allowance::Limited(Amount::new(req.amount))
    };
    s.svc
        .set_supply_allowance(&caller.subject, &AccountId::new(id), allowance)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn multisig_policy(State(s): State<AppState>) -> Json<serde_json::Value> {
    let signers: Vec<String> = s.signers.iter().map(|(v, _)| hex::encode(&v.0)).collect();
    Json(serde_json::json!({ "threshold": s.ctrl.threshold(), "signers": signers }))
}

async fn list_pending(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    serde_json::to_value(s.ctrl.pending_ops())
        .map(Json)
        .map_err(|e| ApiError(InvarError::Serialization(e.to_string())))
}

async fn propose(
    State(s): State<AppState>,
    caller: AuthCaller,
    Json(request): Json<OperationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    caller.require("multisig")?;
    let op = s.ctrl.propose(request)?;
    let preimage = s.ctrl.preimage_for(&op.id)?;
    Ok(Json(serde_json::json!({
        "id": op.id,
        "preimage_hex": hex::encode(preimage),
    })))
}

async fn approve(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
    Json(req): Json<ApproveReq>,
) -> Result<StatusCode, ApiError> {
    caller.require("multisig")?;
    // DEMO: sign on behalf of the selected in-process signer. In production the
    // signature is produced externally and submitted as detached bytes.
    let (vk, sk) = s
        .signers
        .get(req.signer_index)
        .ok_or_else(|| ApiError(InvarError::InvalidState("signer_index out of range".into())))?;
    let preimage = s.ctrl.preimage_for(&id)?;
    let sig = s.svc.crypto().sign(sk, &preimage)?;
    s.ctrl.approve(&id, vk, &sig)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn execute(
    State(s): State<AppState>,
    caller: AuthCaller,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    caller.require("multisig")?;
    s.ctrl.execute(&id)?;
    Ok(StatusCode::OK)
}

async fn entries(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let e = s.svc.entries()?;
    serde_json::to_value(e)
        .map(Json)
        .map_err(|e| ApiError(InvarError::Serialization(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    fn app() -> Router {
        router(AppState::new(TokenConfig::new("Generic USD", "gUSD", 2), "issuer").unwrap())
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn full_http_flow() {
        let app = app();

        // health
        let (st, _) = call(&app, "GET", "/health", serde_json::Value::Null).await;
        assert_eq!(st, StatusCode::OK);

        // onboard acme
        let (st, _) = call(&app, "POST", "/accounts", serde_json::json!({"id":"acme"})).await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, _) = call(
            &app,
            "POST",
            "/accounts/acme/kyc",
            serde_json::json!({"verified":true}),
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        // attest reserve, then mint within it
        let (st, att) = call(
            &app,
            "POST",
            "/attest",
            serde_json::json!({"reserve":1000000,"custodian_ref":"bank:1"}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(att["algorithm"], "ML-DSA-65");

        let (st, _) = call(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":400000}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        let (st, bal) = call(&app, "GET", "/accounts/acme", serde_json::Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(bal["balance"], 400000);

        // minting beyond reserve is rejected with 422
        let (st, err) = call(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":9000000}),
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(err["error"].as_str().unwrap().contains("peg"));
    }

    #[tokio::test]
    async fn p1_endpoints_hold_oracle_delete() {
        let app = app();
        for id in ["acme", "globex"] {
            call(&app, "POST", "/accounts", serde_json::json!({ "id": id })).await;
            call(
                &app,
                "POST",
                &format!("/accounts/{id}/kyc"),
                serde_json::json!({"verified":true}),
            )
            .await;
        }

        // Reserve via external oracle: push a value, then sync.
        let (st, _) = call(
            &app,
            "POST",
            "/reserve/oracle",
            serde_json::json!({"reserve":1000000}),
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, synced) = call(&app, "POST", "/reserve/sync", serde_json::Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(synced["attested_reserve"], 1000000);

        // Mint, then escrow 300k from acme to globex via a hold, then execute it.
        call(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":500000}),
        )
        .await;
        let (st, hold) = call(
            &app,
            "POST",
            "/holds",
            serde_json::json!({"from":"acme","amount":300000,"beneficiary":"globex"}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let hold_id = hold["id"].as_str().unwrap().to_string();

        let (st, bal) = call(&app, "GET", "/accounts/acme", serde_json::Value::Null).await;
        assert_eq!(bal["balance"], 200000, "funds locked in hold");
        let _ = st;

        let (st, _) = call(
            &app,
            "POST",
            &format!("/holds/{hold_id}/execute"),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let (_, bal) = call(&app, "GET", "/accounts/globex", serde_json::Value::Null).await;
        assert_eq!(bal["balance"], 300000, "hold delivered to beneficiary");

        // Metadata + delete lifecycle.
        let (st, _) = call(
            &app,
            "POST",
            "/token/metadata",
            serde_json::json!({"metadata":"ipfs://terms"}),
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, _) = call(&app, "POST", "/token/delete", serde_json::Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        // After delete, mint is rejected (409).
        let (st, _) = call(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":1}),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn p0_multisig_mint_flow() {
        let app = app();
        call(&app, "POST", "/accounts", serde_json::json!({"id":"acme"})).await;
        call(
            &app,
            "POST",
            "/accounts/acme/kyc",
            serde_json::json!({"verified":true}),
        )
        .await;
        call(
            &app,
            "POST",
            "/reserve/oracle",
            serde_json::json!({"reserve":1000000}),
        )
        .await;
        call(&app, "POST", "/reserve/sync", serde_json::Value::Null).await;

        // Policy is 2-of-3.
        let (st, pol) = call(&app, "GET", "/multisig/policy", serde_json::Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(pol["threshold"], 2);

        // Propose a multisig mint.
        let (st, prop) = call(
            &app,
            "POST",
            "/multisig",
            serde_json::json!({"mint":{"to":"acme","amount":400000}}),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "propose: {prop}");
        let id = prop["id"].as_str().unwrap().to_string();
        assert!(!prop["preimage_hex"].as_str().unwrap().is_empty());

        // One approval: quorum not met on execute.
        let (sa, ea) = call(
            &app,
            "POST",
            &format!("/multisig/{id}/approve"),
            serde_json::json!({"signer_index":0}),
        )
        .await;
        assert_eq!(sa, StatusCode::NO_CONTENT, "approve0: {ea}");
        let (st, _) = call(
            &app,
            "POST",
            &format!("/multisig/{id}/execute"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);

        // Second approval reaches quorum; execute mints.
        let (sb, eb) = call(
            &app,
            "POST",
            &format!("/multisig/{id}/approve"),
            serde_json::json!({"signer_index":1}),
        )
        .await;
        assert_eq!(sb, StatusCode::NO_CONTENT, "approve1: {eb}");
        let (st, ee) = call(
            &app,
            "POST",
            &format!("/multisig/{id}/execute"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "execute: {ee}");

        let (_, bal) = call(&app, "GET", "/accounts/acme", serde_json::Value::Null).await;
        assert_eq!(bal["balance"], 400000);
    }

    #[tokio::test]
    async fn p0_allowance_and_rescue() {
        let app = app();
        for id in ["sup", "bob"] {
            call(&app, "POST", "/accounts", serde_json::json!({ "id": id })).await;
            call(
                &app,
                "POST",
                &format!("/accounts/{id}/kyc"),
                serde_json::json!({"verified":true}),
            )
            .await;
        }
        // Grant sup Minter, set a limited allowance of 100, fund reserve.
        call(
            &app,
            "POST",
            "/accounts/sup/roles/grant",
            serde_json::json!({"role":"minter"}),
        )
        .await;
        call(
            &app,
            "POST",
            "/accounts/sup/allowance",
            serde_json::json!({"amount":100}),
        )
        .await;
        call(
            &app,
            "POST",
            "/reserve/oracle",
            serde_json::json!({"reserve":1000000}),
        )
        .await;
        call(&app, "POST", "/reserve/sync", serde_json::Value::Null).await;

        // Rescue endpoint exists and returns OK (treasury empty -> insufficient -> 400).
        let (st, _) = call(
            &app,
            "POST",
            "/rescue",
            serde_json::json!({"to":"bob","amount":1}),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "empty treasury: insufficient balance"
        );
    }

    async fn call_tok(
        app: &Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut rb = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(t) = token {
            rb = rb.header("x-invar-capability", t);
        }
        let req = rb.body(Body::from(body.to_string())).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn p2_capability_enforcement() {
        let app = router(
            AppState::with_caps(TokenConfig::new("Generic USD", "gUSD", 2), "issuer", true)
                .unwrap(),
        );

        // No token -> privileged mint rejected.
        let (st, _) = call_tok(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":1}),
            None,
        )
        .await;
        assert_eq!(
            st,
            StatusCode::FORBIDDEN,
            "missing capability must be rejected"
        );

        // Issue an all-scope admin token.
        let (st, tok) = call_tok(
            &app,
            "POST",
            "/auth/token",
            serde_json::json!({"subject":"issuer","scopes":["*"],"ttl_secs":300}),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let token = tok["token"].as_str().unwrap().to_string();

        // With the token, the full setup + mint succeeds.
        call_tok(
            &app,
            "POST",
            "/accounts",
            serde_json::json!({"id":"acme"}),
            Some(&token),
        )
        .await;
        call_tok(
            &app,
            "POST",
            "/accounts/acme/kyc",
            serde_json::json!({"verified":true}),
            Some(&token),
        )
        .await;
        call_tok(
            &app,
            "POST",
            "/reserve/oracle",
            serde_json::json!({"reserve":1000000}),
            Some(&token),
        )
        .await;
        call_tok(
            &app,
            "POST",
            "/reserve/sync",
            serde_json::Value::Null,
            Some(&token),
        )
        .await;
        let (st, _) = call_tok(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":400000}),
            Some(&token),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "valid capability must authorize mint");

        // A token scoped only to "burn" cannot mint (wrong scope -> 403).
        let (_, tok2) = call_tok(
            &app,
            "POST",
            "/auth/token",
            serde_json::json!({"subject":"issuer","scopes":["burn"],"ttl_secs":300}),
            None,
        )
        .await;
        let token2 = tok2["token"].as_str().unwrap().to_string();
        let (st, _) = call_tok(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":1}),
            Some(&token2),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::FORBIDDEN,
            "insufficient scope must be rejected"
        );

        // A tampered token (bad hex) is rejected.
        let (st, _) = call_tok(
            &app,
            "POST",
            "/mint",
            serde_json::json!({"to":"acme","amount":1}),
            Some("zzzz"),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "malformed capability rejected");
    }
}
