# Contributing to stablecoin-forge

Thanks for your interest! This is a polyglot monorepo (Rust + Go + a small web app).
Contributions are accepted under the project's [Apache-2.0](LICENSE) license.

## Prerequisites

- **Rust** 1.82+ (`rustup`, with `rustfmt` and `clippy`)
- **Go** 1.24+ (for `crypto/mlkem`, `crypto/hkdf`, `crypto/sha3`, `crypto/fips140`)
- **Node** 20+ (for the web dashboard)

## Local checks (these mirror CI — run them before pushing)

```bash
# Rust
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all

# Go (run tests in FIPS mode)
cd go && go vet ./... && GODEBUG=fips140=on go test ./...

# Web
cd web && npm ci && npm run build
```

CI runs exactly these on every pull request; a PR must be green to merge.

## Guidelines

- **Match the existing style.** Rust follows `rustfmt` defaults and is clippy-clean
  at `-D warnings`. Keep comment density and naming consistent with nearby code.
- **New crypto must be conformance-tested.** Glue that crosses the Rust/Go boundary
  must assert byte-equality against `conformance/vectors.json`. Primitive usage
  should be pinned to NIST KATs.
- **Preserve the peg invariant.** Any change touching supply must keep
  `total_supply <= attested_reserve` enforced at mint.
- **Ports over implementations.** Prefer extending a port (`LedgerPort`,
  `CryptoProvider`, `ReserveOracle`) and adding an adapter over hard-coding a backend.
- **Keep the FIPS/PQC claims honest.** Don't describe algorithm-conformant code as a
  validated module. Update `docs/FIPS-PQC.md` if the posture changes.

## Commit / PR

- Small, focused commits with clear messages.
- Describe what changed and how you verified it (paste test output where useful).
- Add tests for new behavior; update docs when you change public interfaces.
