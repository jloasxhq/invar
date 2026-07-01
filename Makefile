# invar — developer convenience targets.
# Requires: cargo, go 1.24+, node 20.19+/22+, (optional) docker.

.PHONY: help build test ci fmt clippy run smoke docker-build docker-up web-build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the Rust workspace and Go module (release)
	cargo build --release
	cd go && go build ./...

test: ## Run all Rust + Go tests (Go under FIPS 140-3)
	cargo test --all
	cd go && GODEBUG=fips140=on go test ./...

ci: fmt clippy test web-build ## Run the full CI gate locally

fmt: ## Check formatting
	cargo fmt --all --check

clippy: ## Lint with warnings as errors
	cargo clippy --all-targets -- -D warnings
	cd go && go vet ./...

run: ## Build + run the backend (loads .env if present)
	bash scripts/run.sh

smoke: ## Run the end-to-end smoke test (starts a throwaway backend)
	bash scripts/smoke-test.sh

web-build: ## Type-check + build the web dashboard
	cd web && npm ci && npm run build

docker-build: ## Build the backend container image
	docker build -t invar:0.1.0 .

docker-up: ## Run the backend via docker compose
	docker compose up --build
