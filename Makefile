# Ferrum — common tasks.
# Works with GNU make on Linux, macOS and Git Bash on Windows.
.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- build

.PHONY: build
build: ## Release build of chaind and chain-cli
	$(CARGO) build --release --bin chaind --bin chain-cli

.PHONY: dev
dev: ## Debug build of the whole workspace
	$(CARGO) build --workspace --all-targets

# ---------------------------------------------------------------- verify

.PHONY: check
check: fmt-check lint test invariants ## Everything CI runs, in CI's order

.PHONY: fmt
fmt: ## Format
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Fail if formatting is needed
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint: ## Clippy, warnings denied
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@# Consensus-critical crates additionally forbid unchecked integer arithmetic:
	@# a silent wrap in fee, subsidy or difficulty maths is a chain split.
	$(CARGO) clippy -p ferrum-chain -p ferrum-script -p ferrum-consensus --lib \
	    -- -D warnings -D clippy::arithmetic_side_effects

.PHONY: test
test: ## Test the workspace
	$(CARGO) test --workspace --all-targets

.PHONY: test-release
test-release: ## Test in release mode — determinism must not depend on opt-level
	$(CARGO) test --workspace --all-targets --release

.PHONY: invariants
invariants: ## Structural rules no unit test can express
	bash scripts/check-invariants.sh

.PHONY: asert
asert: ## Diff the Rust ASERT against the independent Python implementation
	python testing/reference/asert.py --selftest
	$(CARGO) test -p ferrum-consensus asert -- --nocapture

.PHONY: fuzz
fuzz: ## 60s each on the decoder and the script VM (needs nightly + cargo-fuzz)
	cargo +nightly fuzz run --fuzz-dir testing/fuzz decode -- -max_total_time=60
	cargo +nightly fuzz run --fuzz-dir testing/fuzz script -- -max_total_time=60

.PHONY: audit
audit: ## Check dependencies against the RustSec advisory database
	$(CARGO) audit

.PHONY: cov
cov: ## Coverage report (needs cargo-llvm-cov)
	$(CARGO) llvm-cov --workspace --html --open

# ---------------------------------------------------------------- run

.PHONY: run
run: build ## A single mining devnet node
	./target/release/chaind --network devnet --mine --datadir ./data --index

.PHONY: devnet
devnet: build ## Four-node devnet
	bash devnet/up.sh

.PHONY: devnet-down
devnet-down: ## Stop the devnet and delete its data
	bash devnet/down.sh --clean

.PHONY: e2e
e2e: build ## The full end-to-end test CI runs
	bash devnet/ci-e2e.sh

.PHONY: partition
partition: ## Split the running devnet in two
	bash devnet/partition.sh

.PHONY: heal
heal: ## Reconnect and watch the reorg resolve
	bash devnet/heal.sh

.PHONY: clean
clean: ## Remove build artefacts and devnet data
	$(CARGO) clean
	rm -rf devnet/data data
