# Build stage — cache dependencies separately from source so an edit to one
# crate does not rebuild 500 dependencies.
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Manifests first, with stub sources, so this layer is cached on dependency changes only.
COPY Cargo.toml Cargo.lock rust-toolchain.toml clippy.toml rustfmt.toml ./
COPY crates/types/Cargo.toml       crates/types/
COPY crates/crypto/Cargo.toml      crates/crypto/
COPY crates/script/Cargo.toml      crates/script/
COPY crates/storage/Cargo.toml     crates/storage/
COPY crates/consensus/Cargo.toml   crates/consensus/
COPY crates/chain/Cargo.toml       crates/chain/
COPY crates/mempool/Cargo.toml     crates/mempool/
COPY crates/p2p/Cargo.toml         crates/p2p/
COPY crates/rpc/Cargo.toml         crates/rpc/
COPY crates/wallet/Cargo.toml      crates/wallet/
COPY crates/node/Cargo.toml        crates/node/
COPY crates/cli/Cargo.toml         crates/cli/
COPY testing/sim/Cargo.toml        testing/sim/
COPY testing/e2e/Cargo.toml        testing/e2e/
RUN set -eux; \
    for d in crates/* testing/sim testing/e2e; do \
        mkdir -p "$d/src"; echo '' > "$d/src/lib.rs"; \
    done; \
    mkdir -p crates/cli/src/bin; \
    echo 'fn main() {}' > crates/cli/src/bin/chaind.rs; \
    echo 'fn main() {}' > crates/cli/src/bin/chain_cli.rs; \
    cargo build --release --bin chaind --bin chain-cli || true

COPY . .
# Touch the real sources so cargo does not reuse the stub build artefacts.
RUN find crates testing -name '*.rs' -exec touch {} + \
 && cargo build --release --locked --bin chaind --bin chain-cli

# Runtime stage — distroless-ish, no shell, no package manager, nothing to pivot to.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /var/lib/ferrum --shell /usr/sbin/nologin ferrum

COPY --from=builder /build/target/release/chaind    /usr/local/bin/chaind
COPY --from=builder /build/target/release/chain-cli /usr/local/bin/chain-cli
COPY --from=builder /build/explorer                 /usr/share/ferrum/explorer

USER ferrum
WORKDIR /var/lib/ferrum
VOLUME ["/var/lib/ferrum"]

# p2p, rpc, explorer, metrics
EXPOSE 8655 8645 8665 9100

HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -sf -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
      http://127.0.0.1:8645 || exit 1

ENTRYPOINT ["/usr/local/bin/chaind"]
CMD ["--network", "devnet", "--datadir", "/var/lib/ferrum"]
