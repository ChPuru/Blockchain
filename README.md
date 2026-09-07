<div align="center">

# Ferrum

**A UTXO blockchain written from scratch in Rust — stack-based script VM, ASERT difficulty,
proof-of-work with a live upgrade path to BFT consensus.**

[![CI](https://github.com/rahuldhali/ferrum/actions/workflows/ci.yml/badge.svg)](https://github.com/rahuldhali/ferrum/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)
[![Rust](https://img.shields.io/badge/rust-1.95-orange)](rust-toolchain.toml)

</div>

> **This is an experimental network.** The token is never sold, never priced, and never promised to
> appreciate. It exists to demonstrate that the thing works. Do not put anything of value on it.

---

## What this is

Every part of a working blockchain, built from primitives rather than assembled from libraries: the
transaction model, the canonical codec, the hashing scheme, the signature scheme's application, the
script virtual machine, the UTXO database with reorg support, the difficulty controller, the peer
network, the consensus engine, the wallet, the explorer, and the node that wires them together.

No forked codebase. No EVM. No framework. The only third-party cryptography is the secp256k1 curve
implementation and the BLAKE3/SHA-2 primitives — everything built on top of them is here.

```
 ┌──────────┐  ┌──────────┐  ┌──────────┐   cli ── chaind, chain-cli
 │  wallet  │  │   rpc    │  │   p2p    │   node ── sync, mining, telemetry, config
 └────┬─────┘  └────┬─────┘  └────┬─────┘
      │             │             │          consensus ── PoW · BFT, behind one trait
 ┌────┴─────────────┴─────────────┴────┐              (depends on types + crypto ONLY)
 │        chain  ·  mempool            │     chain ── validation, fork choice, reorg, ASERT
 └────┬─────────────┬──────────────────┘
 ┌────┴─────┐  ┌────┴─────┐  ┌──────────┐   storage ── redb: blocks, UTXO set, undo log
 │  script  │  │ storage  │  │consensus │   script ── the VM: opcodes, sighash, templates
 └────┬─────┘  └────┬─────┘  └────┬─────┘
      └─────────────┴─────────────┘          crypto ── tagged hashing, Schnorr, Merkle, BIP-32/39
              ┌──────────┐                   types ── the data model + canonical codec
              │  crypto  │                            (depends on nothing)
              └────┬─────┘
              ┌────┴─────┐
              │  types   │
              └──────────┘
```

The arrow direction is enforced by CI, not by convention. `ferrum-consensus` may depend on
`ferrum-types` and `ferrum-crypto` and nothing else — that single rule is what makes swapping
proof-of-work for BFT a configuration change instead of a rewrite.

---

## Quick start

```sh
git clone https://github.com/rahuldhali/ferrum && cd ferrum
cargo build --release

# a private chain on your laptop, mining immediately
./target/release/chaind --network devnet --mine --index --datadir ./data

# in another shell — the address is stdout, the mnemonic is stderr
./target/release/chain-cli wallet new
./target/release/chain-cli chain info
./target/release/chain-cli faucet request
./target/release/chain-cli wallet balance
./target/release/chain-cli wallet send --to rfer1... --amount 1.5
```

The explorer is on <http://127.0.0.1:8665>, the JSON-RPC on `127.0.0.1:8645`, p2p on
`0.0.0.0:8655`. Metrics are off unless you ask for `--metrics-listen`.

A four-node local network, including the partition-and-heal demonstration:

```sh
bash devnet/up.sh            # 4 nodes; node i: rpc 8645+i-1, explorer 8665+i-1
bash devnet/partition.sh     # split the network in two, both halves keep mining
bash devnet/heal.sh          # reconnect, watch the lower-work branch get reorged away
```

On a fast machine those four nodes may not converge, for reasons that are measured and written down
rather than waved away — see [`docs/RUNNING.md`](docs/RUNNING.md) §2 before you file a bug.

Full operator documentation, including running a public node: [`docs/RUNNING.md`](docs/RUNNING.md).
How a block actually travels through the code: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Genesis

Computed from `ChainParams` on every start, never read from a file. A joining node checks these
independently; if yours differ you are on a different chain, which is the check working.

| Network | Genesis block hash |
|---|---|
| mainnet | `6bfa4fee9e522a6071b5d7d04fc400144d9f519ba95b78d37346f7c597c4436c` |
| testnet | `9edeafc16709d76a957c0b11587881cb0161dd19069fc25025fbdc4b4ff6e516` |
| devnet  | `483bb2d9c173599d19dfbb8705c43ebf8ca0d44860889d50867b0c137d59aaf6` |

All three share `timestamp_ms = 1735689600000` (2025-01-01T00:00:00Z), `version = 1` and
`nonce = 0`; the 50 FRM subsidy is burned to an `OP_RETURN` committing to the network's parameters,
which is what stops mainnet and testnet — identical in every rule but `chain_id` and address prefix
— from sharing a genesis hash. The full field-by-field table is in
[`docs/RUNNING.md`](docs/RUNNING.md) §4.

---

## Design decisions worth defending

Most from-scratch blockchains are a hash-linked list with a proof-of-work loop bolted on. The
distance between that and something that survives contact with a second node is made of about ten
specific decisions. These are the ones that mattered here, each with the failure it prevents.

**Per-block undo data, from the first commit.** Every spent output is recorded — value, script,
height, coinbase flag — so a reorganisation rolls the UTXO set backwards instead of replaying from
genesis. Every tutorial surveyed for this project skips this, and it cannot be retrofitted: the
records for historical blocks do not exist, so adding it later forces a full reindex on every
deployed node.

**The Merkle tree promotes the odd node instead of duplicating it.** Duplicating makes `[a,b,c]` and
`[a,b,c,c]` hash identically, which lets an attacker turn a valid block into one that fails
transaction validation while keeping the header intact — CVE-2012-2459. Leaves and internal nodes are
domain-separated (RFC 6962 shape) so a 32-byte "transaction" cannot be presented as an inner node.

**ASERT difficulty, integer-only.** Bitcoin's 2016-block retarget is fatal for a small chain: rented
hashrate mines an epoch cheaply, leaves, and honest miners face a clamped difficulty for weeks.
ASERT is stateless with respect to recent history, has no oscillation mode, and self-corrects
manipulated timestamps. A float anywhere in this function would be a platform-dependent chain split,
so `f32`/`f64` are denied workspace-wide and an independent Python implementation is diffed against
the Rust one in CI.

**`chain_id` inside the signature preimage.** A testnet signature is rejected on mainnet. Ethereum
retrofitted this as EIP-155 after cross-chain replay cost users real money; it costs four bytes if
you do it on day one and is unfixable-in-place if you do not.

**BIP-340 Schnorr, not ECDSA.** 64-byte signatures, x-only keys — and the real reason: no DER
encoding and no low-`s` rule, so signature malleability simply does not exist. That is what lets
Ferrum have exactly one transaction serialisation and exactly one identifier, with no segregated
witness.

**Script limits in the first version of the interpreter.** Max script 1000 bytes, max stack 100, max
element 520 bytes, max 201 operations, no loops. Retrofitting a limit is how chains get halted. The
absence of loops is also what makes gas metering unnecessary — script cost is statically bounded and
the fee is just `sum(inputs) − sum(outputs)`.

**One atomic write per block, head pointer written last, big-endian keys.** Every ordered key-value
store sorts bytewise; little-endian height keys silently break range scans at block 256 — late
enough that a five-block test fixture passes.

**`Amount` implements no `Add` or `Sub`.** Only `checked_add`, `checked_sub`, `checked_mul_u64`. An
inflation bug cannot be written by accident; it has to be written on purpose, via `.to_grains()`,
which is greppable in review.

The full list, including what was deliberately *not* built and why, is in
[`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## How it is verified

There is no audit. There is this, ranked by how much it actually catches.

`cargo test --workspace --all-targets` runs **2304 tests across 53 test binaries**, all passing.
`cargo test --workspace --doc` is a separate command and adds **21 documentation tests** (1 ignored)
— `--all-targets` does not include them, so CI does not run them either; run it by hand before a
release. Both figures were measured, not estimated, and they move whenever tests are added; the
commands are the durable part.

The larger blocks, from that run: `ferrum-consensus` 213, `ferrum-node` 199, `ferrum-chain` 186,
`ferrum-rpc` 181, `ferrum-storage` 177, `ferrum-sim` 135, `ferrum-mempool` 106.

| | |
|---|---|
| **Reference executor** | A deliberately naive `apply_block` — `BTreeMap`, no caching — written from [`docs/SPEC.md`](docs/SPEC.md) rather than from the production code, run alongside the real executor on every simulated block. State roots must match. This is the single highest-value test asset in the project. |
| **Determinism replay harness** | Records `(pre_state, block)` pairs, replays them, and diffs the resulting state-root sequence against a golden file — in debug, in release, and cross-compiled to aarch64. The gate is itself verified: inserting `SystemTime::now()` into the executor must turn CI red. |
| **Fuzzing** | Two targets, on the two places unauthenticated bytes land: the decoder and the script VM. |
| **Adversarial scenarios** | Ten, each written red-then-green, one file each under `testing/sim/src/scenarios/`: timestamp manipulation across a retarget, a 100-block invalid side chain, a double-spend inside one block, output-sum overflow, cross-chain signature replay, a block engineered to be expensive to validate, a reorg deeper than the mempool's memory, a coinbase overpaying by one grain, a duplicate-txid block (BIP-30), and non-minimal script number encodings. |
| **Multi-node e2e** | Two of them. `testing/e2e` runs four real `Node`s in one process, over real TCP, real Noise, real gossipsub and real `redb` stores, on every `cargo test`. `devnet/ci-e2e.sh` runs four real `chaind` **processes** in CI — the same properties, but with a real command line and a real `SIGKILL`, which is the part an in-process harness cannot fake. Both partition the network, mine both sides, heal, and require every node to converge on one tip hash. `crates/p2p/tests/two_node.rs` covers the transport on its own. |
| **Property tests** | Codec round-trip in *both* directions, UTXO apply/rollback as an exact inverse, the interpreter never panicking, the compact-target codec being idempotent. |
| **Structural invariants** | `scripts/check-invariants.sh` — dependency direction, no unbounded channels, no floats, no wall-clock in the state-transition path, no `mplex`, no `todo!()`. Things no unit test can express. |

The second row is the one usually missing elsewhere. `decode(encode(v)) == v` passes happily on a
codec that accepts three byte strings for one value; only `encode(decode(b)) == b` catches it, and
only that direction protects the transaction id.

---

## Repository layout

```
crates/
  types/        the data model and canonical Borsh codec — depends on nothing
  crypto/       domain-tagged BLAKE3, BIP-340 Schnorr, Merkle, BIP-32/39, bech32m addresses
  script/       the VM: opcodes, interpreter, sighash, standard templates
  storage/      redb tables, atomic block commit, undo log, UTXO set, reverse index
  consensus/    the ConsensusEngine trait + PoW + BFT — depends on types and crypto only
  chain/        validation, the determinism seam, fork choice, reorg, ASERT
  mempool/      fee-ordered pool, orphan pool, eviction, reorg reconciliation
  p2p/          libp2p: noise + yamux + gossipsub, static peers, sync protocol
  rpc/          JSON-RPC over HTTP and WebSocket, plus the explorer REST surface
  wallet/       mnemonic, HD derivation, coin selection, transaction building, signing
  node/         wiring, headers-first sync, mining loop, config, telemetry
  cli/          chaind and chain-cli
testing/
  sim/          deterministic simulator, reference executor, adversarial scenarios
  fuzz/         cargo-fuzz targets (a separate crate: nightly + a sanitizer, never in a normal build)
  e2e/          in-process multi-node harness: real nodes, real TCP, real gossip
  reference/    the independent Python ASERT implementation and its vectors
explorer/       the static block explorer and faucet page, compiled into chaind
devnet/         Dockerfile, docker-compose, and the up / status / partition / heal / kill / fork scripts
docs/           CONTRACT · SPEC · ENCODING · RUNNING · ARCHITECTURE · DECISIONS
```

`docs/CONTRACT.md` is normative — exact names, exact signatures, exact algorithms. If an
implementation and the contract disagree, the contract wins and the implementation is a bug.

---

## What this deliberately does not do

An honest README says what it is not.

- **No light clients or bridges.** There is no state commitment in the 88-byte header, so a light
  client cannot verify a state transition from headers alone. Every node fully validates.
- **No smart contracts** beyond the script templates. No loops, no gas, no general computation.
- **No replace-by-fee**, no segregated witness, no merge-mining.
- **No permissionless peer discovery.** Peers come from a config file. Kademlia, discv5, AutoNAT and
  relay all defend discovery *under attack*; a network with a static peer list has no such problem.
- **No security budget.** The network is small. Anyone willing to rent enough hashrate can
  reorganise it. That is a property of a demonstration chain, and it is not a bug.

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md), then [`docs/CONTRACT.md`](docs/CONTRACT.md). Before
opening a pull request:

```sh
make check      # fmt-check, clippy -D warnings, the whole test suite, then the invariants
```

or, without `make`:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
bash scripts/check-invariants.sh
```

`make help` lists the rest: `make run` for one mining devnet node, `make devnet` for four,
`make e2e` for the four-process end-to-end test and `make e2e-fast` for its in-process
equivalent (which `cargo test --workspace` already runs), `make asert` to diff the Rust ASERT
against the Python reference, `make fuzz` for a 60-second run on each fuzz target.

Security reports: [`SECURITY.md`](SECURITY.md).

## Licence

MIT or Apache-2.0, at your option.
