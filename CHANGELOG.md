# Changelog

All notable changes to Ferrum are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Anything that changes encoding, hashing, script semantics, difficulty or validation is a **hard
fork** and is marked as such.

---

## [0.1.0] — unreleased

First release. A UTXO blockchain built from primitives: transaction model, canonical codec, hashing
scheme, script virtual machine, UTXO database with reorg support, difficulty controller, peer
network, two consensus engines, wallet, explorer, and the node that wires them together.

### Added

**Consensus and chain**
- UTXO ledger with per-block undo data from the first commit, so a reorganisation rolls the UTXO set
  backwards instead of replaying from genesis.
- `apply_block` as a pure function of `(pre-state, block, ctx)` — no clock, no RNG, no I/O, no
  floats, no hash-map iteration. Enforced mechanically by `clippy.toml` and
  `scripts/check-invariants.sh`, not by review.
- Fork choice by cumulative work, never height, with ties broken on the lower block hash so nodes
  that saw candidates in a different order still converge.
- ASERT (`aserti3-2d`) difficulty, integer-only, cross-checked in CI against an independent Python
  implementation over generated vectors.
- BIP-34 height commitment in the coinbase from genesis, closing the duplicate-coinbase-txid class
  (BIP-30 / CVE-2012-1909) permanently.
- `ConsensusEngine` trait with proof-of-work and a Tendermint-shaped BFT engine behind it. The BFT
  round machine is a pure state machine — events in, actions out — which is what keeps
  `ferrum-consensus` free of any dependency on `chain`, `storage` or the network.
- Scheduled PoW→BFT activation by height. No serialised structure changes across the fork, because
  the block seal lives outside the header.

**Cryptography and encoding**
- BLAKE3 derive-key domain separation with a frozen tag list; a test asserts pairwise distinctness so
  a new tag cannot be added without being covered.
- BIP-340 Schnorr over secp256k1. All 19 official test vectors, including the ten invalid cases.
- RFC 6962-shaped Merkle tree that **promotes** an odd node rather than duplicating it
  (CVE-2012-2459), with leaves and internal nodes domain-separated.
- Canonical Borsh encoding with a bijection tested in both directions, a typed transaction envelope
  with a reserved version byte, and an exactly-88-byte block header.
- BIP-32/39 with the official English wordlist, verified against its published SHA-256.
- bech32m addresses (not bech32 — BIP-350 fixed a checksum flaw Ferrum has no legacy reason to
  inherit).

**Script**
- Stack machine with hard limits from the first commit: 1000-byte scripts, 100-deep stack, 520-byte
  elements, 201 operations, no loops. The absence of loops is what makes gas metering unnecessary.
- BIP-143-shaped sighash committing to `chain_id` and the input value, so a testnet signature is
  rejected on mainnet and an offline signer knows what it is authorising.
- Push-only `script_sig` and the clean-stack rule as **consensus** rules, not policy.
- Templates: P2PK, P2PKH, P2SH, k-of-n multisig, CLTV timelock, HTLC.

**Storage, node and tooling**
- `redb` store: one atomic write transaction per block with the tip pointer written last, big-endian
  numeric keys, and an optional transaction/address reverse index that is not consensus state.
- libp2p networking over Noise and Yamux, with all five gossipsub defaults overridden — the 64 KiB
  default `max_transmit_size` alone would have made 1 MB blocks silently unsendable.
- Headers-first sync, fee-ordered mempool with orphan handling and reorg reconciliation.
- HD wallet with branch-and-bound coin selection and an encrypted keystore.
- JSON-RPC over HTTP and WebSocket, a REST surface, and a dependency-free block explorer served by
  the node itself.
- `chaind` and `chain-cli`; a four-node devnet harness with partition, heal, crash and fork
  rehearsal scripts.

### Verification
- A **reference executor** written from `docs/SPEC.md` alone, differentially tested against the
  production executor on every generated block — same verdict, same error variant, same state root.
  It imports the type vocabulary and none of the logic; that independence is what makes the
  differential mean anything.
- A determinism replay harness diffing state-root sequences against a golden file, in debug and
  release and cross-compiled to aarch64.
- `cargo-fuzz` targets on the decoder and the script VM. The decoder target asserts **bijectivity**,
  not just absence of panics.
- Adversarial scenario tests, each written red-then-green.
- Structural invariants no unit test can express: dependency direction, no unbounded channels, no
  floats, no wall-clock in the state-transition path.

### Fixed before release

- **ASERT anchor was fork-dependent.** *(hard fork relative to any earlier build)* The anchor was
  specified and implemented as "the block at height 1", resolved through
  `HeaderView::header_at_height`, which returns the **active chain**. Two nodes that sealed different
  height-1 blocks computed different required `bits` for each other's headers, rejected them as
  `BadDifficultyTransition`, and banned each other — permanently, because a header that fails
  validation never reaches fork choice. The anchor is now genesis, built from `ChainParams` alone, so
  difficulty is a pure function of the parent's height and timestamp. Found by running the four-node
  devnet, not by reading the code. See `docs/DECISIONS.md`.
- **Devnet parameters made the network unwatchable.** A `pow_limit` of `0x7fff…` accepted roughly
  half of all header hashes, so a node sealed its first block before libp2p had dialled anyone, and
  blocks outran gossip. Retuned to a measured block time, with spacing and half-life scaled to match.
  Mainnet and testnet parameters are unchanged.
- **Multiaddr flags were broken under Git Bash on Windows.** MSYS2 rewrote
  `/ip4/127.0.0.1/tcp/8655` into a Windows path, so every `--p2p-listen` and `--peer` failed. The
  devnet scripts now exclude arguments from that conversion.
- Findings from an eight-lens adversarial review — consensus split, inflation, script VM,
  reorg/storage, BFT safety, denial of service, key handling, and tests that pass without proving
  anything. Each surviving finding was fixed red-then-green.

### Known limitations

Stated because an honest changelog says what the software is not.

- **No security budget.** The network is small; anyone willing to rent enough hashrate can reorganise
  it. That is a property of a demonstration chain.
- **Not audited.** The reference executor, determinism harness, fuzzing and adversarial scenarios are
  a real testing programme, and they are not equivalent to two independent audits.
- **No light clients or bridges.** There is no state commitment in the header, so a state transition
  cannot be verified from headers alone. Every node fully validates.
- No replace-by-fee, no segregated witness, no merge-mining, no permissionless peer discovery. Each
  was considered and cut deliberately; see `docs/DECISIONS.md`.

[0.1.0]: https://github.com/rahuldhali/ferrum/releases/tag/v0.1.0
