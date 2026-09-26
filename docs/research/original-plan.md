# Build a Blockchain from Scratch in Rust — UTXO + Script VM + PoW→PoS, Shipped Live

## Context

`D:\Blockchain_Crypto` is empty. Purunjay wants to build a blockchain/cryptocurrency from scratch and
asked for exhaustive research on how, supplying ~21 build-your-own-blockchain tutorials as reference.

**What this is, in his words:** *"i just want to build this to showoff, even the smallest scale, toy
type made for fun also works, just to show that yes we know how to build it from scratch and make it
go live and ship it, just as a project, nothing serious."*

Target: **a portfolio-grade chain that genuinely works and genuinely runs live** — not a commercial
L1. That removes audits, tokenomics, exchange listings, security budget, validator recruitment and
FIU registration, and leaves the half that is interesting to build and impressive to show.

A deep-research workflow (18 dimensions, 44 agents, 713 primary sources, 4.9M tokens) informs
every decision below. Where its recommendations were written for a funded team, they have been
deliberately overridden and the override is marked.

### Confirmed decisions

| Decision | Choice |
|---|---|
| Language | **Rust** (1.95.0 installed) |
| Ledger model | **UTXO** |
| Contracts | **Own stack-based script VM** |
| Consensus | **PoW first, then BFT** — both behind one `ConsensusEngine` trait |
| Purpose | Learning vehicle that ships publicly |

### Why these two choices are better together than I first said

I warned that UTXO + a custom VM is painful. That is true for an *Ethereum-style general-purpose*
VM; it is false here. **A UTXO ledger with a stack-based script VM is Bitcoin Script**, and the
pairing removes the hardest problem in the whole project: **you do not need gas metering.** Script
cost is bounded by static limits (max ops, max stack, max script size, no loops), and the fee is
simply `sum(inputs) − sum(outputs)`. Ethereum needed ten years and four repricing hard forks
(EIP-150, EIP-1884, EIP-2929, EIP-7825) to get gas right. You get to skip that entire category.

### The real trade-off that remains

A custom VM and address format mean **no MetaMask, no Solidity, no Foundry, no Blockscout.** For a
commercial chain that is fatal; here the tooling you build *is* the portfolio. The plan budgets
explicitly for a CLI wallet, an explorer and a faucet, because without them "it's live" is not
demonstrable.

### Honest effort budget

At ~10–12 hrs/week: **M0–M8 (live PoW network) ≈ 195–275 hrs ≈ 5–7 months.** Adding the BFT engine
and the live PoW→PoS fork ≈ **270–400 hrs ≈ 7–10 months.** These are the real numbers; the research
corpus's own "person-week" estimates hide a 3–4 year mainnet timeline for a full L1, which is
exactly the scope this project is refusing.

---

## Recommended approach

One Cargo workspace, one crate per subsystem, hard interface boundaries so the PoW engine swaps for
BFT without touching storage, networking or the VM.

### The five decisions that are genuinely irreversible — do these first, they cost ~1 day total

Everything else is a hard fork, and a hard fork on a chain you control every node of is a Tuesday
evening. These five are not:

1. **Freeze the domain-separation tag list** (~2 hrs). One tag per hash context: `txid`, `sighash`,
   `header`, `merkle/leaf`, `merkle/node`, `address`, `script`. Test that no two collide. Without
   this, a signature over a vote can be replayed as a transaction.
2. **Put `chain_id` + `tx_version` inside the sighash preimage** (~1 hr). Write the test that a
   testnet signature is rejected on mainnet. EIP-155 is the canonical example of what retrofitting
   this costs.
3. **The determinism seam** (1–2 days). `apply_block(pre: &dyn StateView, block: &Block, ctx: &BlockCtx)`
   as a pure function. No `SystemTime::now`, no `rand`, no floats, no `HashMap` iteration, no I/O.
   Enforce mechanically via `clippy.toml` `disallowed-methods`/`disallowed-types`, not code review.
   Retrofitting costs 5–20×.
4. **Canonical codec via Borsh** (2 days) — *not* hand-rolled. Borsh documents a bijective
   object↔bytes mapping, which is the property you actually want; hand-writing a codec is 1–2 weeks
   and historically produces the bugs it claims to prevent. Round-trip proptest both directions.
5. **Typed transaction envelope with a reserved version byte** (~2 hrs). `type_byte(1) || borsh(tx)`,
   type in `[0x00,0x7f]`, `0xff` reserved. One byte bought Ethereum four transaction types years later.

### Overrides applied to the research corpus

The corpus recommends things sized for a funded team. These are deliberately cut:

| Corpus said | This plan does | Why |
|---|---|---|
| AuxPoW merge-mining from genesis | **Skip** | Multi-week protocol; only pays off if a Bitcoin pool agrees to merge-mine you. They won't. |
| Kademlia + discv5 + AutoNAT + DCUtR + relay + addrman port | **Static peer list + gossipsub** | All of it defends permissionless discovery under attack. A 5-node chain with a config file has no such problem. Saves 4–8 weeks. |
| Blockscout (9 containers, 128 GB RAM recommended) | **Own reverse index + 3 JSON routes + one static page** (~2–3 days) | Blockscout's *Sepolia* DB is 5.2 TB. Absurd for a few hundred transactions. |
| 17-table reth storage schema | **6 tables** | reth's schema serves archive nodes and 100 GB+ state. |
| Two audits from two firms + remediation pass | **A naive reference executor differential-tested against production** | $100–300k vs 2 weeks. The reference executor is the single highest-value item in the corpus for a solo builder. |
| MMR for header history, JMT sparse tree, snap-style sync | **Sorted-map binary Merkle (~200 lines), block-by-block sync** | Serve light clients and bridges you are not building. |
| Stratum V1 bridge, BIP-152 compact blocks | **Defer to M11** | Blocks are small; a JSON-RPC `getblocktemplate` is enough for a demo miner. |

### Non-negotiable design decisions (what toys get wrong)

1. **Per-block undo data.** Store every spent output (value, script, height, is_coinbase) so reorgs
   roll the UTXO set backwards. Every one of the 21 supplied tutorials skips this — jeiwan's series,
   the best of them, carries the author's own TODO *"Instead of trusting unconditionally, we should
   validate every incoming block."* Adding undo data later forces a full reindex of every deployed node.
2. **CVE-2012-2459 in the Merkle tree.** Never duplicate the odd node — **promote** it. Domain-separate
   leaves (`0x00`) from internal nodes (`0x01`), RFC 6962 shape. Bitcoin Core's `consensus/merkle.cpp`
   literally contains a comment addressed to people building new systems warning about this.
3. **ASERT (`aserti3-2d`) difficulty, integer-only.** Bitcoin's 2016-block retarget is fatal for a
   small chain — rented hashrate mines an epoch cheap, leaves, and honest miners face clamped 4×
   difficulty for weeks. ASERT is stateless w.r.t. recent history, has no oscillation mode, and
   self-corrects manipulated timestamps. Set `halflife = N × T × ln2` with N ∈ [50,100]; at T=120 s
   that is **halflife = 7200**. Never use floating point here — it is a platform-dependent chain split.
4. **BIP-340 Schnorr, not ECDSA.** 64-byte signatures, x-only keys, batch verification, and — the
   real reason — no DER encoding and no low-s rule, so signature malleability simply does not exist.
5. **Script VM hard limits from the first commit.** Max script 1000 B, max stack 100, max element
   520 B, max ops 201, no loops. Retrofitting limits is how chains get halted.
6. **One atomic write transaction per block**, head pointer written last *inside* it. Big-endian
   numeric keys — every ordered KV store sorts bytewise, and LE keys silently break range scans at
   block 256.

---

## Architecture

### Workspace layout

```
D:\Blockchain_Crypto\
  Cargo.toml                 # workspace; edition 2024, [workspace.dependencies], [workspace.lints]
  rust-toolchain.toml        # exact channel pin
  crates/
    types/                   # Hash32, Address, Amount, OutPoint, TxIn, TxOut, Transaction,
                             #   BlockHeader, Block + Borsh derives. Depends on nothing.
    crypto/                  # blake3 domain-tagged hashing, k256 Schnorr, merkle, BIP-32/39
    script/                  # the VM: opcodes, interpreter, sighash, standard templates
    storage/                 # redb tables, atomic block commit, undo log
    chain/                   # validation, state transition, fork choice, reorg, ASERT
    consensus/               # ConsensusEngine trait + pow + (M9) bft. Depends on types+crypto ONLY.
    mempool/                 # fee-ordered pool, orphan pool, eviction, reorg reconciliation
    p2p/                     # libp2p: noise + yamux + gossipsub, static peers
    rpc/                     # jsonrpsee HTTP+WS
    wallet/                  # mnemonic, derivation, coin selection, tx building, signing
    node/                    # wiring, headers-first sync, config, telemetry
    cli/                     # bins: `chaind` (node), `chain-cli` (wallet/admin)
  testing/{sim,fuzz,e2e}
  explorer/                  # static page + faucet over the node's own index
  devnet/                    # docker-compose, genesis.json, fork/kill scripts
  docs/                      # ENCODING.md, SPEC.md, RUNNING.md
```

**Dependency direction is enforced, not suggested:** add a CI check that fails if `consensus` ever
gains a dependency on `chain` or `storage`. That single rule is what makes the PoW→PoS swap a config
change instead of a rewrite.

### Core types

```rust
struct OutPoint    { txid: Hash32, vout: u32 }
struct TxIn        { prev_out: OutPoint, script_sig: Script, sequence: u32 }
struct TxOut       { value: u64, script_pubkey: Script }
struct Transaction { version: u32, inputs: Vec<TxIn>, outputs: Vec<TxOut>, lock_time: u32 }

// 88 bytes fixed. u64 ms timestamp, not u32 seconds — Bitcoin's field overflows in 2106.
// 8-byte nonce gives ample search space without extranonce rolling.
struct BlockHeader { version: u32, prev_hash: Hash32, merkle_root: Hash32,
                     timestamp_ms: u64, bits: u32, nonce: u64 }
struct Block       { header: BlockHeader, txs: Vec<Transaction> }
```

### The seam that makes PoW→PoS a config change

```rust
trait ConsensusEngine: Send + Sync {
    fn validate_header(&self, h: &BlockHeader, parent: &BlockHeader, ctx: &ChainCtx) -> Result<()>;
    fn seal(&self, tmpl: BlockTemplate, cancel: &AtomicBool) -> Result<Block>;  // mine / propose
    fn work(&self, h: &BlockHeader) -> U256;                                    // fork-choice weight
    fn finalized_height(&self, ctx: &ChainCtx) -> Option<u64>;                  // None for PoW
}
```

- `pow::PowEngine` — nonce grind; `work = (!target / (target + 1)) + 1`; fork choice by **cumulative
  work, never height**.
- `bft::BftEngine` (M9) — Tendermint-shaped propose→prevote→precommit, permissioned validator set
  from genesis, `n ≥ 3f+1`, quorum `2f+1`, minimum **4 validators**. Returns `Some(height)`, and
  reorg stops existing as a concept above consensus.

### Script VM

Stack machine over UTXO scripts. `script_sig` then `script_pubkey`; push-only `script_sig` enforced
as a consensus rule (simpler than Bitcoin's standardness split).

- **Opcodes:** `OP_0..OP_16`, pushdata, `OP_DUP OP_DROP OP_SWAP`, `OP_HASH256 OP_HASH160`,
  `OP_EQUAL OP_EQUALVERIFY OP_VERIFY`, `OP_CHECKSIG OP_CHECKSIGVERIFY OP_CHECKMULTISIG`,
  `OP_CHECKLOCKTIMEVERIFY OP_CHECKSEQUENCEVERIFY`, `OP_IF OP_ELSE OP_ENDIF`, `OP_ADD OP_SUB
  OP_LESSTHAN OP_GREATERTHAN`, `OP_RETURN`.
- **Templates:** P2PK, P2PKH, P2SH, k-of-n multisig, timelock (HTLC-shaped) — the last two are what
  make the demo interesting.
- **Sighash (BIP-143 shape, not legacy):** commits to `chain_id`, tx version, `hash(all outpoints)`,
  `hash(all sequences)`, `hash(all outputs)`, this input's outpoint, script code, **input value**,
  sequence, locktime, sighash type. Legacy Bitcoin sighash is O(n²) and a known DoS vector — there is
  no reason to reproduce it.

### Storage — 6 tables (redb)

| Prefix | Key → Value | Purpose |
|---|---|---|
| `b:` | block hash → block bytes | block store (all forks, not just canonical) |
| `h:` | block hash → header + height + cumulative work + status | fork tree |
| `n:` | be_u64(height) → block hash | active-chain index |
| `u:` | outpoint → value, script, height, is_coinbase | **the UTXO set** |
| `d:` | block hash → spent outputs, in order | **undo data — enables reorg** |
| `m:` | key → value | tip, chain_id, schema_version |

**redb over RocksDB deliberately:** pure Rust, no clang/bindgen. You develop on Windows; RocksDB's
build chain there is a recurring source of lost evenings.

### Verified dependency pins (as of 2026-08-30)

The research corpus gave *conflicting* pins across four briefs. This is the single table; nothing
else restates it.

| Role | Crate | Version | Note |
|---|---|---|---|
| Curve / Schnorr | `k256` | 0.14.0 | Pure Rust, `schnorr` feature = BIP-340. Swap to `secp256k1` 0.33.0 (C bindings, faster) only if profiling demands it |
| Hashing | `blake3`, `sha2` | current | BLAKE3 `derive_key(context, data)` gives domain separation for free |
| Codec | `borsh` | 1.8.1 | Bijective mapping is the guarantee you want |
| Storage | `redb` | 4.2.0 | MVCC, ACID, savepoints, no C toolchain |
| P2P | `libp2p` | 0.56.0 umbrella | `libp2p-gossipsub` is 0.49.5 — sub-crates ship independently, pin both |
| Runtime | `tokio` | 1.53.1 | |
| RPC | `jsonrpsee` | 0.26.0 | What reth pins |
| CLI / logs | `clap` 4.6.6, `tracing` 0.1.44 | | |
| Tests | `proptest`, `cargo-fuzz`, `turmoil` 0.7.2 | | turmoil now covers net + fs + torn writes |

Pin exactly. Do not chase. Upgrade only on a security advisory or a deliberate quarterly window.

### The five rust-libp2p defaults that will silently break you

From `protocols/gossipsub/src/config.rs` — override all of these on day one of M6:

1. `max_transmit_size = 65536` — **your blocks are silently unsendable.**
2. Default message-id is `base58(peer_id) || seqno` — causes duplicate storms. Use a content hash.
3. `mesh_n_low = 5` (spec says 4), `duplicate_cache_time = 60s`, `heartbeat_interval = 1s`.
4. Yamux window is **256 KiB** — a throughput ceiling; at 80 ms RTT one stream caps near 3 MB/s.
5. **Never offer mplex** — the libp2p spec deprecates it outright for liveness.

Also wire the signature verifier to gossipsub's **P₄ (invalid message) score component**. That one
hookup is the cheapest DoS defence available and takes an afternoon.

---

## Milestone ladder

Ship gate is **M8**. M9–M11 are upside.

| # | Milestone | Definition of done — a command you can run | Est. |
|---|---|---|---|
| M0 | Workspace, toolchain pin, lints, crypto | `cargo test -p crypto` — domain-tagged hashing, Schnorr sign/verify, merkle with the CVE-2012-2459 regression test, BIP-32/39 vectors | 10–15 h |
| M1 | Types + Borsh codec + golden vectors | Round-trip proptest **both directions**; 1000 encodings of one value → exactly 1 unique hash; `docs/ENCODING.md` written *before* the encoder | 10–15 h |
| M2 | Script VM | `chain-cli script-eval` runs P2PKH, 2-of-3 multisig, CLTV timelock; limit tests reject oversized/deep/looping scripts; fuzz target finds no panic | 25–35 h |
| M3 | Storage + UTXO set + undo log | Apply then roll back a block → UTXO set **byte-identical**; `kill -9` mid-write 50 times → 50 consistent restarts | 25–35 h |
| M4 | Single-node PoW chain | `chaind --mine` climbs; ASERT holds block time within 2× after a 10× hashrate spike *and* collapse; forced 6-block reorg → state identical to genesis replay | 30–40 h |
| M5 | Mempool + wallet + RPC | Create wallet → mine coinbase → send tx → see it confirmed → balance from the UTXO set, never by rescan | 30–40 h |
| M6 | **Multi-node P2P network** | `devnet/up.sh` starts 4 nodes; tx submitted to node 1 mines on node 3; kill a node → it re-syncs; **partition the network, mine both sides, heal, watch the reorg resolve** ← the money shot | 40–60 h |
| M7 | Explorer + faucet + docs | `/block/:h`, `/tx/:hash`, `/address/:addr` (EIP-3091 route shape) over your own reverse index; one static page; faucet; README a stranger can follow | 25–35 h |
| M8 | **GO LIVE** | 3 seed nodes on real VPSs in 3 regions, public RPC + explorer + faucet on a domain, genesis hash published, a stranger syncs from genesis with zero manual steps | 15–25 h |
| M9 | BFT engine | Same binary, `--consensus bft`, 4 validators: kill 1 → continues; kill 2 → **halts**, and you can explain why halting is correct | 60–100 h |
| M10 | **The PoW→PoS hard fork, on the live chain** | Fork activates at a scheduled timestamp; the live network transitions consensus engines without losing history. This is the single most impressive thing in the project | 20–30 h |
| M11 | Optional polish | Stratum bridge, BIP-152 compact blocks, light client, Grafana dashboard, demo video | — |

---

## Verification

Ranked by leverage, because test infrastructure is where solo projects disappear:

1. **Determinism seam + replay harness (M1–M3, ~3 days).** Record `(base_version, block)` pairs; replay
   produces a state-root sequence; diff against a golden file. Run in CI in **debug, release, and
   cross-compiled to aarch64**. Verify the gate works by deliberately inserting `SystemTime::now()`
   into the executor and confirming CI goes red. This is the highest-value test asset in the project.
2. **Reference executor differential (M4, ~2 weeks).** A deliberately naive `apply_block` written from
   `docs/SPEC.md` with a `BTreeMap` and no caching, run alongside production on every block and every
   fuzz input. State roots must match. This is your substitute for a $100–300k audit.
3. **Fuzz exactly one target: the decoder** (`cargo-fuzz`, ~1 day to wire). That is where
   unauthenticated bytes from anonymous peers land. Run before releases, not nightly.
4. **`devnet/` docker-compose with N nodes** (~2 days) plus a kill/restart/partition script. Assert all
   nodes converge on the same tip hash over 500 blocks.
5. **Property tests** (`proptest`): codec round-trip both directions; UTXO apply/rollback is an exact
   inverse; the script interpreter never panics on arbitrary bytes; compact-`bits` codec is idempotent.
6. **Adversarial scenarios, each red-then-green:** timestamp manipulation across a retarget; a 100-block
   invalid chain; double-spend inside one block; output-sum overflow; cross-chain replay; a block
   engineered to take 90 seconds to validate.
7. **Live check (M8):** a fresh machine syncs from genesis to tip via the public seeds, from your own
   published instructions, with no manual steps. Re-run weekly — a chain that quietly becomes
   unjoinable is dead and its dashboards stay green.

Skip: EEST-shaped fixture suites, Hive, `loom`, Quint model checking, randomised manifest generators.
All have near-zero value with a single implementation and one engineer.

---

## Risks and the ship gate

| Risk | Mitigation | When |
|---|---|---|
| Reorg handling wrong — *the* classic toy-chain failure | Undo log at M3, reorg test in CI from M4 | M3 |
| Consensus split from non-canonical encoding | Borsh + `ENCODING.md` + bidirectional round-trip proptest | M1 |
| Float in the difficulty algorithm → platform-dependent split | Integer-only ASERT; independent Python reference diffed over 200k synthetic headers | M4 |
| Script VM as a DoS surface | Hard limits at first commit + fuzz target | M2 |
| Sync DB calls on the async runtime → 2-second p95 latency | Route every redb call through `spawn_blocking`; grep for direct DB calls in `async fn` | M3 |
| Unbounded channels → OOM instead of load-shed | Zero `unbounded_channel()` in the node; explicit capacity constants | M6 |
| Scope creep into a real L1 | M8 declared shippable; M9–M11 optional | always |
| Solo operator asleep 90% of the time | PoW has no liveness obligation, so a halt is impossible by construction. For M9's BFT phase, document a maximum acceptable halt ("this chain may halt for up to 24 h; it will never fork") and alert at exactly two severities: *halted, fix within a day* and *ignore until the weekend* | M9 |

**Running cost:** 3× small VPS (Hetzner CX22 ≈ $4/mo each, or Oracle free-tier ARM) + a domain +
Cloudflare free ≈ **$15–25/month**. The research corpus's $465/mo "lean floor" assumes archive nodes,
Blockscout and an indexer — all cut above.

**Legal, kept short because "nothing serious" makes it short.** A public experimental network whose
token is never sold, never priced and never promised to appreciate is an engineering demo. To keep it
that way: label it experimental in the README and on the explorer, never run a sale or presale, never
promise returns, don't seek listings, custody nothing for anyone, put a disclaimer on the faucet, and
use MIT or Apache-2.0 (never BUSL — the moat expires in four years and it makes the repo radioactive
to every reviewer). Do not incorporate anything offshore. If money ever changes hands, India's VDA
regime (30% under s.115BBH, 1% TDS under s.194S) and FIU-IND registration become live questions for a
CA and a lawyer — that is a different project.

---

## Reading path (12 weeks, interleaved with M0–M6)

Verified against the actual repos and source files, not reputation.

**Type these three, in this order:** jeiwan.net's Go series, **all 7 parts** (the only tutorial in
your list with UTXO + persistence + addresses + Merkle + a wire protocol); yukimotopress's Ruby
chapters (one evening, then discard — best on-ramp); Programming Bitcoin ch. 1–4 by hand, then
**delete it** and link `k256`.

**Skim four:** lhartikk's TypeScript naivecoin ch. 1–5 (the only one that ranks chains by *work*, not
length); conradoqg/naivecoin for its API/operator split; nambrot/blockchain-in-js steps 4–7 (caches a
UTXO pool per block — the correct "block = state transition" model); freeCodeCamp's Scala/Akka for
node structure only (substitute Apache Pekko — Akka went BSL in 2022).

**Skip twelve**, including both HackerNoon entries, Smashing Magazine, mycoralhealth, the Crystal and
Kotlin and ATS entries, "Tiniest Blockchain", and van Flymen's Python — whose `/mine` computes the
proof from the *previous* block and then sweeps in whatever transactions are pending, so a miner
solves once and chooses the transaction set for free.

**What the list is missing, and what actually matters:** the Bitcoin whitepaper (twice), *Mastering
Bitcoin* 3rd ed (2023 — the 2017 2nd ed predates Taproot), *Building Bitcoin in Rust* (Hozda 2024,
free PDF, the best modern from-scratch book), and reading real source: Bitcoin Core v31.1
`validation.cpp` / `pow.cpp` / `consensus/merkle.cpp`, and reth v2.5.1's `eth-wire` and storage
tables. Also `rust-state-machine` (42 steps, Polkadot-inspired, everything written from scratch).

Full source list: 713 URLs in the research output at
`C:\Users\Lenovo\AppData\Local\Temp\claude\D--Blockchain-Crypto\a52c4063-736f-46db-8249-12414f48bd4f\tasks\wapdczg59.output`.

---

## First session after approval

1. `cargo new --lib` the workspace skeleton with all 12 crates as empty modules in dependency order,
   plus `rust-toolchain.toml`, `[workspace.lints]` (`await_holding_lock = "deny"`,
   `unwrap_used = "deny"`, `arithmetic_side_effects = "deny"` on `chain`/`script`), and the CI check
   that `consensus` never depends on `chain`.
2. Write all six trait definitions with `todo!()` bodies and make the workspace compile.
3. Write `docs/ENCODING.md` — field order, integer endianness, fixed widths, the frozen domain-tag
   list — **before** any encoder exists.
4. M0: `crypto` crate green, including the CVE-2012-2459 Merkle regression test.
