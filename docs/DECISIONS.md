# Decision log

Decisions a reader would otherwise have to reverse-engineer, with the reasoning that produced them.
Entries are append-only; a superseded entry is marked, not deleted.

---

## D1 — Dependency pins differ from the research corpus, deliberately

The research pass verified that `k256` 0.14.0, `redb` 4.2.0, `libp2p` 0.56.0, `jsonrpsee` 0.26.0 and
`sha2` 0.11 exist. They do. They are not what this workspace uses.

The reason is coherence, not conservatism. `k256` 0.14 sits on the RustCrypto `digest` 0.11
generation; `sha2` 0.10, `ripemd` 0.1, `hmac` 0.12 and `pbkdf2` 0.12 sit on `digest` 0.10. Mixing
generations breaks trait bounds across the whole crypto crate, so the choice is all-or-nothing — and
the newer generation buys this project nothing. BIP-340 Schnorr, PBKDF2 and RIPEMD-160 are the same
algorithms either way.

The workspace therefore pins one coherent generation — `k256` 0.13, `sha2` 0.10, `ripemd` 0.1,
`hmac` 0.12, `pbkdf2` 0.12 — plus `redb` 2.x, `libp2p` 0.55 and `jsonrpsee` 0.24. Every one is an
actively maintained release, and `Cargo.lock` is committed, which is what actually pins them.

**Revisit when:** a security advisory lands against any of them, or at a deliberate quarterly upgrade
window. Upgrade the whole RustCrypto set in one pull request, never piecemeal.

---

## D2 — The block seal lives outside the header

`BlockHeader` is exactly 88 bytes and contains no consensus-engine-specific field. A BFT commit
certificate is carried in `Block::seal`, outside both the header and `merkle_root`.

This is not laziness about the header layout — it is forced. A commit certificate is formed *after*
the header exists and cannot commit to itself. Keeping it out of the header also means the block hash
is identical no matter which `2f+1` subset of signatures a given node happened to collect, which is
what makes the certificate non-malleable in practice.

The consequence is that the PoW→BFT hard fork at M10 changes no serialised structure at all. It is a
dispatcher choosing a different `ConsensusEngine` above an activation height.

---

## D3 — There is no state root in the header

The header has no room, and adding one would break D2's property that the fork changes no structure.

`Store::state_root()` computes a sorted binary Merkle over the whole UTXO set on demand. It is used
by the determinism replay harness, by the reference-executor differential, and by the `getstateroot`
RPC. It is **not** consensus state.

The cost is real and is stated rather than hidden: a light client cannot detect an invalid state
transition from headers alone. Every Ferrum node fully validates. A chain that wanted light clients
or bridges would need a commitment in the header, and that would be a hard fork.

---

## D4 — Milliseconds in the header timestamp

`timestamp_ms: u64`, not Bitcoin's `u32` seconds. Bitcoin's field overflows in 2106 and its
successors have to fork around it. Eight bytes costs 4 bytes per header now and removes the problem
permanently.

Median-time-past and locktime comparisons are still done in **seconds**, because `LOCKTIME_THRESHOLD`
and the CLTV/CSV semantics are defined that way, and reproducing them exactly is worth more than
consistency of units.

---

## D5 — Hashes display in natural byte order

Bitcoin displays transaction and block hashes byte-reversed, an accident of its internal
little-endian integer representation leaking into RPC output. Ferrum does not reverse. `Display`,
`FromStr`, the RPC and the explorer all use the order the bytes are hashed in.

The cost is that a Ferrum hash cannot be pasted into a Bitcoin tool. That was never going to work.

---

## D6 — No RBF, no Kademlia, no merge-mining, no Blockscout

Each was considered and cut. Each cut is a scope decision, not an oversight:

- **Kademlia / discv5 / AutoNAT / relay** defend permissionless peer discovery under attack. A
  network with a static peer list in a config file has no such problem. Saves four to eight weeks.
- **AuxPoW merge-mining** only pays off if a Bitcoin mining pool agrees to merge-mine you.
- **Blockscout** recommends 128 GB of RAM and its Sepolia database is measured in terabytes. Ferrum
  serves three JSON routes and one static page from its own reverse index.
- **Replace-by-fee** adds a mempool policy surface and a whole class of tests for no demonstrable
  benefit on a chain with empty blocks. Documented as absent, not forgotten.

---

## D7 — `Amount` has no `Add` or `Sub`

`Amount` exposes only `checked_add`, `checked_sub` and `checked_mul_u64`. There is deliberately no
operator overload, so an inflation bug cannot be written by accident — it has to be written on
purpose, by calling `.to_grains()` first, which is greppable.

This is the cheapest available defence against the worst bug class a currency can have.

---

## D8 — Undo data is stored per block, from the first commit

Every spent output is recorded — value, script, height, coinbase flag — so a reorg rolls the UTXO set
backwards instead of replaying from genesis.

Every from-scratch tutorial surveyed for this project skips this. It cannot be added later without
forcing a full reindex on every deployed node, because the undo records for historical blocks simply
do not exist. It is cheap on day one and impossible on day four hundred.

---

## D9 — ASERT rather than a Bitcoin-style epoch retarget

Bitcoin retargets every 2016 blocks. On a chain with no security budget that is fatal: rented
hashrate mines an epoch cheaply, leaves, and honest miners face a clamped 4× difficulty for weeks
with no way out.

`aserti3-2d` is stateless with respect to recent history, has no oscillation mode, and self-corrects
manipulated timestamps. It is integer-only here — a float in this function is a platform-dependent
chain split — and an independent Python implementation in `testing/reference/asert.py` is diffed
against the Rust one over synthetic vectors in CI.

---

## D10 — Script has hard limits from the first commit

Max script 1000 bytes, max stack 100, max element 520 bytes, max 201 operations, no loops. These are
present in the first version of the interpreter, not added once a denial-of-service report arrives.

Retrofitting a limit is how chains get halted: every historical block that violated the new limit
becomes invalid, so the limit has to be soft-forked in at a height, and the pre-fork blocks stay
expensive forever.

---

## D11 — The genesis commitment covers the fork schedule

`genesis_commitment` hashes `bft_activation_height` and the ordered `bft_validators` list along with
the monetary and difficulty parameters. Both are loaded per node from `--consensus-config`, and both
decide *which engine validates every block* at and above the activation height; the validator order
is consensus in its own right, because the proposer rotation and every commit signature index are
positional.

Before this, two nodes with different fork schedules computed the **same** genesis hash, synced
normally, and discovered the disagreement at the activation height — by which point each had a
branch the other rejects with `WrongEngine` and records as permanently `Invalid`. That is the same
defect shape as a difficulty anchor that is not pinned identically everywhere: a consensus rule
parameterised by a value nothing checks network-wide, with no detection until after the fork.

The activation is encoded as a presence byte followed by the height rather than a sentinel, so
`None` and `Some(u64::MAX)` are different chains. The validator list is length-prefixed and written
in index order, so reordering, truncating or extending it moves the hash.

**Cost, stated rather than hidden:** every published genesis hash changed. README.md and
`docs/RUNNING.md` §4 carry the new values and `the_published_genesis_hashes_are_these` pins them. A
node built before this change cannot peer with one built after it — deliberately, since the two
disagree about what a network *is*. There is still no genesis exchange in the p2p handshake, so the
mismatch surfaces as a failure to sync rather than as a handshake rejection; adding that exchange
would make the failure louder and is left as follow-up work.

---

## D12 — Block size rule 1 measures the block without its seal

SPEC §3.1 rule 1 and CONTRACT §8.1 rule 1 used to compare `Block::serialized_size()` — which
includes `seal.borsh_size()` — against `max_block_size`. D2 puts the seal deliberately *outside*
everything the block hash commits to, and `BftEngine::verify_commit` accepts any number of
signatures from `quorum` to `n`. One block hash therefore had up to `n - quorum + 1` legal encodings,
66 bytes apart, and whether it passed rule 1 depended on which one a node happened to receive: a
relaying peer that re-encoded a block with two more (perfectly valid, publicly gossiped) precommit
signatures could push a copy over the limit for its neighbours while the original stayed under it.
Two honest nodes then disagree about one block hash, and the attacker needs no validator key.

A consensus rule may not be a function of a value the block does not commit to. Rule 1 now measures
`HEADER_SIZE + 4 + Σ tx.borsh_size()` — `Block::consensus_size()`, everything the merkle root and the
header pin down — and the seal is bounded separately by its own rule: a certificate may not exceed
`BlockSeal::max_data_len(n)` = `48 + 66·n` bytes, the largest a commit signed by every validator can
encode to. Both are still context-free, both are checked in `check_block_sanity`, and the transaction
budget no longer moves when a certificate does.

The alternative — canonicalising every certificate to exactly the lowest `quorum` indices before
relaying — was rejected: it makes the *wire* form of a block depend on a rule every relay must apply
identically, and a single relay that skipped it would reintroduce the split.

Consequence for the miner: `block_size_of` measures the same seal-free quantity, so a BFT template
fills to `max_block_size` and the certificate the engine attaches afterwards does not overflow it.
The old accounting reserved five bytes for an *empty* seal at every height, which undercounted a
four-validator certificate by 246 bytes and would have halted the chain at the first full block after
BFT activation.
