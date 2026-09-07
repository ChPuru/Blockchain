# Ferrum protocol specification

> Normative for consensus. `CONTRACT.md` wins on any conflict about names and signatures;
> this document wins on any conflict about *behaviour*.
>
> **This document is written to be implementable without reading the production code.** The
> reference executor in `testing/sim/src/reference.rs` is written from this file alone and
> differentially tested against `ferrum-chain`. That is deliberate: two implementations that share
> an author still catch a misreading, and this is the project's substitute for an audit. If you find
> yourself consulting `crates/chain/` to answer a question this document should answer, that is a bug
> in this document — fix it here.

Companion documents: [`ENCODING.md`](ENCODING.md) for the byte layout, [`CONTRACT.md`](CONTRACT.md)
for API surface, [`DECISIONS.md`](DECISIONS.md) for why things are the way they are.

---

## 1. Chain parameters

| Parameter | Mainnet | Testnet | Devnet |
|---|---|---|---|
| `chain_id` | 1 | 2 | 3 |
| bech32m HRP | `fer` | `tfer` | `rfer` |
| Target block spacing | 120 000 ms | 120 000 ms | 120 000 ms |
| ASERT half-life | 7 200 s | 7 200 s | 7 200 s |
| Initial subsidy | 50 FRM | 50 FRM | 50 FRM |
| Halving interval | 210 000 blocks | 210 000 blocks | 210 000 blocks |
| Coinbase maturity | 100 blocks | 100 blocks | 100 blocks |
| Max block size | 1 000 000 B | 1 000 000 B | 1 000 000 B |
| Max future block time | 7 200 000 ms | 7 200 000 ms | 7 200 000 ms |
| Median time span | 11 headers | 11 headers | 11 headers |
| `pow_limit` | hard | hard | trivially easy |

The half-life is `N × T × ln 2` with `N ≈ 86` at `T = 120 s`, giving 7 200 s. `N` in `[50, 100]` is
the range in which ASERT responds to a real hashrate change within a few hours without amplifying
timestamp noise.

Maximum money is `21 000 000 FRM`, and the subsidy schedule is the only source of new coins:

```
block_subsidy(height) = initial_subsidy >> (height / halving_interval)      // integer division
                      = 0   once the shift reaches 64
```

A property test asserts the sum over all heights never exceeds `MAX_MONEY`. Fees are not new money;
they are recycled, and a miner may claim less than it is owed (that burns the difference).

---

## 2. Genesis

The genesis block is fully determined by `ChainParams`. It is not stored in a file to be trusted; it
is *computed* on startup and its hash is compared against the value published in `RUNNING.md`. A node
whose computed genesis hash differs from its peers cannot sync with them, which is the intended
outcome.

```
genesis.header.version      = 1
genesis.header.prev_hash    = 0x00 * 32
genesis.header.merkle_root  = merkle_root([txid(genesis_coinbase)])
genesis.header.timestamp_ms = params.genesis_timestamp_ms
genesis.header.bits         = params.genesis_bits
genesis.header.nonce        = params.genesis_nonce
genesis.seal                = BlockSeal::POW
```

The genesis coinbase has one input (`OutPoint::NULL`), a `script_sig` carrying a minimally-encoded
push of height `0` followed by an ASCII message, and **one output that is provably unspendable**
(`OP_RETURN`). The genesis subsidy is therefore burned, exactly as Bitcoin's is. This is not
ceremony: an unspendable genesis output removes a special case from the UTXO set and removes any
question about a premine.

Genesis is exempt from: proof-of-work validation against the parent (it has none), difficulty
transition checks, and median-time-past checks.

---

## 3. Block validation

A block is validated in the order below. The order is normative — an implementation that checks
cheap rules after expensive ones is correct but denial-of-service-prone, and an implementation that
checks them in a *different* order can accept a block another node rejects if two rules disagree.

Rules are grouped by what they need, because that grouping is what allows headers-first sync.

### 3.1 Context-free (needs only the block)

1. **`serialized_size(block) ≤ max_block_size`.**
2. **`txs` is non-empty**, `txs[0].is_coinbase()`, and **no other transaction is a coinbase**.
3. **`compute_merkle_root(txs) == header.merkle_root`.**
4. **No duplicate txid within the block.**
5. Every transaction passes §4.1 (transaction sanity).

### 3.2 Header context (needs the parent and the header chain)

6. **`header.prev_hash`** identifies a known header. If not, the block is an **orphan** — a distinct
   outcome from invalid. Orphans are held, not banned.
7. **`header.bits == engine.next_bits(parent, view)`** exactly. A block that "over-pays" difficulty
   is still invalid; there is only one correct target per parent.
8. **Proof of work**: `block_hash ≤ compact_to_target(header.bits)` (PoW engine only).
9. **`header.timestamp_ms > median_time_past(parent) × 1000`.** Strictly greater.
10. **`header.timestamp_ms ≤ now + max_future_block_time_ms`.**
    This is the **only** rule that reads a clock, and it therefore lives in the node, not in
    `apply_block`. Re-validating a historical block must never depend on when you do it.
11. **Seal validity** (`engine.validate_seal`): PoW requires an empty seal; BFT requires a `2f+1`
    commit over this header's hash by the validator set active at this height.

### 3.3 State context (needs the UTXO set)

12. Every non-coinbase transaction passes §4.2 (contextual validation) against an overlay of the UTXO
    set at the parent, applied **in block order**, so a transaction may spend an output created by an
    earlier transaction in the same block but never by a later one.
13. **Coinbase value**: `sum(coinbase.outputs) ≤ block_subsidy(height) + total_fees`.
14. **Coinbase `script_sig`** is between 2 and 100 bytes and **begins with a minimally-encoded push
    of `height`**.
15. **No created output already exists** in the UTXO set.

Rule 14 is BIP-34, and it is the fix for CVE-2012-1909 / BIP-30. Without a height commitment, two
blocks with identical coinbase transactions produce identical txids; the second overwrites the
first's UTXO entry, and the first block's coins are destroyed. It happened twice on Bitcoin mainnet.
Enforcing it from genesis costs nothing and closes the class permanently.

Rule 15 is then redundant with rule 14 for coinbases, but it is kept because it also covers the case
of a non-coinbase transaction colliding with an existing outpoint, and defence in depth on the
inflation path is cheap.

### 3.4 Errors are specific

`ValidationError` has one variant per rule above. Tests assert the *exact* variant, not merely that
validation failed. A test that only asserts "rejected" passes when the block is rejected for the
wrong reason, which is how a rule silently stops being tested.

---

## 4. Transaction validation

### 4.1 Sanity — context-free

- `inputs` is non-empty and `outputs` is non-empty.
- Every `output.value.is_valid_money()`, i.e. `0 ≤ value ≤ MAX_MONEY`.
- `sum(outputs)` does not overflow and `is_valid_money()`.
- No duplicate `OutPoint` among the inputs of one transaction.
- `script_sig` and `script_pubkey` each `≤ MAX_SCRIPT_SIZE` (1000 bytes).
- Coinbase: exactly one input, and it is `OutPoint::NULL`.
- Non-coinbase: no input is `OutPoint::NULL`.

### 4.2 Contextual — against the UTXO overlay

For each input, in order:

1. **Resolve** `prev_out` in the overlay. Absent ⇒ `MissingInput`. The caller decides whether that
   means "orphan" (mempool) or "invalid" (block, since a block must be self-contained plus parent
   state).
2. **Coinbase maturity**: if the resolved coin `is_coinbase`, require
   `height ≥ coin.height + coinbase_maturity`. A coinbase spent too early is invalid, not deferred.
3. **Script**: `script::verify(script_sig, coin.script_pubkey, ctx)` succeeds, where `ctx` carries
   `chain_id`, the whole transaction, the input index, `coin.value`, the block height and the median
   time past in seconds.
4. **Mark spent** in the overlay before validating the next input, so a transaction cannot spend the
   same output twice even across separate inputs (this is also caught by the duplicate check in
   §4.1, again deliberately redundant).

Then:

5. `sum(inputs)` does not overflow and `is_valid_money()`.
6. **`sum(inputs) ≥ sum(outputs)`.** The difference is the fee.
7. `total_fees` for the block accumulates without overflow.

### 4.3 Finality (locktime)

A transaction is **final** if any of:

- `lock_time == 0`; or
- every input has `sequence == 0xFFFFFFFF`; or
- `lock_time < LOCKTIME_THRESHOLD` and `lock_time ≤ height`; or
- `lock_time ≥ LOCKTIME_THRESHOLD` and `lock_time ≤ median_time_past_seconds`.

A non-final transaction in a block makes the block invalid.

Comparing against **median time past** rather than the block's own timestamp is what makes locktime
unmanipulable: a miner controls its own timestamp within a two-hour window, but cannot move the
median of the last eleven blocks without controlling most of them.

### 4.4 Relative locktime (`OP_CHECKSEQUENCEVERIFY`)

BIP-68 semantics on `TxIn::sequence`:

- bit 31 set ⇒ relative locktime **disabled** for this input;
- bit 22 set ⇒ the value is a **time** in units of 512 seconds; otherwise it is a **block count**;
- bits 0–15 carry the value.

`OP_CHECKSEQUENCEVERIFY` fails unless the input's sequence encodes a relative lock of the same type
and at least the required magnitude.

---

## 5. Script

The full opcode table, limits and number encoding are in `CONTRACT.md` §5. The behavioural rules
that a second implementer must not get wrong:

1. **`script_sig` must be push-only**, and this is a *consensus* rule in Ferrum, not a policy rule as
   in Bitcoin. Allowing arbitrary operations in the unlocking script serves no purpose and doubles
   the attack surface.
2. **Clean stack**: after `script_pubkey` executes, exactly one element must remain and it must be
   truthy. A leftover stack is a failure. Bitcoin added this rule late, as policy, because it could
   not make it consensus retroactively.
3. **Execution order**: run `script_sig` on an empty stack; carry the resulting stack into
   `script_pubkey`; if `script_pubkey` matched the P2SH template, then pop the last `script_sig` push
   as the redeem script and execute it on the remaining stack. Limits apply to each script
   separately, and the operation count is *not* reset between them.
4. **P2SH is not recursive.** A redeem script that itself matches the P2SH template does not trigger
   another round; it simply executes.
5. **Untaken branches are still parsed.** Inside a false `OP_IF`, opcodes are skipped, but an
   undefined opcode byte still fails the script and an unbalanced conditional still fails. Ferrum has
   no `OP_NOP1..10` soft-fork hooks, so the opcode table is exhaustive and any other byte is invalid.
6. **Minimality is enforced where a value is read**: pushes must use the shortest available form,
   `ScriptNum` operands must be minimally encoded, and `OP_IF`/`OP_NOTIF` conditions must be exactly
   `{}` or `{0x01}`.
7. **`OP_CHECKMULTISIG` pops exactly what it needs** — `n`, `n` pubkeys, `k`, `k` signatures — with
   no extra dummy element. Bitcoin's off-by-one is a bug, not a feature to copy.
8. **A signature is exactly 65 bytes**: 64-byte Schnorr plus one sighash-type byte.
9. **The interpreter never panics.** Every pop, index and slice is checked. A fuzz target enforces
   this, because the script VM is the largest surface reachable by unauthenticated input.

Sighash construction is in [`ENCODING.md`](ENCODING.md) §5 and is normative there.

---

## 6. Difficulty — ASERT (`aserti3-2d`)

### 6.1 Why not Bitcoin's retarget

Bitcoin adjusts every 2016 blocks with a 4× clamp. On a chain with no security budget that is fatal:
rented hashrate mines an epoch cheaply, leaves, and the honest remainder faces a clamped difficulty
for weeks with no mechanism to escape. Several small chains have died exactly this way.

ASERT is an absolute-schedule exponential controller. It is stateless with respect to recent history
— the next target depends only on a fixed *anchor* block and the parent's height and timestamp — so
it has no oscillation mode, cannot be driven by an alternating-timestamp attack, and self-corrects
after a manipulated timestamp instead of amplifying it.

### 6.2 The algorithm

**Anchor: genesis.** `anchor_height = 0`, `anchor_target` from `params.genesis_bits`,
`anchor_time_s` from `params.genesis_timestamp_ms`. Every one of those comes from `ChainParams`, so
the anchor is identical on every node by construction and difficulty depends only on the parent's
height and timestamp.

The anchor must **not** be read from the chain. An anchor resolved through
`HeaderView::header_at_height` — which returns the *active* chain — makes the difficulty rule
fork-dependent: two nodes holding different blocks at the anchor height compute different required
`bits` for each other's headers, reject them, and fork permanently with no reorg path out, because a
header that fails validation never reaches fork choice. This is why Bitcoin Cash's `aserti3-2d` pins
a fixed anchor.

```
time_diff   = parent_time_s   - anchor_time_s                     // i64, seconds
height_diff = parent_height   - anchor_height                     // i64

exponent    = ((time_diff - target_spacing_s * (height_diff + 1)) * 65536) / halflife_s

shifts      = exponent >> 16                                      // arithmetic shift: floor division
frac        = (exponent & 0xffff) as u64                          // always in [0, 65536)

factor      = 65536 + ((195_766_423_245_049 * frac
                      +     971_821_376 * frac^2
                      +           5_127 * frac^3
                      + (1 << 47)) >> 48)

next_target = anchor_target * factor
next_target = shifts < 0 ? next_target >> (-shifts) : next_target << shifts
next_target = next_target >> 16

if next_target == 0        -> 1
if next_target > pow_limit -> pow_limit
return target_to_compact(next_target)
```

The polynomial is a cubic approximation of `2^(frac/65536)` with relative error below 0.013 %. All
intermediates are `u128` or `U256`; a left shift that would exceed 256 bits saturates to `pow_limit`.

**Everything here is integer arithmetic, and that is not a stylistic choice.** A float in this
function produces platform-dependent rounding, two nodes compute different targets from the same
inputs, and the chain splits along CPU architecture lines. `f32`/`f64` are denied workspace-wide by
`clippy.toml` for this reason.

The arithmetic shift on a negative `exponent` is floor division, which keeps `frac` non-negative;
a truncating division here is a real and easy bug, and it makes difficulty drift asymmetrically
between speed-ups and slow-downs.

### 6.3 Verification

An independent Python implementation lives in `testing/reference/asert.py`. CI runs both over
`testing/reference/asert_vectors.json` — at least 2000 cases spanning on-schedule, 10× fast, 10×
slow, negative drift, very large gaps and the `pow_limit` clamp — and requires exact agreement. Two
implementations written from the same paragraph still catch a misreading of that paragraph; one does
not.

Behavioural tests assert numbers, not directions: constant on-schedule timestamps hold `bits` stable;
a 10× hashrate spike returns block time to within 2× of target within roughly two half-lives; a 10×
collapse likewise; a single manipulated timestamp moves difficulty by no more than the half-life
permits.

---

## 7. Fork choice and reorganisation

### 7.1 Choosing the best chain

The best chain is the one with the **greatest cumulative work**, never the greatest height.

```
work(header) = (!target / (target + 1)) + 1        // 256-bit integers
```

Height is not a proxy for work: a chain of 100 easy blocks can be shorter in work than 10 hard ones,
and ranking by length is the single most common flaw in from-scratch implementations.

Ties are broken by, in order: (1) the chain seen first — a *local* rule, not consensus; then (2) the
lower block hash — a deterministic rule so that nodes which saw the two candidates in different
orders still converge.

### 7.2 Reorganisation

Given a candidate tip with strictly greater cumulative work:

1. Walk both branches back to the common ancestor.
2. `disconnect_tip()` repeatedly down to the ancestor, restoring the UTXO set from each block's
   **undo record**.
3. Connect the candidate branch forward, validating each block fully.
4. If any connect fails, **roll the whole reorg back to the original tip** and mark the candidate
   branch `Invalid`. A half-applied reorg is worse than a rejected one.
5. Reconcile the mempool: re-add transactions from disconnected blocks, drop those now invalid, evict
   anything double-spent by a newly connected block.

Reorg depth is capped by `finalized_height()` when the engine provides one. Under PoW it is `None`
and nothing is ever final. Under BFT it is the last committed height, and reorgs below it are
impossible by construction.

### 7.3 Undo records

Every block stores, in input order, every output it spent: value, script, height and coinbase flag.
This is what makes step 2 possible without replaying from genesis.

Every from-scratch tutorial surveyed for this project omits undo data, and it cannot be retrofitted:
the records for historical blocks do not exist, so adding it later forces a full reindex on every
deployed node. It is cheap on day one.

**Guaranteed property, asserted in CI:** disconnecting *N* blocks and reconnecting them yields a
byte-identical UTXO set and an identical state root.

---

## 8. Determinism

`apply_block(pre: &dyn StateView, block: &Block, ctx: &BlockCtx) -> Result<StateDiff, _>` is a
**pure function**. Given the same pre-state, block and context it returns the same result on every
machine, every architecture and every optimisation level, forever.

Forbidden inside it: `SystemTime::now`, `Instant::now`, RNG, floats, `HashMap`/`HashSet` iteration,
I/O, and anything whose result depends on thread scheduling or address-space layout.

This is enforced **mechanically**, not by review: `clippy.toml` declares the offending methods and
types as `disallowed-methods` / `disallowed-types`, and `scripts/check-invariants.sh` greps the
consensus crates. The gate is itself verified — deliberately inserting `SystemTime::now()` into the
executor must turn CI red, and that check is part of the test plan rather than an assumption.

The one clock-dependent rule, the two-hour future-time bound (§3.2 rule 10), lives in the node above
the seam. Re-validating block 400 must never depend on when you re-validate it.

`BlockCtx` carries `height`, `prev_header`, `median_time_past_s`, `params` and `engine_id` — every
piece of ambient information a block needs, passed explicitly.

---

## 9. Consensus engines

Both engines implement one trait, and the chain layer never names either concretely.

| | PoW | BFT |
|---|---|---|
| `engine_id` | 0 | 1 |
| Seal | empty | `borsh(BftCommit)` |
| `work(h)` | `(!target/(target+1))+1` | constant 1 per block |
| `finalized_height` | `None` | last committed height |
| Liveness under failure | always makes progress | halts below `2f+1` |
| Reorgs | possible at any depth | impossible below finality |

### 9.1 Proof of work

`seal` grinds `nonce`; when the 64-bit nonce space is exhausted it increments `timestamp_ms` and
continues. It checks a cancellation flag roughly every 4096 hashes so a new tip stops the miner
promptly.

### 9.2 BFT (Tendermint-shaped, permissioned)

Validators come from `ChainParams::bft_validators`, `n ≥ 4`, `f = (n-1)/3`, quorum `2f+1`.

Round: **propose → prevote → precommit → commit**, proposer
`validators[(height + round) mod n]`, timeouts doubling per round.

Locking: a validator that precommits a block at round `r` is locked on it, and may only prevote a
different block after seeing a `2f+1` polka for that block at a round greater than `r`. This is the
rule that makes safety hold under asynchrony, and it is the rule most often omitted from simplified
implementations.

`BftCommit { height, round, block_hash, signatures: Vec<(validator_index, Signature)> }`, each
signature over `tagged_hash("ferrum.v1.bft.precommit", borsh(VoteMsg{chain_id, height, round,
block_hash}))`.

**Safety over liveness, deliberately.** With `n = 4`: killing one validator continues; killing two
**halts**. Halting is the correct behaviour — a BFT chain that kept producing blocks without a quorum
would be forking, which is strictly worse than stopping. The operational commitment is stated
plainly in `RUNNING.md`: *this chain may halt for up to 24 hours; it will never fork.*

### 9.3 The PoW→BFT fork

`EngineRouter::engine_for_height` returns the BFT engine at and above
`params.bft_activation_height`, and PoW below it. That is the entire fork.

No serialised structure changes, no header field changes, no reindex, and history stays valid
because each block is validated by the engine that was active at its height. A test asserts height
`h-1` validates under PoW and height `h` under BFT.

---

## 10. Mempool policy (not consensus)

Everything in this section is **policy**. A block containing a transaction the local mempool would
have rejected is still valid. Conflating the two is how implementations accidentally hard-fork
themselves.

- Reject transactions below `min_fee_rate` (grains per 1000 bytes).
- Reject non-standard `script_pubkey` types (outside the `classify()` set).
- Reject a transaction that spends an output already spent by a mempool transaction. **There is no
  replace-by-fee in v1** — documented as absent, not forgotten.
- Hold transactions with missing inputs in an orphan pool keyed by the missing parent txid, capped at
  `max_orphans`.
- Evict the lowest fee-rate entries when over `max_bytes`.
- Expire entries after `expiry_blocks`.
- Block template selection is by descending fee rate, respecting in-block dependency order.

---

## 11. Networking

Transport is TCP + **Noise** + **Yamux**. `mplex` is never offered — the libp2p specification
deprecates it outright for liveness problems.

Gossip topics: `ferrum/{chain_id}/blocks/v1`, `ferrum/{chain_id}/txs/v1`.
Sync is a request-response protocol `/ferrum/sync/1.0.0` with Borsh frames.

Five gossipsub defaults are overridden, each for a concrete reason:

| Default | Ferrum | Why |
|---|---|---|
| `max_transmit_size = 65536` | ≥ 4 MiB | blocks up to 1 MB are otherwise **silently unsendable** |
| message id = `base58(peer) ‖ seqno` | content hash | the default causes duplicate storms |
| `mesh_n_low = 5` | 4 | the specification says 4 |
| `duplicate_cache_time = 60 s` | 120 s | matches the block interval |
| yamux window 256 KiB | raised | 256 KiB at 80 ms RTT caps one stream near 3 MB/s |

Every message is explicitly validated and the result reported, so invalid messages feed gossipsub's
**P₄ invalid-message score**. That one hookup is the cheapest denial-of-service defence available.

Server-side response caps are enforced regardless of what a peer asks for: 2000 headers, 64 blocks.

**No unbounded channels anywhere.** Every queue has an explicit capacity and load-sheds with a
counter when full. An unbounded channel converts backpressure into an out-of-memory kill.

Peer discovery is a **static list** in the config file. Kademlia, discv5, AutoNAT, relay and DCUtR
all defend permissionless discovery under attack; a network whose peers are in a config file has no
such problem. See `DECISIONS.md` D6.

---

## 12. Sync

Headers-first, in three phases:

1. **Header sync.** Send a block locator (exponential back-off: the last 10 tips, then doubling
   gaps back to genesis) and request headers. Validate each header against its parent — proof of
   work, difficulty transition, timestamp — and store them without bodies. A header chain is cheap
   to validate and cheap to discard, so a peer feeding a bogus chain costs bandwidth and nothing
   else.
2. **Body download.** Request bodies for the best header chain, in parallel across peers, in windows.
3. **Connect.** Validate and connect blocks in order, applying §3 in full.

A peer that serves an invalid header or an invalid block is disconnected and its messages are
reported as rejected so its gossip score falls.

---

## 13. What this chain does not do, stated plainly

An honest specification says what it is not.

- **No light clients and no bridges.** There is no state commitment in the header, so a light client
  cannot verify a state transition from headers alone. Every node fully validates. (`DECISIONS.md` D3)
- **No replace-by-fee.** (§10)
- **No segregated witness.** There is one transaction serialisation and one identifier, which is
  possible only because Schnorr removed signature malleability.
- **No smart contracts beyond the script templates.** No loops, no gas, no general computation. The
  absence of loops is what makes static limits sufficient and gas metering unnecessary — Ethereum
  needed four repricing hard forks to get gas right, and this design skips that category entirely.
- **No permissionless peer discovery.** (§11)
- **No security budget.** The network is small. Anyone willing to rent enough hashrate can reorganise
  it. That is a property of a demonstration chain, it is documented, and it is not a bug.
