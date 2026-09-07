# Where this stands — handoff

Written 2026-09-07. Everything below was measured, not assumed. Where something is unverified it
says so.

## Verified working

**The four-node devnet converges.** Run and observed:

```
NODE   STATUS  HEIGHT  TIP                 PEERS
1      up      125     000000951d6f3125f7  3
2      up      125     000000951d6f3125f7  3
3      up      125     000000951d6f3125f7  3
4      up      125     000000951d6f3125f7  3

CONVERGED — every node agrees on one tip.
```

Stronger than the tip check: all four nodes return the **same block hash at heights 1, 20, 40 and
55**, which spans the partition and the heal. Height 1 is the sharp one — it is exactly what the
fork-dependent ASERT anchor used to break.

**Partition → heal → reorg works.** Side A reached height 47, side B 42; on reconnection the losing
node logged `reorg complete: ... connected=2, fork_height=49` and the network settled on one chain.

**Core consensus crates green:** `ferrum-types`, `ferrum-crypto`, `ferrum-script`, `ferrum-storage`,
`ferrum-consensus` — **1046 passed, 0 failed** across 23 test binaries, *after* the review fixes.

**Live single node** (verified earlier): mines, ASERT lifts difficulty under fast mining, explorer
REST serves every field the page reads with no amount as a JSON number, wallet creates and reports
balances, and a `SIGKILL` followed by restart reopens on exactly the same tip and height.

## Not yet verified — start here

`cargo test --workspace --all-targets` has **not** completed since the review fixes landed. The run
was killed by the OS for low memory while four devnet nodes and a gate agent were also running.

```sh
export PATH="/c/Users/Lenovo/.cargo/bin:$PATH"
cd D:/Blockchain_Crypto
cargo test --jobs 4 --workspace --all-targets --no-fail-fast
```

Untested since the fixes: `ferrum-chain`, `ferrum-mempool`, `ferrum-p2p`, `ferrum-rpc`,
`ferrum-wallet`, `ferrum-node`, `ferrum-cli`, `ferrum-sim`, `ferrum-e2e`. The workspace **compiles
clean** (`cargo check --workspace --all-targets` exits 0), so this is about test expectations, not
API breakage. Expect failures where a fix landed without its test being updated — most likely the
published genesis hashes, which moved when the commitment started covering the fork schedule.

Also not run since the fixes: `devnet/ci-e2e.sh`, the fuzz targets, and the release-profile suite.

## The three bugs that running it found, which reading it did not

1. **The ASERT anchor was fork-dependent.** Specified (by me) as "the block at height 1", resolved
   through `HeaderView::header_at_height`, which returns the *active chain*. Two nodes that sealed
   different height-1 blocks computed different required `bits` for each other's headers, rejected
   them as `BadDifficultyTransition`, and banned each other — permanently, because a header that
   fails validation never reaches fork choice. Now anchored on genesis from `ChainParams`.
   The regression test proves the *old* rule would have split on the same inputs, so it cannot pass
   on an implementation that quietly stopped computing anything.
2. **`--datadir` was silently mangled under Git Bash.** `MSYS2_ARG_CONV_EXCL="*"`, added so
   multiaddrs survive argument conversion, also stopped paths being converted — so nodes wrote to
   `D:\d\Blockchain_Crypto\devnet\data\node1`, an invisible second tree `down.sh --clean` never
   deleted. A stale store survived every clean. The genesis-mismatch check caught it and refused to
   start, which is that check working.
3. **`status.sh` reported a poll race as a fork.** It polls four nodes sequentially at ~1 s block
   times, so a node one block behind read as DIVERGED. It now falls back to comparing at a common
   height.

## Review findings: 46 raised, partially fixed

An eight-lens adversarial review produced 5 critical, 15 high, 16 medium, 10 low. Full text:
`C:\Users\Lenovo\AppData\Local\Temp\claude\D--Blockchain-Crypto\2bbb2f36-1eaf-4ca6-aaec-9235be2823f6\scratchpad\findings.json`
(also preserved in the repo at `docs/review/findings-2026-09-07.json`).

Nine agents were fixing them, partitioned by crate, when the deadline cut them short. Two reported
complete:

- **script** — 4 fixed, **2 rejected as wrong after checking the source**, 2 not reached. Fixed:
  `OP_CHECKSEQUENCEVERIFY` enforcing nothing at all (it had no access to the spent coin's age, so the
  opcode was a no-op); sighash mid-states recomputed per signature, making validation quadratic —
  the exact DoS BIP-143 exists to prevent; and the fuzz target that never compiled.
- **storage** — 2 fixed.

Landed but unreported (partial work on disk): the **genesis commitment now covers
`bft_activation_height` and the ordered `bft_validators`** — the critical finding of the same shape
as the anchor bug, where two nodes with different fork schedules computed an identical genesis hash
and forked silently at the activation height. Documented as `DECISIONS.md` D11.

**Unfixed and worth doing first** (from the critical set):
- wallet change paid to an address no caller queries — every send strands the change;
- reorg onto a branch whose bodies have not arrived marks the honest branch permanently `Invalid`
  ("I do not have the body yet" must be retryable, not fatal);
- explorer decodes a whole block per output with a per-output rather than per-request budget.

## Scope explicitly dropped

Docker packaging, on request. `devnet/Dockerfile`, `docker-compose.yml` and `.dockerignore` exist but
**the image has never been built or run** — do not trust it until it has been.

## Repository

23 commits, 341 tracked files, ~90k lines of Rust across 12 crates plus 3 testing crates.
`docs/CONTRACT.md` is normative; `docs/SPEC.md` is written so the reference executor can be
implemented without reading the production code, which is what makes the differential test mean
something.
