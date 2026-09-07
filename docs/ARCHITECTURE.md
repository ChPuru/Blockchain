# Architecture — the life of a block

How one block travels from the miner that seals it to the UTXO set on every other node, and what
happens when two of them disagree. Every name below is a real module, type or function in this
repository, so this document can be read with the source open next to it.

The normative rules live in [`CONTRACT.md`](CONTRACT.md) and [`SPEC.md`](SPEC.md). This file is a
map, not a rule book: where it and the contract differ, the contract wins.

---

## 0. The crates, in dependency order

```
types  ──►  crypto  ──►  script  ──►  chain  ──►  node  ──►  cli
   │           │                        ▲          ▲   ▲
   │           └──────► consensus ──────┘          │   │
   │                                               │   │
   └──────────────────► storage ───────────────────┘   │
                        mempool ───────────────────────┘
                        p2p, rpc, wallet ──────────────┘
```

`ferrum-consensus` may depend on `ferrum-types` and `ferrum-crypto` and nothing else
(`scripts/check-invariants.sh` §1 enforces it). That is the single rule that makes the PoW→BFT
change a configuration change: `chain` calls a `ConsensusEngine` trait object, and the engine has no
way to reach back into the store.

| Crate | The one thing it owns |
|---|---|
| `ferrum-types` | the data model and its Borsh encoding — `Block`, `Transaction`, `Coin`, `ChainParams` |
| `ferrum-crypto` | domain-tagged BLAKE3, BIP-340 Schnorr, the RFC-6962 Merkle tree, bech32m addresses |
| `ferrum-script` | the VM: `script::verify`, `sighash::signature_hash`, the templates |
| `ferrum-consensus` | `ConsensusEngine`, `PowEngine`, `BftEngine`, `EngineRouter`, ASERT, `Target`/`Work` |
| `ferrum-storage` | `Store` over `redb`, `OverlayView`, `StateDiff`, `UndoBlock`, the reverse index |
| `ferrum-chain` | `apply_block` (the determinism seam), `ChainManager`, fork choice, reorg, genesis |
| `ferrum-mempool` | `Mempool` — fee ordering, orphans, eviction, reorg reconciliation |
| `ferrum-p2p` | libp2p: gossipsub topics and the `/ferrum/sync/1.0.0` request-response protocol |
| `ferrum-rpc` | JSON-RPC over HTTP/WS, plus the explorer's REST surface |
| `ferrum-node` | the wiring: miner, relay, sync, faucet, telemetry, configuration |
| `ferrum-cli` | `chaind` and `chain-cli` |

---

## 1. The sequence, end to end

```
 MINER NODE                                        PEER NODE
 ══════════                                        ═════════

 miner::run
   │  build a candidate from the mempool
   ├─► Miner::build_template
   │     └─► Mempool::select_for_block
   │     └─► ChainManager::build_template
   │           └─► chain::template::build_template
   │                 · coinbase script_sig = BIP-34 push of height
   │                 · merkle_root = compute_merkle_root(txs)
   │                 · bits = ConsensusEngine::next_bits(parent)
   │
   ├─► Miner::mine_once      (spawn_blocking — grinding is CPU, not IO)
   │     └─► ConsensusEngine::seal          PowEngine: bump nonce until
   │                                        hash_meets_target; checks the
   │                                        cancel flag every 4096 hashes
   │
   ├─► Miner::mine_and_submit
   │     └─► Relay::accept_block  ────────────────┐   the node's own block takes
   │                                              │   exactly the path a peer's
   │                                              │   block takes — one definition
   │                                              │   of "accepted"
   │            ┌─────────────────────────────────┘
   │            ▼
   │      §2 VALIDATION AND COMMIT  (below)
   │            │
   │            ├─ AcceptOutcome::Extended ──► ChainEvent::NewTip
   │            │                                │
   │            │      tasks::spawn_chain_event_bridge
   │            │        (sync mpsc ──► tokio broadcast)
   │            │                                │
   │            │        ┌───────────────────────┴──────────────┐
   │            │        ▼                                      ▼
   │            │   miner::run cancels the round        Relay::remove_confirmed
   │            │   and restarts on the new tip         (drops mined txs)
   │            │
   └────────────┴─► announce channel (bounded, MINED_BLOCK_CAPACITY;
                     a full queue sheds with a warning — never grows)
                        │
                        ▼
                 tasks::announce_blocks
                   └─► P2pHandle::publish_block
                         └─► gossipsub topic  ferrum/{chain_id}/blocks/v1
                               message id = tagged_hash(TAG_P2P_MSGID, data)
                                        │
                                        │   TCP + Noise + Yamux
                                        └──────────────────────────────►
                                                                        │
                                                    P2pService worker ──┘
                                                          │
                                                    P2pEvent::Gossip
                                                          │
                                                 tasks::handle_event
                                                          │
                                                 tasks::validate_gossip
                                                          │
                                                 Relay::accept_block
                                                    ├─ consensus::check_future_time
                                                    │    (the ONE clock rule;
                                                    │     lives above the seam)
                                                    │
                                                    └─ §2 VALIDATION AND COMMIT
                                                          │
                                                    GossipVerdict
                                                     Accept / Reject / Ignore
                                                          │
                                              P2pHandle::report_validation
                                                          │
                                        gossipsub forwards it, or scores the
                                        sender down through P₄ (invalid message)
```

The verdict is not cosmetic. Gossipsub runs with `validate_messages()`, so nothing is forwarded
until this node has judged it. `relay::block_verdict` maps the outcome:

| Outcome | Verdict | Why |
|---|---|---|
| `Extended` / `Reorged` / `SideChain` | `Accept` | valid; forward it |
| `Duplicate` / `Orphan` | `Ignore` | we cannot judge it yet — an honest peer must not be scored down |
| a consensus `ValidationError` or `ConsensusError` | `Reject` | feeds gossipsub's P₄ invalid-message score |
| our own disk failed, or the fee was below **our** relay floor | `Ignore` | our state, not their fault |

---

## 2. Validation and commit

`ChainManager::accept_block` takes `accept_lock` and runs `accept_locked`
(`crates/chain/src/manager.rs`). In order:

```
 1. store.get_header(hash)          known Invalid  ─► Err(KnownInvalid)
                                    known good     ─► Ok(Duplicate)

 2. chain::validate::check_block_sanity(block, params)
       · serialized_size <= max_block_size
       · txs non-empty, txs[0] is the only coinbase
       · compute_merkle_root(txs) == header.merkle_root
       · no duplicate txid

 3. store.get_header(prev_hash)     absent ─► manager::orphans.insert()  ─► Ok(Orphan)
                                    Invalid ─► Err(KnownInvalid)

 4. EngineRouter::engine_for_height(height)          ── PoW below the fork,
       ConsensusEngine::validate_header(h, parent, StoreHeaderView)
       ConsensusEngine::validate_seal(block, view)      BFT at and above it

 5. fork_choice::cumulative_work(parent_work, engine.work(header))

 6. store.store_header(entry)       ── persist before deciding: a losing branch
    store.store_block_body(hash, b)    may win later, and re-downloading it
                                       would be the expensive way to find out

 7. fork_choice::is_better(candidate, incumbent)
       false ─────────────────────────────────────► Ok(SideChain(hash))
       true and prev_hash == tip ──► §2.1 extend  ─► Ok(Extended(hash))
       true and prev_hash != tip ──► §3  reorg    ─► Ok(Reorged { .. })
```

Fork choice is `chain::fork_choice::compare`: **cumulative work first, then the lower block hash**.
Height never enters it. Ties break on the hash so that every honest node converges on the same
answer without talking to anyone; first-seen is a purely local preference applied before that and is
not consensus.

> **A sharp edge in step 4.** `PowEngine::next_bits` needs the ASERT anchor, and `PowEngine::anchor`
> fetches it with `HeaderView::header_at_height(1)` — which CONTRACT §6.4 defines as *the active
> chain*. `StoreHeaderView::median_time_past` deliberately does the opposite, walking `prev_hash` so
> that a candidate is judged against **its own** ancestors. The consequence is that two nodes whose
> block 1 differs compute different required `bits` for each other's headers, reject them as
> `BadDifficultyTransition`, and ban each other; the fork can never be merged by fork choice because
> neither side can validate the other. It is reachable in practice — `docs/RUNNING.md` §2 shows the
> devnet doing it — and it is the one place in this walkthrough where following the contract
> literally produces branch-dependent consensus.

### 2.1 Extending the tip — the overlay and the atomic write

`chain::reorg::connect_tip_block` is the only function that moves the tip forward. Both the
fast-forward path and every step of a reorg go through it, so there is exactly one implementation of
"connect a block".

```
connect_tip_block(store, params, engines, hash)
  │
  ├─ engine.validate_header(...)          the chain-dependent header rules:
  ├─ engine.validate_seal(...)            bits == next_bits(parent), PoW met,
  │                                       timestamp > median_time_past(parent)
  │
  ├─ view.median_time_past(parent)        seconds, median of up to 11 headers
  ├─ BlockCtx { height, prev_header, median_time_past_s, params, engine_id }
  │
  ├─ chain::apply::apply_block(store, block, ctx)   ◄── THE DETERMINISM SEAM
  │     │
  │     │   A pure function of (pre-state, block, ctx). No clock, no RNG, no
  │     │   IO, no HashMap iteration. `check-invariants.sh` §4 greps for the
  │     │   first two; the reference executor in testing/sim differentials the
  │     │   rest on every simulated block.
  │     │
  │     ├─ OverlayView::new(pre)          BTreeMap<OutPoint, Option<Coin>> in
  │     │                                 front of the store; reads fall
  │     │                                 through, writes stay in memory
  │     │
  │     └─ for each non-coinbase tx, in block order:
  │          · overlay.get_coin(prev_out)     absent ─► MissingInput
  │          · coinbase maturity: height >= coin.height + 100
  │          · sum(inputs) >= sum(outputs), every step checked_*
  │          · is_final(tx, height, mtp_s)
  │          · script::verify(script_sig, coin.script_pubkey, ExecCtx)
  │          · overlay.spend(prev_out)  then  overlay.add(new outpoints)
  │              └─ spending first is what makes a double spend inside one
  │                 block fail on the second spender, and what lets tx N spend
  │                 an output tx N-1 created but never one tx N+1 will create
  │
  │        then the coinbase: script_sig 2..=100 bytes beginning with a
  │        minimally encoded push of the height (BIP-34, which is the fix for
  │        the BIP-30 duplicate-txid class), and
  │        coinbase_out <= block_subsidy(height) + total_fees
  │
  │     ──► StateDiff { spent: Vec<(OutPoint, Coin)>, created: Vec<(OutPoint, Coin)> }
  │         `spent` is in the exact order the inputs were consumed. That order
  │         is the undo record.
  │
  └─ Store::connect_block(hash, height, entry, diff, block)   ── ONE redb write txn
        │
        ├─ read the tip *inside* the transaction and refuse a non-contiguous
        │  or wrong-parent connect (no check-then-use window)
        ├─ blocks[hash]   = borsh(Block)
        ├─ headers[hash]  = borsh(BlockIndexEntry)
        ├─ undo[hash]     = borsh(UndoBlock)          ◄── from diff.spent
        ├─ height[be_u64] = hash                      ◄── big-endian: bytewise
        │                                                 order == numeric order
        ├─ utxo: insert diff.created, then remove diff.spent
        │        (creations first — a block may spend an output it created)
        ├─ if index_transactions: index::index_block  (tx_index, addr_index)
        └─ meta.engine, then meta.tip                 ◄── TIP LAST. Nothing below.
           txn.commit()
```

`meta.tip` being the last write inside the same transaction is what makes a kill at any instant
safe: either the whole block is there and the tip points at it, or none of it is and the tip still
points at the parent. There is no third state, and no crash-recovery code to get wrong.

---

## 3. The reorg path

A candidate with strictly greater cumulative work whose parent is not the current tip goes to
`ChainManager::reorganise`.

```
reorganise(from = current tip, to = candidate)
  │
  ├─ chain::reorg::plan_reorg(store, from, to)
  │     walk both branches back by height to the common ancestor, using
  │     headers only — no bodies are read to compute the plan
  │     ──► ReorgPlan { fork_height, disconnect: [tip …ancestor+1],
  │                                  connect:    [ancestor+1 … to] }
  │
  ├─ engine.finalized_height(view)
  │     Some(h) and plan.fork_height < h ─► Err(ReorgBelowFinalized)
  │     PoW returns None: nothing is ever final. BFT returns a height, and a
  │     reorg below it is refused rather than attempted.
  │
  └─ chain::reorg::execute_reorg(store, params, engines, plan)
       │
       ├─ for each hash in plan.disconnect (tip first):
       │     Store::disconnect_tip()
       │       · restore undo.spent verbatim, then remove the block's created
       │         outpoints — the exact inverse of connect, in the opposite
       │         order, so an output created *and* spent inside the block ends
       │         up absent rather than resurrected
       │       · remove height[tip_height]; unindex if the index is on
       │       · meta.engine = the parent's engine, meta.tip = parent — last
       │     if the returned hash is not the expected one, the tip moved:
       │     roll_back and refuse
       │
       ├─ for each hash in plan.connect (oldest first):
       │     connect_tip_block(...)            ── §2.1, in full
       │     on failure:
       │        roll_back(connected, undone)   ── disconnect what we connected,
       │                                          reconnect what we disconnected
       │        mark_branch_invalid(...)       ── the failing block and every
       │                                          block after it on that branch
       │        return the failing block's own error
       │
       └── ReorgOutcome { disconnected, connected }
```

Because every reconnect goes through `connect_tip_block` → `apply_block` → `Store::connect_block`,
the UTXO set after disconnecting *N* blocks and reconnecting them is byte-identical, and so is
`Store::state_root()`. `testing/sim` asserts exactly that, and it is the property that makes the
undo log worth its disk.

If `roll_back` itself fails, `ChainError::ReorgRollbackFailed` is returned and says so loudly. That
state is not recoverable in place — only a reindex fixes it — and pretending otherwise would be
worse than the failure.

### 3.1 What the rest of the node does about it

```
execute_reorg returns
  │
  ├─ ChainManager::refresh_tip()
  ├─ tracing::info!("reorg complete: new tip", from, to, disconnected, connected)
  │     and telemetry::log_reorg / reorg_line write the line devnet/heal.sh
  │     greps for: "reorg complete: rolled back N block(s), connected M, new tip"
  │
  ├─ ChainEvent::Reorg { from, to, disconnected, connected }
  ├─ ChainEvent::NewTip { hash, height, total_work }
  │     both broadcast through tasks::spawn_chain_event_bridge
  │
  └─ Relay::reconcile_reorg
        └─ Mempool::reconcile_reorg(disconnected, connected, view, height)
             · re-admit transactions from the blocks that came off
             · drop those the new chain already confirms
             · evict anything the new chain double-spends
```

The miner sees the same `ChainEvent` and raises its round's cancel flag, so it stops grinding a
block whose parent no longer exists rather than finishing one nobody will accept.

---

## 4. The other way in: headers-first sync

Gossip only carries blocks a peer produced while you were connected. Everything else arrives through
`ferrum_node::sync` over the `/ferrum/sync/1.0.0` request-response protocol.

```
sync::run  (every round, against the best peer by cumulative work)
  │
  ├─ SyncNetwork::request_tip           SyncRequest::GetTip
  │     ──► TipInfo { hash, height, work }
  │  SyncManager::is_behind(tip)?  no ─► sleep and try again
  │
  ├─ ChainManager::locator()            last ten tips, then doubling gaps back
  │                                     to genesis: ~30 hashes describe any
  │                                     chain length, so the fork point is
  │                                     found in one round trip
  ├─ SyncNetwork::request_headers       SyncRequest::GetHeaders { locator, stop, max }
  │     server side: node::serve::answer ──► ChainManager::headers_from,
  │     capped at 2000 headers regardless of what the request asked for
  │
  ├─ SyncManager::accept_headers
  │     ChainManager::accept_header(h) for each, in order
  │       — the same engine header rules as §2 step 4, but no body and no
  │         state transition, so a peer feeding a bogus chain costs bandwidth
  │         and nothing else
  │       — a rejected header bans the peer (PeerBans::ban) for this session
  │
  ├─ SyncManager::download_window              SyncRequest::GetBlocks { hashes },
  │                                     64 blocks per response, server-side cap
  │
  └─ SyncManager::connect_served
        Relay::accept_block(block) for each, in height order
          ──► §2, identical to the gossip path
```

Both `ChainManager` and `Store` are synchronous. Every call from an `async fn` goes through
`sync::blocking`, which is `tokio::task::spawn_blocking`; `check-invariants.sh` §8 looks for direct
`Store::` calls inside `async fn` bodies.

---

## 5. Where a transaction goes

```
chain-cli wallet send
  └─► Wallet::build_transaction        branch-and-bound, then largest-first
      Wallet::sign_transaction         BIP-340 over the §5.5 sighash preimage,
                                       which contains chain_id and input_value
        └─► RPC sendrawtransaction
              └─► Relay::accept_transaction
                    └─► Mempool::accept(tx, view, tip_height, mtp_s)
                          · standardness, min_fee_rate, no double spend of a
                            mempool outpoint (no RBF in v1)
                          · missing inputs ─► orphan pool, keyed by parent txid
                          └─► P2pHandle::publish_tx
                                topic ferrum/{chain_id}/txs/v1
                                      │
                                      ▼
                              Miner::build_template
                                Mempool::select_for_block  (fee-rate order)
                                      │
                                      ▼
                                  §1, as a block
```

---

## 6. The seams, and why each one is where it is

**`apply_block` is pure.** It takes `&dyn StateView`, a `Block` and a `BlockCtx` and returns a
`StateDiff`. It cannot read a clock, so re-validating block 400 tomorrow gives the same answer it
gave when the block was mined. The one rule that genuinely needs a clock — a block may not be more
than `max_future_block_time_ms` ahead of now — lives in `Relay::accept_block` as
`consensus::check_future_time`, *above* the seam. A block that fails it is refused and **not** marked
invalid, because it may be perfectly good in ten minutes.

**`OverlayView` is the only mutable state during validation.** Nothing touches `redb` until
`Store::connect_block`. A block that fails on its last input leaves no trace.

**`ConsensusEngine` is a trait object chosen per height.** `EngineRouter::engine_for_height` reads
`params.bft_activation_height`. History stays valid across the fork because each block is validated
by the engine that was active at *its* height, and the seal lives outside the header and outside
`merkle_root` — so a BFT commit certificate, which is formed after the header exists, does not have
to commit to itself.

**Every queue is bounded.** `announce`, the p2p command and event channels, the chain-event
broadcast: each has an explicit capacity, and a full one sheds with a `tracing::warn!` and a counter
rather than growing. `check-invariants.sh` §2 greps the whole tree for `unbounded_channel`.

---

## 7. Reading the source in this order

1. `crates/types/src/block.rs` and `tx.rs` — the shapes everything else moves around.
2. `crates/chain/src/apply.rs` — the state transition, top to bottom, one SPEC rule per block of code.
3. `crates/chain/src/reorg.rs` — `connect_tip_block`, then `execute_reorg`.
4. `crates/storage/src/store.rs` — `connect_block` and `disconnect_tip`, as an exact pair.
5. `crates/node/src/relay.rs` — the verdict table, and why each outcome maps where it does.
6. `crates/node/src/sync.rs` — headers first, bodies second, ban on a bad header.
7. `testing/sim/src/reference.rs` — the same rules written again from `SPEC.md`, which is the thing
   that actually catches a divergence between the document and the code.
