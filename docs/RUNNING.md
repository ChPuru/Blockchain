# Running Ferrum

Everything from "I cloned this five minutes ago" to "three seed nodes are live in three regions".

If you only want to see it work, do §1 and stop.

---

## 0. Prerequisites

- Rust **1.95** — `rust-toolchain.toml` pins it, so `rustup` installs it automatically on first build.
- On Windows: the MSVC build tools. On Linux: a C toolchain is *not* required — `redb` is pure Rust
  and there is no RocksDB, deliberately, because its build chain on Windows is a recurring source of
  lost evenings.
- Optional: Docker, for the four-node devnet.

```sh
git clone https://github.com/ChPuru/Blockchain && cd Blockchain
cargo build --release
```

Two binaries land in `target/release/`: **`chaind`** (the node) and **`chain-cli`** (wallet and
admin). On Windows they are `chaind.exe` and `chain-cli.exe`; every command below works unchanged in
Git Bash, PowerShell or `cmd`, except that Git Bash needs `export MSYS2_ARG_CONV_EXCL="*"` before
any command carrying a `--p2p-listen` multiaddr — see §8.

There is a `Makefile` for the common tasks, and `make help` lists them: `make build`, `make run`
(one mining devnet node), `make devnet` (four of them), `make check` (everything CI runs, in CI's
order), `make e2e`, `make clean`. It works with GNU make on Linux, macOS and Git Bash. Every
recipe is a one-line `cargo` or `bash` command, so nothing below depends on having `make`.

---

## 1. A chain on your laptop, in one minute

```sh
./target/release/chaind --network devnet --mine --index --datadir ./data
```

Devnet's `pow_limit` is 256× easier than mainnet's, which on the machine this was tuned on is
about **1.9 s of hashing per block on one core** — real work, but watchable. `--index` is not
required to run a node, but the explorer's transaction and address pages need it — see §3.
In another shell:

```sh
./target/release/chain-cli chain info
./target/release/chain-cli wallet new                 # address on stdout, mnemonic on stderr
./target/release/chain-cli wallet address
./target/release/chain-cli wallet balance
```

Two things about `wallet new` that the one-liner hides:

- It prints the **address** as the last line of stdout and the **mnemonic to stderr**, so
  `wallet new | tail -1` is the address and a redirect cannot leak the seed into a log. Use
  `--output FILE` to send the mnemonic to a file instead.
- `chain-cli --datadir` is **not** the node's `--datadir`. Left unset it is the platform data
  directory — `%APPDATA%\ferrum` on Windows, `~/.local/share/ferrum` on Linux,
  `~/Library/Application Support/ferrum` on macOS — or `FERRUM_DATADIR` if that is set. The wallet
  keystore lives there; the node's store lives wherever you pointed `chaind`. Pass
  `--datadir ./data` to both if you want one directory.

The keystore is encrypted with the **empty passphrase** unless you ask for one: add
`--prompt-passphrase` to be asked, or `--passphrase-file FILE` for unattended use. There is
deliberately no `--passphrase` flag, because an argument vector is readable by other processes and
lands in shell history.

To mine to your own address rather than a throwaway one, restart with
`--mine-address rfer1...`. Coinbase outputs mature after `coinbase_maturity` blocks — **100 on
mainnet and testnet, 10 on devnet** (50 s at devnet's 5 s spacing); until then they show as
`immature` and cannot be spent. That is a consensus rule, not a wallet policy — a chain that let you
spend a coinbase immediately would lose those coins on any reorg deeper than the spend.

Get some coins without waiting out maturity, then send them:

```sh
./target/release/chain-cli faucet request                    # devnet serves the faucet by default
./target/release/chain-cli wallet balance                    # 1.00000000 once it confirms
./target/release/chain-cli wallet send --to rfer1... --amount 0.5 --fee-rate 1000
./target/release/chain-cli tx get <txid>
```

`faucet request` talks to the **explorer** port, not the RPC port, and defaults to
`http://127.0.0.1:8665`; pass `--explorer <URL>` for anything else. With no `--address` it pays this
wallet's current address, and the default payout is 1 FRM
(`[explorer] faucet_amount` changes it).

**Write down the mnemonic.** There is no recovery path, by design — the plaintext seed never touches
disk, and `chain-cli wallet restore` is the only way back in:

```sh
./target/release/chain-cli wallet restore --mnemonic-file seed.txt
echo "arch mango clean strong …" | ./target/release/chain-cli wallet restore   # or stdin
```

There is no `--mnemonic` flag, for the same reason there is no `--passphrase` one. `--force`
overwrites an existing keystore; without it, restoring over one is refused.

One behaviour worth knowing before it surprises you: **`wallet address` on a datadir with no
keystore creates one**, printing the new mnemonic to stderr, exactly as `wallet new` would. That is
what makes a devnet usable with no setup — it is the wallet-side counterpart of `chaind` generating
`node.key` on first run — but it means a typo'd `--datadir` gives you a *new* empty wallet rather
than an error. If a balance you expected is missing, check the datadir before checking the chain.

---

## 2. The four-node devnet, including the reorg demonstration

This is the part worth watching, because it is what separates a working chain from a hash-linked
list.

```sh
bash devnet/up.sh
```

Four nodes: RPC on `8645..8648`, p2p on `8655..8658`, explorer on `8665..8668` and metrics on
`9100..9103`. Node *i* uses RPC `8645+i-1`, p2p `8655+i-1`, explorer `8665+i-1`, metrics `9100+i-1`,
so node 1's explorer is <http://127.0.0.1:8665>. Nodes 1 and 2 mine; 3 and 4 relay. All four share a
genesis and a static peer list.

```sh
bash devnet/status.sh          # every node's tip hash, height and cumulative work
```

> **This used to fail, and it is worth knowing why.** On a fast desktop the four-node devnet used
> to converge only rarely, and `heal.sh` said so in red. Two measured causes, neither of them a
> flake, both now fixed:
>
> 1. **The ASERT anchor was fork-dependent.** It was specified and implemented as "the block at
>    height 1, read through `HeaderView::header_at_height`" — and that method is defined as the
>    *active* chain (CONTRACT §6.4). Two nodes holding different height-1 blocks computed different
>    required `bits` for each other's headers, rejected them as `BadDifficultyTransition`, and
>    banned each other. The fork was permanent and unrecoverable, because a header that fails
>    validation never reaches fork choice at all. The anchor is now **genesis**, built from
>    `ChainParams` alone (SPEC §6.2), so it is byte-identical on every node by construction.
> 2. **Blocks outran gossip.** Devnet's `pow_limit` was `0x7fff…`, which accepts about half of all
>    header hashes: a node sealed a block in roughly a *microsecond*, far faster than a peer could
>    validate, store and gossip one, so a relay node sat permanently behind — and both miners sealed
>    their own height 1 within a millisecond of opening their stores, before libp2p had dialled
>    anyone, which is what made cause 1 fire on almost every run. Devnet's limit is now
>    `0x1e00ffff`, one base-256 digit easier than mainnet's: about `2²⁴` header hashes, measured at
>    ~1.9 s per block on one core of the machine this was tuned on. Two mining nodes therefore seal
>    roughly one block per second, and every node has met its peers long before the first one
>    exists.
>
> `status.sh` should now print `CONVERGED` within a few seconds of `up.sh` finishing, and keep
> printing it. If it does not, that is a real bug rather than a race — `devnet/ci-e2e.sh` is the
> assertion-carrying version and fails loudly.

Now split the network:

```sh
bash devnet/partition.sh       # nodes 1+2 | nodes 3+4, both halves keep mining
sleep 30                       # ~30 blocks per side at the 5 s spacing: a visible divergence
bash devnet/status.sh          # two different tips, both valid, both growing
bash devnet/heal.sh            # reconnect; it waits 180 s for one tip and reports pass or fail
bash devnet/status.sh          # one tip again, on the branch with more cumulative work
```

`partition.sh` and `heal.sh` do not use `iptables`: they restart each node with a narrower or wider
`--peer` list, which needs no privileges and behaves identically on Windows, macOS and Linux.

The same four nodes in containers, for a clean-room reproduction or for anyone who would rather not
install Rust:

```sh
docker compose -f devnet/docker-compose.yml up --build
docker compose -f devnet/docker-compose.yml exec node1 chain-cli chain info
```

The compose file publishes node 1's RPC on `8645`, explorer on `8665` and metrics on `9100`, and
runs every container `read_only` with `cap_drop: ALL` — a devnet node needs no privileges and
nothing writable outside its datadir. The shell scripts drive local binaries instead and are faster
to iterate on; the partition and heal demonstrations are scripts only.

What you are watching in the logs of the losing side is a real reorganisation: blocks disconnected
using their stored undo records, the UTXO set rolled backwards, the mempool reconciled, then the
winning branch connected forward. Note that the winner is the branch with more **cumulative work**,
not the longer one — a chain of a hundred easy blocks can be worth less than ten hard ones.

```sh
bash devnet/down.sh            # stop everything; add --clean to delete devnet/data too
```

On Windows `--clean` can fail to remove `devnet/data` if a node has not fully exited, and the next
`up.sh` then resumes the old chain instead of starting a fresh one. If a run looks impossible —
a node pinned at an old height, `block already known to be invalid` in its log — stop everything and
delete the directory by hand before blaming the code.

### Fault injection

```sh
bash devnet/kill.sh 3          # kill node 3
bash devnet/up.sh 3            # restart it; it re-syncs headers-first from its peers
```

---

## 3. Configuration

Precedence, highest first: **CLI flag → environment variable (`FERRUM_*`) → config file → network
default.**

```toml
# ferrum.toml
network  = "devnet"            # mainnet | testnet | devnet
datadir  = "./data"

[p2p]
listen   = "/ip4/0.0.0.0/tcp/8655"
peers    = ["/ip4/10.0.0.2/tcp/8655", "/ip4/10.0.0.3/tcp/8655"]

[rpc]
listen   = "127.0.0.1:8645"    # bind to localhost unless you mean it - see §5
ws       = true

[explorer]
listen   = "0.0.0.0:8665"
faucet   = true
faucet_amount = "1.0"

[mining]
enabled  = false
address  = "rfer1qqty8ah74r7pclvxsdghtmmrr58ffrfd2575x79n"   # HRP must match `network`
threads  = 4

[index]
transactions = true            # required for getbalance / listunspent / the explorer

[telemetry]
metrics  = "127.0.0.1:9100"    # Prometheus
log_format = "json"            # text | json

[consensus]                    # all three optional; see §6 and §7
engine        = "pow"          # pow | bft — forces an engine at every height
config        = "consensus.toml"
validator_key = "validator.key"
```

```sh
./target/release/chaind --config ferrum.toml
```

Two things this file will refuse:

- **Unknown fields.** A mistyped `[minning]` is an error, not a silent no-op — a node that does not
  mine and a config file that says it does is the worst possible pair.
- **A `mining.address` whose prefix does not match `network`.** `fer1…` is mainnet, `tfer1…`
  testnet, `rfer1…` devnet. Getting this wrong fails at startup with
  `mine address "…" could not be decoded`, which is the check working.

`faucet_amount` is a decimal **string**, never a TOML float: no monetary value in this workspace is
ever carried by a binary float.

To see which of the four layers decided each setting without starting anything:

```sh
./target/release/chaind --config ferrum.toml --print-config
```

It prints the resolved configuration as JSON with a `sources` map naming the layer that won each
setting — `flag`, `environment variable`, `config file field` or `network default` — and exits
without touching the store. It is the fastest way to find out why a node is not doing what the
config file says.

`--index` costs disk and is not consensus state; a node without it is fully valid and simply cannot
answer `/api/tx`, `/api/address`, `getbalance` or `listunspent`. Those return a typed
`index disabled` error (RPC/REST code `1007`) rather than empty data, so a stripped-down node can
never be mistaken for an address with no history. `/api/stats` reports `index_enabled`, and the
explorer page says so at the top when it is off.

---

## 4. The published genesis hashes

A network is defined entirely by its `ChainParams`. Nothing is trusted from a file — genesis is
*computed* on startup from those parameters, and a node whose computed genesis differs from its
peers' cannot sync with them. That is the intended behaviour, and it is the same protection
`chain_id` gives signatures.

These are the values this source tree produces. Check yours against them before you conclude your
node is on the network you think it is on:

| Network | Genesis block hash |
|---|---|
| **mainnet** | `8bfd7dc0fc73ed481b3891f433aee3f50f14a847a6de66ccbf2af3f4942ce229` |
| **testnet** | `0271729260045601a991075df86e689acf74eec3aaa930b64513ada36ef18440` |
| **devnet**  | `7747ccde4c1bae8d7f91913e9bcf2f5288c19a54ba0444ed7d21c49f9715008f` |

The fields behind them, shared by all three except where the table says otherwise:

| Field | Value |
|---|---|
| `version` | `1` |
| `prev_hash` | 32 zero bytes |
| `timestamp_ms` | `1735689600000` — 2025-01-01T00:00:00Z |
| `nonce` | `0` |
| `bits` | `0x1d00ffff` on mainnet and testnet, `0x1e00ffff` on devnet — the same mantissa one base-256 digit easier, i.e. 256× |
| coinbase input | `OutPoint::NULL` — 32 zero bytes and `vout = 0xffffffff` — with `sequence = 0xffffffff` |
| coinbase `script_sig` | `0x00` (`OP_0`, the minimal push of height 0, BIP-34) then a push of the ASCII `Ferrum v1 genesis <network>`; 26 bytes on devnet, inside the 2..=100 window rule 14 requires |
| coinbase output | the 50 FRM subsidy, locked to `OP_RETURN <32-byte genesis_commitment>` — provably unspendable, so the subsidy is burned |
| `merkle_root` | mainnet `42dc1be3c6357b0ca832e5b5865ce1d4005ef6f8316cd8246884b9278d2d42c4` |
| | testnet `a689d3978bcd0c2c0fa4d4d2b1cedb22efdbde5eda1d935b2f2d8eea987c2ff5` |
| | devnet `db335655845805ab6351958c5dedfe3e0ec8f3e94745b1716fc42e425a135654` |
| serialized block | 230 bytes on mainnet and testnet, 229 on devnet (`borsh(Block)`) |

Devnet's hash is not merely a different `chain_id`: `genesis_commitment` covers `target_spacing_ms`,
`asert_halflife_s`, `pow_limit`, `coinbase_maturity` and `genesis_bits`, and devnet sets all five
differently (5 000 ms, 300 s, `0x000000ffff00…`, 10 blocks, `0x1e00ffff`). Change any one of
them and this hash changes, which is the point: two nodes that disagree about the difficulty rule
cannot complete a handshake, let alone a sync.

Mainnet and testnet share every structural and monetary rule and differ only in `chain_id` and
address prefix, so without something network-specific *inside* the block they would have the same
genesis hash and a testnet node could complete a header handshake with a mainnet peer. The
`OP_RETURN` payload is `genesis_commitment(params)`, a `TAG_GENESIS` hash over the consensus-critical
parameters, which is why the three hashes above differ at all.

**The fork schedule is inside the commitment.** `bft_activation_height` and the *ordered*
`bft_validators` list are hashed in alongside the monetary and difficulty parameters, so a node whose
`--consensus-config` disagrees with yours — a missed rollout, a validator list in a different order —
fails at startup with a genesis mismatch instead of at the activation height with a permanent fork.
The three hashes above were republished when that changed; a node built before it computes the older
values and will not peer with this tree, which is the check doing its job. See
[`docs/DECISIONS.md`](DECISIONS.md) D11.

### Verifying a hash yourself

Three independent paths, all of which must agree:

```sh
# 1. what a node computes on first start, before it has spoken to anyone
./target/release/chaind --network mainnet --datadir /tmp/g 2>&1 | grep 'genesis initialised'

# 2. what it then serves over RPC
./target/release/chain-cli block hash 0 | tail -1
```

Note what is **not** on that list any more. `chain-cli genesis mine --network devnet --max-tries 1`
used to reprint the devnet hash, because the old devnet target was met by nonce 0. It no longer is:
`0x1e00ffff` needs about 2²⁴ tries, so that command now fails with `no genesis nonce satisfied bits
0x1e00ffff in 1 tries`, exactly as it always has on mainnet. Devnet genesis still carries
`nonce = 0` and still does not satisfy its own `bits` — SPEC §2 exempts genesis from proof-of-work
validation, because there is no parent to validate it against — so this is a property of the
grinder, not a defect in the block. `genesis mine` is for launching a *new* network; see below.

A third path, if you want to check the arithmetic rather than the tooling: the header is the 88
bytes [`ENCODING.md`](ENCODING.md) §3 lays out, and the hash above is
`tagged_hash("ferrum.v1.header", those_88_bytes)`. Every field of it is in the table below, so it
can be rebuilt by hand.

### Launching a *new* network

`genesis mine` grinds a nonce until the header hash meets `--bits`. It is the tool for bringing up a
network of your own, not for reproducing the three hashes above:

```sh
./target/release/chain-cli genesis mine \
    --network mainnet \
    --message "Ferrum genesis - 2026-09-07" \
    --timestamp 1757203200000
```

It prints `nonce=<n> hash=<hex>` as the last line of stdout, plus the merkle root, the tries taken
and the whole block as hex under `--json`. Put the nonce into `ChainParams::genesis_nonce`, publish
the resulting hash, and every joining node verifies it independently.

Two things to know before you run it against mainnet parameters:

- **It will not reproduce any of the three shipped genesis blocks.** Every network's
  `genesis_nonce` is `0`, and a nonce of 0 meets neither `0x1d00ffff` nor `0x1e00ffff`. That is
  deliberate and it is not a defect:
  SPEC §2 exempts genesis from proof-of-work validation, because there is no parent to validate it
  against, so `ChainManager::init_genesis` never checks it. Grinding a nonce and putting it in the
  params changes `genesis_commitment`, which changes the coinbase, the merkle root and the hash —
  in other words it defines a **different network**, which is exactly what this command is for.
- **The search is not the usual nonce bump.** Because the nonce is committed to by the `OP_RETURN`
  payload, every candidate rebuilds the coinbase and the merkle root from scratch. Measured here:
  about 1.1 million candidates per second on one core, so `0x1d00ffff` — roughly 2³² expected
  tries — is on the order of an hour single-threaded. `--start-nonce` and `--max-tries` let you
  split that across machines.

---

## 5. Running a public node

### Hardware

Three small VPSs in three regions is enough: Hetzner CX22 (~$4/month each) or Oracle's free ARM tier.
Add a domain and Cloudflare's free plan and the whole network costs **$15–25/month**.

That number is not a stripped-down estimate — it is what this design actually needs. Quotes an order
of magnitude higher assume archive nodes, a Blockscout deployment and a separate indexer, none of
which exist here.

### systemd

```ini
# /etc/systemd/system/ferrum.service
[Unit]
Description=Ferrum node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ferrum
ExecStart=/usr/local/bin/chaind --config /etc/ferrum/ferrum.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

# The node needs none of this. Take it away.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ferrum
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now ferrum
journalctl -u ferrum -f
```

### Exposing things safely

| Port | Purpose | Expose? |
|---|---|---|
| 8655 | p2p | **yes** — peers need to reach you |
| 8665 | explorer + faucet | yes, behind a reverse proxy |
| 8645 | JSON-RPC | **localhost only**, unless proxied |
| 9100 | Prometheus metrics | **localhost only** |

The RPC surface includes `submitblock` and `sendrawtransaction`. Binding it to `0.0.0.0` without a
proxy hands anyone on the internet an unmetered entry point into your node's validation path. Put it
behind nginx or Cloudflare with rate limiting, or leave it on loopback.

```nginx
location /rpc  { proxy_pass http://127.0.0.1:8645; limit_req zone=rpc burst=20 nodelay; }
location /     { proxy_pass http://127.0.0.1:8665; }
```

### The check that actually matters

Weekly, from a machine that has never run a node:

```sh
./target/release/chaind --network mainnet --datadir /tmp/fresh \
    --peer /dns4/seed1.example.com/tcp/8655
```

It must reach the current tip from genesis with no manual steps, following only the published
instructions. A chain that has quietly become unjoinable is dead, and its dashboards stay green the
whole time. This is the one test that catches that.

Two lines of that run are the ones worth reading:

```
INFO ferrum_chain::manager: genesis initialised hash=6bfa4f… network=mainnet
```

must match §4, and the node's tip must then climb. Note that the faucet is **off** on mainnet and
testnet and **on** by default on devnet; `--faucet` can only switch it on, and
`[explorer] faucet = false` is the only way to switch a configured one off.

---

## 6. Operating a BFT network

A BFT node needs three things, and it refuses to start without any of them: a validator set, an
activation height, and its own signing key.

```sh
# validator.key — one per validator, generated once and kept out of the repository
./target/release/chain-cli --datadir /var/lib/ferrum wallet new --output /etc/ferrum/validator.key
./target/release/chain-cli wallet dump-pubkey --key /etc/ferrum/validator.key   # 64-hex x-only key
```

```toml
# /etc/ferrum/consensus.toml — byte-identical on every node
bft_activation_height = 50000
bft_validators = [
  "9fcef5de6eaf946615be232f38c8c800b96dbd01c81523b74c1395e4a39d85dd",
  "3c6cabc1e9ecccf65760b6139cb47f7aea7fa163b9030c9efcdb4296c17f743a",
  "0cc1991b505cdf50f997214b47cf115eff2d36af77985db51ebfb3a8b8533f88",
  "071a5bb7d7e65dcbc73aca7ad243cb97c44f86f53da6e34b466009741f3db9c2",
]
```

```sh
./target/release/chaind \
    --consensus-config /etc/ferrum/consensus.toml \
    --validator-key    /etc/ferrum/validator.key
```

Note what is **not** in that command. `--consensus bft` forces the BFT engine at *every* height
including zero, and genesis carries a proof-of-work seal, so a node started that way stops
immediately with `seal declares engine 0 but engine 1 is active at this height`. The flag exists to
pin an engine for testing; the way to run a BFT network is an activation height and let
`EngineRouter` do the switching. Likewise, `--consensus bft` with no validator set fails at startup
with `BFT needs at least 4 validators, got 0` — the check working, not a missing feature.

Validators are fixed in `ChainParams::bft_validators`. With `n` validators, `f = (n-1)/3` and quorum
is `2f+1`; the minimum useful set is **four**.

With four validators:

- kill one → the network continues;
- kill two → the network **halts**.

**Halting is correct.** A BFT chain that kept producing blocks without a quorum would be forking, and
a fork is strictly worse than a stop: a halt is visible and recoverable, a fork silently splits
balances. Say this out loud before anyone asks.

The operational commitment for a solo-operated network, stated plainly:

> **This chain may halt for up to 24 hours. It will never fork.**

Alert at exactly two severities and no more: *halted — fix within a day*, and *ignore until the
weekend*. A pager that fires for anything else gets muted, and then the real one gets muted with it.

Under proof-of-work none of this applies: PoW has no liveness obligation, so a halt is impossible by
construction and the operator can sleep.

---

## 7. The PoW → BFT fork on a live chain

Set `bft_activation_height` in the params, ship the binary to every node, and wait.

```toml
# the same consensus.toml as §6, handed to every node with --consensus-config
bft_activation_height = 50000
bft_validators = ["<64-hex x-only key>", "...", "...", "..."]
```

A node with a different activation height or a different validator set is, above the fork, simply on
a different chain. That is the intended failure mode, and it is why `devnet/fork.sh` writes the same
file into all four datadirs rather than letting each node compute its own.

No serialised structure changes. No header field changes. No reindex. History stays valid because
each block is validated by the engine that was active at its height, and `EngineRouter` simply
returns a different `ConsensusEngine` above the activation height.

That property is not luck — it is why the block seal lives outside the header
([`DECISIONS.md`](DECISIONS.md) D2) and why `ferrum-consensus` is forbidden from depending on
`chain` or `storage`. Both constraints were paid for on day one specifically to make this day cheap.

Rehearse it on devnet first. `devnet/fork.sh` sets an activation height ten blocks out and runs it
end to end.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Node syncs headers then stalls | no peer has bodies for the best header chain | check `chain-cli chain peers`; a peer serving headers it cannot back is disconnected automatically |
| `genesis mismatch: this datadir holds X, these parameters give Y` on startup | the datadir belongs to a different network, or your `ChainParams` differ from the network's | you are on a different chain — that is the check working. Compare `Y` against §4, then either fix `--network` or use a fresh datadir |
| Balance is 0 after mining | coinbase outputs are immature for `coinbase_maturity` blocks — 100 on mainnet and testnet, 10 on devnet | `chain-cli wallet balance` shows `immature` separately |
| Balance is 0 and even the address looks unfamiliar | a wrong or missing `--datadir` made a brand-new wallet — `wallet address` creates a keystore when there is none | check `chain-cli --datadir DIR wallet address` against the address you funded; `FERRUM_DATADIR` sets it once for a shell |
| `getbalance`, `/api/tx` or `/api/address` returns `index disabled` (code `1007`) | the node was started without `--index` | stop the node, run `chain-cli --datadir DIR chain reindex`, restart with `--index`. `/api/stats` reports `index_enabled` so you can check without guessing |
| `peer served an invalid header: bits 0x… does not match the required 0x…`, then the peer is banned and the node stops advancing | the two nodes disagree about the difficulty rule itself, which since the anchor became genesis can only mean **different `ChainParams`** — a different `genesis_bits`, `target_spacing_ms`, `asert_halflife_s` or `pow_limit` | compare `chain-cli block hash 0` on both. Different genesis hashes mean different networks and there is nothing to merge; rebuild both from the same source tree. (Before the anchor was fixed this was reachable with *identical* parameters, whenever two nodes held different height-1 blocks — see §2) |
| `block … is already known to be invalid`, forever, after a failed sync | a block was marked `Invalid` in the store during an earlier bad run, and that verdict is sticky | delete the datadir and re-sync; there is no un-invalidate command, deliberately |
| `mine address "fer1..." could not be decoded` | the `mining.address` prefix does not match `network` | `fer1…` mainnet, `tfer1…` testnet, `rfer1…` devnet |
| `no genesis nonce satisfied bits 0x1d00ffff in N tries` | `genesis mine` ran out of budget against a real target | raise `--max-tries`; expect ~2³² tries at roughly 1.1 M/s per core, or ~2²⁴ against devnet's `0x1e00ffff`. See §4 |
| `seal declares engine 0 but engine 1 is active at this height` | `--consensus bft` forced BFT at height 0, where genesis carries a PoW seal | drop `--consensus` and use `--consensus-config` with `bft_activation_height` — §6 |
| `BFT needs at least 4 validators, got 0` | `--consensus bft` without `--consensus-config` | supply the validator set — §6 |
| `--p2p-listen ... is not a valid libp2p multiaddr`, showing a path like `C:/Program Files/Git/ip4/...` | Git Bash / MSYS2 rewrote the multiaddr into a Windows path | `export MSYS2_ARG_CONV_EXCL="*"` before running the binary. `devnet/lib.sh` already does this; it bites only when you invoke `chaind` by hand from Git Bash |
| Blocks are never gossiped | gossipsub `max_transmit_size` too small for your block size | the default 64 KiB is overridden to 4 MiB — check you have not lowered it |
| Mining produces nothing on mainnet | `pow_limit` is genuinely hard — ~2³² hashes, minutes per block per core | use `--network devnet`, which is 256× easier: ~2²⁴ hashes, about 1.9 s per block per core |

Turn up logging with `RUST_LOG=ferrum_node=debug,ferrum_chain=debug,ferrum_p2p=info`, or
`--log-format json` when shipping to a collector.

---

## 9. Legal note, kept short

A public experimental network whose token is never sold, never priced and never promised to
appreciate is an engineering demonstration. Keeping it that way is a set of concrete habits, not a
disclaimer: label it experimental in the README and on the explorer, never run a sale or presale,
never promise returns, do not seek listings, custody nothing for anyone, and put a notice on the
faucet.

If money ever changes hands, India's virtual-digital-asset regime (30 % under s.115BBH, 1 % TDS under
s.194S) and FIU-IND registration become live questions for a chartered accountant and a lawyer. That
is a different project with a different plan.
