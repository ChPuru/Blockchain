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
git clone https://github.com/rahuldhali/ferrum && cd ferrum
cargo build --release
```

Two binaries land in `target/release/`: **`chaind`** (the node) and **`chain-cli`** (wallet and
admin).

---

## 1. A chain on your laptop, in one minute

```sh
./target/release/chaind --network devnet --mine --datadir ./data
```

Devnet uses a trivially easy `pow_limit`, so blocks appear in seconds rather than minutes. In another
shell:

```sh
./target/release/chain-cli chain info
./target/release/chain-cli wallet new                 # writes an encrypted keystore, prints the mnemonic
./target/release/chain-cli wallet address
./target/release/chain-cli wallet balance
```

To mine to your own address rather than a throwaway one, restart with
`--mine-address rfer1...`. Coinbase outputs mature after **100 blocks**; until then they show as
`immature` and cannot be spent. That is a consensus rule, not a wallet policy — a chain that let you
spend a coinbase immediately would lose those coins on any reorg deeper than the spend.

Send a transaction:

```sh
./target/release/chain-cli wallet send --to rfer1... --amount 1.5 --fee-rate 1000
./target/release/chain-cli tx get <txid>
```

**Write down the mnemonic.** There is no recovery path, by design — the plaintext seed never touches
disk, and `chain-cli wallet restore` is the only way back in.

---

## 2. The four-node devnet, including the reorg demonstration

This is the part worth watching, because it is what separates a working chain from a hash-linked
list.

```sh
bash devnet/up.sh
```

Four nodes: RPC on `8645..8648`, p2p on `8655..8658`, metrics on `9100..9103`, and the explorer on
<http://127.0.0.1:8665>. All four share a genesis and a static peer list.

```sh
bash devnet/status.sh          # every node's tip hash, height and cumulative work
```

All four tips should be identical. Now split the network:

```sh
bash devnet/partition.sh       # nodes 1+2 | nodes 3+4, both halves keep mining
bash devnet/status.sh          # two different tips, both valid, both growing
bash devnet/heal.sh            # reconnect
bash devnet/status.sh          # one tip again, on the branch with more cumulative work
```

What you are watching in the logs of the losing side is a real reorganisation: blocks disconnected
using their stored undo records, the UTXO set rolled backwards, the mempool reconciled, then the
winning branch connected forward. Note that the winner is the branch with more **cumulative work**,
not the longer one — a chain of a hundred easy blocks can be worth less than ten hard ones.

```sh
bash devnet/down.sh
```

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
address  = "fer1..."
threads  = 4

[index]
transactions = true            # required for getbalance / listunspent / the explorer

[telemetry]
metrics  = "127.0.0.1:9100"    # Prometheus
log_format = "json"            # text | json
```

```sh
./target/release/chaind --config ferrum.toml
```

`--index` costs disk and is not consensus state; a node without it is fully valid and simply cannot
answer address queries.

---

## 4. Launching your own network

A new network is defined entirely by its `ChainParams`. Nothing is trusted from a file — genesis is
*computed* on startup and compared against the published hash, so a node whose parameters differ
cannot sync with yours. That is the intended behaviour, and it is the same protection `chain_id`
gives signatures.

```sh
./target/release/chain-cli genesis mine \
    --network mainnet \
    --message "Ferrum genesis - 2026-09-07" \
    --timestamp 1757203200000
```

This grinds a genesis block and prints its nonce and hash. Put the nonce into your params, publish
the hash in your README, and every joining node verifies it independently.

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

---

## 6. Operating a BFT network

```sh
./target/release/chaind --consensus bft --validator-key /etc/ferrum/validator.key
```

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
bft_activation_height = 50000
bft_validators = ["<32-byte x-only key>", "...", "...", "..."]
```

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
| `genesis hash mismatch` on startup | your `ChainParams` differ from the network's | you are on a different chain — that is the check working |
| Balance is 0 after mining | coinbase outputs are immature for 100 blocks | `chain-cli wallet balance` shows `immature` separately |
| `getbalance` returns an error | the node was started without `--index` | restart with `--index`; a reindex is required |
| `--p2p-listen ... is not a valid libp2p multiaddr`, showing a path like `C:/Program Files/Git/ip4/...` | Git Bash / MSYS2 rewrote the multiaddr into a Windows path | `export MSYS2_ARG_CONV_EXCL="*"` before running the binary. `devnet/lib.sh` already does this; it bites only when you invoke `chaind` by hand from Git Bash |
| Blocks are never gossiped | gossipsub `max_transmit_size` too small for your block size | the default 64 KiB is overridden to 4 MiB — check you have not lowered it |
| Mining produces nothing on mainnet | `pow_limit` is genuinely hard | use `--network devnet` to see the machinery work |

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
