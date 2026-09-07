#!/usr/bin/env bash
# Shared helpers for the devnet scripts. Sourced, not executed.
#
# Port scheme, node i in 1..N:
#   RPC       8645 + (i-1)
#   P2P       8655 + (i-1)
#   Explorer  8665 + (i-1)
#   Metrics   9100 + (i-1)

set -uo pipefail

# Git Bash / MSYS2 rewrites any argument that looks like a Unix path into a
# Windows one, so `--p2p-listen /ip4/127.0.0.1/tcp/8655` arrives at the binary as
# `C:/Program Files/Git/ip4/127.0.0.1/tcp/8655` and every multiaddr flag fails.
# Excluding all arguments from that conversion is the documented fix and is a
# no-op on Linux and macOS.
export MSYS2_ARG_CONV_EXCL="*"
export MSYS_NO_PATHCONV=1

DEVNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEVNET_DIR/.." && pwd)"
DATA_ROOT="${FERRUM_DEVNET_DATA:-$DEVNET_DIR/data}"
NODES="${FERRUM_DEVNET_NODES:-4}"

# Prefer a release build; fall back to debug so `cargo build` alone is enough.
if [ -x "$REPO_ROOT/target/release/chaind" ] || [ -x "$REPO_ROOT/target/release/chaind.exe" ]; then
    BIN_DIR="$REPO_ROOT/target/release"
else
    BIN_DIR="$REPO_ROOT/target/debug"
fi
EXE=""
[ -x "$BIN_DIR/chaind.exe" ] && EXE=".exe"
CHAIND="$BIN_DIR/chaind$EXE"
CHAINCLI="$BIN_DIR/chain-cli$EXE"

rpc_port()      { echo $((8645 + $1 - 1)); }
p2p_port()      { echo $((8655 + $1 - 1)); }
explorer_port() { echo $((8665 + $1 - 1)); }
metrics_port()  { echo $((9100 + $1 - 1)); }
node_dir()      { echo "$DATA_ROOT/node$1"; }
pid_file()      { echo "$DATA_ROOT/node$1.pid"; }
log_file()      { echo "$DATA_ROOT/node$1.log"; }
peer_addr()     { echo "/ip4/127.0.0.1/tcp/$(p2p_port "$1")"; }

c_red()   { printf '\033[31m%s\033[0m' "$*"; }
c_green() { printf '\033[32m%s\033[0m' "$*"; }
c_dim()   { printf '\033[2m%s\033[0m' "$*"; }
c_bold()  { printf '\033[1m%s\033[0m' "$*"; }

die() { printf '%s %s\n' "$(c_red 'error:')" "$*" >&2; exit 1; }

require_binaries() {
    [ -x "$CHAIND" ]   || die "chaind not found at $CHAIND — run: cargo build --release"
    [ -x "$CHAINCLI" ] || die "chain-cli not found at $CHAINCLI — run: cargo build --release"
}

# JSON-RPC call: rpc <node> <method> [params-json]
rpc() {
    local n="$1" method="$2" params="${3:-[]}"
    curl -s --max-time 10 \
        -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "http://127.0.0.1:$(rpc_port "$n")" 2>/dev/null
}

# Pull one field out of a JSON-RPC result without needing jq.
json_field() { # json_field <json> <key>
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^,\"}]*\)\"\{0,1\}.*/\1/p" | head -1
}

node_height() { json_field "$(rpc "$1" getblockchaininfo)" height; }
node_tip()    { json_field "$(rpc "$1" getblockchaininfo)" best_hash; }
node_work()   { json_field "$(rpc "$1" getblockchaininfo)" total_work; }
node_peers()  { json_field "$(rpc "$1" getnetworkinfo)" peer_count; }

node_running() {
    local pf; pf="$(pid_file "$1")"
    [ -f "$pf" ] || return 1
    local pid; pid="$(cat "$pf" 2>/dev/null)"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

# Block until a node answers RPC, or fail after `timeout` seconds.
wait_for_rpc() { # wait_for_rpc <node> [timeout_s]
    local n="$1" timeout="${2:-45}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if [ -n "$(node_height "$n")" ]; then return 0; fi
        sleep 1; waited=$((waited + 1))
    done
    return 1
}

# Block until every listed node reports the same tip hash.
# This is the assertion that matters: convergence, not just liveness.
wait_for_convergence() { # wait_for_convergence <timeout_s> <node>...
    local timeout="$1"; shift
    local nodes=("$@") waited=0
    while [ "$waited" -lt "$timeout" ]; do
        local first="" same=1
        for n in "${nodes[@]}"; do
            local tip; tip="$(node_tip "$n")"
            [ -z "$tip" ] && { same=0; break; }
            [ -z "$first" ] && first="$tip"
            [ "$tip" != "$first" ] && { same=0; break; }
        done
        [ "$same" -eq 1 ] && [ -n "$first" ] && { echo "$first"; return 0; }
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

# Block until a node's height advances by `n` from where it is now.
wait_for_growth() { # wait_for_growth <node> <blocks> <timeout_s>
    local node="$1" want="$2" timeout="${3:-120}"
    local start; start="$(node_height "$node")"
    [ -z "$start" ] && return 1
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        local now; now="$(node_height "$node")"
        [ -n "$now" ] && [ "$((now - start))" -ge "$want" ] && return 0
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

# start_node <i> <mine:0|1> <peer-node>...
start_node() {
    local i="$1" mine="$2"; shift 2
    local dir; dir="$(node_dir "$i")"
    mkdir -p "$dir"

    local args=(
        --network devnet
        --datadir "$dir"
        --rpc-listen "127.0.0.1:$(rpc_port "$i")"
        --p2p-listen "/ip4/127.0.0.1/tcp/$(p2p_port "$i")"
        --explorer-listen "127.0.0.1:$(explorer_port "$i")"
        --metrics-listen "127.0.0.1:$(metrics_port "$i")"
        --index
        --log-format text
    )
    for p in "$@"; do args+=(--peer "$(peer_addr "$p")"); done
    # Without --mine-address the node mines to an address derived from its own
    # key file, which is what makes a devnet startable with no wallet setup.
    [ "$mine" = "1" ] && args+=(--mine)

    RUST_LOG="${RUST_LOG:-ferrum_node=info,ferrum_chain=info,ferrum_p2p=warn}" \
        "$CHAIND" "${args[@]}" >"$(log_file "$i")" 2>&1 &
    echo $! > "$(pid_file "$i")"
}

stop_node() {
    local i="$1" pf; pf="$(pid_file "$i")"
    [ -f "$pf" ] || return 0
    local pid; pid="$(cat "$pf" 2>/dev/null)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        # SIGTERM so the node flushes its store and writes the tip pointer last.
        kill "$pid" 2>/dev/null
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 15 ]; do sleep 1; waited=$((waited+1)); done
        kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$pf"
}

# The peer sets for each topology. Partitioning is done by restarting nodes with
# a narrower static peer list rather than with iptables, so it works identically
# on Windows, macOS and Linux CI and needs no privileges.
peers_full()  { # peers_full <i> -> every other node
    local i="$1"
    for j in $(seq 1 "$NODES"); do [ "$j" != "$i" ] && printf '%s ' "$j"; done
}
peers_side()  { # peers_side <i> -> only nodes on the same side of the split
    local i="$1" half=$(( (NODES + 1) / 2 ))
    if [ "$i" -le "$half" ]; then
        for j in $(seq 1 "$half");        do [ "$j" != "$i" ] && printf '%s ' "$j"; done
    else
        for j in $(seq $((half+1)) "$NODES"); do [ "$j" != "$i" ] && printf '%s ' "$j"; done
    fi
}
