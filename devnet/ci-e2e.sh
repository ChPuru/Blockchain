#!/usr/bin/env bash
# The end-to-end test CI runs. Non-interactive, self-cleaning, and it fails loudly.
#
# Six assertions, in order of how much they prove:
#   1. four nodes start and reach each other
#   2. they converge on one tip
#   3. a transaction submitted to node 1 is mined and visible from node 3
#   4. a hard-killed node comes back consistent and re-syncs
#   5. a partitioned network diverges
#   6. a healed network converges again, which means a real reorg completed
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_binaries

FAILURES=0
step()   { echo; echo "$(c_bold "── $* ")"; }
ok()     { echo "  $(c_green PASS) $*"; }
bad()    { echo "  $(c_red FAIL) $*"; FAILURES=$((FAILURES + 1)); }

dump_logs() {
    for i in $(seq 1 "$NODES"); do
        echo "───── node $i (last 40 lines) ─────"
        tail -40 "$(log_file "$i")" 2>/dev/null || echo "(no log)"
    done
}
cleanup() {
    local code=$?
    [ "$code" -ne 0 ] && dump_logs
    bash "$DEVNET_DIR/down.sh" --clean >/dev/null 2>&1 || true
    exit "$code"
}
trap cleanup EXIT

# Always start from nothing, so a stale datadir cannot make this pass.
bash "$DEVNET_DIR/down.sh" --clean >/dev/null 2>&1 || true

step "1. start $NODES nodes"
bash "$DEVNET_DIR/up.sh" >/dev/null || { bad "nodes did not start"; exit 1; }
for i in $(seq 1 "$NODES"); do
    if wait_for_rpc "$i" 90; then ok "node $i answering RPC"; else bad "node $i never answered RPC"; fi
done
[ "$FAILURES" -gt 0 ] && exit 1

step "2. mine and converge"
wait_for_growth 1 5 180 || bad "node 1 did not mine 5 blocks in 180s"
if tip="$(wait_for_convergence 180 $(seq 1 "$NODES" | tr '\n' ' '))"; then
    ok "all $NODES nodes on tip ${tip:0:16} at height $(node_height 1)"
else
    bad "nodes did not converge"; bash "$DEVNET_DIR/status.sh"
fi

step "3. a transaction crosses the network"
# Coinbase outputs are immature for 100 blocks, so wait them out before spending.
# That maturity rule is consensus, not policy: spending a coinbase sooner would
# lose the coins on any reorg deeper than the spend.
MATURITY=100
echo "  mining past coinbase maturity ($MATURITY blocks)…"
if wait_for_growth 1 "$((MATURITY + 5))" 900; then
    addr="$("$CHAINCLI" --rpc "http://127.0.0.1:$(rpc_port 2)" wallet address 2>/dev/null | tail -1)"
    if [ -n "$addr" ]; then
        txid="$("$CHAINCLI" --rpc "http://127.0.0.1:$(rpc_port 1)" wallet send \
                 --to "$addr" --amount 1.0 2>/dev/null | tail -1)"
        if [ -n "$txid" ]; then
            ok "submitted $txid to node 1"
            found=0
            for _ in $(seq 1 60); do
                if [ -n "$(json_field "$(rpc 3 getrawtransaction "[\"$txid\"]")" txid)" ]; then found=1; break; fi
                sleep 2
            done
            [ "$found" = 1 ] && ok "node 3 sees the transaction" || bad "node 3 never saw $txid"
        else
            bad "wallet send produced no txid"
        fi
    else
        bad "could not obtain an address from node 2"
    fi
else
    bad "chain did not reach coinbase maturity in 900s"
fi

step "4. crash recovery"
h_before="$(node_height 3)"
bash "$DEVNET_DIR/kill.sh" 3 >/dev/null
bash "$DEVNET_DIR/up.sh" 3 >/dev/null
if wait_for_rpc 3 90; then
    h_after="$(node_height 3)"
    if [ -n "$h_after" ] && [ "$h_after" -ge "$((h_before - 1))" ]; then
        ok "node 3 recovered from SIGKILL at height $h_after (was $h_before)"
    else
        bad "node 3 lost blocks across a hard kill: $h_before -> $h_after"
    fi
else
    bad "node 3 did not come back after SIGKILL"
fi

step "5. partition"
bash "$DEVNET_DIR/partition.sh" >/dev/null
sleep 45     # let both halves build visibly different branches
tip_a="$(node_tip 1)"; tip_b="$(node_tip "$NODES")"
if [ -n "$tip_a" ] && [ -n "$tip_b" ] && [ "$tip_a" != "$tip_b" ]; then
    ok "network split: A at $(node_height 1), B at $(node_height "$NODES")"
else
    bad "partition did not produce two branches (A=$tip_a B=$tip_b)"
fi

step "6. heal, and require a real reorg to complete"
bash "$DEVNET_DIR/partition.sh" >/dev/null 2>&1 || true
if bash "$DEVNET_DIR/heal.sh"; then
    ok "network reconverged after the partition"
else
    bad "network did not reconverge — fork choice, relay or reorg is broken"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "$(c_green "ALL E2E CHECKS PASSED")"
    exit 0
else
    echo "$(c_red "$FAILURES E2E CHECK(S) FAILED")"
    exit 1
fi
