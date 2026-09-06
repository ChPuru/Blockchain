#!/usr/bin/env bash
# Start the devnet. With no argument, starts all N nodes fully connected.
# With an argument, restarts just that node (used by kill.sh / heal.sh).
#
#   bash devnet/up.sh          # start all nodes
#   bash devnet/up.sh 3        # restart node 3 only
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_binaries

mkdir -p "$DATA_ROOT"

if [ $# -ge 1 ]; then
    i="$1"
    node_running "$i" && { echo "node $i is already running"; exit 0; }
    echo "starting node $i…"
    start_node "$i" 1 $(peers_full "$i")
    if wait_for_rpc "$i" 60; then
        echo "$(c_green ok) node $i up, height $(node_height "$i"), re-syncing from peers"
    else
        die "node $i did not answer RPC within 60s — see $(log_file "$i")"
    fi
    exit 0
fi

echo "$(c_bold "Starting a $NODES-node Ferrum devnet")"
echo "$(c_dim "data: $DATA_ROOT")"
echo

for i in $(seq 1 "$NODES"); do
    if node_running "$i"; then
        echo "  node $i already running"
        continue
    fi
    # Only nodes 1 and 2 mine. Four miners on one laptop just heats the room and
    # makes the partition demo harder to read.
    mine=0; [ "$i" -le 2 ] && mine=1
    start_node "$i" "$mine" $(peers_full "$i")
    printf '  node %s  rpc :%s  p2p :%s  explorer :%s  %s\n' \
        "$i" "$(rpc_port "$i")" "$(p2p_port "$i")" "$(explorer_port "$i")" \
        "$([ "$mine" = 1 ] && echo "$(c_green mining)" || echo "$(c_dim relay)")"
done

echo
printf 'waiting for RPC'
failed=""
for i in $(seq 1 "$NODES"); do
    if wait_for_rpc "$i" 60; then printf '.'; else printf 'x'; failed="$failed $i"; fi
done
echo

if [ -n "$failed" ]; then
    echo "$(c_red 'nodes failed to start:')$failed"
    for i in $failed; do echo "--- node $i log ---"; tail -20 "$(log_file "$i")"; done
    exit 1
fi

echo
echo "$(c_green 'devnet up.')  explorer: http://127.0.0.1:$(explorer_port 1)"
echo
echo "  bash devnet/status.sh      every node's tip, height and cumulative work"
echo "  bash devnet/partition.sh   split the network in two; both halves keep mining"
echo "  bash devnet/heal.sh        reconnect and watch the lower-work branch get reorged away"
echo "  bash devnet/down.sh        stop everything"
