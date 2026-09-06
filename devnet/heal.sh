#!/usr/bin/env bash
# Reconnect a partitioned network and watch it resolve.
#
# This is the money shot. Both halves hold a valid chain from the same ancestor.
# On reconnection every node must converge on the branch with the greater
# CUMULATIVE WORK — not the greater height — and the losing side must roll its
# UTXO set backwards using each block's stored undo record, reconcile its
# mempool, and connect the winning branch forward.
#
# A chain that gets this wrong looks perfectly healthy right up until it does not.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_binaries

HALF=$(( (NODES + 1) / 2 ))

echo "$(c_bold 'Before healing')"
printf '%-6s %-9s %-20s %s\n' NODE HEIGHT TIP WORK
for i in $(seq 1 "$NODES"); do
    node_running "$i" || continue
    printf '%-6s %-9s %-20s %s\n' "$i" "$(node_height "$i")" "$(node_tip "$i" | cut -c1-18)" \
        "$(node_work "$i" | cut -c1-20)"
done

a_tip="$(node_tip 1)"
b_tip="$(node_tip "$NODES")"
a_h="$(node_height 1)"
b_h="$(node_height "$NODES")"

echo
if [ "$a_tip" = "$b_tip" ]; then
    echo "$(c_dim 'Both sides already agree — nothing to heal. Run partition.sh first,')"
    echo "$(c_dim 'and give it a minute so the branches actually diverge.')"
fi

echo "$(c_bold 'Reconnecting…')"
for i in $(seq 1 "$NODES"); do stop_node "$i"; done
for i in $(seq 1 "$NODES"); do
    mine=0; [ "$i" -le 2 ] && mine=1
    start_node "$i" "$mine" $(peers_full "$i")
done

printf 'waiting for RPC'
for i in $(seq 1 "$NODES"); do wait_for_rpc "$i" 60 >/dev/null && printf '.' || printf 'x'; done
echo

echo "waiting for convergence…"
nodes_list=$(seq 1 "$NODES" | tr '\n' ' ')
if tip="$(wait_for_convergence 180 $nodes_list)"; then
    echo
    echo "$(c_green 'CONVERGED') on ${tip:0:18}"
    echo
    printf '%-6s %-9s %-20s\n' NODE HEIGHT TIP
    for i in $(seq 1 "$NODES"); do
        printf '%-6s %-9s %-20s\n' "$i" "$(node_height "$i")" "$(node_tip "$i" | cut -c1-18)"
    done
    echo
    if [ "$tip" = "$a_tip" ]; then
        echo "Side A won (was height $a_h). Side B reorged from $b_h."
        loser=$NODES
    elif [ "$tip" = "$b_tip" ]; then
        echo "Side B won (was height $b_h). Side A reorged from $a_h."
        loser=1
    else
        echo "Both sides reorged onto a branch mined after reconnection."
        loser=1
    fi
    echo
    echo "$(c_bold 'Reorg, as the losing node saw it:')"
    grep -iE 'reorg|disconnect|rolled back|new tip' "$(log_file "$loser")" | tail -12 \
        || echo "$(c_dim '(no reorg lines in the log — check the log format)')"
else
    echo
    echo "$(c_red 'DID NOT CONVERGE within 180s.')"
    bash "$DEVNET_DIR/status.sh"
    echo
    echo "That is a real bug, not a flake. Fork choice, block relay or reorg is broken."
    exit 1
fi
