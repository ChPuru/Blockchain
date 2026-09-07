#!/usr/bin/env bash
# Every node's tip, height, cumulative work and peer count.
# Identical tip hashes across all nodes is the property that matters.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

printf '%-6s %-9s %-9s %-20s %-7s %s\n' NODE STATUS HEIGHT TIP PEERS MEMPOOL
tips=""
for i in $(seq 1 "$NODES"); do
    if ! node_running "$i"; then
        printf '%-6s %-9s %-9s %-20s %-7s %s\n' "$i" "$(c_red down)" "-" "-" "-" "-"
        continue
    fi
    info="$(rpc "$i" getblockchaininfo)"
    h="$(json_field "$info" height)"
    tip="$(json_field "$info" best_hash)"
    mp="$(json_field "$info" mempool_size)"
    peers="$(node_peers "$i")"
    [ -z "$h" ] && { printf '%-6s %-9s %s\n' "$i" "$(c_red 'no rpc')" '-'; continue; }
    printf '%-6s %-9s %-9s %-20s %-7s %s\n' "$i" "$(c_green up)" "$h" "${tip:0:18}" "${peers:-0}" "${mp:-0}"
    tips="$tips $tip"
done

uniq_tips="$(echo "$tips" | tr ' ' '\n' | grep -v '^$' | sort -u | wc -l)"
echo
if [ "$uniq_tips" -eq 1 ]; then
    echo "$(c_green 'CONVERGED') — every node agrees on one tip."
elif [ "$uniq_tips" -eq 0 ]; then
    echo "$(c_red 'no nodes responding')"
else
    # Differing TIPS are not proof of a fork. This script polls nodes one at a
    # time while blocks arrive every second or so, so a node one block behind
    # its neighbour is a measurement artefact, not a divergence. The honest
    # question is whether the nodes agree at a height every one of them has
    # certainly seen.
    lowest=""
    for i in $(seq 1 "$NODES"); do
        node_running "$i" || continue
        h="$(node_height "$i")"
        [ -z "$h" ] && continue
        if [ -z "$lowest" ] || [ "$h" -lt "$lowest" ]; then lowest="$h"; fi
    done
    agreed=""
    if [ -n "$lowest" ] && [ "$lowest" -gt 2 ]; then
        probe=$((lowest - 2))
        agreed="$(for i in $(seq 1 "$NODES"); do
            node_running "$i" || continue
            json_field "$(rpc "$i" getblockhash "[$probe]")" result
        done | grep -v '^$' | sort -u | wc -l | tr -d ' ')"
    fi
    if [ "$agreed" = "1" ]; then
        echo "$(c_green 'CONVERGED') — all nodes agree at height $probe."
        echo "$(c_dim 'The tips differ only because blocks arrive faster than four nodes can be polled.')"
    else
        echo "$(c_red "DIVERGED") — $uniq_tips distinct tips, and they disagree at height ${probe:-?}."
        echo "$(c_dim 'Expected during a partition; a bug otherwise. Fork choice is by cumulative')"
        echo "$(c_dim 'work, not height, so the taller chain need not win.')"
    fi
fi
