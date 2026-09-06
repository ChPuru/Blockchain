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
    echo "$(c_red "DIVERGED") — $uniq_tips distinct tips. Expected during a partition; a bug otherwise."
    echo "$(c_dim 'Fork choice is by cumulative work, not height, so the taller chain need not win.')"
fi
