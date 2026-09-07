#!/usr/bin/env bash
# Split the network in two. Both halves keep mining, so both build valid chains
# from the same common ancestor.
#
# The split is done by restarting each node with a narrower static peer list
# rather than with iptables: it needs no privileges and behaves identically on
# Windows, macOS and Linux CI. The chain data is kept, so each half genuinely
# continues from where it was.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_binaries

HALF=$(( (NODES + 1) / 2 ))
LEFT=$(seq 1 "$HALF" | tr '\n' ' ')
RIGHT=$(seq $((HALF + 1)) "$NODES" | tr '\n' ' ')

ancestor_tip="$(node_tip 1)"
ancestor_height="$(node_height 1)"
echo "$(c_bold 'Partitioning the network')"
echo "  common ancestor: height ${ancestor_height:-?}  ${ancestor_tip:0:18}"
echo "  side A: $LEFT"
echo "  side B: $RIGHT"
echo

for i in $(seq 1 "$NODES"); do stop_node "$i"; done

# Both sides must mine, or one simply stalls and there is nothing to reorg.
for i in $(seq 1 "$NODES"); do
    start_node "$i" 1 $(peers_side "$i")
done

printf 'waiting for RPC'
for i in $(seq 1 "$NODES"); do wait_for_rpc "$i" 60 >/dev/null && printf '.' || printf 'x'; done
echo; echo

echo "$(c_green 'partitioned.')  Both halves are now mining independently."
echo
echo "  bash devnet/status.sh   should show two distinct tips"
echo "  bash devnet/heal.sh     reconnect; the branch with less cumulative work is reorged away"
echo
echo "$(c_dim 'Give it twenty or thirty seconds: at the 5 s devnet spacing that is a')"
echo "$(c_dim 'few dozen blocks per side, so healing it exercises a real reorg.')"
