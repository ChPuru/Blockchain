#!/usr/bin/env bash
# Stop every devnet node. Add --clean to also delete the chain data.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for i in $(seq 1 "$NODES"); do
    if node_running "$i"; then
        printf 'stopping node %s… ' "$i"
        stop_node "$i"
        echo "$(c_green done)"
    else
        stop_node "$i"
    fi
done

if [ "${1:-}" = "--clean" ]; then
    rm -rf "$DATA_ROOT"
    echo "$(c_dim "removed $DATA_ROOT")"
fi
echo "$(c_green 'devnet down.')"
