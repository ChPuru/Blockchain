#!/usr/bin/env bash
# Hard-kill a node (SIGKILL, no clean shutdown) to exercise crash recovery.
# The store must come back consistent: the tip pointer is written last, inside
# the same write transaction as the block it points at.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
i="${1:?usage: kill.sh <node>}"
pf="$(pid_file "$i")"
[ -f "$pf" ] || die "node $i is not running"
pid="$(cat "$pf")"
echo "SIGKILL node $i (pid $pid) at height $(node_height "$i")"
kill -9 "$pid" 2>/dev/null
rm -f "$pf"
echo "$(c_green killed) — restart with: bash devnet/up.sh $i"
