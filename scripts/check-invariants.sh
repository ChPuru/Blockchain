#!/usr/bin/env bash
# Structural invariants that no unit test can express.
# These are the rules from docs/CONTRACT.md that must hold across the whole tree.
# Run locally with: bash scripts/check-invariants.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FAIL=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Grep helper: prints offending lines, returns 0 when there are NO matches.
none() { # none <description> <pattern> <path...>
    local desc="$1" pat="$2"; shift 2
    local hits
    hits=$(grep -rnE "$pat" "$@" --include='*.rs' 2>/dev/null | grep -v '^\s*//' || true)
    if [ -n "$hits" ]; then
        fail "$desc"
        echo "$hits" | sed 's/^/       /' | head -20
    else
        pass "$desc"
    fi
}

info "1. Dependency direction"
# consensus is the seam that makes PoW->BFT a config change. It may depend on
# types and crypto and nothing else internal.
CONSENSUS_INTERNAL=$(grep -oE '^ferrum-[a-z0-9]+' crates/consensus/Cargo.toml | sort -u)
BAD=$(echo "$CONSENSUS_INTERNAL" | grep -vE '^ferrum-(types|crypto)$' || true)
if [ -n "$BAD" ]; then
    fail "ferrum-consensus must depend on ferrum-types and ferrum-crypto only"
    echo "$BAD" | sed 's/^/       forbidden: /'
else
    pass "ferrum-consensus depends on ferrum-types + ferrum-crypto only"
fi

# types is the root of the graph and depends on no internal crate.
if grep -qE '^ferrum-' crates/types/Cargo.toml; then
    fail "ferrum-types must not depend on any other internal crate"
else
    pass "ferrum-types depends on no internal crate"
fi

# crypto depends only on types.
CRYPTO_INTERNAL=$(grep -oE '^ferrum-[a-z0-9]+' crates/crypto/Cargo.toml | sort -u)
BAD=$(echo "$CRYPTO_INTERNAL" | grep -vE '^ferrum-types$' || true)
if [ -n "$BAD" ]; then
    fail "ferrum-crypto must depend on ferrum-types only"
    echo "$BAD" | sed 's/^/       forbidden: /'
else
    pass "ferrum-crypto depends on ferrum-types only"
fi

info "2. Backpressure"
none "no unbounded channels anywhere (OOM instead of load-shed)" \
     'unbounded_channel|unbounded\(\)' crates testing

info "3. Networking"
none "mplex is never offered (libp2p deprecates it for liveness)" \
     '\bmplex\b' crates

info "4. Determinism seam"
# Wall-clock and randomness must not appear in the state-transition path.
none "no wall-clock in chain/consensus/script/storage" \
     'SystemTime::now|Instant::now|Utc::now|Local::now' \
     crates/chain/src crates/consensus/src crates/script/src crates/storage/src
none "no RNG in chain/consensus/script" \
     'thread_rng|OsRng|random\(\)' \
     crates/chain/src crates/consensus/src crates/script/src

info "5. No floating point"
none "no f32/f64 in any crate (platform-dependent chain split)" \
     '\bf32\b|\bf64\b|\bas f32\b|\bas f64\b' crates

info "6. No unfinished code"
none "no todo!/unimplemented! left behind" \
     'todo!\(|unimplemented!\(' crates testing

info "7. No unsafe"
none "no unsafe blocks" '\bunsafe\s*\{|\bunsafe\s+fn\b' crates testing

info "8. Blocking storage calls on the async runtime"
# Heuristic: a `.await`-bearing fn that also calls a Store method directly.
HITS=$(grep -rn --include='*.rs' -B2 -A8 'async fn ' crates/node/src crates/rpc/src 2>/dev/null \
       | grep -E 'store\.(connect_block|disconnect_tip|get_block|get_coin|state_root|iter_utxos)\(' \
       | grep -v 'spawn_blocking' || true)
if [ -n "$HITS" ]; then
    printf '  \033[33mwarn\033[0m review these storage calls inside async fns for spawn_blocking:\n'
    echo "$HITS" | sed 's/^/       /' | head -15
else
    pass "no obvious sync storage calls inside async fns"
fi

info "9. Frozen domain tags"
# Every tag string must be unique. Extract the literals and count duplicates.
if [ -f crates/crypto/src/hashing.rs ]; then
    DUPS=$(grep -oE '"ferrum\.v1\.[a-z.]+"' crates/crypto/src/hashing.rs | sort | uniq -d)
    if [ -n "$DUPS" ]; then
        fail "duplicate domain-separation tag literal"
        echo "$DUPS" | sed 's/^/       /'
    else
        pass "all ferrum.v1.* domain tags are distinct literals"
    fi
else
    printf '  \033[33mwarn\033[0m crates/crypto/src/hashing.rs not present yet\n'
fi

info "10. Licence and docs present"
for f in LICENSE-MIT LICENSE-APACHE README.md docs/CONTRACT.md docs/SPEC.md docs/ENCODING.md docs/RUNNING.md; do
    if [ -f "$f" ]; then pass "$f"; else fail "missing $f"; fi
done

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[32mAll structural invariants hold.\033[0m\n'
else
    printf '\033[31mStructural invariants violated.\033[0m\n'
fi
exit "$FAIL"
