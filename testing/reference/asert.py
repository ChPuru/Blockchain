#!/usr/bin/env python3
"""Independent reference implementation of Ferrum's ASERT (`aserti3-2d`).

This file is written from `docs/CONTRACT.md` section 6.3 and `docs/SPEC.md`
section 6.2 alone.  It deliberately does not consult `crates/consensus/`: two
implementations written from the same paragraph still catch a misreading of that
paragraph, and one does not.  That is this project's substitute for an audit of
the difficulty controller.

The anchor is **genesis**: `anchor_height = 0`, `anchor_target` from
`params.genesis_bits`, `anchor_time_s` from `params.genesis_timestamp_ms`.  All
three come out of the parameter set, so every node has byte-identical anchor
values before it has spoken to a peer.  Anchoring on a block read out of the
chain -- "the block at height 1 on the active chain", as this was originally
specified -- makes difficulty fork-dependent: two nodes holding different blocks
at the anchor height compute different required `bits` for each other's headers,
reject them, and fork permanently, because a header that fails validation never
reaches fork choice.  Bitcoin Cash's `aserti3-2d` pins a fixed anchor for exactly
this reason.

Everything here is exact integer arithmetic.  Python's ints are arbitrary
precision, so there is no overflow to reason about -- which is exactly why it is
a useful cross-check against a Rust implementation that has to bound every
intermediate to 128, 256 or 512 bits.

Usage
-----

    python testing/reference/asert.py --selftest
    python testing/reference/asert.py --generate testing/reference/asert_vectors.json
    python testing/reference/asert.py --verify   testing/reference/asert_vectors.json

`--verify` recomputes every case from its inputs and requires an exact match, so
running it after `--generate` proves the file on disk is what this code says.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys

# --------------------------------------------------------------------------
# Constants (CONTRACT 6.1, 6.3)
# --------------------------------------------------------------------------

#: Fixed-point radix: the ASERT exponent counts 1/65536-ths of a half-life.
RADIX = 65536

#: Bound applied to the exponent before it is split into shifts and frac.
#: 2**25 corresponds to shifts = +-512.  A shift of +512 always overflows 256
#: bits (the product is at least 65536, so it has at least 17 bits) and a shift
#: of -512 always drives the at-most-273-bit product to zero, so both ends
#: already saturate and the clamp cannot change an answer.  It exists so that
#: the Rust side can stay inside i64 and so that this script never allocates a
#: gigabit integer.
EXPONENT_CLAMP = 1 << 25

#: Cubic approximation of 2**(frac/65536), relative error below 0.013 %.
CUBIC_C1 = 195_766_423_245_049
CUBIC_C2 = 971_821_376
CUBIC_C3 = 5_127
CUBIC_ROUND = 1 << 47
CUBIC_SHIFT = 48

#: Compact-target field masks.
COMPACT_MANTISSA_MASK = 0x00FFFFFF
COMPACT_SIGN_BIT = 0x00800000

#: The height the schedule is anchored at: genesis.  Fixed by ChainParams,
#: identical on every node, and impossible to reorg away.  Genesis itself is the
#: only block exempt from the difficulty-transition rule, and only because it has
#: no parent; its child at height 1 is on the ASERT schedule like every other
#: block.  See the module docstring for why this may not be read from the chain.
ANCHOR_HEIGHT = 0

#: Mainnet / testnet pow_limit: 0x00000000ffff0000...
POW_LIMIT_MAINNET = int("00000000ffff" + "0" * 52, 16)

#: Devnet pow_limit: 0x7fffffff...ff
POW_LIMIT_DEVNET = int("7f" + "ff" * 31, 16)


class CompactError(ValueError):
    """A compact target that Ferrum rejects rather than normalises."""


# --------------------------------------------------------------------------
# Compact target encoding (CONTRACT 6.1)
# --------------------------------------------------------------------------


def compact_to_target(compact: int) -> int:
    """Expand a 32-bit compact target into a 256-bit integer.

    Rejects the negative form, a zero mantissa with a non-zero exponent, and any
    expansion needing more than 256 bits.
    """
    if not 0 <= compact <= 0xFFFFFFFF:
        raise CompactError("compact target is not a u32: %r" % (compact,))

    size = (compact >> 24) & 0xFF
    mantissa = compact & COMPACT_MANTISSA_MASK

    if mantissa & COMPACT_SIGN_BIT:
        raise CompactError("compact target %#010x sets the sign bit" % compact)
    if mantissa == 0:
        if size != 0:
            raise CompactError(
                "compact target %#010x has a zero mantissa with a non-zero exponent" % compact
            )
        return 0

    if size <= 3:
        return mantissa >> (8 * (3 - size))

    target = mantissa << (8 * (size - 3))
    if target.bit_length() > 256:
        raise CompactError("compact target %#010x expands past 256 bits" % compact)
    return target


def target_to_compact(target: int) -> int:
    """Compress a 256-bit target into its canonical compact form."""
    if target < 0:
        raise CompactError("a target is never negative")
    if target == 0:
        return 0

    size = (target.bit_length() + 7) // 8
    if size <= 3:
        mantissa = target << (8 * (3 - size))
    else:
        mantissa = target >> (8 * (size - 3))

    # The mantissa's top bit is the sign bit: shed a byte rather than emit the
    # negative form.
    if mantissa & COMPACT_SIGN_BIT:
        mantissa >>= 8
        size += 1

    return (size << 24) | (mantissa & COMPACT_MANTISSA_MASK)


def is_canonical_compact(compact: int) -> bool:
    """True when `compact` is the canonical spelling of what it expands to."""
    try:
        return target_to_compact(compact_to_target(compact)) == compact
    except CompactError:
        return False


def work_from_target(target: int) -> int:
    """Fork-choice weight: (~target / (target + 1)) + 1 in 256-bit integers."""
    mask = (1 << 256) - 1
    inverted = (~target) & mask
    denominator = min(target + 1, mask)
    if denominator == 0:
        return mask
    return min(inverted // denominator + 1, mask)


# --------------------------------------------------------------------------
# ASERT (CONTRACT 6.3)
# --------------------------------------------------------------------------


def truncating_div(numerator: int, denominator: int) -> int:
    """Integer division that truncates toward zero, as C and Rust do.

    Python's `//` floors, which is a different answer for negative numerators.
    Getting this wrong biases the controller asymmetrically between speed-ups
    and slow-downs, which is precisely the bug this file exists to catch.
    """
    if denominator == 0:
        raise ZeroDivisionError("halflife must not be zero")
    quotient = abs(numerator) // abs(denominator)
    if (numerator < 0) != (denominator < 0):
        quotient = -quotient
    return quotient


def asert_exponent(
    anchor_time_s: int,
    anchor_height: int,
    parent_time_s: int,
    parent_height: int,
    target_spacing_s: int,
    halflife_s: int,
) -> int:
    """The clamped fixed-point exponent, in 1/65536-ths of a half-life."""
    if halflife_s <= 0:
        raise ValueError("halflife_s must be positive")
    if target_spacing_s <= 0:
        raise ValueError("target_spacing_s must be positive")

    time_diff = parent_time_s - anchor_time_s
    height_diff = parent_height - anchor_height
    scheduled = target_spacing_s * (height_diff + 1)
    exponent = truncating_div((time_diff - scheduled) * RADIX, halflife_s)
    return max(-EXPONENT_CLAMP, min(EXPONENT_CLAMP, exponent))


def split_exponent(exponent: int) -> tuple[int, int]:
    """Split into (shifts, frac).

    `>>` on a Python int is an arithmetic (floor) shift and `& 0xffff` on a
    negative int yields its two's-complement low bits, so `frac` lands in
    [0, 65536) for negative exponents without any correction.
    """
    return exponent >> 16, exponent & 0xFFFF


def asert_factor(frac: int) -> int:
    """65536 * 2**(frac/65536), by the frozen cubic approximation."""
    if not 0 <= frac < RADIX:
        raise ValueError("frac must be in [0, 65536): %r" % (frac,))
    polynomial = (
        CUBIC_C1 * frac
        + CUBIC_C2 * frac * frac
        + CUBIC_C3 * frac * frac * frac
        + CUBIC_ROUND
    )
    return RADIX + (polynomial >> CUBIC_SHIFT)


def asert_next_target(
    anchor_target: int,
    anchor_time_s: int,
    anchor_height: int,
    parent_time_s: int,
    parent_height: int,
    target_spacing_s: int,
    halflife_s: int,
    pow_limit: int,
) -> int:
    """The target for the child of the block described by `parent_*`."""
    if pow_limit <= 0:
        raise ValueError("pow_limit must be positive")
    if anchor_target < 0:
        raise ValueError("anchor_target must not be negative")

    exponent = asert_exponent(
        anchor_time_s,
        anchor_height,
        parent_time_s,
        parent_height,
        target_spacing_s,
        halflife_s,
    )
    shifts, frac = split_exponent(exponent)
    factor = asert_factor(frac)

    next_target = anchor_target * factor
    if shifts < 0:
        next_target >>= -shifts
    else:
        next_target <<= shifts
    next_target >>= 16

    if next_target == 0:
        next_target = 1
    if next_target > pow_limit:
        next_target = pow_limit
    return next_target


def asert_next_bits(
    anchor_bits: int,
    anchor_time_s: int,
    anchor_height: int,
    parent_time_s: int,
    parent_height: int,
    target_spacing_s: int,
    halflife_s: int,
    pow_limit: int,
) -> int:
    """`asert_next_target`, compressed to the compact form a header carries."""
    return target_to_compact(
        asert_next_target(
            compact_to_target(anchor_bits),
            anchor_time_s,
            anchor_height,
            parent_time_s,
            parent_height,
            target_spacing_s,
            halflife_s,
            pow_limit,
        )
    )


# --------------------------------------------------------------------------
# Vector generation
# --------------------------------------------------------------------------

#: The anchor timestamp for the generated vectors: `genesis_timestamp_ms / 1000`
#: for every Ferrum network, 2025-01-01T00:00:00Z.  The anchor is genesis, so
#: this is literally the anchor time a node uses.
GENESIS_TIME_S = 1_735_689_600  # 2025-01-01T00:00:00Z
SPACING_S = 120
HALFLIFE_S = 7_200

#: Every anchor `bits` used by the generated vectors.  All are canonical.
ANCHOR_BITS = [
    0x1D00FFFF,  # the mainnet pow_limit itself
    0x1B0404CB,  # a historically real Bitcoin difficulty
    0x1900FFFF,  # 2**32 harder than the limit: room to move both ways
    0x1C0FFFF0,
    0x207FFFFF,  # the easiest representable target
    0x1E00FFFF,
]


def _pow_limit_for(bits: int) -> int:
    """Pick a pow_limit that the anchor target actually fits under."""
    if compact_to_target(bits) <= POW_LIMIT_MAINNET:
        return POW_LIMIT_MAINNET
    return POW_LIMIT_DEVNET


def _case(name: str, anchor_bits: int, parent_time_s: int, parent_height: int,
          spacing: int = SPACING_S, halflife: int = HALFLIFE_S,
          pow_limit: int | None = None, anchor_time_s: int = GENESIS_TIME_S,
          anchor_height: int = ANCHOR_HEIGHT) -> dict:
    limit = _pow_limit_for(anchor_bits) if pow_limit is None else pow_limit
    exponent = asert_exponent(
        anchor_time_s, anchor_height, parent_time_s, parent_height, spacing, halflife
    )
    shifts, frac = split_exponent(exponent)
    target = asert_next_target(
        compact_to_target(anchor_bits),
        anchor_time_s,
        anchor_height,
        parent_time_s,
        parent_height,
        spacing,
        halflife,
        limit,
    )
    return {
        "name": name,
        "anchor_bits": anchor_bits,
        "anchor_time_s": anchor_time_s,
        "anchor_height": anchor_height,
        "parent_time_s": parent_time_s,
        "parent_height": parent_height,
        "target_spacing_s": spacing,
        "halflife_s": halflife,
        "pow_limit": "%064x" % limit,
        "exponent": exponent,
        "shifts": shifts,
        "frac": frac,
        "factor": asert_factor(frac),
        "next_target": "%064x" % target,
        "next_bits": target_to_compact(target),
    }


def generate_cases() -> list[dict]:
    """At least 2000 cases spanning every regime the controller has."""
    rng = random.Random(0xFE22_A5E2)
    cases: list[dict] = []

    # 1. Perfectly on schedule.  The exponent is a constant -1092 here, so the
    #    bits must be identical for every one of these -- including i = 0, the
    #    child of genesis, which is on the schedule like every other block.
    for i in range(0, 3000, 10):
        height = ANCHOR_HEIGHT + i
        cases.append(
            _case(
                "on_schedule_h%d" % height,
                0x1900FFFF,
                GENESIS_TIME_S + SPACING_S * i,
                height,
            )
        )

    # 2. Ten times too fast, and 3. ten times too slow.
    for i in range(1, 1500, 5):
        height = ANCHOR_HEIGHT + i
        cases.append(
            _case("fast_10x_h%d" % height, 0x1900FFFF,
                  GENESIS_TIME_S + (SPACING_S * i) // 10, height)
        )
        cases.append(
            _case("slow_10x_h%d" % height, 0x1900FFFF,
                  GENESIS_TIME_S + SPACING_S * i * 10, height)
        )

    # 4. Negative drift: a parent claiming a timestamp before the anchor.
    for i in range(0, 1200, 4):
        height = ANCHOR_HEIGHT + i
        cases.append(
            _case("negative_drift_h%d" % height, 0x1B0404CB,
                  GENESIS_TIME_S - SPACING_S * i, height)
        )

    # 5. Huge gaps: hours, days, years, centuries, and the i64 extremes.
    for bits in ANCHOR_BITS:
        for gap in [
            3_600, 86_400, 604_800, 2_592_000, 31_536_000,
            315_360_000, 3_153_600_000, 31_536_000_000,
            1 << 20, 1 << 30, 1 << 40, 1 << 50, 1 << 60,
            (1 << 62) - 1,
        ]:
            cases.append(_case("huge_gap_+%d_%08x" % (gap, bits), bits,
                               GENESIS_TIME_S + gap, ANCHOR_HEIGHT + 1))
            cases.append(_case("huge_gap_-%d_%08x" % (gap, bits), bits,
                               GENESIS_TIME_S - gap, ANCHOR_HEIGHT + 1))

    # 6. The pow_limit clamp, approached from just under to well over.
    for bits in ANCHOR_BITS:
        for halflives in range(0, 40):
            cases.append(
                _case("clamp_%d_halflives_%08x" % (halflives, bits), bits,
                      GENESIS_TIME_S + SPACING_S * 2 + HALFLIFE_S * halflives,
                      ANCHOR_HEIGHT + 1)
            )
        # ... and the floor, from the other direction.
        for halflives in range(0, 40):
            cases.append(
                _case("floor_%d_halflives_%08x" % (halflives, bits), bits,
                      GENESIS_TIME_S + SPACING_S * 2 - HALFLIFE_S * halflives,
                      ANCHOR_HEIGHT + 1)
            )

    # 7. A random walk with realistic jitter, which is what a live chain does.
    time_s = GENESIS_TIME_S
    for i in range(1, 700):
        time_s += rng.randint(1, 600)
        cases.append(_case("random_walk_%d" % i, 0x1900FFFF, time_s, ANCHOR_HEIGHT + i))

    # 8. Uniformly random (time, height) pairs over a very wide range, which is
    #    where an unclamped intermediate or a sign error shows up.
    for i in range(700):
        bits = rng.choice(ANCHOR_BITS)
        cases.append(
            _case(
                "random_pair_%d" % i,
                bits,
                GENESIS_TIME_S + rng.randint(-10**12, 10**12),
                rng.randint(0, 10**9),
            )
        )

    # 9. Unusual but legal parameter sets: the divisions and the +1 in the
    #    schedule are where an off-by-one hides.
    for spacing, halflife in [
        (1, 1), (1, 7), (2, 3), (7, 13), (60, 3600), (600, 172_800),
        (120, 1), (120, 31_536_000),
    ]:
        for i in range(0, 40):
            cases.append(
                _case(
                    "params_s%d_h%d_%d" % (spacing, halflife, i),
                    0x1900FFFF,
                    GENESIS_TIME_S + spacing * i + (i * 37) % 101 - 50,
                    ANCHOR_HEIGHT + i,
                    spacing=spacing,
                    halflife=halflife,
                )
            )

    # 10. A non-default anchor height, so nothing silently assumes 0.
    for i in range(0, 60):
        cases.append(
            _case("anchor_at_1000_%d" % i, 0x1900FFFF,
                  GENESIS_TIME_S + SPACING_S * i, 1000 + i,
                  anchor_height=1000, anchor_time_s=GENESIS_TIME_S)
        )

    # 11. Parents *below* the anchor, i.e. a negative height_diff.  Consensus
    #     never sees one now that the anchor is genesis and nothing precedes
    #     genesis, but the arithmetic still has to be total and a negative
    #     height_diff is exactly where a sign error hides.
    for i in range(0, 60):
        cases.append(
            _case("anchor_above_the_parent_%d" % i, 0x1900FFFF,
                  GENESIS_TIME_S - SPACING_S * i, 1000 - i,
                  anchor_height=1000, anchor_time_s=GENESIS_TIME_S)
        )

    # 12. The genesis anchor exactly as a node uses it: anchor_height 0, the
    #     anchor timestamp straight from the parameters, and the first dozen
    #     heights of a fresh chain.  Height 0 as the parent is the child of
    #     genesis -- the case that used to be exempt from the rule because the
    #     anchor did not exist yet, and is not exempt any more.
    for bits in ANCHOR_BITS:
        for height in range(0, 12):
            cases.append(
                _case("genesis_anchor_%08x_h%d" % (bits, height), bits,
                      GENESIS_TIME_S + SPACING_S * height, height)
            )

    return cases


def build_document() -> dict:
    cases = generate_cases()
    return {
        "algorithm": "aserti3-2d",
        "source": "docs/CONTRACT.md section 6.3, docs/SPEC.md section 6.2",
        "generator": "testing/reference/asert.py",
        "radix": RADIX,
        "exponent_clamp": EXPONENT_CLAMP,
        "cubic": {
            "c1": CUBIC_C1,
            "c2": CUBIC_C2,
            "c3": CUBIC_C3,
            "round": CUBIC_ROUND,
            "shift": CUBIC_SHIFT,
        },
        "case_count": len(cases),
        "cases": cases,
    }


def verify_document(doc: dict) -> int:
    """Recompute every case and return the number of mismatches."""
    failures = 0
    for case in doc["cases"]:
        limit = int(case["pow_limit"], 16)
        exponent = asert_exponent(
            case["anchor_time_s"],
            case["anchor_height"],
            case["parent_time_s"],
            case["parent_height"],
            case["target_spacing_s"],
            case["halflife_s"],
        )
        shifts, frac = split_exponent(exponent)
        target = asert_next_target(
            compact_to_target(case["anchor_bits"]),
            case["anchor_time_s"],
            case["anchor_height"],
            case["parent_time_s"],
            case["parent_height"],
            case["target_spacing_s"],
            case["halflife_s"],
            limit,
        )
        expected = {
            "exponent": exponent,
            "shifts": shifts,
            "frac": frac,
            "factor": asert_factor(frac),
            "next_target": "%064x" % target,
            "next_bits": target_to_compact(target),
        }
        for key, value in expected.items():
            if case[key] != value:
                failures += 1
                print(
                    "MISMATCH %s.%s: file %r, recomputed %r"
                    % (case["name"], key, case[key], value),
                    file=sys.stderr,
                )
        if target > limit or target < 1:
            failures += 1
            print("MISMATCH %s: target out of range" % case["name"], file=sys.stderr)
    return failures


# --------------------------------------------------------------------------
# Bulk cross-check (CONTRACT section 14: "200k pairs match Rust exactly")
# --------------------------------------------------------------------------
#
# The JSON vector file is a *designed* suite: every case in it exists because
# somebody thought of it.  That is exactly its blind spot.  This section is the
# undesigned half -- 200_000 synthetic (time_diff, height_diff) pairs drawn from
# a fully specified PRNG, so that Rust can draw the identical sequence and the
# two implementations can be compared without shipping a 17 MB artefact.
#
# The comparison is a single SHA-256 over the concatenated results.  A digest
# is a weak error message and a perfect tripwire: any disagreement in any of
# the 200_000 cases changes it, and the vector file above is what you debug
# with once the tripwire fires.

#: Bulk-differential parameters.  Frozen: changing one changes the digest.
BULK_PAIRS = 200_000
BULK_SEED = 0x46_45_52_52_55_4D_01  # b"FERRUM" || 0x01
BULK_ANCHOR_BITS = 0x1900FFFF
BULK_SPACING_S = SPACING_S
BULK_HALFLIFE_S = HALFLIFE_S
BULK_POW_LIMIT = POW_LIMIT_DEVNET

#: Drift magnitudes, in seconds, cycled through by the third PRNG draw.
#: The first three sit inside the exponent clamp and the last two are outside
#: it, so both the live regime and both saturation points are exercised.
BULK_DRIFT_SCALES = (1, 100, 10_000, 1_000_000, 100_000_000)

_U64 = (1 << 64) - 1


def splitmix64(state: int) -> tuple[int, int]:
    """One SplitMix64 draw: returns `(next_state, value)`.

    Specified here in full rather than imported, because the Rust side has to
    produce the identical stream and `random.Random` is not portable.
    """
    state = (state + 0x9E3779B97F4A7C15) & _U64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _U64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _U64
    return state, z ^ (z >> 31)


def bulk_pair(draw_a: int, draw_b: int, draw_c: int) -> tuple[int, int]:
    """Map three PRNG draws to one `(height_diff, time_diff)` pair.

    `height_diff` spans a million blocks -- four months of chain at the
    120 s spacing.  `time_diff` is the on-schedule time for that height plus a
    drift whose magnitude comes from `draw_c`, so the sample covers a chain
    running exactly on time, one drifting mildly, and one so far off that the
    exponent clamps at both ends.
    """
    height_diff = draw_a % 1_000_000
    scale = BULK_DRIFT_SCALES[draw_c % len(BULK_DRIFT_SCALES)]
    drift = draw_b % (2 * scale + 1) - scale
    time_diff = BULK_SPACING_S * (height_diff + 1) + drift
    return height_diff, time_diff


def bulk_digest(pairs: int = BULK_PAIRS, seed: int = BULK_SEED) -> str:
    """SHA-256 over the full result of every synthetic pair.

    Each case contributes 84 big-endian bytes: the pair, then every
    intermediate the contract names (exponent, shifts, frac, factor), then the
    256-bit target and the compact form.  Hashing the intermediates and not
    only the answer means a bug that two errors cancel out still shows up.
    """
    anchor_target = compact_to_target(BULK_ANCHOR_BITS)
    anchor_time_s = GENESIS_TIME_S
    digest = hashlib.sha256()
    state = seed

    for _ in range(pairs):
        state, draw_a = splitmix64(state)
        state, draw_b = splitmix64(state)
        state, draw_c = splitmix64(state)
        height_diff, time_diff = bulk_pair(draw_a, draw_b, draw_c)

        parent_height = ANCHOR_HEIGHT + height_diff
        parent_time_s = anchor_time_s + time_diff

        exponent = asert_exponent(
            anchor_time_s, ANCHOR_HEIGHT, parent_time_s, parent_height,
            BULK_SPACING_S, BULK_HALFLIFE_S,
        )
        shifts, frac = split_exponent(exponent)
        factor = asert_factor(frac)
        target = asert_next_target(
            anchor_target, anchor_time_s, ANCHOR_HEIGHT, parent_time_s,
            parent_height, BULK_SPACING_S, BULK_HALFLIFE_S, BULK_POW_LIMIT,
        )
        bits = target_to_compact(target)

        digest.update(time_diff.to_bytes(8, "big", signed=True))
        digest.update(height_diff.to_bytes(8, "big", signed=True))
        digest.update(exponent.to_bytes(8, "big", signed=True))
        digest.update(shifts.to_bytes(8, "big", signed=True))
        digest.update(frac.to_bytes(8, "big"))
        digest.update(factor.to_bytes(8, "big"))
        digest.update(target.to_bytes(32, "big"))
        digest.update(bits.to_bytes(4, "big"))

    return digest.hexdigest()


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def selftest() -> int:
    """Assert the properties the contract states.  Returns a process exit code."""
    checks = 0

    def check(condition: bool, message: str) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            raise AssertionError(message)

    # --- compact encoding -------------------------------------------------
    check(compact_to_target(0x1D00FFFF) == POW_LIMIT_MAINNET, "1d00ffff is the mainnet limit")
    check(
        "%064x" % compact_to_target(0x1B0404CB)
        == "00000000000404cb000000000000000000000000000000000000000000000000",
        "1b0404cb expands to the documented value",
    )
    check(compact_to_target(0) == 0, "an all-zero compact is zero")
    check(target_to_compact(0) == 0, "zero compresses to an all-zero compact")
    check(compact_to_target(0x207FFFFF) == 0x7FFFFF << 232, "207fffff is the widest mantissa")

    for bits in ANCHOR_BITS:
        check(is_canonical_compact(bits), "%08x must be canonical" % bits)
        check(
            target_to_compact(compact_to_target(bits)) == bits,
            "%08x must round-trip" % bits,
        )

    for bad, why in [
        (0x1D80FFFF, "sign bit"),
        (0x01800000, "sign bit"),
        (0x01000000, "zero mantissa, non-zero exponent"),
        (0xFF000000, "zero mantissa, non-zero exponent"),
        (0x217FFFFF, "expands past 256 bits"),
        (0x2200FFFF, "expands past 256 bits"),
        (0xFF7FFFFF, "expands past 256 bits"),
    ]:
        try:
            compact_to_target(bad)
        except CompactError:
            pass
        else:
            raise AssertionError("%08x must be rejected (%s)" % (bad, why))
        checks += 1

    # Compression never rounds a target easier, and is idempotent.
    rng = random.Random(7)
    for _ in range(2000):
        target = rng.getrandbits(rng.randint(1, 256))
        compact = target_to_compact(target)
        back = compact_to_target(compact)
        check(back <= target, "compression must never round up")
        check(target_to_compact(back) == compact, "compression must be idempotent")
        check(is_canonical_compact(compact), "compression must emit canonical forms")

    # --- work -------------------------------------------------------------
    check(work_from_target(POW_LIMIT_MAINNET) == 0x100010001, "difficulty-1 chainwork")
    check(work_from_target((1 << 256) - 1) == 1, "the easiest target costs one hash")
    check(work_from_target(1) == 1 << 255, "target 1 costs 2**255 hashes")

    # --- truncating division ---------------------------------------------
    check(truncating_div(7, 2) == 3, "truncating division rounds toward zero")
    check(truncating_div(-7, 2) == -3, "and does so for negative numerators")
    check(truncating_div(-7, -2) == 3, "and for negative divisors")
    check(truncating_div(7, -2) == -3, "and for mixed signs")
    check((-7) // 2 == -4, "Python's // floors, which is why the helper exists")

    # --- exponent split ---------------------------------------------------
    for exponent in [-1_000_000, -70_000, -65_537, -65_536, -1092, -1, 0, 1, 65_535, 70_000]:
        shifts, frac = split_exponent(exponent)
        check(0 <= frac < RADIX, "frac must stay in [0, 65536): %d" % exponent)
        check(shifts * RADIX + frac == exponent, "the split must reconstruct the exponent")
    check(split_exponent(-1) == (-1, 65_535), "a negative exponent floors")
    check(split_exponent(-1092) == (-1, 64_444), "the on-schedule exponent")

    # --- the cubic --------------------------------------------------------
    check(asert_factor(0) == RADIX, "2**0 is exactly 1")
    check(131_060 < asert_factor(65_535) <= 131_072, "2**(65535/65536) is just under 2")
    check(abs(asert_factor(32_768) - 92_682) <= 12, "2**0.5 within 0.013 %")
    previous = 0
    for frac in range(0, RADIX, 37):
        factor = asert_factor(frac)
        check(factor >= previous, "the cubic must be monotonic")
        previous = factor

    # --- the controller ---------------------------------------------------
    anchor_bits = 0x1900FFFF
    anchor_target = compact_to_target(anchor_bits)
    limit = POW_LIMIT_MAINNET

    # The anchor is genesis, and genesis is the only exempt block.
    check(ANCHOR_HEIGHT == 0, "the anchor is genesis, not the block after it")

    # On schedule, bits are constant -- and i = 0 is the child of genesis, which
    # is on the schedule like every other block rather than exempt from it.
    first = asert_next_bits(anchor_bits, GENESIS_TIME_S, ANCHOR_HEIGHT,
                            GENESIS_TIME_S, ANCHOR_HEIGHT,
                            SPACING_S, HALFLIFE_S, limit)
    for i in range(0, 2000, 7):
        bits = asert_next_bits(anchor_bits, GENESIS_TIME_S, ANCHOR_HEIGHT,
                               GENESIS_TIME_S + SPACING_S * i, ANCHOR_HEIGHT + i,
                               SPACING_S, HALFLIFE_S, limit)
        check(bits == first, "on-schedule bits must not drift at i = %d" % i)
    check(
        asert_exponent(GENESIS_TIME_S, ANCHOR_HEIGHT, GENESIS_TIME_S, ANCHOR_HEIGHT,
                       SPACING_S, HALFLIFE_S) == -1092,
        "the child of genesis carries the one-spacing on-schedule offset",
    )

    # Difficulty is a pure function of (parent_height, parent_time_s, params):
    # there is no third input a node could disagree about, which is the whole
    # reason the anchor moved to genesis.
    for parent_height, parent_time in [(0, GENESIS_TIME_S), (1, GENESIS_TIME_S + 300),
                                       (17, GENESIS_TIME_S + 2039)]:
        answers = {
            asert_next_bits(anchor_bits, GENESIS_TIME_S, ANCHOR_HEIGHT,
                            parent_time, parent_height, SPACING_S, HALFLIFE_S, limit)
            for _ in range(3)
        }
        check(len(answers) == 1, "difficulty must depend only on (parent, params)")

    # Exactly n half-lives ahead of schedule doubles the target n times.
    for halflives in range(0, 6):
        parent_height = ANCHOR_HEIGHT + 1000
        parent_time = GENESIS_TIME_S + SPACING_S * 1001 + HALFLIFE_S * halflives
        target = asert_next_target(anchor_target, GENESIS_TIME_S, ANCHOR_HEIGHT,
                                   parent_time, parent_height, SPACING_S,
                                   HALFLIFE_S, limit)
        check(
            target == min(anchor_target << halflives, limit),
            "%d half-lives must be an exact doubling" % halflives,
        )
    for halflives in range(0, 6):
        parent_height = ANCHOR_HEIGHT + 1000
        parent_time = GENESIS_TIME_S + SPACING_S * 1001 - HALFLIFE_S * halflives
        target = asert_next_target(anchor_target, GENESIS_TIME_S, ANCHOR_HEIGHT,
                                   parent_time, parent_height, SPACING_S,
                                   HALFLIFE_S, limit)
        check(
            target == anchor_target >> halflives,
            "-%d half-lives must be an exact halving" % halflives,
        )

    # The clamps hold at both ends, for every anchor.
    for bits in ANCHOR_BITS:
        target = compact_to_target(bits)
        pow_limit = _pow_limit_for(bits)
        far = asert_next_target(target, GENESIS_TIME_S, ANCHOR_HEIGHT,
                                GENESIS_TIME_S + 10**18, ANCHOR_HEIGHT + 1,
                                SPACING_S, HALFLIFE_S, pow_limit)
        check(far == pow_limit, "a huge gap must clamp to pow_limit")
        near = asert_next_target(target, GENESIS_TIME_S, ANCHOR_HEIGHT,
                                 GENESIS_TIME_S - 10**18, ANCHOR_HEIGHT + 1,
                                 SPACING_S, HALFLIFE_S, pow_limit)
        check(near == 1, "a huge negative gap must floor at 1")
        check(
            asert_next_target(target, GENESIS_TIME_S, ANCHOR_HEIGHT, 2**62,
                              ANCHOR_HEIGHT + 1, SPACING_S, HALFLIFE_S,
                              pow_limit) == pow_limit,
            "the clamp must be reachable from any anchor",
        )

    # The clamp is unobservable: past it, every answer is the same.
    for bits in ANCHOR_BITS:
        target = compact_to_target(bits)
        pow_limit = _pow_limit_for(bits)
        a = asert_next_target(target, 0, ANCHOR_HEIGHT, 10**15, ANCHOR_HEIGHT + 1,
                              SPACING_S, HALFLIFE_S, pow_limit)
        b = asert_next_target(target, 0, ANCHOR_HEIGHT, 10**17, ANCHOR_HEIGHT + 1,
                              SPACING_S, HALFLIFE_S, pow_limit)
        check(a == b, "past the clamp every answer must agree")

    # Monotonicity: later parents are easier, taller parents are harder.
    previous = 0
    for extra in range(0, 20_000, 200):
        target = asert_next_target(anchor_target, GENESIS_TIME_S, ANCHOR_HEIGHT,
                                   GENESIS_TIME_S + extra, 500, SPACING_S,
                                   HALFLIFE_S, limit)
        check(target >= previous, "the target must be monotone in parent time")
        previous = target
    previous = limit
    for height in range(ANCHOR_HEIGHT, 2000, 20):
        target = asert_next_target(anchor_target, GENESIS_TIME_S, ANCHOR_HEIGHT,
                                   GENESIS_TIME_S + 100_000, height, SPACING_S,
                                   HALFLIFE_S, limit)
        check(target <= previous, "the target must be antitone in parent height")
        previous = target

    # Bad parameters are refused rather than dividing by zero.
    for kwargs, why in [
        ({"halflife_s": 0}, "zero half-life"),
        ({"halflife_s": -1}, "negative half-life"),
        ({"target_spacing_s": 0}, "zero spacing"),
        ({"target_spacing_s": -5}, "negative spacing"),
    ]:
        arguments = {
            "anchor_target": anchor_target,
            "anchor_time_s": GENESIS_TIME_S,
            "anchor_height": ANCHOR_HEIGHT,
            "parent_time_s": GENESIS_TIME_S,
            "parent_height": ANCHOR_HEIGHT,
            "target_spacing_s": SPACING_S,
            "halflife_s": HALFLIFE_S,
            "pow_limit": limit,
        }
        arguments.update(kwargs)
        try:
            asert_next_target(**arguments)
        except (ValueError, ZeroDivisionError):
            pass
        else:
            raise AssertionError("%s must be refused" % why)
        checks += 1

    print("asert.py selftest: %d checks passed" % checks)
    return 0


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true",
                        help="check this implementation against the contract")
    parser.add_argument("--generate", metavar="PATH", nargs="?", const="",
                        help="write the cross-check vectors as JSON")
    parser.add_argument("--verify", metavar="PATH", nargs="?", const="",
                        help="recompute every case in a vector file")
    parser.add_argument("--bulk-digest", action="store_true",
                        help="print the SHA-256 of the synthetic-pair sweep "
                             "that crates/consensus/tests/asert_vectors.rs "
                             "recomputes in Rust")
    parser.add_argument("--pairs", type=int, default=BULK_PAIRS,
                        help="how many synthetic pairs --bulk-digest sweeps "
                             "(default %d; the checked-in digest is for that "
                             "count only)" % BULK_PAIRS)
    parser.add_argument("--seed", type=lambda s: int(s, 0), default=BULK_SEED,
                        help="PRNG seed for --bulk-digest (default 0x%x)"
                             % BULK_SEED)
    args = parser.parse_args(argv)

    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "asert_vectors.json")
    status = 0

    if args.selftest:
        status |= selftest()

    if args.generate is not None:
        path = args.generate or default_path
        document = build_document()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=1, sort_keys=True)
            handle.write("\n")
        print("wrote %d cases to %s" % (document["case_count"], path))

    if args.verify is not None:
        path = args.verify or default_path
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        failures = verify_document(document)
        if failures:
            print("%d mismatches in %s" % (failures, path), file=sys.stderr)
            status |= 1
        else:
            print("verified %d cases in %s" % (len(document["cases"]), path))

    if args.bulk_digest:
        print("pairs=%d seed=0x%x sha256=%s"
              % (args.pairs, args.seed, bulk_digest(args.pairs, args.seed)))

    if (not args.selftest and args.generate is None and args.verify is None
            and not args.bulk_digest):
        parser.print_help()
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
