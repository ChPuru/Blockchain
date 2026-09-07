//! Cross-check ASERT against the independent Python reference.
//!
//! `testing/reference/asert.py` is written from `docs/CONTRACT.md` section 6.3
//! and `docs/SPEC.md` section 6.2 without consulting `crates/consensus/`. It
//! generates `testing/reference/asert_vectors.json`; this test recomputes every
//! case in Rust and requires **exact** agreement — same exponent, same shift,
//! same fraction, same cubic factor, same 256-bit target and same compact form.
//!
//! Two implementations written from the same paragraph still catch a misreading
//! of that paragraph. One does not. This is the project's substitute for an
//! audit of the difficulty controller, and it is why the file is checked in
//! rather than generated during the test run.
//!
//! Regenerate with:
//!
//! ```text
//! python testing/reference/asert.py --selftest
//! python testing/reference/asert.py --generate
//! python testing/reference/asert.py --verify
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use ferrum_consensus::{
    AsertAnchor, AsertParams, CompactTarget, Target, asert_exponent, asert_factor, asert_next_bits,
    asert_next_target, compact_to_target, is_canonical_compact, split_exponent, target_to_compact,
};
use serde::Deserialize;

/// One cross-check case, exactly as `asert.py` writes it.
#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    anchor_bits: u32,
    anchor_time_s: i64,
    anchor_height: u64,
    parent_time_s: i64,
    parent_height: u64,
    target_spacing_s: i64,
    halflife_s: i64,
    pow_limit: String,
    exponent: i64,
    shifts: i64,
    frac: u64,
    factor: u64,
    next_target: String,
    next_bits: u32,
}

/// The whole vector document.
#[derive(Debug, Deserialize)]
struct Vectors {
    algorithm: String,
    radix: i64,
    exponent_clamp: i64,
    case_count: usize,
    cases: Vec<Case>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testing/reference/asert_vectors.json")
}

fn load() -> Vectors {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Regenerate with `python testing/reference/asert.py --generate`",
            path.display()
        )
    });
    serde_json::from_str(&raw).expect("asert_vectors.json is not valid JSON")
}

fn hex_to_target(s: &str) -> Target {
    assert_eq!(s.len(), 64, "a 256-bit value is 64 hex characters: {s:?}");
    let bytes = hex::decode(s).expect("hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Target::from_be_bytes(&arr)
}

#[test]
fn asert_vector_file_is_the_shape_the_contract_asks_for() {
    let v = load();
    assert_eq!(v.algorithm, "aserti3-2d");
    assert_eq!(v.radix, ferrum_consensus::RADIX);
    assert_eq!(v.exponent_clamp, ferrum_consensus::EXPONENT_CLAMP);
    assert_eq!(v.case_count, v.cases.len());
    assert!(
        v.case_count >= 2_000,
        "the contract asks for at least 2000 cases, found {}",
        v.case_count
    );

    // Every documented regime must actually be present, or the file could be
    // 2000 copies of the easy case.
    let prefixes: BTreeSet<&str> =
        v.cases.iter().filter_map(|c| c.name.split('_').next()).collect();
    for regime in [
        "on", "fast", "slow", "negative", "huge", "clamp", "floor", "random", "params", "anchor",
        "genesis",
    ] {
        assert!(prefixes.contains(regime), "no {regime}* cases in the vector file");
    }
}

#[test]
fn asert_vectors_are_anchored_on_genesis() {
    // The anchor is genesis and comes from `ChainParams`, never from the chain.
    // A vector file that had drifted back to a height-1 anchor would still pass
    // every other test here, because both sides would have drifted together.
    assert_eq!(ferrum_consensus::ANCHOR_HEIGHT, 0, "the ASERT anchor is genesis");

    let v = load();
    let on_genesis =
        v.cases.iter().filter(|c| c.anchor_height == ferrum_consensus::ANCHOR_HEIGHT).count();
    assert!(
        on_genesis * 2 > v.cases.len(),
        "only {on_genesis} of {} cases use the real anchor height",
        v.cases.len()
    );
    assert!(
        v.cases.iter().any(|c| c.parent_height == 0),
        "the child of genesis is an ordinary case now, and must be covered"
    );
    // The deliberately unreachable direction is still exercised, because that
    // is where the sign of `height_diff` would go wrong unnoticed.
    assert!(
        v.cases.iter().any(|c| c.parent_height < c.anchor_height),
        "no case places the parent below the anchor"
    );
}

#[test]
fn asert_every_case_agrees_with_the_python_reference_exactly() {
    let v = load();
    for case in &v.cases {
        let name = &case.name;
        let pow_limit = hex_to_target(&case.pow_limit);
        let anchor = AsertAnchor::from_compact(
            CompactTarget(case.anchor_bits),
            case.anchor_time_s,
            case.anchor_height,
        )
        .unwrap_or_else(|e| panic!("{name}: anchor bits rejected: {e}"));
        let params = AsertParams {
            target_spacing_s: case.target_spacing_s,
            halflife_s: case.halflife_s,
            pow_limit,
        };

        let exponent = asert_exponent(&anchor, case.parent_time_s, case.parent_height, &params)
            .unwrap_or_else(|e| panic!("{name}: exponent failed: {e}"));
        assert_eq!(exponent, case.exponent, "{name}: exponent");

        let (shifts, frac) = split_exponent(exponent);
        assert_eq!(shifts, case.shifts, "{name}: shifts");
        assert_eq!(frac, case.frac, "{name}: frac");
        assert!(frac < 65_536, "{name}: frac left the half-open range");

        assert_eq!(asert_factor(frac), case.factor, "{name}: cubic factor");

        let target = asert_next_target(&anchor, case.parent_time_s, case.parent_height, &params)
            .unwrap_or_else(|e| panic!("{name}: next_target failed: {e}"));
        assert_eq!(target, hex_to_target(&case.next_target), "{name}: next_target");

        let bits = asert_next_bits(&anchor, case.parent_time_s, case.parent_height, &params)
            .unwrap_or_else(|e| panic!("{name}: next_bits failed: {e}"));
        assert_eq!(bits, CompactTarget(case.next_bits), "{name}: next_bits");
    }
}

#[test]
fn asert_every_vector_result_is_inside_the_permitted_range() {
    let v = load();
    for case in &v.cases {
        let target = hex_to_target(&case.next_target);
        let limit = hex_to_target(&case.pow_limit);
        assert!(!target.is_zero(), "{}: the floor is 1, never 0", case.name);
        assert!(target <= limit, "{}: target escaped pow_limit", case.name);
        assert!(is_canonical_compact(CompactTarget(case.next_bits)), "{}: bits", case.name);
        assert!(
            compact_to_target(CompactTarget(case.next_bits)).unwrap() <= target,
            "{}: the compact form must never round easier",
            case.name
        );
    }
}

#[test]
fn asert_anchor_bits_in_the_vectors_are_canonical() {
    let v = load();
    let anchors: BTreeSet<u32> = v.cases.iter().map(|c| c.anchor_bits).collect();
    assert!(anchors.len() >= 4, "the vectors should exercise several anchors");
    for bits in anchors {
        let c = CompactTarget(bits);
        assert!(is_canonical_compact(c), "anchor {bits:#010x} is not canonical");
        assert_eq!(target_to_compact(compact_to_target(c).unwrap()), c);
    }
}

#[test]
fn asert_on_schedule_vectors_all_share_one_target() {
    // The controller's defining property, read straight off the vector file:
    // constant on-schedule timestamps produce a constant target.
    let v = load();
    let on_schedule: BTreeSet<&str> = v
        .cases
        .iter()
        .filter(|c| c.name.starts_with("on_schedule_"))
        .map(|c| c.next_target.as_str())
        .collect();
    assert_eq!(on_schedule.len(), 1, "on-schedule blocks must hold the target exactly stable");

    let exponents: BTreeSet<i64> =
        v.cases.iter().filter(|c| c.name.starts_with("on_schedule_")).map(|c| c.exponent).collect();
    assert_eq!(
        exponents.into_iter().collect::<Vec<_>>(),
        vec![-1_092],
        "the on-schedule exponent is a constant -1092: one spacing of built-in offset"
    );
}

#[test]
fn asert_clamp_vectors_reach_both_saturation_points() {
    let v = load();
    let mut hit_limit = 0usize;
    let mut hit_floor = 0usize;
    for case in &v.cases {
        let target = hex_to_target(&case.next_target);
        if target == hex_to_target(&case.pow_limit) {
            hit_limit += 1;
        }
        if target == Target(ferrum_consensus::U256::one()) {
            hit_floor += 1;
        }
    }
    assert!(hit_limit >= 50, "only {hit_limit} vectors reach the pow_limit clamp");
    assert!(hit_floor >= 50, "only {hit_floor} vectors reach the floor of 1");
}

// ---------------------------------------------------------------------------
// The bulk differential — CONTRACT §14, "200k pairs match Rust exactly"
// ---------------------------------------------------------------------------
//
// The JSON file above is a *designed* suite, and that is exactly its blind
// spot: every case in it is one somebody thought of. This is the undesigned
// half — 200_000 synthetic `(time_diff, height_diff)` pairs drawn from a fully
// specified PRNG, so the Python reference can draw the identical sequence and
// the two implementations can be compared without checking in a 17 MB
// artefact.
//
// The comparison is a single SHA-256 over the concatenated results. A digest
// is a weak error message and a perfect tripwire: any disagreement in any of
// the 200_000 cases changes it, and the vector file is what you debug with
// once the tripwire fires.
//
// Regenerate the expected digest with:
//
// ```text
// python testing/reference/asert.py --bulk-digest
// ```
//
// A change to that number is a change to the difficulty controller. It is
// never the right fix for a red test here; find out which case moved first.

/// Anchor timestamp for the sweep, matching `GENESIS_TIME_S` in `asert.py`:
/// 2025-01-01T00:00:00Z. Frozen: changing it changes the digest.
const GENESIS_TIME_S: i64 = 1_735_689_600;

/// SHA-256 of the 200_000-pair sweep, as printed by
/// `python testing/reference/asert.py --bulk-digest`.
const BULK_DIGEST: &str = "c8f7b8e1cfef4e2798bd3600ee4b1964529d93d04db73d86fc4750cdaebb796a";

/// Pair count. Frozen: changing it changes [`BULK_DIGEST`].
const BULK_PAIRS: usize = 200_000;

/// PRNG seed, `b"FERRUM" || 0x01`. Frozen: changing it changes the digest.
const BULK_SEED: u64 = 0x0046_4552_5255_4D01;

/// Anchor difficulty for the sweep: 2^32 harder than the mainnet limit, so the
/// target has room to move in both directions before it saturates.
const BULK_ANCHOR_BITS: u32 = 0x1900_FFFF;

const BULK_SPACING_S: i64 = 120;
const BULK_HALFLIFE_S: i64 = 7_200;

/// Anchor height for the sweep: genesis, as consensus uses it. Only
/// `parent_height - anchor_height` reaches the arithmetic, so this does not
/// affect [`BULK_DIGEST`] — it is here so the sweep reads like the real rule.
const BULK_ANCHOR_HEIGHT: u64 = ferrum_consensus::ANCHOR_HEIGHT;

/// Devnet `pow_limit`, `0x7fff…ff`: high enough that a fast chain is not
/// clipped by the ceiling before the arithmetic has been exercised.
fn bulk_pow_limit() -> Target {
    let mut b = [0xffu8; 32];
    b[0] = 0x7f;
    Target::from_be_bytes(&b)
}

/// Drift magnitudes in seconds, cycled by the third PRNG draw. The first three
/// sit inside the exponent clamp and the last two are outside it, so the sweep
/// covers the live regime and both saturation points.
const BULK_DRIFT_SCALES: [i64; 5] = [1, 100, 10_000, 1_000_000, 100_000_000];

/// One SplitMix64 draw, returning `(next_state, value)`.
///
/// Written out rather than pulled from a crate because the Python reference has
/// to produce a bit-identical stream; a dependency's internals are not a
/// specification.
fn splitmix64(state: u64) -> (u64, u64) {
    let state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (state, z ^ (z >> 31))
}

/// Map three PRNG draws to one `(height_diff, time_diff)` pair.
///
/// `height_diff` spans a million blocks — four months of chain at the 120 s
/// spacing. `time_diff` is the on-schedule time for that height plus a drift
/// whose magnitude comes from the third draw, so the sample covers a chain
/// running exactly on time, one drifting mildly, and one so far off that the
/// exponent clamps at both ends.
fn bulk_pair(draw_a: u64, draw_b: u64, draw_c: u64) -> (i64, i64) {
    let height_diff = i64::try_from(draw_a % 1_000_000).expect("under i64::MAX by construction");
    let scale = BULK_DRIFT_SCALES[(draw_c % BULK_DRIFT_SCALES.len() as u64) as usize];
    let span = u64::try_from(2 * scale + 1).expect("positive by construction");
    let drift = i64::try_from(draw_b % span).expect("below span, which fits i64") - scale;
    let time_diff = BULK_SPACING_S * (height_diff + 1) + drift;
    (height_diff, time_diff)
}

#[test]
fn asert_two_hundred_thousand_synthetic_pairs_match_the_python_digest() {
    let anchor =
        AsertAnchor::from_compact(CompactTarget(BULK_ANCHOR_BITS), GENESIS_TIME_S, BULK_ANCHOR_HEIGHT)
            .expect("the anchor bits are canonical");
    let params = AsertParams {
        target_spacing_s: BULK_SPACING_S,
        halflife_s: BULK_HALFLIFE_S,
        pow_limit: bulk_pow_limit(),
    };

    // 84 bytes per case, hashed in one pass: the sweep is 17 MB, which is
    // cheaper to allocate once than to hash incrementally through a one-shot
    // API.
    let mut stream = Vec::with_capacity(BULK_PAIRS * 84);
    let mut state = BULK_SEED;
    // Coverage counters: a sweep that never clamps would pass this test while
    // testing a third of the algorithm.
    let mut clamped_high = 0usize;
    let mut clamped_low = 0usize;
    let mut at_pow_limit = 0usize;

    for _ in 0..BULK_PAIRS {
        let (next, draw_a) = splitmix64(state);
        let (next, draw_b) = splitmix64(next);
        let (next, draw_c) = splitmix64(next);
        state = next;

        let (height_diff, time_diff) = bulk_pair(draw_a, draw_b, draw_c);
        let parent_height =
            BULK_ANCHOR_HEIGHT + u64::try_from(height_diff).expect("non-negative");
        let parent_time_s = GENESIS_TIME_S + time_diff;

        let exponent =
            asert_exponent(&anchor, parent_time_s, parent_height, &params).expect("valid params");
        let (shifts, frac) = split_exponent(exponent);
        let factor = asert_factor(frac);
        let target = asert_next_target(&anchor, parent_time_s, parent_height, &params)
            .expect("valid params");
        let bits = target_to_compact(target);

        if exponent == ferrum_consensus::EXPONENT_CLAMP {
            clamped_high += 1;
        }
        if exponent == -ferrum_consensus::EXPONENT_CLAMP {
            clamped_low += 1;
        }
        if target == params.pow_limit {
            at_pow_limit += 1;
        }

        stream.extend_from_slice(&time_diff.to_be_bytes());
        stream.extend_from_slice(&height_diff.to_be_bytes());
        stream.extend_from_slice(&exponent.to_be_bytes());
        stream.extend_from_slice(&shifts.to_be_bytes());
        stream.extend_from_slice(&frac.to_be_bytes());
        stream.extend_from_slice(&factor.to_be_bytes());
        stream.extend_from_slice(&target.to_be_bytes());
        stream.extend_from_slice(&bits.0.to_be_bytes());
    }

    assert!(clamped_high > 0, "the sweep never reached the upper exponent clamp");
    assert!(clamped_low > 0, "the sweep never reached the lower exponent clamp");
    assert!(at_pow_limit > 0, "the sweep never saturated at pow_limit");

    assert_eq!(
        hex::encode(ferrum_crypto::sha256(&stream)),
        BULK_DIGEST,
        "Rust and testing/reference/asert.py disagree somewhere in {BULK_PAIRS} synthetic pairs; \
         re-run `python testing/reference/asert.py --bulk-digest` and bisect with --pairs"
    );
}
