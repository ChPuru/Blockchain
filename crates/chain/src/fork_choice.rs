//! Fork choice: **cumulative work, never height** (SPEC §7.1).
//!
//! Height is not a proxy for work. A chain of a hundred easy blocks can be
//! worth less than ten hard ones, and ranking by length is the single most
//! common flaw in from-scratch implementations — it is also exactly what a
//! low-difficulty attacker exploits, because producing length is cheap and
//! producing work is not.
//!
//! ```text
//! work(header) = (!target / (target + 1)) + 1        // 256-bit integers
//! ```
//!
//! # Ties
//!
//! Equal cumulative work is broken by the **lower block hash**. That is a
//! deterministic rule, so two nodes that saw the same two candidates in
//! opposite orders still converge on the same tip. First-seen is the other
//! candidate tiebreak and Ferrum deliberately does not use it for the final
//! decision: it is a *local* rule, it depends on network timing, and two nodes
//! applying it disagree forever.

use core::cmp::Ordering;

use ferrum_consensus::Work;
use ferrum_types::BlockHash;

/// A tip competing to be the best chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipCandidate {
    /// The tip's block hash.
    pub hash: BlockHash,
    /// Its height. Carried for logging and for reorg depth, **never** for the
    /// comparison itself.
    pub height: u64,
    /// Cumulative work from genesis to this tip, inclusive.
    pub total_work: Work,
}

impl TipCandidate {
    /// Build a candidate.
    #[must_use]
    pub fn new(hash: BlockHash, height: u64, total_work: Work) -> Self {
        TipCandidate { hash, height, total_work }
    }
}

/// Order two candidates: [`Ordering::Greater`] means `a` is the better chain.
///
/// Greater cumulative work wins. On exactly equal work the lower hash wins,
/// which is why the hash comparison is reversed: a smaller hash must sort as
/// the greater candidate.
#[must_use]
pub fn compare(a: &TipCandidate, b: &TipCandidate) -> Ordering {
    match a.total_work.cmp(&b.total_work) {
        Ordering::Equal => b.hash.cmp(&a.hash),
        other => other,
    }
}

/// Whether `candidate` should replace `incumbent` as the active tip.
///
/// Strictly better only: a candidate that ties on work *and* hash is the same
/// chain, and a reorg to it would be a no-op that still rewrote the store.
#[must_use]
pub fn is_better(candidate: &TipCandidate, incumbent: &TipCandidate) -> bool {
    compare(candidate, incumbent) == Ordering::Greater
}

/// The best of a set of candidates, or `None` when the set is empty.
///
/// Deterministic for any input order, which is the whole point of the hash
/// tiebreak: two nodes handed the same set in different orders pick the same
/// tip.
#[must_use]
pub fn best_of<'a, I>(candidates: I) -> Option<&'a TipCandidate>
where
    I: IntoIterator<Item = &'a TipCandidate>,
{
    candidates.into_iter().fold(None, |best, next| match best {
        None => Some(next),
        Some(current) if is_better(next, current) => Some(next),
        keep => keep,
    })
}

/// Cumulative work of a block: its parent's total plus its own.
///
/// `None` on overflow. Reaching it would take more work than the universe has
/// energy for, but a silently wrapped total would invert fork choice, so it is
/// a typed failure rather than a wrapping add.
#[must_use]
pub fn cumulative_work(parent_total: Work, block_work: Work) -> Option<Work> {
    parent_total.checked_add(block_work)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use ferrum_consensus::U256;
    use ferrum_types::Hash32;

    use super::*;

    fn hash(n: u8) -> BlockHash {
        BlockHash(Hash32::from_bytes([n; 32]))
    }

    fn work(n: u64) -> Work {
        Work(U256::from(n))
    }

    fn candidate(h: u8, height: u64, w: u64) -> TipCandidate {
        TipCandidate::new(hash(h), height, work(w))
    }

    #[test]
    fn more_work_wins() {
        let heavy = candidate(1, 2, 100);
        let light = candidate(2, 50, 99);
        assert!(is_better(&heavy, &light));
        assert!(!is_better(&light, &heavy));
    }

    #[test]
    fn a_long_easy_chain_loses_to_a_short_hard_one() {
        // 100 blocks worth 1 unit each against 10 blocks worth 25 each.
        let long_easy = candidate(1, 100, 100);
        let short_hard = candidate(2, 10, 250);
        assert!(is_better(&short_hard, &long_easy), "fork choice must ignore height");
        assert!(short_hard.height < long_easy.height);
    }

    #[test]
    fn ties_break_on_the_lower_hash() {
        let low = candidate(1, 5, 100);
        let high = candidate(9, 5, 100);
        assert!(is_better(&low, &high));
        assert!(!is_better(&high, &low));
        assert_eq!(compare(&low, &high), Ordering::Greater);
        assert_eq!(compare(&high, &low), Ordering::Less);
    }

    #[test]
    fn a_candidate_never_beats_itself() {
        let c = candidate(3, 7, 42);
        assert!(!is_better(&c, &c));
        assert_eq!(compare(&c, &c), Ordering::Equal);
    }

    #[test]
    fn height_alone_never_decides() {
        let tall = candidate(1, 1_000_000, 10);
        let short = candidate(2, 1, 11);
        assert!(is_better(&short, &tall));
    }

    #[test]
    fn best_of_is_independent_of_input_order() {
        let a = candidate(1, 3, 10);
        let b = candidate(2, 9, 30);
        let c = candidate(3, 4, 30);
        let forward = [a, b, c];
        let backward = [c, b, a];
        assert_eq!(best_of(forward.iter()), Some(&b), "lower hash wins the 30/30 tie");
        assert_eq!(best_of(backward.iter()), Some(&b));
    }

    #[test]
    fn best_of_an_empty_set_is_none() {
        let empty: [TipCandidate; 0] = [];
        assert_eq!(best_of(empty.iter()), None);
    }

    #[test]
    fn cumulative_work_adds_and_reports_overflow() {
        assert_eq!(cumulative_work(work(3), work(4)), Some(work(7)));
        assert_eq!(cumulative_work(Work(U256::max_value()), Work::ONE), None);
    }

    #[test]
    fn zero_work_candidates_still_order_by_hash() {
        let a = TipCandidate::new(hash(1), 0, Work::ZERO);
        let b = TipCandidate::new(hash(2), 0, Work::ZERO);
        assert!(is_better(&a, &b));
    }
}
