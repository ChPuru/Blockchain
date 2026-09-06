//! **Attack:** make two transactions share an identifier, so that one UTXO
//! entry stands for two sets of coins.
//!
//! This is CVE-2012-1909, and it happened twice on Bitcoin mainnet: blocks
//! 91 722/91 880 and 91 812/91 842 each contained *identical* coinbase
//! transactions, because a coinbase's only variable field was one a miner had
//! left constant. The second block's entry overwrote the first's, and the
//! first block's 50 BTC were destroyed. BIP-30 forbade the collision; BIP-34
//! removed the possibility by requiring the coinbase `script_sig` to begin
//! with a push of the block height, so two coinbases at different heights can
//! never be byte-identical.
//!
//! Ferrum enforces both from genesis, and this module checks all three layers:
//!
//! 1. **Within one block** — two transactions with the same txid is
//!    [`ValidationError::DuplicateTransaction`] (SPEC §3.1 rule 4).
//! 2. **BIP-34** — the coinbase `script_sig` must be 2..=100 bytes and begin
//!    with a *minimally encoded* push of this height
//!    ([`ValidationError::CoinbaseHeightMismatch`],
//!    [`ValidationError::CoinbaseMissingHeightPush`],
//!    [`ValidationError::CoinbaseScriptSigLength`]).
//! 3. **Rule 15** — no created outpoint may already exist in the UTXO set
//!    ([`ValidationError::DuplicateOutPoint`]), which is defence in depth on
//!    the inflation path and covers the non-coinbase case as well.
//!
//! **Red:** each of the three is rejected with its own variant.
//! **Green:** the same block with an honest coinbase is accepted, and two
//! coinbases at *different* heights are provably distinct.

use ferrum_types::{Amount, Coin, OutPoint, Script, Transaction, TxIn, TxOut};

use crate::chain_builder::{BlockPlan, ChainBuilder};
use crate::error::SimError;
use crate::scenarios::{Verdict, judge};

/// A coinbase with an arbitrary `script_sig`, claiming nothing.
#[must_use]
pub fn coinbase_with(script_sig: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(Script::new(script_sig))],
        outputs: vec![TxOut::new(Amount::ZERO, Script::new(vec![0x51]))],
        lock_time: 0,
    }
}

/// Judge a block whose coinbase carries `script_sig`.
///
/// # Errors
///
/// [`SimError`] if the block cannot be built or the executors disagree.
pub fn block_with_coinbase_script_sig(
    chain: &mut ChainBuilder,
    script_sig: Vec<u8>,
) -> Result<Verdict, SimError> {
    let ctx = chain.next_ctx()?;
    let pre = chain.state_view();
    let block = chain.build_block(&BlockPlan {
        coinbase: Some(coinbase_with(script_sig)),
        ..BlockPlan::default()
    })?;
    judge(&pre, &block, &ctx)
}

/// Judge an honest block against a pre-state that *already* holds the outpoint
/// its coinbase is about to create.
///
/// This is the only way to reach SPEC §3.3 rule 15 directly: BIP-34 makes the
/// collision unreachable through normal block production, and a rule that
/// cannot be reached is a rule that stops being tested.
///
/// # Errors
///
/// [`SimError`] if the block cannot be built or the executors disagree.
pub fn colliding_outpoint(chain: &mut ChainBuilder) -> Result<Verdict, SimError> {
    let ctx = chain.next_ctx()?;
    let block = chain.build_block(&BlockPlan::default())?;
    let coinbase =
        block.coinbase().ok_or_else(|| SimError::fixture("the block has no coinbase"))?;
    let op = OutPoint::new(ChainBuilder::txid_of(coinbase), 0);

    let mut pre = chain.state_view();
    pre.insert(
        op,
        Coin {
            value: Amount::from_grains(1),
            script_pubkey: Script::new(vec![0x51]),
            height: 0,
            is_coinbase: true,
        },
    );
    judge(&pre, &block, &ctx)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ferrum_chain::ValidationError;

    use super::*;
    use crate::mutate::filler_tx;
    use crate::prng::XorShift64;
    use crate::reference::reference_height_push;

    fn chain() -> ChainBuilder {
        ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap()
    }

    // ---- red -----------------------------------------------------------

    #[test]
    fn two_identical_transactions_in_one_block_are_rejected() {
        let mut c = chain();
        let tx = filler_tx(9);
        let expected = ChainBuilder::txid_of(&tx);
        let ctx = c.next_ctx().unwrap();
        let pre = c.state_view();
        let block = c
            .build_block(&BlockPlan { txs: vec![tx.clone(), tx], ..BlockPlan::default() })
            .unwrap();
        match judge(&pre, &block, &ctx).unwrap().rejection() {
            Some(ValidationError::DuplicateTransaction { txid }) => assert_eq!(*txid, expected),
            other => panic!("expected DuplicateTransaction, got {other:?}"),
        }
    }

    #[test]
    fn a_coinbase_committing_to_the_wrong_height_is_rejected() {
        let mut c = chain();
        c.advance(4).unwrap();
        let height = c.height() + 1;
        // The BIP-34 push of the *previous* height.
        let mut script_sig = Vec::new();
        crate::sign::push_bytes(&mut script_sig, &reference_height_push(height - 1)).unwrap();
        crate::sign::push_bytes(&mut script_sig, b"nonce").unwrap();
        match block_with_coinbase_script_sig(&mut c, script_sig).unwrap().rejection() {
            Some(ValidationError::CoinbaseHeightMismatch { expected, found }) => {
                assert_eq!(*expected, height);
                assert_eq!(*found, reference_height_push(height - 1));
            }
            other => panic!("expected CoinbaseHeightMismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_coinbase_whose_script_sig_is_not_a_push_is_rejected() {
        let mut c = chain();
        // OP_CHECKSIG twice: two bytes, so the length rule passes and the
        // BIP-34 rule is the one that fires.
        match block_with_coinbase_script_sig(&mut c, vec![0xac, 0xac]).unwrap().rejection() {
            Some(ValidationError::CoinbaseMissingHeightPush) => {}
            other => panic!("expected CoinbaseMissingHeightPush, got {other:?}"),
        }
    }

    #[test]
    fn a_coinbase_script_sig_outside_the_length_window_is_rejected() {
        let mut c = chain();
        match block_with_coinbase_script_sig(&mut c, vec![0x00]).unwrap().rejection() {
            Some(ValidationError::CoinbaseScriptSigLength { len, min, max }) => {
                assert_eq!((*len, *min, *max), (1, 2, 100));
            }
            other => panic!("expected CoinbaseScriptSigLength, got {other:?}"),
        }
        let long = vec![0x00; 101];
        match block_with_coinbase_script_sig(&mut c, long).unwrap().rejection() {
            Some(ValidationError::CoinbaseScriptSigLength { len, .. }) => assert_eq!(*len, 101),
            other => panic!("expected CoinbaseScriptSigLength, got {other:?}"),
        }
    }

    #[test]
    fn a_non_minimal_height_push_is_rejected() {
        // Height 5 spelled as a one-byte direct push instead of OP_5. Without
        // the minimality rule, BIP-34 would have several spellings per height
        // and would stop being a uniqueness argument.
        let mut c = chain();
        c.advance(4).unwrap();
        assert_eq!(c.height() + 1, 5);
        let script_sig = vec![0x01, 0x05, 0x01, 0x00];
        match block_with_coinbase_script_sig(&mut c, script_sig).unwrap().rejection() {
            Some(ValidationError::CoinbaseMissingHeightPush) => {}
            other => panic!("expected CoinbaseMissingHeightPush, got {other:?}"),
        }
    }

    #[test]
    fn creating_an_outpoint_that_already_exists_is_rejected() {
        let mut c = chain();
        match colliding_outpoint(&mut c).unwrap().rejection() {
            Some(ValidationError::DuplicateOutPoint { out_point }) => {
                assert_eq!(out_point.vout, 0);
            }
            other => panic!("expected DuplicateOutPoint, got {other:?}"),
        }
    }

    // ---- green ---------------------------------------------------------

    #[test]
    fn the_honest_coinbase_is_accepted() {
        let mut c = chain();
        c.advance(4).unwrap();
        let height = c.height() + 1;
        let mut script_sig = Vec::new();
        crate::sign::push_bytes(&mut script_sig, &reference_height_push(height)).unwrap();
        crate::sign::push_bytes(&mut script_sig, b"nonce").unwrap();
        assert!(block_with_coinbase_script_sig(&mut c, script_sig).unwrap().is_accepted());
    }

    #[test]
    fn bip34_makes_two_coinbases_at_different_heights_distinct() {
        // Same payout, same extra nonce, different height: the height push is
        // the only difference, and it is enough.
        let mut c = chain();
        let first = c.build_block(&BlockPlan::default()).unwrap();
        c.connect(&first);
        let second = c.build_block(&BlockPlan::default()).unwrap();
        assert_ne!(
            ChainBuilder::txid_of(&first.txs[0]),
            ChainBuilder::txid_of(&second.txs[0]),
            "BIP-34 must separate coinbases by height"
        );
    }

    #[test]
    fn without_bip34_two_branches_at_one_height_would_collide() {
        // The rule BIP-34 does *not* cover: two branches at the same height
        // with the same payout. A miner separates them with an extra nonce,
        // which is why the coinbase carries one.
        let mut a = chain();
        let mut b = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        let block_a = a.build_block(&BlockPlan::default()).unwrap();
        let same = b.build_block(&BlockPlan::default()).unwrap();
        assert_eq!(
            ChainBuilder::txid_of(&block_a.txs[0]),
            ChainBuilder::txid_of(&same.txs[0]),
            "identical inputs must give identical txids; that is the hazard"
        );

        b.set_extra_nonce(1);
        let distinct = b.build_block(&BlockPlan::default()).unwrap();
        assert_ne!(
            ChainBuilder::txid_of(&block_a.txs[0]),
            ChainBuilder::txid_of(&distinct.txs[0]),
            "an extra nonce separates two branches at one height"
        );
    }

    #[test]
    fn two_different_transactions_in_one_block_are_accepted() {
        let mut c = chain();
        let ctx = c.next_ctx().unwrap();
        let pre = c.state_view();
        let block = c
            .build_block(&BlockPlan {
                txs: vec![filler_tx(1), filler_tx(2)],
                ..BlockPlan::default()
            })
            .unwrap();
        // They still fail — those inputs do not exist — but on the *state*
        // rule, not the duplicate rule, which is the point.
        assert!(matches!(
            judge(&pre, &block, &ctx).unwrap().rejection(),
            Some(ValidationError::MissingInput { .. })
        ));
    }
}
