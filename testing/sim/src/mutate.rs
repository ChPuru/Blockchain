//! A catalogue of single-defect invalid blocks.
//!
//! Every entry breaks **exactly one** rule of SPEC §3 or §4 and is otherwise a
//! block the chain would accept: the proof of work is ground, the Merkle root
//! commits to the transactions actually present, the coinbase claims the right
//! amount. Isolating one defect per block is what makes the differential test
//! meaningful — if a fixture broke three rules at once, the two executors could
//! agree on the verdict while disagreeing about every rule that produced it.
//!
//! The catalogue is used two ways: `tests/differential.rs` runs every entry
//! through both executors at every height, and the scenario modules reach for
//! individual builders when they want one specific attack.

use ferrum_chain::{BlockCtx, ValidationError};
use ferrum_consensus::{ConsensusError, compact_to_target, hash_meets_target};
use ferrum_script::sighash::SigHashType;
use ferrum_storage::header_hash;
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, BlockSeal, Coin, OutPoint, Script, Transaction, TxIn,
    TxOut, Txid,
};

use crate::chain_builder::{BlockPlan, ChainBuilder, SpendableCoin, TxPlan};
use crate::error::SimError;
use crate::keys::Lock;

/// One invalid block and the rule it breaks.
#[derive(Clone, Debug)]
pub struct Mutation {
    /// A short name, used in assertion messages.
    pub name: &'static str,
    /// The rule this block breaks, spelled as [`rule_name`] spells it.
    ///
    /// Asserting only "rejected" is what SPEC §3.4 warns about: a mutation
    /// that quietly started tripping a *different* rule would still be
    /// rejected, still agree across both executors, and still count towards
    /// any coverage floor, while the rule it was written for stopped being
    /// tested. Naming the expected rule here turns that into a test failure.
    pub expected: &'static str,
    /// The block itself.
    pub block: Block,
}

/// The rule a [`ValidationError`] names, as a stable string.
///
/// `Header` and `Seal` wrap a [`ConsensusError`], and collapsing either into
/// one bucket hides six distinct rules behind one name — version, parent,
/// timestamp, target, work and engine all become "Header". The inner variant
/// is therefore spelled out.
#[must_use]
pub fn rule_name(e: &ValidationError) -> &'static str {
    match e {
        ValidationError::BlockTooLarge { .. } => "BlockTooLarge",
        ValidationError::SealTooLarge { .. } => "SealTooLarge",
        ValidationError::EmptyBlock => "EmptyBlock",
        ValidationError::MissingCoinbase => "MissingCoinbase",
        ValidationError::MultipleCoinbases { .. } => "MultipleCoinbases",
        ValidationError::MerkleRootMismatch { .. } => "MerkleRootMismatch",
        ValidationError::DuplicateTransaction { .. } => "DuplicateTransaction",
        ValidationError::NoInputs => "NoInputs",
        ValidationError::NoOutputs => "NoOutputs",
        ValidationError::OutputValueOutOfRange { .. } => "OutputValueOutOfRange",
        ValidationError::OutputSumOverflow => "OutputSumOverflow",
        ValidationError::DuplicateInput { .. } => "DuplicateInput",
        ValidationError::ScriptTooLarge { .. } => "ScriptTooLarge",
        ValidationError::CoinbaseInputCount { .. } => "CoinbaseInputCount",
        ValidationError::CoinbaseInputNotNull => "CoinbaseInputNotNull",
        ValidationError::NullInput { .. } => "NullInput",
        ValidationError::Header(inner) => header_rule_name(inner),
        ValidationError::Seal(inner) => seal_rule_name(inner),
        ValidationError::MissingInput { .. } => "MissingInput",
        ValidationError::ImmatureCoinbaseSpend { .. } => "ImmatureCoinbaseSpend",
        ValidationError::InputSumOverflow { .. } => "InputSumOverflow",
        ValidationError::InsufficientInputValue { .. } => "InsufficientInputValue",
        ValidationError::FeeOverflow => "FeeOverflow",
        ValidationError::NonFinalTransaction { .. } => "NonFinalTransaction",
        ValidationError::UnsatisfiedRelativeLock { .. } => "UnsatisfiedRelativeLock",
        ValidationError::UnsupportedRelativeTimeLock { .. } => "UnsupportedRelativeTimeLock",
        ValidationError::SigCheckBudgetExceeded { .. } => "SigCheckBudgetExceeded",
        ValidationError::ScriptVerification { .. } => "ScriptVerification",
        ValidationError::CoinbaseScriptSigLength { .. } => "CoinbaseScriptSigLength",
        ValidationError::CoinbaseMissingHeightPush => "CoinbaseMissingHeightPush",
        ValidationError::CoinbaseHeightMismatch { .. } => "CoinbaseHeightMismatch",
        ValidationError::CoinbaseOverpayment { .. } => "CoinbaseOverpayment",
        ValidationError::CoinbaseAllowanceOverflow => "CoinbaseAllowanceOverflow",
        ValidationError::DuplicateOutPoint { .. } => "DuplicateOutPoint",
        ValidationError::View { .. } => "View",
        ValidationError::Arithmetic(_) => "Arithmetic",
        _ => "unnamed ValidationError",
    }
}

/// The header rule a [`ConsensusError`] names (SPEC §3.2 rules 6–10).
fn header_rule_name(e: &ConsensusError) -> &'static str {
    match e {
        ConsensusError::BadVersion(_) => "Header::BadVersion",
        ConsensusError::WrongParent { .. } => "Header::WrongParent",
        ConsensusError::TimestampTooOld { .. } => "Header::TimestampTooOld",
        ConsensusError::TimestampTooFarInFuture { .. } => "Header::TimestampTooFarInFuture",
        ConsensusError::BadDifficultyTransition { .. } => "Header::BadDifficultyTransition",
        ConsensusError::InsufficientWork { .. } => "Header::InsufficientWork",
        ConsensusError::ZeroTarget => "Header::ZeroTarget",
        ConsensusError::TargetAbovePowLimit { .. } => "Header::TargetAbovePowLimit",
        ConsensusError::NegativeTarget(_) => "Header::NegativeTarget",
        ConsensusError::ZeroMantissaTarget(_) => "Header::ZeroMantissaTarget",
        ConsensusError::TargetOverflow(_) => "Header::TargetOverflow",
        ConsensusError::NonZeroBftNonce(_) => "Header::NonZeroBftNonce",
        _ => "Header::unnamed ConsensusError",
    }
}

/// The seal rule a [`ConsensusError`] names (SPEC §3.2 rule 11).
fn seal_rule_name(e: &ConsensusError) -> &'static str {
    match e {
        ConsensusError::WrongEngine { .. } => "Seal::WrongEngine",
        ConsensusError::NonEmptyPowSeal(_) => "Seal::NonEmptyPowSeal",
        _ => "Seal::unnamed ConsensusError",
    }
}

/// A coin that does not exist, spendable with an empty `script_sig` if it did.
///
/// Used to produce a `MissingInput` without touching the real UTXO set.
#[must_use]
pub fn phantom_coin(seed: u8) -> SpendableCoin {
    SpendableCoin {
        out_point: OutPoint::new(Txid(ferrum_types::Hash32::from_bytes([seed; 32])), 0),
        coin: Coin {
            value: Amount::from_grains(1_000_000),
            script_pubkey: Script::new(vec![0x51]),
            height: 0,
            is_coinbase: false,
        },
        lock: Lock::Anyone,
    }
}

/// A transaction with one non-null input and one output, satisfying nothing.
///
/// Cheap filler for the mutations that only need "a transaction that is not a
/// coinbase" in a particular position.
#[must_use]
pub fn filler_tx(tag: u32) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::new(
            OutPoint::new(Txid(ferrum_types::Hash32::from_bytes([0xab; 32])), tag),
            Script::EMPTY,
        )],
        outputs: vec![TxOut::new(Amount::from_grains(1), Script::new(vec![0x51]))],
        lock_time: 0,
    }
}

/// A transaction shaped exactly like a coinbase, for the second-coinbase rule.
#[must_use]
pub fn fake_coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(Script::new(vec![0x00, 0x01]))],
        outputs: vec![TxOut::new(Amount::ZERO, Script::new(vec![0x51]))],
        lock_time: 0,
    }
}

/// Re-grind a header until its hash **fails** its own target.
///
/// The devnet limit accepts roughly half of all hashes, so "leave the nonce at
/// zero" is not a reliable way to build a block with insufficient work.
///
/// # Errors
///
/// [`SimError::Consensus`] for a target that cannot be expanded, and
/// [`SimError::MiningBudgetExhausted`] if no failing nonce is found, which
/// cannot happen for any target below the maximum.
pub fn grind_until_invalid(header: &mut BlockHeader) -> Result<(), SimError> {
    let target = compact_to_target(header.bits)?;
    for attempt in 0..1_000_000u64 {
        if !hash_meets_target(&header_hash(header), target) {
            return Ok(());
        }
        header.nonce = attempt.saturating_add(1);
    }
    Err(SimError::MiningBudgetExhausted(1_000_000))
}

/// A block whose second transaction spends an output the block's own coinbase
/// creates.
///
/// SPEC §3.3 rule 12 applies every non-coinbase transaction "against an
/// overlay of the UTXO set **at the parent**". The coinbase's outputs join the
/// UTXO set when the block is connected, not while it is being validated, so
/// the spend resolves against nothing and the block is rejected with
/// `MissingInput` — at every `coinbase_maturity`, including zero.
///
/// The block is otherwise flawless: the coinbase claims only the subsidy
/// (claiming less than `subsidy + fees` is legal), the signature over the
/// coinbase's own output is genuine, the Merkle root commits to both
/// transactions and the proof of work is ground.
///
/// # Errors
///
/// [`SimError`] if the fixture cannot be built.
pub fn spend_of_the_blocks_own_coinbase(
    chain: &mut ChainBuilder,
    ctx: &BlockCtx,
) -> Result<Block, SimError> {
    let height = ctx.height;
    let payout = Lock::P2pkh { key: 0 };
    let value = chain.params().block_subsidy(height);
    let coinbase = chain.build_coinbase(height, value, &payout, None)?;
    let script_pubkey = payout.script_pubkey(chain.keys())?;
    let own = SpendableCoin {
        out_point: OutPoint::new(ChainBuilder::txid_of(&coinbase), 0),
        coin: Coin { value, script_pubkey, height, is_coinbase: true },
        lock: payout,
    };
    let tx = chain.build_tx(&TxPlan::sweep(
        vec![own],
        Lock::P2pkh { key: 2 },
        Amount::from_grains(1_000),
    ))?;
    chain.build_block(&BlockPlan {
        coinbase: Some(coinbase),
        txs: vec![tx],
        ..BlockPlan::default()
    })
}

/// Build the full catalogue of single-defect blocks for the next height.
///
/// The catalogue follows `ctx.engine_id`: the proof-of-work entries are built
/// only at a PoW height, because SPEC §3.2 rule 8 is annotated "(PoW engine
/// only)" and a header hash above its target is simply not a defect under BFT.
/// Every other entry is engine-independent and is built at both.
///
/// `chain` is only read for fixtures — no mutation is ever connected — so the
/// caller's chain state is unchanged apart from the lock bookkeeping the
/// transaction factory keeps.
///
/// # Errors
///
/// [`SimError`] if a fixture cannot be built.
pub fn invalid_variants(
    chain: &mut ChainBuilder,
    ctx: &BlockCtx,
) -> Result<Vec<Mutation>, SimError> {
    let mut out: Vec<Mutation> = Vec::new();
    let height = ctx.height;

    // ---- SPEC §3.1: context-free block rules --------------------------
    out.push(Mutation {
        name: "merkle root does not commit to the transactions",
        expected: "MerkleRootMismatch",
        block: chain.build_block(&BlockPlan {
            merkle_root: Some(ferrum_types::Hash32::from_bytes([0x11; 32])),
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "the first transaction is not a coinbase",
        expected: "MissingCoinbase",
        block: chain
            .build_block(&BlockPlan { coinbase: Some(filler_tx(1)), ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "a second coinbase claims a second subsidy",
        expected: "MultipleCoinbases",
        block: chain
            .build_block(&BlockPlan { txs: vec![fake_coinbase()], ..BlockPlan::default() })?,
    });
    let repeated = filler_tx(2);
    out.push(Mutation {
        name: "the same transaction appears twice (BIP-30)",
        expected: "DuplicateTransaction",
        block: chain.build_block(&BlockPlan {
            txs: vec![repeated.clone(), repeated],
            ..BlockPlan::default()
        })?,
    });

    // ---- SPEC §4.1: transaction sanity --------------------------------
    out.push(Mutation {
        name: "a transaction with no inputs",
        expected: "NoInputs",
        block: chain.build_block(&BlockPlan {
            txs: vec![Transaction {
                version: 1,
                inputs: Vec::new(),
                outputs: vec![TxOut::new(Amount::from_grains(1), Script::new(vec![0x51]))],
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "a transaction with no outputs",
        expected: "NoOutputs",
        block: chain.build_block(&BlockPlan {
            txs: vec![Transaction {
                version: 1,
                inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 3), Script::EMPTY)],
                outputs: Vec::new(),
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "an output above MAX_MONEY",
        expected: "OutputValueOutOfRange",
        block: chain.build_block(&BlockPlan {
            txs: vec![Transaction {
                version: 1,
                inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 4), Script::EMPTY)],
                outputs: vec![TxOut::new(
                    Amount::from_grains(Amount::MAX_MONEY.to_grains().saturating_add(1)),
                    Script::new(vec![0x51]),
                )],
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "two outputs that each fit but whose sum does not",
        expected: "OutputSumOverflow",
        block: chain.build_block(&BlockPlan {
            txs: vec![Transaction {
                version: 1,
                inputs: vec![TxIn::new(OutPoint::new(Txid::ZERO, 5), Script::EMPTY)],
                outputs: vec![
                    TxOut::new(Amount::MAX_MONEY, Script::new(vec![0x51])),
                    TxOut::new(Amount::MAX_MONEY, Script::new(vec![0x51])),
                ],
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })?,
    });
    let phantom = phantom_coin(0x33);
    out.push(Mutation {
        name: "one transaction spends the same outpoint twice",
        expected: "DuplicateInput",
        block: chain.build_block(&BlockPlan {
            txs: vec![Transaction {
                version: 1,
                inputs: vec![
                    TxIn::new(phantom.out_point, Script::EMPTY),
                    TxIn::new(phantom.out_point, Script::EMPTY),
                ],
                outputs: vec![TxOut::new(Amount::from_grains(1), Script::new(vec![0x51]))],
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "a non-coinbase transaction names the null outpoint",
        expected: "NullInput",
        block: chain.build_block(&BlockPlan {
            txs: vec![Transaction {
                version: 1,
                inputs: vec![
                    TxIn::new(OutPoint::new(Txid::ZERO, 6), Script::EMPTY),
                    TxIn::coinbase(Script::EMPTY),
                ],
                outputs: vec![TxOut::new(Amount::from_grains(1), Script::new(vec![0x51]))],
                lock_time: 0,
            }],
            ..BlockPlan::default()
        })?,
    });

    // ---- SPEC §3.2: header rules --------------------------------------
    out.push(Mutation {
        name: "a block version below the minimum",
        expected: "Header::BadVersion",
        block: chain.build_block(&BlockPlan { version: Some(0), ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "the header names a parent it does not have",
        expected: "Header::WrongParent",
        block: chain
            .build_block(&BlockPlan { prev_hash: Some(BlockHash::ZERO), ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "the timestamp is not strictly after median time past",
        expected: "Header::TimestampTooOld",
        block: chain.build_block(&BlockPlan {
            timestamp_ms: Some(ctx.median_time_past_ms()),
            ..BlockPlan::default()
        })?,
    });
    // Rule 8 is annotated "(PoW engine only)" and rule 11's payload clause
    // belongs to the PoW seal, so neither has a defect to construct at a BFT
    // height: there the certificate is the proof and the nonce is ignored.
    if ctx.engine_id == BlockSeal::ENGINE_POW {
        let mut weak = chain.build_block(&BlockPlan { grind: false, ..BlockPlan::default() })?;
        grind_until_invalid(&mut weak.header)?;
        out.push(Mutation {
            name: "the header hash does not meet its target",
            expected: "Header::InsufficientWork",
            block: weak,
        });
        out.push(Mutation {
            name: "a proof-of-work seal carrying a payload",
            expected: "Seal::NonEmptyPowSeal",
            block: chain.build_block(&BlockPlan {
                seal: Some(BlockSeal { engine: BlockSeal::ENGINE_POW, data: vec![0xff] }),
                ..BlockPlan::default()
            })?,
        });
    }
    // Rule 11's engine clause has a defect under either engine: whichever one
    // is active at this height, a seal naming the other is wrong.
    let inactive_engine = if ctx.engine_id == BlockSeal::ENGINE_POW {
        BlockSeal::ENGINE_BFT
    } else {
        BlockSeal::ENGINE_POW
    };
    out.push(Mutation {
        name: "a seal naming an engine that is not active here",
        expected: "Seal::WrongEngine",
        block: chain.build_block(&BlockPlan {
            seal: Some(BlockSeal { engine: inactive_engine, data: Vec::new() }),
            ..BlockPlan::default()
        })?,
    });

    // ---- SPEC §3.3: state rules ---------------------------------------
    let orphan_spend = chain_spend(chain, vec![phantom_coin(0x44)], Amount::from_grains(1))?;
    out.push(Mutation {
        name: "a transaction spends an output that does not exist",
        expected: "MissingInput",
        block: chain.build_block(&BlockPlan { txs: vec![orphan_spend], ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "a transaction spends an output the block's own coinbase creates",
        expected: "MissingInput",
        block: spend_of_the_blocks_own_coinbase(chain, ctx)?,
    });

    let mature = chain.mature(height);
    if let Some(coin) = mature.first().cloned() {
        // Two transactions in one block spending the same coin.
        let first = chain_spend(chain, vec![coin.clone()], Amount::from_grains(1_000))?;
        let second = TxPlan {
            inputs: vec![coin.clone()],
            outputs: vec![(
                Lock::P2pkh { key: 5 },
                coin.coin.value.saturating_sub(Amount::from_grains(2_000)),
            )],
            ..TxPlan::default()
        };
        let second = chain.build_tx(&second)?;
        out.push(Mutation {
            name: "two transactions in one block spend the same coin",
            expected: "MissingInput",
            block: chain
                .build_block(&BlockPlan { txs: vec![first, second], ..BlockPlan::default() })?,
        });

        // Outputs exceeding inputs by one grain.
        let inflate = TxPlan {
            inputs: vec![coin.clone()],
            outputs: vec![(
                Lock::P2pkh { key: 6 },
                coin.coin.value.saturating_add(Amount::from_grains(1)),
            )],
            ..TxPlan::default()
        };
        let inflate = chain.build_tx(&inflate)?;
        out.push(Mutation {
            name: "a transaction pays out one grain more than it spends",
            expected: "InsufficientInputValue",
            block: chain.build_block(&BlockPlan { txs: vec![inflate], ..BlockPlan::default() })?,
        });

        // A locktime in the future makes the transaction non-final.
        let late = TxPlan {
            inputs: vec![coin.clone()],
            outputs: vec![(
                Lock::P2pkh { key: 7 },
                coin.coin.value.saturating_sub(Amount::from_grains(1_000)),
            )],
            lock_time: u32::try_from(height.saturating_add(50)).unwrap_or(u32::MAX),
            ..TxPlan::default()
        };
        let late = chain.build_tx(&late)?;
        out.push(Mutation {
            name: "a transaction whose locktime has not been reached",
            expected: "NonFinalTransaction",
            block: chain.build_block(&BlockPlan { txs: vec![late], ..BlockPlan::default() })?,
        });

        // A signature made for the wrong sighash flavour: SIGHASH_SINGLE with
        // no matching output is an error rather than Bitcoin's uint256(1).
        let mut broken = chain_spend(chain, vec![coin.clone()], Amount::from_grains(1_000))?;
        if let Some(input) = broken.inputs.first_mut() {
            let mut bytes = input.script_sig.as_bytes().to_vec();
            if let Some(byte) = bytes.get_mut(1) {
                *byte ^= 0x01;
            }
            input.script_sig = Script::new(bytes);
        }
        out.push(Mutation {
            name: "a corrupted signature",
            expected: "ScriptVerification",
            block: chain.build_block(&BlockPlan { txs: vec![broken], ..BlockPlan::default() })?,
        });
    }

    // An immature coinbase: the most recent block's payout is always younger
    // than `coinbase_maturity`.
    if let Some(young) = chain
        .spendable()
        .iter()
        .rev()
        .find(|c| c.coin.is_coinbase && !c.is_mature(height, chain.params().coinbase_maturity))
        .cloned()
    {
        let tx = chain_spend(chain, vec![young], Amount::from_grains(1_000))?;
        out.push(Mutation {
            name: "a coinbase output spent before it matured",
            expected: "ImmatureCoinbaseSpend",
            block: chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() })?,
        });
    }

    // ---- SPEC §3.3 rules 13 and 14: the coinbase ----------------------
    out.push(Mutation {
        name: "the coinbase overpays by one grain",
        expected: "CoinbaseOverpayment",
        block: chain.build_block(&BlockPlan { coinbase_bonus: 1, ..BlockPlan::default() })?,
    });
    if height > 1 {
        out.push(Mutation {
            name: "the coinbase commits to the wrong height",
            expected: "CoinbaseHeightMismatch",
            block: chain.build_block(&BlockPlan {
                height: Some(height.saturating_sub(1)),
                ..BlockPlan::default()
            })?,
        });
    }
    out.push(Mutation {
        name: "the coinbase script_sig is too short",
        expected: "CoinbaseScriptSigLength",
        block: chain.build_block(&BlockPlan {
            coinbase: Some(Transaction {
                version: 1,
                inputs: vec![TxIn::coinbase(Script::new(vec![0x00]))],
                outputs: vec![TxOut::new(Amount::ZERO, Script::new(vec![0x51]))],
                lock_time: 0,
            }),
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "the coinbase script_sig does not begin with a push",
        expected: "CoinbaseMissingHeightPush",
        block: chain.build_block(&BlockPlan {
            coinbase: Some(Transaction {
                version: 1,
                inputs: vec![TxIn::coinbase(Script::new(vec![0xac, 0xac]))],
                outputs: vec![TxOut::new(Amount::ZERO, Script::new(vec![0x51]))],
                lock_time: 0,
            }),
            ..BlockPlan::default()
        })?,
    });

    Ok(out)
}

/// Build a transaction sweeping `coins` to key 4 minus `fee`.
fn chain_spend(
    chain: &mut ChainBuilder,
    coins: Vec<SpendableCoin>,
    fee: Amount,
) -> Result<Transaction, SimError> {
    let plan = TxPlan {
        sighash_type: SigHashType::ALL,
        ..TxPlan::sweep(coins, Lock::P2pkh { key: 4 }, fee)
    };
    chain.build_tx(&plan)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::prng::XorShift64;

    #[test]
    fn every_variant_is_rejected_by_production_for_the_rule_it_names() {
        let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        chain.advance(105).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let variants = invalid_variants(&mut chain, &ctx).unwrap();
        assert!(variants.len() >= 20, "the catalogue must be broad, saw {}", variants.len());
        for m in &variants {
            // `is_err()` alone would keep passing if a fixture drifted into
            // breaking some *other* rule, which is how a rule silently stops
            // being tested (SPEC §3.4).
            match ferrum_chain::apply_block(&pre, &m.block, &ctx) {
                Err(e) => assert_eq!(rule_name(&e), m.expected, "mutation: {}", m.name),
                Ok(_) => panic!("production accepted a block that breaks: {}", m.name),
            }
        }
    }

    #[test]
    fn the_catalogue_covers_many_distinct_rules() {
        let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        chain.advance(105).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let rules: std::collections::BTreeSet<&str> =
            invalid_variants(&mut chain, &ctx).unwrap().iter().map(|m| m.expected).collect();
        assert!(rules.len() >= 24, "the catalogue collapsed onto {} rules: {rules:?}", rules.len());
        for named in [
            "Header::BadVersion",
            "Header::WrongParent",
            "Header::TimestampTooOld",
            "Header::InsufficientWork",
            "Seal::NonEmptyPowSeal",
            "Seal::WrongEngine",
        ] {
            assert!(rules.contains(named), "no fixture reaches {named}");
        }
    }

    #[test]
    fn header_and_seal_rules_are_named_one_by_one() {
        // The point of naming the inner error: six header rules must not share
        // one bucket, or a mutation can be "covered" while testing nothing.
        let names = [
            rule_name(&ValidationError::Header(ConsensusError::BadVersion(0))),
            rule_name(&ValidationError::Header(ConsensusError::ZeroTarget)),
            rule_name(&ValidationError::Header(ConsensusError::WrongParent {
                expected: ferrum_types::BlockHash::ZERO,
                actual: ferrum_types::BlockHash::ZERO,
            })),
            rule_name(&ValidationError::Seal(ConsensusError::NonEmptyPowSeal(1))),
            rule_name(&ValidationError::Seal(ConsensusError::WrongEngine {
                expected: 0,
                actual: 1,
            })),
        ];
        let distinct: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(distinct.len(), names.len(), "two rules share a name: {names:?}");
        assert!(names.iter().all(|n| !n.contains("unnamed")), "{names:?}");
    }

    #[test]
    fn a_failing_nonce_can_always_be_found() {
        let mut chain = ChainBuilder::devnet(1).unwrap();
        let mut block =
            chain.build_block(&BlockPlan { grind: false, ..BlockPlan::default() }).unwrap();
        grind_until_invalid(&mut block.header).unwrap();
        let target = compact_to_target(block.header.bits).unwrap();
        assert!(!hash_meets_target(&header_hash(&block.header), target));
    }
}
