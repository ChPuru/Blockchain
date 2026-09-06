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

use ferrum_chain::BlockCtx;
use ferrum_consensus::{compact_to_target, hash_meets_target};
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
    /// The block itself.
    pub block: Block,
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

/// Build the full catalogue of single-defect blocks for the next height.
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
        block: chain.build_block(&BlockPlan {
            merkle_root: Some(ferrum_types::Hash32::from_bytes([0x11; 32])),
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "the first transaction is not a coinbase",
        block: chain
            .build_block(&BlockPlan { coinbase: Some(filler_tx(1)), ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "a second coinbase claims a second subsidy",
        block: chain
            .build_block(&BlockPlan { txs: vec![fake_coinbase()], ..BlockPlan::default() })?,
    });
    let repeated = filler_tx(2);
    out.push(Mutation {
        name: "the same transaction appears twice (BIP-30)",
        block: chain.build_block(&BlockPlan {
            txs: vec![repeated.clone(), repeated],
            ..BlockPlan::default()
        })?,
    });

    // ---- SPEC §4.1: transaction sanity --------------------------------
    out.push(Mutation {
        name: "a transaction with no inputs",
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
        block: chain.build_block(&BlockPlan { version: Some(0), ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "the header names a parent it does not have",
        block: chain
            .build_block(&BlockPlan { prev_hash: Some(BlockHash::ZERO), ..BlockPlan::default() })?,
    });
    out.push(Mutation {
        name: "the timestamp is not strictly after median time past",
        block: chain.build_block(&BlockPlan {
            timestamp_ms: Some(ctx.median_time_past_ms()),
            ..BlockPlan::default()
        })?,
    });
    let mut weak = chain.build_block(&BlockPlan { grind: false, ..BlockPlan::default() })?;
    grind_until_invalid(&mut weak.header)?;
    out.push(Mutation { name: "the header hash does not meet its target", block: weak });
    out.push(Mutation {
        name: "a proof-of-work seal carrying a payload",
        block: chain.build_block(&BlockPlan {
            seal: Some(BlockSeal { engine: BlockSeal::ENGINE_POW, data: vec![0xff] }),
            ..BlockPlan::default()
        })?,
    });
    out.push(Mutation {
        name: "a seal naming an engine that is not active here",
        block: chain.build_block(&BlockPlan {
            seal: Some(BlockSeal { engine: BlockSeal::ENGINE_BFT, data: Vec::new() }),
            ..BlockPlan::default()
        })?,
    });

    // ---- SPEC §3.3: state rules ---------------------------------------
    let orphan_spend = chain_spend(chain, vec![phantom_coin(0x44)], Amount::from_grains(1))?;
    out.push(Mutation {
        name: "a transaction spends an output that does not exist",
        block: chain.build_block(&BlockPlan { txs: vec![orphan_spend], ..BlockPlan::default() })?,
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
            block: chain.build_block(&BlockPlan { txs: vec![tx], ..BlockPlan::default() })?,
        });
    }

    // ---- SPEC §3.3 rules 13 and 14: the coinbase ----------------------
    out.push(Mutation {
        name: "the coinbase overpays by one grain",
        block: chain.build_block(&BlockPlan { coinbase_bonus: 1, ..BlockPlan::default() })?,
    });
    if height > 1 {
        out.push(Mutation {
            name: "the coinbase commits to the wrong height",
            block: chain.build_block(&BlockPlan {
                height: Some(height.saturating_sub(1)),
                ..BlockPlan::default()
            })?,
        });
    }
    out.push(Mutation {
        name: "the coinbase script_sig is too short",
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
    fn every_variant_is_rejected_by_production() {
        let mut chain = ChainBuilder::devnet(XorShift64::SCENARIO_SEED).unwrap();
        chain.advance(105).unwrap();
        let ctx = chain.next_ctx().unwrap();
        let pre = chain.state_view();
        let variants = invalid_variants(&mut chain, &ctx).unwrap();
        assert!(variants.len() >= 20, "the catalogue must be broad, saw {}", variants.len());
        for m in &variants {
            assert!(
                ferrum_chain::apply_block(&pre, &m.block, &ctx).is_err(),
                "production accepted a block that breaks: {}",
                m.name
            );
        }
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
