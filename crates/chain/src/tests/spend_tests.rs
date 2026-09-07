//! SPEC §4.2 and §3.3: spending against the UTXO overlay, and the coinbase.
//!
//! Split out of `apply_tests` because these are the rules that guard the money
//! supply, and they deserve to be read together: resolve, mature, pay for what
//! you spend, and claim no more than the subsidy plus the fees.

use ferrum_crypto::{SecretKey, hash160};
use ferrum_script::ScriptError;
use ferrum_script::opcode::encode_push;
use ferrum_script::sighash::{SigHashType, encode_signature, signature_hash};
use ferrum_storage::{EmptyView, header_hash};
use ferrum_types::{
    Amount, Block, BlockHash, BlockHeader, ChainId, ChainParams, Coin, Hash32, OutPoint, Script,
    Transaction, Txid,
};

use crate::apply::{apply_block, max_block_sig_checks};
use crate::ctx::BlockCtx;
use crate::error::ValidationError;
use crate::tests::support::{
    any_spend_script, block_of, burn_script, coin, coinbase, coinbase_with_script_sig, ctx_at,
    devnet, devnet_with, map_view, out_point, parent_header, spend,
};

const PARENT_MS: u64 = 1_700_000_000_000;
const BLOCK_MS: u64 = PARENT_MS + 120_000;
const MTP_S: u64 = PARENT_MS / 1_000;

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

/// A parent header, its hash and a context for its child at height 1.
fn scene(params: &ChainParams) -> (BlockHeader, BlockHash, BlockCtx) {
    let parent = parent_header(PARENT_MS, params);
    let hash = header_hash(&parent);
    let ctx = ctx_at(1, &parent, MTP_S, params);
    (parent, hash, ctx)
}

fn block_with(txs: Vec<Transaction>, prev: BlockHash, params: &ChainParams) -> Block {
    block_of(txs, prev, BLOCK_MS, params.genesis_bits)
}

// ------------------------------------------------------- contextual rules

#[test]
fn spending_an_output_that_does_not_exist_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let ghost = OutPoint::new(Txid(Hash32::from_bytes([15; 32])), 0);
    let tx = spend(&[ghost], &[(amount(1), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 1, out_point: ghost })
    );
}

#[test]
fn a_double_spend_inside_one_block_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([16; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);

    let first = spend(&[funded], &[(amount(900), any_spend_script())]);
    let second = spend(&[funded], &[(amount(800), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), first, second], prev, &params);

    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 2, out_point: funded }),
        "the second spender finds the coin already gone"
    );
}

#[test]
fn a_coinbase_spent_before_maturity_is_rejected() {
    let params = devnet();
    let (_, prev, _) = scene(&params);
    // The last height at which the spend is still one block too early. Derived
    // from the parameters rather than written out, so that retuning devnet's
    // maturity cannot leave this test asserting the wrong boundary: a coin
    // mined at height 1 matures at 1 + maturity.
    let maturity = params.coinbase_maturity;
    let coin_height = 1;
    let too_early = coin_height + maturity - 1;
    let ctx = ctx_at(too_early, &parent_header(PARENT_MS, &params), MTP_S, &params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([17; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), coin_height, true))]);

    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let block = block_of(
        vec![coinbase(too_early, amount(1), b"n"), tx],
        prev,
        BLOCK_MS,
        params.genesis_bits,
    );
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::ImmatureCoinbaseSpend {
            tx_index: 1,
            out_point: funded,
            coin_height,
            spend_height: too_early,
            maturity,
        }),
        "{coin_height} + {maturity} = {}, so height {too_early} is one block too early",
        coin_height + maturity
    );
}

#[test]
fn a_coinbase_spent_exactly_at_maturity_is_accepted() {
    let params = devnet();
    let parent = parent_header(PARENT_MS, &params);
    let prev = header_hash(&parent);
    // The first height at which the spend is legal, derived from the
    // parameters: a coin mined at height 1 matures at `1 + maturity`. Written
    // out as a constant it would silently stop being the boundary the moment
    // devnet's maturity was retuned, which is exactly what happened when it
    // went from 100 to 10.
    let coin_height = 1;
    let exactly = coin_height + params.coinbase_maturity;
    let ctx = ctx_at(exactly, &parent, MTP_S, &params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([18; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), coin_height, true))]);

    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let reward = params.block_subsidy(exactly).checked_add(amount(100)).unwrap();
    let block =
        block_of(vec![coinbase(exactly, reward, b"n"), tx], prev, BLOCK_MS, params.genesis_bits);
    assert!(
        apply_block(&pre, &block, &ctx).is_ok(),
        "{coin_height} + {} = {exactly}, the first legal height",
        params.coinbase_maturity
    );
}

#[test]
fn a_transaction_that_spends_more_than_it_holds_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([19; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(100), 0, false))]);
    let tx = spend(&[funded], &[(amount(101), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::InsufficientInputValue {
            tx_index: 1,
            inputs: amount(100),
            outputs: amount(101),
        })
    );
}

#[test]
fn an_input_sum_outside_the_money_range_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let a = OutPoint::new(Txid(Hash32::from_bytes([20; 32])), 0);
    let b = OutPoint::new(Txid(Hash32::from_bytes([20; 32])), 1);
    let pre =
        map_view(&[(a, coin(Amount::MAX_MONEY, 0, false)), (b, coin(Amount::MAX_MONEY, 0, false))]);
    let tx = spend(&[a, b], &[(amount(1), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::InputSumOverflow { tx_index: 1 })
    );
}

#[test]
fn maturity_is_checked_for_every_input_before_the_input_sum() {
    // CONTRACT §8.1 rule 7 states the per-transaction rules as an ordered list
    // over the whole transaction — resolve, then maturity, then value — not as
    // one interleaved pass per input. The two readings agree on every
    // transaction that breaks a single rule and disagree here, where the second
    // input already pushes the sum out of the money range and the third is an
    // immature coinbase. SPEC §3.4 makes the choice observable, so it is pinned
    // rather than left to whichever loop shape an implementation happens to
    // use; the reference executor in `testing/sim` reads it the same way.
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let a = OutPoint::new(Txid(Hash32::from_bytes([71; 32])), 0);
    let b = OutPoint::new(Txid(Hash32::from_bytes([71; 32])), 1);
    let young = OutPoint::new(Txid(Hash32::from_bytes([72; 32])), 0);
    let pre = map_view(&[
        (a, coin(Amount::MAX_MONEY, 0, false)),
        (b, coin(Amount::MAX_MONEY, 0, false)),
        (young, coin(amount(1_000), 1, true)),
    ]);
    let tx = spend(&[a, b, young], &[(amount(1), any_spend_script())]);
    let block = block_with(vec![coinbase(1, amount(1), b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::ImmatureCoinbaseSpend {
            tx_index: 1,
            out_point: young,
            coin_height: 1,
            spend_height: 1,
            maturity: params.coinbase_maturity,
        }),
        "every input's maturity is judged before any input's value"
    );
}

#[test]
fn a_non_final_transaction_makes_the_block_invalid() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([21; 32])), 0);
    let pre = map_view(&[(funded, coin(amount(1_000), 0, false))]);
    let mut tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    tx.lock_time = 50; // a height lock, and we are at height 1
    tx.inputs[0].sequence = 0;
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::NonFinalTransaction { tx_index: 1, lock_time: 50 })
    );
}

#[test]
fn a_script_that_does_not_satisfy_its_output_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([22; 32])), 0);
    let unspendable =
        Coin { value: amount(1_000), script_pubkey: burn_script(), height: 0, is_coinbase: false };
    let pre = map_view(&[(funded, unspendable)]);
    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert!(matches!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::ScriptVerification { tx_index: 1, input_index: 0, .. })
    ));
}

#[test]
fn fees_accumulate_across_transactions() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let a = OutPoint::new(Txid(Hash32::from_bytes([23; 32])), 0);
    let b = OutPoint::new(Txid(Hash32::from_bytes([24; 32])), 0);
    let pre = map_view(&[(a, coin(amount(500), 0, false)), (b, coin(amount(500), 0, false))]);
    let tx1 = spend(&[a], &[(amount(450), any_spend_script())]);
    let tx2 = spend(&[b], &[(amount(430), any_spend_script())]);
    let reward = params.block_subsidy(1).checked_add(amount(120)).unwrap();

    let ok = block_with(vec![coinbase(1, reward, b"n"), tx1.clone(), tx2.clone()], prev, &params);
    assert!(apply_block(&pre, &ok, &ctx).is_ok(), "50 + 70 grains of fees");

    let over = block_with(
        vec![coinbase(1, reward.checked_add(amount(1)).unwrap(), b"n"), tx1, tx2],
        prev,
        &params,
    );
    assert!(matches!(
        apply_block(&pre, &over, &ctx),
        Err(ValidationError::CoinbaseOverpayment { .. })
    ));
}

// ------------------------------------------------------------ coinbase rules

#[test]
fn a_coinbase_that_overpays_by_one_grain_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let subsidy = params.block_subsidy(1);
    let greedy = subsidy.checked_add(amount(1)).unwrap();
    let block = block_with(vec![coinbase(1, greedy, b"n")], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseOverpayment { claimed: greedy, allowed: subsidy })
    );
}

#[test]
fn a_coinbase_paying_exactly_the_subsidy_is_accepted() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let block = block_with(vec![coinbase(1, params.block_subsidy(1), b"n")], prev, &params);
    assert!(apply_block(&EmptyView, &block, &ctx).is_ok());
}

#[test]
fn a_coinbase_without_the_height_push_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    // OP_DUP OP_DUP: two bytes, so the length rule passes and only BIP-34 can
    // reject it. Without this rule two blocks share a coinbase txid, which is
    // CVE-2012-1909.
    let cb = coinbase_with_script_sig(Script::new(vec![0x76, 0x76]), amount(1));
    let block = block_with(vec![cb], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseMissingHeightPush)
    );
}

#[test]
fn a_coinbase_committing_to_another_height_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let block = block_with(vec![coinbase(2, amount(1), b"n")], prev, &params);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseHeightMismatch { expected: 1, found: vec![0x02] })
    );
}

#[test]
fn a_one_byte_coinbase_script_sig_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let cb = coinbase_with_script_sig(Script::new(vec![0x51]), amount(1));
    let block = block_with(vec![cb], prev, &params);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseScriptSigLength { len: 1, .. })
    ));
}

#[test]
fn an_over_long_coinbase_script_sig_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let mut sig = vec![0x51];
    sig.extend(std::iter::repeat_n(0x61u8, 200));
    let cb = coinbase_with_script_sig(Script::new(sig), amount(1));
    let block = block_with(vec![cb], prev, &params);
    assert!(matches!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::CoinbaseScriptSigLength { len: 201, .. })
    ));
}

#[test]
fn creating_an_outpoint_that_already_exists_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let cb = coinbase(1, amount(1), b"n");
    let collision = out_point(&cb, 0);
    let pre = map_view(&[(collision, coin(amount(7), 0, true))]);
    let block = block_with(vec![cb], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::DuplicateOutPoint { out_point: collision })
    );
}

#[test]
fn a_non_coinbase_output_colliding_with_the_utxo_set_is_rejected() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([25; 32])), 0);
    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let collision = out_point(&tx, 0);
    let pre = map_view(&[
        (funded, coin(amount(1_000), 0, false)),
        (collision, coin(amount(3), 0, false)),
    ]);
    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::DuplicateOutPoint { out_point: collision })
    );
}

// ------------------------------------------ cross-chain signature replay

/// A fixed signing key. Any 32 bytes below the curve order will do.
fn replay_key() -> SecretKey {
    SecretKey::from_bytes(&[7u8; 32]).expect("a fixed test key is on the curve")
}

/// The `script_sig` satisfying a P2PKH output: `<65B sig> <32B x-only key>`.
///
/// Signs input 0 under `chain_id`, which is the only thing the two calls in
/// the replay test below disagree about.
fn p2pkh_script_sig(
    key: &SecretKey,
    tx: &Transaction,
    script_code: &Script,
    value: Amount,
    chain_id: ChainId,
) -> Script {
    let digest = signature_hash(tx, 0, script_code.as_bytes(), value, chain_id, SigHashType::ALL)
        .expect("a single-input SIGHASH_ALL preimage always builds");
    let signature = encode_signature(&key.sign_deterministic(&digest), SigHashType::ALL);
    let mut bytes = encode_push(&signature).expect("65 bytes is a direct push");
    bytes.extend_from_slice(
        &encode_push(key.public_key().as_bytes()).expect("32 bytes is a direct push"),
    );
    Script::new(bytes)
}

/// A block spending one P2PKH coin, signed for `signed_for`, plus the
/// pre-state it spends from.
fn replay_fixture(params: &ChainParams, signed_for: ChainId) -> (ferrum_storage::MapView, Block) {
    let key = replay_key();
    let script_pubkey = ferrum_script::templates::p2pkh(&hash160(key.public_key().as_bytes()));
    let funded = OutPoint::new(Txid(Hash32::from_bytes([31; 32])), 0);
    let value = amount(1_000);
    let pre = map_view(&[(
        funded,
        Coin { value, script_pubkey: script_pubkey.clone(), height: 0, is_coinbase: false },
    )]);

    let mut tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    tx.inputs[0].script_sig = p2pkh_script_sig(&key, &tx, &script_pubkey, value, signed_for);

    let reward = params.block_subsidy(1).checked_add(amount(100)).expect("subsidy plus fee fits");
    let (_, prev, _) = scene(params);
    (pre, block_with(vec![coinbase(1, reward, b"n"), tx], prev, params))
}

#[test]
fn a_signature_made_under_one_chain_id_is_rejected_under_another() {
    // The seam this guards is `apply_block` filling `ExecCtx::chain_id` from
    // `ctx.params.chain_id`. `ferrum-script` already proves the sighash
    // preimage commits to the chain id; only a block-level test proves
    // `ferrum-chain` passes the *running network's* id through rather than a
    // constant, which is what stops a testnet signature being replayed on
    // mainnet.
    let signing = devnet();
    let replay = devnet_with(|p| p.chain_id = ChainId::MAINNET);
    assert_ne!(signing.chain_id, replay.chain_id, "the two networks must differ");

    let (pre, block) = replay_fixture(&signing, signing.chain_id);

    let (_, _, own_ctx) = scene(&signing);
    apply_block(&pre, &block, &own_ctx).expect("the signature is valid on its own chain");

    let (_, _, foreign_ctx) = scene(&replay);
    assert_eq!(
        apply_block(&pre, &block, &foreign_ctx),
        Err(ValidationError::ScriptVerification {
            tx_index: 1,
            input_index: 0,
            source: ScriptError::EvalFalse,
        }),
        "a signature bound to chain 3 must not spend on chain 1"
    );
}

#[test]
fn a_signature_made_for_the_wrong_chain_never_validates_anywhere() {
    // The mirror image: sign for mainnet, then try to spend on devnet.
    let devnet_params = devnet();
    let (pre, block) = replay_fixture(&devnet_params, ChainId::MAINNET);
    let (_, _, ctx) = scene(&devnet_params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::ScriptVerification {
            tx_index: 1,
            input_index: 0,
            source: ScriptError::EvalFalse,
        })
    );
}

// ------------------------------------- SPEC §4.4 relative locktime (BIP-68)
//
// `OP_CHECKSEQUENCEVERIFY` compares the script's operand against the input's
// own `sequence`, which the *spender* writes. That is only half of a timelock.
// The other half — the one that makes it a lock on time rather than a lock on
// the spender's honesty — is the rule below: the coin must actually be old
// enough for the `sequence` it is spent with.

/// A pre-state holding one ordinary coin created at `coin_height`.
fn aged_coin(coin_height: u64) -> (OutPoint, ferrum_storage::MapView) {
    let funded = OutPoint::new(Txid(Hash32::from_bytes([41; 32])), 0);
    (funded, map_view(&[(funded, coin(amount(1_000), coin_height, false))]))
}

/// A block at `height` whose only non-coinbase input spends `funded` with
/// `sequence`, paying a 100-grain fee.
fn block_spending_with_sequence(
    params: &ChainParams,
    prev: BlockHash,
    height: u64,
    funded: OutPoint,
    sequence: u32,
    script_pubkey: Script,
) -> Block {
    let mut tx = spend(&[funded], &[(amount(900), script_pubkey)]);
    tx.inputs[0].sequence = sequence;
    let reward = params.block_subsidy(height).checked_add(amount(100)).unwrap();
    block_of(vec![coinbase(height, reward, b"n"), tx], prev, BLOCK_MS, params.genesis_bits)
}

#[test]
fn a_relative_locktime_of_ten_blocks_is_not_satisfied_by_a_one_block_old_coin() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    let (funded, pre) = aged_coin(0);
    let block =
        block_spending_with_sequence(&params, prev, 1, funded, 10, any_spend_script());
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::UnsatisfiedRelativeLock {
            tx_index: 1,
            input_index: 0,
            sequence: 10,
            required: 10,
            coin_height: 0,
            spend_height: 1,
        }),
        "a coin one block old cannot satisfy a ten-block relative lock"
    );
}

#[test]
fn a_relative_locktime_is_satisfied_once_the_coin_is_old_enough() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(10, &parent, MTP_S, &params);
    let (funded, pre) = aged_coin(0);
    let block =
        block_spending_with_sequence(&params, prev, 10, funded, 10, any_spend_script());
    assert!(
        apply_block(&pre, &block, &ctx).is_ok(),
        "height 10 is exactly ten blocks after the coin's height 0"
    );
}

#[test]
fn a_relative_locktime_one_block_short_is_still_rejected() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(9, &parent, MTP_S, &params);
    let (funded, pre) = aged_coin(0);
    let block = block_spending_with_sequence(&params, prev, 9, funded, 10, any_spend_script());
    assert!(
        matches!(
            apply_block(&pre, &block, &ctx),
            Err(ValidationError::UnsatisfiedRelativeLock { spend_height: 9, .. })
        ),
        "the boundary is >=, and nine blocks is one short of ten"
    );
}

#[test]
fn a_sequence_with_the_disable_bit_set_is_not_a_relative_lock() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    let (funded, pre) = aged_coin(0);
    // The wallet's own choice: one below SEQUENCE_FINAL keeps `lock_time`
    // live while bit 31 opts the input out of BIP-68 entirely.
    let block =
        block_spending_with_sequence(&params, prev, 1, funded, 0xffff_fffe, any_spend_script());
    assert!(apply_block(&pre, &block, &ctx).is_ok(), "bit 31 disables the relative lock");
}

#[test]
fn a_zero_relative_locktime_locks_nothing() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    let (funded, pre) = aged_coin(0);
    let block = block_spending_with_sequence(&params, prev, 1, funded, 0, any_spend_script());
    assert!(apply_block(&pre, &block, &ctx).is_ok(), "a lock of zero blocks is no lock");
}

#[test]
fn the_five_hundred_and_twelve_second_flavour_fails_closed() {
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    let (funded, pre) = aged_coin(0);
    // Bit 22 set: the low bits count 512-second units, which needs the median
    // time past of the block that created the coin. The seam cannot see it.
    let sequence = 1 << 22 | 1;
    let block = block_spending_with_sequence(&params, prev, 1, funded, sequence, any_spend_script());
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::UnsupportedRelativeTimeLock {
            tx_index: 1,
            input_index: 0,
            sequence,
        }),
        "an unenforceable timelock must fail closed, not silently pass"
    );
}

#[test]
fn a_checksequenceverify_output_cannot_be_spent_early() {
    // The end-to-end shape from the finding: a coin locked with
    // `<10> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1`, spent one block later with
    // `sequence = 10`. The script half is satisfied — the operand equals the
    // sequence the spender wrote — so only the chain half can reject it.
    let params = devnet();
    let (parent, prev, _) = scene(&params);
    let ctx = ctx_at(1, &parent, MTP_S, &params);
    // OP_10 (0x5a), OP_CHECKSEQUENCEVERIFY (0xb2), OP_DROP (0x75), OP_1 (0x51)
    let csv_lock = Script::new(vec![0x5a, 0xb2, 0x75, 0x51]);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([42; 32])), 0);
    let pre = map_view(&[(
        funded,
        Coin { value: amount(1_000), script_pubkey: csv_lock, height: 0, is_coinbase: false },
    )]);
    let block = block_spending_with_sequence(&params, prev, 1, funded, 10, any_spend_script());
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::UnsatisfiedRelativeLock {
            tx_index: 1,
            input_index: 0,
            sequence: 10,
            required: 10,
            coin_height: 0,
            spend_height: 1,
        }),
        "OP_CHECKSEQUENCEVERIFY is only a timelock if the chain checks the coin's age"
    );
}

// ----------------------------- SPEC §3.3 rule 15, and the coinbase's outputs
//
// Rule 15 is "no created output already exists **in the UTXO set**", and SPEC
// §3.3 puts it last — after the coinbase's value and BIP-34 rules. Both halves
// matter: "in the UTXO set" means the parent's state, not the overlay this
// block has already been spending from, and "last" is what decides which rule
// a block breaking two of them is rejected for.

#[test]
fn a_non_coinbase_collision_is_reported_after_the_coinbase_value_rule() {
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([25; 32])), 0);
    let tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let collision = out_point(&tx, 0);
    let pre = map_view(&[
        (funded, coin(amount(1_000), 0, false)),
        (collision, coin(amount(3), 0, false)),
    ]);
    // The coinbase claims one grain more than subsidy + fees, so rules 13 and
    // 15 are both broken. SPEC §3.3 numbers the value rule 13 and the
    // collision rule 15.
    let reward = params.block_subsidy(1).checked_add(amount(101)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), tx], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::CoinbaseOverpayment {
            claimed: reward,
            allowed: params.block_subsidy(1).checked_add(amount(100)).unwrap(),
        }),
        "rule 15 is checked last, after the coinbase's value"
    );
}

#[test]
fn spending_the_colliding_coin_in_the_same_block_does_not_hide_the_collision() {
    // The BIP-30 backstop is defence in depth on the inflation path, so it
    // must be read against the *parent's* UTXO set. Checked against the
    // block's own overlay it is defeated by spending the colliding coin
    // earlier in the same block, and `Store::connect_block` then inserts the
    // new coin and removes it again — destroying the block's own output.
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([61; 32])), 0);
    // `later` creates the outpoint; `earlier` spends the coin already sitting
    // at it, which is what makes the overlay forget it exists.
    let later = spend(&[funded], &[(amount(900), any_spend_script())]);
    let collision = out_point(&later, 0);
    let earlier = spend(&[collision], &[(amount(400), any_spend_script())]);
    let pre = map_view(&[
        (funded, coin(amount(1_000), 0, false)),
        (collision, coin(amount(500), 0, false)),
    ]);
    let reward = params.block_subsidy(1).checked_add(amount(200)).unwrap();
    let block = block_with(vec![coinbase(1, reward, b"n"), earlier, later], prev, &params);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::DuplicateOutPoint { out_point: collision }),
        "rule 15 reads the parent's UTXO set, not the post-spend overlay"
    );
}

/// A block at height 1 whose transaction 1 spends the block's own coinbase.
fn block_spending_its_own_coinbase(params: &ChainParams, prev: BlockHash) -> (OutPoint, Block) {
    let subsidy = params.block_subsidy(1);
    let cb = coinbase(1, subsidy, b"n");
    let own = out_point(&cb, 0);
    // No fee, so the coinbase's own value rule is satisfied either way and the
    // verdict is about rule 12 alone.
    let tx = spend(&[own], &[(subsidy, any_spend_script())]);
    (own, block_with(vec![cb, tx], prev, params))
}

#[test]
fn a_transaction_naming_this_block_s_own_coinbase_output_is_missing_input() {
    // SPEC §3.3 rule 12: the coinbase's outputs are *not* in the overlay its
    // own block is validated against — they join the UTXO set when the block
    // is connected. So the verdict is `MissingInput`, and specifically not
    // `ImmatureCoinbaseSpend`: the coin is not there to be immature.
    let params = devnet();
    let (_, prev, ctx) = scene(&params);
    let (own, block) = block_spending_its_own_coinbase(&params, prev);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 1, out_point: own })
    );
}

#[test]
fn the_verdict_on_a_same_block_coinbase_spend_does_not_depend_on_maturity() {
    // The half of rule 12 that is worth a test of its own. Under the other
    // reading — coinbase outputs published into the overlay — a maturity of 0
    // makes this block *valid*, and rule 13 would then bound the coinbase's
    // value using a fee paid by a transaction spending that very output.
    // Excluding them removes the circularity, so the answer is `MissingInput`
    // at every maturity.
    let params = devnet_with(|p| p.coinbase_maturity = 0);
    let (_, prev, ctx) = scene(&params);
    let (own, block) = block_spending_its_own_coinbase(&params, prev);
    assert_eq!(
        apply_block(&EmptyView, &block, &ctx),
        Err(ValidationError::MissingInput { tx_index: 1, out_point: own }),
        "rule 12 is independent of coinbase_maturity"
    );
}

// ------------------------------------ the block's signature-check budget
//
// `MAX_OPS` bounds one input, not one block, and `OP_CHECKMULTISIG` charges
// `1 + n` operations for up to `n` verifications. The expensive script lives in
// the `script_pubkey`, which is already in the UTXO set, so a spending input
// costs its author ~44 bytes and every node ~190 Schnorr verifications. The
// budget below is what restores proportionality between the two.

/// A `script_pubkey` demanding exactly `checks` signature checks against one
/// key, reusing a single pushed signature with `OP_DUP`.
fn many_checksig_script(pubkey: &[u8], checks: usize) -> Script {
    let push_key = encode_push(pubkey).expect("32 bytes is a direct push");
    let mut bytes = Vec::new();
    for _ in 1..checks {
        bytes.push(0x76); // OP_DUP — keep the signature for the next check
        bytes.extend_from_slice(&push_key);
        bytes.push(0xac); // OP_CHECKSIG
        bytes.push(0x69); // OP_VERIFY
    }
    bytes.extend_from_slice(&push_key);
    bytes.push(0xac); // the last check leaves the truthy element behind
    Script::new(bytes)
}

/// A block whose single spend demands `checks` signature verifications.
fn block_demanding_sig_checks(
    params: &ChainParams,
    prev: BlockHash,
    checks: usize,
) -> (ferrum_storage::MapView, Block) {
    let key = replay_key();
    let script_pubkey = many_checksig_script(key.public_key().as_bytes(), checks);
    let funded = OutPoint::new(Txid(Hash32::from_bytes([53; 32])), 0);
    let value = amount(1_000);
    let pre = map_view(&[(
        funded,
        Coin { value, script_pubkey: script_pubkey.clone(), height: 0, is_coinbase: false },
    )]);

    let mut tx = spend(&[funded], &[(amount(900), any_spend_script())]);
    let digest =
        signature_hash(&tx, 0, script_pubkey.as_bytes(), value, params.chain_id, SigHashType::ALL)
            .expect("a single-input SIGHASH_ALL preimage always builds");
    let signature = encode_signature(&key.sign_deterministic(&digest), SigHashType::ALL);
    tx.inputs[0].script_sig = Script::new(encode_push(&signature).expect("65 bytes pushes"));

    let reward = params.block_subsidy(1).checked_add(amount(100)).unwrap();
    (pre, block_with(vec![coinbase(1, reward, b"n"), tx], prev, params))
}

#[test]
fn the_budget_is_proportional_to_the_block_size_limit() {
    assert_eq!(max_block_sig_checks(&devnet()), 20_000, "one check per 50 bytes of a 1 MB block");
    assert_eq!(max_block_sig_checks(&devnet_with(|p| p.max_block_size = 1_000)), 20);
}

#[test]
fn a_block_over_the_signature_check_budget_is_rejected() {
    // A budget of 20, and 44 bytes of block space buying 21 verifications.
    let params = devnet_with(|p| p.max_block_size = 1_000);
    let (_, prev, ctx) = scene(&params);
    let (pre, block) = block_demanding_sig_checks(&params, prev, 21);
    assert_eq!(
        apply_block(&pre, &block, &ctx),
        Err(ValidationError::SigCheckBudgetExceeded { used: 21, budget: 20 })
    );
}

#[test]
fn a_block_exactly_at_the_signature_check_budget_is_accepted() {
    // The control: the budget is a limit, not an off-by-one that rejects
    // honest blocks. Every one of these twenty checks really verifies.
    let params = devnet_with(|p| p.max_block_size = 1_000);
    let (_, prev, ctx) = scene(&params);
    let (pre, block) = block_demanding_sig_checks(&params, prev, 20);
    assert!(apply_block(&pre, &block, &ctx).is_ok(), "twenty checks is the budget, not over it");
}
