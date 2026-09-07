//! SPEC §3.1 and §4.1: the context-free rules, plus BIP-34 and locktime.

use ferrum_crypto::{merkle_leaf, merkle_root};
use ferrum_script::MAX_SCRIPT_SIZE;
use ferrum_storage::txid;
use ferrum_types::{
    Amount, Block, BlockHash, BlockSeal, Hash32, LOCKTIME_THRESHOLD, OutPoint, Script, Transaction,
    TxIn, TxOut, Txid, ValidatorId,
};

use crate::error::ValidationError;
use crate::tests::support::{
    any_spend_script, block_of, coinbase, coinbase_with_script_sig, devnet, out_point, spend,
};
use crate::validate::{
    COINBASE_SCRIPT_SIG_MAX, COINBASE_SCRIPT_SIG_MIN, MEDIAN_TIME_SPAN, build_coinbase_script_sig,
    check_block_sanity, check_coinbase_script_sig, check_coinbase_structure,
    check_transaction_sanity, compute_merkle_root, height_push_data, is_final,
    leading_minimal_push, median_time_past,
};

use ferrum_types::BlockHeader;

fn amount(v: u64) -> Amount {
    Amount::from_grains(v)
}

fn header_at(timestamp_ms: u64) -> BlockHeader {
    BlockHeader { timestamp_ms, ..BlockHeader::default() }
}

// ------------------------------------------------------------ merkle root

#[test]
fn an_empty_transaction_list_has_a_zero_root() {
    assert_eq!(compute_merkle_root(&[]), Hash32::ZERO);
}

#[test]
fn a_single_transaction_root_is_its_tagged_leaf() {
    let tx = coinbase(0, amount(50), b"x");
    let expected = merkle_leaf(txid(&tx).as_bytes());
    assert_eq!(compute_merkle_root(std::slice::from_ref(&tx)), expected);
}

#[test]
fn the_root_uses_the_leaf_tag_not_the_raw_txid() {
    let tx = coinbase(0, amount(50), b"x");
    let raw = merkle_root(&[txid(&tx).0]);
    assert_ne!(
        compute_merkle_root(std::slice::from_ref(&tx)),
        raw,
        "leaves must be domain-separated or a txid could be passed off as an internal node"
    );
}

#[test]
fn changing_any_transaction_changes_the_root() {
    let a = vec![coinbase(1, amount(50), b"a"), spend(&[OutPoint::new(Txid::ZERO, 0)], &[])];
    let mut b = a.clone();
    b[0] = coinbase(1, amount(49), b"a");
    assert_ne!(compute_merkle_root(&a), compute_merkle_root(&b));
}

#[test]
fn a_promoted_odd_leaf_is_not_a_duplicated_one() {
    // CVE-2012-2459: duplicating the last leaf must not produce the same root.
    let txs: Vec<Transaction> =
        (0u64..3).map(|i| coinbase(i, amount(50), &i.to_le_bytes())).collect();
    let mut duplicated = txs.clone();
    duplicated.push(txs[2].clone());
    assert_ne!(compute_merkle_root(&txs), compute_merkle_root(&duplicated));
}

#[test]
fn the_root_depends_on_transaction_order() {
    let a = coinbase(1, amount(50), b"a");
    let b = coinbase(2, amount(50), b"b");
    assert_ne!(compute_merkle_root(&[a.clone(), b.clone()]), compute_merkle_root(&[b, a]));
}

// ------------------------------------------------------- median time past

#[test]
fn an_empty_window_has_a_zero_median() {
    assert_eq!(median_time_past(&[]), 0);
}

#[test]
fn a_single_header_is_its_own_median() {
    assert_eq!(median_time_past(&[header_at(7_000)]), 7);
}

#[test]
fn the_median_is_in_seconds_not_milliseconds() {
    let headers: Vec<BlockHeader> =
        (0..11).map(|i| header_at(1_700_000_000_000 + i * 1_000)).collect();
    assert_eq!(median_time_past(&headers), 1_700_000_005);
}

#[test]
fn the_median_ignores_the_order_it_is_given() {
    let ascending: Vec<BlockHeader> = (0..11).map(|i| header_at(i * 1_000)).collect();
    let mut shuffled = ascending.clone();
    shuffled.reverse();
    assert_eq!(median_time_past(&ascending), median_time_past(&shuffled));
    assert_eq!(median_time_past(&ascending), 5);
}

#[test]
fn only_the_last_eleven_headers_count() {
    // Twenty headers: the first nine are far in the past and must not move the
    // median, because the window ends at the newest header.
    let mut headers: Vec<BlockHeader> = (0..9).map(|_| header_at(0)).collect();
    headers.extend((0..11).map(|i| header_at(1_000_000 + i * 1_000)));
    assert_eq!(median_time_past(&headers), 1_005);
    assert_eq!(MEDIAN_TIME_SPAN, 11);
}

#[test]
fn a_partial_window_still_has_a_median() {
    let headers: Vec<BlockHeader> = (0..4).map(|i| header_at(i * 1_000)).collect();
    // Upper median of an even window.
    assert_eq!(median_time_past(&headers), 2);
}

#[test]
fn one_wildly_future_timestamp_cannot_move_the_median_far() {
    let mut headers: Vec<BlockHeader> = (0..10).map(|i| header_at(i * 1_000)).collect();
    let honest = median_time_past(&headers);
    headers.push(header_at(u64::MAX));
    assert!(median_time_past(&headers) <= honest + 1, "one liar moves the median by one slot");
}

// ------------------------------------------------- transaction sanity §4.1

#[test]
fn a_transaction_with_no_inputs_is_rejected() {
    let tx = Transaction {
        version: 1,
        inputs: Vec::new(),
        outputs: vec![TxOut::new(amount(1), any_spend_script())],
        lock_time: 0,
    };
    assert_eq!(check_transaction_sanity(&tx, &devnet()), Err(ValidationError::NoInputs));
}

#[test]
fn a_transaction_with_no_outputs_is_rejected() {
    let tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[]);
    assert_eq!(check_transaction_sanity(&tx, &devnet()), Err(ValidationError::NoOutputs));
}

#[test]
fn an_output_above_max_money_is_rejected() {
    let bad = Amount::from_grains(Amount::MAX_MONEY.to_grains() + 1);
    let tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(bad, any_spend_script())]);
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::OutputValueOutOfRange { value: bad })
    );
}

#[test]
fn an_output_sum_above_max_money_is_rejected() {
    let tx = spend(
        &[OutPoint::new(Txid::ZERO, 0)],
        &[(Amount::MAX_MONEY, any_spend_script()), (Amount::MAX_MONEY, any_spend_script())],
    );
    assert_eq!(check_transaction_sanity(&tx, &devnet()), Err(ValidationError::OutputSumOverflow));
}

#[test]
fn an_output_sum_that_overflows_u64_is_rejected() {
    // MAX_MONEY is 2.1e15 grains, so it takes 8785 of them to pass u64::MAX.
    // Each one is individually valid money, which is exactly why the *sum*
    // needs its own check.
    let count = (u64::MAX / Amount::MAX_MONEY.to_grains()) + 1;
    let outputs: Vec<(Amount, Script)> =
        (0..count).map(|_| (Amount::MAX_MONEY, any_spend_script())).collect();
    let tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &outputs);
    assert_eq!(check_transaction_sanity(&tx, &devnet()), Err(ValidationError::OutputSumOverflow));
}

#[test]
fn two_inputs_spending_the_same_outpoint_are_rejected() {
    let op = OutPoint::new(Txid(Hash32::from_bytes([7; 32])), 3);
    let tx = spend(&[op, op], &[(amount(1), any_spend_script())]);
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::DuplicateInput { out_point: op })
    );
}

#[test]
fn an_oversized_script_sig_is_rejected() {
    let mut tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]);
    tx.inputs[0].script_sig = Script::new(vec![0x00; MAX_SCRIPT_SIZE + 1]);
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::ScriptTooLarge { len: MAX_SCRIPT_SIZE + 1, max: MAX_SCRIPT_SIZE })
    );
}

#[test]
fn an_oversized_script_pubkey_is_rejected() {
    let big = Script::new(vec![0x00; MAX_SCRIPT_SIZE + 1]);
    let tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), big)]);
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::ScriptTooLarge { len: MAX_SCRIPT_SIZE + 1, max: MAX_SCRIPT_SIZE })
    );
}

#[test]
fn a_null_outpoint_in_a_non_coinbase_is_rejected() {
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TxIn::new(OutPoint::new(Txid(Hash32::from_bytes([1; 32])), 0), Script::EMPTY),
            TxIn::new(OutPoint::NULL, Script::EMPTY),
        ],
        outputs: vec![TxOut::new(amount(1), any_spend_script())],
        lock_time: 0,
    };
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::NullInput { input_index: 1 })
    );
}

#[test]
fn an_ordinary_transaction_passes_sanity() {
    let tx = spend(
        &[OutPoint::new(Txid(Hash32::from_bytes([2; 32])), 1)],
        &[(amount(10), any_spend_script())],
    );
    assert_eq!(check_transaction_sanity(&tx, &devnet()), Ok(()));
}

#[test]
fn a_coinbase_passes_sanity() {
    assert_eq!(check_transaction_sanity(&coinbase(4, amount(50), b"z"), &devnet()), Ok(()));
}

#[test]
fn a_coinbase_with_two_inputs_is_rejected() {
    let mut tx = coinbase(1, amount(50), b"z");
    tx.inputs.push(TxIn::new(OutPoint::NULL, Script::EMPTY));
    assert_eq!(
        check_coinbase_structure(&tx),
        Err(ValidationError::CoinbaseInputCount { count: 2 })
    );
}

#[test]
fn a_coinbase_whose_input_is_not_null_is_rejected() {
    let mut tx = coinbase(1, amount(50), b"z");
    tx.inputs[0].prev_out = OutPoint::new(Txid(Hash32::from_bytes([3; 32])), 0);
    assert_eq!(check_coinbase_structure(&tx), Err(ValidationError::CoinbaseInputNotNull));
}

#[test]
fn a_coinbase_with_no_inputs_is_rejected() {
    let mut tx = coinbase(1, amount(50), b"z");
    tx.inputs.clear();
    assert_eq!(
        check_coinbase_structure(&tx),
        Err(ValidationError::CoinbaseInputCount { count: 0 })
    );
}

// --------------------------------------------------------- block sanity §3.1

fn simple_block(txs: Vec<Transaction>) -> Block {
    block_of(txs, BlockHash::ZERO, 1_000, devnet().genesis_bits)
}

#[test]
fn an_ordinary_block_passes_sanity() {
    let block = simple_block(vec![coinbase(0, amount(50), b"g")]);
    assert_eq!(check_block_sanity(&block, &devnet()), Ok(()));
}

#[test]
fn a_block_over_the_size_limit_is_rejected() {
    let mut params = devnet();
    let block = simple_block(vec![coinbase(0, amount(50), b"g")]);
    // Rule 1 measures the block without its seal (DECISIONS D12), so the limit
    // that must reject this block is one byte under *that*.
    params.max_block_size = block.consensus_size() - 1;
    assert_eq!(
        check_block_sanity(&block, &params),
        Err(ValidationError::BlockTooLarge {
            size: block.consensus_size(),
            max: params.max_block_size,
        })
    );

    // Exactly at the limit is legal: the rule is `<=`.
    params.max_block_size = block.consensus_size();
    assert_eq!(check_block_sanity(&block, &params), Ok(()));
}

#[test]
fn the_size_rule_does_not_move_when_the_certificate_does() {
    // n = 7, quorum = 5: `verify_commit` accepts 5, 6 or 7 signatures over the
    // same block hash, and the seal is not committed to by the header. If rule 1
    // measured it, a relay could re-encode a block that node A accepted with two
    // more valid signatures and node B would reject the same block hash as too
    // large. Both copies must get the same verdict.
    let mut params = devnet();
    params.bft_validators = (0..7).map(|i| ValidatorId::from_bytes([i as u8; 32])).collect();

    let txs = vec![coinbase(0, amount(50), b"g")];
    let quorum_seal = BlockSeal::bft(vec![0u8; BlockSeal::BFT_COMMIT_FIXED + 5 * 66]);
    let full_seal = BlockSeal::bft(vec![0u8; BlockSeal::BFT_COMMIT_FIXED + 7 * 66]);
    let lean = Block::new(simple_block(txs.clone()).header, txs.clone(), quorum_seal);
    let fat = Block::new(lean.header, txs, full_seal);

    // A limit that the smaller copy exactly meets.
    params.max_block_size = lean.consensus_size();
    assert!(fat.serialized_size() > params.max_block_size, "the fat copy really is bigger on the wire");
    assert_eq!(check_block_sanity(&lean, &params), Ok(()));
    assert_eq!(
        check_block_sanity(&fat, &params),
        Ok(()),
        "one block hash, one verdict: the seal is not part of the size rule"
    );
}

#[test]
fn a_seal_longer_than_the_validator_set_allows_is_rejected() {
    // The seal is bounded on its own, so dropping it out of rule 1 does not
    // leave it unbounded: the largest legal certificate is 2f+1..=n signatures,
    // i.e. `48 + 66n` bytes.
    let mut params = devnet();
    params.bft_validators = (0..4).map(|i| ValidatorId::from_bytes([i as u8; 32])).collect();
    let max = BlockSeal::max_data_len(4);

    let txs = vec![coinbase(0, amount(50), b"g")];
    let header = simple_block(txs.clone()).header;
    let at_limit = Block::new(header, txs.clone(), BlockSeal::bft(vec![0u8; max]));
    assert_eq!(check_block_sanity(&at_limit, &params), Ok(()));

    let over = Block::new(header, txs, BlockSeal::bft(vec![0u8; max + 1]));
    assert_eq!(
        check_block_sanity(&over, &params),
        Err(ValidationError::SealTooLarge { size: max + 1, max })
    );
}

#[test]
fn an_empty_block_is_rejected() {
    let block = Block::new(simple_block(vec![]).header, Vec::new(), BlockSeal::POW);
    assert_eq!(check_block_sanity(&block, &devnet()), Err(ValidationError::EmptyBlock));
}

#[test]
fn a_block_whose_first_transaction_is_not_a_coinbase_is_rejected() {
    let tx = spend(
        &[OutPoint::new(Txid(Hash32::from_bytes([4; 32])), 0)],
        &[(amount(1), any_spend_script())],
    );
    let block = simple_block(vec![tx]);
    assert_eq!(check_block_sanity(&block, &devnet()), Err(ValidationError::MissingCoinbase));
}

#[test]
fn a_second_coinbase_is_rejected() {
    let block = simple_block(vec![coinbase(0, amount(50), b"a"), coinbase(0, amount(50), b"b")]);
    assert_eq!(
        check_block_sanity(&block, &devnet()),
        Err(ValidationError::MultipleCoinbases { tx_index: 1 })
    );
}

#[test]
fn a_merkle_root_mismatch_is_rejected() {
    let mut block = simple_block(vec![coinbase(0, amount(50), b"g")]);
    let real = block.header.merkle_root;
    block.header.merkle_root = Hash32::from_bytes([9; 32]);
    assert_eq!(
        check_block_sanity(&block, &devnet()),
        Err(ValidationError::MerkleRootMismatch {
            expected: real,
            actual: Hash32::from_bytes([9; 32]),
        })
    );
}

#[test]
fn a_duplicate_txid_within_a_block_is_rejected() {
    let tx = spend(
        &[OutPoint::new(Txid(Hash32::from_bytes([5; 32])), 0)],
        &[(amount(1), any_spend_script())],
    );
    let block = simple_block(vec![coinbase(0, amount(50), b"g"), tx.clone(), tx.clone()]);
    assert_eq!(
        check_block_sanity(&block, &devnet()),
        Err(ValidationError::DuplicateTransaction { txid: txid(&tx) })
    );
}

#[test]
fn a_block_carrying_an_insane_transaction_is_rejected() {
    let bad = spend(&[OutPoint::new(Txid::ZERO, 0)], &[]);
    let block = simple_block(vec![coinbase(0, amount(50), b"g"), bad]);
    assert_eq!(check_block_sanity(&block, &devnet()), Err(ValidationError::NoOutputs));
}

#[test]
fn size_is_checked_before_the_merkle_root() {
    // A block that breaks both rules must report the cheaper one, or a peer can
    // make us hash a megabyte before we notice it is too big.
    let mut params = devnet();
    let mut block = simple_block(vec![coinbase(0, amount(50), b"g")]);
    block.header.merkle_root = Hash32::ZERO;
    params.max_block_size = 1;
    assert!(matches!(
        check_block_sanity(&block, &params),
        Err(ValidationError::BlockTooLarge { .. })
    ));
}

// ------------------------------------------------------------ finality §4.3

#[test]
fn a_zero_locktime_transaction_is_always_final() {
    let mut tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]);
    tx.lock_time = 0;
    tx.inputs[0].sequence = 0;
    assert!(is_final(&tx, 0, 0));
}

#[test]
fn a_maximal_sequence_makes_any_locktime_final() {
    let mut tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]);
    tx.lock_time = 999_999;
    tx.inputs[0].sequence = u32::MAX;
    assert!(is_final(&tx, 0, 0));
}

#[test]
fn a_height_locktime_is_not_final_before_its_height() {
    let mut tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]);
    tx.lock_time = 500;
    tx.inputs[0].sequence = 0;
    assert!(!is_final(&tx, 499, 0));
    assert!(is_final(&tx, 500, 0), "the lock expires at, not after, its height");
    assert!(is_final(&tx, 501, 0));
}

#[test]
fn a_timestamp_locktime_is_compared_against_median_time_past() {
    let mut tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]);
    tx.lock_time = LOCKTIME_THRESHOLD + 1_000;
    tx.inputs[0].sequence = 0;
    let lock = u64::from(tx.lock_time);
    assert!(!is_final(&tx, u64::MAX, lock - 1), "height must not satisfy a time lock");
    assert!(is_final(&tx, 0, lock));
}

#[test]
fn the_locktime_threshold_selects_the_comparison() {
    let mut tx = spend(&[OutPoint::new(Txid::ZERO, 0)], &[(amount(1), any_spend_script())]);
    tx.inputs[0].sequence = 0;
    tx.lock_time = LOCKTIME_THRESHOLD - 1;
    assert!(is_final(&tx, u64::from(LOCKTIME_THRESHOLD), 0), "just below: a height lock");
    tx.lock_time = LOCKTIME_THRESHOLD;
    assert!(!is_final(&tx, u64::from(LOCKTIME_THRESHOLD), 0), "at the threshold: a time lock");
}

// -------------------------------------------------------------- BIP-34 §3.3

#[test]
fn height_zero_pushes_the_empty_string() {
    assert_eq!(height_push_data(0), Vec::<u8>::new());
}

#[test]
fn small_heights_use_the_single_byte_forms() {
    assert_eq!(height_push_data(1), vec![0x01]);
    assert_eq!(height_push_data(16), vec![0x10]);
    assert_eq!(height_push_data(17), vec![0x11]);
    assert_eq!(height_push_data(127), vec![0x7f]);
}

#[test]
fn a_height_with_the_sign_bit_set_grows_a_zero_byte() {
    // 128 is 0x80, whose top bit is the sign bit, so ScriptNum appends 0x00.
    assert_eq!(height_push_data(128), vec![0x80, 0x00]);
    assert_eq!(height_push_data(255), vec![0xff, 0x00]);
    assert_eq!(height_push_data(256), vec![0x00, 0x01]);
}

#[test]
fn the_leading_push_reads_every_minimal_form() {
    assert_eq!(leading_minimal_push(&Script::new(vec![0x00])), Some(Vec::new()));
    assert_eq!(leading_minimal_push(&Script::new(vec![0x51])), Some(vec![0x01]));
    assert_eq!(leading_minimal_push(&Script::new(vec![0x60])), Some(vec![0x10]));
    assert_eq!(leading_minimal_push(&Script::new(vec![0x4f])), Some(vec![0x81]));
    assert_eq!(leading_minimal_push(&Script::new(vec![0x02, 0xaa, 0xbb])), Some(vec![0xaa, 0xbb]));

    let mut pushdata1 = vec![0x4c, 100];
    pushdata1.extend(std::iter::repeat_n(7u8, 100));
    assert_eq!(leading_minimal_push(&Script::new(pushdata1)), Some(vec![7u8; 100]));

    let mut pushdata2 = vec![0x4d, 0x2c, 0x01];
    pushdata2.extend(std::iter::repeat_n(8u8, 300));
    assert_eq!(leading_minimal_push(&Script::new(pushdata2)), Some(vec![8u8; 300]));
}

#[test]
fn the_leading_push_rejects_a_non_minimal_encoding() {
    // Pushing 0x01 with a direct one-byte push instead of OP_1.
    assert_eq!(leading_minimal_push(&Script::new(vec![0x01, 0x01])), None);
    // Pushing two bytes with OP_PUSHDATA1 instead of a direct push.
    assert_eq!(leading_minimal_push(&Script::new(vec![0x4c, 0x02, 0xaa, 0xbb])), None);
}

#[test]
fn the_leading_push_rejects_a_truncated_push() {
    assert_eq!(leading_minimal_push(&Script::new(vec![0x05, 0x01, 0x02])), None);
    assert_eq!(leading_minimal_push(&Script::new(vec![0x4c])), None);
    assert_eq!(leading_minimal_push(&Script::new(vec![0x4d, 0x10])), None);
}

#[test]
fn the_leading_push_rejects_a_non_push_opcode_and_an_empty_script() {
    assert_eq!(leading_minimal_push(&Script::new(vec![0x76])), None, "OP_DUP is not a push");
    assert_eq!(leading_minimal_push(&Script::EMPTY), None);
}

#[test]
fn a_short_coinbase_script_sig_is_rejected() {
    let sig = Script::new(vec![0x00]);
    assert_eq!(
        check_coinbase_script_sig(&sig, 0),
        Err(ValidationError::CoinbaseScriptSigLength {
            len: 1,
            min: COINBASE_SCRIPT_SIG_MIN,
            max: COINBASE_SCRIPT_SIG_MAX,
        })
    );
}

#[test]
fn a_long_coinbase_script_sig_is_rejected() {
    let sig = Script::new(vec![0x00; COINBASE_SCRIPT_SIG_MAX + 1]);
    assert!(matches!(
        check_coinbase_script_sig(&sig, 0),
        Err(ValidationError::CoinbaseScriptSigLength { .. })
    ));
}

#[test]
fn a_coinbase_without_a_height_push_is_rejected() {
    // OP_DUP OP_DUP: no leading push at all. This is the BIP-30 / CVE-2012-1909
    // fix, and without it two blocks can share a coinbase txid.
    let sig = Script::new(vec![0x76, 0x76]);
    assert_eq!(check_coinbase_script_sig(&sig, 3), Err(ValidationError::CoinbaseMissingHeightPush));
}

#[test]
fn a_coinbase_committing_to_the_wrong_height_is_rejected() {
    let sig = build_coinbase_script_sig(4, b"nonce").unwrap();
    assert_eq!(
        check_coinbase_script_sig(&sig, 5),
        Err(ValidationError::CoinbaseHeightMismatch { expected: 5, found: vec![0x04] })
    );
}

#[test]
fn a_coinbase_committing_to_the_right_height_is_accepted() {
    for height in [0u64, 1, 15, 16, 17, 128, 1_000, 210_000, u32::MAX as u64 + 1] {
        let sig = build_coinbase_script_sig(height, b"extra").unwrap();
        assert_eq!(check_coinbase_script_sig(&sig, height), Ok(()), "height {height}");
    }
}

#[test]
fn a_non_minimally_pushed_height_is_rejected() {
    // Height 1 pushed as a direct one-byte push rather than as OP_1: the data
    // is right, the encoding is not, and allowing both would let a miner grind
    // coinbase txids.
    let sig = Script::new(vec![0x01, 0x01, 0x51]);
    assert_eq!(check_coinbase_script_sig(&sig, 1), Err(ValidationError::CoinbaseMissingHeightPush));
}

#[test]
fn building_a_coinbase_script_sig_rejects_an_oversized_extra() {
    let big = vec![0u8; COINBASE_SCRIPT_SIG_MAX];
    assert!(matches!(
        build_coinbase_script_sig(1, &big),
        Err(ValidationError::CoinbaseScriptSigLength { .. })
    ));
}

#[test]
fn a_built_script_sig_always_validates_against_its_own_height() {
    for height in 0u64..300 {
        let sig = build_coinbase_script_sig(height, &height.to_le_bytes()).unwrap();
        assert!(sig.len() >= COINBASE_SCRIPT_SIG_MIN);
        assert!(sig.len() <= COINBASE_SCRIPT_SIG_MAX);
        assert_eq!(check_coinbase_script_sig(&sig, height), Ok(()));
    }
}

#[test]
fn two_heights_never_share_a_coinbase_script_sig() {
    let a = build_coinbase_script_sig(10, b"").unwrap();
    let b = build_coinbase_script_sig(11, b"").unwrap();
    assert_ne!(a, b, "the height push is what makes coinbase txids unique");
}

#[test]
fn a_coinbase_at_a_height_is_a_different_transaction_at_every_height() {
    let a = txid(&coinbase(1, amount(50), b""));
    let b = txid(&coinbase(2, amount(50), b""));
    assert_ne!(a, b);
}

#[test]
fn a_coinbase_built_by_hand_can_be_pointed_at() {
    let cb = coinbase_with_script_sig(Script::new(vec![0x00, 0x01]), amount(5));
    assert!(cb.is_coinbase());
    assert_eq!(out_point(&cb, 0), OutPoint::new(txid(&cb), 0));
}

// ------------------------------------------ SPEC §4.1: the order of the rules
//
// SPEC §4.1 lists the bullets as: non-empty; output values; output sum;
// **no duplicate OutPoint**; **script sizes**; then the coinbase shape and the
// non-coinbase null-input rule. The reference executor implements exactly
// that. A transaction that breaks the null rule *and* one of the two before it
// is the only way that order is observable, and SPEC §3.4 makes the variant
// the contract.

#[test]
fn two_null_inputs_are_a_duplicate_before_they_are_a_null_input() {
    // Two null outpoints, so `is_coinbase()` is false (it needs exactly one
    // input) and both the duplicate rule and the null rule apply.
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn::new(OutPoint::NULL, Script::EMPTY), TxIn::new(OutPoint::NULL, Script::EMPTY)],
        outputs: vec![TxOut::new(amount(1), any_spend_script())],
        lock_time: 0,
    };
    assert!(!tx.is_coinbase(), "two inputs is not a coinbase shape");
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::DuplicateInput { out_point: OutPoint::NULL }),
        "SPEC §4.1 checks duplicate outpoints before the null-input rule"
    );
}

#[test]
fn an_oversized_script_sig_is_reported_before_a_null_input() {
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TxIn::new(OutPoint::NULL, Script::EMPTY),
            TxIn::new(
                OutPoint::new(Txid(Hash32::from_bytes([9; 32])), 0),
                Script::new(vec![0x00; MAX_SCRIPT_SIZE + 1]),
            ),
        ],
        outputs: vec![TxOut::new(amount(1), any_spend_script())],
        lock_time: 0,
    };
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::ScriptTooLarge { len: MAX_SCRIPT_SIZE + 1, max: MAX_SCRIPT_SIZE }),
        "SPEC §4.1 checks script sizes before the null-input rule"
    );
}

#[test]
fn an_oversized_script_pubkey_is_reported_before_a_null_input() {
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TxIn::new(OutPoint::new(Txid(Hash32::from_bytes([9; 32])), 0), Script::EMPTY),
            TxIn::new(OutPoint::NULL, Script::EMPTY),
        ],
        outputs: vec![TxOut::new(amount(1), Script::new(vec![0x00; MAX_SCRIPT_SIZE + 1]))],
        lock_time: 0,
    };
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::ScriptTooLarge { len: MAX_SCRIPT_SIZE + 1, max: MAX_SCRIPT_SIZE }),
        "every script size is read before the null-input rule"
    );
}

#[test]
fn the_null_input_rule_still_names_the_offending_index() {
    // The order moved; the verdict for a transaction that breaks *only* the
    // null rule did not.
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TxIn::new(OutPoint::new(Txid(Hash32::from_bytes([1; 32])), 0), Script::EMPTY),
            TxIn::new(OutPoint::NULL, Script::EMPTY),
        ],
        outputs: vec![TxOut::new(amount(1), any_spend_script())],
        lock_time: 0,
    };
    assert_eq!(
        check_transaction_sanity(&tx, &devnet()),
        Err(ValidationError::NullInput { input_index: 1 })
    );
}
