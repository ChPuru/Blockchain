//! The frozen consensus parameters of each network.
//!
//! Everything a validator needs in order to disagree with another validator
//! lives in [`ChainParams`]. Three networks are defined: `mainnet`, `testnet`
//! and `devnet`. They differ only in identity (chain id, address prefix) and in
//! how hard it is to mine a block; every monetary and structural rule is
//! shared, so a devnet run exercises exactly the code paths mainnet does.

use serde::{Serialize, Serializer};

use crate::amount::{Amount, COIN};
use crate::block::{BlockSeal, CompactTarget};
use crate::error::TypeError;
use crate::hash::HASH_LEN;
use crate::network::{ChainId, Network, ValidatorId};

/// Mainnet proof-of-work limit: `0x00000000ffff0000...`, the easiest target a
/// block may have. The same shape as Bitcoin's, i.e. compact `0x1d00ffff`.
const POW_LIMIT_MAINNET: [u8; HASH_LEN] = {
    let mut l = [0u8; HASH_LEN];
    l[4] = 0xff;
    l[5] = 0xff;
    l
};

/// Devnet proof-of-work limit: `0x7fffffff...`, i.e. compact `0x207fffff`.
/// Almost every header hash satisfies it, so tests mine instantly.
const POW_LIMIT_DEVNET: [u8; HASH_LEN] = {
    let mut l = [0xffu8; HASH_LEN];
    l[0] = 0x7f;
    l
};

/// Compact form of [`POW_LIMIT_MAINNET`].
const BITS_MAINNET: CompactTarget = CompactTarget(0x1d00_ffff);

/// Compact form of [`POW_LIMIT_DEVNET`].
const BITS_DEVNET: CompactTarget = CompactTarget(0x207f_ffff);

/// Genesis timestamp shared by all three networks: 2025-01-01T00:00:00Z, in
/// milliseconds.
const GENESIS_TIMESTAMP_MS: u64 = 1_735_689_600_000;

/// Serialize a 32-byte array as a hex string, so a dumped parameter set is
/// readable instead of an array of 32 integers.
fn serialize_hex32<S: Serializer>(v: &[u8; HASH_LEN], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

/// The frozen consensus parameters of one network.
///
/// Serialisable so a node can dump exactly what it is validating against.
/// `Deserialize` is deliberately *not* derived: `bech32_hrp` is a
/// `&'static str`, and a parameter set should be selected by name through
/// [`ChainParams::by_name`] rather than reconstructed field by field from an
/// untrusted file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChainParams {
    /// Which network these parameters describe.
    pub network: Network,
    /// The chain id bound into every signature.
    pub chain_id: ChainId,
    /// bech32m human-readable prefix for addresses.
    pub bech32_hrp: &'static str,
    /// Target time between blocks, in milliseconds.
    pub target_spacing_ms: u64,
    /// ASERT half-life, in seconds.
    pub asert_halflife_s: i64,
    /// Easiest permitted target, big-endian.
    #[serde(serialize_with = "serialize_hex32")]
    pub pow_limit: [u8; HASH_LEN],
    /// Block subsidy before the first halving.
    pub initial_subsidy: Amount,
    /// Blocks between subsidy halvings.
    pub halving_interval: u64,
    /// Blocks a coinbase output must age before it can be spent.
    pub coinbase_maturity: u64,
    /// Maximum serialized block size, in bytes.
    pub max_block_size: usize,
    /// How far ahead of local time a block may be timestamped.
    pub max_future_block_time_ms: u64,
    /// Number of headers in the median-time-past window.
    pub median_time_span: usize,
    /// Minimum relay fee, in grains per 1000 bytes.
    pub min_relay_fee_per_kb: Amount,
    /// Genesis block timestamp, Unix milliseconds.
    pub genesis_timestamp_ms: u64,
    /// Genesis block compact target.
    pub genesis_bits: CompactTarget,
    /// Genesis block nonce.
    pub genesis_nonce: u64,
    /// Height at which the BFT engine takes over; `None` while the chain is
    /// proof-of-work only.
    pub bft_activation_height: Option<u64>,
    /// The permissioned BFT validator set; empty on a PoW-only network.
    pub bft_validators: Vec<ValidatorId>,
}

impl ChainParams {
    /// Parameters shared by every network. Only identity and difficulty differ
    /// between the three, so the shared values live in exactly one place: a
    /// devnet test that passes is evidence about mainnet.
    fn common(network: Network, pow_limit: [u8; HASH_LEN], genesis_bits: CompactTarget) -> Self {
        ChainParams {
            network,
            chain_id: network.chain_id(),
            bech32_hrp: network.bech32_hrp(),
            target_spacing_ms: 120_000,
            asert_halflife_s: 7_200,
            pow_limit,
            initial_subsidy: Amount::from_grains(50 * COIN),
            halving_interval: 210_000,
            coinbase_maturity: 100,
            max_block_size: 1_000_000,
            max_future_block_time_ms: 7_200_000,
            median_time_span: 11,
            min_relay_fee_per_kb: Amount::from_grains(1_000),
            genesis_timestamp_ms: GENESIS_TIMESTAMP_MS,
            genesis_bits,
            // Ground by `chain-cli genesis mine` when a network is launched;
            // on devnet almost any nonce satisfies the limit, including zero.
            genesis_nonce: 0,
            bft_activation_height: None,
            bft_validators: Vec::new(),
        }
    }

    /// Mainnet parameters.
    pub fn mainnet() -> Self {
        Self::common(Network::Mainnet, POW_LIMIT_MAINNET, BITS_MAINNET)
    }

    /// Testnet parameters: mainnet difficulty, a different chain id and prefix.
    pub fn testnet() -> Self {
        Self::common(Network::Testnet, POW_LIMIT_MAINNET, BITS_MAINNET)
    }

    /// Devnet parameters: a trivial proof-of-work limit, so a test can mine a
    /// block in microseconds.
    pub fn devnet() -> Self {
        Self::common(Network::Devnet, POW_LIMIT_DEVNET, BITS_DEVNET)
    }

    /// Look up a parameter set by network name; see `Network::from_str` for
    /// the accepted spellings.
    pub fn by_name(s: &str) -> Result<Self, TypeError> {
        Ok(s.parse::<Network>()?.params())
    }

    /// The block subsidy at `height`.
    ///
    /// `initial_subsidy >> (height / halving_interval)`, dropping to zero once
    /// the shift reaches 64 — a `u64` shift of 64 or more is undefined in C
    /// and panics in Rust, so the boundary is handled explicitly here rather
    /// than discovered in production.
    pub fn block_subsidy(&self, height: u64) -> Amount {
        if self.halving_interval == 0 {
            // A zero interval means "never halve"; it is not a division.
            return self.initial_subsidy;
        }
        let halvings = height / self.halving_interval;
        if halvings >= 64 {
            return Amount::ZERO;
        }
        Amount::from_grains(self.initial_subsidy.to_grains() >> halvings)
    }

    /// Which consensus engine seals a block at `height`.
    pub fn engine_at(&self, height: u64) -> u8 {
        match self.bft_activation_height {
            Some(activation) if height >= activation => BlockSeal::ENGINE_BFT,
            _ => BlockSeal::ENGINE_POW,
        }
    }

    /// Target block spacing in **seconds**, the unit ASERT works in.
    pub const fn target_spacing_s(&self) -> u64 {
        self.target_spacing_ms / 1_000
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn networks_have_distinct_identities() {
        assert_eq!(ChainParams::mainnet().chain_id, ChainId(1));
        assert_eq!(ChainParams::testnet().chain_id, ChainId(2));
        assert_eq!(ChainParams::devnet().chain_id, ChainId(3));
        assert_eq!(ChainParams::mainnet().bech32_hrp, "fer");
        assert_eq!(ChainParams::testnet().bech32_hrp, "tfer");
        assert_eq!(ChainParams::devnet().bech32_hrp, "rfer");
    }

    #[test]
    fn by_name_rejects_an_unknown_network() {
        assert_eq!(
            ChainParams::by_name("bitcoin"),
            Err(TypeError::UnknownNetwork("bitcoin".to_owned()))
        );
    }

    #[test]
    fn by_name_matches_the_constructors() {
        assert_eq!(ChainParams::by_name("mainnet").unwrap(), ChainParams::mainnet());
        assert_eq!(ChainParams::by_name("testnet").unwrap(), ChainParams::testnet());
        assert_eq!(ChainParams::by_name("devnet").unwrap(), ChainParams::devnet());
        assert_eq!(ChainParams::by_name("regtest").unwrap(), ChainParams::devnet());
    }

    #[test]
    fn shared_consensus_values_match_the_contract() {
        for p in [ChainParams::mainnet(), ChainParams::testnet(), ChainParams::devnet()] {
            assert_eq!(p.target_spacing_ms, 120_000);
            assert_eq!(p.target_spacing_s(), 120);
            assert_eq!(p.asert_halflife_s, 7_200);
            assert_eq!(p.initial_subsidy, Amount::from_grains(50 * COIN));
            assert_eq!(p.halving_interval, 210_000);
            assert_eq!(p.coinbase_maturity, 100);
            assert_eq!(p.max_block_size, 1_000_000);
            assert_eq!(p.max_future_block_time_ms, 7_200_000);
            assert_eq!(p.median_time_span, 11);
            assert_eq!(p.min_relay_fee_per_kb, Amount::from_grains(1_000));
            assert_eq!(p.genesis_timestamp_ms, GENESIS_TIMESTAMP_MS);
            assert_eq!(p.genesis_nonce, 0);
            assert_eq!(p.bft_activation_height, None);
            assert!(p.bft_validators.is_empty());
            assert!(p.initial_subsidy.is_valid_money());
            assert_eq!(p.chain_id, p.network.chain_id());
            assert_eq!(p.bech32_hrp, p.network.bech32_hrp());
        }
    }

    #[test]
    fn devnet_is_far_easier_to_mine_than_mainnet() {
        let dev = ChainParams::devnet();
        let main = ChainParams::mainnet();
        // Big-endian arrays compare lexicographically, which is numeric order.
        assert!(dev.pow_limit > main.pow_limit, "devnet must accept far more hashes");
        assert_eq!(dev.pow_limit[0], 0x7f);
        assert_eq!(&dev.pow_limit[1..], &[0xff; 31]);
        assert_eq!(main.pow_limit[0..4], [0, 0, 0, 0]);
        assert_eq!(main.pow_limit[4], 0xff);
        assert_eq!(main.pow_limit[5], 0xff);
        assert_eq!(main.pow_limit[6..], [0u8; 26]);
        assert_eq!(dev.genesis_bits, CompactTarget(0x207f_ffff));
        assert_eq!(main.genesis_bits, CompactTarget(0x1d00_ffff));
        assert_eq!(ChainParams::testnet().pow_limit, main.pow_limit);
    }

    #[test]
    fn block_subsidy_starts_at_fifty_frm() {
        let p = ChainParams::mainnet();
        assert_eq!(p.block_subsidy(0), Amount::from_grains(50 * COIN));
        assert_eq!(p.block_subsidy(1), Amount::from_grains(50 * COIN));
        assert_eq!(p.block_subsidy(p.halving_interval - 1), Amount::from_grains(50 * COIN));
    }

    #[test]
    fn block_subsidy_halves_exactly_at_the_interval() {
        let p = ChainParams::mainnet();
        let i = p.halving_interval;
        assert_eq!(p.block_subsidy(i), Amount::from_grains(25 * COIN));
        assert_eq!(p.block_subsidy(i + 1), Amount::from_grains(25 * COIN));
        assert_eq!(p.block_subsidy(2 * i - 1), Amount::from_grains(25 * COIN));
        assert_eq!(p.block_subsidy(2 * i), Amount::from_grains(1_250_000_000));
        assert_eq!(p.block_subsidy(3 * i), Amount::from_grains(625_000_000));
    }

    #[test]
    fn block_subsidy_reaches_zero_by_arithmetic_before_the_shift_guard() {
        let p = ChainParams::mainnet();
        // 50 FRM is 5_000_000_000 grains, below 2^33, so the subsidy is
        // already zero long before the 64-halving guard is reached.
        assert_eq!(p.block_subsidy(33 * p.halving_interval), Amount::ZERO);
    }

    #[test]
    fn block_subsidy_is_zero_at_and_after_sixty_four_halvings() {
        let p = ChainParams::mainnet();
        let i = p.halving_interval;
        assert_eq!(p.block_subsidy(63 * i), Amount::ZERO);
        assert_eq!(p.block_subsidy(64 * i - 1), Amount::ZERO);
        assert_eq!(p.block_subsidy(64 * i), Amount::ZERO, "the shift guard must not panic");
        assert_eq!(p.block_subsidy(u64::MAX), Amount::ZERO);
    }

    #[test]
    fn block_subsidy_shift_guard_holds_for_a_huge_initial_subsidy() {
        // With a subsidy that still has bits set at 63 halvings, the guard is
        // the only thing standing between us and a shift-overflow panic.
        let mut p = ChainParams::mainnet();
        p.initial_subsidy = Amount::from_grains(u64::MAX);
        let i = p.halving_interval;
        assert_eq!(p.block_subsidy(63 * i), Amount::from_grains(1));
        assert_eq!(p.block_subsidy(64 * i), Amount::ZERO);
        assert_eq!(p.block_subsidy(u64::MAX), Amount::ZERO);
    }

    #[test]
    fn a_zero_halving_interval_never_halves_and_never_divides_by_zero() {
        let mut p = ChainParams::devnet();
        p.halving_interval = 0;
        assert_eq!(p.block_subsidy(0), p.initial_subsidy);
        assert_eq!(p.block_subsidy(u64::MAX), p.initial_subsidy);
    }

    /// Sum of every subsidy that will ever be paid, in grains.
    fn total_emission(p: &ChainParams) -> Amount {
        let mut total = Amount::ZERO;
        let mut era = 0u64;
        loop {
            let subsidy = p.block_subsidy(era.saturating_mul(p.halving_interval));
            if subsidy.is_zero() || era >= 64 {
                break;
            }
            let era_total =
                subsidy.checked_mul_u64(p.halving_interval).expect("an era cannot overflow u64");
            total = total.checked_add(era_total).expect("emission cannot overflow u64");
            era = era.saturating_add(1);
        }
        total
    }

    #[test]
    fn total_emission_never_exceeds_max_money() {
        for p in [ChainParams::mainnet(), ChainParams::testnet(), ChainParams::devnet()] {
            let total = total_emission(&p);
            assert!(
                total.is_valid_money(),
                "{} emits {} grains, above MAX_MONEY",
                p.network,
                total.to_grains()
            );
            // ... and it is close enough to 21M that the parameters are not
            // accidentally emitting a tenth of the intended supply.
            assert!(total.to_grains() > Amount::MAX_MONEY.to_grains() / 2);
        }
    }

    #[test]
    fn engine_at_is_pow_until_activation() {
        let mut p = ChainParams::devnet();
        assert_eq!(p.engine_at(0), BlockSeal::ENGINE_POW);
        assert_eq!(p.engine_at(u64::MAX), BlockSeal::ENGINE_POW);

        p.bft_activation_height = Some(100);
        assert_eq!(p.engine_at(99), BlockSeal::ENGINE_POW);
        assert_eq!(p.engine_at(100), BlockSeal::ENGINE_BFT, "activation is inclusive");
        assert_eq!(p.engine_at(101), BlockSeal::ENGINE_BFT);

        p.bft_activation_height = Some(0);
        assert_eq!(p.engine_at(0), BlockSeal::ENGINE_BFT, "a BFT chain from genesis");
    }

    #[test]
    fn params_serialize_readably() {
        let p = ChainParams::devnet();
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["network"], "Devnet");
        assert_eq!(j["chain_id"], 3);
        assert_eq!(j["bech32_hrp"], "rfer");
        assert_eq!(j["initial_subsidy"], 5_000_000_000u64);
        assert_eq!(j["genesis_bits"], 0x207f_ffffu32);
        assert_eq!(j["pow_limit"], format!("7f{}", "ff".repeat(31)));
        assert_eq!(j["bft_activation_height"], serde_json::Value::Null);
        assert_eq!(j["bft_validators"], serde_json::json!([]));
        assert_eq!(j["max_block_size"], 1_000_000);
        assert_eq!(j["median_time_span"], 11);
    }

    #[test]
    fn params_with_validators_serialize() {
        let mut p = ChainParams::devnet();
        p.bft_activation_height = Some(7);
        p.bft_validators = vec![ValidatorId::from_bytes([1; 32]), ValidatorId::from_bytes([2; 32])];
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["bft_activation_height"], 7);
        assert_eq!(j["bft_validators"][0], "01".repeat(32));
        assert_eq!(j["bft_validators"][1], "02".repeat(32));
    }

    proptest! {
        #[test]
        fn subsidy_is_monotonically_non_increasing(a in 0u64..2_000_000, b in 0u64..2_000_000) {
            let p = ChainParams::mainnet();
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(p.block_subsidy(hi) <= p.block_subsidy(lo));
        }

        #[test]
        fn subsidy_is_always_valid_money(h in any::<u64>()) {
            let p = ChainParams::mainnet();
            let s = p.block_subsidy(h);
            prop_assert!(s.is_valid_money());
            prop_assert!(s <= p.initial_subsidy);
        }

        #[test]
        fn subsidy_never_panics_for_any_interval(h in any::<u64>(), interval in any::<u64>()) {
            let mut p = ChainParams::devnet();
            p.halving_interval = interval;
            let _ = p.block_subsidy(h);
        }

        #[test]
        fn engine_at_switches_exactly_once(activation in any::<u64>(), h in any::<u64>()) {
            let mut p = ChainParams::devnet();
            p.bft_activation_height = Some(activation);
            let expected =
                if h >= activation { BlockSeal::ENGINE_BFT } else { BlockSeal::ENGINE_POW };
            prop_assert_eq!(p.engine_at(h), expected);
        }
    }
}
