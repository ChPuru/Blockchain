//! The BFT validator set: identity, quorum arithmetic and the proposer
//! schedule.
//!
//! The set is fixed in `ChainParams::bft_validators` and parsed exactly once,
//! at startup, so a misconfigured key is a boot failure rather than a consensus
//! failure at the fork height.

use std::collections::BTreeSet;

use ferrum_crypto::{PublicKey, Signature};
use ferrum_types::{Hash32, ValidatorId};

use crate::error::ConsensusError;

/// The smallest validator set that can tolerate one Byzantine member.
///
/// With `n = 3`, `f = (3-1)/3 = 0`: the set tolerates nothing, and calling it
/// BFT would be a lie. Four is the real minimum (CONTRACT 6.5).
pub const MIN_VALIDATORS: usize = 4;

/// The active validator set, in index order.
///
/// The index is what a [`BftCommit`](crate::BftCommit) names, so the order of
/// `ChainParams::bft_validators` is consensus-critical: reordering the list is
/// a hard fork.
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    ids: Vec<ValidatorId>,
    keys: Vec<PublicKey>,
}

impl ValidatorSet {
    /// Parse and validate a validator set.
    ///
    /// # Errors
    ///
    /// - [`ConsensusError::ValidatorSetTooSmall`] below [`MIN_VALIDATORS`];
    /// - [`ConsensusError::ValidatorSetTooLarge`] past `u16::MAX` members,
    ///   because the commit certificate indexes validators with a `u16`;
    /// - [`ConsensusError::DuplicateValidator`] when a key repeats, which would
    ///   let one key fill two quorum slots;
    /// - [`ConsensusError::InvalidValidatorKey`] when a key is not a valid
    ///   x-only BIP-340 point.
    pub fn new(ids: Vec<ValidatorId>) -> Result<Self, ConsensusError> {
        if ids.len() < MIN_VALIDATORS {
            return Err(ConsensusError::ValidatorSetTooSmall {
                actual: ids.len(),
                minimum: MIN_VALIDATORS,
            });
        }
        if ids.len() > usize::from(u16::MAX) {
            return Err(ConsensusError::ValidatorSetTooLarge(ids.len()));
        }

        let mut seen = BTreeSet::new();
        let mut keys = Vec::with_capacity(ids.len());
        for (index, id) in ids.iter().enumerate() {
            if !seen.insert(*id.as_bytes()) {
                return Err(ConsensusError::DuplicateValidator(id.to_hex()));
            }
            let key = PublicKey::try_from(*id).map_err(|e| {
                ConsensusError::InvalidValidatorKey { index, reason: e.to_string() }
            })?;
            keys.push(key);
        }
        Ok(ValidatorSet { ids, keys })
    }

    /// Number of validators, `n`.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Always false: [`ValidatorSet::new`] refuses a set below
    /// [`MIN_VALIDATORS`]. Present so the type reads like a collection.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// The validator ids, in index order.
    pub fn ids(&self) -> &[ValidatorId] {
        &self.ids
    }

    /// The public key at `index`.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::ValidatorIndexOutOfRange`] when the index names no
    /// member of the set.
    pub fn key(&self, index: u16) -> Result<&PublicKey, ConsensusError> {
        self.keys
            .get(usize::from(index))
            .ok_or(ConsensusError::ValidatorIndexOutOfRange { index, size: self.ids.len() })
    }

    /// The index of a validator, if it is in the set.
    pub fn index_of(&self, id: &ValidatorId) -> Option<u16> {
        self.ids.iter().position(|v| v == id).and_then(|i| u16::try_from(i).ok())
    }

    /// The number of Byzantine members the set tolerates: `f = (n - 1) / 3`.
    pub fn fault_tolerance(&self) -> usize {
        self.ids.len().saturating_sub(1) / 3
    }

    /// The quorum size, `2f + 1`.
    ///
    /// # Choose `n = 3f + 1`
    ///
    /// Safety needs any two quorums to intersect, i.e. `2 * (2f + 1) > n`. With
    /// `f = (n - 1) / 3` that holds for every set size except **`n = 6`**,
    /// where `f = 1` and two disjoint quorums of three exist. The contract
    /// fixes the formula, so this returns it unchanged;
    /// [`ValidatorSet::has_quorum_intersection`] is how a caller notices, and
    /// operators should use `n = 3f + 1`: 4, 7, 10, 13.
    pub fn quorum(&self) -> usize {
        self.fault_tolerance().saturating_mul(2).saturating_add(1)
    }

    /// True when any two quorums must share at least one validator, which is
    /// what makes two conflicting commits at one height impossible.
    pub fn has_quorum_intersection(&self) -> bool {
        self.quorum().saturating_mul(2) > self.ids.len()
    }

    /// The proposer index for `(height, round)`: `(height + round) % n`.
    ///
    /// Round-robin over both axes, so a crashed proposer is stepped over by the
    /// next round rather than stalling the height forever. The addition is done
    /// in `u128` so `height + round` cannot wrap into a different schedule.
    pub fn proposer_index(&self, height: u64, round: u32) -> u16 {
        let n = u128::try_from(self.ids.len()).unwrap_or(1).max(1);
        let position = u128::from(height).saturating_add(u128::from(round));
        let index = position.checked_rem(n).unwrap_or(0);
        // `index < n <= u16::MAX`, so the conversion cannot truncate; the
        // fallback keeps the function total without an `unwrap`.
        u16::try_from(index).unwrap_or(0)
    }

    /// The proposer for `(height, round)`.
    pub fn proposer(&self, height: u64, round: u32) -> ValidatorId {
        let index = usize::from(self.proposer_index(height, round));
        self.ids.get(index).copied().unwrap_or_else(|| ValidatorId::from_bytes([0u8; 32]))
    }

    /// Verify one BIP-340 signature against the validator at `index`.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::ValidatorIndexOutOfRange`] for an unknown index and
    /// [`ConsensusError::BadCommitSignature`] when the signature does not
    /// verify.
    pub fn verify(
        &self,
        index: u16,
        digest: &Hash32,
        signature: &Signature,
    ) -> Result<(), ConsensusError> {
        let key = self.key(index)?;
        key.verify(digest, signature)
            .map_err(|e| ConsensusError::BadCommitSignature { index, reason: e.to_string() })
    }
}
