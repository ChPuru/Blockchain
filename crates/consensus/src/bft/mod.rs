//! The BFT engine: Tendermint-shaped, permissioned, safety over liveness.
//!
//! # What is here, and what is not
//!
//! The **round machine** — propose, prevote, precommit, commit, with locking
//! and doubling timeouts — is a later milestone. Everything the rest of the
//! system needs *today* is here, because [`ferrum_types::BlockSeal`] already
//! carries a BFT commit:
//!
//! - [`VoteMsg`] and [`BftCommit`], with their frozen Borsh encodings;
//! - the three signing digests ([`proposal_digest`], [`prevote_digest`],
//!   [`precommit_digest`]);
//! - [`BftEngine`], its validator-set validation, quorum arithmetic, round-robin
//!   proposer schedule, timeout schedule and a complete
//!   [`BftEngine::verify_commit`].
//!
//! The [`ConsensusEngine`] methods that need the round machine return
//! [`ConsensusError::EngineUnavailable`]. They do **not** return a permissive
//! default: a BFT engine that said "valid" without a quorum would be the exact
//! bug the whole design exists to prevent.
//!
//! # The rules (CONTRACT 6.5, SPEC 9.2)
//!
//! - The validator set is fixed in `ChainParams::bft_validators`, x-only BIP-340
//!   keys, `n >= 4`, `f = (n - 1) / 3`, quorum `2f + 1`.
//! - Round-robin proposer: `validators[(height + round) % n]`.
//! - Timeouts double each round: `base * 2^round`.
//! - Locking: a validator that precommits a block in round `r` is locked on it
//!   and may only prevote a different block after seeing a `2f+1` polka for
//!   that block at a round greater than `r`. This is the rule that makes safety
//!   hold under asynchrony, and it is the rule most often omitted.
//! - Signed message: `tagged_hash(TAG_BFT_PRECOMMIT, borsh(VoteMsg))`.
//!
//! **Safety over liveness, deliberately.** With `n = 4`, killing one validator
//! continues; killing two **halts**. Halting is correct: a BFT chain that kept
//! producing blocks without a quorum would be forking, which is strictly worse
//! than stopping.

use core::sync::atomic::AtomicBool;
use core::time::Duration;
use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_crypto::{
    PublicKey, SecretKey, Signature, TAG_BFT_PRECOMMIT, TAG_BFT_PREVOTE, TAG_BFT_PROPOSAL,
    tagged_hash,
};
use ferrum_types::{
    Block, BlockHash, BlockHeader, BlockSeal, ChainId, ChainParams, CompactTarget, Hash32,
    ValidatorId,
};
use parking_lot::Mutex;

use crate::engine::{BlockTemplate, ConsensusEngine, HeaderView};
use crate::error::ConsensusError;
use crate::target::Work;

/// The smallest validator set that can tolerate one Byzantine member.
///
/// With `n = 3`, `f = (3-1)/3 = 0`: the set tolerates nothing, and calling it
/// BFT would be a lie. Four is the real minimum.
pub const MIN_VALIDATORS: usize = 4;

/// Default propose timeout at round 0.
pub const DEFAULT_PROPOSE_TIMEOUT: Duration = Duration::from_millis(3_000);
/// Default prevote timeout at round 0.
pub const DEFAULT_PREVOTE_TIMEOUT: Duration = Duration::from_millis(1_000);
/// Default precommit timeout at round 0.
pub const DEFAULT_PRECOMMIT_TIMEOUT: Duration = Duration::from_millis(1_000);

/// The message a validator signs when it votes.
///
/// `chain_id` is the first field, which is what stops a testnet vote from being
/// replayed on mainnet. `round` is inside the preimage, so a vote for the same
/// block in a different round is a different signature and cannot be reused to
/// forge a commit at another round.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct VoteMsg {
    /// Which chain this vote belongs to.
    pub chain_id: ChainId,
    /// The height being decided.
    pub height: u64,
    /// The round within that height.
    pub round: u32,
    /// The block being voted for.
    pub block_hash: BlockHash,
}

/// Borsh-encoded size of a [`VoteMsg`]: `u32 || u64 || u32 || [u8; 32]`.
pub const VOTE_MSG_SIZE: usize = 48;

impl VoteMsg {
    /// Build a vote.
    pub fn new(chain_id: ChainId, height: u64, round: u32, block_hash: BlockHash) -> Self {
        VoteMsg { chain_id, height, round, block_hash }
    }

    /// The canonical signing preimage.
    ///
    /// Borsh serialisation of a fixed-width struct into a `Vec` cannot fail;
    /// the only error `borsh::to_vec` can produce is an `io::Error` from the
    /// writer, and a `Vec` never fails to grow.
    pub fn signing_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("VoteMsg is fixed-width; Vec writes cannot fail")
    }
}

/// Digest a proposal is signed over.
pub fn proposal_digest(vote: &VoteMsg) -> Hash32 {
    tagged_hash(TAG_BFT_PROPOSAL, &vote.signing_bytes())
}

/// Digest a prevote is signed over.
pub fn prevote_digest(vote: &VoteMsg) -> Hash32 {
    tagged_hash(TAG_BFT_PREVOTE, &vote.signing_bytes())
}

/// Digest a precommit is signed over — the one a [`BftCommit`] aggregates.
pub fn precommit_digest(vote: &VoteMsg) -> Hash32 {
    tagged_hash(TAG_BFT_PRECOMMIT, &vote.signing_bytes())
}

/// A `2f+1` commit certificate: the BFT seal payload.
///
/// The certificate lives in `Block::seal`, outside the header and outside
/// `merkle_root`, because it is formed *after* the header exists and cannot
/// commit to itself. Keeping it out means the block hash is identical no matter
/// which `2f+1` subset of signatures a node happened to collect (CONTRACT 2.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BftCommit {
    /// Height the commit decides.
    pub height: u64,
    /// Round the commit was reached in.
    pub round: u32,
    /// The block that was committed.
    pub block_hash: BlockHash,
    /// `(validator index, signature)`, strictly ascending by index.
    pub signatures: Vec<(u16, Signature)>,
}

impl BftCommit {
    /// Build a commit certificate.
    pub fn new(
        height: u64,
        round: u32,
        block_hash: BlockHash,
        signatures: Vec<(u16, Signature)>,
    ) -> Self {
        BftCommit { height, round, block_hash, signatures }
    }

    /// The vote every signature in this commit is over.
    pub fn vote(&self, chain_id: ChainId) -> VoteMsg {
        VoteMsg::new(chain_id, self.height, self.round, self.block_hash)
    }

    /// Borsh encoding, as it appears in `BlockSeal::data`.
    ///
    /// Cannot fail for the same reason [`VoteMsg::signing_bytes`] cannot.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("BftCommit writes into a Vec, which cannot fail")
    }

    /// Decode a commit from a seal payload, rejecting trailing bytes.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::MalformedSeal`] on any decoding failure, including a
    /// tolerated suffix — a trailing byte would be free seal malleability.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConsensusError> {
        borsh::from_slice(bytes).map_err(|e| ConsensusError::MalformedSeal(e.to_string()))
    }

    /// Wrap this commit as a block seal.
    pub fn to_seal(&self) -> BlockSeal {
        BlockSeal::bft(self.encode())
    }
}

/// Where the round machine is between blocks.
///
/// Present and exercised so that [`BftEngine::finalized_height`] is real rather
/// than hard-coded; the round driver that advances it is a later milestone.
#[derive(Debug, Default)]
struct RoundState {
    /// Height currently being decided.
    height: u64,
    /// Round currently being decided.
    round: u32,
    /// `(round, block)` this validator is locked on, if any. The lock is what
    /// makes safety hold under asynchrony.
    locked: Option<(u32, BlockHash)>,
    /// The most recent commit this engine has accepted.
    last_commit: Option<BftCommit>,
}

/// The Tendermint-shaped BFT engine.
#[derive(Debug)]
pub struct BftEngine {
    params: ChainParams,
    validators: Vec<ValidatorId>,
    keys: Vec<PublicKey>,
    signing_key: Option<SecretKey>,
    state: Mutex<RoundState>,
}

impl BftEngine {
    /// Build the engine from a parameter set, optionally with this node's
    /// validator signing key.
    ///
    /// The whole validator set is parsed and checked here, once, so that a
    /// misconfigured key is a startup failure rather than a consensus failure
    /// at the fork height.
    ///
    /// # Errors
    ///
    /// - [`ConsensusError::ValidatorSetTooSmall`] below [`MIN_VALIDATORS`];
    /// - [`ConsensusError::ValidatorSetTooLarge`] past `u16::MAX` members;
    /// - [`ConsensusError::DuplicateValidator`] when a key repeats;
    /// - [`ConsensusError::InvalidValidatorKey`] when a key is not a valid
    ///   x-only BIP-340 point.
    pub fn new(
        params: ChainParams,
        signing_key: Option<SecretKey>,
    ) -> Result<Self, ConsensusError> {
        let validators = params.bft_validators.clone();
        if validators.len() < MIN_VALIDATORS {
            return Err(ConsensusError::ValidatorSetTooSmall {
                actual: validators.len(),
                minimum: MIN_VALIDATORS,
            });
        }
        if validators.len() > usize::from(u16::MAX) {
            return Err(ConsensusError::ValidatorSetTooLarge(validators.len()));
        }

        let mut seen = BTreeSet::new();
        let mut keys = Vec::with_capacity(validators.len());
        for (index, v) in validators.iter().enumerate() {
            if !seen.insert(*v.as_bytes()) {
                return Err(ConsensusError::DuplicateValidator(v.to_hex()));
            }
            let key = PublicKey::try_from(*v).map_err(|e| ConsensusError::InvalidValidatorKey {
                index,
                reason: e.to_string(),
            })?;
            keys.push(key);
        }

        let engine = BftEngine {
            params,
            validators,
            keys,
            signing_key,
            state: Mutex::new(RoundState::default()),
        };
        if !engine.has_quorum_intersection() {
            tracing::warn!(
                validators = engine.validators.len(),
                quorum = engine.quorum(),
                "validator set admits two disjoint quorums; use n = 3f + 1 (4, 7, 10, 13, …)"
            );
        }
        Ok(engine)
    }

    /// The parameter set this engine enforces.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The active validator set, in index order.
    pub fn validators(&self) -> &[ValidatorId] {
        &self.validators
    }

    /// Number of validators, `n`.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// The number of Byzantine members the set tolerates: `f = (n - 1) / 3`.
    pub fn fault_tolerance(&self) -> usize {
        self.validators.len().saturating_sub(1) / 3
    }

    /// The quorum size, `2f + 1`.
    ///
    /// # Choose `n = 3f + 1`
    ///
    /// Safety needs any two quorums to intersect, i.e. `2 * (2f + 1) > n`. With
    /// `f = (n - 1) / 3` that holds for every set size except **`n = 6`**,
    /// where `f = 1` and two disjoint quorums of three exist. The contract
    /// fixes the formula, so this returns it unchanged; [`BftEngine::new`] logs
    /// a warning for any set size that fails quorum intersection, and operators
    /// should use `n = 3f + 1`: 4, 7, 10, 13.
    pub fn quorum(&self) -> usize {
        self.fault_tolerance().saturating_mul(2).saturating_add(1)
    }

    /// True when any two quorums must share at least one validator, which is
    /// what makes two conflicting commits at the same height impossible.
    pub fn has_quorum_intersection(&self) -> bool {
        self.quorum().saturating_mul(2) > self.validators.len()
    }

    /// The proposer for `(height, round)`: `validators[(height + round) % n]`.
    ///
    /// Round-robin over both axes, so a crashed proposer is stepped over by the
    /// next round rather than stalling the height forever.
    pub fn proposer(&self, height: u64, round: u32) -> ValidatorId {
        let n = self.validators.len() as u128;
        let position = u128::from(height).wrapping_add(u128::from(round));
        let index = position.checked_rem(n).unwrap_or(0);
        let index = usize::try_from(index).unwrap_or(0);
        // `index < n == validators.len()`, so this cannot be out of range; the
        // fallback keeps the function total without an `unwrap`.
        self.validators.get(index).copied().unwrap_or_else(|| ValidatorId::from_bytes([0u8; 32]))
    }

    /// True when this node is the proposer for `(height, round)`.
    pub fn is_proposer(&self, height: u64, round: u32) -> bool {
        match self.signing_key.as_ref() {
            Some(key) => ValidatorId::from(key.public_key()) == self.proposer(height, round),
            None => false,
        }
    }

    /// The index of a validator in the active set.
    pub fn validator_index(&self, id: &ValidatorId) -> Option<u16> {
        self.validators.iter().position(|v| v == id).and_then(|i| u16::try_from(i).ok())
    }

    /// This node's own validator index, when it holds a signing key that is in
    /// the set.
    pub fn own_index(&self) -> Option<u16> {
        let key = self.signing_key.as_ref()?;
        self.validator_index(&ValidatorId::from(key.public_key()))
    }

    /// The timeout for `round`: `base * 2^round`, saturating.
    ///
    /// Doubling is what lets an asynchronous network eventually agree: rounds
    /// keep widening until the timeout exceeds the real message delay.
    ///
    /// It saturates at `u64::MAX` milliseconds rather than wrapping. A wrapped
    /// shift would produce a *zero* timeout at high round numbers, which spins
    /// the round machine at full speed exactly when the network is already in
    /// trouble.
    pub fn timeout_for_round(base: Duration, round: u32) -> Duration {
        let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
        if millis == 0 {
            return Duration::ZERO;
        }
        // The shift overflows precisely when it would push a set bit past 64.
        if round > millis.leading_zeros() {
            return Duration::from_millis(u64::MAX);
        }
        Duration::from_millis(millis.checked_shl(round).unwrap_or(u64::MAX))
    }

    /// Sign a precommit for `vote` with this node's validator key.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::EngineUnavailable`] when this node holds no validator
    /// key — it is an observer, not a voter.
    pub fn sign_precommit(&self, vote: &VoteMsg) -> Result<Signature, ConsensusError> {
        let key = self.signing_key.as_ref().ok_or(ConsensusError::EngineUnavailable)?;
        Ok(key.sign_deterministic(&precommit_digest(vote)))
    }

    /// Verify a `2f+1` commit certificate against a block.
    ///
    /// Checks, in order: that the commit describes this block and height; that
    /// the signature list is strictly ascending by validator index (which makes
    /// the encoding canonical *and* rejects a duplicated index that would
    /// otherwise let one validator fill a whole quorum); that every index is in
    /// range; that every signature verifies; and finally that there are at
    /// least `2f + 1` of them.
    ///
    /// The quorum count comes last so that a certificate with enough signatures
    /// but one forgery is reported as a bad signature, not as a short quorum.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::CommitMismatch`],
    /// [`ConsensusError::UnorderedCommitSignatures`],
    /// [`ConsensusError::ValidatorIndexOutOfRange`],
    /// [`ConsensusError::BadCommitSignature`] and
    /// [`ConsensusError::QuorumNotReached`].
    pub fn verify_commit(
        &self,
        commit: &BftCommit,
        block_hash: &BlockHash,
        height: u64,
    ) -> Result<(), ConsensusError> {
        if commit.block_hash != *block_hash || commit.height != height {
            return Err(ConsensusError::CommitMismatch {
                actual: commit.block_hash,
                actual_height: commit.height,
                expected: *block_hash,
                expected_height: height,
            });
        }

        let digest = precommit_digest(&commit.vote(self.params.chain_id));
        let mut previous: Option<u16> = None;
        for (position, (index, signature)) in commit.signatures.iter().enumerate() {
            if let Some(prev) = previous
                && *index <= prev
            {
                return Err(ConsensusError::UnorderedCommitSignatures(position));
            }
            previous = Some(*index);

            let key = self.keys.get(usize::from(*index)).ok_or(
                ConsensusError::ValidatorIndexOutOfRange {
                    index: *index,
                    size: self.validators.len(),
                },
            )?;
            key.verify(&digest, signature).map_err(|e| ConsensusError::BadCommitSignature {
                index: *index,
                reason: e.to_string(),
            })?;
        }

        let quorum = self.quorum();
        if commit.signatures.len() < quorum {
            return Err(ConsensusError::QuorumNotReached {
                have: commit.signatures.len(),
                need: quorum,
            });
        }
        Ok(())
    }

    /// Record a verified commit, which is what makes its height final.
    ///
    /// The round driver calls this; it is public so that the driver can live in
    /// a later milestone without reopening this type.
    pub fn record_commit(&self, commit: BftCommit) {
        let mut state = self.state.lock();
        state.height = commit.height;
        state.round = commit.round;
        state.locked = Some((commit.round, commit.block_hash));
        state.last_commit = Some(commit);
    }

    /// The `(round, block)` this node is locked on, if any.
    pub fn locked_on(&self) -> Option<(u32, BlockHash)> {
        self.state.lock().locked
    }

    /// The most recent commit this engine accepted.
    pub fn last_commit(&self) -> Option<BftCommit> {
        self.state.lock().last_commit.clone()
    }
}

impl ConsensusEngine for BftEngine {
    fn name(&self) -> &'static str {
        "bft"
    }

    fn engine_id(&self) -> u8 {
        BlockSeal::ENGINE_BFT
    }

    /// Not yet available: header validation under BFT needs the round machine
    /// to know which proposer was legitimate at this height and round.
    fn validate_header(
        &self,
        _h: &BlockHeader,
        _parent: &BlockHeader,
        _view: &dyn HeaderView,
    ) -> Result<(), ConsensusError> {
        Err(ConsensusError::EngineUnavailable)
    }

    /// Not yet available. [`BftEngine::verify_commit`] is the complete
    /// certificate check; wiring it into block acceptance waits for the round
    /// machine, and until then this refuses rather than accepting a block whose
    /// seal it cannot place in a round.
    fn validate_seal(&self, _block: &Block, _view: &dyn HeaderView) -> Result<(), ConsensusError> {
        Err(ConsensusError::EngineUnavailable)
    }

    /// Not yet available: under BFT the target is not a difficulty at all, and
    /// what a post-fork header carries in `bits` is decided with the round
    /// machine.
    fn next_bits(
        &self,
        _parent: &BlockHeader,
        _view: &dyn HeaderView,
    ) -> Result<CompactTarget, ConsensusError> {
        Err(ConsensusError::EngineUnavailable)
    }

    /// Not yet available: sealing under BFT means proposing and collecting
    /// `2f+1` precommits, which is the round machine.
    fn seal(
        &self,
        _tmpl: BlockTemplate,
        _cancel: &AtomicBool,
    ) -> Result<Option<Block>, ConsensusError> {
        Err(ConsensusError::EngineUnavailable)
    }

    /// Every BFT block contributes exactly one unit of work (SPEC 9).
    ///
    /// Fork choice below finality is by height under BFT, and a constant weight
    /// per block expresses that in the same currency proof of work uses, so the
    /// chain layer needs no special case.
    fn work(&self, _h: &BlockHeader) -> Work {
        Work::ONE
    }

    /// The last committed height: reorgs below it are impossible by
    /// construction. `None` until this engine has recorded a commit.
    fn finalized_height(&self, _view: &dyn HeaderView) -> Option<u64> {
        self.state.lock().last_commit.as_ref().map(|c| c.height)
    }
}

/// Deterministic validator keys for tests in this crate.
#[cfg(test)]
pub(crate) mod tests_support {
    use ferrum_crypto::SecretKey;
    use ferrum_types::ValidatorId;

    /// The `i`-th test validator's secret key: seed `[i+1; 32]`.
    pub(crate) fn validator_key(i: usize) -> SecretKey {
        let seed = [u8::try_from(i.wrapping_add(1)).unwrap_or(1); 32];
        SecretKey::from_bytes(&seed).expect("a non-zero 32-byte seed is a valid secret key")
    }

    /// `n` distinct, valid x-only validator ids.
    pub(crate) fn validator_ids(n: usize) -> Vec<ValidatorId> {
        (0..n).map(|i| ValidatorId::from(validator_key(i).public_key())).collect()
    }
}

#[cfg(test)]
mod tests;
