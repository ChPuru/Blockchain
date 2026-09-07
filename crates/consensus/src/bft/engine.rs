//! [`BftEngine`]: the [`ConsensusEngine`] face of the round machine.
//!
//! The engine owns the validator set, this node's signing key, one
//! [`BftMachine`] and the finality bookkeeping. It is the only part of the BFT
//! subtree that the chain layer names.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use ferrum_crypto::{SecretKey, Signature};
use ferrum_types::{
    Block, BlockHash, BlockHeader, BlockSeal, ChainParams, CompactTarget, ValidatorId,
};
use parking_lot::Mutex;

use crate::bft::event::{BftAction, BftEvent};
use crate::bft::machine::BftMachine;
use crate::bft::state::{RoundState, TimeoutConfig, timeout_for_round};
use crate::bft::validators::ValidatorSet;
use crate::bft::vote::{BftCommit, VoteMsg, precommit_digest};
use crate::engine::{BlockTemplate, ConsensusEngine, HeaderView, MIN_BLOCK_VERSION, block_hash};
use crate::error::ConsensusError;
use crate::target::Work;

/// Everything the engine mutates behind one lock.
#[derive(Debug)]
struct EngineState {
    machine: BftMachine,
    last_commit: Option<BftCommit>,
    finalized: Option<u64>,
}

/// The Tendermint-shaped BFT engine.
#[derive(Debug)]
pub struct BftEngine {
    params: ChainParams,
    validators: ValidatorSet,
    signing_key: Option<SecretKey>,
    state: Mutex<EngineState>,
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
    /// Every [`ValidatorSet::new`] error.
    pub fn new(
        params: ChainParams,
        signing_key: Option<SecretKey>,
    ) -> Result<Self, ConsensusError> {
        let validators = ValidatorSet::new(params.bft_validators.clone())?;
        if !validators.has_quorum_intersection() {
            tracing::warn!(
                validators = validators.len(),
                quorum = validators.quorum(),
                "validator set admits two disjoint quorums; use n = 3f + 1 (4, 7, 10, 13, …)"
            );
        }
        let machine = BftMachine::new(
            params.chain_id,
            validators.clone(),
            signing_key.clone(),
            TimeoutConfig::default(),
        );
        Ok(BftEngine {
            params,
            validators,
            signing_key,
            state: Mutex::new(EngineState { machine, last_commit: None, finalized: None }),
        })
    }

    // ------------------------------------------------------- the static set

    /// The parameter set this engine enforces.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The active validator set.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validators
    }

    /// The active validator set, in index order.
    pub fn validators(&self) -> &[ValidatorId] {
        self.validators.ids()
    }

    /// Number of validators, `n`.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// The number of Byzantine members the set tolerates: `f = (n - 1) / 3`.
    pub fn fault_tolerance(&self) -> usize {
        self.validators.fault_tolerance()
    }

    /// The quorum size, `2f + 1`.
    pub fn quorum(&self) -> usize {
        self.validators.quorum()
    }

    /// True when any two quorums must share at least one validator.
    pub fn has_quorum_intersection(&self) -> bool {
        self.validators.has_quorum_intersection()
    }

    /// The proposer for `(height, round)`: `validators[(height + round) % n]`.
    pub fn proposer(&self, height: u64, round: u32) -> ValidatorId {
        self.validators.proposer(height, round)
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
        self.validators.index_of(id)
    }

    /// This node's own validator index, when it holds a signing key that is in
    /// the set.
    pub fn own_index(&self) -> Option<u16> {
        let key = self.signing_key.as_ref()?;
        self.validator_index(&ValidatorId::from(key.public_key()))
    }

    /// The timeout for `round`: `base * 2^round`, saturating.
    pub fn timeout_for_round(base: Duration, round: u32) -> Duration {
        timeout_for_round(base, round)
    }

    // --------------------------------------------------------- round driving

    /// Feed one event into the round machine and get the actions back.
    ///
    /// This is the whole driver interface. The node owns the network and the
    /// timers; the engine owns the rules.
    pub fn submit(&self, event: BftEvent) -> Vec<BftAction> {
        self.state.lock().machine.step(event)
    }

    /// A snapshot of the round state.
    pub fn round_state(&self) -> RoundState {
        self.state.lock().machine.state().clone()
    }

    /// Tell the machine which block this node would propose at `height`.
    pub fn set_candidate(&self, height: u64, block_hash: BlockHash) {
        self.state.lock().machine.set_candidate(height, block_hash);
    }

    /// The commit certificate the machine has decided on, if any.
    pub fn decision(&self) -> Option<BftCommit> {
        self.state.lock().machine.decision().cloned()
    }

    /// The `(round, block)` this node is locked on, if any.
    pub fn locked_on(&self) -> Option<(u32, BlockHash)> {
        self.state.lock().machine.state().locked()
    }

    /// The most recent commit this engine accepted.
    pub fn last_commit(&self) -> Option<BftCommit> {
        self.state.lock().last_commit.clone()
    }

    /// Record a verified commit, which is what makes its height final.
    ///
    /// The driver calls this after the block it certifies has been stored.
    /// Finality only ever moves forward: a stale commit cannot lower it.
    pub fn record_commit(&self, commit: BftCommit) {
        let mut state = self.state.lock();
        let height = commit.height;
        state.finalized = Some(state.finalized.map_or(height, |current| current.max(height)));
        state.last_commit = Some(commit);
    }

    // ------------------------------------------------------------ signatures

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
            self.validators.verify(*index, &digest, signature)?;
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

    /// The height of `header`, from the view.
    ///
    /// Prefers the block's own height when the view already knows it, so
    /// re-validating a stored block still works after its parent was pruned.
    fn height_of(
        &self,
        header: &BlockHeader,
        view: &dyn HeaderView,
    ) -> Result<u64, ConsensusError> {
        if let Some(height) = view.height_of(&block_hash(header)) {
            return Ok(height);
        }
        if header.prev_hash.is_zero() {
            return Ok(0);
        }
        view.height_of(&header.prev_hash)
            .map(|h| h.saturating_add(1))
            .ok_or(ConsensusError::UnknownParent(header.prev_hash))
    }

    /// Finality read off the chain itself.
    ///
    /// A block only reaches the active chain after [`Self::validate_seal`] has
    /// verified a `2f+1` certificate over it, so **every** BFT block on the
    /// active chain is final by construction. That makes the tip the finalized
    /// height, with no driver bookkeeping needed, and it is what makes
    /// [`EngineRouter::check_reorg`](crate::EngineRouter::check_reorg) refuse to
    /// unwind a committed block.
    ///
    /// `bft_activation_height` is the source of truth, not `--consensus bft`: a
    /// node that pins the engine from the command line has no *chain* promise
    /// that its peers agree, so it claims finality only for what it has itself
    /// committed through [`Self::record_commit`] or [`Self::seal`].
    fn finalized_from_view(&self, view: &dyn HeaderView) -> Option<u64> {
        let activation = self.params.bft_activation_height?;
        let (tip_hash, tip_height) = view.tip();
        // An empty view reports a zero tip; require the header to exist.
        view.header_by_hash(&tip_hash)?;
        (tip_height >= activation).then_some(tip_height)
    }
}

impl ConsensusEngine for BftEngine {
    fn name(&self) -> &'static str {
        "bft"
    }

    fn engine_id(&self) -> u8 {
        BlockSeal::ENGINE_BFT
    }

    /// Header checks under BFT.
    ///
    /// There is no proof of work to check: the quorum in the seal *is* the
    /// proof, and it is verified by [`Self::validate_seal`]. What is left is
    /// everything that keeps the header canonical:
    ///
    /// 1. `version >= MIN_BLOCK_VERSION`;
    /// 2. `prev_hash` names the parent it was handed;
    /// 3. `bits` equals [`Self::next_bits`], i.e. the parent's — the field is
    ///    frozen at the fork rather than removed, because SPEC 9.3 promises no
    ///    header field changes;
    /// 4. `nonce == 0`. Nothing grinds a nonce under BFT, so a non-zero one is
    ///    a free malleability channel: it would let a proposer offer the same
    ///    content under many block hashes;
    /// 5. `timestamp_ms > median_time_past(parent) * 1000`, strictly, which
    ///    keeps block time monotone across the fork exactly as it was before it.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::BadVersion`], [`ConsensusError::WrongParent`],
    /// [`ConsensusError::BadDifficultyTransition`],
    /// [`ConsensusError::NonZeroBftNonce`],
    /// [`ConsensusError::MedianTimePastUnavailable`] and
    /// [`ConsensusError::TimestampTooOld`].
    fn validate_header(
        &self,
        h: &BlockHeader,
        parent: &BlockHeader,
        view: &dyn HeaderView,
    ) -> Result<(), ConsensusError> {
        if h.version < MIN_BLOCK_VERSION {
            return Err(ConsensusError::BadVersion(h.version));
        }

        let parent_hash = block_hash(parent);
        if h.prev_hash != parent_hash {
            return Err(ConsensusError::WrongParent { expected: parent_hash, actual: h.prev_hash });
        }

        let expected = self.next_bits(parent, view)?;
        if h.bits != expected {
            return Err(ConsensusError::BadDifficultyTransition { expected, actual: h.bits });
        }

        if h.nonce != 0 {
            return Err(ConsensusError::NonZeroBftNonce(h.nonce));
        }

        let mtp_s = view
            .median_time_past(&parent_hash)
            .ok_or(ConsensusError::MedianTimePastUnavailable(parent_hash))?;
        let median_time_past_ms = mtp_s.saturating_mul(1_000);
        if h.timestamp_ms <= median_time_past_ms {
            return Err(ConsensusError::TimestampTooOld {
                timestamp_ms: h.timestamp_ms,
                median_time_past_ms,
            });
        }

        Ok(())
    }

    /// The seal must be a `2f+1` commit over exactly this block hash at exactly
    /// this height.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::WrongEngine`], [`ConsensusError::MalformedSeal`],
    /// [`ConsensusError::UnknownParent`] and every [`Self::verify_commit`]
    /// error.
    fn validate_seal(&self, block: &Block, view: &dyn HeaderView) -> Result<(), ConsensusError> {
        if block.seal.engine != BlockSeal::ENGINE_BFT {
            return Err(ConsensusError::WrongEngine {
                expected: BlockSeal::ENGINE_BFT,
                actual: block.seal.engine,
            });
        }
        let commit = BftCommit::decode(&block.seal.data)?;
        let height = self.height_of(&block.header, view)?;
        self.verify_commit(&commit, &block_hash(&block.header), height)
    }

    /// The parent's `bits`, unchanged.
    ///
    /// Under BFT there is no difficulty: agreement replaces work. The field
    /// stays in the header because SPEC 9.3 promises the serialised structure
    /// does not change across the fork, and freezing it at the parent's value
    /// is the one choice that is deterministic, needs no view lookup, and
    /// leaves the last pre-fork difficulty visible in every post-fork header.
    fn next_bits(
        &self,
        parent: &BlockHeader,
        _view: &dyn HeaderView,
    ) -> Result<CompactTarget, ConsensusError> {
        Ok(parent.bits)
    }

    /// Turn a decided round into a sealed block.
    ///
    /// Sealing under BFT is a network protocol, not a computation: the node
    /// drives the round machine with [`Self::submit`] as proposals and votes
    /// arrive, and this is the point where a round that has already decided
    /// becomes a block. `Ok(None)` means "no block from this call" — the round
    /// was cancelled, or it has not decided yet, or it decided a different
    /// block. It never means "I could not be bothered": a decided round always
    /// produces a block, and the certificate is re-verified on the way out so
    /// this engine cannot emit a seal it would itself reject.
    ///
    /// # Errors
    ///
    /// Every [`Self::verify_commit`] error, if the machine ever produced a
    /// certificate that does not verify — which is a bug, not an input.
    fn seal(
        &self,
        tmpl: BlockTemplate,
        cancel: &AtomicBool,
    ) -> Result<Option<Block>, ConsensusError> {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut header = tmpl.header;
        // The nonce means nothing here and is pinned to zero by
        // `validate_header`; normalise it before hashing so the hash the round
        // agrees on is the hash the network will accept.
        header.nonce = 0;
        let hash = block_hash(&header);

        let mut state = self.state.lock();
        state.machine.set_candidate(tmpl.height, hash);
        let Some(commit) = state.machine.decision().cloned() else {
            return Ok(None);
        };
        if commit.height != tmpl.height || commit.block_hash != hash {
            return Ok(None);
        }
        self.verify_commit(&commit, &hash, tmpl.height)?;

        let height = commit.height;
        state.finalized = Some(state.finalized.map_or(height, |current| current.max(height)));
        state.last_commit = Some(commit.clone());
        Ok(Some(Block::new(header, tmpl.txs, commit.to_seal())))
    }

    /// Every BFT block contributes exactly one unit of work (SPEC 9).
    ///
    /// Fork choice below finality is by height under BFT, and a constant weight
    /// per block expresses that in the same currency proof of work uses, so the
    /// chain layer needs no special case.
    fn work(&self, _h: &BlockHeader) -> Work {
        Work::ONE
    }

    /// The last committed height: reorgs below it are impossible.
    fn finalized_height(&self, view: &dyn HeaderView) -> Option<u64> {
        let recorded = self.state.lock().finalized;
        match (recorded, self.finalized_from_view(view)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }
}
