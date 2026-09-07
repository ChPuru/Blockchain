//! BFT messages: the vote preimage, signed votes, proposals and the `2f+1`
//! commit certificate.
//!
//! Every signature in this module is BIP-340 Schnorr over a **tagged** digest,
//! and every preimage starts with `chain_id`. That is what stops a testnet vote
//! from being replayed on mainnet, and the three distinct tags
//! (`TAG_BFT_PROPOSAL`, `TAG_BFT_PREVOTE`, `TAG_BFT_PRECOMMIT`) are what stop a
//! prevote from being counted as a precommit.

use borsh::{BorshDeserialize, BorshSerialize};
use ferrum_crypto::{
    SecretKey, Signature, TAG_BFT_PRECOMMIT, TAG_BFT_PREVOTE, TAG_BFT_PROPOSAL, tagged_hash,
};
use ferrum_types::{BlockHash, BlockSeal, ChainId, Hash32};

use crate::bft::validators::ValidatorSet;
use crate::error::ConsensusError;

/// The "no block" vote.
///
/// Tendermint votes `nil` to say "I saw no acceptable proposal in this round".
/// Ferrum spells that as the all-zero block hash rather than widening
/// [`VoteMsg`] to an `Option`: the vote preimage is frozen at 48 bytes
/// (CONTRACT 6.5), and no real block hashes to zero.
pub const NIL_BLOCK: BlockHash = BlockHash::ZERO;

/// Borsh-encoded size of a [`VoteMsg`]: `u32 || u64 || u32 || [u8; 32]`.
pub const VOTE_MSG_SIZE: usize = 48;

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
    /// The block being voted for, or [`NIL_BLOCK`].
    pub block_hash: BlockHash,
}

impl VoteMsg {
    /// Build a vote.
    pub fn new(chain_id: ChainId, height: u64, round: u32, block_hash: BlockHash) -> Self {
        VoteMsg { chain_id, height, round, block_hash }
    }

    /// A `nil` vote for `(height, round)`.
    pub fn nil(chain_id: ChainId, height: u64, round: u32) -> Self {
        VoteMsg::new(chain_id, height, round, NIL_BLOCK)
    }

    /// True when this vote is for no block at all.
    pub fn is_nil(&self) -> bool {
        self.block_hash.is_zero()
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

/// Which of the two voting steps a [`SignedVote`] belongs to.
///
/// The kind selects the domain tag, so a prevote can never be replayed as a
/// precommit — which matters because a commit certificate is built from
/// precommits, and a prevote promises nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteKind {
    /// First round trip: "this is the block I saw".
    Prevote,
    /// Second round trip: "I am locked on this block".
    Precommit,
}

impl VoteKind {
    /// The digest a vote of this kind is signed over.
    pub fn digest(self, vote: &VoteMsg) -> Hash32 {
        match self {
            VoteKind::Prevote => prevote_digest(vote),
            VoteKind::Precommit => precommit_digest(vote),
        }
    }
}

/// A vote with the identity and signature of the validator that cast it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedVote {
    /// What was voted for.
    pub vote: VoteMsg,
    /// Index of the signing validator in the active set.
    pub validator: u16,
    /// BIP-340 signature over `kind.digest(&vote)`.
    pub signature: Signature,
}

impl SignedVote {
    /// Build a signed vote from parts.
    pub fn new(vote: VoteMsg, validator: u16, signature: Signature) -> Self {
        SignedVote { vote, validator, signature }
    }

    /// Sign `vote` as `validator`.
    ///
    /// Uses [`SecretKey::sign_deterministic`], so the whole round machine is
    /// reproducible: replaying a recorded run produces byte-identical votes.
    pub fn sign(key: &SecretKey, validator: u16, kind: VoteKind, vote: VoteMsg) -> Self {
        SignedVote { vote, validator, signature: key.sign_deterministic(&kind.digest(&vote)) }
    }

    /// True when this validator voted for no block.
    pub fn is_nil(&self) -> bool {
        self.vote.is_nil()
    }

    /// Verify the signature against the active validator set.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::ValidatorIndexOutOfRange`] and
    /// [`ConsensusError::BadCommitSignature`].
    pub fn verify(&self, kind: VoteKind, set: &ValidatorSet) -> Result<(), ConsensusError> {
        set.verify(self.validator, &kind.digest(&self.vote), &self.signature)
    }
}

/// A block proposal for `(height, round)`.
///
/// `pol_round` is the Tendermint `validRound`: the round at which the proposer
/// claims it already saw a `2f+1` polka for this block. **It is a hint, and it
/// is deliberately outside the signed preimage.** A receiver never acts on the
/// claim; it acts only on a polka it has counted itself, so a proposer that
/// lies about `pol_round` achieves nothing. Keeping it out of the preimage is
/// what lets the signed message stay the frozen 48-byte [`VoteMsg`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proposal {
    /// The height being proposed for.
    pub height: u64,
    /// The round being proposed in.
    pub round: u32,
    /// The proposed block.
    pub block_hash: BlockHash,
    /// The round of a polka the proposer claims to have seen, if any.
    pub pol_round: Option<u32>,
    /// Index of the proposing validator.
    pub proposer: u16,
    /// BIP-340 signature over [`proposal_digest`].
    pub signature: Signature,
}

impl Proposal {
    /// The vote this proposal is signed over.
    pub fn vote(&self, chain_id: ChainId) -> VoteMsg {
        VoteMsg::new(chain_id, self.height, self.round, self.block_hash)
    }

    /// Sign a proposal.
    pub fn sign(
        key: &SecretKey,
        chain_id: ChainId,
        proposer: u16,
        height: u64,
        round: u32,
        block_hash: BlockHash,
        pol_round: Option<u32>,
    ) -> Self {
        let vote = VoteMsg::new(chain_id, height, round, block_hash);
        Proposal {
            height,
            round,
            block_hash,
            pol_round,
            proposer,
            signature: key.sign_deterministic(&proposal_digest(&vote)),
        }
    }

    /// Verify the signature of the proposing validator.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::ValidatorIndexOutOfRange`] and
    /// [`ConsensusError::BadCommitSignature`].
    pub fn verify(&self, chain_id: ChainId, set: &ValidatorSet) -> Result<(), ConsensusError> {
        set.verify(self.proposer, &proposal_digest(&self.vote(chain_id)), &self.signature)
    }
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
