//! The certified-chain reader: committed Sumeragi blocks as their Kura frames certify them
//! (`specs/sumeragi.md` §12.7).
//!
//! Kura holds one frame per committed height: the result-bearing iroha block and its
//! [`CommitCertificate`] — the canonical core [`BlockHeader`], the `CommitQC` and the preimage of
//! the certified result `R` ([`CertifiedResultV1`], the fixed `X` and its execution body). Genesis carries a result-only
//! certificate (no header, no `CommitQC`). Its signed body and registered authority are the
//! network-pinned trust root. The result-only execution preimage is added after genesis executes;
//! genesis signatures do not authenticate that preimage. An exact-quorum successor authenticates
//! `R_g` through its signed `parent_result`; a genesis-only result requires local deterministic
//! execution trust or a separately authenticated replay anchor.
//!
//! The reader offers three reads with explicit authority sources:
//!
//! - [`committed_block`]: **consensus-visible data only**, authenticated by the
//!   original native execution tip captured in the same State publication generation.
//!   A bounded reverse walk checks native `parent_hash`, `parent_result` and the
//!   Iroha parent hash before interpreting the requested result. The tip is issued
//!   only by the original verified worker (or original signed-genesis execution),
//!   outside World to avoid an R self-reference. Snapshot claims are verified
//!   against an actual certified native prefix before this authority is restored.
//!   Local `CommitQC` bytes are never decoded by this deterministic path: honest
//!   nodes may retain different valid exact quorums for the same header and R.
//!   Hash journals and structural frame decoding alone grant no execution authority.
//! - [`CertifiedChain::certified`]: the committed read **plus the local `CommitQC`**. The
//!   certificate must certify exactly this header and result (kind, height, block hash, result,
//!   instance) and verify under the exact BLS quorum of the committee of its height.
//!   Native finality also requires
//!   the authenticated result, schedule and signed availability; signatures alone are insufficient.
//! - [`CertifiedChain::certified_from_execution`]: the same full certificate checks
//!   anchored through the captured original native execution tip. A bounded reverse
//!   walk authenticates the target and its parent; the parent's executed schedule
//!   supplies the target authority. This State-only read refuses genesis and
//!   unanchored/offline sources. It charges each frame before I/O under one retained
//!   allocation scope, avoiding repeated genesis-prefix decoding for recent queries.
//!
//! **Epoch authority.** Every result retains its complete native epoch and schedule graph.
//! The reader verifies the prefix iteratively from the signed genesis context, checks both
//! parent links and the parent result at every height, and carries a bounded schedule plus
//! active authority. Chain parameters retain lag two; a successor authority is admitted only
//! after the incumbent exact quorum certifies the boundary. Every signature
//! binds the scheduling epoch and complete context identity. The preceding certified pulse
//! supplies fresh leader randomness, even when an authority generation is retained.
//! Missing, reordered or invalid authority fails closed even after that committee has rotated
//! out of World. There is no trust-in-local-storage certificate verdict.
//!
//! **Chains.** [`CertifiedChain::walk`] reads consecutive heights and additionally checks that
//! each block extends the previous one: its core header binds the parent's block hash and `R`,
//! and its iroha header the parent's iroha hash.
//!
//! **Resumable proof production.** The finite proof producer retains a bounded node-local
//! ladder of completed prefixes (frame identity, schedule, authority and source fence at a
//! height). A later walk re-reads that exact pinned frame and continues from it, so a proof
//! costs work proportional to its distance from the nearest retained height rather than
//! to its height. Ordinary reads keep their own constant-size cursor and genesis restart.
//!
//! **Restoration.** `CertifiedChain::from_pinned` runs this same verifier before a State exists,
//! against an explicit network, configured chain instance and exact committed hash cut. It
//! accepts no World authority. Each body is checked against the cut before its prefix is
//! authenticated; the lone-genesis execution trust limitation is unchanged.
//!
//! **Local attempts.** Reader failures separate completed [`ChainReadError`] rejections from
//! non-wire [`ExecutionAttemptError::Deferred`] outcomes. Original decoder refusals are
//! classified before diagnostics erase their surviving caller limits. A partial decoder is
//! dropped; retry uses the same captured State and original source bytes. This does not fund
//! the entire decoded graph or invent an allocation-pool release notification.

use std::{num::NonZeroUsize, sync::Arc};

use iroha_crypto::{Hash, HashOf, PublicKey as IrohaPublicKey};
use iroha_data_model::{
    block::{
        BlockHeader as IrohaHeader, CommitCertificate, SignedBlock,
        consensus::{HeightContextId, SumeragiRootScope},
        proofs::{
            TrustedBlockProofAnchor, TrustedBlockProofAnchorError, TrustedExecutionOutputAnchor,
        },
    },
    sumeragi::epoch::ValidatorEpochContextV1,
    sumeragi_finality::{CertifiedResultError, CertifiedResultV1, EpochValidationScope},
    transaction::TransactionEntrypoint,
};
use iroha_sumeragi::{
    crypto::CertError,
    message::{BlockHeader, Qc, VoteKind},
    preimage::TAG_PAY,
    types::{Committee, EpochId, Hash32},
};

use super::{
    commitment::{ExecutionResultCommitment, result_of_preimage},
    crypto::{BlsCrypto, core_key},
    schedule,
    startup::{GENESIS_HEIGHT, core_hash_of},
};
use crate::{
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred, norito_decode_attempt_error},
    kura::Kura,
    state::{StateReadOnly, StateView},
};
use iroha_data_model::NetworkId;
use iroha_model_base::chain::ChainId;

// Independent ceiling shared by portable verification and funded proposal acquisition.
const MAX_PROPOSAL_BYTES: usize = 64 * 1024 * 1024;

mod amx_initialization;
pub(in crate::sumeragi) mod artifacts;
mod native_acquisition;
mod prefix_checkpoints;
mod retained_query_authority;
pub(crate) use retained_query_authority::QueryCacheOwner;
use retained_query_authority::{PrefixAuthority, QueryAuthorityReservation};
#[cfg(test)]
pub(crate) use retained_query_authority::{
    query_authority_shell_layout, with_refused_query_authority_shell,
};
mod query_reader;
pub(crate) use amx_initialization::AmxChainInitialization;
pub(crate) use native_acquisition::NativeCarrierAcquisition;
pub(crate) use prefix_checkpoints::{FinalityPrefixCheckpoints, PrefixCheckpoint};
mod terminal_selection;
pub(crate) use artifacts::PrefixArtifacts;
pub(super) use artifacts::{PrefixArtifactsError, PrefixArtifactsRead};

/// Domain tag of a certified block id: `H(tag ‖ block_hash ‖ R)`.
pub const CERTIFIED_BLOCK_ID_TAG: &[u8] = b"iroha/sumeragi/certified-block/v1";

/// Why a committed height could not be read or verified. Every variant is local: a missing
/// height, a view/Kura disagreement, local corruption or a certificate that does not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainReadError {
    /// The height is zero or above this view's committed height.
    #[error("height {height} is not committed in this view")]
    NotCommitted {
        /// Requested height.
        height: u64,
    },
    /// Kura does not hold the block this view committed at the height.
    #[error("Kura does not hold the block this view committed at {height}")]
    NotInView {
        /// Requested height.
        height: u64,
    },
    /// The block carries no commit certificate.
    #[error("the block at {height} carries no commit certificate")]
    MissingCertificate {
        /// Requested height.
        height: u64,
    },
    /// A certificate part is not one canonical frame, or has the wrong shape.
    #[error("the commit certificate at {height} is malformed: {reason}")]
    Malformed {
        /// Requested height.
        height: u64,
        /// What is wrong.
        reason: String,
    },
    /// The certified header or `CommitQC` does not belong to the stored block at this height.
    #[error("the certified header does not match the block at {height}")]
    HeaderMismatch {
        /// Requested height.
        height: u64,
    },
    /// The result preimage does not hash to the certified result.
    #[error("the result preimage at {height} does not hash to the certified result")]
    ResultMismatch {
        /// Requested height.
        height: u64,
    },
    /// The certified result does not commit the stored result-bearing block.
    #[error("the certified result at {height} does not commit the stored block")]
    ExecutionMismatch {
        /// Requested height.
        height: u64,
    },
    /// The certificate names another chain instance.
    #[error("the block at {height} is certified for another chain instance")]
    WrongInstance {
        /// Requested height.
        height: u64,
    },
    /// The block does not extend the block before it.
    #[error("the block at {height} does not extend its parent")]
    Discontinuous {
        /// Requested height.
        height: u64,
    },
    /// Kura's genesis is not this view's network genesis.
    #[error("Kura's genesis is not this view's network genesis")]
    ForeignGenesis,
    /// The committee of the height cannot be formed.
    #[error("no committee for height {height}: {reason}")]
    Committee {
        /// Requested height.
        height: u64,
        /// What is wrong.
        reason: String,
    },
    /// The `CommitQC` does not verify under the committee of its height.
    #[error("the commit certificate at {height} does not verify: {error:?}")]
    Certificate {
        /// Requested height.
        height: u64,
        /// The failed check.
        error: CertError,
    },
}

// Keep the committed-source failure typed across the portable data-model boundary.
// Local allocation/admission errors never pass through this conversion.
impl From<ChainReadError> for iroha_data_model::sumeragi_finality::ScheduleSourceError {
    fn from(error: ChainReadError) -> Self {
        match error {
            ChainReadError::NotCommitted { height } => Self::NotCommitted { height },
            ChainReadError::NotInView { height } => Self::NotInView { height },
            ChainReadError::MissingCertificate { height } => Self::MissingCertificate { height },
            ChainReadError::Malformed { height, reason } => Self::Malformed { height, reason },
            ChainReadError::HeaderMismatch { height } => Self::HeaderMismatch { height },
            ChainReadError::ResultMismatch { height } => Self::ResultMismatch { height },
            ChainReadError::ExecutionMismatch { height } => Self::ExecutionMismatch { height },
            ChainReadError::WrongInstance { height } => Self::WrongInstance { height },
            ChainReadError::Discontinuous { height } => Self::Discontinuous { height },
            ChainReadError::ForeignGenesis => Self::ForeignGenesis,
            ChainReadError::Committee { height, reason } => Self::Committee { height, reason },
            ChainReadError::Certificate { height, error } => Self::Certificate { height, error },
        }
    }
}

impl From<ChainReadError> for iroha_data_model::sumeragi_finality::ScheduleError {
    fn from(error: ChainReadError) -> Self {
        Self::CommittedSource(error.into())
    }
}

#[derive(Clone, Debug)]
enum PrefixHeader {
    Decoded(BlockHeader),
    Funded(artifacts::metadata::FundedMetadata<BlockHeader>),
}
impl core::ops::Deref for PrefixHeader {
    type Target = BlockHeader;
    fn deref(&self) -> &BlockHeader {
        match self {
            Self::Decoded(value) => value,
            Self::Funded(value) => value,
        }
    }
}

/// The consensus-visible receipt of a committed height: identical on every honest node, derived
/// from the stored block, its core header and its result preimage (never from the `CommitQC`).
#[derive(Clone, Debug)]
pub struct CommittedBlock {
    height: u64,
    block: iroha_data_model::block::SharedSignedBlock,
    header: Option<PrefixHeader>,
    core_hash: Hash32,
    result: Hash32,
    certified_result: CertifiedResultV1,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
}

impl CommittedBlock {
    /// The one-based height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// The committed result-bearing iroha block as Kura stores it. Its
    /// [`commit_certificate`](SignedBlock::commit_certificate) is node-local: deterministic code
    /// must not read it.
    #[must_use]
    pub fn block(&self) -> &iroha_data_model::block::SharedSignedBlock {
        &self.block
    }

    /// The iroha block hash.
    #[must_use]
    pub fn block_hash(&self) -> HashOf<IrohaHeader> {
        self.block.hash()
    }

    /// The certified core header (`None` for genesis).
    #[must_use]
    pub fn header(&self) -> Option<&BlockHeader> {
        self.header.as_deref()
    }

    /// The core block hash: the hash of the core header, or the iroha hash bytes for genesis.
    #[must_use]
    pub fn core_hash(&self) -> Hash32 {
        self.core_hash
    }

    /// The certified execution result `R`.
    #[must_use]
    pub fn result(&self) -> Hash32 {
        self.result
    }

    /// The decoded execution body within the certified `X ‖ body` preimage.
    #[must_use]
    pub fn commitment(&self) -> &ExecutionResultCommitment {
        self.certified_result.commitment()
    }

    /// Original finality header and body checked under this receipt's selected root.
    #[must_use]
    pub fn certified_result(&self) -> &CertifiedResultV1 {
        &self.certified_result
    }

    /// Immutable scope selected by the native reader's authenticated genesis owner.
    #[must_use]
    pub const fn root_scope(&self) -> iroha_data_model::block::consensus::SumeragiRootScope {
        self.root_scope
    }

    /// The certified block id `H(CERTIFIED_BLOCK_ID_TAG ‖ core_hash ‖ R)`: what a `CommitQC` of
    /// this height certifies, as one identifier. Signer floors and proofs pin it in their
    /// `context_id` fields (the data-model field keeps that name until the wire cleanup).
    #[must_use]
    pub fn id(&self) -> HeightContextId {
        certified_block_id(&self.core_hash, &self.result)
    }

    /// The block time in milliseconds.
    #[must_use]
    pub fn block_time_ms(&self) -> u64 {
        u64::try_from(self.block.header().creation_time().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether `self` directly extends `parent`: consecutive heights, the core header binds the
    /// parent's block hash and `R`, and the iroha header the parent's iroha hash.
    #[must_use]
    pub fn extends(&self, parent: &Self) -> bool {
        self.extends_link(
            parent.height,
            &parent.block,
            parent.core_hash,
            parent.result,
        )
    }

    // The sole parent-link predicate needs the original block identity and receipt
    // scalars, not a copy of the parent's complete decoded execution/schedule graph.
    fn extends_link(
        &self,
        parent_height: u64,
        parent_block: &iroha_data_model::block::SharedSignedBlock,
        parent_core_hash: Hash32,
        parent_result: Hash32,
    ) -> bool {
        parent_height.checked_add(1) == Some(self.height)
            && self.block.header().prev_block_hash() == Some(parent_block.hash())
            && self.header.as_ref().is_some_and(|header| {
                header.parent_hash == parent_core_hash && header.parent_result == parent_result
            })
    }

    /// The inclusion anchor of the network entrypoint `entry_hash`, bound to the executed wire
    /// that `R` commits.
    ///
    /// # Errors
    /// The entry is absent or the block's Merkle material is inconsistent.
    pub fn entry_anchor(
        &self,
        entry_hash: &HashOf<TransactionEntrypoint>,
    ) -> Result<TrustedBlockProofAnchor, TrustedBlockProofAnchorError> {
        let execution = &self.commitment().execution;
        TrustedBlockProofAnchor::from_committed_execution(
            &self.block,
            execution.executed_block_wire_len,
            execution.executed_block_wire_hash,
            entry_hash,
        )
    }

    /// The anchor of the typed output at `output_index`, bound to the executed wire that `R`
    /// commits.
    ///
    /// # Errors
    /// The output is absent or the block's Merkle material is inconsistent.
    pub fn output_anchor(
        &self,
        output_index: u32,
    ) -> Result<TrustedExecutionOutputAnchor, TrustedBlockProofAnchorError> {
        let execution = &self.commitment().execution;
        TrustedExecutionOutputAnchor::from_committed_execution(
            &self.block,
            execution.executed_block_wire_len,
            execution.executed_block_wire_hash,
            output_index,
        )
    }
}

// A walk's continuity check retains only the actual original immutable block and
// already-derived link scalars. This private local projection is neither a source
// certificate nor an authority capability; every yielded block is still certified.
struct WalkParentLink {
    height: u64,
    block: iroha_data_model::block::SharedSignedBlock,
    core_hash: Hash32,
    result: Hash32,
}
impl WalkParentLink {
    fn from_committed(parent: &CommittedBlock) -> Self {
        Self {
            height: parent.height,
            block: parent.block.clone(),
            core_hash: parent.core_hash,
            result: parent.result,
        }
    }

    fn is_extended_by(&self, child: &CommittedBlock) -> bool {
        child.extends_link(self.height, &self.block, self.core_hash, self.result)
    }
}

/// `H(CERTIFIED_BLOCK_ID_TAG ‖ block_hash ‖ R)` as the data model's id type.
#[must_use]
pub fn certified_block_id(block_hash: &Hash32, result: &Hash32) -> HeightContextId {
    HeightContextId(HashOf::from_untyped_unchecked(Hash::new_from_chunks(&[
        CERTIFIED_BLOCK_ID_TAG,
        &block_hash.0,
        &result.0,
    ])))
}

/// Read the consensus-visible receipt of the block `view` committed at `height` (see the module
/// documentation). Deterministic: every honest node with the same committed history reads the
/// same receipt, whatever `CommitQC` it stored.
///
/// # Errors
/// The height is not committed, Kura does not hold the view's block, or the frame's header or
/// result preimage does not certify it.
pub fn committed_block(
    view: &(impl StateReadOnly + ?Sized),
    height: u64,
) -> Result<CommittedBlock, ExecutionAttemptError<ChainReadError>> {
    let index = usize::try_from(height)
        .ok()
        .and_then(NonZeroUsize::new)
        .filter(|index| index.get() <= view.block_hashes().len())
        .ok_or(ChainReadError::NotCommitted { height })?;
    view.canonical_history()
        .executed_receipt(index, |_, _| Ok(()))
        .map_err(|error| {
            if cfg!(all(test, sumeragi_core_mutation = "HC43")) {
                return ExecutionAttemptError::Rejected(ChainReadError::Malformed {
                    height,
                    reason: error.to_string(),
                });
            }
            error.map_rejection(|error| ChainReadError::Malformed {
                height,
                reason: error.to_string(),
            })
        })
}

/// Classify the original decoder before any malformed-input diagnostic allocation.
fn read_decode_error(height: u64, error: norito::Error) -> ExecutionAttemptError<ChainReadError> {
    if cfg!(all(test, sumeragi_core_mutation = "HC43")) {
        return ExecutionAttemptError::Rejected(ChainReadError::Malformed {
            height,
            reason: error.to_string(),
        });
    }
    norito_decode_attempt_error(error, |error| ChainReadError::Malformed {
        height,
        reason: error.to_string(),
    })
}

/// Structural interpretation only: the caller must authenticate core hash and R
/// from an original State tip or the full native certificate prefix.
pub(crate) fn read_frame(
    block: iroha_data_model::block::SharedSignedBlock,
    height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
) -> Result<CommittedBlock, ExecutionAttemptError<ChainReadError>> {
    read_frame_with_validation(block, height, root_scope, &mut EpochValidationScope::new())
}

// Shape-validation reuse is private to this exact reader. The complete immutable context must
// match; this scope never stores source, authority, availability or certificate verdicts.
pub(crate) fn read_frame_with_validation(
    block: iroha_data_model::block::SharedSignedBlock,
    height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    validation: &mut EpochValidationScope,
) -> Result<CommittedBlock, ExecutionAttemptError<ChainReadError>> {
    read_prepared_frame(block, height, root_scope, validation, None)
}

// A prepared header comes from the sole certificate metadata decoder of the same carrier;
// the frame is then checked without decoding its header a second time.
fn read_prepared_frame(
    block: iroha_data_model::block::SharedSignedBlock,
    height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    validation: &mut EpochValidationScope,
    prepared: Option<artifacts::metadata::FundedMetadata<BlockHeader>>,
) -> Result<CommittedBlock, ExecutionAttemptError<ChainReadError>> {
    let (header, core_hash) = checked_frame_header(&block, height, prepared)?;
    let certificate = block
        .commit_certificate()
        .ok_or(ChainReadError::MissingCertificate { height })?;
    let result = result_of_preimage(certificate.result_preimage())
        .ok_or(ChainReadError::ResultMismatch { height })?;
    let commitment = CertifiedResultV1::decode_with_validation(
        certificate.result_preimage(),
        root_scope.into(),
        validation,
    )
    .map_err(|error| frame_result_error(height, error))?;
    validate_frame_result(&block, height, header.as_deref(), &commitment, validation)?;
    Ok(CommittedBlock {
        height,
        block,
        header,
        core_hash,
        result,
        certified_result: commitment,
        root_scope,
    })
}

// These three stages retain the original predicate order for both value and placed owners.
fn checked_frame_header(
    block: &SignedBlock,
    height: u64,
    prepared: Option<artifacts::metadata::FundedMetadata<BlockHeader>>,
) -> Result<(Option<PrefixHeader>, Hash32), ExecutionAttemptError<ChainReadError>> {
    #[cfg(test)]
    relation_counts::frame(height);
    let malformed = |reason: String| ChainReadError::Malformed { height, reason };
    // Hashing only: the chain hash `H` needs no admitted key.
    let hasher = BlsCrypto::new();
    let certificate = block
        .commit_certificate()
        .ok_or(ChainReadError::MissingCertificate { height })?;
    let genesis = height == GENESIS_HEIGHT;
    if genesis {
        if !certificate.consensus_header().is_empty()
            || !certificate.commit_qc().is_empty()
            || !certificate.availability().is_empty()
        {
            return Err(malformed("genesis carries a result-only certificate".into()).into());
        }
        Ok((None, core_hash_of(block)))
    } else {
        let header = if let Some(header) = prepared {
            PrefixHeader::Funded(header)
        } else {
            let header: BlockHeader = norito::core::classify_decode_attempt(|| {
                norito::decode_canonical(certificate.consensus_header())
            })
            .map_err(|error| {
                if cfg!(all(test, sumeragi_core_mutation = "HC43")) {
                    return ExecutionAttemptError::Rejected(ChainReadError::Malformed {
                        height,
                        reason: error.to_string(),
                    });
                }
                crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
                    ChainReadError::Malformed {
                        height,
                        reason: error.to_string(),
                    }
                })
            })?;
            PrefixHeader::Decoded(header)
        };
        let payload_len = block
            .resultless_proposal_wire_len()
            .map_err(|error| malformed(error.to_string()))?;
        let payload_hash = Hash::new_from_writer(|writer| {
            writer.write_all(TAG_PAY)?;
            block
                .write_resultless_proposal_wire(writer)
                .map_err(std::io::Error::other)
        })
        .map_err(|error| malformed(error.to_string()))?;
        if certificate.availability().is_empty()
            || header.height != height
            || header.payload_len == 0
            || u32::try_from(payload_len).ok() != Some(header.payload_len)
            || Hash32(*payload_hash.as_ref()) != header.payload_hash
        {
            return Err(ChainReadError::HeaderMismatch { height }.into());
        }
        let core_hash = header.hash(&hasher);
        Ok((Some(header), core_hash))
    }
}

fn frame_result_error(
    height: u64,
    error: CertifiedResultError,
) -> ExecutionAttemptError<ChainReadError> {
    match error {
        CertifiedResultError::Body(super::commitment::CommitmentError::Resource(error)) => {
            if cfg!(all(test, sumeragi_core_mutation = "HC43")) {
                return ExecutionAttemptError::Rejected(ChainReadError::Malformed {
                    height,
                    reason: error.to_string(),
                });
            }
            crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
                ChainReadError::Malformed {
                    height,
                    reason: error.to_string(),
                }
            })
        }
        completed => ExecutionAttemptError::Rejected(ChainReadError::Malformed {
            height,
            reason: completed.to_string(),
        }),
    }
}

fn validate_frame_result(
    block: &SignedBlock,
    height: u64,
    header: Option<&BlockHeader>,
    certified_result: &CertifiedResultV1,
    validation: &mut EpochValidationScope,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    let malformed = |reason: String| ChainReadError::Malformed { height, reason };
    let timestamp_ms = u64::try_from(block.header().creation_time().as_millis())
        .map_err(|_| malformed("block time exceeds u64 milliseconds".into()))?;
    certified_result
        .check_block(height, timestamp_ms)
        .map_err(|error| frame_result_error(height, error))?;
    let commitment = certified_result.commitment();
    if let Some(header) = header {
        super::epoch_beacon::control::verify_result(
            &header.control_witness,
            commitment.beacon.as_ref(),
        )
        .map_err(|error| malformed(error.to_string()))?;
        if commitment.beacon.as_ref().is_some_and(|pulse| {
            pulse.context.instance != header.instance.0
                || pulse.context.epoch != header.epoch.epoch
                || pulse.context.epoch_context_id != header.epoch.context.0
                || pulse.context.parent_consensus_hash != header.parent_hash.0
                || pulse.context.parent_result != header.parent_result.0
        }) {
            return Err(ChainReadError::HeaderMismatch { height }.into());
        }
        let epoch = validation
            .core_epoch(&commitment.schedule.current)
            .map_err(|error| malformed(error.to_string()))?;
        if header.epoch != epoch.id {
            return Err(ChainReadError::HeaderMismatch { height }.into());
        }
    }
    let (wire_len, wire_hash) = block
        .executed_block_wire_identity()
        .map_err(|error| malformed(error.to_string()))?;
    if commitment.height != height
        || block.header().height().get() != height
        || commitment.execution.executed_block_wire_len != wire_len
        || commitment.execution.executed_block_wire_hash != wire_hash
    {
        return Err(ChainReadError::ExecutionMismatch { height }.into());
    }
    if commitment.beacon.as_ref().is_some_and(|pulse| {
        Some(pulse.finalized_chain_anchor.block_hash) != block.header().prev_block_hash()
    }) {
        return Err(malformed("beacon pulse names another committed parent".into()).into());
    }
    Ok(())
}

pub(crate) fn admit_verification_slot<T>(
    budget: &iroha_allocation::AllocationBudget,
) -> Result<iroha_allocation::ChargedBuffer<T>, ExecutionAttemptError<ChainReadError>> {
    iroha_allocation::ChargedBuffer::<T>::new(1, budget).map_err(|error| match error {
        iroha_allocation::ChargedBufferError::Admission(refusal) => {
            ExecutionAttemptError::Deferred(refusal.into())
        }
        original @ iroha_allocation::ChargedBufferError::Allocator { .. } => {
            #[cfg(all(test, sumeragi_core_mutation = "HC954"))]
            {
                let _ = original;
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            }
            #[cfg(not(all(test, sumeragi_core_mutation = "HC954")))]
            ExecutionAttemptError::Deferred(retained_query_authority::buffer_refusal(original))
        }
    })
}

// Vec reclamation precedes its original charge on every normal/unwind path.
struct VerificationSlotTransfer<T> {
    values: Vec<T>,
    _charge: iroha_allocation::AllocationCharge,
}

#[cfg(test)]
#[test]
fn admitted_slot_allocator_refusal_keeps_original_physical_cause() {
    let layout = std::alloc::Layout::array::<CommittedBlock>(1).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(layout.size());
    let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
        admit_verification_slot::<CommittedBlock>(&budget)
    });
    assert!(refused);
    let ExecutionAttemptError::Deferred(error) = result.err().expect("physical slot refusal")
    else {
        panic!("physical failure remains local");
    };
    assert_eq!(
        error.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(error.allocation_refusal().is_none());
    assert!(
        matches!(error.allocator_refusal().and_then(|original| original.buffer_error()),
        Some(iroha_allocation::ChargedBufferError::Allocator { requested_bytes }) if *requested_bytes == layout.size()),
        "HC954 admitted frame allocator refusal retains its original physical cause"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let retry = admit_verification_slot::<CommittedBlock>(&budget).unwrap();
    assert!(retry.belongs_to(&budget));
    drop(retry);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Move the sole initialized element without returning its large value through this stack.
/// The caller supplies a distinct aligned, prepaid destination and exposes it only after
/// all of its fields are initialized. This seam changes no allocation or pool authority.
///
/// # Safety
/// `source` contains exactly one fully initialized element; `destination` is a distinct
/// aligned uninitialized slot for that same type. Neither value is observed or dropped
/// between copying and clearing the moved source prefix.
#[allow(
    unsafe_code,
    reason = "the original Vec/charge remain one drop-ordered owner while its sole valid element moves into the distinct prepaid destination"
)]
unsafe fn transfer_verification_slot<T>(
    source: iroha_allocation::ChargedBuffer<T>,
    destination: *mut T,
) {
    // SAFETY: the caller retains this exact original backing in the move-only guard below.
    // Guard construction cannot fail or allocate. Its Vec is destroyed before its charge;
    // neither field can be extracted or replaced through a safe interface.
    let (values, charge) = unsafe { source.into_allocation_parts() };
    let mut original = VerificationSlotTransfer {
        values,
        _charge: charge,
    };
    // SAFETY: the caller establishes one initialized source and a disjoint destination.
    // No fallible work or destructor runs between this move and clearing the source len.
    // The empty backing then reclaims before its original charge refunds.
    unsafe {
        std::ptr::copy_nonoverlapping(original.values.as_ptr(), destination, 1);
        original.values.set_len(0);
    }
}

#[cfg(test)]
#[test]
#[allow(
    unsafe_code,
    reason = "the control initializes one distinct test destination with the audited transfer, then drops that moved value exactly once"
)]
fn admitted_slot_transfer_reclaims_original_backing_without_dropping_moved_value() {
    use std::{
        alloc::Layout,
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct DropTracked(Arc<AtomicUsize>);
    impl Drop for DropTracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct CompleteReceipt {
        first: DropTracked,
        moved: DropTracked,
    }
    let source_bytes = Layout::array::<DropTracked>(1).unwrap().size();
    let destination_bytes = Layout::array::<CompleteReceipt>(1).unwrap().size();
    let budget = iroha_allocation::AllocationBudget::new(source_bytes + destination_bytes);
    let moved_drops = Arc::new(AtomicUsize::new(0));
    let first_drops = Arc::new(AtomicUsize::new(0));
    let mut source = iroha_allocation::ChargedBuffer::new(1, &budget).unwrap();
    source.push_reserved(DropTracked(Arc::clone(&moved_drops)));
    let mut destination =
        iroha_allocation::ChargedBuffer::<CompleteReceipt>::new(1, &budget).unwrap();
    assert!(source.belongs_to(&budget) && destination.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), source_bytes + destination_bytes);
    assert_eq!(source.as_slice().len(), 1);
    assert_eq!(destination.capacity(), 1);
    assert_eq!(destination.as_slice().len(), 0);
    let pointer = destination.spare_capacity_mut()[0].as_mut_ptr();
    // SAFETY: the destination is aligned and prepaid with one empty CompleteReceipt slot.
    // Writing first cannot fail; the exact source is one disjoint valid value. The transfer
    // leaves the original source Vec empty before reclamation. Both destination fields are
    // complete when its known capacity-one/length-zero owner exposes length one.
    unsafe {
        std::ptr::addr_of_mut!((*pointer).first).write(DropTracked(Arc::clone(&first_drops)));
        transfer_verification_slot(source, std::ptr::addr_of_mut!((*pointer).moved));
        destination.set_initialized_len(1);
    }
    assert_eq!(budget.reserved_bytes(), destination_bytes);
    assert_eq!(moved_drops.load(Ordering::SeqCst), 0);
    assert_eq!(first_drops.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(
        &destination.as_slice()[0].first.0,
        &first_drops
    ));
    assert!(Arc::ptr_eq(
        &destination.as_slice()[0].moved.0,
        &moved_drops
    ));
    let retry = iroha_allocation::ChargedBuffer::<DropTracked>::new(1, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), source_bytes + destination_bytes);
    drop(retry);
    assert_eq!(budget.reserved_bytes(), destination_bytes);
    drop(destination);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(moved_drops.load(Ordering::SeqCst), 1);
    assert_eq!(first_drops.load(Ordering::SeqCst), 1);
}

// Only this producer holds the decoder's large result return value. Its consumer receives
// a small charged handle, so no complete result temporary occupies that caller's stack.
#[allow(
    unsafe_code,
    reason = "the complete decoded result is moved into one aligned prepaid slot before exposing its initialized length"
)]
fn initialize_frame_result_admitted(
    original: &mut iroha_allocation::ChargedBuffer<CertifiedResultV1>,
    preimage: &[u8],
    height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    validation: &mut EpochValidationScope,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    if !original.as_slice().is_empty() {
        return Ok(());
    }
    CertifiedResultV1::decode_with_validation_into(
        preimage,
        root_scope.into(),
        validation,
        |value| {
            // SAFETY: one aligned result slot was prepaid. The sole decoder invokes this owner
            // only after complete validation. Neither write nor initialized-length publication
            // allocates, drops or exposes partial fields. Failure leaves the same empty slot.
            unsafe {
                original.spare_capacity_mut()[0].as_mut_ptr().write(value);
                original.set_initialized_len(1);
            }
        },
    )
    .map_err(|error| frame_result_error(height, error))
}

// The original prepaid backing is initialized only after every frame check succeeds.
#[allow(
    unsafe_code,
    reason = "distinct fields of an exact prepaid slot are written after complete verification; no incomplete receipt is exposed or dropped"
)]
fn initialize_frame_admitted(
    original: &mut iroha_allocation::ChargedBuffer<CommittedBlock>,
    result_slot: &mut Option<iroha_allocation::ChargedBuffer<CertifiedResultV1>>,
    block: iroha_data_model::block::SharedSignedBlock,
    height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    validation: &mut EpochValidationScope,
    budget: &iroha_allocation::AllocationBudget,
    prepared: Option<artifacts::metadata::FundedMetadata<BlockHeader>>,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    if !original.as_slice().is_empty() {
        return Ok(());
    }
    let (header, core_hash) = checked_frame_header(&block, height, prepared)?;
    let certificate = block
        .commit_certificate()
        .ok_or(ChainReadError::MissingCertificate { height })?;
    let result = result_of_preimage(certificate.result_preimage())
        .ok_or(ChainReadError::ResultMismatch { height })?;
    if result_slot.is_none() {
        *result_slot = Some(admit_verification_slot::<CertifiedResultV1>(budget)?);
    }
    let commitment = result_slot.as_mut().expect("original result slot retained");
    initialize_frame_result_admitted(
        commitment,
        certificate.result_preimage(),
        height,
        root_scope,
        validation,
    )?;
    validate_frame_result(
        &block,
        height,
        header.as_deref(),
        &commitment.as_slice()[0],
        validation,
    )?;
    let pointer = original.spare_capacity_mut()[0].as_mut_ptr();
    let commitment = result_slot.take().expect("complete original result slot");
    // SAFETY: one aligned CommittedBlock slot was prepaid. Every fallible predicate
    // finished above. These moves neither allocate nor invoke drop. The complete result
    // moves from its original charged backing, whose length is immediately cleared to
    // prevent a second drop; the charge survives until its empty backing is released.
    unsafe {
        std::ptr::addr_of_mut!((*pointer).height).write(height);
        std::ptr::addr_of_mut!((*pointer).root_scope).write(root_scope);
        std::ptr::addr_of_mut!((*pointer).block).write(block);
        std::ptr::addr_of_mut!((*pointer).header).write(header);
        std::ptr::addr_of_mut!((*pointer).core_hash).write(core_hash);
        std::ptr::addr_of_mut!((*pointer).result).write(result);
        transfer_verification_slot(
            commitment,
            std::ptr::addr_of_mut!((*pointer).certified_result),
        );
        original.set_initialized_len(1);
    }
    Ok(())
}

// Each original verification slot remains owned by its actual read operation until
// complete transfer or operation retirement. A later admission refusal cannot refund
// an earlier slot and thereby satisfy the same operation's returned release wait.
#[derive(Default)]
struct AdmittedFrameRead {
    committed: Option<iroha_allocation::ChargedBuffer<CommittedBlock>>,
    result: Option<iroha_allocation::ChargedBuffer<CertifiedResultV1>>,
    source: Option<iroha_data_model::block::SharedSignedBlock>,
    budget: Option<iroha_allocation::AllocationBudget>,
    scope: Option<SumeragiRootScope>,
}
impl AdmittedFrameRead {
    fn initialize(
        &mut self,
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        validation: &mut EpochValidationScope,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        self.initialize_prepared(block, height, root_scope, validation, budget, None)
    }

    fn initialize_prepared(
        &mut self,
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
        root_scope: SumeragiRootScope,
        validation: &mut EpochValidationScope,
        budget: &iroha_allocation::AllocationBudget,
        prepared: Option<artifacts::metadata::FundedMetadata<BlockHeader>>,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        #[cfg(not(all(test, sumeragi_core_mutation = "HC952")))]
        if self
            .budget
            .as_ref()
            .is_some_and(|original| !original.same_pool(budget))
        {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC952"))]
        let _ = &self.budget;
        // A retained slot binds one exact carrier and scope. A different carrier, even one
        // re-read from Kura with identical bytes, is a local custody fault like a foreign
        // pool: its verdict must never depend on pointer identity.
        let foreign_retained = self.source.as_ref().is_some_and(|original| {
            !iroha_data_model::block::SharedSignedBlock::ptr_eq(original, &block)
        }) || self.scope.is_some_and(|original| original != root_scope);
        #[cfg(all(test, sumeragi_core_mutation = "HC962"))]
        if foreign_retained {
            return Err(ChainReadError::HeaderMismatch { height }.into());
        }
        if foreign_retained {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        if block.header().height().get() != height {
            return Err(ChainReadError::HeaderMismatch { height }.into());
        }
        if self.source.is_none() {
            self.source = Some(block.clone());
            self.budget = Some(budget.clone());
            self.scope = Some(root_scope);
        }
        if self.committed.is_none() {
            self.committed = Some(admit_verification_slot::<CommittedBlock>(budget)?);
        }
        initialize_frame_admitted(
            self.committed
                .as_mut()
                .expect("original frame slot retained"),
            &mut self.result,
            block,
            height,
            root_scope,
            validation,
            budget,
            prepared,
        )
    }

    fn committed(&self) -> &CommittedBlock {
        &self
            .committed
            .as_ref()
            .expect("original frame initialized")
            .as_slice()[0]
    }

    fn take_committed(&mut self) -> iroha_allocation::ChargedBuffer<CommittedBlock> {
        let committed = self.committed.take().expect("original frame initialized");
        self.source = None;
        self.budget = None;
        self.scope = None;
        committed
    }

    // Both slots of a one-shot reader come from one original reservation. A refusal then
    // happens before this operation owns any slot; a physical failure has no release wait.
    fn admit_slots(
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let mut reservation = budget
            .try_reserve_layouts([
                std::alloc::Layout::array::<CommittedBlock>(1).expect("one receipt slot"),
                std::alloc::Layout::array::<CertifiedResultV1>(1).expect("one result slot"),
            ])
            .map_err(|refusal| ExecutionAttemptError::Deferred(refusal.into()))?;
        let committed = prepaid_verification_slot(&mut reservation)?;
        let result = prepaid_verification_slot(&mut reservation)?;
        Ok(Self {
            committed: Some(committed),
            result: Some(result),
            ..Self::default()
        })
    }
}

fn prepaid_verification_slot<T>(
    reservation: &mut iroha_allocation::AllocationReservation,
) -> Result<iroha_allocation::ChargedBuffer<T>, ExecutionAttemptError<ChainReadError>> {
    iroha_allocation::ChargedBuffer::<T>::from_reservation(1, reservation).map_err(|error| {
        ExecutionAttemptError::Deferred(match error {
            iroha_allocation::PrepaidBufferError::Allocation(original) => {
                retained_query_authority::buffer_refusal(original)
            }
            // The pair was reserved exactly; a short remainder is an internal layout fault.
            iroha_allocation::PrepaidBufferError::Reservation(_) => {
                retained_query_authority::invariant()
            }
        })
    })
}

fn read_frame_admitted(
    block: iroha_data_model::block::SharedSignedBlock,
    height: u64,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    validation: &mut EpochValidationScope,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<iroha_allocation::ChargedBuffer<CommittedBlock>, ExecutionAttemptError<ChainReadError>>
{
    let mut original = AdmittedFrameRead::default();
    original.initialize(block, height, root_scope, validation, budget)?;
    Ok(original.take_committed())
}

/// One complete receipt in exact backing admitted by the original history pool.
/// Nested result graphs and cryptographic scratch retain their separate funding rules.
pub(crate) struct AdmittedCommittedBlock(iroha_allocation::ChargedBuffer<CommittedBlock>);

impl AdmittedCommittedBlock {
    /// Use the existing complete frame decoder and original slot-transfer kernel.
    pub(crate) fn read(
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        validation: &mut EpochValidationScope,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        read_frame_admitted(block, height, root_scope, validation, budget).map(Self)
    }

    /// Move the original receipt only after its full decode has returned.
    /// The empty backing is reclaimed before its charge refunds, including on unwind.
    pub(crate) fn into_owned(mut self) -> CommittedBlock {
        self.0
            .pop()
            .expect("the private admitted reader initialized exactly one receipt")
    }

    #[cfg(test)]
    fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }

    #[cfg(test)]
    fn slot_bytes(&self) -> usize {
        assert_eq!(self.0.capacity(), 1);
        assert_eq!(self.0.as_slice().len(), 1);
        std::alloc::Layout::array::<CommittedBlock>(1)
            .unwrap()
            .size()
    }
}

impl std::ops::Deref for AdmittedCommittedBlock {
    type Target = CommittedBlock;

    fn deref(&self) -> &Self::Target {
        &self.0.as_slice()[0]
    }
}

/// How the local `CommitQC` of a height was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QcVerification {
    /// Genesis body signatures and network identity verified, without a `CommitQC`.
    /// This alone does not authenticate its post-execution result preimage. Consumers needing
    /// independent genesis execution evidence require a verified successor or replay anchor.
    Genesis,
    /// The `CommitQC` verified under the committee of its height.
    Verified,
}

// The funded metadata owner cannot shed charges through receipt sharing. Ordinary
// portable callers retain their existing decoded value; no funded value enters it.
#[derive(Clone, Debug)]
enum PrefixQc {
    Decoded(Qc),
    Funded(artifacts::metadata::FundedMetadata<Qc>),
}
impl core::ops::Deref for PrefixQc {
    type Target = Qc;
    fn deref(&self) -> &Qc {
        match self {
            Self::Decoded(value) => value,
            Self::Funded(value) => value,
        }
    }
}

/// A committed height with its local `CommitQC` checked.
#[derive(Clone, Debug)]
pub struct CertifiedBlock {
    committed: CommittedBlock,
    commit_qc: Option<PrefixQc>,
    verification: QcVerification,
    certificate_len: usize,
}

impl CertifiedBlock {
    /// The consensus-visible receipt.
    #[must_use]
    pub fn committed(&self) -> &CommittedBlock {
        &self.committed
    }

    /// Take the consensus-visible receipt.
    #[must_use]
    pub fn into_committed(self) -> CommittedBlock {
        self.committed
    }

    /// This node's `CommitQC` of the block (`None` for genesis).
    #[must_use]
    pub fn commit_qc(&self) -> Option<&Qc> {
        self.commit_qc.as_deref()
    }

    /// How the `CommitQC` was checked.
    #[must_use]
    pub fn verification(&self) -> QcVerification {
        self.verification
    }

    /// The node-local commit certificate (header, `CommitQC`, result preimage); always present
    /// on a certified read.
    #[must_use]
    pub fn certificate(&self) -> Option<&CommitCertificate> {
        self.committed.block.commit_certificate()
    }

    /// Canonical frame bytes of the certificate, for callers that bound what they read.
    #[must_use]
    pub fn certificate_len(&self) -> usize {
        self.certificate_len
    }
}

impl core::ops::Deref for CertifiedBlock {
    type Target = CommittedBlock;

    fn deref(&self) -> &CommittedBlock {
        &self.committed
    }
}

/// A source failure or refusal owned by the explicitly admitted query verifier.
/// Original local refusal remains separate from completed source rejection even without
/// an explicit query scratch callback.
#[derive(Debug, thiserror::Error)]
enum VerificationReadError {
    #[error(transparent)]
    Source(#[from] ChainReadError),
    #[error(transparent)]
    Deferred(ExecutionDeferred),
}

impl From<ExecutionAttemptError<ChainReadError>> for VerificationReadError {
    fn from(error: ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(error) => Self::Source(error),
            ExecutionAttemptError::Deferred(local) => Self::Deferred(local),
        }
    }
}

fn verification_codec_error(
    height: u64,
    original: norito::core::DecodeAttemptError,
) -> VerificationReadError {
    if cfg!(all(test, sumeragi_core_mutation = "HC43")) {
        return VerificationReadError::Source(ChainReadError::Malformed {
            height,
            reason: original.to_string(),
        });
    }
    crate::execution_attempt::canonical_decode_attempt_error(original, |error| {
        ChainReadError::Malformed {
            height,
            reason: error.to_string(),
        }
    })
    .into()
}

mod funded_authority;
mod funded_availability;

/// A borrowed projection of one already established native authority owner.
/// Construction is private; this type creates neither keys nor authority.
#[derive(Clone, Copy)]
struct AuthorityRef<'a> {
    material: &'a ValidatorEpochContextV1,
    epoch: EpochId,
    committee: &'a Committee,
    crypto: &'a dyn iroha_sumeragi::crypto::Crypto,
}

/// One complete epoch authority. Its crypto owner admits only this roster's original proofs.
struct VerifiedAuthority {
    material: ValidatorEpochContextV1,
    epoch: EpochId,
    committee: Committee,
    crypto: BlsCrypto,
}

impl VerifiedAuthority {
    fn projection(&self) -> AuthorityRef<'_> {
        AuthorityRef {
            material: &self.material,
            epoch: self.epoch,
            committee: &self.committee,
            crypto: &self.crypto,
        }
    }

    fn new(
        material: ValidatorEpochContextV1,
        height: u64,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, ChainReadError> {
        Self::with_crypto(material, height, BlsCrypto::new(), validation)
    }

    fn with_crypto(
        material: ValidatorEpochContextV1,
        height: u64,
        crypto: BlsCrypto,
        validation: &mut EpochValidationScope,
    ) -> Result<Self, ChainReadError> {
        let malformed = |reason: String| ChainReadError::Committee { height, reason };
        let epoch = validation
            .core_epoch(&material)
            .map_err(|error| malformed(error.to_string()))?
            .id;
        let keys = material
            .committee
            .iter()
            .map(|member| core_key(member.validator.public_key()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| malformed(error.to_string()))?;
        let committee =
            schedule::global_committee(keys).map_err(|error| malformed(error.to_string()))?;
        crypto
            .admit_committee(material.committee.iter().map(|member| {
                (
                    member.validator.public_key(),
                    member.proof_of_possession.as_slice(),
                )
            }))
            .map_err(|(index, error)| malformed(format!("member {index}: {error}")))?;
        Ok(Self {
            material,
            epoch,
            committee,
            crypto,
        })
    }
}

/// Constant-size cursor: one committed parent, the bounded native schedule and active authority.
/// A sequential walk verifies each height once; older random reads replay from signed genesis.
struct VerifiedPrefix {
    tip: CommittedBlock,
    schedule: schedule::ConsensusSchedule,
    authority: PrefixAuthority,
    // Bounded exact-value structural reuse ends when this cursor is reset or dropped.
    validation: EpochValidationScope,
    // An opt-in local byte fence, never a consensus digest or wire field.
    proof_source: Option<Hash>,
}

// This constant-size, ordered, certificate-inclusive local source fence is never
// serialized, persisted or accepted as finality authority. The sole native verifier
// authenticates each appended receipt; fresh source bytes only govern cursor reuse.
/// Initial value of the local, non-wire canonical-source fence.
pub(crate) fn proof_source_start() -> Hash {
    Hash::new(b"native canonical proof source prefix")
}

/// Extend the local source fence with one ordered, exact canonical native frame.
pub(crate) fn proof_source_append(previous: Hash, height: u64, length: u64, wire: Hash) -> Hash {
    let mut fields = [0_u8; 80];
    fields[..32].copy_from_slice(previous.as_ref());
    fields[32..40].copy_from_slice(&height.to_le_bytes());
    fields[40..48].copy_from_slice(&length.to_le_bytes());
    fields[48..].copy_from_slice(wire.as_ref());
    Hash::new(fields)
}

// A verdict owns only the actual decoded certificate; no result/body graph is cloned.
struct CertificateVerdict {
    commit_qc: Option<PrefixQc>,
    verification: QcVerification,
    certificate_len: usize,
}
impl CertificateVerdict {
    fn into_certified(self, committed: CommittedBlock) -> CertifiedBlock {
        CertifiedBlock {
            committed,
            commit_qc: self.commit_qc,
            verification: self.verification,
            certificate_len: self.certificate_len,
        }
    }
}

// Construction proves all fallible successor checks completed. Only private source owners
// can consume this state to install a gap or deliver a terminal original target.
struct PreparedAdvance {
    certificate: CertificateVerdict,
    schedule: schedule::ConsensusSchedule,
    authority: PrefixAuthority,
    proof_source: Option<Hash>,
}

// Structural frame readers retain X and check C1–C5 without conferring scope authority.
// Only the original signed genesis selects whether an active X is permitted. This check
// borrows the same decoded owner and never repeats body decoding or epoch validation.
fn check_result_scope(
    committed: &CommittedBlock,
    root_scope: SumeragiRootScope,
) -> Result<(), ChainReadError> {
    if root_scope != SumeragiRootScope::Global && committed.certified_result().header().is_active()
    {
        return Err(ChainReadError::Malformed {
            height: committed.height,
            reason: CertifiedResultError::ActiveOutsideGlobal.to_string(),
        });
    }
    Ok(())
}

/// One crypto context for both random pinned reads and one-pass externally streamed evidence.
struct PrefixVerifierContext {
    instance: Hash32,
    root_scope: SumeragiRootScope,
}
impl PrefixVerifierContext {
    fn advance_prefix(
        &self,
        prefix: &mut VerifiedPrefix,
        committed: CommittedBlock,
        artifacts: Option<PrefixArtifacts>,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        let prepared = self.prepare_advance(prefix, &committed, artifacts)?;
        Ok(Self::install_advance(prefix, committed, prepared))
    }

    // All fallible native checks have completed; both retained and one-shot callers use
    // this same publication step and preserve the ordinary returned-receipt semantics.
    fn install_advance(
        prefix: &mut VerifiedPrefix,
        committed: CommittedBlock,
        prepared: PreparedAdvance,
    ) -> CertifiedBlock {
        let certified = prepared.certificate.into_certified(committed);
        // The ordinary returned-receipt API keeps its existing independently retained tip.
        // Terminal AMX selection instead moves the original gap into this same cursor.
        prefix.tip = certified.committed.clone();
        prefix.schedule = prepared.schedule;
        prefix.authority = prepared.authority;
        prefix.proof_source = prepared.proof_source;
        certified
    }

    // Sole fallible successor verifier. The source owner lends its original graph and does
    // not surrender it until every certificate, availability, boundary and schedule check
    // succeeds. This preserves the ordinary reader's predicate and refusal ordering.
    fn prepare_advance(
        &self,
        prefix: &mut VerifiedPrefix,
        committed: &CommittedBlock,
        artifacts: Option<PrefixArtifacts>,
    ) -> Result<PreparedAdvance, ExecutionAttemptError<ChainReadError>> {
        self.prepare_advance_with_funding(prefix, committed, artifacts, false, None, None, None)
    }

    fn prepare_advance_query(
        &self,
        prefix: &mut VerifiedPrefix,
        committed: &CommittedBlock,
        artifacts: Option<PrefixArtifacts>,
        cache: Option<&mut QueryCacheOwner>,
    ) -> Result<PreparedAdvance, ExecutionAttemptError<ChainReadError>> {
        self.prepare_advance_with_funding(prefix, committed, artifacts, true, cache, None, None)
    }

    fn prepare_advance_with_funding(
        &self,
        prefix: &mut VerifiedPrefix,
        committed: &CommittedBlock,
        artifacts: Option<PrefixArtifacts>,
        query: bool,
        cache: Option<&mut QueryCacheOwner>,
        budget: Option<&iroha_allocation::AllocationBudget>,
        pending_authority: Option<
            &mut Option<iroha_allocation::ChargedShared<funded_authority::FundedPrefixAuthority>>,
        >,
    ) -> Result<PreparedAdvance, ExecutionAttemptError<ChainReadError>> {
        let height = committed.height;
        if committed.root_scope != prefix.tip.root_scope || !committed.extends(&prefix.tip) {
            return Err(ChainReadError::Discontinuous { height }.into());
        }
        let malformed = |reason: String| ChainReadError::Committee { height, reason };
        let scheduled = prefix
            .schedule
            .ready(height)
            .map_err(|error| malformed(error.to_string()))?;
        #[cfg(all(test, sumeragi_core_mutation = "HC953"))]
        let same_parameters = true;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC953")))]
        let same_parameters = prefix
            .authority
            .funded_config()
            .is_none_or(|config| config.params == scheduled.params.to_core());
        let authority = if &scheduled.epoch == prefix.authority.material() && same_parameters {
            Clone::clone(&prefix.authority)
        } else if let Some(budget) = budget {
            let retained = if let Some(pending) = pending_authority {
                if let Some(original) = pending.as_ref() {
                    if !original.belongs_to(budget)
                        || !funded_authority::FundedPrefixAuthority::belongs_to(original, budget)
                        || original.projection().material != &scheduled.epoch
                        || original.config().params != scheduled.params.to_core()
                    {
                        return Err(ExecutionAttemptError::Deferred(
                            retained_query_authority::invariant(),
                        ));
                    }
                    original.clone()
                } else {
                    let original = funded_authority::FundedPrefixAuthority::admit(
                        scheduled,
                        height,
                        &mut prefix.validation,
                        budget,
                    )?;
                    // Retain the completed graph before any later scratch refusal can
                    // capture its release epoch. A retry borrows this same graph.
                    #[cfg(not(all(test, sumeragi_core_mutation = "HC957")))]
                    {
                        *pending = Some(original.clone());
                    }
                    #[cfg(all(test, sumeragi_core_mutation = "HC957"))]
                    let _ = pending;
                    original
                }
            } else {
                funded_authority::FundedPrefixAuthority::admit(
                    scheduled,
                    height,
                    &mut prefix.validation,
                    budget,
                )?
            };
            PrefixAuthority::Funded(retained)
        } else if query {
            query_reader::admit_epoch_clone(&scheduled.epoch, height)?;
            norito::core::reserve_decode_arc_allocation::<VerifiedAuthority>()
                .map_err(|error| read_decode_error(height, error))?;
            let mut cache = cache;
            let reservation = cache
                .as_mut()
                .and_then(|owner| owner.reserve_authority(&scheduled.epoch));
            let original = VerifiedAuthority::new_query(
                scheduled.epoch.clone(),
                height,
                &mut prefix.validation,
            )?;
            match cache {
                Some(owner) => owner.retain_authority(original, reservation),
                None => PrefixAuthority::Transient(Arc::new(original)),
            }
        } else {
            PrefixAuthority::Transient(Arc::new(VerifiedAuthority::new(
                scheduled.epoch.clone(),
                height,
                &mut prefix.validation,
            )?))
        };
        if &committed.commitment().schedule.current != authority.material() {
            return Err(
                malformed("result changes its authenticated incumbent context".into()).into(),
            );
        }
        if query {
            query_reader::admit_height_config(&scheduled.epoch, height)?;
        }
        let transient_config;
        let config = if let Some(config) = authority.funded_config() {
            config
        } else {
            transient_config = scheduled
                .height_config_with_validation(&mut prefix.validation)
                .map_err(|error| malformed(error.to_string()))?;
            &transient_config
        };
        let certificate =
            self.prepare_certificate(committed, &authority, Some(config), artifacts, budget)?;
        verify_boundary_source(committed, &prefix.tip, authority.projection())?;
        if query {
            query_reader::admit_schedule(&committed.commitment().schedule, height)?;
            query_reader::admit_height_config(&prefix.tip.commitment().schedule.current, height)?;
            query_reader::admit_height_config(&committed.commitment().schedule.current, height)?;
        }
        let schedule = prefix
            .schedule
            .advanced_with_validation(&committed.commitment().schedule, &mut prefix.validation)
            .map_err(|error| malformed(error.to_string()))?;
        // A local byte fence is folded only after complete native authentication; it never
        // supplies finality, and failure of this pure projection merely disables reuse.
        let proof_source = prefix.proof_source.and_then(|previous| {
            committed
                .block()
                .canonical_wire_identity()
                .ok()
                .map(|(length, wire)| proof_source_append(previous, height, length, wire))
        });
        Ok(PreparedAdvance {
            certificate,
            schedule,
            authority,
            proof_source,
        })
    }

    fn verify_certificate(
        &self,
        committed: CommittedBlock,
        authority: &PrefixAuthority,
        config: Option<&iroha_sumeragi::types::HeightConfig>,
        artifacts: Option<PrefixArtifacts>,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        let certificate =
            self.prepare_certificate(&committed, authority, config, artifacts, None)?;
        Ok(certificate.into_certified(committed))
    }

    fn prepare_certificate(
        &self,
        committed: &CommittedBlock,
        authority: &PrefixAuthority,
        config: Option<&iroha_sumeragi::types::HeightConfig>,
        artifacts: Option<PrefixArtifacts>,
        budget: Option<&iroha_allocation::AllocationBudget>,
    ) -> Result<CertificateVerdict, ExecutionAttemptError<ChainReadError>> {
        // Reuse the original active caller allowance before proposal and RS16 scratch
        // allocation, as the State-tip verifier does. No scope or pool is installed here.
        // TODO(S6): this cumulative callback does not fund the nested authority/crypto
        // graph or provide an independent physical scratch owner for AMX relaying.
        self.prepare_certificate_with_original_pool(
            committed,
            authority.projection(),
            config,
            artifacts,
            &mut state_certificate::query_scratch_admission,
            budget,
        )
        .map_err(|error| match error {
            VerificationReadError::Source(error) => error.into(),
            VerificationReadError::Deferred(local) => ExecutionAttemptError::Deferred(local),
        })
    }

    /// Authenticate an offered original against this independently executed block.
    /// All local-certificate and consensus-carried parent participation paths use
    /// this same complete relation; availability remains independently verified
    /// by the full certificate readers and the original Native execution tip.
    fn verify_commit_qc_original(
        &self,
        committed: &CommittedBlock,
        authority: AuthorityRef<'_>,
        commit_qc: &Qc,
    ) -> Result<(), ChainReadError> {
        check_result_scope(committed, self.root_scope)?;
        let height = committed.height;
        let header = committed
            .header
            .as_ref()
            .ok_or_else(|| ChainReadError::Malformed {
                height,
                reason: "genesis alone has no parent service CommitQC".into(),
            })?;
        if header.epoch != authority.epoch
            || commit_qc.epoch != authority.epoch
            || height < authority.material.authorization.first_height
            || height > authority.material.authorization.last_height
            || commit_qc.kind != VoteKind::Commit
            || commit_qc.height != height
            || commit_qc.block_hash != committed.core_hash
        {
            return Err(ChainReadError::HeaderMismatch { height });
        }
        if commit_qc.result != committed.result {
            return Err(ChainReadError::ResultMismatch { height });
        }
        if header.instance != self.instance || commit_qc.instance != self.instance {
            return Err(ChainReadError::WrongInstance { height });
        }
        #[cfg(test)]
        relation_counts::qc(height);
        let checked = iroha_sumeragi::crypto::Verifier::new(
            authority.crypto,
            &self.instance,
            &authority.epoch,
            authority.committee,
        )
        .verify_qc(commit_qc);
        checked.map_err(|error| ChainReadError::Certificate { height, error })?;
        Ok(())
    }

    #[cfg(test)]
    fn verify_certificate_with_scratch_admission(
        &self,
        committed: CommittedBlock,
        authority: &VerifiedAuthority,
        config: Option<&iroha_sumeragi::types::HeightConfig>,
        artifacts: Option<PrefixArtifacts>,
        admit_scratch: &mut dyn FnMut(usize) -> Result<(), ExecutionDeferred>,
    ) -> Result<CertifiedBlock, VerificationReadError> {
        let certificate = self.prepare_certificate_with_scratch_admission(
            &committed,
            authority.projection(),
            config,
            artifacts,
            admit_scratch,
        )?;
        Ok(certificate.into_certified(committed))
    }

    fn prepare_certificate_with_scratch_admission(
        &self,
        committed: &CommittedBlock,
        authority: AuthorityRef<'_>,
        config: Option<&iroha_sumeragi::types::HeightConfig>,
        artifacts: Option<PrefixArtifacts>,
        admit_scratch: &mut dyn FnMut(usize) -> Result<(), ExecutionDeferred>,
    ) -> Result<CertificateVerdict, VerificationReadError> {
        self.prepare_certificate_with_original_pool(
            committed,
            authority,
            config,
            artifacts,
            admit_scratch,
            None,
        )
    }

    fn prepare_certificate_with_original_pool(
        &self,
        committed: &CommittedBlock,
        authority: AuthorityRef<'_>,
        config: Option<&iroha_sumeragi::types::HeightConfig>,
        artifacts: Option<PrefixArtifacts>,
        admit_scratch: &mut dyn FnMut(usize) -> Result<(), ExecutionDeferred>,
        budget: Option<&iroha_allocation::AllocationBudget>,
    ) -> Result<CertificateVerdict, VerificationReadError> {
        check_result_scope(committed, self.root_scope)?;
        let height = committed.height;
        let malformed = |reason: String| ChainReadError::Malformed { height, reason };
        let certificate = committed
            .block
            .commit_certificate()
            .ok_or(ChainReadError::MissingCertificate { height })?;
        let certificate_len =
            norito::core::classify_decode_attempt(|| norito::canonical_frame_len(certificate))
                .map_err(|error| verification_codec_error(height, error))?;
        let Some(header) = committed.header.as_ref() else {
            return Ok(CertificateVerdict {
                commit_qc: None,
                verification: QcVerification::Genesis,
                certificate_len,
            });
        };
        let (commit_qc, availability) = if let Some(artifacts) = artifacts {
            let (qc, table, payload) = artifacts.into_parts(&committed.block, header)?;
            (PrefixQc::Funded(qc), Some((table, payload)))
        } else {
            let qc = norito::core::classify_decode_attempt(|| {
                norito::decode_canonical(certificate.commit_qc())
            })
            .map_err(|error| verification_codec_error(height, error))?;
            (PrefixQc::Decoded(qc), None)
        };
        self.verify_commit_qc_original(committed, authority, &commit_qc)?;
        // Parent-authenticated parameters and authority also bind the original signed row
        // table. A valid CommitQC alone does not certify possession of these payload bytes.
        let config = config.ok_or_else(|| {
            malformed("non-genesis certificate lacks parent-authenticated configuration".into())
        })?;
        verify_availability(
            committed,
            config,
            authority.crypto,
            availability,
            admit_scratch,
            budget,
        )?;
        Ok(CertificateVerdict {
            commit_qc: Some(commit_qc),
            verification: QcVerification::Verified,
            certificate_len,
        })
    }
}

fn verify_boundary_source(
    certified: &CommittedBlock,
    parent: &CommittedBlock,
    authority: AuthorityRef<'_>,
) -> Result<(), ChainReadError> {
    let height = certified.height();
    let malformed = |reason: String| ChainReadError::Committee { height, reason };
    if let Some(boundary) = &certified.commitment().schedule.boundary {
        if boundary.selection_anchor != parent.block_hash() {
            return Err(malformed(
                "boundary selection anchor differs from certified parent".into(),
            ));
        }
        let pulse = parent.commitment().beacon.as_ref().ok_or_else(|| {
            malformed("boundary predecessor omits its certified selection pulse".into())
        })?;
        let expected_seed = crate::beacon::global_threshold_beacon_npos_successor_seed_v1(
            pulse,
            height,
            boundary.next.authorization.epoch,
        );
        if boundary.next.leader_seed != expected_seed {
            return Err(malformed(
                "boundary leader seed differs from certified fresh pulse".into(),
            ));
        }
        if let Some(preparation) = &boundary.preparation {
            let expected = super::epoch_election::election_seed(
                authority.material.network_id,
                authority.material.authorization.epoch,
                pulse,
            )
            .map_err(malformed)?;
            if preparation.election_seed != expected {
                return Err(malformed(
                    "frozen election seed differs from certified fresh pulse".into(),
                ));
            }
        }
    }
    Ok(())
}

fn verify_availability(
    committed: &CommittedBlock,
    config: &iroha_sumeragi::types::HeightConfig,
    crypto: &dyn iroha_sumeragi::crypto::Crypto,
    prepared: Option<(
        iroha_sumeragi::availability::AvailabilityFrame,
        iroha_sumeragi::availability::PayloadBytes,
    )>,
    admit_scratch: &mut dyn FnMut(usize) -> Result<(), ExecutionDeferred>,
    budget: Option<&iroha_allocation::AllocationBudget>,
) -> Result<(), VerificationReadError> {
    use iroha_sumeragi::availability::{AvailabilityFrame, MAX_AVAILABILITY_FRAME_BYTES};
    let height = committed.height;
    let malformed = |reason: String| {
        VerificationReadError::Source(ChainReadError::Malformed { height, reason })
    };
    let header = committed
        .header
        .as_ref()
        .ok_or_else(|| malformed("availability requires a non-genesis header".into()))?;
    let certificate = committed
        .block
        .commit_certificate()
        .ok_or(ChainReadError::MissingCertificate { height })?;
    // Both preparation paths enforce the same independent portable-reader bounds.
    // RS16 scratch is charged separately to the inherited cumulative decode allowance;
    // retaining a payload/artifact alone never grants scratch allocation authority.
    if certificate.availability().len() > MAX_AVAILABILITY_FRAME_BYTES.saturating_add(128)
        || header.payload_len as usize > MAX_PROPOSAL_BYTES
    {
        return Err(malformed(
            "availability exceeds certified reader bound".into(),
        ));
    }
    let availability_error = |error| match error {
        iroha_data_model::sumeragi_finality::PayloadAvailabilityError::Admission(original) => {
            VerificationReadError::Deferred(original)
        }
        iroha_data_model::sumeragi_finality::PayloadAvailabilityError::Limit(original) => {
            VerificationReadError::Deferred(original.into())
        }
        iroha_data_model::sumeragi_finality::PayloadAvailabilityError::Allocator(original) => {
            VerificationReadError::Deferred(original.into())
        }
        iroha_data_model::sumeragi_finality::PayloadAvailabilityError::Invalid(error) => {
            malformed(error.to_string())
        }
    };
    if let Some((table, payload)) = prepared {
        if let Some(budget) = budget {
            return funded_availability::verify(
                header.instance,
                config,
                header,
                &table,
                payload.as_slice(),
                crypto,
                budget,
                admit_scratch,
            );
        }
        return iroha_data_model::sumeragi_finality::verify_payload_availability_with_admission(
            header.instance,
            config,
            header,
            &table,
            payload.as_slice(),
            crypto,
            admit_scratch,
        )
        .map_err(availability_error);
    }
    let table: AvailabilityFrame = norito::core::classify_decode_attempt(|| {
        norito::decode_canonical(certificate.availability())
    })
    .map_err(|error| verification_codec_error(height, error))?;
    let payload_len = header.payload_len as usize;
    admit_scratch(payload_len).map_err(VerificationReadError::Deferred)?;
    let layout = std::alloc::Layout::array::<u8>(payload_len)
        .expect("publicly bounded empty proposal payload layout");
    let mut payload = Vec::new();
    payload.try_reserve_exact(payload_len).map_err(|original| {
        VerificationReadError::Deferred(
            iroha_allocation::AllocatorRefusal::from_vec_reserve(original, layout).into(),
        )
    })?;
    committed
        .block
        .write_resultless_proposal_wire(&mut payload)
        .map_err(|error| malformed(error.to_string()))?;
    iroha_data_model::sumeragi_finality::verify_payload_availability_with_admission(
        header.instance,
        config,
        header,
        &table,
        &payload,
        crypto,
        admit_scratch,
    )
    .map_err(availability_error)
}

fn genesis_prefix_authority(
    tip: &CommittedBlock,
    material: ValidatorEpochContextV1,
    validation: &mut EpochValidationScope,
) -> Result<(schedule::ConsensusSchedule, PrefixAuthority), ExecutionAttemptError<ChainReadError>> {
    genesis_prefix_authority_with_funding(tip, material, validation, false, None, None)
}

fn genesis_prefix_authority_query(
    tip: &CommittedBlock,
    material: ValidatorEpochContextV1,
    validation: &mut EpochValidationScope,
    cache: Option<&mut QueryCacheOwner>,
    reservation: Option<QueryAuthorityReservation>,
) -> Result<(schedule::ConsensusSchedule, PrefixAuthority), ExecutionAttemptError<ChainReadError>> {
    genesis_prefix_authority_with_funding(tip, material, validation, true, cache, reservation)
}

fn genesis_prefix_authority_with_funding(
    tip: &CommittedBlock,
    material: ValidatorEpochContextV1,
    validation: &mut EpochValidationScope,
    query: bool,
    cache: Option<&mut QueryCacheOwner>,
    reservation: Option<QueryAuthorityReservation>,
) -> Result<(schedule::ConsensusSchedule, PrefixAuthority), ExecutionAttemptError<ChainReadError>> {
    // On an early schedule/source refusal the material drops before its optional
    // persistent credits. A completed constructor consumes the same original field.
    struct OriginalMaterial {
        material: ValidatorEpochContextV1,
        reservation: Option<QueryAuthorityReservation>,
    }
    let input = OriginalMaterial {
        material,
        reservation,
    };
    if tip.commitment().schedule.current != input.material {
        return Err(ChainReadError::Committee {
            height: GENESIS_HEIGHT,
            reason: "genesis result context differs from its signed body".into(),
        }
        .into());
    }
    if query {
        query_reader::admit_schedule(&tip.commitment().schedule, GENESIS_HEIGHT)?;
        query_reader::admit_height_config(&tip.commitment().schedule.current, GENESIS_HEIGHT)?;
    }
    let schedule = schedule::ConsensusSchedule::from_genesis_outcome_with_validation(
        &tip.commitment().schedule,
        validation,
    )
    .map_err(|error| ChainReadError::Committee {
        height: GENESIS_HEIGHT,
        reason: error.to_string(),
    })?;
    let authority = if query {
        norito::core::reserve_decode_arc_allocation::<VerifiedAuthority>()
            .map_err(|error| read_decode_error(GENESIS_HEIGHT, error))?;
        let original = VerifiedAuthority::new_query(input.material, GENESIS_HEIGHT, validation)?;
        match cache {
            Some(owner) => owner.retain_authority(original, input.reservation),
            None => PrefixAuthority::Transient(Arc::new(original)),
        }
    } else {
        PrefixAuthority::Transient(Arc::new(VerifiedAuthority::new(
            input.material,
            GENESIS_HEIGHT,
            validation,
        )?))
    };
    Ok((schedule, authority))
}

fn make_genesis_prefix(
    tip: CommittedBlock,
    material: ValidatorEpochContextV1,
    mut validation: EpochValidationScope,
) -> Result<VerifiedPrefix, ExecutionAttemptError<ChainReadError>> {
    let (schedule, authority) = genesis_prefix_authority(&tip, material, &mut validation)?;
    Ok(VerifiedPrefix {
        tip,
        schedule,
        authority,
        validation,
        proof_source: None,
    })
}

// Keep the opt-in returned prefix owner outside the default genesis-read frame.
#[inline(never)]
fn make_genesis_prefix_with_source(
    tip: CommittedBlock,
    material: ValidatorEpochContextV1,
    validation: EpochValidationScope,
    expected: (u64, Hash),
) -> Result<VerifiedPrefix, ExecutionAttemptError<ChainReadError>> {
    let mut prefix = make_genesis_prefix(tip, material, validation)?;
    // Join the fresh prefix to the exact constructor-authenticated signed source,
    // including the full local result/certificate representation, before eligibility.
    if prefix.tip.block().canonical_wire_identity().ok() == Some(expected) {
        prefix.proof_source = Some(proof_source_append(
            proof_source_start(),
            GENESIS_HEIGHT,
            expected.0,
            expected.1,
        ));
    }
    Ok(prefix)
}

/// Genesis execution authenticated by an actual verified height-two successor.
///
/// This move-only receipt is never decoded or publicly constructed. The genesis has no QC;
/// the successor's exact quorum authenticates its `parent_result` and complete predecessor.
#[derive(Debug)]
pub struct GenesisExecutionAnchor {
    committed: CommittedBlock,
    successor: Hash32,
}
impl GenesisExecutionAnchor {
    /// Original result-bearing genesis whose execution is authenticated by the successor.
    #[must_use]
    pub fn committed(&self) -> &CommittedBlock {
        &self.committed
    }
    /// Native hash of the independently verified successor that signs this result.
    #[must_use]
    pub const fn successor(&self) -> Hash32 {
        self.successor
    }
    /// Move the authenticated execution receipt into its consuming evidence owner.
    #[must_use]
    pub fn into_committed(self) -> CommittedBlock {
        self.committed
    }
}

/// One chronologically verified native successor and, exactly once at H2, its genesis anchor.
#[derive(Debug)]
pub struct CertifiedPrefixStep {
    current: CertifiedBlock,
    genesis: Option<GenesisExecutionAnchor>,
}
impl CertifiedPrefixStep {
    /// Whether this actual prefix step authenticated the original genesis through H2.
    pub(crate) const fn has_genesis_anchor(&self) -> bool {
        self.genesis.is_some()
    }

    /// Consume both actual verification receipts without rebuilding or converting a proof.
    #[must_use]
    pub fn into_parts(self) -> (CertifiedBlock, Option<GenesisExecutionAnchor>) {
        (self.current, self.genesis)
    }
}

/// Original initialization backing retained across local prefix/result refusals.
/// Authentication is still performed by the sole admitted prefix initialization kernel.
#[derive(Default)]
pub(crate) struct AdmittedPrefixInitialization {
    original: Option<iroha_allocation::ChargedBuffer<CertifiedPrefix>>,
    frame: AdmittedFrameRead,
    // Bound before the first admission, so a refused first slot cannot let a retry
    // substitute another pool or genesis carrier.
    budget: Option<iroha_allocation::AllocationBudget>,
    source: Option<iroha_data_model::block::SharedSignedBlock>,
}
impl AdmittedPrefixInitialization {
    pub(crate) fn complete(
        &mut self,
        chain_id: &ChainId,
        network: NetworkId,
        genesis: iroha_data_model::block::SharedSignedBlock,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<
        iroha_allocation::ChargedBuffer<CertifiedPrefix>,
        ExecutionAttemptError<ChainReadError>,
    > {
        if self
            .budget
            .as_ref()
            .is_some_and(|original| !original.same_pool(budget))
            || self.source.as_ref().is_some_and(|original| {
                !iroha_data_model::block::SharedSignedBlock::ptr_eq(original, &genesis)
            })
        {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC965")))]
        if self.source.is_none() {
            self.budget = Some(budget.clone());
            self.source = Some(genesis.clone());
        }
        if self.original.is_none() {
            self.original = Some(admit_verification_slot(budget)?);
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC965"))]
        if self.source.is_none() {
            self.budget = Some(budget.clone());
            self.source = Some(genesis.clone());
        }
        CertifiedPrefix::initialize_admitted(
            self.original
                .as_mut()
                .expect("original admitted prefix slot"),
            &mut self.frame,
            chain_id,
            network,
            genesis,
            budget,
        )?;
        self.budget = None;
        self.source = None;
        Ok(self.original.take().expect("complete original prefix"))
    }
}

/// A successor's original frame slots, retained until native verification completes.
#[derive(Default)]
pub(crate) struct AdmittedPrefixPush {
    frame: AdmittedFrameRead,
    // A later refusal cannot refund its own newly constructed authority graph.
    pending_authority:
        Option<iroha_allocation::ChargedShared<funded_authority::FundedPrefixAuthority>>,
}
impl AdmittedPrefixPush {
    pub(crate) fn complete_with_finish<Output>(
        &mut self,
        prefix: &mut CertifiedPrefix,
        block: iroha_data_model::block::SharedSignedBlock,
        budget: &iroha_allocation::AllocationBudget,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        self.complete_original(prefix, block, budget, None, finish)
    }

    /// Borrow prepared source-bound metadata while retaining the reader's original owners.
    pub(crate) fn complete_prepared_with_finish<Output>(
        &mut self,
        prefix: &mut CertifiedPrefix,
        artifacts: &PrefixArtifacts,
        budget: &iroha_allocation::AllocationBudget,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        self.complete_original(
            prefix,
            artifacts.source().clone(),
            budget,
            Some(artifacts),
            finish,
        )
    }

    fn complete_original<Output>(
        &mut self,
        prefix: &mut CertifiedPrefix,
        block: iroha_data_model::block::SharedSignedBlock,
        budget: &iroha_allocation::AllocationBudget,
        artifacts: Option<&PrefixArtifacts>,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        #[cfg(not(all(test, sumeragi_core_mutation = "HC955")))]
        if artifacts.is_some_and(|original| !original.belongs_to(budget)) {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC955"))]
        let _ = artifacts;
        if prefix
            .original_budget
            .as_ref()
            .is_some_and(|original| !original.same_pool(budget))
        {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        let height = block.header().height().get();
        if prefix.prefix.tip.height.checked_add(1) != Some(height) {
            return Err(ChainReadError::Discontinuous { height }.into());
        }
        let decoded = self.frame.initialize_prepared(
            block,
            height,
            prefix.root_scope,
            &mut prefix.prefix.validation,
            budget,
            artifacts.map(|original| original.header().clone()),
        );
        #[cfg(all(test, sumeragi_core_mutation = "HC951"))]
        if decoded.is_err() {
            self.frame = AdmittedFrameRead::default();
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC951")))]
        let _ = &self.frame;
        decoded?;
        let genesis =
            (prefix.prefix.tip.height == GENESIS_HEIGHT).then(|| prefix.prefix.tip.clone());
        let prepared = PrefixVerifierContext {
            instance: prefix.instance,
            root_scope: prefix.root_scope,
        }
        .prepare_advance_with_funding(
            &mut prefix.prefix,
            self.frame.committed(),
            artifacts.cloned(),
            false,
            None,
            prefix.original_budget.as_ref(),
            Some(&mut self.pending_authority),
        )?;
        Ok(Self::finish(
            prefix,
            self.frame.take_committed(),
            prepared,
            &mut self.pending_authority,
            genesis,
            finish,
        ))
    }
    // Decoding and every fallible verifier have returned before moving this large receipt.
    fn finish<Output>(
        prefix: &mut CertifiedPrefix,
        mut original: iroha_allocation::ChargedBuffer<CommittedBlock>,
        prepared: PreparedAdvance,
        pending_authority: &mut Option<
            iroha_allocation::ChargedShared<funded_authority::FundedPrefixAuthority>,
        >,
        genesis: Option<CommittedBlock>,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Output {
        let committed = original.pop().expect("complete original admitted frame");
        let current =
            PrefixVerifierContext::install_advance(&mut prefix.prefix, committed, prepared);
        // The installed prefix now retains this exact graph. Clearing the pending
        // reference allocates nothing and cannot refund its live charges.
        *pending_authority = None;
        let genesis = genesis.map(|committed| GenesisExecutionAnchor {
            committed,
            successor: current.core_hash,
        });
        let output = finish(CertifiedPrefixStep { current, genesis });
        drop(original);
        output
    }
}

/// One-pass native certificate verification from independently pinned signed genesis.
///
/// The working authority is bounded: the original parent, current authority and lag-two
/// schedule only. Every supplied height is checked once by the same transition verifier as
/// [`CertifiedChain`]. There is no all-history committee cache or World authority lookup.
/// Callers must bound canonical frame allocations before supplying each decoded block.
/// Construction authenticates genesis header/body and its epoch only. No genesis execution
/// receipt is exported until a real verified H2 binds its result through `parent_result`.
pub struct CertifiedPrefix {
    original_budget: Option<iroha_allocation::AllocationBudget>,
    instance: Hash32,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    prefix: VerifiedPrefix,
}
impl CertifiedPrefix {
    /// Construct directly in one exact original-pool slot without a complete prefix on the stack.
    /// All authentication is shared with `new`; admission itself confers no source authority.
    /// The immutable authority owns its exact epoch material, native configuration,
    /// PoP credentials and fallible pairing backing in this original pool.
    /// TODO(S8): decoded result/genesis graphs, schedule validation/advance and shared
    /// validation error diagnostics still need physical custody. The cache is inline;
    /// prepared SCCP metadata and RS16 scratch have original-pool owners. One-shot AMX
    /// callers must migrate to retained initialization so later refusals keep earlier slots.
    ///
    /// # Errors
    /// The original pool/allocator refuses the slot, or the same signed genesis and result
    /// validation required by `new` does not complete.
    pub(crate) fn new_admitted(
        chain_id: &ChainId,
        network: NetworkId,
        genesis: iroha_data_model::block::SharedSignedBlock,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<iroha_allocation::ChargedBuffer<Self>, ExecutionAttemptError<ChainReadError>> {
        let mut original = admit_verification_slot::<Self>(budget)?;
        Self::initialize_admitted(
            &mut original,
            &mut AdmittedFrameRead::default(),
            chain_id,
            network,
            genesis,
            budget,
        )?;
        Ok(original)
    }

    // Both one-shot and retained readers initialize the same exact prepaid slot
    // through this existing admitted verifier. Failure leaves the slot empty;
    // the retained caller keeps its original backing across local refusal.
    #[allow(
        unsafe_code,
        reason = "each distinct field of the prepaid slot is initialized after all fallible verification; no incomplete prefix is exposed or dropped"
    )]
    fn initialize_admitted(
        original: &mut iroha_allocation::ChargedBuffer<Self>,
        frame: &mut AdmittedFrameRead,
        chain_id: &ChainId,
        network: NetworkId,
        genesis: iroha_data_model::block::SharedSignedBlock,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        if !original.belongs_to(budget) {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        let (epoch, instance, root_scope) = authenticate_genesis(&genesis, &network, chain_id)?;
        let mut validation = EpochValidationScope::new();
        frame.initialize(genesis, GENESIS_HEIGHT, root_scope, &mut validation, budget)?;
        if frame.committed().commitment().schedule.current != epoch {
            return Err(ChainReadError::Committee {
                height: GENESIS_HEIGHT,
                reason: "genesis result context differs from its signed body".into(),
            }
            .into());
        }
        let schedule = schedule::ConsensusSchedule::from_genesis_outcome_with_validation(
            &frame.committed().commitment().schedule,
            &mut validation,
        )
        .map_err(|error| ChainReadError::Committee {
            height: GENESIS_HEIGHT,
            reason: error.to_string(),
        })?;
        let scheduled =
            schedule
                .ready(GENESIS_HEIGHT)
                .map_err(|error| ChainReadError::Committee {
                    height: GENESIS_HEIGHT,
                    reason: error.to_string(),
                })?;
        let authority = PrefixAuthority::Funded(funded_authority::FundedPrefixAuthority::admit(
            scheduled,
            GENESIS_HEIGHT,
            &mut validation,
            budget,
        )?);
        let pointer = original.spare_capacity_mut()[0].as_mut_ptr();
        let tip = frame.take_committed();
        // SAFETY: the original exact backing has one aligned Self slot. All fallible work
        // finished above. Field writes only move already valid owners; none invokes a
        // destructor or allocates. Every field is initialized before exposing length one.
        unsafe {
            std::ptr::addr_of_mut!((*pointer).original_budget).write(Some(budget.clone()));
            std::ptr::addr_of_mut!((*pointer).instance).write(instance);
            std::ptr::addr_of_mut!((*pointer).root_scope).write(root_scope);
            // Transfer the already valid receipt without materializing a complete tip value
            // on this stack. The source backing and charge survive the physical transfer;
            // clearing its length prevents its moved payload from being dropped twice.
            transfer_verification_slot(tip, std::ptr::addr_of_mut!((*pointer).prefix.tip));
            std::ptr::addr_of_mut!((*pointer).prefix.schedule).write(schedule);
            std::ptr::addr_of_mut!((*pointer).prefix.authority).write(authority);
            std::ptr::addr_of_mut!((*pointer).prefix.validation).write(validation);
            std::ptr::addr_of_mut!((*pointer).prefix.proof_source).write(None);
            original.set_initialized_len(1);
        }
        Ok(())
    }

    /// Borrow the complete authority already authenticated by this prefix's source relation.
    pub(crate) fn current_epoch_context(&self) -> &ValidatorEpochContextV1 {
        self.prefix.authority.material()
    }

    /// Start with the exact configured chain identity and independently pinned genesis network.
    ///
    /// # Errors
    /// Rejects foreign or unsigned genesis, an invalid complete epoch, or a malformed result
    /// frame. A well-formed genesis result is still untrusted until the first successor.
    pub fn new(
        chain_id: &ChainId,
        network: NetworkId,
        genesis: iroha_data_model::block::SharedSignedBlock,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let (epoch, instance, root_scope) = authenticate_genesis(&genesis, &network, chain_id)?;
        let mut validation = EpochValidationScope::new();
        let tip = read_frame_with_validation(genesis, GENESIS_HEIGHT, root_scope, &mut validation)?;
        Ok(Self {
            original_budget: None,
            instance,
            root_scope,
            prefix: make_genesis_prefix(tip, epoch, validation)?,
        })
    }

    /// Exact immutable scope retained from the authenticated signed genesis.
    #[must_use]
    pub const fn root_scope(&self) -> iroha_data_model::block::consensus::SumeragiRootScope {
        self.root_scope
    }

    /// The native chain instance bound by every subsequent signature.
    #[must_use]
    pub const fn instance(&self) -> Hash32 {
        self.instance
    }

    /// Verify the exact next canonical carrier with BLS quorum and signed availability checks.
    ///
    /// # Errors
    /// Rejects changed/skipped parents, result/context substitutions, malformed certificates,
    /// invalid signatures, incomplete authority, boundary decisions or beacon source links.
    /// A rejected frame does not advance the original verified cursor.
    pub fn push(
        &mut self,
        block: iroha_data_model::block::SharedSignedBlock,
    ) -> Result<CertifiedPrefixStep, ExecutionAttemptError<ChainReadError>> {
        self.push_with_finish(block, None, |step| step)
    }

    /// Consume only artifacts prepared from the exact original carrier. Their allocation
    /// custody follows the same verification predicates as portable reads. The frame is
    /// checked against the artifacts' sole funded header, which the verified tip retains.
    pub(crate) fn push_prepared(
        &mut self,
        artifacts: PrefixArtifacts,
    ) -> Result<CertifiedPrefixStep, ExecutionAttemptError<ChainReadError>> {
        self.push_with_finish(artifacts.source().clone(), Some(artifacts), |step| step)
    }

    /// Consume the original complete verification receipt after all shared prefix checks.
    /// A small projection avoids retaining a large unused receipt on the active caller stack.
    ///
    /// # Errors
    /// Returns exactly the original `push` rejection/refusal without invoking `finish`.
    /// Artifacts prepared from another carrier are a local invariant refusal.
    pub(crate) fn push_with_finish<Output>(
        &mut self,
        block: iroha_data_model::block::SharedSignedBlock,
        artifacts: Option<PrefixArtifacts>,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        let height = block.header().height().get();
        if self.prefix.tip.height.checked_add(1) != Some(height) {
            return Err(ChainReadError::Discontinuous { height }.into());
        }
        // Prepared artifacts bind their exact carrier. Their header comes from the sole
        // certificate metadata decoder and is checked against this frame, never decoded again.
        if artifacts.as_ref().is_some_and(|original| {
            !iroha_data_model::block::SharedSignedBlock::ptr_eq(original.source(), &block)
        }) {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        let committed = read_prepared_frame(
            block,
            height,
            self.root_scope,
            &mut self.prefix.validation,
            artifacts.as_ref().map(|original| original.header().clone()),
        )?;
        self.finish_prefix_push(committed, artifacts, finish)
    }

    /// Verify the same complete successor through exact slots admitted by the original pool.
    /// The existing value-returning readers retain their original behavior; this consumer
    /// keeps only a small charged owner on the active decoder caller stack.
    ///
    /// # Errors
    /// Preserves the same continuity, decoder and certificate failures; exact slot admission
    /// may defer without advancing this prefix or invoking the completion consumer.
    pub(crate) fn push_admitted_with_finish<Output>(
        &mut self,
        block: iroha_data_model::block::SharedSignedBlock,
        budget: &iroha_allocation::AllocationBudget,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        if self
            .original_budget
            .as_ref()
            .is_some_and(|original| !original.same_pool(budget))
        {
            return Err(ExecutionAttemptError::Deferred(
                retained_query_authority::invariant(),
            ));
        }
        let height = block.header().height().get();
        if self.prefix.tip.height.checked_add(1) != Some(height) {
            return Err(ChainReadError::Discontinuous { height }.into());
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC964"))]
        let committed = read_frame_admitted(
            block,
            height,
            self.root_scope,
            &mut self.prefix.validation,
            budget,
        )?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC964")))]
        let committed = {
            // One reservation funds both verification slots of this one-shot read, so a
            // later refusal has no earlier slot of this operation whose refund could
            // satisfy the release wait that refusal returns.
            let mut original = AdmittedFrameRead::admit_slots(budget)?;
            original.initialize(
                block,
                height,
                self.root_scope,
                &mut self.prefix.validation,
                budget,
            )?;
            original.take_committed()
        };
        self.finish_admitted_prefix_push(committed, finish)
    }

    // The decoder has returned before its complete value moves through this small stage.
    // Safe pop retains the original empty backing/charge through normal completion or unwind.
    fn finish_admitted_prefix_push<Output>(
        &mut self,
        mut original: iroha_allocation::ChargedBuffer<CommittedBlock>,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        let committed = original
            .pop()
            .expect("the private admitted reader returned one fully initialized frame");
        let result = self.finish_prefix_push(committed, None, finish);
        drop(original);
        result
    }

    // These complete receipt/anchor values exist only after the original full decode returns.
    // Splitting this stage changes neither prefix mutation nor verification/finish order.
    fn finish_prefix_push<Output>(
        &mut self,
        committed: CommittedBlock,
        artifacts: Option<PrefixArtifacts>,
        finish: impl FnOnce(CertifiedPrefixStep) -> Output,
    ) -> Result<Output, ExecutionAttemptError<ChainReadError>> {
        let genesis = (self.prefix.tip.height == GENESIS_HEIGHT).then(|| self.prefix.tip.clone());
        let verifier = PrefixVerifierContext {
            instance: self.instance,
            root_scope: self.root_scope,
        };
        // A one-shot push retains no owner across refusal: an authority or RS16 scratch it
        // funded would be dropped on a later refusal and refund the very bytes that
        // refusal's release wait observes. Only the retained AdmittedPrefixPush funds them.
        // TODO(S8): migrate one-shot admitted callers to AdmittedPrefixPush so successor
        // authorities and RS16 scratch also keep original-pool custody on those paths.
        #[cfg(all(test, sumeragi_core_mutation = "HC963"))]
        let budget = self.original_budget.as_ref();
        #[cfg(not(all(test, sumeragi_core_mutation = "HC963")))]
        let budget = None;
        let prepared = verifier.prepare_advance_with_funding(
            &mut self.prefix,
            &committed,
            artifacts,
            false,
            None,
            budget,
            None,
        )?;
        let current = PrefixVerifierContext::install_advance(&mut self.prefix, committed, prepared);
        let genesis = genesis.map(|committed| GenesisExecutionAnchor {
            committed,
            successor: current.core_hash,
        });
        Ok(finish(CertifiedPrefixStep { current, genesis }))
    }
}

fn authenticate_genesis(
    genesis: &SignedBlock,
    network: &NetworkId,
    chain_id: &ChainId,
) -> Result<
    (
        ValidatorEpochContextV1,
        Hash32,
        iroha_data_model::block::consensus::SumeragiRootScope,
    ),
    crate::execution_attempt::ExecutionAttemptError<ChainReadError>,
> {
    authenticate_genesis_with(genesis, network, chain_id, || {
        super::epoch::authenticated_genesis(genesis).map_err(|error| {
            crate::execution_attempt::genesis_read_attempt_error(error, |_| {
                ChainReadError::ForeignGenesis
            })
        })
    })
}

// Reuse all original network, signed-body and instance checks for the one canonical
// authentication kernel, whether its policy destination is ordinary or retained.
fn authenticate_genesis_with(
    genesis: &SignedBlock,
    network: &NetworkId,
    chain_id: &ChainId,
    authenticate: impl FnOnce() -> Result<
        iroha_data_model::sumeragi_finality::AuthenticatedGenesis,
        ExecutionAttemptError<ChainReadError>,
    >,
) -> Result<
    (
        ValidatorEpochContextV1,
        Hash32,
        iroha_data_model::block::consensus::SumeragiRootScope,
    ),
    ExecutionAttemptError<ChainReadError>,
> {
    if genesis.hash().as_ref() != network.as_bytes()
        || !genesis.header().is_genesis()
        || genesis.validate_proposal_commitments().is_err()
    {
        return Err(ChainReadError::ForeignGenesis.into());
    }
    let (epoch, root_scope) = authenticate()?.into_parts();
    // TODO: This paired projection removes completed metadata redecoding only.
    // Subsequent partial genesis-result/authority retention and nested graph funding
    // still belong to their original acquisition and prefix owners.
    #[cfg(all(test, sumeragi_core_mutation = "HC205"))]
    let instance = {
        // Deliberately restore only the completed metadata decode that the paired
        // canonical result removed. Authentication and the original typed cause remain.
        let _ = root_scope;
        super::node::root_instance(genesis, &chain_id.to_string())
            .map_err(|error| error.map_rejection(|_| ChainReadError::ForeignGenesis))?
    };
    #[cfg(not(all(test, sumeragi_core_mutation = "HC205")))]
    let instance = root_scope
        .instance_id(
            &BlsCrypto::new(),
            NetworkId::from_genesis_hash(genesis.hash()),
            chain_id.as_ref(),
        )
        .map_err(|_| ChainReadError::ForeignGenesis)?;
    Ok((epoch, instance, root_scope))
}

// Borrow representations only: both feed the same pinned native decoder and
// signed-genesis prefix verifier. Neither a journal nor a hash grants authority.
enum PinnedHashes<'v> {
    Slice(&'v [HashOf<IrohaHeader>]),
    Captured(&'v dyn crate::state::BlockHashRead),
}
impl PinnedHashes<'_> {
    fn get(&self, index: usize) -> Option<&HashOf<IrohaHeader>> {
        match self {
            Self::Slice(hashes) => hashes.get(index),
            Self::Captured(hashes) => hashes.get(index),
        }
    }
}

/// The exact source cut being verified. Pinned restoration never supplies a World or roster.
enum ChainSource<'v, V: StateReadOnly + ?Sized> {
    State(&'v V),
    Frames {
        chain_id: &'v ChainId,
        network: &'v NetworkId,
        hashes: &'v [HashOf<IrohaHeader>],
        frames: &'v [iroha_data_model::block::SharedSignedBlock],
    },
    Pinned {
        chain_id: &'v ChainId,
        network: &'v NetworkId,
        hashes: PinnedHashes<'v>,
        kura: &'v Kura,
        budget: iroha_allocation::AllocationBudget,
        maximum_wire_bytes: usize,
    },
}
impl<V: StateReadOnly + ?Sized> ChainSource<'_, V> {
    fn network_id(&self) -> &NetworkId {
        match self {
            Self::State(view) => view.network_id(),
            Self::Pinned { network, .. } | Self::Frames { network, .. } => network,
        }
    }
    fn chain_id(&self) -> &ChainId {
        match self {
            Self::State(view) => view.chain_id(),
            Self::Pinned { chain_id, .. } | Self::Frames { chain_id, .. } => chain_id,
        }
    }
    fn block(
        &self,
        height: u64,
    ) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<ChainReadError>>
    {
        let index = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(ChainReadError::NotCommitted { height })?;
        match self {
            Self::State(view) => {
                if index.get() > view.block_hashes().len() {
                    return Err(ChainReadError::NotCommitted { height }.into());
                }
                let expected = view
                    .block_hashes()
                    .get(index.get() - 1)
                    .ok_or(ChainReadError::NotCommitted { height })?;
                read_durable_pinned_block(view.kura(), index, *expected, &view.execution_budget())
            }
            Self::Frames { hashes, frames, .. } => {
                let expected = hashes
                    .get(index.get() - 1)
                    .ok_or(ChainReadError::NotCommitted { height })?;
                let block = frames
                    .get(index.get() - 1)
                    .ok_or(ChainReadError::NotInView { height })?;
                if block.hash() != *expected || block.header().height().get() != height {
                    return Err(ChainReadError::NotInView { height }.into());
                }
                Ok(block.clone())
            }
            Self::Pinned {
                hashes,
                kura,
                budget,
                maximum_wire_bytes,
                ..
            } => {
                let expected = hashes
                    .get(index.get() - 1)
                    .ok_or(ChainReadError::NotCommitted { height })?;
                read_durable_pinned_block_bounded(
                    kura,
                    index,
                    *expected,
                    budget,
                    *maximum_wire_bytes,
                )
            }
        }
    }
}

/// Authenticate only the original signed genesis body from a bounded actual native source.
/// This exports no result-only genesis execution or current-state authority.
pub(crate) fn bounded_signed_genesis(
    view: &(impl StateReadOnly + ?Sized),
    maximum_wire_bytes: usize,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<ChainReadError>> {
    let genesis = bounded_native_carrier(view, 1, maximum_wire_bytes, budget)?;
    authenticate_genesis(&genesis, view.network_id(), view.chain_id())?;
    Ok(genesis)
}

/// Inspect only the original durable extent before admitting a bounded native decode.
/// The extent grants no authority and is checked again by the sole subsequent frame reader.
pub(crate) fn bounded_native_carrier_extent(
    view: &(impl StateReadOnly + ?Sized),
    height: u64,
    maximum_wire_bytes: usize,
) -> Result<usize, ExecutionAttemptError<ChainReadError>> {
    let index = usize::try_from(height)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or(ChainReadError::NotCommitted { height })?;
    let expected = *view
        .block_hashes()
        .get(index.get() - 1)
        .ok_or(ChainReadError::NotCommitted { height })?;
    let source = view
        .kura()
        .native_frame_read(height, expected)
        .map_err(|error| {
            crate::execution_attempt::kura_read_attempt_error(error, |_| {
                ChainReadError::NotInView { height }
            })
        })?
        .ok_or(ChainReadError::NotInView { height })?;
    let length =
        usize::try_from(source.wire_len()).map_err(|_| ChainReadError::NotInView { height })?;
    if length == 0 || length > maximum_wire_bytes {
        return Err(ChainReadError::NotInView { height }.into());
    }
    Ok(length)
}

/// Acquire exactly one State-pinned native frame after bounding its original durable extent.
/// This reads no historical prefix and grants no certificate or current-state authority.
pub(crate) fn bounded_native_carrier(
    view: &(impl StateReadOnly + ?Sized),
    height: u64,
    maximum_wire_bytes: usize,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<ChainReadError>> {
    let index = usize::try_from(height)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or(ChainReadError::NotCommitted { height })?;
    let expected = *view
        .block_hashes()
        .get(index.get() - 1)
        .ok_or(ChainReadError::NotCommitted { height })?;
    read_durable_pinned_block_bounded(view.kura(), index, expected, budget, maximum_wire_bytes)
}

/// Read the pinned durable certificate bytes even when Kura retains a decoded body.
/// A cached body cannot establish the continued availability or validity of a local QC.
fn read_durable_pinned_block(
    kura: &Kura,
    index: NonZeroUsize,
    expected: HashOf<IrohaHeader>,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<ChainReadError>> {
    read_durable_pinned_block_bounded(kura, index, expected, budget, usize::MAX)
}

fn read_durable_pinned_block_bounded(
    kura: &Kura,
    index: NonZeroUsize,
    expected: HashOf<IrohaHeader>,
    budget: &iroha_allocation::AllocationBudget,
    maximum_wire_bytes: usize,
) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<ChainReadError>> {
    #[cfg(all(test, sumeragi_core_mutation = "HC11"))]
    {
        let height = index.get() as u64;
        let unavailable = || ChainReadError::NotInView { height };
        let _ = expected;
        kura.get_block(index, budget)
            .map_err(|error| error.map_rejection(|_| unavailable()))?
            .ok_or_else(|| unavailable().into())
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC11")))]
    {
        native_acquisition::NativeCarrierAcquisition::new(
            kura,
            index,
            expected,
            budget.clone(),
            maximum_wire_bytes,
        )
        .complete()
    }
}

#[cfg(test)]
type TerminalProbe<'v> = Box<dyn FnOnce(&CommittedBlock) + Send + Sync + 'v>;

/// Certified history over one immutable State view or explicit pinned restoration cut.
pub struct CertifiedChain<'v, V: StateReadOnly + ?Sized> {
    source: ChainSource<'v, V>,
    genesis: iroha_data_model::block::SharedSignedBlock,
    genesis_epoch: ValidatorEpochContextV1,
    instance: Hash32,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    prefix: parking_lot::Mutex<Option<VerifiedPrefix>>,
    // Only the move-only AMX borrower selects a terminal target. Ordinary read/reset
    // semantics remain separate; a pending terminal job cannot be silently replaced.
    terminal: Option<terminal_selection::TerminalSelection<'v>>,
    #[cfg(test)]
    terminal_probe: parking_lot::Mutex<Option<TerminalProbe<'v>>>,
    // Only the scoped portable producer enables original canonical-byte capture.
    proof_source_genesis: Option<(u64, Hash)>,
    // Optional persistent cache custody never contributes authority or a proof verdict.
    query_cache: parking_lot::Mutex<Option<QueryCacheOwner>>,
    // Only AMX transfers its actual constructor acquisition into this same reader. The
    // genesis body/control lives above; raw bytes and original source retire here after
    // the prefix/terminal graphs at the caller's existing scoped chain drop.
    amx_genesis_authentication: Option<iroha_data_model::sumeragi_finality::OriginalGenesisRead>,
    amx_genesis_source: Option<native_acquisition::NativeCarrierAcquisition<'v>>,
}

impl<V: StateReadOnly + ?Sized> core::fmt::Debug for CertifiedChain<'_, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CertifiedChain")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl<'v, V: StateReadOnly + ?Sized> CertifiedChain<'v, V> {
    /// A reader over `view` with exact BLS quorum and native source checks.
    ///
    /// # Errors
    /// The view has no genesis, or Kura's genesis is not the view's network genesis.
    pub fn new(view: &'v V) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        Self::from_source(ChainSource::State(view))
    }

    fn from_source(
        source: ChainSource<'v, V>,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let genesis = source.block(GENESIS_HEIGHT)?;
        Self::from_genesis(source, genesis)
    }

    fn from_genesis(
        source: ChainSource<'v, V>,
        genesis: iroha_data_model::block::SharedSignedBlock,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let (genesis_epoch, instance, root_scope) =
            authenticate_genesis(&genesis, source.network_id(), source.chain_id())?;
        Ok(Self::from_authenticated_genesis(
            source,
            genesis,
            genesis_epoch,
            instance,
            root_scope,
        ))
    }

    // Private construction consumes only the projection returned by the original
    // guarded authentication above; no public API accepts an unchecked epoch.
    fn from_authenticated_genesis(
        source: ChainSource<'v, V>,
        genesis: iroha_data_model::block::SharedSignedBlock,
        genesis_epoch: ValidatorEpochContextV1,
        instance: Hash32,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Self {
        Self {
            source,
            genesis,
            genesis_epoch,
            instance,
            root_scope,
            prefix: parking_lot::Mutex::new(None),
            terminal: None,
            #[cfg(test)]
            terminal_probe: parking_lot::Mutex::new(None),
            proof_source_genesis: None,
            query_cache: parking_lot::Mutex::new(None),
            amx_genesis_authentication: None,
            amx_genesis_source: None,
        }
    }

    fn verification_context(&self) -> PrefixVerifierContext {
        PrefixVerifierContext {
            instance: self.instance,
            root_scope: self.root_scope,
        }
    }

    /// Exact immutable scope retained from the authenticated signed genesis.
    #[must_use]
    pub const fn root_scope(&self) -> iroha_data_model::block::consensus::SumeragiRootScope {
        self.root_scope
    }

    /// The chain instance `I` every certificate must name.
    #[must_use]
    pub fn instance(&self) -> Hash32 {
        self.instance
    }

    /// The signed genesis body (the chain's trust root). Its result-only certificate was added
    /// after execution and is not authenticated by the genesis signatures.
    #[must_use]
    pub fn genesis(&self) -> &iroha_data_model::block::SharedSignedBlock {
        &self.genesis
    }

    /// The source-pinned receipt of `height` ([`committed_block`]).
    /// This method checks the frame and source identity, not local quorum signatures. In the
    /// pinned restoration mode, consume [`Self::certified`] or [`Self::walk`] before trusting
    /// execution or epoch progress; a pinned header hash alone does not authenticate those.
    ///
    /// # Errors
    /// See [`committed_block`].
    pub fn committed(
        &self,
        height: u64,
    ) -> Result<CommittedBlock, ExecutionAttemptError<ChainReadError>> {
        match &self.source {
            ChainSource::State(view) => committed_block(*view, height),
            ChainSource::Pinned { .. } | ChainSource::Frames { .. } => {
                read_frame(self.source.block(height)?, height, self.root_scope)
            }
        }
    }

    /// The committed block at `height` with its local `CommitQC` checked (see the module
    /// documentation).
    ///
    /// # Errors
    /// The committed read fails, the certificate does not certify the stored header and result,
    /// names another instance, or does not verify under the committee of its height.
    pub fn certified(
        &self,
        height: u64,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        if self
            .terminal
            .as_ref()
            .is_some_and(|pending| !pending.delivered())
        {
            return Err(ChainReadError::NotInView { height }.into());
        }
        self.check_certificate(self.source.block(height)?, height)
    }

    /// The exact authenticated epoch committee and its original proofs of possession.
    /// The complete prefix authenticates historical authority even after World rotates it out.
    ///
    /// # Errors
    /// The signed genesis or certified prefix does not authenticate this height's authority.
    pub fn proof_committee(
        &self,
        height: u64,
    ) -> Result<Vec<(IrohaPublicKey, Vec<u8>)>, ExecutionAttemptError<ChainReadError>> {
        let certified = self.certified(height)?;
        Ok(certified
            .commitment()
            .schedule
            .current
            .committee
            .iter()
            .map(|member| {
                (
                    member.validator.public_key().clone(),
                    member.proof_of_possession.clone(),
                )
            })
            .collect())
    }

    /// The certified blocks `from..=to`, oldest first, each checked to extend the previous one.
    /// The iterator stops after the first error.
    pub fn walk(
        &self,
        from: u64,
        to: u64,
    ) -> impl Iterator<Item = Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>>> + '_
    {
        let mut parent: Option<WalkParentLink> = None;
        let mut failed = false;
        (from..=to).map_while(move |height| {
            if failed {
                return None;
            }
            let read = self.certified(height).and_then(|block| match &parent {
                Some(parent) if !parent.is_extended_by(&block) => {
                    Err(ChainReadError::Discontinuous { height }.into())
                }
                _ => Ok(block),
            });
            match &read {
                Ok(block) => parent = Some(WalkParentLink::from_committed(&block.committed)),
                Err(_) => failed = true,
            }
            Some(read)
        })
    }

    /// Enable local original-wire capture without issuing any capability.
    /// Full native/portable authentication and a fresh byte join still precede reuse.
    pub(crate) fn enable_proof_source_cut(&mut self) {
        self.proof_source_genesis = self.genesis.canonical_wire_identity().ok();
    }

    /// Borrow the constant-size source fence from the genuine native prefix.
    /// This alone conveys no portable admission or continued source availability.
    pub(crate) fn proof_source_cut(&self) -> Option<(u64, Hash)> {
        let cursor = self.prefix.lock();
        let prefix = cursor.as_ref()?;
        Some((prefix.tip.height(), prefix.proof_source?))
    }

    /// Derive authority exclusively from signed genesis, then check the result graph against it.
    /// The graph's execution/parameter data is not independently final until a successor signs Rg.
    fn genesis_prefix(&self) -> Result<VerifiedPrefix, ExecutionAttemptError<ChainReadError>> {
        let genesis = if let Some(original) = &self.amx_genesis_source {
            original.recheck_original_source()?;
            self.genesis.clone()
        } else {
            self.source.block(GENESIS_HEIGHT)?
        };
        self.genesis_prefix_from_original(genesis)
    }

    // The single original result/authority kernel, also used after AMX source retention.
    fn genesis_prefix_from_original(
        &self,
        genesis: iroha_data_model::block::SharedSignedBlock,
    ) -> Result<VerifiedPrefix, ExecutionAttemptError<ChainReadError>> {
        let mut validation = EpochValidationScope::new();
        // AMX lends the same constructor body/bytes, but a partial result/authority graph
        // still retires on failure under the unchanged cumulative decoder context.
        // TODO(S6): retain completed genesis-result/authority stages in actual admitted
        // owners before using this borrower as a release-driven Worker recovery job.
        let tip =
            read_frame_with_validation(genesis, GENESIS_HEIGHT, self.root_scope, &mut validation)?;
        match self.proof_source_genesis {
            Some(expected) => make_genesis_prefix_with_source(
                tip,
                self.genesis_epoch.clone(),
                validation,
                expected,
            ),
            None => make_genesis_prefix(tip, self.genesis_epoch.clone(), validation),
        }
    }

    /// Verify the complete prefix with a bounded working set. Sequential reads reuse its
    /// cursor; an earlier-height read restarts at genesis instead of trusting an unbounded cache.
    fn check_certificate(
        &self,
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        let mut cursor = self.prefix.lock();
        self.prepare_certificate_prefix(&mut cursor, height)?;
        let prefix = cursor.as_mut().ok_or(ChainReadError::ForeignGenesis)?;
        self.check_certificate_at_prefix(prefix, block, height)
    }

    // Initialize the same signed-genesis cursor before target/gap receipt slots are live.
    // The caller retains the lock across this stage and all subsequent verification.
    fn prepare_certificate_prefix(
        &self,
        cursor: &mut Option<VerifiedPrefix>,
        height: u64,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        if cursor
            .as_ref()
            .is_none_or(|prefix| prefix.tip.height >= height)
        {
            *cursor = Some(self.genesis_prefix()?);
        }
        Ok(())
    }

    // Genesis decoding has returned before these complete target and gap receipts exist.
    // Preserve target-before-gap reads, verification order and cursor advancement.
    fn check_certificate_at_prefix(
        &self,
        prefix: &mut VerifiedPrefix,
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<ChainReadError>> {
        self.check_certificate_at_prefix_with_progress(prefix, block, height, &mut || Ok(()))
    }

    // The ordinary reader passes a no-op stop predicate. The finite interval
    // uses this same target-before-gap kernel with checks between actual stages.
    // Only target decoding occupies this frame: complete receipt/certificate return
    // temporaries are created after the deep canonical decoder has retired.
    #[inline(never)]
    fn check_certificate_at_prefix_with_progress<E>(
        &self,
        prefix: &mut VerifiedPrefix,
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
        progress: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<CertifiedBlock, E>
    where
        E: From<ExecutionAttemptError<ChainReadError>>,
    {
        progress()?;
        let committed =
            read_frame_with_validation(block, height, self.root_scope, &mut prefix.validation)?;
        progress()?;
        if height != GENESIS_HEIGHT {
            self.advance_certificate_gaps_with_progress(prefix, height, progress)?;
        }
        self.finish_certificate_at_prefix_with_progress(prefix, committed, height, progress)
    }

    // This finish phase consumes the same original decoded receipt only after the
    // target decoder returns. It neither admits another owner nor changes verification.
    #[inline(never)]
    fn finish_certificate_at_prefix_with_progress<E>(
        &self,
        prefix: &mut VerifiedPrefix,
        committed: CommittedBlock,
        height: u64,
        progress: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<CertifiedBlock, E>
    where
        E: From<ExecutionAttemptError<ChainReadError>>,
    {
        if height == GENESIS_HEIGHT {
            if committed.core_hash != prefix.tip.core_hash || committed.result != prefix.tip.result
            {
                return Err(ExecutionAttemptError::from(ChainReadError::ForeignGenesis).into());
            }
            let verified = self.verification_context().verify_certificate(
                committed,
                &prefix.authority,
                None,
                None,
            )?;
            progress()?;
            return Ok(verified);
        }
        progress()?;
        let verified = self
            .verification_context()
            .advance_prefix(prefix, committed, None)?;
        progress()?;
        Ok(verified)
    }

    // Gap decoding runs before the finish phase and returns only unit, so its
    // complete certificate-return temporaries do not occupy the target decode frame.
    // The same original cursor and predicate order remain intact.
    #[inline(never)]
    fn advance_certificate_gaps_with_progress<E>(
        &self,
        prefix: &mut VerifiedPrefix,
        height: u64,
        progress: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<ExecutionAttemptError<ChainReadError>>,
    {
        while prefix
            .tip
            .height
            .checked_add(1)
            .is_some_and(|next| next < height)
        {
            progress()?;
            let next_height = prefix.tip.height + 1;
            let block = self.source.block(next_height)?;
            progress()?;
            let next = read_frame_with_validation(
                block,
                next_height,
                self.root_scope,
                &mut prefix.validation,
            )?;
            progress()?;
            self.verification_context()
                .advance_prefix(prefix, next, None)?;
            progress()?;
        }
        Ok(())
    }
}

impl<'v> CertifiedChain<'v, StateView<'v>> {
    /// Read a bounded, externally pinned, contiguous journal of canonical native frames.
    ///
    /// The caller must apply its explicit byte/allocation limits before decoding the frames.
    /// This constructor borrows that one source; it neither clones block bodies nor builds
    /// another storage owner. `network` must be independently configured, never taken from the
    /// supplied journal. It pins signed genesis; `chain_id` pins every successor's instance.
    /// The supplied hash cut must be exactly coextensive with the frames. A hash alone does not
    /// authenticate a result: consume `certified`/`walk`, which check every certificate for
    /// this reader only. H1 has
    /// only signed-body authority until a genuine successor or independent local execution
    /// authenticates its result.
    ///
    /// # Errors
    /// Rejects an empty or mismatched cut, foreign genesis, or malformed signed genesis.
    /// Subsequent reads reject mismatched bodies, parent links, results, epochs and certificates.
    pub fn from_frames(
        chain_id: &'v ChainId,
        network: &'v NetworkId,
        hashes: &'v [HashOf<IrohaHeader>],
        frames: &'v [iroha_data_model::block::SharedSignedBlock],
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        if hashes.len() != frames.len() {
            return Err(ChainReadError::NotInView {
                height: GENESIS_HEIGHT,
            }
            .into());
        }
        Self::from_source(ChainSource::Frames {
            chain_id,
            network,
            hashes,
            frames,
        })
    }

    /// Verify an exact pinned history cut before a restored State exists.
    ///
    /// No StateView is constructed: that concrete generic type only selects this constructor.
    /// Every body must match the supplied one-based hash cut. Authority comes from verified
    /// signed genesis and the same exact-quorum prefix walk as State-backed offchain reads.
    /// The configured chain ID enters the signature instance checked by every successor QC.
    ///
    /// This is a restoration/offchain boundary. Deterministic instructions must continue using
    /// State-anchored [`committed_block`] and must not depend on local QC availability. A lone
    /// genesis returns only [`QcVerification::Genesis`]: its unsigned result preimage still
    /// requires deterministic replay or an actually verified successor to authenticate execution.
    ///
    /// # Errors
    /// Rejects an empty cut, absent/mismatched genesis body or foreign signed genesis network.
    /// Later reads reject missing bodies, changed pinned hashes, wrong instances and certificates.
    pub(crate) fn from_pinned(
        chain_id: &'v ChainId,
        network: &'v NetworkId,
        hashes: &'v [HashOf<IrohaHeader>],
        kura: &'v Kura,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        Self::from_source(ChainSource::Pinned {
            chain_id,
            network,
            hashes: PinnedHashes::Slice(hashes),
            kura,
            budget: budget.clone(),
            maximum_wire_bytes: usize::MAX,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod refusal_tests;

#[cfg(test)]
#[test]
fn schedule_source_projection_preserves_every_recovery_variant() {
    use iroha_data_model::sumeragi_finality::{ScheduleError, ScheduleSourceError};
    let variants = [
        (
            ChainReadError::NotCommitted { height: 19 },
            ScheduleSourceError::NotCommitted { height: 19 },
        ),
        (
            ChainReadError::NotInView { height: 19 },
            ScheduleSourceError::NotInView { height: 19 },
        ),
        (
            ChainReadError::MissingCertificate { height: 19 },
            ScheduleSourceError::MissingCertificate { height: 19 },
        ),
        (
            ChainReadError::Malformed {
                height: 19,
                reason: "exact source reason".into(),
            },
            ScheduleSourceError::Malformed {
                height: 19,
                reason: "exact source reason".into(),
            },
        ),
        (
            ChainReadError::HeaderMismatch { height: 19 },
            ScheduleSourceError::HeaderMismatch { height: 19 },
        ),
        (
            ChainReadError::ResultMismatch { height: 19 },
            ScheduleSourceError::ResultMismatch { height: 19 },
        ),
        (
            ChainReadError::ExecutionMismatch { height: 19 },
            ScheduleSourceError::ExecutionMismatch { height: 19 },
        ),
        (
            ChainReadError::WrongInstance { height: 19 },
            ScheduleSourceError::WrongInstance { height: 19 },
        ),
        (
            ChainReadError::Discontinuous { height: 19 },
            ScheduleSourceError::Discontinuous { height: 19 },
        ),
        (
            ChainReadError::ForeignGenesis,
            ScheduleSourceError::ForeignGenesis,
        ),
        (
            ChainReadError::Committee {
                height: 19,
                reason: "exact source reason".into(),
            },
            ScheduleSourceError::Committee {
                height: 19,
                reason: "exact source reason".into(),
            },
        ),
        (
            ChainReadError::Certificate {
                height: 19,
                error: CertError::WrongEpoch,
            },
            ScheduleSourceError::Certificate {
                height: 19,
                error: CertError::WrongEpoch,
            },
        ),
    ];
    for (source, expected) in variants {
        assert_eq!(source.to_string(), expected.to_string());
        assert_eq!(ScheduleSourceError::from(source.clone()), expected);
        assert_eq!(
            ScheduleError::from(source),
            ScheduleError::CommittedSource(expected)
        );
    }
}

mod event_execution;
mod execution_read;
mod state_certificate;
pub(crate) use event_execution::read_event_execution;
pub(crate) use execution_read::NativeExecutionReadAttempt;
pub use execution_read::{
    AuthenticatedExecutionBlock, NativeExecutionRead, NativeExecutionReadError,
    NativeExecutionReadLimits, NativeExecutionReadResource, read_authenticated_execution,
};
pub(crate) use state_certificate::{
    ParentServiceError, ParentServicePreparation, VerifiedParentService,
};

#[cfg(test)]
pub(crate) mod relation_counts;

#[cfg(test)]
use iroha_data_model::sumeragi_finality::{CertifiedResultScope, SccpFinalityHeaderV1};

#[cfg(test)]
fn fixture_result_parts(preimage: &[u8]) -> (SccpFinalityHeaderV1, ExecutionResultCommitment) {
    use iroha_data_model::sumeragi_finality::certified_result::X_LEN;
    (
        SccpFinalityHeaderV1::parse(&preimage[..X_LEN]).unwrap(),
        ExecutionResultCommitment::decode(&preimage[X_LEN..]).unwrap(),
    )
}

#[cfg(test)]
fn fixture_result_preimage(
    header: &SccpFinalityHeaderV1,
    body: &ExecutionResultCommitment,
) -> Vec<u8> {
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&norito::encode_canonical(body).unwrap());
    bytes
}

#[cfg(test)]
pub(crate) use state_certificate::{ParentServiceAdmissionProbe, observe_parent_service_admission};
