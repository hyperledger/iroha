//! The foreign-committee tracker (§11.7): a light client of another Sumeragi instance.
//!
//! An instance `J` whose certificates another instance verifies changes committees only at epoch
//! boundaries, and the applied boundary result `R_{s−1}` authenticates the complete context of the
//! next epoch (§10). The tracker holds, per foreign instance, the latest verified epoch context
//! `C_{J,e}` and its predecessor `C_{J,e−1}`. It accepts a certified block of `J` only if the
//! block's epoch is `e − 1` or `e` and its `CommitQC` verifies under that epoch's committee; it
//! advances to `e + 1` only through a handoff proof: the certified last block of epoch `e`, whose
//! result carries the boundary decision naming the complete next context. Handoffs are applied
//! in sequence, one per epoch, even when the committee is retained, so members removed at an
//! epoch start cannot certify any height of a later epoch.
//! Participants additionally retain authenticated evicted contexts for their unresolved `Yes`
//! obligations. The internal archive verifier shares every certificate check below; ordinary
//! proofs and handoffs cannot select that historical authority.
//!
//! Certificate verification reuses the core's exact-quorum check
//! ([`iroha_sumeragi::crypto::Verifier::verify_qc`]) over the committee's
//! proof-of-possession-verified BLS keys, as the portable finality proofs do.

use iroha_schema::IntoSchema;
use iroha_sumeragi::{
    crypto::Verifier,
    message::{BlockHeader as CoreHeader, Qc, VoteKind},
    types::Hash32,
};
use norito::codec::{Decode, Encode};

use super::{
    AmxError, AmxRecordProofV1,
    proof::{AmxCertifiedBlockV1, AmxHandoffProofV1, MAX_AMX_HEADER_BYTES, MAX_AMX_QC_BYTES},
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    sumeragi::epoch::ValidatorEpochContextV1,
    sumeragi_finality::{
        CertifiedResultScope, CertifiedResultV1, ExecutionResultCommitment, FinalityValidator,
        MAX_RESULT_PREIMAGE_BYTES, ProofCrypto, core_epoch, result_of_preimage,
    },
};

/// The tracked committees of one foreign Sumeragi instance.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxForeignInstanceV1")]
pub struct AmxForeignInstanceV1 {
    /// Consensus instance id `I_J`.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub instance: [u8; 32],
    /// Original registered root class; supplied with the independent epoch authority,
    /// never inferred from an offered result header.
    pub result_scope: CertifiedResultScope,
    /// Latest verified epoch context `C_{J,e}`.
    pub current: ValidatorEpochContextV1,
    /// Its verified predecessor `C_{J,e−1}`; absent until the first handoff.
    #[norito(required)]
    pub previous: Option<ValidatorEpochContextV1>,
}

/// A certified block of a foreign instance that verified under a tracked committee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmxVerifiedBlock {
    /// Height of the block.
    pub height: u64,
    /// Scheduling epoch of the block.
    pub epoch: u64,
    /// Core block hash.
    pub block_hash: [u8; 32],
    /// Certified result `R`.
    pub result: [u8; 32],
    /// The verified complete preimage of `R`, including the finality header.
    certified_result: CertifiedResultV1,
}

impl AmxVerifiedBlock {
    /// The certified execution body, borrowed from its retained finality wrapper.
    #[must_use]
    pub const fn commitment(&self) -> &ExecutionResultCommitment {
        self.certified_result.commitment()
    }

    /// The complete authenticated result, including its finality header.
    #[must_use]
    pub const fn certified_result(&self) -> &CertifiedResultV1 {
        &self.certified_result
    }
}

/// What a handoff proof did to a tracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmxHandoffOutcome {
    /// The tracker advanced to this epoch.
    Advanced {
        /// The new latest tracked epoch.
        epoch: u64,
    },
    /// The proof hands off into an epoch the tracker already holds; nothing changed.
    Stale,
}

fn proof_error(reason: impl Into<String>) -> AmxError {
    AmxError::Proof(reason.into())
}

fn need(condition: bool, reason: &str) -> Result<(), AmxError> {
    if condition {
        Ok(())
    } else {
        Err(proof_error(reason))
    }
}

impl AmxForeignInstanceV1 {
    /// Start tracking instance `instance` from an independently authenticated epoch context
    /// (its signed genesis context, or a context its governance registered).
    ///
    /// # Errors
    /// The anchor context is invalid.
    pub fn new(
        instance: [u8; 32],
        anchor: ValidatorEpochContextV1,
        result_scope: CertifiedResultScope,
    ) -> Result<Self, AmxError> {
        let tracker = Self {
            instance,
            result_scope,
            current: anchor,
            previous: None,
        };
        tracker.validate()?;
        Ok(tracker)
    }

    /// Latest tracked epoch `e`.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.current.authorization.epoch
    }

    /// Check the tracked contexts: each valid, and the current one an exact successor of the
    /// previous one.
    ///
    /// # Errors
    /// An invalid context or a broken succession.
    pub fn validate(&self) -> Result<(), AmxError> {
        self.current.validate().map_err(AmxError::Anchor)?;
        if let Some(previous) = &self.previous {
            self.current
                .validate_successor(previous)
                .map_err(AmxError::Anchor)?;
        }
        Ok(())
    }

    /// The tracked context of scheduling epoch `epoch` (`e` or `e − 1`).
    fn context(&self, epoch: u64) -> Result<&ValidatorEpochContextV1, AmxError> {
        if epoch == self.epoch() {
            return Ok(&self.current);
        }
        match &self.previous {
            Some(previous) if previous.authorization.epoch == epoch => Ok(previous),
            _ => Err(AmxError::EpochNotTracked {
                epoch,
                tracked: self.epoch(),
            }),
        }
    }

    /// Verify a certified block of this instance: its epoch is tracked, its `CommitQC` has exactly
    /// a quorum of valid signatures of that epoch's committee over this header and result, and its
    /// result preimage hashes to the certified `R`. The retained scope comes from the authenticated
    /// source role, never the result header. This compact proof has no block timestamp, so
    /// it cannot independently check C5; the quorum authenticates that time.
    ///
    /// # Errors
    /// Oversized or malformed parts, an untracked epoch, or any failed binding or signature.
    pub fn verify_block(&self, block: &AmxCertifiedBlockV1) -> Result<AmxVerifiedBlock, AmxError> {
        self.verify_block_with_contexts(block, &[])
    }

    fn verify_block_with_contexts(
        &self,
        block: &AmxCertifiedBlockV1,
        decision_contexts: &[ValidatorEpochContextV1],
    ) -> Result<AmxVerifiedBlock, AmxError> {
        need(
            !block.consensus_header.is_empty()
                && block.consensus_header.len() <= MAX_AMX_HEADER_BYTES
                && !block.commit_qc.is_empty()
                && block.commit_qc.len() <= MAX_AMX_QC_BYTES
                && !block.result_preimage.is_empty()
                && block.result_preimage.len() <= MAX_RESULT_PREIMAGE_BYTES,
            "certified block parts are empty or exceed their bounds",
        )?;
        let header: CoreHeader = norito::core::classify_decode_attempt(|| {
            norito::decode_canonical(&block.consensus_header)
        })
        .map_err(|error| super::proof_codec_error(error, "core header"))?;
        let context = self.context(header.epoch.epoch).or_else(|error| {
            decision_contexts
                .binary_search_by_key(&header.epoch.epoch, |context| context.authorization.epoch)
                .map(|index| &decision_contexts[index])
                .map_err(|_| error)
        })?;
        let epoch = core_epoch(context).map_err(|error| AmxError::Anchor(error.to_string()))?;
        need(
            header.instance.0 == self.instance,
            "the block belongs to another instance",
        )?;
        need(
            header.epoch == epoch.id && epoch.contains(header.height),
            "the block is outside its tracked epoch context",
        )?;
        let qc: Qc =
            norito::core::classify_decode_attempt(|| norito::decode_canonical(&block.commit_qc))
                .map_err(|error| super::proof_codec_error(error, "commit certificate"))?;
        let validators: Vec<FinalityValidator> = context
            .committee
            .iter()
            .map(|member| FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession.clone(),
            })
            .collect();
        let (crypto, committee) =
            ProofCrypto::new(&validators).map_err(|error| AmxError::Anchor(error.to_string()))?;
        let block_hash = header.hash(&crypto);
        need(
            qc.kind == VoteKind::Commit
                && qc.instance == header.instance
                && qc.epoch == header.epoch
                && qc.height == header.height
                && qc.block_hash == block_hash,
            "the certificate is not a CommitQC of this header",
        )?;
        Verifier::new(&crypto, &header.instance, &epoch.id, &committee)
            .verify_qc(&qc)
            .map_err(|error| proof_error(format!("commit certificate: {error:?}")))?;
        need(
            result_of_preimage(&block.result_preimage) == Some(qc.result),
            "the result preimage does not hash to the certified result",
        )?;
        // AMX tracks both the global coordinator and foreign roots. Preserve the original
        // registered scope; the offered X cannot select or widen that authority.
        let certified_result = CertifiedResultV1::decode(&block.result_preimage, self.result_scope)
            .map_err(super::certified_result_error)?;
        let commitment = certified_result.commitment();
        need(
            commitment.height == header.height && commitment.schedule.current == *context,
            "the result preimage names another height or epoch context",
        )?;
        let Hash32(result) = qc.result;
        Ok(AmxVerifiedBlock {
            height: header.height,
            epoch: header.epoch.epoch,
            block_hash: block_hash.0,
            result,
            certified_result,
        })
    }

    /// Verify a record proof of this instance: the certified block verifies (see
    /// [`Self::verify_block`]) and the record's write is in its ordinary-write root.
    ///
    /// # Errors
    /// A malformed record, a failed block verification or a path to another root.
    pub fn verify_record(&self, proof: &AmxRecordProofV1) -> Result<AmxVerifiedBlock, AmxError> {
        self.verify_record_with_contexts(proof, &[])
    }

    /// Verify with additional authority retained in committed participant State from this
    /// tracker's authenticated handoffs. The participant restricts this path to the exact
    /// unresolved `Yes` obligation and checks its authenticated decision-height interval.
    pub(super) fn verify_record_with_contexts(
        &self,
        proof: &AmxRecordProofV1,
        decision_contexts: &[ValidatorEpochContextV1],
    ) -> Result<AmxVerifiedBlock, AmxError> {
        let root = proof.claimed_root()?;
        let verified = self.verify_block_with_contexts(&proof.block, decision_contexts)?;
        need(
            root == verified.commitment().execution.ordinary_writes_root,
            "the record is not in the block's write set",
        )?;
        Ok(verified)
    }

    /// Apply a handoff proof: the certified last block of the latest tracked epoch `e` whose
    /// result decides the boundary. The tracker then holds `e + 1` and `e`.
    ///
    /// # Errors
    /// The block does not verify, is of an epoch beyond `e` (an earlier handoff is missing), is
    /// not the last block of `e`, or carries no valid boundary decision.
    pub fn apply_handoff(
        &mut self,
        proof: &AmxHandoffProofV1,
    ) -> Result<AmxHandoffOutcome, AmxError> {
        self.apply_handoff_retaining_evicted(proof)
            .map(|(outcome, _)| outcome)
    }

    /// Move the evicted authenticated context to its participant's obligation archive.
    pub(super) fn apply_handoff_retaining_evicted(
        &mut self,
        proof: &AmxHandoffProofV1,
    ) -> Result<(AmxHandoffOutcome, Option<ValidatorEpochContextV1>), AmxError> {
        let verified = self.verify_block(&proof.block)?;
        if verified.epoch != self.epoch() {
            // Verified under `C_{e−1}`: the handoff into `e`, which the tracker already holds.
            return Ok((AmxHandoffOutcome::Stale, None));
        }
        need(
            verified.height == self.current.authorization.last_height,
            "a handoff is the last block of its epoch",
        )?;
        let boundary = verified
            .commitment()
            .schedule
            .boundary
            .as_ref()
            .ok_or_else(|| proof_error("the boundary block carries no boundary decision"))?;
        boundary
            .validate_against(&self.current)
            .map_err(proof_error)?;
        let next = boundary.next.clone();
        let evicted = self
            .previous
            .replace(std::mem::replace(&mut self.current, next));
        Ok((
            AmxHandoffOutcome::Advanced {
                epoch: self.epoch(),
            },
            evicted,
        ))
    }
}
