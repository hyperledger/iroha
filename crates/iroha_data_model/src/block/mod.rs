//! This module contains `Block` and related implementations.
//!
//! `Block`s are organized into a linear sequence over time (also known as the block chain).
#[cfg(any(test, feature = "transparent_api"))]
use self::execution_output::ExecutionOutputV1;
use self::proofs::{BlockReceiptProof, ExecutionReceiptProof};
use crate::da::commitment::{
    DaCommitmentBundle, DaProofPolicy, DaProofPolicyBundle, DaProofScheme,
};
#[cfg(any(test, feature = "test-fixtures"))]
use crate::da::pin_intent::DaPinIntentBundle;
use iroha_crypto::{Hash, HashOf, MerkleTree, SignatureOf};
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    core::{
        Compression, Error as NoritoFrameError, MAGIC, VERSION_MAJOR, VERSION_MINOR,
        default_encode_flags, hardware_crc64 as norito_crc64,
    },
};
#[cfg(any(test, feature = "transparent_api"))]
use std::collections::{BTreeMap, BTreeSet};
use std::{convert::TryInto, fmt, format, string::String, time::Duration, vec::Vec};
pub mod proofs;
/// Finality-verified historical retail activation; not a current-state proof.
pub mod retail_activation_proof;
/// Root-relative retail state inclusion; supplied root still needs current finality.
pub mod retail_state_map_inclusion;
fn enforce_payload_len_limit(len: usize) -> Result<(), NoritoFrameError> {
    let limit = norito::core::max_archive_len();
    if limit == u64::MAX {
        return Ok(());
    }
    let len_u64 = len as u64;
    if len_u64 > limit {
        return Err(NoritoFrameError::ArchiveLengthExceeded {
            length: len_u64,
            limit,
        });
    }
    Ok(())
}
#[cfg(any(test, feature = "transparent_api"))]
#[doc = "Builder utilities for constructing blocks in transparent API mode."]
pub mod builder;
/// Sumeragi finality proof stored with a committed block.
pub mod commit_certificate;
#[doc = "Consensus parameters, height context and diagnostics shared by Sumeragi components."]
pub mod consensus;
#[doc = "Durable execution context committed by block headers."]
pub mod execution_context;
/// Canonical network and invocation outputs; execution authority remains with finality.
pub mod execution_output;
#[doc = "Block header structures and helpers."]
pub mod header;
/// Canonical routing and QueuePlan admission input values.
pub mod lane_admission;
mod native_results;
/// Explicit applying output policy and bounded reservation arithmetic.
pub mod output_budget;
#[cfg(test)]
pub(crate) mod output_test_support;
#[doc = "Payload container types shared between block variants."]
pub mod payload;
mod prepared_signatures;
mod proposal;
mod shared;
/// Canonical ordered block signatures and original-pool preparation.
pub mod signatures;
#[cfg(any(test, feature = "transparent_api"))]
use crate::fastpq::TransferTranscript;
use crate::transaction::signed::{SignedTransaction, TransactionEntrypoint};
pub use commit_certificate::{
    CertificateAdmissionError, ChargedCertificateParts, CommitCertificate,
};
pub use execution_context::{
    BLOCK_EXECUTION_CONTEXT_BUNDLE_VERSION_V1, BlockExecutionContextBundle,
    ExternalExecutionContext, ExternalExecutionRouteLeg, ExternalExecutionRouteRole,
};
pub use header::{BlockHeader as Header, BlockHeader, BlockSignature};
pub use payload::{BlockPayload as Payload, BlockPayload, BlockResult};
pub use prepared_signatures::{PreparedSignatureBlockError, PreparedSignedBlockSignaturesDecode};
pub use shared::{ReservedSharedSignedBlock, SharedBlockAdmissionError, SharedSignedBlock};
pub use signatures::{BlockSignatureCustodyError, BlockSignatures, PreparedBlockSignatures};
#[model]
mod model {
    use super::*;
    /// Block collecting signatures from validators.
    ///
    /// Stored and distributed blocks use [`SignedBlock::canonical_wire`]. A block
    /// cannot use the generic headerless versioned codec, even with inferred types.
    ///
    /// ```compile_fail
    /// use iroha_data_model::block::SignedBlock;
    /// let _: SignedBlock = iroha_version::codec::decode_exact_versioned(&[]).unwrap();
    /// ```
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Encode,
        IntoSchema,
        Decode,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(decode_fields, decode_from_slice)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::block::model::SignedBlock")]
    pub struct SignedBlock {
        /// Signatures of validators who approved this block.
        pub(super) signatures: BlockSignatures,
        /// Block payload to be signed.
        pub(super) payload: BlockPayload,
        /// Secondary block state resulting from execution.
        ///
        /// Blocks constructed prior to validation do not carry execution results.
        pub(super) result: Option<BlockResult>,
        /// Sumeragi finality proof of a committed block (core header, `CommitQC` and the
        /// preimage of the certified result).
        ///
        /// Absent from proposals, from executed blocks before commit and from genesis. It is
        /// never covered by the block hash (a header hash), the proposal wire or the executed
        /// block wire hash.
        pub(super) commit_certificate: Option<CommitCertificate>,
    }
}
pub use self::model::*;
/// Failure to atomically install the one full canonical execution-output collection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetExecutionOutputsError {
    /// The proposal's existing immutable commitments differ from its payload.
    #[error("invalid proposal commitments: {0}")]
    InvalidProposal(String),
    /// Output source, ordering, receipt or transcript structure is inconsistent.
    #[error("invalid execution outputs: {0}")]
    InvalidOutputs(String),
    /// The supplied applying policy or exact output costs are invalid.
    #[error("invalid execution output limits: {0}")]
    InvalidLimits(String),
    /// The AXT snapshot is not canonical.
    #[error("invalid AXT policy snapshot: {0}")]
    InvalidAxtPolicySnapshot(crate::nexus::AxtPolicySnapshotValidationError),
    /// Actual canonical serialization failed while checking the complete wire.
    #[error("cannot encode executed block: {0}")]
    Encoding(String),
    /// The actual complete wire exceeds applying policy.
    #[error("executed block wire is {actual} bytes, above limit {limit}")]
    ExecutedWireTooLarge {
        /// Exact canonical wire length including version and frame.
        actual: u64,
        /// Explicit applying-policy ceiling.
        limit: u64,
    },
}
/// Private payload-only forwarding adapter; no extra codec field/frame is introduced.
#[derive(PartialEq, Eq)]
struct OutputFieldRef<'a, T>(&'a T);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for OutputFieldRef<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), NoritoFrameError> {
        norito::core::SerializePayload::serialize(self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}
/// Encode-only borrow of the sole `SignedBlock` layout for pre-mutation sizing and proposal hashing.
/// No raw source constructor or alternate accepted decoder is exposed.
#[derive(Encode)]
struct SignedBlockOutputCandidate<'a> {
    signatures: OutputFieldRef<'a, BlockSignatures>,
    payload: OutputFieldRef<'a, BlockPayload>,
    result: Option<OutputFieldRef<'a, BlockResult>>,
    /// Always `None`: the executed wire never covers a commit certificate.
    commit_certificate: Option<OutputFieldRef<'a, CommitCertificate>>,
}
impl norito::NoritoSchema for SignedBlockOutputCandidate<'_> {
    fn nominal_name() -> String {
        <SignedBlock as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SignedBlock as norito::NoritoSchema>::frame_name()
    }
}
/// Original proposal and merge inputs retained unchanged after a rejected lane merge.
pub type MergeEntrypointsRejection = (
    SignedBlock,
    Vec<TransactionEntrypoint>,
    Vec<ExternalExecutionContext>,
    &'static str,
);

impl SignedBlock {
    /// Version of the single canonical block wire: a version byte, Norito header and payload.
    pub const WIRE_VERSION: u8 = 1;

    /// Create new block with a given signature
    ///
    /// # Warning
    ///
    /// All transactions are categorized as valid
    #[cfg(any(test, feature = "transparent_api"))]
    pub fn presigned(
        signature: BlockSignature,
        header: BlockHeader,
        transactions: Vec<SignedTransaction>,
    ) -> SignedBlock {
        let external_entrypoints = transactions
            .into_iter()
            .map(TransactionEntrypoint::from)
            .collect();
        SignedBlock {
            signatures: BlockSignatures::try_from_iter([signature])
                .expect("single block signature"),
            payload: BlockPayload {
                header,
                external_entrypoints,
                execution_context: None,
                da_commitments: None,
                da_proof_policies: None,
                da_pin_intents: None,
                npos_consensus_effects: None,
                global_beacon_pulse: None,
            },
            result: None,
            commit_certificate: None,
        }
    }
    /// Create a block with a given signature and an explicit DA commitment bundle.
    ///
    /// The caller is responsible for ensuring `header.da_commitments_hash` matches the supplied
    /// bundle. Signatures are validated against the provided header unchanged.
    #[cfg(feature = "transparent_api")]
    pub fn presigned_with_da(
        signature: BlockSignature,
        header: BlockHeader,
        transactions: Vec<SignedTransaction>,
        da_commitments: Option<DaCommitmentBundle>,
    ) -> SignedBlock {
        let da_commitments = da_commitments.filter(|bundle| !bundle.is_empty());
        let external_entrypoints = transactions
            .into_iter()
            .map(TransactionEntrypoint::from)
            .collect();
        SignedBlock {
            signatures: BlockSignatures::try_from_iter([signature])
                .expect("single block signature"),
            payload: BlockPayload {
                header,
                external_entrypoints,
                execution_context: None,
                da_commitments,
                da_proof_policies: None,
                da_pin_intents: None,
                npos_consensus_effects: None,
                global_beacon_pulse: None,
            },
            result: None,
            commit_certificate: None,
        }
    }
    /// Create a block with no block signature: a Sumeragi proposal, authenticated by the
    /// certified consensus header that binds its bytes rather than by a block signature.
    #[cfg(feature = "transparent_api")]
    #[must_use]
    pub fn unsigned_with_payload(mut payload: BlockPayload) -> SignedBlock {
        payload.da_commitments = payload.da_commitments.filter(|bundle| !bundle.is_empty());
        payload.da_pin_intents = payload.da_pin_intents.filter(|bundle| !bundle.is_empty());
        SignedBlock {
            signatures: BlockSignatures::default(),
            payload,
            result: None,
            commit_certificate: None,
        }
    }
    /// Create a block with a given signature and payload.
    #[cfg(feature = "transparent_api")]
    pub fn presigned_with_payload(
        signature: BlockSignature,
        mut payload: BlockPayload,
    ) -> SignedBlock {
        payload.da_commitments = payload.da_commitments.filter(|bundle| !bundle.is_empty());
        payload.da_pin_intents = payload.da_pin_intents.filter(|bundle| !bundle.is_empty());
        SignedBlock {
            signatures: BlockSignatures::try_from_iter([signature])
                .expect("single block signature"),
            payload,
            result: None,
            commit_certificate: None,
        }
    }
    /// Atomically install actual typed outputs and their one checked Merkle cache.
    ///
    /// This validates structural source ownership and explicit applying-policy costs.
    /// It does not authenticate execution, callbacks, State policy or finality. Every
    /// proposal commitment, header byte and signature remains unchanged. The actual
    /// fragment count is supplied by the execution owner, never inferred from leaves.
    ///
    /// # Errors
    /// Rejects malformed proposal/output structure, noncanonical policy, or any
    /// row/aggregate/complete-wire limit before changing this block.
    #[cfg(any(test, feature = "transparent_api"))]
    #[allow(clippy::too_many_arguments)]
    pub fn set_execution_outputs(
        &mut self,
        outputs: Vec<ExecutionOutputV1>,
        committed_fragment_count: u64,
        fastpq_transcripts: BTreeMap<Hash, Vec<TransferTranscript>>,
        axt_envelopes: Vec<crate::nexus::AxtEnvelopeRecord>,
        axt_policy_snapshot: crate::nexus::AxtPolicySnapshot,
        axt_transitioned_dataspaces: BTreeSet<iroha_model_base::topology::DataSpaceId>,
        limits: &output_budget::ExecutionOutputLimits,
    ) -> Result<(), SetExecutionOutputsError> {
        self.validate_proposal_commitments()
            .map_err(SetExecutionOutputsError::InvalidProposal)?;
        self.validate_output_rows(&outputs, &fastpq_transcripts)
            .map_err(SetExecutionOutputsError::InvalidOutputs)?;
        axt_policy_snapshot
            .validate()
            .map_err(SetExecutionOutputsError::InvalidAxtPolicySnapshot)?;
        limits
            .validate_outputs(&outputs)
            .map_err(SetExecutionOutputsError::InvalidLimits)?;
        let output_merkle = outputs.iter().map(HashOf::new).collect();
        let result = BlockResult {
            outputs,
            output_merkle,
            committed_fragment_count,
            fastpq_transcripts,
            axt_envelopes,
            axt_policy_snapshot,
            axt_transitioned_dataspaces,
        };
        let candidate = SignedBlockOutputCandidate {
            signatures: OutputFieldRef(&self.signatures),
            payload: OutputFieldRef(&self.payload),
            result: Some(OutputFieldRef(&result)),
            commit_certificate: None,
        };
        let frame_len = norito::canonical_frame_len(&candidate)
            .map_err(|error| SetExecutionOutputsError::Encoding(error.to_string()))?;
        let actual = u64::try_from(frame_len)
            .ok()
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| {
                SetExecutionOutputsError::Encoding("executed wire length overflows u64".into())
            })?;
        let limit = limits
            .max_executed_wire_bytes
            .min(consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES);
        if actual > limit {
            return Err(SetExecutionOutputsError::ExecutedWireTooLarge { actual, limit });
        }
        enforce_payload_len_limit(frame_len.saturating_sub(norito::core::Header::SIZE))
            .map_err(|error| SetExecutionOutputsError::Encoding(error.to_string()))?;
        self.result = Some(result);
        Ok(())
    }
    /// Revalidate exact complete executed wire at the publication/proof boundary.
    ///
    /// Attachment does not freeze signatures or authenticate execution. Callers must
    /// check the final bytes again after signature changes and bind them to actual finality.
    /// # Errors
    /// Rejects invalid source/output/cache/policy or row, aggregate, protocol or wire limits.
    pub fn validate_execution_outputs(
        &self,
        limits: &output_budget::ExecutionOutputLimits,
    ) -> Result<(), SetExecutionOutputsError> {
        self.validate_output_merkle_cache()
            .map_err(|error| SetExecutionOutputsError::InvalidOutputs(error.to_string()))?;
        limits
            .validate_outputs(self.execution_outputs())
            .map_err(SetExecutionOutputsError::InvalidLimits)?;
        let candidate = SignedBlockOutputCandidate {
            signatures: OutputFieldRef(&self.signatures),
            payload: OutputFieldRef(&self.payload),
            result: self.result.as_ref().map(OutputFieldRef),
            commit_certificate: None,
        };
        let frame_len = norito::canonical_frame_len(&candidate)
            .map_err(|error| SetExecutionOutputsError::Encoding(error.to_string()))?;
        let actual = u64::try_from(frame_len)
            .ok()
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| {
                SetExecutionOutputsError::Encoding("executed wire length overflows u64".into())
            })?;
        let limit = limits
            .max_executed_wire_bytes
            .min(consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES);
        if actual > limit {
            return Err(SetExecutionOutputsError::ExecutedWireTooLarge { actual, limit });
        }
        enforce_payload_len_limit(frame_len.saturating_sub(norito::core::Header::SIZE))
            .map_err(|error| SetExecutionOutputsError::Encoding(error.to_string()))?;
        Ok(())
    }
    /// Replace the embedded AXT policy snapshot for adversarial validation fixtures.
    ///
    /// Production block construction must use
    /// [`Self::set_execution_outputs`], which rejects
    /// non-canonical snapshots.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn replace_axt_policy_snapshot_for_testing(
        &mut self,
        snapshot: crate::nexus::AxtPolicySnapshot,
    ) -> Option<crate::nexus::AxtPolicySnapshot> {
        self.result
            .as_mut()
            .map(|result| core::mem::replace(&mut result.axt_policy_snapshot, snapshot))
    }
    /// Number of successful execution fragments recorded with this block result.
    #[inline]
    pub fn committed_fragment_count(&self) -> Option<u64> {
        self.result
            .as_ref()
            .map(|result| result.committed_fragment_count)
    }
    /// Produce a network-input proof joined to its exact typed Network output.
    /// The output position and complete input position are independent indices.
    #[must_use]
    pub fn network_execution_proof(
        &self,
        input_hash: &HashOf<TransactionEntrypoint>,
    ) -> Option<proofs::BlockProofs> {
        self.validate_output_merkle_cache().ok()?;
        let input_index = u32::try_from(
            self.network_input_hashes()
                .position(|hash| hash == *input_hash)?,
        )
        .ok()?;
        let (output_index, _) = self.network_output_at(input_index)?;
        let output = self
            .execution_outputs()
            .get(usize::try_from(output_index).ok()?)?
            .clone();
        let tree = self.network_input_merkle_tree();
        Some(proofs::BlockProofs {
            block_height: self.header().height(),
            block_hash: self.hash(),
            executed_block_wire_hash: self.executed_block_wire_hash().ok()?,
            entry_hash: *input_hash,
            entry_commitment: tree.commitment()?,
            entry_proof: BlockReceiptProof::new(*input_hash, tree.get_proof(input_index)?),
            output_commitment: self.output_merkle_commitment()?,
            output_proof: ExecutionReceiptProof::new(output, self.output_proof(output_index)?),
            fastpq_transcripts: self.fastpq_transcripts().clone(),
        })
    }
    /// Whether execution results are attached to this block.
    #[inline]
    #[must_use]
    pub fn has_results(&self) -> bool {
        self.result.is_some()
    }
    /// Whether this block is in the exact resultless shape accepted as a consensus proposal.
    ///
    /// Execution outputs are absent from a canonical proposal. The full output collection is part of
    /// the encoded block and therefore must not be supplied by proposal ingress. A proposal never
    /// carries a commit certificate either.
    #[inline]
    #[must_use]
    pub fn is_resultless_proposal(&self) -> bool {
        self.result.is_none() && self.commit_certificate.is_none()
    }
    /// Return the canonical resultless proposal corresponding to this block.
    ///
    /// Clone the checked original proposal prefix, signatures, and proposal-only header without
    /// cloning execution outputs that the returned proposal must omit.
    ///
    /// The commit certificate is removed as well: a proposal never carries finality.
    ///
    /// Entrypoints appended from merged lane blocks (`specs/sumeragi_lanes.md` §4.3) are execution
    /// inputs, not proposal content: they are removed and the header roots recomputed.
    /// # Errors
    /// Rejects an impossible merged suffix, malformed context alignment, encoding error,
    /// or an original proposal larger than the active archive limit.
    pub fn canonical_resultless_proposal(&self) -> Result<Self, NoritoFrameError> {
        let proposal = proposal::Proposal::new(self)?;
        proposal.checked_payload_len()?;
        Ok(proposal.materialize())
    }

    /// Borrow the original proposal's header after projecting any executed lane suffix.
    ///
    /// Certified lane expansion changes execution roots. Source custody must bind the
    /// original proposal roots instead, without cloning its transactions or evidence.
    /// This projection establishes no signature, lane or execution authority.
    ///
    /// # Errors
    /// Rejects an impossible merged suffix, malformed context alignment or encoding error.
    pub fn canonical_resultless_header(&self) -> Result<BlockHeader, NoritoFrameError> {
        Ok(proposal::Proposal::new(self)?.shape().0)
    }

    /// The lane merge section this block carries, if any.
    #[must_use]
    pub fn lane_merge(&self) -> Option<&crate::sumeragi_lanes::SumeragiLaneMergeSection> {
        self.payload
            .execution_context
            .as_ref()
            .and_then(|context| context.lane_merge.as_ref())
    }

    /// Number of trailing entrypoints that come from merged lane blocks.
    #[must_use]
    pub fn merged_entrypoint_count(&self) -> usize {
        self.lane_merge()
            .map_or(0, |section| {
                usize::try_from(section.merged_count).unwrap_or(usize::MAX)
            })
            .min(self.payload.external_entrypoints.len())
    }

    /// The execution block of a proposal that merges lane blocks: `merged` appended to the
    /// entrypoints (with their `contexts`), the merged count recorded and the header roots
    /// recomputed. The proposal is recovered with [`Self::canonical_resultless_proposal`].
    ///
    /// # Errors
    /// The block is not a resultless proposal with a lane merge section and no merged
    /// entrypoints yet, or `contexts` does not align with `merged`. Rejection returns
    /// the original proposal, merged inputs, contexts, and reason without mutation.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the original proposal and input owners without allocating"
    )]
    pub fn with_merged_entrypoints(
        mut self,
        merged: Vec<TransactionEntrypoint>,
        contexts: Vec<ExternalExecutionContext>,
    ) -> Result<Self, MergeEntrypointsRejection> {
        // All protocol validation precedes mutation. A rejected merge returns the
        // same proposal and both original input vectors, without cloning a graph.
        let check = (|| {
            if !self.is_resultless_proposal() {
                return Err("only a resultless proposal takes merged entrypoints");
            }
            if merged.len() != contexts.len() {
                return Err("merged entrypoints and contexts differ in length");
            }
            let count = u32::try_from(merged.len()).map_err(|_| "too many merged entrypoints")?;
            let context = self
                .payload
                .execution_context
                .as_ref()
                .ok_or("the block carries no lane merge section")?;
            let section = context
                .lane_merge
                .as_ref()
                .ok_or("the block carries no lane merge section")?;
            if section.merged_count != 0 {
                return Err("the block already carries merged entrypoints");
            }
            if context.external.len() != self.payload.external_entrypoints.len() {
                return Err("existing contexts do not align with the entrypoints");
            }
            Ok(count)
        })();
        let count = match check {
            Ok(count) => count,
            Err(reason) => return Err((self, merged, contexts, reason)),
        };
        let context = self
            .payload
            .execution_context
            .as_mut()
            .expect("checked context");
        context
            .lane_merge
            .as_mut()
            .expect("checked merge section")
            .merged_count = count;
        context.external.extend(contexts);
        self.payload.external_entrypoints.extend(merged);
        Self::refresh_entrypoint_roots(&mut self.payload);
        Ok(self)
    }

    fn refresh_entrypoint_roots(payload: &mut BlockPayload) {
        let mut merkle = iroha_crypto::MerkleTree::<TransactionEntrypoint>::default();
        for entrypoint in &payload.external_entrypoints {
            merkle.add(entrypoint.hash());
        }
        payload.header.merkle_root = merkle.root();
        payload
            .header
            .set_execution_context_hash(payload.execution_context.as_ref().map(HashOf::new));
    }
    /// Compare the exact canonical resultless proposals while borrowing both source graphs.
    ///
    /// Both proposals undergo real canonical payload counting and the active archive-limit
    /// check before comparison. All signatures and all eight payload fields participate;
    /// only the execution result is ignored. This avoids whole-proposal encoding buffers,
    /// but instruction equality can still allocate each instruction's encoded payload.
    ///
    /// # Errors
    /// Returns a serialization or length error, including an exceeded active archive limit,
    /// from either resultless proposal. Callers must not treat two errors as equality.
    pub fn checked_resultless_proposal_eq(&self, other: &Self) -> Result<bool, NoritoFrameError> {
        let original = proposal::Proposal::new(self)?;
        let candidate = proposal::Proposal::new(other)?;
        let original_len = original.checked_payload_len()?;
        let candidate_len = candidate.checked_payload_len()?;
        Ok(original_len == candidate_len && original.same_content(&candidate))
    }
    fn checked_raw_resultless_payload_len(&self) -> Result<usize, NoritoFrameError> {
        let proposal = SignedBlockOutputCandidate {
            signatures: OutputFieldRef(&self.signatures),
            payload: OutputFieldRef(&self.payload),
            result: None,
            commit_certificate: None,
        };
        let _flags = norito::core::DecodeFlagsGuard::enter(default_encode_flags());
        let payload_len = norito::core::encoded_payload_len(&proposal)?;
        // Match the canonical writer's payload-length conversion and archive ceiling.
        u64::try_from(payload_len).map_err(|_| NoritoFrameError::LengthMismatch)?;
        enforce_payload_len_limit(payload_len)?;
        Ok(payload_len)
    }
    /// Exact byte length of this block's canonical resultless, certificate-free proposal wire.
    ///
    /// Counts the checked original proposal prefix without cloning transactions, execution context,
    /// signatures or allocating a complete encoded payload. Includes the version and header.
    ///
    /// # Errors
    /// A serialization, length overflow or active archive-limit error.
    pub fn resultless_proposal_wire_len(&self) -> Result<usize, NoritoFrameError> {
        proposal::Proposal::new(self)?
            .checked_payload_len()?
            .checked_add(1 + norito::core::Header::SIZE)
            .ok_or(NoritoFrameError::LengthMismatch)
    }

    /// Write the canonical resultless, certificate-free proposal while borrowing this block.
    ///
    /// Executed and certified blocks project to their original proposal without copying the
    /// source graph. The writer can use an exact original-pool allocation or a comparison sink.
    /// Encoding and archive limits are checked before writing the first byte. A writer error
    /// may leave a prefix; the caller retains and resets its own destination before retrying.
    ///
    /// # Errors
    /// A serialization, archive-limit or destination I/O error.
    pub fn write_resultless_proposal_wire<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<(), NoritoFrameError> {
        let proposal = proposal::Proposal::new(self)?;
        proposal.checked_payload_len()?;
        writer.write_all(&[Self::WIRE_VERSION])?;
        norito::core::write_canonical_to_writer(&proposal, writer)
    }

    /// Compare this exact borrowed resultless proposal with its canonical complete wire.
    ///
    /// The canonical encoder writes directly into a byte-comparison sink; this does not copy
    /// the payload, decode a second block, or omit signatures or proposal context fields.
    ///
    /// # Errors
    /// Returns canonical encoding or archive-limit errors. A differing frame returns false.
    pub fn matches_resultless_proposal_wire(&self, wire: &[u8]) -> Result<bool, NoritoFrameError> {
        struct Compare<'a> {
            expected: &'a [u8],
            position: usize,
            equal: bool,
        }
        impl std::io::Write for Compare<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let end = self
                    .position
                    .checked_add(bytes.len())
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
                self.equal &= self.expected.get(self.position..end) == Some(bytes);
                self.position = end;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        if !self.is_resultless_proposal() || wire.first() != Some(&Self::WIRE_VERSION) {
            return Ok(false);
        }
        self.checked_raw_resultless_payload_len()?;
        let proposal = SignedBlockOutputCandidate {
            signatures: OutputFieldRef(&self.signatures),
            payload: OutputFieldRef(&self.payload),
            result: None,
            commit_certificate: None,
        };
        let mut compare = Compare {
            expected: &wire[1..],
            position: 0,
            equal: true,
        };
        norito::core::write_canonical_to_writer(&proposal, &mut compare)?;
        Ok(compare.equal && compare.position == compare.expected.len())
    }
    /// Consume the original block and discard its execution result and finality certificate.
    ///
    /// This restores the original proposal prefix and signatures without cloning any
    /// nested transaction or consensus evidence allocation.
    /// # Errors
    /// Returns the unchanged original block and the same malformed-suffix, encoding or
    /// archive-limit error before mutating any part of the source graph.
    #[expect(
        clippy::result_large_err,
        reason = "refusal must return the original graph without allocating an error box"
    )]
    pub fn into_resultless_proposal(mut self) -> Result<Self, (Self, NoritoFrameError)> {
        // Perform the fallible borrowed projection once. Inherited codec counters must
        // not be rechecked after the caller loses its original owner.
        let prepared_shape = (|| {
            let projection = proposal::Proposal::new(&self)?;
            projection.checked_payload_len()?;
            Ok::<_, NoritoFrameError>(projection.shape())
        })();
        let (header, keep, context_keep) = match prepared_shape {
            Ok(shape) => shape,
            Err(error) => return Err((self, error)),
        };
        self.payload.header = header;
        self.payload.external_entrypoints.truncate(keep);
        if let (Some(context), Some(keep)) = (self.payload.execution_context.as_mut(), context_keep)
        {
            context.external.truncate(keep);
            if let Some(merge) = context.lane_merge.as_mut() {
                merge.merged_count = 0;
            }
        }
        self.result = None;
        self.commit_certificate = None;
        Ok(self)
    }
    /// Sumeragi finality proof attached to this committed block, if any.
    #[inline]
    #[must_use]
    pub fn commit_certificate(&self) -> Option<&CommitCertificate> {
        self.commit_certificate.as_ref()
    }
    /// Attach (or with `None`, remove) the Sumeragi finality proof and return the previous one.
    ///
    /// Neither the block hash, the canonical proposal wire nor the executed block wire hash
    /// changes. This setter grants neither finality nor allocation authority. Core verifies
    /// the exact committee and result independently; production publication also requires
    /// original-pool admission of the immutable certificate storage.
    pub fn set_commit_certificate(
        &mut self,
        certificate: Option<CommitCertificate>,
    ) -> Option<CommitCertificate> {
        core::mem::replace(&mut self.commit_certificate, certificate)
    }
    /// Builder form of [`Self::set_commit_certificate`].
    #[must_use]
    pub fn with_commit_certificate(mut self, certificate: Option<CommitCertificate>) -> Self {
        self.commit_certificate = certificate;
        self
    }
    /// Hash the canonical resultless proposal wire.
    ///
    /// # Errors
    /// Returns [`NoritoFrameError`] if the canonical Norito header cannot be emitted.
    pub fn canonical_proposal_wire_hash(&self) -> Result<Hash, NoritoFrameError> {
        let mut codec_error = None;
        let hash = Hash::new_from_writer(|writer| {
            self.write_resultless_proposal_wire(writer)
                .map_err(|error| {
                    codec_error = Some(error);
                    std::io::Error::other("canonical proposal encoding failed")
                })
        });
        if let Some(error) = codec_error {
            return Err(error);
        }
        hash.map_err(NoritoFrameError::from)
    }
    /// Hash this exact canonical block wire, including deterministic execution results.
    ///
    /// The commit certificate is excluded (the wire is hashed with it cleared): the certified
    /// execution result commits to this hash, so the certificate cannot be part of it.
    ///
    /// # Errors
    /// Returns [`NoritoFrameError`] if the canonical Norito header cannot be emitted.
    pub fn executed_block_wire_hash(&self) -> Result<Hash, NoritoFrameError> {
        self.executed_block_wire_identity().map(|(_, hash)| hash)
    }
    /// The byte length and hash of this exact canonical block wire without the node-local
    /// commit certificate (the pair a certified execution result commits to), computed by
    /// borrowing the block and streaming its canonical wire without a complete encoded buffer.
    ///
    /// # Errors
    /// Returns [`NoritoFrameError`] if the canonical Norito header cannot be emitted.
    pub fn executed_block_wire_identity(&self) -> Result<(u64, Hash), NoritoFrameError> {
        let candidate = SignedBlockOutputCandidate {
            signatures: OutputFieldRef(&self.signatures),
            payload: OutputFieldRef(&self.payload),
            result: self.result.as_ref().map(OutputFieldRef),
            commit_certificate: None,
        };
        let _flags = norito::core::DecodeFlagsGuard::enter(default_encode_flags());
        let payload_len = norito::core::encoded_payload_len(&candidate)?;
        enforce_payload_len_limit(payload_len)?;
        let len = payload_len
            .checked_add(1 + norito::core::Header::SIZE)
            .and_then(|len| u64::try_from(len).ok())
            .ok_or(NoritoFrameError::LengthMismatch)?;
        let mut codec_error = None;
        let hash = Hash::new_from_writer(|writer| {
            writer.write_all(&[Self::WIRE_VERSION])?;
            norito::core::write_canonical_to_writer(&candidate, writer).map_err(|error| {
                codec_error = Some(error);
                std::io::Error::other("canonical executed block encoding failed")
            })
        });
        if let Some(error) = codec_error {
            return Err(error);
        }
        Ok((len, hash.map_err(NoritoFrameError::from)?))
    }
    #[inline]
    pub(crate) fn result_ref(&self) -> &BlockResult {
        self.result
            .as_ref()
            .expect("block results are unavailable; block not validated")
    }
    /// Block header
    #[inline]
    pub fn header(&self) -> BlockHeader {
        self.payload.header
    }
    /// Replace the header without rebuilding body Merkle material for adversarial fixtures.
    ///
    /// This is intentionally available only to data-model tests and the
    /// existing `test-fixtures` feature. Production block construction must
    /// use the validated builders and result-attachment APIs.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn replace_header_for_testing(&mut self, header: BlockHeader) -> BlockHeader {
        core::mem::replace(&mut self.payload.header, header)
    }
    /// Replace DA sidecars without canonicalizing empty bundles for adversarial fixtures.
    ///
    /// This is intentionally available only to data-model tests and the
    /// existing `test-fixtures` feature. Production block construction
    /// canonicalizes empty sidecars to absence.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn replace_da_sidecars_for_testing(
        &mut self,
        da_commitments: Option<DaCommitmentBundle>,
        da_pin_intents: Option<DaPinIntentBundle>,
    ) -> (Option<DaCommitmentBundle>, Option<DaPinIntentBundle>) {
        (
            core::mem::replace(&mut self.payload.da_commitments, da_commitments),
            core::mem::replace(&mut self.payload.da_pin_intents, da_pin_intents),
        )
    }
    /// Signatures of peers which approved this block.
    #[inline]
    pub fn signatures(
        &self,
    ) -> impl ExactSizeIterator<Item = &BlockSignature> + DoubleEndedIterator {
        self.signatures.iter()
    }
    /// Whether the canonical ordered signatures retain this exact original finite pool.
    /// This proves physical collection/leaf custody only, never finality or full graph funding.
    pub fn signatures_admitted_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.signatures.admitted_to(budget)
    }
    /// Prepare the exact empty local-construction signature leaf in the original pool.
    ///
    /// Canonical wire bytes, header, payload and all original transaction children are unchanged.
    /// An already admitted same-pool leaf is retained without allocating or replacing its control.
    /// This proves only signature-leaf physical custody, never availability or execution authority.
    /// Ordinary remote decoding and validator admission remain mandatory.
    ///
    /// # Errors
    /// Returns the exact original allocation/control refusal without moving this block. Rejects
    /// signed, executed, certified or foreign-pool profiles without changing their original graph.
    #[cfg(feature = "transparent_api")]
    pub fn prepare_local_unsigned_signature_custody(
        &mut self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), BlockSignatureCustodyError> {
        if !self.is_resultless_proposal() {
            return Err(BlockSignatureCustodyError::UnsignedProfile);
        }
        self.signatures.prepare_local_unsigned(budget)
    }

    /// Whether the two blocks retain one identical prepared signature collection owner.
    /// This identity establishes no execution, availability or finality authorization.
    pub fn same_signature_custody(&self, other: &Self) -> bool {
        BlockSignatures::ptr_eq(&self.signatures, &other.signatures)
    }
    /// Calculate block hash
    #[inline]
    pub fn hash(&self) -> HashOf<BlockHeader> {
        self.payload.header.hash()
    }
    /// Fallibly add additional signature to this block.
    ///
    /// # Errors
    ///
    /// Returns [`iroha_crypto::Error::Signing`] when the configured signing
    /// backend rejects the private-key material or finalized block header hash.
    #[cfg(feature = "transparent_api")]
    pub fn try_sign(
        &mut self,
        private_key: &iroha_crypto::PrivateKey,
        signatory: usize,
    ) -> Result<(), iroha_crypto::Error> {
        self.signatures.try_insert(BlockSignature::new(
            signatory as u64,
            SignatureOf::try_from_hash(private_key, self.payload.header.hash())?,
        ))?;
        Ok(())
    }
    /// Add additional signature to this block.
    #[cfg(feature = "transparent_api")]
    pub fn sign(&mut self, private_key: &iroha_crypto::PrivateKey, signatory: usize) {
        self.try_sign(private_key, signatory)
            .expect("signing should succeed for a valid private key and finalized block header");
    }
    /// Add signature to the block
    ///
    /// # Errors
    ///
    /// if signature is invalid
    #[cfg(feature = "transparent_api")]
    pub fn add_signature(&mut self, signature: BlockSignature) -> Result<(), iroha_crypto::Error> {
        if self.signatures().any(|s| signature.index() == s.index()) {
            return Err(iroha_crypto::Error::Signing(
                "Duplicate signature".to_owned(),
            ));
        }
        self.signatures.try_insert(signature)?;
        Ok(())
    }
    /// Replace signatures without verification
    ///
    /// # Errors
    ///
    /// if there is a duplicate signature
    #[cfg(feature = "transparent_api")]
    pub fn replace_signatures(
        &mut self,
        signatures: BlockSignatures,
    ) -> Result<BlockSignatures, iroha_crypto::Error> {
        if signatures.is_empty() {
            return Err(iroha_crypto::Error::Signing("Signatures empty".to_owned()));
        }
        signatures.iter().map(BlockSignature::index).try_fold(
            BTreeSet::new(),
            |mut acc, elem| {
                if !acc.insert(elem) {
                    return Err(iroha_crypto::Error::Signing(format!(
                        "{elem}: Duplicate signature"
                    )));
                }
                Ok(acc)
            },
        )?;
        if !self.signatures.permits_replacement(&signatures) {
            return Err(iroha_crypto::Error::Signing(
                "block signature replacement changed original custody".into(),
            ));
        }
        Ok(core::mem::replace(&mut self.signatures, signatures))
    }
    /// Creates a canonical resultless genesis proposal signed with the genesis private key.
    ///
    /// `da_commitments` lets the caller embed a [`DaCommitmentBundle`] into the genesis payload once
    /// DA receipts are available during block assembly.
    pub fn genesis(
        transactions: Vec<SignedTransaction>,
        private_key: &iroha_crypto::PrivateKey,
        confidential_features: Option<crate::confidential::ConfidentialFeatureDigest>,
        da_commitments: Option<DaCommitmentBundle>,
    ) -> SignedBlock {
        Self::try_genesis(
            transactions,
            private_key,
            confidential_features,
            da_commitments,
        )
        .expect("genesis block signing should succeed for non-empty transactions and valid key material")
    }
    /// Try to create a canonical resultless genesis proposal signed with the genesis private key.
    ///
    /// `da_commitments` lets the caller embed a [`DaCommitmentBundle`] into the genesis payload once
    /// DA receipts are available during block assembly.
    ///
    /// # Errors
    ///
    /// Returns [`iroha_crypto::Error::Signing`] when the transaction set is
    /// empty or the configured signing backend rejects the private-key material
    /// or finalized genesis header hash.
    pub fn try_genesis(
        transactions: Vec<SignedTransaction>,
        private_key: &iroha_crypto::PrivateKey,
        confidential_features: Option<crate::confidential::ConfidentialFeatureDigest>,
        da_commitments: Option<DaCommitmentBundle>,
    ) -> Result<SignedBlock, iroha_crypto::Error> {
        Self::try_genesis_with_da_proof_policies(
            transactions,
            private_key,
            confidential_features,
            da_commitments,
            None,
        )
    }
    /// Try to create a canonical resultless genesis proposal signed with the genesis private key,
    /// overriding DA proof policies.
    ///
    /// `da_commitments` lets the caller embed a [`DaCommitmentBundle`] into the genesis payload once
    /// DA receipts are available during block assembly.
    ///
    /// # Errors
    ///
    /// Returns [`iroha_crypto::Error::Signing`] when the transaction set is
    /// empty or the configured signing backend rejects the private-key material
    /// or finalized genesis header hash.
    pub fn try_genesis_with_da_proof_policies(
        transactions: Vec<SignedTransaction>,
        private_key: &iroha_crypto::PrivateKey,
        confidential_features: Option<crate::confidential::ConfidentialFeatureDigest>,
        da_commitments: Option<DaCommitmentBundle>,
        da_proof_policies: Option<DaProofPolicyBundle>,
    ) -> Result<SignedBlock, iroha_crypto::Error> {
        use nonzero_ext::nonzero;
        let da_commitments = da_commitments.filter(|bundle| !bundle.is_empty());
        let mut entry_merkle = MerkleTree::default();
        for tx in &transactions {
            entry_merkle.add(tx.hash_as_entrypoint());
        }
        let merkle_root = entry_merkle.root().ok_or_else(|| {
            iroha_crypto::Error::Signing("Genesis block must have transactions".to_owned())
        })?;
        let creation_time_ms = Self::get_genesis_block_creation_time(&transactions);
        let confidential_features = confidential_features.or(Some(
            crate::confidential::DEFAULT_CONFIDENTIAL_FEATURE_DIGEST,
        ));
        let proof_policies = da_proof_policies.unwrap_or_else(|| {
            DaProofPolicyBundle::new(vec![DaProofPolicy {
                lane_id: iroha_model_base::topology::LaneId::SINGLE,
                dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                alias: "default".to_string(),
                proof_scheme: DaProofScheme::MerkleSha256,
            }])
        });
        let proof_policy_hash = HashOf::new(&proof_policies);
        let da_commitments_hash = da_commitments
            .as_ref()
            .and_then(DaCommitmentBundle::merkle_commitment);
        let header = BlockHeader {
            height: nonzero!(1_u64),
            prev_block_hash: None,
            merkle_root: Some(merkle_root),
            da_proof_policies_hash: Some(proof_policy_hash),
            da_commitments_hash,
            da_pin_intents_hash: None,
            npos_effects_hash: None,
            global_beacon_pulse_hash: None,
            execution_context_hash: None,
            creation_time_ms,
            view_change_index: 0,
            confidential_features,
        };
        let signature =
            BlockSignature::new(0, SignatureOf::try_from_hash(private_key, header.hash())?);
        let external_entrypoints: Vec<TransactionEntrypoint> = transactions
            .into_iter()
            .map(TransactionEntrypoint::from)
            .collect();
        let payload = BlockPayload {
            header,
            external_entrypoints,
            execution_context: None,
            da_commitments,
            da_proof_policies: Some(proof_policies),
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        };
        Ok(SignedBlock {
            signatures: BlockSignatures::try_from_iter([signature])
                .map_err(|error| iroha_crypto::Error::Signing(error.to_string()))?,
            payload,
            result: None,
            commit_certificate: None,
        })
    }
    /// Serialize this block into a canonical Norito wire frame (version byte + header + payload).
    ///
    /// # Errors
    /// Returns [`NoritoFrameError`] if constructing the canonical frame header fails.
    pub fn encode_wire(&self) -> Result<Vec<u8>, NoritoFrameError> {
        self.canonical_wire().map(SignedBlockWire::into_vec)
    }
    /// Length and hash of this complete canonical stored frame, including its certificate.
    /// This streams the original graph without allocating another payload or frame vector.
    /// Unlike the execution-result identity, this identity also binds the node-local certificate.
    ///
    /// # Errors
    /// Canonical encoding failure or an encoded length that does not fit in `u64`.
    pub fn canonical_wire_identity(&self) -> Result<(u64, Hash), NoritoFrameError> {
        let length = norito::canonical_frame_len(self)?
            .checked_add(1)
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(NoritoFrameError::LengthMismatch)?;
        let mut codec_error = None;
        let hash = Hash::new_from_writer(|writer| {
            writer.write_all(&[Self::WIRE_VERSION])?;
            norito::core::write_canonical_to_writer(self, writer).map_err(|error| {
                codec_error = Some(error);
                std::io::Error::other("canonical stored block encoding failed")
            })
        });
        if let Some(error) = codec_error {
            return Err(error);
        }
        hash.map(|hash| (length, hash))
            .map_err(NoritoFrameError::from)
    }
    /// Obtain the canonical Norito wire helper for inspecting or framing this block.
    ///
    /// # Errors
    /// Returns [`NoritoFrameError`] if the Norito header cannot be emitted with the V1 layout
    /// flags.
    pub fn canonical_wire(&self) -> Result<SignedBlockWire, NoritoFrameError> {
        let payload = encode_signed_block_payload(self);
        let version = Self::WIRE_VERSION;
        let mut frame = Vec::with_capacity(1 + norito::core::Header::SIZE + payload.len());
        frame.push(version);
        write_signed_block_header(&payload, &mut frame)?;
        frame.extend_from_slice(&payload);
        Ok(SignedBlockWire { frame })
    }
    fn get_genesis_block_creation_time(transactions: &[SignedTransaction]) -> u64 {
        let latest_txn_time = transactions
            .iter()
            .map(SignedTransaction::creation_time)
            .max()
            .expect("INTERNAL BUG: Genesis block is empty");
        let creation_time = latest_txn_time + Duration::from_millis(1);
        creation_time
            .as_millis()
            .try_into()
            .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX")
    }
}
impl fmt::Display for SignedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header())
    }
}
#[cfg(feature = "http")]
pub mod stream {
    //! Blocks for streaming API.
    pub use self::model::*;
    use super::*;
    use iroha_schema::IntoSchema;
    use norito::{
        codec::{Decode, Encode},
        core::{Error as NoritoError, SerializePayload},
    };
    use std::num::NonZeroU64;
    #[model]
    mod model {
        use super::*;
        use std::num::NonZeroU64;
        /// Request sent to subscribe to blocks stream starting from the given height.
        #[derive(
            Debug,
            Clone,
            Copy,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[repr(transparent)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::block::stream::model::BlockSubscriptionRequest")]
        pub struct BlockSubscriptionRequest(pub NonZeroU64);
        /// Message sent by the stream producer containing block.
        #[derive(
            Debug,
            Clone,
            Decode,
            Encode,
            IntoSchema,
            crate :: DeriveJsonSerialize,
            crate :: DeriveJsonDeserialize,
        )]
        #[repr(transparent)]
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::block::stream::model::BlockMessage")]
        pub struct BlockMessage(pub SignedBlock);
    }
    impl From<BlockMessage> for SignedBlock {
        fn from(source: BlockMessage) -> Self {
            source.0
        }
    }
    /// Message sent by the stream producer containing block by shared ownership
    /// without requiring an additional clone of the block data.
    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct BlockMessageSend(pub SharedSignedBlock);

    #[derive(Encode)]
    struct BorrowedBlockMessage<'a>(OutputFieldRef<'a, SignedBlock>);
    impl norito::NoritoSchema for BlockMessageSend {
        fn nominal_name() -> String {
            "iroha_data_model::block::stream::BlockMessageSend".to_owned()
        }
        fn frame_name() -> String {
            <BlockMessage as norito::NoritoSchema>::frame_name()
        }
    }

    impl SerializePayload for BlockMessageSend {
        fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), NoritoError> {
            // The sole BlockMessage layout, borrowed from the original funded graph.
            let msg = BorrowedBlockMessage(OutputFieldRef(self.0.as_ref()));
            SerializePayload::serialize(&msg, writer)
        }
    }
    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{BlockMessage, BlockMessageSend, BlockSubscriptionRequest};
    }
    impl BlockSubscriptionRequest {
        /// Create a new [`BlockSubscriptionRequest`].
        pub fn new(height: NonZeroU64) -> Self {
            Self(height)
        }
    }
}
pub mod error {
    //! Module containing errors that can occur during instruction evaluation
    pub use self::model::*;
    use super::*;
    #[model]
    mod model {
        use super::*;
        /// The reason for rejecting a transaction with new blocks.
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            iroha_macro::FromVariant,
            Decode,
            Encode,
            IntoSchema,
        )]
        pub enum BlockRejectionReason {
            /// Block was rejected during consensus.
            ConsensusBlockRejection,
            /// Block contains transactions already committed.
            ContainsCommittedTransactions,
            /// Block violated the non-empty block policy.
            EmptyBlock,
            /// Previous block hash does not match local expectation.
            PrevBlockHashMismatch,
            /// Previous block height does not match local expectation.
            PrevBlockHeightMismatch,
            /// Merkle root of block contents is invalid.
            MerkleRootMismatch,
            /// Transaction in the block failed admission or validation.
            TransactionValidationFailed,
            /// Block signatures do not match current topology.
            TopologyMismatch,
            /// Block is missing required number of valid signatures.
            InsufficientBlockSignatures,
            /// Block contains signature from an unknown peer.
            UnknownBlockSignatory,
            /// Block signatory does not have an active consensus key for this height/role.
            InactiveConsensusKey,
            /// Block contains an invalid signature payload.
            InvalidBlockSignature,
            /// Block is missing proxy tail signature.
            ProxyTailSignatureMissing,
            /// Block is missing leader signature.
            LeaderSignatureMissing,
            /// Block signature check failed for an unspecified reason.
            OtherSignatureError,
            /// Genesis block validation failed.
            InvalidGenesis,
            /// Block creation time is earlier than previous block.
            BlockInThePast,
            /// Block creation time is in the future relative to local clock.
            BlockInTheFuture,
            /// Block contains transactions created in the future.
            TransactionInTheFuture,
            /// Confidential feature digest does not match local expectation.
            ConfidentialFeatureDigestMismatch,
            /// Proof policy hash does not match the configured lane catalog.
            DaProofPolicyMismatch,
            /// DA shard cursor was missing or regressed.
            DaShardCursorViolation,
            /// Deterministic `NPoS` effects did not match the signed block header or local validation.
            NposEffectsMismatch,
        }
    }

    impl BlockRejectionReason {
        fn json_label(self) -> &'static str {
            match self {
                Self::ConsensusBlockRejection => "ConsensusBlockRejection",
                Self::ContainsCommittedTransactions => "ContainsCommittedTransactions",
                Self::EmptyBlock => "EmptyBlock",
                Self::PrevBlockHashMismatch => "PrevBlockHashMismatch",
                Self::PrevBlockHeightMismatch => "PrevBlockHeightMismatch",
                Self::MerkleRootMismatch => "MerkleRootMismatch",
                Self::TransactionValidationFailed => "TransactionValidationFailed",
                Self::TopologyMismatch => "TopologyMismatch",
                Self::InsufficientBlockSignatures => "InsufficientBlockSignatures",
                Self::UnknownBlockSignatory => "UnknownBlockSignatory",
                Self::InactiveConsensusKey => "InactiveConsensusKey",
                Self::InvalidBlockSignature => "InvalidBlockSignature",
                Self::ProxyTailSignatureMissing => "ProxyTailSignatureMissing",
                Self::LeaderSignatureMissing => "LeaderSignatureMissing",
                Self::OtherSignatureError => "OtherSignatureError",
                Self::InvalidGenesis => "InvalidGenesis",
                Self::BlockInThePast => "BlockInThePast",
                Self::BlockInTheFuture => "BlockInTheFuture",
                Self::TransactionInTheFuture => "TransactionInTheFuture",
                Self::ConfidentialFeatureDigestMismatch => "ConfidentialFeatureDigestMismatch",
                Self::DaProofPolicyMismatch => "DaProofPolicyMismatch",
                Self::DaShardCursorViolation => "DaShardCursorViolation",
                Self::NposEffectsMismatch => "NposEffectsMismatch",
            }
        }
    }

    impl norito::json::FastJsonWrite for BlockRejectionReason {
        fn write_json(&self, out: &mut String) {
            norito::json::write_json_string(self.json_label(), out);
        }
        fn write_json_to(
            &self,
            out: &mut dyn norito::json::JsonWriteSink,
        ) -> Result<(), norito::json::BoundedJsonError> {
            norito::json::write_json_string_to(self.json_label(), out)
        }
    }

    impl norito::json::JsonDeserialize for BlockRejectionReason {
        fn json_deserialize(
            parser: &mut norito::json::Parser<'_>,
        ) -> Result<Self, norito::json::Error> {
            let value = parser.parse_string()?;
            match value.as_str() {
                "ConsensusBlockRejection" => Ok(BlockRejectionReason::ConsensusBlockRejection),
                "ContainsCommittedTransactions" => {
                    Ok(BlockRejectionReason::ContainsCommittedTransactions)
                }
                "EmptyBlock" => Ok(BlockRejectionReason::EmptyBlock),
                "PrevBlockHashMismatch" => Ok(BlockRejectionReason::PrevBlockHashMismatch),
                "PrevBlockHeightMismatch" => Ok(BlockRejectionReason::PrevBlockHeightMismatch),
                "MerkleRootMismatch" => Ok(BlockRejectionReason::MerkleRootMismatch),
                "TransactionValidationFailed" => {
                    Ok(BlockRejectionReason::TransactionValidationFailed)
                }
                "TopologyMismatch" => Ok(BlockRejectionReason::TopologyMismatch),
                "InsufficientBlockSignatures" => {
                    Ok(BlockRejectionReason::InsufficientBlockSignatures)
                }
                "UnknownBlockSignatory" => Ok(BlockRejectionReason::UnknownBlockSignatory),
                "InactiveConsensusKey" => Ok(BlockRejectionReason::InactiveConsensusKey),
                "InvalidBlockSignature" => Ok(BlockRejectionReason::InvalidBlockSignature),
                "ProxyTailSignatureMissing" => Ok(BlockRejectionReason::ProxyTailSignatureMissing),
                "LeaderSignatureMissing" => Ok(BlockRejectionReason::LeaderSignatureMissing),
                "OtherSignatureError" => Ok(BlockRejectionReason::OtherSignatureError),
                "InvalidGenesis" => Ok(BlockRejectionReason::InvalidGenesis),
                "BlockInThePast" => Ok(BlockRejectionReason::BlockInThePast),
                "BlockInTheFuture" => Ok(BlockRejectionReason::BlockInTheFuture),
                "TransactionInTheFuture" => Ok(BlockRejectionReason::TransactionInTheFuture),
                "ConfidentialFeatureDigestMismatch" => {
                    Ok(BlockRejectionReason::ConfidentialFeatureDigestMismatch)
                }
                "DaProofPolicyMismatch" => Ok(BlockRejectionReason::DaProofPolicyMismatch),
                "DaShardCursorViolation" => Ok(BlockRejectionReason::DaShardCursorViolation),
                "NposEffectsMismatch" => Ok(BlockRejectionReason::NposEffectsMismatch),
                other => Err(norito::json::Error::unknown_field(other)),
            }
        }
    }
    impl std::error::Error for BlockRejectionReason {}
}
impl fmt::Display for error::BlockRejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            error::BlockRejectionReason::ConsensusBlockRejection => {
                f.write_str("Block was rejected during consensus")
            }
            error::BlockRejectionReason::ContainsCommittedTransactions => {
                f.write_str("Block contains transactions already committed")
            }
            error::BlockRejectionReason::EmptyBlock => {
                f.write_str("Block contained no committed overlays")
            }
            error::BlockRejectionReason::PrevBlockHashMismatch => {
                f.write_str("Previous block hash mismatch")
            }
            error::BlockRejectionReason::PrevBlockHeightMismatch => {
                f.write_str("Previous block height mismatch")
            }
            error::BlockRejectionReason::MerkleRootMismatch => f.write_str("Merkle root mismatch"),
            error::BlockRejectionReason::TransactionValidationFailed => {
                f.write_str("Transaction validation failed during block processing")
            }
            error::BlockRejectionReason::TopologyMismatch => {
                f.write_str("Block signatures do not match network topology")
            }
            error::BlockRejectionReason::InsufficientBlockSignatures => {
                f.write_str("Block lacks sufficient valid signatures")
            }
            error::BlockRejectionReason::UnknownBlockSignatory => {
                f.write_str("Block signed by unknown peer")
            }
            error::BlockRejectionReason::InactiveConsensusKey => {
                f.write_str("Block signatory does not have an active consensus key")
            }
            error::BlockRejectionReason::InvalidBlockSignature => {
                f.write_str("Block signature is invalid")
            }
            error::BlockRejectionReason::ProxyTailSignatureMissing => {
                f.write_str("Block missing proxy tail signature")
            }
            error::BlockRejectionReason::LeaderSignatureMissing => {
                f.write_str("Block missing leader signature")
            }
            error::BlockRejectionReason::OtherSignatureError => {
                f.write_str("Block signature verification failed for unspecified reason")
            }
            error::BlockRejectionReason::InvalidGenesis => f.write_str("Invalid genesis block"),
            error::BlockRejectionReason::BlockInThePast => {
                f.write_str("Block creation time is earlier than previous block")
            }
            error::BlockRejectionReason::BlockInTheFuture => {
                f.write_str("Block creation time is in the future relative to local clock")
            }
            error::BlockRejectionReason::TransactionInTheFuture => {
                f.write_str("Block contains transactions created in the future")
            }
            error::BlockRejectionReason::ConfidentialFeatureDigestMismatch => {
                f.write_str("Confidential feature digest mismatch")
            }
            error::BlockRejectionReason::DaProofPolicyMismatch => {
                f.write_str("DA proof policy bundle hash mismatch")
            }
            error::BlockRejectionReason::DaShardCursorViolation => {
                f.write_str("DA shard cursor regression or unknown lane")
            }
            error::BlockRejectionReason::NposEffectsMismatch => {
                f.write_str("NPoS consensus effects mismatch")
            }
        }
    }
}
/// Canonical wire representation of a [`SignedBlock`], owning only its framed bytes.
#[derive(Clone)]
pub struct SignedBlockWire {
    frame: Vec<u8>,
}
impl SignedBlockWire {
    /// Consume the wire representation, returning the framed bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.frame
    }
    /// Borrowing accessor for the framed bytes (version byte + Norito header + payload).
    pub fn as_framed(&self) -> &[u8] {
        &self.frame
    }
    /// Clone the framed bytes into an owned vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.frame.clone()
    }
    /// Return the version byte encoded in this frame.
    pub fn version(&self) -> u8 {
        self.frame
            .first()
            .copied()
            .expect("canonical wire always contains a version byte")
    }
    /// Borrow the Norito payload bytes (without version byte or header).
    pub fn payload(&self) -> &[u8] {
        let header_size = norito::core::Header::SIZE;
        &self.frame[1 + header_size..]
    }
}
fn write_signed_block_header(payload: &[u8], out: &mut Vec<u8>) -> Result<(), NoritoFrameError> {
    enforce_payload_len_limit(payload.len())?;
    out.extend_from_slice(MAGIC.as_slice());
    out.push(VERSION_MAJOR);
    out.push(VERSION_MINOR);
    out.extend_from_slice(&norito::schema::identity::frame_hash::<SignedBlock>());
    out.push(Compression::None as u8);
    let len = u64::try_from(payload.len()).map_err(|_| NoritoFrameError::LengthMismatch)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&norito_crc64(payload).to_le_bytes());
    #[cfg(debug_assertions)]
    if norito::debug_trace_enabled() {
        eprintln!(
            "write_signed_block_header default_flags=0x{:02x}",
            default_encode_flags()
        );
    }
    let encode_flags = default_encode_flags();
    #[cfg(debug_assertions)]
    if norito::debug_trace_enabled() {
        eprintln!("write_signed_block_header flags=0x{encode_flags:02x}");
    }
    out.push(encode_flags);
    Ok(())
}
fn validate_signed_block_header(payload: &[u8]) -> Result<(), NoritoFrameError> {
    let header_size = norito::core::Header::SIZE;
    if payload.len() < header_size {
        return Err(NoritoFrameError::LengthMismatch);
    }
    let major = payload[4];
    if major != VERSION_MAJOR {
        return Err(NoritoFrameError::UnsupportedVersion {
            found: major,
            expected: VERSION_MAJOR,
        });
    }
    let minor = payload[5];
    if minor != VERSION_MINOR {
        return Err(NoritoFrameError::UnsupportedMinorVersion {
            found: minor,
            supported: VERSION_MINOR,
        });
    }
    let mut schema_bytes = [0u8; 16];
    schema_bytes.copy_from_slice(&payload[6..22]);
    if schema_bytes != norito::schema::identity::frame_hash::<SignedBlock>() {
        return Err(NoritoFrameError::SchemaMismatch);
    }
    let compression = payload[22];
    if compression != Compression::None as u8 {
        return Err(NoritoFrameError::UnsupportedCompression {
            found: compression,
            supported: &[Compression::None],
        });
    }
    let mut length_bytes = [0u8; 8];
    length_bytes.copy_from_slice(&payload[23..31]);
    let expected_len_u64 = u64::from_le_bytes(length_bytes);
    let limit = norito::core::max_archive_len();
    if expected_len_u64 > limit {
        return Err(NoritoFrameError::ArchiveLengthExceeded {
            length: expected_len_u64,
            limit,
        });
    }
    let expected_len: usize = expected_len_u64
        .try_into()
        .map_err(|_| NoritoFrameError::LengthMismatch)?;
    let mut checksum_bytes = [0u8; 8];
    checksum_bytes.copy_from_slice(&payload[31..39]);
    let checksum = u64::from_le_bytes(checksum_bytes);
    let bare_payload = &payload[header_size..];
    if bare_payload.len() != expected_len {
        return Err(NoritoFrameError::LengthMismatch);
    }
    if norito_crc64(bare_payload) != checksum {
        return Err(NoritoFrameError::ChecksumMismatch);
    }
    let flags = payload[header_size - 1];
    norito::core::validate_header_flags(flags)?;
    if flags != default_encode_flags() {
        return Err(NoritoFrameError::UnsupportedFeature(
            "non-canonical signed block wire layout",
        ));
    }
    Ok(())
}
#[cfg(test)]
fn decode_field<T>(bytes: &[u8]) -> Result<(T, &[u8]), NoritoFrameError>
where
    T: for<'de> norito::NoritoDeserialize<'de> + norito::NoritoSerialize,
{
    if bytes.len() < 8 {
        return Err(NoritoFrameError::LengthMismatch);
    }
    let mut len_prefix = [0u8; 8];
    len_prefix.copy_from_slice(&bytes[..8]);
    let field_len: usize = u64::from_le_bytes(len_prefix)
        .try_into()
        .map_err(|_| NoritoFrameError::LengthMismatch)?;
    let payload = bytes
        .get(8..8 + field_len)
        .ok_or(NoritoFrameError::LengthMismatch)?;
    let (value, used) = norito::core::decode_field_canonical::<T>(payload)?;
    if used != field_len {
        return Err(NoritoFrameError::LengthMismatch);
    }
    let rest = &bytes[8 + field_len..];
    Ok((value, rest))
}
/// Decode the sole canonical framed [`SignedBlock`] wire representation.
///
/// Header, version, fixed first-release layout and exact streaming canonical equality are
/// authenticated by the same owner. Unsupported versions never copy the source frame.
///
/// # Errors
/// Returns the original captured decoder admission error, distinguishing invalid wire bytes
/// from a caller resource refusal even after the enclosing decoder scope has retired.
pub fn decode_framed_signed_block(
    bytes: &[u8],
) -> Result<SignedBlock, norito::core::DecodeAttemptError> {
    norito::core::classify_decode_attempt(|| {
        let (version, framed_payload) = borrow_framed_signed_block_payload(bytes)?;
        decode_framed_versioned_signed_block_inner(version, framed_payload, bytes)
    })
}
fn borrow_framed_signed_block_payload(bytes: &[u8]) -> Result<(u8, &[u8]), NoritoFrameError> {
    let (&version, framed_payload) = bytes
        .split_first()
        .ok_or(NoritoFrameError::LengthMismatch)?;
    validate_signed_block_header(framed_payload)?;
    Ok((version, framed_payload))
}
fn encode_signed_block_payload<T: norito::core::SerializePayload>(block: &T) -> Vec<u8> {
    norito::core::reset_decode_state();
    norito::codec::encode_adaptive(block)
}
fn decode_framed_versioned_signed_block_inner(
    version: u8,
    framed_payload: &[u8],
    source: &[u8],
) -> Result<SignedBlock, NoritoFrameError> {
    struct CanonicalSource<'a> {
        remaining: &'a [u8],
        mismatch: bool,
    }
    impl std::io::Write for CanonicalSource<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining.get(..bytes.len()) != Some(bytes) {
                self.mismatch = true;
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            self.remaining = &self.remaining[bytes.len()..];
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    if version != SignedBlock::WIRE_VERSION {
        return Err(NoritoFrameError::UnsupportedVersion {
            found: version,
            expected: 1,
        });
    }
    let view = norito::core::from_bytes_view(framed_payload)?;
    let block = view.decode::<SignedBlock>()?;
    // Count using the canonical flags; authenticate the source without a second payload or
    // source-sized frame allocation. Header and decoder limits have already bounded input.
    let canonical_len = {
        let _flags = norito::core::DecodeFlagsGuard::enter(default_encode_flags());
        norito::core::encoded_payload_len(&block)?
            .checked_add(1 + norito::core::Header::SIZE)
            .ok_or(NoritoFrameError::LengthMismatch)?
    };
    if canonical_len != source.len() {
        return Err(NoritoFrameError::NonCanonicalEncoding);
    }
    let mut canonical = CanonicalSource {
        remaining: source,
        mismatch: false,
    };
    if std::io::Write::write_all(&mut canonical, &[version]).is_err() {
        return Err(NoritoFrameError::NonCanonicalEncoding);
    }
    let encoded = norito::core::write_canonical_to_writer(&block, &mut canonical);
    if canonical.mismatch {
        return Err(NoritoFrameError::NonCanonicalEncoding);
    }
    // A serializer resource error without a byte mismatch is still the original error.
    encoded?;
    if !canonical.remaining.is_empty() {
        return Err(NoritoFrameError::NonCanonicalEncoding);
    }
    Ok(block)
}
pub mod prelude {
    //! For glob-import
    pub use super::{BlockHeader, BlockSignature, SignedBlock, error::BlockRejectionReason};
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(all(test, feature = "transparent_api"))]
#[path = "output_attachment_tests.rs"]
mod output_attachment_tests;

#[cfg(test)]
#[path = "proposal_wire_hash_tests.rs"]
mod proposal_wire_hash_tests;

#[cfg(all(test, feature = "transparent_api"))]
#[path = "executed_wire_identity_tests.rs"]
mod executed_wire_identity_tests;

#[cfg(all(test, feature = "transparent_api"))]
mod resultless_owner_tests;

#[cfg(all(test, feature = "transparent_api"))]
#[path = "local_unsigned_custody_tests.rs"]
mod local_unsigned_custody_tests;
