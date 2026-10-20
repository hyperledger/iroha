//! Borrowed projection of executed lane merges to their original signed proposal.

use super::*;
use crate::{
    consensus::{FinalizedGlobalThresholdBeaconPulseV1, NposConsensusEffects},
    da::pin_intent::DaPinIntentBundle,
    sumeragi_lanes::{SumeragiLaneMerge, SumeragiLaneMergeSection},
};

/// The sole `SignedBlock` payload layout, with only execution-derived fields projected.
#[derive(Encode)]
pub(super) struct Proposal<'a> {
    signatures: OutputFieldRef<'a, BlockSignatures>,
    payload: Payload<'a>,
    result: Option<OutputFieldRef<'a, BlockResult>>,
    commit_certificate: Option<OutputFieldRef<'a, CommitCertificate>>,
}
impl norito::NoritoSchema for Proposal<'_> {
    fn nominal_name() -> String {
        <SignedBlock as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <SignedBlock as norito::NoritoSchema>::frame_name()
    }
}
impl<'a> Proposal<'a> {
    pub(super) fn new(block: &'a SignedBlock) -> Result<Self, NoritoFrameError> {
        Ok(Self {
            signatures: OutputFieldRef(&block.signatures),
            payload: Payload::new(&block.payload)?,
            result: None,
            commit_certificate: None,
        })
    }
    pub(super) fn materialize(self) -> SignedBlock {
        SignedBlock {
            signatures: self.signatures.0.clone(),
            payload: BlockPayload {
                header: self.payload.header,
                external_entrypoints: self.payload.external_entrypoints.0.to_vec(),
                da_commitments: self.payload.da_commitments.0.clone(),
                da_proof_policies: self.payload.da_proof_policies.0.clone(),
                da_pin_intents: self.payload.da_pin_intents.0.clone(),
                npos_consensus_effects: self.payload.npos_consensus_effects.0.clone(),
                global_beacon_pulse: *self.payload.global_beacon_pulse.0,
                execution_context: self.payload.execution_context.map(|context| {
                    BlockExecutionContextBundle {
                        version: context.version,
                        external: context.external.0.to_vec(),
                        lane_merge: context.lane_merge.map(|merge| SumeragiLaneMergeSection {
                            merges: merge.merges.0.to_vec(),
                            time_floor_ms: merge.time_floor_ms,
                            merged_count: merge.merged_count,
                        }),
                    }
                }),
            },
            result: None,
            commit_certificate: None,
        }
    }
    pub(super) fn shape(&self) -> (BlockHeader, usize, Option<usize>) {
        (
            self.payload.header,
            self.payload.external_entrypoints.0.len(),
            self.payload
                .execution_context
                .as_ref()
                .map(|context| context.external.0.len()),
        )
    }
    pub(super) fn same_content(&self, other: &Self) -> bool {
        self.signatures.0 == other.signatures.0 && self.payload == other.payload
    }
    pub(super) fn checked_payload_len(&self) -> Result<usize, NoritoFrameError> {
        let _flags = norito::core::DecodeFlagsGuard::enter(default_encode_flags());
        let len = norito::core::encoded_payload_len(self)?;
        u64::try_from(len).map_err(|_| NoritoFrameError::LengthMismatch)?;
        enforce_payload_len_limit(len)?;
        Ok(len)
    }
}

/// Borrow only the original prefix; the codec owns all sequence framing.
#[derive(PartialEq, Eq)]
struct Elements<'a, T>(&'a [T]);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for Elements<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), NoritoFrameError> {
        norito::core::write_element_sequence::<T, _>(writer, self.0.iter())
    }
}

#[derive(Encode, PartialEq, Eq)]
struct Merge<'a> {
    merges: Elements<'a, SumeragiLaneMerge>,
    time_floor_ms: u64,
    merged_count: u32,
}
impl<'a> From<&'a SumeragiLaneMergeSection> for Merge<'a> {
    fn from(section: &'a SumeragiLaneMergeSection) -> Self {
        Self {
            merges: Elements(&section.merges),
            time_floor_ms: section.time_floor_ms,
            merged_count: 0,
        }
    }
}

#[derive(Encode, PartialEq, Eq)]
struct Context<'a> {
    version: u8,
    external: Elements<'a, ExternalExecutionContext>,
    lane_merge: Option<Merge<'a>>,
}

#[derive(Encode, PartialEq, Eq)]
struct Payload<'a> {
    header: BlockHeader,
    external_entrypoints: Elements<'a, TransactionEntrypoint>,
    da_commitments: OutputFieldRef<'a, Option<DaCommitmentBundle>>,
    da_proof_policies: OutputFieldRef<'a, Option<DaProofPolicyBundle>>,
    da_pin_intents: OutputFieldRef<'a, Option<DaPinIntentBundle>>,
    npos_consensus_effects: OutputFieldRef<'a, Option<NposConsensusEffects>>,
    global_beacon_pulse: OutputFieldRef<'a, Option<FinalizedGlobalThresholdBeaconPulseV1>>,
    execution_context: Option<Context<'a>>,
}
impl<'a> Payload<'a> {
    fn new(source: &'a BlockPayload) -> Result<Self, NoritoFrameError> {
        let count = source
            .execution_context
            .as_ref()
            .and_then(|context| context.lane_merge.as_ref())
            .map_or(0, |section| section.merged_count);
        let count = usize::try_from(count).map_err(|_| NoritoFrameError::LengthMismatch)?;
        let keep = source
            .external_entrypoints
            .len()
            .checked_sub(count)
            .ok_or_else(|| {
                NoritoFrameError::Message("merged suffix exceeds block entrypoints".into())
            })?;
        if count > 0
            && source
                .execution_context
                .as_ref()
                .is_none_or(|context| context.external.len() != source.external_entrypoints.len())
        {
            return Err(NoritoFrameError::Message(
                "merged entrypoints and contexts differ in length".into(),
            ));
        }
        let external = &source.external_entrypoints[..keep];
        let execution_context = source.execution_context.as_ref().map(|context| Context {
            version: context.version,
            external: Elements(if count == 0 {
                &context.external
            } else {
                &context.external[..keep]
            }),
            lane_merge: context.lane_merge.as_ref().map(Merge::from),
        });
        let mut header = source.header;
        if count > 0 {
            header.merkle_root = MerkleTree::<TransactionEntrypoint>::root_from_typed_leaves(
                external.iter().map(|entrypoint| entrypoint.hash()),
            );
            let context = execution_context
                .as_ref()
                .expect("nonzero merge has a context");
            let mut codec_error = None;
            let hash = Hash::new_from_writer(|mut writer| {
                norito::codec::encode_adaptive_into(context, &mut writer)
                    .map(|_| ())
                    .map_err(|error| {
                        codec_error = Some(error);
                        std::io::Error::other("proposal context encoding failed")
                    })
            });
            if let Some(error) = codec_error {
                return Err(error);
            }
            header.set_execution_context_hash(Some(HashOf::from_untyped_unchecked(
                hash.map_err(NoritoFrameError::from)?,
            )));
        }
        Ok(Self {
            header,
            external_entrypoints: Elements(external),
            da_commitments: OutputFieldRef(&source.da_commitments),
            da_proof_policies: OutputFieldRef(&source.da_proof_policies),
            da_pin_intents: OutputFieldRef(&source.da_pin_intents),
            npos_consensus_effects: OutputFieldRef(&source.npos_consensus_effects),
            global_beacon_pulse: OutputFieldRef(&source.global_beacon_pulse),
            execution_context,
        })
    }
}
