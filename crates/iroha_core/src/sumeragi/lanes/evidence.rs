//! Authenticate original lane frames against independently committed lane authority and history.
//!
//! Certificate authentication and admission reproduction are separate: the global merge may
//! advance a Byzantine-certified malformed batch without effect (§4.3), while an evidence
//! consumer claiming a valid lane execution must reproduce admission and its certified result.

mod ancestry;
pub(in crate::sumeragi) mod frame;
pub use ancestry::{LaneAncestry, LaneAncestryError};

use iroha_data_model::{
    NetworkId,
    sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneRecord},
};
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody},
    message::{Qc, VoteKind},
    types::{Hash32, HeightConfig},
};

use super::{
    Admission, AdmissionAttemptError, AdmissionError, AnchorView, LaneChainView, LaneResult, admit,
    global::StatelessChecks, lane_genesis_hash, lane_genesis_result, lane_height_config,
    lane_instance,
};
use crate::sumeragi::crypto::BlsCrypto;

/// Why an original lane frame cannot supply the claimed evidence.
#[derive(Debug, thiserror::Error)]
pub enum LaneEntryError {
    /// The independent record has invalid committee credentials or parameters.
    #[error("invalid pinned lane authority: {0}")]
    Authority(String),
    /// The original frame differs from its independent context or predecessor.
    #[error("lane frame binding: {0}")]
    Binding(&'static str),
    /// The exact native commit quorum does not authenticate the frame and result.
    #[error("lane commit certificate: {0}")]
    Certificate(String),
    /// This reader has not acquired the independently authenticated global anchor.
    #[error("lane admission anchor is not available")]
    UnavailableAnchor,
    /// The certified payload does not reproduce valid lane admission.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Admission could not finish under the reader's inherited local resources.
    #[error("lane evidence decode deferred: {0:?}")]
    Deferred(norito::core::DecodeResourceError),
    /// The independently authenticated anchor read retains its original local retry owner.
    #[error("lane evidence anchor read deferred: {0}")]
    AnchorDeferred(crate::execution_attempt::ExecutionDeferred),
}

impl From<AdmissionAttemptError> for LaneEntryError {
    fn from(error: AdmissionAttemptError) -> Self {
        match error {
            AdmissionAttemptError::Rejected(error) => Self::Admission(error),
            AdmissionAttemptError::Deferred(refusal) => Self::Deferred(refusal),
            AdmissionAttemptError::AnchorDeferred(refusal) => Self::AnchorDeferred(refusal),
        }
    }
}

/// Authenticate a frame's complete commit certificate under an independent lane record.
///
/// `record`, `network`, `chain_id` and `predecessor` must come from authenticated history,
/// never from the supplied frame. This checks signatures and source identity, not the lane
/// admission result; a Byzantine lane quorum can sign arbitrary payload/result bytes.
/// The opaque body must carry the exact complete independent source, including committee,
/// parameters, availability layout and authority generation; its prior verification alone is
/// not authority to relabel it for this record.
///
/// # Errors
/// Invalid pinned credentials, source/predecessor mismatch or invalid exact native quorum.
pub fn verify_lane_certificate(
    record: &SumeragiLaneRecord,
    network: &NetworkId,
    chain_id: &str,
    predecessor: &SumeragiLaneFrontier,
    body: &AvailableBody,
    qc: &Qc,
) -> Result<HeightConfig, LaneEntryError> {
    if record.lane.as_u32() == 0
        || record.incarnation == [0; 32]
        || !iroha_data_model::block::consensus::is_valid_committee_size(record.committee.len())
        || record
            .committee
            .windows(2)
            .any(|pair| pair[0].peer >= pair[1].peer)
    {
        return Err(LaneEntryError::Authority(
            "invalid incarnation or committee order".into(),
        ));
    }
    let config =
        lane_height_config(record).map_err(|error| LaneEntryError::Authority(error.to_string()))?;
    let crypto = BlsCrypto::new();
    crypto
        .admit_committee(
            record
                .committee
                .iter()
                .map(|member| (member.peer.public_key(), member.pop.as_slice())),
        )
        .map_err(|(index, error)| LaneEntryError::Authority(format!("member {index}: {error}")))?;
    let instance = lane_instance(&crypto, network, chain_id, record);
    if predecessor.height == 0
        && (predecessor.block_hash != lane_genesis_hash(network, record).0
            || predecessor.result != lane_genesis_result(record).0)
    {
        return Err(LaneEntryError::Binding(
            "first frame has another lane genesis",
        ));
    }
    let height = predecessor
        .height
        .checked_add(1)
        .ok_or(LaneEntryError::Binding("lane predecessor height overflow"))?;
    let header = body.header();
    if header.height != height
        || header.instance != instance
        || header.epoch != config.epoch.id
        || header.parent_hash != Hash32(predecessor.block_hash)
        || header.parent_result != Hash32(predecessor.result)
        || !header.control_witness.is_empty()
        || header.payload_len > config.params.max_block_bytes
        || usize::try_from(header.proposer).map_or(true, |index| index >= config.committee.n())
        || qc.kind != VoteKind::Commit
        || qc.height != height
        || qc.view < header.origin_view
        || qc.block_hash != body.hash(&crypto)
    {
        return Err(LaneEntryError::Binding(
            "header, predecessor, payload or QC subject differs",
        ));
    }
    iroha_sumeragi::crypto::Verifier::new(&crypto, &instance, &config.epoch.id, &config.committee)
        .verify_qc(qc)
        .map_err(|error| LaneEntryError::Certificate(format!("{error:?}")))?;
    let source = AvailabilitySource::new(instance, height, qc.block_hash, config.clone())
        .map_err(|_| LaneEntryError::Binding("invalid independent availability source"))?;
    if body.source() != &source {
        return Err(LaneEntryError::Binding(
            "body was authenticated under another historical authority",
        ));
    }
    Ok(config)
}

/// Reproduce a certified lane admission under independently authenticated global and lane history.
///
/// This is a strict evidence check, not the global merge's policy for Byzantine-certified
/// malformed batches. It shares the production intrinsic checks and admission implementation.
///
/// # Errors
/// Certificate failure, unavailable anchor, invalid admission or a different certified result.
pub fn verify_lane_entry(
    record: &SumeragiLaneRecord,
    network: &NetworkId,
    chain_id: &str,
    anchors: &impl AnchorView,
    history: &LaneChainView,
    predecessor: &SumeragiLaneFrontier,
    body: &AvailableBody,
    qc: &Qc,
) -> Result<LaneResult, LaneEntryError> {
    let config = verify_lane_certificate(record, network, chain_id, predecessor, body, qc)?;
    let checks = StatelessChecks::new(*network);
    let Admission::Valid(result) = admit(
        record,
        anchors,
        history,
        &checks,
        &config,
        body.payload().as_slice(),
    )?
    else {
        return Err(LaneEntryError::UnavailableAnchor);
    };
    if result.hash() != qc.result {
        return Err(LaneEntryError::Binding(
            "QC result differs from reproduced admission",
        ));
    }
    Ok(result)
}

#[cfg(test)]
#[path = "evidence/tests.rs"]
mod tests;
