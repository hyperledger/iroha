//! SCCP v1 Torii read-API records (`specs/sccp.md` §6).
//!
//! These are the wire types every Taira peer serves from committed state and that wallets, the
//! CLI and the SDKs decode, so Torii and the wallet agree on one layout. Each record is Norito
//! (binary, bare or headered) and Norito JSON, with a stable schema name
//! `iroha_sccp::api::<Type>`. JSON follows the data-model conventions of the records Torii
//! serves next to them: fixed-size byte arrays (digests, addresses, signatures, Merkle
//! siblings) are hex strings, and the variable-length transfer payload is padded standard
//! base64, exactly as in `SccpOutboundMessageRecordV1`.
//!
//! Native proof bundles retain the exact 116-byte `QC_FIXED`, 221-byte finality header and
//! 96-byte BLS aggregate signature, with an explicit direct or historical block reference.
//! Shape checks and conversion to destination wire forms do not authenticate finality.
//! Callers must verify against the destination's independently obtained live committee state,
//! pinned network identity and consensus instance with `v1::destination`.
//!
//! TODO: serve these native bundles after the Torii native finality and retention work is
//! integrated. The retired attestation and roster transport is not a fallback.
//!
//! - [`SccpCapabilitiesV1`] (`GET /v1/sccp/capabilities`): identity, parameters, compiled
//!   light-client profiles and page limits.
//! - The views of [`views`]: the message status union, outbound and control pages, recent
//!   messages, light-client detail and checkpoint cover, governance proposal detail and history
//!   paths.
//!
//! Routes that serve stored data-model records (registry, light-client sets) use those records
//! directly.
//!
//! TODO(ws35): add the governance targets beyond the proposal listing and detail (diffs,
//! readiness).

use iroha_data_model::bridge::SccpNetworkV1;
use norito::codec::{Decode, Encode};

pub mod views;
pub use views::*;

use crate::v1::{
    committee::{is_canonical_order, quorum, successor_keys_match},
    constants::{MAX_BLOCK_PATH, MAX_HISTORY_PATH, MAX_PAYLOAD_BYTES},
    destination::{BlockRefV1, ControlProofV1, MessageProofV1, TairaCertificateV1},
    finality::{QcFixedV1, SccpFinalityHeaderV1, check_signers},
    payload::SccpTransferPayloadV1,
};

/// A record exceeds a protocol bound before any cryptographic check (§3.4, §3.5, §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiShapeError {
    /// Committee geometry, ordering, bitmap or header fields are not canonical or disagree.
    BadCertificate,
    /// A compressed certificate point cannot be converted to the destination wire form.
    BadCertificatePoint,
    /// A rotation does not name the supplied successor committee.
    BadRotation,
    /// A decoded payload or a response label differs from the selected request or deployment.
    MetadataMismatch,
    /// A block path longer than 9 siblings.
    BlockPathTooLong,
    /// A history path longer than 32 siblings.
    HistoryPathTooLong,
    /// A transfer payload longer than 4096 bytes.
    PayloadTooLong,
}

impl core::fmt::Display for ApiShapeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::BadCertificate => {
                "a certificate has a canonical header and exactly one committee quorum"
            }
            Self::BadCertificatePoint => {
                "a compressed certificate point has no canonical destination encoding"
            }
            Self::BadRotation => "a rotation names the supplied canonical successor committee",
            Self::MetadataMismatch => {
                "a response label differs from its payload, request or destination"
            }
            Self::BlockPathTooLong => "a block path has at most 9 siblings",
            Self::HistoryPathTooLong => "a history path has at most 32 siblings",
            Self::PayloadTooLong => "a transfer payload has at most 4096 bytes",
        })
    }
}

impl std::error::Error for ApiShapeError {}

/// Recorded reason a committee generation began; this is peer DATA, not authority.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "kind", content = "value")]
#[norito_schema(name = "iroha_sccp::api::SccpGenerationCauseV1")]
pub enum SccpGenerationCauseV1 {
    /// The original signed genesis committee.
    Genesis,
    /// An authenticated epoch boundary changed the keys.
    KeyChange,
    /// A heartbeat renewed the keys.
    Heartbeat,
    /// A missed boundary was followed by authenticated recovery.
    Resync,
}

/// Captured staking registration for one ordered committee member (§6).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGenerationMemberV1")]
pub struct SccpGenerationMemberV1 {
    /// Canonical numeric wire projection of `LaneId::as_u32()`.
    pub lane_id: u32,
    /// Canonical domainless validator account, including its complete controller.
    pub validator: iroha_data_model::account::AccountId,
    /// Activation height distinguishing this registration from a later one.
    pub activation_height: u64,
}

/// Retained outgoing boundary and successor binding (§6).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGenerationEndV1")]
pub struct SccpGenerationEndV1 {
    /// Last height signed by this generation, inclusive.
    pub end_height: u64,
    /// Timestamp of the outgoing block.
    pub end_timestamp_ms: u64,
    /// Ordered-key root of the successor.
    pub next_committee_root: [u8; 32],
    /// Destination validity granted to the successor.
    pub successor_validity_ms: u64,
}

/// Full retained generation DATA from one committed view (§6).
///
/// `liable` uses that view's actual current-generation cell and liability clock. Even a
/// historical generation response can change as liability progresses. Neither the offered
/// keys nor their root establish a destination trust pin.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGenerationV1")]
pub struct SccpGenerationV1 {
    /// Generation number, starting at one.
    pub generation: u64,
    /// Root of the ordered keys.
    pub committee_root: [u8; 32],
    /// Retained creation reason.
    pub cause: SccpGenerationCauseV1,
    /// First height assigned to this generation.
    pub start_height: u64,
    /// Retained handoff or genesis/resync time.
    pub start_timestamp_ms: u64,
    /// Liability clock at creation.
    pub start_lc: u64,
    /// Captured destination validity.
    pub validity_ms: u64,
    /// Captured destination deadline.
    pub deadline_ms: u64,
    /// Captured evidence-submission grace.
    pub grace_ms: u64,
    /// Captured bound on destination progress extension.
    pub progress_cap_ms: u64,
    /// Inclusive time-based liability boundary.
    pub liable_until_lc: u64,
    /// Clock at which all relevant destinations passed the deadline, if observed.
    #[norito(required)]
    pub dest_cleared_lc: Option<u64>,
    /// Liability computed at this same committed view.
    pub liable: bool,
    /// Outgoing boundary, if this generation ended.
    #[norito(required)]
    pub end: Option<SccpGenerationEndV1>,
    /// Canonical ordered compressed BLS keys; bitmap positions use this order.
    pub keys: Vec<[u8; 48]>,
    /// Captured registration in the same key order; unresolved entries remain absent.
    pub members: Vec<Option<SccpGenerationMemberV1>>,
}

/// A native Sumeragi certificate as served by Torii (§6), retaining the exact signed fields.
///
/// The committee is offered data. Its root agreeing with this certificate does not establish
/// trust: only the pinned destination state or a previously authenticated rotation can do so.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpCertificateV1")]
pub struct SccpCertificateV1 {
    /// Height duplicated from the header for indexing; checked for equality.
    pub height: u64,
    /// Exact `QC_FIXED` bytes, with the canonical big-endian signer word.
    pub qc: [u8; 116],
    /// Compressed BLS aggregate signature of the Commit preimage.
    pub aggregate_signature: [u8; 96],
    /// Exact finality header `X` from the original certified result preimage.
    pub header: [u8; 221],
    /// Compressed committee keys in canonical order, at most 31.
    pub committee: Vec<[u8; 48]>,
}

impl SccpCertificateV1 {
    /// Check bounded committee geometry, exact quorum and the duplicated header fields.
    /// This is a shape check, not signature verification or committee authentication.
    ///
    /// # Errors
    /// Returns [`ApiShapeError::BadCertificate`] for any inconsistent field.
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if quorum(self.committee.len()).is_none() || !is_canonical_order(&self.committee) {
            return Err(ApiShapeError::BadCertificate);
        }
        let qc = QcFixedV1::parse(&self.qc).map_err(|_| ApiShapeError::BadCertificate)?;
        check_signers(qc.signers, self.committee.len())
            .map_err(|_| ApiShapeError::BadCertificate)?;
        let header =
            SccpFinalityHeaderV1::parse(&self.header).map_err(|_| ApiShapeError::BadCertificate)?;
        if header.height() != self.height
            || !header.is_active()
            || !successor_keys_match(&self.committee, &header.committee_root())
        {
            return Err(ApiShapeError::BadCertificate);
        }
        Ok(())
    }

    /// Convert the exact native certificate to the EVM and TON destination wire forms.
    /// The returned certificate still requires verification against trusted destination state.
    ///
    /// # Errors
    /// Returns a shape error or [`ApiShapeError::BadCertificatePoint`] for an invalid point.
    pub fn to_destination_certificate(&self) -> Result<TairaCertificateV1, ApiShapeError> {
        self.check_shape()?;
        let qc = QcFixedV1::parse(&self.qc).map_err(|_| ApiShapeError::BadCertificate)?;
        let header =
            SccpFinalityHeaderV1::parse(&self.header).map_err(|_| ApiShapeError::BadCertificate)?;
        TairaCertificateV1::new(&qc, &header, &self.aggregate_signature, &self.committee)
            .ok_or(ApiShapeError::BadCertificatePoint)
    }
}

/// A certified rotation and the ordered keys committed by its successor root (§6).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpRotationV1")]
pub struct SccpRotationV1 {
    /// Native certificate with `ROTATION` set.
    pub certificate: SccpCertificateV1,
    /// Successor keys, including the unchanged keys for a heartbeat.
    pub next_committee: Vec<[u8; 48]>,
}

impl SccpRotationV1 {
    /// Check the rotation shape and successor commitment, without authenticating the handoff.
    ///
    /// # Errors
    /// Returns a certificate shape error or [`ApiShapeError::BadRotation`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        self.certificate.check_shape()?;
        let header = SccpFinalityHeaderV1::parse(&self.certificate.header)
            .map_err(|_| ApiShapeError::BadCertificate)?;
        if !header.is_rotation()
            || !successor_keys_match(&self.next_committee, &header.next_committee_root())
        {
            return Err(ApiShapeError::BadRotation);
        }
        Ok(())
    }
}

/// The direct or historical block containing one leaf, relative to a certified header (§6).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpBlockRefV1")]
pub struct SccpBlockRefV1 {
    /// Height of the block containing the message or control.
    pub height: u64,
    /// Commitment root of that block.
    pub sccp_root: [u8; 32],
    /// Number of committed leaves.
    pub message_count: u32,
    /// History leaf index, zero for the certificate's own block.
    pub history_index: u64,
    /// History path, empty for the certificate's own block.
    pub history_path: Vec<[u8; 32]>,
}

impl SccpBlockRefV1 {
    /// Bound the history path before conversion; the destination verifies its root and index.
    ///
    /// # Errors
    /// Returns [`ApiShapeError::HistoryPathTooLong`] above 32 siblings.
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.history_path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(())
    }
}

impl TryFrom<&SccpBlockRefV1> for BlockRefV1 {
    type Error = ApiShapeError;

    fn try_from(block: &SccpBlockRefV1) -> Result<Self, Self::Error> {
        if block.history_path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(Self {
            height: block.height,
            sccp_root: block.sccp_root,
            message_count: block.message_count,
            history_index: block.history_index,
            history_path: block.history_path.clone(),
        })
    }
}

impl TryFrom<&BlockRefV1> for SccpBlockRefV1 {
    type Error = ApiShapeError;

    fn try_from(block: &BlockRefV1) -> Result<Self, Self::Error> {
        if block.history_path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(Self {
            height: block.height,
            sccp_root: block.sccp_root,
            message_count: block.message_count,
            history_index: block.history_index,
            history_path: block.history_path.clone(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// History proof
// ---------------------------------------------------------------------------------------------

/// A historical SCCP-bearing block and the path of its history leaf (§3.5, `HistoryProofV1`
/// of §5.2.2).
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpHistoryProofV1")]
pub struct SccpHistoryProofV1 {
    /// Height of the historical block.
    pub height: u64,
    /// Its commitment root.
    pub sccp_root: [u8; 32],
    /// Its leaf count (transfers and controls).
    pub message_count: u32,
    /// Index of its history leaf.
    pub leaf_index: u64,
    /// History path (at most 32 siblings).
    pub path: Vec<[u8; 32]>,
}

impl SccpHistoryProofV1 {
    /// Reject a path longer than 32 siblings.
    ///
    /// # Errors
    ///
    /// Returns [`ApiShapeError::HistoryPathTooLong`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(())
    }
}

impl TryFrom<&SccpHistoryProofV1> for BlockRefV1 {
    type Error = ApiShapeError;

    fn try_from(proof: &SccpHistoryProofV1) -> Result<Self, Self::Error> {
        if proof.path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(Self {
            height: proof.height,
            sccp_root: proof.sccp_root,
            message_count: proof.message_count,
            history_index: proof.leaf_index,
            history_path: proof.path.clone(),
        })
    }
}

impl TryFrom<&BlockRefV1> for SccpHistoryProofV1 {
    type Error = ApiShapeError;

    fn try_from(proof: &BlockRefV1) -> Result<Self, Self::Error> {
        if proof.history_path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(Self {
            height: proof.height,
            sccp_root: proof.sccp_root,
            message_count: proof.message_count,
            leaf_index: proof.history_index,
            path: proof.history_path.clone(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Message proof bundle
// ---------------------------------------------------------------------------------------------

/// A transfer leaf, its block reference and the native certificate authenticating that root.
/// Readers verify it against the destination's current committee before submitting (§6).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpMessageProofBundleV1")]
pub struct SccpMessageProofBundleV1 {
    /// `message_id` (§3.3).
    pub message_id: [u8; 32],
    /// The §3.2 transfer payload.
    #[norito(json = "crate::api::base64_json")]
    pub payload: Vec<u8>,
    /// Destination-time mint deadline copied from the payload.
    pub deadline_ms: u64,
    /// Commitment index of the transfer leaf in its block.
    pub leaf_index: u32,
    /// Block path of the transfer leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// Block containing the leaf, directly or through the certificate's history root.
    pub block: SccpBlockRefV1,
    /// Native certificate of the selected committed height.
    pub certificate: SccpCertificateV1,
}

impl SccpMessageProofBundleV1 {
    /// Whether the bundle proves the message through the history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.block.height < self.certificate.height
    }

    /// Check the requested message id and duplicated payload labels, then convert the proof.
    /// `taira_network_id` must come from the caller's pinned destination identity. This
    /// checks labels and bounds only; the destination must still verify finality and paths.
    ///
    /// # Errors
    /// Returns a shape error or [`ApiShapeError::MetadataMismatch`] before copying buffers.
    pub fn message_proof(
        &self,
        taira_network_id: &[u8; 32],
        expected_message_id: &[u8; 32],
    ) -> Result<MessageProofV1, ApiShapeError> {
        self.check_shape()?;
        let payload = SccpTransferPayloadV1::decode(&self.payload)
            .map_err(|_| ApiShapeError::MetadataMismatch)?;
        if self.message_id != *expected_message_id
            || payload.deadline_ms != self.deadline_ms
            || payload
                .message_id(taira_network_id)
                .map_err(|_| ApiShapeError::MetadataMismatch)?
                != self.message_id
        {
            return Err(ApiShapeError::MetadataMismatch);
        }
        Ok(MessageProofV1 {
            payload: self.payload.clone(),
            leaf_index: self.leaf_index,
            path: self.path.clone(),
            block: BlockRefV1::try_from(&self.block)?,
        })
    }

    /// Reject oversized fields before certificate shape checks and conversion.
    ///
    /// # Errors
    ///
    /// Returns the first violated [`ApiShapeError`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ApiShapeError::PayloadTooLong);
        }
        if self.path.len() > MAX_BLOCK_PATH {
            return Err(ApiShapeError::BlockPathTooLong);
        }
        self.block.check_shape()?;
        self.certificate.check_shape()
    }
}

// ---------------------------------------------------------------------------------------------
// Control proof bundle
// ---------------------------------------------------------------------------------------------

/// A native Parliament or fast-pause control leaf and its certified block reference (§6).
/// The destination computes the leaf from its own route identity and these fields.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpControlProofBundleV1")]
pub struct SccpControlProofBundleV1 {
    /// Target network of the control.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment the control commands.
    pub revision: u32,
    /// Control nonce (at least 1, strictly increasing per `(network, revision)`).
    pub control_nonce: u64,
    /// Authority track: 1 for Parliament, 2 for fast pause.
    pub track: u8,
    /// Parliament pause state after the control.
    pub parliament_paused: bool,
    /// Fast-pause expiry after the control, or zero for none.
    pub fast_pause_until_ms: u64,
    /// Identity of the authorizing certificate.
    pub certificate_id: [u8; 32],
    /// Hash of that certificate's effect preimage.
    pub effect_hash: [u8; 32],
    /// Commitment index of the control leaf in its block.
    pub leaf_index: u32,
    /// Block path of the control leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// Block containing the leaf, directly or through the certificate's history root.
    pub block: SccpBlockRefV1,
    /// Native certificate of the selected committed height.
    pub certificate: SccpCertificateV1,
}

impl SccpControlProofBundleV1 {
    /// Whether the bundle proves the control through the history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.block.height < self.certificate.height
    }

    /// Check the independently selected destination and convert the full native control proof.
    /// This checks labels and bounds only; the destination must still verify finality and paths.
    ///
    /// # Errors
    /// Returns a shape error or [`ApiShapeError::MetadataMismatch`] before copying buffers.
    pub fn control_proof(
        &self,
        network: SccpNetworkV1,
        revision: u32,
    ) -> Result<ControlProofV1, ApiShapeError> {
        self.check_shape()?;
        if self.network != network || self.revision != revision {
            return Err(ApiShapeError::MetadataMismatch);
        }
        Ok(ControlProofV1 {
            control_nonce: self.control_nonce,
            track: self.track,
            parliament_paused: u8::from(self.parliament_paused),
            fast_pause_until_ms: self.fast_pause_until_ms,
            certificate_id: self.certificate_id,
            effect_hash: self.effect_hash,
            leaf_index: self.leaf_index,
            path: self.path.clone(),
            block: BlockRefV1::try_from(&self.block)?,
        })
    }

    /// Reject oversized fields before certificate shape checks and conversion.
    ///
    /// # Errors
    ///
    /// Returns the first violated [`ApiShapeError`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.path.len() > MAX_BLOCK_PATH {
            return Err(ApiShapeError::BlockPathTooLong);
        }
        self.block.check_shape()?;
        self.certificate.check_shape()
    }
}

// ---------------------------------------------------------------------------------------------
// Governance and capabilities
// ---------------------------------------------------------------------------------------------

/// One open SCCP governance proposal (`GET /v1/sccp/governance/proposals`, §4.14.5 item 4).
///
/// The Parliament driver creates attempts for admissible proposals without one, oldest first.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceProposalStatusV1")]
pub struct SccpGovernanceProposalStatusV1 {
    /// Proposal content id (the key of every attempt).
    pub content_id: iroha_data_model::governance::types::ProposalContentId,
    /// Taira height at which the proposal was submitted.
    pub created_height: u64,
    /// The proposal.
    pub proposal: iroha_data_model::sccp::governance::SccpGovernanceProposalV1,
    /// A new attempt would pass the SCCP preflight: every base revision is current and every
    /// registered destination word is unused.
    pub admissible: bool,
    /// The newest Parliament attempt, if any.
    #[norito(required)]
    pub latest_attempt: Option<iroha_data_model::governance::types::GovernanceAttemptV1>,
}

/// The light-client profile one source chain runs under for the next Taira block (§4.13.2, §6).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpLcProfileStatusV1")]
pub struct SccpLcProfileStatusV1 {
    /// External source chain.
    pub network: SccpNetworkV1,
    /// Active compiled profile version (1 until the Parliament activates another).
    pub version: u32,
    /// Profile hash of the version: the hash the activation recorded, or the compiled hash of
    /// version 1.
    pub profile_hash: [u8; 32],
    /// First Taira height verifying under the version; `None` for version 1 (from genesis).
    #[norito(required)]
    pub activation_height: Option<u64>,
    /// Parliament proposal that activated the version; `None` for version 1.
    #[norito(required)]
    pub proposal_id: Option<[u8; 32]>,
    /// Unix time (ms) from which source evidence lies beyond the version's `supported_until`
    /// and fails closed; wallets stop burning seven days before it (§7.2).
    #[norito(required)]
    pub supported_until_ms: Option<u64>,
}

/// Native finality wire constants advertised with capabilities (§3.7–§3.8, §6).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpFinalityConstantsV1")]
pub struct SccpFinalityConstantsV1 {
    /// Exact finality header `X` length.
    pub header_length: u32,
    /// Exact `QC_FIXED` length.
    pub qc_length: u32,
    /// Compressed BLS aggregate signature length.
    pub signature_length: u32,
    /// Consensus hash-to-curve domain, as literal ASCII bytes.
    pub signature_dst: Vec<u8>,
    /// Outer certified result hash domain.
    pub result_tag: Vec<u8>,
    /// Inner execution-result body hash domain.
    pub result_body_tag: Vec<u8>,
}

impl SccpFinalityConstantsV1 {
    /// Constants compiled into this release, for exact comparison with an untrusted peer.
    #[must_use]
    pub fn current() -> Self {
        use crate::v1::{
            committee::SIGNATURE_LEN,
            finality::{DST_SIG, QC_FIXED_LEN, RESULT_BODY_TAG, RESULT_TAG, X_LEN},
        };
        Self {
            header_length: X_LEN as u32,
            qc_length: QC_FIXED_LEN as u32,
            signature_length: SIGNATURE_LEN as u32,
            signature_dst: DST_SIG.to_vec(),
            result_tag: RESULT_TAG.to_vec(),
            result_body_tag: RESULT_BODY_TAG.to_vec(),
        }
    }
}

/// `GET /v1/sccp/capabilities`: the Taira identity, parameters and light-client profiles a
/// wallet reads before any flow (§6, §7.1).
///
/// TODO: Torii work package (TT-A1): add the current committee
/// generation with its deadline, the liability clock, the forgery-hold summary, the seated
/// panel ids and the launch-gate state of §6.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpCapabilitiesV1")]
pub struct SccpCapabilitiesV1 {
    /// Live Taira `NetworkId`; callers compare it with their pinned destination identity.
    pub network_id: [u8; 32],
    /// Original committed Global Sumeragi instance; callers compare their independent pin.
    pub consensus_instance: [u8; 32],
    /// Native finality encodings used by the running release.
    pub finality: SccpFinalityConstantsV1,
    /// SCCP parameters; `None` when SCCP does not exist on this network.
    #[norito(required)]
    pub parameters: Option<iroha_data_model::sccp::params::SccpParametersV1>,
    /// Latest committed Taira height.
    pub committed_height: u64,
    /// Active light-client profile of every external source chain, in network order.
    pub light_client_profiles: Vec<SccpLcProfileStatusV1>,
    /// Taira chain id.
    pub chain_id: String,
    /// Newest compiled source-chain profile of every network in the running release (§4.13.2),
    /// in network order. The chain verifies under `light_client_profiles`, which may name an
    /// older version until the Parliament activates the newer one.
    pub profiles: Vec<SccpChainProfileViewV1>,
    /// Keccak-256 commitment to the version and profile hash active at the next block for every
    /// network (`SccpLcActiveProfilesV1::policy_hash`, the versions `light_client_profiles`
    /// lists): the SCCP light-client input of the confidential policy digest (§4.13.2).
    pub profiles_policy_hash: [u8; 32],
    /// Page limits of the read routes.
    pub limits: SccpReadLimitsV1,
    /// Path templates of the SCCP read routes this peer serves.
    pub path_templates: Vec<String>,
}

/// Norito JSON field helper for `Vec<u8>` as padded standard base64 (RFC 4648 §4), the
/// data-model convention for opaque byte strings. Decoding accepts only the canonical
/// encoding: padded, standard alphabet, zero unused bits.
pub mod base64_json {
    use norito::json::{self, BoundedJsonError, JsonWriteSink, Parser};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Write `bytes` as one base64 JSON string.
    pub fn serialize(bytes: &[u8], out: &mut String) {
        json::write_base64_json(bytes, out);
    }

    /// Write `bytes` as one base64 JSON string through a checked sink.
    ///
    /// # Errors
    ///
    /// Returns the sink's [`BoundedJsonError`].
    pub fn serialize_bounded(
        bytes: &[u8],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        json::write_base64_json_to(bytes, out)
    }

    /// Read one canonical base64 JSON string.
    ///
    /// # Errors
    ///
    /// Returns a JSON error for a non-string or a non-canonical encoding.
    pub fn deserialize(parser: &mut Parser<'_>) -> Result<Vec<u8>, json::Error> {
        let text = parser.parse_string()?;
        decode(&text)
            .ok_or_else(|| json::Error::Message("expected canonical padded base64".to_owned()))
    }

    fn sextet(byte: u8) -> Option<u8> {
        ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .and_then(|index| u8::try_from(index).ok())
    }

    /// Strictly decode padded standard base64; `None` for any non-canonical input.
    #[must_use]
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        if !bytes.len().is_multiple_of(4) {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        let quads = bytes.len() / 4;
        for (index, quad) in bytes.chunks_exact(4).enumerate() {
            let last = index + 1 == quads;
            let padding = quad.iter().rev().take_while(|byte| **byte == b'=').count();
            if padding > 2 || (padding > 0 && !last) {
                return None;
            }
            let mut values = [0_u8; 4];
            for (slot, byte) in values.iter_mut().zip(&quad[..4 - padding]) {
                *slot = sextet(*byte)?;
            }
            let word = (u32::from(values[0]) << 18)
                | (u32::from(values[1]) << 12)
                | (u32::from(values[2]) << 6)
                | u32::from(values[3]);
            let [_, first, second, third] = word.to_be_bytes();
            match padding {
                0 => out.extend_from_slice(&[first, second, third]),
                1 => {
                    if third != 0 {
                        return None;
                    }
                    out.extend_from_slice(&[first, second]);
                }
                _ => {
                    if second != 0 || third != 0 {
                        return None;
                    }
                    out.push(first);
                }
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use norito::{NoritoSchema as _, codec::DecodeAll, core::DecodeFromSlice, json::Value};

    use super::*;
    use crate::v1::{
        committee::committee_root,
        finality::{
            FLAG_ACTIVE, FLAG_ROTATION, SccpFinalityHeaderFieldsV1, commit_preimage, outer_result,
            verify_certificate,
        },
    };
    use iroha_crypto::{
        Algorithm, KeyPair, PrivateKey,
        bls::consensus::{aggregate, sign_preimage},
    };

    const INSTANCE: [u8; 32] = [0x51; 32];

    /// Native certificate signed by an exact quorum, without claiming the synthetic roots
    /// below are real message or history proofs.
    fn certificate(rotation: bool) -> SccpCertificateV1 {
        let mut members: Vec<([u8; 48], PrivateKey)> = (0_u8..4)
            .map(|index| {
                let pair = KeyPair::from_seed(
                    vec![b's', b'c', b'c', b'p', b'a', index],
                    Algorithm::BlsNormal,
                );
                let (public, private) = pair.into_parts();
                let (algorithm, raw) = public.to_bytes();
                assert_eq!(algorithm, Algorithm::BlsNormal);
                (raw.try_into().expect("48 bytes"), private)
            })
            .collect();
        members.sort_by_key(|member| member.0);
        let keys: Vec<_> = members.iter().map(|member| member.0).collect();
        let root = committee_root(&keys).expect("committee");
        let header = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            network_id: [0x33; 32],
            height: 60,
            timestamp_ms: 1000,
            flags: FLAG_ACTIVE | if rotation { FLAG_ROTATION } else { 0 },
            message_count: 3,
            sccp_root: [0xe4; 32],
            history_size: 2,
            history_root: [0xf5; 32],
            generation: 1,
            committee_root: root,
            validity_ms: if rotation { 86_400_000 } else { 0 },
            next_committee_root: if rotation { root } else { [0; 32] },
        })
        .expect("header");
        let qc = QcFixedV1 {
            epoch: 1,
            epoch_context: [0x44; 32],
            view: 2,
            block_hash: [0x55; 32],
            result_body: [0x66; 32],
            signers: 0b1110,
        };
        let result = outer_result(&header, &qc.result_body).0;
        let preimage = commit_preimage(&INSTANCE, &qc, header.height(), &result);
        let shares: Vec<_> = members
            .iter()
            .skip(1)
            .map(|(_, private)| sign_preimage(private, &preimage).expect("native signature"))
            .collect();
        SccpCertificateV1 {
            height: header.height(),
            qc: qc.encode(),
            aggregate_signature: aggregate(shares).expect("aggregate"),
            header: *header.as_bytes(),
            committee: keys,
        }
    }

    fn block(history: Option<SccpHistoryProofV1>) -> SccpBlockRefV1 {
        match history {
            Some(proof) => {
                SccpBlockRefV1::try_from(&BlockRefV1::try_from(&proof).expect("history bound"))
                    .expect("block bound")
            }
            None => SccpBlockRefV1 {
                height: 60,
                sccp_root: [0xe4; 32],
                message_count: 3,
                history_index: 0,
                history_path: vec![],
            },
        }
    }

    fn history() -> SccpHistoryProofV1 {
        SccpHistoryProofV1 {
            height: 50,
            sccp_root: [0xe4; 32],
            message_count: 1,
            leaf_index: 0,
            path: vec![[0xf5; 32]],
        }
    }

    fn message_bundle(history: Option<SccpHistoryProofV1>) -> SccpMessageProofBundleV1 {
        let payload = SccpTransferPayloadV1::outbound(
            SccpNetworkV1::EthereumMainnet,
            0,
            1,
            1_800_086_400_000,
            1000,
            vec![1, 2, 3],
            vec![0x33; 20],
        )
        .expect("payload");
        SccpMessageProofBundleV1 {
            message_id: payload.message_id(&[0x33; 32]).expect("message id"),
            payload: payload.encode().expect("payload encoding"),
            deadline_ms: payload.deadline_ms,
            leaf_index: 1,
            path: vec![[0x01; 32], [0x02; 32]],
            block: block(history),
            certificate: certificate(false),
        }
    }

    fn control_bundle(history: Option<SccpHistoryProofV1>) -> SccpControlProofBundleV1 {
        SccpControlProofBundleV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            control_nonce: 2,
            track: 1,
            parliament_paused: true,
            fast_pause_until_ms: 0,
            certificate_id: [0x12; 32],
            effect_hash: [0x34; 32],
            leaf_index: 2,
            path: vec![[0x03; 32]],
            block: block(history),
            certificate: certificate(false),
        }
    }

    /// Bare, headered, zero-copy slice and JSON roundtrips.
    fn roundtrip<T>(value: &T)
    where
        T: norito::codec::Encode
            + DecodeAll
            + norito::NoritoSerialize
            + for<'a> norito::NoritoDeserialize<'a>
            + for<'a> DecodeFromSlice<'a>
            + norito::json::JsonSerialize
            + norito::json::JsonDeserialize
            + PartialEq
            + core::fmt::Debug,
    {
        let encoded = value.encode();
        assert_eq!(
            &T::decode_all(&mut encoded.as_slice()).expect("bare decode"),
            value
        );
        let (decoded, used) = T::decode_from_slice(&encoded).expect("slice decode");
        assert_eq!(used, encoded.len());
        assert_eq!(&decoded, value);
        let framed = norito::to_bytes(value).expect("frame");
        assert_eq!(
            &norito::decode_from_bytes::<T>(&framed).expect("frame decode"),
            value
        );
        let json = norito::json::to_json(value).expect("JSON");
        assert_eq!(
            &norito::json::from_json::<T>(&json).expect("JSON decode"),
            value,
            "{json}"
        );
    }

    fn assert_rejects_unknown_field<T>(value: &T)
    where
        T: norito::json::JsonSerialize + norito::json::JsonDeserialize + core::fmt::Debug,
    {
        let mut json = norito::json::to_value(value).expect("JSON value");
        json.as_object_mut()
            .expect("object")
            .insert("adversarial".to_owned(), Value::Null);
        let hostile = norito::json::to_json(&json).expect("JSON");
        assert!(norito::json::from_json::<T>(&hostile).is_err(), "{hostile}");
    }

    fn assert_requires_field<T>(value: &T, field: &str)
    where
        T: norito::json::JsonSerialize + norito::json::JsonDeserialize + core::fmt::Debug,
    {
        let mut json = norito::json::to_value(value).expect("JSON value");
        json.as_object_mut()
            .expect("object")
            .remove(field)
            .expect("field present");
        let missing = norito::json::to_json(&json).expect("JSON");
        assert!(norito::json::from_json::<T>(&missing).is_err(), "{missing}");
    }

    #[test]
    fn api_shape_errors_display_their_bounds() {
        assert_eq!(
            ApiShapeError::BadCertificate.to_string(),
            "a certificate has a canonical header and exactly one committee quorum"
        );
        assert_eq!(
            ApiShapeError::BlockPathTooLong.to_string(),
            "a block path has at most 9 siblings"
        );
        assert_eq!(
            ApiShapeError::HistoryPathTooLong.to_string(),
            "a history path has at most 32 siblings"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(ApiShapeError::PayloadTooLong);
        assert!(boxed.to_string().contains("4096"));
    }

    #[test]
    fn api_schema_names_are_stable() {
        assert_eq!(
            SccpGenerationV1::nominal_name(),
            "iroha_sccp::api::SccpGenerationV1"
        );
        assert_eq!(
            SccpGenerationCauseV1::nominal_name(),
            "iroha_sccp::api::SccpGenerationCauseV1"
        );
        assert_eq!(
            SccpGenerationMemberV1::nominal_name(),
            "iroha_sccp::api::SccpGenerationMemberV1"
        );
        assert_eq!(
            SccpGenerationEndV1::nominal_name(),
            "iroha_sccp::api::SccpGenerationEndV1"
        );
        assert_eq!(
            SccpCertificateV1::nominal_name(),
            "iroha_sccp::api::SccpCertificateV1"
        );
        assert_eq!(
            SccpHistoryProofV1::nominal_name(),
            "iroha_sccp::api::SccpHistoryProofV1"
        );
        assert_eq!(
            SccpMessageProofBundleV1::nominal_name(),
            "iroha_sccp::api::SccpMessageProofBundleV1"
        );
        assert_eq!(
            SccpControlProofBundleV1::nominal_name(),
            "iroha_sccp::api::SccpControlProofBundleV1"
        );
        assert_eq!(
            SccpLcProfileStatusV1::nominal_name(),
            "iroha_sccp::api::SccpLcProfileStatusV1"
        );
    }

    #[test]
    fn light_client_profile_status_roundtrips_and_is_closed() {
        let genesis = SccpLcProfileStatusV1 {
            network: SccpNetworkV1::EthereumMainnet,
            version: 1,
            profile_hash: [0x11; 32],
            activation_height: None,
            proposal_id: None,
            supported_until_ms: Some(1_814_313_600_000),
        };
        let activated = SccpLcProfileStatusV1 {
            network: SccpNetworkV1::TonMainnet,
            version: 2,
            profile_hash: [0x22; 32],
            activation_height: Some(1_234),
            proposal_id: Some([0x33; 32]),
            supported_until_ms: None,
        };
        for status in [genesis, activated] {
            roundtrip(&status);
            assert_rejects_unknown_field(&status);
            for field in ["activation_height", "proposal_id", "supported_until_ms"] {
                assert_requires_field(&status, field);
            }
        }
    }

    #[test]
    fn api_records_roundtrip_in_every_codec() {
        roundtrip(&message_bundle(None));
        roundtrip(&message_bundle(Some(history())));
        roundtrip(&control_bundle(None));
        roundtrip(&control_bundle(Some(history())));
        roundtrip(&history());
        roundtrip(&certificate(false));
        roundtrip(&certificate(true));
        let rotation = SccpRotationV1 {
            next_committee: certificate(true).committee.clone(),
            certificate: certificate(true),
        };
        roundtrip(&rotation);
        roundtrip(&block(None));
        roundtrip(&block(Some(history())));
    }

    #[test]
    fn api_json_objects_are_closed_and_complete() {
        assert_rejects_unknown_field(&message_bundle(None));
        assert_rejects_unknown_field(&control_bundle(Some(history())));
        assert_rejects_unknown_field(&history());
        assert_rejects_unknown_field(&certificate(false));
        assert_rejects_unknown_field(&block(None));
        assert_requires_field(&message_bundle(None), "block");
        assert_requires_field(&message_bundle(None), "certificate");
        assert_requires_field(&message_bundle(None), "payload");
        assert_requires_field(&control_bundle(None), "block");
        assert_requires_field(&control_bundle(None), "certificate");
        assert_requires_field(&control_bundle(None), "control_nonce");
    }

    #[test]
    fn bundles_carry_no_attestation_roster_or_signature_field() {
        // The attestation transport is gone: a bundle that still names one of its fields is not
        // a bundle.
        let retired = [
            "statement",
            "digest",
            "roster",
            "signatures",
            "history",
            "message_count",
        ];
        let message = norito::json::to_value(&message_bundle(None)).expect("JSON value");
        let control = norito::json::to_value(&control_bundle(None)).expect("JSON value");
        for field in retired {
            assert!(message.get(field).is_none(), "{field}");
            assert!(control.get(field).is_none(), "{field}");
            let mut hostile = message.clone();
            hostile
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), Value::Null);
            let text = norito::json::to_json(&hostile).expect("JSON");
            assert!(
                norito::json::from_json::<SccpMessageProofBundleV1>(&text).is_err(),
                "{text}"
            );
            let mut hostile = control.clone();
            hostile
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), Value::Null);
            let text = norito::json::to_json(&hostile).expect("JSON");
            assert!(
                norito::json::from_json::<SccpControlProofBundleV1>(&text).is_err(),
                "{text}"
            );
        }
        let message_fields: Vec<&str> = message
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            message_fields,
            [
                "block",
                "certificate",
                "deadline_ms",
                "leaf_index",
                "message_id",
                "path",
                "payload",
            ]
        );
        let control_fields: Vec<&str> = control
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            control_fields,
            [
                "block",
                "certificate",
                "certificate_id",
                "control_nonce",
                "effect_hash",
                "fast_pause_until_ms",
                "leaf_index",
                "network",
                "parliament_paused",
                "path",
                "revision",
                "track",
            ]
        );
    }

    #[test]
    fn api_json_uses_base64_payload_and_hex_arrays() {
        let mut bundle = message_bundle(None);
        bundle.payload = vec![0x02, 0x01, 0xaa, 0xbb];
        bundle.message_id = [0x0a; 32];
        let json = norito::json::to_value(&bundle).expect("JSON value");
        assert_eq!(
            json.get("payload").and_then(Value::as_str),
            Some("AgGquw==")
        );
        let message_id = json
            .get("message_id")
            .and_then(Value::as_str)
            .expect("message id");
        assert_eq!(message_id, "0A".repeat(32));
        assert!(json.get("block").expect("block key").is_object());
        assert!(
            json.get("certificate")
                .expect("certificate key")
                .is_object()
        );
        let mut hostile = json.clone();
        hostile
            .as_object_mut()
            .expect("object")
            .insert("payload".to_owned(), Value::from("AgGquw"));
        let text = norito::json::to_json(&hostile).expect("JSON");
        assert!(norito::json::from_json::<SccpMessageProofBundleV1>(&text).is_err());
    }

    #[test]
    fn base64_decoder_is_strict_and_canonical() {
        assert_eq!(base64_json::decode(""), Some(Vec::new()));
        assert_eq!(base64_json::decode("AA=="), Some(vec![0]));
        assert_eq!(base64_json::decode("AAE="), Some(vec![0, 1]));
        assert_eq!(base64_json::decode("AAEC"), Some(vec![0, 1, 2]));
        assert_eq!(
            base64_json::decode("AAECA/8="),
            Some(vec![0, 1, 2, 3, 0xff])
        );
        assert_eq!(base64_json::decode("AAECAw"), None, "unpadded");
        assert_eq!(base64_json::decode("AB=="), None, "nonzero unused bits");
        assert_eq!(base64_json::decode("AAF="), None, "nonzero unused bits");
        assert_eq!(base64_json::decode("A==="), None, "three padding chars");
        assert_eq!(
            base64_json::decode("AA==AAAA"),
            None,
            "padding before the end"
        );
        assert_eq!(base64_json::decode("AA-_"), None, "URL-safe alphabet");
        assert_eq!(base64_json::decode("AA A"), None, "whitespace");
        let mut out = String::new();
        base64_json::serialize(&[0, 1, 2, 3, 0xff], &mut out);
        assert_eq!(out, "\"AAECA/8=\"");
        let mut parser = norito::json::Parser::new(&out);
        assert_eq!(
            base64_json::deserialize(&mut parser).expect("decodes"),
            vec![0, 1, 2, 3, 0xff]
        );
    }

    #[test]
    fn certificate_converts_exact_native_bytes_and_quorum() {
        let view = certificate(false);
        assert_eq!(view.check_shape(), Ok(()));
        let qc = QcFixedV1::parse(&view.qc).expect("QC");
        assert_eq!(qc.signers, 0b1110);
        assert_eq!(qc.signers.count_ones(), 3);
        let contract = view
            .to_destination_certificate()
            .expect("destination forms");
        assert_eq!(contract.qc, view.qc);
        assert_eq!(contract.header, view.header);
        assert_eq!(contract.ton_signature, view.aggregate_signature);
        assert_eq!(contract.committee, view.committee.concat());
        assert_eq!(contract.signature.len(), 192);
        assert_eq!(contract.signer_ys.len(), 3 * 48);
        assert_eq!(
            crate::v1::committee::signature_from_evm192(
                contract.signature.as_slice().try_into().expect("192 bytes")
            ),
            Ok(view.aggregate_signature)
        );
        assert!(
            verify_certificate(
                &INSTANCE,
                &view.qc,
                &view.header,
                &view.aggregate_signature,
                &view.committee
            )
            .is_ok()
        );
        for signers in [0, 0b0110, 0b1111, 0b1_0110, 0x8000_000e] {
            let mut changed = view.clone();
            changed.qc = QcFixedV1 { signers, ..qc }.encode();
            assert_eq!(
                changed.check_shape(),
                Err(ApiShapeError::BadCertificate),
                "{signers:#x}"
            );
        }
        for length in [0, 1, 3, 5, 32] {
            let mut changed = view.clone();
            changed.committee.resize(length, [0; 48]);
            assert_eq!(
                changed.check_shape(),
                Err(ApiShapeError::BadCertificate),
                "{length}"
            );
        }
        let mut duplicate = view.clone();
        duplicate.committee[1] = duplicate.committee[0];
        assert_eq!(duplicate.check_shape(), Err(ApiShapeError::BadCertificate));
        let mut reversed = view.clone();
        reversed.committee.reverse();
        assert_eq!(reversed.check_shape(), Err(ApiShapeError::BadCertificate));
        let mut wrong_height = view.clone();
        wrong_height.height += 1;
        assert_eq!(
            wrong_height.check_shape(),
            Err(ApiShapeError::BadCertificate)
        );
        let mut wrong_root = view.clone();
        wrong_root.header[149] ^= 1;
        assert_eq!(wrong_root.check_shape(), Err(ApiShapeError::BadCertificate));
        let mut inactive = view.clone();
        inactive.header = *SccpFinalityHeaderV1::inactive([0x33; 32], view.height, 1000)
            .expect("inactive header")
            .as_bytes();
        assert_eq!(inactive.check_shape(), Err(ApiShapeError::BadCertificate));
    }

    #[test]
    fn certificate_shape_never_claims_signature_or_root_trust() {
        let mut changed = certificate(false);
        changed.aggregate_signature = [0; 96];
        assert_eq!(changed.check_shape(), Ok(()), "shape is not authentication");
        assert_eq!(
            changed.to_destination_certificate(),
            Err(ApiShapeError::BadCertificatePoint)
        );
        assert!(
            verify_certificate(
                &INSTANCE,
                &changed.qc,
                &changed.header,
                &changed.aggregate_signature,
                &changed.committee
            )
            .is_err()
        );
        let genuine = certificate(false);
        assert!(
            verify_certificate(
                &[0x52; 32],
                &genuine.qc,
                &genuine.header,
                &genuine.aggregate_signature,
                &genuine.committee
            )
            .is_err(),
            "foreign instance"
        );
    }

    #[test]
    fn rotation_binds_flag_and_successor_but_requires_authentication() {
        let cert = certificate(true);
        let rotation = SccpRotationV1 {
            next_committee: cert.committee.clone(),
            certificate: cert,
        };
        assert_eq!(rotation.check_shape(), Ok(()), "heartbeat retains keys");
        assert_rejects_unknown_field(&rotation);
        assert_requires_field(&rotation, "next_committee");
        let mut changed = rotation.clone();
        changed.certificate = certificate(false);
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        let mut changed = rotation.clone();
        changed.next_committee.reverse();
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        let mut changed = rotation.clone();
        changed.next_committee.clear();
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        let mut changed = rotation;
        changed.next_committee[3] = [0xff; 48];
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
    }

    #[test]
    fn history_proof_converts_both_ways() {
        let proof = history();
        let contract = BlockRefV1::try_from(&proof).expect("history");
        assert_eq!(contract.height, 50);
        assert_eq!(contract.sccp_root, [0xe4; 32]);
        assert_eq!(contract.message_count, 1);
        assert_eq!(contract.history_index, 0);
        assert_eq!(contract.history_path, vec![[0xf5; 32]]);
        assert_eq!(
            SccpHistoryProofV1::try_from(&contract).expect("history"),
            proof
        );
        let mut long = proof;
        long.path = vec![[0; 32]; MAX_HISTORY_PATH + 1];
        assert_eq!(long.check_shape(), Err(ApiShapeError::HistoryPathTooLong));
    }

    #[test]
    fn bundle_accessors_expose_contract_structures() {
        let direct = message_bundle(None);
        assert!(!direct.is_historical());
        assert_eq!(direct.block.history_index, 0);
        assert!(direct.block.history_path.is_empty());
        let proof = direct
            .message_proof(&[0x33; 32], &direct.message_id)
            .expect("message labels");
        assert_eq!(proof.payload, direct.payload);
        assert_eq!(proof.leaf_index, 1);
        assert_eq!(proof.path, direct.path);
        assert_eq!(
            SccpBlockRefV1::try_from(&proof.block).expect("block"),
            direct.block
        );
        assert_eq!(direct.check_shape(), Ok(()));

        let historical = message_bundle(Some(history()));
        assert!(historical.is_historical());
        assert_eq!(historical.block.height, 50);

        let mut oversized = direct.clone();
        oversized.payload = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(oversized.check_shape(), Err(ApiShapeError::PayloadTooLong));
        let mut long_path = direct;
        long_path.path = vec![[0; 32]; MAX_BLOCK_PATH + 1];
        assert_eq!(
            long_path.check_shape(),
            Err(ApiShapeError::BlockPathTooLong)
        );

        let control = control_bundle(Some(history()));
        assert!(control.is_historical());
        let control_proof = control
            .control_proof(SccpNetworkV1::EthereumMainnet, 1)
            .expect("control labels");
        assert_eq!(control_proof.control_nonce, 2);
        assert_eq!(control_proof.track, 1);
        assert_eq!(control_proof.parliament_paused, 1);
        assert_eq!(control_proof.fast_pause_until_ms, 0);
        assert_eq!(control_proof.certificate_id, [0x12; 32]);
        assert_eq!(control_proof.effect_hash, [0x34; 32]);
        assert_eq!(control_proof.leaf_index, 2);
        assert_eq!(control_proof.block.history_index, 0);
        assert_eq!(control.check_shape(), Ok(()));
        let mut long_control = control;
        long_control.path = vec![[0; 32]; MAX_BLOCK_PATH + 1];
        assert_eq!(
            long_control.check_shape(),
            Err(ApiShapeError::BlockPathTooLong)
        );
        assert!(!control_bundle(None).is_historical());
        // A history path beyond 32 siblings is refused through either bundle.
        let mut long_message_history = message_bundle(Some(history()));
        long_message_history.block.history_path = vec![[0; 32]; MAX_HISTORY_PATH + 1];
        assert_eq!(
            long_message_history.check_shape(),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        let mut long_control_history = control_bundle(Some(history()));
        long_control_history.block.history_path = vec![[0; 32]; MAX_HISTORY_PATH + 1];
        assert_eq!(
            long_control_history.check_shape(),
            Err(ApiShapeError::HistoryPathTooLong)
        );
    }
    #[test]
    fn proof_conversions_reject_oversized_buffers_and_unbound_labels() {
        let direct = message_bundle(None);
        let mut changed = direct.clone();
        changed.payload = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            changed.message_proof(&[0x33; 32], &direct.message_id),
            Err(ApiShapeError::PayloadTooLong)
        );
        let mut changed = direct.clone();
        changed.deadline_ms += 1;
        assert_eq!(
            changed.message_proof(&[0x33; 32], &direct.message_id),
            Err(ApiShapeError::MetadataMismatch)
        );
        assert_eq!(
            direct.message_proof(&[0x33; 32], &[0x99; 32]),
            Err(ApiShapeError::MetadataMismatch)
        );
        assert_eq!(
            direct.message_proof(&[0x99; 32], &direct.message_id),
            Err(ApiShapeError::MetadataMismatch)
        );
        let mut changed = direct;
        changed.path.resize(MAX_BLOCK_PATH + 1, [0; 32]);
        assert_eq!(
            changed.message_proof(&[0x33; 32], &changed.message_id),
            Err(ApiShapeError::BlockPathTooLong)
        );
        let mut control = control_bundle(None);
        assert_eq!(
            control.control_proof(SccpNetworkV1::BscMainnet, 1),
            Err(ApiShapeError::MetadataMismatch)
        );
        assert_eq!(
            control.control_proof(SccpNetworkV1::EthereumMainnet, 2),
            Err(ApiShapeError::MetadataMismatch)
        );
        control.path.resize(MAX_BLOCK_PATH + 1, [0; 32]);
        assert_eq!(
            control.control_proof(SccpNetworkV1::EthereumMainnet, 1),
            Err(ApiShapeError::BlockPathTooLong)
        );
        let mut large = block(None);
        large.history_path.resize(MAX_HISTORY_PATH + 1, [0; 32]);
        assert_eq!(
            BlockRefV1::try_from(&large),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        let raw = BlockRefV1 {
            history_path: large.history_path.clone(),
            ..BlockRefV1::default()
        };
        assert_eq!(
            SccpBlockRefV1::try_from(&raw),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        assert_eq!(
            SccpHistoryProofV1::try_from(&raw),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        let mut large_history = history();
        large_history.path = large.history_path;
        assert_eq!(
            BlockRefV1::try_from(&large_history),
            Err(ApiShapeError::HistoryPathTooLong)
        );
    }

    #[test]
    fn native_finality_constants_are_pinned_and_roundtrip() {
        let constants = SccpFinalityConstantsV1::current();
        assert_eq!(
            (
                constants.header_length,
                constants.qc_length,
                constants.signature_length
            ),
            (221, 116, 96)
        );
        assert_eq!(
            constants.signature_dst,
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
        );
        assert_eq!(constants.result_tag, b"iroha/sumeragi/result/v1");
        assert_eq!(constants.result_body_tag, b"iroha/sumeragi/result-body/v1");
        assert_eq!(
            (MAX_BLOCK_PATH, MAX_HISTORY_PATH, MAX_PAYLOAD_BYTES),
            (9, 32, 4096)
        );
        roundtrip(&constants);
        assert_rejects_unknown_field(&constants);
        assert_requires_field(&constants, "signature_dst");
    }
    #[test]
    fn full_generation_data_roundtrips_all_fields_without_trust_conversion() {
        let member = SccpGenerationMemberV1 {
            lane_id: u32::MAX,
            validator: iroha_data_model::account::AccountId::new(
                KeyPair::from_seed(vec![0x35; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ),
            activation_height: 7,
        };
        roundtrip(&member);
        assert_rejects_unknown_field(&member);
        let json = norito::json::to_value(&member).unwrap();
        assert_eq!(
            json.get("lane_id").and_then(Value::as_u64),
            Some(u64::from(u32::MAX))
        );
        let end = SccpGenerationEndV1 {
            end_height: 20,
            end_timestamp_ms: 30,
            next_committee_root: [0x21; 32],
            successor_validity_ms: 40,
        };
        roundtrip(&end);
        assert_rejects_unknown_field(&end);
        for cause in [
            SccpGenerationCauseV1::Genesis,
            SccpGenerationCauseV1::KeyChange,
            SccpGenerationCauseV1::Heartbeat,
            SccpGenerationCauseV1::Resync,
        ] {
            for ended in [false, true] {
                let data = SccpGenerationV1 {
                    generation: 2,
                    committee_root: [0x11; 32],
                    cause,
                    start_height: 8,
                    start_timestamp_ms: 9,
                    start_lc: 6,
                    validity_ms: 10,
                    deadline_ms: 19,
                    grace_ms: 11,
                    progress_cap_ms: 12,
                    liable_until_lc: 27,
                    dest_cleared_lc: ended.then_some(31),
                    liable: !ended,
                    end: ended.then_some(end.clone()),
                    keys: vec![[0x12; 48]; 4],
                    members: vec![Some(member.clone()), None, None, None],
                };
                roundtrip(&data);
                assert_rejects_unknown_field(&data);
                for field in [
                    "generation",
                    "committee_root",
                    "cause",
                    "start_height",
                    "start_timestamp_ms",
                    "start_lc",
                    "validity_ms",
                    "deadline_ms",
                    "grace_ms",
                    "progress_cap_ms",
                    "liable_until_lc",
                    "dest_cleared_lc",
                    "liable",
                    "end",
                    "keys",
                    "members",
                ] {
                    assert_requires_field(&data, field);
                }
                // Deliberately synthetic DATA keys: codecs do not certify a committee.
                assert_eq!(data.keys[0], data.keys[1]);
            }
        }
    }
}
