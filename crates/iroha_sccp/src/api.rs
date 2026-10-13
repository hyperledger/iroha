//! SCCP v1 Torii read-API records (`specs/sccp.md` §6).
//!
//! These records use Norito binary encoding and Norito JSON. Fixed-size byte arrays are hex
//! strings; the variable-length transfer payload is padded standard base64.
//!
//! [`SccpCertificateV1`] carries the Sumeragi CommitQC, its compressed aggregate signature,
//! the 221-byte finality header and the signing committee. Both proof bundles carry their
//! block reference and certificate; [`SccpRotationV1`] carries the successor committee.
//!
//! Decoding, conversions and `check_shape` do not authenticate these records. Torii must
//! run [`crate::v1::finality::verify_certificate`] using its authenticated committee and
//! consensus instance, and verify the block and leaf paths (§5.1.5). Wallets must also check
//! chain identity, generation and destination policy against the target's live committee
//! state before submitting (§5.1.3–§5.1.6). A committee supplied by a peer is not a trust
//! anchor. No API record or conversion substitutes for the current certified result `X`.
//!
//! [`SccpCapabilitiesV1`] and [`views`] describe committed identity, parameters, profiles,
//! message status, pages, light-client state, governance and history paths. Stored registry
//! and light-client records use their data-model types directly.
//!
//! Governance diagnostics preserve unavailable Parliament eligibility and due-work sources.

use iroha_data_model::bridge::SccpNetworkV1;
use norito::codec::{Decode, Encode};

mod evidence;
pub use evidence::*;
mod governance;
pub use governance::*;
mod generation;
pub use generation::*;
mod reconciliation;
pub use reconciliation::*;
mod fast_pause;
pub use fast_pause::*;
pub mod views;
pub use views::*;

use crate::v1::{
    committee::{
        committee_root, is_canonical_order, is_valid_committee_size, successor_keys_match,
    },
    constants::{MAX_BLOCK_PATH, MAX_HISTORY_PATH, MAX_PAYLOAD_BYTES},
    destination::{BlockRefV1, ControlProofV1, MessageProofV1},
    finality::{QcFixedV1, SccpFinalityHeaderV1, check_signers},
};

/// A structural protocol constraint failed before authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiShapeError {
    /// The committee does not have 4, 7, …, 31 keys in strictly ascending order.
    BadCommittee,
    /// The header violates the finality-header layout constraints X1–X7.
    BadFinalityHeader,
    /// The response height differs from the height encoded in its finality header.
    CertificateHeightMismatch,
    /// The active header's committee root differs from the supplied keys' root.
    CommitteeRootMismatch,
    /// The QC bitmap is not exactly a quorum of the supplied committee.
    BadSignerSet,
    /// A rotation lacks the ROTATION flag or does not bind its successor keys.
    BadRotation,
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
            Self::BadCommittee => "a committee has 4, 7, ..., 31 keys in strictly ascending order",
            Self::BadFinalityHeader => "a finality header must satisfy X1 through X7",
            Self::CertificateHeightMismatch => {
                "certificate height differs from its finality header"
            }
            Self::CommitteeRootMismatch => {
                "committee keys differ from the active header's committee root"
            }
            Self::BadSignerSet => {
                "certificate signers must be exactly a committee quorum with no spare bits"
            }
            Self::BadRotation => {
                "a rotation must bind its successor committee in a ROTATION header"
            }
            Self::BlockPathTooLong => "a block path has at most 9 siblings",
            Self::HistoryPathTooLong => "a history path has at most 32 siblings",
            Self::PayloadTooLong => "a transfer payload has at most 4096 bytes",
        })
    }
}

impl std::error::Error for ApiShapeError {}

/// Certificate-height selector for `?at=record|latest|<H>` (§6).
///
/// This is a local query value, not a Norito wire record. Explicit heights must be positive.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SccpProofHeightV1 {
    /// Use the committed height of the message or control record.
    #[default]
    Record,
    /// Use the latest durable committed height.
    Latest,
    /// Use this explicit committed height.
    At(u64),
}

/// A query selector is neither `record`, `latest`, nor a positive decimal `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SccpProofHeightParseError;

impl core::fmt::Display for SccpProofHeightParseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("proof height must be record, latest, or a positive decimal u64")
    }
}

impl std::error::Error for SccpProofHeightParseError {}

impl core::str::FromStr for SccpProofHeightV1 {
    type Err = SccpProofHeightParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "record" => Ok(Self::Record),
            "latest" => Ok(Self::Latest),
            _ if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => value
                .parse::<u64>()
                .ok()
                .filter(|height| *height != 0)
                .map(Self::At)
                .ok_or(SccpProofHeightParseError),
            _ => Err(SccpProofHeightParseError),
        }
    }
}

impl core::fmt::Display for SccpProofHeightV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Record => formatter.write_str("record"),
            Self::Latest => formatter.write_str("latest"),
            Self::At(height) => height.fmt(formatter),
        }
    }
}

/// Certificate of a committed height (`GET /v1/sccp/finality/{height}`, §6).
///
/// The keys must be checked against an authenticated committee root before the caller runs
/// [`crate::v1::finality::verify_certificate`]. The redundant `height` must equal `X.height`.
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
    /// Height encoded in the certified finality header.
    pub height: u64,
    /// The fixed 116-byte QC layout of §3.7.
    pub qc: [u8; 116],
    /// The compressed 96-byte BLS aggregate signature.
    pub aggregate_signature: [u8; 96],
    /// The 221-byte finality header `X` of the certified result.
    pub header: [u8; 221],
    /// Compressed BLS keys of the signing committee in canonical order.
    pub committee: Vec<[u8; 48]>,
}

impl SccpCertificateV1 {
    /// Check the header, committee shape and exact quorum, without verifying a signature or
    /// trusting a generation. Equality with a self-supplied root is not authentication.
    ///
    /// # Errors
    /// Returns the first structural [`ApiShapeError`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if !is_valid_committee_size(self.committee.len()) || !is_canonical_order(&self.committee) {
            return Err(ApiShapeError::BadCommittee);
        }
        let header = SccpFinalityHeaderV1::parse(&self.header)
            .map_err(|_| ApiShapeError::BadFinalityHeader)?;
        if self.height != header.height() {
            return Err(ApiShapeError::CertificateHeightMismatch);
        }
        if header.is_active() && committee_root(&self.committee) != Some(header.committee_root()) {
            return Err(ApiShapeError::CommitteeRootMismatch);
        }
        let qc = QcFixedV1::parse(&self.qc).map_err(|_| ApiShapeError::BadSignerSet)?;
        check_signers(qc.signers, self.committee.len()).map_err(|_| ApiShapeError::BadSignerSet)
    }
}

/// An ending generation's rotation certificate and its successor committee (§6).
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
    /// Certificate whose finality header has the ROTATION flag.
    pub certificate: SccpCertificateV1,
    /// Successor keys in canonical order, matching `X.next_committee_root`.
    pub next_committee: Vec<[u8; 48]>,
}

impl SccpRotationV1 {
    /// Check the structural certificate and successor binding; this does not authenticate
    /// the rotation or authorize a transition from the destination's current generation.
    ///
    /// # Errors
    /// Returns the certificate's structural error or [`ApiShapeError::BadRotation`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        self.certificate.check_shape()?;
        let header = SccpFinalityHeaderV1::parse(&self.certificate.header)
            .map_err(|_| ApiShapeError::BadFinalityHeader)?;
        if !header.is_rotation()
            || !successor_keys_match(&self.next_committee, &header.next_committee_root())
        {
            return Err(ApiShapeError::BadRotation);
        }
        Ok(())
    }
}

/// A leaf's block relative to the finality header of a certificate (§5.1.5, §6).
///
/// A direct proof has `height == X.height`, the same root/count as `X`, history index zero
/// and an empty history path. An older block requires inclusion in `X.history_root`.
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
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpBlockRefV1")]
pub struct SccpBlockRefV1 {
    /// Height of the block that contains the leaf.
    pub height: u64,
    /// The block's commitment root.
    pub sccp_root: [u8; 32],
    /// The block's leaf count (transfers and controls).
    pub message_count: u32,
    /// Index of the block's history leaf, or zero for the certified block itself.
    pub history_index: u64,
    /// History path (at most 32 siblings), empty for the certified block itself.
    pub history_path: Vec<[u8; 32]>,
}

impl SccpBlockRefV1 {
    /// Reject an oversized history path without verifying it.
    ///
    /// # Errors
    /// Returns [`ApiShapeError::HistoryPathTooLong`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.history_path.len() > MAX_HISTORY_PATH {
            return Err(ApiShapeError::HistoryPathTooLong);
        }
        Ok(())
    }
}

impl From<&SccpBlockRefV1> for BlockRefV1 {
    fn from(block: &SccpBlockRefV1) -> Self {
        Self {
            height: block.height,
            sccp_root: block.sccp_root,
            message_count: block.message_count,
            history_index: block.history_index,
            history_path: block.history_path.clone(),
        }
    }
}

impl From<&BlockRefV1> for SccpBlockRefV1 {
    fn from(block: &BlockRefV1) -> Self {
        Self {
            height: block.height,
            sccp_root: block.sccp_root,
            message_count: block.message_count,
            history_index: block.history_index,
            history_path: block.history_path.clone(),
        }
    }
}

/// A transfer, its block and history paths, and a finality certificate (§5.1.5, §6).
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
#[norito_schema(name = "iroha_sccp::api::SccpMessageProofBundleV1")]
pub struct SccpMessageProofBundleV1 {
    /// `message_id` (§3.3), to be recomputed from the payload.
    pub message_id: [u8; 32],
    /// The §3.2 transfer payload.
    #[norito(json = "crate::api::base64_json")]
    pub payload: Vec<u8>,
    /// Destination-time mint deadline, to be checked against the payload.
    pub deadline_ms: u64,
    /// Commitment index of the transfer leaf in its block.
    pub leaf_index: u32,
    /// Block path of the transfer leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// Block that contains the transfer leaf and its optional history path.
    pub block: SccpBlockRefV1,
    /// Finality certificate against which both paths must be verified.
    pub certificate: SccpCertificateV1,
}

impl SccpMessageProofBundleV1 {
    /// Whether the claimed leaf block is older than the claimed certificate height.
    /// This comparison does not verify either height or any proof.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.block.height < self.certificate.height
    }

    /// The destination's current message-proof fields, without authenticating them.
    #[must_use]
    pub fn message_proof(&self) -> MessageProofV1 {
        MessageProofV1 {
            payload: self.payload.clone(),
            leaf_index: self.leaf_index,
            path: self.path.clone(),
            block: BlockRefV1::from(&self.block),
        }
    }

    /// Check sizes and certificate structure before verification. This does not verify the
    /// message id, payload deadline, Merkle paths or certificate signature.
    ///
    /// # Errors
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

/// The complete control leaf, its block and history paths, and a certificate (§5.1.6, §6).
///
/// Verifiers derive the leaf using the destination's own network and deployment identity.
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
#[norito_schema(name = "iroha_sccp::api::SccpControlProofBundleV1")]
pub struct SccpControlProofBundleV1 {
    /// Target network of the control.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment the control commands.
    pub revision: u32,
    /// Control nonce (at least 1, strictly increasing per network and revision).
    pub control_nonce: u64,
    /// Authority track: 1 Parliament, 2 fast pause.
    pub track: u8,
    /// Whether Parliament has paused minting.
    pub parliament_paused: bool,
    /// Destination-time expiry of the fast pause, or zero when none is active.
    pub fast_pause_until_ms: u64,
    /// Identifier of the Parliament or fast-pause certificate that enacted the change.
    pub certificate_id: [u8; 32],
    /// Effect hash of the change's authority certificate.
    pub effect_hash: [u8; 32],
    /// Commitment index of the control leaf in its block.
    pub leaf_index: u32,
    /// Block path of the control leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// Block that contains the control leaf and its optional history path.
    pub block: SccpBlockRefV1,
    /// Finality certificate against which both paths must be verified.
    pub certificate: SccpCertificateV1,
}

impl SccpControlProofBundleV1 {
    /// Whether the claimed leaf block is older than the claimed certificate height.
    /// This comparison does not verify either height or any proof.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.block.height < self.certificate.height
    }

    /// The destination's current control-proof fields, without authenticating them.
    #[must_use]
    pub fn control_proof(&self) -> ControlProofV1 {
        ControlProofV1 {
            control_nonce: self.control_nonce,
            track: self.track,
            parliament_paused: u8::from(self.parliament_paused),
            fast_pause_until_ms: self.fast_pause_until_ms,
            certificate_id: self.certificate_id,
            effect_hash: self.effect_hash,
            leaf_index: self.leaf_index,
            path: self.path.clone(),
            block: BlockRefV1::from(&self.block),
        }
    }

    /// Check sizes and certificate structure before verification. This does not validate
    /// the control fields, Merkle paths, destination policy or certificate signature.
    ///
    /// # Errors
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

/// Original committed identities of the two emergency panels.
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
#[norito_schema(name = "iroha_sccp::api::SccpPausePanelIdsV1")]
pub struct SccpPausePanelIdsV1 {
    /// Primary panel identity from the committed draw.
    pub primary: [u8; 32],
    /// Backup panel identity from the same committed draw.
    pub backup: [u8; 32],
}

/// `GET /v1/sccp/capabilities`: the Taira identity, parameters and light-client profiles a
/// wallet reads before any flow (§6, §7.1).
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
    /// Live network identity; readers authenticate it against signed genesis.
    pub network_id: [u8; 32],
    /// Global Sumeragi instance derived from this network and chain label.
    pub consensus_instance: [u8; 32],
    /// Exact first-release finality domains and header layout.
    pub finality: SccpFinalityConstantsV1,
    /// Current committed generation and deadline, absent before initialization.
    #[norito(required)]
    pub current_generation: Option<SccpCurrentGenerationV1>,
    /// Sum of the `f + 1` smallest actual per-member maximum penalties in the
    /// current generation. Each penalty rounds toward zero at its exposure's
    /// canonical scale; an already-recorded generation/member offence contributes
    /// zero additional seizure. Absent only before SCCP initialization; unavailable or
    /// inconsistent original member custody makes the whole request unavailable.
    #[norito(required)]
    pub coalition_slashable_floor: Option<iroha_crypto::numeric::Quantity>,
    /// Current committed liability clock.
    pub liability_clock: u64,
    /// Highest generation with recorded native forgery evidence, absent before any offence.
    #[norito(required)]
    pub forgery_max_generation: Option<u64>,
    /// Current committed primary and backup panel identities, in that order.
    #[norito(required)]
    pub pause_panel_ids: Option<SccpPausePanelIdsV1>,
    /// Qualified Parliament ballot availability; false forbids every SCCP proposal.
    pub parliament_binding_ballot_available: bool,
    /// Complete quarantine reconciliation availability, the other registration launch leg.
    pub reconciliation_available: bool,
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
    use crate::v1::finality::{CertificateError, verify_certificate};

    fn reference() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/sccp/finality_v1.json");
        let text = std::fs::read_to_string(path).expect("finality reference fixture");
        let value: Value = norito::json::from_str(&text).expect("finality reference JSON");
        assert_eq!(
            value.get("schema").and_then(Value::as_str),
            Some("iroha.sccp.finality.v1")
        );
        value
    }

    fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
        value
            .get(name)
            .unwrap_or_else(|| panic!("missing reference field {name}"))
    }

    fn bytes(value: &Value) -> Vec<u8> {
        crate::decode_hex_bytes(value.as_str().expect("hex string")).expect("hex bytes")
    }

    fn certificate_from_row(reference: &Value, row: &Value) -> SccpCertificateV1 {
        let wire = field(row, "evm");
        let name = field(row, "committee").as_str().expect("committee name");
        let committee = field(field(field(reference, "committees"), name), "keys")
            .as_array()
            .expect("committee keys")
            .iter()
            .map(|key| bytes(key).try_into().expect("48-byte key"))
            .collect();
        SccpCertificateV1 {
            height: field(field(row, "header_fields"), "height")
                .as_u64()
                .expect("height"),
            qc: bytes(field(wire, "qc")).try_into().expect("116-byte QC"),
            aggregate_signature: bytes(field(field(row, "aggregate_signature"), "compressed"))
                .try_into()
                .expect("96-byte signature"),
            header: bytes(field(wire, "header"))
                .try_into()
                .expect("221-byte header"),
            committee,
        }
    }

    fn certificate() -> SccpCertificateV1 {
        let reference = reference();
        let row = field(&reference, "certificates")
            .as_array()
            .expect("certificates")
            .first()
            .expect("nonempty certificates");
        certificate_from_row(&reference, row)
    }

    fn rotation() -> SccpRotationV1 {
        let reference = reference();
        let row = field(&reference, "certificates")
            .as_array()
            .expect("certificates")
            .iter()
            .find(|row| field(field(row, "header_fields"), "flags").as_u64() == Some(3))
            .expect("rotation reference");
        let certificate = certificate_from_row(&reference, row);
        let header = SccpFinalityHeaderV1::parse(&certificate.header).expect("rotation header");
        let next_committee = field(&reference, "committees")
            .as_object()
            .expect("committees")
            .values()
            .map(|committee| {
                field(committee, "keys")
                    .as_array()
                    .expect("keys")
                    .iter()
                    .map(|key| bytes(key).try_into().expect("48-byte key"))
                    .collect::<Vec<[u8; 48]>>()
            })
            .find(|keys| committee_root(keys) == Some(header.next_committee_root()))
            .expect("reference successor committee");
        SccpRotationV1 {
            certificate,
            next_committee,
        }
    }

    // These paths exercise codecs and conversion only; they do not claim leaf inclusion.
    fn block(certificate: &SccpCertificateV1, historical: bool) -> SccpBlockRefV1 {
        let header = SccpFinalityHeaderV1::parse(&certificate.header).expect("header");
        if historical {
            SccpBlockRefV1 {
                height: certificate.height - 1,
                sccp_root: [0xe4; 32],
                message_count: 3,
                history_index: 2,
                history_path: vec![[0xf5; 32]],
            }
        } else {
            SccpBlockRefV1 {
                height: certificate.height,
                sccp_root: header.sccp_root(),
                message_count: header.message_count(),
                history_index: 0,
                history_path: Vec::new(),
            }
        }
    }

    fn message_bundle(historical: bool) -> SccpMessageProofBundleV1 {
        let certificate = certificate();
        SccpMessageProofBundleV1 {
            message_id: [0x0a; 32],
            payload: vec![0x02, 0x01, 0xaa, 0xbb],
            deadline_ms: 1_800_086_400_000,
            leaf_index: 1,
            path: vec![[0x01; 32], [0x02; 32]],
            block: block(&certificate, historical),
            certificate,
        }
    }

    fn control_bundle(historical: bool) -> SccpControlProofBundleV1 {
        let certificate = certificate();
        SccpControlProofBundleV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            control_nonce: 2,
            track: 2,
            parliament_paused: true,
            fast_pause_until_ms: 1_800_000_000_000,
            certificate_id: [0x04; 32],
            effect_hash: [0x05; 32],
            leaf_index: 1,
            path: vec![[0x03; 32]],
            block: block(&certificate, historical),
            certificate,
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
    fn proof_height_selector_is_strict_and_formats_current_values() {
        assert_eq!(SccpProofHeightV1::default(), SccpProofHeightV1::Record);
        for (text, expected) in [
            ("record", SccpProofHeightV1::Record),
            ("latest", SccpProofHeightV1::Latest),
            ("1", SccpProofHeightV1::At(1)),
            ("18446744073709551615", SccpProofHeightV1::At(u64::MAX)),
        ] {
            assert_eq!(text.parse::<SccpProofHeightV1>(), Ok(expected));
            assert_eq!(expected.to_string(), text);
        }
        assert_eq!(
            "001".parse::<SccpProofHeightV1>(),
            Ok(SccpProofHeightV1::At(1))
        );
        for text in [
            "",
            "own",
            "Record",
            "LATEST",
            "0",
            "000",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1\n",
            "\tlatest",
            "1_000",
            "1.0",
            "0x1",
            "１",
            "18446744073709551616",
        ] {
            assert_eq!(
                text.parse::<SccpProofHeightV1>(),
                Err(SccpProofHeightParseError),
                "{text:?}"
            );
        }
        let error: Box<dyn std::error::Error> = Box::new(SccpProofHeightParseError);
        assert_eq!(
            error.to_string(),
            "proof height must be record, latest, or a positive decimal u64"
        );
    }

    #[test]
    fn api_shape_errors_display_their_bounds() {
        for (error, text) in [
            (
                ApiShapeError::BadCommittee,
                "a committee has 4, 7, ..., 31 keys in strictly ascending order",
            ),
            (
                ApiShapeError::BadFinalityHeader,
                "a finality header must satisfy X1 through X7",
            ),
            (
                ApiShapeError::CertificateHeightMismatch,
                "certificate height differs from its finality header",
            ),
            (
                ApiShapeError::CommitteeRootMismatch,
                "committee keys differ from the active header's committee root",
            ),
            (
                ApiShapeError::BadSignerSet,
                "certificate signers must be exactly a committee quorum with no spare bits",
            ),
            (
                ApiShapeError::BadRotation,
                "a rotation must bind its successor committee in a ROTATION header",
            ),
            (
                ApiShapeError::BlockPathTooLong,
                "a block path has at most 9 siblings",
            ),
            (
                ApiShapeError::HistoryPathTooLong,
                "a history path has at most 32 siblings",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
        let boxed: Box<dyn std::error::Error> = Box::new(ApiShapeError::PayloadTooLong);
        assert!(boxed.to_string().contains("4096"));
    }

    #[test]
    fn api_schema_names_are_stable() {
        assert_eq!(
            SccpCertificateV1::nominal_name(),
            "iroha_sccp::api::SccpCertificateV1"
        );
        assert_eq!(
            SccpRotationV1::nominal_name(),
            "iroha_sccp::api::SccpRotationV1"
        );
        assert_eq!(
            SccpBlockRefV1::nominal_name(),
            "iroha_sccp::api::SccpBlockRefV1"
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
    fn api_records_roundtrip_in_every_codec() {
        roundtrip(&message_bundle(false));
        roundtrip(&message_bundle(true));
        roundtrip(&control_bundle(false));
        roundtrip(&control_bundle(true));
        roundtrip(&block(&certificate(), true));
        roundtrip(&certificate());
        roundtrip(&rotation());
    }

    #[test]
    fn api_json_objects_are_closed_and_complete() {
        let message = message_bundle(false);
        let control = control_bundle(true);
        let certificate = certificate();
        let block = block(&certificate, true);
        let rotation = rotation();
        assert_rejects_unknown_field(&message);
        assert_rejects_unknown_field(&control);
        assert_rejects_unknown_field(&certificate);
        assert_rejects_unknown_field(&block);
        assert_rejects_unknown_field(&rotation);
        for name in [
            "message_id",
            "payload",
            "deadline_ms",
            "leaf_index",
            "path",
            "block",
            "certificate",
        ] {
            assert_requires_field(&message, name);
        }
        for name in [
            "network",
            "revision",
            "control_nonce",
            "track",
            "parliament_paused",
            "fast_pause_until_ms",
            "certificate_id",
            "effect_hash",
            "leaf_index",
            "path",
            "block",
            "certificate",
        ] {
            assert_requires_field(&control, name);
        }
        for name in ["height", "qc", "aggregate_signature", "header", "committee"] {
            assert_requires_field(&certificate, name);
        }
        for name in [
            "height",
            "sccp_root",
            "message_count",
            "history_index",
            "history_path",
        ] {
            assert_requires_field(&block, name);
        }
        for name in ["certificate", "next_committee"] {
            assert_requires_field(&rotation, name);
        }
    }

    #[test]
    fn bundles_carry_no_attestation_roster_or_signature_field() {
        let message = norito::json::to_value(&message_bundle(false)).expect("JSON value");
        let control = norito::json::to_value(&control_bundle(false)).expect("JSON value");
        for field in [
            "statement",
            "digest",
            "roster",
            "signatures",
            "history",
            "message_count",
            "paused",
        ] {
            assert!(message.get(field).is_none(), "{field}");
            assert!(control.get(field).is_none(), "{field}");
            let mut hostile = message.clone();
            hostile
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), Value::Null);
            assert!(
                norito::json::from_value::<SccpMessageProofBundleV1>(hostile).is_err(),
                "{field}"
            );
            let mut hostile = control.clone();
            hostile
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), Value::Null);
            assert!(
                norito::json::from_value::<SccpControlProofBundleV1>(hostile).is_err(),
                "{field}"
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
                "payload"
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
                "track"
            ]
        );
    }

    #[test]
    fn api_json_uses_base64_payload_and_hex_arrays() {
        let bundle = message_bundle(false);
        let json = norito::json::to_value(&bundle).expect("JSON value");
        assert_eq!(
            json.get("payload").and_then(Value::as_str),
            Some("AgGquw==")
        );
        assert_eq!(
            field(&json, "message_id").as_str().expect("message id"),
            "0A".repeat(32)
        );
        let certificate_json = field(&json, "certificate");
        for (name, length) in [("qc", 116), ("aggregate_signature", 96), ("header", 221)] {
            let text = field(certificate_json, name).as_str().expect("hex string");
            assert_eq!(text.len(), 2 * length);
            assert!(text.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        let keys = field(certificate_json, "committee")
            .as_array()
            .expect("keys");
        assert_eq!(keys.len(), 4);
        assert!(
            keys.iter()
                .all(|key| key.as_str().expect("hex key").len() == 96)
        );
        let mut hostile = json;
        hostile
            .as_object_mut()
            .expect("object")
            .insert("payload".to_owned(), Value::from("AgGquw"));
        assert!(norito::json::from_value::<SccpMessageProofBundleV1>(hostile).is_err());
    }

    #[test]
    fn certificate_json_rejects_wrong_fixed_widths_and_retired_fields() {
        let value = norito::json::to_value(&certificate()).expect("JSON value");
        for (name, length) in [("qc", 116), ("aggregate_signature", 96), ("header", 221)] {
            for width in [length - 1, length + 1] {
                let mut hostile = value.clone();
                hostile
                    .as_object_mut()
                    .expect("object")
                    .insert(name.to_owned(), Value::from("00".repeat(width)));
                assert!(
                    norito::json::from_value::<SccpCertificateV1>(hostile).is_err(),
                    "{name}/{width}"
                );
            }
        }
        for width in [47, 49] {
            let mut hostile = value.clone();
            hostile.as_object_mut().expect("object").insert(
                "committee".to_owned(),
                Value::Array(vec![Value::from("00".repeat(width))]),
            );
            assert!(
                norito::json::from_value::<SccpCertificateV1>(hostile).is_err(),
                "key/{width}"
            );
        }
        for name in [
            "statement",
            "digest",
            "signer_bitmap",
            "signatures",
            "roster",
        ] {
            let mut hostile = value.clone();
            hostile
                .as_object_mut()
                .expect("object")
                .insert(name.to_owned(), Value::Null);
            assert!(
                norito::json::from_value::<SccpCertificateV1>(hostile).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn certificate_shape_checks_consistency_without_granting_authentication() {
        let certificate = certificate();
        assert_eq!(certificate.check_shape(), Ok(()));
        let mut changed = certificate.clone();
        changed.height += 1;
        assert_eq!(
            changed.check_shape(),
            Err(ApiShapeError::CertificateHeightMismatch)
        );
        changed = certificate.clone();
        changed.header[0] ^= 1;
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadFinalityHeader));
        changed = certificate.clone();
        changed.committee.pop();
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadCommittee));
        changed = certificate.clone();
        changed.committee.swap(0, 1);
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadCommittee));
        changed = certificate.clone();
        changed.committee[1] = changed.committee[0];
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadCommittee));
        changed = certificate.clone();
        changed.committee[0][47] ^= 1;
        assert_eq!(
            changed.check_shape(),
            Err(ApiShapeError::CommitteeRootMismatch)
        );
        for signers in [0, 0b0011, 0b1111, 0b1_0011] {
            changed = certificate.clone();
            let mut qc = QcFixedV1::parse(&changed.qc).expect("QC");
            qc.signers = signers;
            changed.qc = qc.encode();
            assert_eq!(
                changed.check_shape(),
                Err(ApiShapeError::BadSignerSet),
                "{signers}"
            );
        }
        changed = certificate;
        changed.aggregate_signature = [0; 96];
        assert_eq!(
            changed.check_shape(),
            Ok(()),
            "shape checking cannot authenticate a signature"
        );
        assert!(
            verify_certificate(
                &[0x77; 32],
                &changed.qc,
                &changed.header,
                &changed.aggregate_signature,
                &changed.committee
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_codec_preserves_authenticated_finality_and_refuses_tampering() {
        let reference = reference();
        let row = field(&reference, "certificates")
            .as_array()
            .expect("certificates")
            .first()
            .expect("certificate");
        let certificate = certificate_from_row(&reference, row);
        let instance: [u8; 32] = bytes(field(
            field(&reference, "verification_context"),
            "consensus_instance",
        ))
        .try_into()
        .expect("instance");
        let pinned_root: [u8; 32] = bytes(field(field(row, "pin"), "committee_root"))
            .try_into()
            .expect("root");
        assert_eq!(committee_root(&certificate.committee), Some(pinned_root));
        let encoded = certificate.encode();
        let decoded =
            SccpCertificateV1::decode_all(&mut encoded.as_slice()).expect("decoded certificate");
        let verify = |value: &SccpCertificateV1, instance: &[u8; 32]| {
            verify_certificate(
                instance,
                &value.qc,
                &value.header,
                &value.aggregate_signature,
                &value.committee,
            )
        };
        let verified = verify(&decoded, &instance).expect("genuine aggregate certificate");
        assert_eq!(verified.header.height(), decoded.height);
        assert_eq!(verified.header.committee_root(), pinned_root);
        assert_eq!(verified.result.as_slice(), bytes(field(row, "r")));
        assert_eq!(
            verified.checkpoint_id.as_slice(),
            bytes(field(row, "checkpoint_id"))
        );
        assert_eq!(
            verify(&decoded, &[0x78; 32]),
            Err(CertificateError::Signature)
        );
        let mut changed = decoded.clone();
        changed.qc[80] ^= 1;
        assert_eq!(
            verify(&changed, &instance),
            Err(CertificateError::Signature)
        );
        changed = decoded.clone();
        changed.aggregate_signature[95] ^= 1;
        assert!(verify(&changed, &instance).is_err());
        changed = decoded;
        changed.header[100] ^= 1;
        assert!(verify(&changed, &instance).is_err());
    }

    #[test]
    fn rotation_shape_requires_rotation_and_bound_successor_keys() {
        let rotation = rotation();
        assert_eq!(rotation.check_shape(), Ok(()));
        let mut changed = rotation.clone();
        changed.certificate = certificate();
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        changed = rotation.clone();
        changed.next_committee.pop();
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        changed = rotation.clone();
        changed.next_committee.swap(0, 1);
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        changed = rotation.clone();
        changed.next_committee[0][47] ^= 1;
        assert_eq!(changed.check_shape(), Err(ApiShapeError::BadRotation));
        changed = rotation;
        changed.certificate.height += 1;
        assert_eq!(
            changed.check_shape(),
            Err(ApiShapeError::CertificateHeightMismatch)
        );
    }

    #[test]
    fn block_reference_converts_both_ways() {
        for historical in [false, true] {
            let block = block(&certificate(), historical);
            let contract = BlockRefV1::from(&block);
            assert_eq!(contract.height, block.height);
            assert_eq!(contract.sccp_root, block.sccp_root);
            assert_eq!(contract.message_count, block.message_count);
            assert_eq!(contract.history_index, block.history_index);
            assert_eq!(contract.history_path, block.history_path);
            assert_eq!(SccpBlockRefV1::from(&contract), block);
        }
        let mut long = block(&certificate(), true);
        long.history_path = vec![[0; 32]; MAX_HISTORY_PATH];
        assert_eq!(long.check_shape(), Ok(()));
        long.history_path.push([0; 32]);
        assert_eq!(long.check_shape(), Err(ApiShapeError::HistoryPathTooLong));
    }

    #[test]
    fn bundle_accessors_expose_contract_structures() {
        for historical in [false, true] {
            let message = message_bundle(historical);
            assert_eq!(message.is_historical(), historical);
            let proof = message.message_proof();
            assert_eq!(proof.payload, message.payload);
            assert_eq!(proof.leaf_index, message.leaf_index);
            assert_eq!(proof.path, message.path);
            assert_eq!(SccpBlockRefV1::from(&proof.block), message.block);
            assert_eq!(message.check_shape(), Ok(()));
            for paused in [false, true] {
                let mut control = control_bundle(historical);
                control.parliament_paused = paused;
                assert_eq!(control.is_historical(), historical);
                let proof = control.control_proof();
                assert_eq!(proof.control_nonce, control.control_nonce);
                assert_eq!(proof.track, control.track);
                assert_eq!(proof.parliament_paused, u8::from(paused));
                assert_eq!(proof.fast_pause_until_ms, control.fast_pause_until_ms);
                assert_eq!(proof.certificate_id, control.certificate_id);
                assert_eq!(proof.effect_hash, control.effect_hash);
                assert_eq!(proof.leaf_index, control.leaf_index);
                assert_eq!(proof.path, control.path);
                assert_eq!(SccpBlockRefV1::from(&proof.block), control.block);
                assert_eq!(control.check_shape(), Ok(()));
            }
        }
    }

    #[test]
    fn bundle_shapes_enforce_payload_path_and_certificate_bounds() {
        let mut message = message_bundle(false);
        message.payload = vec![0; MAX_PAYLOAD_BYTES];
        message.path = vec![[0; 32]; MAX_BLOCK_PATH];
        message.block.history_path = vec![[0; 32]; MAX_HISTORY_PATH];
        assert_eq!(message.check_shape(), Ok(()));
        message.payload.push(0);
        assert_eq!(message.check_shape(), Err(ApiShapeError::PayloadTooLong));
        message.payload.pop();
        message.path.push([0; 32]);
        assert_eq!(message.check_shape(), Err(ApiShapeError::BlockPathTooLong));
        message.path.pop();
        message.block.history_path.push([0; 32]);
        assert_eq!(
            message.check_shape(),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        message.block.history_path.pop();
        message.certificate.committee.clear();
        assert_eq!(message.check_shape(), Err(ApiShapeError::BadCommittee));

        let mut control = control_bundle(true);
        control.path = vec![[0; 32]; MAX_BLOCK_PATH];
        control.block.history_path = vec![[0; 32]; MAX_HISTORY_PATH];
        assert_eq!(control.check_shape(), Ok(()));
        control.path.push([0; 32]);
        assert_eq!(control.check_shape(), Err(ApiShapeError::BlockPathTooLong));
        control.path.pop();
        control.block.history_path.push([0; 32]);
        assert_eq!(
            control.check_shape(),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        control.block.history_path.pop();
        control.certificate.height += 1;
        assert_eq!(
            control.check_shape(),
            Err(ApiShapeError::CertificateHeightMismatch)
        );
    }
}
