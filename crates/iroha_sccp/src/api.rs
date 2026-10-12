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
//! Proof material:
//!
//! - [`SccpHistoryProofV1`]: a historical SCCP block and its history path (§3.5).
//! - [`SccpMessageProofBundleV1`] and [`SccpControlProofBundleV1`]: a transfer or complete
//!   control leaf, its ordered block path, block reference and native Sumeragi certificate.
//! - [`finality::verify_native_certificate`]: verifies the certificate against independently
//!   authenticated caller authority; decoding transport grants no finality authority.
//!
//! Nothing here is trusted by its reader: wallets recompute every digest, signature and Merkle
//! path locally (`iroha_sccp_wallet::pure`). The conversions below map the records onto the
//! contract-visible `v1` structures that the verifiers and ABI encoders take.
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
pub mod finality;
pub use iroha_data_model::sccp::finality::{
    SccpBlockRefV1, SccpCertificateV1, SccpGenerationV1, SccpRotationV1,
};

use crate::v1::{
    constants::{MAX_BLOCK_LEAVES, MAX_BLOCK_PATH, MAX_HISTORY_PATH, MAX_PAYLOAD_BYTES},
    control::ControlLeafV1,
    proof::{HistoryBlockV1, HistoryProofV1, MessageProofV1},
};

/// Maximum native committee rotations returned in one read page (§6).
pub const MAX_ROTATION_STEPS: usize = 16;

/// A record exceeds a protocol bound before any cryptographic check (§3.4, §3.5, §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiShapeError {
    /// The untrusted certificate claims a committee outside the first-release 3f+1 geometry.
    CertificateCommitteeSize,
    /// Block coordinates do not describe direct or historical inclusion in this certificate.
    BlockReference,
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
            Self::CertificateCommitteeSize => "a native committee has 3f + 1 keys for 1 <= f <= 10",
            Self::BlockReference => "block coordinates do not match the certified inclusion mode",
            Self::BlockPathTooLong => "a block path has at most 9 siblings",
            Self::HistoryPathTooLong => "a history path has at most 32 siblings",
            Self::PayloadTooLong => "a transfer payload has at most 4096 bytes",
        })
    }
}

impl std::error::Error for ApiShapeError {}

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

impl From<&SccpHistoryProofV1> for HistoryProofV1 {
    fn from(proof: &SccpHistoryProofV1) -> Self {
        Self {
            block: HistoryBlockV1 {
                height: proof.height,
                sccp_root: proof.sccp_root,
                message_count: proof.message_count,
            },
            leaf_index: proof.leaf_index,
            path: proof.path.clone(),
        }
    }
}

impl From<&HistoryProofV1> for SccpHistoryProofV1 {
    fn from(proof: &HistoryProofV1) -> Self {
        Self {
            height: proof.block.height,
            sccp_root: proof.block.sccp_root,
            message_count: proof.block.message_count,
            leaf_index: proof.leaf_index,
            path: proof.path.clone(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Message proof bundle
// ---------------------------------------------------------------------------------------------

/// A transfer leaf, its block inclusion path and a native certificate (§3.4, §3.5, §6).
/// Readers authenticate the certificate independently and verify the block/history paths.
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
    /// The recorded block, including the path to a later certificate's history if required.
    pub block: SccpBlockRefV1,
    /// Native CommitQC projection; verification requires independent caller authority.
    pub certificate: SccpCertificateV1,
}

impl SccpMessageProofBundleV1 {
    /// Whether the bundle proves the message through the history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.block.height < self.certificate.height
    }

    /// `MessageProofV1 { payload, leafIndex, path }` (§5.2.2).
    #[must_use]
    pub fn message_proof(&self) -> MessageProofV1 {
        MessageProofV1 {
            payload: self.payload.clone(),
            leaf_index: self.leaf_index,
            path: self.path.clone(),
        }
    }

    /// `HistoryProofV1` of historical mode.
    #[must_use]
    pub fn history_proof(&self) -> Option<HistoryProofV1> {
        history_for_block(&self.block, self.certificate.height)
    }

    /// Reject oversized fields before any hashing.
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
        check_block_shape(&self.block, &self.certificate, self.leaf_index)
    }
}

// ---------------------------------------------------------------------------------------------
// Control proof bundle
// ---------------------------------------------------------------------------------------------

/// A complete control leaf, its block inclusion path and a native certificate (§6).
/// All pause tracks and their authority digests are retained; no single pause flag substitutes
/// for the canonical control preimage. Readers verify finality and inclusion independently.
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
    /// Authority track: Parliament (1) or fast pause (2).
    pub track: u8,
    /// Parliament pause state after the change.
    pub parliament_paused: bool,
    /// Fast-pause expiry after the change, or zero for none.
    pub fast_pause_until_ms: u64,
    /// Enacting authority certificate identity.
    pub certificate_id: [u8; 32],
    /// Enacting authority effect preimage hash.
    pub effect_hash: [u8; 32],
    /// Commitment index of the control leaf in its block.
    pub leaf_index: u32,
    /// Block path of the control leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// The recorded block, including the path to a later certificate's history if required.
    pub block: SccpBlockRefV1,
    /// Native CommitQC projection; verification requires independent caller authority.
    pub certificate: SccpCertificateV1,
}

impl SccpControlProofBundleV1 {
    /// Whether the bundle proves the control through the history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.block.height < self.certificate.height
    }

    /// Complete canonical control fields, before lane/destination binding and hashing.
    #[must_use]
    pub fn control_leaf(&self) -> ControlLeafV1 {
        ControlLeafV1 {
            route_revision: self.revision,
            control_nonce: self.control_nonce,
            track: self.track,
            parliament_paused: u8::from(self.parliament_paused),
            fast_pause_until_ms: self.fast_pause_until_ms,
            certificate_id: self.certificate_id,
            effect_hash: self.effect_hash,
        }
    }

    /// `HistoryProofV1` of historical mode.
    #[must_use]
    pub fn history_proof(&self) -> Option<HistoryProofV1> {
        history_for_block(&self.block, self.certificate.height)
    }

    /// Reject oversized fields before any hashing.
    ///
    /// # Errors
    ///
    /// Returns the first violated [`ApiShapeError`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.path.len() > MAX_BLOCK_PATH {
            return Err(ApiShapeError::BlockPathTooLong);
        }
        check_block_shape(&self.block, &self.certificate, self.leaf_index)
    }
}

// ---------------------------------------------------------------------------------------------
// Native block inclusion shape (transport only, never finality authority)
// ---------------------------------------------------------------------------------------------

fn history_for_block(block: &SccpBlockRefV1, certificate_height: u64) -> Option<HistoryProofV1> {
    (block.height < certificate_height).then(|| HistoryProofV1 {
        block: HistoryBlockV1 {
            height: block.height,
            sccp_root: block.sccp_root,
            message_count: block.message_count,
        },
        leaf_index: block.history_index,
        path: block.history_path.clone(),
    })
}

fn check_block_shape(
    block: &SccpBlockRefV1,
    certificate: &SccpCertificateV1,
    leaf_index: u32,
) -> Result<(), ApiShapeError> {
    if block.history_path.len() > MAX_HISTORY_PATH {
        return Err(ApiShapeError::HistoryPathTooLong);
    }
    if !iroha_data_model::block::consensus::is_valid_committee_size(certificate.committee.len()) {
        return Err(ApiShapeError::CertificateCommitteeSize);
    }
    if block.height == 0
        || block.height > certificate.height
        || !(1..=MAX_BLOCK_LEAVES).contains(&block.message_count)
        || leaf_index >= block.message_count
        || (block.height == certificate.height
            && (block.history_index != 0 || !block.history_path.is_empty()))
    {
        return Err(ApiShapeError::BlockReference);
    }
    Ok(())
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

/// `GET /v1/sccp/capabilities`: the Taira identity, parameters and light-client profiles a
/// wallet reads before any flow (§6, §7.1).
///
/// TODO: connect the finality constants and real forgery-hold, seated-panel and launch-gate
/// owners of §6. Missing owners must not be represented as fabricated safe/empty state.
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
    /// Live Taira `NetworkId` authenticated by native finality.
    pub network_id: [u8; 32],
    /// Native consensus instance; `None` only while SCCP is absent.
    #[norito(required)]
    pub consensus_instance: Option<[u8; 32]>,
    /// SCCP parameters; `None` when SCCP does not exist on this network.
    #[norito(required)]
    pub parameters: Option<iroha_data_model::sccp::params::SccpParametersV1>,
    /// Latest committed Taira height.
    pub committed_height: u64,
    /// Current retained generation and its liability at this same committed cut.
    #[norito(required)]
    pub current_generation: Option<SccpGenerationV1>,
    /// Replicated liability clock at this committed cut.
    pub liability_clock: u64,
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
    fn history() -> SccpHistoryProofV1 {
        SccpHistoryProofV1 {
            height: 50,
            sccp_root: [0xe4; 32],
            message_count: 3,
            leaf_index: 0,
            path: vec![[0xf5; 32]],
        }
    }

    // Codec fixtures are intentionally unauthenticated claims; the finality module tests
    // independently verified native CommitQCs. A successful shape/roundtrip is not authority.
    fn certificate(height: u64) -> SccpCertificateV1 {
        SccpCertificateV1 {
            height,
            qc: [1; 116],
            aggregate_signature: [2; 96],
            header: [3; 221],
            committee: vec![[4; 48]; 4],
        }
    }

    fn block(history: Option<SccpHistoryProofV1>) -> SccpBlockRefV1 {
        history.map_or_else(
            || SccpBlockRefV1 {
                height: 60,
                sccp_root: [0xe4; 32],
                message_count: 3,
                history_index: 0,
                history_path: Vec::new(),
            },
            |history| SccpBlockRefV1 {
                height: history.height,
                sccp_root: history.sccp_root,
                message_count: history.message_count,
                history_index: history.leaf_index,
                history_path: history.path,
            },
        )
    }

    fn message_bundle(history: Option<SccpHistoryProofV1>) -> SccpMessageProofBundleV1 {
        SccpMessageProofBundleV1 {
            message_id: [0x0a; 32],
            payload: vec![0x02, 0x01, 0xaa, 0xbb],
            deadline_ms: 1_800_086_400_000,
            leaf_index: 1,
            path: vec![[0x01; 32], [0x02; 32]],
            block: block(history),
            certificate: certificate(60),
        }
    }

    fn control_bundle(history: Option<SccpHistoryProofV1>) -> SccpControlProofBundleV1 {
        SccpControlProofBundleV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            control_nonce: 2,
            track: crate::v1::control::TRACK_FAST_PAUSE,
            parliament_paused: true,
            fast_pause_until_ms: 1_234,
            certificate_id: [0xc1; 32],
            effect_hash: [0xef; 32],
            leaf_index: 2,
            path: vec![[0x03; 32]],
            block: block(history),
            certificate: certificate(60),
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
            ApiShapeError::CertificateCommitteeSize.to_string(),
            "a native committee has 3f + 1 keys for 1 <= f <= 10"
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
    }

    #[test]
    fn api_json_objects_are_closed_and_complete() {
        assert_rejects_unknown_field(&message_bundle(None));
        assert_rejects_unknown_field(&control_bundle(Some(history())));
        assert_rejects_unknown_field(&history());
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
        let bundle = message_bundle(None);
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
        assert!(json.get("block").expect("block reference").is_object());
        assert!(
            json.get("certificate")
                .expect("native certificate")
                .is_object()
        );
        assert!(json.get("history").is_none());
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
    fn history_proof_converts_both_ways() {
        let proof = history();
        let contract = HistoryProofV1::from(&proof);
        assert_eq!(contract.block.height, 50);
        assert_eq!(contract.block.sccp_root, [0xe4; 32]);
        assert_eq!(contract.block.message_count, 3);
        assert_eq!(contract.leaf_index, 0);
        assert_eq!(contract.path, vec![[0xf5; 32]]);
        assert_eq!(SccpHistoryProofV1::from(&contract), proof);
        let mut long = proof;
        long.path = vec![[0; 32]; MAX_HISTORY_PATH + 1];
        assert_eq!(long.check_shape(), Err(ApiShapeError::HistoryPathTooLong));
    }

    #[test]
    fn bundle_accessors_expose_contract_structures() {
        let direct = message_bundle(None);
        assert!(!direct.is_historical());
        assert_eq!(direct.history_proof(), None);
        let proof = direct.message_proof();
        assert_eq!(proof.payload, direct.payload);
        assert_eq!(proof.leaf_index, 1);
        assert_eq!(proof.path, direct.path);
        assert_eq!(direct.check_shape(), Ok(()));

        let historical = message_bundle(Some(history()));
        assert!(historical.is_historical());
        assert_eq!(
            historical.history_proof().expect("history").block.height,
            50
        );

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
        let leaf = control.control_leaf();
        assert_eq!(leaf.route_revision, control.revision);
        assert_eq!(leaf.control_nonce, 2);
        assert_eq!(leaf.track, crate::v1::control::TRACK_FAST_PAUSE);
        assert_eq!(leaf.parliament_paused, 1);
        assert_eq!(leaf.fast_pause_until_ms, 1_234);
        assert_eq!(leaf.certificate_id, [0xc1; 32]);
        assert_eq!(leaf.effect_hash, [0xef; 32]);
        assert_eq!(crate::v1::control::check_control_constraints(&leaf), Ok(()));
        assert_eq!(control.history_proof().expect("history").leaf_index, 0);
        assert_eq!(control.check_shape(), Ok(()));
        let mut long_control = control;
        long_control.path = vec![[0; 32]; MAX_BLOCK_PATH + 1];
        assert_eq!(
            long_control.check_shape(),
            Err(ApiShapeError::BlockPathTooLong)
        );
        assert!(!control_bundle(None).is_historical());
        // A history path beyond 32 siblings is refused through either bundle.
        let mut long_history = history();
        long_history.path = vec![[0; 32]; MAX_HISTORY_PATH + 1];
        assert_eq!(
            message_bundle(Some(long_history.clone())).check_shape(),
            Err(ApiShapeError::HistoryPathTooLong)
        );
        assert_eq!(
            control_bundle(Some(long_history)).check_shape(),
            Err(ApiShapeError::HistoryPathTooLong)
        );
    }

    #[test]
    fn native_bundle_shape_rejects_malformed_geometry_and_inclusion_coordinates() {
        for members in 0..=33 {
            let mut message = message_bundle(None);
            message.certificate.committee = vec![[4; 48]; members];
            let accepted = (4..=31).contains(&members) && (members - 1) % 3 == 0;
            assert_eq!(
                message.check_shape().is_ok(),
                accepted,
                "committee size {members}"
            );
        }
        let direct = message_bundle(None);
        for invalid in [
            SccpBlockRefV1 {
                height: 0,
                ..direct.block.clone()
            },
            SccpBlockRefV1 {
                height: 61,
                ..direct.block.clone()
            },
            SccpBlockRefV1 {
                message_count: 0,
                ..direct.block.clone()
            },
            SccpBlockRefV1 {
                message_count: MAX_BLOCK_LEAVES + 1,
                ..direct.block.clone()
            },
            SccpBlockRefV1 {
                history_index: 1,
                ..direct.block.clone()
            },
            SccpBlockRefV1 {
                history_path: vec![[1; 32]],
                ..direct.block.clone()
            },
        ] {
            let mut message = direct.clone();
            message.block = invalid.clone();
            assert_eq!(message.check_shape(), Err(ApiShapeError::BlockReference));
            let mut control = control_bundle(None);
            control.block = invalid;
            assert_eq!(control.check_shape(), Err(ApiShapeError::BlockReference));
        }
        let mut outside = direct;
        outside.leaf_index = outside.block.message_count;
        assert_eq!(outside.check_shape(), Err(ApiShapeError::BlockReference));
        let mut one_leaf_history = message_bundle(Some(history()));
        one_leaf_history.block.history_path.clear();
        assert!(
            one_leaf_history.is_historical(),
            "an empty singleton history path is still historical"
        );
        assert!(one_leaf_history.history_proof().is_some());
        assert_eq!(one_leaf_history.check_shape(), Ok(()));
    }

    #[test]
    fn native_control_conversion_preserves_every_preimage_field() {
        use crate::v1::control::{TRACK_PARLIAMENT, control_leaf};
        use crate::v1::merkle::{PromoteOddTree, verify_block_inclusion};
        let bundle = control_bundle(None);
        let original = bundle.control_leaf();
        let hash = |leaf: &ControlLeafV1| {
            control_leaf(&[0x44; 32], bundle.network, &[0x99; 32], leaf).unwrap()
        };
        let expected = hash(&original);
        let tree = PromoteOddTree::block(&[[0x11; 32], expected, [0x22; 32]]).unwrap();
        let path = tree.path(1).unwrap();
        assert_eq!(
            verify_block_inclusion(&expected, 1, 3, &path, &tree.root()),
            Ok(())
        );
        for changed in [
            ControlLeafV1 {
                route_revision: original.route_revision + 1,
                ..original
            },
            ControlLeafV1 {
                control_nonce: original.control_nonce + 1,
                ..original
            },
            ControlLeafV1 {
                track: TRACK_PARLIAMENT,
                ..original
            },
            ControlLeafV1 {
                parliament_paused: 0,
                ..original
            },
            ControlLeafV1 {
                fast_pause_until_ms: original.fast_pause_until_ms + 1,
                ..original
            },
            ControlLeafV1 {
                certificate_id: [0x33; 32],
                ..original
            },
            ControlLeafV1 {
                effect_hash: [0x55; 32],
                ..original
            },
        ] {
            assert_ne!(hash(&changed), expected);
            assert!(verify_block_inclusion(&hash(&changed), 1, 3, &path, &tree.root()).is_err());
        }
        let mut hostile = norito::json::to_value(&bundle).unwrap();
        hostile
            .as_object_mut()
            .unwrap()
            .insert("paused".into(), Value::Bool(true));
        assert!(norito::json::from_value::<SccpControlProofBundleV1>(hostile).is_err());
        for field in [
            "track",
            "parliament_paused",
            "fast_pause_until_ms",
            "certificate_id",
            "effect_hash",
        ] {
            assert_requires_field(&bundle, field);
        }
    }

    #[test]
    fn capabilities_keep_explicit_native_options_and_no_attestation_domain() {
        let mut value = SccpCapabilitiesV1 {
            network_id: [9; 32],
            consensus_instance: None,
            parameters: None,
            committed_height: 7,
            current_generation: None,
            liability_clock: 0,
            light_client_profiles: Vec::new(),
            chain_id: "test".into(),
            profiles: Vec::new(),
            profiles_policy_hash: [8; 32],
            limits: SccpReadLimitsV1::v1(),
            path_templates: Vec::new(),
        };
        roundtrip(&value);
        assert_rejects_unknown_field(&value);
        for field in [
            "consensus_instance",
            "parameters",
            "current_generation",
            "liability_clock",
        ] {
            assert_requires_field(&value, field);
        }
        let json = norito::json::to_value(&value).unwrap();
        assert!(json.get("domain_separator").is_none());
        assert_eq!(MAX_ROTATION_STEPS, 16);

        // Present transport claims exercise every nested optional field without treating
        // these deliberately unauthenticated keys as a valid native committee.
        let parameters = iroha_data_model::sccp::params::SccpParametersV1::taira_default();
        value.consensus_instance = Some([6; 32]);
        value.liability_clock = 1_000;
        value.current_generation = Some(SccpGenerationV1 {
            generation: 1,
            committee_root: [5; 32],
            keys: vec![[4; 48]; 4],
            members: vec![None; 4],
            cause: iroha_data_model::sccp::committee::SccpGenerationCauseV1::Genesis,
            start_height: 1,
            start_timestamp_ms: 1_000,
            start_lc: 1_000,
            validity_ms: parameters.committee_validity_ms,
            deadline_ms: 1_000 + parameters.committee_validity_ms,
            grace_ms: parameters.forgery_evidence_grace_ms,
            progress_cap_ms: parameters.destination_progress_cap_ms,
            liable_until_lc: 1_000
                + parameters.committee_validity_ms
                + parameters.forgery_evidence_grace_ms,
            dest_cleared_lc: None,
            end: None,
            liable: true,
        });
        value.parameters = Some(parameters);
        roundtrip(&value);
    }
}
