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
//! - [`SccpSignatureSetV1`]: a §3.8 signature set, one 65-byte signature per set bitmap bit in
//!   ascending bit order.
//! - [`SccpHistoryProofV1`]: a historical SCCP block and its history path (§3.5).
//! - [`SccpMessageProofBundleV1`] and [`SccpControlProofBundleV1`]: the leaf of one transfer or
//!   control, its block path and, for an older block, the history proof.
//!
//! The bundles carry no finality proof and no route serves them: destinations verify Taira's
//! Sumeragi `CommitQC`, so the attestation statement and the roster and rotation records of
//! the attestation transport are gone. [`SccpSignatureSetV1`] remains only as the view of
//! `crate::v1::signature`, which WP-S1 deletes with the other revision 4 encodings.
//!
//! TODO: Torii work package (TT-A1): add the block reference and the certificate of §6 to both
//! bundles, the committee generation, rotation, evidence and hold records, and serve them.
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

use crate::v1::{
    constants::{
        MAX_BLOCK_PATH, MAX_HISTORY_PATH, MAX_PAYLOAD_BYTES, MAX_ROSTER_MEMBERS, SIGNATURE_BYTES,
    },
    proof::{ControlProofV1, HistoryBlockV1, HistoryProofV1, MessageProofV1},
    signature::SignatureSetV1,
};

/// A record exceeds a protocol bound before any cryptographic check (§3.4, §3.5, §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiShapeError {
    /// More than 31 signatures, or a signature count that differs from the bitmap popcount.
    BadSignatureCount,
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
            Self::BadSignatureCount => {
                "a signature set has one signature per set bitmap bit and at most 31"
            }
            Self::BlockPathTooLong => "a block path has at most 9 siblings",
            Self::HistoryPathTooLong => "a history path has at most 32 siblings",
            Self::PayloadTooLong => "a transfer payload has at most 4096 bytes",
        })
    }
}

impl std::error::Error for ApiShapeError {}

// ---------------------------------------------------------------------------------------------
// Signature set
// ---------------------------------------------------------------------------------------------

/// A §3.8 signature set: bit `i` names roster member `i`; one 65-byte `r ‖ s ‖ v` signature
/// per set bit, in ascending bit order.
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
#[norito_schema(name = "iroha_sccp::api::SccpSignatureSetV1")]
pub struct SccpSignatureSetV1 {
    /// Bit `i` set iff roster member `i` signed.
    pub signer_bitmap: u32,
    /// One signature per set bit, in ascending bit order.
    pub signatures: Vec<[u8; 65]>,
}

impl SccpSignatureSetV1 {
    /// Number of set bitmap bits.
    #[must_use]
    pub fn popcount(&self) -> u32 {
        self.signer_bitmap.count_ones()
    }

    /// Reject more than 31 signatures or a count that differs from the bitmap popcount.
    ///
    /// # Errors
    ///
    /// Returns [`ApiShapeError::BadSignatureCount`].
    pub fn check_shape(&self) -> Result<(), ApiShapeError> {
        if self.signatures.len() > MAX_ROSTER_MEMBERS
            || self.signatures.len() != self.popcount() as usize
        {
            return Err(ApiShapeError::BadSignatureCount);
        }
        Ok(())
    }

    /// The contract-visible set with the signatures concatenated (`SignaturesV1`).
    #[must_use]
    pub fn to_signature_set(&self) -> SignatureSetV1 {
        SignatureSetV1 {
            signer_bitmap: self.signer_bitmap,
            signatures: self.signatures.iter().flatten().copied().collect(),
        }
    }
}

impl TryFrom<&SignatureSetV1> for SccpSignatureSetV1 {
    type Error = ApiShapeError;

    fn try_from(set: &SignatureSetV1) -> Result<Self, Self::Error> {
        if !set.signatures.len().is_multiple_of(SIGNATURE_BYTES) {
            return Err(ApiShapeError::BadSignatureCount);
        }
        let signatures = set
            .signatures
            .chunks_exact(SIGNATURE_BYTES)
            .map(|chunk| {
                let mut signature = [0_u8; 65];
                signature.copy_from_slice(chunk);
                signature
            })
            .collect();
        let view = Self {
            signer_bitmap: set.signer_bitmap,
            signatures,
        };
        view.check_shape()?;
        Ok(view)
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

/// The leaf-and-path part of a message proof (§3.4, §3.5, §6).
///
/// Without [`Self::history`] the message is proven against the root of its own block; with it,
/// the message is proven against the historical block and that block against a later history
/// root. The bundle names no finality proof of either root, and no route serves it.
///
/// TODO: Torii work package (TT-A1): add `block: SccpBlockRefV1` and
/// `certificate: SccpCertificateV1` (§6) and serve the bundle from
/// `GET /v1/sccp/messages/{message_id}/proof`.
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
    /// Leaf count of the block that holds the message.
    pub message_count: u32,
    /// Block path of the transfer leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// History proof of an older block (historical mode), or `None` (direct mode).
    #[norito(required)]
    pub history: Option<SccpHistoryProofV1>,
}

impl SccpMessageProofBundleV1 {
    /// Whether the bundle proves the message through the history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.history.is_some()
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
        self.history.as_ref().map(HistoryProofV1::from)
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
        if let Some(history) = &self.history {
            history.check_shape()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Control proof bundle
// ---------------------------------------------------------------------------------------------

/// The leaf-and-path part of a control proof (§4.14.6, §5.1.6, §6).
///
/// The bundle carries the control's fields, never its leaf: a verifier computes the control
/// leaf from the destination's own immutables and these fields. It names no finality proof of
/// the block root, and no route serves it.
///
/// TODO: Torii work package (TT-A1): add `block: SccpBlockRefV1` and
/// `certificate: SccpCertificateV1` (§6) and serve the bundle from
/// `GET /v1/sccp/controls/{network}/{revision}/{control_nonce}/proof`.
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
    /// `true` pauses minting, `false` resumes it.
    pub paused: bool,
    /// Commitment index of the control leaf in its block.
    pub leaf_index: u32,
    /// Leaf count of the block that holds the control.
    pub message_count: u32,
    /// Block path of the control leaf (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
    /// History proof of an older block (historical mode), or `None` (direct mode).
    #[norito(required)]
    pub history: Option<SccpHistoryProofV1>,
}

impl SccpControlProofBundleV1 {
    /// Whether the bundle proves the control through the history root.
    #[must_use]
    pub fn is_historical(&self) -> bool {
        self.history.is_some()
    }

    /// `ControlProofV1 { controlNonce, paused, leafIndex, path }` (§5.2.2).
    #[must_use]
    pub fn control_proof(&self) -> ControlProofV1 {
        ControlProofV1 {
            control_nonce: self.control_nonce,
            paused: self.paused,
            leaf_index: self.leaf_index,
            path: self.path.clone(),
        }
    }

    /// `HistoryProofV1` of historical mode.
    #[must_use]
    pub fn history_proof(&self) -> Option<HistoryProofV1> {
        self.history.as_ref().map(HistoryProofV1::from)
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
        if let Some(history) = &self.history {
            history.check_shape()?;
        }
        Ok(())
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

/// `GET /v1/sccp/capabilities`: the Taira identity, parameters and light-client profiles a
/// wallet reads before any flow (§6, §7.1).
///
/// TODO: Torii work package (TT-A1): add the finality constants, the current committee
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
    /// Live Taira `NetworkId` (the EIP-712 salt).
    pub network_id: [u8; 32],
    /// EIP-712 domain separator of attestations (§3.6).
    pub domain_separator: [u8; 32],
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
    use crate::v1::{hashes::keccak256, signature::sign_digest};

    fn secret(index: u8) -> [u8; 32] {
        keccak256(&[b"SCCP/API/TEST/KEY", &[index]])
    }

    /// Three signatures of a four-slot set over one digest, as the API view.
    fn signatures() -> SccpSignatureSetV1 {
        let digest = keccak256(&[b"SCCP/API/TEST/DIGEST"]);
        let entries: Vec<(usize, [u8; 65])> = (0..3_u8)
            .map(|key| {
                (
                    usize::from(key) + 1,
                    sign_digest(&secret(key), &digest).expect("signature"),
                )
            })
            .collect();
        let set = SignatureSetV1::from_signers(4, &entries).expect("set");
        SccpSignatureSetV1::try_from(&set).expect("view")
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
        SccpMessageProofBundleV1 {
            message_id: [0x0a; 32],
            payload: vec![0x02, 0x01, 0xaa, 0xbb],
            deadline_ms: 1_800_086_400_000,
            leaf_index: 1,
            message_count: 3,
            path: vec![[0x01; 32], [0x02; 32]],
            history,
        }
    }

    fn control_bundle(history: Option<SccpHistoryProofV1>) -> SccpControlProofBundleV1 {
        SccpControlProofBundleV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            control_nonce: 2,
            paused: true,
            leaf_index: 2,
            message_count: 3,
            path: vec![[0x03; 32]],
            history,
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
            ApiShapeError::BadSignatureCount.to_string(),
            "a signature set has one signature per set bitmap bit and at most 31"
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
            SccpSignatureSetV1::nominal_name(),
            "iroha_sccp::api::SccpSignatureSetV1"
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
        roundtrip(&signatures());
        roundtrip(&SccpSignatureSetV1::default());
    }

    #[test]
    fn api_json_objects_are_closed_and_complete() {
        assert_rejects_unknown_field(&message_bundle(None));
        assert_rejects_unknown_field(&control_bundle(Some(history())));
        assert_rejects_unknown_field(&history());
        assert_rejects_unknown_field(&signatures());
        assert_requires_field(&message_bundle(None), "history");
        assert_requires_field(&message_bundle(None), "payload");
        assert_requires_field(&control_bundle(None), "history");
        assert_requires_field(&control_bundle(None), "control_nonce");
    }

    #[test]
    fn bundles_carry_no_attestation_roster_or_signature_field() {
        // The attestation transport is gone: a bundle that still names one of its fields is not
        // a bundle.
        let retired = ["statement", "digest", "roster", "signatures"];
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
                "deadline_ms",
                "history",
                "leaf_index",
                "message_count",
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
                "control_nonce",
                "history",
                "leaf_index",
                "message_count",
                "network",
                "path",
                "paused",
                "revision",
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
        assert_eq!(message_id, "0a".repeat(32));
        assert!(json.get("history").expect("history key").is_null());
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
    fn signature_set_view_converts_and_checks_counts() {
        let view = signatures();
        let set = view.to_signature_set();
        assert_eq!(set.signatures.len(), 3 * SIGNATURE_BYTES);
        assert_eq!(set.signer_bitmap, view.signer_bitmap);
        assert_eq!(set.signer_bitmap, 0b1110);
        assert_eq!(SccpSignatureSetV1::try_from(&set).expect("view"), view);
        assert_eq!(view.popcount(), 3);
        assert_eq!(view.check_shape(), Ok(()));
        let ragged = SignatureSetV1 {
            signer_bitmap: 1,
            signatures: vec![0; 64],
        };
        assert_eq!(
            SccpSignatureSetV1::try_from(&ragged),
            Err(ApiShapeError::BadSignatureCount)
        );
        let mut mismatched = view;
        mismatched.signatures.pop();
        assert_eq!(
            mismatched.check_shape(),
            Err(ApiShapeError::BadSignatureCount)
        );
        // More signatures than any committee has seats, even with a matching bitmap.
        let oversized = SccpSignatureSetV1 {
            signer_bitmap: u32::MAX,
            signatures: vec![[0; 65]; 32],
        };
        assert_eq!(
            oversized.check_shape(),
            Err(ApiShapeError::BadSignatureCount)
        );
    }

    #[test]
    fn history_proof_converts_both_ways() {
        let proof = history();
        let contract = HistoryProofV1::from(&proof);
        assert_eq!(contract.block.height, 50);
        assert_eq!(contract.block.sccp_root, [0xe4; 32]);
        assert_eq!(contract.block.message_count, 1);
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
        let control_proof = control.control_proof();
        assert_eq!(control_proof.control_nonce, 2);
        assert!(control_proof.paused);
        assert_eq!(control_proof.leaf_index, 2);
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
}
