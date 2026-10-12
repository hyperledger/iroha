//! SCCP v1 read-model views (`specs/sccp.md` §6).
//!
//! - [`SccpMessageStatusV1`] (`GET /v1/sccp/messages/{message_id}`): the status union of an
//!   outbound record (recorded, voided, refunded, stranded), an inbound record (pending,
//!   released, bounced) or an id Taira does not know.
//! - [`SccpOutboundPageV1`] (`GET /v1/sccp/outbound/{network}/{revision}`): records by nonce for
//!   void and refund planning and for finding a just-recorded transfer.
//! - [`SccpRecentMessagesV1`] (`GET /v1/sccp/messages/recent`): newest records first.
//! - [`SccpControlPageV1`] (`GET /v1/sccp/controls/{network}/{revision}`): destination controls.
//! - [`SccpLightClientDetailV1`] and [`SccpLcCheckpointCoverV1`] (`GET
//!   /v1/sccp/light-clients/{network}` and `/checkpoints?covering=N`).
//! - [`SccpGovernanceProposalDetailV1`] (`GET /v1/sccp/governance/proposals/{proposal_id}`).
//! - [`SccpHistoryPathViewV1`] (`GET /v1/sccp/history/{height}`).
//!
//! Like every read record these are untrusted transport: wallets verify proofs themselves.

use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    governance::types::{GovernanceAttemptV1, ProposalContentId},
    sccp::{
        control::SccpControlRecordV1,
        governance::SccpGovernanceProposalV1,
        inbound::SccpInboundRecordV1,
        light_client::{SccpLcCheckpointV1, SccpLcPointV1, SccpLightClientV1},
        outbound::{SccpOutboundMessageRecordV1, SccpStatusHeightV1, SccpVoidStatusV1},
    },
};
use norito::codec::{Decode, Encode};

use super::SccpBlockRefV1;

/// Largest `GET /v1/sccp/messages/recent` page (§6).
pub const MAX_RECENT_MESSAGES: usize = 50;
/// Largest `GET /v1/sccp/outbound/{network}/{revision}` page (§6).
pub const MAX_OUTBOUND_PAGE: usize = 256;
/// Largest `GET /v1/sccp/controls/{network}/{revision}` page (§6).
pub const MAX_CONTROLS_PAGE: usize = 64;

// ---------------------------------------------------------------------------------------------
// Message status union
// ---------------------------------------------------------------------------------------------

/// Payload of [`SccpOutboundStateV1::Recorded`].
///
/// TODO: Torii work package (TT-A1): add `provable` once the request-funded native proof
/// producer can serve a certificate covering the record height (§6).
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
#[norito_schema(name = "iroha_sccp::api::SccpRecordedStateV1")]
pub struct SccpRecordedStateV1 {
    /// Destination-time mint deadline.
    pub deadline_ms: u64,
}

/// Wallet-facing state of an outbound record (§6, §7.1 step 4, §7.3).
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
#[norito(tag = "state", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpOutboundStateV1")]
pub enum SccpOutboundStateV1 {
    /// Recorded on Taira.
    #[codec(index = 0)]
    #[norito(rename = "recorded")]
    Recorded(SccpRecordedStateV1),
    /// Voided on the destination and proven on Taira.
    #[codec(index = 1)]
    #[norito(rename = "voided")]
    Voided(SccpVoidStatusV1),
    /// Refunded to the sender.
    #[codec(index = 2)]
    #[norito(rename = "refunded")]
    Refunded(SccpStatusHeightV1),
    /// Moved to the route's stranded balance.
    #[codec(index = 3)]
    #[norito(rename = "stranded")]
    Stranded(SccpStatusHeightV1),
}

impl SccpOutboundStateV1 {
    /// Whether the state can no longer change (refunded or stranded).
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Refunded(_) | Self::Stranded(_))
    }
}

/// One outbound record with its wallet-facing state.
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
#[norito_schema(name = "iroha_sccp::api::SccpOutboundMessageViewV1")]
pub struct SccpOutboundMessageViewV1 {
    /// `message_id` (§3.3).
    pub message_id: [u8; 32],
    /// The stored record.
    pub record: SccpOutboundMessageRecordV1,
    /// Its state.
    pub state: SccpOutboundStateV1,
}

/// One inbound record; its `status` is the inbound state (`pending{reason}`, `released`,
/// `bounced{bounce_message_id}`).
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
#[norito_schema(name = "iroha_sccp::api::SccpInboundMessageViewV1")]
pub struct SccpInboundMessageViewV1 {
    /// `message_id` (§3.3).
    pub message_id: [u8; 32],
    /// The stored record.
    pub record: SccpInboundRecordV1,
}

/// `GET /v1/sccp/messages/{message_id}`: the status union of one message id (§6).
///
/// An id that is neither an outbound nor an inbound record is `unknown`: for a burn on an
/// external chain this means its proof was not submitted (or not accepted) yet.
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
#[norito(tag = "direction", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpMessageStatusV1")]
pub enum SccpMessageStatusV1 {
    /// A Taira → external transfer.
    #[codec(index = 0)]
    #[norito(rename = "outbound")]
    Outbound(SccpOutboundMessageViewV1),
    /// An external → Taira transfer.
    #[codec(index = 1)]
    #[norito(rename = "inbound")]
    Inbound(SccpInboundMessageViewV1),
    /// Taira holds no record with this id.
    #[codec(index = 2)]
    #[norito(rename = "unknown")]
    Unknown,
}

impl SccpMessageStatusV1 {
    /// Whether the status can no longer change: a refunded or stranded outbound record, or a
    /// released or bounced inbound record.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        match self {
            Self::Outbound(view) => view.state.is_final(),
            Self::Inbound(view) => !view.record.status.is_pending(),
            Self::Unknown => false,
        }
    }

    /// The outbound view, if this is an outbound record.
    #[must_use]
    pub const fn outbound(&self) -> Option<&SccpOutboundMessageViewV1> {
        match self {
            Self::Outbound(view) => Some(view),
            _ => None,
        }
    }

    /// The inbound view, if this is an inbound record.
    #[must_use]
    pub const fn inbound(&self) -> Option<&SccpInboundMessageViewV1> {
        match self {
            Self::Inbound(view) => Some(view),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------------------------

/// `GET /v1/sccp/outbound/{network}/{revision}?from_nonce&limit`: records by nonce, ascending.
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
#[norito_schema(name = "iroha_sccp::api::SccpOutboundPageV1")]
pub struct SccpOutboundPageV1 {
    /// External network.
    pub network: SccpNetworkV1,
    /// Route revision.
    pub revision: u32,
    /// The revision's next unassigned nonce (records exist for `0..next_outbound_nonce`).
    pub next_outbound_nonce: u64,
    /// Records with nonce `≥ from_nonce`, ascending, at most 256.
    pub records: Vec<SccpOutboundMessageViewV1>,
    /// `from_nonce` of the next page, when more records exist.
    #[norito(required)]
    pub next_from_nonce: Option<u64>,
}

/// `GET /v1/sccp/messages/recent?direction&network&before&limit`: records newest first.
///
/// Outbound records are ordered by `(height, commitment_index)` and inbound records by
/// `(proven_at_height, message_id)`; [`Self::next_before`] is the `before` cursor of the next
/// (older) page: `<height>:<commitment_index>` outbound, `<height>:<message_id hex>` inbound.
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
#[norito_schema(name = "iroha_sccp::api::SccpRecentMessagesV1")]
pub struct SccpRecentMessagesV1 {
    /// At most 50 records of one direction, newest first.
    pub messages: Vec<SccpMessageStatusV1>,
    /// Cursor of the next page, when more records exist.
    #[norito(required)]
    pub next_before: Option<String>,
}

/// One destination control.
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
#[norito_schema(name = "iroha_sccp::api::SccpControlViewV1")]
pub struct SccpControlViewV1 {
    /// Control nonce (`≥ 1`, strictly increasing per revision).
    pub control_nonce: u64,
    /// The stored combined pause state, certificate cause and committed leaf location.
    pub record: SccpControlRecordV1,
}

/// `GET /v1/sccp/controls/{network}/{revision}?after_nonce&limit`: controls ascending (§4.14.6).
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
#[norito_schema(name = "iroha_sccp::api::SccpControlPageV1")]
pub struct SccpControlPageV1 {
    /// External network.
    pub network: SccpNetworkV1,
    /// Route revision.
    pub revision: u32,
    /// The revision's next control nonce.
    pub next_control_nonce: u64,
    /// Controls with nonce `> after_nonce`, ascending, at most 64.
    pub controls: Vec<SccpControlViewV1>,
    /// `after_nonce` of the next page, when more controls exist.
    #[norito(required)]
    pub next_after_nonce: Option<u64>,
}

// ---------------------------------------------------------------------------------------------
// Light clients
// ---------------------------------------------------------------------------------------------

/// Stored consensus sets of one light client.
#[derive(
    Debug,
    Clone,
    Copy,
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
#[norito_schema(name = "iroha_sccp::api::SccpLcSetsSummaryV1")]
pub struct SccpLcSetsSummaryV1 {
    /// Retained sets.
    pub count: u64,
    /// Lowest retained set id.
    #[norito(required)]
    pub oldest_set_id: Option<u64>,
    /// Highest stored set id.
    #[norito(required)]
    pub latest_set_id: Option<u64>,
}

/// Stored checkpoints of one light client.
#[derive(
    Debug,
    Clone,
    Copy,
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
#[norito_schema(name = "iroha_sccp::api::SccpLcCheckpointsSummaryV1")]
pub struct SccpLcCheckpointsSummaryV1 {
    /// Retained checkpoints.
    pub count: u64,
    /// Lowest retained checkpoint height.
    #[norito(required)]
    pub lowest_source_height: Option<u64>,
    /// Highest retained checkpoint height.
    #[norito(required)]
    pub highest_source_height: Option<u64>,
    /// Stride buckets with a permanent lowest checkpoint (§4.13.1).
    pub permanent_buckets: u64,
}

/// `GET /v1/sccp/light-clients/{network}`: one light client with its freshness and stored
/// data (§4.13).
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
#[norito_schema(name = "iroha_sccp::api::SccpLightClientDetailV1")]
pub struct SccpLightClientDetailV1 {
    /// The stored light client: params, head, freeze state and `state_hash`.
    pub light_client: SccpLightClientV1,
    /// Installed, not frozen and within its weak-subjectivity bound at the committed block
    /// time, so burns on its chain are provable now.
    pub usable: bool,
    /// Taira time from which its newest signing set is stale (§4.13.4).
    #[norito(required)]
    pub weak_subjectivity_deadline_ms: Option<u64>,
    /// Last source time the profile version active at the next block verifies (§4.13.2);
    /// `None` on a peer whose release does not compile that version.
    #[norito(required)]
    pub supported_until_ms: Option<u64>,
    /// Stored consensus sets.
    pub sets: SccpLcSetsSummaryV1,
    /// Stored checkpoints.
    pub checkpoints: SccpLcCheckpointsSummaryV1,
}

/// One stored checkpoint and whether it is kept permanently.
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
#[norito_schema(name = "iroha_sccp::api::SccpLcCheckpointEntryV1")]
pub struct SccpLcCheckpointEntryV1 {
    /// The checkpoint.
    pub checkpoint: SccpLcCheckpointV1,
    /// Lowest of its stride bucket or Parliament-installed, so it is never pruned.
    pub permanent: bool,
}

/// `GET /v1/sccp/light-clients/{network}/checkpoints?covering=N`: the stored checkpoints that
/// anchor an ancestry proof of source height `N` (§4.13.5, §7.2).
///
/// An ancestry segment runs backwards from a stored checkpoint, so the anchor is the nearest
/// retained checkpoint at or above `N`; the nearest permanent one is reported too because a
/// prunable anchor may disappear before a slow claim lands.
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
#[norito_schema(name = "iroha_sccp::api::SccpLcCheckpointCoverV1")]
pub struct SccpLcCheckpointCoverV1 {
    /// Source network.
    pub network: SccpNetworkV1,
    /// The source height to cover.
    pub covering: u64,
    /// The light client's latest finalized point.
    pub head: SccpLcPointV1,
    /// Lowest retained checkpoint at or above `covering`.
    pub nearest: SccpLcCheckpointEntryV1,
    /// Lowest permanent checkpoint at or above `covering`, if any.
    #[norito(required)]
    pub nearest_permanent: Option<SccpLcCheckpointEntryV1>,
}

// ---------------------------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------------------------

/// Outcome of an SCCP governance proposal, mirrored from its newest Parliament attempt.
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
#[norito(tag = "phase", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceProposalPhaseV1")]
pub enum SccpGovernanceProposalPhaseV1 {
    /// Open: its newest attempt is active or certified, or it has none yet.
    #[codec(index = 0)]
    #[norito(rename = "proposed")]
    Proposed,
    /// Rejected by a binding Parliament body.
    #[codec(index = 1)]
    #[norito(rename = "rejected")]
    Rejected,
    /// Enacted.
    #[codec(index = 2)]
    #[norito(rename = "enacted")]
    Enacted,
    /// A base revision was no longer current at execution.
    #[codec(index = 3)]
    #[norito(rename = "superseded")]
    Superseded,
    /// The certified effect failed deterministic execution.
    #[codec(index = 4)]
    #[norito(rename = "execution_failed")]
    ExecutionFailed,
}

/// `GET /v1/sccp/governance/proposals/{proposal_id}`: one SCCP proposal in any phase (§6).
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
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceProposalDetailV1")]
pub struct SccpGovernanceProposalDetailV1 {
    /// Proposal content id.
    pub content_id: ProposalContentId,
    /// Submitting account.
    pub proposer: AccountId,
    /// Taira height at which it was submitted.
    pub created_height: u64,
    /// Its outcome so far.
    pub phase: SccpGovernanceProposalPhaseV1,
    /// The full proposal body.
    pub proposal: SccpGovernanceProposalV1,
    /// A new attempt would pass the SCCP preflight against current state (every base revision
    /// is current and every registered destination word is unused).
    pub admissible: bool,
    /// The newest Parliament attempt, if any.
    #[norito(required)]
    pub latest_attempt: Option<GovernanceAttemptV1>,
}

// ---------------------------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------------------------

/// `GET /v1/sccp/history/{height}?size=S`: the history leaf of SCCP block `height` and its path
/// within `history_root(S)` (§3.5).
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
#[norito_schema(name = "iroha_sccp::api::SccpHistoryPathViewV1")]
pub struct SccpHistoryPathViewV1 {
    /// History size `S` the path is taken in.
    pub history_size: u64,
    /// `history_root(S)`.
    pub history_root: [u8; 32],
    /// The block, its history leaf index and the path.
    pub proof: SccpBlockRefV1,
}

// ---------------------------------------------------------------------------------------------
// Capabilities parts
// ---------------------------------------------------------------------------------------------

/// The compiled source-chain profile of one network in the running release (§4.13.2).
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
#[norito_schema(name = "iroha_sccp::api::SccpChainProfileViewV1")]
pub struct SccpChainProfileViewV1 {
    /// Source network.
    pub network: SccpNetworkV1,
    /// Last source time the newest compiled profile version supports.
    #[norito(required)]
    pub supported_until_ms: Option<u64>,
}

/// Page limits of the §6 read routes.
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
#[norito_schema(name = "iroha_sccp::api::SccpReadLimitsV1")]
pub struct SccpReadLimitsV1 {
    /// `GET /v1/sccp/messages/recent`.
    pub recent_messages: u32,
    /// `GET /v1/sccp/outbound/{network}/{revision}`.
    pub outbound_page: u32,
    /// `GET /v1/sccp/controls/{network}/{revision}`.
    pub controls_page: u32,
    /// `GET /v1/sccp/committees/rotations`.
    pub rotations_page: u32,
}

impl SccpReadLimitsV1 {
    /// The limits this release serves.
    #[must_use]
    pub const fn v1() -> Self {
        // Equal to the `MAX_*` constants (pinned by a unit test).
        Self {
            recent_messages: 50,
            outbound_page: 256,
            controls_page: 64,
            rotations_page: 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sccp::{
        inbound::{SccpInboundStatusV1, SccpPendingReasonV1, SccpSourceLocatorV1},
        light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcHeadV1, SccpLightClientParamsV1,
        },
        outbound::{SccpOutboundStatusV1, SccpVoidKindV1},
    };
    use norito::{NoritoSchema as _, codec::DecodeAll, core::DecodeFromSlice, json::Value};

    fn account() -> AccountId {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![7; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("deterministic seed");
        AccountId::new(key_pair.public_key().clone())
    }

    /// Bare, headered, zero-copy slice and JSON roundtrips.
    fn roundtrip<T>(value: &T)
    where
        T: Encode
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

    fn assert_closed<T>(value: &T, required: &str)
    where
        T: norito::json::JsonSerialize + norito::json::JsonDeserialize + core::fmt::Debug,
    {
        let json = norito::json::to_value(value).expect("JSON value");
        let mut hostile = json.clone();
        hostile
            .as_object_mut()
            .expect("object")
            .insert("adversarial".to_owned(), Value::Null);
        let text = norito::json::to_json(&hostile).expect("JSON");
        assert!(norito::json::from_json::<T>(&text).is_err(), "{text}");
        let mut missing = json;
        missing
            .as_object_mut()
            .expect("object")
            .remove(required)
            .expect("field present");
        let text = norito::json::to_json(&missing).expect("JSON");
        assert!(norito::json::from_json::<T>(&text).is_err(), "{text}");
    }

    fn outbound(state: SccpOutboundStateV1) -> SccpOutboundMessageViewV1 {
        SccpOutboundMessageViewV1 {
            message_id: [1; 32],
            record: SccpOutboundMessageRecordV1 {
                network: SccpNetworkV1::TonMainnet,
                revision: 2,
                nonce: 5,
                height: 12,
                commitment_index: 1,
                deadline_ms: 99,
                sender: account(),
                amount: 10,
                payload: vec![2, 1],
                leaf: [3; 32],
                status: SccpOutboundStatusV1::Recorded,
            },
            state,
        }
    }

    fn inbound() -> SccpInboundMessageViewV1 {
        SccpInboundMessageViewV1 {
            message_id: [2; 32],
            record: SccpInboundRecordV1 {
                network: SccpNetworkV1::BscMainnet,
                revision: 1,
                payload: vec![4],
                source_locator: SccpSourceLocatorV1 {
                    source_height: 8,
                    block_hash: [5; 32],
                    index_in_block: 2,
                },
                proven_at_height: 20,
                fee_due: 0,
                status: SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled),
            },
        }
    }

    fn states() -> Vec<SccpOutboundStateV1> {
        vec![
            SccpOutboundStateV1::Recorded(SccpRecordedStateV1 { deadline_ms: 99 }),
            SccpOutboundStateV1::Voided(SccpVoidStatusV1 {
                kind: SccpVoidKindV1::Frozen,
                proven_at_height: 30,
                refund_pending: true,
            }),
            SccpOutboundStateV1::Refunded(SccpStatusHeightV1 { height: 31 }),
            SccpOutboundStateV1::Stranded(SccpStatusHeightV1 { height: 32 }),
        ]
    }

    fn checkpoint(height: u64) -> SccpLcCheckpointEntryV1 {
        SccpLcCheckpointEntryV1 {
            checkpoint: SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    source_height: height,
                    block_hash: [6; 32],
                    state_root: Some([7; 32]),
                    receipts_or_tx_root: [8; 32],
                    source_time_ms: 9,
                },
                recorded_at_taira_ms: 10,
                origin: SccpLcCheckpointOriginV1::Advance,
            },
            permanent: true,
        }
    }

    fn head() -> SccpLcPointV1 {
        SccpLcPointV1 {
            source_height: 500,
            block_hash: [9; 32],
            source_time_ms: 11,
        }
    }

    fn detail() -> SccpLightClientDetailV1 {
        SccpLightClientDetailV1 {
            light_client: SccpLightClientV1 {
                params: SccpLightClientParamsV1::defaults_for(SccpNetworkV1::EthereumMainnet)
                    .expect("external"),
                head: SccpLcHeadV1 {
                    latest_set_id: 4,
                    latest_finalized: head(),
                    last_progress_taira_ms: 12,
                },
                frozen: None,
                state_hash: [13; 32],
            },
            usable: true,
            weak_subjectivity_deadline_ms: Some(14),
            supported_until_ms: None,
            sets: SccpLcSetsSummaryV1 {
                count: 2,
                oldest_set_id: Some(3),
                latest_set_id: Some(4),
            },
            checkpoints: SccpLcCheckpointsSummaryV1::default(),
        }
    }

    #[test]
    fn limits_equal_the_page_constants() {
        let limits = SccpReadLimitsV1::v1();
        assert_eq!(
            u32::try_from(MAX_RECENT_MESSAGES),
            Ok(limits.recent_messages)
        );
        assert_eq!(u32::try_from(MAX_OUTBOUND_PAGE), Ok(limits.outbound_page));
        assert_eq!(u32::try_from(MAX_CONTROLS_PAGE), Ok(limits.controls_page));
        assert_eq!(
            usize::try_from(limits.rotations_page),
            Ok(crate::v1::destination::MAX_CERTIFICATES_PER_CALL)
        );
        let json = norito::json::to_value(&limits).expect("JSON");
        assert!(json.get("rotation_steps").is_none());
        assert_eq!(json.as_object().expect("object").len(), 4);
    }

    #[test]
    fn status_predicates_follow_finality() {
        let finals: Vec<bool> = states().iter().map(SccpOutboundStateV1::is_final).collect();
        assert_eq!(finals, vec![false, false, true, true]);
        assert!(!SccpMessageStatusV1::Unknown.is_final());
        assert!(!SccpMessageStatusV1::Inbound(inbound()).is_final());
        let mut released = inbound();
        released.record.status = SccpInboundStatusV1::Released(SccpStatusHeightV1 { height: 21 });
        let released = SccpMessageStatusV1::Inbound(released);
        assert!(released.is_final());
        assert!(released.inbound().is_some() && released.outbound().is_none());
        let outbound = SccpMessageStatusV1::Outbound(outbound(states()[2]));
        assert!(outbound.is_final() && outbound.outbound().is_some());
    }

    #[test]
    fn outbound_state_has_four_contiguous_indices_and_no_attested_state() {
        for (state, index) in states().iter().zip([0_u32, 1, 2, 3]) {
            assert!(state.encode().starts_with(&index.encode()), "{state:?}");
        }
        for index in [4_u32, 5, u32::MAX] {
            let mut encoded = index.encode();
            encoded.extend_from_slice(&[0x11; 64]);
            assert!(
                SccpOutboundStateV1::decode_all(&mut encoded.as_slice()).is_err(),
                "state index {index}"
            );
        }
        let recorded = norito::json::to_json(&states()[0]).expect("JSON");
        assert!(recorded.contains(r#""state":"recorded""#), "{recorded}");
        let attested = recorded.replace(r#""state":"recorded""#, r#""state":"attested""#);
        assert!(norito::json::from_json::<SccpOutboundStateV1>(&attested).is_err());
    }

    #[test]
    fn views_roundtrip_in_every_codec() {
        let recorded = SccpRecordedStateV1 { deadline_ms: 99 };
        roundtrip(&recorded);
        assert_closed(&recorded, "deadline_ms");
        for state in states() {
            roundtrip(&state);
            roundtrip(&SccpMessageStatusV1::Outbound(outbound(state)));
        }
        roundtrip(&SccpMessageStatusV1::Inbound(inbound()));
        roundtrip(&SccpMessageStatusV1::Unknown);
        roundtrip(&SccpOutboundPageV1 {
            network: SccpNetworkV1::TonMainnet,
            revision: 2,
            next_outbound_nonce: 6,
            records: vec![outbound(states()[0])],
            next_from_nonce: Some(6),
        });
        roundtrip(&SccpRecentMessagesV1 {
            messages: vec![
                SccpMessageStatusV1::Outbound(outbound(states()[1])),
                SccpMessageStatusV1::Inbound(inbound()),
            ],
            next_before: Some("12:1".to_owned()),
        });
        roundtrip(&SccpControlPageV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            next_control_nonce: 3,
            controls: vec![SccpControlViewV1 {
                control_nonce: 2,
                record: SccpControlRecordV1 {
                    track: 1,
                    parliament_paused: true,
                    fast_pause_until_ms: 0,
                    height: 12,
                    commitment_index: 0,
                    leaf: [1; 32],
                    certificate_id: [2; 32],
                    effect_hash: [5; 32],
                },
            }],
            next_after_nonce: None,
        });
        roundtrip(&detail());
        roundtrip(&SccpLcCheckpointCoverV1 {
            network: SccpNetworkV1::EthereumMainnet,
            covering: 100,
            head: head(),
            nearest: checkpoint(120),
            nearest_permanent: Some(checkpoint(8_192)),
        });
        roundtrip(&SccpHistoryPathViewV1 {
            history_size: 3,
            history_root: [4; 32],
            proof: SccpBlockRefV1 {
                height: 10,
                sccp_root: [5; 32],
                message_count: 1,
                history_index: 0,
                history_path: vec![[6; 32]],
            },
        });
        for phase in [
            SccpGovernanceProposalPhaseV1::Proposed,
            SccpGovernanceProposalPhaseV1::Rejected,
            SccpGovernanceProposalPhaseV1::Enacted,
            SccpGovernanceProposalPhaseV1::Superseded,
            SccpGovernanceProposalPhaseV1::ExecutionFailed,
        ] {
            roundtrip(&phase);
        }
        roundtrip(&SccpChainProfileViewV1 {
            network: SccpNetworkV1::BscMainnet,
            supported_until_ms: Some(1),
        });
        roundtrip(&SccpReadLimitsV1::v1());
    }

    #[test]
    fn view_json_is_closed_tagged_and_complete() {
        assert_closed(&outbound(states()[0]), "state");
        assert_closed(&inbound(), "record");
        assert_closed(&detail(), "supported_until_ms");
        let unknown = norito::json::to_value(&SccpMessageStatusV1::Unknown).expect("JSON");
        assert_eq!(
            unknown.get("direction").and_then(Value::as_str),
            Some("unknown")
        );
        let voided = norito::json::to_value(&SccpMessageStatusV1::Outbound(outbound(states()[1])))
            .expect("JSON");
        assert_eq!(
            voided.get("direction").and_then(Value::as_str),
            Some("outbound")
        );
        let state = &voided["detail"]["state"];
        assert_eq!(state.get("state").and_then(Value::as_str), Some("voided"));
        assert_eq!(
            state["detail"]
                .get("proven_at_height")
                .and_then(Value::as_u64),
            Some(30)
        );
        // A control names no attestation state.
        let control = SccpControlViewV1 {
            control_nonce: 2,
            record: SccpControlRecordV1 {
                track: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0,
                height: 12,
                commitment_index: 0,
                leaf: [1; 32],
                certificate_id: [2; 32],
                effect_hash: [5; 32],
            },
        };
        assert_closed(&control, "record");
        let json = norito::json::to_value(&control).expect("JSON");
        assert!(json.get("attestation").is_none());
    }

    #[test]
    fn view_schema_names_are_stable() {
        assert_eq!(
            SccpMessageStatusV1::nominal_name(),
            "iroha_sccp::api::SccpMessageStatusV1"
        );
        assert_eq!(
            SccpOutboundPageV1::nominal_name(),
            "iroha_sccp::api::SccpOutboundPageV1"
        );
        assert_eq!(
            SccpLcCheckpointCoverV1::nominal_name(),
            "iroha_sccp::api::SccpLcCheckpointCoverV1"
        );
        assert_eq!(
            SccpGovernanceProposalDetailV1::nominal_name(),
            "iroha_sccp::api::SccpGovernanceProposalDetailV1"
        );
    }
}
