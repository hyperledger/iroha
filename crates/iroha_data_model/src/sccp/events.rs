//! SCCP v1 data events (`specs/sccp.md` §4.17).
//!
//! [`SccpEvent`] is the Taira data-event family of SCCP. Every variant carries an explicit
//! payload struct. Parliament proposal lifecycle outcomes are reported by the existing
//! Parliament governance events; SCCP adds only [`SccpEvent::GovernanceEnacted`] with the
//! subjects it changed.
//!
//! The first-release event family has one contiguous native layout.

use super::{
    generation::SccpGenerationCauseV1,
    governance::SccpGovernanceSubjectV1,
    inbound::SccpSourceLocatorV1,
    light_client::{SccpLcFreezeReasonV1, SccpLcPointV1},
    native::{SccpForgeryOffenderV1, SccpForgeryRuleV1},
    outbound::SccpVoidKindV1,
    registry::SccpRouteActivationV1,
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, bridge::SccpNetworkV1,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Declare one closed SCCP event payload struct with the shared codec derives.
macro_rules! sccp_event_payload {
    ($(#[$meta:meta])* pub struct $name:ident { $($body:tt)* }) => {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Decode,
            Encode,
            IntoSchema,
            DeriveJsonSerialize,
            DeriveJsonDeserialize,
        )]
        #[norito(no_fast_from_json)]
        #[norito(decode_from_slice)]
        #[norito(deny_unknown_fields)]
        #[derive(norito::NoritoSchema)]
        $(#[$meta])*
        pub struct $name { $($body)* }
    };
}

/// A canonical panel draw could not seat a replacement.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "kind", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpPausePanelUnavailableReasonV1")]
pub enum SccpPausePanelUnavailableReasonV1 {
    /// Fewer than two complete panels are eligible.
    #[codec(index = 0)]
    #[norito(rename = "insufficient_candidates")]
    InsufficientCandidates,
    /// The canonical citizen snapshot exceeds its byte ceiling.
    #[codec(index = 1)]
    #[norito(rename = "snapshot_too_large")]
    SnapshotTooLarge,
}

/// A deterministic certification or enactment recheck failed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "kind", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseNoResultReasonV1")]
pub enum SccpFastPauseNoResultReasonV1 {
    /// The endorsement window has closed.
    #[codec(index = 0)]
    #[norito(rename = "expired")]
    Expired,
    /// The seated panel no longer matches the round.
    #[codec(index = 1)]
    #[norito(rename = "panel_changed")]
    PanelChanged,
    /// Too few eligible seat holders still endorse the round.
    #[codec(index = 2)]
    #[norito(rename = "insufficient_eligible_endorsements")]
    InsufficientEligibleEndorsements,
    /// The `FastHold` head differs from the endorsed head.
    #[codec(index = 3)]
    #[norito(rename = "head_changed")]
    HeadChanged,
    /// Parliament suspended the emergency pause pipeline.
    #[codec(index = 4)]
    #[norito(rename = "suspended")]
    Suspended,
    /// An active pause is outside its renewal window.
    #[codec(index = 5)]
    #[norito(rename = "renewal_window_closed")]
    RenewalWindowClosed,
    /// No route revision still accepts transfer activity.
    #[codec(index = 6)]
    #[norito(rename = "no_live_revision")]
    NoLiveRevision,
    /// The deterministic block control-leaf capacity is exhausted.
    #[codec(index = 7)]
    #[norito(rename = "control_capacity")]
    ControlCapacity,
    /// A protocol counter cannot advance.
    #[codec(index = 8)]
    #[norito(rename = "counter_exhausted")]
    CounterExhausted,
}

/// The approving ballot cannot lift a newer emergency pause.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "kind", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseRetainedReasonV1")]
pub enum SccpFastPauseRetainedReasonV1 {
    /// The ballot casting-open anchor does not follow pause enactment.
    #[codec(index = 0)]
    #[norito(rename = "ballot_opened_before_or_at_enactment")]
    BallotOpenedBeforeOrAtEnactment,
}

/// The authority under which an emergency pause part was removed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "kind", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseClearedReasonV1")]
pub enum SccpFastPauseClearedReasonV1 {
    /// A later Parliament ballot approved lifting this part.
    #[codec(index = 0)]
    #[norito(rename = "lifted")]
    Lifted,
}

/// One independently liftable part of an emergency pause.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "kind", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPausePartV1")]
pub enum SccpFastPausePartV1 {
    /// The Taira-side transfer hold.
    #[codec(index = 0)]
    #[norito(rename = "taira")]
    Taira,
    /// The destination hold for one route revision.
    #[codec(index = 1)]
    #[norito(rename = "destination")]
    Destination {
        /// Route revision whose destination hold is affected.
        revision: u32,
    },
}

sccp_event_payload! {
    /// A canonical citizen panel was seated.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpPausePanelSeatedV1")]
    #[derive(Copy)]
pub struct SccpPausePanelSeatedV1 {
        /// Monotone sequence of the seated panel.
        pub panel_seq: u64,
        /// Captured epoch-boundary beacon pulse.
        pub pulse_id: [u8; 32],
        /// Primary panel identifier.
        pub primary_id: [u8; 32],
        /// Backup panel identifier.
        pub backup_id: [u8; 32],
        /// Seating block height.
        pub seated_height: u64,
        /// Seating block time.
        pub seated_at_ms: u64,
        /// End of the initial seat acceptance window.
        pub accept_until_ms: u64,
        /// Earliest time a new boundary may draw a replacement.
        pub term_ends_at_ms: u64,
        /// Number of drawn citizens including reserve.
        pub drawn_count: u32,
    }
}

sccp_event_payload! {
    /// A canonical draw retained the previous panel.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpPausePanelUnavailableV1")]
    #[derive(Copy)]
pub struct SccpPausePanelUnavailableV1 {
        /// Pulse at which the draw was attempted.
        pub pulse_id: [u8; 32],
        /// Closed draw refusal reason.
        pub reason: SccpPausePanelUnavailableReasonV1,
    }
}

sccp_event_payload! {
    /// A drawn citizen accepted the current panel position.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpPausePanelSeatAcceptedV1")]
    pub struct SccpPausePanelSeatAcceptedV1 {
        /// Sequence of the current panel.
        pub panel_seq: u64,
        /// Citizen who accepted.
        pub member: AccountId,
    }
}

sccp_event_payload! {
    /// A current seat holder publicly endorsed an emergency pause.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseEndorsedV1")]
    pub struct SccpFastPauseEndorsedV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Primary or backup panel identifier.
        pub panel_id: [u8; 32],
        /// Citizen whose endorsement was accepted.
        pub endorser: AccountId,
        /// Public incident digest.
        pub incident_digest: [u8; 32],
        /// Current eligible seat-holding endorsement count.
        pub count: u32,
    }
}

sccp_event_payload! {
    /// An emergency round failed a deterministic recheck.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseNoResultV1")]
    #[derive(Copy)]
pub struct SccpFastPauseNoResultV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Panel of the concluded round.
        pub panel_id: [u8; 32],
        /// Closed failed-recheck reason.
        pub reason: SccpFastPauseNoResultReasonV1,
    }
}

sccp_event_payload! {
    /// A certified emergency pause was enacted or renewed.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseEnactedV1")]
    #[derive(Copy)]
pub struct SccpFastPauseEnactedV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Identifier of the exact certified fields.
        pub certificate_id: super::fast_pause::SccpFastPauseCertificateId,
        /// Exclusive hold expiry.
        pub until_ms: u64,
        /// Whether this replaced an active pause.
        pub renewal: bool,
    }
}

sccp_event_payload! {
    /// A Parliament resume retained a newer emergency hold.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseRetainedV1")]
    #[derive(Copy)]
pub struct SccpFastPauseRetainedV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Part whose hold remains.
        pub part: SccpFastPausePartV1,
        /// Closed retention reason.
        pub reason: SccpFastPauseRetainedReasonV1,
    }
}

sccp_event_payload! {
    /// A later Parliament ballot lifted an emergency hold part.
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseClearedV1")]
    #[derive(Copy)]
pub struct SccpFastPauseClearedV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Part whose hold was cleared.
        pub part: SccpFastPausePartV1,
        /// Closed lift reason.
        pub reason: SccpFastPauseClearedReasonV1,
    }
}

sccp_event_payload! {
    /// A native generation starts under original committee and liability custody (§4.2 G2).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpCommitteeGenerationCreatedV1")]
    pub struct SccpCommitteeGenerationCreatedV1 {
        /// New generation.
        pub generation: u64,
        /// Genesis, key change or time-based renewal.
        pub cause: SccpGenerationCauseV1,
        /// Canonical committee key root.
        pub committee_root: [u8; 32],
        /// First governed height.
        pub start_height: u64,
        /// Immutable destination trust deadline.
        pub deadline_ms: u64,
    }
}
sccp_event_payload! {
    /// A committee key lacks a slashable registration at creation (§4.2 G6).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpGenerationMemberUnslashableV1")]
    pub struct SccpGenerationMemberUnslashableV1 {
        /// Generation retaining the unresolved member.
        pub generation: u64,
        /// Canonical key position.
        pub index: u8,
    }
}
sccp_event_payload! {
    /// Authenticated authority recovered after a missed boundary (§4.2 G7).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpCommitteeResyncV1")]
    pub struct SccpCommitteeResyncV1 {
        /// New independently pinned generation.
        pub generation: u64,
        /// Canonical current committee root.
        pub committee_root: [u8; 32],
        /// First recovered height.
        pub start_height: u64,
    }
}
sccp_event_payload! {
    /// Every active destination passed this generation's trust deadline (§4.8 L5).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpGenerationDestinationClearedV1")]
    pub struct SccpGenerationDestinationClearedV1 {
        /// Ended generation.
        pub generation: u64,
        /// Liability clock of first clearance.
        pub lc: u64,
    }
}
/// Closed allocation-free reasons for SCCP failing closed at one native height.
///
/// Node-local allocation, storage and resource refusals defer execution; they must never
/// be converted to these deterministic replicated input or bookkeeping reasons.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "reason", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpFinalityDegradedReasonV1")]
pub enum SccpFinalityDegradedReasonV1 {
    /// No authenticated native inputs exist for this execution.
    #[codec(index = 0)]
    #[norito(rename = "missing_inputs")]
    MissingInputs,
    /// The supplied authenticated inputs have invalid execution geometry.
    #[codec(index = 1)]
    #[norito(rename = "invalid_inputs")]
    InvalidInputs,
    /// The current generation is absent.
    #[codec(index = 2)]
    #[norito(rename = "missing_generation")]
    MissingGeneration,
    /// A retained generation violates its native structural relation.
    #[codec(index = 3)]
    #[norito(rename = "invalid_generation")]
    InvalidGeneration,
    /// The required authenticated native parent is absent.
    #[codec(index = 4)]
    #[norito(rename = "missing_parent")]
    MissingParent,
    /// The next deterministic generation or height cannot be represented.
    #[codec(index = 5)]
    #[norito(rename = "counter_exhausted")]
    CounterExhausted,
}

sccp_event_payload! {
    /// SCCP alone failed closed; native block execution remains valid (§4.6).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFinalityDegradedV1")]
    pub struct SccpFinalityDegradedV1 {
        /// Executing height.
        pub height: u64,
        /// Deterministic reason, independent of node-local configuration.
        pub reason: SccpFinalityDegradedReasonV1,
    }
}

sccp_event_payload! {
    /// `RecordSccpMessage` or a bounce recorded an outbound message (§4.4 step 14).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpMessageRecordedV1")]
    pub struct SccpMessageRecordedV1 {
        /// Message id (§3.3).
        pub message_id: [u8; 32],
        /// External target network.
        pub network: SccpNetworkV1,
        /// Route revision.
        pub revision: u32,
        /// Per-revision nonce.
        pub nonce: u64,
        /// Recording Taira height.
        pub height: u64,
        /// Leaf index within the block.
        pub commitment_index: u32,
        /// Destination-time mint deadline.
        pub deadline_ms: u64,
    }
}

sccp_event_payload! {
    /// The post-execution hook committed a block's SCCP leaves (§4.5).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpBlockCommittedV1")]
    pub struct SccpBlockCommittedV1 {
        /// Committing Taira height.
        pub height: u64,
        /// §3.4 block root.
        pub root: [u8; 32],
        /// Number of leaves.
        pub count: u32,
        /// History size after appending the block.
        pub history_size: u64,
    }
}

sccp_event_payload! {
    /// An inbound burn was proven (§4.12.1).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpInboundProvenV1")]
    pub struct SccpInboundProvenV1 {
        /// Message id (§3.3).
        pub message_id: [u8; 32],
        /// External source network.
        pub network: SccpNetworkV1,
        /// Route revision.
        pub revision: u32,
        /// Payload amount in Taira units.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
        /// Source-chain position of the burn.
        pub source_locator: SccpSourceLocatorV1,
        /// Self-claim fee due at release.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub fee_due: u128,
    }
}

sccp_event_payload! {
    /// Core registered an absent account to credit it (§4.12.3 step 5, §4.16).
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpRecipientRegisteredV1")]
    pub struct SccpRecipientRegisteredV1 {
        /// Registered account.
        pub account: AccountId,
        /// Route network of the credit.
        pub network: SccpNetworkV1,
        /// Inbound or outbound message being settled; `None` for a stranded release.
        #[norito(required)]
        pub message_id: Option<[u8; 32]>,
    }
}

sccp_event_payload! {
    /// An inbound message was released to its recipient (§4.12.3 step 7).
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpInboundReleasedV1")]
    pub struct SccpInboundReleasedV1 {
        /// Message id.
        pub message_id: [u8; 32],
        /// External source network.
        pub network: SccpNetworkV1,
        /// Route revision.
        pub revision: u32,
        /// Credited account.
        pub recipient: AccountId,
        /// Full payload amount (the recipient receives `amount − fee`).
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
        /// Fee sent to the Nexus fee sink.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub fee: u128,
    }
}

/// Why an inbound settlement bounced (§4.12.3): the recipient can never be credited.
///
/// Only permanent identity refusals bounce; a credit the release movement refuses now holds the
/// record `Pending` (`SccpPendingReasonV1::CreditRefused`) instead.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "reason", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpBounceReasonV1")]
pub enum SccpBounceReasonV1 {
    /// The recipient bytes do not decode as an `AccountAddress`.
    #[codec(index = 0)]
    #[norito(rename = "undecodable_recipient")]
    UndecodableRecipient,
    /// The recipient is an SCCP escrow account.
    #[codec(index = 1)]
    #[norito(rename = "escrow_recipient")]
    EscrowRecipient,
    /// The recipient's controller uses an algorithm or curve account admission refuses.
    #[codec(index = 2)]
    #[norito(rename = "inadmissible_controller")]
    InadmissibleController,
    /// The recipient is absent and `Register<Account>` refuses its identity (for example a
    /// retired rekey predecessor or a reserved protocol escrow identity).
    #[codec(index = 3)]
    #[norito(rename = "unregistrable_recipient")]
    UnregistrableRecipient,
}

sccp_event_payload! {
    /// An inbound message bounced back to its source-chain sender (§4.12.5).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpInboundBouncedV1")]
    pub struct SccpInboundBouncedV1 {
        /// Inbound message id.
        pub message_id: [u8; 32],
        /// External network.
        pub network: SccpNetworkV1,
        /// Inbound revision.
        pub revision: u32,
        /// Outbound message returning the value.
        pub bounce_message_id: [u8; 32],
        /// Revision the bounce was recorded on.
        pub bounce_revision: u32,
        /// Bounced amount.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
        /// Bounce cause.
        pub reason: SccpBounceReasonV1,
    }
}

sccp_event_payload! {
    /// Settlement or a bounce found `liability(r) < amount` (§4.12.3 step 1).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpInboundLiabilityShortfallV1")]
    pub struct SccpInboundLiabilityShortfallV1 {
        /// Inbound message id.
        pub message_id: [u8; 32],
        /// External network.
        pub network: SccpNetworkV1,
        /// Revision.
        pub revision: u32,
        /// Amount to settle.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
        /// Liability of the revision.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub liability: u128,
    }
}

sccp_event_payload! {
    /// A destination void of an outbound message was proven (§4.16).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpOutboundVoidedV1")]
    pub struct SccpOutboundVoidedV1 {
        /// Outbound message id.
        pub message_id: [u8; 32],
        /// External network.
        pub network: SccpNetworkV1,
        /// Revision.
        pub revision: u32,
        /// Voided nonce.
        pub nonce: u64,
        /// Void kind.
        pub kind: SccpVoidKindV1,
        /// Whether the refund still waits for `SettleSccpV1::Refund` after the void's own
        /// refund attempt; `false` when the same instruction refunded or stranded it.
        pub refund_pending: bool,
    }
}

sccp_event_payload! {
    /// A voided outbound message was refunded to its sender (§4.16).
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpOutboundRefundedV1")]
    pub struct SccpOutboundRefundedV1 {
        /// Outbound message id.
        pub message_id: [u8; 32],
        /// External network.
        pub network: SccpNetworkV1,
        /// Revision.
        pub revision: u32,
        /// Nonce.
        pub nonce: u64,
        /// Credited sender.
        pub recipient: AccountId,
        /// Refunded amount.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
    }
}

sccp_event_payload! {
    /// A voided outbound message moved to the route's `stranded` balance (§4.16).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpOutboundStrandedV1")]
    pub struct SccpOutboundStrandedV1 {
        /// Outbound message id.
        pub message_id: [u8; 32],
        /// External network.
        pub network: SccpNetworkV1,
        /// Revision.
        pub revision: u32,
        /// Nonce.
        pub nonce: u64,
        /// Stranded amount.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
    }
}

sccp_event_payload! {
    /// A Parliament-enacted `ReleaseStranded` paid out stranded value (§4.14.3).
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpStrandedReleasedV1")]
    pub struct SccpStrandedReleasedV1 {
        /// External network of the route.
        pub network: SccpNetworkV1,
        /// Credited account.
        pub recipient: AccountId,
        /// Released amount.
        #[norito(json = "crate::json_helpers::u128_string")]
        pub amount: u128,
        /// Public memo of the action.
        pub memo: String,
        /// Enacted proposal.
        pub proposal_id: [u8; 32],
    }
}

sccp_event_payload! {
    /// An advance moved a light client's head (§4.13.2).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpLightClientAdvancedV1")]
    pub struct SccpLightClientAdvancedV1 {
        /// Source chain.
        pub network: SccpNetworkV1,
        /// Newest stored set.
        pub latest_set_id: u64,
        /// Newest finalized point.
        pub latest_finalized: SccpLcPointV1,
        /// New state hash.
        pub state_hash: [u8; 32],
    }
}

sccp_event_payload! {
    /// A light client was frozen (§4.13.2).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpLightClientFrozenV1")]
    pub struct SccpLightClientFrozenV1 {
        /// Source chain.
        pub network: SccpNetworkV1,
        /// Freeze reason.
        pub reason: SccpLcFreezeReasonV1,
    }
}

sccp_event_payload! {
    /// A Parliament-enacted `InitializeLightClient` installed a light client (§4.13.2).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpLightClientInitializedV1")]
    pub struct SccpLightClientInitializedV1 {
        /// Source chain.
        pub network: SccpNetworkV1,
        /// Bootstrap set.
        pub latest_set_id: u64,
        /// Bootstrap checkpoint.
        pub latest_finalized: SccpLcPointV1,
        /// Initial state hash.
        pub state_hash: [u8; 32],
        /// Enacted proposal.
        pub proposal_id: [u8; 32],
    }
}

sccp_event_payload! {
    /// A Parliament-enacted `InstallTrustedCheckpoint` wrote a checkpoint (§4.13.2).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpTrustedCheckpointInstalledV1")]
    pub struct SccpTrustedCheckpointInstalledV1 {
        /// Source chain.
        pub network: SccpNetworkV1,
        /// Checkpoint source height.
        pub source_height: u64,
        /// Checkpoint block hash.
        pub block_hash: [u8; 32],
        /// Enacted proposal.
        pub proposal_id: [u8; 32],
    }
}

sccp_event_payload! {
    /// A revision changed activation state (§4.14.2).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpRevisionActivationChangedV1")]
    pub struct SccpRevisionActivationChangedV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Revision.
        pub revision: u32,
        /// Previous state; `None` when `RegisterRoute` created the revision.
        #[norito(required)]
        pub from: Option<SccpRouteActivationV1>,
        /// New state; `None` when `RemoveStaged` removed the revision.
        #[norito(required)]
        pub to: Option<SccpRouteActivationV1>,
    }
}

sccp_event_payload! {
    /// A destination control message was recorded (§4.14.6).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpControlRecordedV1")]
    pub struct SccpControlRecordedV1 {
        /// External network.
        pub network: SccpNetworkV1,
        /// Revision.
        pub revision: u32,
        /// Control nonce.
        pub control_nonce: u64,
        /// Enacting track: 1 for Parliament, 2 for the fast-pause panel.
        pub track: u8,
        /// Parliament flag after the effect.
        pub parliament_paused: bool,
        /// Active destination fast-pause expiry, or zero.
        pub fast_pause_until_ms: u64,
        /// Content identifier of the actual enacting certificate.
        pub certificate_id: [u8; 32],
        /// Recording Taira height.
        pub height: u64,
        /// Leaf index within the block.
        pub commitment_index: u32,
    }
}

sccp_event_payload! {
    /// An SCCP Parliament proposal was enacted (§4.14.3).
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpGovernanceEnactedV1")]
    pub struct SccpGovernanceEnactedV1 {
        /// Enacted proposal id.
        pub proposal_id: [u8; 32],
        /// `S(P)`: the subjects whose revision counters were incremented.
        pub subjects: Vec<SccpGovernanceSubjectV1>,
    }
}

sccp_event_payload! {
    /// The first Global block-start pass at or after a fast pause's expiry (§4.14.7 G4).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpFastPauseLapsedV1")]
    pub struct SccpFastPauseLapsedV1 {
        /// External network whose original record was removed.
        pub network: SccpNetworkV1,
        /// Exact certificate retained by that expired record.
        pub certificate_id: [u8; 32],
        /// Original absolute expiry; no new deadline is derived during cleanup.
        pub until_ms: u64,
    }
}

sccp_event_payload! {
    /// A native SCCP forgery was admitted and permanently recorded (§4.9).
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpForgeryEvidenceRecordedV1")]
    pub struct SccpForgeryEvidenceRecordedV1 {
        /// Exact immutable evidence identifier.
        pub evidence_id: [u8; 32],
        /// Retained native committee generation.
        pub generation: u64,
        /// Height claimed by the signed X, not the penalty-liability height.
        pub height: u64,
        /// First E1–E4 mismatch established at admission.
        pub rule: SccpForgeryRuleV1,
        /// Newly deduplicated slashable signers with original registration identity.
        pub offenders: Vec<SccpForgeryOffenderV1>,
    }
}

sccp_event_payload! {
    /// An authenticated forgery signer has no retained staking member (§4.9 step 6).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpForgeryOffenderUnslashableV1")]
    pub struct SccpForgeryOffenderUnslashableV1 {
        /// Retained native committee generation.
        pub generation: u64,
        /// Original signer index whose generation member is absent.
        pub signer: u32,
    }
}

sccp_event_payload! {
    /// New forgery evidence caused this revision to become held (§4.10).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpRevisionForgeryHeldV1")]
    pub struct SccpRevisionForgeryHeldV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Route revision.
        pub revision: u32,
        /// Revision's unchanged forgery floor.
        pub forgery_floor: u64,
        /// New maximum admitted forgery generation causing the hold.
        pub generation: u64,
    }
}

sccp_event_payload! {
    /// Parliament progress moved this revision above the forgery hold (§4.10).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpRevisionForgeryReleasedV1")]
    pub struct SccpRevisionForgeryReleasedV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Route revision.
        pub revision: u32,
        /// Newly enacted monotone forgery floor; other holds remain independent.
        pub forgery_floor: u64,
    }
}

sccp_event_payload! {
    /// Parliament permanently quarantined this revision (§4.10).
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpRevisionQuarantinedV1")]
    pub struct SccpRevisionQuarantinedV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Route revision.
        pub revision: u32,
        /// Exact Parliament certificate that enacted quarantine.
        pub certificate_id: [u8; 32],
        /// Canonical enactment height.
        pub since_height: u64,
    }
}

sccp_event_payload! {
    /// The sole reconciliation window was opened by Parliament.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpReconciliationOpenedV1")]
    pub struct SccpReconciliationOpenedV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Quarantined revision.
        pub revision: u32,
        /// Enacting ledger time.
        pub opened_at_ms: u64,
        /// Proof deadline and window-end due time.
        pub closes_at_ms: u64,
    }
}
sccp_event_payload! {
    /// A distinct finalized forged mint was counted in an open window.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpForgedMintProvenV1")]
    pub struct SccpForgedMintProvenV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Quarantined revision.
        pub revision: u32,
        /// Payload-bound finalized message id.
        pub message_id: [u8; 32],
        /// Authenticated minted face amount.
        pub amount: u128,
    }
}
sccp_event_payload! {
    /// A window ended and fixed the immutable pro-rata rate.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpReconciliationSettledV1")]
    pub struct SccpReconciliationSettledV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Quarantined revision.
        pub revision: u32,
        /// Liability net of pending refunds.
        pub backing: u128,
        /// Distinct forged face amount counted in the window.
        pub forged_supply: u128,
    }
}
sccp_event_payload! {
    /// A reconciled claim left Pending and consumed its face amount.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpReconciledClaimSettledV1")]
    pub struct SccpReconciledClaimSettledV1 {
        /// External route network.
        pub network: SccpNetworkV1,
        /// Quarantined revision.
        pub revision: u32,
        /// Inbound claim message id.
        pub message_id: [u8; 32],
        /// Claim face amount.
        pub amount: u128,
        /// Actual payout; the remainder is void.
        pub payout: u128,
    }
}

sccp_event_payload! {
    /// An inbound bounce had only a quarantined fallback and moved its payout to stranded.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::events::SccpInboundStrandedV1")]
    pub struct SccpInboundStrandedV1 {
        /// Inbound claim id.
        pub message_id: [u8; 32],
        /// External network.
        pub network: SccpNetworkV1,
        /// Source revision.
        pub revision: u32,
        /// Actual stranded amount after any reconciliation haircut.
        pub amount: u128,
        /// Permanent recipient refusal that selected the bounce path.
        pub reason: SccpBounceReasonV1,
    }
}

/// SCCP data events (§4.17).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    iroha_data_model_derive::EventSet,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "event", content = "payload")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::events::SccpEvent")]
#[event_set(schema_name = "iroha_data_model::sccp::events::SccpEventSet")]
pub enum SccpEvent {
    /// Outbound message recorded.
    #[codec(index = 0)]
    #[norito(rename = "message_recorded")]
    MessageRecorded(SccpMessageRecordedV1),
    /// Block leaves committed.
    #[codec(index = 1)]
    #[norito(rename = "block_committed")]
    BlockCommitted(SccpBlockCommittedV1),
    /// Inbound burn proven.
    #[codec(index = 2)]
    #[norito(rename = "inbound_proven")]
    InboundProven(SccpInboundProvenV1),
    /// Absent account registered for a credit.
    #[codec(index = 3)]
    #[norito(rename = "recipient_registered")]
    RecipientRegistered(SccpRecipientRegisteredV1),
    /// Inbound message released.
    #[codec(index = 4)]
    #[norito(rename = "inbound_released")]
    InboundReleased(SccpInboundReleasedV1),
    /// Inbound message bounced.
    #[codec(index = 5)]
    #[norito(rename = "inbound_bounced")]
    InboundBounced(SccpInboundBouncedV1),
    /// Inbound settlement hit a liability shortfall.
    #[codec(index = 6)]
    #[norito(rename = "inbound_liability_shortfall")]
    InboundLiabilityShortfall(SccpInboundLiabilityShortfallV1),
    /// Outbound void proven.
    #[codec(index = 7)]
    #[norito(rename = "outbound_voided")]
    OutboundVoided(SccpOutboundVoidedV1),
    /// Outbound refund paid.
    #[codec(index = 8)]
    #[norito(rename = "outbound_refunded")]
    OutboundRefunded(SccpOutboundRefundedV1),
    /// Outbound value stranded.
    #[codec(index = 9)]
    #[norito(rename = "outbound_stranded")]
    OutboundStranded(SccpOutboundStrandedV1),
    /// Stranded value released by the Parliament.
    #[codec(index = 10)]
    #[norito(rename = "stranded_released")]
    StrandedReleased(SccpStrandedReleasedV1),
    /// Light-client head advanced.
    #[codec(index = 11)]
    #[norito(rename = "light_client_advanced")]
    LightClientAdvanced(SccpLightClientAdvancedV1),
    /// Light client frozen.
    #[codec(index = 12)]
    #[norito(rename = "light_client_frozen")]
    LightClientFrozen(SccpLightClientFrozenV1),
    /// Light client initialized.
    #[codec(index = 13)]
    #[norito(rename = "light_client_initialized")]
    LightClientInitialized(SccpLightClientInitializedV1),
    /// Trusted checkpoint installed.
    #[codec(index = 14)]
    #[norito(rename = "trusted_checkpoint_installed")]
    TrustedCheckpointInstalled(SccpTrustedCheckpointInstalledV1),
    /// Revision activation changed.
    #[codec(index = 15)]
    #[norito(rename = "revision_activation_changed")]
    RevisionActivationChanged(SccpRevisionActivationChangedV1),
    /// Destination control recorded.
    #[codec(index = 16)]
    #[norito(rename = "control_recorded")]
    ControlRecorded(SccpControlRecordedV1),
    /// SCCP governance proposal enacted.
    #[codec(index = 17)]
    #[norito(rename = "governance_enacted")]
    GovernanceEnacted(SccpGovernanceEnactedV1),
    /// Native generation created.
    #[codec(index = 18)]
    #[norito(rename = "committee_generation_created")]
    CommitteeGenerationCreated(SccpCommitteeGenerationCreatedV1),
    /// Unresolved original staking member.
    #[codec(index = 19)]
    #[norito(rename = "generation_member_unslashable")]
    GenerationMemberUnslashable(SccpGenerationMemberUnslashableV1),
    /// Recovery from a missed committee boundary.
    #[codec(index = 20)]
    #[norito(rename = "committee_resync")]
    CommitteeResync(SccpCommitteeResyncV1),
    /// Every active destination cleared a deadline.
    #[codec(index = 21)]
    #[norito(rename = "generation_destination_cleared")]
    GenerationDestinationCleared(SccpGenerationDestinationClearedV1),
    /// SCCP finality failed closed for one block.
    #[codec(index = 22)]
    #[norito(rename = "finality_degraded")]
    FinalityDegraded(SccpFinalityDegradedV1),
    /// Expired fast-pause record removed without changing Parliament state or heads.
    #[codec(index = 23)]
    #[norito(rename = "fast_pause_lapsed")]
    FastPauseLapsed(SccpFastPauseLapsedV1),
    /// A native SCCP forgery was admitted and permanently recorded (§4.9).
    #[codec(index = 24)]
    #[norito(rename = "forgery_evidence_recorded")]
    ForgeryEvidenceRecorded(SccpForgeryEvidenceRecordedV1),
    /// An authenticated forgery signer has no retained staking member (§4.9 step 6).
    #[codec(index = 25)]
    #[norito(rename = "forgery_offender_unslashable")]
    ForgeryOffenderUnslashable(SccpForgeryOffenderUnslashableV1),
    /// New forgery evidence caused this revision to become held (§4.10).
    #[codec(index = 26)]
    #[norito(rename = "revision_forgery_held")]
    RevisionForgeryHeld(SccpRevisionForgeryHeldV1),
    /// Parliament progress moved this revision above the forgery hold (§4.10).
    #[codec(index = 27)]
    #[norito(rename = "revision_forgery_released")]
    RevisionForgeryReleased(SccpRevisionForgeryReleasedV1),
    /// Parliament permanently quarantined this revision (§4.10).
    #[codec(index = 28)]
    #[norito(rename = "revision_quarantined")]
    RevisionQuarantined(SccpRevisionQuarantinedV1),
    /// The sole reconciliation window was opened by Parliament.
    #[codec(index = 29)]
    #[norito(rename = "reconciliation_opened")]
    ReconciliationOpened(SccpReconciliationOpenedV1),
    /// A distinct finalized forged mint was counted in an open window.
    #[codec(index = 30)]
    #[norito(rename = "forged_mint_proven")]
    ForgedMintProven(SccpForgedMintProvenV1),
    /// A window ended and fixed the immutable pro-rata rate.
    #[codec(index = 31)]
    #[norito(rename = "reconciliation_settled")]
    ReconciliationSettled(SccpReconciliationSettledV1),
    /// A reconciled claim left Pending and consumed its face amount.
    #[codec(index = 32)]
    #[norito(rename = "reconciled_claim_settled")]
    ReconciledClaimSettled(SccpReconciledClaimSettledV1),
    /// Inbound payout moved to stranded because the fallback revision is quarantined.
    #[codec(index = 33)]
    #[norito(rename = "inbound_stranded")]
    InboundStranded(SccpInboundStrandedV1),
    /// A canonical citizen panel was seated.
    #[codec(index = 34)]
    #[norito(rename = "pause_panel_seated")]
    PausePanelSeated(SccpPausePanelSeatedV1),
    /// A canonical draw retained the previous panel.
    #[codec(index = 35)]
    #[norito(rename = "pause_panel_unavailable")]
    PausePanelUnavailable(SccpPausePanelUnavailableV1),
    /// A drawn citizen accepted the current panel position.
    #[codec(index = 36)]
    #[norito(rename = "pause_panel_seat_accepted")]
    PausePanelSeatAccepted(SccpPausePanelSeatAcceptedV1),
    /// A current seat holder publicly endorsed an emergency pause.
    #[codec(index = 37)]
    #[norito(rename = "fast_pause_endorsed")]
    FastPauseEndorsed(SccpFastPauseEndorsedV1),
    /// An emergency round failed a deterministic recheck.
    #[codec(index = 38)]
    #[norito(rename = "fast_pause_no_result")]
    FastPauseNoResult(SccpFastPauseNoResultV1),
    /// A certified emergency pause was enacted or renewed.
    #[codec(index = 39)]
    #[norito(rename = "fast_pause_enacted")]
    FastPauseEnacted(SccpFastPauseEnactedV1),
    /// A Parliament resume retained a newer emergency hold.
    #[codec(index = 40)]
    #[norito(rename = "fast_pause_retained")]
    FastPauseRetained(SccpFastPauseRetainedV1),
    /// A later Parliament ballot lifted an emergency hold part.
    #[codec(index = 41)]
    #[norito(rename = "fast_pause_cleared")]
    FastPauseCleared(SccpFastPauseClearedV1),
}

#[cfg(test)]
mod tests;
