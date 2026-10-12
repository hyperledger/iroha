//! SCCP v1 data events (`specs/sccp.md` §4.17).
//!
//! [`SccpEvent`] is the Taira data-event family of SCCP. Every variant carries an explicit
//! payload struct. Parliament proposal lifecycle outcomes are reported by the existing
//! Parliament governance events; SCCP adds only [`SccpEvent::GovernanceEnacted`] with the
//! subjects it changed.
//!
//! Codec indices 2 to 9 belonged to the events of the attestation transport and stay
//! unassigned: no variant decodes from them, and new events take indices above the last one.

use super::{
    generation::SccpGenerationCauseV1,
    governance::SccpGovernanceSubjectV1,
    inbound::SccpSourceLocatorV1,
    light_client::{SccpLcFreezeReasonV1, SccpLcPointV1},
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
    #[codec(index = 10)]
    #[norito(rename = "inbound_proven")]
    InboundProven(SccpInboundProvenV1),
    /// Absent account registered for a credit.
    #[codec(index = 11)]
    #[norito(rename = "recipient_registered")]
    RecipientRegistered(SccpRecipientRegisteredV1),
    /// Inbound message released.
    #[codec(index = 12)]
    #[norito(rename = "inbound_released")]
    InboundReleased(SccpInboundReleasedV1),
    /// Inbound message bounced.
    #[codec(index = 13)]
    #[norito(rename = "inbound_bounced")]
    InboundBounced(SccpInboundBouncedV1),
    /// Inbound settlement hit a liability shortfall.
    #[codec(index = 14)]
    #[norito(rename = "inbound_liability_shortfall")]
    InboundLiabilityShortfall(SccpInboundLiabilityShortfallV1),
    /// Outbound void proven.
    #[codec(index = 15)]
    #[norito(rename = "outbound_voided")]
    OutboundVoided(SccpOutboundVoidedV1),
    /// Outbound refund paid.
    #[codec(index = 16)]
    #[norito(rename = "outbound_refunded")]
    OutboundRefunded(SccpOutboundRefundedV1),
    /// Outbound value stranded.
    #[codec(index = 17)]
    #[norito(rename = "outbound_stranded")]
    OutboundStranded(SccpOutboundStrandedV1),
    /// Stranded value released by the Parliament.
    #[codec(index = 18)]
    #[norito(rename = "stranded_released")]
    StrandedReleased(SccpStrandedReleasedV1),
    /// Light-client head advanced.
    #[codec(index = 19)]
    #[norito(rename = "light_client_advanced")]
    LightClientAdvanced(SccpLightClientAdvancedV1),
    /// Light client frozen.
    #[codec(index = 20)]
    #[norito(rename = "light_client_frozen")]
    LightClientFrozen(SccpLightClientFrozenV1),
    /// Light client initialized.
    #[codec(index = 21)]
    #[norito(rename = "light_client_initialized")]
    LightClientInitialized(SccpLightClientInitializedV1),
    /// Trusted checkpoint installed.
    #[codec(index = 22)]
    #[norito(rename = "trusted_checkpoint_installed")]
    TrustedCheckpointInstalled(SccpTrustedCheckpointInstalledV1),
    /// Revision activation changed.
    #[codec(index = 23)]
    #[norito(rename = "revision_activation_changed")]
    RevisionActivationChanged(SccpRevisionActivationChangedV1),
    /// Destination control recorded.
    #[codec(index = 24)]
    #[norito(rename = "control_recorded")]
    ControlRecorded(SccpControlRecordedV1),
    /// SCCP governance proposal enacted.
    #[codec(index = 25)]
    #[norito(rename = "governance_enacted")]
    GovernanceEnacted(SccpGovernanceEnactedV1),
    /// Native generation created.
    #[codec(index = 26)]
    #[norito(rename = "committee_generation_created")]
    CommitteeGenerationCreated(SccpCommitteeGenerationCreatedV1),
    /// Unresolved original staking member.
    #[codec(index = 27)]
    #[norito(rename = "generation_member_unslashable")]
    GenerationMemberUnslashable(SccpGenerationMemberUnslashableV1),
    /// Recovery from a missed committee boundary.
    #[codec(index = 28)]
    #[norito(rename = "committee_resync")]
    CommitteeResync(SccpCommitteeResyncV1),
    /// Every active destination cleared a deadline.
    #[codec(index = 29)]
    #[norito(rename = "generation_destination_cleared")]
    GenerationDestinationCleared(SccpGenerationDestinationClearedV1),
    /// SCCP finality failed closed for one block.
    #[codec(index = 30)]
    #[norito(rename = "finality_degraded")]
    FinalityDegraded(SccpFinalityDegradedV1),
    /// Expired fast-pause record removed without changing Parliament state or heads.
    #[codec(index = 31)]
    #[norito(rename = "fast_pause_lapsed")]
    FastPauseLapsed(SccpFastPauseLapsedV1),
}

#[cfg(test)]
mod tests;
