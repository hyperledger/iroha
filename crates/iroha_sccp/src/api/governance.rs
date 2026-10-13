//! Governance diagnostics from original committed state; these records grant no authority.

use iroha_data_model::{
    bridge::SccpNetworkV1,
    governance::types::{GovernanceAttemptV1, GovernanceExpectedHeadV1},
    sccp::registry::SccpRouteActivationV1,
};
use norito::codec::{Decode, Encode};

/// Frozen binding and terminal outcome of one Parliament attempt.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceAttemptViewV1")]
pub struct SccpGovernanceAttemptViewV1 {
    /// Canonical id, retry sequence, risk, stage and status.
    pub attempt: GovernanceAttemptV1,
    /// Compare-and-set head frozen when this attempt was created.
    pub expected_head: GovernanceExpectedHeadV1,
    /// Committed terminal outcome height, if one exists.
    #[norito(required)]
    pub terminal_height: Option<u64>,
    /// Original competing head observed at supersession.
    #[norito(required)]
    pub superseding_head: Option<GovernanceExpectedHeadV1>,
    /// Original deterministic execution-failure transcript root.
    #[norito(required)]
    pub execution_failure_root: Option<[u8; 32]>,
}

/// One requested activation change compared with current committed state.
/// Rows follow action order; they describe intent and do not predict execution success.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceActivationDiffV1")]
pub struct SccpGovernanceActivationDiffV1 {
    /// Zero-based proposal action index.
    pub action_index: u32,
    /// Affected external network.
    pub network: SccpNetworkV1,
    /// Affected revision; absent when a pause has no live target in the ordered preview.
    #[norito(required)]
    pub revision: Option<u32>,
    /// Current committed activation; absent for a missing revision.
    #[norito(required)]
    pub current: Option<SccpRouteActivationV1>,
    /// Requested activation; absent for removal.
    #[norito(required)]
    pub requested: Option<SccpRouteActivationV1>,
}

/// Configured Parliament body sizes; eligibility is reported separately, never inferred.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceBodySizesV1")]
pub struct SccpGovernanceBodySizesV1 {
    /// Rules Committee seats.
    pub rules_committee: u64,
    /// Agenda Council seats.
    pub agenda_council: u64,
    /// Interest Panel seats.
    pub interest_panel: u64,
    /// Review Panel seats.
    pub review_panel: u64,
    /// Coordination Council seats.
    pub coordination_council: u64,
    /// Policy Jury seats.
    pub policy_jury: u64,
    /// Confirmation Jury seats.
    pub confirmation_jury: u64,
    /// Oversight Committee seats.
    pub oversight_committee: u64,
    /// MPC Committee seats.
    pub mpc_committee: u64,
    /// FMA Committee seats.
    pub fma_committee: u64,
    /// Configured alternate seats.
    pub alternates: u64,
}

/// Active attempt and the availability of its Parliament-owned next due item.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceActiveAttemptV1")]
pub struct SccpGovernanceActiveAttemptV1 {
    /// Original attempt id, proposal, stage and status.
    pub attempt: GovernanceAttemptV1,
    /// Whether Parliament supplied its complete next-due observation.
    pub due_available: bool,
    /// Next due height, when supplied by Parliament.
    #[norito(required)]
    pub next_due_height: Option<u64>,
    /// Next due ledger time, when supplied by Parliament.
    #[norito(required)]
    pub next_due_timestamp_ms: Option<u64>,
}

/// `GET /v1/sccp/governance/readiness`: diagnostics, never a launch authorization.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpGovernanceReadinessV1")]
pub struct SccpGovernanceReadinessV1 {
    /// Height of the captured committed view.
    pub committed_height: u64,
    /// Parliament-qualified eligible citizens; unavailable is not zero.
    #[norito(required)]
    pub eligible_citizens: Option<u64>,
    /// Body sizes from this view's governance configuration.
    pub body_sizes: SccpGovernanceBodySizesV1,
    /// Original active global beacon session, if installed.
    #[norito(required)]
    pub active_beacon_session: Option<[u8; 32]>,
    /// The active session binds the exact ordered current consensus roster.
    pub beacon_matches_current_roster: bool,
    /// Qualified Parliament binding-ballot launch leg.
    pub parliament_binding_ballot_available: bool,
    /// Qualified shared-position reconciliation launch leg.
    pub reconciliation_available: bool,
    /// Qualified attempt latency; unavailable is not zero.
    #[norito(required)]
    pub attempt_latency_ms: Option<u64>,
    /// Every active or certified SCCP attempt, in canonical attempt-id order.
    pub active_attempts: Vec<SccpGovernanceActiveAttemptV1>,
}
