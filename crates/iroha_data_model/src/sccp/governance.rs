//! SCCP v1 Parliament governance payload (`specs/sccp.md` §4.14.3).
//!
//! The SORA Parliament is SCCP's only governance authority. A proposal is carried by the kept
//! `ProposeSccpRouteGovernance` → Parliament → due-certificate → enactment pipeline and applies
//! its [`SccpGovernanceActionV1`]s atomically, in order. Every action has exactly one
//! [`SccpGovernanceSubjectV1`]; the proposal's expected head is scoped to the sorted,
//! deduplicated subject list `S(P)` ([`SccpGovernanceProposalV1::subjects`]), and
//! `base_revisions` records the `rev(s)` the proposer saw for exactly those subjects.
//!
//! This module holds the payload and every state-independent check of the Propose step
//! ([`SccpGovernanceProposalV1::validate_static`] and
//! [`SccpGovernanceProposalV1::first_json_u64_violation`]). State-dependent rules (unused
//! destination words, current revisions, activation states) are checked by core at proposal,
//! attempt creation and enactment.

use super::{
    deployment::SccpDeploymentV1,
    light_client::{
        SCCP_LC_BOOTSTRAP_MAX_BYTES_V1, SCCP_LC_GENESIS_PROFILE_VERSION_V1, SccpLcBootstrapV1,
        SccpLcCheckpointDataV1, SccpLcInitExpectationV1, SccpLightClientParamsError,
        SccpLightClientParamsV1,
    },
    native::{SccpCommitteePinV1, SccpNativeDataError},
    params::{SccpParametersError, SccpParametersV1},
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId, account::AccountId,
    bridge::SccpNetworkV1,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Maximum actions in one SCCP governance proposal.
pub const SCCP_GOVERNANCE_MAX_ACTIONS_V1: usize = 16;
/// Maximum UTF-8 bytes of a `ReleaseStranded` memo.
pub const SCCP_GOVERNANCE_MEMO_MAX_BYTES_V1: usize = 256;
/// Largest `u64` a Parliament proposal may carry (`2^53 − 1`), exact in binary64 SDK runtimes.
pub const SCCP_JSON_SAFE_U64_MAX_V1: u64 = (1 << 53) - 1;
/// Exclusive upper bound on a TON route's `max_wrapped_supply` (`2^96`).
pub const SCCP_TON_MAX_WRAPPED_SUPPLY_EXCLUSIVE_V1: u128 = 1 << 96;

/// The state an SCCP governance action is scoped to; the key of `sccp_governance_revisions`.
///
/// Ordering is by variant in declaration order, then by the variant's value, which fixes the
/// canonical order of `S(P)` and of `base_revisions`.
///
/// Codec index 4 belonged to the bridge-key fault subject of the attestation transport and stays
/// unassigned.
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
#[norito(tag = "subject", content = "key")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpGovernanceSubjectV1")]
pub enum SccpGovernanceSubjectV1 {
    /// Route lifecycle of one external network: registry, revisions, activation, stranded value.
    #[codec(index = 0)]
    #[norito(rename = "route")]
    Route(SccpNetworkV1),
    /// Destination pause state (`destination_paused`, `next_control_nonce`) of one route.
    #[codec(index = 1)]
    #[norito(rename = "route_control")]
    RouteControl(SccpNetworkV1),
    /// Light client of one external network, including its active compiled profile version.
    #[codec(index = 2)]
    #[norito(rename = "light_client")]
    LightClient(SccpNetworkV1),
    /// SCCP consensus parameters.
    #[codec(index = 3)]
    #[norito(rename = "parameters")]
    Parameters,
}

/// `RegisterRoute`: stage a new revision bound to one destination deployment.
///
/// The pin is mandatory DATA. Core must authenticate it against retained generations, every
/// intervening deadline, resolved membership and the destination deployment (§4.14.3 P0–P5).
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpRegisterRouteActionV1")]
pub struct SccpRegisterRouteActionV1 {
    /// External network of the route.
    pub network: SccpNetworkV1,
    /// New revision; must be the route's latest revision plus one at enactment.
    pub revision: u32,
    /// Deployed destination contract.
    pub deployment: SccpDeploymentV1,
    /// Required native committee installed by the actual destination deployment.
    pub initial_committee: SccpCommitteePinV1,
    /// Supply cap in Taira units (equal to token units); equals the contract cap.
    #[norito(json = "crate::json_helpers::u128_string")]
    pub max_wrapped_supply: u128,
}

/// Action naming one revision of one route (`ActivateRevision`, `DeactivateOutbound`,
/// `RetireRevision`, `RemoveStaged`).
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpRouteRevisionActionV1")]
pub struct SccpRouteRevisionActionV1 {
    /// External network of the route.
    pub network: SccpNetworkV1,
    /// Revision acted on.
    pub revision: u32,
}

/// `SwitchRevision`: `from` becomes `InboundOnly` and `to` moves `Staged` → `Bidirectional`.
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpSwitchRevisionActionV1")]
pub struct SccpSwitchRevisionActionV1 {
    /// External network of the route.
    pub network: SccpNetworkV1,
    /// Current `Bidirectional` or `Paused` revision.
    pub from: u32,
    /// `Staged` successor.
    pub to: u32,
}

/// `ReleaseStranded`: credit stranded route value to a recipient.
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
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpReleaseStrandedActionV1")]
pub struct SccpReleaseStrandedActionV1 {
    /// External network of the route.
    pub network: SccpNetworkV1,
    /// Positive amount in Taira units, at most the route's `stranded` at enactment.
    #[norito(json = "crate::json_helpers::u128_string")]
    pub amount: u128,
    /// Recipient account, registered at enactment if absent.
    pub recipient: AccountId,
    /// Public memo, at most [`SCCP_GOVERNANCE_MEMO_MAX_BYTES_V1`] UTF-8 bytes.
    pub memo: String,
}

/// `SetTairaPaused`: ensure the route's live revision is `Paused` or `Bidirectional`.
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpSetTairaPausedActionV1")]
pub struct SccpSetTairaPausedActionV1 {
    /// External network of the route.
    pub network: SccpNetworkV1,
    /// `true` pauses a `Bidirectional` revision; `false` resumes a `Paused` one.
    pub paused: bool,
}

/// `SetDestinationPaused`: record a destination control message (§4.14.6).
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpSetDestinationPausedActionV1")]
pub struct SccpSetDestinationPausedActionV1 {
    /// External network of the route.
    pub network: SccpNetworkV1,
    /// Revision whose deployment receives the control.
    pub revision: u32,
    /// Minting pause state commanded to the destination.
    pub paused: bool,
}

/// `InitializeLightClient`: install params and a weak-subjectivity bootstrap.
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
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpInitializeLightClientActionV1")]
pub struct SccpInitializeLightClientActionV1 {
    /// External source chain.
    pub network: SccpNetworkV1,
    /// Light-client state required at enactment.
    pub expected: SccpLcInitExpectationV1,
    /// Parameters to store.
    pub params: SccpLightClientParamsV1,
    /// Bootstrap whose signing set must be fresh at the enactment block time.
    pub bootstrap: SccpLcBootstrapV1,
}

/// `InstallTrustedCheckpoint`: write a Parliament checkpoint exempt from the weak-subjectivity
/// bound.
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpInstallTrustedCheckpointActionV1")]
pub struct SccpInstallTrustedCheckpointActionV1 {
    /// External source chain.
    pub network: SccpNetworkV1,
    /// Checkpoint written with `origin: Parliament`.
    pub checkpoint: SccpLcCheckpointDataV1,
}

/// `FreezeLightClient`: set `frozen` without equivocation evidence.
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpFreezeLightClientActionV1")]
pub struct SccpFreezeLightClientActionV1 {
    /// External source chain.
    pub network: SccpNetworkV1,
}

/// `ActivateLightClientProfile`: make a compiled light-client profile version the network's
/// active version from the block after enactment (§4.13.2).
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
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::sccp::governance::SccpActivateLightClientProfileActionV1"
)]
pub struct SccpActivateLightClientProfileActionV1 {
    /// External source chain.
    pub network: SccpNetworkV1,
    /// Compiled profile version; at least 2 and above the network's newest recorded version.
    pub version: u32,
    /// Keccak-256 of the version's canonical profile bytes; the enacting release must compile
    /// the version with exactly this hash.
    pub profile_hash: [u8; 32],
}

/// `SetParameters`: replace the complete SCCP parameter value.
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpSetParametersActionV1")]
pub struct SccpSetParametersActionV1 {
    /// New parameters; must satisfy every rule of §4.1.
    pub next: SccpParametersV1,
}

/// One Parliament-enacted SCCP action (§4.14.3). Each has exactly one subject
/// ([`SccpGovernanceActionV1::subject`]).
///
/// Codec index 13 belonged to the bridge-key fault clearing of the attestation transport and
/// stays unassigned.
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
#[norito(tag = "action", content = "payload")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpGovernanceActionV1")]
pub enum SccpGovernanceActionV1 {
    /// New `Staged` revision (subject `Route`).
    #[codec(index = 0)]
    #[norito(rename = "register_route")]
    RegisterRoute(SccpRegisterRouteActionV1),
    /// `Staged` → `Bidirectional` (subject `Route`).
    #[codec(index = 1)]
    #[norito(rename = "activate_revision")]
    ActivateRevision(SccpRouteRevisionActionV1),
    /// `from` → `InboundOnly`, `to`: `Staged` → `Bidirectional` (subject `Route`).
    #[codec(index = 2)]
    #[norito(rename = "switch_revision")]
    SwitchRevision(SccpSwitchRevisionActionV1),
    /// `Bidirectional` | `Paused` → `InboundOnly` (subject `Route`).
    #[codec(index = 3)]
    #[norito(rename = "deactivate_outbound")]
    DeactivateOutbound(SccpRouteRevisionActionV1),
    /// `InboundOnly` → `Retired` (subject `Route`).
    #[codec(index = 4)]
    #[norito(rename = "retire_revision")]
    RetireRevision(SccpRouteRevisionActionV1),
    /// Remove a never-activated `Staged` revision (subject `Route`).
    #[codec(index = 5)]
    #[norito(rename = "remove_staged")]
    RemoveStaged(SccpRouteRevisionActionV1),
    /// Release stranded route value (subject `Route`).
    #[codec(index = 6)]
    #[norito(rename = "release_stranded")]
    ReleaseStranded(SccpReleaseStrandedActionV1),
    /// Ensure `Bidirectional` ⇄ `Paused` on Taira (subject `Route`).
    #[codec(index = 7)]
    #[norito(rename = "set_taira_paused")]
    SetTairaPaused(SccpSetTairaPausedActionV1),
    /// Record a destination control message (subject `RouteControl`).
    #[codec(index = 8)]
    #[norito(rename = "set_destination_paused")]
    SetDestinationPaused(SccpSetDestinationPausedActionV1),
    /// Install or re-install a light client (subject `LightClient`).
    #[codec(index = 9)]
    #[norito(rename = "initialize_light_client")]
    InitializeLightClient(SccpInitializeLightClientActionV1),
    /// Install a Parliament checkpoint (subject `LightClient`).
    #[codec(index = 10)]
    #[norito(rename = "install_trusted_checkpoint")]
    InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1),
    /// Freeze a light client (subject `LightClient`).
    #[codec(index = 11)]
    #[norito(rename = "freeze_light_client")]
    FreezeLightClient(SccpFreezeLightClientActionV1),
    /// Replace the SCCP parameters (subject `Parameters`).
    #[codec(index = 12)]
    #[norito(rename = "set_parameters")]
    SetParameters(SccpSetParametersActionV1),
    /// Activate a compiled light-client profile version (subject `LightClient`).
    #[codec(index = 14)]
    #[norito(rename = "activate_light_client_profile")]
    ActivateLightClientProfile(SccpActivateLightClientProfileActionV1),
}

/// One entry of `base_revisions`: a subject and the `rev(s)` the proposer saw.
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
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpGovernanceBaseRevisionV1")]
pub struct SccpGovernanceBaseRevisionV1 {
    /// Subject of the proposal.
    pub subject: SccpGovernanceSubjectV1,
    /// `sccp_governance_revisions[subject]` as seen by the proposer (0 when absent).
    pub revision: u64,
}

impl From<(SccpGovernanceSubjectV1, u64)> for SccpGovernanceBaseRevisionV1 {
    fn from((subject, revision): (SccpGovernanceSubjectV1, u64)) -> Self {
        Self { subject, revision }
    }
}

/// Complete SCCP Parliament proposal payload (`SccpGovernanceProposalV1`, §4.14.3).
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
#[norito_schema(name = "iroha_data_model::sccp::governance::SccpGovernanceProposalV1")]
pub struct SccpGovernanceProposalV1 {
    /// Live Taira `NetworkId` the proposal is bound to.
    pub network_id: NetworkId,
    /// Exactly `S(P)` in ascending order, each with the `rev(s)` the proposer saw.
    pub base_revisions: Vec<SccpGovernanceBaseRevisionV1>,
    /// 1..=16 actions, applied atomically in this order.
    pub actions: Vec<SccpGovernanceActionV1>,
}

/// A state-independent check of the Propose step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpGovernanceStaticError {
    /// `network_id` differs from the live `NetworkId`.
    #[error("proposal network_id does not equal the live NetworkId")]
    NetworkIdMismatch,
    /// The proposal carries no action.
    #[error("proposal carries no actions")]
    NoActions,
    /// The proposal carries more than [`SCCP_GOVERNANCE_MAX_ACTIONS_V1`] actions.
    #[error("proposal carries {count} actions; at most 16 are allowed")]
    TooManyActions {
        /// Number of actions.
        count: usize,
    },
    /// An action names `sora-taira` instead of an external network.
    #[error("action {action} names sora-taira; SCCP actions target external networks only")]
    TairaNetwork {
        /// Index of the offending action.
        action: usize,
    },
    /// An action names revision 0.
    #[error("action {action} names revision 0; revisions start at 1")]
    ZeroRevision {
        /// Index of the offending action.
        action: usize,
    },
    /// `SwitchRevision` switches a revision to itself.
    #[error("action {action} switches a revision to itself")]
    SwitchRevisionToSelf {
        /// Index of the offending action.
        action: usize,
    },
    /// `RegisterRoute` carries a zero `max_wrapped_supply`.
    #[error("action {action} registers a zero max_wrapped_supply")]
    ZeroMaxWrappedSupply {
        /// Index of the offending action.
        action: usize,
    },
    /// A TON `RegisterRoute` carries `max_wrapped_supply ≥ 2^96`.
    #[error("action {action} registers a TON max_wrapped_supply of 2^96 or more")]
    TonMaxWrappedSupplyTooLarge {
        /// Index of the offending action.
        action: usize,
    },
    /// `RegisterRoute` carries a deployment that does not fit its network.
    #[error("action {action} registers a deployment that does not fit its network")]
    DeploymentNetworkMismatch {
        /// Index of the offending action.
        action: usize,
    },
    /// `RegisterRoute` carries a malformed native committee pin.
    #[error("action {action} has an invalid native committee pin: {error}")]
    InvalidCommitteePin {
        /// Index of the offending action.
        action: usize,
        /// Violated state-independent pin rule.
        error: SccpNativeDataError,
    },
    /// Two `RegisterRoute` actions of the proposal share a destination word.
    #[error("action {action} repeats the destination word registered by action {first}")]
    DuplicateDestinationWord {
        /// Index of the offending action.
        action: usize,
        /// Index of the earlier action with the same word.
        first: usize,
    },
    /// `ReleaseStranded` releases zero.
    #[error("action {action} releases a zero amount")]
    ZeroAmount {
        /// Index of the offending action.
        action: usize,
    },
    /// `ReleaseStranded` memo exceeds [`SCCP_GOVERNANCE_MEMO_MAX_BYTES_V1`] bytes.
    #[error("action {action} memo has {len} bytes; at most 256 are allowed")]
    MemoTooLong {
        /// Index of the offending action.
        action: usize,
        /// Memo length in bytes.
        len: usize,
    },
    /// `InitializeLightClient` params name a different network than the action.
    #[error("action {action} light-client params name a different network")]
    LightClientParamsNetworkMismatch {
        /// Index of the offending action.
        action: usize,
    },
    /// `InitializeLightClient` params are invalid.
    #[error("action {action} light-client params are invalid: {error}")]
    InvalidLightClientParams {
        /// Index of the offending action.
        action: usize,
        /// Violated params rule.
        error: SccpLightClientParamsError,
    },
    /// `InitializeLightClient` bootstrap names a different network than the action.
    #[error("action {action} bootstrap names a different network")]
    BootstrapNetworkMismatch {
        /// Index of the offending action.
        action: usize,
    },
    /// `InitializeLightClient` bootstrap is empty.
    #[error("action {action} bootstrap is empty")]
    EmptyBootstrap {
        /// Index of the offending action.
        action: usize,
    },
    /// `InitializeLightClient` bootstrap exceeds [`SCCP_LC_BOOTSTRAP_MAX_BYTES_V1`].
    #[error("action {action} bootstrap has {len} bytes; at most 1 048 576 are allowed")]
    BootstrapTooLarge {
        /// Index of the offending action.
        action: usize,
        /// Bootstrap length in bytes.
        len: usize,
    },
    /// `ActivateLightClientProfile` names version 0 or 1; version 1 is active from genesis.
    #[error(
        "action {action} activates light-client profile version {version}; version 1 is active \
         from genesis, so activations start at version 2"
    )]
    GenesisLightClientProfileVersion {
        /// Index of the offending action.
        action: usize,
        /// Named version.
        version: u32,
    },
    /// `ActivateLightClientProfile` names a zero profile hash.
    #[error("action {action} activates a light-client profile with a zero profile hash")]
    ZeroLightClientProfileHash {
        /// Index of the offending action.
        action: usize,
    },
    /// `InstallTrustedCheckpoint` names TON, whose light client reads no checkpoints (old
    /// masterchain blocks are reached through `OldMcBlocksInfo`).
    #[error("action {action} installs a TON checkpoint; the TON light client reads none")]
    TonTrustedCheckpoint {
        /// Index of the offending action.
        action: usize,
    },
    /// `SetParameters` carries parameters that break a §4.1 rule.
    #[error("action {action} parameters are invalid: {error}")]
    InvalidParameters {
        /// Index of the offending action.
        action: usize,
        /// Violated parameter rule.
        error: SccpParametersError,
    },
    /// `base_revisions` does not list exactly `S(P)` in ascending order.
    #[error("base_revisions must list exactly the proposal's subjects in ascending order")]
    BaseRevisionsMismatch,
    /// A `u64` of the payload exceeds [`SCCP_JSON_SAFE_U64_MAX_V1`].
    #[error("{detail}")]
    ExceedsJsonSafeInteger {
        /// Which value exceeds the bound.
        detail: &'static str,
    },
}

impl SccpGovernanceActionV1 {
    /// Return the action's subject (the comment group of §4.14.3).
    #[must_use]
    pub fn subject(&self) -> SccpGovernanceSubjectV1 {
        match self {
            Self::RegisterRoute(SccpRegisterRouteActionV1 { network, .. })
            | Self::ActivateRevision(SccpRouteRevisionActionV1 { network, .. })
            | Self::SwitchRevision(SccpSwitchRevisionActionV1 { network, .. })
            | Self::DeactivateOutbound(SccpRouteRevisionActionV1 { network, .. })
            | Self::RetireRevision(SccpRouteRevisionActionV1 { network, .. })
            | Self::RemoveStaged(SccpRouteRevisionActionV1 { network, .. })
            | Self::ReleaseStranded(SccpReleaseStrandedActionV1 { network, .. })
            | Self::SetTairaPaused(SccpSetTairaPausedActionV1 { network, .. }) => {
                SccpGovernanceSubjectV1::Route(*network)
            }
            Self::SetDestinationPaused(action) => {
                SccpGovernanceSubjectV1::RouteControl(action.network)
            }
            Self::InitializeLightClient(SccpInitializeLightClientActionV1 { network, .. })
            | Self::InstallTrustedCheckpoint(SccpInstallTrustedCheckpointActionV1 {
                network,
                ..
            })
            | Self::FreezeLightClient(SccpFreezeLightClientActionV1 { network })
            | Self::ActivateLightClientProfile(SccpActivateLightClientProfileActionV1 {
                network,
                ..
            }) => SccpGovernanceSubjectV1::LightClient(*network),
            Self::SetParameters(_) => SccpGovernanceSubjectV1::Parameters,
        }
    }

    /// Return the network the action names, if any (`SetParameters` names none).
    #[must_use]
    pub fn network(&self) -> Option<SccpNetworkV1> {
        match self.subject() {
            SccpGovernanceSubjectV1::Route(network)
            | SccpGovernanceSubjectV1::RouteControl(network)
            | SccpGovernanceSubjectV1::LightClient(network) => Some(network),
            SccpGovernanceSubjectV1::Parameters => None,
        }
    }

    /// Return a message for the first `u64` of the action above [`SCCP_JSON_SAFE_U64_MAX_V1`].
    #[must_use]
    pub fn first_json_u64_violation(&self) -> Option<&'static str> {
        let maximum = SCCP_JSON_SAFE_U64_MAX_V1;
        match self {
            Self::InitializeLightClient(action) => action.params.first_json_u64_violation(maximum),
            Self::InstallTrustedCheckpoint(action) => {
                action.checkpoint.first_json_u64_violation(maximum)
            }
            Self::SetParameters(action) => action.next.first_json_u64_violation(maximum),
            Self::RegisterRoute(action) => {
                let pin = action.initial_committee;
                if pin.generation > maximum {
                    Some("initial_committee.generation exceeds the exact JSON u64 bound")
                } else if pin.start_height > maximum {
                    Some("initial_committee.start_height exceeds the exact JSON u64 bound")
                } else if pin.until_ms > maximum {
                    Some("initial_committee.until_ms exceeds the exact JSON u64 bound")
                } else {
                    None
                }
            }
            Self::ActivateRevision(_)
            | Self::SwitchRevision(_)
            | Self::DeactivateOutbound(_)
            | Self::RetireRevision(_)
            | Self::RemoveStaged(_)
            | Self::ReleaseStranded(_)
            | Self::SetTairaPaused(_)
            | Self::SetDestinationPaused(_)
            | Self::FreezeLightClient(_)
            | Self::ActivateLightClientProfile(_) => None,
        }
    }

    /// Check the action's state-independent rules; `index` is its position in the proposal.
    fn validate_static(&self, index: usize) -> Result<(), SccpGovernanceStaticError> {
        let action = index;
        if self.network().is_some_and(|network| !network.is_external()) {
            return Err(SccpGovernanceStaticError::TairaNetwork { action });
        }
        let nonzero = |revision: u32| {
            if revision == 0 {
                Err(SccpGovernanceStaticError::ZeroRevision { action })
            } else {
                Ok(())
            }
        };
        match self {
            Self::RegisterRoute(register) => {
                nonzero(register.revision)?;
                register
                    .initial_committee
                    .validate_shape()
                    .map_err(|error| SccpGovernanceStaticError::InvalidCommitteePin {
                        action,
                        error,
                    })?;
                if register.max_wrapped_supply == 0 {
                    return Err(SccpGovernanceStaticError::ZeroMaxWrappedSupply { action });
                }
                if register.network == SccpNetworkV1::TonMainnet
                    && register.max_wrapped_supply >= SCCP_TON_MAX_WRAPPED_SUPPLY_EXCLUSIVE_V1
                {
                    return Err(SccpGovernanceStaticError::TonMaxWrappedSupplyTooLarge { action });
                }
                if !register.deployment.fits_network(register.network) {
                    return Err(SccpGovernanceStaticError::DeploymentNetworkMismatch { action });
                }
                Ok(())
            }
            Self::ActivateRevision(target)
            | Self::DeactivateOutbound(target)
            | Self::RetireRevision(target)
            | Self::RemoveStaged(target) => nonzero(target.revision),
            Self::SwitchRevision(switch) => {
                nonzero(switch.from)?;
                nonzero(switch.to)?;
                if switch.from == switch.to {
                    return Err(SccpGovernanceStaticError::SwitchRevisionToSelf { action });
                }
                Ok(())
            }
            Self::ReleaseStranded(release) => {
                if release.amount == 0 {
                    return Err(SccpGovernanceStaticError::ZeroAmount { action });
                }
                if release.memo.len() > SCCP_GOVERNANCE_MEMO_MAX_BYTES_V1 {
                    return Err(SccpGovernanceStaticError::MemoTooLong {
                        action,
                        len: release.memo.len(),
                    });
                }
                Ok(())
            }
            Self::SetDestinationPaused(control) => nonzero(control.revision),
            Self::InitializeLightClient(initialize) => {
                if initialize.params.network != initialize.network {
                    return Err(
                        SccpGovernanceStaticError::LightClientParamsNetworkMismatch { action },
                    );
                }
                initialize.params.validate().map_err(|error| {
                    SccpGovernanceStaticError::InvalidLightClientParams { action, error }
                })?;
                if initialize.bootstrap.network != initialize.network {
                    return Err(SccpGovernanceStaticError::BootstrapNetworkMismatch { action });
                }
                let len = initialize.bootstrap.bytes.len();
                if len == 0 {
                    return Err(SccpGovernanceStaticError::EmptyBootstrap { action });
                }
                if len > SCCP_LC_BOOTSTRAP_MAX_BYTES_V1 {
                    return Err(SccpGovernanceStaticError::BootstrapTooLarge { action, len });
                }
                Ok(())
            }
            // The Propose step reads no state: the staking floor and the Parliament attempt
            // latency are checked at enactment (`SccpParametersV1::validate_against`).
            Self::SetParameters(set) => set
                .next
                .validate()
                .map_err(|error| SccpGovernanceStaticError::InvalidParameters { action, error }),
            Self::ActivateLightClientProfile(activate) => {
                if activate.version <= SCCP_LC_GENESIS_PROFILE_VERSION_V1 {
                    return Err(
                        SccpGovernanceStaticError::GenesisLightClientProfileVersion {
                            action,
                            version: activate.version,
                        },
                    );
                }
                if activate.profile_hash == [0; 32] {
                    return Err(SccpGovernanceStaticError::ZeroLightClientProfileHash { action });
                }
                Ok(())
            }
            Self::InstallTrustedCheckpoint(install) => {
                if install.network == SccpNetworkV1::TonMainnet {
                    return Err(SccpGovernanceStaticError::TonTrustedCheckpoint { action });
                }
                Ok(())
            }
            Self::SetTairaPaused(_) | Self::FreezeLightClient(_) => Ok(()),
        }
    }
}

impl SccpGovernanceProposalV1 {
    /// Return `S(P)`: the proposal's action subjects, sorted and deduplicated.
    #[must_use]
    pub fn subjects(&self) -> Vec<SccpGovernanceSubjectV1> {
        let mut subjects: Vec<_> = self
            .actions
            .iter()
            .map(SccpGovernanceActionV1::subject)
            .collect();
        subjects.sort();
        subjects.dedup();
        subjects
    }

    /// Run every state-independent check of the §4.14.3 Propose step.
    ///
    /// `network_id` equals `live`; there are 1..=16 actions; every action names an external
    /// network, nonzero revisions, a positive amount and cap (TON cap below `2^96`), a
    /// deployment that fits its network, a memo of at most 256 bytes, valid light-client params
    /// and a bounded bootstrap of the same network, no trusted checkpoint for TON, a light-client
    /// profile version of at least 2 with a nonzero profile hash, and valid parameters; no two
    /// `RegisterRoute` actions share a destination word; `base_revisions` lists exactly `S(P)`
    /// in ascending order; and every `u64` is at most `2^53 − 1`.
    ///
    /// # Errors
    ///
    /// Returns the first failed check.
    pub fn validate_static(&self, live: &NetworkId) -> Result<(), SccpGovernanceStaticError> {
        if self.network_id != *live {
            return Err(SccpGovernanceStaticError::NetworkIdMismatch);
        }
        match self.actions.len() {
            0 => return Err(SccpGovernanceStaticError::NoActions),
            count if count > SCCP_GOVERNANCE_MAX_ACTIONS_V1 => {
                return Err(SccpGovernanceStaticError::TooManyActions { count });
            }
            _ => {}
        }
        let mut words: Vec<([u8; 32], usize)> = Vec::new();
        for (index, action) in self.actions.iter().enumerate() {
            action.validate_static(index)?;
            if let SccpGovernanceActionV1::RegisterRoute(register) = action {
                let word = register.deployment.destination_word();
                if let Some((_, first)) = words.iter().find(|(seen, _)| *seen == word) {
                    return Err(SccpGovernanceStaticError::DuplicateDestinationWord {
                        action: index,
                        first: *first,
                    });
                }
                words.push((word, index));
            }
        }
        let subjects = self.subjects();
        if !self
            .base_revisions
            .iter()
            .map(|entry| &entry.subject)
            .eq(subjects.iter())
        {
            return Err(SccpGovernanceStaticError::BaseRevisionsMismatch);
        }
        if let Some(detail) = self.first_json_u64_violation() {
            return Err(SccpGovernanceStaticError::ExceedsJsonSafeInteger { detail });
        }
        Ok(())
    }

    /// Return a message for the first `u64` anywhere in the payload above `2^53 − 1`.
    ///
    /// Covers base revisions, parameters, light-client params and checkpoint fields. This is the
    /// SCCP arm of `first_release_exact_json_u64_invariant_error`.
    #[must_use]
    pub fn first_json_u64_violation(&self) -> Option<&'static str> {
        if self
            .base_revisions
            .iter()
            .any(|entry| entry.revision > SCCP_JSON_SAFE_U64_MAX_V1)
        {
            return Some("SCCP proposal base revision exceeds the exact JSON integer maximum");
        }
        self.actions
            .iter()
            .find_map(SccpGovernanceActionV1::first_json_u64_violation)
    }
}

#[cfg(test)]
mod tests;
