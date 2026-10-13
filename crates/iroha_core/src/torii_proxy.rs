//! Peer-to-peer proxy envelopes for Torii ingress routing.
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_crypto::HashOf;
use iroha_data_model::transaction::TransactionEntrypoint;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::codec::{Decode, Encode};
use std::fmt;
/// Schema version for deadline-bound Torii proxy requests.
pub const TORII_PROXY_REQUEST_VERSION_V1: u16 = 1;
/// Maximum inner body admitted by a first-release Torii proxy request.
pub const TORII_PROXY_REQUEST_MAX_INNER_BODY_BYTES_V1: usize = 64_000_000;
/// Source-coupled allowance for the signed proxy request envelope.
pub const TORII_PROXY_REQUEST_FRAME_OVERHEAD_BYTES_V1: usize = 8 * 1024 * 1024;
/// Maximum encoded `ToriiProxyRequestV1`/HTTP body before relay framing.
pub const TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1: usize =
    TORII_PROXY_REQUEST_MAX_INNER_BODY_BYTES_V1 + TORII_PROXY_REQUEST_FRAME_OVERHEAD_BYTES_V1;
/// Maximum enum/length framing around one proxy request or response inside `NetworkMessage`.
pub const TORII_PROXY_NETWORK_MESSAGE_OVERHEAD_BYTES_V1: usize = 64 * 1024;
/// Maximum P2P relay framing above the bounded `NetworkMessage` carrier.
pub const TORII_PROXY_REQUEST_RELAY_OVERHEAD_BYTES_V1: usize = 1024 * 1024;
/// Maximum complete encoded first-release Torii proxy frame admitted from P2P.
pub const TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1: usize =
    TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1 + TORII_PROXY_REQUEST_RELAY_OVERHEAD_BYTES_V1;
/// Maximum cumulative allocation while decoding one first-release proxy request.
///
/// The submitted transaction is reconstructed through nested owned proxy,
/// entrypoint, executable, and instruction containers. Keep that graph under
/// an explicit eightfold cap while the independent 64 MB body and 73 MB frame
/// limits continue to bound attacker-controlled source bytes.
pub const TORII_PROXY_REQUEST_MAX_DECODE_ALLOCATED_BYTES_V1: usize =
    TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1.saturating_mul(8);
/// Maximum encoded proxy-response body plus its bounded HTTP header envelope.
pub const TORII_PROXY_RESPONSE_MAX_ENCODED_BYTES_V1: usize =
    TORII_PROXY_REQUEST_MAX_INNER_BODY_BYTES_V1 + TORII_PROXY_REQUEST_FRAME_OVERHEAD_BYTES_V1;
/// Maximum complete first-release proxy-response frame admitted from P2P.
pub const TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1: usize =
    TORII_PROXY_RESPONSE_MAX_ENCODED_BYTES_V1 + TORII_PROXY_REQUEST_RELAY_OVERHEAD_BYTES_V1;
/// Maximum cumulative allocation while decoding one first-release proxy response.
pub const TORII_PROXY_RESPONSE_MAX_DECODE_ALLOCATED_BYTES_V1: usize =
    TORII_PROXY_RESPONSE_MAX_ENCODED_BYTES_V1;
/// Schema version for peer-to-peer Torii proxy responses.
pub const TORII_PROXY_RESPONSE_VERSION_V1: u16 = 1;
/// Maximum participant routes admitted in one Native AMX routing-plan hint.
pub const TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1: usize = 255;
/// Stable lane/dataspace assignment determined at ingress.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiRouteHintV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiRouteHintV1 {
    /// Nexus lane selected for the request.
    pub lane_id: LaneId,
    /// Dataspace selected for the request.
    pub dataspace_id: DataSpaceId,
}
impl From<crate::queue::RoutingDecision> for ToriiRouteHintV1 {
    fn from(value: crate::queue::RoutingDecision) -> Self {
        Self {
            lane_id: value.lane_id,
            dataspace_id: value.dataspace_id,
        }
    }
}
impl From<ToriiRouteHintV1> for crate::queue::RoutingDecision {
    fn from(value: ToriiRouteHintV1) -> Self {
        Self::new(value.lane_id, value.dataspace_id)
    }
}
/// Role of one route in a Torii transaction routing plan hint.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiRouteLegRoleV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ToriiRouteLegRoleV1 {
    /// Coordinator route for final admission and commit ordering.
    Coordinator,
    /// Dataspace-local participant route.
    Participant,
}
impl From<crate::queue::RouteLegRole> for ToriiRouteLegRoleV1 {
    fn from(value: crate::queue::RouteLegRole) -> Self {
        match value {
            crate::queue::RouteLegRole::Coordinator => Self::Coordinator,
            crate::queue::RouteLegRole::Participant => Self::Participant,
        }
    }
}
impl From<ToriiRouteLegRoleV1> for crate::queue::RouteLegRole {
    fn from(value: ToriiRouteLegRoleV1) -> Self {
        match value {
            ToriiRouteLegRoleV1::Coordinator => Self::Coordinator,
            ToriiRouteLegRoleV1::Participant => Self::Participant,
        }
    }
}
/// One lane/dataspace leg in a Torii transaction routing plan hint.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiRouteLegHintV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiRouteLegHintV1 {
    /// Lane/dataspace route selected for this leg.
    pub route: ToriiRouteHintV1,
    /// Role assigned to this leg.
    pub role: ToriiRouteLegRoleV1,
}
impl From<crate::queue::RouteLeg> for ToriiRouteLegHintV1 {
    fn from(value: crate::queue::RouteLeg) -> Self {
        Self {
            route: value.route.into(),
            role: value.role.into(),
        }
    }
}
impl From<ToriiRouteLegHintV1> for crate::queue::RouteLeg {
    fn from(value: ToriiRouteLegHintV1) -> Self {
        Self::new(value.route.into(), value.role.into())
    }
}
/// Kind of validation failure in a Torii routing-plan hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToriiRoutingPlanHintErrorKind {
    /// A coordinator leg was encoded with a non-coordinator role.
    UnexpectedCoordinatorRole,
    /// A participant leg was encoded with a non-participant role.
    UnexpectedParticipantRole,
    /// A Native AMX hint contains more participant routes than the protocol permits.
    NativeAmxParticipantLimitExceeded,
    /// A Native AMX hint repeats one participant route.
    NativeAmxDuplicateParticipantRoute,
    /// Native AMX participant routes are not in canonical dataspace/lane order.
    NativeAmxParticipantsOutOfOrder,
    /// A Native AMX hint advertised a digest that does not match its route legs.
    NativeAmxPlanDigestMismatch,
}
/// Error returned when a Torii routing-plan hint is not internally canonical.
/// Only the fields relevant to the selected refusal are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToriiRoutingPlanHintError(RoutingPlanHintRefusal);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoutingPlanHintRefusal {
    CoordinatorRole(ToriiRouteLegRoleV1),
    ParticipantRole {
        index: usize,
        actual: ToriiRouteLegRoleV1,
    },
    ParticipantLimit {
        count: usize,
        limit: usize,
    },
    DuplicateRoute {
        index: usize,
        route: ToriiRouteHintV1,
    },
    RouteOrder {
        index: usize,
        previous: ToriiRouteHintV1,
        actual: ToriiRouteHintV1,
    },
    DigestMismatch {
        advertised: Hash,
        computed: Hash,
    },
}
impl ToriiRoutingPlanHintError {
    /// Construct an error for a malformed coordinator leg role.
    #[must_use]
    pub const fn unexpected_coordinator_role(actual: ToriiRouteLegRoleV1) -> Self {
        Self(RoutingPlanHintRefusal::CoordinatorRole(actual))
    }
    /// Construct an error for a malformed participant leg role.
    #[must_use]
    pub const fn unexpected_participant_role(index: usize, actual: ToriiRouteLegRoleV1) -> Self {
        Self(RoutingPlanHintRefusal::ParticipantRole { index, actual })
    }
    /// Construct an error for a Native AMX participant vector above the protocol limit.
    #[must_use]
    pub const fn native_amx_participant_limit_exceeded(count: usize, limit: usize) -> Self {
        Self(RoutingPlanHintRefusal::ParticipantLimit { count, limit })
    }
    /// Construct an error for a repeated Native AMX participant route.
    #[must_use]
    pub const fn native_amx_duplicate_participant_route(
        index: usize,
        route: ToriiRouteHintV1,
    ) -> Self {
        Self(RoutingPlanHintRefusal::DuplicateRoute { index, route })
    }
    /// Construct an error for noncanonical Native AMX participant ordering.
    #[must_use]
    pub const fn native_amx_participants_out_of_order(
        index: usize,
        previous: ToriiRouteHintV1,
        actual: ToriiRouteHintV1,
    ) -> Self {
        Self(RoutingPlanHintRefusal::RouteOrder {
            index,
            previous,
            actual,
        })
    }
    /// Construct an error for a Native AMX digest that does not match the route legs.
    #[must_use]
    pub const fn native_amx_plan_digest_mismatch(advertised: Hash, computed: Hash) -> Self {
        Self(RoutingPlanHintRefusal::DigestMismatch {
            advertised,
            computed,
        })
    }
    /// Return the failure kind.
    #[must_use]
    pub const fn kind(&self) -> ToriiRoutingPlanHintErrorKind {
        match self.0 {
            RoutingPlanHintRefusal::CoordinatorRole(_) => {
                ToriiRoutingPlanHintErrorKind::UnexpectedCoordinatorRole
            }
            RoutingPlanHintRefusal::ParticipantRole { .. } => {
                ToriiRoutingPlanHintErrorKind::UnexpectedParticipantRole
            }
            RoutingPlanHintRefusal::ParticipantLimit { .. } => {
                ToriiRoutingPlanHintErrorKind::NativeAmxParticipantLimitExceeded
            }
            RoutingPlanHintRefusal::DuplicateRoute { .. } => {
                ToriiRoutingPlanHintErrorKind::NativeAmxDuplicateParticipantRoute
            }
            RoutingPlanHintRefusal::RouteOrder { .. } => {
                ToriiRoutingPlanHintErrorKind::NativeAmxParticipantsOutOfOrder
            }
            RoutingPlanHintRefusal::DigestMismatch { .. } => {
                ToriiRoutingPlanHintErrorKind::NativeAmxPlanDigestMismatch
            }
        }
    }
    /// Return the malformed leg role, when this error is role-related.
    #[must_use]
    pub const fn actual_role(&self) -> Option<ToriiRouteLegRoleV1> {
        match self.0 {
            RoutingPlanHintRefusal::CoordinatorRole(actual)
            | RoutingPlanHintRefusal::ParticipantRole { actual, .. } => Some(actual),
            _ => None,
        }
    }
    /// Return the malformed participant index, when this error identifies one route leg.
    #[must_use]
    pub const fn leg_index(&self) -> Option<usize> {
        match self.0 {
            RoutingPlanHintRefusal::ParticipantRole { index, .. }
            | RoutingPlanHintRefusal::DuplicateRoute { index, .. }
            | RoutingPlanHintRefusal::RouteOrder { index, .. } => Some(index),
            _ => None,
        }
    }
    /// Return the advertised participant count, when this error is count-related.
    #[must_use]
    pub const fn participant_count(&self) -> Option<usize> {
        match self.0 {
            RoutingPlanHintRefusal::ParticipantLimit { count, .. } => Some(count),
            _ => None,
        }
    }
    /// Return the maximum participant count, when this error is count-related.
    #[must_use]
    pub const fn participant_limit(&self) -> Option<usize> {
        match self.0 {
            RoutingPlanHintRefusal::ParticipantLimit { limit, .. } => Some(limit),
            _ => None,
        }
    }
    /// Return the preceding participant route, when this error is order-related.
    #[must_use]
    pub const fn previous_route(&self) -> Option<ToriiRouteHintV1> {
        match self.0 {
            RoutingPlanHintRefusal::DuplicateRoute { route, .. } => Some(route),
            RoutingPlanHintRefusal::RouteOrder { previous, .. } => Some(previous),
            _ => None,
        }
    }
    /// Return the malformed participant route, when this error is route-related.
    #[must_use]
    pub const fn actual_route(&self) -> Option<ToriiRouteHintV1> {
        match self.0 {
            RoutingPlanHintRefusal::DuplicateRoute { route, .. } => Some(route),
            RoutingPlanHintRefusal::RouteOrder { actual, .. } => Some(actual),
            _ => None,
        }
    }
    /// Return the advertised Native AMX plan digest, when this error is digest-related.
    #[must_use]
    pub const fn advertised_digest(&self) -> Option<Hash> {
        match self.0 {
            RoutingPlanHintRefusal::DigestMismatch { advertised, .. } => Some(advertised),
            _ => None,
        }
    }
    /// Return the recomputed Native AMX plan digest, when this error is digest-related.
    #[must_use]
    pub const fn computed_digest(&self) -> Option<Hash> {
        match self.0 {
            RoutingPlanHintRefusal::DigestMismatch { computed, .. } => Some(computed),
            _ => None,
        }
    }
}
impl fmt::Display for ToriiRoutingPlanHintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            RoutingPlanHintRefusal::CoordinatorRole(actual) => {
                write!(f, "unexpected coordinator role {actual:?}")
            }
            RoutingPlanHintRefusal::ParticipantRole { index, actual } => {
                write!(f, "unexpected participant role {actual:?} at index {index}")
            }
            RoutingPlanHintRefusal::ParticipantLimit { count, limit } => write!(
                f,
                "native AMX participant count {count} exceeds protocol limit {limit}"
            ),
            RoutingPlanHintRefusal::DuplicateRoute { index, route } => write!(
                f,
                "duplicate native AMX participant route at index {index}: dataspace {}, lane {}",
                route.dataspace_id.as_u64(),
                route.lane_id.as_u32()
            ),
            RoutingPlanHintRefusal::RouteOrder {
                index,
                previous,
                actual,
            } => write!(
                f,
                "native AMX participant routes are out of canonical (dataspace, lane) order at index {index}: previous ({}, {}), actual ({}, {})",
                previous.dataspace_id.as_u64(),
                previous.lane_id.as_u32(),
                actual.dataspace_id.as_u64(),
                actual.lane_id.as_u32()
            ),
            RoutingPlanHintRefusal::DigestMismatch {
                advertised,
                computed,
            } => write!(
                f,
                "native AMX plan digest mismatch: advertised {advertised}, computed {computed}"
            ),
        }
    }
}
impl std::error::Error for ToriiRoutingPlanHintError {}
/// Stable full routing plan determined at ingress.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiRoutingPlanHintV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ToriiRoutingPlanHintV1 {
    /// Single coordinator route.
    Single(ToriiRouteLegHintV1),
    /// Native AMX coordinator and participant route set.
    NativeAmx {
        /// Stable digest of the native AMX plan.
        plan_digest: Hash,
        /// Coordinator route for final ordering.
        coordinator: ToriiRouteLegHintV1,
        /// Dataspace-local participant routes.
        participants: Vec<ToriiRouteLegHintV1>,
    },
}
impl ToriiRoutingPlanHintV1 {
    /// Return the coordinator route for peer selection and diagnostics.
    #[must_use]
    pub fn coordinator_route(&self) -> ToriiRouteHintV1 {
        match self {
            Self::Single(leg) => leg.route,
            Self::NativeAmx { coordinator, .. } => coordinator.route,
        }
    }
    /// Convert this hint to a full routing plan after validating redundant wire fields.
    ///
    /// # Errors
    /// Returns an error when leg roles are not canonical, the participant vector exceeds the
    /// protocol limit or is not in strict canonical route order, or a Native AMX hint's advertised
    /// digest does not match the digest recomputed from its route legs.
    pub fn try_into_routing_plan(
        self,
    ) -> Result<crate::queue::RoutingPlan, ToriiRoutingPlanHintError> {
        match self {
            Self::Single(leg) => {
                if leg.role != ToriiRouteLegRoleV1::Coordinator {
                    return Err(ToriiRoutingPlanHintError::unexpected_coordinator_role(
                        leg.role,
                    ));
                }
                Ok(crate::queue::RoutingPlan::single(
                    crate::queue::RouteLeg::from(leg).route,
                ))
            }
            Self::NativeAmx {
                plan_digest,
                coordinator,
                participants,
            } => {
                if coordinator.role != ToriiRouteLegRoleV1::Coordinator {
                    return Err(ToriiRoutingPlanHintError::unexpected_coordinator_role(
                        coordinator.role,
                    ));
                }
                if participants.len() > TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1 {
                    return Err(
                        ToriiRoutingPlanHintError::native_amx_participant_limit_exceeded(
                            participants.len(),
                            TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1,
                        ),
                    );
                }
                let mut participant_legs = Vec::with_capacity(participants.len());
                let mut previous_route: Option<ToriiRouteHintV1> = None;
                for (index, leg) in participants.into_iter().enumerate() {
                    if leg.role != ToriiRouteLegRoleV1::Participant {
                        return Err(ToriiRoutingPlanHintError::unexpected_participant_role(
                            index, leg.role,
                        ));
                    }
                    if let Some(previous) = previous_route {
                        let previous_key = (previous.dataspace_id, previous.lane_id);
                        let actual_key = (leg.route.dataspace_id, leg.route.lane_id);
                        if actual_key == previous_key {
                            return Err(
                                ToriiRoutingPlanHintError::native_amx_duplicate_participant_route(
                                    index, leg.route,
                                ),
                            );
                        }
                        if actual_key < previous_key {
                            return Err(
                                ToriiRoutingPlanHintError::native_amx_participants_out_of_order(
                                    index, previous, leg.route,
                                ),
                            );
                        }
                    }
                    previous_route = Some(leg.route);
                    participant_legs.push(crate::queue::RouteLeg::from(leg));
                }
                let plan = crate::queue::RoutingPlan::native_amx(
                    crate::queue::RouteLeg::from(coordinator).route,
                    participant_legs,
                );
                let computed = plan.digest();
                if computed != plan_digest {
                    return Err(ToriiRoutingPlanHintError::native_amx_plan_digest_mismatch(
                        plan_digest,
                        computed,
                    ));
                }
                Ok(plan)
            }
        }
    }
}
impl From<crate::queue::RoutingPlan> for ToriiRoutingPlanHintV1 {
    fn from(value: crate::queue::RoutingPlan) -> Self {
        match value {
            crate::queue::RoutingPlan::Single(leg) => Self::Single(leg.into()),
            crate::queue::RoutingPlan::NativeAmx(plan) => Self::NativeAmx {
                plan_digest: plan.plan_digest,
                coordinator: plan.coordinator.into(),
                participants: plan.participants.into_iter().map(Into::into).collect(),
            },
        }
    }
}
impl TryFrom<ToriiRoutingPlanHintV1> for crate::queue::RoutingPlan {
    type Error = ToriiRoutingPlanHintError;
    fn try_from(value: ToriiRoutingPlanHintV1) -> Result<Self, Self::Error> {
        value.try_into_routing_plan()
    }
}
/// Encoded response format requested by the ingress node.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiProxyResponseFormatV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ToriiProxyResponseFormatV1 {
    /// Serialize the response body as Norito.
    Norito,
    /// Serialize the response body as JSON.
    Json,
}
/// Supported read endpoints forwarded over the Torii control plane.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiReadEndpointV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ToriiReadEndpointV1 {
    /// `GET /v1/accounts/{account_id}`
    AccountGet,
    /// `GET /v1/explorer/accounts/{account_id}`
    ExplorerAccountDetail,
    /// `GET /v1/accounts/{account_id}/assets`
    AccountAssetsGet,
    /// `POST /v1/accounts/{account_id}/assets/query`
    AccountAssetsQuery,
    /// `GET /v1/accounts/{account_id}/permissions`
    AccountPermissionsGet,
    /// `GET /v1/accounts/{account_id}/transactions`
    AccountTransactionsGet,
    /// `POST /v1/accounts/{account_id}/transactions/query`
    AccountTransactionsQuery,
    /// `POST /v1/transactions/query`
    TransactionsQuery,
    /// `GET /v1/pipeline/transactions/status`
    PipelineTransactionStatusGet,
    /// `GET /v1/proofs/{id}`
    ProofRecordGet,
    /// `GET /v1/accounts`
    AccountsList,
    /// `POST /v1/accounts/query`
    AccountsQuery,
    /// `GET /v1/accounts/{uaid}/portfolio`
    AccountsPortfolio,
    /// `GET /v1/assets/definitions`
    AssetDefinitionsList,
    /// `GET /v1/assets/definitions/{asset}`
    AssetDefinitionGet,
    /// `POST /v1/assets/definitions/query`
    AssetDefinitionsQuery,
    /// `GET /v1/assets/definitions/{asset}/holders`
    AssetHoldersGet,
    /// `POST /v1/assets/definitions/{asset}/holders/query`
    AssetHoldersQuery,
    /// `GET /v1/domains`
    DomainsList,
    /// `POST /v1/domains/query`
    DomainsQuery,
    /// `GET /v1/nfts`
    NftsList,
    /// `POST /v1/nfts/query`
    NftsQuery,
    /// `GET /v1/nexus/public-lanes/{lane_id}/validators`
    NexusPublicLaneValidators,
    /// `GET /v1/nexus/public-lanes/{lane_id}/stake`
    NexusPublicLaneStake,
    /// `GET /v1/nexus/public-lanes/{lane_id}/rewards/pending`
    NexusPublicLaneRewards,
    /// `GET /v1/nexus/dataspaces/accounts/{literal}/summary`
    NexusDataspacesAccountSummary,
    /// `GET /v1/space-directory/uaids/{uaid}`
    SpaceDirectoryBindingsGet,
    /// `GET /v1/space-directory/uaids/{uaid}/manifests`
    SpaceDirectoryManifestsGet,
    /// `GET /v1/rwas`
    RwasList,
    /// `POST /v1/rwas/query`
    RwasQuery,
    /// `POST /v1/aliases/resolve`
    AliasResolve,
    /// `POST /v1/aliases/resolve-index`
    AliasResolveIndex,
    /// `POST /v1/aliases/by-account`
    AliasLookupByAccount,
    /// `GET /v1/explorer/asset-definitions/{id}`
    ExplorerAssetDefinitionDetail,
    /// `GET /v1/explorer/asset-definitions/{id}/econometrics`
    ExplorerAssetDefinitionEconometrics,
    /// `GET /v1/explorer/asset-definitions/{id}/snapshot`
    ExplorerAssetDefinitionSnapshot,
    /// `POST /v1/contracts/aliases/resolve`
    ContractAliasResolve,
    /// `GET /v1/contracts/state`
    ContractStateGet,
    /// `POST /v1/contracts/view`
    ContractViewPost,
    /// `POST /v1/contracts/view/batch`
    ContractViewBatchPost,
    /// `GET /v1/accounts/{account_id}/history`
    AccountHistoryGet,
    /// `GET /v1/internal/accounts/{account_id}`
    InternalAccountGet,
    /// `GET /v1/internal/accounts/{account_id}/transactions/{entrypoint_hash}`
    InternalAccountTransactionGet,
    /// `GET /v1/internal/accounts/{account_id}/assets/{asset_definition_id}?scope=...`
    InternalAccountAssetGet,
    /// `POST /v1/contracts/deployment-state`
    ContractDeploymentState,
    /// `POST /v1/accounts/onboarding/current-state`
    AccountOnboardingCurrentState,
    /// `POST /v1/accounts/{account_id}/permissions/query`
    AccountPermissionsQuery,
    /// `POST /v1/space-directory/uaids/{uaid}/manifests/query`
    UaidManifestsQuery,
    /// `POST /v1/accounts/{account_id}/history/query`
    AccountHistoryQuery,
}
/// Canonical routed read executed on an authoritative Torii peer.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiReadProxyRequestV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiReadProxyRequestV1 {
    /// Supported read endpoint identifier.
    pub endpoint: ToriiReadEndpointV1,
    /// Complete caller-visible route scope authorized by the ingress node.
    pub route_scope: ToriiFanoutRouteScopeV1,
    /// Stable route resolved by the ingress node.
    pub expected_route: ToriiRouteHintV1,
    /// String path arguments in endpoint-specific order.
    pub path_args: Vec<String>,
    /// Raw query string without the leading `?`.
    pub query_string: Option<String>,
    /// Raw JSON body for POST-style read endpoints.
    pub body: Vec<u8>,
    /// Response encoding negotiated by the ingress node.
    pub response_format: ToriiProxyResponseFormatV1,
}
/// Route set Nexus should recompute for a coordinated fanout request.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiFanoutRouteScopeV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ToriiFanoutRouteScopeV1 {
    /// Fan out across all configured dataspace routes.
    AllDataspaces,
    /// Fan out across the dataspaces that may own the target account.
    TargetAccount {
        /// Canonical target account id literal.
        account_id: String,
        /// Canonical signed caller whose full visible scope authorizes row disclosure.
        caller_account_id: Option<String>,
    },
    /// Fan out across public routes plus caller-visible private dataspaces.
    VisibleAccount {
        /// Optional canonical caller account id literal.
        caller_account_id: Option<String>,
    },
}
/// Merge behavior requested for an App API read fanout.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiReadFanoutMergeV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ToriiReadFanoutMergeV1 {
    /// Merge JSON list-style responses.
    List,
    /// Merge JSON singleton responses.
    Singleton,
    /// Merge account-detail responses while preserving the requested response format.
    Account,
    /// Merge account portfolio responses.
    Portfolio,
    /// Merge dataspace account summary responses.
    DataspaceSummary,
    /// Merge space-directory bindings responses.
    SpaceDirectoryBindings,
}
/// App API read fanout coordinated by the Nexus/default route.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiReadFanoutProxyRequestV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiReadFanoutProxyRequestV1 {
    /// Supported read endpoint identifier.
    pub endpoint: ToriiReadEndpointV1,
    /// Route scope that Nexus must recompute from its local catalog/world.
    pub route_scope: ToriiFanoutRouteScopeV1,
    /// Merge behavior for the endpoint response.
    pub merge: ToriiReadFanoutMergeV1,
    /// String path arguments in endpoint-specific order.
    pub path_args: Vec<String>,
    /// Raw query string without the leading `?`.
    pub query_string: Option<String>,
    /// Raw JSON body for POST-style read endpoints.
    pub body: Vec<u8>,
    /// Response encoding negotiated by the ingress node.
    pub response_format: ToriiProxyResponseFormatV1,
}
/// Hosted HTTP request forwarded to a peer that may own a healthy Inrou target.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiHostedHttpProxyRequestV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiHostedHttpProxyRequestV1 {
    /// Soracloud service name already resolved from the public route.
    pub service_name: String,
    /// Exact service revision selected by the ingress node.
    pub service_version: String,
    /// Exact authoritative replica slot selected by the ingress node.
    pub replica_slot: u16,
    /// Request path relative to the admitted public route prefix.
    pub request_path: String,
    /// Original client HTTP method.
    pub method: String,
    /// Raw query string without the leading `?`.
    pub query_string: Option<String>,
    /// End-to-end application headers preserved after ingress removes platform and hop-by-hop
    /// metadata.
    pub headers: Vec<ToriiProxyHeaderV1>,
    /// Raw request body bytes.
    pub body: Vec<u8>,
    /// Original client IP address when known, used for deterministic canary selection.
    pub remote_ip: Option<String>,
}
/// Canonical first-release Torii request body forwarded over the P2P control plane.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::derive::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiProxyRequestKindV1")]
pub enum ToriiProxyRequestKindV1 {
    /// Submit a signed transaction to the authoritative lane validator.
    #[codec(index = 0)]
    SubmitTransaction {
        /// Original transaction entrypoint from the client.
        transaction: TransactionEntrypoint,
        /// Full routing plan resolved by the ingress node.
        expected_plan: ToriiRoutingPlanHintV1,
    },
    /// Execute a signed query on the authoritative lane validator.
    #[codec(index = 1)]
    SignedQuery {
        /// Norito-encoded signed query from the client.
        query_bytes: Vec<u8>,
        /// Route resolved by the ingress node.
        expected_route: ToriiRouteHintV1,
        /// Response encoding negotiated by the ingress node.
        response_format: ToriiProxyResponseFormatV1,
    },
    /// Exhaust a client-signed query on one exact authoritative route.
    #[codec(index = 2)]
    SignedQueryRouteScan {
        /// Original versioned Norito-encoded signed query from the client.
        query_bytes: Vec<u8>,
        /// Route resolved by the ingress node.
        expected_route: ToriiRouteHintV1,
        /// Response encoding negotiated by the ingress node.
        response_format: ToriiProxyResponseFormatV1,
    },
    /// Execute a client-signed query fanout coordinated by the Nexus/default route.
    #[codec(index = 3)]
    SignedQueryFanout {
        /// Original versioned Norito-encoded signed query from the client.
        query_bytes: Vec<u8>,
        /// Response encoding negotiated by the ingress node.
        response_format: ToriiProxyResponseFormatV1,
    },
    /// Execute a routed Torii read endpoint on the authoritative peer.
    #[codec(index = 4)]
    Read(ToriiReadProxyRequestV1),
    /// Execute an App API read fanout coordinated by the Nexus/default route.
    #[codec(index = 5)]
    ReadFanout(ToriiReadFanoutProxyRequestV1),
    /// Proxy a Soracloud public hosted-HTTP request to a peer with a local healthy Inrou target.
    #[codec(index = 6)]
    HostedHttp(ToriiHostedHttpProxyRequestV1),
}
/// First-release P2P Torii proxy request sent from ingress to an authoritative peer.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiProxyRequestV1")]
pub struct ToriiProxyRequestV1 {
    /// Version of the proxy request envelope.
    pub schema_version: u16,
    /// Correlation id selected by the ingress node.
    pub request_id: Hash,
    /// Authenticated absolute execution deadline in Unix epoch milliseconds.
    ///
    /// Every proxy hop preserves this value. Receivers reject expired or
    /// excessive horizons before executing the request, and reserve the final
    /// portion of the budget for returning the bounded response.
    pub deadline_unix_ms: u64,
    /// Current forwarding depth observed by this hop.
    pub hop_count: u8,
    /// Maximum number of hops allowed before the request is rejected.
    pub max_hops: u8,
    /// Peer ids already traversed by the request to prevent proxy loops.
    pub visited_peer_ids: Vec<PeerId>,
    /// Canonical request to execute on the authoritative peer.
    pub request: ToriiProxyRequestKindV1,
}
/// One HTTP header preserved across the Torii proxy response snapshot.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiProxyHeaderV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiProxyHeaderV1 {
    /// Lower- or mixed-case header name as received from the responder.
    pub name: String,
    /// Raw header value bytes.
    pub value: Vec<u8>,
}
/// Serialized HTTP response sent back to the ingress node.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiProxyHttpResponseV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiProxyHttpResponseV1 {
    /// HTTP status code returned by the authoritative responder.
    pub status_code: u16,
    /// HTTP headers returned by the authoritative responder.
    pub headers: Vec<ToriiProxyHeaderV1>,
    /// Raw response body bytes returned by the authoritative responder.
    pub body: Vec<u8>,
}
/// P2P Torii proxy response sent from the authoritative peer back to ingress.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::torii_proxy::ToriiProxyResponseV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ToriiProxyResponseV1 {
    /// Version of the proxy response envelope.
    pub schema_version: u16,
    /// Correlation id selected by the ingress node.
    pub request_id: Hash,
    /// Serialized HTTP response from the authoritative peer.
    pub response: ToriiProxyHttpResponseV1,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{RouteLeg, RouteLegRole, RoutingDecision, RoutingPlan};
    fn torii_proxy_test_network_id(seed: &[u8]) -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(Hash::new(seed)),
        )
    }
    fn torii_read_endpoint_wire_index(endpoint: ToriiReadEndpointV1) -> u32 {
        let encoded = norito::codec::Encode::encode(&endpoint);
        assert_eq!(
            encoded.len(),
            4,
            "ToriiReadEndpointV1 should encode as a u32 variant index"
        );
        u32::from_le_bytes(encoded.try_into().expect("four-byte variant index"))
    }
    #[test]
    fn transaction_proxy_preserves_original_signed_envelope_and_routing_plan() {
        let signer =
            iroha_crypto::KeyPair::from_seed(vec![0x71; 32], iroha_crypto::Algorithm::Ed25519);
        let transaction = TransactionEntrypoint::External(
            iroha_data_model::transaction::TransactionBuilder::new(
                torii_proxy_test_network_id(b"native-transaction-proxy"),
                iroha_data_model::account::AccountId::new(signer.public_key().clone()),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .sign(signer.private_key()),
        );
        let original = norito::to_bytes(&transaction).expect("canonical original entrypoint");
        let plan = ToriiRoutingPlanHintV1::from(RoutingPlan::single(RoutingDecision::new(
            LaneId::new(2),
            DataSpaceId::new(5),
        )));
        let request = ToriiProxyRequestKindV1::SubmitTransaction {
            transaction,
            expected_plan: plan.clone(),
        };
        let encoded = norito::to_bytes(&request).expect("encode native submission");
        let decoded = norito::decode_from_bytes::<ToriiProxyRequestKindV1>(&encoded)
            .expect("decode native submission");
        assert_eq!(decoded, request);
        let ToriiProxyRequestKindV1::SubmitTransaction {
            transaction,
            expected_plan,
        } = decoded
        else {
            panic!("submission remains a submission")
        };
        assert_eq!(
            norito::to_bytes(&transaction).expect("canonical decoded entrypoint"),
            original
        );
        assert_eq!(expected_plan, plan);
    }
    #[test]
    fn torii_proxy_v1_envelope_roundtrips_exact_deadline_bound_request() {
        let request = ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::new(b"torii-proxy-v1-roundtrip"),
            deadline_unix_ms: 1_900_000_000_000,
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: Vec::new(),
            request: ToriiProxyRequestKindV1::Read(ToriiReadProxyRequestV1 {
                endpoint: ToriiReadEndpointV1::AccountsList,
                route_scope: ToriiFanoutRouteScopeV1::AllDataspaces,
                expected_route: ToriiRouteHintV1 {
                    lane_id: LaneId::new(3),
                    dataspace_id: DataSpaceId::new(9),
                },
                path_args: Vec::new(),
                query_string: None,
                body: Vec::new(),
                response_format: ToriiProxyResponseFormatV1::Json,
            }),
        };
        let encoded = norito::to_bytes(&request).expect("encode V1 Torii proxy request");
        let decoded = norito::decode_from_bytes::<ToriiProxyRequestV1>(&encoded)
            .expect("decode V1 Torii proxy request");
        assert_eq!(decoded, request);
    }
    #[test]
    fn torii_read_endpoint_wire_indexes_match_first_release_schema() {
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::AccountTransactionsGet),
            5
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::AccountTransactionsQuery),
            6
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::AccountHistoryGet),
            40
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::InternalAccountGet),
            41
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::InternalAccountTransactionGet),
            42
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::InternalAccountAssetGet),
            43
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::ContractDeploymentState),
            44
        );
        assert_eq!(
            torii_read_endpoint_wire_index(ToriiReadEndpointV1::AccountOnboardingCurrentState),
            45
        );
    }
    #[test]
    fn collection_read_endpoint_wire_indexes_are_distinct() {
        for (endpoint, expected) in [
            (ToriiReadEndpointV1::AccountPermissionsQuery, 46),
            (ToriiReadEndpointV1::UaidManifestsQuery, 47),
            (ToriiReadEndpointV1::AccountHistoryQuery, 48),
        ] {
            assert_eq!(torii_read_endpoint_wire_index(endpoint), expected);
        }
    }
    fn native_amx_participant_legs(count: usize) -> Vec<RouteLeg> {
        (0..count)
            .map(|index| {
                let ordinal = u32::try_from(index + 1).expect("participant fixture index fits u32");
                RouteLeg::new(
                    RoutingDecision::new(
                        LaneId::new(ordinal),
                        DataSpaceId::new(u64::from(ordinal)),
                    ),
                    RouteLegRole::Participant,
                )
            })
            .collect()
    }
    #[test]
    fn routing_plan_refusals_retain_only_their_variant_details() {
        const { assert!(std::mem::size_of::<ToriiRoutingPlanHintError>() <= 128) };
        let route = ToriiRouteHintV1 {
            lane_id: LaneId::new(2),
            dataspace_id: DataSpaceId::new(3),
        };
        let later_route = ToriiRouteHintV1 {
            lane_id: LaneId::new(4),
            dataspace_id: DataSpaceId::new(5),
        };
        let advertised = Hash::new(b"advertised");
        let computed = Hash::new(b"computed");
        let refusals = [
            ToriiRoutingPlanHintError::unexpected_coordinator_role(
                ToriiRouteLegRoleV1::Participant,
            ),
            ToriiRoutingPlanHintError::unexpected_participant_role(
                7,
                ToriiRouteLegRoleV1::Coordinator,
            ),
            ToriiRoutingPlanHintError::native_amx_participant_limit_exceeded(256, 255),
            ToriiRoutingPlanHintError::native_amx_duplicate_participant_route(7, route),
            ToriiRoutingPlanHintError::native_amx_participants_out_of_order(7, later_route, route),
            ToriiRoutingPlanHintError::native_amx_plan_digest_mismatch(advertised, computed),
        ];
        let expected_kinds = [
            ToriiRoutingPlanHintErrorKind::UnexpectedCoordinatorRole,
            ToriiRoutingPlanHintErrorKind::UnexpectedParticipantRole,
            ToriiRoutingPlanHintErrorKind::NativeAmxParticipantLimitExceeded,
            ToriiRoutingPlanHintErrorKind::NativeAmxDuplicateParticipantRoute,
            ToriiRoutingPlanHintErrorKind::NativeAmxParticipantsOutOfOrder,
            ToriiRoutingPlanHintErrorKind::NativeAmxPlanDigestMismatch,
        ];
        for (refusal, expected_kind) in refusals.into_iter().zip(expected_kinds) {
            assert_eq!(refusal.kind(), expected_kind);
            let expected_role = match refusal.kind() {
                ToriiRoutingPlanHintErrorKind::UnexpectedCoordinatorRole => {
                    Some(ToriiRouteLegRoleV1::Participant)
                }
                ToriiRoutingPlanHintErrorKind::UnexpectedParticipantRole => {
                    Some(ToriiRouteLegRoleV1::Coordinator)
                }
                _ => None,
            };
            assert_eq!(refusal.actual_role(), expected_role);
            let indexed = matches!(
                refusal.kind(),
                ToriiRoutingPlanHintErrorKind::UnexpectedParticipantRole
                    | ToriiRoutingPlanHintErrorKind::NativeAmxDuplicateParticipantRoute
                    | ToriiRoutingPlanHintErrorKind::NativeAmxParticipantsOutOfOrder
            );
            assert_eq!(refusal.leg_index(), indexed.then_some(7));
            let limited =
                refusal.kind() == ToriiRoutingPlanHintErrorKind::NativeAmxParticipantLimitExceeded;
            assert_eq!(refusal.participant_count(), limited.then_some(256));
            assert_eq!(refusal.participant_limit(), limited.then_some(255));
            let expected_previous = match refusal.kind() {
                ToriiRoutingPlanHintErrorKind::NativeAmxDuplicateParticipantRoute => Some(route),
                ToriiRoutingPlanHintErrorKind::NativeAmxParticipantsOutOfOrder => Some(later_route),
                _ => None,
            };
            assert_eq!(refusal.previous_route(), expected_previous);
            assert_eq!(refusal.actual_route(), expected_previous.map(|_| route));
            let digest_mismatch =
                refusal.kind() == ToriiRoutingPlanHintErrorKind::NativeAmxPlanDigestMismatch;
            assert_eq!(
                refusal.advertised_digest(),
                digest_mismatch.then_some(advertised)
            );
            assert_eq!(
                refusal.computed_digest(),
                digest_mismatch.then_some(computed)
            );
        }
        assert_eq!(
            refusals[0].to_string(),
            "unexpected coordinator role Participant"
        );
        assert_eq!(
            refusals[1].to_string(),
            "unexpected participant role Coordinator at index 7"
        );
        assert_eq!(
            refusals[2].to_string(),
            "native AMX participant count 256 exceeds protocol limit 255"
        );
        assert_eq!(
            refusals[3].to_string(),
            "duplicate native AMX participant route at index 7: dataspace 3, lane 2"
        );
        assert_eq!(
            refusals[4].to_string(),
            "native AMX participant routes are out of canonical (dataspace, lane) order at index 7: previous (5, 4), actual (3, 2)"
        );
        assert_eq!(
            refusals[5].to_string(),
            format!(
                "native AMX plan digest mismatch: advertised {advertised}, computed {computed}"
            )
        );
    }
    #[test]
    fn torii_routing_plan_hint_roundtrips_single_and_native_amx_plans() {
        let single_route = RoutingDecision::new(LaneId::new(4), DataSpaceId::new(9));
        let single_hint = ToriiRoutingPlanHintV1::from(RoutingPlan::single(single_route));
        assert_eq!(
            single_hint.coordinator_route(),
            ToriiRouteHintV1 {
                lane_id: single_route.lane_id,
                dataspace_id: single_route.dataspace_id,
            }
        );
        assert_eq!(
            single_hint
                .clone()
                .try_into_routing_plan()
                .expect("canonical single-route hint should validate"),
            RoutingPlan::single(single_route)
        );
        assert_eq!(
            RoutingPlan::try_from(single_hint).expect("single routing hint should validate"),
            RoutingPlan::single(single_route)
        );
        let coordinator = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7));
        let native_plan = RoutingPlan::native_amx(
            coordinator,
            vec![
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(2), DataSpaceId::new(8)),
                    RouteLegRole::Coordinator,
                ),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7)),
                    RouteLegRole::Coordinator,
                ),
            ],
        );
        let native_hint = ToriiRoutingPlanHintV1::from(native_plan.clone());
        assert_eq!(
            native_hint.coordinator_route(),
            ToriiRouteHintV1 {
                lane_id: coordinator.lane_id,
                dataspace_id: coordinator.dataspace_id,
            }
        );
        let ToriiRoutingPlanHintV1::NativeAmx {
            plan_digest,
            participants,
            ..
        } = &native_hint
        else {
            panic!("expected native AMX routing plan hint");
        };
        assert_eq!(*plan_digest, native_plan.digest());
        assert!(
            participants
                .iter()
                .all(|leg| leg.role == ToriiRouteLegRoleV1::Participant)
        );
        assert_eq!(
            native_hint
                .clone()
                .try_into_routing_plan()
                .expect("canonical native AMX hint should validate"),
            native_plan
        );
        assert_eq!(
            RoutingPlan::try_from(native_hint).expect("native AMX routing hint should validate"),
            native_plan
        );
    }
    #[test]
    fn torii_routing_plan_hint_enforces_native_amx_participant_limit() {
        assert_eq!(
            TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1, 255,
            "Torii hint bound must remain source-bound to the Native AMX protocol cap"
        );
        let coordinator = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        let maximum_plan = RoutingPlan::native_amx(
            coordinator,
            native_amx_participant_legs(TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1),
        );
        assert_eq!(
            ToriiRoutingPlanHintV1::from(maximum_plan.clone()).try_into_routing_plan(),
            Ok(maximum_plan),
            "the exact participant limit must remain admissible"
        );
        let oversized_count = TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1 + 1;
        let oversized_hint = ToriiRoutingPlanHintV1::from(RoutingPlan::native_amx(
            coordinator,
            native_amx_participant_legs(oversized_count),
        ));
        let error = oversized_hint
            .try_into_routing_plan()
            .expect_err("a participant vector above the protocol cap must fail closed");
        assert_eq!(
            error,
            ToriiRoutingPlanHintError::native_amx_participant_limit_exceeded(
                oversized_count,
                TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1,
            )
        );
        assert_eq!(
            error.kind(),
            ToriiRoutingPlanHintErrorKind::NativeAmxParticipantLimitExceeded
        );
        assert_eq!(error.participant_count(), Some(oversized_count));
        assert_eq!(
            error.participant_limit(),
            Some(TORII_ROUTING_PLAN_MAX_NATIVE_AMX_PARTICIPANTS_V1)
        );
        assert_eq!(
            error.to_string(),
            "native AMX participant count 256 exceeds protocol limit 255"
        );
    }
    #[test]
    fn torii_routing_plan_hint_rejects_duplicate_participants_without_deduplication() {
        let coordinator = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7));
        let plan = RoutingPlan::native_amx(coordinator, native_amx_participant_legs(2));
        let mut hint = ToriiRoutingPlanHintV1::from(plan);
        let ToriiRoutingPlanHintV1::NativeAmx { participants, .. } = &mut hint else {
            panic!("expected native AMX hint");
        };
        let duplicate = participants[0];
        participants.insert(1, duplicate);
        let error = hint
            .try_into_routing_plan()
            .expect_err("duplicate participant hints must not be silently deduplicated");
        assert_eq!(
            error,
            ToriiRoutingPlanHintError::native_amx_duplicate_participant_route(1, duplicate.route)
        );
        assert_eq!(
            error.kind(),
            ToriiRoutingPlanHintErrorKind::NativeAmxDuplicateParticipantRoute
        );
        assert_eq!(error.leg_index(), Some(1));
        assert_eq!(error.previous_route(), Some(duplicate.route));
        assert_eq!(error.actual_route(), Some(duplicate.route));
        assert_eq!(
            error.to_string(),
            "duplicate native AMX participant route at index 1: dataspace 1, lane 1"
        );
    }
    #[test]
    fn torii_routing_plan_hint_rejects_out_of_order_participants_without_sorting() {
        let coordinator = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7));
        let plan = RoutingPlan::native_amx(coordinator, native_amx_participant_legs(2));
        let mut hint = ToriiRoutingPlanHintV1::from(plan);
        let ToriiRoutingPlanHintV1::NativeAmx { participants, .. } = &mut hint else {
            panic!("expected native AMX hint");
        };
        participants.swap(0, 1);
        let previous = participants[0].route;
        let actual = participants[1].route;
        let error = hint
            .try_into_routing_plan()
            .expect_err("out-of-order participant hints must not be silently sorted");
        assert_eq!(
            error,
            ToriiRoutingPlanHintError::native_amx_participants_out_of_order(1, previous, actual,)
        );
        assert_eq!(
            error.kind(),
            ToriiRoutingPlanHintErrorKind::NativeAmxParticipantsOutOfOrder
        );
        assert_eq!(error.leg_index(), Some(1));
        assert_eq!(error.previous_route(), Some(previous));
        assert_eq!(error.actual_route(), Some(actual));
        assert_eq!(
            error.to_string(),
            "native AMX participant routes are out of canonical (dataspace, lane) order at index \
             1: previous (2, 2), actual (1, 1)"
        );
    }
    #[test]
    fn torii_routing_plan_hint_rejects_forged_digest_and_roles() {
        let coordinator = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(7));
        let native_plan = RoutingPlan::native_amx(
            coordinator,
            vec![
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(2), DataSpaceId::new(8)),
                    RouteLegRole::Participant,
                ),
                RouteLeg::new(
                    RoutingDecision::new(LaneId::new(3), DataSpaceId::new(9)),
                    RouteLegRole::Participant,
                ),
            ],
        );
        let mut forged_digest = ToriiRoutingPlanHintV1::from(native_plan.clone());
        let advertised = Hash::new(b"forged-native-amx-plan-digest");
        let ToriiRoutingPlanHintV1::NativeAmx { plan_digest, .. } = &mut forged_digest else {
            panic!("expected native AMX hint");
        };
        *plan_digest = advertised;
        assert_eq!(
            forged_digest.clone().try_into_routing_plan(),
            Err(ToriiRoutingPlanHintError::native_amx_plan_digest_mismatch(
                advertised,
                native_plan.digest()
            ))
        );
        assert_eq!(
            RoutingPlan::try_from(forged_digest),
            Err(ToriiRoutingPlanHintError::native_amx_plan_digest_mismatch(
                advertised,
                native_plan.digest()
            ))
        );
        let wrong_single_role = ToriiRoutingPlanHintV1::Single(ToriiRouteLegHintV1 {
            route: ToriiRouteHintV1::from(coordinator),
            role: ToriiRouteLegRoleV1::Participant,
        });
        assert_eq!(
            wrong_single_role.try_into_routing_plan(),
            Err(ToriiRoutingPlanHintError::unexpected_coordinator_role(
                ToriiRouteLegRoleV1::Participant
            ))
        );
        let mut wrong_participant_role = ToriiRoutingPlanHintV1::from(native_plan);
        let ToriiRoutingPlanHintV1::NativeAmx { participants, .. } = &mut wrong_participant_role
        else {
            panic!("expected native AMX hint");
        };
        participants[1].role = ToriiRouteLegRoleV1::Coordinator;
        assert_eq!(
            wrong_participant_role.try_into_routing_plan(),
            Err(ToriiRoutingPlanHintError::unexpected_participant_role(
                1,
                ToriiRouteLegRoleV1::Coordinator
            ))
        );
    }
}
