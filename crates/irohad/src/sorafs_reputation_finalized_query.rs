//! Exact-anchor SoraFS reputation queries backed by the durable core archive.
//!
//! This adapter never consults [`iroha_core::state::State`] and therefore has
//! no current-head fallback. Every response is materialized from one fully
//! validated immutable archive record. Requests below the archive's explicit
//! activation floor fail with a distinct payload-free receipt. The daemon
//! launcher opens this archive from explicit `iroha_config` bounds, reconciles
//! the authenticated Kura tip before constructing the adapter, and passes the
//! same archive to Sumeragi so every fresh Sumeragi commit captures its immutable
//! post-execution view after the Kura/WSV checkpoint boundary and before live
//! State publication.
//!
//! Journal delivery is revalidated as one policy/page request before it leaves
//! this boundary. The other V1 page types do not expose data-model validation
//! methods; their source-order and exact-anchor invariants are validated when
//! the archive record is opened, their exclusive cursor is resolved against
//! that immutable row here, and the reputation worker independently validates
//! the returned anchor and continuation before consuming the page.
use crate::sorafs_provider_ingest_finalized_query::archive_boundary::{
    ArchiveActivationGateV1, ArchiveStartupBoundaryV1, classify_archive_startup_boundary,
};
use eyre::{Result, bail};
use iroha_config::parameters::{actual::SorafsReputationRuntime, is_production_runtime_handle};
use iroha_core::{
    kura::Kura,
    query::reputation_finalized::{
        ReputationFinalizedArchive, ReputationFinalizedArchiveBounds,
        ReputationFinalizedArchiveCompactionOutcomeV1, ReputationFinalizedArchiveError,
        ReputationFinalizedArchiveKeyV1, ReputationFinalizedArchiveQualificationV1,
        ReputationFinalizedArchiveReconcileOutcomeV1,
        ReputationFinalizedArchiveRetentionAuthorityBindingV1,
        ReputationFinalizedArchiveRetentionAuthorityV1, ReputationFinalizedProjectionV1,
    },
    state::{
        State, StateQueryView, StateReadOnly as _, WorldReadOnly as _, WorldStateSnapshot as _,
    },
};
use iroha_data_model::{
    NetworkId,
    query::sorafs::prelude::{
        FindSorafsReputationJournalAuthorityPolicy, FindSorafsReputationJournalEventBySourceId,
    },
    sorafs::{
        capacity::ProviderId,
        moderation_ledger::{
            REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1, REPAIR_QUERY_MAX_ITEMS_V1,
            RepairFinalizedCursorV1, RepairFinalizedEventCursorV1, RepairFinalizedEventPageV1,
            RepairFinalizedEventV1,
        },
        orderbook::{
            ORDERBOOK_QUERY_MAX_EVENT_PAGE_BYTES_V1, ORDERBOOK_QUERY_MAX_ITEMS_V1,
            OrderbookFinalizedCursorV1, OrderbookFinalizedEventCursorV1,
            OrderbookFinalizedEventPageV1, OrderbookFinalizedEventV1,
        },
        proof_ledger::{
            PROOF_OUTCOME_QUERY_MAX_EVENT_PAGE_BYTES_V1, PROOF_OUTCOME_QUERY_MAX_ITEMS_V1,
            ProofOutcomeFinalizedCursorV1, ProofOutcomeFinalizedEventCursorV1,
            ProofOutcomeFinalizedEventPageV1, ProofOutcomeFinalizedEventV1,
        },
        reputation::{
            REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1, ReputationFinalizedArchiveRetentionRequestV1,
            ReputationJournalAuthorityPolicyRecordV1 as AuthorityPolicyRecord,
            ReputationJournalFinalizedCursorV1, ReputationJournalFinalizedEventCursorV1,
            ReputationJournalFinalizedEventPageV1, ReputationJournalFinalizedEventV1,
            ReputationJournalSourceIdV1,
        },
        reserve::{
            RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1, RESERVE_QUERY_MAX_ITEMS_V1,
            ReserveFinalizedCursorV1, ReserveFinalizedEventCursorV1, ReserveFinalizedEventPageV1,
            ReserveFinalizedEventV1, ReserveProviderAccountPageV1,
        },
    },
};
use norito::core::NoritoSerialize;
use sorafs_node::reputation::{
    ReputationFinalizedIdentityV1,
    runtime::{
        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1, ReputationExternalFailureV1,
        ReputationFinalizedAnchorV1, ReputationFinalizedQueryV1,
        ReputationJournalDeliveryFinalizedViewV1, ReputationJournalSourceFinalizedViewV1,
        ReputationRuntimeProviderQualificationV1, ReputationRuntimeProviderV1,
    },
};
use std::{fmt, sync::Arc};
const FAILURE_INVALID_REQUEST: u8 = 0xA1;
const FAILURE_ARCHIVE_READ: u8 = 0xA2;
const FAILURE_MISSING_ANCHOR: u8 = 0xA3;
const FAILURE_ANCHOR_MISMATCH: u8 = 0xA4;
const FAILURE_INVALID_LIMIT: u8 = 0xA5;
const FAILURE_INVALID_CURSOR: u8 = 0xA6;
const FAILURE_PAGE_BOUNDS: u8 = 0xA7;
const FAILURE_BELOW_ACTIVATION_FLOOR: u8 = 0xA8;
/// Typed failure while qualifying the configured finalized archive for startup.
#[derive(Debug)]
pub(crate) enum ReputationFinalizedArchiveStartupErrorV1 {
    /// Recovered State and the durable current-consensus Kura boundary disagreed.
    StartupBoundary {
        /// Stable payload-free rejection reason.
        reason: &'static str,
    },
    /// Reading the exact durable Kura boundary failed.
    KuraBoundary {
        /// Payload-free storage diagnostic.
        detail: String,
    },
    /// Runtime retention-authority presence disagreed with public configuration.
    RetentionAuthorityConfiguration {
        /// Stable payload-free rejection reason.
        reason: &'static str,
    },
    /// One named archive qualification stage failed.
    Archive {
        /// Payload-free startup stage.
        stage: &'static str,
        /// Typed durable archive failure.
        source: Box<iroha_core::query::reputation_finalized::ReputationFinalizedArchiveError>,
    },
}
impl fmt::Display for ReputationFinalizedArchiveStartupErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupBoundary { reason } => {
                write!(
                    formatter,
                    "invalid finalized reputation startup boundary: {reason}"
                )
            }
            Self::KuraBoundary { detail } => write!(
                formatter,
                "finalized reputation startup could not read the exact durable Kura boundary: {detail}"
            ),
            Self::RetentionAuthorityConfiguration { reason } => write!(
                formatter,
                "invalid finalized reputation retention-authority configuration: {reason}"
            ),
            Self::Archive { stage, .. } => {
                write!(formatter, "finalized reputation archive failed at {stage}")
            }
        }
    }
}
impl std::error::Error for ReputationFinalizedArchiveStartupErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StartupBoundary { .. }
            | Self::KuraBoundary { .. }
            | Self::RetentionAuthorityConfiguration { .. } => None,
            Self::Archive { source, .. } => Some(source.as_ref()),
        }
    }
}
/// Recovery mode authenticated while opening the reputation archive.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "startup retains the authenticated reconciliation value without heap indirection"
)]
pub(crate) enum ReputationFinalizedArchiveStartupModeV1 {
    /// Fresh height-zero State/Kura with a completely empty archive namespace.
    BootstrapAwaitingGenesisCapture,
    /// Ordinary startup reconciled and qualified with an exact zero-gap tip.
    Qualified {
        /// Exact startup reconciliation against committed State and Kura.
        reconciliation: ReputationFinalizedArchiveReconcileOutcomeV1,
        /// Subsequent configured live-lag qualification.
        live_qualification: ReputationFinalizedArchiveQualificationV1,
    },
}
impl ReputationFinalizedArchiveStartupModeV1 {
    fn activation_gate(&self) -> ArchiveActivationGateV1 {
        match self {
            Self::BootstrapAwaitingGenesisCapture => ArchiveActivationGateV1::AwaitingGenesis,
            Self::Qualified { .. } => ArchiveActivationGateV1::StrictLive,
        }
    }
}
/// Exact archive qualification retained between startup and adapter assembly.
#[derive(Debug)]
#[must_use]
pub(crate) struct PreparedReputationFinalizedArchiveV1 {
    archive: Arc<ReputationFinalizedArchive>,
    startup_mode: ReputationFinalizedArchiveStartupModeV1,
    activation: ReputationFinalizedArchiveActivationV1,
    retention_authority: Option<QualifiedReputationRetentionAuthorityV1>,
}
impl PreparedReputationFinalizedArchiveV1 {
    /// Return the archive installed into the Sumeragi commit corridor.
    pub(crate) fn archive(&self) -> &Arc<ReputationFinalizedArchive> {
        &self.archive
    }
    /// Return the exact authenticated startup mode.
    pub(crate) const fn startup_mode(&self) -> &ReputationFinalizedArchiveStartupModeV1 {
        &self.startup_mode
    }
    /// Return the cloneable deferred-activation probe retained by the runtime
    /// launcher.
    pub(crate) const fn activation(&self) -> &ReputationFinalizedArchiveActivationV1 {
        &self.activation
    }
    /// Return the authority qualified for explicit finalized-prefix retention.
    pub(crate) const fn retention_authority(
        &self,
    ) -> Option<&QualifiedReputationRetentionAuthorityV1> {
        self.retention_authority.as_ref()
    }
    /// Build the supervised explicit-retention controller when configured.
    pub(crate) fn retention_controller(
        &self,
    ) -> Option<ReputationFinalizedArchiveRetentionControllerV1> {
        let authority = self.retention_authority.as_ref()?.clone();
        Some(ReputationFinalizedArchiveRetentionControllerV1 {
            network_id: self.activation.network_id,
            archive: Arc::clone(&self.archive),
            state: Arc::clone(&self.activation.state),
            kura: Arc::clone(&self.activation.kura),
            binding: authority.binding,
            authority: authority.authority,
        })
    }
}
/// Exact configured retention authority retained after startup qualification.
#[derive(Clone)]
pub(crate) struct QualifiedReputationRetentionAuthorityV1 {
    binding: ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    authority: Arc<dyn ReputationFinalizedArchiveRetentionAuthorityV1>,
}
impl fmt::Debug for QualifiedReputationRetentionAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedReputationRetentionAuthorityV1")
            .field("handle", &self.binding.handle())
            .field("qualification", &self.binding.qualification())
            .finish_non_exhaustive()
    }
}
/// One supervised result for the explicit finalized-archive retention control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReputationFinalizedArchiveRetentionControlOutcomeV1 {
    /// No governed retention request is committed.
    NoRequest,
    /// The exact requested prefix is already covered by a durable checkpoint.
    AlreadyApplied {
        /// Canonical request identity.
        request_digest: [u8; 32],
        /// Fresh committed anchor that exposed the request.
        authorization_anchor: ReputationFinalizedArchiveKeyV1,
        /// Current virtual-base retention floor.
        retention_floor: ReputationFinalizedArchiveKeyV1,
    },
    /// The exact request was approved externally and installed locally.
    Applied {
        /// Canonical request identity.
        request_digest: [u8; 32],
        /// Fresh committed anchor that exposed the request.
        authorization_anchor: ReputationFinalizedArchiveKeyV1,
        /// Durable compaction result.
        compaction: ReputationFinalizedArchiveCompactionOutcomeV1,
    },
}
/// Fail-closed error while reconciling explicit finalized-archive retention.
#[derive(Debug)]
pub(crate) enum ReputationFinalizedArchiveRetentionControlErrorV1 {
    /// State, Kura, archive, or request lineage violated a fixed boundary.
    Boundary {
        /// Stable payload-free reason.
        reason: &'static str,
    },
    /// A matching committed custom parameter was malformed.
    Request {
        /// Payload-free structural diagnostic.
        detail: String,
    },
    /// Durable archive authentication or publication failed.
    Archive {
        /// Underlying typed archive failure.
        source: Box<ReputationFinalizedArchiveError>,
    },
}
impl fmt::Display for ReputationFinalizedArchiveRetentionControlErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary { reason } => {
                write!(formatter, "invalid reputation retention boundary: {reason}")
            }
            Self::Request { detail } => {
                write!(
                    formatter,
                    "invalid committed reputation retention request: {detail}"
                )
            }
            Self::Archive { .. } => {
                write!(formatter, "explicit reputation archive retention failed")
            }
        }
    }
}
impl std::error::Error for ReputationFinalizedArchiveRetentionControlErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Archive { source } => Some(source.as_ref()),
            Self::Boundary { .. } | Self::Request { .. } => None,
        }
    }
}
/// Runtime contract consumed by the supervised reputation worker.
pub(crate) trait ReputationFinalizedArchiveRetentionControlV1:
    fmt::Debug + Send + Sync
{
    /// Revalidate the deployment-owned authority without performing work.
    fn revalidate(
        &self,
    ) -> std::result::Result<(), ReputationFinalizedArchiveRetentionControlErrorV1>;
    /// Reconcile the latest explicit caller-signed committed request once.
    fn reconcile_once(
        &self,
    ) -> std::result::Result<
        ReputationFinalizedArchiveRetentionControlOutcomeV1,
        ReputationFinalizedArchiveRetentionControlErrorV1,
    >;
}
/// State/Kura/archive-bound implementation of explicit governed retention.
#[derive(Clone)]
pub(crate) struct ReputationFinalizedArchiveRetentionControllerV1 {
    network_id: NetworkId,
    archive: Arc<ReputationFinalizedArchive>,
    state: Arc<State>,
    kura: Arc<Kura>,
    binding: ReputationFinalizedArchiveRetentionAuthorityBindingV1,
    authority: Arc<dyn ReputationFinalizedArchiveRetentionAuthorityV1>,
}
impl fmt::Debug for ReputationFinalizedArchiveRetentionControllerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReputationFinalizedArchiveRetentionControllerV1")
            .field("network_id", &self.network_id)
            .field("archive_root", &self.archive.root())
            .field("authority_handle", &self.binding.handle())
            .field("authority_qualification", &self.binding.qualification())
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
struct ReputationRetentionAuthorizationSnapshotV1 {
    request: ReputationFinalizedArchiveRetentionRequestV1,
    authorization_anchor: ReputationFinalizedArchiveKeyV1,
    qualification: ReputationFinalizedArchiveQualificationV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReputationRetentionDecisionV1 {
    Apply(ReputationFinalizedArchiveKeyV1),
    AlreadyApplied(ReputationFinalizedArchiveKeyV1),
}
impl ReputationFinalizedArchiveRetentionControllerV1 {
    fn archive_error(
        source: ReputationFinalizedArchiveError,
    ) -> ReputationFinalizedArchiveRetentionControlErrorV1 {
        ReputationFinalizedArchiveRetentionControlErrorV1::Archive {
            source: Box::new(source),
        }
    }
    fn revalidate_authority(
        &self,
    ) -> std::result::Result<(), ReputationFinalizedArchiveRetentionControlErrorV1> {
        let handle_before = self.authority.handle();
        let qualification = self.authority.qualification().map_err(|_| {
            ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                reason: "retention authority is unavailable",
            }
        })?;
        let handle_after = self.authority.handle();
        if handle_before != self.binding.handle()
            || handle_after != handle_before
            || qualification != self.binding.qualification()
        {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention authority is substituted or stale",
                },
            );
        }
        Ok(())
    }
    fn authorization_snapshot(
        &self,
    ) -> std::result::Result<
        Option<ReputationRetentionAuthorizationSnapshotV1>,
        ReputationFinalizedArchiveRetentionControlErrorV1,
    > {
        let view = self.state.query_view();
        if !std::ptr::eq(view.kura(), self.kura.as_ref()) {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "committed State is bound to another Kura instance",
                },
            );
        }
        if view.network_id() != &self.network_id {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "committed State is bound to another chain",
                },
            );
        }
        let Some(custom) = view
            .world()
            .parameters()
            .custom()
            .get(&ReputationFinalizedArchiveRetentionRequestV1::parameter_id())
        else {
            return Ok(None);
        };
        let request = ReputationFinalizedArchiveRetentionRequestV1::from_custom_parameter(custom)
            .map_err(
                |error| ReputationFinalizedArchiveRetentionControlErrorV1::Request {
                    detail: error.to_string(),
                },
            )?
            .ok_or(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention parameter changed reserved identity",
                },
            )?;
        if request.network_id != self.network_id {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention request targets another chain",
                },
            );
        }
        let authorization_height = u64::try_from(view.height()).map_err(|_| {
            ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                reason: "committed State height exceeds the supported range",
            }
        })?;
        if request.compact_through.height >= authorization_height {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention target does not precede its authorization anchor",
                },
            );
        }
        let target_index = usize::try_from(request.compact_through.height)
            .ok()
            .and_then(|height| height.checked_sub(1))
            .ok_or(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention target height is not representable",
                },
            )?;
        if view
            .block_hashes()
            .get(target_index)
            .map(|hash| *hash.as_ref())
            != Some(request.compact_through.block_hash)
        {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention target is not the exact committed ancestor",
                },
            );
        }
        let authorization_hash = view
            .latest_block_hash()
            .map(|hash| *hash.as_ref())
            .filter(|hash| *hash != [0; 32])
            .ok_or(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "committed authorization anchor has no block hash",
                },
            )?;
        let authorization_anchor = ReputationFinalizedArchiveKeyV1::try_new(
            self.network_id,
            authorization_height,
            authorization_hash,
        )
        .map_err(Self::archive_error)?;
        let qualification = self
            .archive
            .qualify_against_certified_tip(&view, self.kura.as_ref(), 0)
            .map_err(Self::archive_error)?;
        if qualification.archive_tip() != &authorization_anchor {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "fresh committed State and exact archive tip disagree",
                },
            );
        }
        Ok(Some(ReputationRetentionAuthorizationSnapshotV1 {
            request,
            authorization_anchor,
            qualification,
        }))
    }
    fn classify(
        snapshot: &ReputationRetentionAuthorizationSnapshotV1,
    ) -> std::result::Result<
        ReputationRetentionDecisionV1,
        ReputationFinalizedArchiveRetentionControlErrorV1,
    > {
        classify_retention_request(
            &snapshot.request,
            &snapshot.authorization_anchor,
            snapshot.qualification.activation_floor(),
            snapshot.qualification.checkpoint_digest(),
        )
    }
}
fn classify_retention_request(
    request: &ReputationFinalizedArchiveRetentionRequestV1,
    authorization_anchor: &ReputationFinalizedArchiveKeyV1,
    activation_floor: &ReputationFinalizedArchiveKeyV1,
    checkpoint_digest: Option<[u8; 32]>,
) -> std::result::Result<
    ReputationRetentionDecisionV1,
    ReputationFinalizedArchiveRetentionControlErrorV1,
> {
    if request.network_id != authorization_anchor.network_id
        || request.compact_through.height >= authorization_anchor.height
    {
        return Err(
            ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                reason: "retention target is not below its exact authorization anchor",
            },
        );
    }
    let target = ReputationFinalizedArchiveKeyV1::try_new(
        request.network_id,
        request.compact_through.height,
        request.compact_through.block_hash,
    )
    .map_err(ReputationFinalizedArchiveRetentionControllerV1::archive_error)?;
    if activation_floor.network_id != target.network_id {
        return Err(
            ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                reason: "retention activation floor is bound to another chain",
            },
        );
    }
    if checkpoint_digest.is_some() && activation_floor.height >= target.height {
        if activation_floor.height == target.height
            && activation_floor.block_hash != target.block_hash
        {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention checkpoint conflicts with the requested exact target",
                },
            );
        }
        return Ok(ReputationRetentionDecisionV1::AlreadyApplied(
            *activation_floor,
        ));
    }
    if activation_floor.height > target.height {
        return Err(
            ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                reason: "retention target predates the archive activation floor",
            },
        );
    }
    Ok(ReputationRetentionDecisionV1::Apply(target))
}
impl ReputationFinalizedArchiveRetentionControlV1
    for ReputationFinalizedArchiveRetentionControllerV1
{
    fn revalidate(
        &self,
    ) -> std::result::Result<(), ReputationFinalizedArchiveRetentionControlErrorV1> {
        self.revalidate_authority()
    }
    fn reconcile_once(
        &self,
    ) -> std::result::Result<
        ReputationFinalizedArchiveRetentionControlOutcomeV1,
        ReputationFinalizedArchiveRetentionControlErrorV1,
    > {
        self.revalidate_authority()?;
        let Some(snapshot) = self.authorization_snapshot()? else {
            return Ok(ReputationFinalizedArchiveRetentionControlOutcomeV1::NoRequest);
        };
        let target = match Self::classify(&snapshot)? {
            ReputationRetentionDecisionV1::Apply(target) => target,
            ReputationRetentionDecisionV1::AlreadyApplied(retention_floor) => {
                return Ok(
                    ReputationFinalizedArchiveRetentionControlOutcomeV1::AlreadyApplied {
                        request_digest: snapshot.request.request_digest,
                        authorization_anchor: snapshot.authorization_anchor,
                        retention_floor,
                    },
                );
            }
        };
        let fence = self
            .archive
            .retention_fence_for(&target)
            .map_err(Self::archive_error)?;
        let proposal = self
            .archive
            .prepare_certified_compaction(&fence, &self.state.query_view(), self.kura.as_ref())
            .map_err(Self::archive_error)?;
        let refreshed = self.authorization_snapshot()?.ok_or(
            ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                reason: "retention authorization was removed before approval",
            },
        )?;
        if refreshed.request != snapshot.request
            || refreshed.authorization_anchor.height < snapshot.authorization_anchor.height
        {
            return Err(
                ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                    reason: "retention authorization changed before approval",
                },
            );
        }
        self.revalidate_authority()?;
        let compaction = self
            .archive
            .approve_and_install_certified_compaction(
                &proposal,
                &self.state.query_view(),
                self.kura.as_ref(),
                &self.binding,
                self.authority.as_ref(),
            )
            .map_err(Self::archive_error)?;
        Ok(
            ReputationFinalizedArchiveRetentionControlOutcomeV1::Applied {
                request_digest: snapshot.request.request_digest,
                authorization_anchor: refreshed.authorization_anchor,
                compaction,
            },
        )
    }
}
impl QualifiedReputationRetentionAuthorityV1 {
    /// Return the exact credential-free expected authority binding.
    pub(crate) const fn binding(&self) -> &ReputationFinalizedArchiveRetentionAuthorityBindingV1 {
        &self.binding
    }
    /// Return the runtime-only deployment-owned authority.
    pub(crate) const fn authority(
        &self,
    ) -> &Arc<dyn ReputationFinalizedArchiveRetentionAuthorityV1> {
        &self.authority
    }
    fn revalidate(&self) -> Result<(), ReputationFinalizedArchiveStartupErrorV1> {
        let handle_before = self.authority.handle();
        let qualification = self.authority.qualification().map_err(|_| {
            ReputationFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                reason: "retention authority became unavailable during startup",
            }
        })?;
        let handle_after = self.authority.handle();
        if handle_before != self.binding.handle()
            || handle_after != handle_before
            || qualification != self.binding.qualification()
        {
            return Err(
                ReputationFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                    reason: "retention authority became substituted or stale during startup",
                },
            );
        }
        Ok(())
    }
}
/// Cloneable fail-closed activation probe for deferred reputation assembly.
#[derive(Clone)]
pub(crate) struct ReputationFinalizedArchiveActivationV1 {
    network_id: NetworkId,
    archive: Arc<ReputationFinalizedArchive>,
    state: Arc<State>,
    kura: Arc<Kura>,
    maximum_kura_tip_lag_blocks: u64,
    gate: ArchiveActivationGateV1,
}
impl fmt::Debug for ReputationFinalizedArchiveActivationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReputationFinalizedArchiveActivationV1")
            .field("network_id", &self.network_id)
            .field("archive_root", &self.archive.root())
            .field(
                "maximum_kura_tip_lag_blocks",
                &self.maximum_kura_tip_lag_blocks,
            )
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}
impl ReputationFinalizedArchiveActivationV1 {
    /// Qualify one current committed State view before allowing runtime activation.
    ///
    /// Empty bootstrap waits for genesis; every nonempty archive must authenticate its exact
    /// retained coverage through the current certified chain before it becomes visible.
    pub(crate) fn activation_ready(&self) -> Result<bool, ReputationFinalizedArchiveError> {
        let view = self.state.query_view();
        if !std::ptr::eq(view.kura(), self.kura.as_ref()) || view.network_id() != &self.network_id {
            return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
                reason: "reputation activation State has a substituted network or Kura binding",
            });
        }
        if self.gate == ArchiveActivationGateV1::AwaitingGenesis && view.height() == 0 {
            if self.archive.is_empty()? {
                return Ok(false);
            }
            return Err(ReputationFinalizedArchiveError::ArchiveUnavailable {
                reason: "uncommitted bootstrap has a nonempty reputation archive",
            });
        }
        let qualification = self.archive.qualify_against_certified_tip(
            &view,
            self.kura.as_ref(),
            self.maximum_kura_tip_lag_blocks,
        )?;
        if u64::try_from(view.height()).ok() != Some(qualification.archive_tip().height) {
            return Ok(false);
        }
        if view.latest_block_hash().map(|hash| *hash.as_ref())
            != Some(qualification.archive_tip().block_hash)
        {
            return Err(ReputationFinalizedArchiveError::FinalityAuthentication {
                reason: "reputation activation State and archive tips disagree",
            });
        }
        Ok(true)
    }
}
type ArchiveStartupResultV1<T> = std::result::Result<T, ReputationFinalizedArchiveStartupErrorV1>;
struct AuthenticatedArchiveStartupV1<'state> {
    state_view: StateQueryView<'state>,
    boundary: ArchiveStartupBoundaryV1,
}
fn archive_startup_error(
    stage: &'static str,
    source: ReputationFinalizedArchiveError,
) -> ReputationFinalizedArchiveStartupErrorV1 {
    ReputationFinalizedArchiveStartupErrorV1::Archive {
        stage,
        source: Box::new(source),
    }
}
fn open_reputation_finalized_archive(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    state_ro: &impl iroha_core::state::StateReadOnly,
    kura: &Kura,
    authority: Option<Arc<dyn ReputationFinalizedArchiveRetentionAuthorityV1>>,
) -> ArchiveStartupResultV1<(
    Arc<ReputationFinalizedArchive>,
    Option<QualifiedReputationRetentionAuthorityV1>,
)> {
    let bounds = ReputationFinalizedArchiveBounds::try_new(
        config.finalized_archive_max_record_bytes,
        config.finalized_archive_max_entries,
        config.finalized_archive_max_total_bytes,
    )
    .map_err(|source| archive_startup_error("resource-bound validation", source))?;
    let (archive, qualified_authority) = match (
        &config.finalized_archive_retention_authority,
        authority,
    ) {
        (None, None) => (
            ReputationFinalizedArchive::try_open(&config.finalized_archive_root, bounds),
            None,
        ),
        (Some(expected), Some(authority)) => {
            let binding = ReputationFinalizedArchiveRetentionAuthorityBindingV1::try_new(
                expected.handle.clone(),
                expected.revision,
                expected.policy_digest,
            )
            .map_err(|source| {
                archive_startup_error("retention-authority binding validation", source)
            })?;
            let archive = ReputationFinalizedArchive::try_open_with_retention_authority(
                &config.finalized_archive_root,
                bounds,
                network_id,
                state_ro,
                kura,
                &binding,
                authority.as_ref(),
            );
            (
                archive,
                Some(QualifiedReputationRetentionAuthorityV1 { binding, authority }),
            )
        }
        (Some(_), None) => {
            return Err(
                ReputationFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                    reason: "enabled retention requires its deployment-owned sealed CAS authority",
                },
            );
        }
        (None, Some(_)) => {
            return Err(
                ReputationFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                    reason: "manual retention mode rejects an unexpected runtime authority",
                },
            );
        }
    };
    archive
        .map(Arc::new)
        .map(|archive| (archive, qualified_authority))
        .map_err(|source| archive_startup_error("durable open and retention recovery", source))
}
fn authenticate_archive_startup<'state>(
    state: &'state State,
    kura: &Kura,
) -> ArchiveStartupResultV1<AuthenticatedArchiveStartupV1<'state>> {
    let state_view = state.query_view();
    if !std::ptr::eq(state_view.kura(), kura) {
        return Err(ReputationFinalizedArchiveStartupErrorV1::StartupBoundary {
            reason: "State is bound to a substituted Kura instance",
        });
    }
    let state_height = u64::try_from(state_view.height()).map_err(|_| {
        ReputationFinalizedArchiveStartupErrorV1::StartupBoundary {
            reason: "committed State height exceeds the supported range",
        }
    })?;
    let kura_height = u64::try_from(kura.exact_durable_blocks_count().map_err(|source| {
        ReputationFinalizedArchiveStartupErrorV1::KuraBoundary {
            detail: source.to_string(),
        }
    })?)
    .map_err(
        |_| ReputationFinalizedArchiveStartupErrorV1::StartupBoundary {
            reason: "durable Kura height exceeds the supported range",
        },
    )?;
    let boundary = classify_archive_startup_boundary(state_height, kura_height)
        .map_err(|reason| ReputationFinalizedArchiveStartupErrorV1::StartupBoundary { reason })?;
    Ok(AuthenticatedArchiveStartupV1 {
        state_view,
        boundary,
    })
}
fn qualify_existing_archive(
    archive: &ReputationFinalizedArchive,
    kura: &Kura,
    startup: &AuthenticatedArchiveStartupV1<'_>,
    maximum_kura_tip_lag_blocks: u64,
) -> ArchiveStartupResultV1<ReputationFinalizedArchiveStartupModeV1> {
    let reconciliation = archive
        .reconcile_certified_state_tip(&startup.state_view, kura)
        .map_err(|source| archive_startup_error("exact Kura-tip reconciliation", source))?;
    let live_qualification = archive
        .qualify_against_certified_tip(&startup.state_view, kura, maximum_kura_tip_lag_blocks)
        .map_err(|source| archive_startup_error("configured live-lag qualification", source))?;
    Ok(ReputationFinalizedArchiveStartupModeV1::Qualified {
        reconciliation,
        live_qualification,
    })
}
fn prepare_archive_startup_mode(
    archive: &ReputationFinalizedArchive,
    kura: &Kura,
    startup: &AuthenticatedArchiveStartupV1<'_>,
    archive_empty: bool,
    maximum_kura_tip_lag_blocks: u64,
) -> ArchiveStartupResultV1<ReputationFinalizedArchiveStartupModeV1> {
    match startup.boundary {
        ArchiveStartupBoundaryV1::Bootstrap => {
            if !archive_empty {
                return Err(ReputationFinalizedArchiveStartupErrorV1::StartupBoundary {
                    reason: "height-zero bootstrap requires a completely empty archive namespace",
                });
            }
            Ok(ReputationFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture)
        }
        ArchiveStartupBoundaryV1::Qualified => {
            qualify_existing_archive(archive, kura, startup, maximum_kura_tip_lag_blocks)
        }
    }
}
/// Open and qualify the deployment-owned reputation archive before consensus.
///
/// The exact Kura-tip reconciliation always uses a zero-gap barrier. Only
/// after it succeeds is the configured live-lag allowance evaluated. An
/// existing nonempty chain may establish an explicit activation floor at its
/// current tip; callers must surface that floor rather than claiming earlier
/// historical coverage. Height-zero startup accepts only a completely empty
/// namespace and defers qualification until genesis capture. Startup requires the recovered
/// committed State height to equal the exact durable Kura height.
///
/// # Errors
///
/// Fails for invalid resource bounds, unsafe durable storage, a substituted
/// State/Kura boundary, nonempty height-zero storage, incomplete
/// archive coverage, or a configured lag violation.
pub(crate) fn prepare_reputation_finalized_archive_v1(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    state: &Arc<State>,
    kura: &Arc<Kura>,
    retention_authority: Option<Arc<dyn ReputationFinalizedArchiveRetentionAuthorityV1>>,
) -> std::result::Result<
    PreparedReputationFinalizedArchiveV1,
    ReputationFinalizedArchiveStartupErrorV1,
> {
    let startup = authenticate_archive_startup(state.as_ref(), kura.as_ref())?;
    if startup.state_view.network_id() != network_id {
        return Err(ReputationFinalizedArchiveStartupErrorV1::StartupBoundary {
            reason: "configured reputation network differs from committed State",
        });
    }
    let (archive, retention_authority) = open_reputation_finalized_archive(
        config,
        network_id,
        &startup.state_view,
        kura.as_ref(),
        retention_authority,
    )?;
    let archive_empty = archive.is_empty().map_err(|source| {
        archive_startup_error("complete bootstrap namespace validation", source)
    })?;
    let startup_mode = prepare_archive_startup_mode(
        archive.as_ref(),
        kura.as_ref(),
        &startup,
        archive_empty,
        config.finalized_archive_max_kura_tip_lag_blocks,
    )?;
    if let Some(authority) = &retention_authority {
        authority.revalidate()?;
    }
    let activation = ReputationFinalizedArchiveActivationV1 {
        network_id: *network_id,
        archive: Arc::clone(&archive),
        state: Arc::clone(state),
        kura: Arc::clone(kura),
        maximum_kura_tip_lag_blocks: config.finalized_archive_max_kura_tip_lag_blocks,
        gate: startup_mode.activation_gate(),
    };
    Ok(PreparedReputationFinalizedArchiveV1 {
        archive,
        startup_mode,
        activation,
        retention_authority,
    })
}
/// Production finalized-query adapter over immutable reputation archive rows.
#[derive(Debug)]
pub struct ArchivedReputationFinalizedQueryV1 {
    handle: String,
    qualification: ReputationRuntimeProviderQualificationV1,
    archive: Arc<ReputationFinalizedArchive>,
}
impl ArchivedReputationFinalizedQueryV1 {
    /// Bind one public runtime identity and qualification to a durable archive.
    ///
    /// This constructor accepts no credentials or signing authority. The
    /// qualification digest must be derived independently from the configured
    /// reputation ingest policy.
    ///
    /// # Errors
    ///
    /// Rejects test-marked or malformed handles, an unsupported provider
    /// revision, a zero policy digest, or an empty archive root.
    pub fn try_new(
        handle: impl Into<String>,
        qualification: ReputationRuntimeProviderQualificationV1,
        archive: Arc<ReputationFinalizedArchive>,
    ) -> Result<Self> {
        let handle = handle.into();
        if !is_production_runtime_handle(&handle) {
            bail!("finalized reputation archive handle is not production-safe");
        }
        if qualification.revision() != REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1
            || qualification.policy_digest() == [0; 32]
        {
            bail!("finalized reputation archive qualification is invalid");
        }
        if archive.root().as_os_str().is_empty() {
            bail!("finalized reputation archive root is not durable");
        }
        Ok(Self {
            handle,
            qualification,
            archive,
        })
    }
    fn ensure_at_or_above_activation_floor(
        &self,
        network_id: &NetworkId,
        height: u64,
    ) -> ExternalResult<()> {
        if self
            .archive
            .activation_floor(network_id)
            .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?
            .is_some_and(|floor| height < floor.height)
        {
            return Err(external_failure(FAILURE_BELOW_ACTIVATION_FLOOR));
        }
        Ok(())
    }
    fn select_at_or_before(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> ExternalResult<ReputationFinalizedProjectionV1> {
        if network_id.as_bytes()[31] & 1 != 1 || maximum_height == 0 {
            return Err(external_failure(FAILURE_INVALID_REQUEST));
        }
        self.ensure_at_or_above_activation_floor(network_id, maximum_height)?;
        self.archive
            .latest_at_or_before(network_id, maximum_height)
            .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?
            .ok_or_else(|| external_failure(FAILURE_MISSING_ANCHOR))
    }
    fn select_delivery_at_or_before(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> ExternalResult<(ReputationFinalizedProjectionV1, Vec<AuthorityPolicyRecord>)> {
        if network_id.as_bytes()[31] & 1 != 1 || maximum_height == 0 {
            return Err(external_failure(FAILURE_INVALID_REQUEST));
        }
        self.ensure_at_or_above_activation_floor(network_id, maximum_height)?;
        self.archive
            .latest_at_or_before_with_policy_history(network_id, maximum_height)
            .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?
            .ok_or_else(|| external_failure(FAILURE_MISSING_ANCHOR))
    }
    fn load_exact(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
    ) -> ExternalResult<ReputationFinalizedProjectionV1> {
        if anchor.network_id.as_bytes()[31] & 1 != 1
            || anchor.identity.height == 0
            || anchor.identity.block_hash == [0; 32]
            || anchor.finalized_at_unix_ms == 0
            || anchor.finalized_at_unix_ms == u64::MAX
        {
            return Err(external_failure(FAILURE_INVALID_REQUEST));
        }
        let key = ReputationFinalizedArchiveKeyV1::try_new(
            anchor.network_id,
            anchor.identity.height,
            anchor.identity.block_hash,
        )
        .map_err(|_| external_failure(FAILURE_INVALID_REQUEST))?;
        self.ensure_at_or_above_activation_floor(&anchor.network_id, key.height)?;
        let projection = self
            .archive
            .get_exact(&key)
            .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?
            .ok_or_else(|| external_failure(FAILURE_MISSING_ANCHOR))?;
        if projection.finalized_at_unix_ms != anchor.finalized_at_unix_ms {
            return Err(external_failure(FAILURE_ANCHOR_MISMATCH));
        }
        Ok(projection)
    }
    fn journal_page_from_projection(
        projection: &ReputationFinalizedProjectionV1,
        after: Option<ReputationJournalFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<ReputationJournalFinalizedEventPageV1> {
        let finalized_cursor = ReputationJournalFinalizedCursorV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
            finalized_at_unix_ms: projection.finalized_at_unix_ms,
        };
        let page = materialize_bounded_page(
            &projection.journal_events,
            after,
            limit,
            REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1,
            REPUTATION_JOURNAL_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            ReputationJournalFinalizedEventV1::cursor,
            |events, has_more, next_after| ReputationJournalFinalizedEventPageV1 {
                finalized_cursor,
                events,
                has_more,
                next_after,
            },
        )?;
        page.validate_after(after)
            .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?;
        Ok(page)
    }
}
impl ReputationRuntimeProviderV1 for ArchivedReputationFinalizedQueryV1 {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(&self) -> ExternalResult<ReputationRuntimeProviderQualificationV1> {
        // Provider identity readiness is valid before genesis capture, but it
        // still rescans the complete empty namespace. Once any record exists,
        // require a synchronized nonempty generation. Data reads and runtime
        // activation remain unavailable until exact Kura-tip qualification.
        let empty = self
            .archive
            .is_empty()
            .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?;
        if !empty {
            self.archive
                .health_generation()
                .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?;
        }
        Ok(self.qualification)
    }
}
impl ReputationFinalizedQueryV1 for ArchivedReputationFinalizedQueryV1 {
    fn finalized_at_or_before(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
    ) -> ExternalResult<ReputationFinalizedAnchorV1> {
        let projection = self.select_at_or_before(network_id, maximum_height)?;
        Ok(anchor_from_projection(&projection))
    }
    fn reputation_journal_delivery_view(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
        _policy_query: FindSorafsReputationJournalAuthorityPolicy,
        after: Option<ReputationJournalFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<ReputationJournalDeliveryFinalizedViewV1> {
        let (projection, authority_policy_history) =
            self.select_delivery_at_or_before(network_id, maximum_height)?;
        let journal_page = Self::journal_page_from_projection(&projection, after, limit)?;
        let view = ReputationJournalDeliveryFinalizedViewV1 {
            anchor: anchor_from_projection(&projection),
            authority_policy_history,
            authority_policy: projection.authority_policy,
            journal_page,
        };
        view.validate_for_request(network_id, after, limit, maximum_height)
            .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?;
        Ok(view)
    }
    fn reputation_journal_event_by_source_id(
        &self,
        network_id: &NetworkId,
        maximum_height: u64,
        query: FindSorafsReputationJournalEventBySourceId,
    ) -> ExternalResult<ReputationJournalSourceFinalizedViewV1> {
        if network_id.as_bytes()[31] & 1 != 1
            || maximum_height == 0
            || query.source_id() == ReputationJournalSourceIdV1::ZERO
        {
            return Err(external_failure(FAILURE_INVALID_REQUEST));
        }
        let source_view = if let Some(cursor) = query.expected_finalized_cursor() {
            cursor
                .validate()
                .map_err(|_| external_failure(FAILURE_INVALID_REQUEST))?;
            if cursor.height > maximum_height {
                return Err(external_failure(FAILURE_PAGE_BOUNDS));
            }
            self.ensure_at_or_above_activation_floor(network_id, cursor.height)?;
            let key = ReputationFinalizedArchiveKeyV1::try_new(
                *network_id,
                cursor.height,
                cursor.block_hash,
            )
            .map_err(|_| external_failure(FAILURE_INVALID_REQUEST))?;
            let source_view = self
                .archive
                .journal_event_by_source_at_exact(&key, query.source_id())
                .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?
                .ok_or_else(|| external_failure(FAILURE_MISSING_ANCHOR))?;
            if source_view.finalized_at_unix_ms != cursor.finalized_at_unix_ms {
                return Err(external_failure(FAILURE_ANCHOR_MISMATCH));
            }
            source_view
        } else {
            self.ensure_at_or_above_activation_floor(network_id, maximum_height)?;
            self.archive
                .latest_journal_event_by_source_at_or_before(
                    network_id,
                    maximum_height,
                    query.source_id(),
                )
                .map_err(|_| external_failure(FAILURE_ARCHIVE_READ))?
                .ok_or_else(|| external_failure(FAILURE_MISSING_ANCHOR))?
        };
        let view = ReputationJournalSourceFinalizedViewV1 {
            anchor: ReputationFinalizedAnchorV1 {
                network_id: source_view.key.network_id,
                identity: ReputationFinalizedIdentityV1 {
                    height: source_view.key.height,
                    block_hash: source_view.key.block_hash,
                },
                finalized_at_unix_ms: source_view.finalized_at_unix_ms,
            },
            event: source_view.event,
        };
        view.validate_for_request(network_id, maximum_height, query)
            .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?;
        Ok(view)
    }
    fn proof_outcome_page(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
        after: Option<ProofOutcomeFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<ProofOutcomeFinalizedEventPageV1> {
        let projection = self.load_exact(anchor)?;
        let finalized_cursor = ProofOutcomeFinalizedCursorV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
        };
        materialize_bounded_page(
            &projection.proof_outcomes,
            after,
            limit,
            PROOF_OUTCOME_QUERY_MAX_ITEMS_V1,
            PROOF_OUTCOME_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            ProofOutcomeFinalizedEventV1::cursor,
            |events, has_more, next_after| ProofOutcomeFinalizedEventPageV1 {
                finalized_cursor,
                events,
                has_more,
                next_after,
            },
        )
    }
    fn reputation_journal_page(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
        after: Option<ReputationJournalFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<ReputationJournalFinalizedEventPageV1> {
        let projection = self.load_exact(anchor)?;
        Self::journal_page_from_projection(&projection, after, limit)
    }
    fn repair_page(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
        after: Option<RepairFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<RepairFinalizedEventPageV1> {
        let projection = self.load_exact(anchor)?;
        let finalized_cursor = RepairFinalizedCursorV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
        };
        materialize_bounded_page(
            &projection.repair_events,
            after,
            limit,
            usize::try_from(REPAIR_QUERY_MAX_ITEMS_V1)
                .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?,
            REPAIR_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            RepairFinalizedEventV1::cursor,
            |events, has_more, next_after| RepairFinalizedEventPageV1 {
                finalized_cursor,
                events,
                has_more,
                next_after,
            },
        )
    }
    fn orderbook_page(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
        after: Option<OrderbookFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<OrderbookFinalizedEventPageV1> {
        let projection = self.load_exact(anchor)?;
        let finalized_cursor = OrderbookFinalizedCursorV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
        };
        materialize_bounded_page(
            &projection.orderbook_events,
            after,
            limit,
            usize::try_from(ORDERBOOK_QUERY_MAX_ITEMS_V1)
                .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?,
            ORDERBOOK_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            OrderbookFinalizedEventV1::cursor,
            |events, has_more, next_after| OrderbookFinalizedEventPageV1 {
                finalized_cursor,
                events,
                has_more,
                next_after,
            },
        )
    }
    fn reserve_page(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
        after: Option<ReserveFinalizedEventCursorV1>,
        limit: u32,
    ) -> ExternalResult<ReserveFinalizedEventPageV1> {
        let projection = self.load_exact(anchor)?;
        let finalized_cursor = ReserveFinalizedCursorV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
        };
        materialize_bounded_page(
            &projection.reserve_events,
            after,
            limit,
            usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1)
                .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?,
            RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            ReserveFinalizedEventV1::cursor,
            |events, has_more, next_after| ReserveFinalizedEventPageV1 {
                finalized_cursor,
                events,
                has_more,
                next_after,
            },
        )
    }
    fn reserve_provider_page(
        &self,
        anchor: &ReputationFinalizedAnchorV1,
        after_provider_id: Option<ProviderId>,
        limit: u32,
    ) -> ExternalResult<ReserveProviderAccountPageV1> {
        let projection = self.load_exact(anchor)?;
        let finalized_cursor = ReserveFinalizedCursorV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
        };
        materialize_bounded_page(
            &projection.reserve_providers,
            after_provider_id,
            limit,
            usize::try_from(RESERVE_QUERY_MAX_ITEMS_V1)
                .map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?,
            RESERVE_QUERY_MAX_EVENT_PAGE_BYTES_V1,
            |account| account.terms.provider_id,
            |accounts, has_more, next_after| ReserveProviderAccountPageV1 {
                finalized_cursor,
                accounts,
                has_more,
                next_after,
            },
        )
    }
}
type ExternalResult<T> = std::result::Result<T, ReputationExternalFailureV1>;
fn anchor_from_projection(
    projection: &ReputationFinalizedProjectionV1,
) -> ReputationFinalizedAnchorV1 {
    ReputationFinalizedAnchorV1 {
        network_id: projection.key.network_id,
        identity: ReputationFinalizedIdentityV1 {
            height: projection.key.height,
            block_hash: projection.key.block_hash,
        },
        finalized_at_unix_ms: projection.finalized_at_unix_ms,
    }
}
fn materialize_bounded_page<T, C, P>(
    all: &[T],
    after: Option<C>,
    limit: u32,
    maximum_items: usize,
    maximum_encoded_bytes: usize,
    cursor: impl Fn(&T) -> C,
    build: impl Fn(Vec<T>, bool, Option<C>) -> P,
) -> ExternalResult<P>
where
    T: Clone,
    C: Copy + Eq,
    P: NoritoSerialize,
{
    let limit = usize::try_from(limit).map_err(|_| external_failure(FAILURE_INVALID_LIMIT))?;
    if limit == 0 || limit > maximum_items {
        return Err(external_failure(FAILURE_INVALID_LIMIT));
    }
    let start = if let Some(after) = after {
        all.iter()
            .position(|item| cursor(item) == after)
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| external_failure(FAILURE_INVALID_CURSOR))?
    } else {
        0
    };
    let maximum_end = start.saturating_add(limit).min(all.len());
    let minimum_end = if start < maximum_end {
        start.saturating_add(1)
    } else {
        start
    };
    let maximum_rows = all[start..maximum_end].to_vec();
    let maximum_has_more = maximum_end < all.len();
    let maximum_next_after = maximum_has_more.then(|| {
        cursor(
            maximum_rows
                .last()
                .expect("a positive page limit produces a row when more rows remain"),
        )
    });
    let maximum_page = build(maximum_rows, maximum_has_more, maximum_next_after);
    let maximum_encoded =
        norito::to_bytes(&maximum_page).map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?;
    if maximum_encoded.len() <= maximum_encoded_bytes {
        return Ok(maximum_page);
    }
    if minimum_end == maximum_end {
        return Err(external_failure(FAILURE_PAGE_BOUNDS));
    }
    let mut lower = minimum_end;
    let mut upper = maximum_end - 1;
    let mut best = None;
    while lower <= upper {
        let end = lower.saturating_add(upper.saturating_sub(lower) / 2);
        let rows = all[start..end].to_vec();
        let has_more = end < all.len();
        let next_after = has_more.then(|| {
            cursor(
                rows.last()
                    .expect("a positive page limit produces a row when more rows remain"),
            )
        });
        let page = build(rows, has_more, next_after);
        let encoded = norito::to_bytes(&page).map_err(|_| external_failure(FAILURE_PAGE_BOUNDS))?;
        if encoded.len() <= maximum_encoded_bytes {
            best = Some(page);
            lower = end + 1;
        } else {
            upper = end - 1;
        }
    }
    best.ok_or_else(|| external_failure(FAILURE_PAGE_BOUNDS))
}
fn external_failure(marker: u8) -> ReputationExternalFailureV1 {
    ReputationExternalFailureV1::try_new([marker; 32])
        .expect("fixed finalized-query failure markers are non-zero")
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::base::util::Bytes;
    use iroha_core::{
        query::{
            reputation_finalized::ReputationFinalizedArchiveInsertOutcome, store::LiveQueryStore,
        },
        state::World,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        sorafs::reputation::{
            PorTerminalOutcomeV1, PorTerminalStatusV1,
            REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            ReputationFinalizedArchiveRetentionTargetV1, ReputationJournalAuthorityPolicyRecordV1,
            ReputationJournalAuthorityPolicyV1, ReputationJournalEntryV1,
            ReputationJournalPayloadV1,
        },
    };
    use std::path::PathBuf;
    use tempfile::TempDir;
    const FINALIZED_AT_MS: u64 = 1_800_000_010_000;
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(Hash::new(
                vec![seed; 32],
            )),
        )
    }
    fn runtime_config(root: PathBuf) -> SorafsReputationRuntime {
        SorafsReputationRuntime {
            state_dir: root.with_extension("state"),
            finalized_archive_root: root,
            finalized_archive_max_record_bytes: 4 * 1024 * 1024,
            finalized_archive_max_entries: 32,
            finalized_archive_max_total_bytes: 64 * 1024 * 1024,
            finalized_archive_max_kura_tip_lag_blocks: 0,
            finalized_archive_retention_authority: None,
            window_start_height: 1,
            window_end_height: 10,
            finalized_query_handle: "reputation-archive:region-a".to_owned(),
            journal_checkpoint_provider_handle: "sealed.reputation.journal.region-a".to_owned(),
            journal_checkpoint_provider_revision: 1,
            journal_checkpoint_provider_policy_digest: [0x60; 32],
            journal_transaction_submitter_handle: "reputation-journal:region-a".to_owned(),
            journal_transaction_submitter_revision: 1,
            journal_transaction_submitter_policy_digest: [0x61; 32],
            threshold_signer_handle: "reputation-threshold:region-a".to_owned(),
            threshold_signer_revision: 1,
            threshold_signer_policy_digest: [0x62; 32],
            governance_dag_handle: "reputation-dag:region-a".to_owned(),
            governance_dag_revision: 1,
            governance_dag_policy_digest: [0x63; 32],
            governance_publisher_peer_id: b"12D3KooWReputationPublisher".to_vec(),
            governance_publisher_public_key: [0x73; 32],
            poll_interval: std::time::Duration::from_secs(1),
            page_items: 64,
            max_pages_per_batch: 64,
            max_providers: 1_024,
            max_pending_events: 1_024,
            max_replay_receipts: 4_096,
            max_material_delivery_failures: 32,
            ingest_checkpoint_max_bytes: Bytes(4 * 1024 * 1024),
            publication_checkpoint_max_bytes: Bytes(4 * 1024 * 1024),
            por_success_bps: 2_200,
            pdp_success_bps: 2_000,
            potr_success_bps: 1_800,
            latency_bps: 1_500,
            dispute_bps: 1_000,
            token_violation_bps: 500,
            repair_breach_bps: 1_000,
        }
    }
    fn retention_request(
        target_height: u64,
        target_hash: [u8; 32],
    ) -> ReputationFinalizedArchiveRetentionRequestV1 {
        ReputationFinalizedArchiveRetentionRequestV1::try_new(
            network_id(0x61),
            1,
            None,
            ReputationFinalizedArchiveRetentionTargetV1::try_new(target_height, target_hash)
                .expect("valid target"),
        )
        .expect("valid request")
    }
    fn archive_key(height: u64, block_hash: [u8; 32]) -> ReputationFinalizedArchiveKeyV1 {
        ReputationFinalizedArchiveKeyV1::try_new(network_id(0x61), height, block_hash)
            .expect("valid archive key")
    }
    #[test]
    fn explicit_retention_classification_is_fresh_monotonic_and_idempotent() {
        let request = retention_request(7, [0x71; 32]);
        let authorization = archive_key(8, [0x81; 32]);
        let physical_floor = archive_key(1, [0x11; 32]);
        assert_eq!(
            classify_retention_request(&request, &authorization, &physical_floor, None,)
                .expect("physical target remains actionable"),
            ReputationRetentionDecisionV1::Apply(archive_key(7, [0x71; 32]))
        );
        let checkpoint_floor = archive_key(7, [0x71; 32]);
        assert_eq!(
            classify_retention_request(
                &request,
                &authorization,
                &checkpoint_floor,
                Some([0xC1; 32]),
            )
            .expect("exact checkpoint is idempotent"),
            ReputationRetentionDecisionV1::AlreadyApplied(checkpoint_floor)
        );
        assert!(matches!(
            classify_retention_request(
                &request,
                &authorization,
                &archive_key(7, [0x72; 32]),
                Some([0xC2; 32]),
            ),
            Err(ReputationFinalizedArchiveRetentionControlErrorV1::Boundary { .. })
        ));
        assert!(matches!(
            classify_retention_request(
                &request,
                &archive_key(7, [0x73; 32]),
                &physical_floor,
                None,
            ),
            Err(ReputationFinalizedArchiveRetentionControlErrorV1::Boundary { .. })
        ));
        assert!(matches!(
            classify_retention_request(&request, &authorization, &archive_key(9, [0x91; 32]), None,),
            Err(ReputationFinalizedArchiveRetentionControlErrorV1::Boundary { .. })
        ));
    }
    #[test]
    fn enabled_retention_fails_before_open_without_injected_authority() {
        let directory = TempDir::new().expect("create archive directory");
        let root = std::fs::canonicalize(directory.path())
            .expect("canonicalize archive directory")
            .join("archive");
        let mut config = runtime_config(root);
        config.finalized_archive_retention_authority = Some(
            iroha_config::parameters::actual::SorafsReputationFinalizedArchiveRetentionAuthority {
                handle: "sealed.reputation.archive.primary".to_owned(),
                revision: 7,
                policy_digest: [0xA7; 32],
            },
        );
        let kura = Kura::blank_kura_for_testing();
        let network_id = network_id(0x63);
        assert!(matches!(
            open_reputation_finalized_archive(
                &config,
                &network_id,
                &State::new_with_chain_and_network_id_for_testing(
                    World::default(),
                    Arc::clone(&kura),
                    LiveQueryStore::start_test(),
                    iroha_model_base::chain::ChainId::from("reputation-retention-test"),
                    network_id
                )
                .query_view(),
                kura.as_ref(),
                None,
            ),
            Err(ReputationFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration { .. })
        ));
    }
    #[test]
    fn fresh_height_zero_opens_empty_archive_for_genesis_capture() {
        let directory = TempDir::new().expect("create archive directory");
        let root = std::fs::canonicalize(directory.path())
            .expect("canonicalize archive directory")
            .join("archive");
        let config = runtime_config(root);
        let kura = Kura::blank_kura_for_testing();
        let network_id = network_id(0x64);
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            World::default(),
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            iroha_model_base::chain::ChainId::from("reputation-finalized-query-test"),
            network_id,
        ));
        let prepared =
            prepare_reputation_finalized_archive_v1(&config, &network_id, &state, &kura, None)
                .expect("fresh empty archive must await genesis capture");
        assert!(matches!(
            prepared.startup_mode(),
            ReputationFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture
        ));
        assert!(prepared.archive().is_empty().expect("empty archive"));
        assert!(
            !prepared
                .activation()
                .activation_ready()
                .expect("bootstrap activation gate"),
            "identity readiness must not pretend genesis is already captured"
        );
    }
    #[test]
    fn fresh_height_zero_rejects_archive_for_another_chain() {
        let directory = TempDir::new().expect("create archive directory");
        let root = std::fs::canonicalize(directory.path())
            .expect("canonicalize archive directory")
            .join("archive");
        let config = runtime_config(root.clone());
        let bounds = ReputationFinalizedArchiveBounds::try_new(
            config.finalized_archive_max_record_bytes,
            config.finalized_archive_max_entries,
            config.finalized_archive_max_total_bytes,
        )
        .expect("archive bounds");
        {
            let archive =
                ReputationFinalizedArchive::try_open(&root, bounds).expect("open stale archive");
            archive
                .insert(projection(1, [0x71; 32], Vec::new()))
                .expect("insert stale anchor");
        }
        let kura = Kura::blank_kura_for_testing();
        let network_id = network_id(0x65);
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            World::default(),
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            iroha_model_base::chain::ChainId::from("reputation-finalized-query-test"),
            network_id,
        ));
        let error =
            prepare_reputation_finalized_archive_v1(&config, &network_id, &state, &kura, None)
                .expect_err("height-zero startup must reject any retained archive namespace");
        assert!(matches!(
            error,
            ReputationFinalizedArchiveStartupErrorV1::StartupBoundary { .. }
        ));
    }
    #[test]
    fn startup_requires_exact_recovered_certified_boundary() {
        assert_eq!(
            classify_archive_startup_boundary(0, 0),
            Ok(ArchiveStartupBoundaryV1::Bootstrap)
        );
        assert_eq!(
            classify_archive_startup_boundary(8, 8),
            Ok(ArchiveStartupBoundaryV1::Qualified)
        );
        assert!(classify_archive_startup_boundary(7, 8).is_err());
        assert!(classify_archive_startup_boundary(8, 7).is_err());
        assert!(classify_archive_startup_boundary(0, 1).is_err());
        assert_eq!(
            ReputationFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture
                .activation_gate(),
            ArchiveActivationGateV1::AwaitingGenesis
        );
    }
    fn account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed.max(1); 32], Algorithm::Ed25519)
            .expect("derive deterministic account");
        AccountId::new(keypair.public_key().clone())
    }
    fn authority_policy() -> ReputationJournalAuthorityPolicyV1 {
        ReputationJournalAuthorityPolicyV1 {
            version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: account(1),
            dispute_recorder_authority: account(2),
            token_recorder_authority: account(3),
            stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
            max_source_age_ms: 86_400_000,
        }
    }
    fn authority_record() -> ReputationJournalAuthorityPolicyRecordV1 {
        ReputationJournalAuthorityPolicyRecordV1::try_new(authority_policy(),
(account(4)).clone(),
FINALIZED_AT_MS - 1_000,
iroha_data_model::sorafs::reputation::ReputationJournalPolicyOriginV1::Network(
    iroha_data_model::sorafs::stream_token_gateway::native::StreamTokenGatewayExecutionV1 {
        height: 2, transaction_hash: [0x61; 32], entry_index: 0, instruction_index: 0,
        recorded_at_unix_ms: FINALIZED_AT_MS - 1_000, authority: (account(4)).clone(),
    }))
        .expect("valid authority policy record")
    }
    fn journal_event(
        sequence: u64,
        event_index: u32,
        marker: u8,
        height: u64,
        block_hash: [u8; 32],
    ) -> ReputationJournalFinalizedEventV1 {
        let policy = authority_policy();
        let outcome = PorTerminalOutcomeV1 {
            challenge_id: [marker; 32],
            manifest_digest: [0x41; 32],
            epoch_id: 7,
            drand_round: 11,
            forced: false,
            sample_count: 4,
            failed_samples: 0,
            issued_at_unix_ms: FINALIZED_AT_MS - 2_000,
            deadline_at_unix_ms: FINALIZED_AT_MS - 500,
            responded_at_unix_ms: Some(FINALIZED_AT_MS - 750),
            decided_at_unix_ms: FINALIZED_AT_MS - 100,
            proof_digest: Some([marker.wrapping_add(1); 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(17),
            status: PorTerminalStatusV1::Verified,
        };
        let entry = ReputationJournalEntryV1::try_new(
            ProviderId::new([marker; 32]),
            policy
                .canonical_digest()
                .expect("canonical authority policy digest"),
            policy.por_recorder_authority,
            outcome.decided_at_unix_ms,
            None,
            ReputationJournalPayloadV1::PorTerminal(outcome),
        )
        .expect("valid journal entry");
        ReputationJournalFinalizedEventV1 {
            sequence,
            block_height: height,
            block_hash,
            event_index,
            recorded_at_unix_ms: FINALIZED_AT_MS - 50,
            entry,
        }
    }
    fn projection(
        height: u64,
        block_hash: [u8; 32],
        journal_events: Vec<ReputationJournalFinalizedEventV1>,
    ) -> ReputationFinalizedProjectionV1 {
        ReputationFinalizedProjectionV1 {
            key: ReputationFinalizedArchiveKeyV1::try_new(network_id(0x61), height, block_hash)
                .expect("valid archive key"),
            finalized_at_unix_ms: FINALIZED_AT_MS,
            authority_policy: authority_record(),
            proof_outcomes: Vec::new(),
            journal_events,
            repair_events: Vec::new(),
            orderbook_events: Vec::new(),
            reserve_events: Vec::new(),
            reserve_providers: Vec::new(),
        }
    }
    fn qualification() -> ReputationRuntimeProviderQualificationV1 {
        ReputationRuntimeProviderQualificationV1::new(
            REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
            [0xD1; 32],
        )
    }
    fn adapter_with(
        projections: impl IntoIterator<Item = ReputationFinalizedProjectionV1>,
    ) -> (TempDir, ArchivedReputationFinalizedQueryV1) {
        let directory = TempDir::new().expect("create archive directory");
        let bounds =
            ReputationFinalizedArchiveBounds::try_new(4 * 1024 * 1024, 16, 64 * 1024 * 1024)
                .expect("valid archive bounds");
        let root = std::fs::canonicalize(directory.path()).expect("canonicalize archive directory");
        let archive =
            Arc::new(ReputationFinalizedArchive::try_open(root, bounds).expect("open archive"));
        for projection in projections {
            assert_eq!(
                archive.insert(projection).expect("insert projection"),
                ReputationFinalizedArchiveInsertOutcome::Inserted
            );
        }
        let adapter = ArchivedReputationFinalizedQueryV1::try_new(
            "reputation-archive:region-a",
            qualification(),
            archive,
        )
        .expect("construct archived query");
        (directory, adapter)
    }
    fn anchor(height: u64, block_hash: [u8; 32]) -> ReputationFinalizedAnchorV1 {
        ReputationFinalizedAnchorV1 {
            network_id: network_id(0x61),
            identity: ReputationFinalizedIdentityV1 { height, block_hash },
            finalized_at_unix_ms: FINALIZED_AT_MS,
        }
    }
    #[test]
    fn selects_historical_anchor_at_or_before_bound() {
        let (_directory, adapter) = adapter_with([
            projection(7, [0x71; 32], Vec::new()),
            projection(9, [0x91; 32], Vec::new()),
        ]);
        assert_eq!(adapter.handle(), "reputation-archive:region-a");
        assert_eq!(
            adapter.qualification().expect("qualification"),
            qualification()
        );
        assert_eq!(
            adapter
                .finalized_at_or_before(&network_id(0x61), 8)
                .expect("select height seven"),
            anchor(7, [0x71; 32])
        );
        assert_eq!(
            adapter
                .finalized_at_or_before(&network_id(0x61), 9)
                .expect("select height nine"),
            anchor(9, [0x91; 32])
        );
        assert!(
            adapter
                .finalized_at_or_before(&network_id(0x62), 9)
                .is_err()
        );
        assert_eq!(
            adapter
                .finalized_at_or_before(&network_id(0x61), 6)
                .expect_err("request below explicit activation floor")
                .receipt(),
            [FAILURE_BELOW_ACTIVATION_FLOOR; 32]
        );
    }
    #[test]
    fn live_qualification_rejects_post_start_archive_corruption() {
        let exact = projection(7, [0x71; 32], Vec::new());
        let (_directory, adapter) = adapter_with([exact.clone()]);
        assert_eq!(
            adapter.qualification().expect("healthy qualification"),
            qualification()
        );
        let path = adapter
            .archive
            .record_path(&exact.key)
            .expect("derive archive record path");
        let mut bytes = std::fs::read(&path).expect("read archive record");
        let last = bytes.last_mut().expect("archive record is non-empty");
        *last ^= 0xFF;
        std::fs::write(path, bytes).expect("corrupt archive record");
        assert!(
            adapter.qualification().is_err(),
            "live qualification must rescan the durable generation"
        );
    }
    #[test]
    fn journal_cursor_and_delivery_view_remain_on_one_archive_row() {
        let block_hash = [0x91; 32];
        let first = journal_event(1, 0, 0x21, 9, block_hash);
        let second = journal_event(2, 1, 0x22, 9, block_hash);
        let (_directory, adapter) = adapter_with([projection(
            9,
            block_hash,
            vec![first.clone(), second.clone()],
        )]);
        let exact_anchor = anchor(9, block_hash);
        let first_page = adapter
            .reputation_journal_page(&exact_anchor, None, 1)
            .expect("first journal page");
        assert_eq!(first_page.events, vec![first.clone()]);
        assert!(first_page.has_more);
        assert_eq!(first_page.next_after, Some(first.cursor()));
        let second_page = adapter
            .reputation_journal_page(&exact_anchor, first_page.next_after, 1)
            .expect("second journal page");
        assert_eq!(second_page.events, vec![second.clone()]);
        assert!(!second_page.has_more);
        assert_eq!(second_page.next_after, None);
        let delivery = adapter
            .reputation_journal_delivery_view(
                &network_id(0x61),
                9,
                FindSorafsReputationJournalAuthorityPolicy,
                Some(first.cursor()),
                1,
            )
            .expect("single-row policy and journal view");
        delivery
            .validate_for_request(&network_id(0x61), Some(first.cursor()), 1, 9)
            .expect("adapter returns a coherently revalidated delivery view");
        assert_eq!(delivery.anchor, exact_anchor);
        assert_eq!(delivery.authority_policy, authority_record());
        assert_eq!(delivery.authority_policy_history, vec![authority_record()]);
        assert_eq!(delivery.journal_page.events, vec![second.clone()]);
        let finalized_cursor = ReputationJournalFinalizedCursorV1 {
            height: exact_anchor.identity.height,
            block_hash: exact_anchor.identity.block_hash,
            finalized_at_unix_ms: exact_anchor.finalized_at_unix_ms,
        };
        let source_query = FindSorafsReputationJournalEventBySourceId::new(
            second.entry.source_id,
            Some(finalized_cursor),
        );
        let source = adapter
            .reputation_journal_event_by_source_id(&network_id(0x61), 9, source_query)
            .expect("source-indexed immutable view");
        source
            .validate_for_request(&network_id(0x61), 9, source_query)
            .expect("source response matches request");
        assert_eq!(source.anchor, exact_anchor);
        assert_eq!(source.event, Some(second));
        let absent_query = FindSorafsReputationJournalEventBySourceId::new(
            iroha_data_model::sorafs::reputation::ReputationJournalSourceIdV1::for_por_challenge(
                [0xFE; 32],
            ),
            None,
        );
        let absent = adapter
            .reputation_journal_event_by_source_id(&network_id(0x61), 9, absent_query)
            .expect("complete archive proves source absence");
        assert_eq!(absent.event, None);
        let mut stale_cursor = first.cursor();
        stale_cursor.block_hash = [0x92; 32];
        assert!(
            adapter
                .reputation_journal_page(&exact_anchor, Some(stale_cursor), 1)
                .is_err()
        );
    }
    #[test]
    fn source_query_expected_cursor_selects_exact_historical_archive_row() {
        let historical_hash = [0x81; 32];
        let latest_hash = [0x91; 32];
        let historical_event = journal_event(1, 0, 0x31, 8, historical_hash);
        let latest_event = journal_event(2, 0, 0x32, 9, latest_hash);
        let (_directory, adapter) = adapter_with([
            projection(8, historical_hash, vec![historical_event.clone()]),
            projection(9, latest_hash, vec![historical_event.clone(), latest_event]),
        ]);
        let historical_cursor = ReputationJournalFinalizedCursorV1 {
            height: 8,
            block_hash: historical_hash,
            finalized_at_unix_ms: FINALIZED_AT_MS,
        };
        let query = FindSorafsReputationJournalEventBySourceId::new(
            historical_event.entry.source_id,
            Some(historical_cursor),
        );
        let view = adapter
            .reputation_journal_event_by_source_id(&network_id(0x61), 9, query)
            .expect("load exact historical source view");
        assert_eq!(view.anchor, anchor(8, historical_hash));
        assert_eq!(view.event, Some(historical_event));
        view.validate_for_request(&network_id(0x61), 9, query)
            .expect("historical response honors the expected cursor");
        let timestamp_substitution = FindSorafsReputationJournalEventBySourceId::new(
            query.source_id(),
            Some(ReputationJournalFinalizedCursorV1 {
                finalized_at_unix_ms: historical_cursor.finalized_at_unix_ms + 1,
                ..historical_cursor
            }),
        );
        assert_eq!(
            adapter
                .reputation_journal_event_by_source_id(
                    &network_id(0x61),
                    9,
                    timestamp_substitution,
                )
                .expect_err("exact archive identity must include finalized time")
                .receipt(),
            [FAILURE_ANCHOR_MISMATCH; 32]
        );
    }
    #[test]
    fn source_query_reports_explicit_activation_floor_before_archive_selection() {
        let floor_hash = [0x71; 32];
        let floor_event = journal_event(1, 0, 0x41, 7, floor_hash);
        let (_directory, adapter) =
            adapter_with([projection(7, floor_hash, vec![floor_event.clone()])]);
        let network_id = network_id(0x61);
        let cursorless =
            FindSorafsReputationJournalEventBySourceId::new(floor_event.entry.source_id, None);
        assert_eq!(
            adapter
                .reputation_journal_event_by_source_id(&network_id, 6, cursorless)
                .expect_err("cursorless source request below activation floor")
                .receipt(),
            [FAILURE_BELOW_ACTIVATION_FLOOR; 32]
        );
        let below_floor_cursor = ReputationJournalFinalizedCursorV1 {
            height: 6,
            block_hash: [0x61; 32],
            finalized_at_unix_ms: FINALIZED_AT_MS - 1,
        };
        let exact_below_floor = FindSorafsReputationJournalEventBySourceId::new(
            floor_event.entry.source_id,
            Some(below_floor_cursor),
        );
        assert_eq!(
            adapter
                .reputation_journal_event_by_source_id(&network_id, 7, exact_below_floor)
                .expect_err("exact source request below activation floor")
                .receipt(),
            [FAILURE_BELOW_ACTIVATION_FLOOR; 32]
        );
        let missing_above_floor = FindSorafsReputationJournalEventBySourceId::new(
            floor_event.entry.source_id,
            Some(ReputationJournalFinalizedCursorV1 {
                height: 8,
                block_hash: [0x81; 32],
                finalized_at_unix_ms: FINALIZED_AT_MS + 1,
            }),
        );
        assert_eq!(
            adapter
                .reputation_journal_event_by_source_id(&network_id, 8, missing_above_floor)
                .expect_err("missing exact source anchor remains distinct from activation floor")
                .receipt(),
            [FAILURE_MISSING_ANCHOR; 32]
        );
        let mismatched_floor_time = FindSorafsReputationJournalEventBySourceId::new(
            floor_event.entry.source_id,
            Some(ReputationJournalFinalizedCursorV1 {
                height: 7,
                block_hash: floor_hash,
                finalized_at_unix_ms: FINALIZED_AT_MS + 1,
            }),
        );
        assert_eq!(
            adapter
                .reputation_journal_event_by_source_id(&network_id, 7, mismatched_floor_time)
                .expect_err("exact source timestamp mismatch remains distinct")
                .receipt(),
            [FAILURE_ANCHOR_MISMATCH; 32]
        );
    }
    #[test]
    fn source_query_preserves_archive_read_failure_receipt() {
        let block_hash = [0x71; 32];
        let event = journal_event(1, 0, 0x45, 7, block_hash);
        let exact = projection(7, block_hash, vec![event.clone()]);
        let key = exact.key;
        let (_directory, adapter) = adapter_with([exact]);
        let path = adapter
            .archive
            .record_path(&key)
            .expect("derive archive record path");
        let mut bytes = std::fs::read(&path).expect("read archive record");
        let last = bytes.last_mut().expect("archive record is non-empty");
        *last ^= 0x01;
        std::fs::write(path, bytes).expect("corrupt archive record");
        let query = FindSorafsReputationJournalEventBySourceId::new(event.entry.source_id, None);
        assert_eq!(
            adapter
                .reputation_journal_event_by_source_id(&network_id(0x61), 7, query)
                .expect_err("corrupt source archive must stay an archive-read failure")
                .receipt(),
            [FAILURE_ARCHIVE_READ; 32]
        );
    }
    #[test]
    fn page_byte_fitting_selects_the_largest_bounded_prefix() {
        let block_hash = [0x91; 32];
        let events = (0_u8..8)
            .map(|offset| {
                journal_event(
                    u64::from(offset) + 1,
                    u32::from(offset),
                    0x20 + offset,
                    9,
                    block_hash,
                )
            })
            .collect::<Vec<_>>();
        let finalized_cursor = ReputationJournalFinalizedCursorV1 {
            height: 9,
            block_hash,
            finalized_at_unix_ms: FINALIZED_AT_MS,
        };
        let three_row_page = ReputationJournalFinalizedEventPageV1 {
            finalized_cursor,
            events: events[..3].to_vec(),
            has_more: true,
            next_after: Some(events[2].cursor()),
        };
        let maximum_bytes = norito::to_bytes(&three_row_page)
            .expect("encode byte-bound fixture")
            .len();
        let page = materialize_bounded_page(
            &events,
            None,
            8,
            8,
            maximum_bytes,
            ReputationJournalFinalizedEventV1::cursor,
            |events, has_more, next_after| ReputationJournalFinalizedEventPageV1 {
                finalized_cursor,
                events,
                has_more,
                next_after,
            },
        )
        .expect("fit largest journal prefix");
        assert_eq!(page.events, events[..3]);
        assert!(page.has_more);
        assert_eq!(page.next_after, Some(events[2].cursor()));
    }
    #[test]
    fn rejects_invalid_page_limits() {
        let block_hash = [0x71; 32];
        let (_directory, adapter) = adapter_with([projection(7, block_hash, Vec::new())]);
        let exact_anchor = anchor(7, block_hash);
        assert!(adapter.proof_outcome_page(&exact_anchor, None, 0).is_err());
        assert!(
            adapter
                .reputation_journal_page(
                    &exact_anchor,
                    None,
                    u32::try_from(REPUTATION_JOURNAL_QUERY_MAX_ITEMS_V1)
                        .expect("journal maximum fits u32")
                        .saturating_add(1),
                )
                .is_err()
        );
        assert!(
            adapter
                .repair_page(
                    &exact_anchor,
                    None,
                    REPAIR_QUERY_MAX_ITEMS_V1.saturating_add(1),
                )
                .is_err()
        );
        assert!(
            adapter
                .orderbook_page(
                    &exact_anchor,
                    None,
                    ORDERBOOK_QUERY_MAX_ITEMS_V1.saturating_add(1),
                )
                .is_err()
        );
        assert!(
            adapter
                .reserve_page(
                    &exact_anchor,
                    None,
                    RESERVE_QUERY_MAX_ITEMS_V1.saturating_add(1),
                )
                .is_err()
        );
        assert!(
            adapter
                .reserve_provider_page(
                    &exact_anchor,
                    None,
                    RESERVE_QUERY_MAX_ITEMS_V1.saturating_add(1),
                )
                .is_err()
        );
    }
    #[test]
    fn rejects_invalid_cursors_and_mismatched_exact_anchors() {
        let block_hash = [0x71; 32];
        let (_directory, adapter) = adapter_with([projection(7, block_hash, Vec::new())]);
        let exact_anchor = anchor(7, block_hash);
        assert!(
            adapter
                .proof_outcome_page(
                    &exact_anchor,
                    Some(ProofOutcomeFinalizedEventCursorV1 {
                        sequence: 1,
                        block_height: 7,
                        block_hash,
                        event_index: 0,
                    }),
                    1,
                )
                .is_err()
        );
        assert!(
            adapter
                .repair_page(
                    &exact_anchor,
                    Some(RepairFinalizedEventCursorV1 {
                        sequence: 1,
                        block_height: 7,
                        block_hash,
                        event_index: 0,
                    }),
                    1,
                )
                .is_err()
        );
        assert!(
            adapter
                .orderbook_page(
                    &exact_anchor,
                    Some(OrderbookFinalizedEventCursorV1 {
                        sequence: 1,
                        block_height: 7,
                        block_hash,
                        event_index: 0,
                    }),
                    1,
                )
                .is_err()
        );
        assert!(
            adapter
                .reserve_page(
                    &exact_anchor,
                    Some(ReserveFinalizedEventCursorV1 {
                        sequence: 1,
                        block_height: 7,
                        block_hash,
                        event_index: 0,
                    }),
                    1,
                )
                .is_err()
        );
        assert!(
            adapter
                .reserve_provider_page(&exact_anchor, Some(ProviderId::new([0x31; 32])), 1,)
                .is_err()
        );
        let mut wrong_hash = exact_anchor.clone();
        wrong_hash.identity.block_hash = [0x72; 32];
        assert!(adapter.proof_outcome_page(&wrong_hash, None, 1).is_err());
        let mut wrong_timestamp = exact_anchor.clone();
        wrong_timestamp.finalized_at_unix_ms += 1;
        assert!(
            adapter
                .proof_outcome_page(&wrong_timestamp, None, 1)
                .is_err()
        );
        let mut wrong_chain = exact_anchor;
        wrong_chain.network_id = network_id(0x62);
        assert!(adapter.proof_outcome_page(&wrong_chain, None, 1).is_err());
    }
    #[test]
    fn empty_pages_are_terminal_and_share_the_exact_anchor() {
        let block_hash = [0x71; 32];
        let (_directory, adapter) = adapter_with([projection(7, block_hash, Vec::new())]);
        let exact_anchor = anchor(7, block_hash);
        let proof = adapter
            .proof_outcome_page(&exact_anchor, None, 1)
            .expect("empty proof page");
        assert!(proof.events.is_empty());
        assert!(!proof.has_more);
        assert_eq!(proof.next_after, None);
        assert_eq!(proof.finalized_cursor.height, 7);
        assert_eq!(proof.finalized_cursor.block_hash, block_hash);
        let journal = adapter
            .reputation_journal_page(&exact_anchor, None, 1)
            .expect("empty journal page");
        assert!(journal.events.is_empty());
        assert!(!journal.has_more);
        assert_eq!(journal.next_after, None);
        assert_eq!(
            journal.finalized_cursor.finalized_at_unix_ms,
            FINALIZED_AT_MS
        );
        let repair = adapter
            .repair_page(&exact_anchor, None, 1)
            .expect("empty repair page");
        assert!(repair.events.is_empty());
        assert!(!repair.has_more);
        assert_eq!(repair.next_after, None);
        let orderbook = adapter
            .orderbook_page(&exact_anchor, None, 1)
            .expect("empty orderbook page");
        assert!(orderbook.events.is_empty());
        assert!(!orderbook.has_more);
        assert_eq!(orderbook.next_after, None);
        let reserve = adapter
            .reserve_page(&exact_anchor, None, 1)
            .expect("empty reserve page");
        assert!(reserve.events.is_empty());
        assert!(!reserve.has_more);
        assert_eq!(reserve.next_after, None);
        let providers = adapter
            .reserve_provider_page(&exact_anchor, None, 1)
            .expect("empty provider page");
        assert!(providers.accounts.is_empty());
        assert!(!providers.has_more);
        assert_eq!(providers.next_after, None);
    }
    #[test]
    fn construction_rejects_test_handles_and_invalid_qualification() {
        let directory = TempDir::new().expect("create archive directory");
        let bounds = ReputationFinalizedArchiveBounds::try_new(1 << 20, 2, 2 << 20)
            .expect("valid archive bounds");
        let root = std::fs::canonicalize(directory.path()).expect("canonicalize archive directory");
        let archive =
            Arc::new(ReputationFinalizedArchive::try_open(root, bounds).expect("open archive"));
        let empty_adapter = ArchivedReputationFinalizedQueryV1::try_new(
            "reputation-archive:region-a",
            qualification(),
            Arc::clone(&archive),
        )
        .expect("construct empty archived query");
        assert_eq!(
            empty_adapter.qualification().expect("identity readiness"),
            qualification(),
            "an empty validated namespace may expose identity readiness"
        );
        assert!(
            empty_adapter
                .finalized_at_or_before(&network_id(0x61), u64::MAX)
                .is_err(),
            "data reads remain unavailable before genesis capture"
        );
        for rejected in [
            "test-adapter",
            "https://operator:secret@reputation.example",
            "https://reputation.example/query?token=secret",
            "https://reputation.example/query#fragment",
            "provider://reputation/dummy/query",
        ] {
            assert!(
                ArchivedReputationFinalizedQueryV1::try_new(
                    rejected,
                    qualification(),
                    Arc::clone(&archive),
                )
                .is_err(),
                "{rejected:?} must fail before archive access"
            );
        }
        assert!(
            ArchivedReputationFinalizedQueryV1::try_new(
                "reputation-archive:region-a",
                ReputationRuntimeProviderQualificationV1::new(
                    REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1 + 1,
                    [0xD1; 32],
                ),
                Arc::clone(&archive),
            )
            .is_err()
        );
        assert!(
            ArchivedReputationFinalizedQueryV1::try_new(
                "reputation-archive:region-a",
                ReputationRuntimeProviderQualificationV1::new(
                    REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
                    [0; 32],
                ),
                archive,
            )
            .is_err()
        );
    }
}
