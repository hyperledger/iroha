//! Provider-ingest queries backed only by the durable finalized archive.
//!
//! The launcher resolves the configured relative namespace beneath the
//! daemon's Kura root, opens exactly one single-writer archive, reconciles the
//! recovered State tip against Kura with a zero-gap barrier, and then applies
//! the configured live-lag ceiling. The query adapter shares that same
//! [`Arc`] and never sources rows from current process-local State. A fresh
//! State view supplies only the publication fence that prevents a pre-WSV
//! durable archive record from becoming visible early.
//!
//! Runtime continuations carry only height, hash, and order identity. The
//! adapter therefore retains the archive's complete timestamp-, provider-, and
//! provider-state-root-bound cursor internally and rejects interleaved or
//! substituted continuations. The separately constructed capture reader
//! reconstructs complete cursors from immutable archive records. Its lazy
//! ephemeral signer serializes reads and retains one exact signed response so
//! cancellation or response loss can retry a generation byte-for-byte without
//! selecting a later head.
/// Archive startup and activation boundary rules shared with the reputation archive adapter.
pub(crate) mod archive_boundary;
mod current_source_assignment;
mod current_source_stream_token_custody;

use archive_boundary::{
    ArchiveActivationGateV1, ArchiveStartupBoundaryV1, classify_archive_startup_boundary,
};

pub use current_source_assignment::ProviderIngestCurrentSourceAssignmentV1;
use current_source_assignment::authenticate_retained_admission_ancestor;
#[cfg(test)]
use current_source_assignment::materialize_current_source_assignment;
pub use current_source_stream_token_custody::ProviderIngestCurrentSourceStreamTokenCustodyV1;

use iroha_config::parameters::actual::SorafsProviderIngestFinalizedArchive;
use iroha_core::{
    kura::Kura,
    query::provider_ingest_finalized::{
        ProviderIngestFinalizedArchiveAssignmentLookupV1,
        ProviderIngestFinalizedArchiveAssignmentV1, ProviderIngestFinalizedArchiveBoundsV1,
        ProviderIngestFinalizedArchiveCursorV1, ProviderIngestFinalizedArchiveErrorV1,
        ProviderIngestFinalizedArchiveKeyV1, ProviderIngestFinalizedArchivePageV1,
        ProviderIngestFinalizedArchiveQualificationV1,
        ProviderIngestFinalizedArchiveReconcileOutcomeV1,
        ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
        ProviderIngestFinalizedArchiveRetentionAuthorityV1, ProviderIngestFinalizedArchiveV1,
    },
    state::{State, StateQueryView, StateReadOnly as _},
};
use iroha_crypto::{Algorithm, KeyPair, Signature as IrohaSignature};
use iroha_data_model::{
    NetworkId,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            PinManifestFinalizedCursorV1, PinManifestFinalizedRecordV1, PinStatus,
            ProviderIngestCompletionAuthorityV1, ReplicationOrderId, ReplicationOrderStatus,
        },
    },
};
#[cfg(test)]
use iroha_model_base::chain::ChainId;
use sorafs_node::{
    FinalizedProviderIngestAuthorizationV1, ProviderIngestCompletedMusubiCaptureRequestV1,
    ProviderIngestCompletedMusubiCaptureSourcePageV1,
    ProviderIngestCompletedMusubiCaptureSourceRowV1,
    ProviderIngestCompletedMusubiCaptureVerifierBindingV1,
    ProviderIngestCompletedMusubiSignedCaptureLedgerV1,
    ProviderIngestCompletedMusubiSignedCapturePageV1, ProviderIngestFinalizedAssignmentPageV1,
    ProviderIngestFinalizedAssignmentV1, ProviderIngestFinalizedClaimFactoryV1,
    ProviderIngestFinalizedCursorV1, ProviderIngestFinalizedLedgerErrorV1,
    ProviderIngestFinalizedLedgerV1, ProviderIngestFutureV1, ProviderIngestSourceFetchErrorV1,
    provider_ingest_completed_musubi_capture_transcript_digest_v1,
    provider_ingest_runtime::ProviderIngestSourceRequestV1,
};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fmt, io,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
const LIVE_SELECTION_ATTEMPTS_V1: usize = 4;
/// Typed failure while opening and qualifying the provider-ingest archive.
#[derive(Debug)]
pub(crate) enum ProviderIngestFinalizedArchiveStartupErrorV1 {
    /// State, Kura, or the authenticated pending-tip plan disagreed.
    StartupBoundary {
        /// Stable payload-free rejection reason.
        reason: &'static str,
    },
    /// Reading the exact durable Kura boundary failed.
    KuraBoundary {
        /// Payload-free storage diagnostic.
        detail: String,
    },
    /// The relative namespace could not be bound below the daemon root.
    InvalidDaemonArchiveRoot {
        /// Path-resolution failure.
        source: io::Error,
    },
    /// Runtime retention-authority presence disagreed with public configuration.
    RetentionAuthorityConfiguration {
        /// Stable payload-free rejection reason.
        reason: &'static str,
    },
    /// One named archive operation failed closed.
    Archive {
        /// Payload-free startup stage.
        stage: &'static str,
        /// Typed durable archive failure.
        source: Box<ProviderIngestFinalizedArchiveErrorV1>,
    },
}
impl fmt::Display for ProviderIngestFinalizedArchiveStartupErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupBoundary { reason } => {
                write!(
                    formatter,
                    "invalid finalized provider-ingest startup boundary: {reason}"
                )
            }
            Self::KuraBoundary { detail } => write!(
                formatter,
                "finalized provider-ingest startup could not read the exact durable Kura boundary: {detail}"
            ),
            Self::InvalidDaemonArchiveRoot { .. } => formatter.write_str(
                "finalized provider-ingest archive root could not be bound below the daemon storage root",
            ),
            Self::RetentionAuthorityConfiguration { reason } => write!(
                formatter,
                "invalid finalized provider-ingest retention-authority configuration: {reason}"
            ),
            Self::Archive { stage, .. } => {
                write!(formatter, "finalized provider-ingest archive failed at {stage}")
            }
        }
    }
}
impl std::error::Error for ProviderIngestFinalizedArchiveStartupErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StartupBoundary { .. }
            | Self::KuraBoundary { .. }
            | Self::RetentionAuthorityConfiguration { .. } => None,
            Self::InvalidDaemonArchiveRoot { source } => Some(source),
            Self::Archive { source, .. } => Some(source.as_ref()),
        }
    }
}
/// Recovery mode authenticated while opening the provider-ingest archive.
#[derive(Debug)]
pub(crate) enum ProviderIngestFinalizedArchiveStartupModeV1 {
    /// Fresh height-zero State/Kura with a completely empty archive namespace.
    BootstrapAwaitingGenesisCapture,
    /// Ordinary startup reconciled and qualified with an exact zero-gap tip.
    Qualified {
        /// Exact startup reconciliation against committed State and Kura.
        reconciliation: ProviderIngestFinalizedArchiveReconcileOutcomeV1,
        /// Subsequent configured live-lag qualification.
        live_qualification: ProviderIngestFinalizedArchiveQualificationV1,
    },
}
/// Exact archive qualification retained after daemon startup.
#[derive(Debug)]
#[must_use]
pub(crate) struct PreparedProviderIngestFinalizedArchiveV1 {
    startup_mode: ProviderIngestFinalizedArchiveStartupModeV1,
    archive: Arc<ProviderIngestFinalizedArchiveV1>,
    query: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
    runtime_query: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
    signed_capture_reader: Option<ArchivedProviderIngestFinalizedLedgerV1>,
    retention_authority: Option<QualifiedProviderIngestRetentionAuthorityV1>,
}
impl PreparedProviderIngestFinalizedArchiveV1 {
    /// Return the exact authenticated startup mode.
    pub(crate) const fn startup_mode(&self) -> &ProviderIngestFinalizedArchiveStartupModeV1 {
        &self.startup_mode
    }
    /// Return the single-writer archive installed in the consensus commit
    /// corridor.
    pub(crate) const fn archive(&self) -> &Arc<ProviderIngestFinalizedArchiveV1> {
        &self.archive
    }
    /// Return the archive-only finalized assignment query adapter.
    pub(crate) fn query(&self) -> &Arc<ArchivedProviderIngestFinalizedLedgerV1> {
        &self.query
    }
    /// Return the independently cursor-fenced archive reader reserved for the
    /// supervised provider-ingest worker.
    pub(crate) fn runtime_query(&self) -> &Arc<ArchivedProviderIngestFinalizedLedgerV1> {
        &self.runtime_query
    }
    /// Take the one request-bound signed archive reader reserved for the inert
    /// completed-Musubi capture coordinator.
    ///
    /// No cloneable accessor is exposed: the private daemon composer must move
    /// this exact reader into the matching `NodeHandle` tenure once.
    pub(crate) fn take_signed_capture_reader(
        &mut self,
    ) -> Option<ArchivedProviderIngestFinalizedLedgerV1> {
        self.signed_capture_reader.take()
    }
    /// Return the authority qualified for explicit archive retention.
    pub(crate) const fn retention_authority(
        &self,
    ) -> Option<&QualifiedProviderIngestRetentionAuthorityV1> {
        self.retention_authority.as_ref()
    }
}
/// Exact configured retention authority retained after startup qualification.
pub(crate) struct QualifiedProviderIngestRetentionAuthorityV1 {
    binding: ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1,
    authority: Arc<dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1>,
}
impl fmt::Debug for QualifiedProviderIngestRetentionAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedProviderIngestRetentionAuthorityV1")
            .field("handle", &self.binding.handle())
            .field("qualification", &self.binding.qualification())
            .finish_non_exhaustive()
    }
}
impl QualifiedProviderIngestRetentionAuthorityV1 {
    /// Return the exact credential-free expected authority binding.
    pub(crate) const fn binding(
        &self,
    ) -> &ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1 {
        &self.binding
    }
    /// Return the runtime-only deployment-owned authority.
    pub(crate) const fn authority(
        &self,
    ) -> &Arc<dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1> {
        &self.authority
    }
    fn revalidate(&self) -> Result<(), ProviderIngestFinalizedArchiveStartupErrorV1> {
        let handle_before = self.authority.handle();
        let qualification = self.authority.qualification().map_err(|_| {
            ProviderIngestFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                reason: "retention authority became unavailable during startup",
            }
        })?;
        let handle_after = self.authority.handle();
        if handle_before != self.binding.handle()
            || handle_after != handle_before
            || qualification != self.binding.qualification()
        {
            return Err(
                ProviderIngestFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                    reason: "retention authority became substituted or stale during startup",
                },
            );
        }
        Ok(())
    }
}
struct AuthenticatedArchiveStartupBoundaryV1<'state> {
    state_view: StateQueryView<'state>,
    kind: ArchiveStartupBoundaryV1,
}
/// Open and qualify the daemon-owned provider-ingest archive before consensus.
///
/// The recovered State tip is reconciled against its same-State certified
/// Kura block with a zero-gap barrier. The configured lag allowance is evaluated
/// only after that exact reconciliation succeeds. An empty archive may
/// establish an explicit activation floor at the current authenticated tip;
/// it never claims historical coverage below that floor. Height-zero startup
/// accepts only a completely empty namespace and defers qualification until
/// genesis capture. Current consensus replay must finish before this boundary;
/// a crash may leave only one committed successor missing from an existing archive.
///
/// # Errors
///
/// Fails for an escaping or unresolvable relative root, invalid bounds, unsafe
/// durable storage, a substituted State/Kura boundary, nonempty
/// height-zero storage, incomplete coverage, a fork, or a configured lag
/// violation.
pub(crate) fn prepare_provider_ingest_finalized_archive_v1(
    config: &SorafsProviderIngestFinalizedArchive,
    network_id: NetworkId,
    provider_id: ProviderId,
    daemon_storage_root: &Path,
    state: &Arc<State>,
    kura: &Arc<Kura>,
    retention_authority: Option<Arc<dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1>>,
) -> Result<PreparedProviderIngestFinalizedArchiveV1, ProviderIngestFinalizedArchiveStartupErrorV1>
{
    if network_id != *state.network_id_ref() {
        return Err(
            ProviderIngestFinalizedArchiveStartupErrorV1::StartupBoundary {
                reason: "configured provider-ingest network identity differs from committed State",
            },
        );
    }
    let (archive, retention_authority) = open_provider_ingest_finalized_archive(
        config,
        &network_id,
        &state.query_view(),
        kura.as_ref(),
        daemon_storage_root,
        retention_authority,
    )?;
    let boundary = authenticate_archive_startup_boundary(state.as_ref(), kura.as_ref())?;
    let archive_empty = archive.is_empty().map_err(|source| {
        ProviderIngestFinalizedArchiveStartupErrorV1::Archive {
            stage: "complete bootstrap namespace validation",
            source: Box::new(source),
        }
    })?;
    let startup_mode = select_archive_startup_mode(
        config,
        archive.as_ref(),
        kura.as_ref(),
        &boundary,
        archive_empty,
    )?;
    if let Some(authority) = &retention_authority {
        authority.revalidate()?;
    }
    let reader_args = ArchivedProviderIngestFinalizedLedgerArgsV1 {
        network_id,
        provider_id,
        archive: Arc::clone(&archive),
        kura: Arc::clone(kura),
        state: Arc::clone(state),
        max_page_rows: config.max_page_rows,
        max_kura_tip_lag_blocks: config.max_kura_tip_lag_blocks,
        activation_gate: activation_gate_for_startup_mode(&startup_mode),
    };
    let query = Arc::new(ArchivedProviderIngestFinalizedLedgerV1::new(
        reader_args.clone(),
    ));
    let runtime_query = Arc::new(ArchivedProviderIngestFinalizedLedgerV1::new(
        reader_args.clone(),
    ));
    let signed_capture_reader =
        Some(ArchivedProviderIngestFinalizedLedgerV1::new_replay_safe_capture(reader_args));
    Ok(PreparedProviderIngestFinalizedArchiveV1 {
        startup_mode,
        archive,
        query,
        runtime_query,
        signed_capture_reader,
        retention_authority,
    })
}
fn open_provider_ingest_finalized_archive(
    config: &SorafsProviderIngestFinalizedArchive,
    network_id: &NetworkId,
    state_view: &StateQueryView<'_>,
    kura: &Kura,
    daemon_storage_root: &Path,
    authority: Option<Arc<dyn ProviderIngestFinalizedArchiveRetentionAuthorityV1>>,
) -> Result<
    (
        Arc<ProviderIngestFinalizedArchiveV1>,
        Option<QualifiedProviderIngestRetentionAuthorityV1>,
    ),
    ProviderIngestFinalizedArchiveStartupErrorV1,
> {
    let root = resolve_daemon_archive_root(daemon_storage_root, &config.relative_root).map_err(
        |source| ProviderIngestFinalizedArchiveStartupErrorV1::InvalidDaemonArchiveRoot { source },
    )?;
    let bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
        config.max_record_bytes,
        config.max_archive_entries,
        config.max_total_bytes,
        config.max_providers_per_anchor,
        config.max_orders_per_provider,
        config.max_total_orders_per_anchor,
        config.max_page_rows,
    )
    .map_err(
        |source| ProviderIngestFinalizedArchiveStartupErrorV1::Archive {
            stage: "resource-bound validation",
            source: Box::new(source),
        },
    )?;
    let (archive, qualified_authority) = match (&config.retention_authority, authority) {
        (None, None) => (
            ProviderIngestFinalizedArchiveV1::try_open(root, bounds),
            None,
        ),
        (Some(expected), Some(authority)) => {
            let binding = ProviderIngestFinalizedArchiveRetentionAuthorityBindingV1::try_new(
                expected.handle.clone(),
                expected.revision,
                expected.policy_digest,
            )
            .map_err(|source| {
                ProviderIngestFinalizedArchiveStartupErrorV1::Archive {
                    stage: "retention-authority binding validation",
                    source: Box::new(source),
                }
            })?;
            let archive = ProviderIngestFinalizedArchiveV1::try_open_with_retention_authority(
                root,
                bounds,
                network_id,
                state_view,
                kura,
                &binding,
                authority.as_ref(),
            );
            (
                archive,
                Some(QualifiedProviderIngestRetentionAuthorityV1 { binding, authority }),
            )
        }
        (Some(_), None) => {
            return Err(
                ProviderIngestFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                    reason: "enabled retention requires its deployment-owned sealed CAS authority",
                },
            );
        }
        (None, Some(_)) => {
            return Err(
                ProviderIngestFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration {
                    reason: "manual retention mode rejects an unexpected runtime authority",
                },
            );
        }
    };
    archive
        .map(Arc::new)
        .map(|archive| (archive, qualified_authority))
        .map_err(
            |source| ProviderIngestFinalizedArchiveStartupErrorV1::Archive {
                stage: "durable open and retention recovery",
                source: Box::new(source),
            },
        )
}
fn authenticate_archive_startup_boundary<'state>(
    state: &'state State,
    kura: &Kura,
) -> Result<
    AuthenticatedArchiveStartupBoundaryV1<'state>,
    ProviderIngestFinalizedArchiveStartupErrorV1,
> {
    let state_view = state.query_view();
    if !std::ptr::eq(state_view.kura(), kura) {
        return Err(
            ProviderIngestFinalizedArchiveStartupErrorV1::StartupBoundary {
                reason: "State is bound to a substituted Kura instance",
            },
        );
    }
    let state_height = u64::try_from(state_view.height()).map_err(|_| {
        ProviderIngestFinalizedArchiveStartupErrorV1::StartupBoundary {
            reason: "committed State height exceeds the supported range",
        }
    })?;
    let kura_height = u64::try_from(kura.exact_durable_blocks_count().map_err(|source| {
        ProviderIngestFinalizedArchiveStartupErrorV1::KuraBoundary {
            detail: source.to_string(),
        }
    })?)
    .map_err(
        |_| ProviderIngestFinalizedArchiveStartupErrorV1::StartupBoundary {
            reason: "durable Kura height exceeds the supported range",
        },
    )?;
    let kind = classify_archive_startup_boundary(state_height, kura_height).map_err(|reason| {
        ProviderIngestFinalizedArchiveStartupErrorV1::StartupBoundary { reason }
    })?;
    Ok(AuthenticatedArchiveStartupBoundaryV1 { state_view, kind })
}
fn select_archive_startup_mode(
    config: &SorafsProviderIngestFinalizedArchive,
    archive: &ProviderIngestFinalizedArchiveV1,
    kura: &Kura,
    boundary: &AuthenticatedArchiveStartupBoundaryV1<'_>,
    archive_empty: bool,
) -> Result<ProviderIngestFinalizedArchiveStartupModeV1, ProviderIngestFinalizedArchiveStartupErrorV1>
{
    match boundary.kind {
        ArchiveStartupBoundaryV1::Bootstrap => {
            if !archive_empty {
                return Err(
                    ProviderIngestFinalizedArchiveStartupErrorV1::StartupBoundary {
                        reason: "height-zero bootstrap requires a completely empty archive namespace",
                    },
                );
            }
            Ok(ProviderIngestFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture)
        }
        ArchiveStartupBoundaryV1::Qualified => {
            prepare_qualified_archive_mode(config, archive, kura, &boundary.state_view)
        }
    }
}
fn prepare_qualified_archive_mode(
    config: &SorafsProviderIngestFinalizedArchive,
    archive: &ProviderIngestFinalizedArchiveV1,
    kura: &Kura,
    state_view: &StateQueryView<'_>,
) -> Result<ProviderIngestFinalizedArchiveStartupModeV1, ProviderIngestFinalizedArchiveStartupErrorV1>
{
    let reconciliation = archive
        .reconcile_certified_state_tip(state_view, kura)
        .map_err(
            |source| ProviderIngestFinalizedArchiveStartupErrorV1::Archive {
                stage: "exact Kura-tip reconciliation",
                source: Box::new(source),
            },
        )?;
    let live_qualification = archive
        .qualify_against_certified_tip(state_view, kura, config.max_kura_tip_lag_blocks)
        .map_err(
            |source| ProviderIngestFinalizedArchiveStartupErrorV1::Archive {
                stage: "configured live-lag qualification",
                source: Box::new(source),
            },
        )?;
    Ok(ProviderIngestFinalizedArchiveStartupModeV1::Qualified {
        reconciliation,
        live_qualification,
    })
}
fn activation_gate_for_startup_mode(
    startup_mode: &ProviderIngestFinalizedArchiveStartupModeV1,
) -> ArchiveActivationGateV1 {
    match startup_mode {
        ProviderIngestFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture => {
            ArchiveActivationGateV1::AwaitingGenesis
        }
        ProviderIngestFinalizedArchiveStartupModeV1::Qualified { .. } => {
            ArchiveActivationGateV1::StrictLive
        }
    }
}
fn resolve_daemon_archive_root(
    daemon_storage_root: &Path,
    relative_root: &Path,
) -> io::Result<PathBuf> {
    if relative_root.as_os_str().is_empty()
        || relative_root.is_absolute()
        || !relative_root
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "archive namespace must be a normalized relative path",
        ));
    }
    let daemon_storage_root = std::path::absolute(daemon_storage_root)?;
    let archive_root = daemon_storage_root.join(relative_root);
    if archive_root == daemon_storage_root || !archive_root.starts_with(&daemon_storage_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "archive namespace escaped the daemon storage root",
        ));
    }
    Ok(archive_root)
}
#[derive(Debug, Clone)]
struct ActiveArchiveScanV1 {
    key: ProviderIngestFinalizedArchiveKeyV1,
    cursor: ProviderIngestFinalizedArchiveCursorV1,
}
/// One current State/Kura-qualified assignment, retained only inside the daemon.
///
/// This contains no endpoint, admission, advert, credential, token, or grant authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderIngestCurrentAssignmentSnapshotV1 {
    key: ProviderIngestFinalizedArchiveKeyV1,
    provider_state_root: [u8; 32],
    assignment: ProviderIngestFinalizedArchiveAssignmentV1,
    source_provider_ids: Vec<[u8; 32]>,
}
impl ProviderIngestCurrentAssignmentSnapshotV1 {
    /// Bind a source request and revision to this independently read current assignment.
    /// A request is only a payload-free transport input; it cannot authenticate itself.
    fn matches_source_request(
        &self,
        source_provider_id: [u8; 32],
        request: &ProviderIngestSourceRequestV1,
        assignment_revision: u64,
    ) -> bool {
        let musubi_matches = match (
            self.assignment.musubi_archive.as_ref(),
            request.musubi_archive(),
        ) {
            (None, None) => true,
            (Some(current), Some(candidate)) => {
                candidate.network_id() == &self.key.network_id
                    && candidate.provider_id() == *self.assignment.provider_id.as_bytes()
                    && candidate.binding() == current
                    && candidate.observed_finalized_cursor().height <= self.key.height
                    && (candidate.observed_finalized_cursor().height != self.key.height
                        || candidate.observed_finalized_cursor().block_hash == self.key.block_hash)
            }
            _ => false,
        };
        assignment_revision != 0
            && assignment_revision == self.assignment.expected_assignment_revision
            && self.source_provider_ids.as_slice() == request.source_provider_ids()
            && self
                .source_provider_ids
                .binary_search(&source_provider_id)
                .is_ok()
            && request.authorization().provider_id() == *self.assignment.provider_id.as_bytes()
            && self.provider_state_root != [0; 32]
            && musubi_matches
    }
}
type ArchivedCompletedMusubiCaptureSignerSlotV1 =
    Arc<Mutex<Option<Arc<ArchivedCompletedMusubiCaptureSignerV1>>>>;
struct ArchivedCompletedMusubiCaptureSignerV1 {
    key_pair: KeyPair,
    session_generation: u64,
    signed_read: Mutex<ArchivedCompletedMusubiSignedReadStateV1>,
}
#[derive(Default)]
struct ArchivedCompletedMusubiSignedReadStateV1 {
    last_request: Option<ProviderIngestCompletedMusubiCaptureRequestV1>,
    last_response: Option<ProviderIngestCompletedMusubiSignedCapturePageV1>,
}
impl ArchivedCompletedMusubiCaptureSignerV1 {
    fn try_new() -> Result<Self, ProviderIngestFinalizedLedgerErrorV1> {
        let key_pair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let (algorithm, public_key) = key_pair
            .public_key()
            .try_to_bytes()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        if algorithm != Algorithm::Ed25519 || public_key.len() != 32 {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let generation_bytes: [u8; 8] = public_key[..8]
            .try_into()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let session_generation = u64::from_be_bytes(generation_bytes).max(1);
        Ok(Self {
            key_pair,
            session_generation,
            signed_read: Mutex::new(ArchivedCompletedMusubiSignedReadStateV1::default()),
        })
    }
    fn public_key_bytes(&self) -> Result<[u8; 32], ProviderIngestFinalizedLedgerErrorV1> {
        let (algorithm, public_key) = self
            .key_pair
            .public_key()
            .try_to_bytes()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        if algorithm != Algorithm::Ed25519 {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        public_key
            .try_into()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)
    }
}
/// Archive-only provider assignment reader.
///
/// One adapter permits one sequential scan at a time. The first page
/// requalifies the archive against the live authenticated Kura tip and pins
/// the exact archive key visible through a fresh committed State view.
/// Continuations must match both the public cursor and the full context
/// retained in `ActiveArchiveScanV1`. The dedicated capture instance instead
/// reconstructs every continuation from the immutable archive and never
/// mutates `active`. Its lazy signed-reader session adds an exact-response
/// generation cache, making both fresh reads and continuations safe to retry
/// after validation failure or task cancellation.
#[derive(Clone)]
pub struct ArchivedProviderIngestFinalizedLedgerV1 {
    network_id: NetworkId,
    provider_id: ProviderId,
    archive: Arc<ProviderIngestFinalizedArchiveV1>,
    kura: Arc<Kura>,
    state: Arc<State>,
    max_page_rows: usize,
    max_kura_tip_lag_blocks: u64,
    activation_gate: ArchiveActivationGateV1,
    replay_safe_capture: bool,
    capture_signer: Option<ArchivedCompletedMusubiCaptureSignerSlotV1>,
    #[cfg(test)]
    signed_capture_source_reads: Arc<AtomicUsize>,
    #[cfg(test)]
    live_qualification_attempts: Arc<AtomicUsize>,
    active: Arc<Mutex<Option<ActiveArchiveScanV1>>>,
}
#[derive(Clone)]
struct ArchivedProviderIngestFinalizedLedgerArgsV1 {
    network_id: NetworkId,
    provider_id: ProviderId,
    archive: Arc<ProviderIngestFinalizedArchiveV1>,
    kura: Arc<Kura>,
    state: Arc<State>,
    max_page_rows: usize,
    max_kura_tip_lag_blocks: u64,
    activation_gate: ArchiveActivationGateV1,
}
impl fmt::Debug for ArchivedProviderIngestFinalizedLedgerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArchivedProviderIngestFinalizedLedgerV1")
            .field("network_id", &self.network_id)
            .field("provider_id", &self.provider_id)
            .field("max_page_rows", &self.max_page_rows)
            .field("max_kura_tip_lag_blocks", &self.max_kura_tip_lag_blocks)
            .field("replay_safe_capture", &self.replay_safe_capture)
            .finish_non_exhaustive()
    }
}
impl ArchivedProviderIngestFinalizedLedgerV1 {
    /// Test-only reader with no committed State/Kura head for fail-closed HTTP evidence checks.
    #[cfg(test)]
    pub(crate) fn unfinalized_for_https_evidence_test(
        network_id: NetworkId,
        provider_id: ProviderId,
    ) -> (tempfile::TempDir, Self) {
        let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        std::fs::create_dir_all(&target).expect("workspace target directory");
        let target = target.canonicalize().expect("normalized workspace target");
        let root = tempfile::Builder::new()
            .prefix("irohad-provider-ingest-https-evidence-")
            .tempdir_in(target)
            .expect("temporary finalized archive");
        let bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            8,
            16 * 1024 * 1024,
            8,
            8,
            16,
            2,
        )
        .expect("archive bounds");
        let archive = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(root.path().join("archive"), bounds)
                .expect("open archive"),
        );
        let kura = Kura::blank_kura_for_testing();
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            iroha_core::state::World::default(),
            Arc::clone(&kura),
            iroha_core::query::store::LiveQueryStore::start_test(),
            ChainId::from("provider-ingest-https-evidence-unfinalized"),
            network_id,
        ));
        let reader = Self::new(ArchivedProviderIngestFinalizedLedgerArgsV1 {
            network_id,
            provider_id,
            archive,
            kura,
            state,
            max_page_rows: 2,
            max_kura_tip_lag_blocks: 0,
            activation_gate: ArchiveActivationGateV1::StrictLive,
        });
        (root, reader)
    }
    fn new(args: ArchivedProviderIngestFinalizedLedgerArgsV1) -> Self {
        Self::new_with_capture_mode(args, None)
    }
    fn new_replay_safe_capture(args: ArchivedProviderIngestFinalizedLedgerArgsV1) -> Self {
        Self::new_with_capture_mode(args, Some(Arc::new(Mutex::new(None))))
    }
    fn new_with_capture_mode(
        args: ArchivedProviderIngestFinalizedLedgerArgsV1,
        capture_signer: Option<ArchivedCompletedMusubiCaptureSignerSlotV1>,
    ) -> Self {
        let ArchivedProviderIngestFinalizedLedgerArgsV1 {
            network_id,
            provider_id,
            archive,
            kura,
            state,
            max_page_rows,
            max_kura_tip_lag_blocks,
            activation_gate,
        } = args;
        Self {
            network_id,
            provider_id,
            archive,
            kura,
            state,
            max_page_rows,
            max_kura_tip_lag_blocks,
            activation_gate,
            replay_safe_capture: capture_signer.is_some(),
            capture_signer,
            #[cfg(test)]
            signed_capture_source_reads: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            live_qualification_attempts: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(Mutex::new(None)),
        }
    }
    fn completed_musubi_capture_verifier_binding(
        &self,
    ) -> Result<
        ProviderIngestCompletedMusubiCaptureVerifierBindingV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        let signer = self.completed_musubi_capture_signer()?;
        ProviderIngestCompletedMusubiCaptureVerifierBindingV1::try_from_untrusted_reader_parts(
            self.network_id,
            *self.provider_id.as_bytes(),
            signer.session_generation,
            signer.public_key_bytes()?,
        )
    }
    fn completed_musubi_capture_signer(
        &self,
    ) -> Result<Arc<ArchivedCompletedMusubiCaptureSignerV1>, ProviderIngestFinalizedLedgerErrorV1>
    {
        let signer_slot = self
            .capture_signer
            .as_ref()
            .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let mut signer = signer_slot
            .lock()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        if signer.is_none() {
            *signer = Some(Arc::new(ArchivedCompletedMusubiCaptureSignerV1::try_new()?));
        }
        signer
            .as_ref()
            .cloned()
            .ok_or(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
    }
    /// Return the exact genesis-derived security domain frozen into this reader.
    pub(crate) const fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Return the exact provider index frozen into this reader.
    pub(crate) const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
    /// Requalify the captured archive against the current authenticated Kura
    /// boundary using the configured live-lag ceiling.
    pub(crate) fn qualify_live(
        &self,
    ) -> Result<ProviderIngestFinalizedArchiveQualificationV1, ProviderIngestFinalizedArchiveErrorV1>
    {
        self.qualify_live_with_view()
            .map(|(_view, qualification)| qualification)
    }
    // Keep the exact view that authenticated this qualification through activation's
    // visibility check. A second current view could describe an ordinary next commit.
    fn qualify_live_with_view(
        &self,
    ) -> Result<
        (
            StateQueryView<'_>,
            ProviderIngestFinalizedArchiveQualificationV1,
        ),
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        self.qualify_live_with_view_observed(
            #[cfg(test)]
            &mut || Ok(()),
        )
    }

    fn qualify_live_with_view_observed(
        &self,
        #[cfg(test)] interleave: &mut impl FnMut() -> Result<(), ProviderIngestFinalizedArchiveErrorV1>,
    ) -> Result<
        (
            StateQueryView<'_>,
            ProviderIngestFinalizedArchiveQualificationV1,
        ),
        ProviderIngestFinalizedArchiveErrorV1,
    > {
        for _ in 0..LIVE_SELECTION_ATTEMPTS_V1 {
            let view = self.state.query_view();
            if view.network_id() != &self.network_id {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                        reason: "provider-ingest reader network differs from its native State",
                    },
                );
            }
            #[cfg(test)]
            self.live_qualification_attempts
                .fetch_add(1, Ordering::SeqCst);
            #[cfg(test)]
            let qualification = self
                .archive
                .qualify_against_certified_tip_with_interleaving_for_testing(
                    &view,
                    self.kura.as_ref(),
                    self.max_kura_tip_lag_blocks,
                    |_| interleave(),
                );
            #[cfg(not(test))]
            let qualification = self.archive.qualify_against_certified_tip(
                &view,
                self.kura.as_ref(),
                self.max_kura_tip_lag_blocks,
            );
            match qualification {
                Err(ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                    ..
                }) => {}
                Ok(qualification) => return Ok((view, qualification)),
                Err(error) => return Err(error),
            }
        }
        Err(
            ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                boundary: "archive/Kura",
            },
        )
    }
    /// Validate adapter identity readiness without requiring a first commit to
    /// have completed before Sumeragi starts.
    ///
    /// Empty bootstrap, authenticated archive lag within the configured ceiling,
    /// and an unstable boundary after bounded qualification defer activation.
    /// None grants query authority; corruption, incompatible
    /// finality and excessive lag retain their original errors.
    pub(crate) fn activation_ready(&self) -> Result<bool, ProviderIngestFinalizedArchiveErrorV1> {
        self.activation_ready_observed(
            #[cfg(test)]
            &mut || Ok(()),
        )
    }

    fn activation_ready_observed(
        &self,
        #[cfg(test)] interleave: &mut impl FnMut() -> Result<(), ProviderIngestFinalizedArchiveErrorV1>,
    ) -> Result<bool, ProviderIngestFinalizedArchiveErrorV1> {
        match self.qualify_live_with_view_observed(
            #[cfg(test)]
            interleave,
        ) {
            Ok((view, qualification)) => self.qualification_is_visible(&view, &qualification),
            Err(ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged { .. }) => {
                Ok(false)
            }
            Err(error) => match self.activation_gate {
                ArchiveActivationGateV1::StrictLive => Err(error),
                ArchiveActivationGateV1::AwaitingGenesis => {
                    self.awaiting_genesis_activation_ready(error)
                }
            },
        }
    }

    fn awaiting_genesis_activation_ready(
        &self,
        error: ProviderIngestFinalizedArchiveErrorV1,
    ) -> Result<bool, ProviderIngestFinalizedArchiveErrorV1> {
        let (_view, state_height) = self.activation_state_view()?;
        let kura_height = self.activation_kura_height("read deferred genesis Kura boundary")?;
        if state_height == 0 && kura_height <= 1 && self.archive.is_empty()? {
            return Ok(false);
        }
        Err(error)
    }
    fn activation_state_view(
        &self,
    ) -> Result<(StateQueryView<'_>, u64), ProviderIngestFinalizedArchiveErrorV1> {
        let view = self.state.query_view();
        if !std::ptr::eq(view.kura(), self.kura.as_ref()) {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "provider-ingest activation State is bound to another Kura instance",
                },
            );
        }
        let height = u64::try_from(view.height()).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                reason: "provider-ingest activation State height exceeds the supported range",
            }
        })?;
        Ok((view, height))
    }
    fn activation_kura_height(
        &self,
        operation: &'static str,
    ) -> Result<u64, ProviderIngestFinalizedArchiveErrorV1> {
        u64::try_from(self.kura.exact_durable_blocks_count().map_err(|error| {
            ProviderIngestFinalizedArchiveErrorV1::KuraAuthentication {
                operation,
                detail: error.to_string(),
            }
        })?)
        .map_err(
            |_| ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                reason: "provider-ingest activation Kura height exceeds the supported range",
            },
        )
    }
    fn qualification_is_visible(
        &self,
        view: &StateQueryView<'_>,
        qualification: &ProviderIngestFinalizedArchiveQualificationV1,
    ) -> Result<bool, ProviderIngestFinalizedArchiveErrorV1> {
        if !std::ptr::eq(view.kura(), self.kura.as_ref()) {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "provider-ingest activation State is bound to another Kura instance",
                },
            );
        }
        let state_height = u64::try_from(view.height()).map_err(|_| {
            ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                reason: "provider-ingest activation State height exceeds the supported range",
            }
        })?;
        if state_height != qualification.archive_tip().height {
            // The executor publishes State before capturing its archive. A successful
            // qualification already proved the configured lag bound and exact ancestry;
            // wait for capture on the next bounded tick without declaring readiness.
            return Ok(false);
        }
        let state_hash = view
            .latest_block_hash()
            .map(|hash| *hash.as_ref())
            .filter(|hash| *hash != [0; 32])
            .ok_or(
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "provider-ingest activation State has no committed block hash",
                },
            )?;
        if state_hash != qualification.archive_tip().block_hash {
            return Err(
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "provider-ingest activation State and archive tips disagree",
                },
            );
        }
        Ok(true)
    }
    // Return the generation already authenticated by this bounded selection. A capture
    // page must close against this same generation rather than requalifying only to read it.
    fn select_visible_committed_key(
        &self,
    ) -> Result<(ProviderIngestFinalizedArchiveKeyV1, u64), ProviderIngestFinalizedArchiveErrorV1>
    {
        for _ in 0..LIVE_SELECTION_ATTEMPTS_V1 {
            let view = self.state.query_view();
            if !std::ptr::eq(view.kura(), self.kura.as_ref()) {
                return Err(
                    ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                        reason: "provider-ingest query State is bound to another Kura instance",
                    },
                );
            }
            let height = u64::try_from(view.height()).map_err(|_| {
                ProviderIngestFinalizedArchiveErrorV1::FinalityAuthentication {
                    reason: "provider-ingest query State height exceeds the supported range",
                }
            })?;
            let block_hash = view
                .latest_block_hash()
                .map(|hash| *hash.as_ref())
                .filter(|hash| *hash != [0; 32])
                .ok_or(ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                    reason: "provider-ingest query State has no committed block",
                })?;
            let qualification = self.qualify_live()?;
            if height > qualification.archive_tip().height {
                return Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveUnavailable {
                    reason: "provider-ingest archive does not cover the visible committed State head",
                });
            }
            let key = self
                .archive
                .resolve_exact_key(&self.network_id, height, block_hash)?;
            if self.archive.health_generation()? == qualification.generation() {
                return Ok((key, qualification.generation()));
            }
        }
        Err(
            ProviderIngestFinalizedArchiveErrorV1::QualificationBoundaryChanged {
                boundary: "archive/State visibility",
            },
        )
    }
    /// Read an exact current assignment without consuming the worker's page cursor.
    ///
    /// The old admission cursor is an immutable job identity, not the current assignment
    /// revision. This method proves its retained ancestor on the Kura-qualified archive chain,
    /// rechecks the visible committed State/Kura key and archive generation after the direct read,
    /// and returns no grant or transport authority.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or no-longer-pending assignment binding; fails closed when current
    /// finality, archive qualification, or a stable head cannot be authenticated.
    // The stock native source transport authorizes signed assignment requests through
    // `iroha_core::query::provider_ingest_source`; it does not issue gateway grants.
    // TODO: an independently administered HTTPS gateway-grant resolver must still join
    // this observation to its governed admission, advert, pin and token authority.
    pub(crate) fn lookup_current_assignment(
        &self,
        network_id: NetworkId,
        source_provider_id: [u8; 32],
        authorization: &FinalizedProviderIngestAuthorizationV1,
    ) -> Result<ProviderIngestCurrentAssignmentSnapshotV1, ProviderIngestFinalizedLedgerErrorV1>
    {
        if self.replay_safe_capture
            || network_id != self.network_id
            || source_provider_id == [0; 32]
            || source_provider_id == *self.provider_id.as_bytes()
            || authorization.validate().is_err()
            || authorization.provider_id() != *self.provider_id.as_bytes()
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        for _ in 0..LIVE_SELECTION_ATTEMPTS_V1 {
            if !self
                .activation_ready()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?
            {
                return Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable);
            }
            let (before, _) = self
                .select_visible_committed_key()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
            let generation_before = self
                .archive
                .health_generation()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
            let admission_ancestry = authenticate_retained_admission_ancestor(
                self.archive.as_ref(),
                network_id,
                &before,
                authorization,
            );
            let lookup = self.archive.read_provider_assignment(
                &before,
                self.provider_id,
                ReplicationOrderId::new(authorization.order_id()),
            );
            let (after, _) = self
                .select_visible_committed_key()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
            let generation_after = self
                .archive
                .health_generation()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
            if before != after || generation_before != generation_after {
                continue;
            }
            if !self
                .activation_ready()
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?
            {
                return Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable);
            }
            admission_ancestry?;
            return authenticate_current_assignment(
                network_id,
                self.provider_id,
                source_provider_id,
                authorization,
                lookup.map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?,
            );
        }
        Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
    }
    /// Validate an externally supplied observation between two exact current assignment reads.
    ///
    /// The observation may check admission, advert, revocation, and transport pins, but this
    /// method neither issues a grant nor confers readiness. Its caller must authenticate those
    /// independent inputs and recheck them at every grant use boundary. A changed finalized head,
    /// provider root, source inventory, or revision during observation fails closed.
    pub(crate) fn validate_with_current_source_request(
        &self,
        network_id: NetworkId,
        source_provider_id: [u8; 32],
        request: &ProviderIngestSourceRequestV1,
        assignment_revision: u64,
        inspect: impl FnOnce() -> Result<(), ProviderIngestSourceFetchErrorV1>,
    ) -> Result<(), ProviderIngestSourceFetchErrorV1> {
        let lookup = || {
            self.lookup_current_assignment(network_id, source_provider_id, request.authorization())
                .map_err(|error| match error {
                    ProviderIngestFinalizedLedgerErrorV1::Unavailable => {
                        ProviderIngestSourceFetchErrorV1::Unavailable
                    }
                    ProviderIngestFinalizedLedgerErrorV1::Rejected => {
                        ProviderIngestSourceFetchErrorV1::Rejected
                    }
                })
        };
        let generation_before = self
            .archive
            .health_generation()
            .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)?;
        let before = lookup()?;
        if !before.matches_source_request(source_provider_id, request, assignment_revision) {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        inspect()?;
        let after = lookup()?;
        let generation_after = self
            .archive
            .health_generation()
            .map_err(|_| ProviderIngestSourceFetchErrorV1::Unavailable)?;
        if before != after
            || generation_before != generation_after
            || !after.matches_source_request(source_provider_id, request, assignment_revision)
        {
            return Err(ProviderIngestSourceFetchErrorV1::Rejected);
        }
        Ok(())
    }
    fn read_page_with_claim_factory(
        &self,
        claim_factory: Option<&ProviderIngestFinalizedClaimFactoryV1>,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<ProviderIngestFinalizedAssignmentPageV1, ProviderIngestFinalizedLedgerErrorV1> {
        if self.replay_safe_capture || limit == 0 || limit > self.max_page_rows {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let mut active = self
            .active
            .lock()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let (key, cursor) = match at_finalized_cursor {
            None => {
                if after_order_id.is_some() || active.is_some() {
                    return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
                }
                let (key, _) = self
                    .select_visible_committed_key()
                    .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
                (key, None)
            }
            Some(public_cursor) => {
                let retained = active
                    .as_ref()
                    .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
                let retained_public_cursor = ProviderIngestFinalizedCursorV1 {
                    height: retained.key.height,
                    block_hash: retained.key.block_hash,
                };
                if public_cursor != retained_public_cursor
                    || after_order_id != Some(*retained.cursor.after_order_id.as_bytes())
                {
                    return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
                }
                (retained.key, Some(retained.cursor))
            }
        };
        let archive_page = self
            .archive
            .read_provider_page(&key, self.provider_id, cursor.as_ref(), limit)
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let page = map_archive_page(
            self.network_id,
            self.provider_id,
            &archive_page,
            claim_factory,
        )?;
        *active = archive_page
            .next_cursor
            .map(|cursor| ActiveArchiveScanV1 { key, cursor });
        Ok(page)
    }
    fn read_replay_safe_capture_source_page(
        &self,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<
        ProviderIngestCompletedMusubiCaptureSourcePageV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        if !self.replay_safe_capture
            || limit == 0
            || limit > self.max_page_rows
            || at_finalized_cursor.is_none() != after_order_id.is_none()
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let (key, after_order_id, expected_generation) = match (at_finalized_cursor, after_order_id)
        {
            (None, None) => {
                let (key, generation) = self
                    .select_visible_committed_key()
                    .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
                (key, None, generation)
            }
            (Some(public_cursor), Some(after_order_id)) => {
                let qualification = self
                    .qualify_live()
                    .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
                let key = self
                    .archive
                    .resolve_exact_key(
                        &self.network_id,
                        public_cursor.height,
                        public_cursor.block_hash,
                    )
                    .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
                (key, Some(after_order_id), qualification.generation())
            }
            (None, Some(_)) | (Some(_), None) => unreachable!("validated capture cursor shape"),
        };
        self.read_generation_fenced_capture_source_page(
            &key,
            expected_generation,
            after_order_id,
            limit,
        )
    }
    fn read_generation_fenced_capture_source_page(
        &self,
        key: &ProviderIngestFinalizedArchiveKeyV1,
        expected_generation: u64,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<
        ProviderIngestCompletedMusubiCaptureSourcePageV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        let page = self.read_replay_safe_exact_capture_source_page(key, after_order_id, limit)?;
        if self
            .archive
            .health_generation()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?
            != expected_generation
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable);
        }
        Ok(page)
    }
    fn read_and_sign_completed_musubi_capture_page(
        &self,
        request: ProviderIngestCompletedMusubiCaptureRequestV1,
    ) -> Result<
        ProviderIngestCompletedMusubiSignedCapturePageV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        let at_finalized_cursor = request.at_finalized_cursor();
        let after_order_id = request.after_order_id();
        let limit = usize::from(request.limit());
        self.read_and_sign_completed_musubi_capture_page_with(request, || {
            self.read_replay_safe_capture_source_page(at_finalized_cursor, after_order_id, limit)
        })
    }
    fn read_and_sign_completed_musubi_capture_page_with<ReadSource>(
        &self,
        request: ProviderIngestCompletedMusubiCaptureRequestV1,
        read_source: ReadSource,
    ) -> Result<
        ProviderIngestCompletedMusubiSignedCapturePageV1,
        ProviderIngestFinalizedLedgerErrorV1,
    >
    where
        ReadSource: FnOnce() -> Result<
            ProviderIngestCompletedMusubiCaptureSourcePageV1,
            ProviderIngestFinalizedLedgerErrorV1,
        >,
    {
        if !self.replay_safe_capture || usize::from(request.limit()) > self.max_page_rows {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let signer = self.completed_musubi_capture_signer()?;
        let expected_binding = self.completed_musubi_capture_verifier_binding()?;
        if request.binding() != &expected_binding {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let mut signed_read = signer
            .signed_read
            .lock()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        if signed_read.last_request.as_ref() == Some(&request) {
            return signed_read
                .last_response
                .clone()
                .ok_or(ProviderIngestFinalizedLedgerErrorV1::Unavailable);
        }
        let expected_generation = match signed_read.last_request.as_ref() {
            Some(previous) => previous
                .generation()
                .checked_add(1)
                .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?,
            None => 1,
        };
        if request.generation() != expected_generation {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        #[cfg(test)]
        self.signed_capture_source_reads
            .fetch_add(1, Ordering::SeqCst);
        let source_page = read_source()?;
        let digest =
            provider_ingest_completed_musubi_capture_transcript_digest_v1(&request, &source_page)?;
        let signature = IrohaSignature::try_new(signer.key_pair.private_key(), &digest)
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let signature: [u8; 64] = signature
            .payload()
            .try_into()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        let response =
            ProviderIngestCompletedMusubiSignedCapturePageV1::from_untrusted_reader_parts(
                request.clone(),
                source_page,
                signature,
            );
        signed_read.last_request = Some(request);
        signed_read.last_response = Some(response.clone());
        Ok(response)
    }
    fn read_replay_safe_exact_capture_source_page(
        &self,
        key: &ProviderIngestFinalizedArchiveKeyV1,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<
        ProviderIngestCompletedMusubiCaptureSourcePageV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        if !self.replay_safe_capture || limit == 0 || limit > self.max_page_rows {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let cursor = if let Some(after_order_id) = after_order_id {
            let first = self
                .archive
                .read_provider_page(key, self.provider_id, None, 1)
                .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
            Some(ProviderIngestFinalizedArchiveCursorV1 {
                key: *key,
                provider_id: self.provider_id,
                provider_state_root: first.provider_state_root,
                after_order_id: ReplicationOrderId::new(after_order_id),
            })
        } else {
            None
        };
        let archive_page = self
            .archive
            .read_provider_page(key, self.provider_id, cursor.as_ref(), limit)
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        map_archive_capture_source_page(self.network_id, self.provider_id, &archive_page)
    }
    #[cfg(test)]
    fn read_page_without_musubi_claims_for_test(
        &self,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<ProviderIngestFinalizedAssignmentPageV1, ProviderIngestFinalizedLedgerErrorV1> {
        self.read_page_with_claim_factory(None, at_finalized_cursor, after_order_id, limit)
    }
}
impl ProviderIngestFinalizedLedgerV1 for ArchivedProviderIngestFinalizedLedgerV1 {
    fn read_assignment_page(
        &self,
        claim_factory: ProviderIngestFinalizedClaimFactoryV1,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> ProviderIngestFutureV1<
        '_,
        Result<ProviderIngestFinalizedAssignmentPageV1, ProviderIngestFinalizedLedgerErrorV1>,
    > {
        let query = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    query.read_page_with_claim_factory(
                        Some(&claim_factory),
                        at_finalized_cursor,
                        after_order_id,
                        limit,
                    )
                }),
            )
            .await
            .unwrap_or(Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable))
        })
    }
}
impl ProviderIngestCompletedMusubiSignedCaptureLedgerV1
    for ArchivedProviderIngestFinalizedLedgerV1
{
    fn capture_verifier_binding(
        &self,
    ) -> Result<
        ProviderIngestCompletedMusubiCaptureVerifierBindingV1,
        ProviderIngestFinalizedLedgerErrorV1,
    > {
        self.completed_musubi_capture_verifier_binding()
    }
    fn read_signed_completed_musubi_capture_page(
        &self,
        request: ProviderIngestCompletedMusubiCaptureRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        Result<
            ProviderIngestCompletedMusubiSignedCapturePageV1,
            ProviderIngestFinalizedLedgerErrorV1,
        >,
    > {
        let query = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    query.read_and_sign_completed_musubi_capture_page(request)
                }),
            )
            .await
            .unwrap_or(Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable))
        })
    }
}
fn authenticate_current_assignment(
    network_id: NetworkId,
    destination_provider_id: ProviderId,
    source_provider_id: [u8; 32],
    authorization: &FinalizedProviderIngestAuthorizationV1,
    lookup: ProviderIngestFinalizedArchiveAssignmentLookupV1,
) -> Result<ProviderIngestCurrentAssignmentSnapshotV1, ProviderIngestFinalizedLedgerErrorV1> {
    let ProviderIngestFinalizedArchiveAssignmentLookupV1 {
        key,
        provider_id,
        provider_state_root,
        assignment,
        source_provider_ids,
    } = lookup;
    let row = assignment.ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
    let mut previous_source = None;
    for source in &source_provider_ids {
        if *source == [0; 32]
            || source == destination_provider_id.as_bytes()
            || previous_source.is_some_and(|previous| previous >= *source)
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        previous_source = Some(*source);
    }
    let admission_cursor = authorization.admission_finalized_cursor();
    // This structural helper does not authenticate history. The live reader first resolves the
    // immutable admission cursor against the Kura-qualified archive chain. An independent
    // finalized admission service must still authenticate council lineage and current revocation
    // before any grant is issued or used.
    let has_current_admission_anchor = admission_cursor.height < key.height
        || admission_cursor.height == key.height && admission_cursor.block_hash == key.block_hash;
    let musubi_matches = match (
        authorization.musubi_context(),
        row.replication_order.musubi_archive,
        row.musubi_archive.as_ref(),
    ) {
        (None, None, None) => true,
        (Some(context), Some(archive_id), Some(binding)) => {
            context.network_id() == &network_id
                && context.archive_id() == archive_id
                && binding.archive_id == archive_id
                && binding.replication_order == row.replication_order.order_id
                && binding.validate().is_ok()
                && binding.commitment.root_cid == row.pin_manifest.root_cid
                && binding.commitment.chunker == row.pin_manifest.chunker
                && binding.commitment.chunk_plan_digest.as_bytes()
                    == &row.pin_manifest.chunk_digest_sha3_256
                && binding.commitment.por_root.as_bytes() == &row.pin_manifest.por_root
                && binding.commitment.content_length == row.pin_manifest.content_length
        }
        _ => false,
    };
    if authorization.validate().is_err()
        || key.network_id != network_id
        || provider_id != destination_provider_id
        || row.provider_id != destination_provider_id
        || provider_state_root == [0; 32]
        || source_provider_id == [0; 32]
        || source_provider_id == *destination_provider_id.as_bytes()
        || !source_provider_ids.contains(&source_provider_id)
        || authorization.provider_id() != *destination_provider_id.as_bytes()
        || !has_current_admission_anchor
        || row.finalized_anchor.height != key.height
        || row.finalized_anchor.block_hash != key.block_hash
        || row.finalized_at_unix_ms != key.finalized_at_unix_ms
        || row.replication_order.order_id.as_bytes() != &authorization.order_id()
        || row.expected_assignment_revision == 0
        || row.expected_assignment_revision != row.replication_order.assignment_revision
        || row
            .replication_order
            .provider_completion(destination_provider_id)
            .is_some()
        || !matches!(
            &row.replication_order.status,
            ReplicationOrderStatus::Pending
        )
        || !matches!(&row.pin_manifest.status, PinStatus::Approved(_))
        || row.completion_epoch.is_none()
        || row.pin_manifest.digest.as_bytes() != &authorization.manifest_digest()
        || row.replication_order.manifest_digest != row.pin_manifest.digest
        || row.pin_manifest.root_cid.as_bytes() != authorization.manifest_cid()
        || row.replication_order.manifest_root_cid != row.pin_manifest.root_cid
        || row.pin_manifest.chunker.to_handle() != authorization.chunker_handle()
        || row.pin_manifest.chunk_digest_sha3_256 != authorization.chunk_digest_sha3_256()
        || row.pin_manifest.por_root != authorization.por_root()
        || row.pin_manifest.content_length != authorization.content_length()
        || !musubi_matches
    {
        return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
    }
    Ok(ProviderIngestCurrentAssignmentSnapshotV1 {
        key,
        provider_state_root,
        assignment: row,
        source_provider_ids,
    })
}
fn map_archive_page(
    expected_network_id: NetworkId,
    expected_provider_id: ProviderId,
    page: &ProviderIngestFinalizedArchivePageV1,
    claim_factory: Option<&ProviderIngestFinalizedClaimFactoryV1>,
) -> Result<ProviderIngestFinalizedAssignmentPageV1, ProviderIngestFinalizedLedgerErrorV1> {
    if page.provider_id != expected_provider_id {
        return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
    }
    let finalized_cursor = ProviderIngestFinalizedCursorV1 {
        height: page.key.height,
        block_hash: page.key.block_hash,
    };
    let pin_cursor = PinManifestFinalizedCursorV1 {
        height: page.key.height,
        block_hash: page.key.block_hash,
    };
    let mut rows = Vec::new();
    rows.try_reserve(page.rows.len())
        .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
    for row in &page.rows {
        if row.provider_id != expected_provider_id
            || row.finalized_anchor.height != page.key.height
            || row.finalized_anchor.block_hash != page.key.block_hash
            || row.finalized_at_unix_ms != page.key.finalized_at_unix_ms
            || row.expected_assignment_revision != row.replication_order.assignment_revision
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let completion_authority =
            match (row.expected_owner.as_ref(), row.expected_authority.as_ref()) {
                (Some(owner), Some(authority))
                    if authority.is_valid() && &authority.provider_owner == owner =>
                {
                    Some(authority.clone())
                }
                (_, None) => None,
                _ => {
                    return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
                }
            };
        let musubi_archive = row
            .musubi_archive
            .clone()
            .map(|binding| {
                claim_factory
                    .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?
                    .seal_musubi_archive(
                        &expected_network_id,
                        finalized_cursor,
                        *row.replication_order.order_id.as_bytes(),
                        &row.pin_manifest,
                        binding,
                    )
            })
            .transpose()?;
        let completed_musubi_archive = match row.musubi_archive.clone() {
            Some(binding)
                if row
                    .replication_order
                    .provider_completion(expected_provider_id)
                    .is_some() =>
            {
                Some(
                    claim_factory
                        .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?
                        .seal_completed_musubi_archive(
                            &expected_network_id,
                            finalized_cursor,
                            expected_provider_id,
                            &row.replication_order,
                            &row.pin_manifest,
                            binding,
                        )?,
                )
            }
            Some(_) | None => None,
        };
        rows.push(ProviderIngestFinalizedAssignmentV1 {
            pin: PinManifestFinalizedRecordV1 {
                finalized_cursor: pin_cursor,
                manifest: row.pin_manifest.clone(),
            },
            order: row.replication_order.clone(),
            musubi_archive,
            completed_musubi_archive,
            provider_owner: row.expected_owner.clone(),
            completion_authority,
            completion_epoch: row.completion_epoch,
            committed_transaction_hash: None,
        });
    }
    let next_after_order_id = page
        .next_cursor
        .as_ref()
        .map(|cursor| *cursor.after_order_id.as_bytes());
    if next_after_order_id.is_some()
        && rows
            .last()
            .is_none_or(|row| Some(*row.order.order_id.as_bytes()) != next_after_order_id)
    {
        return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
    }
    Ok(ProviderIngestFinalizedAssignmentPageV1 {
        finalized_cursor,
        finalized_block_time_ms: page.key.finalized_at_unix_ms,
        rows,
        next_after_order_id,
    })
}
fn map_archive_capture_source_page(
    expected_network_id: NetworkId,
    expected_provider_id: ProviderId,
    page: &ProviderIngestFinalizedArchivePageV1,
) -> Result<ProviderIngestCompletedMusubiCaptureSourcePageV1, ProviderIngestFinalizedLedgerErrorV1>
{
    if page.provider_id != expected_provider_id {
        return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
    }
    let finalized_cursor = ProviderIngestFinalizedCursorV1 {
        height: page.key.height,
        block_hash: page.key.block_hash,
    };
    let pin_cursor = PinManifestFinalizedCursorV1 {
        height: page.key.height,
        block_hash: page.key.block_hash,
    };
    let mut rows = Vec::new();
    rows.try_reserve(page.rows.len())
        .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
    for row in &page.rows {
        if row.provider_id != expected_provider_id
            || row.finalized_anchor.height != page.key.height
            || row.finalized_anchor.block_hash != page.key.block_hash
            || row.finalized_at_unix_ms != page.key.finalized_at_unix_ms
            || row.expected_assignment_revision != row.replication_order.assignment_revision
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let completion_authority =
            match (row.expected_owner.as_ref(), row.expected_authority.as_ref()) {
                (Some(owner), Some(authority))
                    if authority.is_valid() && &authority.provider_owner == owner =>
                {
                    Some(authority.clone())
                }
                (_, None) => None,
                _ => return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            };
        rows.push(
            ProviderIngestCompletedMusubiCaptureSourceRowV1::from_projected_fields(
                PinManifestFinalizedRecordV1 {
                    finalized_cursor: pin_cursor,
                    manifest: row.pin_manifest.clone(),
                },
                row.replication_order.clone(),
                row.musubi_archive.clone(),
                row.expected_owner.clone(),
                completion_authority,
                row.completion_epoch,
                None,
            ),
        );
    }
    let next_after_order_id = page
        .next_cursor
        .as_ref()
        .map(|cursor| *cursor.after_order_id.as_bytes());
    if next_after_order_id.is_some()
        && page.rows.last().is_none_or(|row| {
            Some(*row.replication_order.order_id.as_bytes()) != next_after_order_id
        })
    {
        return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
    }
    Ok(
        ProviderIngestCompletedMusubiCaptureSourcePageV1::from_projected_fields(
            expected_network_id,
            *expected_provider_id.as_bytes(),
            finalized_cursor,
            page.key.finalized_at_unix_ms,
            rows,
            next_after_order_id,
        ),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        query::{
            provider_ingest_finalized::{
                ProviderIngestFinalizedArchiveAssignmentV1, ProviderIngestFinalizedArchiveV1,
                ProviderIngestFinalizedArchivedOrderV1, ProviderIngestFinalizedProjectionV1,
                ProviderIngestFinalizedProviderProjectionV1,
            },
            store::LiveQueryStore,
        },
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        block::{BlockHeader, SignedBlock},
        musubi::{
            MusubiArchiveCommitmentV1, MusubiContentDigestV1,
            MusubiReplicationOrderArchiveBindingV1,
        },
        sorafs::pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ManifestRootCid, PinManifestRecord, PinPolicy,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderCompletionRecord, ReplicationOrderId,
            ReplicationOrderRecord, ReplicationOrderStatus,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::metadata::Metadata;
    use sorafs_manifest::capacity::{
        REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1,
        ReplicationOrderV1,
    };
    use sorafs_node::FinalizedProviderIngestMusubiContextV1;
    fn physical_tempdir() -> std::io::Result<tempfile::TempDir> {
        let temp_root = std::env::temp_dir().canonicalize()?;
        tempfile::Builder::new()
            .prefix("irohad-provider-ingest-finalized-")
            .tempdir_in(temp_root)
    }
    fn archive_config() -> SorafsProviderIngestFinalizedArchive {
        SorafsProviderIngestFinalizedArchive {
            relative_root: PathBuf::from("provider-ingest-finalized-v1"),
            max_record_bytes: 2 * 1024 * 1024,
            max_archive_entries: 8,
            max_total_bytes: 16 * 1024 * 1024,
            max_providers_per_anchor: 8,
            max_orders_per_provider: 8,
            max_total_orders_per_anchor: 16,
            max_page_rows: 2,
            max_kura_tip_lag_blocks: 0,
            retention_authority: None,
        }
    }
    fn empty_state(chain_id: &ChainId, kura: &Arc<Kura>) -> Arc<State> {
        Arc::new(State::new_with_chain_for_testing(
            World::default(),
            Arc::clone(kura),
            LiveQueryStore::start_test(),
            chain_id.clone(),
        ))
    }
    fn test_network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            [seed; 32],
        )))
    }
    fn account(seed: u8) -> AccountId {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic account key");
        AccountId::new(key.public_key().clone())
    }
    fn replay_safe_archived_order(
        order_seed: u8,
        provider_id: ProviderId,
    ) -> ProviderIngestFinalizedArchivedOrderV1 {
        let digest = ManifestDigest::new([order_seed.wrapping_add(0x20); 32]);
        let root = ManifestRootCid::from_blake3_digest([order_seed.wrapping_add(0x30); 32])
            .expect("capture replay manifest root");
        let chunker = ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        };
        let mut pin_manifest = PinManifestRecord::new(
            digest,
            root,
            chunker,
            [order_seed.wrapping_add(0x40); 32],
            [order_seed.wrapping_add(0x50); 32],
            4_096,
            PinPolicy {
                retention_epoch: 100,
                ..PinPolicy::default()
            },
            account(1),
            1,
            None,
            None,
            Metadata::default(),
        );
        pin_manifest.approve(1, None);
        let order_id = [order_seed; 32];
        let canonical = ReplicationOrderV1 {
            version: REPLICATION_ORDER_VERSION_V1,
            order_id,
            manifest_cid: root.as_bytes().to_vec(),
            manifest_digest: *digest.as_bytes(),
            chunking_profile: "sorafs.sf1@1.0.0".to_owned(),
            target_replicas: 1,
            assignments: vec![ReplicationAssignmentV1 {
                provider_id: *provider_id.as_bytes(),
                slice_gib: 1,
                lane: None,
            }],
            issued_at: 1,
            deadline_at: 100,
            sla: ReplicationOrderSlaV1 {
                ingest_deadline_secs: 10,
                min_availability_percent_milli: 99_000,
                min_por_success_percent_milli: 99_000,
            },
            metadata: Vec::new(),
        };
        canonical
            .validate()
            .expect("capture replay canonical order");
        ProviderIngestFinalizedArchivedOrderV1 {
            pin_manifest,
            replication_order: ReplicationOrderRecord {
                order_id: ReplicationOrderId::new(order_id),
                manifest_digest: digest,
                manifest_root_cid: root,
                musubi_archive: None,
                issued_by: account(1),
                issued_epoch: 1,
                deadline_epoch: 100,
                canonical_order: norito::to_bytes(&canonical).expect("capture replay order bytes"),
                assignment_revision: 1,
                provider_completions: Vec::new(),
                status: ReplicationOrderStatus::Pending,
            },
            musubi_archive: None,
        }
    }
    fn completion_record(
        provider_id: ProviderId,
        completed_by: AccountId,
    ) -> ReplicationOrderCompletionRecord {
        ReplicationOrderCompletionRecord {
            provider_id,
            completed_by: completed_by.clone(),
            completion_epoch: 7,
            assignment_revision: 1,
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                (completed_by).clone(),
                completed_by,
                ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: [0x91; 32],
                    revision: 1,
                    predecessor_digest: None,
                    policy_digest: [0x92; 32],
                },
            ),
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 7,
                block_hash: [0x79; 32],
            },
        }
    }
    fn archive_page_with_raw_musubi_binding() -> ProviderIngestFinalizedArchivePageV1 {
        let provider_id = ProviderId::new([0x51; 32]);
        let order_id = ReplicationOrderId::new([0x61; 32]);
        let digest = ManifestDigest::new([0x71; 32]);
        let root_cid = ManifestRootCid::from_blake3_digest([0x72; 32]).expect("root CID");
        let chunker = ChunkerProfileHandle {
            profile_id: 1,
            namespace: "sorafs".to_owned(),
            name: "sf1".to_owned(),
            semver: "1.0.0".to_owned(),
            multihash_code: 0x1f,
        };
        let pin_manifest = PinManifestRecord::new(
            digest,
            root_cid,
            chunker.clone(),
            [0x73; 32],
            [0x74; 32],
            4_096,
            PinPolicy::default(),
            account(1),
            1,
            None,
            None,
            Metadata::default(),
        );
        let commitment = MusubiArchiveCommitmentV1 {
            root_cid,
            chunker,
            chunk_plan_digest: MusubiContentDigestV1::new([0x73; 32]),
            por_root: MusubiContentDigestV1::new([0x74; 32]),
            content_length: 4_096,
            car_digest: MusubiContentDigestV1::new([0x75; 32]),
            car_size: 5_120,
            bundle_digest: MusubiContentDigestV1::new([0x76; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x77; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x78; 32]),
            file_count: 1,
            chunk_count: 1,
        };
        let key = ProviderIngestFinalizedArchiveKeyV1::try_new(
            test_network_id(0x79),
            7,
            [0x79; 32],
            7_000,
        )
        .expect("archive key");
        ProviderIngestFinalizedArchivePageV1 {
            key,
            provider_id,
            provider_state_root: [0x7A; 32],
            rows: vec![ProviderIngestFinalizedArchiveAssignmentV1 {
                provider_id,
                expected_owner: None,
                expected_authority: None,
                expected_assignment_revision: 1,
                finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                    height: key.height,
                    block_hash: key.block_hash,
                },
                finalized_at_unix_ms: key.finalized_at_unix_ms,
                pin_manifest,
                replication_order: ReplicationOrderRecord {
                    order_id,
                    manifest_digest: digest,
                    manifest_root_cid: root_cid,
                    musubi_archive: Some(commitment.archive_id()),
                    issued_by: account(1),
                    issued_epoch: 1,
                    deadline_epoch: 10,
                    canonical_order: vec![1],
                    assignment_revision: 1,
                    provider_completions: Vec::new(),
                    status: ReplicationOrderStatus::Pending,
                },
                musubi_archive: Some(MusubiReplicationOrderArchiveBindingV1::new(
                    order_id,
                    commitment.archive_id(),
                    commitment,
                )),
                completion_epoch: Some(7),
            }],
            next_cursor: None,
        }
    }
    #[test]
    fn relative_archive_root_is_bound_below_daemon_root() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let resolved = resolve_daemon_archive_root(
            daemon_root.path(),
            Path::new("provider-ingest/finalized-v1"),
        )
        .expect("resolve child archive");
        assert!(resolved.starts_with(daemon_root.path()));
        assert!(resolved.ends_with("provider-ingest/finalized-v1"));
        for rejected in [
            Path::new(""),
            Path::new("."),
            Path::new("../escape"),
            daemon_root.path(),
        ] {
            assert!(resolve_daemon_archive_root(daemon_root.path(), rejected).is_err());
        }
    }
    #[test]
    fn enabled_retention_fails_before_open_without_injected_authority() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let kura = Kura::blank_kura_for_testing();
        let mut config = archive_config();
        config.retention_authority = Some(
            iroha_config::parameters::actual::SorafsProviderIngestFinalizedArchiveRetentionAuthority {
                handle:
                    "sealed://sorafs/provider-ingest/archive-retention-primary".to_owned(),
                revision: 7,
                policy_digest: [0xA7; 32],
            },
        );
        assert!(matches!(
            open_provider_ingest_finalized_archive(
                &config,
                &test_network_id(0x41),
                &empty_state(&ChainId::from("retention"), &kura).query_view(),
                kura.as_ref(),
                daemon_root.path(),
                None,
            ),
            Err(
                ProviderIngestFinalizedArchiveStartupErrorV1::RetentionAuthorityConfiguration { .. }
            )
        ));
    }
    #[test]
    fn fresh_height_zero_opens_empty_archive_for_genesis_capture() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let kura = Kura::blank_kura_for_testing();
        let chain_id = ChainId::from("provider-ingest-empty-state");
        let state = empty_state(&chain_id, &kura);
        let network_id = *state.network_id_ref();
        let mut prepared = prepare_provider_ingest_finalized_archive_v1(
            &archive_config(),
            network_id,
            ProviderId::new([0x51; 32]),
            daemon_root.path(),
            &state,
            &kura,
            None,
        )
        .expect("fresh empty archive must await genesis capture");
        assert!(matches!(
            prepared.startup_mode(),
            ProviderIngestFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture
        ));
        assert!(
            daemon_root
                .path()
                .join("provider-ingest-finalized-v1")
                .exists()
        );
        assert!(prepared.archive().is_empty().expect("empty archive"));
        assert!(
            !prepared
                .runtime_query()
                .activation_ready()
                .expect("bootstrap activation gate"),
            "identity readiness must not pretend genesis is already captured"
        );
        assert!(
            !prepared
                .signed_capture_reader
                .as_ref()
                .expect("prepared signed capture reader")
                .activation_ready()
                .expect("bootstrap capture activation gate"),
            "capture readiness must not pretend genesis is already captured"
        );
        let runtime_query = prepared.runtime_query();
        let capture_query = prepared
            .signed_capture_reader
            .as_ref()
            .expect("prepared signed capture reader");
        assert!(!runtime_query.replay_safe_capture);
        assert!(capture_query.replay_safe_capture);
        assert!(
            capture_query
                .capture_signer
                .as_ref()
                .expect("capture signer slot")
                .lock()
                .expect("capture signer slot lock")
                .is_none(),
            "ordinary archive preparation must not initialize an ephemeral signer"
        );
        assert!(
            !Arc::ptr_eq(&runtime_query.active, &capture_query.active),
            "runtime and capture readers must own distinct continuation state"
        );
        let key = ProviderIngestFinalizedArchiveKeyV1::try_new(network_id, 1, [0x52; 32], 1_000)
            .expect("test archive key");
        let runtime_scan = ActiveArchiveScanV1 {
            key,
            cursor: ProviderIngestFinalizedArchiveCursorV1 {
                key,
                provider_id: ProviderId::new([0x51; 32]),
                provider_state_root: [0x53; 32],
                after_order_id: ReplicationOrderId::new([0x54; 32]),
            },
        };
        *runtime_query.active.lock().expect("runtime cursor lock") = Some(runtime_scan.clone());
        assert!(
            capture_query
                .active
                .lock()
                .expect("capture cursor lock")
                .is_none(),
            "starting a runtime scan must not start or advance the capture scan"
        );
        assert_eq!(
            runtime_query
                .active
                .lock()
                .expect("runtime cursor lock")
                .as_ref()
                .expect("runtime scan retained")
                .cursor
                .after_order_id,
            ReplicationOrderId::new([0x54; 32]),
            "the dedicated replay-safe capture reader must not mutate the runtime cursor"
        );
        assert!(
            prepared.take_signed_capture_reader().is_some(),
            "the exact prepared reader must be movable once"
        );
        assert!(
            prepared.take_signed_capture_reader().is_none(),
            "the prepared reader must not expose a second raw tenure"
        );
    }
    #[test]
    fn archive_startup_requires_complete_current_consensus_replay() {
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
    }

    #[test]
    fn current_certified_startup_activates_and_recovers_one_commit_without_sidecars() {
        use iroha_core::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let root = physical_tempdir().unwrap();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let prepare = |chain: &CertifiedTestChain| {
            prepare_provider_ingest_finalized_archive_v1(
                &archive_config(),
                chain.network_id(),
                ProviderId::new([0x51; 32]),
                root.path(),
                chain.state(),
                chain.kura(),
                None,
            )
        };
        let first = prepare(&chain).unwrap();
        assert!(first.runtime_query().activation_ready().unwrap());
        assert_eq!(
            first.query().qualify_live().unwrap().archive_tip().height,
            1
        );
        let generation = first.archive().health_generation().unwrap();
        drop(first);
        // Simulate the only allowed crash gap: Kura and State commit one block before capture.
        chain.commit_at(2_000, Vec::new());
        let recovered = prepare(&chain).unwrap();
        assert!(recovered.runtime_query().activation_ready().unwrap());
        assert_eq!(
            recovered
                .query()
                .qualify_live()
                .unwrap()
                .archive_tip()
                .height,
            2
        );
        assert_eq!(
            recovered.archive().health_generation().unwrap(),
            generation + 1
        );
        drop(recovered);
        let replayed = prepare(&chain).unwrap();
        assert_eq!(
            replayed.archive().health_generation().unwrap(),
            generation + 1
        );
    }
    #[test]
    fn certified_state_before_archive_capture_defers_activation_then_requalifies() {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

        let root = physical_tempdir().unwrap();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let mut config = archive_config();
        config.max_kura_tip_lag_blocks = 2;
        let prepared = prepare_provider_ingest_finalized_archive_v1(
            &config,
            chain.network_id(),
            ProviderId::new([0x51; 32]),
            root.path(),
            chain.state(),
            chain.kura(),
            None,
        )
        .unwrap();
        let reader = prepared.runtime_query();
        assert!(reader.activation_ready().unwrap());
        // This is the actual executor ordering: durable Kura and committed State publish
        // first, then its configured archive captures that exact State before apply completes.
        // The genuine certified chain produces every block and signature; the test withholds
        // only the separate archive capture, without replacing State, Kura or a qualification.
        chain.commit_at(2_000, Vec::new());
        let qualification = reader.qualify_live().unwrap();
        assert_eq!(qualification.archive_tip().height, 1);
        assert_eq!(qualification.kura_tip_height(), 2);
        assert_eq!(qualification.lag_blocks(), 1);
        assert_eq!(chain.state().query_view().height(), 2);
        assert!(
            !reader
                .activation_ready()
                .expect("authenticated publication skew must defer"),
            "an older archive must not declare the new committed State ready"
        );
        let mut bootstrap_reader = reader.as_ref().clone();
        bootstrap_reader.activation_gate = ArchiveActivationGateV1::AwaitingGenesis;
        assert!(
            !bootstrap_reader.activation_ready().unwrap(),
            "the bootstrap reader must also survive later ordinary commits"
        );
        let mut zero_lag = reader.as_ref().clone();
        zero_lag.max_kura_tip_lag_blocks = 0;
        assert!(matches!(
            zero_lag.activation_ready(),
            Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveKuraTipLagExceeded {
                    archive_height: 1,
                    kura_height: 2,
                    lag: 1,
                    maximum: 0,
                }
            )
        ));
        prepared
            .archive()
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap();
        assert!(reader.activation_ready().unwrap());
        assert!(bootstrap_reader.activation_ready().unwrap());
        assert!(zero_lag.activation_ready().unwrap());

        // Finality bindings remain hard errors after prior successful activation.
        let mut wrong_network = reader.as_ref().clone();
        wrong_network.network_id = test_network_id(0x78);
        assert_ne!(wrong_network.network_id, reader.network_id);
        assert!(wrong_network.activation_ready().is_err());
        let mut foreign_kura = reader.as_ref().clone();
        foreign_kura.kura = Kura::blank_kura_for_testing();
        assert!(foreign_kura.activation_ready().is_err());
        assert!(reader.activation_ready().unwrap());

        // A same-height hash substitution is an invalid native anchor, never a deferral.
        let forged_root = physical_tempdir().unwrap();
        let forged_archive = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(
                forged_root.path().join("wrong-anchor"),
                ProviderIngestFinalizedArchiveBoundsV1::try_new(
                    2 * 1024 * 1024,
                    8,
                    16 * 1024 * 1024,
                    8,
                    8,
                    16,
                    2,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let wrong_key =
            ProviderIngestFinalizedArchiveKeyV1::try_new(chain.network_id(), 2, [0x79; 32], 2_000)
                .unwrap();
        assert_ne!(
            wrong_key.block_hash,
            *chain.committed(2).block().hash().as_ref()
        );
        forged_archive
            .insert(ProviderIngestFinalizedProjectionV1 {
                key: wrong_key,
                providers: Vec::new(),
            })
            .unwrap();
        let mut wrong_anchor = reader.as_ref().clone();
        wrong_anchor.archive = forged_archive;
        assert!(matches!(
            wrong_anchor.activation_ready(),
            Err(ProviderIngestFinalizedArchiveErrorV1::ArchiveKuraAnchorMismatch { .. })
        ));

        let archive_root = root.path().join(&config.relative_root);
        let records = archive_root.join("records");
        let record = std::fs::read_dir(&records)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original = std::fs::read(&record).unwrap();
        std::fs::write(&record, [0xff]).unwrap();
        let corrupt = reader.activation_ready();
        std::fs::write(&record, &original).unwrap();
        assert!(
            corrupt.is_err(),
            "malformed retained bytes must remain fatal"
        );
        assert!(reader.activation_ready().unwrap());
        let held = archive_root.join("held-records");
        std::fs::rename(&records, &held).unwrap();
        std::fs::create_dir(&records).unwrap();
        let replaced = reader.activation_ready();
        std::fs::remove_dir(&records).unwrap();
        std::fs::rename(&held, &records).unwrap();
        assert!(replaced.is_err(), "reopened custody must remain fatal");
        assert!(reader.activation_ready().unwrap());

        // The last admitted lag still waits; exceeding the unchanged bound remains fatal.
        chain.commit_at(3_000, Vec::new());
        assert!(!reader.activation_ready().unwrap());
        chain.commit_at(4_000, Vec::new());
        assert_eq!(reader.qualify_live().unwrap().lag_blocks(), 2);
        assert!(!reader.activation_ready().unwrap());
        chain.commit_at(5_000, Vec::new());
        assert!(matches!(
            reader.activation_ready(),
            Err(
                ProviderIngestFinalizedArchiveErrorV1::ArchiveKuraTipLagExceeded {
                    archive_height: 2,
                    kura_height: 5,
                    lag: 3,
                    maximum: 2,
                }
            )
        ));
    }
    #[test]
    fn activation_defers_exhausted_genuine_boundary_drift_without_issuing_readiness() {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

        let root = physical_tempdir().unwrap();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let config = archive_config();
        let prepared = prepare_provider_ingest_finalized_archive_v1(
            &config,
            chain.network_id(),
            ProviderId::new([0x51; 32]),
            root.path(),
            chain.state(),
            chain.kura(),
            None,
        )
        .unwrap();
        let reader = prepared.runtime_query();
        assert!(reader.activation_ready().unwrap());
        let before = reader.live_qualification_attempts.load(Ordering::SeqCst);
        let mut drifts = 0;
        let mut interleave = || {
            drifts += 1;
            chain.commit_at(1_000 + drifts * 1_000, Vec::new());
            prepared
                .archive()
                .capture_certified_view(&chain.state().view(), chain.kura())?;
            Ok(())
        };
        assert!(!reader.activation_ready_observed(&mut interleave).unwrap());
        assert_eq!(drifts, u64::try_from(LIVE_SELECTION_ATTEMPTS_V1).unwrap());
        assert_eq!(
            reader.live_qualification_attempts.load(Ordering::SeqCst) - before,
            LIVE_SELECTION_ATTEMPTS_V1
        );
        assert!(
            reader.activation_ready().unwrap(),
            "settled original writers permit a fresh qualification"
        );
        let key = reader.qualify_live().unwrap().archive_tip().clone();
        let record = prepared.archive().record_path(&key).unwrap();
        let original = std::fs::read(&record).unwrap();
        std::fs::write(&record, [0xff]).unwrap();
        assert!(
            reader.activation_ready().is_err(),
            "stable corrupt storage is still fatal"
        );
        std::fs::write(&record, original).unwrap();
        assert!(reader.activation_ready().unwrap());
    }

    #[test]
    fn native_capture_selection_qualifies_once_and_fences_archive_generation() {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

        let root = physical_tempdir().unwrap();
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit_at(2_000, Vec::new());
        let config = archive_config();
        let provider = ProviderId::new([0x51; 32]);
        let mut prepared = prepare_provider_ingest_finalized_archive_v1(
            &config,
            chain.network_id(),
            provider,
            root.path(),
            chain.state(),
            chain.kura(),
            None,
        )
        .unwrap();
        let query = prepared.take_signed_capture_reader().unwrap();
        let qualification_count = || query.live_qualification_attempts.load(Ordering::SeqCst);
        let expected = |height, time_ms| {
            ProviderIngestCompletedMusubiCaptureSourcePageV1::from_projected_fields(
                chain.network_id(),
                *provider.as_bytes(),
                ProviderIngestFinalizedCursorV1 {
                    height,
                    block_hash: *chain.committed(height).block().hash().as_ref(),
                },
                time_ms,
                Vec::new(),
                None,
            )
        };
        let first_expected = expected(2, 2_000);
        let before = qualification_count();
        assert_eq!(
            query
                .read_replay_safe_capture_source_page(None, None, 1)
                .unwrap(),
            first_expected,
            "native empty capture retains its exact certified head and terminal page"
        );
        assert_eq!(qualification_count() - before, 1);
        let before = qualification_count();
        assert_eq!(
            query
                .read_replay_safe_capture_source_page(None, None, 1)
                .unwrap(),
            first_expected
        );
        assert_eq!(
            qualification_count() - before,
            1,
            "a later scan requalifies"
        );
        assert!(query.active.lock().unwrap().is_none());

        let (selected, selected_generation) = query.select_visible_committed_key().unwrap();
        assert_eq!(selected.height, 2);
        assert_eq!(
            selected_generation,
            prepared.archive().health_generation().unwrap()
        );
        let record = prepared.archive().record_path(&selected).unwrap();
        let original = std::fs::read(&record).unwrap();
        let mut corrupt = original.clone();
        corrupt[0] ^= 1;
        std::fs::write(&record, &corrupt).unwrap();
        let after_selection_corrupt = query.read_generation_fenced_capture_source_page(
            &selected,
            selected_generation,
            None,
            1,
        );
        let next_scan_corrupt = query.read_replay_safe_capture_source_page(None, None, 1);
        std::fs::write(&record, &original).unwrap();
        assert_eq!(
            after_selection_corrupt,
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
        );
        assert_eq!(
            next_scan_corrupt,
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
        );
        assert_eq!(
            query
                .read_generation_fenced_capture_source_page(&selected, selected_generation, None, 1)
                .unwrap(),
            first_expected,
            "restored original source can be revalidated without cached refusal"
        );

        // Genuine publication advances State and Kura, then the same native archive owner.
        // The retained old key is still a valid immutable page; its old generation cannot
        // authorize returning that page after the selection-to-read fence has changed.
        chain.commit_at(3_000, Vec::new());
        assert_eq!(
            query.read_replay_safe_capture_source_page(None, None, 1),
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable),
            "a fresh scan cannot use the old archive while native State has advanced"
        );
        prepared
            .archive()
            .capture_certified_view(&chain.state().query_view(), chain.kura())
            .unwrap();
        assert_eq!(
            prepared.archive().health_generation().unwrap(),
            selected_generation + 1
        );
        assert_eq!(
            query
                .read_replay_safe_exact_capture_source_page(&selected, None, 1)
                .unwrap(),
            first_expected
        );
        assert_eq!(
            query.read_generation_fenced_capture_source_page(
                &selected,
                selected_generation,
                None,
                1
            ),
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
        );
        let next_expected = ProviderIngestCompletedMusubiCaptureSourcePageV1::from_projected_fields(
            chain.network_id(),
            *provider.as_bytes(),
            ProviderIngestFinalizedCursorV1 {
                height: 3,
                block_hash: *chain.committed(3).block().hash().as_ref(),
            },
            3_000,
            Vec::new(),
            None,
        );
        let before = qualification_count();
        assert_eq!(
            query
                .read_replay_safe_capture_source_page(None, None, 1)
                .unwrap(),
            next_expected
        );
        assert_eq!(qualification_count() - before, 1);
        assert!(query.active.lock().unwrap().is_none());

        let mut foreign_kura = query.clone();
        foreign_kura.kura = Kura::blank_kura_for_testing();
        assert_eq!(
            foreign_kura.read_replay_safe_capture_source_page(None, None, 1),
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
        );
        let mut foreign_network = query.clone();
        foreign_network.network_id = test_network_id(0x78);
        assert_ne!(foreign_network.network_id, query.network_id);
        assert_eq!(
            foreign_network.read_replay_safe_capture_source_page(None, None, 1),
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable)
        );
        assert_eq!(
            query
                .read_replay_safe_capture_source_page(None, None, 1)
                .unwrap(),
            next_expected
        );
    }
    #[test]
    fn query_rejects_unbounded_page_before_archive_access() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            8,
            16 * 1024 * 1024,
            8,
            8,
            16,
            2,
        )
        .expect("archive bounds");
        let archive = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(daemon_root.path().join("archive"), bounds)
                .expect("open archive"),
        );
        let kura = Kura::blank_kura_for_testing();
        let chain_id = ChainId::from("provider-ingest-page-limit");
        let state = empty_state(&chain_id, &kura);
        let network_id = *state.network_id_ref();
        let args = ArchivedProviderIngestFinalizedLedgerArgsV1 {
            network_id,
            provider_id: ProviderId::new([0x51; 32]),
            archive,
            kura,
            state,
            max_page_rows: 2,
            max_kura_tip_lag_blocks: 0,
            activation_gate: ArchiveActivationGateV1::StrictLive,
        };
        let query = ArchivedProviderIngestFinalizedLedgerV1::new(args.clone());
        let capture_query = ArchivedProviderIngestFinalizedLedgerV1::new_replay_safe_capture(args);
        assert_eq!(
            query.read_page_without_musubi_claims_for_test(None, None, 0),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected)
        );
        assert_eq!(
            query.read_page_without_musubi_claims_for_test(None, None, 3),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected)
        );
        assert_eq!(
            capture_query.read_page_without_musubi_claims_for_test(None, None, 1),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "capture mode must reject the stateful cursor path"
        );
        assert_eq!(
            query.read_replay_safe_exact_capture_source_page(
                &ProviderIngestFinalizedArchiveKeyV1::try_new(
                    test_network_id(0x58),
                    1,
                    [0x58; 32],
                    1_000,
                )
                .expect("cross-mode archive key"),
                None,
                1,
            ),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "stateful mode must reject the replay-safe capture path"
        );
        assert!(capture_query.replay_safe_capture);
    }
    #[test]
    fn replay_safe_capture_exact_requests_do_not_consume_adapter_cursor_state() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            8,
            16 * 1024 * 1024,
            8,
            8,
            16,
            2,
        )
        .expect("archive bounds");
        let archive = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(
                daemon_root.path().join("capture-replay-archive"),
                bounds,
            )
            .expect("open capture replay archive"),
        );
        let chain_id = ChainId::from("provider-ingest-capture-replay");
        let kura = Kura::blank_kura_for_testing();
        let state = empty_state(&chain_id, &kura);
        let network_id = *state.network_id_ref();
        let provider_id = ProviderId::new([0x56; 32]);
        let key = ProviderIngestFinalizedArchiveKeyV1::try_new(network_id, 7, [0x57; 32], 7_000)
            .expect("capture replay key");
        archive
            .insert(ProviderIngestFinalizedProjectionV1 {
                key,
                providers: vec![ProviderIngestFinalizedProviderProjectionV1 {
                    provider_id,
                    expected_owner: None,
                    expected_authority: None,
                    orders: vec![
                        replay_safe_archived_order(0x61, provider_id),
                        replay_safe_archived_order(0x62, provider_id),
                    ],
                }],
            })
            .expect("insert capture replay projection");
        let query = ArchivedProviderIngestFinalizedLedgerV1::new_replay_safe_capture(
            ArchivedProviderIngestFinalizedLedgerArgsV1 {
                network_id,
                provider_id,
                archive,
                state,
                kura,
                max_page_rows: 2,
                max_kura_tip_lag_blocks: 0,
                activation_gate: ArchiveActivationGateV1::StrictLive,
            },
        );
        let first = query
            .read_replay_safe_exact_capture_source_page(&key, None, 1)
            .expect("first replay-safe capture page");
        let first_replay = query
            .read_replay_safe_exact_capture_source_page(&key, None, 1)
            .expect("replay first capture page after simulated cancellation");
        assert_eq!(first_replay, first);
        let after_order_id = first
            .next_after_order_id()
            .expect("two rows require a continuation");
        let second = query
            .read_replay_safe_exact_capture_source_page(&key, Some(after_order_id), 1)
            .expect("capture continuation");
        let second_replay = query
            .read_replay_safe_exact_capture_source_page(&key, Some(after_order_id), 1)
            .expect("replay capture continuation after validation failure");
        assert_eq!(second_replay, second);
        assert!(second.next_after_order_id().is_none());
        assert!(
            query
                .active
                .lock()
                .expect("capture active cursor lock")
                .is_none(),
            "replay-safe reads must never consume adapter-local cursor state"
        );
    }
    // Keep the stateful cache sequence together so every assertion observes
    // the exact response retained by the immediately preceding generation.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn signed_capture_reader_caches_exact_generation_across_archive_advance() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            8,
            16 * 1024 * 1024,
            8,
            8,
            16,
            2,
        )
        .expect("archive bounds");
        let archive = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(
                daemon_root.path().join("signed-capture-cache-archive"),
                bounds,
            )
            .expect("open signed capture archive"),
        );
        let chain_id = ChainId::from("provider-ingest-signed-capture-cache");
        let provider_id = ProviderId::new([0x66; 32]);
        let genesis_signer = KeyPair::from_seed(vec![0x67; 32], Algorithm::Ed25519);
        let genesis_transaction = TransactionBuilder::new_genesis(
            AccountId::new(genesis_signer.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .sign(genesis_signer.private_key());
        let mut genesis = SignedBlock::genesis(
            vec![genesis_transaction],
            genesis_signer.private_key(),
            None,
            None,
        );
        let proposal_header = genesis.header();
        let proposal_signatures = genesis.signatures().cloned().collect::<Vec<_>>();
        let outputs = vec![
            iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: Ok(iroha_data_model::transaction::DataTriggerSequence::default())
                        .into(),
                    completions: Vec::new(),
                },
            ),
        ];
        let expected_output_tree: iroha_crypto::MerkleTree<
            iroha_data_model::block::execution_output::ExecutionOutputV1,
        > = outputs.iter().map(HashOf::new).collect();
        let output_limits =
            iroha_data_model::parameter::ExecutionOutputPolicyV1::bootstrap().limits();
        genesis
            .set_execution_outputs(
                outputs,
                1,
                Default::default(),
                Vec::new(),
                Default::default(),
                Default::default(),
                &output_limits,
            )
            .expect("attach one canonical successful Network output to archive genesis");
        genesis
            .validate_proposal_commitments()
            .expect("archive genesis must commit its actual proposal inputs");
        genesis
            .validate_execution_outputs(&output_limits)
            .expect("archive genesis outputs, cached tree and complete wire must be canonical");
        assert_eq!(genesis.header(), proposal_header);
        assert_eq!(
            genesis.signatures().cloned().collect::<Vec<_>>(),
            proposal_signatures
        );
        assert_eq!(genesis.committed_fragment_count(), Some(1));
        assert_eq!(
            genesis.output_merkle_commitment(),
            expected_output_tree.commitment()
        );
        assert_eq!(genesis.network_entrypoint_count(), 1);
        assert!(
            genesis
                .network_output_at(0)
                .is_some_and(|(_, output)| output.result.is_ok())
        );
        {
            let mut final_signatures = genesis.signatures();
            let final_signature = final_signatures
                .next()
                .expect("result-bearing archive genesis signature");
            assert_eq!(final_signature.index(), 0);
            assert!(final_signatures.next().is_none());
            final_signature
                .signature()
                .verify_hash(genesis_signer.public_key(), genesis.hash())
                .expect("verify result-bearing archive genesis signature");
        }
        let genesis_hash = *genesis.hash().as_ref();
        let network_id = NetworkId::from_genesis_hash(genesis.hash());
        let kura = Kura::blank_kura_for_testing();
        // Establish the test State's canonical lane-geometry journal before placing a block in
        // Kura. Starting State after an independently stored block correctly rejects the missing
        // journal, while this replay-safe capture test does not exercise State application.
        let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
            World::default(),
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            chain_id.clone(),
            network_id,
        ));
        kura.store_block(
            iroha_data_model::block::SharedSignedBlock::try_new(
                genesis,
                &state.ivm_execution_budget(),
            )
            .expect("admit signed-capture genesis owner"),
        )
        .expect("store signed-capture test genesis");
        let first_key =
            ProviderIngestFinalizedArchiveKeyV1::try_new(network_id, 1, genesis_hash, 1_000)
                .expect("signed capture first key");
        archive
            .insert(ProviderIngestFinalizedProjectionV1 {
                key: first_key,
                providers: vec![ProviderIngestFinalizedProviderProjectionV1 {
                    provider_id,
                    expected_owner: None,
                    expected_authority: None,
                    orders: vec![
                        // A continuation must name an actual immutable predecessor.
                        replay_safe_archived_order(0x01, provider_id),
                        replay_safe_archived_order(0x61, provider_id),
                        replay_safe_archived_order(0x62, provider_id),
                    ],
                }],
            })
            .expect("insert signed capture projection");
        let query = ArchivedProviderIngestFinalizedLedgerV1::new_replay_safe_capture(
            ArchivedProviderIngestFinalizedLedgerArgsV1 {
                network_id,
                provider_id,
                archive: Arc::clone(&archive),
                state,
                kura,
                max_page_rows: 2,
                max_kura_tip_lag_blocks: 0,
                activation_gate: ArchiveActivationGateV1::StrictLive,
            },
        );
        assert_eq!(
            query.read_replay_safe_exact_capture_source_page(&first_key, Some([0x02; 32]), 1),
            Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable),
            "an absent predecessor must not become a fabricated archive continuation"
        );
        let first_source_page = query
            .read_replay_safe_exact_capture_source_page(&first_key, Some([0x01; 32]), 1)
            .expect("first deterministic signed source page");
        let second_source_page = query
            .read_replay_safe_exact_capture_source_page(&first_key, Some([0x61; 32]), 1)
            .expect("second deterministic signed source page");
        let binding = query
            .completed_musubi_capture_verifier_binding()
            .expect("lazy signed capture binding");
        let request_one =
            ProviderIngestCompletedMusubiCaptureRequestV1::try_from_untrusted_reader_parts(
                binding.clone(),
                Some(ProviderIngestFinalizedCursorV1 {
                    height: 1,
                    block_hash: genesis_hash,
                }),
                Some([0x01; 32]),
                1,
                1,
            )
            .expect("generation-one signed request");
        let first = query
            .read_and_sign_completed_musubi_capture_page_with(request_one.clone(), || {
                Ok(first_source_page)
            })
            .expect("generation-one signed page");
        let first_retry = query
            .read_and_sign_completed_musubi_capture_page_with(request_one.clone(), || {
                panic!("an exact generation-one retry must not reread its source")
            })
            .expect("exact generation-one retry");
        assert_eq!(first_retry, first);
        assert_eq!(query.signed_capture_source_reads.load(Ordering::SeqCst), 1);
        let different_same_generation =
            ProviderIngestCompletedMusubiCaptureRequestV1::try_from_untrusted_reader_parts(
                binding.clone(),
                request_one.at_finalized_cursor(),
                Some([0x02; 32]),
                1,
                1,
            )
            .expect("different generation-one request");
        assert_eq!(
            query.read_and_sign_completed_musubi_capture_page_with(
                different_same_generation,
                || panic!("a different same-generation request must fail before source read"),
            ),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected)
        );
        let skipped =
            ProviderIngestCompletedMusubiCaptureRequestV1::try_from_untrusted_reader_parts(
                binding.clone(),
                request_one.at_finalized_cursor(),
                Some([0x61; 32]),
                1,
                3,
            )
            .expect("skipped signed request");
        assert_eq!(
            query.read_and_sign_completed_musubi_capture_page_with(skipped, || {
                panic!("a skipped generation must fail before source read")
            }),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected)
        );
        let request_two =
            ProviderIngestCompletedMusubiCaptureRequestV1::try_from_untrusted_reader_parts(
                binding,
                request_one.at_finalized_cursor(),
                Some([0x61; 32]),
                1,
                2,
            )
            .expect("generation-two signed request");
        let second = query
            .read_and_sign_completed_musubi_capture_page_with(request_two.clone(), || {
                Ok(second_source_page)
            })
            .expect("generation-two signed page");
        assert_eq!(query.signed_capture_source_reads.load(Ordering::SeqCst), 2);
        let advanced_projection = ProviderIngestFinalizedProjectionV1 {
            key: ProviderIngestFinalizedArchiveKeyV1::try_new(network_id, 2, [0x68; 32], 2_000)
                .expect("advanced archive key"),
            providers: vec![ProviderIngestFinalizedProviderProjectionV1 {
                provider_id,
                expected_owner: None,
                expected_authority: None,
                // Every previously pending order remains in immutable committed history.
                orders: vec![
                    replay_safe_archived_order(0x01, provider_id),
                    replay_safe_archived_order(0x61, provider_id),
                    replay_safe_archived_order(0x62, provider_id),
                    replay_safe_archived_order(0x63, provider_id),
                ],
            }],
        };
        for missing in [0x01, 0x61, 0x62] {
            let mut lost_pending = advanced_projection.clone();
            lost_pending.providers[0].orders.retain(|order| {
                order.replication_order.order_id != ReplicationOrderId::new([missing; 32])
            });
            assert!(
                matches!(
                    archive.insert(lost_pending),
                    Err(ProviderIngestFinalizedArchiveErrorV1::InvalidTransition {
                        reason: "pending replication order disappeared from committed history"
                    })
                ),
                "dropping pending order {missing:02x} must not advance the archive"
            );
        }
        archive
            .insert(advanced_projection)
            .expect("advance immutable archive after signed response");
        let second_retry = query
            .read_and_sign_completed_musubi_capture_page_with(request_two, || {
                panic!("a cached generation-two response must not read the advanced archive")
            })
            .expect("cached generation-two response after archive advance");
        assert_eq!(second_retry, second);
        assert_eq!(query.signed_capture_source_reads.load(Ordering::SeqCst), 2);
        assert_eq!(
            query.read_and_sign_completed_musubi_capture_page_with(request_one, || {
                panic!("a lower generation must fail before source read")
            }),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "a lower generation must not replay after the cache advances"
        );
    }
    #[test]
    fn retained_full_cursor_rejects_public_cursor_substitution() {
        let daemon_root = physical_tempdir().expect("daemon root");
        let bounds = ProviderIngestFinalizedArchiveBoundsV1::try_new(
            2 * 1024 * 1024,
            8,
            16 * 1024 * 1024,
            8,
            8,
            16,
            2,
        )
        .expect("archive bounds");
        let archive = Arc::new(
            ProviderIngestFinalizedArchiveV1::try_open(daemon_root.path().join("archive"), bounds)
                .expect("open archive"),
        );
        let kura = Kura::blank_kura_for_testing();
        let chain_id = ChainId::from("provider-ingest-cursor-binding");
        let state = empty_state(&chain_id, &kura);
        let network_id = *state.network_id_ref();
        let provider_id = ProviderId::new([0x51; 32]);
        let query = ArchivedProviderIngestFinalizedLedgerV1::new(
            ArchivedProviderIngestFinalizedLedgerArgsV1 {
                network_id,
                provider_id,
                archive,
                kura,
                state,
                max_page_rows: 2,
                max_kura_tip_lag_blocks: 0,
                activation_gate: ArchiveActivationGateV1::StrictLive,
            },
        );
        let key = ProviderIngestFinalizedArchiveKeyV1::try_new(
            network_id,
            7,
            [0x71; 32],
            1_800_000_000_000,
        )
        .expect("exact key");
        let after_order_id = ReplicationOrderId::new([0x01; 32]);
        *query.active.lock().expect("active cursor lock") = Some(ActiveArchiveScanV1 {
            key,
            cursor: ProviderIngestFinalizedArchiveCursorV1 {
                key,
                provider_id,
                provider_state_root: [0x91; 32],
                after_order_id,
            },
        });
        assert_eq!(
            query.read_page_without_musubi_claims_for_test(None, None, 1),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "an interleaved first page must not replace the retained full cursor"
        );
        assert_eq!(
            query.read_page_without_musubi_claims_for_test(
                Some(ProviderIngestFinalizedCursorV1 {
                    height: 7,
                    block_hash: [0x72; 32],
                }),
                Some(*after_order_id.as_bytes()),
                1,
            ),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "a substituted public hash must fail before archive access"
        );
        assert_eq!(
            query.read_page_without_musubi_claims_for_test(
                Some(ProviderIngestFinalizedCursorV1 {
                    height: 7,
                    block_hash: [0x71; 32],
                }),
                Some([0x02; 32]),
                1,
            ),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "a substituted exclusive boundary must fail before archive access"
        );
    }
    include!("sorafs_provider_ingest_finalized_query/current_source_assignment_tests.rs");
    #[test]
    fn raw_musubi_binding_requires_runtime_issued_claim_factory() {
        let mut page = archive_page_with_raw_musubi_binding();
        assert_eq!(
            map_archive_page(test_network_id(0x91), page.provider_id, &page, None),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "publisher-shaped binding data cannot become a finalized claim"
        );
        page.rows[0]
            .replication_order
            .provider_completions
            .push(completion_record(page.provider_id, account(8)));
        assert_eq!(
            map_archive_page(test_network_id(0x91), page.provider_id, &page, None),
            Err(ProviderIngestFinalizedLedgerErrorV1::Rejected),
            "a finalized completion plus publisher-shaped binding still cannot forge either opaque claim"
        );
        page.rows[0].musubi_archive = None;
        page.rows[0].replication_order.musubi_archive = None;
        let generic = map_archive_page(test_network_id(0x91), page.provider_id, &page, None)
            .expect("generic replication orders need no Musubi claim capability");
        assert!(generic.rows[0].musubi_archive.is_none());
        assert!(generic.rows[0].completed_musubi_archive.is_none());
    }
}
