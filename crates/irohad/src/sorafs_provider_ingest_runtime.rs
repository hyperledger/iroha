//! Supervised production wiring for finalized-ledger SoraFS provider ingest.
//!
//! Authoritative assignments come only from the daemon-owned immutable archive
//! captured inside the Sumeragi commit corridor. Runtime-only source
//! authentication and governed signing use explicitly selected native software custody or
//! deployment-injected providers. Both paths retain exact public qualifications, finalized
//! authority checks and the same durable claim/completion protocol. Secret bytes remain runtime-only.
pub mod https_source;
pub mod https_source_evidence;
pub mod https_source_pool;
#[cfg(any(unix, windows))]
#[path = "sorafs_provider_ingest_runtime/native_attestation.rs"]
mod native_attestation;
#[cfg(any(unix, windows))]
pub(crate) mod native_software;

use crate::sorafs_provider_ingest_finalized_query::{
    ArchivedProviderIngestFinalizedLedgerV1, PreparedProviderIngestFinalizedArchiveV1,
};
use eyre::{Result, WrapErr, bail};
use iroha_config::parameters::{
    actual::{
        SorafsProviderAttestationJournal, SorafsProviderAttestationRuntimeBinding,
        SorafsProviderIngestRuntime,
    },
    defaults::sorafs::storage::provider_ingest_runtime::outbox as provider_ingest_outbox_defaults,
    is_production_runtime_handle,
};
use iroha_core::{
    queue::{Error as QueueError, Queue},
    state::{
        BlockHashRead, State, StateReadOnly as _, WorldReadOnly as _, WorldStateSnapshot as _,
    },
    tx::AcceptedTransaction,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::musubi::{
    MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleVerificationAttestationV1,
    MusubiProviderBundleVerificationPayloadV1,
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::sorafs::CompleteReplicationOrder,
    musubi::MusubiArchiveCommitmentV1,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            PinManifestRecord, PinStatus, ProviderIngestCompletionAuthorityV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId, ReplicationOrderRecord,
            ReplicationOrderStatus, derive_sorafs_auto_replication_order_id_v1,
        },
    },
    transaction::{
        FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
        TransactionPayload,
    },
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use mv::storage::StorageReadOnly as _;
use norito::{core::DecodeLimits, decode_from_bytes_with_limits};
use rand::{rand_core::TryRngCore as _, rngs::OsRng};
use sorafs_car::{
    CarBuildPlan, ChunkStoreError, compute_chunk_plan_digest_sha3,
    musubi::{MusubiBundleVerifierV1, VerifiedMusubiBundleV1},
};
use sorafs_manifest::{
    ManifestV1,
    capacity::{
        MAX_CAPACITY_METADATA_VALUE_BYTES, MAX_REPLICATION_ORDER_ASSIGNMENTS, ReplicationOrderV1,
    },
    validate_registered_chunker_profile,
};
use sorafs_node::provider_ingest_runtime::{
    ProviderIngestAuthenticatedSourcePoolV1, ProviderIngestCompletionSignerBindingV1,
    ProviderIngestCompletionSignerQualificationV1, ProviderIngestLocalStoredV1,
    ProviderIngestRuntimeProviderQualificationV1, ProviderIngestVerifiedMusubiBundleReceiptV1,
};
use sorafs_node::{
    AdmittedPayloadReadLeaseErrorV1, FinalizedProviderIngestAuthorizationV1,
    MusubiProviderAttestationJournalPolicyV1, NodeHandle, NodeStorageError,
    ProviderIngestAuthenticatedSourceFetchV1, ProviderIngestCheckpointExternalErrorV1,
    ProviderIngestCheckpointProviderQualificationV1, ProviderIngestCheckpointRuntimeV1,
    ProviderIngestClaimOwnerV1, ProviderIngestCompletedMusubiCaptureCoordinatorV1,
    ProviderIngestCompletionPayloadBuilderV1, ProviderIngestCompletionPayloadErrorV1,
    ProviderIngestCompletionPayloadRequestV1, ProviderIngestCompletionSignerErrorV1,
    ProviderIngestCompletionSignerPolicyV1, ProviderIngestCompletionSignerResolutionContextV1,
    ProviderIngestCompletionSignerResolverErrorV1, ProviderIngestCompletionSignerResolverV1,
    ProviderIngestCompletionSignerV1, ProviderIngestFinalizedAssignmentPageV1,
    ProviderIngestFinalizedClaimFactoryV1, ProviderIngestFinalizedCursorV1,
    ProviderIngestFinalizedLedgerErrorV1, ProviderIngestFinalizedLedgerV1,
    ProviderIngestFinalizedMusubiArchiveClaimV1, ProviderIngestFutureV1,
    ProviderIngestIngressDispositionV1, ProviderIngestIngressPrepareErrorV1,
    ProviderIngestLocalStorageErrorV1, ProviderIngestLocalStorageV1, ProviderIngestRuntimeErrorV1,
    ProviderIngestRuntimePolicyV1, ProviderIngestRuntimeV1, ProviderIngestSourceFetchErrorV1,
    ProviderIngestSourceRequestV1, ProviderIngestSystemClockV1, ProviderIngestTickOutcomeV1,
    ProviderIngestTransactionIngressV1, ProviderIngestTransactionObservationV1,
    store::{StorageError, StoredManifest},
};
use sorafs_node::{
    MusubiProviderAttestationClaimOwnerV1, MusubiProviderAttestationInventoryErrorV1,
    MusubiProviderAttestationInventoryItemV1, MusubiProviderAttestationInventoryQualificationV1,
    MusubiProviderAttestationInventoryReadbackV1, MusubiProviderAttestationInventoryReaderV1,
    MusubiProviderAttestationInventoryRuntimeErrorV1, MusubiProviderAttestationInventoryRuntimeV1,
    MusubiProviderAttestationInventoryScopeV1, MusubiProviderAttestationInventorySinkV1,
    MusubiProviderAttestationInventoryV1, MusubiProviderAttestationJournalRuntimeV1,
    MusubiProviderAttestationSignerErrorV1, MusubiProviderAttestationSignerQualificationV1,
    MusubiProviderAttestationSignerV1, ProviderIngestCompletedMusubiAttestationDriverV1,
    ProviderIngestMusubiAttestationApprovalRequestV1,
    musubi_provider_attestation_controller_policy_digest_v1,
    validate_musubi_provider_attestation_inventory_binding_v1,
};
use std::{
    cell::Cell,
    fmt,
    io::{self, Read},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SHUTDOWN_WAIT_FLOOR: Duration = Duration::from_secs(2);
const READINESS_STALE_TICK_MULTIPLIER_V1: u32 = 3;
const MILLIS_PER_UNIX_SECOND: u64 = 1_000;
const REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1: usize = 256 * 1024;
const REPLICATION_ORDER_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    MAX_CAPACITY_METADATA_VALUE_BYTES,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1,
    131_072,
    REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
/// Move the exact prepared signed reader into this node's one inert capture tenure.
///
/// This composer is intentionally crate-private and performs no lazy scanner
/// activation, page read, journal or inventory access, signing, transaction
/// submission, registry mutation, or child start. Retaining its result merely
/// prevents any later reader substitution for the same process-local
/// storage/outbox incarnation.
pub(crate) fn compose_inert_completed_musubi_capture_coordinator_v1(
    node: &NodeHandle,
    prepared: &mut PreparedProviderIngestFinalizedArchiveV1,
    network_id: NetworkId,
    max_page_rows: usize,
) -> Result<ProviderIngestCompletedMusubiCaptureCoordinatorV1> {
    let signed_reader = prepared.take_signed_capture_reader().ok_or_else(|| {
        eyre::eyre!("prepared completed-Musubi signed capture reader was already taken")
    })?;
    node.take_provider_ingest_completed_musubi_capture_coordinator(
        network_id,
        max_page_rows,
        Arc::new(signed_reader),
    )
    .wrap_err("reserve the inert completed-Musubi capture coordinator tenure")
}
/// Compose, but do not run, one deployment-bound completed-Musubi effect pump.
///
/// `journal` must come from ordinary `open_journal_runtime`; the node binder
/// rejects a runtime returned by the explicit H0 initialization path. This
/// composer never initializes history, activates capture, starts a child, or calls an effect.
/// Native startup supplies the exact ordinary-open custody before supervising the driver.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_inert_completed_musubi_attestation_driver_v1(
    node: &NodeHandle,
    coordinator: ProviderIngestCompletedMusubiCaptureCoordinatorV1,
    journal: Arc<MusubiProviderAttestationJournalRuntimeV1>,
    state: Arc<State>,
    network_id: NetworkId,
    config: &SorafsProviderAttestationJournal,
    signer: Arc<dyn MusubiProviderAttestationSignerV1>,
    inventory: Arc<dyn MusubiProviderAttestationInventoryRuntimeV1>,
) -> Result<ProviderIngestCompletedMusubiAttestationDriverV1> {
    let provider_id = node
        .config()
        .provider_id()
        .ok_or_else(|| eyre::eyre!("SoraFS provider identity is not configured"))?;
    let policy = provider_attestation_journal_policy(config)?;
    let claim_owner = random_provider_attestation_claim_owner()?;
    let owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1> = state;
    let signer: Arc<dyn MusubiProviderAttestationSignerV1> =
        Arc::new(GovernedMusubiProviderAttestationSignerV1::new(
            signer,
            config.approval_signer.clone(),
            owner_authority,
            network_id,
            provider_id,
        ));
    let inventory: Arc<dyn MusubiProviderAttestationInventoryRuntimeV1> =
        Arc::new(GovernedMusubiProviderAttestationInventoryV1::new(
            inventory,
            config.inventory.clone(),
            network_id,
            provider_id,
        ));
    node.bind_provider_ingest_completed_musubi_attestation_driver_v1(
        coordinator,
        journal,
        claim_owner,
        policy,
        signer,
        inventory,
    )
    .wrap_err("bind inert completed-Musubi provider-attestation effect pump")
}
/// Exact verified source material passed directly into local `SoraFS` storage.
///
/// The reader may stream from a bounded authenticated transport or a
/// deployment-owned temporary object. Its manifest, plan, declared length,
/// `PoR` root, and governed advert have already been authenticated. Payload
/// digest, exact length, zero trailing bytes, and any post-stream provider
/// qualification are finalized only when the reader reaches authenticated
/// EOF; dropping or failing the reader before EOF invalidates the stream.
/// Every underlying read must carry a hard transport deadline no longer than
/// the configured source-operation deadline. URLs, grants, bearer tokens, and
/// credentials are intentionally absent.
pub struct VerifiedProviderIngestPayloadV1 {
    /// Canonical manifest returned by the authenticated source.
    pub manifest: ManifestV1,
    /// Exact CAR build plan bound to `manifest`.
    pub plan: CarBuildPlan,
    /// Authenticated payload stream whose verification completes at exact EOF.
    pub reader: Box<dyn Read + Send>,
}
impl fmt::Debug for VerifiedProviderIngestPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderIngestPayloadV1")
            .field("manifest_digest", &self.manifest.digest().ok())
            .field("content_length", &self.plan.content_length)
            .field("reader", &"<verified stream>")
            .finish()
    }
}
impl VerifiedProviderIngestPayloadV1 {
    /// Construct exact verified material without copying payload bytes.
    #[must_use]
    pub fn new(manifest: ManifestV1, plan: CarBuildPlan, reader: Box<dyn Read + Send>) -> Self {
        Self {
            manifest,
            plan,
            reader,
        }
    }
}
/// Runtime-only authenticated source provider.
///
/// Implementations must resolve only current governance-admitted signed
/// adverts, use authenticated bounded grants with pinned trust, and perform
/// exact streaming verification before returning. Secrets and source
/// locations must never be exposed through `Debug`, logs, or readiness
/// artifacts.
pub trait ProviderIngestAuthenticatedSourceRuntimeV1:
    ProviderIngestAuthenticatedSourceFetchV1<Fetched = VerifiedProviderIngestPayloadV1>
{
    /// Stable production identity compared with `iroha_config`.
    fn runtime_handle(&self) -> &str;
    /// Exact public source-pool revision and policy digest.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure when the public qualification cannot be
    /// authenticated.
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestSourceFetchErrorV1,
    >;
    /// Canonical, identity-pinned governed provider inventory.
    ///
    /// Production startup requires at least two non-local providers and reads
    /// this exact slice again after readiness probing and on every worker tick.
    fn source_provider_ids(&self) -> &[[u8; 32]];
    /// Non-mutating authenticated readiness probe.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure when the authenticated source cannot be
    /// qualified without mutation.
    fn check_readiness(&self) -> std::result::Result<(), ProviderIngestSourceFetchErrorV1>;
}
impl ProviderIngestAuthenticatedSourceRuntimeV1
    for ProviderIngestAuthenticatedSourcePoolV1<VerifiedProviderIngestPayloadV1>
{
    fn runtime_handle(&self) -> &str {
        ProviderIngestAuthenticatedSourcePoolV1::runtime_handle(self)
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestSourceFetchErrorV1,
    > {
        Ok(ProviderIngestAuthenticatedSourcePoolV1::qualification(self))
    }
    fn source_provider_ids(&self) -> &[[u8; 32]] {
        ProviderIngestAuthenticatedSourcePoolV1::source_provider_ids(self)
    }
    fn check_readiness(&self) -> std::result::Result<(), ProviderIngestSourceFetchErrorV1> {
        ProviderIngestAuthenticatedSourcePoolV1::check_readiness(self)
    }
}
/// Runtime-only governed signer resolver.
///
/// Resolution must validate the requested owner, signer policy, and exact
/// non-zero assignment revision against immutable governance/assignment state
/// at the supplied finalized cursor, including current key rotation and
/// revocation. It must not infer any of those values from the transaction
/// payload. The returned signer must repeat the resolved checks atomically with
/// signing and sign only a payload matching that independently pinned context.
pub trait ProviderIngestGovernedSignerResolverRuntimeV1: Send + Sync + 'static {
    /// Stable production identity compared with `iroha_config`.
    fn runtime_handle(&self) -> &str;
    /// Exact public resolver revision and policy digest.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure when the public qualification cannot be
    /// authenticated.
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestCompletionSignerResolverErrorV1,
    >;
    /// Exact public signer/key binding exposed by this resolver.
    ///
    /// # Errors
    ///
    /// Returns a fixed payload-free resolver failure when the binding cannot
    /// be authenticated.
    fn signer_binding(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerBindingV1,
        ProviderIngestCompletionSignerResolverErrorV1,
    >;
    /// Non-mutating signer and governance-readiness probe.
    ///
    /// # Errors
    ///
    /// Returns a payload-free failure when the configured signer binding
    /// cannot be qualified without mutation.
    fn check_readiness(
        &self,
    ) -> std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1>;
    /// Resolve one governed signer for the exact finalized authorization.
    fn resolve(
        &self,
        context: ProviderIngestCompletionSignerResolutionContextV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<
            Option<Arc<dyn ProviderIngestCompletionSignerV1>>,
            ProviderIngestCompletionSignerResolverErrorV1,
        >,
    >;
}
fn validate_authenticated_source_qualification(
    source: &dyn ProviderIngestAuthenticatedSourceRuntimeV1,
    expected: ProviderIngestRuntimeProviderQualificationV1,
) -> std::result::Result<(), ProviderIngestSourceFetchErrorV1> {
    if !expected.is_valid() {
        return Err(ProviderIngestSourceFetchErrorV1::Rejected);
    }
    let actual = match source.qualification() {
        Ok(qualification) => qualification,
        Err(ProviderIngestSourceFetchErrorV1::Unavailable) => {
            return Err(ProviderIngestSourceFetchErrorV1::Unavailable);
        }
        Err(
            ProviderIngestSourceFetchErrorV1::ContentRejected
            | ProviderIngestSourceFetchErrorV1::Rejected,
        ) => return Err(ProviderIngestSourceFetchErrorV1::Rejected),
    };
    if !actual.is_valid() || actual != expected {
        return Err(ProviderIngestSourceFetchErrorV1::Rejected);
    }
    Ok(())
}
#[derive(Clone)]
struct AuthenticatedSourceAdapterV1 {
    source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
    expected_qualification: ProviderIngestRuntimeProviderQualificationV1,
}
impl ProviderIngestAuthenticatedSourceFetchV1 for AuthenticatedSourceAdapterV1 {
    type Fetched = VerifiedProviderIngestPayloadV1;
    fn fetch(
        &self,
        request: ProviderIngestSourceRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>,
    > {
        Box::pin(async move {
            validate_authenticated_source_qualification(
                self.source.as_ref(),
                self.expected_qualification,
            )?;
            let result = self.source.fetch(request).await;
            let post_fetch_qualification = validate_authenticated_source_qualification(
                self.source.as_ref(),
                self.expected_qualification,
            );
            match (result, post_fetch_qualification) {
                (
                    Err(ProviderIngestSourceFetchErrorV1::Rejected),
                    Ok(()) | Err(ProviderIngestSourceFetchErrorV1::Unavailable),
                )
                | (
                    _,
                    Err(
                        ProviderIngestSourceFetchErrorV1::ContentRejected
                        | ProviderIngestSourceFetchErrorV1::Rejected,
                    ),
                ) => Err(ProviderIngestSourceFetchErrorV1::Rejected),
                (
                    Err(ProviderIngestSourceFetchErrorV1::ContentRejected),
                    Err(ProviderIngestSourceFetchErrorV1::Unavailable),
                ) => Err(ProviderIngestSourceFetchErrorV1::ContentRejected),
                (_, Err(ProviderIngestSourceFetchErrorV1::Unavailable)) => {
                    Err(ProviderIngestSourceFetchErrorV1::Unavailable)
                }
                (result, Ok(())) => result,
            }
        })
    }
}
#[derive(Clone)]
struct GovernedCompletionSignerV1 {
    signer: Arc<dyn ProviderIngestCompletionSignerV1>,
    owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1>,
    provider_id: ProviderId,
    expected_context: ProviderIngestCompletionSignerResolutionContextV1,
    expected_binding: ProviderIngestCompletionSignerBindingV1,
}
fn completion_payload_matches_resolution_context(
    payload: &TransactionPayload,
    context: &ProviderIngestCompletionSignerResolutionContextV1,
    expected_provider_id: ProviderId,
) -> bool {
    if !context.is_valid() || payload.authority() != &context.expected_authority.completion_signer {
        return false;
    }
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        payload.instructions()
    else {
        return false;
    };
    if instructions.len() != 1 {
        return false;
    }
    let Some(completion) = instructions[0]
        .as_any()
        .downcast_ref::<CompleteReplicationOrder>()
    else {
        return false;
    };
    let authority = completion.expected_authority();
    let anchor = completion.finalized_anchor();
    completion.order_id().as_bytes() != &[0; 32]
        && completion.provider_id() == &expected_provider_id
        && *completion.completion_epoch() != 0
        && *completion.expected_assignment_revision() == context.expected_assignment_revision
        && authority.is_valid()
        && authority == &context.expected_authority
        && anchor.height == context.finalized_cursor.height
        && anchor.block_hash == context.finalized_cursor.block_hash
}
impl ProviderIngestCompletionSignerV1 for GovernedCompletionSignerV1 {
    fn runtime_handle(&self) -> &str {
        self.signer.runtime_handle()
    }
    fn authority(&self) -> &AccountId {
        self.signer.authority()
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerQualificationV1,
        ProviderIngestCompletionSignerErrorV1,
    > {
        let qualification = self.signer.qualification()?;
        if self.expected_binding.validate().is_err()
            || self.signer.runtime_handle() != self.expected_binding.runtime_handle.as_str()
            || qualification != self.expected_binding.qualification
            || qualification.validate().is_err()
            || !qualification
                .matches_authority(&self.expected_context.expected_authority.completion_signer)
        {
            return Err(ProviderIngestCompletionSignerErrorV1::Unavailable);
        }
        Ok(qualification)
    }
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.signer.signer_policy()
    }
    fn current_eligibility(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerPolicyV1,
        ProviderIngestCompletionSignerErrorV1,
    > {
        let qualification = self.qualification()?;
        let current_policy = self.signer.current_eligibility()?;
        if !self
            .owner_authority
            .authority_matches(self.provider_id, &self.expected_context.expected_authority)
            || self.signer.authority()
                != &self.expected_context.expected_authority.completion_signer
            || self.signer.signer_policy() != current_policy
            || current_policy != qualification.signer_policy
            || current_policy != self.expected_context.expected_authority.signer_policy
            || !current_policy.is_valid()
        {
            return Err(ProviderIngestCompletionSignerErrorV1::Unavailable);
        }
        Ok(current_policy)
    }
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<SignedTransaction, ProviderIngestCompletionSignerErrorV1>,
    > {
        Box::pin(async move {
            if !completion_payload_matches_resolution_context(
                &payload,
                &self.expected_context,
                self.provider_id,
            ) {
                return Err(ProviderIngestCompletionSignerErrorV1::Rejected);
            }
            self.current_eligibility()?;
            let expected_payload = payload.clone();
            let transaction = self.signer.sign(payload).await?;
            self.current_eligibility()?;
            if transaction.payload() != &expected_payload
                || !completion_payload_matches_resolution_context(
                    transaction.payload(),
                    &self.expected_context,
                    self.provider_id,
                )
            {
                return Err(ProviderIngestCompletionSignerErrorV1::Rejected);
            }
            Ok(transaction)
        })
    }
}
#[derive(Clone)]
struct GovernedSignerResolverAdapterV1 {
    resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
    owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1>,
    provider_id: ProviderId,
    expected_resolver_qualification: ProviderIngestRuntimeProviderQualificationV1,
    expected_signer_binding: ProviderIngestCompletionSignerBindingV1,
}
fn validate_resolver_qualification(
    resolver: &dyn ProviderIngestGovernedSignerResolverRuntimeV1,
    expected: ProviderIngestRuntimeProviderQualificationV1,
) -> std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1> {
    if !expected.is_valid() {
        return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
    }
    let actual = resolver.qualification()?;
    if !actual.is_valid() || actual != expected {
        return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
    }
    Ok(())
}
fn validate_resolver_signer_binding(
    resolver: &dyn ProviderIngestGovernedSignerResolverRuntimeV1,
    expected: &ProviderIngestCompletionSignerBindingV1,
) -> std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1> {
    if expected.validate().is_err() {
        return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
    }
    let actual = resolver.signer_binding()?;
    if actual.validate().is_err() || &actual != expected {
        return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
    }
    Ok(())
}
impl ProviderIngestCompletionSignerResolverV1 for GovernedSignerResolverAdapterV1 {
    type Signer = GovernedCompletionSignerV1;
    fn resolve(
        &self,
        context: ProviderIngestCompletionSignerResolutionContextV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Option<Self::Signer>, ProviderIngestCompletionSignerResolverErrorV1>,
    > {
        Box::pin(async move {
            if !context.is_valid()
                || context.expected_authority.signer_policy
                    != self.expected_signer_binding.qualification.signer_policy
            {
                return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
            }
            validate_resolver_qualification(
                self.resolver.as_ref(),
                self.expected_resolver_qualification,
            )?;
            validate_resolver_signer_binding(
                self.resolver.as_ref(),
                &self.expected_signer_binding,
            )?;
            if !self
                .owner_authority
                .authority_matches(self.provider_id, &context.expected_authority)
            {
                return Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable);
            }
            let expected_context = context.clone();
            let signer = self.resolver.resolve(context).await;
            validate_resolver_qualification(
                self.resolver.as_ref(),
                self.expected_resolver_qualification,
            )?;
            validate_resolver_signer_binding(
                self.resolver.as_ref(),
                &self.expected_signer_binding,
            )?;
            let signer = signer?;
            let Some(signer) = signer else {
                return Ok(None);
            };
            let signer_qualification = match signer.qualification() {
                Ok(qualification) => qualification,
                Err(ProviderIngestCompletionSignerErrorV1::Unavailable) => {
                    return Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable);
                }
                Err(ProviderIngestCompletionSignerErrorV1::Rejected) => {
                    return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
                }
            };
            let expected_policy = match signer.current_eligibility() {
                Ok(policy) => policy,
                Err(ProviderIngestCompletionSignerErrorV1::Unavailable) => {
                    return Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable);
                }
                Err(ProviderIngestCompletionSignerErrorV1::Rejected) => {
                    return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
                }
            };
            if !self
                .owner_authority
                .authority_matches(self.provider_id, &expected_context.expected_authority)
            {
                return Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable);
            }
            if signer.authority() != &expected_context.expected_authority.completion_signer
                || signer.signer_policy() != expected_policy
                || !expected_policy.is_valid()
                || expected_policy != expected_context.expected_authority.signer_policy
                || signer.runtime_handle() != self.expected_signer_binding.runtime_handle.as_str()
                || signer_qualification != self.expected_signer_binding.qualification
                || signer_qualification.validate().is_err()
                || !signer_qualification
                    .matches_authority(&expected_context.expected_authority.completion_signer)
                || expected_policy != signer_qualification.signer_policy
            {
                return Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected);
            }
            Ok(Some(GovernedCompletionSignerV1 {
                signer,
                owner_authority: Arc::clone(&self.owner_authority),
                provider_id: self.provider_id,
                expected_context,
                expected_binding: self.expected_signer_binding.clone(),
            }))
        })
    }
}
trait ProviderIngestFinalizedCompletionAuthorityV1: Send + Sync + 'static {
    fn authority_matches(
        &self,
        provider_id: ProviderId,
        expected: &ProviderIngestCompletionAuthorityV1,
    ) -> bool;
}
impl ProviderIngestFinalizedCompletionAuthorityV1 for State {
    fn authority_matches(
        &self,
        provider_id: ProviderId,
        expected: &ProviderIngestCompletionAuthorityV1,
    ) -> bool {
        let view = self.query_view();
        let world = view.world();
        expected.is_valid()
            && world.accounts().get(&expected.provider_owner).is_some()
            && world.accounts().get(&expected.completion_signer).is_some()
            && world.provider_owners().get(&provider_id) == Some(&expected.provider_owner)
            && world
                .provider_ingest_completion_authorities()
                .get(&provider_id)
                == Some(expected)
            && iroha_core::query::provider_ingest_source::has_provider_completion_permission_v1(
                world,
                &expected.completion_signer,
                provider_id,
            )
    }
}
// Native composition retains this full-authority guard around its exact dedicated-key signer.
#[derive(Clone)]
struct GovernedMusubiProviderAttestationSignerV1 {
    signer: Arc<dyn MusubiProviderAttestationSignerV1>,
    configured_binding: SorafsProviderAttestationRuntimeBinding,
    owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1>,
    expected_network_id: NetworkId,
    expected_provider_id: ProviderId,
}
#[derive(Clone, Copy)]
struct MusubiProviderAttestationRequestBindingV1<'a> {
    payload: &'a MusubiProviderBundleVerificationPayloadV1,
    completion_claim_digest: [u8; 32],
    observed_finalized_cursor: ProviderIngestFinalizedCursorV1,
    signer_policy: ProviderIngestCompletionSignerPolicyV1,
}
type MusubiProviderAttestationApprovalFutureV1<'a> = ProviderIngestFutureV1<
    'a,
    Result<MusubiProviderBundleVerificationAttestationV1, MusubiProviderAttestationSignerErrorV1>,
>;
impl<'a> From<&'a ProviderIngestMusubiAttestationApprovalRequestV1>
    for MusubiProviderAttestationRequestBindingV1<'a>
{
    fn from(request: &'a ProviderIngestMusubiAttestationApprovalRequestV1) -> Self {
        Self {
            payload: request.payload(),
            completion_claim_digest: request.completion_claim_digest(),
            observed_finalized_cursor: request.observed_finalized_cursor(),
            signer_policy: request.signer_policy(),
        }
    }
}
impl GovernedMusubiProviderAttestationSignerV1 {
    fn new(
        signer: Arc<dyn MusubiProviderAttestationSignerV1>,
        configured_binding: SorafsProviderAttestationRuntimeBinding,
        owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1>,
        expected_network_id: NetworkId,
        expected_provider_id: ProviderId,
    ) -> Self {
        Self {
            signer,
            configured_binding,
            owner_authority,
            expected_network_id,
            expected_provider_id,
        }
    }
    fn validate_configured_binding(&self) -> Result<(), MusubiProviderAttestationSignerErrorV1> {
        if !is_production_runtime_handle(&self.configured_binding.handle)
            || self.configured_binding.revision == 0
            || self.configured_binding.policy_digest == [0; 32]
            || self.expected_network_id.as_bytes()[31] & 1 != 1
            || *self.expected_provider_id.as_bytes() == [0; 32]
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        Ok(())
    }
    fn qualified_snapshot(
        &self,
    ) -> Result<
        MusubiProviderAttestationSignerQualificationV1,
        MusubiProviderAttestationSignerErrorV1,
    > {
        self.validate_configured_binding()?;
        let handle_before = self.signer.runtime_handle().to_owned();
        if !is_production_runtime_handle(&handle_before)
            || handle_before != self.configured_binding.handle
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        let qualification = self.signer.qualification()?;
        let expected_controller_policy_digest =
            musubi_provider_attestation_controller_policy_digest_v1(&qualification.authority)
                .map_err(|_| MusubiProviderAttestationSignerErrorV1::Rejected)?;
        if self.signer.runtime_handle() != handle_before
            || qualification.validate().is_err()
            || qualification.adapter_revision() != self.configured_binding.revision
            || qualification.adapter_policy_digest() != self.configured_binding.policy_digest
            || self.signer.authority() != &qualification.authority
            || self.signer.signer_policy() != qualification.signer_policy
            || qualification.controller_policy_digest != expected_controller_policy_digest
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        Ok(qualification)
    }
    fn request_snapshot(
        &self,
        request: MusubiProviderAttestationRequestBindingV1<'_>,
    ) -> Result<
        MusubiProviderAttestationSignerQualificationV1,
        MusubiProviderAttestationSignerErrorV1,
    > {
        let binding = &request.payload.binding;
        let finalized_cursor = request.observed_finalized_cursor;
        let finalized_anchor = binding.finalized_anchor;
        if request.payload.validate().is_err()
            || binding.network_id != self.expected_network_id
            || binding.provider_id != self.expected_provider_id
            || request.completion_claim_digest == [0; 32]
            || finalized_cursor.height == 0
            || finalized_cursor.block_hash == [0; 32]
            || !request.signer_policy.is_valid()
            || binding.completed_by != binding.completion_authority.completion_signer
            || request.signer_policy != binding.completion_authority.signer_policy
            || finalized_anchor.height > finalized_cursor.height
            || finalized_anchor.height == finalized_cursor.height
                && finalized_anchor.block_hash != finalized_cursor.block_hash
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        let qualification = self.qualification()?;
        let eligibility = self.current_eligibility()?;
        let expected_controller_policy_digest =
            musubi_provider_attestation_controller_policy_digest_v1(&binding.completed_by)
                .map_err(|_| MusubiProviderAttestationSignerErrorV1::Rejected)?;
        let qualification_matches_completion_authority =
            qualification.authority == binding.completed_by;
        if !qualification_matches_completion_authority
            || qualification.signer_policy != request.signer_policy
            || qualification.controller_policy_digest != expected_controller_policy_digest
            || self.signer.authority() != &binding.completed_by
            || self.signer.signer_policy() != request.signer_policy
            || eligibility != request.signer_policy
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        Ok(qualification)
    }
    async fn approve_bound<'a, Approve>(
        &'a self,
        request: MusubiProviderAttestationRequestBindingV1<'a>,
        approve: Approve,
    ) -> Result<MusubiProviderBundleVerificationAttestationV1, MusubiProviderAttestationSignerErrorV1>
    where
        Approve: FnOnce() -> MusubiProviderAttestationApprovalFutureV1<'a> + Send + 'a,
    {
        self.validate_configured_binding()?;
        let binding = &request.payload.binding;
        if request.payload.validate().is_err()
            || binding.network_id != self.expected_network_id
            || binding.provider_id != self.expected_provider_id
            || request.completion_claim_digest == [0; 32]
            || !request.signer_policy.is_valid()
            || binding.completed_by != binding.completion_authority.completion_signer
            || request.signer_policy != binding.completion_authority.signer_policy
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        let expected_authority = &binding.completion_authority;
        if !self
            .owner_authority
            .authority_matches(self.expected_provider_id, expected_authority)
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        let qualification_before = self.request_snapshot(request)?;
        if !self
            .owner_authority
            .authority_matches(self.expected_provider_id, expected_authority)
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        let approval = approve().await;
        if !self
            .owner_authority
            .authority_matches(self.expected_provider_id, expected_authority)
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        let qualification_after = self.request_snapshot(request);
        if !self
            .owner_authority
            .authority_matches(self.expected_provider_id, expected_authority)
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        let qualification_after = qualification_after?;
        if qualification_after != qualification_before {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        let attestation = approval?;
        if &attestation.payload != request.payload
            || attestation.verify(&request.payload.binding).is_err()
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        Ok(attestation)
    }
}
impl MusubiProviderAttestationSignerV1 for GovernedMusubiProviderAttestationSignerV1 {
    fn runtime_handle(&self) -> &str {
        &self.configured_binding.handle
    }
    fn authority(&self) -> &AccountId {
        self.signer.authority()
    }
    fn qualification(
        &self,
    ) -> Result<
        MusubiProviderAttestationSignerQualificationV1,
        MusubiProviderAttestationSignerErrorV1,
    > {
        let before = self.qualified_snapshot()?;
        let after = self.qualified_snapshot()?;
        if before != after {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        Ok(after)
    }
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.signer.signer_policy()
    }
    fn current_eligibility(
        &self,
    ) -> Result<ProviderIngestCompletionSignerPolicyV1, MusubiProviderAttestationSignerErrorV1>
    {
        let qualification_before = self.qualified_snapshot()?;
        let eligibility = self.signer.current_eligibility()?;
        let qualification_after = self.qualified_snapshot()?;
        if qualification_before != qualification_after
            || eligibility != qualification_before.signer_policy
            || self.signer.signer_policy() != qualification_before.signer_policy
        {
            return Err(MusubiProviderAttestationSignerErrorV1::Unavailable);
        }
        Ok(eligibility)
    }
    fn approve<'a>(
        &'a self,
        request: &'a ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> MusubiProviderAttestationApprovalFutureV1<'a> {
        Box::pin(self.approve_bound(request.into(), || self.signer.approve(request)))
    }
}
// Private composition fences the exact selected local inventory around every effect.
// Local retention is separate from independently registered native attestation inclusion.
#[derive(Clone)]
struct GovernedMusubiProviderAttestationInventoryV1 {
    inventory: Arc<dyn MusubiProviderAttestationInventoryRuntimeV1>,
    configured_binding: SorafsProviderAttestationRuntimeBinding,
    expected_network_id: NetworkId,
    expected_provider_id: ProviderId,
}
impl GovernedMusubiProviderAttestationInventoryV1 {
    fn new(
        inventory: Arc<dyn MusubiProviderAttestationInventoryRuntimeV1>,
        configured_binding: SorafsProviderAttestationRuntimeBinding,
        expected_network_id: NetworkId,
        expected_provider_id: ProviderId,
    ) -> Self {
        Self {
            inventory,
            configured_binding,
            expected_network_id,
            expected_provider_id,
        }
    }
    fn validate_configured_binding(
        &self,
    ) -> std::result::Result<(), MusubiProviderAttestationInventoryRuntimeErrorV1> {
        if !is_production_runtime_handle(&self.configured_binding.handle)
            || self.configured_binding.revision == 0
            || self.configured_binding.policy_digest == [0; 32]
            || self.expected_network_id.as_bytes()[31] & 1 != 1
            || *self.expected_provider_id.as_bytes() == [0; 32]
        {
            return Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected);
        }
        Ok(())
    }
    fn qualified_snapshot(
        &self,
    ) -> std::result::Result<
        MusubiProviderAttestationInventoryQualificationV1,
        MusubiProviderAttestationInventoryRuntimeErrorV1,
    > {
        self.validate_configured_binding()?;
        let handle_before = self.inventory.runtime_handle().to_owned();
        if !is_production_runtime_handle(&handle_before)
            || handle_before != self.configured_binding.handle
        {
            return Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected);
        }
        let qualification = self.inventory.qualification()?;
        if self.inventory.runtime_handle() != handle_before
            || validate_musubi_provider_attestation_inventory_binding_v1(
                &handle_before,
                &qualification,
            )
            .is_err()
            || qualification.adapter_revision() != self.configured_binding.revision
            || qualification.policy_digest() != self.configured_binding.policy_digest
        {
            return Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected);
        }
        Ok(qualification)
    }
    fn validate_scope(
        &self,
        scope: &MusubiProviderAttestationInventoryScopeV1,
    ) -> std::result::Result<(), MusubiProviderAttestationInventoryErrorV1> {
        if scope.validate().is_err() || scope.network_id != self.expected_network_id {
            return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
        }
        Ok(())
    }
    fn validate_key(
        &self,
        scope: &MusubiProviderAttestationInventoryScopeV1,
        key: MusubiProviderBundleAttestationKeyV1,
    ) -> std::result::Result<(), MusubiProviderAttestationInventoryErrorV1> {
        self.validate_scope(scope)?;
        let key_targets_expected_provider = key.provider_id == self.expected_provider_id;
        if key.validate().is_err()
            || key.archive_id != scope.archive_id
            || key.replication_order != scope.replication_order
            || !key_targets_expected_provider
        {
            return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
        }
        Ok(())
    }
    fn validate_item(
        &self,
        item: &MusubiProviderAttestationInventoryItemV1,
    ) -> std::result::Result<(), MusubiProviderAttestationInventoryErrorV1> {
        if item.validate().is_err() {
            return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
        }
        self.validate_key(item.scope(), item.key())
    }
    fn validate_readback(
        &self,
        scope: &MusubiProviderAttestationInventoryScopeV1,
        key: MusubiProviderBundleAttestationKeyV1,
        readback: &MusubiProviderAttestationInventoryReadbackV1,
    ) -> std::result::Result<(), MusubiProviderAttestationInventoryErrorV1> {
        self.validate_key(scope, key)?;
        if readback.inventory_revision() == 0
            || readback.item().validate().is_err()
            || readback.item().scope() != scope
            || readback.item().key() != key
        {
            return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
        }
        Ok(())
    }
    fn validate_inventory(
        &self,
        scope: &MusubiProviderAttestationInventoryScopeV1,
        inventory: &MusubiProviderAttestationInventoryV1,
    ) -> std::result::Result<(), MusubiProviderAttestationInventoryErrorV1> {
        self.validate_scope(scope)?;
        if inventory.scope() != scope || inventory.validate().is_err() {
            return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
        }
        Ok(())
    }
}
fn map_musubi_inventory_runtime_error(
    error: MusubiProviderAttestationInventoryRuntimeErrorV1,
) -> MusubiProviderAttestationInventoryErrorV1 {
    match error {
        MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable => {
            MusubiProviderAttestationInventoryErrorV1::Unavailable
        }
        MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected => {
            MusubiProviderAttestationInventoryErrorV1::Rejected
        }
    }
}
impl MusubiProviderAttestationInventoryRuntimeV1 for GovernedMusubiProviderAttestationInventoryV1 {
    fn runtime_handle(&self) -> &str {
        &self.configured_binding.handle
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        MusubiProviderAttestationInventoryQualificationV1,
        MusubiProviderAttestationInventoryRuntimeErrorV1,
    > {
        let before = self.qualified_snapshot()?;
        let after = self.qualified_snapshot()?;
        if before != after {
            return Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected);
        }
        Ok(after)
    }
    fn check_readiness(
        &self,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<(), MusubiProviderAttestationInventoryRuntimeErrorV1>,
    > {
        Box::pin(async move {
            let before = self.qualified_snapshot()?;
            let readiness = self.inventory.check_readiness().await;
            let after = self.qualified_snapshot()?;
            if before != after {
                return Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected);
            }
            readiness
        })
    }
}
impl MusubiProviderAttestationInventorySinkV1 for GovernedMusubiProviderAttestationInventoryV1 {
    fn put(
        &self,
        item: MusubiProviderAttestationInventoryItemV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<u64, MusubiProviderAttestationInventoryErrorV1>,
    > {
        Box::pin(async move {
            self.validate_item(&item)?;
            let before = self
                .qualified_snapshot()
                .map_err(map_musubi_inventory_runtime_error)?;
            let result = self.inventory.put(item).await;
            let after = self
                .qualified_snapshot()
                .map_err(map_musubi_inventory_runtime_error)?;
            if before != after {
                return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
            }
            let revision = result?;
            if revision == 0 {
                return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
            }
            Ok(revision)
        })
    }
}
impl MusubiProviderAttestationInventoryReaderV1 for GovernedMusubiProviderAttestationInventoryV1 {
    fn get<'a>(
        &'a self,
        scope: &'a MusubiProviderAttestationInventoryScopeV1,
        key: MusubiProviderBundleAttestationKeyV1,
    ) -> ProviderIngestFutureV1<
        'a,
        std::result::Result<
            Option<MusubiProviderAttestationInventoryReadbackV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    > {
        Box::pin(async move {
            self.validate_key(scope, key)?;
            let before = self
                .qualified_snapshot()
                .map_err(map_musubi_inventory_runtime_error)?;
            let result = self.inventory.get(scope, key).await;
            let after = self
                .qualified_snapshot()
                .map_err(map_musubi_inventory_runtime_error)?;
            if before != after {
                return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
            }
            let readback = result?;
            if let Some(readback) = readback.as_ref() {
                self.validate_readback(scope, key, readback)?;
            }
            Ok(readback)
        })
    }
    fn inventory<'a>(
        &'a self,
        scope: &'a MusubiProviderAttestationInventoryScopeV1,
    ) -> ProviderIngestFutureV1<
        'a,
        std::result::Result<
            Option<MusubiProviderAttestationInventoryV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    > {
        Box::pin(async move {
            self.validate_scope(scope)?;
            let before = self
                .qualified_snapshot()
                .map_err(map_musubi_inventory_runtime_error)?;
            let result = self.inventory.inventory(scope).await;
            let after = self
                .qualified_snapshot()
                .map_err(map_musubi_inventory_runtime_error)?;
            if before != after {
                return Err(MusubiProviderAttestationInventoryErrorV1::Rejected);
            }
            let inventory = result?;
            if let Some(inventory) = inventory.as_ref() {
                self.validate_inventory(scope, inventory)?;
            }
            Ok(inventory)
        })
    }
}
#[derive(Debug, Clone, Copy)]
struct FinalizedSnapshotProbeV1 {
    completed_cursor: Option<ProviderIngestFinalizedCursorV1>,
}
/// Archive-only finalized assignment reader with a payload-free terminal-page
/// observation used by daemon readiness.
#[derive(Clone)]
struct ObservedArchivedFinalizedAssignmentLedgerV1 {
    archived: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
    probe: Arc<Mutex<FinalizedSnapshotProbeV1>>,
}
impl ObservedArchivedFinalizedAssignmentLedgerV1 {
    fn new(
        archived: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
        probe: Arc<Mutex<FinalizedSnapshotProbeV1>>,
    ) -> Self {
        Self { archived, probe }
    }
}
impl ProviderIngestFinalizedLedgerV1 for ObservedArchivedFinalizedAssignmentLedgerV1 {
    fn read_assignment_page(
        &self,
        claim_factory: ProviderIngestFinalizedClaimFactoryV1,
        at_finalized_cursor: Option<ProviderIngestFinalizedCursorV1>,
        after_order_id: Option<[u8; 32]>,
        limit: usize,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<
            ProviderIngestFinalizedAssignmentPageV1,
            ProviderIngestFinalizedLedgerErrorV1,
        >,
    > {
        let archived = Arc::clone(&self.archived);
        let probe = Arc::clone(&self.probe);
        Box::pin(async move {
            let page = archived
                .read_assignment_page(claim_factory, at_finalized_cursor, after_order_id, limit)
                .await?;
            if page.next_after_order_id.is_none() {
                probe
                    .lock()
                    .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?
                    .completed_cursor = Some(page.finalized_cursor);
            }
            Ok(page)
        })
    }
}
#[derive(Clone)]
struct NativeProviderIngestLocalStorageV1 {
    node: NodeHandle,
    state: Arc<State>,
    operation_timeout: Duration,
}
impl NativeProviderIngestLocalStorageV1 {
    fn new(node: NodeHandle, state: Arc<State>, operation_timeout: Duration) -> Self {
        Self {
            node,
            state,
            operation_timeout,
        }
    }
}

fn current_staged_publisher_assignment_v1(
    state: &State,
    authorization: &FinalizedProviderIngestAuthorizationV1,
    expected_revision: Option<u64>,
) -> std::result::Result<u64, StorageError> {
    use iroha_core::query::provider_ingest_source::{
        PublisherSourceBindingV1, authorize_publisher_source_v1,
    };
    let rejected = || {
        StorageError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "publisher staging current native authority unavailable",
        ))
    };
    authorization.validate().map_err(|_| rejected())?;
    let view = state.view();
    let floor = authorization.admission_finalized_cursor();
    iroha_core::query::signer_finality::verify_signer_finality_v1(
        &view,
        floor.height,
        floor.block_hash,
    )
    .map_err(|_| rejected())?;
    let order_id = ReplicationOrderId::new(authorization.order_id());
    let order = view
        .world()
        .replication_orders()
        .get(&order_id)
        .ok_or_else(rejected)?;
    let pin = view
        .world()
        .pin_manifests()
        .get(&order.manifest_digest)
        .ok_or_else(rejected)?;
    if expected_revision.is_some_and(|revision| revision != order.assignment_revision)
        || pin.digest.as_bytes() != &authorization.manifest_digest()
        || pin.root_cid.as_bytes().as_slice() != authorization.manifest_cid()
        || pin.content_length != authorization.content_length()
        || pin.chunk_digest_sha3_256 != authorization.chunk_digest_sha3_256()
        || pin.por_root != authorization.por_root()
        || pin.chunker.to_handle() != authorization.chunker_handle()
    {
        return Err(rejected());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| rejected())?
        .as_secs();
    authorize_publisher_source_v1(
        &view,
        &pin.submitted_by,
        &PublisherSourceBindingV1 {
            provider_id: ProviderId::new(authorization.provider_id()),
            order_id,
            manifest_digest: order.manifest_digest,
            assignment_revision: order.assignment_revision,
        },
        now,
    )
    .map_err(|_| rejected())?;
    Ok(order.assignment_revision)
}
struct DeadlineBoundedReaderV1 {
    inner: Box<dyn Read + Send>,
    deadline: Instant,
    remaining: u64,
    terminal_state: DeadlineBoundedReaderTerminalStateV1,
    #[cfg(test)]
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}
struct ObservedAdmittedPayloadReaderV1<'observation, R> {
    inner: R,
    first_error_kind: &'observation Cell<Option<io::ErrorKind>>,
}
impl<R: Read> Read for ObservedAdmittedPayloadReaderV1<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output).inspect_err(|error| {
            if self.first_error_kind.get().is_none() {
                self.first_error_kind.set(Some(error.kind()));
            }
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadlineBoundedReaderTerminalStateV1 {
    Pending,
    Authenticated,
    Failed(io::ErrorKind),
}
impl DeadlineBoundedReaderV1 {
    fn new(inner: Box<dyn Read + Send>, timeout: Duration, expected_bytes: u64) -> Self {
        Self {
            inner,
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
            remaining: expected_bytes,
            terminal_state: DeadlineBoundedReaderTerminalStateV1::Pending,
            #[cfg(test)]
            clock: Arc::new(Instant::now),
        }
    }
    #[cfg(test)]
    fn new_with_clock(
        inner: Box<dyn Read + Send>,
        timeout: Duration,
        expected_bytes: u64,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let started_at = clock();
        Self {
            inner,
            deadline: started_at.checked_add(timeout).unwrap_or(started_at),
            remaining: expected_bytes,
            terminal_state: DeadlineBoundedReaderTerminalStateV1::Pending,
            clock,
        }
    }
    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        reason = "the production and test clock paths share one reader method"
    )]
    fn current_time(&self) -> Instant {
        Instant::now()
    }
    #[cfg(test)]
    fn current_time(&self) -> Instant {
        (self.clock)()
    }
    fn failure(&mut self, kind: io::ErrorKind, message: &'static str) -> io::Error {
        self.terminal_state = DeadlineBoundedReaderTerminalStateV1::Failed(kind);
        io::Error::new(kind, message)
    }
    fn record_inner_failure(&mut self, error: io::Error) -> io::Error {
        self.terminal_state = DeadlineBoundedReaderTerminalStateV1::Failed(error.kind());
        error
    }
    fn require_live_deadline(&mut self) -> io::Result<()> {
        if self.current_time() >= self.deadline {
            return Err(self.failure(
                io::ErrorKind::TimedOut,
                "provider-ingest verified reader exceeded its operation deadline",
            ));
        }
        Ok(())
    }
    fn authenticate_terminal_eof(&mut self) -> io::Result<usize> {
        self.require_live_deadline()?;
        let mut trailing = [0_u8; 1];
        let result = self.inner.read(&mut trailing);
        self.require_live_deadline()?;
        match result {
            Ok(0) => {
                self.terminal_state = DeadlineBoundedReaderTerminalStateV1::Authenticated;
                Ok(0)
            }
            Ok(_) => Err(self.failure(
                io::ErrorKind::InvalidData,
                "provider-ingest verified reader exceeded its authorized length",
            )),
            Err(error) => Err(self.record_inner_failure(error)),
        }
    }
}
impl Read for DeadlineBoundedReaderV1 {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        match self.terminal_state {
            DeadlineBoundedReaderTerminalStateV1::Authenticated => return Ok(0),
            DeadlineBoundedReaderTerminalStateV1::Failed(kind) => {
                return Err(io::Error::new(
                    kind,
                    "provider-ingest verified reader previously failed",
                ));
            }
            DeadlineBoundedReaderTerminalStateV1::Pending => {}
        }
        if self.remaining == 0 {
            return self.authenticate_terminal_eof();
        }
        self.require_live_deadline()?;
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let read_limit = remaining.min(output.len());
        let result = self.inner.read(&mut output[..read_limit]);
        self.require_live_deadline()?;
        let read = match result {
            Ok(0) => {
                return Err(self.failure(
                    io::ErrorKind::UnexpectedEof,
                    "provider-ingest verified reader ended before its authorized length",
                ));
            }
            Ok(read) if read <= read_limit => read,
            Ok(_) => {
                return Err(self.failure(
                    io::ErrorKind::InvalidData,
                    "provider-ingest verified reader violated its bounded read contract",
                ));
            }
            Err(error) => return Err(self.record_inner_failure(error)),
        };
        let Some(remaining) = self
            .remaining
            .checked_sub(u64::try_from(read).unwrap_or(u64::MAX))
        else {
            return Err(self.failure(
                io::ErrorKind::InvalidData,
                "provider-ingest verified reader exceeded its authorized length",
            ));
        };
        self.remaining = remaining;
        Ok(read)
    }
}
struct BlockingStoreJoinGuardV1(Option<std::thread::JoinHandle<std::thread::Result<()>>>);
impl BlockingStoreJoinGuardV1 {
    fn join(mut self) -> bool {
        self.0
            .take()
            .is_some_and(|thread| crate::panic_recovery::join_thread_recoverable(thread).is_ok())
    }
}
impl Drop for BlockingStoreJoinGuardV1 {
    fn drop(&mut self) {
        if let Some(thread) = self.0.take() {
            let _ = crate::panic_recovery::join_thread_recoverable(thread);
        }
    }
}
impl ProviderIngestLocalStorageV1<VerifiedProviderIngestPayloadV1>
    for NativeProviderIngestLocalStorageV1
{
    fn verify_existing(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Option<ProviderIngestLocalStoredV1>, ProviderIngestLocalStorageErrorV1>,
    > {
        let node = self.node.clone();
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    let existing =
                        verify_existing_manifest(&node, &authorization, musubi_archive.as_ref())?;
                    if existing.is_some() {
                        return Ok(existing);
                    }
                    let revision =
                        current_staged_publisher_assignment_v1(&state, &authorization, None)
                            .map_err(|_| ProviderIngestLocalStorageErrorV1::Retryable)?;
                    let mut current_authority = || {
                        current_staged_publisher_assignment_v1(
                            &state,
                            &authorization,
                            Some(revision),
                        )
                        .map(|_| ())
                    };
                    if node
                        .ingest_staged_publisher_source(
                            &authorization,
                            revision,
                            &mut current_authority,
                        )
                        .map_err(|error| classify_storage_error(&error))?
                        .is_none()
                    {
                        return Ok(None);
                    }
                    verify_existing_manifest(&node, &authorization, musubi_archive.as_ref())
                }),
            )
            .await
            .map_err(|_| ProviderIngestLocalStorageErrorV1::Retryable)?
        })
    }
    fn store(
        &self,
        authorization: FinalizedProviderIngestAuthorizationV1,
        musubi_archive: Option<ProviderIngestFinalizedMusubiArchiveClaimV1>,
        mut fetched: VerifiedProviderIngestPayloadV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<ProviderIngestLocalStoredV1, ProviderIngestLocalStorageErrorV1>,
    > {
        let node = self.node.clone();
        let operation_timeout = self.operation_timeout;
        Box::pin(async move {
            validate_verified_payload(&authorization, &fetched.manifest, &fetched.plan)?;
            fetched.reader = Box::new(DeadlineBoundedReaderV1::new(
                fetched.reader,
                operation_timeout,
                authorization.content_length(),
            ));
            let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
            let thread = crate::panic_recovery::spawn_thread_recoverable(
                std::thread::Builder::new().name("sorafs-provider-ingest-store".to_owned()),
                move || {
                    let result = match node.ingest_manifest(
                        &fetched.manifest,
                        &fetched.plan,
                        &mut fetched.reader,
                    ) {
                        Ok(manifest_id) => finish_newly_admitted_manifest_verification(
                            manifest_id.as_str(),
                            verify_existing_manifest(
                                &node,
                                &authorization,
                                musubi_archive.as_ref(),
                            ),
                        ),
                        Err(NodeStorageError::Storage(StorageError::ManifestExists {
                            manifest_id,
                        })) => {
                            match verify_existing_manifest(
                                &node,
                                &authorization,
                                musubi_archive.as_ref(),
                            ) {
                                Ok(Some(stored)) if stored.manifest_id() == manifest_id => {
                                    Ok(stored)
                                }
                                Ok(Some(_) | None) => {
                                    Err(ProviderIngestLocalStorageErrorV1::Permanent)
                                }
                                Err(error) => Err(error),
                            }
                        }
                        Err(error) => Err(classify_storage_error(&error)),
                    };
                    let _ = result_sender.send(result);
                },
            )
            .map_err(|_| ProviderIngestLocalStorageErrorV1::Retryable)?;
            let guard = BlockingStoreJoinGuardV1(Some(thread));
            let result = result_receiver
                .await
                .map_err(|_| ProviderIngestLocalStorageErrorV1::Retryable)?;
            if !guard.join() {
                return Err(ProviderIngestLocalStorageErrorV1::Retryable);
            }
            result
        })
    }
}
/// Finish verification after this provider-ingest call admitted a manifest.
///
/// Admission may deduplicate into a generic `SoraFS` object that another reference already uses, so
/// a permanent verification failure cannot safely evict the object. `Quarantined` instead requires
/// the provider-ingest runtime to retain the object, durably dead-letter the exact authorization,
/// and make the completion path unreachable. Transient verification failures remain retryable.
// Durable restart recovery revalidates admitted storage before refetch and dead-letters permanent
// failures without evicting shared chunks; the native regression covers a second reopen and replay.
fn finish_newly_admitted_manifest_verification(
    manifest_id: &str,
    verification: std::result::Result<
        Option<ProviderIngestLocalStoredV1>,
        ProviderIngestLocalStorageErrorV1,
    >,
) -> std::result::Result<ProviderIngestLocalStoredV1, ProviderIngestLocalStorageErrorV1> {
    match verification {
        Ok(Some(stored)) if stored.manifest_id() == manifest_id => Ok(stored),
        Ok(Some(_) | None)
        | Err(
            ProviderIngestLocalStorageErrorV1::Permanent
            | ProviderIngestLocalStorageErrorV1::Quarantined,
        ) => Err(ProviderIngestLocalStorageErrorV1::Quarantined),
        Err(ProviderIngestLocalStorageErrorV1::Retryable) => {
            Err(ProviderIngestLocalStorageErrorV1::Retryable)
        }
    }
}
fn verify_existing_manifest(
    node: &NodeHandle,
    authorization: &FinalizedProviderIngestAuthorizationV1,
    musubi_archive: Option<&ProviderIngestFinalizedMusubiArchiveClaimV1>,
) -> std::result::Result<Option<ProviderIngestLocalStoredV1>, ProviderIngestLocalStorageErrorV1> {
    authorization
        .validate()
        .map_err(|_| ProviderIngestLocalStorageErrorV1::Permanent)?;
    let stored = match node.manifest_metadata_by_digest(&authorization.manifest_digest()) {
        Ok(stored) => stored,
        Err(NodeStorageError::Storage(StorageError::ManifestNotFound { .. })) => return Ok(None),
        Err(error) => return Err(classify_storage_error(&error)),
    };
    if !stored.payload_available() {
        return Err(ProviderIngestLocalStorageErrorV1::Quarantined);
    }
    if stored.manifest_digest() != &authorization.manifest_digest()
        || stored.manifest_cid() != authorization.manifest_cid()
        || stored.content_length() != authorization.content_length()
        || stored.chunk_profile_handle() != authorization.chunker_handle()
    {
        return Err(ProviderIngestLocalStorageErrorV1::Permanent);
    }
    let manifest = stored
        .load_manifest()
        .map_err(|error| classify_storage_backend_error(&error))?;
    validate_manifest_binding(authorization, &manifest)?;
    // Existing records are accepted only through StorageBackend's admission
    // invariant, which separately binds raw bytes to the stored plan payload
    // digest and ManifestV1.car_digest to the reconstructed full CARv2 archive.
    let manifest_id = stored.manifest_id().to_owned();
    let claim = match (authorization.musubi_context(), musubi_archive) {
        (None, None) => {
            return Ok(Some(ProviderIngestLocalStoredV1::generic(manifest_id)));
        }
        (Some(_), Some(claim)) => claim,
        (None, Some(_)) | (Some(_), None) => {
            return Err(ProviderIngestLocalStorageErrorV1::Permanent);
        }
    };
    let receipt = verify_existing_musubi_bundle(node, authorization, claim, &stored, &manifest)?;
    Ok(Some(ProviderIngestLocalStoredV1::musubi(
        manifest_id,
        receipt,
    )))
}
fn verify_existing_musubi_bundle(
    node: &NodeHandle,
    authorization: &FinalizedProviderIngestAuthorizationV1,
    claim: &ProviderIngestFinalizedMusubiArchiveClaimV1,
    stored: &StoredManifest,
    manifest: &ManifestV1,
) -> std::result::Result<
    ProviderIngestVerifiedMusubiBundleReceiptV1,
    ProviderIngestLocalStorageErrorV1,
> {
    validate_musubi_claim_binding(authorization, claim)?;
    let verified =
        verify_admitted_musubi_bundle(node, authorization, claim.commitment(), stored, manifest)?;
    ProviderIngestVerifiedMusubiBundleReceiptV1::from_verified_bundle(
        claim,
        authorization,
        &verified,
    )
}
/// Reconstruct and verify one admitted Musubi payload under a fresh lifecycle lease.
///
/// This helper deliberately returns the verifier's closed evidence instead of a persisted
/// pre-completion receipt. The post-completion attestation path instead enters a new admitted
/// payload lifecycle lease and calls
/// `NodeHandle::verify_provider_ingest_completed_musubi_capture_bundle` with
/// the independently sealed, store-instance-bound completed-row claim;
/// possession of this earlier evidence never skips that read or authorizes
/// signing.
fn verify_admitted_musubi_bundle(
    node: &NodeHandle,
    authorization: &FinalizedProviderIngestAuthorizationV1,
    commitment: &MusubiArchiveCommitmentV1,
    stored: &StoredManifest,
    manifest: &ManifestV1,
) -> std::result::Result<VerifiedMusubiBundleV1, ProviderIngestLocalStorageErrorV1> {
    validate_musubi_commitment_binding(authorization, commitment)?;
    let registered_profile = validate_registered_chunker_profile(&manifest.chunking)
        .map_err(|_| ProviderIngestLocalStorageErrorV1::Permanent)?;
    let plan = stored
        .try_to_car_plan(registered_profile.profile)
        .map_err(|error| classify_storage_backend_error(&error))?;
    validate_verified_payload(authorization, manifest, &plan)?;
    let verification = node
        .with_admitted_payload_read_lease(&authorization.manifest_digest(), |lease| {
            if lease.manifest_digest() != &authorization.manifest_digest()
                || lease.content_length() != authorization.content_length()
                || lease.payload_digest() != plan.payload_digest.as_bytes()
            {
                return None;
            }
            let first_read_error = Cell::new(None);
            let verified =
                MusubiBundleVerifierV1::verify_payload_with_factory(&plan, commitment, || {
                    lease
                        .open_reader()
                        .inspect_err(|error| {
                            if first_read_error.get().is_none() {
                                first_read_error.set(Some(error.kind()));
                            }
                        })
                        .map(|inner| ObservedAdmittedPayloadReaderV1 {
                            inner,
                            first_error_kind: &first_read_error,
                        })
                });
            Some((verified, first_read_error.get()))
        })
        .map_err(classify_admitted_payload_lease_error)?
        .ok_or(ProviderIngestLocalStorageErrorV1::Permanent)?;
    match verification {
        (Ok(verified), _) => Ok(verified),
        (Err(_), Some(kind)) if admitted_payload_read_error_is_retryable(kind) => {
            Err(ProviderIngestLocalStorageErrorV1::Retryable)
        }
        (Err(_), _) => Err(ProviderIngestLocalStorageErrorV1::Permanent),
    }
}
fn validate_musubi_claim_binding(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    claim: &ProviderIngestFinalizedMusubiArchiveClaimV1,
) -> std::result::Result<(), ProviderIngestLocalStorageErrorV1> {
    if !claim.matches_authorization(authorization) {
        return Err(ProviderIngestLocalStorageErrorV1::Permanent);
    }
    Ok(())
}
fn validate_musubi_commitment_binding(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    commitment: &MusubiArchiveCommitmentV1,
) -> std::result::Result<(), ProviderIngestLocalStorageErrorV1> {
    let Some(musubi_context) = authorization.musubi_context() else {
        return Err(ProviderIngestLocalStorageErrorV1::Permanent);
    };
    if authorization.validate().is_err()
        || commitment.validate().is_err()
        || musubi_context.archive_id() != commitment.archive_id()
        || commitment.root_cid.as_bytes() != authorization.manifest_cid()
        || commitment.chunker.to_handle() != authorization.chunker_handle()
        || commitment.chunk_plan_digest.as_bytes() != &authorization.chunk_digest_sha3_256()
        || commitment.por_root.as_bytes() != &authorization.por_root()
        || commitment.content_length != authorization.content_length()
    {
        return Err(ProviderIngestLocalStorageErrorV1::Permanent);
    }
    Ok(())
}
const fn classify_admitted_payload_lease_error(
    error: AdmittedPayloadReadLeaseErrorV1,
) -> ProviderIngestLocalStorageErrorV1 {
    match error {
        AdmittedPayloadReadLeaseErrorV1::StorageUnavailable
        | AdmittedPayloadReadLeaseErrorV1::NotAdmitted => {
            ProviderIngestLocalStorageErrorV1::Retryable
        }
        AdmittedPayloadReadLeaseErrorV1::Disabled => ProviderIngestLocalStorageErrorV1::Permanent,
    }
}
const fn admitted_payload_read_error_is_retryable(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::NotFound
            | io::ErrorKind::Other
    )
}
fn validate_manifest_binding(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    manifest: &ManifestV1,
) -> std::result::Result<(), ProviderIngestLocalStorageErrorV1> {
    let digest = manifest
        .digest()
        .map_err(|_| ProviderIngestLocalStorageErrorV1::Permanent)?;
    let profile = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    if digest.as_bytes() != &authorization.manifest_digest()
        || manifest.root_cid.as_slice() != authorization.manifest_cid()
        || profile != authorization.chunker_handle()
        || manifest.chunk_digest_sha3_256 != authorization.chunk_digest_sha3_256()
        || manifest.por_root != authorization.por_root()
        || manifest.content_length != authorization.content_length()
    {
        return Err(ProviderIngestLocalStorageErrorV1::Permanent);
    }
    Ok(())
}
fn validate_verified_payload(
    authorization: &FinalizedProviderIngestAuthorizationV1,
    manifest: &ManifestV1,
    plan: &CarBuildPlan,
) -> std::result::Result<(), ProviderIngestLocalStorageErrorV1> {
    authorization
        .validate()
        .map_err(|_| ProviderIngestLocalStorageErrorV1::Permanent)?;
    validate_manifest_binding(authorization, manifest)?;
    if plan.content_length != authorization.content_length()
        || compute_chunk_plan_digest_sha3(&plan.chunks) != authorization.chunk_digest_sha3_256()
        || u32::try_from(plan.chunk_profile.min_size).ok() != Some(manifest.chunking.min_size)
        || u32::try_from(plan.chunk_profile.target_size).ok() != Some(manifest.chunking.target_size)
        || u32::try_from(plan.chunk_profile.max_size).ok() != Some(manifest.chunking.max_size)
        || u32::try_from(plan.chunk_profile.break_mask).ok() != Some(manifest.chunking.break_mask)
    {
        return Err(ProviderIngestLocalStorageErrorV1::Permanent);
    }
    Ok(())
}
fn classify_storage_error(error: &NodeStorageError) -> ProviderIngestLocalStorageErrorV1 {
    match error {
        NodeStorageError::Storage(error) => classify_storage_backend_error(error),
        NodeStorageError::Disabled | NodeStorageError::Scheduler(_) => {
            ProviderIngestLocalStorageErrorV1::Retryable
        }
    }
}
#[cfg(test)]
fn classify_completed_attestation_manifest_lookup_error(
    error: &NodeStorageError,
) -> ProviderIngestLocalStorageErrorV1 {
    match error {
        NodeStorageError::Disabled => ProviderIngestLocalStorageErrorV1::Permanent,
        NodeStorageError::Storage(StorageError::ManifestNotFound { .. }) => {
            ProviderIngestLocalStorageErrorV1::Retryable
        }
        other => classify_storage_error(other),
    }
}
fn classify_storage_backend_error(error: &StorageError) -> ProviderIngestLocalStorageErrorV1 {
    match error {
        StorageError::ChunkDigestMismatch { .. }
        | StorageError::PayloadLengthMismatch { .. }
        | StorageError::UnsupportedManifestVersion { .. }
        | StorageError::ManifestContentLengthMismatch
        | StorageError::ManifestChunkPlanDigestMismatch
        | StorageError::CarArchiveReconstruction { .. }
        | StorageError::ManifestCarArchiveDigestMismatch
        | StorageError::ManifestCarSizeMismatch { .. }
        | StorageError::ManifestDagCodecMismatch { .. }
        | StorageError::ChunkProfileMismatch
        | StorageError::PorRootMismatch
        | StorageError::ChunkStore(
            ChunkStoreError::UnexpectedEof { .. }
            | ChunkStoreError::DigestMismatch { .. }
            | ChunkStoreError::LengthMismatch { .. }
            | ChunkStoreError::PayloadDigestMismatch
            | ChunkStoreError::SinkChunkOrder { .. }
            | ChunkStoreError::SinkChunkMetadataMismatch { .. }
            | ChunkStoreError::SinkChunkLengthMismatch { .. }
            | ChunkStoreError::SinkChunkDigestMismatch { .. }
            | ChunkStoreError::SinkIncomplete { .. },
        )
        | StorageError::Norito(_)
        | StorageError::PersistentArtifactTooLarge { .. }
        | StorageError::LayoutValueTooLarge { .. }
        | StorageError::InvalidFileLayout { .. }
        | StorageError::CorruptStorageState { .. }
        | StorageError::UnsupportedIndexVersion { .. } => {
            ProviderIngestLocalStorageErrorV1::Permanent
        }
        _ => ProviderIngestLocalStorageErrorV1::Retryable,
    }
}
fn validate_completion_order_binding(
    request: &ProviderIngestCompletionPayloadRequestV1,
    provider_id: ProviderId,
    order_record: &ReplicationOrderRecord,
    pin: &PinManifestRecord,
    current_finalized_unix_epoch: u64,
) -> std::result::Result<(), ProviderIngestCompletionPayloadErrorV1> {
    let order_id = ReplicationOrderId::new(request.authorization.order_id());
    let PinStatus::Approved(approved_epoch) = pin.status else {
        return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
    };
    let is_automatic = order_record.order_id
        == derive_sorafs_auto_replication_order_id_v1(&order_record.manifest_digest);
    if !matches!(order_record.status, ReplicationOrderStatus::Pending)
        || order_record.provider_completion(provider_id).is_some()
        || pin.approved_epoch != Some(approved_epoch)
        || order_record.issued_epoch < approved_epoch
        || is_automatic && order_record.issued_epoch != approved_epoch
        || order_record.assignment_revision != request.expected_assignment_revision
        || request.completion_epoch < order_record.issued_epoch
        || request.completion_epoch > order_record.deadline_epoch
        || request.completion_epoch > current_finalized_unix_epoch
        || current_finalized_unix_epoch > order_record.deadline_epoch
        || order_record.order_id != order_id
        || *order_record.manifest_digest.as_bytes() != request.authorization.manifest_digest()
        || order_record.manifest_root_cid.as_bytes() != request.authorization.manifest_cid()
        || order_record.canonical_order.is_empty()
        || order_record.canonical_order.len() > REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1
    {
        return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
    }
    let order = decode_from_bytes_with_limits::<ReplicationOrderV1>(
        &order_record.canonical_order,
        REPLICATION_ORDER_DECODE_LIMITS_V1,
    )
    .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
    order
        .validate()
        .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
    if norito::to_bytes(&order).map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?
        != order_record.canonical_order
        || order.order_id != request.authorization.order_id()
        || order.manifest_digest != request.authorization.manifest_digest()
        || order.manifest_cid.as_slice() != request.authorization.manifest_cid()
        || order.issued_at != order_record.issued_epoch
        || order.deadline_at != order_record.deadline_epoch
        || !order
            .assignments
            .iter()
            .any(|assignment| assignment.provider_id == request.authorization.provider_id())
        || pin.digest != order_record.manifest_digest
        || pin.root_cid != order_record.manifest_root_cid
        || pin.chunker.to_handle() != request.authorization.chunker_handle()
        || pin.chunk_digest_sha3_256 != request.authorization.chunk_digest_sha3_256()
        || pin.por_root != request.authorization.por_root()
        || pin.content_length != request.authorization.content_length()
    {
        return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
    }
    Ok(())
}
#[derive(Clone)]
struct NativeCompletionPayloadBuilderV1 {
    network_id: NetworkId,
    state: Arc<State>,
    queue: Arc<Queue>,
    ttl: Duration,
    max_signed_transaction_bytes: u64,
}
impl NativeCompletionPayloadBuilderV1 {
    fn unsigned_completion_payload(
        &self,
        request: ProviderIngestCompletionPayloadRequestV1,
        order_id: ReplicationOrderId,
        provider_id: ProviderId,
    ) -> std::result::Result<TransactionPayload, ProviderIngestCompletionPayloadErrorV1> {
        let completion_signer = request.expected_authority.completion_signer.clone();
        let instruction = CompleteReplicationOrder::new(
            order_id,
            provider_id,
            request.completion_epoch,
            request.expected_authority,
            request.expected_assignment_revision,
            ProviderIngestFinalizedAnchorV1 {
                height: request.finalized_cursor.height,
                block_hash: request.finalized_cursor.block_hash,
            },
        );
        let mut builder = TransactionBuilder::new(
            *self.state.network_id_ref(),
            completion_signer,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction]);
        builder.set_ttl(self.ttl);
        builder
            .into_payload()
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)
    }
    fn build_payload_sync(
        &self,
        request: ProviderIngestCompletionPayloadRequestV1,
    ) -> std::result::Result<TransactionPayload, ProviderIngestCompletionPayloadErrorV1> {
        if request.network_id != self.network_id
            || request.finalized_cursor.height == 0
            || request.finalized_cursor.block_hash == [0; 32]
            || request.expected_assignment_revision == 0
            || !request.expected_authority.is_valid()
            || request.expected_authority.provider_owner != request.provider_owner
        {
            return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
        }
        let view = self.state.query_view();
        let height = u64::try_from(view.height())
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        let head_hash = view
            .latest_block_hash()
            .map(|hash| *hash.as_ref())
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Unavailable)?;
        let finalized_height = usize::try_from(request.finalized_cursor.height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        let finalized_at_unix_ms = view
            .block_by_height(finalized_height)
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Unavailable)?
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Unavailable)?
            .header()
            .creation_time_ms;
        let head_at_unix_ms = view
            .latest_block()
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Unavailable)?
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Unavailable)?
            .header()
            .creation_time_ms;
        if view.network_id() != &self.network_id
            || !completion_payload_anchor_matches_committed_chain(
                request.finalized_cursor,
                request.completion_epoch,
                finalized_at_unix_ms,
                height,
                head_hash,
                head_at_unix_ms,
                view.block_hashes(),
            )
        {
            return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
        }
        let provider_id = ProviderId::new(request.authorization.provider_id());
        let order_id = ReplicationOrderId::new(request.authorization.order_id());
        let world = view.world();
        if world.provider_owners().get(&provider_id) != Some(&request.provider_owner) {
            return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
        }
        if world
            .provider_ingest_completion_authorities()
            .get(&provider_id)
            != Some(&request.expected_authority)
        {
            return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
        }
        let order_record = world
            .replication_orders()
            .get(&order_id)
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        let pin = world
            .pin_manifests()
            .get(&order_record.manifest_digest)
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        validate_completion_order_binding(
            &request,
            provider_id,
            order_record,
            pin,
            head_at_unix_ms / MILLIS_PER_UNIX_SECOND,
        )?;
        let mut payload = self.unsigned_completion_payload(request, order_id, provider_id)?;
        let route = self
            .queue
            .route_payload_plan_with_state(&payload, self.state.as_ref())
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        let iroha_core::queue::RoutingPlan::Single(route) = route else {
            return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
        };
        let next_height = height
            .checked_add(1)
            .ok_or(ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        let quote = iroha_core::executor::quote_nexus_fee_admission_draft(
            view.world(),
            &view.nexus,
            &view.pipeline,
            &view.zk.gas,
            &payload,
            payload.creation_time_ms,
            iroha_core::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Unavailable)?,
            next_height,
            Some(route.route.dataspace_id),
        )
        .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        payload.fee_payment = quote.recommended_intent;
        let encoded = norito::to_bytes(&payload)
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Rejected)?;
        if encoded_len
            .checked_add(
                provider_ingest_outbox_defaults::SIGNED_TRANSACTION_ENVELOPE_RESERVE_BYTES_V1,
            )
            .is_none_or(|bytes| bytes > self.max_signed_transaction_bytes)
        {
            return Err(ProviderIngestCompletionPayloadErrorV1::Rejected);
        }
        Ok(payload)
    }
}
impl ProviderIngestCompletionPayloadBuilderV1 for NativeCompletionPayloadBuilderV1 {
    fn build_payload(
        &self,
        request: ProviderIngestCompletionPayloadRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<TransactionPayload, ProviderIngestCompletionPayloadErrorV1>,
    > {
        let builder = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    builder.build_payload_sync(request)
                }),
            )
            .await
            .map_err(|_| ProviderIngestCompletionPayloadErrorV1::Unavailable)?
        })
    }
}
#[derive(Clone)]
struct NativeTransactionIngressV1 {
    state: Arc<State>,
    queue: Arc<Queue>,
}
impl NativeTransactionIngressV1 {
    fn prepare_sync(
        &self,
        transaction: SignedTransaction,
    ) -> std::result::Result<AcceptedTransaction<'static>, ProviderIngestIngressPrepareErrorV1>
    {
        let (max_clock_drift, transaction_parameters) = self.state.transaction_admission_limits();
        AcceptedTransaction::accept(
            transaction,
            self.state.network_id_ref(),
            max_clock_drift,
            transaction_parameters,
            self.state.crypto().as_ref(),
        )
        .map_err(|_| ProviderIngestIngressPrepareErrorV1::Rejected)
    }
    fn expose_sync(
        &self,
        prepared: AcceptedTransaction<'static>,
        transaction: &SignedTransaction,
    ) -> ProviderIngestIngressDispositionV1 {
        if prepared.hash_as_entrypoint() != transaction.hash_as_entrypoint() {
            return ProviderIngestIngressDispositionV1::Rejected;
        }
        match self
            .queue
            .push_with_lane_with_state(prepared, self.state.as_ref())
        {
            Ok(_) => ProviderIngestIngressDispositionV1::Submitted,
            Err(failure)
                if matches!(
                    failure.err,
                    QueueError::InBlockchain | QueueError::IsInQueue
                ) =>
            {
                ProviderIngestIngressDispositionV1::Submitted
            }
            Err(failure)
                if matches!(
                    failure.err,
                    QueueError::Full
                        | QueueError::LatencySaturated
                        | QueueError::MaximumTransactionsPerUser
                ) =>
            {
                ProviderIngestIngressDispositionV1::DefinitelyNotSubmitted
            }
            Err(_) => ProviderIngestIngressDispositionV1::Rejected,
        }
    }
    fn observe_sync(&self, transaction_hash: [u8; 32]) -> ProviderIngestTransactionObservationV1 {
        if transaction_hash == [0; 32] {
            return ProviderIngestTransactionObservationV1::CommittedRejected;
        }
        let hash =
            HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(transaction_hash));
        let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash);
        let Some(height) = self.state.committed_entrypoint_height(&entrypoint_hash) else {
            return if self
                .queue
                .contains_pending_hash(entrypoint_hash, self.state.as_ref())
            {
                ProviderIngestTransactionObservationV1::Pending
            } else {
                ProviderIngestTransactionObservationV1::Unknown
            };
        };
        let Ok(Some(block)) = self.state.block_by_height(height) else {
            return ProviderIngestTransactionObservationV1::Unavailable;
        };
        observe_committed_provider_transaction(&block, hash)
    }
}
/// Read a committed transaction through its explicit Network source/output join.
/// Pipeline and Time outputs never supply an external transaction's disposition.
fn observe_committed_provider_transaction(
    block: &iroha_data_model::SignedBlock,
    transaction_hash: HashOf<SignedTransaction>,
) -> ProviderIngestTransactionObservationV1 {
    let Some(index) = block.network_entrypoints().position(|entrypoint| {
        matches!(entrypoint, TransactionEntrypoint::External(transaction)
            if transaction.hash() == transaction_hash)
    }) else {
        return ProviderIngestTransactionObservationV1::Unavailable;
    };
    // This also validates proposal/source commitments and output ownership.
    if block.validate_output_merkle_cache().is_err() {
        return ProviderIngestTransactionObservationV1::Unavailable;
    }
    match u32::try_from(index)
        .ok()
        .and_then(|index| block.network_output_at(index))
        .map(|(_, output)| output.result.as_ref())
    {
        Some(Ok(_)) => ProviderIngestTransactionObservationV1::CommittedSuccess,
        Some(Err(_)) => ProviderIngestTransactionObservationV1::CommittedRejected,
        None => ProviderIngestTransactionObservationV1::Unavailable,
    }
}

impl ProviderIngestTransactionIngressV1 for NativeTransactionIngressV1 {
    type Prepared = AcceptedTransaction<'static>;
    fn prepare(
        &self,
        transaction: SignedTransaction,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Self::Prepared, ProviderIngestIngressPrepareErrorV1>,
    > {
        let ingress = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    ingress.prepare_sync(transaction)
                }),
            )
            .await
            .map_err(|_| ProviderIngestIngressPrepareErrorV1::Rejected)?
        })
    }
    fn expose(
        &self,
        prepared: Self::Prepared,
        transaction: SignedTransaction,
    ) -> ProviderIngestFutureV1<'_, ProviderIngestIngressDispositionV1> {
        let ingress = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    ingress.expose_sync(prepared, &transaction)
                }),
            )
            .await
            .unwrap_or(ProviderIngestIngressDispositionV1::Ambiguous)
        })
    }
    fn observe(
        &self,
        transaction_hash: [u8; 32],
    ) -> ProviderIngestFutureV1<'_, ProviderIngestTransactionObservationV1> {
        let ingress = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    ingress.observe_sync(transaction_hash)
                }),
            )
            .await
            .unwrap_or(ProviderIngestTransactionObservationV1::Unavailable)
        })
    }
}
#[derive(Debug, Default)]
struct ProviderIngestDaemonCountersV1 {
    successful_ticks: AtomicU64,
    failed_ticks: AtomicU64,
    rows_scanned: AtomicU64,
    jobs_inserted: AtomicU64,
    jobs_finalized: AtomicU64,
    jobs_cancelled: AtomicU64,
    source_jobs_claimed: AtomicU64,
    manifests_stored: AtomicU64,
    completions_signed: AtomicU64,
    completion_submissions: AtomicU64,
}
/// Payload-free supervised provider-ingest metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestDaemonMetricsV1 {
    /// Successful bounded reconciliation ticks.
    pub successful_ticks: u64,
    /// Failed dependency probes or reconciliation ticks.
    pub failed_ticks: u64,
    /// Finalized assignment rows inspected.
    pub rows_scanned: u64,
    /// Durable jobs first admitted.
    pub jobs_inserted: u64,
    /// Jobs reconciled to finalized completion.
    pub jobs_finalized: u64,
    /// Jobs reconciled to authoritative cancellation.
    pub jobs_cancelled: u64,
    /// Source jobs claimed.
    pub source_jobs_claimed: u64,
    /// Exact manifests confirmed durable.
    pub manifests_stored: u64,
    /// Completion transactions signed.
    pub completions_signed: u64,
    /// Completion transaction exposure attempts.
    pub completion_submissions: u64,
}
/// Internal two-state status flag with an explicit boolean projection.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestStatusFlagV1(bool);
impl ProviderIngestStatusFlagV1 {
    /// Return the externally emitted boolean value.
    #[must_use]
    pub const fn is_set(self) -> bool {
        self.0
    }
}
impl From<bool> for ProviderIngestStatusFlagV1 {
    fn from(value: bool) -> Self {
        Self(value)
    }
}
/// Payload-free provider-ingest readiness projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderIngestDaemonStatusV1 {
    /// Whether the supervised worker task is still alive.
    pub worker_running: ProviderIngestStatusFlagV1,
    /// Whether both runtime-only adapters passed the latest probe.
    pub external_dependencies_healthy: ProviderIngestStatusFlagV1,
    /// Whether one bounded tick is currently executing.
    pub tick_in_flight: ProviderIngestStatusFlagV1,
    /// Whether a successful tick is within the configured freshness bound.
    pub last_tick_fresh: ProviderIngestStatusFlagV1,
    /// Latest fully scanned immutable finalized cursor.
    pub completed_scan_cursor: Option<ProviderIngestFinalizedCursorV1>,
    /// Current committed head height.
    pub finalized_head_height: u64,
    /// Whether the completed cursor can still be a prefix of the current
    /// finalized head.
    pub finalized_cursor_consistent: ProviderIngestStatusFlagV1,
    /// Difference between current head and completed scan.
    pub finalized_lag_blocks: u64,
    /// Non-terminal durable outbox rows.
    pub active_jobs: usize,
    /// Terminal durable outbox rows.
    pub terminal_jobs: usize,
    /// Terminal dead letters, which block readiness.
    pub dead_letters: usize,
    /// Operational health/readiness, independent of whether admitted work is
    /// currently drained.
    pub ready: bool,
    /// Whether all admitted work reached a terminal non-dead-letter state.
    pub drained: bool,
    /// Release-gate readiness: operationally ready and fully drained.
    pub release_ready: bool,
}
impl ProviderIngestDaemonStatusV1 {
    /// Return whether the supervised worker is alive.
    #[must_use]
    pub const fn worker_running(&self) -> bool {
        self.worker_running.is_set()
    }
    /// Return whether the external runtime adapters are healthy.
    #[must_use]
    pub const fn external_dependencies_healthy(&self) -> bool {
        self.external_dependencies_healthy.is_set()
    }
    /// Return whether one bounded tick is executing.
    #[must_use]
    pub const fn tick_in_flight(&self) -> bool {
        self.tick_in_flight.is_set()
    }
    /// Return whether the latest successful tick is fresh.
    #[must_use]
    pub const fn last_tick_fresh(&self) -> bool {
        self.last_tick_fresh.is_set()
    }
    /// Return whether the retained finalized cursor matches committed history.
    #[must_use]
    pub const fn finalized_cursor_consistent(&self) -> bool {
        self.finalized_cursor_consistent.is_set()
    }
}
/// Cloneable status/metrics handle retained by `irohad`.
#[derive(Clone)]
pub struct ProviderIngestRuntimeHandleV1 {
    node: NodeHandle,
    state: Arc<State>,
    config: SorafsProviderIngestRuntime,
    probe: Arc<Mutex<FinalizedSnapshotProbeV1>>,
    counters: Arc<ProviderIngestDaemonCountersV1>,
    worker_running: Arc<AtomicBool>,
    external_dependencies_healthy: Arc<AtomicBool>,
    tick_in_flight: Arc<AtomicBool>,
    last_successful_tick: Arc<Mutex<Option<Instant>>>,
}
impl fmt::Debug for ProviderIngestRuntimeHandleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIngestRuntimeHandleV1")
            .field("runtime_state", &"[PAYLOAD-FREE]")
            .finish_non_exhaustive()
    }
}
impl ProviderIngestRuntimeHandleV1 {
    /// Return payload-free status without performing runtime work.
    ///
    /// # Errors
    ///
    /// Returns an error when the finalized view or one payload-free runtime
    /// status projection cannot be read consistently.
    pub fn status(&self) -> Result<ProviderIngestDaemonStatusV1> {
        let completed_scan_cursor = self
            .probe
            .lock()
            .map_err(|_| eyre::eyre!("provider-ingest finalized snapshot probe is poisoned"))?
            .completed_cursor;
        let view = self.state.query_view();
        let finalized_head_height = u64::try_from(view.height())
            .wrap_err("provider-ingest committed height is not representable")?;
        let finalized_head_hash = view
            .latest_block_hash()
            .map(|hash| *hash.as_ref())
            .filter(|hash| *hash != [0; 32])
            .ok_or_else(|| eyre::eyre!("provider-ingest committed head is unavailable"))?;
        let finalized_cursor_consistent = completed_cursor_matches_committed_chain(
            completed_scan_cursor,
            finalized_head_height,
            finalized_head_hash,
            view.block_hashes(),
        );
        let finalized_lag_blocks = finalized_head_height
            .saturating_sub(completed_scan_cursor.map_or(0, |cursor| cursor.height));
        let last_tick_fresh = self
            .last_successful_tick
            .lock()
            .map_err(|_| eyre::eyre!("provider-ingest tick freshness state is poisoned"))?
            .as_ref()
            .is_some_and(|instant| {
                instant.elapsed()
                    <= Duration::from_millis(self.config.scan_interval_ms)
                        .checked_mul(READINESS_STALE_TICK_MULTIPLIER_V1)
                        .unwrap_or(Duration::MAX)
            });
        let (active_jobs, terminal_jobs, dead_letters) = self.outbox_counts()?;
        let worker_running = self.worker_running.load(Ordering::Acquire);
        let external_dependencies_healthy =
            self.external_dependencies_healthy.load(Ordering::Acquire);
        let tick_in_flight = self.tick_in_flight.load(Ordering::Acquire);
        let ready = worker_running
            && external_dependencies_healthy
            && !tick_in_flight
            && last_tick_fresh
            && finalized_cursor_consistent
            && finalized_lag_blocks <= self.config.finalized_archive.max_kura_tip_lag_blocks
            && dead_letters == 0;
        let drained = active_jobs == 0 && dead_letters == 0;
        let release_ready = ready && drained;
        Ok(ProviderIngestDaemonStatusV1 {
            worker_running: worker_running.into(),
            external_dependencies_healthy: external_dependencies_healthy.into(),
            tick_in_flight: tick_in_flight.into(),
            last_tick_fresh: last_tick_fresh.into(),
            completed_scan_cursor,
            finalized_head_height,
            finalized_cursor_consistent: finalized_cursor_consistent.into(),
            finalized_lag_blocks,
            active_jobs,
            terminal_jobs,
            dead_letters,
            ready,
            drained,
            release_ready,
        })
    }
    /// Return payload-free monotonic counters.
    #[must_use]
    pub fn metrics(&self) -> ProviderIngestDaemonMetricsV1 {
        ProviderIngestDaemonMetricsV1 {
            successful_ticks: self.counters.successful_ticks.load(Ordering::Relaxed),
            failed_ticks: self.counters.failed_ticks.load(Ordering::Relaxed),
            rows_scanned: self.counters.rows_scanned.load(Ordering::Relaxed),
            jobs_inserted: self.counters.jobs_inserted.load(Ordering::Relaxed),
            jobs_finalized: self.counters.jobs_finalized.load(Ordering::Relaxed),
            jobs_cancelled: self.counters.jobs_cancelled.load(Ordering::Relaxed),
            source_jobs_claimed: self.counters.source_jobs_claimed.load(Ordering::Relaxed),
            manifests_stored: self.counters.manifests_stored.load(Ordering::Relaxed),
            completions_signed: self.counters.completions_signed.load(Ordering::Relaxed),
            completion_submissions: self.counters.completion_submissions.load(Ordering::Relaxed),
        }
    }
    fn outbox_counts(&self) -> Result<(usize, usize, usize)> {
        let counts = self
            .node
            .finalized_provider_ingest_counts()
            .wrap_err("inspect provider-ingest durable outbox counts")?;
        Ok((counts.active, counts.terminal, counts.dead_letters))
    }
}
fn committed_head_matches_hash_journal(
    head_height: u64,
    head_hash: [u8; 32],
    committed_hashes: &(impl BlockHashRead + ?Sized),
) -> bool {
    usize::try_from(head_height).ok() == Some(committed_hashes.hash_count())
        && committed_hashes
            .hash_count()
            .checked_sub(1)
            .and_then(|index| committed_hashes.hash_at(index))
            .is_some_and(|hash| *hash.as_ref() == head_hash)
}
fn cursor_matches_committed_hashes(
    cursor: ProviderIngestFinalizedCursorV1,
    committed_hashes: &(impl BlockHashRead + ?Sized),
) -> bool {
    let Some(index) = usize::try_from(cursor.height)
        .ok()
        .and_then(|height| height.checked_sub(1))
    else {
        return false;
    };
    cursor.block_hash != [0; 32]
        && committed_hashes
            .hash_at(index)
            .is_some_and(|hash| *hash.as_ref() == cursor.block_hash)
}
fn completion_payload_anchor_matches_committed_chain(
    cursor: ProviderIngestFinalizedCursorV1,
    completion_epoch: u64,
    finalized_at_unix_ms: u64,
    head_height: u64,
    head_hash: [u8; 32],
    head_at_unix_ms: u64,
    committed_hashes: &(impl BlockHashRead + ?Sized),
) -> bool {
    let finalized_unix_epoch = finalized_at_unix_ms / MILLIS_PER_UNIX_SECOND;
    let head_unix_epoch = head_at_unix_ms / MILLIS_PER_UNIX_SECOND;
    cursor.height <= head_height
        && completion_epoch == finalized_unix_epoch
        && finalized_unix_epoch <= head_unix_epoch
        && committed_head_matches_hash_journal(head_height, head_hash, committed_hashes)
        && cursor_matches_committed_hashes(cursor, committed_hashes)
}
fn completed_cursor_matches_committed_chain(
    completed: Option<ProviderIngestFinalizedCursorV1>,
    head_height: u64,
    head_hash: [u8; 32],
    committed_hashes: &(impl BlockHashRead + ?Sized),
) -> bool {
    let Some(completed) = completed else {
        return false;
    };
    completed.height <= head_height
        && committed_head_matches_hash_journal(head_height, head_hash, committed_hashes)
        && cursor_matches_committed_hashes(completed, committed_hashes)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeDependencyProbeV1 {
    Ready,
    Unavailable,
    Rejected,
    TimedOut,
    Panicked,
}
async fn bounded_blocking_readiness_probe<F>(
    deadline: Duration,
    probe: F,
) -> RuntimeDependencyProbeV1
where
    F: FnOnce() -> RuntimeDependencyProbeV1 + Send + 'static,
{
    match tokio::time::timeout(
        deadline,
        crate::panic_recovery::spawn_blocking_recoverable(probe),
    )
    .await
    {
        Ok(joined) => crate::panic_recovery::recover_joined(joined)
            .unwrap_or(RuntimeDependencyProbeV1::Panicked),
        Err(_) => RuntimeDependencyProbeV1::TimedOut,
    }
}
fn source_readiness_probe(
    result: std::result::Result<(), ProviderIngestSourceFetchErrorV1>,
) -> RuntimeDependencyProbeV1 {
    match result {
        Ok(()) => RuntimeDependencyProbeV1::Ready,
        Err(ProviderIngestSourceFetchErrorV1::Unavailable) => RuntimeDependencyProbeV1::Unavailable,
        Err(
            ProviderIngestSourceFetchErrorV1::ContentRejected
            | ProviderIngestSourceFetchErrorV1::Rejected,
        ) => RuntimeDependencyProbeV1::Rejected,
    }
}
fn signer_readiness_probe(
    result: std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1>,
) -> RuntimeDependencyProbeV1 {
    match result {
        Ok(()) => RuntimeDependencyProbeV1::Ready,
        Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable) => {
            RuntimeDependencyProbeV1::Unavailable
        }
        Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected) => {
            RuntimeDependencyProbeV1::Rejected
        }
    }
}
fn combine_runtime_dependency_probes(
    source: RuntimeDependencyProbeV1,
    signer: RuntimeDependencyProbeV1,
) -> RuntimeDependencyProbeV1 {
    if source == RuntimeDependencyProbeV1::Rejected || signer == RuntimeDependencyProbeV1::Rejected
    {
        RuntimeDependencyProbeV1::Rejected
    } else if source == RuntimeDependencyProbeV1::Panicked
        || signer == RuntimeDependencyProbeV1::Panicked
    {
        RuntimeDependencyProbeV1::Panicked
    } else if source == RuntimeDependencyProbeV1::TimedOut
        || signer == RuntimeDependencyProbeV1::TimedOut
    {
        RuntimeDependencyProbeV1::TimedOut
    } else if source == RuntimeDependencyProbeV1::Unavailable
        || signer == RuntimeDependencyProbeV1::Unavailable
    {
        RuntimeDependencyProbeV1::Unavailable
    } else {
        RuntimeDependencyProbeV1::Ready
    }
}
async fn probe_runtime_dependencies(
    authenticated_source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
    signer_resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
    source_deadline: Duration,
    signer_deadline: Duration,
) -> RuntimeDependencyProbeV1 {
    let source = bounded_blocking_readiness_probe(source_deadline, move || {
        source_readiness_probe(authenticated_source.check_readiness())
    });
    let signer = bounded_blocking_readiness_probe(signer_deadline, move || {
        signer_readiness_probe(signer_resolver.check_readiness())
    });
    let (source, signer) = tokio::join!(source, signer);
    combine_runtime_dependency_probes(source, signer)
}
async fn probe_checkpoint_runtime_identity(
    runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
    expected_handle: String,
    expected_qualification: ProviderIngestCheckpointProviderQualificationV1,
    deadline: Duration,
) -> RuntimeDependencyProbeV1 {
    bounded_blocking_readiness_probe(deadline, move || {
        let handle_before = runtime.handle().to_owned();
        let qualification = runtime.qualification();
        let handle_after = runtime.handle().to_owned();
        match qualification {
            Ok(qualification)
                if is_production_runtime_handle(&handle_before)
                    && handle_before == expected_handle
                    && handle_after == expected_handle
                    && qualification.validate().is_ok()
                    && qualification == expected_qualification =>
            {
                RuntimeDependencyProbeV1::Ready
            }
            Err(ProviderIngestCheckpointExternalErrorV1::Unavailable) => {
                RuntimeDependencyProbeV1::Unavailable
            }
            Ok(_)
            | Err(
                ProviderIngestCheckpointExternalErrorV1::Rejected
                | ProviderIngestCheckpointExternalErrorV1::Ambiguous,
            ) => RuntimeDependencyProbeV1::Rejected,
        }
    })
    .await
}
fn provider_ingest_shutdown_wait(config: &SorafsProviderIngestRuntime) -> Duration {
    let source_budget = config.source_operation_timeout_ms.saturating_mul(3);
    let signer_budget = config.signer_timeout_ms.saturating_mul(4);
    let ingress_budget = config.ingress_timeout_ms.saturating_mul(4);
    Duration::from_millis(
        source_budget
            .saturating_add(signer_budget)
            .saturating_add(ingress_budget),
    )
    .saturating_add(SHUTDOWN_WAIT_FLOOR)
}
fn configured_authenticated_source_qualification(
    config: &SorafsProviderIngestRuntime,
) -> ProviderIngestRuntimeProviderQualificationV1 {
    ProviderIngestRuntimeProviderQualificationV1::new(
        config.authenticated_source_fetch_revision,
        config.authenticated_source_fetch_policy_digest,
    )
}
fn configured_completion_signer_resolver_qualification(
    config: &SorafsProviderIngestRuntime,
) -> ProviderIngestRuntimeProviderQualificationV1 {
    ProviderIngestRuntimeProviderQualificationV1::new(
        config.completion_signer_resolver_revision,
        config.completion_signer_resolver_policy_digest,
    )
}
fn configured_completion_signer_binding(
    config: &SorafsProviderIngestRuntime,
) -> ProviderIngestCompletionSignerBindingV1 {
    ProviderIngestCompletionSignerBindingV1::new(
        config.completion_signer_handle.clone(),
        ProviderIngestCompletionSignerQualificationV1::new(
            config.completion_signer_adapter_revision,
            config.completion_signer_policy,
            config.completion_signer_algorithm,
            config.completion_signer_public_key.clone(),
        ),
    )
}
fn configured_checkpoint_qualification(
    config: &SorafsProviderIngestRuntime,
) -> ProviderIngestCheckpointProviderQualificationV1 {
    ProviderIngestCheckpointProviderQualificationV1::new(
        config.checkpoint_store_revision,
        config.checkpoint_store_policy_digest,
    )
}
type NativeProviderIngestRuntimeV1 = ProviderIngestRuntimeV1<
    ObservedArchivedFinalizedAssignmentLedgerV1,
    AuthenticatedSourceAdapterV1,
    NativeProviderIngestLocalStorageV1,
    NativeCompletionPayloadBuilderV1,
    GovernedSignerResolverAdapterV1,
    NativeTransactionIngressV1,
    ProviderIngestSystemClockV1,
>;
/// Deployment-owned provider-ingest runtime adapters.
pub struct ProviderIngestRuntimeAdaptersV1 {
    authenticated_source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
    signer_resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
}
impl ProviderIngestRuntimeAdaptersV1 {
    /// Bundle the authenticated source and governed signer resolver.
    #[must_use]
    pub fn new(
        authenticated_source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
        signer_resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
    ) -> Self {
        Self {
            authenticated_source,
            signer_resolver,
        }
    }
}
/// Opaque proof that provider-ingest's external source, signer, and checkpoint
/// roles passed a state-free, bounded startup preflight.
///
/// Only [`preflight_runtime_adapters`] constructs this token. Keeping its
/// fields private prevents a launcher from assembling provider-ingest durable
/// state from raw, unqualified adapters. Runtime startup consumes the token
/// and repeats every identity, qualification, inventory, and readiness check
/// before worker assembly.
pub(crate) struct QualifiedProviderIngestRuntimeAdaptersV1 {
    adapters: ProviderIngestRuntimeAdaptersV1,
    checkpoint_runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
    qualification: ProviderIngestStartupQualificationV1,
}
impl QualifiedProviderIngestRuntimeAdaptersV1 {
    /// Return the exact preflighted checkpoint runtime for `NodeHandle`
    /// construction. The token retains the same object for launch-time
    /// revalidation.
    pub(crate) fn checkpoint_runtime(&self) -> Arc<dyn ProviderIngestCheckpointRuntimeV1> {
        Arc::clone(&self.checkpoint_runtime)
    }
}
struct ProviderIngestStartContextV1 {
    network_id: NetworkId,
    state: Arc<State>,
    queue: Arc<Queue>,
    node: NodeHandle,
    finalized_ledger: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
    authenticated_source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
    signer_resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
}
/// Daemon-owned inputs needed to launch the supervised provider-ingest worker.
pub(crate) struct ProviderIngestRuntimeStartArgsV1 {
    network_id: NetworkId,
    state: Arc<State>,
    queue: Arc<Queue>,
    node: NodeHandle,
    finalized_ledger: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
}
impl ProviderIngestRuntimeStartArgsV1 {
    /// Bind one runtime launch to its exact network, node, and archive-only
    /// finalized reader.
    pub(crate) fn new(
        network_id: NetworkId,
        state: Arc<State>,
        queue: Arc<Queue>,
        node: NodeHandle,
        finalized_ledger: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
    ) -> Self {
        Self {
            network_id,
            state,
            queue,
            node,
            finalized_ledger,
        }
    }
}
struct ProviderIngestStartupQualificationV1 {
    expected_authenticated_source_qualification: ProviderIngestRuntimeProviderQualificationV1,
    expected_resolver_qualification: ProviderIngestRuntimeProviderQualificationV1,
    expected_signer_binding: ProviderIngestCompletionSignerBindingV1,
    expected_checkpoint_qualification: ProviderIngestCheckpointProviderQualificationV1,
    provider_id: ProviderId,
    source_provider_ids: Vec<[u8; 32]>,
}
fn validate_startup_dependency_qualifications(
    config: &SorafsProviderIngestRuntime,
    authenticated_source: &dyn ProviderIngestAuthenticatedSourceRuntimeV1,
    signer_resolver: &dyn ProviderIngestGovernedSignerResolverRuntimeV1,
    expected_authenticated_source: ProviderIngestRuntimeProviderQualificationV1,
    expected_resolver: ProviderIngestRuntimeProviderQualificationV1,
    expected_signer: &ProviderIngestCompletionSignerBindingV1,
) -> Result<()> {
    validate_dependency_identity(
        "authenticated source-fetch",
        &config.authenticated_source_fetch_handle,
        authenticated_source.runtime_handle(),
    )?;
    validate_dependency_identity(
        "completion signer-resolver",
        &config.completion_signer_resolver_handle,
        signer_resolver.runtime_handle(),
    )?;
    validate_authenticated_source_qualification(
        authenticated_source,
        expected_authenticated_source,
    )
    .map_err(|_| {
        eyre::eyre!(
            "authenticated source-fetch qualification does not match SoraFS provider-ingest configuration"
        )
    })?;
    validate_resolver_qualification(signer_resolver, expected_resolver).map_err(|_| {
        eyre::eyre!(
            "completion signer-resolver qualification does not match SoraFS provider-ingest configuration"
        )
    })?;
    validate_resolver_signer_binding(signer_resolver, expected_signer).map_err(|_| {
        eyre::eyre!("completion signer binding does not match SoraFS provider-ingest configuration")
    })
}
#[expect(
    clippy::too_many_arguments,
    reason = "startup atomically revalidates the complete provider-ingest dependency set"
)]
fn revalidate_startup_dependencies_after_probe(
    config: &SorafsProviderIngestRuntime,
    authenticated_source: &dyn ProviderIngestAuthenticatedSourceRuntimeV1,
    signer_resolver: &dyn ProviderIngestGovernedSignerResolverRuntimeV1,
    expected_authenticated_source: ProviderIngestRuntimeProviderQualificationV1,
    expected_resolver: ProviderIngestRuntimeProviderQualificationV1,
    expected_signer: &ProviderIngestCompletionSignerBindingV1,
    provider_id: [u8; 32],
    source_provider_ids: &[[u8; 32]],
) -> Result<()> {
    validate_dependency_identity(
        "authenticated source-fetch",
        &config.authenticated_source_fetch_handle,
        authenticated_source.runtime_handle(),
    )?;
    validate_dependency_identity(
        "completion signer-resolver",
        &config.completion_signer_resolver_handle,
        signer_resolver.runtime_handle(),
    )?;
    validate_authenticated_source_qualification(
        authenticated_source,
        expected_authenticated_source,
    )
    .map_err(|_| {
        eyre::eyre!(
            "authenticated source-fetch qualification changed during provider-ingest startup readiness"
        )
    })?;
    validate_resolver_qualification(signer_resolver, expected_resolver).map_err(|_| {
        eyre::eyre!(
            "completion signer-resolver qualification changed during provider-ingest startup readiness"
        )
    })?;
    validate_resolver_signer_binding(signer_resolver, expected_signer).map_err(|_| {
        eyre::eyre!("completion signer binding changed during provider-ingest startup readiness")
    })?;
    validate_authenticated_source_inventory(
        authenticated_source,
        provider_id,
        Some(source_provider_ids),
        config.native_completion_credential.is_some(),
    )
}
async fn qualify_external_runtime_adapters(
    config: &SorafsProviderIngestRuntime,
    provider_id: ProviderId,
    authenticated_source: &Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
    signer_resolver: &Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
    checkpoint_runtime: &Arc<dyn ProviderIngestCheckpointRuntimeV1>,
    expected_source_provider_ids: Option<&[[u8; 32]]>,
) -> Result<ProviderIngestStartupQualificationV1> {
    validate_config(config)?;
    if provider_id.as_bytes() == &[0; 32] {
        bail!("provider-ingest runtime requires a non-zero configured provider id");
    }
    let expected_authenticated_source_qualification =
        configured_authenticated_source_qualification(config);
    let expected_resolver_qualification =
        configured_completion_signer_resolver_qualification(config);
    let expected_signer_binding = configured_completion_signer_binding(config);
    let expected_checkpoint_qualification = configured_checkpoint_qualification(config);
    validate_startup_dependency_qualifications(
        config,
        authenticated_source.as_ref(),
        signer_resolver.as_ref(),
        expected_authenticated_source_qualification,
        expected_resolver_qualification,
        &expected_signer_binding,
    )?;
    validate_authenticated_source_inventory(
        authenticated_source.as_ref(),
        *provider_id.as_bytes(),
        expected_source_provider_ids,
        config.native_completion_credential.is_some(),
    )?;
    let source_provider_ids = authenticated_source.source_provider_ids().to_vec();
    let dependency_probe = probe_runtime_dependencies(
        Arc::clone(authenticated_source),
        Arc::clone(signer_resolver),
        Duration::from_millis(config.source_operation_timeout_ms),
        Duration::from_millis(config.signer_timeout_ms),
    )
    .await;
    revalidate_startup_dependencies_after_probe(
        config,
        authenticated_source.as_ref(),
        signer_resolver.as_ref(),
        expected_authenticated_source_qualification,
        expected_resolver_qualification,
        &expected_signer_binding,
        *provider_id.as_bytes(),
        &source_provider_ids,
    )?;
    match dependency_probe {
        RuntimeDependencyProbeV1::Ready => {}
        RuntimeDependencyProbeV1::Unavailable => {
            bail!("SoraFS provider-ingest runtime dependencies are temporarily unavailable");
        }
        RuntimeDependencyProbeV1::Rejected => {
            bail!("SoraFS provider-ingest runtime dependency qualification was rejected");
        }
        RuntimeDependencyProbeV1::TimedOut => {
            bail!("SoraFS provider-ingest runtime dependency readiness probe failed its deadline");
        }
        RuntimeDependencyProbeV1::Panicked => {
            bail!("SoraFS provider-ingest runtime dependency readiness probe panicked");
        }
    }
    for phase in ["initial", "confirmation"] {
        let checkpoint_probe = probe_checkpoint_runtime_identity(
            Arc::clone(checkpoint_runtime),
            config.checkpoint_store_handle.clone(),
            expected_checkpoint_qualification,
            Duration::from_millis(config.outbox.checkpoint_operation_timeout_ms),
        )
        .await;
        match checkpoint_probe {
            RuntimeDependencyProbeV1::Ready => {}
            RuntimeDependencyProbeV1::Unavailable => {
                bail!(
                    "SoraFS provider-ingest checkpoint runtime is unavailable during {phase} state-free qualification"
                );
            }
            RuntimeDependencyProbeV1::Rejected => {
                bail!(
                    "SoraFS provider-ingest checkpoint runtime is substituted, stale, test-marked, or rejected during {phase} state-free qualification"
                );
            }
            RuntimeDependencyProbeV1::TimedOut => {
                bail!(
                    "SoraFS provider-ingest checkpoint runtime exceeded its {phase} state-free qualification deadline"
                );
            }
            RuntimeDependencyProbeV1::Panicked => {
                bail!(
                    "SoraFS provider-ingest checkpoint runtime panicked during {phase} state-free qualification"
                );
            }
        }
    }
    Ok(ProviderIngestStartupQualificationV1 {
        expected_authenticated_source_qualification,
        expected_resolver_qualification,
        expected_signer_binding,
        expected_checkpoint_qualification,
        provider_id,
        source_provider_ids,
    })
}
/// Qualify deployment-owned provider-ingest source, signer, and checkpoint
/// roles without opening daemon, outbox, checkpoint, or filesystem state.
///
/// # Errors
///
/// Fails closed when configuration is invalid or any adapter is missing,
/// substituted, stale, test-marked, unavailable, noncanonical, or changes
/// identity/qualification across the bounded readiness probes.
pub(crate) async fn preflight_runtime_adapters(
    config: &SorafsProviderIngestRuntime,
    provider_id: ProviderId,
    adapters: ProviderIngestRuntimeAdaptersV1,
    checkpoint_runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1>,
) -> Result<QualifiedProviderIngestRuntimeAdaptersV1> {
    let qualification = qualify_external_runtime_adapters(
        config,
        provider_id,
        &adapters.authenticated_source,
        &adapters.signer_resolver,
        &checkpoint_runtime,
        None,
    )
    .await?;
    Ok(QualifiedProviderIngestRuntimeAdaptersV1 {
        adapters,
        checkpoint_runtime,
        qualification,
    })
}
async fn qualify_provider_ingest_startup(
    config: &SorafsProviderIngestRuntime,
    context: &ProviderIngestStartContextV1,
    checkpoint_runtime: &Arc<dyn ProviderIngestCheckpointRuntimeV1>,
    preflight: &ProviderIngestStartupQualificationV1,
) -> Result<ProviderIngestStartupQualificationV1> {
    validate_config(config)?;
    if context.finalized_ledger.network_id() != context.network_id {
        bail!("daemon-owned finalized provider-ingest query has a substituted network identity");
    }
    context.finalized_ledger.activation_ready().wrap_err(
        "qualify daemon-owned finalized provider-ingest archive activation gate at runtime startup",
    )?;
    let provider_id =
        context.node.config().provider_id().ok_or_else(|| {
            eyre::eyre!("provider-ingest runtime requires a configured provider id")
        })?;
    if context.finalized_ledger.provider_id() != provider_id {
        bail!("daemon-owned finalized provider-ingest query has a substituted provider identity");
    }
    if preflight.provider_id != provider_id
        || preflight.expected_authenticated_source_qualification
            != configured_authenticated_source_qualification(config)
        || preflight.expected_resolver_qualification
            != configured_completion_signer_resolver_qualification(config)
        || preflight.expected_signer_binding != configured_completion_signer_binding(config)
        || preflight.expected_checkpoint_qualification
            != configured_checkpoint_qualification(config)
    {
        bail!("provider-ingest runtime configuration changed after state-free preflight");
    }
    let qualification = qualify_external_runtime_adapters(
        config,
        provider_id,
        &context.authenticated_source,
        &context.signer_resolver,
        checkpoint_runtime,
        Some(&preflight.source_provider_ids),
    )
    .await?;
    if qualification.expected_authenticated_source_qualification
        != preflight.expected_authenticated_source_qualification
        || qualification.expected_resolver_qualification
            != preflight.expected_resolver_qualification
        || qualification.expected_signer_binding != preflight.expected_signer_binding
        || qualification.expected_checkpoint_qualification
            != preflight.expected_checkpoint_qualification
        || qualification.provider_id != preflight.provider_id
        || qualification.source_provider_ids != preflight.source_provider_ids
    {
        bail!("provider-ingest runtime adapter binding changed after state-free preflight");
    }
    Ok(qualification)
}
fn provider_ingest_runtime_policy(
    config: &SorafsProviderIngestRuntime,
) -> ProviderIngestRuntimePolicyV1 {
    ProviderIngestRuntimePolicyV1 {
        max_page_rows: config.max_page_rows,
        max_pages_per_tick: config.max_pages_per_tick,
        max_source_jobs_per_tick: config.max_source_jobs_per_tick,
        max_source_providers: config.max_source_providers,
        scan_interval_ms: config.scan_interval_ms,
        source_operation_timeout_ms: config.source_operation_timeout_ms,
        source_lease_renew_interval_ms: config.source_lease_renew_interval_ms,
        signer_timeout_ms: config.signer_timeout_ms,
        ingress_timeout_ms: config.ingress_timeout_ms,
    }
}
fn provider_attestation_journal_policy(
    config: &SorafsProviderAttestationJournal,
) -> Result<MusubiProviderAttestationJournalPolicyV1> {
    for (role, binding) in [
        ("clock seal", &config.clock),
        ("approval signer", &config.approval_signer),
        ("inventory", &config.inventory),
    ] {
        validate_provider_attestation_runtime_binding(role, binding)?;
    }
    let policy = MusubiProviderAttestationJournalPolicyV1 {
        max_entries: config.max_entries,
        max_attempts: config.max_attempts,
        lease_ttl_ms: config.lease_ttl_ms,
        approval_timeout_ms: config.approval_timeout_ms,
        handoff_timeout_ms: config.handoff_timeout_ms,
        retry_delay_ms: config.retry_delay_ms,
        checkpoint_max_bytes: config.checkpoint_max_bytes,
        max_cas_retries: config.max_cas_retries,
    };
    policy
        .validate()
        .wrap_err("validate provider-attestation durable journal policy")?;
    Ok(policy)
}
fn validate_provider_attestation_runtime_binding(
    role: &str,
    binding: &SorafsProviderAttestationRuntimeBinding,
) -> Result<()> {
    if !is_production_runtime_handle(&binding.handle)
        || binding.revision == 0
        || binding.policy_digest == [0; 32]
    {
        bail!("provider-attestation {role} runtime binding is invalid");
    }
    Ok(())
}
fn assemble_native_provider_ingest_runtime(
    config: &SorafsProviderIngestRuntime,
    context: &ProviderIngestStartContextV1,
    qualification: &ProviderIngestStartupQualificationV1,
) -> Result<(NativeProviderIngestRuntimeV1, ProviderIngestRuntimeHandleV1)> {
    let claim_owner = random_claim_owner()?;
    let probe = Arc::new(Mutex::new(FinalizedSnapshotProbeV1 {
        completed_cursor: None,
    }));
    let ledger = Arc::new(ObservedArchivedFinalizedAssignmentLedgerV1::new(
        Arc::clone(&context.finalized_ledger),
        Arc::clone(&probe),
    ));
    let fetch = Arc::new(AuthenticatedSourceAdapterV1 {
        source: Arc::clone(&context.authenticated_source),
        expected_qualification: qualification.expected_authenticated_source_qualification,
    });
    let storage = Arc::new(NativeProviderIngestLocalStorageV1::new(
        context.node.clone(),
        Arc::clone(&context.state),
        Duration::from_millis(config.source_operation_timeout_ms),
    ));
    let payload_builder = Arc::new(NativeCompletionPayloadBuilderV1 {
        network_id: context.network_id,
        state: Arc::clone(&context.state),
        queue: Arc::clone(&context.queue),
        ttl: Duration::from_millis(config.completion_transaction_ttl_ms),
        max_signed_transaction_bytes: config.outbox.max_signed_transaction_bytes.0,
    });
    let owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1> =
        context.state.clone();
    let resolver = Arc::new(GovernedSignerResolverAdapterV1 {
        resolver: Arc::clone(&context.signer_resolver),
        owner_authority,
        provider_id: qualification.provider_id,
        expected_resolver_qualification: qualification.expected_resolver_qualification,
        expected_signer_binding: qualification.expected_signer_binding.clone(),
    });
    let ingress = Arc::new(NativeTransactionIngressV1 {
        state: Arc::clone(&context.state),
        queue: Arc::clone(&context.queue),
    });
    let runtime = context
        .node
        .build_provider_ingest_runtime(
            context.network_id,
            claim_owner,
            provider_ingest_runtime_policy(config),
            ledger,
            fetch,
            storage,
            payload_builder,
            resolver,
            ingress,
            Arc::new(ProviderIngestSystemClockV1),
        )
        .wrap_err("assemble finalized-ledger provider-ingest runtime")?;
    let handle = ProviderIngestRuntimeHandleV1 {
        node: context.node.clone(),
        state: Arc::clone(&context.state),
        config: config.clone(),
        probe,
        counters: Arc::new(ProviderIngestDaemonCountersV1::default()),
        worker_running: Arc::new(AtomicBool::new(false)),
        external_dependencies_healthy: Arc::new(AtomicBool::new(false)),
        tick_in_flight: Arc::new(AtomicBool::new(false)),
        last_successful_tick: Arc::new(Mutex::new(None)),
    };
    Ok((runtime, handle))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderIngestWorkerControlV1 {
    Continue,
    Stop,
}
fn provider_ingest_tick_error_is_transient(error: &ProviderIngestRuntimeErrorV1) -> bool {
    matches!(
        error,
        ProviderIngestRuntimeErrorV1::FinalizedLedgerUnavailable
    )
}
struct ProviderIngestWorkerV1 {
    config: SorafsProviderIngestRuntime,
    runtime: NativeProviderIngestRuntimeV1,
    handle: ProviderIngestRuntimeHandleV1,
    finalized_ledger: Arc<ArchivedProviderIngestFinalizedLedgerV1>,
    authenticated_source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1>,
    signer_resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1>,
    expected_authenticated_source_qualification: ProviderIngestRuntimeProviderQualificationV1,
    expected_resolver_qualification: ProviderIngestRuntimeProviderQualificationV1,
    expected_signer_binding: ProviderIngestCompletionSignerBindingV1,
    provider_id: ProviderId,
    source_provider_ids: Vec<[u8; 32]>,
}
impl ProviderIngestWorkerV1 {
    fn adapter_identity_probe(&self) -> RuntimeDependencyProbeV1 {
        if validate_dependency_identity(
            "authenticated source-fetch",
            &self.config.authenticated_source_fetch_handle,
            self.authenticated_source.runtime_handle(),
        )
        .is_err()
            || validate_dependency_identity(
                "completion signer-resolver",
                &self.config.completion_signer_resolver_handle,
                self.signer_resolver.runtime_handle(),
            )
            .is_err()
            || validate_authenticated_source_inventory(
                self.authenticated_source.as_ref(),
                *self.provider_id.as_bytes(),
                Some(&self.source_provider_ids),
                self.config.native_completion_credential.is_some(),
            )
            .is_err()
        {
            return RuntimeDependencyProbeV1::Rejected;
        }
        let source = source_readiness_probe(validate_authenticated_source_qualification(
            self.authenticated_source.as_ref(),
            self.expected_authenticated_source_qualification,
        ));
        let resolver = signer_readiness_probe(validate_resolver_qualification(
            self.signer_resolver.as_ref(),
            self.expected_resolver_qualification,
        ));
        let signer = signer_readiness_probe(validate_resolver_signer_binding(
            self.signer_resolver.as_ref(),
            &self.expected_signer_binding,
        ));
        combine_runtime_dependency_probes(
            source,
            combine_runtime_dependency_probes(resolver, signer),
        )
    }
    async fn probe_dependencies_or_shutdown(
        &self,
        shutdown_signal: &ShutdownSignal,
    ) -> Option<RuntimeDependencyProbeV1> {
        let dependency_probe = probe_runtime_dependencies(
            Arc::clone(&self.authenticated_source),
            Arc::clone(&self.signer_resolver),
            Duration::from_millis(self.config.source_operation_timeout_ms),
            Duration::from_millis(self.config.signer_timeout_ms),
        );
        tokio::pin!(dependency_probe);
        tokio::select! {
            probe = &mut dependency_probe => Some(probe),
            () = shutdown_signal.receive() => {
                iroha_logger::debug!(
                    "SoraFS provider-ingest runtime is being shut down during dependency probing"
                );
                None
            }
        }
    }
    fn record_successful_tick(&self, outcome: ProviderIngestTickOutcomeV1) -> bool {
        record_tick_outcome(&self.handle.counters, outcome);
        self.handle
            .counters
            .successful_ticks
            .fetch_add(1, Ordering::Relaxed);
        self.handle.last_successful_tick.lock().map_or_else(
            |_| {
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::error!(
                    "SoraFS provider-ingest freshness state is poisoned; stopping supervised worker"
                );
                false
            },
            |mut last_tick| {
                *last_tick = Some(Instant::now());
                true
            },
        )
    }
    async fn reconcile_or_shutdown(
        &mut self,
        shutdown_signal: &ShutdownSignal,
    ) -> ProviderIngestWorkerControlV1 {
        self.handle
            .external_dependencies_healthy
            .store(true, Ordering::Release);
        let shutdown_requested = AtomicBool::new(false);
        let mut stop_after_tick = false;
        let tick_result = {
            let tick = self.runtime.tick_with_shutdown(&shutdown_requested);
            tokio::pin!(tick);
            loop {
                tokio::select! {
                    result = &mut tick => break result,
                    () = shutdown_signal.receive(), if !stop_after_tick => {
                        shutdown_requested.store(true, Ordering::Release);
                        self.handle
                            .external_dependencies_healthy
                            .store(false, Ordering::Release);
                        stop_after_tick = true;
                    }
                }
            }
        };
        match tick_result {
            Ok(outcome) if stop_after_tick => {
                record_tick_outcome(&self.handle.counters, outcome);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::debug!(
                    "SoraFS provider-ingest runtime drained its active row for shutdown"
                );
                ProviderIngestWorkerControlV1::Stop
            }
            Ok(outcome) => {
                if self.record_successful_tick(outcome) {
                    self.handle.tick_in_flight.store(false, Ordering::Release);
                    ProviderIngestWorkerControlV1::Continue
                } else {
                    ProviderIngestWorkerControlV1::Stop
                }
            }
            Err(error) => {
                self.handle
                    .counters
                    .failed_ticks
                    .fetch_add(1, Ordering::Relaxed);
                self.handle
                    .external_dependencies_healthy
                    .store(false, Ordering::Release);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                if provider_ingest_tick_error_is_transient(&error) {
                    iroha_logger::warn!(
                        error = %error,
                        "SoraFS provider-ingest reconciliation dependency is temporarily unavailable; retrying on the next bounded tick"
                    );
                    ProviderIngestWorkerControlV1::Continue
                } else {
                    iroha_logger::error!(
                        error = %error,
                        "SoraFS provider-ingest reconciliation failed fatally; stopping supervised worker"
                    );
                    ProviderIngestWorkerControlV1::Stop
                }
            }
        }
    }
    async fn tick(&mut self, shutdown_signal: &ShutdownSignal) -> ProviderIngestWorkerControlV1 {
        self.handle.tick_in_flight.store(true, Ordering::Release);
        self.handle
            .external_dependencies_healthy
            .store(false, Ordering::Release);
        match self.finalized_ledger.activation_ready() {
            Ok(true) => {}
            Ok(false) => {
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::debug!(
                    "SoraFS provider-ingest runtime is awaiting finalized archive activation"
                );
                return ProviderIngestWorkerControlV1::Continue;
            }
            Err(error) => {
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::error!(
                    %error,
                    "SoraFS provider-ingest finalized archive activation gate failed closed"
                );
                return ProviderIngestWorkerControlV1::Stop;
            }
        }
        match self.adapter_identity_probe() {
            RuntimeDependencyProbeV1::Ready => {}
            RuntimeDependencyProbeV1::Unavailable | RuntimeDependencyProbeV1::TimedOut => {
                self.handle
                    .counters
                    .failed_ticks
                    .fetch_add(1, Ordering::Relaxed);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::warn!(
                    "SoraFS provider-ingest runtime adapter qualification is temporarily unavailable"
                );
                return ProviderIngestWorkerControlV1::Continue;
            }
            RuntimeDependencyProbeV1::Rejected | RuntimeDependencyProbeV1::Panicked => {
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::error!(
                    "SoraFS provider-ingest runtime adapter identity or qualification was rejected; stopping supervised worker"
                );
                return ProviderIngestWorkerControlV1::Stop;
            }
        }
        let Some(dependency_probe) = self.probe_dependencies_or_shutdown(shutdown_signal).await
        else {
            return ProviderIngestWorkerControlV1::Stop;
        };
        let dependency_probe =
            combine_runtime_dependency_probes(dependency_probe, self.adapter_identity_probe());
        match dependency_probe {
            RuntimeDependencyProbeV1::Ready => {}
            RuntimeDependencyProbeV1::Unavailable => {
                self.handle
                    .counters
                    .failed_ticks
                    .fetch_add(1, Ordering::Relaxed);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::warn!(
                    "SoraFS provider-ingest runtime dependency is temporarily unavailable"
                );
                return ProviderIngestWorkerControlV1::Continue;
            }
            RuntimeDependencyProbeV1::TimedOut => {
                self.handle
                    .counters
                    .failed_ticks
                    .fetch_add(1, Ordering::Relaxed);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::warn!(
                    "SoraFS provider-ingest runtime dependency probe exceeded its deadline; retrying on the next bounded tick"
                );
                return ProviderIngestWorkerControlV1::Continue;
            }
            RuntimeDependencyProbeV1::Rejected => {
                self.handle
                    .counters
                    .failed_ticks
                    .fetch_add(1, Ordering::Relaxed);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::error!(
                    "SoraFS provider-ingest runtime dependency identity or qualification was rejected; stopping supervised worker"
                );
                return ProviderIngestWorkerControlV1::Stop;
            }
            RuntimeDependencyProbeV1::Panicked => {
                self.handle
                    .counters
                    .failed_ticks
                    .fetch_add(1, Ordering::Relaxed);
                self.handle.tick_in_flight.store(false, Ordering::Release);
                iroha_logger::error!(
                    "SoraFS provider-ingest runtime dependency probe panicked; stopping supervised worker"
                );
                return ProviderIngestWorkerControlV1::Stop;
            }
        }
        self.reconcile_or_shutdown(shutdown_signal).await
    }
    async fn run(mut self, shutdown_signal: ShutdownSignal) {
        let _liveness = ProviderIngestWorkerLivenessGuardV1::new(
            Arc::clone(&self.handle.worker_running),
            Arc::clone(&self.handle.tick_in_flight),
        );
        let mut interval =
            tokio::time::interval(Duration::from_millis(self.config.scan_interval_ms));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if self.tick(&shutdown_signal).await == ProviderIngestWorkerControlV1::Stop {
                        break;
                    }
                }
                () = shutdown_signal.receive() => {
                    self.handle.tick_in_flight.store(false, Ordering::Release);
                    iroha_logger::debug!(
                        "SoraFS provider-ingest runtime is being shut down"
                    );
                    break;
                }
                else => break,
            }
        }
    }
}
/// Assemble and start supervised finalized-ledger provider ingest.
///
/// Missing, test-marked, unready, or identity-substituted runtime adapters
/// fail startup before the worker is spawned.
pub(crate) async fn start(
    config: SorafsProviderIngestRuntime,
    args: ProviderIngestRuntimeStartArgsV1,
    preflight: QualifiedProviderIngestRuntimeAdaptersV1,
    shutdown_signal: ShutdownSignal,
) -> Result<(ProviderIngestRuntimeHandleV1, Child)> {
    let ProviderIngestRuntimeStartArgsV1 {
        network_id,
        state,
        queue,
        node,
        finalized_ledger,
    } = args;
    let QualifiedProviderIngestRuntimeAdaptersV1 {
        adapters:
            ProviderIngestRuntimeAdaptersV1 {
                authenticated_source,
                signer_resolver,
            },
        checkpoint_runtime,
        qualification: preflight_qualification,
    } = preflight;
    let context = ProviderIngestStartContextV1 {
        network_id,
        state,
        queue,
        node,
        finalized_ledger,
        authenticated_source,
        signer_resolver,
    };
    let qualification = qualify_provider_ingest_startup(
        &config,
        &context,
        &checkpoint_runtime,
        &preflight_qualification,
    )
    .await?;
    let (runtime, handle) =
        assemble_native_provider_ingest_runtime(&config, &context, &qualification)?;
    let shutdown_wait = provider_ingest_shutdown_wait(&config);
    let worker = ProviderIngestWorkerV1 {
        config,
        runtime,
        handle: handle.clone(),
        finalized_ledger: Arc::clone(&context.finalized_ledger),
        authenticated_source: context.authenticated_source,
        signer_resolver: context.signer_resolver,
        expected_authenticated_source_qualification: qualification
            .expected_authenticated_source_qualification,
        expected_resolver_qualification: qualification.expected_resolver_qualification,
        expected_signer_binding: qualification.expected_signer_binding,
        provider_id: qualification.provider_id,
        source_provider_ids: qualification.source_provider_ids,
    };
    let task = tokio::spawn(worker.run(shutdown_signal));
    Ok((handle, Child::new(task, OnShutdown::Wait(shutdown_wait))))
}
struct ProviderIngestWorkerLivenessGuardV1 {
    worker_running: Arc<AtomicBool>,
    tick_in_flight: Arc<AtomicBool>,
}
impl ProviderIngestWorkerLivenessGuardV1 {
    fn new(worker_running: Arc<AtomicBool>, tick_in_flight: Arc<AtomicBool>) -> Self {
        worker_running.store(true, Ordering::Release);
        Self {
            worker_running,
            tick_in_flight,
        }
    }
}
impl Drop for ProviderIngestWorkerLivenessGuardV1 {
    fn drop(&mut self) {
        self.tick_in_flight.store(false, Ordering::Release);
        self.worker_running.store(false, Ordering::Release);
    }
}
fn record_tick_outcome(
    counters: &ProviderIngestDaemonCountersV1,
    outcome: ProviderIngestTickOutcomeV1,
) {
    counters.rows_scanned.fetch_add(
        u64::try_from(outcome.rows_scanned).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.jobs_inserted.fetch_add(
        u64::try_from(outcome.jobs_inserted).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.jobs_finalized.fetch_add(
        u64::try_from(outcome.jobs_finalized).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.jobs_cancelled.fetch_add(
        u64::try_from(outcome.jobs_cancelled).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.source_jobs_claimed.fetch_add(
        u64::try_from(outcome.source_jobs_claimed).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.manifests_stored.fetch_add(
        u64::try_from(outcome.manifests_stored).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.completions_signed.fetch_add(
        u64::try_from(outcome.completions_signed).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.completion_submissions.fetch_add(
        u64::try_from(outcome.completion_submissions).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}
fn random_claim_owner() -> Result<ProviderIngestClaimOwnerV1> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .wrap_err("operating-system randomness unavailable for provider-ingest claim owner")?;
        if let Ok(owner) = ProviderIngestClaimOwnerV1::new(bytes) {
            return Ok(owner);
        }
    }
    bail!("operating-system randomness repeatedly returned a zero provider-ingest claim owner")
}
fn random_provider_attestation_claim_owner() -> Result<MusubiProviderAttestationClaimOwnerV1> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        OsRng.try_fill_bytes(&mut bytes).wrap_err(
            "operating-system randomness unavailable for provider-attestation claim owner",
        )?;
        if let Ok(owner) = MusubiProviderAttestationClaimOwnerV1::new(bytes) {
            return Ok(owner);
        }
    }
    bail!("operating-system randomness repeatedly returned a zero provider-attestation claim owner")
}
fn validate_config(config: &SorafsProviderIngestRuntime) -> Result<()> {
    let authenticated_source_qualification = configured_authenticated_source_qualification(config);
    let completion_signer_resolver_qualification =
        configured_completion_signer_resolver_qualification(config);
    let completion_signer_binding = configured_completion_signer_binding(config);
    let checkpoint_qualification = configured_checkpoint_qualification(config);
    if !is_production_runtime_handle(&config.authenticated_source_fetch_handle)
        || !is_production_runtime_handle(&config.completion_signer_resolver_handle)
        || !is_production_runtime_handle(&config.checkpoint_store_handle)
        || !authenticated_source_qualification.is_valid()
        || !completion_signer_resolver_qualification.is_valid()
        || completion_signer_binding.validate().is_err()
        || checkpoint_qualification.validate().is_err()
        || config.scan_interval_ms == 0
        || config.max_page_rows == 0
        || config.max_pages_per_tick == 0
        || config.max_source_jobs_per_tick == 0
        || config.max_source_providers == 0
        || config.source_operation_timeout_ms == 0
        || config.source_lease_renew_interval_ms == 0
        || config.signer_timeout_ms == 0
        || config.ingress_timeout_ms == 0
        || config.completion_transaction_ttl_ms == 0
        || config.finalized_archive.max_record_bytes == 0
        || config.finalized_archive.max_archive_entries == 0
        || config.finalized_archive.max_total_bytes < config.finalized_archive.max_record_bytes
        || config.finalized_archive.max_providers_per_anchor == 0
        || config.finalized_archive.max_orders_per_provider == 0
        || config.finalized_archive.max_total_orders_per_anchor == 0
        || config.finalized_archive.max_page_rows == 0
        || config.max_page_rows > config.finalized_archive.max_page_rows
        || config.max_page_rows > config.finalized_archive.max_orders_per_provider
        || config.source_lease_renew_interval_ms >= config.outbox.source_lease_ttl_ms
        || config.outbox.max_signed_transaction_bytes.0
            < provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN
        || config
            .max_page_rows
            .checked_mul(config.max_pages_per_tick)
            .is_none()
    {
        bail!("SoraFS provider-ingest runtime configuration is invalid");
    }
    let policy = sorafs_node::ProviderIngestOutboxPolicyV1 {
        max_active_entries: config.outbox.max_active_entries,
        max_terminal_entries: config.outbox.max_terminal_entries,
        max_attempts: config.outbox.max_attempts,
        checkpoint_max_bytes: config.outbox.checkpoint_max_bytes.0,
        checkpoint_operation_timeout_ms: config.outbox.checkpoint_operation_timeout_ms,
        source_lease_ttl_ms: config.outbox.source_lease_ttl_ms,
        retry_base_delay_ms: config.outbox.retry_base_delay_ms,
        retry_max_delay_ms: config.outbox.retry_max_delay_ms,
        terminal_retention_blocks: config.outbox.terminal_retention_blocks,
        max_signed_transaction_bytes: config.outbox.max_signed_transaction_bytes.0,
        max_status_page_size: config.outbox.max_status_page_size,
    };
    policy
        .validate()
        .wrap_err("validate provider-ingest durable outbox policy")?;
    if let Some(journal) = config.provider_attestation_journal.as_ref() {
        provider_attestation_journal_policy(journal)?;
    }
    Ok(())
}
fn validate_dependency_identity(label: &str, expected: &str, actual: &str) -> Result<()> {
    if !is_production_runtime_handle(actual) || actual != expected {
        bail!("{label} adapter identity does not match SoraFS provider-ingest configuration");
    }
    Ok(())
}
fn validate_authenticated_source_inventory(
    source: &dyn ProviderIngestAuthenticatedSourceRuntimeV1,
    local_provider_id: [u8; 32],
    expected: Option<&[[u8; 32]]>,
    native_staging: bool,
) -> Result<()> {
    let provider_ids = source.source_provider_ids();
    if (!native_staging && provider_ids.len() < 2)
        || provider_ids.len() > MAX_REPLICATION_ORDER_ASSIGNMENTS
        || provider_ids
            .iter()
            .any(|provider_id| *provider_id == [0; 32] || *provider_id == local_provider_id)
        || provider_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || expected.is_some_and(|expected| expected != provider_ids)
    {
        bail!(
            "authenticated provider-ingest source inventory is missing, substituted, noncanonical, or out of bounds"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests;

#[cfg(any(unix, windows))]
pub(crate) use native_attestation::start as start_native_attestation;
