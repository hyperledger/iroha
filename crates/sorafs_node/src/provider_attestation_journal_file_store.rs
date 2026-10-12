//! Root-fenced local persistence for the Musubi provider-attestation journal.
//!
//! The adapter stores exact private journal checkpoint bytes in the existing descriptor-relative
//! two-slot CAS primitive. Linux and macOS are the only qualified V1 targets. Windows remains
//! fail-closed until the two-slot files and initialization lock pin their exact owner SID and DACL.
//!
//! This local seal detects link/path substitution, torn writes, and invalid two-slot lineage. A
//! private wrapper treats the authenticated external checkpoint head/blob as authority, so a
//! privileged offline rollback of the complete local filesystem cannot become current. Store
//! initialization uses a fixed, bounded cross-process lock wait. Normal loads and mutations use
//! typed nonblocking locks and return `Unavailable` on contention.
//!
//! Generic abstract journal store/runtime injection is a trusted internal boundary. File-backed
//! integrations must consume this adapter through the explicit asynchronous initialize/open paths,
//! which bind the local store to the exact network/provider/policy checkpoint scope.
//!
//! Daemon activation requires construction below the supervised provider-ingest child, accepted
//! crash/corruption evidence, and a singleton rooted runtime session or provider-side cross-machine
//! fencing for each external scope. Windows remains unsupported until exact SID/DACL pinning is
//! qualified; the local OS lease fences only processes sharing this state root.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::governance_rooted_fs::{TwoSlotInitializationWaitV1, TwoSlotStoreConfigV1};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::provider_attestation_journal::MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1;
use crate::{
    governance::GovernanceFilesystemRootGuard,
    governance_rooted_fs::{
        RootedDirectory, TwoSlotBoundOperationLeaseV1, TwoSlotCasOutcomeV1, TwoSlotSnapshotV1,
        TwoSlotStoreV1, TwoSlotTryErrorV1,
    },
    provider_attestation_clock::{
        MusubiProviderAttestationClockScopeV1,
        MusubiProviderAttestationJournalCheckpointHeadRecordV1,
        MusubiProviderAttestationJournalCheckpointHeadV1,
        MusubiProviderAttestationJournalCheckpointScopeV1,
        MusubiProviderAttestationJournalCheckpointSealErrorV1,
        MusubiProviderAttestationSealedUnixClockV1,
    },
    provider_attestation_journal::{
        MusubiProviderAttestationJournalCasOutcomeV1, MusubiProviderAttestationJournalErrorV1,
        MusubiProviderAttestationJournalPolicyV1, MusubiProviderAttestationJournalRuntimeV1,
        MusubiProviderAttestationJournalStoreErrorV1,
        MusubiProviderAttestationJournalStoreSnapshotV1, MusubiProviderAttestationJournalStoreV1,
        musubi_provider_attestation_journal_checkpoint_revision_v1,
        validate_musubi_provider_attestation_journal_checkpoint_metadata_v1,
    },
    provider_ingest_runtime::ProviderIngestFutureV1,
};
use iroha_data_model::{NetworkId, sorafs::capacity::ProviderId};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{ffi::OsStr, time::Duration};
use std::{fmt, io, path::Path, sync::Arc};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
#[cfg(any(target_os = "linux", target_os = "macos"))]
const JOURNAL_DIRECTORY_NAME_V1: &str = "musubi-provider-attestation-journal-v1";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const JOURNAL_TWO_SLOT_STORE_NAME_V1: &str = "checkpoint-v1";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const JOURNAL_TWO_SLOT_DOMAIN_LABEL_V1: &[u8] =
    b"sorafs.musubi.provider-attestation.journal-file-store.domain.v1\0";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const JOURNAL_TWO_SLOT_NONCE_DOMAIN_V1: &[u8] =
    b"sorafs.musubi.provider-attestation.journal-file-store.binding.v1\0";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const JOURNAL_INITIALIZATION_TIMEOUT_V1: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "macos"))]
const JOURNAL_INITIALIZATION_RETRY_INTERVAL_V1: Duration = Duration::from_millis(10);
/// Exact deployment identity bound into one journal file-store layout.
///
/// The stable two-slot nonce is derived internally from these public values; callers cannot select
/// a path-independent nonce or silently reuse another chain/provider journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusubiProviderAttestationJournalFileBindingV1 {
    network_id: NetworkId,
    provider_id: ProviderId,
}
impl MusubiProviderAttestationJournalFileBindingV1 {
    /// Construct one non-inert deployment binding.
    ///
    /// # Errors
    ///
    /// Returns `StoreRejected` for an invalid network or zero provider identity.
    pub fn try_new(
        network_id: NetworkId,
        provider_id: ProviderId,
    ) -> Result<Self, MusubiProviderAttestationJournalErrorV1> {
        if network_id.as_bytes()[31] & 1 != 1 || *provider_id.as_bytes() == [0; 32] {
            return Err(MusubiProviderAttestationJournalErrorV1::StoreRejected);
        }
        Ok(Self {
            network_id,
            provider_id,
        })
    }
    /// Borrow the exact configured deployment identity.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Return the exact configured provider identity.
    #[must_use]
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
    /// Derive the exact clock-seal scope paired with this file-store binding.
    ///
    /// The construction cannot fail because this binding was already validated.
    #[must_use]
    pub fn clock_scope(&self) -> MusubiProviderAttestationClockScopeV1 {
        MusubiProviderAttestationClockScopeV1::try_new(self.network_id, self.provider_id)
            .expect("validated journal file binding yields a valid clock scope")
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn stable_store_nonce(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(JOURNAL_TWO_SLOT_NONCE_DOMAIN_V1);
        hasher.update(self.network_id.as_bytes());
        hasher.update(self.provider_id.as_bytes());
        *hasher.finalize().as_bytes()
    }
}
/// Local root-fenced two-slot persistence adapter for the attestation journal.
///
/// `Debug` deliberately omits the configured state-root path and underlying file handles. Clone
/// instances share a nonblocking process-local single- flight gate; separately opened adapters
/// additionally contend through the generic store's nonblocking operating-system lock. Raw
/// checkpoint bytes and CAS operations stay crate-private; external callers can only inspect the
/// public binding/policy or consume the adapter into the scope-bound runtime.
///
/// ```compile_fail
/// use sorafs_node::MusubiProviderAttestationJournalFileStoreV1;
///
/// fn bypass_authenticated_transitions(store: &MusubiProviderAttestationJournalFileStoreV1) {
///     let _ = store.load();
/// }
/// ```
#[derive(Clone)]
pub struct MusubiProviderAttestationJournalFileStoreV1 {
    root_guard: GovernanceFilesystemRootGuard,
    journal_directory: RootedDirectory,
    store: TwoSlotStoreV1,
    binding: MusubiProviderAttestationJournalFileBindingV1,
    policy: MusubiProviderAttestationJournalPolicyV1,
    local_gate: Arc<Semaphore>,
    composite_gate: Arc<Semaphore>,
}
impl fmt::Debug for MusubiProviderAttestationJournalFileStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiProviderAttestationJournalFileStoreV1")
            .field("state_root", &"<redacted>")
            .field("binding", &self.binding)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}
impl MusubiProviderAttestationJournalFileStoreV1 {
    /// Open or initialize the fixed journal namespace below an existing root.
    ///
    /// The caller supplies a pre-existing state root. The adapter captures and continually
    /// revalidates its owner, ACL, ancestor, and physical identity; it creates only fixed direct
    /// child names through retained handles. Initialization waits at most five seconds on the
    /// generic two-slot cross-process init lock. Normal trait operations are nonblocking with
    /// respect to both local and cross-process store locks.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid policy, unsafe/substituted root,
    /// conflicting deployment binding, corrupt checkpoint/generation lineage,
    /// initialization failure, or an unsupported platform. Windows and targets
    /// other than Linux/macOS fail with [`io::ErrorKind::Unsupported`].
    pub fn open_or_create_under(
        state_root: &Path,
        binding: MusubiProviderAttestationJournalFileBindingV1,
        policy: MusubiProviderAttestationJournalPolicyV1,
    ) -> io::Result<Self> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (state_root, binding, policy);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Musubi provider-attestation journal file storage is qualified only on Linux and macOS",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            policy.validate().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Musubi provider-attestation journal file-store policy is invalid",
                )
            })?;
            let root_guard = GovernanceFilesystemRootGuard::capture_writer(state_root)?;
            root_guard.revalidate()?;
            let opened = (|| {
                let journal_directory = root_guard
                    .rooted_directory()
                    .open_or_create_directory(OsStr::new(JOURNAL_DIRECTORY_NAME_V1))?;
                let config = two_slot_config(&binding)?;
                let wait = TwoSlotInitializationWaitV1::try_new(
                    JOURNAL_INITIALIZATION_TIMEOUT_V1,
                    JOURNAL_INITIALIZATION_RETRY_INTERVAL_V1,
                )?;
                let store = journal_directory.open_or_create_two_slot_store_v1_bounded(
                    config,
                    &[],
                    wait,
                )?;
                Ok((journal_directory, store))
            })();
            let post_open = root_guard.revalidate();
            let (journal_directory, store) = match (opened, post_open) {
                (_, Err(error)) | (Err(error), Ok(())) => return Err(error),
                (Ok(opened), Ok(())) => opened,
            };
            let adapter = Self {
                root_guard,
                journal_directory,
                store,
                binding,
                policy,
                local_gate: Arc::new(Semaphore::new(1)),
                composite_gate: Arc::new(Semaphore::new(1)),
            };
            adapter.validate_current_blocking()?;
            Ok(adapter)
        }
    }
    /// Borrow the deployment identity sealed into this store.
    #[must_use]
    pub const fn binding(&self) -> &MusubiProviderAttestationJournalFileBindingV1 {
        &self.binding
    }
    /// Return the checkpoint policy used for byte/schema validation.
    ///
    /// A journal coordinator using this adapter must use this exact policy as well; otherwise its
    /// logical capacity rules and the store's decode rules would diverge.
    #[must_use]
    pub const fn policy(&self) -> MusubiProviderAttestationJournalPolicyV1 {
        self.policy
    }
    /// Explicitly provision empty external H0 and construct a sealed runtime.
    ///
    /// Initialization first proves the local two-slot store is the unique safe empty snapshot. It
    /// never promotes local checkpoint bytes. An identical already-provisioned empty H0 is accepted
    /// as an idempotent retry; any nonempty local or external head is rejected.
    ///
    /// # Errors
    ///
    /// Returns a stable journal store error for an unsafe root, nonempty local state, foreign clock
    /// scope, policy mismatch, unavailable seal, or nonempty/substituted external head.
    pub async fn initialize_journal_runtime(
        self,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
    ) -> Result<MusubiProviderAttestationJournalRuntimeV1, MusubiProviderAttestationJournalErrorV1>
    {
        let checkpoint_scope = self.checkpoint_scope()?;
        let lease = self
            .acquire_composite_operation_lease()
            .await
            .map_err(map_store_error_to_journal)?;
        let initialization = async {
            let local = self.load_local().await?;
            if local != MusubiProviderAttestationJournalStoreSnapshotV1::empty() {
                return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
            }
            let h0 = clock
                .initialize_journal_checkpoint_seal(&checkpoint_scope)
                .await
                .map_err(map_checkpoint_error_to_store)?;
            if h0.head().is_some() || h0.generation() != 1 {
                return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
            }
            let (verified_h0, verified_blob) = clock
                .load_journal_checkpoint(&checkpoint_scope, self.policy)
                .await
                .map_err(map_checkpoint_error_to_store)?;
            if verified_h0 != h0
                || verified_blob.is_some()
                || self.load_local().await?
                    != MusubiProviderAttestationJournalStoreSnapshotV1::empty()
            {
                return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
            }
            Ok(())
        }
        .await;
        finish_composite_operation(lease, initialization)
            .await
            .map_err(map_store_error_to_journal)?;
        let policy = self.policy;
        let sealed = Arc::new(MusubiProviderAttestationSealedJournalFileStoreV1::new(
            self,
            Arc::clone(&clock),
            checkpoint_scope.clone(),
        ));
        MusubiProviderAttestationJournalRuntimeV1::new_initialized(
            sealed,
            policy,
            clock,
            checkpoint_scope,
        )
    }
    /// Open an existing externally sealed journal runtime.
    ///
    /// Ordinary open rejects an absent external H0 and never initializes from local bytes. The
    /// external head/blob is authoritative. A safe local exact direct predecessor may be repaired
    /// forward; all deeper rollback, ahead/fork, missing-blob, and substituted state is rejected.
    ///
    /// # Errors
    ///
    /// Returns a stable journal store error for unsafe local state, absent or invalid external
    /// authority, scope/policy mismatch, or failed bounded direct-predecessor repair.
    pub async fn open_journal_runtime(
        self,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
    ) -> Result<MusubiProviderAttestationJournalRuntimeV1, MusubiProviderAttestationJournalErrorV1>
    {
        let checkpoint_scope = self.checkpoint_scope()?;
        let policy = self.policy;
        let sealed = Arc::new(MusubiProviderAttestationSealedJournalFileStoreV1::new(
            self,
            Arc::clone(&clock),
            checkpoint_scope.clone(),
        ));
        sealed
            .load_sealed()
            .await
            .map_err(map_store_error_to_journal)?;
        MusubiProviderAttestationJournalRuntimeV1::new_opened(
            sealed,
            policy,
            clock,
            checkpoint_scope,
        )
    }
    fn checkpoint_scope(
        &self,
    ) -> Result<
        MusubiProviderAttestationJournalCheckpointScopeV1,
        MusubiProviderAttestationJournalErrorV1,
    > {
        let policy_digest = self.policy.digest()?;
        MusubiProviderAttestationJournalCheckpointScopeV1::try_new(
            *self.binding.network_id(),
            self.binding.provider_id(),
            policy_digest,
        )
        .map_err(|_| MusubiProviderAttestationJournalErrorV1::StoreRejected)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn validate_current_blocking(&self) -> io::Result<()> {
        self.root_guard.revalidate()?;
        let loaded = self.store.try_load();
        let validated = match loaded {
            Ok(snapshot) => self
                .validate_physical_snapshot(&snapshot)
                .map(|_| ())
                .map_err(store_error_to_io),
            Err(TwoSlotTryErrorV1::Busy) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Musubi provider-attestation journal two-slot store is busy",
            )),
            Err(TwoSlotTryErrorV1::Io(error)) => Err(error),
        };
        let post_load = self.root_guard.revalidate();
        match (validated, post_load) {
            (_, Err(error)) | (Err(error), Ok(())) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
    async fn run_blocking<ResultValue, Operation>(
        &self,
        operation: Operation,
    ) -> Result<ResultValue, MusubiProviderAttestationJournalStoreErrorV1>
    where
        ResultValue: Send + 'static,
        Operation: FnOnce(&Self) -> Result<ResultValue, MusubiProviderAttestationJournalStoreErrorV1>
            + Send
            + 'static,
    {
        let permit = Arc::clone(&self.local_gate)
            .try_acquire_owned()
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
        let adapter = self.clone();
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
        runtime
            .spawn_blocking(move || {
                let _permit = permit;
                adapter.run_revalidated(operation)
            })
            .await
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?
    }
    fn run_revalidated<ResultValue, Operation>(
        &self,
        operation: Operation,
    ) -> Result<ResultValue, MusubiProviderAttestationJournalStoreErrorV1>
    where
        Operation:
            FnOnce(&Self) -> Result<ResultValue, MusubiProviderAttestationJournalStoreErrorV1>,
    {
        self.root_guard.revalidate().map_err(map_store_io_error)?;
        let result = operation(self);
        let post_operation = self.root_guard.revalidate().map_err(map_store_io_error);
        match (result, post_operation) {
            (_, Err(error)) | (Err(error), Ok(())) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
    fn load_nonblocking(
        &self,
    ) -> Result<
        MusubiProviderAttestationJournalStoreSnapshotV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let physical = self.store.try_load().map_err(map_two_slot_try_error)?;
        let validated = self.validate_physical_snapshot(&physical)?;
        if validated.sequence == 0 {
            return Ok(MusubiProviderAttestationJournalStoreSnapshotV1::empty());
        }
        let snapshot = MusubiProviderAttestationJournalStoreSnapshotV1::from_checkpoint_bytes(
            physical.payload().to_vec(),
        )?;
        if snapshot.revision() != validated.revision {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        Ok(snapshot)
    }
    fn compare_and_swap_nonblocking(
        &self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> Result<
        MusubiProviderAttestationJournalCasOutcomeV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let replacement_snapshot =
            MusubiProviderAttestationJournalStoreSnapshotV1::from_checkpoint_bytes(
                replacement_checkpoint_bytes.clone(),
            )?;
        let replacement_revision = replacement_snapshot
            .revision()
            .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?;
        let replacement_sequence = self.validate_checkpoint_bytes(&replacement_checkpoint_bytes)?;
        let current_physical = self.store.try_load().map_err(map_two_slot_try_error)?;
        let current = self.validate_physical_snapshot(&current_physical)?;
        // An exact current-byte replay is a successful idempotent no-op even
        // when the caller retained an older predecessor revision. Re-enter the
        // two-slot CAS lock so a concurrent successor cannot make this stale
        // preflight look successful. This cannot install or acknowledge any
        // other checkpoint: replacement validation already proved the exact
        // bytes, sequence, deployment binding, and content revision. Every
        // differing replacement still observes strict expected-revision CAS.
        if current_physical.payload() == replacement_checkpoint_bytes.as_slice() {
            return match self
                .store
                .try_compare_and_swap(&current_physical, &replacement_checkpoint_bytes)
                .map_err(map_two_slot_try_error)?
            {
                TwoSlotCasOutcomeV1::Stored(stored) => {
                    let stored_checkpoint = self.validate_physical_snapshot(&stored)?;
                    if stored.payload() != replacement_checkpoint_bytes.as_slice()
                        || stored_checkpoint.sequence != replacement_sequence
                        || stored_checkpoint.revision != Some(replacement_revision)
                    {
                        return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
                    }
                    Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                        revision: replacement_revision,
                    })
                }
                TwoSlotCasOutcomeV1::Conflict(latest) => {
                    let latest_checkpoint = self.validate_physical_snapshot(&latest)?;
                    if latest.payload() == replacement_checkpoint_bytes.as_slice() {
                        Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                            revision: replacement_revision,
                        })
                    } else if latest_checkpoint.revision != expected_revision {
                        Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict)
                    } else {
                        Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
                    }
                }
            };
        }
        if current.revision != expected_revision {
            return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict);
        }
        if current
            .sequence
            .checked_add(1)
            .is_none_or(|expected_sequence| expected_sequence != replacement_sequence)
        {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        match self
            .store
            .try_compare_and_swap(&current_physical, &replacement_checkpoint_bytes)
            .map_err(map_two_slot_try_error)?
        {
            TwoSlotCasOutcomeV1::Stored(stored) => {
                let stored_checkpoint = self.validate_physical_snapshot(&stored)?;
                if stored.payload() != replacement_checkpoint_bytes.as_slice()
                    || stored_checkpoint.sequence != replacement_sequence
                    || stored_checkpoint.revision != Some(replacement_revision)
                {
                    return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
                }
                Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                    revision: replacement_revision,
                })
            }
            TwoSlotCasOutcomeV1::Conflict(latest) => {
                let latest_checkpoint = self.validate_physical_snapshot(&latest)?;
                if latest.payload() == replacement_checkpoint_bytes.as_slice() {
                    return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                        revision: replacement_revision,
                    });
                }
                if latest_checkpoint.revision != expected_revision {
                    Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict)
                } else {
                    Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
                }
            }
        }
    }
    fn validate_physical_snapshot(
        &self,
        snapshot: &TwoSlotSnapshotV1,
    ) -> Result<ValidatedPhysicalCheckpointV1, MusubiProviderAttestationJournalStoreErrorV1> {
        if snapshot.payload().is_empty() {
            return if snapshot.generation() == 1 {
                Ok(ValidatedPhysicalCheckpointV1 {
                    sequence: 0,
                    revision: None,
                })
            } else {
                Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
            };
        }
        let sequence = self.validate_checkpoint_bytes(snapshot.payload())?;
        if sequence
            .checked_add(1)
            .is_none_or(|expected_generation| expected_generation != snapshot.generation())
        {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        Ok(ValidatedPhysicalCheckpointV1 {
            sequence,
            revision: Some(musubi_provider_attestation_journal_checkpoint_revision_v1(
                snapshot.payload(),
            )),
        })
    }
    fn validate_checkpoint_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<u64, MusubiProviderAttestationJournalStoreErrorV1> {
        validate_musubi_provider_attestation_journal_checkpoint_metadata_v1(
            bytes,
            self.policy,
            self.binding.network_id(),
            self.binding.provider_id(),
        )
        .map(|(sequence, _)| sequence)
        .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Rejected)
    }
    async fn load_local(
        &self,
    ) -> Result<
        MusubiProviderAttestationJournalStoreSnapshotV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        self.run_blocking(|adapter| adapter.load_nonblocking())
            .await
    }
    async fn compare_and_swap_local(
        &self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> Result<
        MusubiProviderAttestationJournalCasOutcomeV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        self.run_blocking(move |adapter| {
            adapter.compare_and_swap_nonblocking(expected_revision, replacement_checkpoint_bytes)
        })
        .await
    }
    async fn acquire_composite_operation_lease(
        &self,
    ) -> Result<
        MusubiProviderAttestationJournalCompositeOperationLeaseV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let process_permit = Arc::clone(&self.composite_gate)
            .try_acquire_owned()
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
        let root_guard = self.root_guard.clone();
        let journal_directory = self.journal_directory.clone();
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            root_guard.revalidate().map_err(map_store_io_error)?;
            let bound_lease = store
                .try_acquire_bound_operation_lease(&journal_directory)
                .map_err(map_two_slot_try_error)?;
            let lease = MusubiProviderAttestationJournalCompositeOperationLeaseV1 {
                root_guard,
                bound_lease: Some(bound_lease),
                _process_permit: process_permit,
            };
            lease.verify()?;
            Ok(lease)
        })
        .await
        .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?
    }
}
/// Root-fenced cross-process lease spanning external and local journal state.
///
/// The per-call two-slot lock is intentionally insufficient here: the external blob/head mutation
/// and the following local CAS form one composite operation. Holding the nonblocking init-lock
/// identity already committed in the two-slot headers prevents another process from advancing the
/// external head through the bounded one-step repair window.
struct MusubiProviderAttestationJournalCompositeOperationLeaseV1 {
    root_guard: GovernanceFilesystemRootGuard,
    bound_lease: Option<TwoSlotBoundOperationLeaseV1>,
    _process_permit: OwnedSemaphorePermit,
}
impl MusubiProviderAttestationJournalCompositeOperationLeaseV1 {
    fn verify(&self) -> Result<(), MusubiProviderAttestationJournalStoreErrorV1> {
        self.bound_lease
            .as_ref()
            .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?
            .verify()
            .map_err(map_store_io_error)?;
        self.root_guard.revalidate().map_err(map_store_io_error)
    }
    fn release_blocking(mut self) -> Result<(), MusubiProviderAttestationJournalStoreErrorV1> {
        let before = self.verify();
        let unlock = self
            .bound_lease
            .take()
            .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
            .and_then(|lease| lease.release().map_err(map_store_io_error));
        let after = self.root_guard.revalidate().map_err(map_store_io_error);
        match (before, unlock, after) {
            (_, Err(error), _) | (Err(error), Ok(()), _) | (Ok(()), Ok(()), Err(error)) => {
                Err(error)
            }
            (Ok(()), Ok(()), Ok(())) => Ok(()),
        }
    }
}
async fn finish_composite_operation<ResultValue>(
    lease: MusubiProviderAttestationJournalCompositeOperationLeaseV1,
    result: Result<ResultValue, MusubiProviderAttestationJournalStoreErrorV1>,
) -> Result<ResultValue, MusubiProviderAttestationJournalStoreErrorV1> {
    let release = tokio::task::spawn_blocking(move || lease.release_blocking())
        .await
        .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
    match (result, release) {
        (_, Err(error)) | (Err(error), Ok(())) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
struct MusubiProviderAttestationSealedJournalFileStoreV1 {
    local: MusubiProviderAttestationJournalFileStoreV1,
    clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
    checkpoint_scope: MusubiProviderAttestationJournalCheckpointScopeV1,
    operation_gate: Mutex<()>,
    #[cfg(test)]
    fail_next_local_sync: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pause_after_external_commit: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    external_commit_reached: tokio::sync::Notify,
    #[cfg(test)]
    resume_after_external_commit: tokio::sync::Notify,
}
impl fmt::Debug for MusubiProviderAttestationSealedJournalFileStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiProviderAttestationSealedJournalFileStoreV1")
            .field("local", &self.local)
            .field("checkpoint_scope", &self.checkpoint_scope)
            .finish_non_exhaustive()
    }
}
impl MusubiProviderAttestationSealedJournalFileStoreV1 {
    fn new(
        local: MusubiProviderAttestationJournalFileStoreV1,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
        checkpoint_scope: MusubiProviderAttestationJournalCheckpointScopeV1,
    ) -> Self {
        Self {
            local,
            clock,
            checkpoint_scope,
            operation_gate: Mutex::new(()),
            #[cfg(test)]
            fail_next_local_sync: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            pause_after_external_commit: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            external_commit_reached: tokio::sync::Notify::new(),
            #[cfg(test)]
            resume_after_external_commit: tokio::sync::Notify::new(),
        }
    }
    async fn load_sealed(
        &self,
    ) -> Result<
        MusubiProviderAttestationJournalStoreSnapshotV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
        let lease = self.local.acquire_composite_operation_lease().await?;
        let result = self
            .load_and_reconcile_locked()
            .await
            .map(|(_, snapshot)| snapshot);
        finish_composite_operation(lease, result).await
    }
    async fn load_and_reconcile_locked(
        &self,
    ) -> Result<
        (
            MusubiProviderAttestationJournalCheckpointHeadRecordV1,
            MusubiProviderAttestationJournalStoreSnapshotV1,
        ),
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let (record, blob) = self
            .clock
            .load_journal_checkpoint(&self.checkpoint_scope, self.local.policy)
            .await
            .map_err(map_checkpoint_error_to_store)?;
        let snapshot = self
            .reconcile_local_to_authoritative(&record, blob.as_deref())
            .await?;
        Ok((record, snapshot))
    }
    async fn reconcile_local_to_authoritative(
        &self,
        record: &MusubiProviderAttestationJournalCheckpointHeadRecordV1,
        authoritative_blob: Option<&[u8]>,
    ) -> Result<
        MusubiProviderAttestationJournalStoreSnapshotV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let authoritative = match (record.head(), authoritative_blob) {
            (None, None) if record.generation() == 1 => {
                MusubiProviderAttestationJournalStoreSnapshotV1::empty()
            }
            (Some(head), Some(blob)) => {
                let snapshot =
                    MusubiProviderAttestationJournalStoreSnapshotV1::from_checkpoint_bytes(
                        blob.to_vec(),
                    )?;
                if snapshot.revision() != Some(head.checkpoint_revision()) {
                    return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
                }
                snapshot
            }
            _ => return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected),
        };
        let local = self.local.load_local().await?;
        if local == authoritative {
            return Ok(authoritative);
        }
        let Some(authoritative_head) = record.head() else {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        };
        let local_sequence = match local.checkpoint_bytes() {
            None => 0,
            Some(bytes) => self.local.validate_checkpoint_bytes(bytes)?,
        };
        if local_sequence.checked_add(1) != Some(authoritative_head.checkpoint_sequence()) {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        let (predecessor, predecessor_blob) = self
            .clock
            .load_journal_checkpoint_direct_predecessor(
                &self.checkpoint_scope,
                self.local.policy,
                record,
            )
            .await
            .map_err(map_checkpoint_error_to_store)?;
        let local_is_exact_predecessor = match (predecessor.head(), predecessor_blob.as_deref()) {
            (None, None) => local == MusubiProviderAttestationJournalStoreSnapshotV1::empty(),
            (Some(head), Some(blob)) => {
                local.revision() == Some(head.checkpoint_revision())
                    && local.checkpoint_bytes() == Some(blob)
            }
            _ => false,
        };
        if !local_is_exact_predecessor {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        let authoritative_bytes = authoritative
            .checkpoint_bytes()
            .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?
            .to_vec();
        self.sync_local_successor(local.revision(), authoritative_bytes)
            .await?;
        let repaired = self.local.load_local().await?;
        if repaired != authoritative {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        Ok(repaired)
    }
    async fn compare_and_swap_sealed(
        &self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> Result<
        MusubiProviderAttestationJournalCasOutcomeV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Unavailable)?;
        let lease = self.local.acquire_composite_operation_lease().await?;
        let result = self
            .compare_and_swap_sealed_locked(expected_revision, replacement_checkpoint_bytes)
            .await;
        finish_composite_operation(lease, result).await
    }
    async fn compare_and_swap_sealed_locked(
        &self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> Result<
        MusubiProviderAttestationJournalCasOutcomeV1,
        MusubiProviderAttestationJournalStoreErrorV1,
    > {
        let (current_record, current) = self.load_and_reconcile_locked().await?;
        let replacement = MusubiProviderAttestationJournalStoreSnapshotV1::from_checkpoint_bytes(
            replacement_checkpoint_bytes.clone(),
        )?;
        let replacement_revision = replacement
            .revision()
            .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?;
        let (replacement_sequence, last_observed_unix_ms) =
            validate_musubi_provider_attestation_journal_checkpoint_metadata_v1(
                &replacement_checkpoint_bytes,
                self.local.policy,
                self.local.binding.network_id(),
                self.local.binding.provider_id(),
            )
            .map_err(|_| MusubiProviderAttestationJournalStoreErrorV1::Rejected)?;
        if current == replacement {
            return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: replacement_revision,
            });
        }
        if current.revision() != expected_revision {
            return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict);
        }
        let expected_sequence = match current_record.head() {
            None => 1,
            Some(head) => head
                .checkpoint_sequence()
                .checked_add(1)
                .ok_or(MusubiProviderAttestationJournalStoreErrorV1::Rejected)?,
        };
        if replacement_sequence != expected_sequence {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        let head = MusubiProviderAttestationJournalCheckpointHeadV1::try_new(
            replacement_sequence,
            replacement_revision,
            last_observed_unix_ms,
        )
        .map_err(map_checkpoint_error_to_store)?;
        match self
            .clock
            .seal_journal_checkpoint(
                &self.checkpoint_scope,
                self.local.policy,
                &current_record,
                head,
                &replacement_checkpoint_bytes,
            )
            .await
        {
            Ok(_) => {
                #[cfg(test)]
                if self
                    .pause_after_external_commit
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    self.external_commit_reached.notify_one();
                    self.resume_after_external_commit.notified().await;
                }
                self.sync_local_successor(current.revision(), replacement_checkpoint_bytes)
                    .await?;
                Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                    revision: replacement_revision,
                })
            }
            Err(error) => {
                let reloaded = self
                    .clock
                    .load_journal_checkpoint(&self.checkpoint_scope, self.local.policy)
                    .await;
                let Ok((latest_record, latest_blob)) = reloaded else {
                    return Err(map_checkpoint_error_to_store(error));
                };
                let latest = self
                    .reconcile_local_to_authoritative(&latest_record, latest_blob.as_deref())
                    .await?;
                if latest == replacement {
                    return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                        revision: replacement_revision,
                    });
                }
                if latest_record.validate_successor_of(&current_record).is_ok() {
                    return Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict);
                }
                if latest_record == current_record {
                    return Err(map_checkpoint_error_to_store(error));
                }
                Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
            }
        }
    }
    async fn sync_local_successor(
        &self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> Result<(), MusubiProviderAttestationJournalStoreErrorV1> {
        #[cfg(test)]
        if self
            .fail_next_local_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Unavailable);
        }
        let expected_bytes = replacement_checkpoint_bytes.clone();
        match self
            .local
            .compare_and_swap_local(expected_revision, replacement_checkpoint_bytes)
            .await?
        {
            MusubiProviderAttestationJournalCasOutcomeV1::Stored { .. } => {}
            MusubiProviderAttestationJournalCasOutcomeV1::Conflict => {
                let latest = self.local.load_local().await?;
                if latest.checkpoint_bytes() != Some(expected_bytes.as_slice()) {
                    return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
                }
            }
        }
        let latest = self.local.load_local().await?;
        if latest.checkpoint_bytes() != Some(expected_bytes.as_slice()) {
            return Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected);
        }
        Ok(())
    }
}
impl MusubiProviderAttestationJournalStoreV1 for MusubiProviderAttestationSealedJournalFileStoreV1 {
    fn load<'a>(
        &'a self,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderAttestationJournalStoreSnapshotV1,
            MusubiProviderAttestationJournalStoreErrorV1,
        >,
    > {
        Box::pin(async move { self.load_sealed().await })
    }
    fn compare_and_swap<'a>(
        &'a self,
        expected_revision: Option<[u8; 32]>,
        replacement_checkpoint_bytes: Vec<u8>,
    ) -> ProviderIngestFutureV1<
        'a,
        Result<
            MusubiProviderAttestationJournalCasOutcomeV1,
            MusubiProviderAttestationJournalStoreErrorV1,
        >,
    > {
        Box::pin(async move {
            self.compare_and_swap_sealed(expected_revision, replacement_checkpoint_bytes)
                .await
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatedPhysicalCheckpointV1 {
    sequence: u64,
    revision: Option<[u8; 32]>,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn two_slot_config(
    binding: &MusubiProviderAttestationJournalFileBindingV1,
) -> io::Result<TwoSlotStoreConfigV1> {
    let domain = *blake3::hash(JOURNAL_TWO_SLOT_DOMAIN_LABEL_V1).as_bytes();
    TwoSlotStoreConfigV1::try_new(
        JOURNAL_TWO_SLOT_STORE_NAME_V1,
        domain,
        binding.stable_store_nonce(),
        MUSUBI_PROVIDER_ATTESTATION_JOURNAL_CHECKPOINT_MAX_BYTES_V1,
    )
}
fn map_two_slot_try_error(
    error: TwoSlotTryErrorV1,
) -> MusubiProviderAttestationJournalStoreErrorV1 {
    match error {
        TwoSlotTryErrorV1::Busy => MusubiProviderAttestationJournalStoreErrorV1::Unavailable,
        TwoSlotTryErrorV1::Io(error) => map_store_io_error(error),
    }
}
fn map_store_io_error(error: io::Error) -> MusubiProviderAttestationJournalStoreErrorV1 {
    match error.kind() {
        io::ErrorKind::InvalidInput
        | io::ErrorKind::InvalidData
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::NotFound
        | io::ErrorKind::AlreadyExists
        | io::ErrorKind::Unsupported
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::Other => MusubiProviderAttestationJournalStoreErrorV1::Rejected,
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::TimedOut => {
            MusubiProviderAttestationJournalStoreErrorV1::Unavailable
        }
        _ => MusubiProviderAttestationJournalStoreErrorV1::Unavailable,
    }
}
fn map_checkpoint_error_to_store(
    error: MusubiProviderAttestationJournalCheckpointSealErrorV1,
) -> MusubiProviderAttestationJournalStoreErrorV1 {
    match error {
        MusubiProviderAttestationJournalCheckpointSealErrorV1::SealUnavailable
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::SealAmbiguous => {
            MusubiProviderAttestationJournalStoreErrorV1::Unavailable
        }
        MusubiProviderAttestationJournalCheckpointSealErrorV1::InvalidScope
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::InvalidHead
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::InvalidRecord
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::InvalidLineage
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::InvalidBlob
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::MissingBlob
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::AlreadyInitialized
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::Uninitialized
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::InvalidSealBinding
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::SealRejected
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::Rollback
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::Fork
        | MusubiProviderAttestationJournalCheckpointSealErrorV1::ArithmeticOverflow => {
            MusubiProviderAttestationJournalStoreErrorV1::Rejected
        }
    }
}
fn map_store_error_to_journal(
    error: MusubiProviderAttestationJournalStoreErrorV1,
) -> MusubiProviderAttestationJournalErrorV1 {
    match error {
        MusubiProviderAttestationJournalStoreErrorV1::Unavailable => {
            MusubiProviderAttestationJournalErrorV1::StoreUnavailable
        }
        MusubiProviderAttestationJournalStoreErrorV1::Rejected => {
            MusubiProviderAttestationJournalErrorV1::StoreRejected
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn store_error_to_io(error: MusubiProviderAttestationJournalStoreErrorV1) -> io::Error {
    match error {
        MusubiProviderAttestationJournalStoreErrorV1::Unavailable => io::Error::new(
            io::ErrorKind::WouldBlock,
            "Musubi provider-attestation journal file store is unavailable",
        ),
        MusubiProviderAttestationJournalStoreErrorV1::Rejected => io::Error::new(
            io::ErrorKind::InvalidData,
            "Musubi provider-attestation journal file store rejected durable state",
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::provider_attestation_clock::{
        MusubiProviderAttestationClockSealBindingV1, MusubiProviderAttestationClockSealErrorV1,
        MusubiProviderAttestationClockSealQualificationV1,
        MusubiProviderAttestationClockSealRecordV1, MusubiProviderAttestationClockSealV1,
        MusubiProviderAttestationJournalCheckpointHeadRecordV1,
        musubi_provider_attestation_journal_checkpoint_blob_revision_v1,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::provider_attestation_journal::musubi_provider_attestation_journal_test_checkpoint_bytes_v1;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::block::BlockHeader;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{Arc, Mutex as StdMutex},
    };
    use tempfile::TempDir;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CLOCK_SEAL_HANDLE: &str = "sealed://musubi/provider-attestation/journal-clock-primary";
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    type CheckpointKey = ([u8; 32], [u8; 32]);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    type CheckpointBlobs = BTreeMap<CheckpointKey, Vec<u8>>;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    type CheckpointHeadRecords =
        BTreeMap<CheckpointKey, MusubiProviderAttestationJournalCheckpointHeadRecordV1>;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug)]
    struct LocalClockSeal {
        qualification: MusubiProviderAttestationClockSealQualificationV1,
        record: StdMutex<Option<([u8; 32], MusubiProviderAttestationClockSealRecordV1)>>,
        checkpoint_blobs: StdMutex<CheckpointBlobs>,
        checkpoint_heads:
            StdMutex<BTreeMap<[u8; 32], MusubiProviderAttestationJournalCheckpointHeadRecordV1>>,
        checkpoint_head_records: StdMutex<CheckpointHeadRecords>,
        next_checkpoint_head_error: StdMutex<Option<MusubiProviderAttestationClockSealErrorV1>>,
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl LocalClockSeal {
        fn new() -> Self {
            Self {
                qualification: MusubiProviderAttestationClockSealQualificationV1::new(
                    1, [0xA5; 32],
                ),
                record: StdMutex::new(None),
                checkpoint_blobs: StdMutex::new(BTreeMap::new()),
                checkpoint_heads: StdMutex::new(BTreeMap::new()),
                checkpoint_head_records: StdMutex::new(BTreeMap::new()),
                next_checkpoint_head_error: StdMutex::new(None),
            }
        }
        fn binding(&self) -> MusubiProviderAttestationClockSealBindingV1 {
            MusubiProviderAttestationClockSealBindingV1::try_new(
                CLOCK_SEAL_HANDLE,
                self.qualification,
            )
            .expect("valid local clock-seal binding")
        }
        fn fail_next_checkpoint_head(&self, error: MusubiProviderAttestationClockSealErrorV1) {
            *self
                .next_checkpoint_head_error
                .lock()
                .expect("checkpoint head error lock") = Some(error);
        }
        fn remove_checkpoint_blob(&self, scope_digest: [u8; 32], revision: [u8; 32]) {
            self.checkpoint_blobs
                .lock()
                .expect("checkpoint blob lock")
                .remove(&(scope_digest, revision));
        }
        fn substitute_checkpoint_blob(
            &self,
            scope_digest: [u8; 32],
            revision: [u8; 32],
            bytes: Vec<u8>,
        ) {
            self.checkpoint_blobs
                .lock()
                .expect("checkpoint blob lock")
                .insert((scope_digest, revision), bytes);
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl MusubiProviderAttestationClockSealV1 for LocalClockSeal {
        fn runtime_handle(&self) -> &str {
            CLOCK_SEAL_HANDLE
        }
        fn qualification(
            &self,
        ) -> Result<
            MusubiProviderAttestationClockSealQualificationV1,
            MusubiProviderAttestationClockSealErrorV1,
        > {
            Ok(self.qualification)
        }
        fn load_latest<'a>(
            &'a self,
            scope_digest: [u8; 32],
        ) -> ProviderIngestFutureV1<
            'a,
            Result<
                Option<MusubiProviderAttestationClockSealRecordV1>,
                MusubiProviderAttestationClockSealErrorV1,
            >,
        > {
            Box::pin(async move {
                match self.record.lock().expect("clock-seal record lock").as_ref() {
                    None => Ok(None),
                    Some((retained_scope, record)) if *retained_scope == scope_digest => {
                        Ok(Some(record.clone()))
                    }
                    Some(_) => Err(MusubiProviderAttestationClockSealErrorV1::Rejected),
                }
            })
        }
        fn compare_and_swap<'a>(
            &'a self,
            scope_digest: [u8; 32],
            expected: Option<[u8; 32]>,
            next: &'a MusubiProviderAttestationClockSealRecordV1,
        ) -> ProviderIngestFutureV1<'a, Result<(), MusubiProviderAttestationClockSealErrorV1>>
        {
            Box::pin(async move {
                let mut retained = self.record.lock().expect("clock-seal record lock");
                if retained
                    .as_ref()
                    .is_some_and(|(retained_scope, _)| *retained_scope != scope_digest)
                    || retained.as_ref().map(|(_, record)| record.record_digest()) != expected
                {
                    return Err(MusubiProviderAttestationClockSealErrorV1::Rejected);
                }
                *retained = Some((scope_digest, next.clone()));
                Ok(())
            })
        }
        fn put_journal_checkpoint_blob<'a>(
            &'a self,
            scope_digest: [u8; 32],
            checkpoint_revision: [u8; 32],
            checkpoint_blob: &'a [u8],
        ) -> ProviderIngestFutureV1<'a, Result<(), MusubiProviderAttestationClockSealErrorV1>>
        {
            Box::pin(async move {
                if musubi_provider_attestation_journal_checkpoint_blob_revision_v1(checkpoint_blob)
                    .ok()
                    != Some(checkpoint_revision)
                {
                    return Err(MusubiProviderAttestationClockSealErrorV1::Rejected);
                }
                let mut blobs = self.checkpoint_blobs.lock().expect("checkpoint blob lock");
                if blobs
                    .get(&(scope_digest, checkpoint_revision))
                    .is_some_and(|retained| retained.as_slice() != checkpoint_blob)
                {
                    return Err(MusubiProviderAttestationClockSealErrorV1::Rejected);
                }
                blobs
                    .entry((scope_digest, checkpoint_revision))
                    .or_insert_with(|| checkpoint_blob.to_vec());
                Ok(())
            })
        }
        fn load_journal_checkpoint_blob<'a>(
            &'a self,
            scope_digest: [u8; 32],
            checkpoint_revision: [u8; 32],
        ) -> ProviderIngestFutureV1<
            'a,
            Result<Option<Vec<u8>>, MusubiProviderAttestationClockSealErrorV1>,
        > {
            Box::pin(async move {
                Ok(self
                    .checkpoint_blobs
                    .lock()
                    .expect("checkpoint blob lock")
                    .get(&(scope_digest, checkpoint_revision))
                    .cloned())
            })
        }
        fn load_journal_checkpoint_head<'a>(
            &'a self,
            scope_digest: [u8; 32],
        ) -> ProviderIngestFutureV1<
            'a,
            Result<
                Option<MusubiProviderAttestationJournalCheckpointHeadRecordV1>,
                MusubiProviderAttestationClockSealErrorV1,
            >,
        > {
            Box::pin(async move {
                Ok(self
                    .checkpoint_heads
                    .lock()
                    .expect("checkpoint head lock")
                    .get(&scope_digest)
                    .cloned())
            })
        }
        fn load_journal_checkpoint_head_record<'a>(
            &'a self,
            scope_digest: [u8; 32],
            record_digest: [u8; 32],
        ) -> ProviderIngestFutureV1<
            'a,
            Result<
                Option<MusubiProviderAttestationJournalCheckpointHeadRecordV1>,
                MusubiProviderAttestationClockSealErrorV1,
            >,
        > {
            Box::pin(async move {
                Ok(self
                    .checkpoint_head_records
                    .lock()
                    .expect("checkpoint head record lock")
                    .get(&(scope_digest, record_digest))
                    .cloned())
            })
        }
        fn compare_and_swap_journal_checkpoint_head<'a>(
            &'a self,
            scope_digest: [u8; 32],
            expected: Option<[u8; 32]>,
            next: &'a MusubiProviderAttestationJournalCheckpointHeadRecordV1,
        ) -> ProviderIngestFutureV1<'a, Result<(), MusubiProviderAttestationClockSealErrorV1>>
        {
            Box::pin(async move {
                let error = self
                    .next_checkpoint_head_error
                    .lock()
                    .expect("checkpoint head error lock")
                    .take();
                let mut heads = self.checkpoint_heads.lock().expect("checkpoint head lock");
                if heads.get(&scope_digest) == Some(next) {
                    return Ok(());
                }
                if heads
                    .get(&scope_digest)
                    .map(MusubiProviderAttestationJournalCheckpointHeadRecordV1::record_digest)
                    != expected
                    || next.scope_digest() != scope_digest
                    || next.head().is_some_and(|head| {
                        !self
                            .checkpoint_blobs
                            .lock()
                            .expect("checkpoint blob lock")
                            .contains_key(&(scope_digest, head.checkpoint_revision()))
                    })
                {
                    return Err(MusubiProviderAttestationClockSealErrorV1::Rejected);
                }
                if error != Some(MusubiProviderAttestationClockSealErrorV1::Rejected) {
                    heads.insert(scope_digest, next.clone());
                    self.checkpoint_head_records
                        .lock()
                        .expect("checkpoint head record lock")
                        .insert((scope_digest, next.record_digest()), next.clone());
                }
                error.map_or(Ok(()), Err)
            })
        }
    }
    fn binding(seed: u8) -> MusubiProviderAttestationJournalFileBindingV1 {
        MusubiProviderAttestationJournalFileBindingV1::try_new(
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                [seed; 32],
            ))),
            ProviderId::new([seed.wrapping_add(1); 32]),
        )
        .expect("valid file-store binding")
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn sealed_clock(
        binding: &MusubiProviderAttestationJournalFileBindingV1,
    ) -> Arc<MusubiProviderAttestationSealedUnixClockV1> {
        sealed_clock_and_provider(binding).await.0
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn sealed_clock_and_provider(
        binding: &MusubiProviderAttestationJournalFileBindingV1,
    ) -> (
        Arc<MusubiProviderAttestationSealedUnixClockV1>,
        Arc<LocalClockSeal>,
    ) {
        let seal = Arc::new(LocalClockSeal::new());
        let seal_binding = seal.binding();
        let clock = Arc::new(
            MusubiProviderAttestationSealedUnixClockV1::initialize(
                binding.clock_scope(),
                seal_binding,
                seal.clone(),
            )
            .await
            .expect("initialize local sealed clock"),
        );
        (clock, seal)
    }
    #[test]
    fn file_binding_derives_the_exact_clock_scope() {
        let binding = binding(0x30);
        let scope = binding.clock_scope();
        assert_eq!(scope.network_id(), binding.network_id());
        assert_eq!(scope.provider_id(), binding.provider_id());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn canonical_root(temp: &TempDir) -> PathBuf {
        temp.path().canonicalize().expect("canonical state root")
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn store(
        root: &Path,
        binding: MusubiProviderAttestationJournalFileBindingV1,
    ) -> MusubiProviderAttestationJournalFileStoreV1 {
        MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            root,
            binding,
            MusubiProviderAttestationJournalPolicyV1::default(),
        )
        .expect("open journal file store")
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn initialized_sealed_store(
        root: &Path,
        binding: MusubiProviderAttestationJournalFileBindingV1,
    ) -> (
        Arc<MusubiProviderAttestationSealedJournalFileStoreV1>,
        Arc<MusubiProviderAttestationSealedUnixClockV1>,
        Arc<LocalClockSeal>,
    ) {
        let local = store(root, binding.clone());
        let checkpoint_scope = local.checkpoint_scope().expect("checkpoint scope");
        let (clock, seal) = sealed_clock_and_provider(&binding).await;
        clock
            .initialize_journal_checkpoint_seal(&checkpoint_scope)
            .await
            .expect("initialize checkpoint H0");
        let sealed = Arc::new(MusubiProviderAttestationSealedJournalFileStoreV1::new(
            local,
            Arc::clone(&clock),
            checkpoint_scope,
        ));
        (sealed, clock, seal)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reopened_sealed_store(
        root: &Path,
        binding: MusubiProviderAttestationJournalFileBindingV1,
        clock: Arc<MusubiProviderAttestationSealedUnixClockV1>,
    ) -> Arc<MusubiProviderAttestationSealedJournalFileStoreV1> {
        let local = store(root, binding);
        let checkpoint_scope = local.checkpoint_scope().expect("checkpoint scope");
        Arc::new(MusubiProviderAttestationSealedJournalFileStoreV1::new(
            local,
            clock,
            checkpoint_scope,
        ))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn advance_external_checkpoint(
        sealed: &MusubiProviderAttestationSealedJournalFileStoreV1,
        sequence: u64,
        last_observed_unix_ms: u64,
    ) -> (
        MusubiProviderAttestationJournalCheckpointHeadRecordV1,
        Vec<u8>,
    ) {
        let (current, _) = sealed
            .clock
            .load_journal_checkpoint(&sealed.checkpoint_scope, sealed.local.policy)
            .await
            .expect("load external predecessor");
        let bytes = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(
            sequence,
            last_observed_unix_ms,
        );
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&bytes);
        let head = MusubiProviderAttestationJournalCheckpointHeadV1::try_new(
            sequence,
            revision,
            last_observed_unix_ms,
        )
        .expect("external checkpoint head");
        let committed = sealed
            .clock
            .seal_journal_checkpoint(
                &sealed.checkpoint_scope,
                sealed.local.policy,
                &current,
                head,
                &bytes,
            )
            .await
            .expect("advance external checkpoint");
        (committed, bytes)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn bound_runtime_accepts_only_the_exact_store_scope_and_policy() {
        let parent = TempDir::new().expect("parent state root");
        let sensitive_root = parent.path().join("operator-secret-state-root");
        std::fs::create_dir(&sensitive_root).expect("create state root");
        let sensitive_root = sensitive_root.canonicalize().expect("canonical state root");
        let binding = binding(0x21);
        let mut policy = MusubiProviderAttestationJournalPolicyV1::default();
        policy.max_entries = 1;
        let store = MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            &sensitive_root,
            binding.clone(),
            policy,
        )
        .expect("open bound journal file store");
        let clock = sealed_clock(&binding).await;
        let runtime = store
            .initialize_journal_runtime(clock)
            .await
            .expect("matching deployment scope must construct the runtime");
        assert_eq!(runtime.policy(), policy);
        assert!(
            !runtime.matches_binding(*binding.network_id(), binding.provider_id(), policy),
            "explicit H0 initialization is never eligible for effect-driver binding"
        );
        let debug = format!("{runtime:?}");
        assert!(!debug.contains(sensitive_root.to_string_lossy().as_ref()));
        assert!(!debug.contains("operator-secret-state-root"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn bound_runtime_rejects_a_foreign_clock_scope() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let store_binding = binding(0x22);
        let store = store(&root_path, store_binding);
        let foreign_clock = sealed_clock(&binding(0x23)).await;
        assert_eq!(
            store
                .initialize_journal_runtime(foreign_clock)
                .await
                .expect_err("a foreign clock scope must fail closed"),
            MusubiProviderAttestationJournalErrorV1::StoreRejected
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn ordinary_open_rejects_absent_head_while_initialize_provisions_h0() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x24);
        let (clock, _) = sealed_clock_and_provider(&binding).await;
        assert_eq!(
            store(&root_path, binding.clone())
                .open_journal_runtime(Arc::clone(&clock))
                .await
                .expect_err("ordinary open must not provision absent H0"),
            MusubiProviderAttestationJournalErrorV1::StoreRejected
        );
        let initialized = store(&root_path, binding.clone())
            .initialize_journal_runtime(Arc::clone(&clock))
            .await
            .expect("explicit initialization provisions empty H0");
        drop(initialized);
        let opened = store(&root_path, binding.clone())
            .open_journal_runtime(clock)
            .await
            .expect("ordinary open accepts existing exact H0");
        let policy = MusubiProviderAttestationJournalPolicyV1::default();
        assert!(opened.matches_binding(*binding.network_id(), binding.provider_id(), policy));
        let foreign = self::binding(0x34);
        assert!(!opened.matches_binding(*foreign.network_id(), foreign.provider_id(), policy));
        let mut foreign_policy = policy;
        foreign_policy.max_entries -= 1;
        assert!(!opened.matches_binding(
            *binding.network_id(),
            binding.provider_id(),
            foreign_policy,
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn explicit_initialize_rejects_nonempty_local_state_without_provisioning_h0() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x2F);
        let local = store(&root_path, binding.clone());
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        local
            .compare_and_swap_local(None, checkpoint)
            .await
            .expect("install structurally valid local-only checkpoint");
        let (clock, provider) = sealed_clock_and_provider(&binding).await;
        assert_eq!(
            local
                .initialize_journal_runtime(clock)
                .await
                .expect_err("initialization never promotes nonempty local bytes"),
            MusubiProviderAttestationJournalErrorV1::StoreRejected
        );
        assert!(
            provider
                .checkpoint_heads
                .lock()
                .expect("checkpoint-head lock")
                .is_empty(),
            "rejected local state must not create external H0"
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn sealed_seq1_survives_exact_public_open() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x25);
        let (sealed, clock, _) = initialized_sealed_store(&root_path, binding.clone()).await;
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        assert_eq!(
            sealed
                .compare_and_swap(None, checkpoint.clone())
                .await
                .expect("seal sequence one"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision }
        );
        assert_eq!(
            sealed
                .load()
                .await
                .expect("load exact sealed checkpoint")
                .checkpoint_bytes(),
            Some(checkpoint.as_slice())
        );
        drop(sealed);
        store(&root_path, binding)
            .open_journal_runtime(clock)
            .await
            .expect("exact local/external restart opens");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn lost_head_response_and_exact_replay_are_idempotent() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let (sealed, _, provider) = initialized_sealed_store(&root_path, binding(0x26)).await;
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        provider.fail_next_checkpoint_head(MusubiProviderAttestationClockSealErrorV1::Ambiguous);
        assert_eq!(
            sealed
                .compare_and_swap(None, checkpoint.clone())
                .await
                .expect("exact readback resolves lost head response"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision }
        );
        assert_eq!(
            sealed
                .compare_and_swap(None, checkpoint)
                .await
                .expect("exact replay with stale predecessor is idempotent"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision }
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn retry_repairs_external_commit_after_local_sync_failure() {
        use std::sync::atomic::Ordering;
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let (sealed, _, _) = initialized_sealed_store(&root_path, binding(0x27)).await;
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        sealed.fail_next_local_sync.store(true, Ordering::SeqCst);
        assert_eq!(
            sealed.compare_and_swap(None, checkpoint.clone()).await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Unavailable)
        );
        assert_eq!(
            sealed
                .local
                .load_local()
                .await
                .expect("local remains direct predecessor"),
            MusubiProviderAttestationJournalStoreSnapshotV1::empty()
        );
        assert_eq!(
            sealed
                .compare_and_swap(None, checkpoint.clone())
                .await
                .expect("retry repairs local direct predecessor"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision }
        );
        assert_eq!(
            sealed
                .local
                .load_local()
                .await
                .expect("repaired local checkpoint")
                .checkpoint_bytes(),
            Some(checkpoint.as_slice())
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn composite_lease_fences_a_second_adapter_until_local_sync() {
        use std::sync::atomic::Ordering;
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x2D);
        let (first, clock, _) = initialized_sealed_store(&root_path, binding.clone()).await;
        let cloned = Arc::new(MusubiProviderAttestationSealedJournalFileStoreV1::new(
            first.local.clone(),
            Arc::clone(&clock),
            first.checkpoint_scope.clone(),
        ));
        let second = reopened_sealed_store(&root_path, binding, clock);
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        first
            .pause_after_external_commit
            .store(true, Ordering::SeqCst);
        let writer = tokio::spawn({
            let first = Arc::clone(&first);
            let checkpoint = checkpoint.clone();
            async move { first.compare_and_swap(None, checkpoint).await }
        });
        first.external_commit_reached.notified().await;
        assert_eq!(
            first.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Unavailable),
            "same-wrapper concurrency remains nonblocking"
        );
        assert_eq!(
            cloned.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Unavailable),
            "a wrapper over a cloned local adapter cannot reenter the process lease"
        );
        assert_eq!(
            second.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Unavailable),
            "a separately opened adapter cannot enter the composite repair window"
        );
        let second_checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(2, 1);
        assert_eq!(
            second
                .compare_and_swap(Some(revision), second_checkpoint)
                .await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Unavailable),
            "sequence two cannot commit before sequence one's local sync"
        );
        first.resume_after_external_commit.notify_one();
        assert_eq!(
            writer.await.expect("first writer task"),
            Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision })
        );
        assert_eq!(
            second
                .load()
                .await
                .expect("second adapter observes the completed composite write")
                .checkpoint_bytes(),
            Some(checkpoint.as_slice())
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn cancellation_after_external_commit_releases_lease_for_exact_repair() {
        use std::sync::atomic::Ordering;
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x2E);
        let (first, clock, _) = initialized_sealed_store(&root_path, binding.clone()).await;
        let second = reopened_sealed_store(&root_path, binding, clock);
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        first
            .pause_after_external_commit
            .store(true, Ordering::SeqCst);
        let writer = tokio::spawn({
            let first = Arc::clone(&first);
            let checkpoint = checkpoint.clone();
            async move { first.compare_and_swap(None, checkpoint).await }
        });
        first.external_commit_reached.notified().await;
        writer.abort();
        assert!(
            writer
                .await
                .expect_err("cancel the writer in the crash window")
                .is_cancelled()
        );
        assert_eq!(
            second
                .compare_and_swap(None, checkpoint.clone())
                .await
                .expect("exact retry repairs the direct predecessor"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored { revision }
        );
        assert_eq!(
            second
                .local
                .load_local()
                .await
                .expect("local checkpoint repaired after cancellation")
                .checkpoint_bytes(),
            Some(checkpoint.as_slice())
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn init_lock_unlink_recreate_cannot_split_the_composite_lease() {
        use std::{os::unix::fs::PermissionsExt as _, sync::atomic::Ordering};
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x3A);
        let (first, clock, provider) = initialized_sealed_store(&root_path, binding.clone()).await;
        let second = reopened_sealed_store(&root_path, binding, clock);
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        first
            .pause_after_external_commit
            .store(true, Ordering::SeqCst);
        let writer = tokio::spawn({
            let first = Arc::clone(&first);
            let checkpoint = checkpoint.clone();
            async move { first.compare_and_swap(None, checkpoint).await }
        });
        first.external_commit_reached.notified().await;
        let init_lock_name = first.local.store.init_lock_name_for_test();
        let journal_path = root_path.join(JOURNAL_DIRECTORY_NAME_V1);
        let checkpoint_store_path = journal_path.join(JOURNAL_TWO_SLOT_STORE_NAME_V1);
        assert_eq!(
            std::fs::read_dir(&checkpoint_store_path)
                .expect("read exact two-slot directory")
                .count(),
            2,
            "the bound operation lease must not create a third two-slot child"
        );
        let init_lock_path = journal_path.join(&init_lock_name);
        std::fs::remove_file(&init_lock_path).expect("unlink held init lock fixture");
        assert_eq!(
            second.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected),
            "a missing bound init lock fails closed"
        );
        assert!(
            !init_lock_path.exists(),
            "normal operation must not recreate a missing critical lock"
        );
        drop(std::fs::File::create(&init_lock_path).expect("install replacement init lock"));
        std::fs::set_permissions(&init_lock_path, std::fs::Permissions::from_mode(0o600))
            .expect("make replacement init lock private");
        let second_checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(2, 1);
        assert_eq!(
            second
                .compare_and_swap(Some(revision), second_checkpoint)
                .await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected),
            "replacement lock identity cannot admit a second composite writer"
        );
        let scope_digest = first
            .checkpoint_scope
            .scope_digest()
            .expect("checkpoint scope digest");
        assert_eq!(
            provider
                .checkpoint_heads
                .lock()
                .expect("checkpoint head lock")
                .get(&scope_digest)
                .expect("sequence one is externally committed")
                .generation(),
            2,
            "sequence two must not become externally authoritative"
        );
        first.resume_after_external_commit.notify_one();
        assert_eq!(
            writer.await.expect("first writer task"),
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected),
            "the original holder detects its unlinked retained binding at release"
        );
        assert_eq!(
            first
                .local
                .load_local()
                .await
                .expect("first writer synchronized sequence one locally")
                .checkpoint_bytes(),
            Some(checkpoint.as_slice())
        );
        assert_eq!(
            std::fs::read_dir(&checkpoint_store_path)
                .expect("read exact two-slot directory after substitution")
                .count(),
            2,
            "operation locking never mutates the exact two-slot inventory"
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn direct_predecessor_repairs_but_deeper_rollback_is_rejected() {
        let direct_root = TempDir::new().expect("direct predecessor root");
        let direct_path = canonical_root(&direct_root);
        let (direct, _, _) = initialized_sealed_store(&direct_path, binding(0x28)).await;
        let (_, first) = advance_external_checkpoint(&direct, 1, 0).await;
        assert_eq!(
            direct
                .load()
                .await
                .expect("empty local H0 repairs to external sequence one")
                .checkpoint_bytes(),
            Some(first.as_slice())
        );
        let deep_root = TempDir::new().expect("deep rollback root");
        let deep_path = canonical_root(&deep_root);
        let (deep, _, _) = initialized_sealed_store(&deep_path, binding(0x29)).await;
        advance_external_checkpoint(&deep, 1, 0).await;
        advance_external_checkpoint(&deep, 2, 1).await;
        assert_eq!(
            deep.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn local_fork_and_missing_or_substituted_external_blob_are_rejected() {
        let fork_root = TempDir::new().expect("fork root");
        let fork_path = canonical_root(&fork_root);
        let (forked, _, _) = initialized_sealed_store(&fork_path, binding(0x2A)).await;
        let local_fork = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 1);
        forked
            .local
            .compare_and_swap_local(None, local_fork)
            .await
            .expect("install local-only fork fixture");
        advance_external_checkpoint(&forked, 1, 2).await;
        assert_eq!(
            forked.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
        let blob_root = TempDir::new().expect("blob root");
        let blob_path = canonical_root(&blob_root);
        let (sealed, _, provider) = initialized_sealed_store(&blob_path, binding(0x2B)).await;
        let (_, checkpoint) = advance_external_checkpoint(&sealed, 1, 0).await;
        sealed
            .load()
            .await
            .expect("repair exact external checkpoint");
        let scope_digest = sealed
            .checkpoint_scope
            .scope_digest()
            .expect("checkpoint scope digest");
        let revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        provider.remove_checkpoint_blob(scope_digest, revision);
        assert_eq!(
            sealed.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
        provider.substitute_checkpoint_blob(scope_digest, revision, vec![0xFF]);
        assert_eq!(
            sealed.load().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn externally_initialized_policy_scope_cannot_be_reinterpreted() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x2C);
        let (sealed, clock, _) = initialized_sealed_store(&root_path, binding.clone()).await;
        drop(sealed);
        let mut foreign_policy = MusubiProviderAttestationJournalPolicyV1::default();
        foreign_policy.max_attempts += 1;
        let foreign = MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            &root_path,
            binding,
            foreign_policy,
        )
        .expect("local empty bytes remain structurally valid");
        assert_eq!(
            foreign
                .open_journal_runtime(clock)
                .await
                .expect_err("policy digest selects a different absent external scope"),
            MusubiProviderAttestationJournalErrorV1::StoreRejected
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn pristine_store_is_empty_and_checkpoint_survives_reopen() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x31);
        let journal_store = store(&root_path, binding.clone());
        assert_eq!(
            journal_store
                .load_local()
                .await
                .expect("load pristine store"),
            MusubiProviderAttestationJournalStoreSnapshotV1::empty()
        );
        let checkpoint = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let expected_revision =
            musubi_provider_attestation_journal_checkpoint_revision_v1(&checkpoint);
        assert_eq!(
            journal_store
                .compare_and_swap_local(None, checkpoint.clone())
                .await
                .expect("store first checkpoint"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: expected_revision
            }
        );
        drop(journal_store);
        let reopened = store(&root_path, binding);
        let loaded = reopened.load_local().await.expect("load reopened store");
        assert_eq!(loaded.revision(), Some(expected_revision));
        assert_eq!(loaded.checkpoint_bytes(), Some(checkpoint.as_slice()));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn stale_conflict_and_exact_replay_preserve_the_winner() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let store = store(&root_path, binding(0x41));
        let first = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let first_revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&first);
        store
            .compare_and_swap_local(None, first.clone())
            .await
            .expect("store first checkpoint");
        assert_eq!(
            store
                .compare_and_swap_local(None, first.clone())
                .await
                .expect("replay ambiguous first commit"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: first_revision
            }
        );
        let second = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(2, 1);
        assert_eq!(
            store
                .compare_and_swap_local(None, second.clone())
                .await
                .expect("reject stale predecessor"),
            MusubiProviderAttestationJournalCasOutcomeV1::Conflict
        );
        assert_eq!(
            store
                .load_local()
                .await
                .expect("load winner")
                .checkpoint_bytes(),
            Some(first.as_slice())
        );
        let second_revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&second);
        assert_eq!(
            store
                .compare_and_swap_local(Some(first_revision), second.clone())
                .await
                .expect("store direct successor"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: second_revision
            }
        );
        assert_eq!(
            store
                .compare_and_swap_local(Some(first_revision), second.clone())
                .await
                .expect("replay direct successor"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: second_revision
            }
        );
        assert_eq!(
            store
                .compare_and_swap_local(Some([0xA5; 32]), second)
                .await
                .expect("exact current bytes are an idempotent no-op"),
            MusubiProviderAttestationJournalCasOutcomeV1::Stored {
                revision: second_revision
            }
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn invalid_replacement_and_sequence_jump_are_rejected() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let store = store(&root_path, binding(0x51));
        assert_eq!(
            store.compare_and_swap_local(None, Vec::new()).await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
        let first = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0);
        let first_revision = musubi_provider_attestation_journal_checkpoint_revision_v1(&first);
        store
            .compare_and_swap_local(None, first)
            .await
            .expect("store first checkpoint");
        let jumped = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(3, 1);
        assert_eq!(
            store
                .compare_and_swap_local(Some(first_revision), jumped)
                .await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn physical_generation_checkpoint_sequence_mismatch_is_rejected() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x52);
        let store = store(&root_path, binding.clone());
        let physical = store.store.try_load().expect("load physical predecessor");
        let non_successor = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(2, 0);
        assert!(matches!(
            store
                .store
                .try_compare_and_swap(&physical, &non_successor)
                .expect("install deliberately mismatched physical fixture"),
            TwoSlotCasOutcomeV1::Stored(_)
        ));
        assert_eq!(
            store.load_local().await,
            Err(MusubiProviderAttestationJournalStoreErrorV1::Rejected)
        );
        drop(store);
        let error = MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            &root_path,
            binding,
            MusubiProviderAttestationJournalPolicyV1::default(),
        )
        .expect_err("reopen must reject mismatched physical lineage");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::Other
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn independent_adapters_never_install_two_racing_successors() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let binding = binding(0x61);
        let left = Arc::new(store(&root_path, binding.clone()));
        let right = Arc::new(store(&root_path, binding));
        let left_bytes = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 1);
        let right_bytes = musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 2);
        let left_task = tokio::spawn({
            let store = Arc::clone(&left);
            let bytes = left_bytes.clone();
            async move { store.compare_and_swap_local(None, bytes).await }
        });
        let right_task = tokio::spawn({
            let store = Arc::clone(&right);
            let bytes = right_bytes.clone();
            async move { store.compare_and_swap_local(None, bytes).await }
        });
        let left_outcome = left_task.await.expect("left task");
        let right_outcome = right_task.await.expect("right task");
        let stored_count = [&left_outcome, &right_outcome]
            .into_iter()
            .filter(|outcome| {
                matches!(
                    outcome,
                    Ok(MusubiProviderAttestationJournalCasOutcomeV1::Stored { .. })
                )
            })
            .count();
        assert_eq!(stored_count, 1);
        let loaded = left.load_local().await.expect("load race winner");
        let winner = loaded.checkpoint_bytes().expect("winner checkpoint");
        assert!(winner == left_bytes || winner == right_bytes);
        let loser = if winner == left_bytes {
            right_bytes
        } else {
            left_bytes
        };
        assert_eq!(
            right.compare_and_swap_local(None, loser).await,
            Ok(MusubiProviderAttestationJournalCasOutcomeV1::Conflict)
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn trait_futures_are_send() {
        fn assert_send<Value: Send>(_: &Value) {}
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let store = store(&root_path, binding(0x71));
        let load = store.load_local();
        assert_send(&load);
        load.await.expect("load through Send future");
        let compare = store.compare_and_swap_local(
            None,
            musubi_provider_attestation_journal_test_checkpoint_bytes_v1(1, 0),
        );
        assert_send(&compare);
        compare.await.expect("CAS through Send future");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn reopening_with_another_deployment_binding_is_rejected() {
        let root = TempDir::new().expect("state root");
        let root_path = canonical_root(&root);
        let expected_binding = binding(0x72);
        let first = store(&root_path, expected_binding.clone());
        drop(first);
        let error = MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            &root_path,
            binding(0x73),
            MusubiProviderAttestationJournalPolicyV1::default(),
        )
        .expect_err("another chain/provider binding must not open the same namespace");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::Other
        ));
        store(&root_path, expected_binding)
            .load_local()
            .await
            .expect("binding substitution must not damage the original store");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unsafe_symlink_root_is_rejected_and_debug_redacts_path() {
        use std::os::unix::fs::symlink;
        let parent = TempDir::new().expect("parent root");
        let parent_path = canonical_root(&parent);
        let target = parent_path.join("target");
        std::fs::create_dir(&target).expect("create target");
        let target = target.canonicalize().expect("canonical target root");
        let alias = parent_path.join("alias");
        symlink(&target, &alias).expect("create symlink root");
        let error = MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            &alias,
            binding(0x81),
            MusubiProviderAttestationJournalPolicyV1::default(),
        )
        .expect_err("symlink root must fail closed");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::Other
        ));
        let store = store(&target, binding(0x82));
        let debug = format!("{store:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(target.to_string_lossy().as_ref()));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn unsupported_platform_fails_closed() {
        let root = TempDir::new().expect("state root");
        let error = MusubiProviderAttestationJournalFileStoreV1::open_or_create_under(
            root.path(),
            binding(0x91),
            MusubiProviderAttestationJournalPolicyV1::default(),
        )
        .expect_err("platform must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
