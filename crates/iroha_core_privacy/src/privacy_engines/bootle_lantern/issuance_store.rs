//! Durable, bounded, one-shot authorization state for native blind issuance.
//!
//! The file-backed implementation is the first-release production store. It persists one strict,
//! versioned record per authorization with atomic replace-and-sync transitions. A held Unix
//! advisory lock enforces exactly one live issuer process per directory without stale lock-file
//! recovery. Reopen, crash recovery, and pruning stay within the configured count and byte budget
//! without materializing secondary full-store batches. The directory and its ancestors are an
//! authenticated local trust boundary and must not be writable by an attacker while the issuer is
//! running.
use super::codec::BLIND_ISSUANCE_RESPONSE_BYTES_V1;
#[cfg(any(unix, test))]
use std::io::Read;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    ops::Bound::{Excluded, Unbounded},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use thiserror::Error;
#[cfg(test)]
use {
    std::sync::atomic::AtomicBool, std::sync::atomic::AtomicU8, std::sync::atomic::AtomicUsize,
    std::sync::atomic::Ordering,
};
const STORE_RECORD_MAGIC_V1: [u8; 4] = *b"ILS1";
const STORE_RECORD_VERSION_V1: u8 = 1;
const STORE_RECORD_EXTENSION_V1: &str = ".bls1";
#[cfg(any(unix, test))]
const STORE_TEMP_DIRECTORY_V1: &str = ".tmp";
const STORE_TEMP_EXTENSION_V1: &str = ".tmp";
#[cfg(any(unix, test))]
const STORE_WRITER_LOCK_FILE_V1: &str = ".writer.lock";
const STORE_RECORD_HEADER_BYTES_V1: usize = 4 + 1 + 1 + 32 + 32 + 8 + 8;
const STORE_FRESH_TAG_V1: u8 = 0;
const STORE_PROCESSING_TAG_V1: u8 = 1;
const STORE_COMPLETED_TAG_V1: u8 = 2;
const STORE_FAILED_TAG_V1: u8 = 3;
const STORE_PROCESSING_BYTES_V1: usize = STORE_RECORD_HEADER_BYTES_V1 + 32 + 8;
const STORE_COMPLETED_BYTES_V1: usize =
    STORE_RECORD_HEADER_BYTES_V1 + 32 + 8 + 8 + BLIND_ISSUANCE_RESPONSE_BYTES_V1;
const STORE_FAILED_BYTES_V1: usize = STORE_RECORD_HEADER_BYTES_V1 + 32 + 8 + 8;
/// Canonical first-release durable issuance-store profile committed by privacy metadata.
pub(crate) const BOOTLE_LANTERN_ISSUANCE_STORE_PROFILE_DESCRIPTOR_V1: &[u8] = b"ILS1:record-header=magic-ILS1,version-u8=1,state-u8,authorization-id[32],authorization-digest[32],issued-at-u64be,expires-at-u64be|state-0-Fresh=header-only|state-1-Processing=request-digest[32],claimed-at-u64be|state-2-Completed=request-digest[32],claimed-at-u64be,completed-at-u64be,canonical-request-bound-ILR1[3176]|state-3-Failed=request-digest[32],claimed-at-u64be,failed-at-u64be|canonical=exact-state-length,no-trailing-bytes,nonzero-digests,lifetime=1..4096,claimed-in-lifetime,terminal-height>=claimed|namespace=lowercase-hex-authorization-id.bls1,.tmp,.writer.lock-only|ownership=canonical-process-lease+unix-nonblocking-exclusive-flock-held-for-lifetime,nofollow-single-link-empty-lock,non-unix-unsupported|durability=temp-create-new-0600,write-all,file-sync,atomic-rename,record-dir-sync,temp-dir-sync,post-rename-sync-error-poisons-live-handle|open=reject-unknown,non-utf8,symlink,non-regular,hardlink,identity-race,truncated,trailing,oversized,noncanonical,filename-id-mismatch,duplicate,capacity-overflow;clean-only-strict-bounded-known-temp|capacity=max-records<=1000000,max-total<=3310000000,worst-case-3310-byte-reservation-per-authorization,fail-before-mutation,explicit-prune-only|replay=nonmutating-preflight-before-P1+atomic-claim-recheck,Completed-same-request-exact-cache-regardless-expiry,substitution-consumed,Processing-busy-and-crash-persistent,no-terminal-to-Fresh-transition|recovery=explicit-authoritative-committed-height,validate-max-issued+claim-or-terminal-height-for-all-records-before-mutation,file-open-snapshot-Processing-only-to-Failed-at-height,Fresh+Completed+Failed+post-open-Processing-unchanged,durable-per-record,resumable-idempotent,write-error-poisons-live-handle|retention=blocks-1..4294967295,checked-authoritative-height,Fresh-from-expiry,Completed-from-max(expiry,completion),Failed-from-max(expiry,failure),Processing-never-pruned";
/// Largest canonical first-release issuance-store record, in bytes.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1: u64 = STORE_COMPLETED_BYTES_V1 as u64;
/// Hard upper bound on records accepted by one issuance store.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RECORDS_V1: usize = 1_000_000;
/// Hard upper bound on canonical record bytes reserved by one issuance store.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_TOTAL_BYTES_V1: u64 =
    BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1
        * BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RECORDS_V1 as u64;
/// Hard upper bound on configured terminal-retention blocks.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RETENTION_BLOCKS_V1: u64 = u32::MAX as u64;
/// Default maximum authorization count.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_RECORDS_V1: usize = 4_096;
/// Default retention after the later of authorization expiry and terminal transition.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_RETENTION_BLOCKS_V1: u64 = 4_096;
/// Default maximum reserved canonical record bytes.
pub const BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_TOTAL_BYTES_V1: u64 =
    BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1
        * BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_RECORDS_V1 as u64;
/// Validated capacity and retention policy for one issuance store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootleLanternIssuanceStoreConfigV1 {
    max_records: usize,
    max_total_bytes: u64,
    terminal_retention_blocks: u64,
}
impl BootleLanternIssuanceStoreConfigV1 {
    /// Construct a bounded first-release store configuration.
    ///
    /// `max_total_bytes` must reserve the largest canonical `ILR1`-bearing
    /// record for every accepted authorization. This makes completion unable
    /// to fail merely because a fresh record grows into a completed record.
    ///
    /// # Errors
    ///
    /// Rejects zero limits, limits above the hard caps, zero retention, and a
    /// byte limit that cannot reserve the worst-case footprint of every slot.
    pub fn new(
        max_records: usize,
        max_total_bytes: u64,
        terminal_retention_blocks: u64,
    ) -> Result<Self, BootleLanternIssuanceStoreErrorV1> {
        if max_records == 0
            || max_records > BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RECORDS_V1
            || max_total_bytes == 0
            || max_total_bytes > BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_TOTAL_BYTES_V1
            || terminal_retention_blocks == 0
            || terminal_retention_blocks
                > BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RETENTION_BLOCKS_V1
        {
            return Err(BootleLanternIssuanceStoreErrorV1::ConfigurationInvalid);
        }
        let required = u64::try_from(max_records)
            .ok()
            .and_then(|count| count.checked_mul(BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1))
            .ok_or(BootleLanternIssuanceStoreErrorV1::ConfigurationInvalid)?;
        if max_total_bytes < required {
            return Err(BootleLanternIssuanceStoreErrorV1::ConfigurationInvalid);
        }
        Ok(Self {
            max_records,
            max_total_bytes,
            terminal_retention_blocks,
        })
    }
    /// Maximum number of retained authorization records.
    #[must_use]
    pub const fn max_records(self) -> usize {
        self.max_records
    }
    /// Maximum reserved canonical record bytes.
    #[must_use]
    pub const fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }
    /// Blocks retained after the applicable terminal horizon.
    #[must_use]
    pub const fn terminal_retention_blocks(self) -> u64 {
        self.terminal_retention_blocks
    }
}
impl Default for BootleLanternIssuanceStoreConfigV1 {
    fn default() -> Self {
        Self {
            max_records: BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_RECORDS_V1,
            max_total_bytes: BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_MAX_TOTAL_BYTES_V1,
            terminal_retention_blocks: BOOTLE_LANTERN_ISSUANCE_STORE_DEFAULT_RETENTION_BLOCKS_V1,
        }
    }
}
/// Result of non-mutating replay and lifetime classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuancePreflightV1 {
    /// The authorization is live and has not been claimed.
    Fresh,
    /// The same request already completed; these are the exact canonical
    /// cached `ILR1` response bytes.
    Completed(Vec<u8>),
}
/// Result of atomically claiming one issuance authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootleLanternIssuanceClaimV1 {
    /// This caller atomically changed the authorization from fresh to
    /// processing and is the sole permitted producer.
    Fresh,
    /// The same request already completed; these are the exact canonical
    /// cached `ILR1` response bytes.
    Completed(Vec<u8>),
}
/// Thread-safe persistence boundary for one-shot blind issuance.
///
/// Every transition is atomic with respect to the authorization identifier. Implementations must
/// never change `Processing`, `Completed`, or `Failed` back to `Fresh`. Completed same-request
/// retries remain readable after authorization expiry until explicit height-based pruning reaches
/// their configured retention horizon.
pub trait BootleLanternIssuanceStoreV1: Send + Sync {
    /// Register a newly generated authorization as fresh.
    fn register_fresh_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1>;
    /// Classify an exact request without changing state.
    ///
    /// This is the cheap replay gate used before expensive P1 verification.
    /// A subsequent [`Self::claim_v1`] independently rechecks the same state
    /// and height under its transition lock.
    fn preflight_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        current_height: u64,
    ) -> Result<BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreErrorV1>;
    /// Atomically claim a fresh authorization for one exact request.
    ///
    /// A completed retry for the same request returns the cached response even after expiry. An
    /// in-flight retry returns [`BootleLanternIssuanceStoreErrorV1::Busy`]. Every request
    /// substitution and terminal failure returns
    /// [`BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed`].
    fn claim_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        current_height: u64,
    ) -> Result<BootleLanternIssuanceClaimV1, BootleLanternIssuanceStoreErrorV1>;
    /// Atomically persist exact canonical response bytes and mark completed.
    fn complete_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        response_bytes: &[u8],
        completed_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1>;
    /// Irreversibly mark a claimed authorization failed.
    fn fail_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        failed_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1>;
    /// Irreversibly fail every issuance left in `Processing` by a recovered
    /// store at an authoritative committed height.
    ///
    /// Implementations must validate the supplied height against every record's issue height and
    /// every observed claim or terminal transition before changing any record. `Fresh`,
    /// `Completed`, and `Failed` records are never changed. Repeating recovery at the same height
    /// is idempotent and returns zero.
    ///
    /// The default fails closed for test or adapter stores that do not persist
    /// recoverable processing state.
    fn recover_processing_v1(
        &self,
        _authoritative_height: u64,
    ) -> Result<usize, BootleLanternIssuanceStoreErrorV1> {
        Err(BootleLanternIssuanceStoreErrorV1::Backend)
    }
    /// Remove only expired-fresh and terminal records whose retention horizon
    /// has been reached at the supplied authoritative height.
    ///
    /// Processing records are never silently evicted. Callers must explicitly resolve a recovered
    /// in-flight record to `Failed` before it can become eligible for terminal pruning.
    fn prune_v1(
        &self,
        authoritative_height: u64,
    ) -> Result<usize, BootleLanternIssuanceStoreErrorV1>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredAuthorizationV1 {
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
    state: StoredIssuanceStateV1,
    // This is process-local state, never part of the canonical record. Keeping
    // it beside the record avoids a second full-store index during reopen.
    processing_at_file_open: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum StoredIssuanceStateV1 {
    Fresh,
    Processing {
        request_digest: [u8; 32],
        claimed_at_height: u64,
    },
    Completed {
        request_digest: [u8; 32],
        claimed_at_height: u64,
        completed_at_height: u64,
        response_bytes: Vec<u8>,
    },
    Failed {
        request_digest: [u8; 32],
        claimed_at_height: u64,
        failed_at_height: u64,
    },
}
impl StoredAuthorizationV1 {
    fn encoded_len_v1(&self) -> usize {
        match &self.state {
            StoredIssuanceStateV1::Fresh => STORE_RECORD_HEADER_BYTES_V1,
            StoredIssuanceStateV1::Processing { .. } => STORE_PROCESSING_BYTES_V1,
            StoredIssuanceStateV1::Completed { .. } => STORE_COMPLETED_BYTES_V1,
            StoredIssuanceStateV1::Failed { .. } => STORE_FAILED_BYTES_V1,
        }
    }
    fn retention_horizon_reached_v1(&self, current_height: u64, retention: u64) -> bool {
        let basis = match &self.state {
            StoredIssuanceStateV1::Fresh => self.expires_at_height,
            StoredIssuanceStateV1::Processing { .. } => return false,
            StoredIssuanceStateV1::Completed {
                completed_at_height,
                ..
            } => self.expires_at_height.max(*completed_at_height),
            StoredIssuanceStateV1::Failed {
                failed_at_height, ..
            } => self.expires_at_height.max(*failed_at_height),
        };
        current_height
            .checked_sub(basis)
            .is_some_and(|elapsed| elapsed >= retention)
    }
}
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug)]
struct InMemoryStateV1 {
    records: BTreeMap<[u8; 32], StoredAuthorizationV1>,
    canonical_bytes: u64,
}
#[cfg(any(test, feature = "test-utils"))]
/// Mutex-backed bounded store for deterministic tests and ephemeral tooling.
///
/// Because this store has no reopen boundary, explicit recovery treats every
/// current `Processing` record as recovered.
///
/// Production issuers should use [`BootleLanternFileIssuanceStoreV1`].
#[derive(Debug)]
pub struct BootleLanternInMemoryIssuanceStoreV1 {
    config: BootleLanternIssuanceStoreConfigV1,
    state: Mutex<InMemoryStateV1>,
    #[cfg(test)]
    fail_next_completion: AtomicBool,
}
#[cfg(any(test, feature = "test-utils"))]
impl BootleLanternInMemoryIssuanceStoreV1 {
    /// Construct an empty store with default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(BootleLanternIssuanceStoreConfigV1::default())
    }
    /// Construct an empty store with validated explicit bounds.
    #[must_use]
    pub fn with_config(config: BootleLanternIssuanceStoreConfigV1) -> Self {
        Self {
            config,
            state: Mutex::new(InMemoryStateV1 {
                records: BTreeMap::new(),
                canonical_bytes: 0,
            }),
            #[cfg(test)]
            fail_next_completion: AtomicBool::new(false),
        }
    }
    #[cfg(test)]
    pub(crate) fn inject_next_completion_failure_v1(&self) {
        self.fail_next_completion.store(true, Ordering::SeqCst);
    }
}
#[cfg(any(test, feature = "test-utils"))]
impl Default for BootleLanternInMemoryIssuanceStoreV1 {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(any(test, feature = "test-utils"))]
impl BootleLanternIssuanceStoreV1 for BootleLanternInMemoryIssuanceStoreV1 {
    fn register_fresh_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        validate_registration_v1(
            authorization_id,
            authorization_digest,
            issued_at_height,
            expires_at_height,
        )?;
        let record = StoredAuthorizationV1 {
            authorization_id,
            authorization_digest,
            issued_at_height,
            expires_at_height,
            state: StoredIssuanceStateV1::Fresh,
            processing_at_file_open: false,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        if state.records.contains_key(&authorization_id) {
            return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists);
        }
        ensure_new_record_capacity_v1(&*state, self.config, record.encoded_len_v1())?;
        state.canonical_bytes = state
            .canonical_bytes
            .checked_add(record.encoded_len_v1() as u64)
            .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
        state.records.insert(authorization_id, record);
        Ok(())
    }
    fn preflight_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        current_height: u64,
    ) -> Result<BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreErrorV1> {
        validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
        let state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        classify_preflight_v1(record, request_digest, current_height)
    }
    fn claim_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        current_height: u64,
    ) -> Result<BootleLanternIssuanceClaimV1, BootleLanternIssuanceStoreErrorV1> {
        validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        match classify_preflight_v1(record, request_digest, current_height)? {
            BootleLanternIssuancePreflightV1::Completed(bytes) => {
                Ok(BootleLanternIssuanceClaimV1::Completed(bytes))
            }
            BootleLanternIssuancePreflightV1::Fresh => {
                let mut candidate = record.clone();
                candidate.state = StoredIssuanceStateV1::Processing {
                    request_digest,
                    claimed_at_height: current_height,
                };
                commit_in_memory_candidate_v1(&mut state, candidate, self.config)?;
                Ok(BootleLanternIssuanceClaimV1::Fresh)
            }
        }
    }
    fn complete_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        response_bytes: &[u8],
        completed_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        validate_completion_shape_v1(
            authorization_id,
            authorization_digest,
            request_digest,
            response_bytes,
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        let claimed_at_height = match &record.state {
            StoredIssuanceStateV1::Processing {
                request_digest: active,
                claimed_at_height,
            } if *active == request_digest => *claimed_at_height,
            _ => return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed),
        };
        validate_completion_request_binding_v1(request_digest, response_bytes)?;
        if completed_at_height < claimed_at_height {
            return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
        }
        #[cfg(test)]
        if self.fail_next_completion.swap(false, Ordering::SeqCst) {
            return Err(BootleLanternIssuanceStoreErrorV1::Backend);
        }
        let mut candidate = record.clone();
        candidate.state = StoredIssuanceStateV1::Completed {
            request_digest,
            claimed_at_height,
            completed_at_height,
            response_bytes: response_bytes.to_vec(),
        };
        commit_in_memory_candidate_v1(&mut state, candidate, self.config)
    }
    fn fail_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        failed_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        let claimed_at_height = match &record.state {
            StoredIssuanceStateV1::Processing {
                request_digest: active,
                claimed_at_height,
            } if *active == request_digest => *claimed_at_height,
            StoredIssuanceStateV1::Failed {
                request_digest: failed,
                ..
            } if *failed == request_digest => return Ok(()),
            _ => return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed),
        };
        if failed_at_height < claimed_at_height {
            return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
        }
        let mut candidate = record.clone();
        candidate.state = StoredIssuanceStateV1::Failed {
            request_digest,
            claimed_at_height,
            failed_at_height,
        };
        commit_in_memory_candidate_v1(&mut state, candidate, self.config)
    }
    fn recover_processing_v1(
        &self,
        authoritative_height: u64,
    ) -> Result<usize, BootleLanternIssuanceStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let (recovered, recovered_bytes) = validate_processing_recovery_v1(
            &state.records,
            ProcessingRecoveryScopeV1::All,
            state.canonical_bytes,
            self.config.max_total_bytes,
            authoritative_height,
        )?;
        let mut cursor = None;
        while let Some(candidate) = next_processing_recovery_candidate_v1(
            &state.records,
            ProcessingRecoveryScopeV1::All,
            cursor,
            authoritative_height,
        ) {
            cursor = Some(candidate.authorization_id);
            state.records.insert(candidate.authorization_id, candidate);
        }
        state.canonical_bytes = recovered_bytes;
        Ok(recovered)
    }
    fn prune_v1(
        &self,
        authoritative_height: u64,
    ) -> Result<usize, BootleLanternIssuanceStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let mut removed = 0_usize;
        let mut cursor = None;
        while let Some((id, encoded_len)) = next_prunable_record_v1(
            &state.records,
            cursor,
            authoritative_height,
            self.config.terminal_retention_blocks,
        ) {
            cursor = Some(id);
            let record = state
                .records
                .remove(&id)
                .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
            if record.encoded_len_v1() != encoded_len {
                return Err(BootleLanternIssuanceStoreErrorV1::Backend);
            }
            state.canonical_bytes = state
                .canonical_bytes
                .checked_sub(encoded_len as u64)
                .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
            removed = removed
                .checked_add(1)
                .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
        }
        Ok(removed)
    }
}
#[derive(Debug)]
struct FileStoreStateV1 {
    records: BTreeMap<[u8; 32], StoredAuthorizationV1>,
    canonical_bytes: u64,
    poisoned: bool,
}
#[derive(Debug)]
struct FileStoreDirectoryLeaseV1 {
    canonical_root: PathBuf,
}
impl Drop for FileStoreDirectoryLeaseV1 {
    fn drop(&mut self) {
        if let Ok(mut open_roots) = open_file_store_roots_v1().lock() {
            open_roots.remove(&self.canonical_root);
        }
    }
}
/// Atomic, file-backed first-release issuance store.
///
/// Each authorization is one `ILS1` file named by its lowercase hexadecimal identifier. Open
/// rejects every unknown, non-regular, symlinked, oversized, truncated, non-canonical, or duplicate
/// entry. State transitions write and sync a temporary file, atomically rename it, then sync both
/// affected directories before reporting durable success. Open admits the configured count and
/// aggregate byte footprint before allocating each record buffer; recovery and pruning stream one
/// record at a time in identifier order.
///
/// `Processing` records loaded by [`Self::open`] form the explicit recovery set. Claims started
/// after open remain live and are not failed by a delayed recovery call; they enter the recovery
/// set only if a later open observes them still in progress.
///
/// A process-local directory lease and a held Unix advisory lock reject every second live opener,
/// including another process, without a stale-lock-file protocol. Non-Unix construction fails
/// explicitly. Never place this store in an attacker-writable directory hierarchy.
#[derive(Debug)]
pub struct BootleLanternFileIssuanceStoreV1 {
    root: PathBuf,
    temp_root: PathBuf,
    config: BootleLanternIssuanceStoreConfigV1,
    state: Mutex<FileStoreStateV1>,
    _lease: FileStoreDirectoryLeaseV1,
    _writer_lock: File,
    #[cfg(test)]
    fail_next_write_stage: AtomicU8,
    #[cfg(test)]
    fail_write_countdown: AtomicUsize,
}
impl BootleLanternFileIssuanceStoreV1 {
    /// Open or create an exclusively owned store directory.
    ///
    /// The immediate parent must already exist. A newly created store
    /// directory is synced through its parent before opening records.
    ///
    /// # Errors
    ///
    /// Rejects invalid configuration, every concurrent opener, untrusted entry types, unknown
    /// names, stale malformed temporary files, corrupt/non-canonical records, configured-capacity
    /// violations, and all filesystem failures.
    pub fn open(
        root: impl AsRef<Path>,
        config: BootleLanternIssuanceStoreConfigV1,
    ) -> Result<Self, BootleLanternIssuanceStoreErrorV1> {
        #[cfg(not(unix))]
        {
            let _ = (root, config);
            return Err(BootleLanternIssuanceStoreErrorV1::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let requested_root = root.as_ref();
            if requested_root.as_os_str().is_empty() {
                return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
            }
            ensure_store_root_v1(requested_root)?;
            let canonical_root = fs::canonicalize(requested_root)
                .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            let lease = acquire_file_store_lease_v1(canonical_root.clone())?;
            let writer_lock = acquire_file_store_writer_lock_v1(&canonical_root)?;
            let temp_root = canonical_root.join(STORE_TEMP_DIRECTORY_V1);
            ensure_temp_root_v1(&canonical_root, &temp_root)?;
            clean_stale_temp_files_v1(&temp_root)?;
            let state = load_file_store_v1(&canonical_root, config)?;
            Ok(Self {
                root: canonical_root,
                temp_root,
                config,
                state: Mutex::new(state),
                _lease: lease,
                _writer_lock: writer_lock,
                #[cfg(test)]
                fail_next_write_stage: AtomicU8::new(0),
                #[cfg(test)]
                fail_write_countdown: AtomicUsize::new(0),
            })
        }
    }
    /// Canonical path of the exclusively owned store directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    #[cfg(test)]
    fn inject_next_write_before_rename_failure_v1(&self) {
        self.inject_write_failure_after_successes_v1(0, 1);
    }
    #[cfg(test)]
    fn inject_next_write_after_rename_failure_v1(&self) {
        self.inject_write_failure_after_successes_v1(0, 2);
    }
    #[cfg(test)]
    fn inject_write_failure_after_successes_v1(&self, successful_writes: usize, stage: u8) {
        debug_assert!(matches!(stage, 1 | 2));
        let countdown = successful_writes
            .checked_add(1)
            .expect("test failure countdown must fit usize");
        self.fail_next_write_stage.store(stage, Ordering::SeqCst);
        self.fail_write_countdown.store(countdown, Ordering::SeqCst);
    }
    #[cfg(test)]
    fn take_injected_write_failure_v1(&self) -> u8 {
        let remaining = self.fail_write_countdown.load(Ordering::SeqCst);
        if remaining == 0 {
            return 0;
        }
        let previous = self.fail_write_countdown.fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            self.fail_next_write_stage.swap(0, Ordering::SeqCst)
        } else {
            0
        }
    }
    fn persist_candidate_v1(
        &self,
        record: &StoredAuthorizationV1,
    ) -> Result<(), DurableMutationFailureV1> {
        let bytes = encode_record_v1(record).map_err(|_| DurableMutationFailureV1::before())?;
        let file_name = record_file_name_v1(record.authorization_id);
        let target = self.root.join(&file_name);
        let temp = self
            .temp_root
            .join(format!("{file_name}{STORE_TEMP_EXTENSION_V1}"));
        reject_untrusted_existing_target_v1(&target)
            .map_err(|_| DurableMutationFailureV1::before())?;
        reject_untrusted_existing_temp_v1(&temp).map_err(|_| DurableMutationFailureV1::before())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| DurableMutationFailureV1::before())?;
        if file.write_all(&bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(DurableMutationFailureV1::before());
        }
        drop(file);
        #[cfg(test)]
        let injected_failure = self.take_injected_write_failure_v1();
        #[cfg(test)]
        if injected_failure == 1 {
            let _ = fs::remove_file(&temp);
            return Err(DurableMutationFailureV1::before());
        }
        if fs::rename(&temp, &target).is_err() {
            let _ = fs::remove_file(&temp);
            return Err(DurableMutationFailureV1::before());
        }
        #[cfg(test)]
        if injected_failure == 2 {
            return Err(DurableMutationFailureV1::after());
        }
        if sync_directory_v1(&self.root).is_err() || sync_directory_v1(&self.temp_root).is_err() {
            return Err(DurableMutationFailureV1::after());
        }
        Ok(())
    }
    fn remove_record_file_v1(
        &self,
        authorization_id: [u8; 32],
    ) -> Result<(), DurableMutationFailureV1> {
        let target = self.root.join(record_file_name_v1(authorization_id));
        reject_untrusted_existing_target_v1(&target)
            .map_err(|_| DurableMutationFailureV1::before())?;
        fs::remove_file(target).map_err(|_| DurableMutationFailureV1::before())?;
        sync_directory_v1(&self.root).map_err(|_| DurableMutationFailureV1::after())
    }
    fn commit_candidate_locked_v1(
        &self,
        state: &mut FileStoreStateV1,
        mut candidate: StoredAuthorizationV1,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        let authorization_id = candidate.authorization_id;
        let remains_processing =
            matches!(&candidate.state, StoredIssuanceStateV1::Processing { .. });
        if !remains_processing {
            candidate.processing_at_file_open = false;
        }
        let old_len = state
            .records
            .get(&authorization_id)
            .map_or(0, StoredAuthorizationV1::encoded_len_v1);
        let new_len = candidate.encoded_len_v1();
        let new_total = replace_size_v1(
            state.canonical_bytes,
            old_len,
            new_len,
            self.config.max_total_bytes,
        )?;
        match self.persist_candidate_v1(&candidate) {
            Ok(()) => {
                state.records.insert(authorization_id, candidate);
                state.canonical_bytes = new_total;
                Ok(())
            }
            Err(failure) if failure.committed => {
                state.records.insert(authorization_id, candidate);
                state.canonical_bytes = new_total;
                state.poisoned = true;
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            }
            Err(_) => Err(BootleLanternIssuanceStoreErrorV1::Backend),
        }
    }
}
impl BootleLanternIssuanceStoreV1 for BootleLanternFileIssuanceStoreV1 {
    fn register_fresh_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        validate_registration_v1(
            authorization_id,
            authorization_digest,
            issued_at_height,
            expires_at_height,
        )?;
        let candidate = StoredAuthorizationV1 {
            authorization_id,
            authorization_digest,
            issued_at_height,
            expires_at_height,
            state: StoredIssuanceStateV1::Fresh,
            processing_at_file_open: false,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        if state.records.contains_key(&authorization_id) {
            return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists);
        }
        ensure_new_record_capacity_v1(&*state, self.config, candidate.encoded_len_v1())?;
        self.commit_candidate_locked_v1(&mut state, candidate)
    }
    fn preflight_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        current_height: u64,
    ) -> Result<BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreErrorV1> {
        validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
        let state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        classify_preflight_v1(record, request_digest, current_height)
    }
    fn claim_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        current_height: u64,
    ) -> Result<BootleLanternIssuanceClaimV1, BootleLanternIssuanceStoreErrorV1> {
        validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        match classify_preflight_v1(record, request_digest, current_height)? {
            BootleLanternIssuancePreflightV1::Completed(bytes) => {
                Ok(BootleLanternIssuanceClaimV1::Completed(bytes))
            }
            BootleLanternIssuancePreflightV1::Fresh => {
                let mut candidate = record.clone();
                candidate.state = StoredIssuanceStateV1::Processing {
                    request_digest,
                    claimed_at_height: current_height,
                };
                self.commit_candidate_locked_v1(&mut state, candidate)?;
                Ok(BootleLanternIssuanceClaimV1::Fresh)
            }
        }
    }
    fn complete_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        response_bytes: &[u8],
        completed_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        validate_completion_shape_v1(
            authorization_id,
            authorization_digest,
            request_digest,
            response_bytes,
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        let claimed_at_height = match &record.state {
            StoredIssuanceStateV1::Processing {
                request_digest: active,
                claimed_at_height,
            } if *active == request_digest => *claimed_at_height,
            _ => return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed),
        };
        validate_completion_request_binding_v1(request_digest, response_bytes)?;
        if completed_at_height < claimed_at_height {
            return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
        }
        let mut candidate = record.clone();
        candidate.state = StoredIssuanceStateV1::Completed {
            request_digest,
            claimed_at_height,
            completed_at_height,
            response_bytes: response_bytes.to_vec(),
        };
        self.commit_candidate_locked_v1(&mut state, candidate)
    }
    fn fail_v1(
        &self,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        failed_at_height: u64,
    ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
        validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        let record = checked_record_v1(&state.records, authorization_id, authorization_digest)?;
        let claimed_at_height = match &record.state {
            StoredIssuanceStateV1::Processing {
                request_digest: active,
                claimed_at_height,
            } if *active == request_digest => *claimed_at_height,
            StoredIssuanceStateV1::Failed {
                request_digest: failed,
                ..
            } if *failed == request_digest => return Ok(()),
            _ => return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed),
        };
        if failed_at_height < claimed_at_height {
            return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
        }
        let mut candidate = record.clone();
        candidate.state = StoredIssuanceStateV1::Failed {
            request_digest,
            claimed_at_height,
            failed_at_height,
        };
        self.commit_candidate_locked_v1(&mut state, candidate)
    }
    fn recover_processing_v1(
        &self,
        authoritative_height: u64,
    ) -> Result<usize, BootleLanternIssuanceStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        let (recovered, _) = validate_processing_recovery_v1(
            &state.records,
            ProcessingRecoveryScopeV1::FileOpenSnapshot,
            state.canonical_bytes,
            self.config.max_total_bytes,
            authoritative_height,
        )?;
        let mut cursor = None;
        while let Some(candidate) = next_processing_recovery_candidate_v1(
            &state.records,
            ProcessingRecoveryScopeV1::FileOpenSnapshot,
            cursor,
            authoritative_height,
        ) {
            cursor = Some(candidate.authorization_id);
            if let Err(error) = self.commit_candidate_locked_v1(&mut state, candidate) {
                // A batch can have earlier durable records even when this
                // particular replacement failed before rename. Force reopen
                // and idempotent retry rather than exposing an ambiguous live
                // view to the issuer.
                state.poisoned = true;
                return Err(error);
            }
        }
        Ok(recovered)
    }
    fn prune_v1(
        &self,
        authoritative_height: u64,
    ) -> Result<usize, BootleLanternIssuanceStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        ensure_file_store_healthy_v1(&state)?;
        let mut removed = 0_usize;
        let mut cursor = None;
        while let Some((id, encoded_len)) = next_prunable_record_v1(
            &state.records,
            cursor,
            authoritative_height,
            self.config.terminal_retention_blocks,
        ) {
            cursor = Some(id);
            match self.remove_record_file_v1(id) {
                Ok(()) => {}
                Err(failure) if failure.committed => {
                    let record = state
                        .records
                        .remove(&id)
                        .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
                    if record.encoded_len_v1() != encoded_len {
                        state.poisoned = true;
                        return Err(BootleLanternIssuanceStoreErrorV1::Backend);
                    }
                    state.canonical_bytes = state
                        .canonical_bytes
                        .checked_sub(encoded_len as u64)
                        .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
                    state.poisoned = true;
                    return Err(BootleLanternIssuanceStoreErrorV1::Backend);
                }
                Err(_) => return Err(BootleLanternIssuanceStoreErrorV1::Backend),
            }
            let record = state
                .records
                .remove(&id)
                .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
            if record.encoded_len_v1() != encoded_len {
                state.poisoned = true;
                return Err(BootleLanternIssuanceStoreErrorV1::Backend);
            }
            state.canonical_bytes = state
                .canonical_bytes
                .checked_sub(encoded_len as u64)
                .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
            removed = removed
                .checked_add(1)
                .ok_or(BootleLanternIssuanceStoreErrorV1::Backend)?;
        }
        Ok(removed)
    }
}
#[derive(Clone, Copy, Debug)]
struct DurableMutationFailureV1 {
    committed: bool,
}
impl DurableMutationFailureV1 {
    const fn before() -> Self {
        Self { committed: false }
    }
    const fn after() -> Self {
        Self { committed: true }
    }
}
/// Atomic issuance-store failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BootleLanternIssuanceStoreErrorV1 {
    /// Zero, empty, reversed-height, or otherwise invalid values were supplied.
    #[error("Bootle/Lantern issuance store input is invalid")]
    InvalidInput,
    /// The configured bounds are zero, inconsistent, or exceed hard caps.
    #[error("Bootle/Lantern issuance store configuration is invalid")]
    ConfigurationInvalid,
    /// A generated authorization identifier collided with an existing record.
    #[error("Bootle/Lantern issuance authorization already exists")]
    AuthorizationExists,
    /// The authorization was absent, substituted, spent, pruned, or failed.
    #[error("Bootle/Lantern issuance authorization is consumed")]
    AuthorizationConsumed,
    /// The authorization has not reached its issue height.
    #[error("Bootle/Lantern issuance authorization is not yet valid")]
    AuthorizationNotYetValid,
    /// The fresh authorization is past its last valid height.
    #[error("Bootle/Lantern issuance authorization expired")]
    AuthorizationExpired,
    /// The same request is currently being issued by another worker.
    #[error("Bootle/Lantern issuance authorization is busy")]
    Busy,
    /// No worst-case record slot remains; explicit authoritative pruning is required.
    #[error("Bootle/Lantern issuance store capacity is exhausted")]
    CapacityExceeded,
    /// The directory is already open by another store object or process.
    #[error("Bootle/Lantern issuance store directory is already open")]
    StoreAlreadyOpen,
    /// Durable file-store locking is unavailable on this operating system.
    #[error("Bootle/Lantern durable issuance store requires Unix advisory locking")]
    UnsupportedPlatform,
    /// A store entry is malformed, non-canonical, unknown, oversized, or untrusted.
    #[error("Bootle/Lantern issuance store is corrupt")]
    Corrupt,
    /// Persistence, locking, or durable commit failed.
    #[error("Bootle/Lantern issuance store failed")]
    Backend,
}
fn validate_registration_v1(
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    if authorization_id == [0; 32] || authorization_digest == [0; 32] {
        return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
    }
    let lifetime = expires_at_height
        .checked_sub(issued_at_height)
        .ok_or(BootleLanternIssuanceStoreErrorV1::InvalidInput)?;
    if lifetime == 0
        || lifetime > super::issuer::MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1
    {
        return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
    }
    Ok(())
}
fn validate_request_inputs_v1(
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    if authorization_id == [0; 32] || authorization_digest == [0; 32] || request_digest == [0; 32] {
        return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
    }
    Ok(())
}
fn validate_completion_inputs_v1(
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    response_bytes: &[u8],
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    validate_completion_shape_v1(
        authorization_id,
        authorization_digest,
        request_digest,
        response_bytes,
    )?;
    validate_completion_request_binding_v1(request_digest, response_bytes)
}
fn validate_completion_shape_v1(
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
    request_digest: [u8; 32],
    response_bytes: &[u8],
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    validate_request_inputs_v1(authorization_id, authorization_digest, request_digest)?;
    if response_bytes.len() != BLIND_ISSUANCE_RESPONSE_BYTES_V1
        || super::issuer::BootleLanternBlindIssuanceResponseV1::decode_exact(response_bytes)
            .is_err()
    {
        return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
    }
    Ok(())
}
fn validate_completion_request_binding_v1(
    request_digest: [u8; 32],
    response_bytes: &[u8],
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    let request_offset = BLIND_ISSUANCE_RESPONSE_BYTES_V1
        .checked_sub(3 * 32)
        .ok_or(BootleLanternIssuanceStoreErrorV1::InvalidInput)?;
    if response_bytes.get(request_offset..request_offset + 32) != Some(request_digest.as_slice()) {
        return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
    }
    Ok(())
}
fn checked_record_v1(
    records: &BTreeMap<[u8; 32], StoredAuthorizationV1>,
    authorization_id: [u8; 32],
    authorization_digest: [u8; 32],
) -> Result<&StoredAuthorizationV1, BootleLanternIssuanceStoreErrorV1> {
    let record = records
        .get(&authorization_id)
        .ok_or(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)?;
    if record.authorization_digest != authorization_digest {
        return Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed);
    }
    Ok(record)
}
fn ensure_file_store_healthy_v1(
    state: &FileStoreStateV1,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    if state.poisoned {
        Err(BootleLanternIssuanceStoreErrorV1::Backend)
    } else {
        Ok(())
    }
}
fn classify_preflight_v1(
    record: &StoredAuthorizationV1,
    request_digest: [u8; 32],
    current_height: u64,
) -> Result<BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreErrorV1> {
    match &record.state {
        StoredIssuanceStateV1::Fresh => {
            if current_height < record.issued_at_height {
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid)
            } else if current_height > record.expires_at_height {
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExpired)
            } else {
                Ok(BootleLanternIssuancePreflightV1::Fresh)
            }
        }
        StoredIssuanceStateV1::Processing {
            request_digest: active,
            ..
        } if *active == request_digest => Err(BootleLanternIssuanceStoreErrorV1::Busy),
        StoredIssuanceStateV1::Completed {
            request_digest: completed,
            response_bytes,
            ..
        } if *completed == request_digest => Ok(BootleLanternIssuancePreflightV1::Completed(
            response_bytes.clone(),
        )),
        StoredIssuanceStateV1::Processing { .. }
        | StoredIssuanceStateV1::Completed { .. }
        | StoredIssuanceStateV1::Failed { .. } => {
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessingRecoveryScopeV1 {
    #[cfg(any(test, feature = "test-utils"))]
    All,
    FileOpenSnapshot,
}
fn validate_processing_recovery_v1(
    records: &BTreeMap<[u8; 32], StoredAuthorizationV1>,
    scope: ProcessingRecoveryScopeV1,
    canonical_bytes: u64,
    max_total_bytes: u64,
    authoritative_height: u64,
) -> Result<(usize, u64), BootleLanternIssuanceStoreErrorV1> {
    // Validate every height first. In particular, a lower-id processing
    // record must not be failed before a later record proves that the caller
    // supplied a regressed chain height.
    for record in records.values() {
        let observed_height = match &record.state {
            StoredIssuanceStateV1::Fresh => record.issued_at_height,
            StoredIssuanceStateV1::Processing {
                claimed_at_height, ..
            } => record.issued_at_height.max(*claimed_at_height),
            StoredIssuanceStateV1::Completed {
                completed_at_height,
                ..
            } => record.issued_at_height.max(*completed_at_height),
            StoredIssuanceStateV1::Failed {
                failed_at_height, ..
            } => record.issued_at_height.max(*failed_at_height),
        };
        if authoritative_height < observed_height {
            return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
        }
    }
    let mut recovered_bytes = canonical_bytes;
    let mut recovered = 0_usize;
    for record in records.values() {
        let Some(candidate) = processing_recovery_candidate_v1(record, scope, authoritative_height)
        else {
            continue;
        };
        recovered_bytes = replace_size_v1(
            recovered_bytes,
            record.encoded_len_v1(),
            candidate.encoded_len_v1(),
            max_total_bytes,
        )?;
        recovered = recovered
            .checked_add(1)
            .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
    }
    Ok((recovered, recovered_bytes))
}
fn next_processing_recovery_candidate_v1(
    records: &BTreeMap<[u8; 32], StoredAuthorizationV1>,
    scope: ProcessingRecoveryScopeV1,
    after: Option<[u8; 32]>,
    authoritative_height: u64,
) -> Option<StoredAuthorizationV1> {
    let lower_bound = after.map_or(Unbounded, Excluded);
    records
        .range((lower_bound, Unbounded))
        .find_map(|(_, record)| {
            processing_recovery_candidate_v1(record, scope, authoritative_height)
        })
}
fn processing_recovery_candidate_v1(
    record: &StoredAuthorizationV1,
    scope: ProcessingRecoveryScopeV1,
    authoritative_height: u64,
) -> Option<StoredAuthorizationV1> {
    if scope == ProcessingRecoveryScopeV1::FileOpenSnapshot && !record.processing_at_file_open {
        return None;
    }
    let StoredIssuanceStateV1::Processing {
        request_digest,
        claimed_at_height,
    } = &record.state
    else {
        return None;
    };
    let mut candidate = record.clone();
    candidate.state = StoredIssuanceStateV1::Failed {
        request_digest: *request_digest,
        claimed_at_height: *claimed_at_height,
        failed_at_height: authoritative_height,
    };
    Some(candidate)
}
fn next_prunable_record_v1(
    records: &BTreeMap<[u8; 32], StoredAuthorizationV1>,
    after: Option<[u8; 32]>,
    authoritative_height: u64,
    retention_blocks: u64,
) -> Option<([u8; 32], usize)> {
    let lower_bound = after.map_or(Unbounded, Excluded);
    records
        .range((lower_bound, Unbounded))
        .find_map(|(authorization_id, record)| {
            record
                .retention_horizon_reached_v1(authoritative_height, retention_blocks)
                .then_some((*authorization_id, record.encoded_len_v1()))
        })
}
trait StoreCapacityStateV1 {
    fn records_len_v1(&self) -> usize;
    fn canonical_bytes_v1(&self) -> u64;
}
#[cfg(any(test, feature = "test-utils"))]
impl StoreCapacityStateV1 for InMemoryStateV1 {
    fn records_len_v1(&self) -> usize {
        self.records.len()
    }
    fn canonical_bytes_v1(&self) -> u64 {
        self.canonical_bytes
    }
}
impl StoreCapacityStateV1 for FileStoreStateV1 {
    fn records_len_v1(&self) -> usize {
        self.records.len()
    }
    fn canonical_bytes_v1(&self) -> u64 {
        self.canonical_bytes
    }
}
fn ensure_new_record_capacity_v1(
    state: &impl StoreCapacityStateV1,
    config: BootleLanternIssuanceStoreConfigV1,
    fresh_bytes: usize,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    if state.records_len_v1() >= config.max_records {
        return Err(BootleLanternIssuanceStoreErrorV1::CapacityExceeded);
    }
    let next_slots = state
        .records_len_v1()
        .checked_add(1)
        .and_then(|count| u64::try_from(count).ok())
        .and_then(|count| count.checked_mul(BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1))
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
    if next_slots > config.max_total_bytes {
        return Err(BootleLanternIssuanceStoreErrorV1::CapacityExceeded);
    }
    state
        .canonical_bytes_v1()
        .checked_add(fresh_bytes as u64)
        .filter(|total| *total <= config.max_total_bytes)
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
    Ok(())
}
fn replace_size_v1(
    current: u64,
    old_len: usize,
    new_len: usize,
    max_total: u64,
) -> Result<u64, BootleLanternIssuanceStoreErrorV1> {
    current
        .checked_sub(old_len as u64)
        .and_then(|without_old| without_old.checked_add(new_len as u64))
        .filter(|total| *total <= max_total)
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)
}
#[cfg(any(test, feature = "test-utils"))]
fn commit_in_memory_candidate_v1(
    state: &mut InMemoryStateV1,
    candidate: StoredAuthorizationV1,
    config: BootleLanternIssuanceStoreConfigV1,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    let old_len = state
        .records
        .get(&candidate.authorization_id)
        .map_or(0, StoredAuthorizationV1::encoded_len_v1);
    let new_total = replace_size_v1(
        state.canonical_bytes,
        old_len,
        candidate.encoded_len_v1(),
        config.max_total_bytes,
    )?;
    state.records.insert(candidate.authorization_id, candidate);
    state.canonical_bytes = new_total;
    Ok(())
}
fn encode_record_v1(
    record: &StoredAuthorizationV1,
) -> Result<Vec<u8>, BootleLanternIssuanceStoreErrorV1> {
    validate_decoded_record_v1(record)?;
    let mut bytes = Vec::with_capacity(record.encoded_len_v1());
    bytes.extend_from_slice(&STORE_RECORD_MAGIC_V1);
    bytes.push(STORE_RECORD_VERSION_V1);
    bytes.push(match &record.state {
        StoredIssuanceStateV1::Fresh => STORE_FRESH_TAG_V1,
        StoredIssuanceStateV1::Processing { .. } => STORE_PROCESSING_TAG_V1,
        StoredIssuanceStateV1::Completed { .. } => STORE_COMPLETED_TAG_V1,
        StoredIssuanceStateV1::Failed { .. } => STORE_FAILED_TAG_V1,
    });
    bytes.extend_from_slice(&record.authorization_id);
    bytes.extend_from_slice(&record.authorization_digest);
    bytes.extend_from_slice(&record.issued_at_height.to_be_bytes());
    bytes.extend_from_slice(&record.expires_at_height.to_be_bytes());
    match &record.state {
        StoredIssuanceStateV1::Fresh => {}
        StoredIssuanceStateV1::Processing {
            request_digest,
            claimed_at_height,
        } => {
            bytes.extend_from_slice(request_digest);
            bytes.extend_from_slice(&claimed_at_height.to_be_bytes());
        }
        StoredIssuanceStateV1::Completed {
            request_digest,
            claimed_at_height,
            completed_at_height,
            response_bytes,
        } => {
            bytes.extend_from_slice(request_digest);
            bytes.extend_from_slice(&claimed_at_height.to_be_bytes());
            bytes.extend_from_slice(&completed_at_height.to_be_bytes());
            bytes.extend_from_slice(response_bytes);
        }
        StoredIssuanceStateV1::Failed {
            request_digest,
            claimed_at_height,
            failed_at_height,
        } => {
            bytes.extend_from_slice(request_digest);
            bytes.extend_from_slice(&claimed_at_height.to_be_bytes());
            bytes.extend_from_slice(&failed_at_height.to_be_bytes());
        }
    }
    if bytes.len() != record.encoded_len_v1() {
        return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
    }
    Ok(bytes)
}
#[cfg(any(unix, test))]
fn decode_record_v1(
    bytes: &[u8],
) -> Result<StoredAuthorizationV1, BootleLanternIssuanceStoreErrorV1> {
    if bytes.len() < STORE_RECORD_HEADER_BYTES_V1
        || bytes.len() as u64 > BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1
    {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    let mut offset = 0_usize;
    let magic = take_array_v1::<4>(bytes, &mut offset)?;
    let version = take_array_v1::<1>(bytes, &mut offset)?[0];
    let state_tag = take_array_v1::<1>(bytes, &mut offset)?[0];
    if magic != STORE_RECORD_MAGIC_V1 || version != STORE_RECORD_VERSION_V1 {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    let authorization_id = take_array_v1::<32>(bytes, &mut offset)?;
    let authorization_digest = take_array_v1::<32>(bytes, &mut offset)?;
    let issued_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
    let expires_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
    let state = match state_tag {
        STORE_FRESH_TAG_V1 if bytes.len() == STORE_RECORD_HEADER_BYTES_V1 => {
            StoredIssuanceStateV1::Fresh
        }
        STORE_PROCESSING_TAG_V1 if bytes.len() == STORE_PROCESSING_BYTES_V1 => {
            let request_digest = take_array_v1::<32>(bytes, &mut offset)?;
            let claimed_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
            StoredIssuanceStateV1::Processing {
                request_digest,
                claimed_at_height,
            }
        }
        STORE_COMPLETED_TAG_V1 if bytes.len() == STORE_COMPLETED_BYTES_V1 => {
            let request_digest = take_array_v1::<32>(bytes, &mut offset)?;
            let claimed_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
            let completed_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
            let response_bytes =
                take_array_v1::<BLIND_ISSUANCE_RESPONSE_BYTES_V1>(bytes, &mut offset)?.to_vec();
            StoredIssuanceStateV1::Completed {
                request_digest,
                claimed_at_height,
                completed_at_height,
                response_bytes,
            }
        }
        STORE_FAILED_TAG_V1 if bytes.len() == STORE_FAILED_BYTES_V1 => {
            let request_digest = take_array_v1::<32>(bytes, &mut offset)?;
            let claimed_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
            let failed_at_height = u64::from_be_bytes(take_array_v1::<8>(bytes, &mut offset)?);
            StoredIssuanceStateV1::Failed {
                request_digest,
                claimed_at_height,
                failed_at_height,
            }
        }
        _ => return Err(BootleLanternIssuanceStoreErrorV1::Corrupt),
    };
    if offset != bytes.len() {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    let record = StoredAuthorizationV1 {
        authorization_id,
        authorization_digest,
        issued_at_height,
        expires_at_height,
        state,
        processing_at_file_open: false,
    };
    validate_decoded_record_v1(&record).map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)?;
    if encode_record_v1(&record).map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)? != bytes {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    Ok(record)
}
fn validate_decoded_record_v1(
    record: &StoredAuthorizationV1,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    validate_registration_v1(
        record.authorization_id,
        record.authorization_digest,
        record.issued_at_height,
        record.expires_at_height,
    )?;
    match &record.state {
        StoredIssuanceStateV1::Fresh => Ok(()),
        StoredIssuanceStateV1::Processing {
            request_digest,
            claimed_at_height,
        } => {
            validate_request_inputs_v1(
                record.authorization_id,
                record.authorization_digest,
                *request_digest,
            )?;
            if *claimed_at_height < record.issued_at_height
                || *claimed_at_height > record.expires_at_height
            {
                return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
            }
            Ok(())
        }
        StoredIssuanceStateV1::Completed {
            request_digest,
            claimed_at_height,
            completed_at_height,
            response_bytes,
        } => {
            validate_completion_inputs_v1(
                record.authorization_id,
                record.authorization_digest,
                *request_digest,
                response_bytes,
            )?;
            if *claimed_at_height < record.issued_at_height
                || *claimed_at_height > record.expires_at_height
                || *completed_at_height < *claimed_at_height
            {
                return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
            }
            Ok(())
        }
        StoredIssuanceStateV1::Failed {
            request_digest,
            claimed_at_height,
            failed_at_height,
        } => {
            validate_request_inputs_v1(
                record.authorization_id,
                record.authorization_digest,
                *request_digest,
            )?;
            if *claimed_at_height < record.issued_at_height
                || *claimed_at_height > record.expires_at_height
                || *failed_at_height < *claimed_at_height
            {
                return Err(BootleLanternIssuanceStoreErrorV1::InvalidInput);
            }
            Ok(())
        }
    }
}
#[cfg(any(unix, test))]
fn take_array_v1<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], BootleLanternIssuanceStoreErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(BootleLanternIssuanceStoreErrorV1::Corrupt)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(BootleLanternIssuanceStoreErrorV1::Corrupt)?
        .try_into()
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)?;
    *offset = end;
    Ok(value)
}
fn record_file_name_v1(authorization_id: [u8; 32]) -> String {
    let mut name = String::with_capacity(64 + STORE_RECORD_EXTENSION_V1.len());
    for byte in authorization_id {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(STORE_RECORD_EXTENSION_V1);
    name
}
#[cfg(any(unix, test))]
fn parse_record_file_name_v1(name: &str) -> Result<[u8; 32], BootleLanternIssuanceStoreErrorV1> {
    let hex = name
        .strip_suffix(STORE_RECORD_EXTENSION_V1)
        .ok_or(BootleLanternIssuanceStoreErrorV1::Corrupt)?;
    if hex.len() != 64 || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    if hex.as_bytes().iter().any(u8::is_ascii_uppercase) {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    let mut id = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        id[index] = (hex_nibble_v1(pair[0])? << 4) | hex_nibble_v1(pair[1])?;
    }
    if record_file_name_v1(id) != name {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    Ok(id)
}
#[cfg(any(unix, test))]
fn hex_nibble_v1(byte: u8) -> Result<u8, BootleLanternIssuanceStoreErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BootleLanternIssuanceStoreErrorV1::Corrupt),
    }
}
#[cfg(any(unix, test))]
fn ensure_store_root_v1(root: &Path) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = root
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or(BootleLanternIssuanceStoreErrorV1::InvalidInput)?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
            fs::create_dir(root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            sync_directory_v1(parent).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        }
        Err(_) => return Err(BootleLanternIssuanceStoreErrorV1::Backend),
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn ensure_temp_root_v1(
    root: &Path,
    temp_root: &Path,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    match fs::symlink_metadata(temp_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(temp_root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            sync_directory_v1(root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        }
        Err(_) => return Err(BootleLanternIssuanceStoreErrorV1::Backend),
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn clean_stale_temp_files_v1(temp_root: &Path) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    let mut removed = false;
    for entry in fs::read_dir(temp_root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)? {
        let entry = entry.map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let file_type = entry
            .file_type()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)?;
        let record_name = name
            .strip_suffix(STORE_TEMP_EXTENSION_V1)
            .ok_or(BootleLanternIssuanceStoreErrorV1::Corrupt)?;
        parse_record_file_name_v1(record_name)?;
        let metadata = entry
            .metadata()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        if metadata.len() > BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1 {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        fs::remove_file(entry.path()).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        removed = true;
    }
    if removed {
        sync_directory_v1(temp_root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
    }
    Ok(())
}
#[cfg(any(unix, test))]
fn admit_file_record_allocation_v1(
    loaded_records: usize,
    loaded_bytes: u64,
    record_bytes: u64,
    config: BootleLanternIssuanceStoreConfigV1,
) -> Result<u64, BootleLanternIssuanceStoreErrorV1> {
    let next_count = loaded_records
        .checked_add(1)
        .filter(|count| *count <= config.max_records)
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
    u64::try_from(next_count)
        .ok()
        .and_then(|count| count.checked_mul(BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1))
        .filter(|reserved| *reserved <= config.max_total_bytes)
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
    loaded_bytes
        .checked_add(record_bytes)
        .filter(|total| *total <= config.max_total_bytes)
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)
}
#[cfg(unix)]
fn acquire_file_store_writer_lock_v1(
    root: &Path,
) -> Result<File, BootleLanternIssuanceStoreErrorV1> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let path = root.join(STORE_WRITER_LOCK_FILE_V1);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.len() != 0
            {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(BootleLanternIssuanceStoreErrorV1::Backend),
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(u32::cast_signed(rustix::fs::OFlags::NOFOLLOW.bits()))
        .mode(0o600);
    let file = options
        .open(&path)
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)?;
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || path_metadata.len() != 0
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::StoreAlreadyOpen)?;
    sync_directory_v1(root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
    Ok(file)
}
#[cfg(any(unix, test))]
fn load_file_store_v1(
    root: &Path,
    config: BootleLanternIssuanceStoreConfigV1,
) -> Result<FileStoreStateV1, BootleLanternIssuanceStoreErrorV1> {
    let mut records = BTreeMap::new();
    let mut canonical_bytes = 0_u64;
    for entry in fs::read_dir(root).map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)? {
        let entry = entry.map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)?;
        if name == STORE_TEMP_DIRECTORY_V1 {
            let file_type = entry
                .file_type()
                .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
            continue;
        }
        if name == STORE_WRITER_LOCK_FILE_V1 {
            let file_type = entry
                .file_type()
                .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            let metadata = entry
                .metadata()
                .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
            if file_type.is_symlink() || !file_type.is_file() || metadata.len() != 0 {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
                }
            }
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        let file_id = parse_record_file_name_v1(&name)?;
        let metadata = entry
            .metadata()
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        if metadata.len() < STORE_RECORD_HEADER_BYTES_V1 as u64
            || metadata.len() > BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1
        {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        let next_canonical_bytes = admit_file_record_allocation_v1(
            records.len(),
            canonical_bytes,
            metadata.len(),
            config,
        )?;
        let file = open_record_file_v1(&entry.path(), &metadata)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
        if bytes.len() as u64 != metadata.len()
            || bytes.len() as u64 > BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1
        {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        let mut record = decode_record_v1(&bytes)?;
        if record.authorization_id != file_id {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        record.processing_at_file_open =
            matches!(&record.state, StoredIssuanceStateV1::Processing { .. });
        if records.insert(record.authorization_id, record).is_some() {
            return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
        }
        canonical_bytes = next_canonical_bytes;
    }
    let reserved = u64::try_from(records.len())
        .ok()
        .and_then(|count| count.checked_mul(BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1))
        .ok_or(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)?;
    if reserved > config.max_total_bytes {
        return Err(BootleLanternIssuanceStoreErrorV1::CapacityExceeded);
    }
    Ok(FileStoreStateV1 {
        records,
        canonical_bytes,
        poisoned: false,
    })
}
fn reject_untrusted_existing_target_v1(
    path: &Path,
) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(BootleLanternIssuanceStoreErrorV1::Backend),
    }
    Ok(())
}
#[cfg(unix)]
fn open_record_file_v1(
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<File, BootleLanternIssuanceStoreErrorV1> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if path_metadata.nlink() != 1 {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(u32::cast_signed(rustix::fs::OFlags::NOFOLLOW.bits()))
        .open(path)
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::Corrupt)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.nlink() != 1
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || path_metadata.len() != opened_metadata.len()
    {
        return Err(BootleLanternIssuanceStoreErrorV1::Corrupt);
    }
    Ok(file)
}
#[cfg(all(test, not(unix)))]
fn open_record_file_v1(
    _path: &Path,
    _path_metadata: &fs::Metadata,
) -> Result<File, BootleLanternIssuanceStoreErrorV1> {
    Err(BootleLanternIssuanceStoreErrorV1::UnsupportedPlatform)
}
fn reject_untrusted_existing_temp_v1(path: &Path) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(BootleLanternIssuanceStoreErrorV1::Corrupt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BootleLanternIssuanceStoreErrorV1::Backend),
    }
}
fn sync_directory_v1(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}
fn open_file_store_roots_v1() -> &'static Mutex<BTreeSet<PathBuf>> {
    static ROOTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    ROOTS.get_or_init(|| Mutex::new(BTreeSet::new()))
}
#[cfg(any(unix, test))]
fn acquire_file_store_lease_v1(
    canonical_root: PathBuf,
) -> Result<FileStoreDirectoryLeaseV1, BootleLanternIssuanceStoreErrorV1> {
    let mut open_roots = open_file_store_roots_v1()
        .lock()
        .map_err(|_| BootleLanternIssuanceStoreErrorV1::Backend)?;
    if !open_roots.insert(canonical_root.clone()) {
        return Err(BootleLanternIssuanceStoreErrorV1::StoreAlreadyOpen);
    }
    Ok(FileStoreDirectoryLeaseV1 { canonical_root })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    const AUTHORIZATION_ID: [u8; 32] = [1; 32];
    const AUTHORIZATION_DIGEST: [u8; 32] = [2; 32];
    const REQUEST_DIGEST: [u8; 32] = [3; 32];
    const ISSUED_AT: u64 = 10;
    const EXPIRES_AT: u64 = 20;
    fn response_bytes() -> Vec<u8> {
        response_bytes_for_v1(REQUEST_DIGEST)
    }
    fn response_bytes_for_v1(request_digest: [u8; 32]) -> Vec<u8> {
        let mut bytes = vec![0; BLIND_ISSUANCE_RESPONSE_BYTES_V1];
        bytes[..4].copy_from_slice(b"ILR1");
        bytes[4] = 1;
        let request_offset = BLIND_ISSUANCE_RESPONSE_BYTES_V1 - 3 * 32;
        bytes[request_offset..request_offset + 32].copy_from_slice(&request_digest);
        bytes[request_offset + 32..request_offset + 64].fill(4);
        bytes[request_offset + 64..].fill(5);
        bytes
    }
    fn one_record_config(retention: u64) -> BootleLanternIssuanceStoreConfigV1 {
        BootleLanternIssuanceStoreConfigV1::new(
            1,
            BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1,
            retention,
        )
        .unwrap()
    }
    fn register_default(store: &dyn BootleLanternIssuanceStoreV1) {
        register_record_v1(
            store,
            AUTHORIZATION_ID,
            AUTHORIZATION_DIGEST,
            ISSUED_AT,
            EXPIRES_AT,
        );
    }
    fn register_record_v1(
        store: &dyn BootleLanternIssuanceStoreV1,
        authorization_id: [u8; 32],
        authorization_digest: [u8; 32],
        issued_at_height: u64,
        expires_at_height: u64,
    ) {
        store
            .register_fresh_v1(
                authorization_id,
                authorization_digest,
                issued_at_height,
                expires_at_height,
            )
            .unwrap();
    }
    #[test]
    fn configuration_enforces_hard_caps_and_worst_case_reservation() {
        for (records, bytes, retention) in [
            (0, BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1, 1),
            (1, 0, 1),
            (1, BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1, 0),
            (
                BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RECORDS_V1 + 1,
                BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_TOTAL_BYTES_V1,
                1,
            ),
            (
                2,
                BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1 * 2 - 1,
                1,
            ),
            (
                1,
                BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_TOTAL_BYTES_V1 + 1,
                1,
            ),
            (
                1,
                BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1,
                BOOTLE_LANTERN_ISSUANCE_STORE_HARD_MAX_RETENTION_BLOCKS_V1 + 1,
            ),
        ] {
            assert_eq!(
                BootleLanternIssuanceStoreConfigV1::new(records, bytes, retention),
                Err(BootleLanternIssuanceStoreErrorV1::ConfigurationInvalid)
            );
        }
        assert!(
            BootleLanternIssuanceStoreConfigV1::new(
                2,
                BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1 * 2,
                1,
            )
            .is_ok()
        );
    }
    #[test]
    fn file_record_allocation_is_admitted_before_payload_read() {
        let config = one_record_config(1);
        assert_eq!(
            admit_file_record_allocation_v1(0, 0, STORE_RECORD_HEADER_BYTES_V1 as u64, config),
            Ok(STORE_RECORD_HEADER_BYTES_V1 as u64)
        );
        assert_eq!(
            admit_file_record_allocation_v1(1, 0, STORE_RECORD_HEADER_BYTES_V1 as u64, config),
            Err(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)
        );
        assert_eq!(
            admit_file_record_allocation_v1(0, config.max_total_bytes, 1, config),
            Err(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)
        );
    }
    #[test]
    fn registration_and_request_inputs_fail_closed_at_every_boundary() {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        for (id, digest, issued, expires) in [
            ([0; 32], AUTHORIZATION_DIGEST, ISSUED_AT, EXPIRES_AT),
            (AUTHORIZATION_ID, [0; 32], ISSUED_AT, EXPIRES_AT),
            (AUTHORIZATION_ID, AUTHORIZATION_DIGEST, ISSUED_AT, ISSUED_AT),
            (
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                EXPIRES_AT,
                ISSUED_AT,
            ),
            (
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                1,
                2 + super::super::issuer::MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1,
            ),
        ] {
            assert_eq!(
                store.register_fresh_v1(id, digest, issued, expires),
                Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
            );
        }
        register_default(&store);
        assert_eq!(
            store.register_fresh_v1(AUTHORIZATION_ID, [9; 32], ISSUED_AT, EXPIRES_AT,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists)
        );
        for (id, digest, request) in [
            ([0; 32], AUTHORIZATION_DIGEST, REQUEST_DIGEST),
            (AUTHORIZATION_ID, [0; 32], REQUEST_DIGEST),
            (AUTHORIZATION_ID, AUTHORIZATION_DIGEST, [0; 32]),
        ] {
            assert_eq!(
                store.preflight_v1(id, digest, request, ISSUED_AT),
                Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
            );
            assert_eq!(
                store.claim_v1(id, digest, request, ISSUED_AT),
                Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
            );
        }
        assert_eq!(
            store.preflight_v1(AUTHORIZATION_ID, [9; 32], REQUEST_DIGEST, ISSUED_AT,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
    }
    #[test]
    fn preflight_and_claim_enforce_height_but_completed_retry_ignores_expiry() {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_default(&store);
        for height in [0, ISSUED_AT - 1] {
            assert_eq!(
                store.preflight_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    height,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid)
            );
            assert_eq!(
                store.claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    height,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid)
            );
        }
        assert_eq!(
            store.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                EXPIRES_AT + 1,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExpired)
        );
        assert_eq!(
            store.claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            ),
            Ok(BootleLanternIssuanceClaimV1::Fresh)
        );
        let response = response_bytes();
        store
            .complete_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                &response,
                ISSUED_AT + 1,
            )
            .unwrap();
        assert_eq!(
            store.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                u64::MAX,
            ),
            Ok(BootleLanternIssuancePreflightV1::Completed(
                response.clone()
            ))
        );
        assert_eq!(
            store.claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                u64::MAX,
            ),
            Ok(BootleLanternIssuanceClaimV1::Completed(response))
        );
    }
    #[test]
    fn concurrent_claim_has_exactly_one_fresh_winner() {
        let store = Arc::new(BootleLanternInMemoryIssuanceStoreV1::new());
        register_default(store.as_ref());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store.claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Ok(BootleLanternIssuanceClaimV1::Fresh))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Err(BootleLanternIssuanceStoreErrorV1::Busy))
                .count(),
            1
        );
    }
    #[test]
    fn substitutions_and_invalid_transition_heights_never_change_processing() {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_default(&store);
        store
            .claim_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 15)
            .unwrap();
        assert_eq!(
            store.complete_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                &response_bytes(),
                14,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
        );
        assert_eq!(
            store.fail_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 14,),
            Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
        );
        for (authorization_digest, request_digest) in
            [([9; 32], REQUEST_DIGEST), (AUTHORIZATION_DIGEST, [8; 32])]
        {
            assert_eq!(
                store.complete_v1(
                    AUTHORIZATION_ID,
                    authorization_digest,
                    request_digest,
                    &response_bytes(),
                    15,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
            );
        }
        assert_eq!(
            store.preflight_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 15,),
            Err(BootleLanternIssuanceStoreErrorV1::Busy)
        );
    }
    #[test]
    fn malformed_or_request_substituted_ilr1_never_completes_processing() {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_default(&store);
        store
            .claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            )
            .unwrap();
        let valid = response_bytes();
        let mut bad_header = valid.clone();
        bad_header[0] ^= 1;
        let mut substituted_request = valid.clone();
        let request_offset = BLIND_ISSUANCE_RESPONSE_BYTES_V1 - 3 * 32;
        substituted_request[request_offset..request_offset + 32].fill(9);
        for malformed in [
            Vec::new(),
            valid[..valid.len() - 1].to_vec(),
            {
                let mut trailing = valid.clone();
                trailing.push(0);
                trailing
            },
            bad_header,
            substituted_request,
        ] {
            assert_eq!(
                store.complete_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    &malformed,
                    ISSUED_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
            );
            assert_eq!(
                store.preflight_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::Busy)
            );
        }
        store
            .complete_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                &valid,
                ISSUED_AT,
            )
            .unwrap();
    }
    #[test]
    fn completion_failure_can_only_advance_to_terminal_failed() {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        register_default(&store);
        store
            .claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            )
            .unwrap();
        store.inject_next_completion_failure_v1();
        assert_eq!(
            store.complete_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                &response_bytes(),
                ISSUED_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::Backend)
        );
        store
            .fail_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            )
            .unwrap();
        assert_eq!(
            store.claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
        assert_eq!(
            store.register_fresh_v1(AUTHORIZATION_ID, [7; 32], ISSUED_AT, EXPIRES_AT,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists)
        );
    }
    #[test]
    fn in_memory_recovery_is_height_atomic_idempotent_and_mixed_state_safe() {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        let fresh = ([4; 32], [14; 32]);
        let processing_early = ([5; 32], [15; 32], [25; 32], 12);
        let processing_late = ([6; 32], [16; 32], [26; 32], 16);
        let completed = ([7; 32], [17; 32], [27; 32], 13, 17);
        let failed = ([8; 32], [18; 32], [28; 32], 14, 18);
        for (id, digest) in [
            fresh,
            (processing_early.0, processing_early.1),
            (processing_late.0, processing_late.1),
            (completed.0, completed.1),
            (failed.0, failed.1),
        ] {
            register_record_v1(&store, id, digest, ISSUED_AT, EXPIRES_AT);
        }
        store
            .claim_v1(
                processing_early.0,
                processing_early.1,
                processing_early.2,
                processing_early.3,
            )
            .unwrap();
        store
            .claim_v1(
                processing_late.0,
                processing_late.1,
                processing_late.2,
                processing_late.3,
            )
            .unwrap();
        store
            .claim_v1(completed.0, completed.1, completed.2, completed.3)
            .unwrap();
        let completed_response = response_bytes_for_v1(completed.2);
        store
            .complete_v1(
                completed.0,
                completed.1,
                completed.2,
                &completed_response,
                completed.4,
            )
            .unwrap();
        store
            .claim_v1(failed.0, failed.1, failed.2, failed.3)
            .unwrap();
        store
            .fail_v1(failed.0, failed.1, failed.2, failed.4)
            .unwrap();
        let (fresh_before, completed_before, failed_before) = {
            let state = store.state.lock().unwrap();
            (
                state.records[&fresh.0].clone(),
                state.records[&completed.0].clone(),
                state.records[&failed.0].clone(),
            )
        };
        assert_eq!(
            store.recover_processing_v1(15),
            Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
        );
        for (id, digest, request, claimed_at) in [processing_early, processing_late] {
            assert_eq!(
                store.preflight_v1(id, digest, request, claimed_at),
                Err(BootleLanternIssuanceStoreErrorV1::Busy)
            );
        }
        assert_eq!(store.recover_processing_v1(18), Ok(2));
        assert_eq!(store.recover_processing_v1(18), Ok(0));
        assert_eq!(
            store.recover_processing_v1(17),
            Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
        );
        for (id, digest, request, claimed_at) in [processing_early, processing_late] {
            assert_eq!(
                store.preflight_v1(id, digest, request, claimed_at),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
            );
        }
        assert_eq!(
            store.preflight_v1(fresh.0, fresh.1, [29; 32], 18),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
        assert_eq!(
            store.preflight_v1(completed.0, completed.1, completed.2, u64::MAX),
            Ok(BootleLanternIssuancePreflightV1::Completed(
                completed_response
            ))
        );
        assert_eq!(
            store.preflight_v1(failed.0, failed.1, failed.2, 18),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
        let state = store.state.lock().unwrap();
        assert_eq!(state.records[&fresh.0], fresh_before);
        assert_eq!(state.records[&completed.0], completed_before);
        assert_eq!(state.records[&failed.0], failed_before);
        for id in [processing_early.0, processing_late.0] {
            assert!(matches!(
                &state.records[&id].state,
                StoredIssuanceStateV1::Failed {
                    failed_at_height: 18,
                    ..
                }
            ));
        }
    }
    #[test]
    fn in_memory_recovered_processing_uses_failed_retention_horizon() {
        let config = BootleLanternIssuanceStoreConfigV1::new(
            1,
            BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1,
            5,
        )
        .unwrap();
        let store = BootleLanternInMemoryIssuanceStoreV1::with_config(config);
        register_default(&store);
        store
            .claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            )
            .unwrap();
        assert_eq!(store.recover_processing_v1(EXPIRES_AT + 10), Ok(1));
        assert_eq!(store.prune_v1(EXPIRES_AT + 14), Ok(0));
        assert_eq!(store.prune_v1(EXPIRES_AT + 15), Ok(1));
        assert_eq!(store.recover_processing_v1(EXPIRES_AT + 15), Ok(0));
    }
    #[test]
    fn canonical_record_codec_rejects_every_non_exact_shape() {
        let record = StoredAuthorizationV1 {
            authorization_id: AUTHORIZATION_ID,
            authorization_digest: AUTHORIZATION_DIGEST,
            issued_at_height: ISSUED_AT,
            expires_at_height: EXPIRES_AT,
            state: StoredIssuanceStateV1::Completed {
                request_digest: REQUEST_DIGEST,
                claimed_at_height: ISSUED_AT,
                completed_at_height: EXPIRES_AT + 1,
                response_bytes: response_bytes(),
            },
            processing_at_file_open: false,
        };
        let bytes = encode_record_v1(&record).unwrap();
        assert_eq!(bytes.len(), STORE_COMPLETED_BYTES_V1);
        assert_eq!(decode_record_v1(&bytes), Ok(record));
        for corrupted in [
            bytes[..bytes.len() - 1].to_vec(),
            {
                let mut value = bytes.clone();
                value.push(0);
                value
            },
            {
                let mut value = bytes.clone();
                value[0] ^= 1;
                value
            },
            {
                let mut value = bytes.clone();
                value[4] = 2;
                value
            },
            {
                let mut value = bytes.clone();
                value[5] = 0xff;
                value
            },
            {
                let mut value = bytes.clone();
                value[6..38].fill(0);
                value
            },
        ] {
            assert_eq!(
                decode_record_v1(&corrupted),
                Err(BootleLanternIssuanceStoreErrorV1::Corrupt)
            );
        }
        let mut reversed_terminal_height = bytes.clone();
        let completed_height_offset = STORE_RECORD_HEADER_BYTES_V1 + 32 + 8;
        reversed_terminal_height[completed_height_offset..completed_height_offset + 8]
            .copy_from_slice(&(ISSUED_AT - 1).to_be_bytes());
        assert_eq!(
            decode_record_v1(&reversed_terminal_height),
            Err(BootleLanternIssuanceStoreErrorV1::Corrupt)
        );
        let mut reversed_lifetime = bytes;
        let expires_offset = 4 + 1 + 1 + 32 + 32 + 8;
        reversed_lifetime[expires_offset..expires_offset + 8]
            .copy_from_slice(&ISSUED_AT.to_be_bytes());
        assert_eq!(
            decode_record_v1(&reversed_lifetime),
            Err(BootleLanternIssuanceStoreErrorV1::Corrupt)
        );
    }
    #[test]
    fn file_store_reopens_completed_response_exactly_after_expiry() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let response = response_bytes();
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            assert_eq!(
                store.claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                ),
                Ok(BootleLanternIssuanceClaimV1::Fresh)
            );
            store
                .complete_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    &response,
                    ISSUED_AT + 1,
                )
                .unwrap();
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(
            reopened.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                u64::MAX,
            ),
            Ok(BootleLanternIssuancePreflightV1::Completed(
                response.clone()
            ))
        );
        assert_eq!(
            reopened.claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                u64::MAX,
            ),
            Ok(BootleLanternIssuanceClaimV1::Completed(response))
        );
        assert_eq!(
            reopened.claim_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, [4; 32], ISSUED_AT,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
    }
    #[test]
    fn file_store_reopens_processing_as_busy_and_never_fresh() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            store
                .claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
                .unwrap();
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(
            reopened.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::Busy)
        );
        assert_eq!(
            reopened.claim_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, [4; 32], ISSUED_AT,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
        assert_eq!(reopened.prune_v1(u64::MAX), Ok(0));
    }
    #[test]
    fn file_store_recovery_is_durable_idempotent_and_mixed_state_safe() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let processing = ([4; 32], [14; 32], [24; 32], 12);
        let completed = ([5; 32], [15; 32], [25; 32], 13, 17);
        let failed = ([6; 32], [16; 32], [26; 32], 14, 18);
        let completed_response = response_bytes_for_v1(completed.2);
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            for (id, digest) in [
                (processing.0, processing.1),
                (completed.0, completed.1),
                (failed.0, failed.1),
            ] {
                register_record_v1(&store, id, digest, ISSUED_AT, EXPIRES_AT);
            }
            store
                .claim_v1(processing.0, processing.1, processing.2, processing.3)
                .unwrap();
            store
                .claim_v1(completed.0, completed.1, completed.2, completed.3)
                .unwrap();
            store
                .complete_v1(
                    completed.0,
                    completed.1,
                    completed.2,
                    &completed_response,
                    completed.4,
                )
                .unwrap();
            store
                .claim_v1(failed.0, failed.1, failed.2, failed.3)
                .unwrap();
            store
                .fail_v1(failed.0, failed.1, failed.2, failed.4)
                .unwrap();
        }
        let fresh_path = root.join(record_file_name_v1(AUTHORIZATION_ID));
        let completed_path = root.join(record_file_name_v1(completed.0));
        let failed_path = root.join(record_file_name_v1(failed.0));
        let fresh_before = fs::read(&fresh_path).unwrap();
        let completed_before = fs::read(&completed_path).unwrap();
        let failed_before = fs::read(&failed_path).unwrap();
        {
            let recovered = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            assert_eq!(recovered.recover_processing_v1(18), Ok(1));
            assert_eq!(fs::read(&fresh_path).unwrap(), fresh_before);
            assert_eq!(fs::read(&completed_path).unwrap(), completed_before);
            assert_eq!(fs::read(&failed_path).unwrap(), failed_before);
            assert_eq!(recovered.recover_processing_v1(18), Ok(0));
            assert_eq!(
                recovered.preflight_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 18,),
                Ok(BootleLanternIssuancePreflightV1::Fresh)
            );
            assert_eq!(
                recovered.preflight_v1(processing.0, processing.1, processing.2, 18),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
            );
            assert_eq!(
                recovered.preflight_v1(completed.0, completed.1, completed.2, u64::MAX),
                Ok(BootleLanternIssuancePreflightV1::Completed(
                    completed_response.clone()
                ))
            );
            assert_eq!(
                recovered.preflight_v1(failed.0, failed.1, failed.2, 18),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
            );
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(reopened.recover_processing_v1(18), Ok(0));
        assert_eq!(
            reopened.preflight_v1(processing.0, processing.1, processing.2, 18),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
        assert_eq!(
            reopened.preflight_v1(completed.0, completed.1, completed.2, u64::MAX),
            Ok(BootleLanternIssuancePreflightV1::Completed(
                completed_response
            ))
        );
    }
    #[test]
    fn file_store_recovery_only_fails_processing_present_at_open() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let post_open = ([4; 32], [14; 32], [24; 32], 12);
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            store
                .claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
                .unwrap();
        }
        {
            let recovered = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_record_v1(&recovered, post_open.0, post_open.1, ISSUED_AT, EXPIRES_AT);
            recovered
                .claim_v1(post_open.0, post_open.1, post_open.2, post_open.3)
                .unwrap();
            {
                let state = recovered.state.lock().unwrap();
                assert!(state.records[&AUTHORIZATION_ID].processing_at_file_open);
                assert!(!state.records[&post_open.0].processing_at_file_open);
            }
            assert_eq!(recovered.recover_processing_v1(EXPIRES_AT), Ok(1));
            assert_eq!(
                recovered.preflight_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    EXPIRES_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
            );
            assert_eq!(
                recovered.preflight_v1(post_open.0, post_open.1, post_open.2, EXPIRES_AT,),
                Err(BootleLanternIssuanceStoreErrorV1::Busy)
            );
            assert_eq!(recovered.recover_processing_v1(EXPIRES_AT), Ok(0));
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(reopened.recover_processing_v1(EXPIRES_AT), Ok(1));
        assert_eq!(
            reopened.preflight_v1(post_open.0, post_open.1, post_open.2, EXPIRES_AT,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
    }
    #[test]
    fn file_store_recovery_rejects_height_regression_without_partial_mutation() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let later = ([4; 32], [14; 32], [24; 32], 16);
        let future_fresh = ([9; 32], [19; 32], 30, 40);
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            register_record_v1(&store, later.0, later.1, ISSUED_AT, EXPIRES_AT);
            register_record_v1(
                &store,
                future_fresh.0,
                future_fresh.1,
                future_fresh.2,
                future_fresh.3,
            );
            store
                .claim_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 11)
                .unwrap();
            store.claim_v1(later.0, later.1, later.2, later.3).unwrap();
        }
        let early_path = root.join(record_file_name_v1(AUTHORIZATION_ID));
        let later_path = root.join(record_file_name_v1(later.0));
        let future_path = root.join(record_file_name_v1(future_fresh.0));
        let early_before = fs::read(&early_path).unwrap();
        let later_before = fs::read(&later_path).unwrap();
        let future_before = fs::read(&future_path).unwrap();
        let recovered = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(
            recovered.recover_processing_v1(future_fresh.2 - 1),
            Err(BootleLanternIssuanceStoreErrorV1::InvalidInput)
        );
        assert_eq!(fs::read(&early_path).unwrap(), early_before);
        assert_eq!(fs::read(&later_path).unwrap(), later_before);
        assert_eq!(fs::read(&future_path).unwrap(), future_before);
        assert_eq!(
            recovered.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                future_fresh.2 - 1,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::Busy)
        );
        assert_eq!(
            recovered.preflight_v1(later.0, later.1, later.2, later.3),
            Err(BootleLanternIssuanceStoreErrorV1::Busy)
        );
        assert_eq!(
            recovered.preflight_v1(future_fresh.0, future_fresh.1, [29; 32], future_fresh.2 - 1,),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid)
        );
        assert_eq!(recovered.recover_processing_v1(future_fresh.2), Ok(2));
        assert_eq!(fs::read(&future_path).unwrap(), future_before);
    }
    #[test]
    fn file_store_recovery_write_failure_poisons_and_resumes_after_reopen() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let later = ([4; 32], [14; 32], [24; 32], 12);
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            register_record_v1(&store, later.0, later.1, ISSUED_AT, EXPIRES_AT);
            store
                .claim_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 11)
                .unwrap();
            store.claim_v1(later.0, later.1, later.2, later.3).unwrap();
        }
        {
            let recovered = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            recovered.inject_write_failure_after_successes_v1(1, 1);
            assert_eq!(
                recovered.recover_processing_v1(16),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
            assert_eq!(
                recovered.preflight_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 16,),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
            assert_eq!(
                recovered.recover_processing_v1(16),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
        }
        {
            let reopened = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            assert_eq!(
                reopened.preflight_v1(AUTHORIZATION_ID, AUTHORIZATION_DIGEST, REQUEST_DIGEST, 16,),
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
            );
            assert_eq!(
                reopened.preflight_v1(later.0, later.1, later.2, 16),
                Err(BootleLanternIssuanceStoreErrorV1::Busy)
            );
            assert_eq!(reopened.recover_processing_v1(16), Ok(1));
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(reopened.recover_processing_v1(16), Ok(0));
        assert_eq!(
            reopened.preflight_v1(later.0, later.1, later.2, 16),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
    }
    #[test]
    fn file_store_recovery_post_rename_failure_is_poisoned_and_committed_on_reopen() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            store
                .claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
                .unwrap();
        }
        {
            let recovered = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            recovered.inject_next_write_after_rename_failure_v1();
            assert_eq!(
                recovered.recover_processing_v1(EXPIRES_AT),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
            assert_eq!(
                recovered.preflight_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    EXPIRES_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(reopened.recover_processing_v1(EXPIRES_AT), Ok(0));
        assert_eq!(
            reopened.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                EXPIRES_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
    }
    #[test]
    fn file_store_recovered_processing_prunes_from_recovery_height_after_reopen() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store =
                BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
            register_default(&store);
            store
                .claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
                .unwrap();
        }
        {
            let recovered =
                BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
            assert_eq!(recovered.recover_processing_v1(EXPIRES_AT + 10), Ok(1));
            assert_eq!(recovered.prune_v1(EXPIRES_AT + 14), Ok(0));
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
        assert_eq!(reopened.prune_v1(EXPIRES_AT + 15), Ok(1));
        register_record_v1(&reopened, [4; 32], [14; 32], ISSUED_AT, EXPIRES_AT);
    }
    #[test]
    fn file_store_rejects_second_same_process_opener() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let first = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::StoreAlreadyOpen
        );
        drop(first);
        assert!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .is_ok()
        );
    }
    #[test]
    fn file_store_capacity_fails_before_mutation_until_authoritative_prune() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let store = BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
        register_default(&store);
        assert_eq!(
            store.register_fresh_v1([4; 32], [5; 32], ISSUED_AT, EXPIRES_AT),
            Err(BootleLanternIssuanceStoreErrorV1::CapacityExceeded)
        );
        assert_eq!(store.prune_v1(EXPIRES_AT + 4), Ok(0));
        assert_eq!(
            store.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                EXPIRES_AT,
            ),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
        assert_eq!(store.prune_v1(EXPIRES_AT + 5), Ok(1));
        assert_eq!(
            store.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                EXPIRES_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
        store
            .register_fresh_v1([4; 32], [5; 32], ISSUED_AT, EXPIRES_AT)
            .unwrap();
    }
    #[test]
    fn completed_retention_horizon_uses_later_of_expiry_and_completion() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let store = BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
        register_default(&store);
        store
            .claim_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            )
            .unwrap();
        store
            .complete_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                &response_bytes(),
                EXPIRES_AT + 10,
            )
            .unwrap();
        assert_eq!(store.prune_v1(EXPIRES_AT + 14), Ok(0));
        assert_eq!(store.prune_v1(EXPIRES_AT + 15), Ok(1));
    }
    #[test]
    fn failed_retention_horizon_is_explicit_and_persists_across_reopen() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store =
                BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
            register_default(&store);
            store
                .claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
                .unwrap();
            store
                .fail_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    EXPIRES_AT + 10,
                )
                .unwrap();
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(&root, one_record_config(5)).unwrap();
        assert_eq!(
            reopened.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                EXPIRES_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed)
        );
        assert_eq!(reopened.prune_v1(EXPIRES_AT + 14), Ok(0));
        assert_eq!(reopened.prune_v1(EXPIRES_AT + 15), Ok(1));
    }
    #[test]
    fn write_failure_before_rename_leaves_prior_durable_state() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            store.inject_next_write_before_rename_failure_v1();
            assert_eq!(
                store.claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
            assert_eq!(
                store.preflight_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                ),
                Ok(BootleLanternIssuancePreflightV1::Fresh)
            );
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(
            reopened.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            ),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
    }
    #[test]
    fn post_rename_sync_failure_poisons_live_handle_and_reopens_committed_state() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
            store.inject_next_write_after_rename_failure_v1();
            assert_eq!(
                store.claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
            assert_eq!(
                store.preflight_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                ),
                Err(BootleLanternIssuanceStoreErrorV1::Backend)
            );
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(
            reopened.preflight_v1(
                AUTHORIZATION_ID,
                AUTHORIZATION_DIGEST,
                REQUEST_DIGEST,
                ISSUED_AT,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::Busy)
        );
    }
    #[test]
    fn file_store_concurrent_claim_has_one_durable_winner() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let store = Arc::new(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap(),
        );
        register_default(store.as_ref());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store.claim_v1(
                    AUTHORIZATION_ID,
                    AUTHORIZATION_DIGEST,
                    REQUEST_DIGEST,
                    ISSUED_AT,
                )
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Ok(BootleLanternIssuanceClaimV1::Fresh))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Err(BootleLanternIssuanceStoreErrorV1::Busy))
                .count(),
            1
        );
    }
    fn make_registered_store_bytes_v1(root: &Path) -> (PathBuf, Vec<u8>) {
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            register_default(&store);
        }
        let record_path = root.join(record_file_name_v1(AUTHORIZATION_ID));
        let bytes = fs::read(&record_path).unwrap();
        (record_path, bytes)
    }
    #[test]
    fn open_rejects_truncated_trailing_corrupt_and_oversized_records() {
        for mutation in 0..5 {
            let parent = tempfile::tempdir().unwrap();
            let root = parent.path().join("issuance");
            let (record_path, mut bytes) = make_registered_store_bytes_v1(&root);
            match mutation {
                0 => {
                    bytes.pop();
                }
                1 => bytes.push(0),
                2 => bytes[0] ^= 1,
                3 => bytes[5] = STORE_COMPLETED_TAG_V1,
                4 => bytes.resize(
                    BOOTLE_LANTERN_ISSUANCE_STORE_MAX_RECORD_BYTES_V1 as usize + 1,
                    0,
                ),
                _ => unreachable!(),
            }
            fs::write(record_path, bytes).unwrap();
            assert_eq!(
                BootleLanternFileIssuanceStoreV1::open(
                    &root,
                    BootleLanternIssuanceStoreConfigV1::default(),
                )
                .unwrap_err(),
                BootleLanternIssuanceStoreErrorV1::Corrupt
            );
        }
    }
    #[test]
    fn open_rejects_filename_record_id_substitution_and_unknown_entries() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let (record_path, bytes) = make_registered_store_bytes_v1(&root);
        fs::rename(record_path, root.join(record_file_name_v1([9; 32]))).unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let _ = make_registered_store_bytes_v1(&root);
        fs::write(root.join("unknown"), bytes).unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
    }
    #[cfg(unix)]
    #[test]
    fn open_rejects_symlink_and_non_regular_entries() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        fs::create_dir(&root).unwrap();
        let outside = parent.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join(record_file_name_v1(AUTHORIZATION_ID))).unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join(record_file_name_v1(AUTHORIZATION_ID))).unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
        let parent = tempfile::tempdir().unwrap();
        let real_root = parent.path().join("real");
        fs::create_dir(&real_root).unwrap();
        let linked_root = parent.path().join("linked");
        symlink(&real_root, &linked_root).unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &linked_root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
    }
    #[cfg(unix)]
    #[test]
    fn open_rejects_hardlinked_records_and_lock_file_substitution() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        let (record_path, _) = make_registered_store_bytes_v1(&root);
        fs::hard_link(&record_path, parent.path().join("record-alias")).unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let _store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
        }
        fs::hard_link(
            root.join(STORE_WRITER_LOCK_FILE_V1),
            parent.path().join("lock-alias"),
        )
        .unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let _store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
        }
        fs::write(root.join(STORE_WRITER_LOCK_FILE_V1), b"not-empty").unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
    }
    #[test]
    fn open_cleans_only_strict_bounded_stale_temp_files() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("issuance");
        {
            let store = BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap();
            let stale = store.temp_root.join(format!(
                "{}{}",
                record_file_name_v1(AUTHORIZATION_ID),
                STORE_TEMP_EXTENSION_V1
            ));
            fs::write(&stale, b"uncommitted").unwrap();
        }
        let reopened = BootleLanternFileIssuanceStoreV1::open(
            &root,
            BootleLanternIssuanceStoreConfigV1::default(),
        )
        .unwrap();
        assert_eq!(fs::read_dir(&reopened.temp_root).unwrap().count(), 0);
        drop(reopened);
        fs::write(root.join(STORE_TEMP_DIRECTORY_V1).join("unknown.tmp"), b"x").unwrap();
        assert_eq!(
            BootleLanternFileIssuanceStoreV1::open(
                &root,
                BootleLanternIssuanceStoreConfigV1::default(),
            )
            .unwrap_err(),
            BootleLanternIssuanceStoreErrorV1::Corrupt
        );
    }
}
