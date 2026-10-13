//! Caller-owned geometry work across physical lock release and local I/O failure.
//!
//! This is raw storage-operation custody, not finality or pre-vote capacity
//! admission. The claim excludes all competing journal mutation until this
//! original attempt publishes its catalog or completes its owned rollback.

use super::*;
use crate::kura::{KuraInstanceIdentity, KuraPublicationLease};
use parking_lot::Mutex;
use std::sync::Weak;
use tokio::sync::watch;

/// Release of one exact operation claim; retry must acquire and authenticate again.
#[derive(Clone, Debug)]
pub struct RawGeometryWait {
    released: watch::Receiver<bool>,
}

impl std::fmt::Display for RawGeometryWait {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(if *self.released.borrow() {
            "released; retry acquisition"
        } else {
            "release pending"
        })
    }
}

impl RawGeometryWait {
    /// Wait only after releasing every Kura and State physical fence.
    pub async fn wait_for_release(&mut self) {
        while !*self.released.borrow_and_update() {
            if self.released.changed().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Debug)]
struct ClaimSignal {
    released: watch::Sender<bool>,
}

#[derive(Debug, Default)]
struct ClaimState {
    active: Weak<ClaimSignal>,
    abandoned: bool,
}

/// Kura-instance-local exclusion for journal mutation and instance collection.
#[derive(Debug, Default)]
pub(in crate::kura) struct RawGeometryClaimGate {
    state: Arc<Mutex<ClaimState>>,
}

impl RawGeometryClaimGate {
    fn claim(&self) -> Result<RawGeometryClaim> {
        let mut state = self.state.lock();
        Self::available(&state)?;
        let (released, _) = watch::channel(false);
        let signal = Arc::new(ClaimSignal { released });
        state.active = Arc::downgrade(&signal);
        Ok(RawGeometryClaim {
            state: Arc::clone(&self.state),
            signal,
            effects_started: false,
            complete: false,
        })
    }

    fn available(state: &ClaimState) -> Result<()> {
        if state.abandoned {
            return Err(Error::LaneGeometryAttemptAbandoned);
        }
        if let Some(active) = state.active.upgrade() {
            return Err(Error::LaneGeometryAttemptBusy {
                wait: RawGeometryWait {
                    released: active.released.subscribe(),
                },
            });
        }
        Ok(())
    }

    pub(in crate::kura) fn ensure_unclaimed(&self) -> Result<()> {
        Self::available(&self.state.lock())
    }
}

struct RawGeometryClaim {
    state: Arc<Mutex<ClaimState>>,
    signal: Arc<ClaimSignal>,
    effects_started: bool,
    complete: bool,
}

impl RawGeometryClaim {
    fn authorizes(&self, gate: &RawGeometryClaimGate) -> bool {
        let state = self.state.lock();
        Arc::ptr_eq(&self.state, &gate.state)
            && !state.abandoned
            && state.active.ptr_eq(&Arc::downgrade(&self.signal))
            && !self.complete
    }

    fn finish(&mut self) {
        self.complete = true;
        self.state.lock().active = Weak::new();
        self.signal.released.send_replace(true);
    }
}

impl Drop for RawGeometryClaim {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if state.active.ptr_eq(&Arc::downgrade(&self.signal)) {
            state.active = Weak::new();
            // A dropped partial temporary or reference mutation needs startup
            // recovery. Never let another live owner silently reconstruct it.
            state.abandoned |= self.effects_started && !self.complete;
        }
        drop(state);
        self.signal.released.send_replace(true);
    }
}

/// Observable operation progress, never a State or consensus authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawGeometryPhase {
    /// Purely captured request; no storage effects have run.
    Captured,
    /// Original pending GC and history reconciliation are being completed.
    Maintenance,
    /// Exact target journal/instance application is in progress.
    Applying,
    /// Files and original successor map are installed; caller still owns catalog publication.
    FilesApplied,
    /// The retained CatalogPublished phase is being made durable.
    PublishingCatalog,
    /// Owned inverse reference publication is in progress.
    RollingBack,
    /// Original provisioning crossed an effect boundary; Strict startup owns repair.
    RecoveryRequired,
    /// Catalog publication completed; the operation claim has been released.
    CatalogPublished,
    /// The original predecessor references and rollback journal are durable.
    RolledBack,
}

struct OwnedRequest {
    previous: LaneConfig,
    updated: LaneConfig,
    previous_incarnations: BTreeMap<LaneId, Hash>,
    updated_incarnations: BTreeMap<LaneId, Hash>,
    previous_activation_heights: BTreeMap<LaneId, u64>,
    updated_activation_heights: BTreeMap<LaneId, u64>,
    previous_lineage_root: Hash,
    updated_lineage_root: Hash,
    transition_height: u64,
    replaced: BTreeSet<LaneId>,
}

impl OwnedRequest {
    fn capture(request: &GeometryBindingRequest<'_>, replaced: &BTreeSet<LaneId>) -> Self {
        Self {
            previous: request.previous.clone(),
            updated: request.updated.clone(),
            previous_incarnations: request.previous_incarnations.clone(),
            updated_incarnations: request.updated_incarnations.clone(),
            previous_activation_heights: request.previous_activation_heights.clone(),
            updated_activation_heights: request.updated_activation_heights.clone(),
            previous_lineage_root: request.previous_lineage_root,
            updated_lineage_root: request.updated_lineage_root,
            transition_height: request.transition_height,
            replaced: replaced.clone(),
        }
    }

    fn matches(&self, request: &GeometryBindingRequest<'_>, replaced: &BTreeSet<LaneId>) -> bool {
        self.previous == *request.previous
            && self.updated == *request.updated
            && self.previous_incarnations == *request.previous_incarnations
            && self.updated_incarnations == *request.updated_incarnations
            && self.previous_activation_heights == *request.previous_activation_heights
            && self.updated_activation_heights == *request.updated_activation_heights
            && self.previous_lineage_root == request.previous_lineage_root
            && self.updated_lineage_root == request.updated_lineage_root
            && self.transition_height == request.transition_height
            && self.replaced == *replaced
    }
}

/// One maintenance journal replacement, retained before its first file write.
struct MaintenanceWrite {
    bytes: Box<[u8]>,
}

/// Maintains exact per-write custody through idempotent historical/GC stages.
#[derive(Default)]
pub(super) struct RawGeometryMaintenance {
    writer: Option<retained_journal::RetainedGeometryJournal>,
    pending: Option<MaintenanceWrite>,
}

impl RawGeometryMaintenance {
    fn flush(&mut self, kura: &Kura) -> Result<()> {
        if let Some(pending) = &mut self.pending {
            self.writer
                .as_mut()
                .ok_or_else(|| {
                    kura.geometry_error(
                        ErrorKind::InvalidData,
                        "maintenance lost its original journal writer",
                    )
                })?
                .persist(kura, LaneGeometryPhase::CatalogPublished, &pending.bytes)?;
            self.pending = None;
        }
        Ok(())
    }

    pub(super) fn write(&mut self, kura: &Kura, journal: &LaneGeometryJournal) -> Result<()> {
        self.flush(kura)?;
        kura.validate_lane_geometry_journal(journal)?;
        let bytes = journal.encode().into_boxed_slice();
        self.writer
            .as_mut()
            .ok_or_else(|| {
                kura.geometry_error(
                    ErrorKind::InvalidData,
                    "maintenance lost its original journal writer",
                )
            })?
            .prepare_next_write(bytes.len())?;
        self.pending = Some(MaintenanceWrite { bytes });
        self.flush(kura)
    }
}

/// A borrow of the exact operation claim and already-held physical fences.
pub(super) struct RawGeometryMutation<'attempt, 'kura> {
    lease: &'attempt KuraPublicationLease<'kura>,
    claim: &'attempt RawGeometryClaim,
    maintenance: &'attempt mut RawGeometryMaintenance,
}

impl RawGeometryMutation<'_, '_> {
    pub(super) fn authenticate(&self, kura: &Kura) -> Result<()> {
        if !self.lease.belongs_to(kura) || !self.claim.authorizes(&kura.raw_geometry_claim) {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "geometry mutation lost its original claim or Kura lease",
            ));
        }
        Ok(())
    }

    pub(super) fn write(&mut self, kura: &Kura, journal: &LaneGeometryJournal) -> Result<()> {
        self.authenticate(kura)?;
        self.maintenance.write(kura, journal)
    }
}

#[derive(Clone, Copy)]
enum TargetKind {
    Unchanged,
    Published,
    Retained,
    Fresh,
}

struct TargetPlan {
    kind: TargetKind,
    index: Option<usize>,
    desired_previous_count: usize,
}

struct RawGeometryProvisioningFailure {
    lane_id: LaneId,
    operation: usize,
    cause: Arc<Error>,
}
impl RawGeometryProvisioningFailure {
    fn error(&self) -> Error {
        Error::LaneGeometryInstanceRecoveryRequired {
            lane_id: self.lane_id,
            operation: self.operation,
            source: Arc::clone(&self.cause),
        }
    }
}

/// Exact request, original storage images and journal writer across local retry.
#[must_use = "retain the original geometry operation until catalog publication or owned rollback"]
pub(crate) struct RawGeometryAttempt {
    kura: KuraInstanceIdentity,
    request: OwnedRequest,
    previous_bindings: Vec<LaneGeometryBinding>,
    updated_bindings: Vec<LaneGeometryBinding>,
    previous_entries: Option<BTreeMap<LaneId, LaneStorageEntry>>,
    updated_entries: Option<BTreeMap<LaneId, LaneStorageEntry>>,
    journal: LaneGeometryJournal,
    journal_was_present: bool,
    plan: Option<TargetPlan>,
    maintenance: RawGeometryMaintenance,
    target: Option<PreparedGeometryJournalTransition>,
    pending_phase: Option<LaneGeometryPhase>,
    intent_complete: bool,
    operation_cursor: usize,
    provisioning_failure: Option<RawGeometryProvisioningFailure>,
    phase: RawGeometryPhase,
    catalog_baseline: CatalogPublicationBaseline,
    // Last: abandoned partial effects retain fail-closed exclusion after payload drop.
    claim: RawGeometryClaim,
}

/// Distinguish unpublished custody from a captured unconfigured catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogPublicationBaseline {
    Uncaptured,
    Captured(Option<Hash>),
}

impl std::fmt::Debug for RawGeometryAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawGeometryAttempt")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl KuraPublicationLease<'_> {
    /// Capture one exact operation before any filesystem/reference mutation.
    pub(crate) fn begin_raw_geometry_attempt(
        &self,
        request: &GeometryBindingRequest<'_>,
        replaced: &BTreeSet<LaneId>,
    ) -> Result<RawGeometryAttempt> {
        let kura = self.original_kura();
        kura.durable_mutation_authorized()?;
        kura.require_raw_geometry_canonical_recovery_complete()?;
        kura.ensure_nonzero_lineage_root(request.previous_lineage_root)?;
        kura.ensure_nonzero_lineage_root(request.updated_lineage_root)?;
        request.validate_additions_only(replaced)?;
        let claim = kura.raw_geometry_claim.claim()?;
        let previous_bindings = kura.geometry_bindings(
            request.previous,
            request.previous_incarnations,
            request.previous_activation_heights,
        )?;
        let updated_bindings = kura.geometry_bindings(
            request.updated,
            request.updated_incarnations,
            request.updated_activation_heights,
        )?;
        let previous_entries = kura.lane_storage_entries_from_geometry(
            request.previous,
            request.previous_incarnations,
            request.previous_activation_heights,
        )?;
        let updated_entries = kura.lane_storage_entries_from_geometry(
            request.updated,
            request.updated_incarnations,
            request.updated_activation_heights,
        )?;
        let journal_was_present = !kura.store_root.as_os_str().is_empty()
            && kura.validate_path_kind(&kura.lane_geometry_journal_path(), false)?;
        let journal = if kura.store_root.as_os_str().is_empty() {
            LaneGeometryJournal::default()
        } else {
            kura.read_lane_geometry_journal_structure()?
        };
        let maintenance = if kura.store_root.as_os_str().is_empty() {
            RawGeometryMaintenance::default()
        } else {
            let writer =
                retained_journal::RetainedGeometryJournal::capture(kura, journal.encode().len())?;
            let observed = writer
                .predecessor()
                .map(|bytes| decode_exact::<LaneGeometryJournal>(bytes).map_err(Error::NoritoFrame))
                .transpose()?
                .unwrap_or_default();
            if observed != journal {
                return Err(kura.geometry_error(
                    ErrorKind::InvalidData,
                    "geometry journal changed during original operation capture",
                ));
            }
            RawGeometryMaintenance {
                writer: Some(writer),
                pending: None,
            }
        };
        Ok(RawGeometryAttempt {
            kura: kura.instance_identity(),
            request: OwnedRequest::capture(request, replaced),
            previous_bindings,
            updated_bindings,
            previous_entries: Some(previous_entries),
            updated_entries: Some(updated_entries),
            journal,
            journal_was_present,
            plan: None,
            maintenance,
            target: None,
            pending_phase: None,
            intent_complete: false,
            operation_cursor: 0,
            provisioning_failure: None,
            phase: RawGeometryPhase::Captured,
            catalog_baseline: CatalogPublicationBaseline::Uncaptured,
            claim,
        })
    }
}

impl RawGeometryAttempt {
    #[cfg(test)]
    pub(super) fn surrender_structural_fixture(&mut self) {
        // Old storage fixtures inspect a durable FilesApplied image separately
        // from their explicit catalog/recovery call. No pending write is ever
        // surrendered, and production callers have no access to this adapter.
        if !self.has_pending_journal_write() && self.phase == RawGeometryPhase::FilesApplied {
            self.claim.finish();
        }
    }

    /// Return the original local recovery cause before any other owner reverses effects.
    pub(crate) fn recovery_refusal(&self) -> Option<Error> {
        self.provisioning_failure
            .as_ref()
            .map(RawGeometryProvisioningFailure::error)
    }

    pub(crate) fn phase(&self) -> RawGeometryPhase {
        self.phase
    }

    /// Comparison only: equal request bytes cannot create or replace this owner.
    pub(crate) fn matches_request(
        &self,
        request: &GeometryBindingRequest<'_>,
        replaced: &BTreeSet<LaneId>,
    ) -> bool {
        self.request.matches(request, replaced)
    }

    pub(crate) fn has_pending_journal_write(&self) -> bool {
        self.pending_phase.is_some() || self.maintenance.pending.is_some()
    }

    fn authenticate<'lease>(
        &self,
        lease: &'lease KuraPublicationLease<'_>,
    ) -> Result<&'lease Kura> {
        let kura = lease.original_kura();
        if !self.kura.matches(kura) || !self.claim.authorizes(&kura.raw_geometry_claim) {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "raw geometry attempt belongs to another Kura or released claim",
            ));
        }
        if let Some(failure) = &self.provisioning_failure {
            return Err(failure.error());
        }
        kura.ensure_prune_recovery_not_required()?;
        kura.durable_mutation_authorized()?;
        kura.require_raw_geometry_canonical_recovery_complete()?;
        Ok(kura)
    }

    fn persist_target(&mut self, kura: &Kura, phase: LaneGeometryPhase) -> Result<()> {
        if self.pending_phase.is_some_and(|pending| pending != phase) {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "pending geometry journal phase must complete before changing direction",
            ));
        }
        self.pending_phase = Some(phase);
        self.target
            .as_mut()
            .ok_or_else(|| {
                kura.geometry_error(
                    ErrorKind::InvalidData,
                    "geometry attempt lost its original target writer",
                )
            })?
            .persist(kura, phase)?;
        self.pending_phase = None;
        Ok(())
    }

    fn prepare_target(
        &mut self,
        kura: &Kura,
        index: usize,
    ) -> Result<PreparedGeometryJournalTransition> {
        PreparedGeometryJournalTransition::prepare_with_retained_writer(
            kura,
            self.journal.clone(),
            index,
            &mut self.maintenance.writer,
        )
    }

    fn select_plan(&self, kura: &Kura) -> Result<TargetPlan> {
        let previous_catalog = geometry_catalog_fingerprint(&self.previous_bindings);
        let updated_catalog = geometry_catalog_fingerprint(&self.updated_bindings);
        let current = self
            .journal
            .records
            .iter()
            .position(|r| r.phase == LaneGeometryPhase::RolledBack)
            .unwrap_or(self.journal.records.len());
        let matches = |index: usize| {
            self.journal.records.get(index).is_some_and(|record| {
                record.transition_height == self.request.transition_height
                    && record.previous_catalog == previous_catalog
                    && record.previous_lineage_root == self.request.previous_lineage_root
                    && record.updated_catalog == updated_catalog
                    && record.updated_lineage_root == self.request.updated_lineage_root
            })
        };
        let uncertain = self.journal.records.iter().position(|record| {
            matches!(
                record.phase,
                LaneGeometryPhase::Intent | LaneGeometryPhase::FilesApplied
            )
        });
        let frontier = uncertain.filter(|index| matches(*index)).or_else(|| {
            (current < self.journal.records.len() && matches(current)).then_some(current)
        });
        let published = current.checked_sub(1).filter(|index| {
            self.journal.records[*index].phase == LaneGeometryPhase::CatalogPublished
                && matches(*index)
        });
        let retained = frontier.or(published).or_else(|| {
            let mut candidates = (0..self.journal.records.len()).filter(|index| matches(*index));
            let first = candidates.next()?;
            candidates.next().is_none().then_some(first)
        });
        if let Some(index) = retained {
            let record = &self.journal.records[index];
            if record.previous_bindings != self.previous_bindings
                || record.updated_bindings != self.updated_bindings
            {
                return Err(kura.geometry_error(
                    ErrorKind::InvalidData,
                    "lane geometry transition id collides with a different exact identity",
                ));
            }
            return Ok(TargetPlan {
                kind: if published == Some(index) {
                    TargetKind::Published
                } else {
                    TargetKind::Retained
                },
                index: Some(index),
                desired_previous_count: index,
            });
        }
        if previous_catalog == updated_catalog
            && self.request.previous_lineage_root == self.request.updated_lineage_root
        {
            return Ok(TargetPlan {
                kind: TargetKind::Unchanged,
                index: None,
                desired_previous_count: current,
            });
        }
        if current != self.journal.records.len() {
            return Err(kura.geometry_error(
                ErrorKind::InvalidData,
                "lane geometry cannot branch across a retained rolled-back transition",
            ));
        }
        Ok(TargetPlan {
            kind: TargetKind::Fresh,
            index: None,
            desired_previous_count: current,
        })
    }

    /// Resume only the original apply direction; errors leave all original custody here.
    pub(crate) fn resume_under(&mut self, lease: &KuraPublicationLease<'_>) -> Result<()> {
        let kura = self.authenticate(lease)?;
        match self.phase {
            RawGeometryPhase::FilesApplied => return Ok(()),
            RawGeometryPhase::Captured
            | RawGeometryPhase::Maintenance
            | RawGeometryPhase::Applying => {}
            _ => {
                return Err(kura.geometry_error(
                    ErrorKind::InvalidInput,
                    "geometry apply cannot replace its current publication or rollback direction",
                ));
            }
        }
        if kura.store_root.as_os_str().is_empty() {
            self.claim.effects_started = true;
            if let Some(entries) = self.updated_entries.take() {
                *kura.lane_storage_entries.lock() = entries;
            }
            self.phase = RawGeometryPhase::FilesApplied;
            return Ok(());
        }
        self.maintenance.flush(kura)?;
        if self.phase == RawGeometryPhase::Captured {
            self.phase = RawGeometryPhase::Maintenance;
        }
        if self.phase == RawGeometryPhase::Maintenance {
            self.claim.effects_started = true;
            // Validate the retained journal before choosing any physical operation.
            kura.validate_lane_geometry_journal(&self.journal)?;
            if self.plan.is_none() {
                self.plan = Some(self.select_plan(kura)?);
            }
            let plan = self.plan.as_ref().ok_or_else(|| {
                kura.geometry_error(
                    ErrorKind::InvalidData,
                    "geometry attempt lost its exact target plan",
                )
            })?;
            if !matches!(plan.kind, TargetKind::Published) {
                let mut mutation = RawGeometryMutation {
                    lease,
                    claim: &self.claim,
                    maintenance: &mut self.maintenance,
                };
                kura.reconcile_lane_geometry_history_to_count_with_custody(
                    &mut self.journal,
                    geometry_catalog_fingerprint(&self.previous_bindings),
                    self.request.previous_lineage_root,
                    plan.desired_previous_count,
                    Some(&mut mutation),
                )?;
                kura.ensure_authoritative_lane_markers(
                    &self.request.previous,
                    &self.request.previous_incarnations,
                    &self.request.previous_activation_heights,
                )?;
            }
            self.phase = RawGeometryPhase::Applying;
        }
        let kind = self
            .plan
            .as_ref()
            .ok_or_else(|| {
                kura.geometry_error(
                    ErrorKind::InvalidData,
                    "geometry attempt lost its target plan",
                )
            })?
            .kind;
        if matches!(kind, TargetKind::Unchanged) {
            if self.journal_was_present || self.journal != LaneGeometryJournal::default() {
                self.maintenance.write(kura, &self.journal)?;
            }
        } else {
            if self.target.is_none() {
                let plan = self.plan.as_mut().ok_or_else(|| {
                    kura.geometry_error(
                        ErrorKind::InvalidData,
                        "geometry attempt lost its target plan",
                    )
                })?;
                if plan.index.is_none() {
                    let last = self
                        .journal
                        .records
                        .iter()
                        .map(|r| r.transition_sequence)
                        .max();
                    let sequence = last.map_or(Ok(0), |last| {
                        last.checked_add(1).ok_or_else(|| {
                            kura.geometry_error(
                                ErrorKind::InvalidData,
                                "lane geometry transition sequence overflow",
                            )
                        })
                    })?;
                    let previous_catalog = geometry_catalog_fingerprint(&self.previous_bindings);
                    let updated_catalog = geometry_catalog_fingerprint(&self.updated_bindings);
                    let id = geometry_transition_id(
                        sequence,
                        self.request.transition_height,
                        previous_catalog,
                        self.request.previous_lineage_root,
                        updated_catalog,
                        self.request.updated_lineage_root,
                    );
                    let operations = kura.build_geometry_operations(
                        id,
                        &self.previous_bindings,
                        &self.updated_bindings,
                        &self.request.replaced,
                    )?;
                    self.journal.records.push(LaneGeometryIntent {
                        transition_id: id,
                        transition_sequence: sequence,
                        transition_height: self.request.transition_height,
                        previous_catalog,
                        previous_lineage_root: self.request.previous_lineage_root,
                        updated_catalog,
                        updated_lineage_root: self.request.updated_lineage_root,
                        previous_bindings: self.previous_bindings.clone(),
                        updated_bindings: self.updated_bindings.clone(),
                        phase: LaneGeometryPhase::Intent,
                        operations,
                    });
                    plan.index = Some(self.journal.records.len() - 1);
                }
                let index = plan.index.ok_or_else(|| {
                    kura.geometry_error(
                        ErrorKind::InvalidData,
                        "geometry target has no journal record",
                    )
                })?;
                // All semantic preparation must precede moving the sole retained
                // descriptor. Preserve it if any preparation step refuses.
                self.target = Some(self.prepare_target(kura, index)?);
            }
            if matches!(kind, TargetKind::Fresh) && !self.intent_complete {
                self.persist_target(kura, LaneGeometryPhase::Intent)?;
                self.intent_complete = true;
            }
            let policy = if matches!(kind, TargetKind::Fresh) {
                GeometryEvidencePolicy::FreshJournalIntent
            } else {
                GeometryEvidencePolicy::RequireDurableEvidence
            };
            let target = self.target.as_ref().ok_or_else(|| {
                kura.geometry_error(ErrorKind::InvalidData, "geometry target writer is missing")
            })?;
            while self.operation_cursor < target.operations().len() {
                let operation = &target.operations()[self.operation_cursor];
                let mut provisioning_started = false;
                if let Err(cause) = kura.apply_geometry_operations_forward_with_progress(
                    std::slice::from_ref(operation),
                    policy,
                    Some(&mut provisioning_started),
                ) {
                    if matches!(kind, TargetKind::Fresh) && provisioning_started {
                        let failure = RawGeometryProvisioningFailure {
                            lane_id: operation.lane_id,
                            operation: self.operation_cursor,
                            cause: Arc::new(cause),
                        };
                        let error = failure.error();
                        self.provisioning_failure = Some(failure);
                        self.phase = RawGeometryPhase::RecoveryRequired;
                        return Err(error);
                    }
                    return Err(cause);
                }
                self.operation_cursor += 1;
            }
            if !matches!(kind, TargetKind::Published) {
                self.persist_target(kura, LaneGeometryPhase::FilesApplied)?;
            }
        }
        kura.ensure_authoritative_lane_markers(
            &self.request.updated,
            &self.request.updated_incarnations,
            &self.request.updated_activation_heights,
        )?;
        if let Some(entries) = self.updated_entries.take() {
            *kura.lane_storage_entries.lock() = entries;
        }
        self.phase = RawGeometryPhase::FilesApplied;
        Ok(())
    }

    /// Publish the retained target phase, retaining renamed-file custody on failure.
    pub(crate) fn publish_catalog_under(
        &mut self,
        lease: &KuraPublicationLease<'_>,
        configured_baseline: Option<Hash>,
    ) -> Result<()> {
        let kura = self.authenticate(lease)?;
        if !matches!(
            self.phase,
            RawGeometryPhase::FilesApplied | RawGeometryPhase::PublishingCatalog
        ) {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "catalog publication requires the original completed geometry apply",
            ));
        }
        if let CatalogPublicationBaseline::Captured(original) = self.catalog_baseline
            && original != configured_baseline
        {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "catalog publication changed its original configured baseline",
            ));
        }
        if let Some(expected) = configured_baseline {
            if self.journal.configured_catalog_hash != Some(expected)
                || self.journal.configured_primary_binding.as_ref() != self.updated_bindings.first()
            {
                return Err(kura.geometry_error(
                    ErrorKind::InvalidData,
                    "configured catalog publication differs from its authenticated original anchor",
                ));
            }
            let primary = self.updated_bindings.first().ok_or_else(|| {
                kura.geometry_error(
                    ErrorKind::InvalidData,
                    "configured catalog has no primary binding",
                )
            })?;
            if primary.lane_id != LaneId::SINGLE || primary.activation_height != 0 {
                return Err(kura.geometry_error(
                    ErrorKind::InvalidData,
                    "configured primary binding is not lane zero at activation zero",
                ));
            }
            kura.require_lane_marker(primary)?;
        }
        #[cfg(test)]
        if kura
            .fail_next_lane_geometry_publication
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(kura.geometry_error(
                ErrorKind::Other,
                "lane geometry publication failed for test injection",
            ));
        }
        self.catalog_baseline = CatalogPublicationBaseline::Captured(configured_baseline);
        self.phase = RawGeometryPhase::PublishingCatalog;
        if self.target.is_some() {
            self.persist_target(kura, LaneGeometryPhase::CatalogPublished)?;
        }
        #[cfg(test)]
        if kura
            .fail_next_lane_geometry_publication_after_write
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(kura.geometry_error(
                ErrorKind::Other,
                "lane geometry publication failed after journal replacement for test injection",
            ));
        }
        self.phase = RawGeometryPhase::CatalogPublished;
        self.claim.finish();
        Ok(())
    }

    /// Rejoin a completed operation to its original journal and installed identities.
    /// This read cannot reacquire a claim or authorize another geometry mutation.
    pub(crate) fn reauthenticate_catalog_under(
        &self,
        lease: &KuraPublicationLease<'_>,
        configured_baseline: Option<Hash>,
    ) -> Result<()> {
        let kura = lease.original_kura();
        if !self.kura.matches(kura)
            || self.phase != RawGeometryPhase::CatalogPublished
            || (!cfg!(all(test, sumeragi_core_mutation = "HC256"))
                && self.catalog_baseline
                    != CatalogPublicationBaseline::Captured(configured_baseline))
            || !self.claim.complete
            || self.has_pending_journal_write()
        {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "geometry completion requires its original completed catalog owner",
            ));
        }
        kura.ensure_prune_recovery_not_required()?;
        kura.durable_mutation_authorized()?;
        kura.require_raw_geometry_canonical_recovery_complete()?;
        kura.raw_geometry_claim.ensure_unclaimed()?;
        if let Some(target) = &self.target {
            target.reauthenticate_completed(kura, LaneGeometryPhase::CatalogPublished)?;
        } else if let Some(writer) = &self.maintenance.writer {
            writer.reauthenticate_current(kura)?;
        } else if !kura.store_root.as_os_str().is_empty() {
            return Err(kura.geometry_error(
                ErrorKind::InvalidData,
                "geometry completion lost its original physical journal owner",
            ));
        }
        let installed = kura.lane_storage_entries.lock();
        if installed.len() != self.updated_bindings.len()
            || self.updated_bindings.iter().any(|binding| {
                installed.get(&binding.lane_id).map(|entry| entry.identity)
                    != Some(binding.identity())
            })
        {
            return Err(kura.geometry_error(
                ErrorKind::InvalidData,
                "geometry completion differs from its original installed successor",
            ));
        }
        Ok(())
    }

    /// Complete a chosen rollback without replacing a pending journal phase.
    pub(crate) fn rollback_under(&mut self, lease: &KuraPublicationLease<'_>) -> Result<()> {
        let kura = self.authenticate(lease)?;
        if self.maintenance.pending.is_some()
            || self.pending_phase.is_some_and(|phase| {
                self.phase != RawGeometryPhase::RollingBack
                    || phase != LaneGeometryPhase::RolledBack
            })
        {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "pending geometry journal write must finish before owned rollback",
            ));
        }
        if matches!(
            self.phase,
            RawGeometryPhase::PublishingCatalog
                | RawGeometryPhase::CatalogPublished
                | RawGeometryPhase::RolledBack
        ) {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "geometry publication direction cannot be replaced by rollback",
            ));
        }
        if self.phase == RawGeometryPhase::Captured {
            self.phase = RawGeometryPhase::RolledBack;
            self.claim.finish();
            return Ok(());
        }
        if self.phase == RawGeometryPhase::Maintenance {
            return Err(kura.geometry_error(
                ErrorKind::InvalidInput,
                "owned geometry maintenance must complete before rollback",
            ));
        }
        if self.phase != RawGeometryPhase::RollingBack {
            self.operation_cursor = 0;
            self.phase = RawGeometryPhase::RollingBack;
        }
        if let Some(target) = &self.target {
            let policy = if self
                .plan
                .as_ref()
                .is_some_and(|p| matches!(p.kind, TargetKind::Fresh))
            {
                GeometryEvidencePolicy::AllowJournalIntentProvisioning
            } else {
                GeometryEvidencePolicy::RequireDurableEvidence
            };
            while self.operation_cursor < target.operations().len() {
                let index = target.operations().len() - self.operation_cursor - 1;
                kura.apply_geometry_operations_rollback(
                    &target.operations()[index..=index],
                    policy,
                )?;
                self.operation_cursor += 1;
            }
            self.persist_target(kura, LaneGeometryPhase::RolledBack)?;
        }
        if !kura.store_root.as_os_str().is_empty() {
            kura.ensure_authoritative_lane_markers(
                &self.request.previous,
                &self.request.previous_incarnations,
                &self.request.previous_activation_heights,
            )?;
        }
        if let Some(entries) = self.previous_entries.take() {
            *kura.lane_storage_entries.lock() = entries;
        }
        self.phase = RawGeometryPhase::RolledBack;
        self.claim.finish();
        Ok(())
    }
}

impl Kura {
    /// The original canonical resolver owns repair at Strict startup. A retained
    /// geometry operation may inspect this boundary under its joint lease, but
    /// cannot repair canonical storage or reacquire its original locks.
    fn require_raw_geometry_canonical_recovery_complete(&self) -> Result<()> {
        if self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        let store = self.block_store.lock();
        if store.deferred_da_recovery_fault.is_some()
            || store.read_eviction_compaction_stage()?.is_some()
            || store.read_da_block_rewrite_stage()?.is_some()
        {
            return Err(Error::LaneGeometryCanonicalRecoveryRequired);
        }
        drop(store);
        Ok(())
    }
}
