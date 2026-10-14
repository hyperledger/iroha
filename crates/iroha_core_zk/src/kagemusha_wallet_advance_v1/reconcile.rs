//! Startup and pre-operation reconciliation (spec §4.2 step 1, §§1.2, 3.2; G2 design rev 2
//! §5 R0-R10).
//!
//! Before any operation the provider reconciles every marker generation and journal record of
//! the slot:
//!
//! - **R0** protected storage must be available (the custody lock is held by the provider);
//! - **R2** the current marker is the highest generation, read strictly; it is compared with
//!   the iOS anchor before anything is written, and **R4** the payment key must be present and
//!   equal to the marker's;
//! - **R1** staging files are removed; **R3** the current marker is adopted durably
//!   (fresh-inode rewrite when it may hold an unacknowledged write of this boot; on a full
//!   disk such rewrites and copy repairs may draw the ballast);
//! - **R5** the capsule bound by a head is loaded from either copy and repaired, with the
//!   completion record under a Selected head (adopted, or its invalid never-released copies
//!   removed) or the retained record under a Released head (`CompletionLost` when every copy is
//!   gone; never a reason to sign again);
//! - **R6** a completion record, tombstone or capsule above the current marker is evidence of a
//!   rolled-back marker set: reconciliation stops and discards nothing; **R7** staging that no
//!   marker binds is discarded; **R8** lower generations are retired by name;
//! - **R9** a Selected head is finished offline (receipt, record, Released marker) and a
//!   lagging anchor is raised. Every fully reconciled anchor also requires an acknowledged
//!   exact mutation: a visible value can belong to an earlier uncertain write;
//! - **R10** without any marker, an intent whose key is definitively absent may continue
//!   enrollment, an intent with a key is abandoned (never used), and a key or any journal
//!   record without a marker is lost custody. No slot, key or file is deleted on these paths.
//!
//! A slot verified by a full reconcile is cached, a selected head waiting for its receipt
//! included; later operations re-list `markers/` and compare the current marker's exact
//! bytes, and fall back to a full reconcile on any difference or after any error. A cached
//! selected head is finished again when a transition owner is given, without rewriting its
//! files a second time. Rollback by restore happens while the app is not running, so every new
//! provider reconciles each slot fully, anchor check included.
//!
//! A read, listing, lock, key-store or storage error is `Unavailable` at every step: nothing is
//! inferred from it, and no loss is classified from it. Protected storage is checked at R0,
//! around every key probe, before a receipt is signed after a record was found absent, before
//! a slot is abandoned, and again at the end of every full reconcile: an answer read while
//! storage locked (Android credential-encrypted names read as absent while their keys are
//! evicted) is replaced by `Unavailable`.
//!
//! Once a Selected marker is durable, R9 failures other than custody loss leave the slot
//! `Pending` (the reason is kept by the provider); they are never reported as errors.

use iroha_data_model::kagemusha::KagemushaWalletTerminalReasonV1;

use super::{
    KagemushaWalletEnrollmentPhaseV1, KagemushaWalletLostCustodyV1, KagemushaWalletProviderErrorV1,
    advance::FinishedV1,
    advance::{KagemushaWalletAdvanceCapsuleV1, KagemushaWalletTransitionOwnerV1},
    anchor::{kagemusha_wallet_check_anchor_v1, kagemusha_wallet_raise_anchor_v1},
    capsule::{
        KagemushaWalletLoadedPairV1, kagemusha_wallet_list_capsules_v1,
        kagemusha_wallet_load_capsule_v1, kagemusha_wallet_repair_pair_v1,
        kagemusha_wallet_settle_pair_v1, remove_pair,
    },
    completion::{
        KagemushaWalletCompletionExpectationV1, KagemushaWalletCompletionFrameV1,
        kagemusha_wallet_completion_names_v1, kagemusha_wallet_load_completion_v1,
    },
    layout::{
        KAGEMUSHA_WALLET_ABANDONED_NAME_V1, KAGEMUSHA_WALLET_ABANDONMENT_NAME_V1,
        KAGEMUSHA_WALLET_ABANDONMENT_SELECTION_NAME_V1, KAGEMUSHA_WALLET_ARCHIVE_DIR_NAME_V1,
        KAGEMUSHA_WALLET_CAPSULES_DIR_NAME_V1, KAGEMUSHA_WALLET_COMPLETION_DIR_NAME_V1,
        KAGEMUSHA_WALLET_ENROLLMENT_NAME_V1, KAGEMUSHA_WALLET_INTENT_NAME_V1,
        KAGEMUSHA_WALLET_KEY_GENERATION_ATTEMPT_NAME_V1, KAGEMUSHA_WALLET_MARKERS_DIR_NAME_V1,
        KAGEMUSHA_WALLET_OPS_DIR_NAME_V1, KagemushaWalletCopyV1, KagemushaWalletCustodyDirV1,
        KagemushaWalletSlotIdV1, kagemusha_wallet_capsule_name_v1,
        kagemusha_wallet_capsules_dir_v1, kagemusha_wallet_completion_dir_v1,
        kagemusha_wallet_is_staging_name_v1, kagemusha_wallet_list_dir_v1,
        kagemusha_wallet_markers_dir_v1, kagemusha_wallet_ops_dir_v1,
        kagemusha_wallet_parse_credential_name_v1, kagemusha_wallet_probe_dir_v1,
        kagemusha_wallet_require_removed_v1, kagemusha_wallet_slot_dir_v1,
        kagemusha_wallet_slots_dir_v1,
    },
    marker::{
        KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1, KagemushaWalletDurableMarkerV1,
        KagemushaWalletMarkerPhaseV1, KagemushaWalletMarkerRecordV1,
        kagemusha_wallet_adopt_marker_v1, kagemusha_wallet_list_markers_v1,
        kagemusha_wallet_load_current_marker_v1, kagemusha_wallet_retire_markers_v1,
    },
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletPlatformV1,
        KagemushaWalletProbeV1, KagemushaWalletReadV1, KagemushaWalletUnavailableV1,
    },
    provider::{KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1},
    retained::highest_retained_generation,
};

/// Reason a slot was abandoned before any marker (recorded in `abandoned.norito`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletSlotAbandonReasonV1 {
    /// A payment key existed for the slot without a marker; it is never used (spec §4.2).
    KeyWithoutMarker,
    /// The enrollment challenge expired before the marker was written.
    ChallengeExpired,
    /// The holder abandoned an enrollment that never had a marker (design §3.2 no-marker
    /// form): no key is ever probed, adopted, generated or initialized under the slot again.
    HolderAbandoned,
}

impl KagemushaWalletSlotAbandonReasonV1 {
    /// Stored tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::KeyWithoutMarker => 1,
            Self::ChallengeExpired => 2,
            Self::HolderAbandoned => 3,
        }
    }

    /// Reason of a stored tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::KeyWithoutMarker),
            2 => Some(Self::ChallengeExpired),
            3 => Some(Self::HolderAbandoned),
            _ => None,
        }
    }
}

/// Classified top level of one slot directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct SlotFilesV1 {
    pub(super) intent: bool,
    pub(super) generation_attempt: bool,
    pub(super) abandoned: bool,
    pub(super) journal: bool,
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Reconcile only after preserving any successful generation reply held by this owner.
    /// An abandoned slot without a marker is terminal first: generation recovery checks the
    /// abandoned-slot record before it touches a retained reply, and reconciliation without a
    /// marker returns `SlotAbandoned` before any key probe (design §3.2).
    pub(super) fn reconcile_slot(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: Option<&dyn KagemushaWalletTransitionOwnerV1<C, R>>,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        self.recover_generated_key(slot)?;
        self.reconcile_slot_after_generation(slot, owner)
    }

    /// Whether `slot` is terminally abandoned without a marker, read strictly inside storage
    /// brackets; never probes the key. A present record is decoded and made durable (file and
    /// directory synchronized) before it counts, so a visible but unsynchronized record from an
    /// uncertain write never reports a terminal state. A record that coexists with a marker or
    /// journal record is conflicting custody. On `true` any retained generation dispatch or reply
    /// of the slot is dropped, never adopted. Unavailable or uncertain storage stays an error,
    /// never "abandoned" or "not abandoned", and preserves the retained state.
    pub(super) fn abandoned_without_marker(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<bool, KagemushaWalletProviderErrorV1> {
        self.require_storage()?;
        let files = self.slot_files(slot)?;
        if !files.abandoned {
            return Ok(false);
        }
        if files.journal
            || kagemusha_wallet_load_current_marker_v1(&self.store, slot, &self.scheme_id)?
                .is_some()
        {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "abandoned slot custody conflict",
            });
        }
        let adopted = self.adopt_abandoned_record(slot);
        self.guard(slot, adopted)?;
        self.require_storage()?;
        self.generation_dispatches.remove(slot);
        self.generation_results.remove(slot);
        self.poison(slot);
        Ok(true)
    }

    /// Refuse a marker whose slot also holds an abandoned-slot record: the two are conflicting
    /// custody, never a usable head. A single strict read; nothing is written.
    fn require_not_abandoned(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        match self.store.read(
            &kagemusha_wallet_slot_dir_v1(slot),
            &super::layout::kagemusha_wallet_fixed_name_v1(KAGEMUSHA_WALLET_ABANDONED_NAME_V1),
            0,
        ) {
            KagemushaWalletReadV1::Absent => Ok(()),
            KagemushaWalletReadV1::Unavailable(reason) => {
                Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
            }
            KagemushaWalletReadV1::Present(_) | KagemushaWalletReadV1::Oversized => {
                Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "abandoned slot custody conflict",
                })
            }
        }
    }

    /// A genuine in-memory reply cannot revive an abandoned slot or conceal prior journals.
    pub(super) fn require_recoverable_generation_slot(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let files = self.slot_files(slot)?;
        if !files.intent || files.abandoned || files.journal {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "generation slot custody",
            });
        }
        Ok(())
    }

    /// Ordinary reconciliation after generation reply custody; never invokes generation.
    pub(super) fn reconcile_slot_after_generation(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: Option<&dyn KagemushaWalletTransitionOwnerV1<C, R>>,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        // R0.
        self.require_storage()?;
        if let Some(status) = self.cached_status(slot)? {
            // A verified marker beside an abandoned-slot record is conflicting custody.
            let conflict = self.require_not_abandoned(slot);
            self.guard(slot, conflict)?;
            // The enrollment phase verified with the cached marker must be unchanged; any other
            // version is reconciled (and authenticated) in full again.
            let unchanged = self.verified_phase_unchanged(slot);
            if self.guard(slot, unchanged)? {
                if let Some(record) = status.marker() {
                    let result = self.require_archive_checkpoint(record);
                    self.require_storage()?;
                    self.guard(slot, result)?;
                }
                return match (status, owner) {
                    (KagemushaWalletSlotStatusV1::Pending(record), Some(owner)) => {
                        let result = self.finish_cached_pending(slot, owner, record);
                        self.guard(slot, result)
                    }
                    (status, _) => Ok(status),
                };
            }
            self.poison(slot);
        }
        let result = self.reconcile_full(slot, owner).and_then(|status| {
            if let Some(record) = status.marker() {
                self.require_archive_checkpoint(record)?;
            }
            Ok(status)
        });
        // Every answer of this reconcile counts only while storage stayed available.
        let result = self.require_storage().and(result);
        self.guard(slot, result)
    }

    /// R9 for a selected head verified by an earlier full reconcile of this process: its
    /// unacknowledged files are already rewritten, so only the capsule is read again and the
    /// finishing steps are retried.
    fn finish_cached_pending(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
        record: KagemushaWalletMarkerRecordV1,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        let durable = self
            .cache
            .get(slot)
            .map(|cached| cached.durable.clone())
            .filter(|durable| durable.record() == &record)
            .ok_or(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            ))?;
        let (Some(selected_generation), Some((_, _, capsule_digest))) =
            (record.selected_generation(), record.head())
        else {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.phase",
            });
        };
        let capsule = kagemusha_wallet_load_capsule_v1::<F, C>(
            &self.store,
            slot,
            selected_generation,
            &capsule_digest,
            &C::marker_binding(record.marker()),
        )?;
        let boot = self.boot();
        let finished =
            self.finish_selected(slot, owner, &durable, capsule.value(), &[], &boot, None);
        Self::finished_status(record, finished)
    }

    /// Status after an R9 attempt on the Selected head `record`: released, or still pending for
    /// every failure except custody loss (the operation is performed; the reason is kept).
    fn finished_status(
        record: KagemushaWalletMarkerRecordV1,
        finished: Result<FinishedV1<R>, KagemushaWalletProviderErrorV1>,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        match finished {
            Ok(FinishedV1::Released(_, released)) => Ok(KagemushaWalletSlotStatusV1::Released(
                released.record().clone(),
            )),
            Err(
                error @ (KagemushaWalletProviderErrorV1::LostCustody(_)
                | KagemushaWalletProviderErrorV1::KeyLost),
            ) => Err(error),
            Ok(FinishedV1::Stalled(_)) | Err(_) => Ok(KagemushaWalletSlotStatusV1::Pending(record)),
        }
    }

    /// Status of a slot verified earlier whose marker set is unchanged on disk.
    fn cached_status(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<Option<KagemushaWalletSlotStatusV1>, KagemushaWalletProviderErrorV1> {
        let Some(cached) = self.cache.get(slot) else {
            return Ok(None);
        };
        let record = cached.durable.record();
        let Some(listing) = kagemusha_wallet_list_markers_v1(&self.store, slot)? else {
            return Ok(None);
        };
        if listing.generations.as_slice() != [record.generation()] || !listing.staging.is_empty() {
            return Ok(None);
        }
        match self.store.read(
            &kagemusha_wallet_markers_dir_v1(slot),
            &record.file_name(),
            KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1,
        ) {
            KagemushaWalletReadV1::Present(bytes) if bytes == record.file_bytes() => {
                Ok(Some(cached.status.clone()))
            }
            KagemushaWalletReadV1::Unavailable(reason) => {
                Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
            }
            _ => Ok(None),
        }
    }

    fn reconcile_full(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: Option<&dyn KagemushaWalletTransitionOwnerV1<C, R>>,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        self.poison(slot);
        let boot = self.boot();
        // R2: read-only selection and checks before anything is written.
        let Some(current) =
            kagemusha_wallet_load_current_marker_v1(&self.store, slot, &self.scheme_id)?
        else {
            return self.reconcile_without_marker(slot);
        };
        self.require_not_abandoned(slot)?;
        // The authenticated enrollment phase names this marker before any effect.
        self.require_marker_phase(current.record())?;
        kagemusha_wallet_check_anchor_v1(&self.platform, current.record())?;
        let phase = current.record().phase();
        if phase != KagemushaWalletMarkerPhaseV1::Terminal {
            self.require_payment_key(current.record())?; // R4
        }
        // R1, R3.
        self.remove_all_staging(slot)?;
        // Fresh-inode rewrites need space: on a full disk they may draw the ballast.
        let durable = self.with_ballast(true, || {
            kagemusha_wallet_adopt_marker_v1(&self.store, &current, &boot)
        })?;
        let record = durable.record().clone();
        match phase {
            KagemushaWalletMarkerPhaseV1::Enrollment => {
                self.reconcile_journal(&durable)?;
                kagemusha_wallet_retire_markers_v1(&self.store, &durable, current.lower())?;
                // The pre-key phase commits this exact durable marker before it is used.
                self.commit_enrollment_marker_phase(&record)?;
                kagemusha_wallet_raise_anchor_v1(&self.platform, &record)?;
                let status = KagemushaWalletSlotStatusV1::Enrollment(record);
                self.remember(slot, durable, status.clone());
                Ok(status)
            }
            KagemushaWalletMarkerPhaseV1::Selected => {
                // R6 first: rollback evidence stops reconciliation before any repair or
                // discard touches a record.
                self.reconcile_journal(&durable)?;
                let capsule = self.settle_capsule(&durable, &boot, true)?;
                self.settle_selected_completion(&durable, &boot)?;
                kagemusha_wallet_retire_markers_v1(&self.store, &durable, current.lower())?;
                // R9.
                let Some(owner) = owner else {
                    // Verified and adopted: later status calls of this process need not rewrite
                    // these files again.
                    let status = KagemushaWalletSlotStatusV1::Pending(record);
                    self.remember(slot, durable, status.clone());
                    return Ok(status);
                };
                let finished =
                    self.finish_selected(slot, owner, &durable, capsule.value(), &[], &boot, None);
                Self::finished_status(record, finished)
            }
            KagemushaWalletMarkerPhaseV1::Released => {
                self.reconcile_journal(&durable)?;
                self.settle_capsule(&durable, &boot, false)?;
                self.settle_released_completion(&durable, &boot)?;
                kagemusha_wallet_retire_markers_v1(&self.store, &durable, current.lower())?;
                kagemusha_wallet_raise_anchor_v1(&self.platform, &record)?;
                let status = KagemushaWalletSlotStatusV1::Released(record);
                self.remember(slot, durable, status.clone());
                Ok(status)
            }
            KagemushaWalletMarkerPhaseV1::Terminal => {
                kagemusha_wallet_retire_markers_v1(&self.store, &durable, current.lower())?;
                kagemusha_wallet_raise_anchor_v1(&self.platform, &record)?;
                if matches!(
                    record.marker().state,
                    iroha_data_model::kagemusha::KagemushaWalletMarkerStateV1::Terminal {
                        reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
                        ..
                    }
                ) {
                    self.finish_custody_deletion(slot)?;
                }
                let status = KagemushaWalletSlotStatusV1::Terminal(record);
                self.remember(slot, durable, status.clone());
                Ok(status)
            }
        }
    }

    /// The authenticated enrollment phase of `record`'s slot must name it: a generation-zero
    /// marker is the selected (or committed, exact file) marker of its phase, and every later
    /// marker belongs to a committed phase with the same payment key. A marker without a phase
    /// is lost custody. Read-only.
    fn require_marker_phase(
        &self,
        record: &KagemushaWalletMarkerRecordV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let state = self.enrollment_phase_for_slot(record.slot())?.ok_or(
            KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "enrollment phase",
            },
        )?;
        let named = match (record.phase(), state.phase) {
            (
                KagemushaWalletMarkerPhaseV1::Enrollment,
                KagemushaWalletEnrollmentPhaseV1::MarkerSelected {
                    marker_digest,
                    payment_key,
                    ..
                },
            ) => marker_digest == *record.marker_digest() && payment_key == *record.payment_key(),
            (
                KagemushaWalletMarkerPhaseV1::Enrollment,
                KagemushaWalletEnrollmentPhaseV1::MarkerCommitted {
                    marker_digest,
                    payment_key,
                    marker_file_digest,
                    ..
                },
            ) => {
                marker_digest == *record.marker_digest()
                    && payment_key == *record.payment_key()
                    && marker_file_digest == *record.marker_file_digest()
            }
            (
                KagemushaWalletMarkerPhaseV1::Selected
                | KagemushaWalletMarkerPhaseV1::Released
                | KagemushaWalletMarkerPhaseV1::Terminal,
                KagemushaWalletEnrollmentPhaseV1::MarkerCommitted { payment_key, .. },
            ) => payment_key == *record.payment_key(),
            _ => false,
        };
        if !named {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "enrollment marker phase",
            });
        }
        Ok(())
    }

    /// Commit the pre-key phase of a durable generation-zero marker before any use of it (the
    /// phase was checked by [`Self::require_marker_phase`]).
    fn commit_enrollment_marker_phase(
        &mut self,
        record: &KagemushaWalletMarkerRecordV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let state = self.enrollment_phase_for_slot(record.slot())?.ok_or(
            KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "enrollment phase",
            },
        )?;
        self.commit_marker_phase(
            &state.binding.request_id,
            *record.marker_digest(),
            *record.marker_file_digest(),
        )
    }

    /// Restore the generation-zero marker that the pre-key phase selected but which no file
    /// holds: only with the exact witnessed key present, no named anchor and no journal or
    /// tombstone. A new boot stamp is acceptable only in this window; the restored marker is
    /// committed before any use.
    fn restore_selected_marker(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        state: &super::KagemushaWalletEnrollmentPhaseStateV1,
        intent_present: bool,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        let KagemushaWalletEnrollmentPhaseV1::MarkerSelected { payment_key, .. } = state.phase
        else {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "enrollment phase",
            });
        };
        // No journal, no named anchor: checked before anything is restored or probed.
        self.require_marker_publication(slot, &state.binding.request_id, &state.binding.intent())?;
        if !intent_present {
            self.restore_selected_intent(slot, state)?;
        }
        let intent = self.require_selected_intent(slot, state)?;
        match self.probe_key(slot)? {
            KagemushaWalletProbeV1::Present(key) if key == payment_key => {}
            KagemushaWalletProbeV1::Present(_) | KagemushaWalletProbeV1::Absent => {
                return Err(KagemushaWalletProviderErrorV1::KeyLost);
            }
            KagemushaWalletProbeV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
            }
        }
        match self.publish_enrollment_marker(
            slot,
            &intent,
            super::platform::KagemushaWalletKeyGenerationV1::Generated(payment_key),
            Some(state.binding.request_id),
        )? {
            super::enrollment::KagemushaWalletEnrollmentStepV1::Enrolled { marker, .. } => {
                Ok(KagemushaWalletSlotStatusV1::Enrollment(*marker))
            }
            super::enrollment::KagemushaWalletEnrollmentStepV1::Pending { .. } => Err(
                KagemushaWalletProviderErrorV1::Uncertain(KagemushaWalletUnavailableV1::Busy),
            ),
            super::enrollment::KagemushaWalletEnrollmentStepV1::SlotAbandoned { .. } => {
                Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "abandoned slot custody conflict",
                })
            }
        }
    }

    /// R4: the payment key must be present and be the marker's key (probed inside storage
    /// brackets, so a locked key store is never read as a lost key).
    fn require_payment_key(
        &self,
        record: &KagemushaWalletMarkerRecordV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        match self.probe_key(record.slot())? {
            KagemushaWalletProbeV1::Present(key) if key == *record.payment_key() => Ok(()),
            KagemushaWalletProbeV1::Present(_) | KagemushaWalletProbeV1::Absent => {
                Err(KagemushaWalletProviderErrorV1::KeyLost)
            }
            KagemushaWalletProbeV1::Unavailable(reason) => {
                Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
            }
        }
    }

    /// R1: remove the store's staging files under the root and the slot.
    fn remove_all_staging(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let slot_dir = kagemusha_wallet_slot_dir_v1(slot);
        let dirs = [
            KagemushaWalletCustodyDirV1::root(),
            kagemusha_wallet_probe_dir_v1(),
            kagemusha_wallet_slots_dir_v1(),
            slot_dir.clone(),
            kagemusha_wallet_markers_dir_v1(slot),
            kagemusha_wallet_capsules_dir_v1(slot),
            kagemusha_wallet_completion_dir_v1(slot),
            kagemusha_wallet_ops_dir_v1(slot),
        ];
        for dir in &dirs {
            self.store.remove_staging(dir)?;
        }
        Ok(())
    }

    /// R5: load the capsule bound by a head from either copy, settle the valid copies
    /// (fresh inode under a Selected head when written this boot) and repair the others.
    fn settle_capsule(
        &self,
        durable: &KagemushaWalletDurableMarkerV1,
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
        selected: bool,
    ) -> Result<KagemushaWalletLoadedPairV1<C>, KagemushaWalletProviderErrorV1> {
        let record = durable.record();
        let (Some(selected_generation), Some((_, _, capsule_digest))) =
            (record.selected_generation(), record.head())
        else {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.phase",
            });
        };
        let mut pair = kagemusha_wallet_load_capsule_v1::<F, C>(
            &self.store,
            record.slot(),
            selected_generation,
            &capsule_digest,
            &C::marker_binding(record.marker()),
        )?;
        let fresh = selected && Self::written_this_boot(&pair, boot);
        self.with_ballast(true, || {
            kagemusha_wallet_settle_pair_v1(&self.store, &pair, fresh)
        })?;
        self.with_ballast(true, || {
            kagemusha_wallet_repair_pair_v1(&self.store, &mut pair, boot)
        })?;
        Ok(pair)
    }

    fn written_this_boot<T>(
        pair: &KagemushaWalletLoadedPairV1<T>,
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    ) -> bool {
        KagemushaWalletCopyV1::BOTH
            .iter()
            .any(|copy| pair.written_this_boot(*copy, boot))
    }

    /// R5/R7 under a Selected head: adopt a valid record (it was never released), or remove
    /// invalid copies, which were never released either.
    fn settle_selected_completion(
        &self,
        durable: &KagemushaWalletDurableMarkerV1,
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let record = durable.record();
        let expectation = KagemushaWalletCompletionExpectationV1::for_marker(record).ok_or(
            KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.phase",
            },
        )?;
        let slot = record.slot();
        let loaded = kagemusha_wallet_load_completion_v1::<F, R>(
            &self.store,
            slot,
            &expectation,
            &R::marker_binding(record.marker()),
        )?;
        match loaded {
            Some(mut pair) => {
                let fresh = Self::written_this_boot(&pair, boot);
                self.with_ballast(true, || {
                    kagemusha_wallet_settle_pair_v1(&self.store, &pair, fresh)
                })?;
                self.with_ballast(true, || {
                    kagemusha_wallet_repair_pair_v1(&self.store, &mut pair, boot)
                })
            }
            None => {
                let Some((_, operation_id, _)) = record.head() else {
                    return Ok(());
                };
                let names = kagemusha_wallet_completion_names_v1(&operation_id);
                let dir = kagemusha_wallet_completion_dir_v1(slot);
                let mut present = false;
                for name in &names {
                    match self.store.read(&dir, name, 0) {
                        KagemushaWalletReadV1::Absent => {}
                        KagemushaWalletReadV1::Unavailable(reason) => {
                            return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
                        }
                        KagemushaWalletReadV1::Present(_) | KagemushaWalletReadV1::Oversized => {
                            present = true;
                        }
                    }
                }
                if present {
                    remove_pair(&self.store, &dir, &names)?;
                }
                Ok(())
            }
        }
    }

    /// R5 under a Released head: the retained record must exist in some copy.
    fn settle_released_completion(
        &self,
        durable: &KagemushaWalletDurableMarkerV1,
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let record = durable.record();
        let expectation = KagemushaWalletCompletionExpectationV1::for_marker(record).ok_or(
            KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.phase",
            },
        )?;
        let mut pair = kagemusha_wallet_load_completion_v1::<F, R>(
            &self.store,
            record.slot(),
            &expectation,
            &R::marker_binding(record.marker()),
        )?
        .ok_or(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::CompletionLost,
        ))?;
        kagemusha_wallet_settle_pair_v1(&self.store, &pair, false)?;
        self.with_ballast(true, || {
            kagemusha_wallet_repair_pair_v1(&self.store, &mut pair, boot)
        })
    }

    /// R6 and R7 for an Enrollment, Selected or Released current marker.
    ///
    /// Retained records (completion copies, tombstones) may name at most the current head's
    /// Selected generation. Capsules may be bound by the current head, older (kept until the
    /// state owner collects them), or staging of the next generation (discarded); a capsule
    /// beyond the next generation is evidence of a rolled-back marker set.
    fn reconcile_journal(
        &self,
        durable: &KagemushaWalletDurableMarkerV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let record = durable.record();
        let slot = record.slot();
        let above = KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "journal above current marker",
        };
        let retained_limit = record.selected_generation();
        if let Some(highest) = highest_retained_generation::<F, R>(&self.store, slot)?
            && retained_limit.is_none_or(|limit| highest > limit)
        {
            return Err(above);
        }
        let generation = record.generation();
        // Highest capsule generation that may exist: the staging generation after an
        // Enrollment or Released marker, the marker's own after a Selected one.
        let capsule_limit = match record.phase() {
            KagemushaWalletMarkerPhaseV1::Selected => generation,
            _ => generation
                .checked_add(1)
                .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                    field: "marker.generation",
                })?,
        };
        let bound = record
            .selected_generation()
            .zip(record.head().map(|(_, _, capsule_digest)| capsule_digest));
        // Unbound capsules from this generation on were never bound by a durable marker.
        let discard_from = retained_limit.unwrap_or(0);
        let names = kagemusha_wallet_list_capsules_v1(&self.store, slot)?.unwrap_or_default();
        if names
            .iter()
            .any(|name| name.selected_generation > capsule_limit)
        {
            return Err(above);
        }
        let dir = kagemusha_wallet_capsules_dir_v1(slot);
        for name in names {
            let is_bound = bound == Some((name.selected_generation, name.capsule_digest));
            if is_bound || name.selected_generation < discard_from {
                continue;
            }
            kagemusha_wallet_require_removed_v1(self.store.remove_file(
                &dir,
                &kagemusha_wallet_capsule_name_v1(
                    name.selected_generation,
                    &name.capsule_digest,
                    name.copy,
                ),
            ))?;
        }
        Ok(())
    }

    /// R10: classify a slot without any marker. Nothing is deleted.
    // `slots()` includes surviving Keychain aliases even without a slot directory. The same
    // read-only classification applies; no directory or replacement key is created here.
    fn reconcile_without_marker(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        let mut files = self.slot_files(slot)?;
        if files.journal {
            return Err(KagemushaWalletProviderErrorV1::LostCustody(
                KagemushaWalletLostCustodyV1::JournalWithoutMarker,
            ));
        }
        // The durable pre-key phase decides whether an absent intent or marker is legitimate;
        // an intent or generation attempt never exists without one.
        let phase = self.enrollment_phase_for_slot(slot)?;
        if phase.is_none() && (files.intent || files.generation_attempt) {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "enrollment phase",
            });
        }
        if let Some(state) = &phase {
            match state.phase {
                KagemushaWalletEnrollmentPhaseV1::MarkerCommitted { .. } => {
                    // A committed marker is never reconstructed and never becomes absence.
                    return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                        object: "committed enrollment marker",
                    });
                }
                KagemushaWalletEnrollmentPhaseV1::MarkerSelected { .. } => {
                    if files.abandoned {
                        return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                            object: "abandoned slot custody conflict",
                        });
                    }
                    return self.restore_selected_marker(slot, state, files.intent);
                }
                KagemushaWalletEnrollmentPhaseV1::PreIntent
                | KagemushaWalletEnrollmentPhaseV1::IntentSelected { .. } => {}
            }
        }
        if !files.abandoned {
            match phase.as_ref().map(|state| state.phase) {
                Some(KagemushaWalletEnrollmentPhaseV1::PreIntent) => {
                    if files.intent || files.generation_attempt {
                        return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                            object: "intent without selected phase",
                        });
                    }
                    // No intent was ever selected, so no key was ever generated for the slot.
                    return Ok(KagemushaWalletSlotStatusV1::Empty);
                }
                Some(KagemushaWalletEnrollmentPhaseV1::IntentSelected { .. }) => {
                    let state = phase.as_ref().expect("matched phase");
                    if !files.intent {
                        self.restore_selected_intent(slot, state)?;
                        files = self.slot_files(slot)?;
                    }
                    // Only the exact selected intent is probed or abandoned under.
                    self.require_selected_intent(slot, state)?;
                }
                _ => {}
            }
        }
        if files.abandoned {
            // Terminal only once the exact record is durable; never a key probe.
            let adopted = self.adopt_abandoned_record(slot);
            self.guard(slot, adopted)?;
            return Ok(KagemushaWalletSlotStatusV1::SlotAbandoned);
        }
        if !files.intent {
            if files.generation_attempt {
                return Err(KagemushaWalletProviderErrorV1::LostCustody(
                    KagemushaWalletLostCustodyV1::JournalWithoutMarker,
                ));
            }
            return match self.probe_key(slot)? {
                KagemushaWalletProbeV1::Present(_) => {
                    Err(KagemushaWalletProviderErrorV1::LostCustody(
                        KagemushaWalletLostCustodyV1::KeyWithoutMarker,
                    ))
                }
                KagemushaWalletProbeV1::Absent => Ok(KagemushaWalletSlotStatusV1::Empty),
                KagemushaWalletProbeV1::Unavailable(reason) => {
                    Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
                }
            };
        }
        let intent = self
            .read_intent(slot)?
            .ok_or(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            ))?;
        if files.generation_attempt {
            self.validate_generation_attempt(slot, &intent)?;
        }
        match self.probe_key(slot)? {
            KagemushaWalletProbeV1::Absent => {
                self.remove_all_staging(slot)?;
                Ok(KagemushaWalletSlotStatusV1::IntentOnly)
            }
            // A key without a marker is a used incarnation (spec §§3.2, 4.2 step 3).
            KagemushaWalletProbeV1::Present(_) => {
                self.abandon_slot(slot, KagemushaWalletSlotAbandonReasonV1::KeyWithoutMarker)?;
                Ok(KagemushaWalletSlotStatusV1::SlotAbandoned)
            }
            KagemushaWalletProbeV1::Unavailable(reason) => {
                Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
            }
        }
    }

    /// Classify a slot directory strictly: provider files, its subdirectories and staging.
    pub(super) fn slot_files(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<SlotFilesV1, KagemushaWalletProviderErrorV1> {
        let mut files = SlotFilesV1::default();
        let unexpected = KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slot" };
        let slot_dir = kagemusha_wallet_slot_dir_v1(slot);
        for entry in kagemusha_wallet_list_dir_v1(&self.store, &slot_dir)?.unwrap_or_default() {
            match entry.kind {
                KagemushaWalletEntryKindV1::File => match entry.name.as_str() {
                    KAGEMUSHA_WALLET_INTENT_NAME_V1 => files.intent = true,
                    KAGEMUSHA_WALLET_KEY_GENERATION_ATTEMPT_NAME_V1 => {
                        files.generation_attempt = true
                    }
                    KAGEMUSHA_WALLET_ABANDONED_NAME_V1 => files.abandoned = true,
                    KAGEMUSHA_WALLET_ENROLLMENT_NAME_V1
                    | KAGEMUSHA_WALLET_ABANDONMENT_NAME_V1
                    | KAGEMUSHA_WALLET_ABANDONMENT_SELECTION_NAME_V1 => {
                        files.journal = true;
                    }
                    name if kagemusha_wallet_parse_credential_name_v1(name).is_some() => {
                        files.journal = true;
                    }
                    name if kagemusha_wallet_is_staging_name_v1(name) => {}
                    _ => return Err(unexpected),
                },
                KagemushaWalletEntryKindV1::Directory => match entry.name.as_str() {
                    KAGEMUSHA_WALLET_MARKERS_DIR_NAME_V1 => {}
                    KAGEMUSHA_WALLET_CAPSULES_DIR_NAME_V1
                    | KAGEMUSHA_WALLET_COMPLETION_DIR_NAME_V1
                    | KAGEMUSHA_WALLET_OPS_DIR_NAME_V1
                    | KAGEMUSHA_WALLET_ARCHIVE_DIR_NAME_V1 => {
                        let dir = slot_dir.child(
                            &super::layout::KagemushaWalletEntryNameV1::new(&entry.name)
                                .ok_or(unexpected)?,
                        );
                        let entries =
                            kagemusha_wallet_list_dir_v1(&self.store, &dir)?.unwrap_or_default();
                        if entries
                            .iter()
                            .any(|entry| !kagemusha_wallet_is_staging_name_v1(&entry.name))
                        {
                            files.journal = true;
                        }
                    }
                    _ => return Err(unexpected),
                },
                KagemushaWalletEntryKindV1::Other => return Err(unexpected),
            }
        }
        Ok(files)
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod tests;
