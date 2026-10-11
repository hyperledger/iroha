//! Terminal custody flows (spec §§1.2, 3.2, 6.3; G2 design rev 2 §6 T1-T4, D1-D4).
//!
//! **Abandonment** of an unused enrollment is allowed only while the generation-0 enrollment
//! marker is current after reconciliation and no Bootstrap head, completion record or
//! tombstone exists:
//!
//! - **T1** the `Terminal{Abandoned}` marker is created at generation 1 with NOREPLACE, so it
//!   competes with the Bootstrap Selected marker for the same generation: exactly one wins;
//! - **T2** generation 0 is retired and the iOS anchor raised to the terminal marker;
//! - **T3** the signed Abandon ledger control naming the durable terminal marker and its exact
//!   output selection are retained create-new before return; **T4** every submission sends
//!   those exact bytes. A selected but missing original is a custody failure, never a re-sign.
//!
//! **Custody deletion** is deliberate and user-confirmed for exactly the state the user saw:
//!
//! - **D1** `Terminal{CustodyDeleted}` at the current generation + 1 (an enrollment marker is
//!   abandoned instead); **D2** the old marker is retired and the anchor raised;
//! - **D3** the payment key is deleted only after the terminal marker is durable (and, on iOS,
//!   anchored); **D4** capsules, completion records and the state owner's archive are removed.
//!
//! The terminal marker, the intent, tombstones and the anchor are kept, so a deliberate
//! deletion never reads as lost custody. Reconciliation of a terminal slot resumes these steps.

use iroha_data_model::kagemusha::{
    KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1, KAGEMUSHA_WALLET_VERSION_V1,
    KagemushaWalletAbandonmentV1, KagemushaWalletLedgerControlV1, KagemushaWalletMarkerStateV1,
    KagemushaWalletSigningDomainV1, KagemushaWalletTerminalReasonV1,
};
use rand::rand_core::TryRngCore as _;

use super::{
    KagemushaWalletProviderErrorV1,
    advance::KagemushaWalletAdvanceCapsuleV1,
    anchor::kagemusha_wallet_raise_anchor_v1,
    completion::{KagemushaWalletCompletionFrameV1, kagemusha_wallet_list_completions_v1},
    decode_envelope_v1, encode_envelope_v1, kagemusha_wallet_provider_digest_v1,
    layout::{
        KAGEMUSHA_WALLET_ABANDONMENT_NAME_V1,
        KAGEMUSHA_WALLET_ABANDONMENT_SELECTION_NAME_V1 as ABANDONMENT_SELECTION_NAME,
        KagemushaWalletCustodyDirV1, KagemushaWalletEntryNameV1, KagemushaWalletSlotIdV1,
        kagemusha_wallet_archive_dir_v1, kagemusha_wallet_capsules_dir_v1,
        kagemusha_wallet_completion_dir_v1, kagemusha_wallet_fixed_name_v1,
        kagemusha_wallet_list_dir_v1, kagemusha_wallet_require_published_v1,
        kagemusha_wallet_require_removed_v1, kagemusha_wallet_slot_dir_v1,
    },
    marker::{
        KagemushaWalletDurableMarkerV1, KagemushaWalletMarkerPublicationV1,
        KagemushaWalletMarkerRecordV1, kagemusha_wallet_publish_marker_v1,
        kagemusha_wallet_retire_markers_v1,
    },
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletNotPublishedV1,
        KagemushaWalletPlatformV1, KagemushaWalletProbeV1, KagemushaWalletPublishOutcomeV1,
        KagemushaWalletReadV1, KagemushaWalletRemoveOutcomeV1, KagemushaWalletUnavailableV1,
        kagemusha_wallet_boot_stamp_v1, kagemusha_wallet_sign_domain_v1,
    },
    provider::{KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1},
    retained::kagemusha_wallet_list_tombstones_v1,
};

/// The user's confirmation of deleting exactly the custody state they were shown (§1.2:
/// destructive consequences are shown before any wallet-controlled reset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KagemushaWalletDestructiveConfirmationV1 {
    /// Slot to delete.
    pub slot: KagemushaWalletSlotIdV1,
    /// `marker_file_digest` of the current marker shown with the warning.
    pub marker_file_digest: [u8; 32],
}

impl KagemushaWalletDestructiveConfirmationV1 {
    /// Confirmation for the state `status` of `slot`; `None` without a current head.
    #[must_use]
    pub fn for_status(
        slot: KagemushaWalletSlotIdV1,
        status: &KagemushaWalletSlotStatusV1,
    ) -> Option<Self> {
        match status {
            KagemushaWalletSlotStatusV1::Released(record)
            | KagemushaWalletSlotStatusV1::Pending(record) => Some(Self {
                slot,
                marker_file_digest: *record.marker_file_digest(),
            }),
            _ => None,
        }
    }
}

// This local immutable output selection follows durable original publication. It detects
// missing/substituted selected output; complete filesystem rollback is outside this primitive.
const ABANDONMENT_SELECTION_MAX: usize = 512;
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_advance_v1::AbandonmentSelectionV1")]
struct AbandonmentSelectionV1 {
    version: u16,
    slot: [u8; 32],
    terminal: [u8; 32],
    original: [u8; 32],
}
fn abandonment_custody_error() -> KagemushaWalletProviderErrorV1 {
    KagemushaWalletProviderErrorV1::UnavailableCustodyData {
        object: "selected abandonment",
    }
}
fn abandonment_digest(bytes: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("abandonment-original", bytes)
}

fn terminal_reason(
    record: &KagemushaWalletMarkerRecordV1,
) -> Option<KagemushaWalletTerminalReasonV1> {
    match record.marker().state {
        KagemushaWalletMarkerStateV1::Terminal { reason, .. } => Some(reason),
        _ => None,
    }
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Abandon the unused enrollment of `slot` (T1-T3) and return the exact canonical
    /// `KagemushaWalletAbandonmentV1` frame to submit; a resumed abandonment returns the
    /// retained frame.
    ///
    /// # Errors
    ///
    /// `Invalid("abandon.bootstrap")` once a Bootstrap head was selected or released (or won
    /// generation 1), `Invalid("abandon.retained")` when a completion record or tombstone
    /// exists, `Terminal` after custody deletion, `Invalid("slot.not_enrolled")` without an
    /// enrollment marker, `Unavailable` when the key cannot sign, and the reconcile, read and
    /// write errors.
    pub fn abandon_enrollment(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        let terminal = match self.reconcile_slot(slot, None)? {
            KagemushaWalletSlotStatusV1::Enrollment(record) => {
                let committed = self.commit_abandonment(slot, &record);
                self.guard(slot, committed)?
            }
            KagemushaWalletSlotStatusV1::Terminal(record)
                if terminal_reason(&record) == Some(KagemushaWalletTerminalReasonV1::Abandoned) =>
            {
                record
            }
            KagemushaWalletSlotStatusV1::Terminal(_) => {
                return Err(KagemushaWalletProviderErrorV1::Terminal);
            }
            KagemushaWalletSlotStatusV1::Pending(_) | KagemushaWalletSlotStatusV1::Released(_) => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "abandon.bootstrap",
                });
            }
            KagemushaWalletSlotStatusV1::Empty
            | KagemushaWalletSlotStatusV1::IntentOnly
            | KagemushaWalletSlotStatusV1::SlotAbandoned => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "slot.not_enrolled",
                });
            }
        };
        let retained = self.retain_abandonment(slot, &terminal);
        self.guard(slot, retained)
    }

    /// T1-T2 from the current enrollment marker `enrollment`.
    fn commit_abandonment(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        enrollment: &KagemushaWalletMarkerRecordV1,
    ) -> Result<KagemushaWalletMarkerRecordV1, KagemushaWalletProviderErrorV1> {
        let has_completion = !kagemusha_wallet_list_completions_v1(&self.store, slot)?
            .unwrap_or_default()
            .is_empty();
        if has_completion || !kagemusha_wallet_list_tombstones_v1(&self.store, slot)?.is_empty() {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "abandon.retained",
            });
        }
        let terminal = enrollment.terminate(
            KagemushaWalletTerminalReasonV1::Abandoned,
            kagemusha_wallet_boot_stamp_v1(&self.boot()),
        )?;
        self.poison(slot);
        let durable = match kagemusha_wallet_publish_marker_v1(&self.store, terminal)? {
            KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
            // Bootstrap holds generation 1: it was selected first and is never abandoned.
            KagemushaWalletMarkerPublicationV1::GenerationTaken => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "abandon.bootstrap",
                });
            }
        };
        self.finish_terminal_markers(&durable, &[enrollment.generation()])?;
        let record = durable.record().clone();
        self.remember(
            slot,
            durable,
            KagemushaWalletSlotStatusV1::Terminal(record.clone()),
        );
        Ok(record)
    }

    /// T3: the retained signed abandonment, or a new one written create-new.
    fn retain_abandonment(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        terminal: &KagemushaWalletMarkerRecordV1,
    ) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        let dir = kagemusha_wallet_slot_dir_v1(slot);
        let name = kagemusha_wallet_fixed_name_v1(KAGEMUSHA_WALLET_ABANDONMENT_NAME_V1);
        let selected = self.read_abandonment_selection(&dir, terminal)?;
        if let Some(existing) = self.read_abandonment(&dir, &name, terminal)? {
            if selected
                .as_ref()
                .is_some_and(|value| value.original != abandonment_digest(&existing))
            {
                return Err(abandonment_custody_error());
            }
            kagemusha_wallet_require_published_v1(self.store.rewrite_same(&dir, &name, &existing))?;
            self.select_abandonment(&dir, terminal, &existing)?;
            return Ok(existing);
        }
        if selected.is_some() {
            return Err(abandonment_custody_error());
        }
        let intent = self
            .read_intent(slot)?
            .ok_or(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "intent" })?;
        let challenge_digest = intent.challenge.challenge_digest();
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| {
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(0))
        })?;
        let body =
            KagemushaWalletAbandonmentV1::control_body(terminal.marker(), &challenge_digest, nonce)
                .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                    field: "abandon.body",
                })?;
        let signature = kagemusha_wallet_sign_domain_v1(
            &self.platform,
            slot,
            terminal.payment_key(),
            KagemushaWalletSigningDomainV1::LedgerControl,
            &body.transcript(),
        )?;
        let abandonment = KagemushaWalletAbandonmentV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            control: KagemushaWalletLedgerControlV1 { body, signature },
            payment_key: *terminal.payment_key(),
            challenge_digest,
        };
        abandonment
            .require_terminal_marker(terminal.marker())
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                field: "abandon.terminal",
            })?;
        let frame = abandonment.to_canonical_bytes().map_err(|_| {
            KagemushaWalletProviderErrorV1::Invalid {
                field: "abandon.frame",
            }
        })?;
        let frame = match self.store.write_new(&dir, &name, &frame) {
            // An earlier attempt retained another signature: it wins.
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists,
            ) => {
                let existing = self.read_abandonment(&dir, &name, terminal)?.ok_or(
                    KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy),
                )?;
                kagemusha_wallet_require_published_v1(
                    self.store.rewrite_same(&dir, &name, &existing),
                )?;
                Ok(existing)
            }
            outcome => kagemusha_wallet_require_published_v1(outcome).map(|()| frame),
        }?;
        self.select_abandonment(&dir, terminal, &frame)?;
        Ok(frame)
    }

    fn read_abandonment_selection(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        terminal: &KagemushaWalletMarkerRecordV1,
    ) -> Result<Option<AbandonmentSelectionV1>, KagemushaWalletProviderErrorV1> {
        let name = kagemusha_wallet_fixed_name_v1(ABANDONMENT_SELECTION_NAME);
        match self.store.read(dir, &name, ABANDONMENT_SELECTION_MAX) {
            KagemushaWalletReadV1::Absent => Ok(None),
            KagemushaWalletReadV1::Unavailable(reason) => {
                Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
            }
            KagemushaWalletReadV1::Oversized => Err(abandonment_custody_error()),
            KagemushaWalletReadV1::Present(bytes) => {
                let selected: AbandonmentSelectionV1 =
                    decode_envelope_v1(&bytes, ABANDONMENT_SELECTION_MAX)
                        .map_err(|_| abandonment_custody_error())?;
                if selected.version != 1
                    || selected.slot != terminal.slot().0
                    || selected.terminal != *terminal.marker_file_digest()
                    || selected.original == [0; 32]
                {
                    return Err(abandonment_custody_error());
                }
                Ok(Some(selected))
            }
        }
    }

    fn select_abandonment(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        terminal: &KagemushaWalletMarkerRecordV1,
        original: &[u8],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let selected = AbandonmentSelectionV1 {
            version: 1,
            slot: terminal.slot().0,
            terminal: *terminal.marker_file_digest(),
            original: abandonment_digest(original),
        };
        let bytes = encode_envelope_v1(&selected, ABANDONMENT_SELECTION_MAX)?;
        let name = kagemusha_wallet_fixed_name_v1(ABANDONMENT_SELECTION_NAME);
        match self.store.write_new(dir, &name, &bytes) {
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists,
            ) => {
                if self.read_abandonment_selection(dir, terminal)?.as_ref() != Some(&selected) {
                    return Err(abandonment_custody_error());
                }
                kagemusha_wallet_require_published_v1(self.store.rewrite_same(dir, &name, &bytes))
            }
            outcome => kagemusha_wallet_require_published_v1(outcome),
        }
    }

    fn read_abandonment(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &KagemushaWalletEntryNameV1,
        terminal: &KagemushaWalletMarkerRecordV1,
    ) -> Result<Option<Vec<u8>>, KagemushaWalletProviderErrorV1> {
        let corrupt = KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "abandonment",
        };
        match self
            .store
            .read(dir, name, KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1)
        {
            KagemushaWalletReadV1::Present(bytes) => {
                let abandonment = KagemushaWalletAbandonmentV1::decode_canonical(
                    &bytes,
                    &terminal.marker().scheme_id,
                )
                .map_err(|_| corrupt)?;
                abandonment
                    .require_terminal_marker(terminal.marker())
                    .map_err(|_| corrupt)?;
                Ok(Some(bytes))
            }
            KagemushaWalletReadV1::Absent => Ok(None),
            KagemushaWalletReadV1::Oversized => Err(corrupt),
            KagemushaWalletReadV1::Unavailable(reason) => {
                Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
            }
        }
    }

    /// Delete the custody of `slot` deliberately (D1-D4) after the user confirmed the warning
    /// for exactly its current state.
    ///
    /// # Errors
    ///
    /// `Invalid` for a confirmation of another slot or an older state, for an enrollment
    /// marker (abandon instead) and for an unenrolled slot; `Terminal` after abandonment; the
    /// reconcile, key-store, read and write errors otherwise. A completed deletion is
    /// reported again as `Ok(Terminal)`.
    pub fn delete_custody(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        confirmation: &KagemushaWalletDestructiveConfirmationV1,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        if confirmation.slot != *slot {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "custody.confirmation_slot",
            });
        }
        let current = match self.reconcile_slot(slot, None)? {
            KagemushaWalletSlotStatusV1::Released(record)
            | KagemushaWalletSlotStatusV1::Pending(record) => record,
            KagemushaWalletSlotStatusV1::Terminal(record)
                if terminal_reason(&record)
                    == Some(KagemushaWalletTerminalReasonV1::CustodyDeleted) =>
            {
                return Ok(KagemushaWalletSlotStatusV1::Terminal(record));
            }
            KagemushaWalletSlotStatusV1::Terminal(_) => {
                return Err(KagemushaWalletProviderErrorV1::Terminal);
            }
            KagemushaWalletSlotStatusV1::Enrollment(_) => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "custody.abandon_enrollment",
                });
            }
            KagemushaWalletSlotStatusV1::Empty
            | KagemushaWalletSlotStatusV1::IntentOnly
            | KagemushaWalletSlotStatusV1::SlotAbandoned => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "slot.not_enrolled",
                });
            }
        };
        if *current.marker_file_digest() != confirmation.marker_file_digest {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "custody.confirmation_stale",
            });
        }
        let deleted = self.commit_custody_deletion(slot, &current);
        let terminal = self.guard(slot, deleted)?;
        Ok(KagemushaWalletSlotStatusV1::Terminal(terminal))
    }

    fn commit_custody_deletion(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        current: &KagemushaWalletMarkerRecordV1,
    ) -> Result<KagemushaWalletMarkerRecordV1, KagemushaWalletProviderErrorV1> {
        let terminal = current.terminate(
            KagemushaWalletTerminalReasonV1::CustodyDeleted,
            kagemusha_wallet_boot_stamp_v1(&self.boot()),
        )?;
        self.poison(slot);
        // D1.
        let durable = match kagemusha_wallet_publish_marker_v1(&self.store, terminal)? {
            KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
            KagemushaWalletMarkerPublicationV1::GenerationTaken => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
        };
        // D2-D4.
        self.finish_terminal_markers(&durable, &[current.generation()])?;
        self.finish_custody_deletion(slot)?;
        let record = durable.record().clone();
        self.remember(
            slot,
            durable,
            KagemushaWalletSlotStatusV1::Terminal(record.clone()),
        );
        Ok(record)
    }

    /// T2/D2: retire `lower` and raise the anchor to the durable terminal marker.
    fn finish_terminal_markers(
        &self,
        terminal: &KagemushaWalletDurableMarkerV1,
        lower: &[u128],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        kagemusha_wallet_retire_markers_v1(&self.store, terminal, lower)?;
        kagemusha_wallet_raise_anchor_v1(&self.platform, terminal.record())
    }

    /// D3-D4 under a durable `Terminal{CustodyDeleted}` marker whose anchor is raised. The key
    /// probe is bracketed by storage checks, so a locked key store never skips D3.
    pub(super) fn finish_custody_deletion(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        match self.probe_key(slot)? {
            KagemushaWalletProbeV1::Absent => {}
            KagemushaWalletProbeV1::Present(_) => match self.platform.key_delete(slot) {
                KagemushaWalletRemoveOutcomeV1::Removed => {}
                KagemushaWalletRemoveOutcomeV1::NotRemoved(reason) => {
                    return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
                }
                KagemushaWalletRemoveOutcomeV1::Uncertain(reason) => {
                    return Err(KagemushaWalletProviderErrorV1::Uncertain(reason));
                }
            },
            KagemushaWalletProbeV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
            }
        }
        for dir in [
            kagemusha_wallet_capsules_dir_v1(slot),
            kagemusha_wallet_completion_dir_v1(slot),
            kagemusha_wallet_archive_dir_v1(slot),
        ] {
            self.remove_files(&dir)?;
        }
        Ok(())
    }

    /// Durably remove every regular file of `dir`.
    // TODO(G2-S): the state owner's archive layout may add subdirectories; they are kept until
    // the archive owner defines their removal.
    fn remove_files(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        for entry in kagemusha_wallet_list_dir_v1(&self.store, dir)?.unwrap_or_default() {
            if entry.kind != KagemushaWalletEntryKindV1::File {
                continue;
            }
            let name = KagemushaWalletEntryNameV1::new(&entry.name)
                .ok_or(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "slot" })?;
            kagemusha_wallet_require_removed_v1(self.store.remove_file(dir, &name))?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
