//! Retained results by operation identity (spec §§4.1, 5.3; G2 design rev 2 A1, A12, R6, R8).
//!
//! A completion record keyed by its operation and once bound by a Released marker is the
//! retained result of that operation: every retry returns its exact frame. The current head's
//! record is never pruned (the next transition needs its receipt). The state owner may prune
//! older records; pruning first writes a permanent tombstone `ops/<op>.t`, so a later lookup
//! reports the operation as archived instead of unknown, and the operation identity stays used.
//!
//! Lookups never infer absence from an error: a copy that cannot be read is `Unavailable`, a
//! record whose copies are all present but invalid is delivery-data loss, and only names that
//! are definitively absent with no tombstone are unknown.

use super::{
    KagemushaWalletProviderErrorV1,
    advance::KagemushaWalletAdvanceCapsuleV1,
    capsule::{
        KagemushaWalletFrozenFileV1, KagemushaWalletLoadedPairV1, file_max,
        kagemusha_wallet_list_capsules_v1, read_pair, remove_pair,
    },
    completion::{
        KagemushaWalletCompletionFrameV1, kagemusha_wallet_completion_names_v1,
        kagemusha_wallet_list_completions_v1,
    },
    decode_envelope_v1, encode_envelope_v1,
    layout::{
        KagemushaWalletSlotIdV1, kagemusha_wallet_capsule_name_v1,
        kagemusha_wallet_capsules_dir_v1, kagemusha_wallet_completion_dir_v1,
        kagemusha_wallet_is_staging_name_v1, kagemusha_wallet_list_dir_v1,
        kagemusha_wallet_ops_dir_v1, kagemusha_wallet_parse_tombstone_name_v1,
        kagemusha_wallet_require_removed_v1, kagemusha_wallet_tombstone_name_v1,
    },
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletNotPublishedV1,
        KagemushaWalletPlatformV1, KagemushaWalletPublishOutcomeV1, KagemushaWalletReadV1,
    },
    provider::{KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1},
    store::KagemushaWalletDurableStoreV1,
};

/// Tombstone version.
pub const KAGEMUSHA_WALLET_TOMBSTONE_VERSION_V1: u16 = 1;
/// Maximum encoded tombstone.
pub const KAGEMUSHA_WALLET_TOMBSTONE_MAX_BYTES_V1: usize = 512;

/// What is retained for one operation identity (carried by `OperationIdConflict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletRetainedStatusV1 {
    /// The operation's head is selected and not yet released.
    Selected {
        /// Capsule digest of the selected head.
        capsule_digest: [u8; 32],
    },
    /// The operation's result is released and retained.
    Released {
        /// Capsule digest the receipt signs.
        capsule_digest: [u8; 32],
        /// Completion digest of the retained record.
        completion_digest: [u8; 32],
    },
    /// The operation's record was pruned after its tombstone was written.
    Archived {
        /// Capsule digest the receipt signed.
        capsule_digest: [u8; 32],
        /// Completion digest of the pruned record.
        completion_digest: [u8; 32],
    },
    /// The operation was released but every copy of its record is invalid or missing.
    DeliveryDataLoss,
}

/// One released result: the exact retained completion frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletRetainedV1<R> {
    /// Operation identity.
    pub operation_id: [u8; 32],
    /// Capsule digest the receipt signs.
    pub capsule_digest: [u8; 32],
    /// Generation of the Selected marker the record was written under.
    pub selected_generation: u128,
    /// Completion digest (bound by the Released marker of the head).
    pub completion_digest: [u8; 32],
    /// Exact canonical completion frame; identical on every retry.
    pub frame: Vec<u8>,
    /// Decoded record.
    pub record: R,
}

impl<R: KagemushaWalletCompletionFrameV1> KagemushaWalletRetainedV1<R> {
    /// Retained result of a loaded completion pair.
    pub(super) fn from_pair(pair: KagemushaWalletLoadedPairV1<R>) -> Self {
        let frame = pair.frame().to_vec();
        let completion_digest = *pair.frame_digest();
        let selected_generation = pair.selected_generation();
        let record = pair.into_value();
        Self {
            operation_id: record.operation_id(),
            capsule_digest: record.capsule_digest(),
            selected_generation,
            completion_digest,
            frame,
            record,
        }
    }

    /// Retained status of this result.
    #[must_use]
    pub fn status(&self) -> KagemushaWalletRetainedStatusV1 {
        KagemushaWalletRetainedStatusV1::Released {
            capsule_digest: self.capsule_digest,
            completion_digest: self.completion_digest,
        }
    }
}

/// Permanent tombstone of a pruned completion record.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::TombstoneV1")]
pub struct KagemushaWalletTombstoneV1 {
    /// Version; exactly [`KAGEMUSHA_WALLET_TOMBSTONE_VERSION_V1`].
    pub version: u16,
    /// Operation identity.
    pub operation_id: [u8; 32],
    /// Opaque operation-kind tag supplied by the state owner.
    pub kind: u8,
    /// Generation of the Selected marker the record was written under.
    pub selected_generation: u128,
    /// Capsule digest the receipt signed.
    pub capsule_digest: [u8; 32],
    /// Completion digest of the pruned record.
    pub completion_digest: [u8; 32],
}

impl KagemushaWalletTombstoneV1 {
    /// Canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid tombstone.
    pub fn encode(&self) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        self.validate()?;
        encode_envelope_v1(self, KAGEMUSHA_WALLET_TOMBSTONE_MAX_BYTES_V1)
    }

    /// Decode and validate canonical bytes.
    ///
    /// # Errors
    ///
    /// Rejects oversized, noncanonical or invalid bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KagemushaWalletProviderErrorV1> {
        let tombstone: Self = decode_envelope_v1(bytes, KAGEMUSHA_WALLET_TOMBSTONE_MAX_BYTES_V1)?;
        tombstone.validate()?;
        Ok(tombstone)
    }

    /// Retained status recorded by this tombstone.
    #[must_use]
    pub fn status(&self) -> KagemushaWalletRetainedStatusV1 {
        KagemushaWalletRetainedStatusV1::Archived {
            capsule_digest: self.capsule_digest,
            completion_digest: self.completion_digest,
        }
    }

    fn validate(&self) -> Result<(), KagemushaWalletProviderErrorV1> {
        if self.version != KAGEMUSHA_WALLET_TOMBSTONE_VERSION_V1
            || self.operation_id == [0; 32]
            || self.capsule_digest == [0; 32]
            || self.completion_digest == [0; 32]
        {
            return Err(KagemushaWalletProviderErrorV1::Invalid { field: "tombstone" });
        }
        Ok(())
    }
}

/// Answer of a lookup by operation identity (design `lookup`). `Unknown` means only that no
/// selected head is recorded here; the state owner's current head stays authoritative.
// Keep the selected digest inline: its fixed 32 bytes outweigh a Box on 32-bit
// targets, but adding an allocation would not improve this bounded lookup result.
#[cfg_attr(target_pointer_width = "32", allow(variant_size_differences))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KagemushaWalletLookupV1<R> {
    /// The released result, byte-identical on every call.
    Retained(Box<KagemushaWalletRetainedV1<R>>),
    /// The operation's head is selected but its receipt is not yet released.
    SelectedUnsigned {
        /// Capsule digest of the selected head.
        capsule_digest: [u8; 32],
    },
    /// The record was pruned after its permanent tombstone.
    Archived(Box<KagemushaWalletTombstoneV1>),
    /// The operation was released but every copy of its record is invalid or missing.
    DeliveryDataLoss,
    /// No selected head is recorded for the operation.
    Unknown,
}

/// Older released record of one operation found by name.
pub(super) enum OlderCompletionV1<R> {
    /// A valid copy.
    Found(KagemushaWalletLoadedPairV1<R>),
    /// Copies exist but none is valid.
    Invalid,
    /// Both names are definitively absent.
    Absent,
}

/// Load the record of `operation_id` written under any generation (lookups of operations
/// other than the current head's).
///
/// # Errors
///
/// `Unavailable` when no copy is valid and one could not be read.
pub(super) fn load_older_completion<F, R>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
    operation_id: &[u8; 32],
    binding: &R::Binding,
) -> Result<OlderCompletionV1<R>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    R: KagemushaWalletCompletionFrameV1,
{
    let dir = kagemusha_wallet_completion_dir_v1(slot);
    let names = kagemusha_wallet_completion_names_v1(operation_id);
    let mut present = false;
    let mut generations: Vec<u128> = Vec::with_capacity(2);
    for name in &names {
        match store.read(&dir, name, file_max::<R>()) {
            KagemushaWalletReadV1::Present(bytes) => {
                present = true;
                if let Ok(file) =
                    decode_envelope_v1::<KagemushaWalletFrozenFileV1>(&bytes, file_max::<R>())
                    && !generations.contains(&file.selected_generation)
                {
                    generations.push(file.selected_generation);
                }
            }
            KagemushaWalletReadV1::Oversized => present = true,
            KagemushaWalletReadV1::Absent => {}
            KagemushaWalletReadV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
            }
        }
    }
    for generation in generations {
        if let Some(pair) = read_pair::<F, R>(
            store,
            &dir,
            names.clone(),
            generation,
            binding,
            |record, _| record.operation_id() == *operation_id,
        )? {
            return Ok(OlderCompletionV1::Found(pair));
        }
    }
    Ok(if present {
        OlderCompletionV1::Invalid
    } else {
        OlderCompletionV1::Absent
    })
}

/// Read the tombstone of `operation_id`: `None` when definitively absent, `Some(None)` when
/// present but invalid.
///
/// # Errors
///
/// `Unavailable` on a read error.
pub(super) fn read_tombstone<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
    operation_id: &[u8; 32],
) -> Result<Option<Option<KagemushaWalletTombstoneV1>>, KagemushaWalletProviderErrorV1> {
    match store.read(
        &kagemusha_wallet_ops_dir_v1(slot),
        &kagemusha_wallet_tombstone_name_v1(operation_id),
        KAGEMUSHA_WALLET_TOMBSTONE_MAX_BYTES_V1,
    ) {
        KagemushaWalletReadV1::Present(bytes) => Ok(Some(
            KagemushaWalletTombstoneV1::decode(&bytes)
                .ok()
                .filter(|tombstone| tombstone.operation_id == *operation_id),
        )),
        KagemushaWalletReadV1::Oversized => Ok(Some(None)),
        KagemushaWalletReadV1::Absent => Ok(None),
        KagemushaWalletReadV1::Unavailable(reason) => {
            Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
        }
    }
}

/// List tombstone operation identities of `slot` strictly; staging files are skipped.
///
/// # Errors
///
/// `Unavailable` on a listing error and `UnexpectedEntry` for a foreign entry.
pub fn kagemusha_wallet_list_tombstones_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<Vec<[u8; 32]>, KagemushaWalletProviderErrorV1> {
    let entries = kagemusha_wallet_list_dir_v1(store, &kagemusha_wallet_ops_dir_v1(slot))?
        .unwrap_or_default();
    let mut operations = Vec::with_capacity(entries.len());
    for entry in entries {
        let is_file = entry.kind == KagemushaWalletEntryKindV1::File;
        match is_file
            .then(|| kagemusha_wallet_parse_tombstone_name_v1(&entry.name))
            .flatten()
        {
            Some(operation_id) => operations.push(operation_id),
            None if is_file && kagemusha_wallet_is_staging_name_v1(&entry.name) => {}
            None => return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "ops" }),
        }
    }
    Ok(operations)
}

/// Highest Selected-marker generation recorded by any completion copy or tombstone of `slot`
/// (design R6). Copies and tombstones that do not decode are skipped: they prove nothing.
///
/// # Errors
///
/// `Unavailable` on any listing or read error and `UnexpectedEntry` for a foreign entry.
pub(super) fn highest_retained_generation<F, R>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<Option<u128>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    R: KagemushaWalletCompletionFrameV1,
{
    let mut highest: Option<u128> = None;
    let dir = kagemusha_wallet_completion_dir_v1(slot);
    for name in kagemusha_wallet_list_completions_v1(store, slot)?.unwrap_or_default() {
        let entry =
            super::layout::kagemusha_wallet_completion_name_v1(&name.operation_id, name.copy);
        match store.read(&dir, &entry, file_max::<R>()) {
            KagemushaWalletReadV1::Present(bytes) => {
                if let Ok(file) =
                    decode_envelope_v1::<KagemushaWalletFrozenFileV1>(&bytes, file_max::<R>())
                {
                    highest = highest.max(Some(file.selected_generation));
                }
            }
            KagemushaWalletReadV1::Oversized | KagemushaWalletReadV1::Absent => {}
            KagemushaWalletReadV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
            }
        }
    }
    for operation_id in kagemusha_wallet_list_tombstones_v1(store, slot)? {
        if let Some(Some(tombstone)) = read_tombstone(store, slot, &operation_id)? {
            highest = highest.max(Some(tombstone.selected_generation));
        }
    }
    Ok(highest)
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Prune the released record of an older operation (state-owner policy, §5.3): write its
    /// permanent tombstone durably, then remove both copies. Repeating a completed prune
    /// returns the existing tombstone.
    ///
    /// # Errors
    ///
    /// `Invalid` for the current head's own operation, an operation with no valid record and
    /// no tombstone, or a slot without a head; `UnavailableCustodyData` when an existing
    /// tombstone disagrees; the reconcile, read and write errors otherwise.
    pub fn prune_completion(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        operation_id: &[u8; 32],
        kind: u8,
    ) -> Result<KagemushaWalletTombstoneV1, KagemushaWalletProviderErrorV1> {
        let status = self.reconcile_slot(slot, None)?;
        let current = match &status {
            KagemushaWalletSlotStatusV1::Released(record)
            | KagemushaWalletSlotStatusV1::Pending(record) => record.clone(),
            _ => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "prune.slot",
                });
            }
        };
        if current
            .head()
            .is_some_and(|(_, head_op, _)| head_op == *operation_id)
        {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "prune.current_head",
            });
        }
        let binding = R::marker_binding(current.marker());
        let pair = match load_older_completion::<F, R>(&self.store, slot, operation_id, &binding)? {
            OlderCompletionV1::Found(pair) => pair,
            OlderCompletionV1::Invalid => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "prune.record_invalid",
                });
            }
            OlderCompletionV1::Absent => {
                return match read_tombstone(&self.store, slot, operation_id)? {
                    Some(Some(tombstone)) => Ok(tombstone),
                    _ => Err(KagemushaWalletProviderErrorV1::Invalid {
                        field: "prune.unknown_operation",
                    }),
                };
            }
        };
        let tombstone = KagemushaWalletTombstoneV1 {
            version: KAGEMUSHA_WALLET_TOMBSTONE_VERSION_V1,
            operation_id: *operation_id,
            kind,
            selected_generation: pair.selected_generation(),
            capsule_digest: pair.value().capsule_digest(),
            completion_digest: *pair.frame_digest(),
        };
        let written = self.write_tombstone(slot, &tombstone);
        self.guard(slot, written)?;
        let removed = remove_pair(
            &self.store,
            &kagemusha_wallet_completion_dir_v1(slot),
            &kagemusha_wallet_completion_names_v1(operation_id),
        );
        let removed = self.require_storage().and(removed);
        self.guard(slot, removed)?;
        Ok(tombstone)
    }

    fn write_tombstone(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        tombstone: &KagemushaWalletTombstoneV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let dir = kagemusha_wallet_ops_dir_v1(slot);
        let name = kagemusha_wallet_tombstone_name_v1(&tombstone.operation_id);
        let bytes = tombstone.encode()?;
        match self.store.write_new(&dir, &name, &bytes) {
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::DestinationExists,
            ) => match read_tombstone(&self.store, slot, &tombstone.operation_id)? {
                Some(Some(existing)) if existing == *tombstone => {
                    // Adopt a tombstone left by an interrupted prune: make it durable.
                    super::layout::kagemusha_wallet_require_published_v1(
                        self.store.rewrite_same(&dir, &name, &bytes),
                    )
                }
                _ => Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "tombstone",
                }),
            },
            outcome => super::layout::kagemusha_wallet_require_published_v1(outcome),
        }
    }

    /// Remove exactly one older capsule pair selected by the state owner's durable collection
    /// intent. Current-head custody is never collected, and no directory enumeration occurs.
    ///
    /// # Errors
    /// Current/future generations, missing heads or uncertain protected-storage removal.
    pub fn collect_capsule(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        selected_generation: u128,
        capsule_digest: &[u8; 32],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let status = self.reconcile_slot(slot, None)?;
        let bound = status
            .marker()
            .and_then(super::marker::KagemushaWalletMarkerRecordV1::selected_generation)
            .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                field: "collect.slot",
            })?;
        if selected_generation >= bound || *capsule_digest == [0; 32] {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "collect.current_capsule",
            });
        }
        let dir = kagemusha_wallet_capsules_dir_v1(slot);
        for copy in super::layout::KagemushaWalletCopyV1::BOTH {
            let name = kagemusha_wallet_capsule_name_v1(selected_generation, capsule_digest, copy);
            let result = kagemusha_wallet_require_removed_v1(self.store.remove_file(&dir, &name));
            let result = self.require_storage().and(result);
            self.guard(slot, result)?;
        }
        Ok(())
    }
    /// Remove capsules the state owner has durably archived: every copy whose Selected
    /// generation is at most `through` and below the current head's (design R8). The capsule
    /// bound by the current marker is never removed. Returns the number of files removed.
    ///
    /// # Errors
    ///
    /// `Invalid` when `through` reaches the current head's capsule or the slot has no head;
    /// the reconcile, listing and removal errors otherwise.
    pub fn collect_capsules(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        through_selected_generation: u128,
    ) -> Result<usize, KagemushaWalletProviderErrorV1> {
        let status = self.reconcile_slot(slot, None)?;
        let bound = status
            .marker()
            .and_then(super::marker::KagemushaWalletMarkerRecordV1::selected_generation)
            .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                field: "collect.slot",
            })?;
        if through_selected_generation >= bound {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "collect.current_capsule",
            });
        }
        let names = kagemusha_wallet_list_capsules_v1(&self.store, slot)?.unwrap_or_default();
        let dir = kagemusha_wallet_capsules_dir_v1(slot);
        let mut removed = 0_usize;
        for name in names
            .into_iter()
            .filter(|name| name.selected_generation <= through_selected_generation)
        {
            let outcome = self.store.remove_file(
                &dir,
                &kagemusha_wallet_capsule_name_v1(
                    name.selected_generation,
                    &name.capsule_digest,
                    name.copy,
                ),
            );
            let result = kagemusha_wallet_require_removed_v1(outcome);
            self.guard(slot, result)?;
            removed = removed
                .checked_add(1)
                .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                    field: "collect.count",
                })?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
#[path = "retained_tests.rs"]
mod tests;
