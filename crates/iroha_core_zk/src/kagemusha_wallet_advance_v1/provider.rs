//! Exclusive provider handle over one custody root (spec §4.1; G2 design rev 2 §§1, 4, 5).
//!
//! [`KagemushaWalletProviderV1`] owns the durable store, the platform services and the
//! exclusive custody lock for its lifetime: a second opener of the same root gets
//! `Unavailable(Busy)`, and any lock error is `Unavailable` (the provider never proceeds
//! unlocked). Every mutating method takes `&mut self`, so operations on one root are serialized
//! inside the process; the bridge keeps one handle per process.
//!
//! Each operation starts with reconciliation of its slot (`reconcile.rs`). A slot whose marker
//! was verified by a full reconcile is cached; the next operation only re-lists `markers/` and
//! compares the current marker's exact bytes. This includes a selected head that waits for its
//! receipt (`Pending`): its unacknowledged files were rewritten once by the full reconcile, so
//! later status calls in this process do not rewrite them again, and calls with a transition
//! owner retry only the finishing steps. Any write with an unknown outcome drops the cache
//! entry (poisons the slot), so the next operation reconciles fully from disk.
//!
//! The durable store and the platform services are private to the provider: custody files
//! and the payment key are reached only through its operations.

use std::{collections::BTreeMap, marker::PhantomData};

use iroha_data_model::kagemusha::{
    KagemushaWalletCompletionRecordV1, KagemushaWalletRecoveryCapsuleV1,
};

use super::{
    KagemushaWalletProviderErrorV1,
    advance::{KagemushaWalletAdvanceCapsuleV1, KagemushaWalletTransitionOwnerV1},
    completion::KagemushaWalletCompletionFrameV1,
    layout::{
        KAGEMUSHA_WALLET_BALLAST_BYTES_V1, KAGEMUSHA_WALLET_CANARY_NAME_V1,
        KAGEMUSHA_WALLET_LOCK_NAME_V1, KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1,
        KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1, KagemushaWalletCustodyDirV1,
        KagemushaWalletRootSentinelV1, KagemushaWalletSlotIdV1,
        kagemusha_wallet_is_staging_name_v1, kagemusha_wallet_list_dir_v1,
        kagemusha_wallet_list_slots_v1, kagemusha_wallet_prepare_root_v1,
        kagemusha_wallet_read_root_sentinel_v1,
    },
    marker::{KagemushaWalletDurableMarkerV1, KagemushaWalletMarkerRecordV1},
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletPlatformV1,
        KagemushaWalletUnavailableV1,
    },
    store::KagemushaWalletDurableStoreV1,
};

/// Node-local provider options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KagemushaWalletProviderOptionsV1 {
    /// Size of the capacity ballast; production uses the worst-case Advance footprint
    /// [`KAGEMUSHA_WALLET_BALLAST_BYTES_V1`].
    pub ballast_bytes: u64,
}

impl Default for KagemushaWalletProviderOptionsV1 {
    fn default() -> Self {
        Self {
            ballast_bytes: KAGEMUSHA_WALLET_BALLAST_BYTES_V1,
        }
    }
}

/// Reconciled state of one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KagemushaWalletSlotStatusV1 {
    /// The slot directory exists without an intent: an interrupted slot creation, never used.
    Empty,
    /// The intent is durable, the payment key is definitively absent and no marker exists:
    /// enrollment may continue on this slot while its challenge is live.
    IntentOnly,
    /// The slot was abandoned before any marker; its key (if any) is never used.
    SlotAbandoned,
    /// The generation-0 enrollment marker is current.
    Enrollment(KagemushaWalletMarkerRecordV1),
    /// A selected head waits for its receipt (signing unavailable, or no transition owner was
    /// given); the operation is performed but not released.
    Pending(KagemushaWalletMarkerRecordV1),
    /// A released head is current.
    Released(KagemushaWalletMarkerRecordV1),
    /// A terminal marker is current; operations are refused.
    Terminal(KagemushaWalletMarkerRecordV1),
}

impl KagemushaWalletSlotStatusV1 {
    /// Current marker, when one exists.
    #[must_use]
    pub fn marker(&self) -> Option<&KagemushaWalletMarkerRecordV1> {
        match self {
            Self::Enrollment(record)
            | Self::Pending(record)
            | Self::Released(record)
            | Self::Terminal(record) => Some(record),
            Self::Empty | Self::IntentOnly | Self::SlotAbandoned => None,
        }
    }
}

/// Verified durable marker of one slot and the status it produced.
#[derive(Debug, Clone)]
pub(super) struct CachedSlotV1 {
    pub(super) durable: KagemushaWalletDurableMarkerV1,
    pub(super) status: KagemushaWalletSlotStatusV1,
}

/// Stock-phone Advance provider over one custody root.
///
/// `C` and `R` are the frozen capsule and completion types (the G1 objects by default).
pub struct KagemushaWalletProviderV1<
    F: KagemushaWalletFsV1,
    P,
    C = KagemushaWalletRecoveryCapsuleV1,
    R = KagemushaWalletCompletionRecordV1,
> {
    pub(super) store: KagemushaWalletDurableStoreV1<F>,
    pub(super) platform: P,
    pub(super) scheme_id: [u8; 32],
    pub(super) options: KagemushaWalletProviderOptionsV1,
    pub(super) cache: BTreeMap<KagemushaWalletSlotIdV1, CachedSlotV1>,
    pub(super) pending_reasons: BTreeMap<KagemushaWalletSlotIdV1, KagemushaWalletProviderErrorV1>,
    pub(super) generation_results:
        BTreeMap<KagemushaWalletSlotIdV1, super::enrollment::RetainedGeneratedKeyV1>,
    pub(super) generation_dispatches:
        BTreeMap<KagemushaWalletSlotIdV1, super::enrollment::RetainedGenerationDispatchV1>,
    /// Exact bytes this process published or durably adopted on a fresh inode, by directory and
    /// name. A visible record from an uncertain write authorizes nothing until it is adopted
    /// here; a sync alone cannot prove durability after a lost writeback.
    pub(super) adopted:
        std::cell::RefCell<BTreeMap<(KagemushaWalletCustodyDirV1, String), Vec<u8>>>,
    /// Request identity and exact phase version this process last verified for each phased
    /// slot; cached returns re-read the phase and compare.
    /// Bytes are the phase, Client, Accepted permit and Slot selection, in that order.
    pub(super) slot_phases:
        std::cell::RefCell<BTreeMap<KagemushaWalletSlotIdV1, ([u8; 32], [Vec<u8>; 4])>>,
    sentinel: KagemushaWalletRootSentinelV1,
    _lock: F::Lock,
    _frames: PhantomData<fn() -> (C, R)>,
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Open the custody root behind `fs` for slots of `scheme_id` (design R0): require
    /// available protected storage, take the exclusive lock, then adopt the root sentinel or
    /// create it on a root that holds nothing else.
    ///
    /// # Errors
    ///
    /// `Unavailable` when storage is locked, the lock is held elsewhere (`Busy`) or any read
    /// fails; `UnavailableCustodyData` for an invalid sentinel, a sentinel without `slots/`, or
    /// a root that holds custody entries without one; `Invalid` for a zero ballast size; the
    /// write errors of the sentinel adoption and directory creation (a sentinel is rewritten to
    /// a fresh inode on every open, two syncs).
    pub fn open(
        fs: F,
        platform: P,
        scheme_id: [u8; 32],
        options: KagemushaWalletProviderOptionsV1,
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        if options.ballast_bytes == 0 {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "options.ballast_bytes",
            });
        }
        platform
            .storage_state()
            .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
        let store = KagemushaWalletDurableStoreV1::new(fs);
        let lock = store
            .lock_exclusive()
            .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
        if kagemusha_wallet_read_root_sentinel_v1(&store)?.is_none() {
            // A fresh root holds at most the lock, the canary, staging files and the skeleton
            // directories of an interrupted first open (their emptiness is checked when they
            // are recreated); anything else without a sentinel is never adopted as an empty
            // wallet.
            let entries =
                kagemusha_wallet_list_dir_v1(&store, &KagemushaWalletCustodyDirV1::root())?
                    .unwrap_or_default();
            if entries.iter().any(|entry| {
                let skeleton = entry.kind == KagemushaWalletEntryKindV1::Directory
                    && (entry.name == KAGEMUSHA_WALLET_PROBE_DIR_NAME_V1
                        || entry.name == KAGEMUSHA_WALLET_SLOTS_DIR_NAME_V1);
                !skeleton
                    && entry.name != KAGEMUSHA_WALLET_LOCK_NAME_V1
                    && entry.name != KAGEMUSHA_WALLET_CANARY_NAME_V1
                    && !kagemusha_wallet_is_staging_name_v1(&entry.name)
            }) {
                return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "root sentinel",
                });
            }
        }
        let sentinel = kagemusha_wallet_prepare_root_v1(&store)?;
        Ok(Self {
            store,
            platform,
            scheme_id,
            options,
            cache: BTreeMap::new(),
            pending_reasons: BTreeMap::new(),
            generation_results: BTreeMap::new(),
            generation_dispatches: BTreeMap::new(),
            adopted: std::cell::RefCell::new(BTreeMap::new()),
            slot_phases: std::cell::RefCell::new(BTreeMap::new()),
            sentinel,
            _lock: lock,
            _frames: PhantomData,
        })
    }

    /// Durable store (provider-internal; tests).
    #[cfg(test)]
    pub(super) fn store(&self) -> &KagemushaWalletDurableStoreV1<F> {
        &self.store
    }

    /// Platform services (provider-internal; tests: the payment key is reached only through
    /// the provider's operations).
    #[cfg(test)]
    pub(super) fn platform(&self) -> &P {
        &self.platform
    }

    /// Why the selected head of `slot` was last left unreleased in this process, when it was:
    /// signing unavailable, an unknown write outcome, a full disk, or a transition-owner
    /// failure. The operation itself stays performed and pending; this is a diagnostic only.
    #[must_use]
    pub fn pending_reason(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Option<KagemushaWalletProviderErrorV1> {
        self.pending_reasons.get(slot).copied()
    }

    /// Scheme of every slot under this root.
    pub fn scheme_id(&self) -> &[u8; 32] {
        &self.scheme_id
    }

    /// Root sentinel.
    pub fn sentinel(&self) -> &KagemushaWalletRootSentinelV1 {
        &self.sentinel
    }

    /// Options.
    pub fn options(&self) -> &KagemushaWalletProviderOptionsV1 {
        &self.options
    }

    /// Every file slot and, on Keychain platforms, every surviving payment-key slot,
    /// ascending and unique. A key with no app files is retained for read-only R10 diagnosis;
    /// listing creates no slot, key, marker or replacement wallet.
    ///
    /// # Errors
    ///
    /// `Unavailable` on storage, listing or Keychain enumeration errors, including malformed
    /// or oversized platform inventories, and `UnexpectedEntry` for a foreign file entry.
    pub fn slots(&self) -> Result<Vec<KagemushaWalletSlotIdV1>, KagemushaWalletProviderErrorV1> {
        self.require_storage()?;
        let answer = (|| {
            let mut slots = kagemusha_wallet_list_slots_v1(&self.store)?.unwrap_or_default();
            if self.platform.anchor_policy() == super::KagemushaWalletAnchorPolicyV1::Keychain {
                let keys = self
                    .platform
                    .key_enumerate()
                    .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
                if keys.len() > super::KAGEMUSHA_WALLET_KEY_ENUMERATION_MAX_SLOTS_V1
                    || keys.iter().any(|slot| slot.0 == [0; 32])
                    || !keys.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(KagemushaWalletProviderErrorV1::Unavailable(
                        KagemushaWalletUnavailableV1::Platform(0),
                    ));
                }
                slots.extend(keys);
            }
            slots.sort_unstable();
            slots.dedup();
            Ok(slots)
        })();
        // A successful empty read, or a custody-loss candidate, counts only while storage
        // remained available. A lock transition never authorizes empty-wallet recreation.
        self.require_storage().and(answer)
    }

    /// Reconcile `slot` without signing: a selected head stays `Pending`.
    ///
    /// # Errors
    ///
    /// As [`Self::reconcile`].
    pub fn status(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        self.reconcile_slot(slot, None)
    }

    /// Reconcile `slot` (startup, after an uncertain write and before every operation) and
    /// finish a selected head offline with `owner`.
    ///
    /// # Errors
    ///
    /// `Unavailable` (retry) for any read, lock, key-store or storage error; `Uncertain` when a
    /// write's outcome is unknown; `UnavailableCustodyData` for a current marker or bound
    /// object missing in every copy; `LostCustody` and `KeyLost` for custody loss, which is
    /// shown and never acted on destructively; `UnexpectedEntry` for a foreign entry.
    pub fn reconcile(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
    ) -> Result<KagemushaWalletSlotStatusV1, KagemushaWalletProviderErrorV1> {
        self.reconcile_slot(slot, Some(owner))
    }

    /// Read the actual payment key inside protected-storage brackets, without generation.
    /// Positive lookup remains useful even when the platform cannot prove absence.
    /// # Errors
    /// Locked or unavailable storage. An unknown key result remains `Unavailable`.
    pub fn probe_payment_key(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<
        super::KagemushaWalletProbeV1<iroha_data_model::kagemusha::KagemushaDevicePublicKeyV1>,
        KagemushaWalletProviderErrorV1,
    > {
        self.probe_key(slot)
    }

    /// Read the exact capsule selected by the reconciled current source marker.
    /// This read capability creates no Selected marker or monetary proof verdict.
    /// # Errors
    /// Reconciliation, custody loss or unknown protected-storage/read state; never absence.
    pub fn current_capsule(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<Option<C>, KagemushaWalletProviderErrorV1> {
        let status = self.status(slot)?;
        let record = match status {
            KagemushaWalletSlotStatusV1::Enrollment(_) => return Ok(None),
            KagemushaWalletSlotStatusV1::Pending(record)
            | KagemushaWalletSlotStatusV1::Released(record) => record,
            KagemushaWalletSlotStatusV1::Terminal(_) => {
                return Err(KagemushaWalletProviderErrorV1::Terminal);
            }
            _ => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "current source",
                });
            }
        };
        self.require_storage()?;
        let answer = (|| {
            let selected = record.selected_generation().ok_or(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "selected generation",
                },
            )?;
            let (_, _, digest) =
                record
                    .head()
                    .ok_or(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                        object: "selected capsule",
                    })?;
            let capsule = super::capsule::kagemusha_wallet_load_capsule_v1::<F, C>(
                &self.store,
                slot,
                selected,
                &digest,
                &C::marker_binding(record.marker()),
            )?;
            Ok(Some(capsule.into_value()))
        })();
        self.require_storage().and(answer)
    }

    /// Read a native sleep-inclusive clock under the same protected custody lifetime.
    /// No payment key or store is exposed; unknown time never becomes a zero reading.
    pub(crate) fn monotonic_reading(
        &self,
    ) -> Result<
        iroha_data_model::kagemusha::KagemushaWalletMonotonicReadingV1,
        KagemushaWalletProviderErrorV1,
    > {
        self.require_storage()?;
        let answer = (|| {
            let boot_id = self
                .boot()
                .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
            if boot_id == [0; 32] {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Platform(0),
                ));
            }
            let monotonic_ms = self
                .platform
                .monotonic_ms()
                .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
            if self
                .boot()
                .map_err(KagemushaWalletProviderErrorV1::Unavailable)?
                != boot_id
            {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
            Ok(
                iroha_data_model::kagemusha::KagemushaWalletMonotonicReadingV1 {
                    boot_id,
                    monotonic_ms,
                },
            )
        })();
        self.require_storage().and(answer)
    }

    pub(crate) fn prekey_root_identity(&self) -> [u8; 32] {
        self.sentinel.root_nonce
    }

    pub(crate) fn enrollment_generation_policy(
        &self,
    ) -> Result<super::KagemushaWalletKeyGenerationPolicyV1, KagemushaWalletProviderErrorV1> {
        self.require_storage()?;
        self.platform
            .key_generation_policy()
            .map_err(KagemushaWalletProviderErrorV1::Unavailable)
    }

    /// Current boot identity.
    pub(super) fn boot(&self) -> Result<[u8; 32], KagemushaWalletUnavailableV1> {
        self.platform.boot_id()
    }

    /// Free custody storage and memory available to the app now, for the design §5.3 runtime
    /// capacity check. Free space is read inside the protected-storage bracket.
    ///
    /// # Errors
    ///
    /// `Unavailable` when protected storage is locked or free space cannot be read. An
    /// unreadable value is never reported as a shortfall.
    pub fn runtime_resources(
        &self,
    ) -> Result<
        crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1,
        KagemushaWalletProviderErrorV1,
    > {
        self.require_storage()?;
        let storage_bytes = self
            .store
            .available_bytes()
            .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
        Ok(
            crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1 {
                storage_bytes,
                memory_bytes: self.platform.available_memory(),
            },
        )
    }

    /// Require available protected storage now. Called before and after every answer from
    /// which absence or loss would be concluded (design R0, I9): on Android, credential-
    /// encrypted names read as absent while their keys are evicted.
    ///
    /// # Errors
    ///
    /// `Unavailable` with the platform's reason.
    pub(super) fn require_storage(&self) -> Result<(), KagemushaWalletProviderErrorV1> {
        self.platform
            .storage_state()
            .map_err(KagemushaWalletProviderErrorV1::Unavailable)
    }

    /// Probe the payment key of `slot` inside storage-state brackets: an `Absent` or
    /// mismatching answer counts only while storage was available before and after it.
    ///
    /// # Errors
    ///
    /// `Unavailable` when storage is locked at either bracket.
    pub(super) fn probe_key(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<
        super::platform::KagemushaWalletProbeV1<
            iroha_data_model::kagemusha::KagemushaDevicePublicKeyV1,
        >,
        KagemushaWalletProviderErrorV1,
    > {
        self.require_storage()?;
        let answer = self.platform.key_probe(slot);
        self.require_storage()?;
        Ok(answer)
    }

    /// Durably adopt the exact visible `bytes` of `name`: republished on a fresh inode once per
    /// process (then remembered), so a record left visible by an uncertain write or a lost
    /// writeback counts only once it is durable.
    ///
    /// # Errors
    /// `Unavailable`/`Uncertain` when the republication gives no durable answer; `Unavailable`
    /// (`Busy`) when the name no longer holds exactly `bytes`.
    pub(super) fn adopt_exact(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &super::layout::KagemushaWalletEntryNameV1,
        bytes: &[u8],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let key = (dir.clone(), name.as_str().to_owned());
        if self
            .adopted
            .borrow()
            .get(&key)
            .is_some_and(|adopted| adopted.as_slice() == bytes)
        {
            return Ok(());
        }
        match self.store.rewrite_same(dir, name, bytes) {
            super::platform::KagemushaWalletPublishOutcomeV1::NotPublished(
                super::platform::KagemushaWalletNotPublishedV1::ContentMismatch
                | super::platform::KagemushaWalletNotPublishedV1::DestinationAbsent,
            ) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
            outcome => super::layout::kagemusha_wallet_require_published_v1(outcome)?,
        }
        self.adopted.borrow_mut().insert(key, bytes.to_vec());
        Ok(())
    }

    /// Remember exact bytes this process has just published durably.
    pub(super) fn note_durable(
        &self,
        dir: &KagemushaWalletCustodyDirV1,
        name: &super::layout::KagemushaWalletEntryNameV1,
        bytes: &[u8],
    ) {
        self.adopted
            .borrow_mut()
            .insert((dir.clone(), name.as_str().to_owned()), bytes.to_vec());
    }

    /// Forget the verified state of `slot`; the next operation reconciles it fully.
    pub(super) fn poison(&mut self, slot: &KagemushaWalletSlotIdV1) {
        self.cache.remove(slot);
    }

    /// Record why the selected head of `slot` stays unreleased.
    pub(super) fn note_pending(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        reason: KagemushaWalletProviderErrorV1,
    ) {
        self.pending_reasons.insert(*slot, reason);
    }

    /// Remember a verified stable state of `slot`.
    pub(super) fn remember(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        durable: KagemushaWalletDurableMarkerV1,
        status: KagemushaWalletSlotStatusV1,
    ) {
        self.cache.insert(*slot, CachedSlotV1 { durable, status });
    }

    /// Poison `slot` when `result` is an error (an unknown write outcome among them), so the
    /// next operation reconciles it fully from disk.
    pub(super) fn guard<T>(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        result: Result<T, KagemushaWalletProviderErrorV1>,
    ) -> Result<T, KagemushaWalletProviderErrorV1> {
        if result.is_err() {
            self.poison(slot);
        }
        result
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
