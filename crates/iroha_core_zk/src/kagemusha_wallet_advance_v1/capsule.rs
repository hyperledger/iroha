//! Frozen recovery capsules in redundant boot-stamped copies (spec §4.1; G2 design A4, R3,
//! R5, R7).
//!
//! A capsule copy is `capsules/c-<selected_gen:032x>-<capsule_digest:64x>.cap` (primary) or
//! `.cap.r` (replica), holding a [`KagemushaWalletFrozenFileV1`] envelope around the canonical
//! capsule frame. The full digest in the name means a create-new collision names identical
//! frame bytes; every read still re-checks the digest and decodes the frame.
//!
//! The redundancy machinery here ([`KagemushaWalletLoadedPairV1`],
//! [`kagemusha_wallet_repair_pair_v1`], [`kagemusha_wallet_settle_pair_v1`]) is generic over
//! [`KagemushaWalletFrozenFrameV1`] and is shared with completion records. It never treats an
//! unavailable copy as absent: a pair with no valid copy and at least one unavailable copy is
//! `Unavailable`, and only a pair whose copies are all definitively absent or invalid is
//! missing.

use iroha_data_model::kagemusha::{
    KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1, KagemushaWalletDigestRoleV1,
    KagemushaWalletRecoveryCapsuleV1, KagemushaWalletValidationErrorV1, kagemusha_wallet_digest_v1,
};

use super::{
    KagemushaWalletProviderErrorV1, decode_envelope_v1, encode_envelope_v1,
    layout::{
        KagemushaWalletCapsuleNameV1, KagemushaWalletCopyV1, KagemushaWalletCustodyDirV1,
        KagemushaWalletEntryNameV1, KagemushaWalletSlotIdV1, kagemusha_wallet_capsule_name_v1,
        kagemusha_wallet_capsules_dir_v1, kagemusha_wallet_is_staging_name_v1,
        kagemusha_wallet_list_dir_v1, kagemusha_wallet_parse_capsule_name_v1,
        kagemusha_wallet_require_published_v1, kagemusha_wallet_require_removed_v1,
    },
    marker::{KagemushaWalletDurableMarkerV1, KagemushaWalletMarkerPhaseV1},
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletNotPublishedV1,
        KagemushaWalletPublishOutcomeV1, KagemushaWalletReadV1, KagemushaWalletUnavailableV1,
        kagemusha_wallet_boot_stamp_v1,
    },
    store::KagemushaWalletDurableStoreV1,
};

/// Frozen-file envelope version.
pub const KAGEMUSHA_WALLET_FROZEN_FILE_VERSION_V1: u16 = 1;
/// Envelope overhead allowed beyond a frame's own bound.
pub const KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1: usize = 512;

/// Canonical frozen object persisted by the provider: a G1 recovery capsule, a completion
/// record, or a later object of the same shape. The provider stores its exact frame and
/// checks its digest; it never interprets the object beyond this trait.
pub trait KagemushaWalletFrozenFrameV1: Sized {
    /// Object label for errors.
    const OBJECT: &'static str;
    /// Maximum canonical frame bytes.
    const MAX_FRAME_BYTES: usize;
    /// Expected binding passed to the decoder (for example a scheme or wallet identity); the
    /// Advance and reconcile owners derive it from the current marker.
    type Binding;

    /// Validate and encode the canonical frame.
    ///
    /// # Errors
    ///
    /// Returns the owner's validation error.
    fn encode_frame(&self) -> Result<Vec<u8>, KagemushaWalletValidationErrorV1>;

    /// Decode and validate one canonical frame under `binding`.
    ///
    /// # Errors
    ///
    /// Returns the owner's validation error.
    fn decode_frame(
        bytes: &[u8],
        binding: &Self::Binding,
    ) -> Result<Self, KagemushaWalletValidationErrorV1>;

    /// Digest of one canonical frame.
    fn frame_digest(frame: &[u8]) -> [u8; 32];
}

impl KagemushaWalletFrozenFrameV1 for KagemushaWalletRecoveryCapsuleV1 {
    const OBJECT: &'static str = "capsule";
    const MAX_FRAME_BYTES: usize = KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1;
    /// Expected scheme identity.
    type Binding = [u8; 32];

    fn encode_frame(&self) -> Result<Vec<u8>, KagemushaWalletValidationErrorV1> {
        Ok(self.to_canonical_bytes())
    }

    fn decode_frame(
        bytes: &[u8],
        binding: &[u8; 32],
    ) -> Result<Self, KagemushaWalletValidationErrorV1> {
        Self::decode_canonical(bytes, binding)
    }

    fn frame_digest(frame: &[u8]) -> [u8; 32] {
        kagemusha_wallet_digest_v1(KagemushaWalletDigestRoleV1::Capsule, frame)
    }
}

/// Boot-stamped envelope of one frozen frame copy.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::FrozenFileV1")]
pub struct KagemushaWalletFrozenFileV1 {
    /// Envelope version; exactly [`KAGEMUSHA_WALLET_FROZEN_FILE_VERSION_V1`].
    pub version: u16,
    /// Boot identity when written; zero when it could not be read.
    pub written_boot_id: [u8; 32],
    /// Generation of the Selected marker that binds (or would bind) the frame.
    pub selected_generation: u128,
    /// Canonical frame.
    pub frame: Vec<u8>,
}

/// Maximum envelope bytes of one copy of `T`.
pub(super) fn file_max<T: KagemushaWalletFrozenFrameV1>() -> usize {
    T::MAX_FRAME_BYTES.saturating_add(KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1)
}

/// Encode one boot-stamped envelope around `frame`.
pub(super) fn encode_file<T: KagemushaWalletFrozenFrameV1>(
    selected_generation: u128,
    written_boot_id: [u8; 32],
    frame: &[u8],
) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
    encode_envelope_v1(
        &KagemushaWalletFrozenFileV1 {
            version: KAGEMUSHA_WALLET_FROZEN_FILE_VERSION_V1,
            written_boot_id,
            selected_generation,
            frame: frame.to_vec(),
        },
        file_max::<T>(),
    )
}

/// State of one copy of a redundant pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletCopyStateV1 {
    /// Present and valid.
    Valid,
    /// Definitively absent.
    Absent,
    /// Present but oversized, undecodable, for another generation or digest, or not the pair's
    /// frame.
    Invalid,
    /// Not readable now; never treated as absent.
    Unavailable(KagemushaWalletUnavailableV1),
}

/// Valid copy bytes retained for fresh-inode adoption.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidCopyV1 {
    file_bytes: Vec<u8>,
    written_boot_id: [u8; 32],
}

/// A redundant pair read from disk with at least one valid copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletLoadedPairV1<T> {
    value: T,
    frame: Vec<u8>,
    frame_digest: [u8; 32],
    selected_generation: u128,
    dir: KagemushaWalletCustodyDirV1,
    names: [KagemushaWalletEntryNameV1; 2],
    states: [KagemushaWalletCopyStateV1; 2],
    valid: [Option<ValidCopyV1>; 2],
}

impl<T> KagemushaWalletLoadedPairV1<T> {
    /// Decoded value of the valid copy.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume into the decoded value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Exact canonical frame.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Frame digest.
    pub fn frame_digest(&self) -> &[u8; 32] {
        &self.frame_digest
    }

    /// Generation of the Selected marker the pair belongs to.
    pub fn selected_generation(&self) -> u128 {
        self.selected_generation
    }

    /// State of `copy` (test diagnostics).
    #[cfg(test)]
    pub fn state(&self, copy: KagemushaWalletCopyV1) -> KagemushaWalletCopyStateV1 {
        self.states[copy_index(copy)]
    }

    /// Whether `copy` may have been written in the current boot.
    pub fn written_this_boot(
        &self,
        copy: KagemushaWalletCopyV1,
        current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    ) -> bool {
        self.valid[copy_index(copy)].as_ref().is_some_and(|valid| {
            super::platform::kagemusha_wallet_written_this_boot_v1(
                &valid.written_boot_id,
                current_boot,
            )
        })
    }
}

fn copy_index(copy: KagemushaWalletCopyV1) -> usize {
    match copy {
        KagemushaWalletCopyV1::Primary => 0,
        KagemushaWalletCopyV1::Replica => 1,
    }
}

/// Read both copies of a pair and keep the first valid one.
///
/// `accept` checks the decoded value and frame digest against what the caller expects. A
/// valid replica whose frame differs from a valid primary is classified `Invalid`.
///
/// Returns `Ok(None)` when every copy is absent or invalid.
///
/// # Errors
///
/// `Unavailable` when no copy is valid and at least one could not be read.
pub(super) fn read_pair<F, T>(
    store: &KagemushaWalletDurableStoreV1<F>,
    dir: &KagemushaWalletCustodyDirV1,
    names: [KagemushaWalletEntryNameV1; 2],
    selected_generation: u128,
    binding: &T::Binding,
    accept: impl Fn(&T, &[u8; 32]) -> bool,
) -> Result<Option<KagemushaWalletLoadedPairV1<T>>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    T: KagemushaWalletFrozenFrameV1,
{
    Ok(
        match read_pair_states(store, dir, names, selected_generation, binding, accept)? {
            KagemushaWalletPairReadV1::Loaded(pair) => Some(pair),
            KagemushaWalletPairReadV1::Missing(_) => None,
        },
    )
}

/// A redundant pair read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum KagemushaWalletPairReadV1<T> {
    /// At least one copy is valid.
    Loaded(KagemushaWalletLoadedPairV1<T>),
    /// No copy is valid: each copy is `Absent` (a definitive native-open absence) or
    /// `Invalid`, never `Unavailable`.
    Missing([KagemushaWalletCopyStateV1; 2]),
}

/// [`read_pair`] that keeps the per-copy states of a pair without a valid copy.
///
/// # Errors
///
/// As [`read_pair`].
pub(super) fn read_pair_states<F, T>(
    store: &KagemushaWalletDurableStoreV1<F>,
    dir: &KagemushaWalletCustodyDirV1,
    names: [KagemushaWalletEntryNameV1; 2],
    selected_generation: u128,
    binding: &T::Binding,
    accept: impl Fn(&T, &[u8; 32]) -> bool,
) -> Result<KagemushaWalletPairReadV1<T>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    T: KagemushaWalletFrozenFrameV1,
{
    let mut states = [KagemushaWalletCopyStateV1::Absent; 2];
    let mut valid: [Option<ValidCopyV1>; 2] = [None, None];
    let mut chosen: Option<(T, Vec<u8>, [u8; 32])> = None;
    for (index, name) in names.iter().enumerate() {
        let bytes = match store.read(dir, name, file_max::<T>()) {
            KagemushaWalletReadV1::Present(bytes) => bytes,
            KagemushaWalletReadV1::Absent => continue,
            KagemushaWalletReadV1::Oversized => {
                states[index] = KagemushaWalletCopyStateV1::Invalid;
                continue;
            }
            KagemushaWalletReadV1::Unavailable(reason) => {
                states[index] = KagemushaWalletCopyStateV1::Unavailable(reason);
                continue;
            }
        };
        let decoded = decode_envelope_v1::<KagemushaWalletFrozenFileV1>(&bytes, file_max::<T>())
            .ok()
            .filter(|file| {
                file.version == KAGEMUSHA_WALLET_FROZEN_FILE_VERSION_V1
                    && file.selected_generation == selected_generation
                    && file.frame.len() <= T::MAX_FRAME_BYTES
            })
            .and_then(|file| {
                let digest = T::frame_digest(&file.frame);
                let value = T::decode_frame(&file.frame, binding).ok()?;
                accept(&value, &digest).then_some((value, file, digest))
            });
        let Some((value, file, digest)) = decoded else {
            states[index] = KagemushaWalletCopyStateV1::Invalid;
            continue;
        };
        if let Some((_, frame, _)) = &chosen
            && *frame != file.frame
        {
            states[index] = KagemushaWalletCopyStateV1::Invalid;
            continue;
        }
        states[index] = KagemushaWalletCopyStateV1::Valid;
        valid[index] = Some(ValidCopyV1 {
            file_bytes: bytes,
            written_boot_id: file.written_boot_id,
        });
        if chosen.is_none() {
            chosen = Some((value, file.frame, digest));
        }
    }
    let Some((value, frame, frame_digest)) = chosen else {
        if let Some(reason) = states.iter().find_map(|state| match state {
            KagemushaWalletCopyStateV1::Unavailable(reason) => Some(*reason),
            _ => None,
        }) {
            return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
        }
        return Ok(KagemushaWalletPairReadV1::Missing(states));
    };
    Ok(KagemushaWalletPairReadV1::Loaded(KagemushaWalletLoadedPairV1 {
        value,
        frame,
        frame_digest,
        selected_generation,
        dir: dir.clone(),
        names,
        states,
        valid,
    }))
}

/// Restore every copy of `pair` that is absent or invalid from the valid frame, stamped with
/// the current boot. Invalid copies are removed durably first.
///
/// # Errors
///
/// `Unavailable` when a copy cannot be read now or a write fails, `Uncertain` when a write's
/// outcome is unknown, `NoSpace` when storage is full.
pub(super) fn kagemusha_wallet_repair_pair_v1<F, T>(
    store: &KagemushaWalletDurableStoreV1<F>,
    pair: &mut KagemushaWalletLoadedPairV1<T>,
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
) -> Result<(), KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    T: KagemushaWalletFrozenFrameV1,
{
    for index in 0..2 {
        match pair.states[index] {
            KagemushaWalletCopyStateV1::Valid => continue,
            KagemushaWalletCopyStateV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
            }
            KagemushaWalletCopyStateV1::Invalid => {
                kagemusha_wallet_require_removed_v1(
                    store.remove_file(&pair.dir, &pair.names[index]),
                )?;
                pair.states[index] = KagemushaWalletCopyStateV1::Absent;
            }
            KagemushaWalletCopyStateV1::Absent => {}
        }
        let written_boot_id = kagemusha_wallet_boot_stamp_v1(current_boot);
        let file_bytes = encode_file::<T>(pair.selected_generation, written_boot_id, &pair.frame)?;
        kagemusha_wallet_require_published_v1(store.write_new(
            &pair.dir,
            &pair.names[index],
            &file_bytes,
        ))?;
        pair.states[index] = KagemushaWalletCopyStateV1::Valid;
        pair.valid[index] = Some(ValidCopyV1 {
            file_bytes,
            written_boot_id,
        });
    }
    Ok(())
}

/// Make every valid copy of `pair` durable: rewrite it to a fresh inode when `fresh_inode`
/// (a file of the current boot under a Selected marker, G2 design R3), otherwise sync it;
/// then sync the directory.
///
/// # Errors
///
/// `Uncertain` when a rewrite's outcome is unknown and `Unavailable` when a sync fails or a
/// copy changed concurrently.
pub(super) fn kagemusha_wallet_settle_pair_v1<F, T>(
    store: &KagemushaWalletDurableStoreV1<F>,
    pair: &KagemushaWalletLoadedPairV1<T>,
    fresh_inode: bool,
) -> Result<(), KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
{
    for (name, valid) in pair.names.iter().zip(&pair.valid) {
        let Some(valid) = valid else {
            continue;
        };
        if fresh_inode {
            kagemusha_wallet_require_published_v1(store.rewrite_same(
                &pair.dir,
                name,
                &valid.file_bytes,
            ))?;
        } else {
            store
                .sync_file(&pair.dir, name)
                .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
        }
    }
    store
        .sync_dir(&pair.dir)
        .map_err(KagemushaWalletProviderErrorV1::Unavailable)
}

/// Durably remove both copies named `names` in `dir`.
///
/// # Errors
///
/// `Unavailable` or `Uncertain` when a removal fails or its outcome is unknown.
pub(super) fn remove_pair<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    dir: &KagemushaWalletCustodyDirV1,
    names: &[KagemushaWalletEntryNameV1; 2],
) -> Result<(), KagemushaWalletProviderErrorV1> {
    for name in names {
        kagemusha_wallet_require_removed_v1(store.remove_file(dir, name))?;
    }
    Ok(())
}

/// Map one pair-write outcome; `DestinationExists` is returned as `Ok(false)`.
pub(super) fn pair_write_published(
    outcome: KagemushaWalletPublishOutcomeV1,
) -> Result<bool, KagemushaWalletProviderErrorV1> {
    match outcome {
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        ) => Ok(false),
        other => kagemusha_wallet_require_published_v1(other).map(|()| true),
    }
}

/// Write both copies of `frame` create-new.
pub(super) fn write_pair<F, T>(
    store: &KagemushaWalletDurableStoreV1<F>,
    dir: &KagemushaWalletCustodyDirV1,
    names: &[KagemushaWalletEntryNameV1; 2],
    selected_generation: u128,
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    frame: &[u8],
) -> Result<[KagemushaWalletPublishOutcomeV1; 2], KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    T: KagemushaWalletFrozenFrameV1,
{
    let file_bytes = encode_file::<T>(
        selected_generation,
        kagemusha_wallet_boot_stamp_v1(current_boot),
        frame,
    )?;
    Ok(store.write_new_pair(dir, (&names[0], &file_bytes), (&names[1], &file_bytes)))
}

// ---------------------------------------------------------------------------------------
// Capsules
// ---------------------------------------------------------------------------------------

/// Both copy names of one capsule.
#[must_use]
pub fn kagemusha_wallet_capsule_names_v1(
    selected_generation: u128,
    capsule_digest: &[u8; 32],
) -> [KagemushaWalletEntryNameV1; 2] {
    KagemushaWalletCopyV1::BOTH
        .map(|copy| kagemusha_wallet_capsule_name_v1(selected_generation, capsule_digest, copy))
}

/// Capsule staged durably for the next Selected marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletStagedCapsuleV1 {
    /// Generation of the Selected marker that will bind it.
    pub selected_generation: u128,
    /// Capsule digest the marker and the receipt bind.
    pub capsule_digest: [u8; 32],
}

/// Stage both copies of a frozen capsule for the generation after the durable `current`
/// marker (G2 design A4).
///
/// Existing copies of the same name are adopted after their digest and frame are checked and
/// rewritten to a fresh inode; invalid ones are replaced. Nothing a durable marker binds is
/// ever touched: the target generation is above every marker.
///
/// # Errors
///
/// `Invalid` when `current` is not an Enrollment or Released marker, is no longer current on
/// disk, or the capsule does not encode; `NoSpace`, `NoReplaceUnsupported`, `Unavailable` and
/// `Uncertain` from the reads and writes.
pub(super) fn kagemusha_wallet_stage_capsule_v1<F, C>(
    store: &KagemushaWalletDurableStoreV1<F>,
    current: &KagemushaWalletDurableMarkerV1,
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    capsule: &C,
    binding: &C::Binding,
) -> Result<KagemushaWalletStagedCapsuleV1, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    C: KagemushaWalletFrozenFrameV1,
{
    let record = current.record();
    if !matches!(
        record.phase(),
        KagemushaWalletMarkerPhaseV1::Enrollment | KagemushaWalletMarkerPhaseV1::Released
    ) {
        return Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "marker.phase",
        });
    }
    current.require_current(store)?;
    let selected_generation =
        record
            .generation()
            .checked_add(1)
            .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.generation",
            })?;
    let frame = capsule
        .encode_frame()
        .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: C::OBJECT })?;
    let capsule_digest = C::frame_digest(&frame);
    let dir = kagemusha_wallet_capsules_dir_v1(record.slot());
    let names = kagemusha_wallet_capsule_names_v1(selected_generation, &capsule_digest);
    let outcomes = write_pair::<F, C>(
        store,
        &dir,
        &names,
        selected_generation,
        current_boot,
        &frame,
    )?;
    let mut fresh = true;
    for outcome in outcomes {
        fresh &= pair_write_published(outcome)?;
    }
    if !fresh {
        // A copy of this exact name already exists (an interrupted earlier attempt): adopt it
        // after checking it, replace an invalid one, and rewrite it to a fresh inode.
        match read_pair::<F, C>(
            store,
            &dir,
            names.clone(),
            selected_generation,
            binding,
            |_, digest| *digest == capsule_digest,
        )? {
            Some(mut pair) => {
                kagemusha_wallet_repair_pair_v1(store, &mut pair, current_boot)?;
                kagemusha_wallet_settle_pair_v1(store, &pair, true)?;
            }
            None => {
                remove_pair(store, &dir, &names)?;
                for outcome in write_pair::<F, C>(
                    store,
                    &dir,
                    &names,
                    selected_generation,
                    current_boot,
                    &frame,
                )? {
                    kagemusha_wallet_require_published_v1(outcome)?;
                }
            }
        }
    }
    Ok(KagemushaWalletStagedCapsuleV1 {
        selected_generation,
        capsule_digest,
    })
}

/// Load the capsule bound by a Selected or Released marker from either copy.
///
/// # Errors
///
/// `Unavailable` when no copy is valid and one could not be read; `UnavailableCustodyData`
/// when every copy is absent or invalid (never a fallback to the old balance).
pub fn kagemusha_wallet_load_capsule_v1<F, C>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
    selected_generation: u128,
    capsule_digest: &[u8; 32],
    binding: &C::Binding,
) -> Result<KagemushaWalletLoadedPairV1<C>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    C: KagemushaWalletFrozenFrameV1,
{
    read_pair::<F, C>(
        store,
        &kagemusha_wallet_capsules_dir_v1(slot),
        kagemusha_wallet_capsule_names_v1(selected_generation, capsule_digest),
        selected_generation,
        binding,
        |_, digest| digest == capsule_digest,
    )?
    .ok_or(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: C::OBJECT })
}

/// Durably discard staged capsule copies above the durable `current` marker (G2 design R7).
///
/// # Errors
///
/// `Invalid` when the generation is not above `current` (such a capsule may be bound) or
/// `current` is no longer current on disk; `Unavailable` or `Uncertain` from the reads and
/// removals.
pub(super) fn kagemusha_wallet_discard_staged_capsule_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    current: &KagemushaWalletDurableMarkerV1,
    selected_generation: u128,
    capsule_digest: &[u8; 32],
) -> Result<(), KagemushaWalletProviderErrorV1> {
    if selected_generation <= current.record().generation() {
        return Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "capsule.selected_generation",
        });
    }
    // A superseded `current` could name a generation a newer marker binds.
    current.require_current(store)?;
    remove_pair(
        store,
        &kagemusha_wallet_capsules_dir_v1(current.record().slot()),
        &kagemusha_wallet_capsule_names_v1(selected_generation, capsule_digest),
    )
}
// Capsules below the current head are collected after the state owner's durable
// acknowledgement by `retained.rs` (`collect_capsules`); the bound capsule never is.

/// List `capsules/` of `slot` strictly; `None` when the directory is definitively absent.
///
/// Staging files are skipped (reconcile removes them).
///
/// # Errors
///
/// `Unavailable` on a listing error and `UnexpectedEntry` for a foreign entry.
pub fn kagemusha_wallet_list_capsules_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<Option<Vec<KagemushaWalletCapsuleNameV1>>, KagemushaWalletProviderErrorV1> {
    let Some(entries) =
        kagemusha_wallet_list_dir_v1(store, &kagemusha_wallet_capsules_dir_v1(slot))?
    else {
        return Ok(None);
    };
    let mut names = Vec::with_capacity(entries.len());
    for entry in entries {
        let parsed = (entry.kind == KagemushaWalletEntryKindV1::File)
            .then(|| kagemusha_wallet_parse_capsule_name_v1(&entry.name))
            .flatten();
        match parsed {
            Some(name) => names.push(name),
            None if entry.kind == KagemushaWalletEntryKindV1::File
                && kagemusha_wallet_is_staging_name_v1(&entry.name) => {}
            None => {
                return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "capsules" });
            }
        }
    }
    Ok(Some(names))
}

#[cfg(test)]
#[path = "capsule_tests.rs"]
mod tests;
