//! Marker generations (spec §§3.2, 4.2; G2 design rev 2 §§2, 3).
//!
//! Each marker file `markers/m-<gen:032x>.mk` is a local envelope
//! [`KagemushaWalletMarkerFileV1`] around one G1 `KagemushaWalletMarkerV1` frame. Its phase
//! is:
//!
//! | phase       | G1 state     | `completion_digest` | generation               |
//! |-------------|--------------|---------------------|--------------------------|
//! | Enrollment  | `Enrollment` | zero                | 0                        |
//! | Selected    | `Head`       | zero                | Enrollment or Released + 1 |
//! | Released    | `Head`       | nonzero             | previous + 1, same head  |
//! | Terminal    | `Terminal`   | zero                | previous + 1             |
//!
//! Released-to-Released metadata generations bind the durable archive manifest without
//! changing the monetary head, original Selected generation or completion bytes. The iOS
//! anchor is raised before the preceding marker is retired.
//!
//! A receipt may be signed only while a durable Selected marker is current
//! ([`KagemushaWalletSelectedCapabilityV1`]); under a Released marker a missing completion is
//! lost, never re-signed. The G1 `marker_digest` covers the frame only; the local
//! `marker_file_digest = H("marker-file", envelope)` also covers the phase and the slot's
//! anchor kind.
//!
//! Every marker of a slot carries the anchor kind chosen at enrollment (none on Android,
//! keychain on iPhone), so the rollback-anchor check is bound to the slot rather than to what
//! the platform adapter answers later.
//!
//! Selection reads only the highest generation. Lower generations are retired by name without
//! being read, and only after the current marker is durable
//! ([`KagemushaWalletDurableMarkerV1`]). An unexpected entry in `markers/`, or an unreadable or
//! invalid current marker, stops selection: a lower generation is never selected.
//!
//! A [`KagemushaWalletDurableMarkerV1`], and the capability derived from it, exist only for a
//! marker this module published or adopted after re-reading its exact bytes from disk; these
//! functions are private to the provider.

use iroha_data_model::kagemusha::{
    KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1, KagemushaDevicePublicKeyV1, KagemushaWalletMarkerStateV1,
    KagemushaWalletMarkerV1, KagemushaWalletTerminalReasonV1,
};

use super::{
    KagemushaWalletProviderErrorV1, decode_envelope_v1, encode_envelope_v1,
    kagemusha_wallet_provider_digest_v1,
    layout::{
        KagemushaWalletEntryNameV1, KagemushaWalletSlotIdV1, kagemusha_wallet_is_staging_name_v1,
        kagemusha_wallet_list_dir_v1, kagemusha_wallet_marker_name_v1,
        kagemusha_wallet_markers_dir_v1, kagemusha_wallet_parse_marker_name_v1,
        kagemusha_wallet_require_published_v1, kagemusha_wallet_require_removed_v1,
    },
    platform::{
        KagemushaWalletAnchorPolicyV1, KagemushaWalletEntryKindV1, KagemushaWalletFsV1,
        KagemushaWalletListedEntryV1, KagemushaWalletNotPublishedV1,
        KagemushaWalletPublishOutcomeV1, KagemushaWalletReadV1, KagemushaWalletUnavailableV1,
        kagemusha_wallet_written_this_boot_v1,
    },
    store::KagemushaWalletDurableStoreV1,
};

/// Marker file envelope version.
pub const KAGEMUSHA_WALLET_MARKER_FILE_VERSION_V1: u16 = 1;
/// Maximum encoded marker file.
pub const KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1: usize = 2_048;

/// Local marker file envelope.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::MarkerFileV1")]
pub struct KagemushaWalletMarkerFileV1 {
    /// Envelope version; exactly [`KAGEMUSHA_WALLET_MARKER_FILE_VERSION_V1`].
    pub version: u16,
    /// Slot of the payment key.
    pub slot: [u8; 32],
    /// Anchor kind of the slot ([`KagemushaWalletAnchorPolicyV1::tag`]); identical in every
    /// generation.
    pub anchor_kind: u8,
    /// Boot identity when written; zero when it could not be read.
    pub written_boot_id: [u8; 32],
    /// Completion digest of a Released head; zero for every other phase.
    pub completion_digest: [u8; 32],
    /// Original Selected generation of this head; zero for non-head markers.
    pub selected_generation: u128,
    /// Content digest of the state owner's durable archive checkpoint; zero before the first.
    pub archive_checkpoint: [u8; 32],
    /// Canonical G1 marker frame.
    pub marker: Vec<u8>,
}

/// Phase of one marker generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletMarkerPhaseV1 {
    /// Generation-0 enrollment marker.
    Enrollment,
    /// Head chosen, receipt not yet released.
    Selected,
    /// Head released; binds its completion digest.
    Released,
    /// Terminal; never advanced again.
    Terminal,
}

/// One validated marker generation with its exact file bytes and digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletMarkerRecordV1 {
    slot: KagemushaWalletSlotIdV1,
    marker: KagemushaWalletMarkerV1,
    anchor: KagemushaWalletAnchorPolicyV1,
    phase: KagemushaWalletMarkerPhaseV1,
    completion_digest: Option<[u8; 32]>,
    selected_generation: u128,
    archive_checkpoint: [u8; 32],
    written_boot_id: [u8; 32],
    marker_digest: [u8; 32],
    marker_file_digest: [u8; 32],
    file_bytes: Vec<u8>,
}

fn invalid(field: &'static str) -> KagemushaWalletProviderErrorV1 {
    KagemushaWalletProviderErrorV1::Invalid { field }
}

fn phase_of(
    marker: &KagemushaWalletMarkerV1,
    completion_digest: Option<[u8; 32]>,
) -> Result<KagemushaWalletMarkerPhaseV1, KagemushaWalletProviderErrorV1> {
    match (marker.state, completion_digest) {
        (KagemushaWalletMarkerStateV1::Enrollment { .. }, None) => {
            Ok(KagemushaWalletMarkerPhaseV1::Enrollment)
        }
        (KagemushaWalletMarkerStateV1::Head { .. }, None) => {
            Ok(KagemushaWalletMarkerPhaseV1::Selected)
        }
        (KagemushaWalletMarkerStateV1::Head { .. }, Some(_)) => {
            Ok(KagemushaWalletMarkerPhaseV1::Released)
        }
        (KagemushaWalletMarkerStateV1::Terminal { .. }, None) => {
            Ok(KagemushaWalletMarkerPhaseV1::Terminal)
        }
        _ => Err(invalid("marker.completion_digest")),
    }
}

impl KagemushaWalletMarkerRecordV1 {
    /// Validate and encode one marker generation of `slot` whose anchor kind is `anchor`.
    ///
    /// `completion_digest` is present exactly for a Released head and must be nonzero.
    ///
    /// # Errors
    ///
    /// Rejects an invalid G1 marker, a zero or misplaced completion digest, and an oversized
    /// envelope.
    pub(super) fn new(
        slot: KagemushaWalletSlotIdV1,
        marker: KagemushaWalletMarkerV1,
        anchor: KagemushaWalletAnchorPolicyV1,
        completion_digest: Option<[u8; 32]>,
        written_boot_id: [u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        let phase = phase_of(&marker, completion_digest)?;
        let selected_generation = match phase {
            KagemushaWalletMarkerPhaseV1::Selected => marker.generation,
            KagemushaWalletMarkerPhaseV1::Released => marker
                .generation
                .checked_sub(1)
                .ok_or_else(|| invalid("marker.generation"))?,
            _ => 0,
        };
        Self::new_bound(
            slot,
            marker,
            anchor,
            completion_digest,
            written_boot_id,
            selected_generation,
            [0; 32],
        )
    }

    fn new_bound(
        slot: KagemushaWalletSlotIdV1,
        marker: KagemushaWalletMarkerV1,
        anchor: KagemushaWalletAnchorPolicyV1,
        completion_digest: Option<[u8; 32]>,
        written_boot_id: [u8; 32],
        selected_generation: u128,
        archive_checkpoint: [u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        if completion_digest == Some([0; 32]) {
            return Err(invalid("marker.completion_digest"));
        }
        let phase = phase_of(&marker, completion_digest)?;
        let valid_selected = match phase {
            KagemushaWalletMarkerPhaseV1::Selected => selected_generation == marker.generation,
            KagemushaWalletMarkerPhaseV1::Released => {
                selected_generation > 0 && selected_generation < marker.generation
            }
            _ => selected_generation == 0 && archive_checkpoint == [0; 32],
        };
        if !valid_selected {
            return Err(invalid("marker.selected_generation"));
        }
        let frame = marker
            .to_canonical_bytes()
            .map_err(|_| invalid("marker.frame"))?;
        let marker_digest = marker
            .marker_digest()
            .map_err(|_| invalid("marker.frame"))?;
        let file = KagemushaWalletMarkerFileV1 {
            version: KAGEMUSHA_WALLET_MARKER_FILE_VERSION_V1,
            slot: slot.0,
            anchor_kind: anchor.tag(),
            written_boot_id,
            completion_digest: completion_digest.unwrap_or([0; 32]),
            selected_generation,
            archive_checkpoint,
            marker: frame,
        };
        let file_bytes = encode_envelope_v1(&file, KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1)?;
        Ok(Self {
            slot,
            marker,
            anchor,
            phase,
            completion_digest,
            selected_generation,
            archive_checkpoint,
            written_boot_id,
            marker_digest,
            marker_file_digest: kagemusha_wallet_provider_digest_v1("marker-file", &file_bytes),
            file_bytes,
        })
    }

    /// Decode and validate one marker file of `slot` for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects oversized or noncanonical bytes, another envelope version, slot or anchor kind,
    /// an oversized or invalid G1 frame (including another scheme), and an inconsistent phase.
    pub fn decode(
        bytes: &[u8],
        slot: &KagemushaWalletSlotIdV1,
        expected_scheme_id: &[u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        let file: KagemushaWalletMarkerFileV1 =
            decode_envelope_v1(bytes, KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1)?;
        if file.version != KAGEMUSHA_WALLET_MARKER_FILE_VERSION_V1 {
            return Err(invalid("marker_file.version"));
        }
        if file.slot != slot.0 {
            return Err(invalid("marker_file.slot"));
        }
        let anchor = KagemushaWalletAnchorPolicyV1::from_tag(file.anchor_kind)
            .ok_or_else(|| invalid("marker_file.anchor_kind"))?;
        if file.marker.len() > KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1 {
            return Err(invalid("marker.frame"));
        }
        let marker = KagemushaWalletMarkerV1::decode_canonical(&file.marker, expected_scheme_id)
            .map_err(|_| invalid("marker.frame"))?;
        let completion_digest =
            (file.completion_digest != [0; 32]).then_some(file.completion_digest);
        let record = Self::new_bound(
            *slot,
            marker,
            anchor,
            completion_digest,
            file.written_boot_id,
            file.selected_generation,
            file.archive_checkpoint,
        )?;
        if record.file_bytes != bytes {
            return Err(invalid("marker_file.encoding"));
        }
        Ok(record)
    }

    /// Successor generation selecting `head` (a G1 `Head` state) after an Enrollment or
    /// Released marker: Bootstrap or the next transition.
    ///
    /// # Errors
    ///
    /// Rejects another phase, a non-head state and what [`Self::validate_successor_of`]
    /// rejects.
    pub(super) fn select(
        &self,
        head: KagemushaWalletMarkerStateV1,
        written_boot_id: [u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        if !matches!(
            self.phase,
            KagemushaWalletMarkerPhaseV1::Enrollment | KagemushaWalletMarkerPhaseV1::Released
        ) || !matches!(head, KagemushaWalletMarkerStateV1::Head { .. })
        {
            return Err(invalid("marker.phase"));
        }
        let marker = self
            .marker
            .successor(head)
            .map_err(|_| invalid("marker.state"))?;
        let next = Self::new_bound(
            self.slot,
            marker,
            self.anchor,
            None,
            written_boot_id,
            marker.generation,
            self.archive_checkpoint,
        )?;
        next.validate_successor_of(self)?;
        Ok(next)
    }

    /// Released successor of this Selected head, bound to `completion_digest`.
    ///
    /// # Errors
    ///
    /// Rejects another phase, a zero digest and generation overflow.
    pub(super) fn release(
        &self,
        completion_digest: [u8; 32],
        written_boot_id: [u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        if self.phase != KagemushaWalletMarkerPhaseV1::Selected {
            return Err(invalid("marker.phase"));
        }
        let generation = self
            .marker
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("marker.generation"))?;
        let marker = KagemushaWalletMarkerV1 {
            generation,
            ..self.marker
        };
        let next = Self::new_bound(
            self.slot,
            marker,
            self.anchor,
            Some(completion_digest),
            written_boot_id,
            self.selected_generation,
            self.archive_checkpoint,
        )?;
        next.validate_successor_of(self)?;
        Ok(next)
    }

    /// New Released generation binding an archive checkpoint without selecting/signing a head.
    pub(super) fn checkpoint(
        &self,
        digest: [u8; 32],
        written_boot_id: [u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        if self.phase != KagemushaWalletMarkerPhaseV1::Released || digest == [0; 32] {
            return Err(invalid("marker.archive_checkpoint"));
        }
        let marker = KagemushaWalletMarkerV1 {
            generation: self
                .marker
                .generation
                .checked_add(1)
                .ok_or_else(|| invalid("marker.generation"))?,
            ..self.marker
        };
        let next = Self::new_bound(
            self.slot,
            marker,
            self.anchor,
            self.completion_digest,
            written_boot_id,
            self.selected_generation,
            digest,
        )?;
        next.validate_successor_of(self)?;
        Ok(next)
    }

    /// Terminal successor: `Abandoned` after Enrollment, `CustodyDeleted` after a head.
    ///
    /// # Errors
    ///
    /// Rejects a terminal predecessor and a reason the G1 successor rules refuse.
    pub(super) fn terminate(
        &self,
        reason: KagemushaWalletTerminalReasonV1,
        written_boot_id: [u8; 32],
    ) -> Result<Self, KagemushaWalletProviderErrorV1> {
        let last_capsule_digest = match self.marker.state {
            KagemushaWalletMarkerStateV1::Enrollment { .. } => [0; 32],
            KagemushaWalletMarkerStateV1::Head { capsule_digest, .. } => capsule_digest,
            KagemushaWalletMarkerStateV1::Terminal { .. } => return Err(invalid("marker.phase")),
        };
        let marker = self
            .marker
            .successor(KagemushaWalletMarkerStateV1::Terminal {
                reason,
                last_capsule_digest,
            })
            .map_err(|_| invalid("marker.state"))?;
        let next = Self::new(self.slot, marker, self.anchor, None, written_boot_id)?;
        next.validate_successor_of(self)?;
        Ok(next)
    }

    /// Validate `self` as the direct successor generation of `previous`.
    ///
    /// Enrollment → Selected (Bootstrap) or Terminal; Selected → Released (identical head) or
    /// Terminal; Released → Selected (next sequence, linked capsule), Released (same head,
    /// completion and original selection, new archive metadata), or Terminal; Terminal →
    /// nothing. Identity, slot, anchor kind and generation + 1 are always required. The G1
    /// successor rules apply except when preserving the same head for release/metadata.
    ///
    /// # Errors
    ///
    /// Rejects every other transition.
    pub fn validate_successor_of(
        &self,
        previous: &Self,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        use KagemushaWalletMarkerPhaseV1 as Phase;
        if self.slot != previous.slot {
            return Err(invalid("marker.slot"));
        }
        if self.anchor != previous.anchor {
            return Err(invalid("marker.anchor_kind"));
        }
        match (previous.phase, self.phase) {
            (Phase::Selected, Phase::Released) | (Phase::Released, Phase::Released) => {
                let generation = previous
                    .marker
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| invalid("marker.generation"))?;
                let same_head = KagemushaWalletMarkerV1 {
                    generation,
                    ..previous.marker
                };
                if self.marker != same_head
                    || self.selected_generation != previous.selected_generation
                {
                    return Err(invalid("marker.state"));
                }
                if previous.phase == Phase::Released {
                    if self.completion_digest != previous.completion_digest
                        || self.archive_checkpoint == [0; 32]
                    {
                        return Err(invalid("marker.archive_checkpoint"));
                    }
                } else if self.archive_checkpoint != previous.archive_checkpoint {
                    return Err(invalid("marker.archive_checkpoint"));
                }
                Ok(())
            }
            (Phase::Enrollment | Phase::Released, Phase::Selected) => {
                if self.archive_checkpoint != previous.archive_checkpoint {
                    return Err(invalid("marker.archive_checkpoint"));
                }
                self.marker
                    .validate_successor_of(&previous.marker)
                    .map_err(|_| invalid("marker.state"))
            }
            (Phase::Enrollment | Phase::Selected | Phase::Released, Phase::Terminal) => self
                .marker
                .validate_successor_of(&previous.marker)
                .map_err(|_| invalid("marker.state")),
            _ => Err(invalid("marker.phase")),
        }
    }

    /// Slot.
    #[must_use]
    pub fn slot(&self) -> &KagemushaWalletSlotIdV1 {
        &self.slot
    }

    /// G1 marker.
    #[must_use]
    pub fn marker(&self) -> &KagemushaWalletMarkerV1 {
        &self.marker
    }

    /// Anchor kind of the slot, fixed at enrollment.
    #[must_use]
    pub fn anchor(&self) -> KagemushaWalletAnchorPolicyV1 {
        self.anchor
    }

    /// Generation.
    #[must_use]
    pub fn generation(&self) -> u128 {
        self.marker.generation
    }

    /// Phase.
    #[must_use]
    pub fn phase(&self) -> KagemushaWalletMarkerPhaseV1 {
        self.phase
    }

    /// Payment key the marker covers.
    #[must_use]
    pub fn payment_key(&self) -> &KagemushaDevicePublicKeyV1 {
        &self.marker.payment_key
    }

    /// Completion digest of a Released head.
    #[must_use]
    pub fn completion_digest(&self) -> Option<[u8; 32]> {
        self.completion_digest
    }

    /// Head fields `(sequence, operation_id, capsule_digest)` of a Selected or Released head.
    #[must_use]
    pub fn head(&self) -> Option<(u128, [u8; 32], [u8; 32])> {
        match self.marker.state {
            KagemushaWalletMarkerStateV1::Head {
                sequence,
                operation_id,
                capsule_digest,
                ..
            } => Some((sequence, operation_id, capsule_digest)),
            _ => None,
        }
    }

    /// Generation of the original Selected marker whose capsule this head binds. Release and
    /// archive metadata generations preserve it; it is not inferred from the current number.
    #[must_use]
    pub fn selected_generation(&self) -> Option<u128> {
        self.head().map(|_| self.selected_generation)
    }

    /// State-owner archive checkpoint authenticated by this exact marker and its iOS anchor.
    #[must_use]
    pub fn archive_checkpoint(&self) -> [u8; 32] {
        self.archive_checkpoint
    }

    /// Boot identity stamped when the file was written.
    #[must_use]
    pub fn written_boot_id(&self) -> &[u8; 32] {
        &self.written_boot_id
    }

    /// G1 marker digest `H("marker", frame)`.
    #[must_use]
    pub fn marker_digest(&self) -> &[u8; 32] {
        &self.marker_digest
    }

    /// Local digest `H("marker-file", envelope)`.
    #[must_use]
    pub fn marker_file_digest(&self) -> &[u8; 32] {
        &self.marker_file_digest
    }

    /// Exact envelope bytes.
    #[must_use]
    pub fn file_bytes(&self) -> &[u8] {
        &self.file_bytes
    }

    /// File name of this generation.
    #[must_use]
    pub fn file_name(&self) -> KagemushaWalletEntryNameV1 {
        kagemusha_wallet_marker_name_v1(self.marker.generation)
    }
}

/// Classified listing of `markers/`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KagemushaWalletMarkerListingV1 {
    /// Marker generations, ascending.
    pub generations: Vec<u128>,
    /// Staging files left by interrupted writes.
    pub staging: Vec<KagemushaWalletEntryNameV1>,
}

impl KagemushaWalletMarkerListingV1 {
    /// Highest generation: the current marker.
    #[must_use]
    pub fn current(&self) -> Option<u128> {
        self.generations.last().copied()
    }

    /// Generations below the current one.
    #[must_use]
    pub fn lower(&self) -> &[u128] {
        let len = self.generations.len().saturating_sub(1);
        &self.generations[..len]
    }
}

/// Classify a complete `markers/` listing strictly.
///
/// # Errors
///
/// `UnexpectedEntry` for anything other than marker files and staging files.
pub(super) fn kagemusha_wallet_classify_markers_v1(
    entries: &[KagemushaWalletListedEntryV1],
) -> Result<KagemushaWalletMarkerListingV1, KagemushaWalletProviderErrorV1> {
    let mut listing = KagemushaWalletMarkerListingV1::default();
    for entry in entries {
        if entry.kind != KagemushaWalletEntryKindV1::File {
            return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" });
        }
        if let Some(generation) = kagemusha_wallet_parse_marker_name_v1(&entry.name) {
            listing.generations.push(generation);
        } else if kagemusha_wallet_is_staging_name_v1(&entry.name) {
            listing.staging.push(
                KagemushaWalletEntryNameV1::new(&entry.name)
                    .ok_or(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" })?,
            );
        } else {
            return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" });
        }
    }
    listing.generations.sort_unstable();
    Ok(listing)
}

/// List and classify `markers/` of `slot`; `None` when the directory is definitively absent.
///
/// # Errors
///
/// `Unavailable` on a listing error and `UnexpectedEntry` for a foreign entry.
pub(super) fn kagemusha_wallet_list_markers_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<Option<KagemushaWalletMarkerListingV1>, KagemushaWalletProviderErrorV1> {
    kagemusha_wallet_list_dir_v1(store, &kagemusha_wallet_markers_dir_v1(slot))?
        .map(|entries| kagemusha_wallet_classify_markers_v1(&entries))
        .transpose()
}

/// Current marker as found on disk, before adoption.
///
/// Its fields are private: it is produced only by [`kagemusha_wallet_load_current_marker_v1`],
/// so adoption always starts from bytes that were read from `markers/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletCurrentMarkerV1 {
    record: KagemushaWalletMarkerRecordV1,
    lower: Vec<u128>,
}

impl KagemushaWalletCurrentMarkerV1 {
    /// The highest generation, read and validated.
    #[must_use]
    pub fn record(&self) -> &KagemushaWalletMarkerRecordV1 {
        &self.record
    }

    /// Lower generations still present; retired by name, never read.
    #[must_use]
    pub fn lower(&self) -> &[u128] {
        &self.lower
    }
}

/// Read the current (highest) marker of `slot`; `None` when no marker exists.
///
/// Only the highest generation is read. Lower generations are never read or selected.
///
/// # Errors
///
/// `Unavailable` on any listing or read error (including a listed file that is no longer
/// present), `UnexpectedEntry` for a foreign entry, and `UnavailableCustodyData` when the
/// highest marker is oversized or invalid or names another generation.
pub(super) fn kagemusha_wallet_load_current_marker_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
    expected_scheme_id: &[u8; 32],
) -> Result<Option<KagemushaWalletCurrentMarkerV1>, KagemushaWalletProviderErrorV1> {
    let Some(listing) = kagemusha_wallet_list_markers_v1(store, slot)? else {
        return Ok(None);
    };
    let Some(generation) = listing.current() else {
        return Ok(None);
    };
    let corrupt = KagemushaWalletProviderErrorV1::UnavailableCustodyData { object: "marker" };
    let bytes = match store.read(
        &kagemusha_wallet_markers_dir_v1(slot),
        &kagemusha_wallet_marker_name_v1(generation),
        KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1,
    ) {
        KagemushaWalletReadV1::Present(bytes) => bytes,
        KagemushaWalletReadV1::Oversized => return Err(corrupt),
        // Listed under the lock but gone: a concurrent change, never absence.
        KagemushaWalletReadV1::Absent => {
            return Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            ));
        }
        KagemushaWalletReadV1::Unavailable(reason) => {
            return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
        }
    };
    let record = KagemushaWalletMarkerRecordV1::decode(&bytes, slot, expected_scheme_id)
        .map_err(|_| corrupt)?;
    if record.generation() != generation {
        return Err(corrupt);
    }
    Ok(Some(KagemushaWalletCurrentMarkerV1 {
        record,
        lower: listing.lower().to_vec(),
    }))
}

/// Whether adopting `record` needs a fresh-inode rewrite (G2 design R3).
///
/// A file possibly written in the current boot is rewritten when it is Selected or
/// Enrollment, or while a lower marker still exists: in those states its publication was not
/// followed by a later successful sync that retired its predecessor. A Released or Terminal
/// marker with no lower marker, or a file from an earlier boot, is synced instead.
// The Enrollment case extends design R3: a generation-0 marker has no lower generation, so an
// uncertain E4 publication followed by a vacuous sync would otherwise go unrepaired.
#[must_use]
pub(super) fn kagemusha_wallet_marker_needs_fresh_inode_v1(
    record: &KagemushaWalletMarkerRecordV1,
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    lower_exists: bool,
) -> bool {
    kagemusha_wallet_written_this_boot_v1(&record.written_boot_id, current_boot)
        && (lower_exists
            || matches!(
                record.phase,
                KagemushaWalletMarkerPhaseV1::Selected | KagemushaWalletMarkerPhaseV1::Enrollment
            ))
}

/// Marker known to be durable: published by this process or adopted from disk after its
/// exact bytes were read back. Only this module constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletDurableMarkerV1 {
    record: KagemushaWalletMarkerRecordV1,
}

impl KagemushaWalletDurableMarkerV1 {
    /// The durable record.
    #[must_use]
    pub fn record(&self) -> &KagemushaWalletMarkerRecordV1 {
        &self.record
    }

    /// Capability to sign the receipt of this marker's head; only for a Selected marker.
    #[must_use]
    pub(super) fn selected_capability(&self) -> Option<KagemushaWalletSelectedCapabilityV1> {
        if self.record.phase != KagemushaWalletMarkerPhaseV1::Selected {
            return None;
        }
        let (_, operation_id, capsule_digest) = self.record.head()?;
        Some(KagemushaWalletSelectedCapabilityV1 {
            slot: self.record.slot,
            scheme_id: self.record.marker.scheme_id,
            generation: self.record.generation(),
            marker_file_digest: self.record.marker_file_digest,
            payment_key: self.record.marker.payment_key,
            operation_id,
            capsule_digest,
        })
    }

    /// Require that this marker is still the current marker on disk.
    ///
    /// # Errors
    ///
    /// As [`kagemusha_wallet_require_current_marker_v1`].
    pub fn require_current<F: KagemushaWalletFsV1>(
        &self,
        store: &KagemushaWalletDurableStoreV1<F>,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        kagemusha_wallet_require_current_marker_v1(
            store,
            &self.record.slot,
            &self.record.marker.scheme_id,
            &self.record.marker_file_digest,
        )
    }
}

/// Proof that a Selected marker was durable and current when it was derived; the only way to
/// reach the `receipt-body` signer and to replace never-released completion copies.
///
/// It is neither `Clone` nor `Copy`, and only [`KagemushaWalletDurableMarkerV1`] derives it.
/// The signer and every persistence step that relies on it re-check the marker on disk
/// ([`Self::require_current`]), so a capability kept after its marker was superseded (for
/// example by the Released marker) can neither sign nor replace a released result.
// `advance.rs` derives it inside one in-flight finish (A6-A11) and drops it with that call,
// after the Released marker is published.
#[derive(Debug, PartialEq, Eq)]
pub struct KagemushaWalletSelectedCapabilityV1 {
    slot: KagemushaWalletSlotIdV1,
    scheme_id: [u8; 32],
    generation: u128,
    marker_file_digest: [u8; 32],
    payment_key: KagemushaDevicePublicKeyV1,
    operation_id: [u8; 32],
    capsule_digest: [u8; 32],
}

impl KagemushaWalletSelectedCapabilityV1 {
    /// Slot.
    #[must_use]
    pub fn slot(&self) -> &KagemushaWalletSlotIdV1 {
        &self.slot
    }

    /// Generation of the Selected marker.
    #[must_use]
    pub fn generation(&self) -> u128 {
        self.generation
    }

    /// Payment key the marker covers.
    #[must_use]
    pub fn payment_key(&self) -> &KagemushaDevicePublicKeyV1 {
        &self.payment_key
    }

    /// Operation identity of the selected transition.
    #[must_use]
    pub fn operation_id(&self) -> &[u8; 32] {
        &self.operation_id
    }

    /// Digest of the frozen capsule the receipt signs.
    #[must_use]
    pub fn capsule_digest(&self) -> &[u8; 32] {
        &self.capsule_digest
    }

    /// Require that the Selected marker is still the current marker on disk.
    ///
    /// # Errors
    ///
    /// As [`kagemusha_wallet_require_current_marker_v1`].
    pub fn require_current<F: KagemushaWalletFsV1>(
        &self,
        store: &KagemushaWalletDurableStoreV1<F>,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        kagemusha_wallet_require_current_marker_v1(
            store,
            &self.slot,
            &self.scheme_id,
            &self.marker_file_digest,
        )
    }
}

/// Require that the current marker of `slot` on disk has `marker_file_digest`.
///
/// # Errors
///
/// `Invalid("marker.superseded")` when another marker (or none) is current; the read errors of
/// [`kagemusha_wallet_load_current_marker_v1`] otherwise.
pub(super) fn kagemusha_wallet_require_current_marker_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
    scheme_id: &[u8; 32],
    marker_file_digest: &[u8; 32],
) -> Result<(), KagemushaWalletProviderErrorV1> {
    match kagemusha_wallet_load_current_marker_v1(store, slot, scheme_id)? {
        Some(current) if current.record.marker_file_digest == *marker_file_digest => Ok(()),
        _ => Err(invalid("marker.superseded")),
    }
}

/// Result of publishing a new marker generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KagemushaWalletMarkerPublicationV1 {
    /// Published durably; the generation is now current.
    Durable(KagemushaWalletDurableMarkerV1),
    /// Another marker already holds this generation (create-new refused); nothing changed.
    GenerationTaken,
}

/// Publish `record` create-new as `markers/m-<gen>.mk` (commit point of its transition).
///
/// # Errors
///
/// `Uncertain` when the outcome is unknown, and the errors of
/// [`kagemusha_wallet_require_published_v1`] otherwise.
pub(super) fn kagemusha_wallet_publish_marker_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    record: KagemushaWalletMarkerRecordV1,
) -> Result<KagemushaWalletMarkerPublicationV1, KagemushaWalletProviderErrorV1> {
    match store.write_new(
        &kagemusha_wallet_markers_dir_v1(&record.slot),
        &record.file_name(),
        &record.file_bytes,
    ) {
        KagemushaWalletPublishOutcomeV1::NotPublished(
            KagemushaWalletNotPublishedV1::DestinationExists,
        ) => Ok(KagemushaWalletMarkerPublicationV1::GenerationTaken),
        outcome => {
            kagemusha_wallet_require_published_v1(outcome)?;
            Ok(KagemushaWalletMarkerPublicationV1::Durable(
                KagemushaWalletDurableMarkerV1 { record },
            ))
        }
    }
}

/// Adopt the current marker durably (G2 design R3): rewrite it to a fresh inode when
/// [`kagemusha_wallet_marker_needs_fresh_inode_v1`] says so, otherwise sync it and
/// `markers/`.
///
/// Both paths prove that the file under the record's name holds exactly the record's bytes:
/// the rewrite compares them before replacing, and the sync path reads them back first. A
/// record that is not on disk never becomes durable.
///
/// # Errors
///
/// `Uncertain` when a rewrite's outcome is unknown, `Unavailable` when a read or sync fails or
/// the file changed concurrently (`Busy`), and `Invalid("rewrite content")` when the rewrite
/// finds other bytes.
pub(super) fn kagemusha_wallet_adopt_marker_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    current: &KagemushaWalletCurrentMarkerV1,
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
) -> Result<KagemushaWalletDurableMarkerV1, KagemushaWalletProviderErrorV1> {
    let record = &current.record;
    let dir = kagemusha_wallet_markers_dir_v1(&record.slot);
    let name = record.file_name();
    if kagemusha_wallet_marker_needs_fresh_inode_v1(record, current_boot, !current.lower.is_empty())
    {
        kagemusha_wallet_require_published_v1(store.rewrite_same(&dir, &name, &record.file_bytes))?;
    } else {
        match store.read(&dir, &name, KAGEMUSHA_WALLET_MARKER_FILE_MAX_BYTES_V1) {
            KagemushaWalletReadV1::Present(bytes) if bytes == record.file_bytes => {}
            KagemushaWalletReadV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason));
            }
            // Gone or changed since it was listed under the lock: a concurrent change.
            _ => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
        }
        store
            .sync_file(&dir, &name)
            .and_then(|()| store.sync_dir(&dir))
            .map_err(KagemushaWalletProviderErrorV1::Unavailable)?;
    }
    Ok(KagemushaWalletDurableMarkerV1 {
        record: record.clone(),
    })
}

/// Durably retire `lower` generations of the durable current marker by name, without reading
/// them.
///
/// # Errors
///
/// `Invalid` for a generation at or above the current one; `Unavailable` or `Uncertain` when
/// a removal fails or its outcome is unknown.
pub(super) fn kagemusha_wallet_retire_markers_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    current: &KagemushaWalletDurableMarkerV1,
    lower: &[u128],
) -> Result<(), KagemushaWalletProviderErrorV1> {
    let current_generation = current.record.generation();
    if lower
        .iter()
        .any(|generation| *generation >= current_generation)
    {
        return Err(invalid("marker.retired_generation"));
    }
    let dir = kagemusha_wallet_markers_dir_v1(&current.record.slot);
    for generation in lower {
        kagemusha_wallet_require_removed_v1(
            store.remove_file(&dir, &kagemusha_wallet_marker_name_v1(*generation)),
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "marker_tests.rs"]
mod tests;
