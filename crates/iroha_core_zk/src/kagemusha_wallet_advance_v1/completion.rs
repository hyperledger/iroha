//! Completion records in redundant boot-stamped copies (spec §4.1; G2 design A8, R5).
//!
//! A completion copy is `completion/<op:64x>.cr` (primary) or `.cr.r` (replica), holding a
//! [`KagemushaWalletFrozenFileV1`](super::KagemushaWalletFrozenFileV1) envelope around the canonical completion record frame:
//! the receipt and the exact released output bytes.
//!
//! - **Under a Selected marker** nothing has been released. A valid existing record for the
//!   operation is adopted (its signature wins; a fresh one is discarded) and invalid copies may
//!   be replaced. Both need the durable Selected-marker capability.
//! - **Under a Released marker** the record whose frame digest equals the marker's
//!   `completion_digest` is the retained result; every retry returns its exact bytes. If no copy
//!   is valid and none is merely unreadable, custody of that result is lost
//!   (`CompletionLost`): the provider never signs again for a released head.

use iroha_data_model::kagemusha::{
    KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1, KagemushaWalletCompletionRecordV1,
    KagemushaWalletDigestRoleV1, KagemushaWalletMarkerV1, KagemushaWalletValidationErrorV1,
    kagemusha_wallet_digest_v1,
};

use super::{
    KagemushaWalletLostCustodyV1, KagemushaWalletProviderErrorV1,
    capsule::{
        KagemushaWalletCopyStateV1, KagemushaWalletFrozenFrameV1, KagemushaWalletLoadedPairV1,
        KagemushaWalletPairReadV1, kagemusha_wallet_repair_pair_v1, kagemusha_wallet_settle_pair_v1,
        pair_write_published, read_pair, read_pair_states, write_pair,
    },
    layout::{
        KagemushaWalletCompletionNameV1, KagemushaWalletCopyV1, KagemushaWalletEntryNameV1,
        KagemushaWalletSlotIdV1, kagemusha_wallet_completion_dir_v1,
        kagemusha_wallet_completion_name_v1, kagemusha_wallet_is_staging_name_v1,
        kagemusha_wallet_list_dir_v1, kagemusha_wallet_parse_completion_name_v1,
        kagemusha_wallet_require_removed_v1,
    },
    marker::{
        KagemushaWalletMarkerPhaseV1, KagemushaWalletMarkerRecordV1,
        KagemushaWalletSelectedCapabilityV1,
    },
    platform::{KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletUnavailableV1},
    store::KagemushaWalletDurableStoreV1,
};

/// Frozen completion record: a [`KagemushaWalletFrozenFrameV1`] bound to one operation and
/// the private wrapper joined to its signed public commitment.
pub trait KagemushaWalletCompletionFrameV1: KagemushaWalletFrozenFrameV1 {
    /// Decode binding of the completion records covered by `marker` (G1: its wallet identity).
    fn marker_binding(marker: &KagemushaWalletMarkerV1) -> Self::Binding;
    /// Operation identity.
    fn operation_id(&self) -> [u8; 32];
    /// Private custody digest of the recovery wrapper.
    fn capsule_digest(&self) -> [u8; 32];
}

impl KagemushaWalletFrozenFrameV1 for KagemushaWalletCompletionRecordV1 {
    const OBJECT: &'static str = "completion";
    const MAX_FRAME_BYTES: usize = KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1;
    /// Expected wallet identity.
    type Binding = [u8; 32];

    fn encode_frame(&self) -> Result<Vec<u8>, KagemushaWalletValidationErrorV1> {
        self.to_canonical_bytes()
    }

    fn decode_frame(
        bytes: &[u8],
        binding: &[u8; 32],
    ) -> Result<Self, KagemushaWalletValidationErrorV1> {
        Self::decode_canonical(bytes, binding)
    }

    fn frame_digest(frame: &[u8]) -> [u8; 32] {
        kagemusha_wallet_digest_v1(KagemushaWalletDigestRoleV1::Completion, frame)
    }
}

impl KagemushaWalletCompletionFrameV1 for KagemushaWalletCompletionRecordV1 {
    fn marker_binding(marker: &KagemushaWalletMarkerV1) -> [u8; 32] {
        marker.wallet_id
    }

    fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }

    fn capsule_digest(&self) -> [u8; 32] {
        self.capsule_digest
    }
}

/// What the current marker says about an operation's completion record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletCompletionExpectationV1 {
    /// Selected head: any valid record for the operation and capsule; none may exist yet.
    Selected {
        /// Generation of the Selected marker.
        selected_generation: u128,
        /// Operation identity.
        operation_id: [u8; 32],
        /// Private custody digest of the recovery wrapper.
        capsule_digest: [u8; 32],
    },
    /// Released head: exactly the record whose frame digest is `completion_digest`.
    Released {
        /// Generation of the Selected marker that preceded the release.
        selected_generation: u128,
        /// Operation identity.
        operation_id: [u8; 32],
        /// Private custody digest of the recovery wrapper.
        capsule_digest: [u8; 32],
        /// Frame digest bound by the Released marker.
        completion_digest: [u8; 32],
    },
}

impl KagemushaWalletCompletionExpectationV1 {
    /// Expectation of a Selected or Released head marker; `None` for other phases.
    #[must_use]
    pub fn for_marker(record: &KagemushaWalletMarkerRecordV1) -> Option<Self> {
        let (_, operation_id, capsule_digest) = record.head()?;
        let selected_generation = record.selected_generation()?;
        match (record.phase(), record.completion_digest()) {
            (KagemushaWalletMarkerPhaseV1::Selected, None) => Some(Self::Selected {
                selected_generation,
                operation_id,
                capsule_digest,
            }),
            (KagemushaWalletMarkerPhaseV1::Released, Some(completion_digest)) => {
                Some(Self::Released {
                    selected_generation,
                    operation_id,
                    capsule_digest,
                    completion_digest,
                })
            }
            _ => None,
        }
    }

    fn parts(&self) -> (u128, [u8; 32], [u8; 32], Option<[u8; 32]>) {
        match *self {
            Self::Selected {
                selected_generation,
                operation_id,
                capsule_digest,
            } => (selected_generation, operation_id, capsule_digest, None),
            Self::Released {
                selected_generation,
                operation_id,
                capsule_digest,
                completion_digest,
            } => (
                selected_generation,
                operation_id,
                capsule_digest,
                Some(completion_digest),
            ),
        }
    }
}

/// Both copy names of one operation's completion record.
#[must_use]
pub fn kagemusha_wallet_completion_names_v1(
    operation_id: &[u8; 32],
) -> [KagemushaWalletEntryNameV1; 2] {
    KagemushaWalletCopyV1::BOTH.map(|copy| kagemusha_wallet_completion_name_v1(operation_id, copy))
}

/// Load the completion record the current marker expects, from either copy.
///
/// Returns `Ok(None)` only under a Selected marker with no valid record.
///
/// # Errors
///
/// `Unavailable` when no copy is valid and one could not be read; under a Released marker,
/// `LostCustody(CompletionLost)` when every copy is absent or invalid.
pub fn kagemusha_wallet_load_completion_v1<F, R>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
    expectation: &KagemushaWalletCompletionExpectationV1,
    binding: &R::Binding,
) -> Result<Option<KagemushaWalletLoadedPairV1<R>>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    R: KagemushaWalletCompletionFrameV1,
{
    let (selected_generation, operation_id, capsule_digest, completion_digest) =
        expectation.parts();
    let pair = read_pair::<F, R>(
        store,
        &kagemusha_wallet_completion_dir_v1(slot),
        kagemusha_wallet_completion_names_v1(&operation_id),
        selected_generation,
        binding,
        |record, digest| {
            record.operation_id() == operation_id
                && record.capsule_digest() == capsule_digest
                && completion_digest.is_none_or(|expected| *digest == expected)
        },
    )?;
    if pair.is_none() && completion_digest.is_some() {
        return Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::CompletionLost,
        ));
    }
    Ok(pair)
}

/// Completion record staged durably under a Selected marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletStagedCompletionV1<R> {
    /// The retained record: an adopted existing one, or the caller's.
    pub record: R,
    /// Its exact canonical frame.
    pub frame: Vec<u8>,
    /// Its frame digest, which the Released marker binds.
    pub completion_digest: [u8; 32],
    /// Whether an existing valid record was adopted and the caller's discarded.
    pub adopted: bool,
}

/// Stage the completion record of the durable Selected marker's operation (G2 design A8).
///
/// A valid existing record for the operation and capsule is adopted (repaired and rewritten to
/// a fresh inode) and the caller's record is discarded, so one Selected head never yields two
/// released results. Otherwise invalid copies, which were never released, are removed and both
/// copies of `record` are written create-new; a definitively absent copy is not removed again.
///
/// `record` is encoded and decoded back under the marker's `binding` before any copy is
/// touched: a record that a later load would classify as invalid (for example one bound to
/// another wallet) is refused without writing, so it can never be written, discarded and
/// signed again in a loop.
///
/// # Errors
///
/// `Invalid` when `record` names another operation or capsule, does not encode or does not
/// decode under `binding`, or when the capability's Selected marker is no longer current;
/// `Unavailable` when a copy or the marker cannot be read or a concurrent write appears;
/// `NoSpace`, `NoReplaceUnsupported` and `Uncertain` from the writes.
pub(super) fn kagemusha_wallet_stage_completion_v1<F, R>(
    store: &KagemushaWalletDurableStoreV1<F>,
    capability: &KagemushaWalletSelectedCapabilityV1,
    current_boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    record: &R,
    binding: &R::Binding,
) -> Result<KagemushaWalletStagedCompletionV1<R>, KagemushaWalletProviderErrorV1>
where
    F: KagemushaWalletFsV1,
    R: KagemushaWalletCompletionFrameV1,
{
    let operation_id = *capability.operation_id();
    let capsule_digest = *capability.capsule_digest();
    if record.operation_id() != operation_id || record.capsule_digest() != capsule_digest {
        return Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "completion.binding",
        });
    }
    // Exactly what `kagemusha_wallet_load_completion_v1` will accept, checked before writing.
    let frame = record
        .encode_frame()
        .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: R::OBJECT })?;
    let decoded = R::decode_frame(&frame, binding)
        .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: R::OBJECT })?;
    if decoded.operation_id() != operation_id || decoded.capsule_digest() != capsule_digest {
        return Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "completion.binding",
        });
    }
    // Only a still-current Selected marker proves that nothing was released for this head.
    capability.require_current(store)?;
    let dir = kagemusha_wallet_completion_dir_v1(capability.slot());
    let names = kagemusha_wallet_completion_names_v1(&operation_id);
    // The Selected expectation of `kagemusha_wallet_load_completion_v1`, keeping the per-copy
    // states of this read (after `require_current`) when no copy is valid.
    let states = match read_pair_states::<F, R>(
        store,
        &dir,
        names.clone(),
        capability.generation(),
        binding,
        |record, _| {
            record.operation_id() == operation_id && record.capsule_digest() == capsule_digest
        },
    )? {
        KagemushaWalletPairReadV1::Loaded(mut pair) => {
            kagemusha_wallet_repair_pair_v1(store, &mut pair, current_boot)?;
            kagemusha_wallet_settle_pair_v1(store, &pair, true)?;
            let frame = pair.frame().to_vec();
            let completion_digest = *pair.frame_digest();
            return Ok(KagemushaWalletStagedCompletionV1 {
                record: pair.into_value(),
                frame,
                completion_digest,
                adopted: true,
            });
        }
        KagemushaWalletPairReadV1::Missing(states) => states,
    };
    // No valid record exists under this Selected marker: a present copy is invalid and was
    // never released, so it is removed (and its removal synced) before the fresh pair is
    // written. A definitively absent copy needs no removal: the pair's create-new renames
    // land in the same directory, whose sync precedes the Released marker and also covers
    // any earlier unsynced removal there.
    for (name, state) in names.iter().zip(states) {
        if state == KagemushaWalletCopyStateV1::Invalid {
            kagemusha_wallet_require_removed_v1(store.remove_file(&dir, name))?;
        }
    }
    for outcome in write_pair::<F, R>(
        store,
        &dir,
        &names,
        capability.generation(),
        current_boot,
        &frame,
    )? {
        if !pair_write_published(outcome)? {
            return Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            ));
        }
    }
    Ok(KagemushaWalletStagedCompletionV1 {
        record: decoded,
        completion_digest: R::frame_digest(&frame),
        frame,
        adopted: false,
    })
}
// Released records below the current head are pruned by `retained.rs` (`prune_completion`),
// which writes the permanent `ops/<op>.t` tombstone first; the current head's record never is.

/// List `completion/` of `slot` strictly; `None` when the directory is definitively absent.
///
/// Staging files are skipped (reconcile removes them).
///
/// # Errors
///
/// `Unavailable` on a listing error and `UnexpectedEntry` for a foreign entry.
pub fn kagemusha_wallet_list_completions_v1<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &KagemushaWalletSlotIdV1,
) -> Result<Option<Vec<KagemushaWalletCompletionNameV1>>, KagemushaWalletProviderErrorV1> {
    let Some(entries) =
        kagemusha_wallet_list_dir_v1(store, &kagemusha_wallet_completion_dir_v1(slot))?
    else {
        return Ok(None);
    };
    let mut names = Vec::with_capacity(entries.len());
    for entry in entries {
        let is_file = entry.kind == KagemushaWalletEntryKindV1::File;
        match is_file
            .then(|| kagemusha_wallet_parse_completion_name_v1(&entry.name))
            .flatten()
        {
            Some(name) => names.push(name),
            None if is_file && kagemusha_wallet_is_staging_name_v1(&entry.name) => {}
            None => {
                return Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "completion" });
            }
        }
    }
    Ok(Some(names))
}

#[cfg(test)]
#[path = "completion_tests.rs"]
mod tests;
