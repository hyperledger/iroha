//! Bounded unpublished object construction and explicit durable materialization.
//!
//! Drafts own clearing payload allocations. Their digests are logical references,
//! never durable acknowledgments. Only the complete materialization result may
//! accompany publication of roots built from a draft.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::{Error, ObjectStore, ObjectWorkspace, PrivateArchiveBytes};
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as digest;

/// Independent payload and metadata-count bounds for one native draft.
#[derive(Clone, Copy, Debug)]
pub(super) struct WorkspaceLimits {
    /// Maximum sum of distinct staged payload lengths.
    pub max_bytes: usize,
    /// Maximum number of distinct staged objects, bounding metadata allocations.
    pub max_objects: usize,
}

/// Canonically ordered, clearing object originals with no durability authority.
pub(super) struct ObjectBatch {
    objects: Vec<([u8; 32], PrivateArchiveBytes)>,
    bytes: usize,
}

/// Acknowledgment that every object in one batch passed durable publication.
/// Construction is private to materialization; this never acknowledges a manifest.
pub(super) struct MaterializedObjects {
    _acknowledged: (),
}

impl ObjectBatch {
    /// Validate an already bounded, clearing decode without copying its payloads.
    /// The enclosing reader must enforce its frame/allocation limit before decoding.
    pub(super) fn from_owned(
        objects: Vec<([u8; 32], PrivateArchiveBytes)>,
        limits: WorkspaceLimits,
    ) -> Result<Self, Error> {
        if objects.len() > limits.max_objects {
            return Err(Error::NotEnoughMemory);
        }
        let mut bytes = 0_usize;
        let mut previous = None;
        for (key, original) in &objects {
            bytes = bytes
                .checked_add(original.len())
                .filter(|bytes| *bytes <= limits.max_bytes)
                .ok_or(Error::NotEnoughMemory)?;
            if previous.is_some_and(|previous| previous >= *key) || digest(original) != *key {
                return Err(Error::WitnessLost("preparation batch object binding"));
            }
            previous = Some(*key);
        }
        Ok(Self { objects, bytes })
    }

    /// Borrow canonical originals for bounded streaming serialization.
    #[cfg(test)]
    pub(super) fn entries(&self) -> &[([u8; 32], PrivateArchiveBytes)] {
        &self.objects
    }

    /// Move the clearing originals into the enclosing canonical batch record.
    pub(super) fn into_owned(self) -> Vec<([u8; 32], PrivateArchiveBytes)> {
        self.objects
    }

    /// Materialize every exact original, retaining the batch on any uncertain error.
    /// The caller must already have acknowledged the immutable recovery batch.
    pub(super) fn materialize(
        &self,
        store: &mut dyn ObjectStore,
    ) -> Result<MaterializedObjects, Error> {
        for (key, original) in &self.objects {
            if store.write_object(original, original.len())? != *key {
                return Err(Error::WitnessLost("preparation materialization digest"));
            }
        }
        Ok(MaterializedObjects { _acknowledged: () })
    }

    /// Re-read every materialized original from durable storage after its publication.
    /// Each read is bounded by the original's length and must reproduce its content key;
    /// no copy is retained. This creates no object and acknowledges no manifest.
    pub(super) fn read_back(&self, store: &mut dyn ObjectStore) -> Result<(), Error> {
        for (key, original) in &self.objects {
            drop(Zeroizing::new(checked_read(store, key, original.len())?));
        }
        Ok(())
    }
}

/// One finite logical view over an authenticated durable source.
/// No method on this owner writes to or removes from the underlying store.
pub(super) struct DraftWorkspace<'a> {
    source: &'a mut dyn ObjectStore,
    limits: WorkspaceLimits,
    batch: ObjectBatch,
    positions: HashMap<[u8; 32], usize>,
}

impl<'a> DraftWorkspace<'a> {
    /// Begin an allocation-free draft with explicit payload/item limits.
    pub(super) fn new(source: &'a mut dyn ObjectStore, limits: WorkspaceLimits) -> Self {
        Self {
            source,
            limits,
            batch: ObjectBatch {
                objects: Vec::new(),
                bytes: 0,
            },
            positions: HashMap::new(),
        }
    }

    /// Release the source borrow and canonically order originals without copying payloads.
    pub(super) fn into_batch(mut self) -> ObjectBatch {
        self.batch.objects.sort_unstable_by_key(|(key, _)| *key);
        self.batch
    }
}

fn copy_fallible(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::NotEnoughMemory)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn checked_read(
    source: &mut dyn ObjectStore,
    key: &[u8; 32],
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let mut original = Zeroizing::new(source.read_object(key, maximum)?);
    if original.len() > maximum || digest(&original) != *key {
        return Err(Error::WitnessLost("workspace source object binding"));
    }
    Ok(std::mem::take(&mut *original))
}

impl ObjectWorkspace for DraftWorkspace<'_> {
    fn read_staged_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        if let Some(position) = self.positions.get(key) {
            let original = &self.batch.objects[*position].1;
            if original.len() > maximum {
                return Err(Error::WitnessLost("staged object read bound"));
            }
            return copy_fallible(original);
        }
        checked_read(self.source, key, maximum)
    }

    fn stage_object(&mut self, original: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        if original.len() > maximum {
            return Err(Error::Invalid("staged object size"));
        }
        let key = digest(original);
        if let Some(position) = self.positions.get(&key) {
            if self.batch.objects[*position].1.as_slice() != original {
                return Err(Error::WitnessLost("staged object digest conflict"));
            }
            return Ok(key);
        }
        let bytes = self
            .batch
            .bytes
            .checked_add(original.len())
            .filter(|bytes| *bytes <= self.limits.max_bytes)
            .ok_or(Error::NotEnoughMemory)?;
        if self.batch.objects.len() >= self.limits.max_objects {
            return Err(Error::NotEnoughMemory);
        }
        // Both metadata structures are bounded by the object count and reserve
        // fallibly before retaining any new payload. No BTreeMap allocates implicitly.
        self.batch
            .objects
            .try_reserve(1)
            .map_err(|_| Error::NotEnoughMemory)?;
        self.positions
            .try_reserve(1)
            .map_err(|_| Error::NotEnoughMemory)?;
        let mut owned = Zeroizing::new(Vec::new());
        owned
            .try_reserve_exact(original.len())
            .map_err(|_| Error::NotEnoughMemory)?;
        owned.extend_from_slice(original);
        let position = self.batch.objects.len();
        self.batch
            .objects
            .push((key, PrivateArchiveBytes::from_guarded(owned)));
        self.positions.insert(key, position);
        self.batch.bytes = bytes;
        Ok(key)
    }
}

/// Exact replay of a materialized plan; logical writes can only confirm existing bytes.
pub(super) struct ReadOnlyWorkspace<'a> {
    source: &'a mut dyn ObjectStore,
    batch: Option<&'a ObjectBatch>,
}

impl<'a> ReadOnlyWorkspace<'a> {
    /// Borrow the durable source without granting its write capability to preparation.
    pub(super) fn new(source: &'a mut dyn ObjectStore) -> Self {
        Self {
            source,
            batch: None,
        }
    }

    /// Replay an exact recovered batch before its objects have been materialized.
    /// Missing bytes cannot be created by validation of an already retained batch.
    pub(super) fn with_batch(source: &'a mut dyn ObjectStore, batch: &'a ObjectBatch) -> Self {
        Self {
            source,
            batch: Some(batch),
        }
    }
}

impl ObjectWorkspace for ReadOnlyWorkspace<'_> {
    fn read_staged_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        if let Some(batch) = self.batch {
            if let Ok(position) = batch.objects.binary_search_by_key(key, |(key, _)| *key) {
                let original = &batch.objects[position].1;
                if original.len() > maximum {
                    return Err(Error::WitnessLost("replayed batch read bound"));
                }
                return copy_fallible(original);
            }
        }
        checked_read(self.source, key, maximum)
    }

    fn stage_object(&mut self, original: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        if original.len() > maximum {
            return Err(Error::Invalid("replay object size"));
        }
        let key = digest(original);
        let held = Zeroizing::new(self.read_staged_object(&key, maximum)?);
        if held.as_slice() != original {
            return Err(Error::WitnessLost("replay object differs"));
        }
        Ok(key)
    }
}

#[cfg(test)]
#[path = "object_workspace/tests.rs"]
mod tests;
