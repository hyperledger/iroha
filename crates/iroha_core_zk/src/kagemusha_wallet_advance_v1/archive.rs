//! State-owner archive checkpoint generations under the same custody lock and iOS anchor.
//!
//! These records change no monetary head and sign no receipt. The checkpoint bytes are
//! durable before a fresh Released marker binds their digest. Original Selected/completion
//! identities survive metadata generations. Thus loss of both checkpoint copies is visible
//! from the authoritative marker, including after restart; an iOS restore is also checked
//! against its existing passcode-bound marker anchor.

use super::{
    KagemushaWalletProviderErrorV1 as Error, KagemushaWalletUnavailableV1 as Unavailable,
    advance::KagemushaWalletAdvanceCapsuleV1,
    anchor::kagemusha_wallet_raise_anchor_v1,
    completion::KagemushaWalletCompletionFrameV1,
    kagemusha_wallet_provider_digest_v1,
    layout::{
        KagemushaWalletEntryNameV1 as Name, KagemushaWalletSlotIdV1 as Slot,
        kagemusha_wallet_archive_dir_v1, kagemusha_wallet_require_published_v1,
    },
    marker::{
        KagemushaWalletMarkerPublicationV1, KagemushaWalletMarkerRecordV1,
        kagemusha_wallet_publish_marker_v1, kagemusha_wallet_retire_markers_v1,
    },
    platform::{KagemushaWalletFsV1, KagemushaWalletPlatformV1, KagemushaWalletReadV1},
    provider::{KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1},
    store::KagemushaWalletDurableStoreV1,
};

/// Bound on the local index-root manifest, not on proof/checkpoint payloads it references.
/// A manifest holds fixed incarnation/head fields and digest roots; large objects belong in
/// the archive by content digest and use the native descriptor's own size bound.
pub const KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1: usize = 4_096;

/// Content identity used by the source marker for its state-owner archive manifest.
#[must_use]
pub fn kagemusha_wallet_archive_checkpoint_digest_v1(bytes: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("archive-checkpoint", bytes)
}

fn names(digest: &[u8; 32]) -> [Name; 2] {
    let base = format!("a-{}.chk", hex::encode(digest));
    [base.clone(), format!("{base}.r")]
        .map(|name| Name::new(&name).expect("fixed archive checkpoint name"))
}

fn read<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &Slot,
    digest: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let directory = kagemusha_wallet_archive_dir_v1(slot);
    let mut unavailable = None;
    for name in names(digest) {
        match store.read(
            &directory,
            &name,
            KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1,
        ) {
            KagemushaWalletReadV1::Present(bytes)
                if kagemusha_wallet_archive_checkpoint_digest_v1(&bytes) == *digest =>
            {
                return Ok(bytes);
            }
            KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
            _ => {}
        }
    }
    Err(unavailable.map_or(
        Error::UnavailableCustodyData {
            object: "archive checkpoint",
        },
        Error::Unavailable,
    ))
}

fn persist<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &Slot,
    digest: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Error> {
    let directory = kagemusha_wallet_archive_dir_v1(slot);
    for name in names(digest) {
        let outcome = match store.read(
            &directory,
            &name,
            KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1,
        ) {
            KagemushaWalletReadV1::Present(old) if old == bytes => {
                store.rewrite_same(&directory, &name, bytes)
            }
            KagemushaWalletReadV1::Absent => store.write_new(&directory, &name, bytes),
            KagemushaWalletReadV1::Unavailable(reason) => return Err(Error::Unavailable(reason)),
            _ => {
                return Err(Error::UnavailableCustodyData {
                    object: "archive checkpoint",
                });
            }
        };
        kagemusha_wallet_require_published_v1(outcome)?;
    }
    Ok(())
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Read the archive manifest selected by the authoritative current marker.
    ///
    /// # Errors
    /// Reconciliation/protected-storage errors and missing or corrupt checkpoint copies.
    /// `None` means the current marker has never selected an archive manifest.
    pub fn archive_checkpoint(
        &mut self,
        slot: &Slot,
    ) -> Result<Option<([u8; 32], Vec<u8>)>, Error> {
        let status = self.reconcile_slot(slot, None)?;
        let record = status.marker().ok_or(Error::Invalid {
            field: "archive.slot",
        })?;
        let digest = record.archive_checkpoint();
        let answer = if digest == [0; 32] {
            Ok(None)
        } else {
            read(&self.store, slot, &digest).map(|bytes| Some((digest, bytes)))
        };
        self.require_storage()?;
        answer
    }

    /// Compare-and-publish a durable archive manifest in a fresh metadata generation.
    ///
    /// The caller must durably write all referenced immutable data before this operation.
    /// This method does not select a monetary head or create/recreate any receipt. An exact
    /// retry adopts the existing checkpoint and preserves its original completion bytes.
    ///
    /// # Errors
    /// Stale manifest, non-Released head, invalid size, storage/anchor errors or uncertain
    /// publication. An error never implies reversal of an already committed monetary head;
    /// reconcile the marker and compare its checkpoint digest before retrying.
    pub fn publish_archive_checkpoint(
        &mut self,
        slot: &Slot,
        expected: [u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], Error> {
        if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1 {
            return Err(Error::Invalid {
                field: "archive.manifest_size",
            });
        }
        let KagemushaWalletSlotStatusV1::Released(current) = self.reconcile_slot(slot, None)?
        else {
            return Err(Error::Invalid {
                field: "archive.head_not_released",
            });
        };
        let digest = kagemusha_wallet_archive_checkpoint_digest_v1(bytes);
        if current.archive_checkpoint() == digest {
            persist(&self.store, slot, &digest, bytes)?;
            self.require_storage()?;
            return Ok(digest);
        }
        if current.archive_checkpoint() != expected {
            return Err(Error::Invalid {
                field: "archive.stale_checkpoint",
            });
        }
        let result = (|| {
            persist(&self.store, slot, &digest, bytes)?;
            let record = current.checkpoint(digest, self.boot().unwrap_or([0; 32]))?;
            self.poison(slot);
            let durable = match kagemusha_wallet_publish_marker_v1(&self.store, record.clone())? {
                KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
                KagemushaWalletMarkerPublicationV1::GenerationTaken => {
                    return Err(Error::Unavailable(Unavailable::Busy));
                }
            };
            kagemusha_wallet_raise_anchor_v1(&self.platform, &record)?;
            kagemusha_wallet_retire_markers_v1(&self.store, &durable, &[current.generation()])?;
            self.require_storage()?;
            self.remember(slot, durable, KagemushaWalletSlotStatusV1::Released(record));
            Ok(digest)
        })();
        self.guard(slot, result)
    }

    /// Validate source-selected archive bytes during every reconcile, including cached ones.
    pub(super) fn require_archive_checkpoint(
        &self,
        record: &KagemushaWalletMarkerRecordV1,
    ) -> Result<(), Error> {
        let digest = record.archive_checkpoint();
        if digest != [0; 32] {
            read(&self.store, record.slot(), &digest)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;

/// Content identity of one immutable state-owner archive object.
#[must_use]
pub fn kagemusha_wallet_archive_object_digest_v1(bytes: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("archive-object", bytes)
}

/// A scoped archive capability: only the provider creates it, while holding the custody lock
/// and inside protected-storage availability brackets. It cannot reach markers or signers.
pub struct KagemushaWalletArchiveAccessV1<'a, F: KagemushaWalletFsV1> {
    store: &'a KagemushaWalletDurableStoreV1<F>,
    slot: &'a Slot,
}

fn object_names(digest: &[u8; 32]) -> [Name; 2] {
    let base = format!("o-{}.obj", hex::encode(digest));
    [base.clone(), format!("{base}.r")]
        .map(|name| Name::new(&name).expect("fixed archive object name"))
}

impl<F: KagemushaWalletFsV1> KagemushaWalletArchiveAccessV1<'_, F> {
    /// Read a content-addressed object within its authenticated descriptor's exact bound.
    ///
    /// # Errors
    /// Missing/corrupt known content, unavailable storage or an oversized object.
    pub fn read(&self, digest: &[u8; 32], max_bytes: usize) -> Result<Vec<u8>, Error> {
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut unavailable = None;
        for name in object_names(digest) {
            match self.store.read(&directory, &name, max_bytes) {
                KagemushaWalletReadV1::Present(bytes)
                    if kagemusha_wallet_archive_object_digest_v1(&bytes) == *digest =>
                {
                    return Ok(bytes);
                }
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                _ => {}
            }
        }
        Err(unavailable.map_or(
            Error::UnavailableCustodyData {
                object: "archive object",
            },
            Error::Unavailable,
        ))
    }

    /// Publish redundant immutable bytes within their descriptor's bound, using a fresh inode
    /// when adopting an exact retry. All referenced objects must precede manifest publication.
    ///
    /// # Errors
    /// Oversized input, unavailable storage, conflicting content or uncertain publication.
    pub fn write(&self, bytes: &[u8], max_bytes: usize) -> Result<[u8; 32], Error> {
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(Error::Invalid {
                field: "archive.object_size",
            });
        }
        let digest = kagemusha_wallet_archive_object_digest_v1(bytes);
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        for name in object_names(&digest) {
            let outcome = match self.store.read(&directory, &name, max_bytes) {
                KagemushaWalletReadV1::Present(old) if old == bytes => {
                    self.store.rewrite_same(&directory, &name, bytes)
                }
                KagemushaWalletReadV1::Absent => self.store.write_new(&directory, &name, bytes),
                KagemushaWalletReadV1::Unavailable(reason) => {
                    return Err(Error::Unavailable(reason));
                }
                _ => {
                    return Err(Error::UnavailableCustodyData {
                        object: "archive object",
                    });
                }
            };
            kagemusha_wallet_require_published_v1(outcome)?;
        }
        Ok(digest)
    }
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Run bounded archive operations under the exclusive provider and protected-data checks.
    /// The callback cannot create a selected marker, sign a receipt or choose another root.
    ///
    /// # Errors
    /// Reconciliation, callback or protected-storage errors. A failed final probe supersedes
    /// the callback answer, so eviction never masquerades as missing private data.
    pub fn with_archive<T>(
        &mut self,
        slot: &Slot,
        operation: impl FnOnce(&KagemushaWalletArchiveAccessV1<'_, F>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let status = self.reconcile_slot(slot, None)?;
        if !matches!(
            status,
            KagemushaWalletSlotStatusV1::Enrollment(_)
                | KagemushaWalletSlotStatusV1::Pending(_)
                | KagemushaWalletSlotStatusV1::Released(_)
        ) {
            return Err(Error::Invalid {
                field: "archive.slot",
            });
        }
        let result = operation(&KagemushaWalletArchiveAccessV1 {
            store: &self.store,
            slot,
        });
        let result = self.require_storage().and(result);
        self.guard(slot, result)
    }
}

fn record_names(key: &[u8; 32]) -> [Name; 2] {
    let base = format!("w-{}.rec", hex::encode(key));
    [base.clone(), format!("{base}.r")]
        .map(|name| Name::new(&name).expect("fixed archive record name"))
}
impl<F: KagemushaWalletFsV1> KagemushaWalletArchiveAccessV1<'_, F> {
    /// Read one immutable state-owner record. A digest prefix authenticates each redundant
    /// copy; the caller additionally checks its canonical incarnation/key envelope.
    ///
    /// # Errors
    /// Unavailable or corrupt copies, conflicting valid copies, or a violated payload bound.
    pub fn read_record(&self, key: &[u8; 32], max_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
        let limit = max_bytes.checked_add(32).ok_or(Error::Invalid {
            field: "archive.record_size",
        })?;
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut valid = None;
        let mut unavailable = None;
        let mut corrupt = false;
        for name in record_names(key) {
            match self.store.read(&directory, &name, limit) {
                KagemushaWalletReadV1::Absent => {}
                KagemushaWalletReadV1::Oversized => corrupt = true,
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                KagemushaWalletReadV1::Present(bytes) => {
                    if bytes.len() < 32
                        || kagemusha_wallet_archive_object_digest_v1(&bytes[32..]) != bytes[..32]
                    {
                        corrupt = true;
                        continue;
                    }
                    let bytes = bytes[32..].to_vec();
                    if valid.as_ref().is_some_and(|old| *old != bytes) {
                        return Err(Error::UnavailableCustodyData {
                            object: "conflicting archive records",
                        });
                    }
                    valid = Some(bytes);
                }
            }
        }
        if let Some(bytes) = valid {
            return Ok(Some(bytes));
        }
        if let Some(reason) = unavailable {
            return Err(Error::Unavailable(reason));
        }
        if corrupt {
            return Err(Error::UnavailableCustodyData {
                object: "archive record",
            });
        }
        Ok(None)
    }
    /// Remove both copies of a state-owner record after its selected archive manifest records
    /// the collection decision. This capability remains inside the protected-data bracket.
    ///
    /// # Errors
    /// An unavailable or uncertain deletion is returned unchanged; absence is idempotent.
    pub fn remove_record(&self, key: &[u8; 32]) -> Result<(), Error> {
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        for name in record_names(key) {
            super::layout::kagemusha_wallet_require_removed_v1(
                self.store.remove_file(&directory, &name),
            )?;
        }
        Ok(())
    }
    /// Publish the exact bytes at an immutable key under the provider's custody capability.
    ///
    /// # Errors
    /// Conflicting existing bytes, unavailable storage or uncertain durable publication.
    pub fn write_record(&self, key: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        if self
            .read_record(key, bytes.len())?
            .as_ref()
            .is_some_and(|old| *old != bytes)
        {
            return Err(Error::Invalid {
                field: "archive.immutable_record",
            });
        }
        let mut framed = Vec::with_capacity(bytes.len() + 32);
        framed.extend_from_slice(&kagemusha_wallet_archive_object_digest_v1(bytes));
        framed.extend_from_slice(bytes);
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        for name in record_names(key) {
            let outcome = match self.store.read(&directory, &name, framed.len()) {
                KagemushaWalletReadV1::Absent => self.store.write_new(&directory, &name, &framed),
                KagemushaWalletReadV1::Present(old) if old == framed => {
                    self.store.rewrite_same(&directory, &name, &framed)
                }
                KagemushaWalletReadV1::Unavailable(reason) => {
                    return Err(Error::Unavailable(reason));
                }
                _ => {
                    return Err(Error::UnavailableCustodyData {
                        object: "archive immutable record",
                    });
                }
            };
            kagemusha_wallet_require_published_v1(outcome)?;
        }
        Ok(())
    }
}
