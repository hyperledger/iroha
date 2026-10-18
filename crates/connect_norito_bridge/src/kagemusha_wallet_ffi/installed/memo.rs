//! One process-local admitted graph, reused only for byte-identical installation originals
//! under the same carrier root (design §9.1).
//!
//! The single entry holds the public objects of one complete successful installation: the
//! installed verifier pack, the complete source graph and the carrier reader with its
//! observed custody. It holds no provider, platform, custody root, key or enrollment state;
//! the source graph keeps its verify-once memos (process-local, success-only, exact-byte
//! keyed), which a later installation in this process may reuse for mathematical validity
//! only. It is never serialized, persisted or exposed over C or JNI, and it grants nothing:
//! every attempt authenticates its own originals, and a hit is used only after the caller has
//! closed custody over the reader's observed originals and re-hashed every stored frame.

use super::*;
use std::sync::MutexGuard;

/// Domain of the exact framed originals hashed into a key.
const DOMAIN: &[u8] = b"iroha.kagemusha.wallet-admitted-graph-memo.v1\0";

/// Exact identity of one attempt's inputs: the eight runtime originals, each framed by its
/// length, and the kernel identity of the carrier root. The whole frame is retained and
/// compared on every lookup; an equal digest alone never selects an entry.
#[derive(PartialEq, Eq)]
pub(super) struct MemoKey {
    digest: [u8; 32],
    frame: Box<[u8]>,
}

impl MemoKey {
    /// Frame `input` (already bounded by `validate_bounds`) and the opened root's identity.
    pub(super) fn new(input: &RuntimeOriginals<'_>, root: iroha_fs::FileIdentity) -> Self {
        let originals = [
            input.app_manifest,
            input.envelope,
            input.wallet_runtime,
            input.verifier_pack,
            input.producer_inventory,
            input.signed_genesis,
            input.originals_root,
            input.registration_source,
        ];
        let (kind, volume, object) = root.local_parts();
        let mut frame = Vec::with_capacity(
            DOMAIN.len()
                + originals
                    .iter()
                    .map(|original| 8 + original.len())
                    .sum::<usize>()
                + 1
                + 8
                + object.len(),
        );
        frame.extend_from_slice(DOMAIN);
        for original in originals {
            frame.extend_from_slice(&(original.len() as u64).to_le_bytes());
            frame.extend_from_slice(original);
        }
        frame.push(kind);
        frame.extend_from_slice(&volume.to_le_bytes());
        frame.extend_from_slice(&object);
        Self {
            digest: BlobV1::of(&frame).sha256,
            frame: frame.into_boxed_slice(),
        }
    }
}

struct Slot<T> {
    // Changes whenever an entry is stored or evicted.
    generation: u64,
    entry: Option<(MemoKey, T)>,
}

/// A one-entry, process-local, success-only memo. The lock is held only to compare, clone
/// or swap the entry, never across I/O, proving or a platform upcall, and a replaced,
/// evicted or discarded entry is dropped after the lock is released. A poisoned lock is a
/// miss that discards its entry.
pub(super) struct Memo<T> {
    slot: Mutex<Slot<T>>,
}

impl<T> Memo<T> {
    pub(super) const fn new() -> Self {
        Self {
            slot: Mutex::new(Slot {
                generation: 0,
                entry: None,
            }),
        }
    }

    /// The unpoisoned slot. A poisoned memo is a miss: whatever it held is discarded and
    /// dropped after the lock is released, and the lock is then taken again.
    fn lock(&self) -> MutexGuard<'_, Slot<T>> {
        loop {
            match self.slot.lock() {
                Ok(slot) => return slot,
                Err(poisoned) => {
                    let mut slot = poisoned.into_inner();
                    slot.generation = slot.generation.wrapping_add(1);
                    let stale = slot.entry.take();
                    self.slot.clear_poison();
                    drop(slot);
                    drop(stale);
                }
            }
        }
    }

    /// Make `entry` (or nothing) the only entry; the previous one is dropped unlocked.
    fn replace(&self, entry: Option<(MemoKey, T)>) {
        let mut slot = self.lock();
        slot.generation = slot.generation.wrapping_add(1);
        let previous = std::mem::replace(&mut slot.entry, entry);
        drop(slot);
        drop(previous);
    }

    /// Settle one installation attempt. Complete success stores its admitted entry; an
    /// INVALID or CUSTODY_LOST result evicts the entry; any other refusal leaves it.
    pub(super) fn settle<R>(&self, result: Result<(R, (MemoKey, T))>) -> Result<R> {
        match result {
            Ok((value, entry)) => {
                self.replace(Some(entry));
                Ok(value)
            }
            Err(error) => {
                if matches!(error.status, INVALID | CUSTODY_LOST) {
                    self.replace(None);
                }
                Err(error)
            }
        }
    }
}

impl<T: Clone> Memo<T> {
    /// The entry stored under exactly `key`, with its generation. Any other entry is
    /// evicted, so a fresh admission never runs beside a stale graph.
    fn get(&self, key: &MemoKey) -> Option<(u64, T)> {
        let mut slot = self.lock();
        if let Some((stored, value)) = &slot.entry
            && stored == key
        {
            return Some((slot.generation, value.clone()));
        }
        slot.generation = slot.generation.wrapping_add(1);
        let stale = slot.entry.take();
        drop(slot);
        drop(stale);
        None
    }

    /// Offer the entry stored under exactly `key` to `reuse`, outside the lock. Another
    /// entry, and this entry when `reuse` refuses it, is evicted and `None` returns, so the
    /// caller admits from scratch. An entry stored meanwhile by another attempt is kept.
    pub(super) fn reuse<R>(&self, key: &MemoKey, reuse: impl FnOnce(T) -> Result<R>) -> Option<R> {
        let (generation, value) = self.get(key)?;
        if let Ok(reused) = reuse(value) {
            return Some(reused);
        }
        let mut slot = self.lock();
        let stale = if slot.generation == generation {
            slot.generation = slot.generation.wrapping_add(1);
            slot.entry.take()
        } else {
            None
        };
        drop(slot);
        drop(stale);
        None
    }
}

#[cfg(test)]
mod tests;
