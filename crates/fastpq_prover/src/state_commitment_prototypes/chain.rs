//! Candidate 4 (baseline): canonical sorted hash chain.
//!
//! The entries in canonical order are folded into one running digest:
//! `acc_0 = H(start)`, `acc_{i+1} = compress(acc_i, leaf_i)`, and the root is
//! the last accumulator. There is no tree.
//!
//! - **Inclusion**: the accumulator before the entry and the leaf digest of
//!   every later entry.
//! - **Absence** and **complete range**: the accumulator before the disclosed
//!   predecessor, the predecessor and successor leaves, and the leaf digest of
//!   every entry after the successor. Absence is the empty range
//!   `[key, key ‖ 0x00)`.
//!
//! Updates, witnesses and verification are linear in the number of entries
//! after the touched position. The baseline exists to show what the tree
//! candidates buy; it is not a proposal.
//!
//! TODO(G.3): prototype for measurement only; delete with the selection.

use core::marker::PhantomData;

use super::{
    Change, DOMAIN_CHAIN, Engine, Reject, Storage,
    codec::{Reader, Writer},
    entry_leaf,
    hash::{DIGEST_BYTES, Digest, HashProfile},
    immediate_successor, key_digest, leaf_digest, value_digest,
};

/// Storage model: a persisted entry keeps its leaf digest, its value digest
/// and the accumulator before it.
pub const MODEL_ENTRY_BYTES: u64 = 96;
/// Storage model: the last accumulator, the root.
pub const MODEL_ROOT_BYTES: u64 = 32;

#[derive(Clone)]
struct Entry {
    key: Vec<u8>,
    value: Digest,
    leaf: Digest,
}

/// The chain: the sorted entries and the accumulator before each of them.
pub struct SortedHashChain<H> {
    entries: Vec<Entry>,
    /// `accumulators[i]` is the digest before entry `i`; the last one is the root.
    accumulators: Vec<Digest>,
    profile: PhantomData<H>,
}

impl<H> Clone for SortedHashChain<H> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            accumulators: self.accumulators.clone(),
            profile: PhantomData,
        }
    }
}

fn start<H: HashProfile>() -> Digest {
    H::hash_bytes(DOMAIN_CHAIN, &[])
}

fn step<H: HashProfile>(accumulator: &Digest, leaf: &Digest) -> Digest {
    H::compress(DOMAIN_CHAIN, 0, accumulator, leaf)
}

fn read_disclosed<H: HashProfile>(reader: &mut Reader<'_, H>) -> Result<(Vec<u8>, Digest), Reject> {
    let key = reader.bytes()?.to_vec();
    let value = reader.digest()?;
    let leaf = leaf_digest::<H>(&key_digest::<H>(&key), &value);
    Ok((key, leaf))
}

fn read_flag<H: HashProfile>(reader: &mut Reader<'_, H>) -> Result<bool, Reject> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Reject::Malformed),
    }
}

impl<H: HashProfile> SortedHashChain<H> {
    fn position(&self, key: &[u8]) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|entry| entry.key.as_slice().cmp(key))
    }

    fn write_suffix(&self, writer: &mut Writer, from: usize) {
        writer.count(self.entries.len() - from);
        for entry in &self.entries[from..] {
            writer.digest(&entry.leaf);
        }
    }
}

impl<H: HashProfile> Engine for SortedHashChain<H> {
    type Hash = H;

    const CONSTRUCTION: &'static str = "sorted-hash-chain/baseline/v0";

    fn new() -> Self {
        Self {
            entries: Vec::new(),
            accumulators: vec![start::<H>()],
            profile: PhantomData,
        }
    }

    fn apply(&mut self, changes: &[Change<'_>]) {
        // One merge of the sorted changes into the sorted entries, so a large
        // change set costs one pass rather than one shift per change.
        let mut sorted: Vec<Change<'_>> = changes.to_vec();
        sorted.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut pending = sorted.into_iter().peekable();
        let mut merged = Vec::with_capacity(self.entries.len() + changes.len());
        let mut first_changed: Option<usize> = None;
        let insert = |merged: &mut Vec<Entry>, key: &[u8], value: &[u8]| {
            let digest = value_digest::<H>(value);
            merged.push(Entry {
                key: key.to_vec(),
                value: digest,
                leaf: leaf_digest::<H>(&key_digest::<H>(key), &digest),
            });
        };
        for entry in core::mem::take(&mut self.entries) {
            while let Some((key, value)) = pending.next_if(|(key, _)| *key < entry.key.as_slice()) {
                if let Some(value) = value {
                    first_changed.get_or_insert(merged.len());
                    insert(&mut merged, key, value);
                }
            }
            match pending.next_if(|(key, _)| *key == entry.key.as_slice()) {
                None => merged.push(entry),
                Some((_, None)) => {
                    first_changed.get_or_insert(merged.len());
                }
                Some((_, Some(value))) => {
                    let digest = value_digest::<H>(value);
                    if digest == entry.value {
                        merged.push(entry);
                    } else {
                        first_changed.get_or_insert(merged.len());
                        merged.push(Entry {
                            leaf: leaf_digest::<H>(&key_digest::<H>(&entry.key), &digest),
                            value: digest,
                            key: entry.key,
                        });
                    }
                }
            }
        }
        for (key, value) in pending {
            if let Some(value) = value {
                first_changed.get_or_insert(merged.len());
                insert(&mut merged, key, value);
            }
        }
        self.entries = merged;
        let first_changed =
            first_changed.map_or(self.entries.len(), |first| first.min(self.entries.len()));
        self.accumulators.truncate(first_changed + 1);
        for index in first_changed..self.entries.len() {
            let next = step::<H>(&self.accumulators[index], &self.entries[index].leaf);
            self.accumulators.push(next);
        }
    }

    fn structure_root(&self) -> Digest {
        self.accumulators[self.entries.len()]
    }

    fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    fn prove_inclusion(&self, key: &[u8]) -> Option<Vec<u8>> {
        let index = self.position(key).ok()?;
        let mut writer = Writer::default();
        writer.digest(&self.accumulators[index]);
        self.write_suffix(&mut writer, index + 1);
        Some(writer.finish())
    }

    fn prove_absence(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.position(key).is_ok() {
            return None;
        }
        Some(self.prove_range(key, Some(&immediate_successor(key))))
    }

    fn prove_range(&self, lower: &[u8], upper: Option<&[u8]>) -> Vec<u8> {
        let first = self
            .entries
            .partition_point(|entry| entry.key.as_slice() < lower);
        let end = upper.map_or(self.entries.len(), |upper| {
            self.entries
                .partition_point(|entry| entry.key.as_slice() < upper)
        });
        let mut writer = Writer::default();
        match first.checked_sub(1) {
            Some(predecessor) => {
                writer.u8(1);
                writer.digest(&self.accumulators[predecessor]);
                writer.bytes(&self.entries[predecessor].key);
                writer.digest(&self.entries[predecessor].value);
            }
            None => writer.u8(0),
        }
        match self.entries.get(end) {
            Some(successor) => {
                writer.u8(1);
                writer.bytes(&successor.key);
                writer.digest(&successor.value);
                self.write_suffix(&mut writer, end + 1);
            }
            None => writer.u8(0),
        }
        writer.finish()
    }

    fn inclusion_root(key: &[u8], value: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        let mut reader = Reader::<H>::new(witness);
        let prefix = reader.digest()?;
        let mut accumulator = step::<H>(&prefix, &entry_leaf::<H>(key, value));
        for _ in 0..reader.count(DIGEST_BYTES)? {
            accumulator = step::<H>(&accumulator, &reader.digest()?);
        }
        reader.finish()?;
        Ok(accumulator)
    }

    fn absence_root(key: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        Self::range_root(key, Some(&immediate_successor(key)), &[], witness)
    }

    fn range_root(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<Digest, Reject> {
        let mut reader = Reader::<H>::new(witness);
        // Without a predecessor the run starts at the start of the chain.
        let mut accumulator = if read_flag(&mut reader)? {
            let prefix = reader.digest()?;
            let (key, leaf) = read_disclosed(&mut reader)?;
            if key.as_slice() >= lower {
                return Err(Reject::NotProven);
            }
            step::<H>(&prefix, &leaf)
        } else {
            start::<H>()
        };
        for (key, value) in entries {
            accumulator = step::<H>(&accumulator, &entry_leaf::<H>(key, value));
        }
        // Without a successor the run ends at the end of the chain.
        if read_flag(&mut reader)? {
            let (key, leaf) = read_disclosed(&mut reader)?;
            if upper.is_none_or(|upper| key.as_slice() < upper) {
                return Err(Reject::NotProven);
            }
            accumulator = step::<H>(&accumulator, &leaf);
            for _ in 0..reader.count(DIGEST_BYTES)? {
                accumulator = step::<H>(&accumulator, &reader.digest()?);
            }
        }
        reader.finish()?;
        Ok(accumulator)
    }

    fn storage(&self) -> Storage {
        let entries = self.entries.len() as u64;
        Storage {
            entries,
            // Leaf and value digest per entry and every kept accumulator.
            digests: 2 * entries + self.accumulators.len() as u64,
            structure_bytes: entries * MODEL_ENTRY_BYTES + MODEL_ROOT_BYTES,
            auxiliary_bytes: 0,
            max_depth: u32::try_from(entries).unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment_prototypes::hash::{Blake2bProfile, take_hash_work};

    type Chain = SortedHashChain<Blake2bProfile>;

    /// A change set is merged in one pass and only the accumulators from the
    /// first changed position on are recomputed.
    #[test]
    fn change_set_recomputes_only_the_suffix_after_its_first_change() {
        let keys: Vec<Vec<u8>> = (0..100_u8).map(|index| vec![index]).collect();
        let initial: Vec<Change<'_>> = keys
            .iter()
            .map(|key| (key.as_slice(), Some(&b"v"[..])))
            .collect();
        let mut chain = Chain::new();
        let _ = take_hash_work();
        chain.apply(&initial);
        let build = take_hash_work();
        // One leaf and one step per entry.
        assert_eq!(build.compressions, 200);
        assert_eq!(chain.accumulators.len(), 101);
        let root = chain.structure_root();

        // Unordered changes: an insertion near the end, a rewrite and a removal.
        chain.apply(&[
            (&[98, 0], Some(b"new")),
            (&[90], Some(b"w")),
            (&[95], None),
            (&[200], None),
            (&[3], Some(b"v")),
        ]);
        let update = take_hash_work();
        // Two new leaves, then every step from position 90 to the end.
        assert_eq!(chain.len(), 100);
        assert_eq!(update.compressions, 2 + 10);
        assert_ne!(chain.structure_root(), root);
        let sorted: Vec<&[u8]> = chain
            .entries
            .iter()
            .map(|entry| entry.key.as_slice())
            .collect();
        assert!(sorted.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(chain.position(&[98, 0]), Ok(98));
        assert_eq!(chain.position(&[95]), Err(95));

        // The same content built cold has the same root.
        let mut cold = Chain::new();
        let content: Vec<(Vec<u8>, &[u8])> = keys
            .iter()
            .filter(|key| key[0] != 95)
            .map(|key| {
                (
                    key.clone(),
                    if key[0] == 90 { &b"w"[..] } else { &b"v"[..] },
                )
            })
            .chain(core::iter::once((vec![98, 0], &b"new"[..])))
            .collect();
        let changes: Vec<Change<'_>> = content
            .iter()
            .map(|(key, value)| (key.as_slice(), Some(*value)))
            .collect();
        cold.apply(&changes);
        assert_eq!(cold.structure_root(), chain.structure_root());
        // The storage model counts the kept digests: two per entry and one
        // accumulator before each entry and after the last.
        let storage = chain.storage();
        assert_eq!(chain.accumulators.len(), 101);
        assert_eq!((storage.entries, storage.digests), (100, 2 * 100 + 101));
        assert_eq!(storage.structure_bytes, 100 * 96 + 32);
        let copy = chain.clone();
        assert_eq!(copy.structure_root(), chain.structure_root());
        assert_eq!(copy.storage(), storage);
        // Removing the last entry drops its accumulator.
        chain.apply(&[(&[99], None)]);
        assert_eq!(chain.accumulators.len(), 100);
        assert_eq!(start::<Blake2bProfile>(), Chain::new().structure_root());
    }
}
