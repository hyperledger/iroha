//! Admission-ordered index of queue-resident inputs.
//!
//! Every resident input owns exactly one entry keyed by its non-reusable admission incarnation:
//! a FIFO position, an optional expiry deadline and the digest of its exact canonical entrypoint
//! frame. Removal is by key, so retiring committed, expired or cleared inputs costs `O(log n)`
//! per removed input and never rescans unrelated queued work. Memory is bounded by the number of
//! resident inputs; no stale entry survives a removal.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use iroha_crypto::Hash;

use super::EntrypointHash;

/// One queue-resident input in admission order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PendingOrderEntry {
    /// Canonical entrypoint identity of the resident input.
    pub(super) hash: EntrypointHash,
    /// Canonical admission timestamp in milliseconds, used for queue-residence age.
    pub(super) enqueued_at_ms: u64,
    /// First instant at which the input is expired; `None` when it never expires by TTL.
    pub(super) expires_at: Option<Duration>,
    /// Digest of the exact canonical entrypoint frame the queue retains and gossips.
    pub(super) frame: Hash,
}

/// FIFO keyed by admission incarnation, with a deadline-ordered expiry set and frame digests.
///
/// The owning queue mutates it only under its admission/removal fence; the surrounding mutex
/// serves lock-free readers such as pressure snapshots and gossip ingress.
#[derive(Debug, Default)]
pub(super) struct PendingOrderIndex {
    /// Incarnations increase with admission order, so key order is FIFO order.
    fifo: BTreeMap<u64, PendingOrderEntry>,
    /// `(deadline, incarnation)` of every entry with a finite expiry deadline.
    expiry: BTreeSet<(Duration, u64)>,
    /// Canonical frame digest of every entry, mapped to its incarnation.
    frames: HashMap<Hash, u64>,
    /// Advisory local sampling position: the first incarnation of the next bounded window.
    /// It is never part of proposal validity. Any removal restarts sampling at the FIFO front.
    scan_from: Option<u64>,
}

impl PendingOrderIndex {
    /// Record one admitted input under its fresh incarnation.
    ///
    /// Returns `false` and changes nothing when the incarnation or the exact frame is already
    /// indexed; the queue treats that as an admission invariant failure.
    pub(super) fn insert(&mut self, incarnation: u64, entry: PendingOrderEntry) -> bool {
        if self.fifo.contains_key(&incarnation) || self.frames.contains_key(&entry.frame) {
            return false;
        }
        if let Some(deadline) = entry.expires_at {
            self.expiry.insert((deadline, incarnation));
        }
        self.frames.insert(entry.frame, incarnation);
        self.fifo.insert(incarnation, entry);
        true
    }

    /// Remove the entry of one admission and restart advisory sampling at the FIFO front.
    pub(super) fn remove(&mut self, incarnation: u64) -> Option<PendingOrderEntry> {
        let entry = self.fifo.remove(&incarnation)?;
        if let Some(deadline) = entry.expires_at {
            self.expiry.remove(&(deadline, incarnation));
        }
        if self.frames.get(&entry.frame) == Some(&incarnation) {
            self.frames.remove(&entry.frame);
        }
        self.scan_from = None;
        Some(entry)
    }

    /// Number of resident inputs.
    pub(super) fn len(&self) -> usize {
        self.fifo.len()
    }

    /// Whether no input is resident.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.fifo.is_empty()
    }

    /// Oldest admitted resident input.
    pub(super) fn front(&self) -> Option<&PendingOrderEntry> {
        self.fifo.first_key_value().map(|(_, entry)| entry)
    }

    /// Whether a resident input retains exactly this canonical frame digest.
    pub(super) fn holds_frame(&self, frame: &Hash) -> bool {
        self.frames.contains_key(frame)
    }

    /// Take the next advisory window of at most `max` resident inputs in admission order.
    ///
    /// Returns the window and whether further resident inputs follow it. A window that reaches
    /// the FIFO end makes the next call start again at the front.
    pub(super) fn next_window(&mut self, max: usize) -> (Vec<(u64, EntrypointHash)>, bool) {
        let start = self
            .scan_from
            .take()
            .filter(|first| self.fifo.range(*first..).next().is_some());
        let range = match start {
            Some(first) => self.fifo.range(first..),
            None => self.fifo.range(..),
        };
        let mut window = Vec::with_capacity(max.min(self.fifo.len()));
        let mut next = None;
        for (&incarnation, entry) in range {
            if window.len() == max {
                next = Some(incarnation);
                break;
            }
            window.push((incarnation, entry.hash));
        }
        self.scan_from = next;
        (window, next.is_some())
    }

    /// Resident inputs whose expiry deadline is not after `now`, earliest deadline first.
    pub(super) fn expired(&self, now: Duration, max: usize) -> Vec<(u64, EntrypointHash)> {
        self.expiry
            .iter()
            .take_while(|(deadline, _)| *deadline <= now)
            .take(max)
            .filter_map(|(_, incarnation)| {
                self.fifo
                    .get(incarnation)
                    .map(|entry| (*incarnation, entry.hash))
            })
            .collect()
    }

    /// Rewrite every resident input's admission timestamp and expiry deadline in place.
    ///
    /// FIFO order is preserved; only fixtures that backdate queue residence use this.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(super) fn rebase(
        &mut self,
        mut rebase: impl FnMut(&PendingOrderEntry) -> (u64, Option<Duration>),
    ) {
        let mut expiry = BTreeSet::new();
        for (incarnation, entry) in &mut self.fifo {
            let (enqueued_at_ms, expires_at) = rebase(entry);
            entry.enqueued_at_ms = enqueued_at_ms;
            entry.expires_at = expires_at;
            if let Some(deadline) = expires_at {
                expiry.insert((deadline, *incarnation));
            }
        }
        self.expiry = expiry;
    }

    /// Number of entries tracked by the expiry set.
    #[cfg(test)]
    pub(super) fn expiry_len(&self) -> usize {
        self.expiry.len()
    }

    /// Number of tracked frame digests.
    #[cfg(test)]
    pub(super) fn frame_len(&self) -> usize {
        self.frames.len()
    }

    /// Every entry in admission order.
    #[cfg(test)]
    pub(super) fn entries(&self) -> Vec<(u64, PendingOrderEntry)> {
        self.fifo
            .iter()
            .map(|(incarnation, entry)| (*incarnation, *entry))
            .collect()
    }

    /// Whether an entry for `hash` is resident.
    #[cfg(test)]
    pub(super) fn contains_hash(&self, hash: &EntrypointHash) -> bool {
        self.fifo.values().any(|entry| entry.hash == *hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::HashOf;

    fn entry(seed: u8, expires_at_ms: Option<u64>) -> PendingOrderEntry {
        PendingOrderEntry {
            hash: HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32])),
            enqueued_at_ms: u64::from(seed),
            expires_at: expires_at_ms.map(Duration::from_millis),
            frame: Hash::new([seed]),
        }
    }

    fn hashes(window: &[(u64, EntrypointHash)]) -> Vec<u64> {
        window.iter().map(|(incarnation, _)| *incarnation).collect()
    }

    #[test]
    fn insert_rejects_reused_incarnation_and_frame_without_mutation() {
        let mut index = PendingOrderIndex::default();
        assert!(index.insert(1, entry(1, Some(10))));
        assert!(
            !index.insert(1, entry(2, Some(20))),
            "incarnations are unique"
        );
        assert!(
            !index.insert(2, entry(1, Some(30))),
            "one resident owner per frame"
        );
        assert_eq!(index.len(), 1);
        assert_eq!(index.expiry_len(), 1);
        assert_eq!(index.frame_len(), 1);
        assert!(index.holds_frame(&Hash::new([1])));
        assert!(!index.holds_frame(&Hash::new([2])));
    }

    #[test]
    fn removal_by_key_clears_fifo_expiry_and_frame_without_touching_other_entries() {
        let mut index = PendingOrderIndex::default();
        for seed in 1..=4 {
            assert!(index.insert(u64::from(seed), entry(seed, Some(u64::from(seed) * 10))));
        }
        assert!(index.insert(5, entry(5, None)));
        assert_eq!(index.remove(2), Some(entry(2, Some(20))));
        assert_eq!(index.remove(2), None, "removal is idempotent");
        assert_eq!(index.remove(5), Some(entry(5, None)));
        assert_eq!(
            index
                .entries()
                .into_iter()
                .map(|(incarnation, _)| incarnation)
                .collect::<Vec<_>>(),
            vec![1, 3, 4]
        );
        assert_eq!(index.expiry_len(), 3);
        assert_eq!(index.frame_len(), 3);
        assert!(!index.holds_frame(&Hash::new([2])));
        assert_eq!(index.front(), Some(&entry(1, Some(10))));
        assert_eq!(
            index.remove(1).map(|removed| removed.hash),
            Some(entry(1, None).hash)
        );
        assert_eq!(index.front().map(|front| front.enqueued_at_ms), Some(3));
        for incarnation in [3, 4] {
            assert!(index.remove(incarnation).is_some());
        }
        assert!(index.is_empty());
        assert_eq!((index.expiry_len(), index.frame_len()), (0, 0));
    }

    #[test]
    fn windows_follow_admission_order_wrap_at_the_end_and_restart_after_removal() {
        let mut index = PendingOrderIndex::default();
        for seed in 1..=5 {
            assert!(index.insert(u64::from(seed), entry(seed, None)));
        }
        let (first, more) = index.next_window(2);
        assert_eq!((hashes(&first), more), (vec![1, 2], true));
        let (second, more) = index.next_window(2);
        assert_eq!((hashes(&second), more), (vec![3, 4], true));
        let (third, more) = index.next_window(2);
        assert_eq!((hashes(&third), more), (vec![5], false));
        let (wrapped, more) = index.next_window(2);
        assert_eq!(
            (hashes(&wrapped), more),
            (vec![1, 2], true),
            "an exhausted window restarts at the FIFO front"
        );
        assert!(index.remove(1).is_some());
        let (restarted, more) = index.next_window(2);
        assert_eq!(
            (hashes(&restarted), more),
            (vec![2, 3], true),
            "removal restarts sampling at the oldest resident input"
        );
        let (all, more) = index.next_window(usize::MAX);
        assert_eq!((hashes(&all), more), (vec![4, 5], false));
        assert_eq!(index.next_window(usize::MAX).0.len(), 4);
    }

    #[test]
    fn expired_returns_only_due_deadlines_in_deadline_order_and_respects_the_budget() {
        let mut index = PendingOrderIndex::default();
        // Admission order differs from deadline order.
        assert!(index.insert(1, entry(1, Some(30))));
        assert!(index.insert(2, entry(2, Some(10))));
        assert!(index.insert(3, entry(3, None)));
        assert!(index.insert(4, entry(4, Some(20))));
        assert!(index.expired(Duration::from_millis(9), 8).is_empty());
        assert_eq!(
            hashes(&index.expired(Duration::from_millis(10), 8)),
            vec![2]
        );
        assert_eq!(
            hashes(&index.expired(Duration::from_millis(30), 8)),
            vec![2, 4, 1]
        );
        assert_eq!(
            hashes(&index.expired(Duration::from_millis(30), 2)),
            vec![2, 4]
        );
        assert_eq!(index.expired(Duration::MAX, usize::MAX).len(), 3);
    }

    #[test]
    fn rebase_rewrites_age_and_expiry_without_reordering() {
        let mut index = PendingOrderIndex::default();
        assert!(index.insert(1, entry(1, Some(50))));
        assert!(index.insert(2, entry(2, None)));
        index.rebase(|current| (current.enqueued_at_ms + 100, Some(Duration::from_millis(5))));
        assert_eq!(index.front().map(|front| front.enqueued_at_ms), Some(101));
        assert_eq!(index.expiry_len(), 2);
        assert_eq!(
            hashes(&index.expired(Duration::from_millis(5), 8)),
            vec![1, 2]
        );
        let (window, _) = index.next_window(8);
        assert_eq!(hashes(&window), vec![1, 2]);
    }
}
