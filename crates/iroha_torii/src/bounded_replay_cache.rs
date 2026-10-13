//! Fail-closed in-memory replay protection shared by Torii authentication paths.
use iroha_crypto::Hash;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    num::NonZeroUsize,
    sync::Mutex,
    time::{Duration, Instant},
};
#[cfg(test)]
const REPLAY_KEY_DIGEST_DOMAIN_V1: &[u8] = b"iroha:torii:replay-cache:v1\0";
/// Reason a nonce could not be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// The nonce is already live in the cache.
    Replay,
    /// All configured slots contain live nonces, or slot storage is unavailable.
    Capacity,
    /// The configured lifetime cannot be represented by the monotonic clock.
    LifetimeOverflow,
}
#[derive(Debug)]
struct Inner {
    ttl: Duration,
    capacity: NonZeroUsize,
    entries: HashMap<Hash, ReplayEntry>,
    expirations: BinaryHeap<Reverse<(Instant, Hash)>>,
    has_discarded_evidence: bool,
    admission_gate: AdmissionGate,
}
#[derive(Clone, Copy, Debug)]
struct ReplayEntry {
    inserted_at: Instant,
    expires_at: Option<Instant>,
}
#[derive(Clone, Copy, Debug)]
enum AdmissionGate {
    Open,
    QuarantinedUntil(Instant),
    Closed,
}
impl Inner {
    fn prune_expired(&mut self, now: Instant) {
        while let Some(Reverse((expires_at, _))) = self.expirations.peek() {
            if *expires_at > now {
                break;
            }
            let Some(Reverse((expires_at, key))) = self.expirations.pop() else {
                break;
            };
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.expires_at == Some(expires_at))
            {
                self.entries.remove(&key);
                self.has_discarded_evidence = true;
            }
        }
    }

    fn reserve_for_insert(&mut self, additional: usize) -> Result<(), InsertError> {
        self.entries
            .try_reserve(additional)
            .map_err(|_| InsertError::Capacity)?;
        self.expirations
            .try_reserve(additional)
            .map_err(|_| InsertError::Capacity)
    }

    fn extend_live_expirations(&mut self, ttl: Duration) {
        if ttl <= self.ttl {
            return;
        }
        for entry in self.entries.values_mut() {
            let Some(current) = entry.expires_at else {
                continue;
            };
            // If the monotonic clock cannot represent the widened deadline,
            // retain the evidence indefinitely rather than expiring it early.
            let Some(widened) = entry.inserted_at.checked_add(ttl) else {
                entry.expires_at = None;
                continue;
            };
            entry.expires_at = Some(current.max(widened));
        }

        // Every live finite entry already had a queued expiration, so clearing
        // and rebuilding in place cannot grow the heap allocation.
        self.expirations.clear();
        let Self {
            entries,
            expirations,
            ..
        } = self;
        for (key, entry) in entries {
            if let Some(expires_at) = entry.expires_at {
                expirations.push(Reverse((expires_at, *key)));
            }
        }
    }

    fn quarantine_for_ttl_widening(&mut self, ttl: Duration, now: Instant) {
        if ttl <= self.ttl || !self.has_discarded_evidence {
            return;
        }
        // A wider window could otherwise make a nonce whose evidence was
        // already pruned admissible again. Reject all unknown nonces for the
        // newly exposed interval; live keys still take the Replay path.
        let extension = ttl.checked_sub(self.ttl).unwrap();
        let base = match self.admission_gate {
            AdmissionGate::QuarantinedUntil(until) if until > now => until,
            AdmissionGate::Closed => return,
            AdmissionGate::Open | AdmissionGate::QuarantinedUntil(_) => now,
        };
        self.admission_gate = base
            .checked_add(extension)
            .map_or(AdmissionGate::Closed, AdmissionGate::QuarantinedUntil);
    }

    fn admits_new_nonce_at(&mut self, now: Instant) -> bool {
        match self.admission_gate {
            AdmissionGate::Open => true,
            AdmissionGate::QuarantinedUntil(until) if now >= until => {
                self.admission_gate = AdmissionGate::Open;
                true
            }
            AdmissionGate::QuarantinedUntil(_) | AdmissionGate::Closed => false,
        }
    }
}
/// Bounded replay cache that never evicts an unexpired nonce.
#[derive(Debug)]
pub struct ReplayCache {
    inner: Mutex<Inner>,
}
impl ReplayCache {
    /// Create a cache with a fixed nonce lifetime and capacity.
    pub(crate) fn new(ttl: Duration, capacity: NonZeroUsize) -> Self {
        debug_assert!(!ttl.is_zero());
        Self {
            inner: Mutex::new(Inner {
                ttl,
                capacity,
                entries: HashMap::new(),
                expirations: BinaryHeap::new(),
                has_discarded_evidence: false,
                admission_gate: AdmissionGate::Open,
            }),
        }
    }
    /// Reconfigure future inserts without discarding live replay evidence.
    ///
    /// Widening after any evidence was pruned temporarily fails closed for the
    /// TTL delta so that discarded history cannot become admissible again.
    pub(crate) fn configure(&self, ttl: Duration, capacity: NonZeroUsize) {
        self.configure_at(ttl, capacity, Instant::now());
    }

    fn configure_at(&self, ttl: Duration, capacity: NonZeroUsize, now: Instant) {
        debug_assert!(!ttl.is_zero());
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.prune_expired(now);
        inner.extend_live_expirations(ttl);
        inner.quarantine_for_ttl_widening(ttl, now);
        inner.ttl = ttl;
        inner.capacity = capacity;
    }
    /// Admit a new nonce, rejecting replay and saturated live state.
    #[cfg(test)]
    pub(crate) fn check_and_insert(&self, key: String) -> Result<(), InsertError> {
        self.check_and_insert_at(key, Instant::now())
    }
    /// Admit a caller-domain-separated fixed-size replay digest.
    ///
    /// Protocol paths that can stream their structured replay identity should
    /// use this seam instead of first formatting an attacker-sized `String`.
    pub(crate) fn check_and_insert_digest(&self, key: Hash) -> Result<(), InsertError> {
        self.check_and_insert_digest_at(key, Instant::now())
    }

    /// Admit a fixed-size replay digest while retaining it for at least the
    /// freshness-policy lifetime captured by the caller.
    ///
    /// A verifier snapshots freshness policy before doing signature work. If
    /// configuration shrinks concurrently, the mutable cache TTL must not
    /// shorten evidence for that already-admitted timestamp window.
    pub(crate) fn check_and_insert_digest_with_minimum_ttl(
        &self,
        key: Hash,
        minimum_ttl: Duration,
    ) -> Result<(), InsertError> {
        self.check_and_insert_digest_at_with_minimum_ttl(key, Instant::now(), minimum_ttl)
    }
    #[cfg(test)]
    fn check_and_insert_at(&self, key: String, now: Instant) -> Result<(), InsertError> {
        // Callers may include an attacker-sized authority representation in
        // this key. Retain only a domain-separated fixed-size digest; keeping
        // the original String in both indices would turn the count cap into a
        // large variable-byte cache.
        let key = Hash::new_from_chunks(&[REPLAY_KEY_DIGEST_DOMAIN_V1, key.as_bytes()]);
        self.check_and_insert_digest_at(key, now)
    }
    fn check_and_insert_digest_at(&self, key: Hash, now: Instant) -> Result<(), InsertError> {
        self.check_and_insert_digest_at_with_minimum_ttl(key, now, Duration::ZERO)
    }

    fn check_and_insert_digest_at_with_minimum_ttl(
        &self,
        key: Hash,
        now: Instant,
        minimum_ttl: Duration,
    ) -> Result<(), InsertError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.prune_expired(now);
        if inner.entries.contains_key(&key) {
            return Err(InsertError::Replay);
        }
        if !inner.admits_new_nonce_at(now) {
            return Err(InsertError::Capacity);
        }
        if inner.entries.len() >= inner.capacity.get() {
            return Err(InsertError::Capacity);
        }
        let retention = inner.ttl.max(minimum_ttl);
        let expires_at = now
            .checked_add(retention)
            .ok_or(InsertError::LifetimeOverflow)?;
        inner.reserve_for_insert(1)?;
        inner.entries.insert(
            key,
            ReplayEntry {
                inserted_at: now,
                expires_at: Some(expires_at),
            },
        );
        inner.expirations.push(Reverse((expires_at, key)));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_cache_preserves_every_live_nonce() {
        let cache = ReplayCache::new(
            Duration::from_secs(300),
            NonZeroUsize::new(2).expect("non-zero"),
        );
        cache
            .check_and_insert("protected-a".to_owned())
            .expect("first nonce");
        cache
            .check_and_insert("protected-b".to_owned())
            .expect("second nonce");
        assert_eq!(
            cache.check_and_insert("overflow".to_owned()),
            Err(InsertError::Capacity)
        );
        assert_eq!(
            cache.check_and_insert("protected-a".to_owned()),
            Err(InsertError::Replay)
        );
        assert_eq!(
            cache.check_and_insert("protected-b".to_owned()),
            Err(InsertError::Replay)
        );
    }
    #[test]
    fn expired_nonce_releases_capacity_without_sleeping() {
        let cache = ReplayCache::new(
            Duration::from_secs(1),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        let start = Instant::now();
        cache
            .check_and_insert_at("expired".to_owned(), start)
            .expect("first nonce");
        cache
            .check_and_insert_at("replacement".to_owned(), start + Duration::from_secs(1))
            .expect("expired nonce must release its slot");
        assert_eq!(
            cache.check_and_insert_at("expired".to_owned(), start + Duration::from_secs(1)),
            Err(InsertError::Capacity)
        );
    }
    #[test]
    fn shrinking_capacity_never_evicts_live_evidence() {
        let cache = ReplayCache::new(
            Duration::from_secs(300),
            NonZeroUsize::new(2).expect("non-zero"),
        );
        cache
            .check_and_insert("protected-a".to_owned())
            .expect("first nonce");
        cache
            .check_and_insert("protected-b".to_owned())
            .expect("second nonce");
        cache.configure(
            Duration::from_secs(300),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        assert_eq!(
            cache.check_and_insert("protected-a".to_owned()),
            Err(InsertError::Replay)
        );
        assert_eq!(
            cache.check_and_insert("protected-b".to_owned()),
            Err(InsertError::Replay)
        );
        assert_eq!(
            cache.check_and_insert("new".to_owned()),
            Err(InsertError::Capacity)
        );
    }

    #[test]
    fn reservation_failure_does_not_publish_partial_replay_evidence() {
        let cache = ReplayCache::new(
            Duration::from_secs(300),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        {
            let mut inner = cache
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(
                inner.reserve_for_insert(usize::MAX),
                Err(InsertError::Capacity)
            );
            assert!(inner.entries.is_empty());
            assert!(inner.expirations.is_empty());
        }
        cache
            .check_and_insert("admitted-after-reservation-failure".to_owned())
            .expect("a failed reservation must not poison cache state");
    }

    #[test]
    fn widening_ttl_extends_live_evidence_to_the_widened_deadline() {
        let cache = ReplayCache::new(
            Duration::from_secs(10),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        let start = Instant::now();
        cache
            .check_and_insert_at("protected".to_owned(), start)
            .expect("first nonce");

        cache.configure_at(
            Duration::from_secs(30),
            NonZeroUsize::new(1).expect("non-zero"),
            start + Duration::from_secs(5),
        );

        assert_eq!(
            cache.check_and_insert_at("protected".to_owned(), start + Duration::from_secs(10)),
            Err(InsertError::Replay),
            "the old deadline must not discard evidence after widening"
        );
        assert_eq!(
            cache.check_and_insert_at("protected".to_owned(), start + Duration::from_secs(29)),
            Err(InsertError::Replay),
            "evidence must remain live until the widened deadline"
        );
        cache
            .check_and_insert_at("protected".to_owned(), start + Duration::from_secs(31))
            .expect("the nonce may be admitted again after the widened deadline");
    }

    #[test]
    fn widening_ttl_quarantines_unknown_nonces_until_pruned_history_is_stale() {
        let cache = ReplayCache::new(
            Duration::from_secs(10),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        let start = Instant::now();
        cache
            .check_and_insert_at("already-pruned".to_owned(), start)
            .expect("first nonce");
        {
            let mut inner = cache
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.prune_expired(start + Duration::from_secs(11));
            assert!(inner.entries.is_empty());
        }

        cache.configure_at(
            Duration::from_secs(30),
            NonZeroUsize::new(1).expect("non-zero"),
            start + Duration::from_secs(11),
        );

        assert_eq!(
            cache.check_and_insert_at("already-pruned".to_owned(), start + Duration::from_secs(12)),
            Err(InsertError::Capacity),
            "widening must fail closed while pruned history could become fresh again"
        );
        assert_eq!(
            cache.check_and_insert_at("new".to_owned(), start + Duration::from_secs(30)),
            Err(InsertError::Capacity),
            "the widening quarantine applies to every unknown nonce"
        );
        cache
            .check_and_insert_at("new".to_owned(), start + Duration::from_secs(32))
            .expect("admission resumes after the TTL-delta quarantine");
    }

    #[test]
    fn shrinking_ttl_does_not_shorten_live_evidence() {
        let cache = ReplayCache::new(
            Duration::from_secs(30),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        let start = Instant::now();
        cache
            .check_and_insert_at("protected".to_owned(), start)
            .expect("first nonce");

        cache.configure_at(
            Duration::from_secs(10),
            NonZeroUsize::new(1).expect("non-zero"),
            start + Duration::from_secs(5),
        );

        assert_eq!(
            cache.check_and_insert_at("protected".to_owned(), start + Duration::from_secs(29)),
            Err(InsertError::Replay),
            "shrinking the TTL must not shorten existing evidence"
        );
    }

    #[test]
    fn in_flight_snapshot_ttl_survives_concurrent_shrink() {
        let cache = ReplayCache::new(
            Duration::from_secs(30),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        let start = Instant::now();
        let verifier_snapshot_ttl = Duration::from_secs(30);

        cache.configure_at(
            Duration::from_secs(10),
            NonZeroUsize::new(1).expect("non-zero"),
            start,
        );
        let key = Hash::new(b"in-flight-before-shrink");
        cache
            .check_and_insert_digest_at_with_minimum_ttl(
                key,
                start + Duration::from_secs(1),
                verifier_snapshot_ttl,
            )
            .expect("in-flight verifier retains its snapshotted lifetime");

        assert_eq!(
            cache.check_and_insert_digest_at(key, start + Duration::from_secs(30)),
            Err(InsertError::Replay),
            "the new shorter cache TTL must not truncate in-flight evidence"
        );
        cache
            .check_and_insert_digest_at(key, start + Duration::from_secs(32))
            .expect("evidence expires after the snapshotted lifetime");
    }

    #[test]
    fn retained_replay_keys_are_fixed_size_digests() {
        let cache = ReplayCache::new(
            Duration::from_secs(300),
            NonZeroUsize::new(1).expect("non-zero"),
        );
        cache
            .check_and_insert("x".repeat(1024 * 1024))
            .expect("large transient key should hash into one cache slot");
        let inner = cache
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retained_key = inner.entries.keys().next().expect("one retained digest");
        assert_eq!(std::mem::size_of_val(retained_key), Hash::LENGTH);
        let Reverse((_expires_at, queued_key)) = inner
            .expirations
            .peek()
            .expect("one retained expiration digest");
        assert_eq!(std::mem::size_of_val(queued_key), Hash::LENGTH);
    }
    #[test]
    fn structured_digest_admission_preserves_one_shot_semantics() {
        let cache = ReplayCache::new(
            Duration::from_secs(300),
            NonZeroUsize::new(2).expect("non-zero"),
        );
        let first = Hash::new(b"structured-a");
        let second = Hash::new(b"structured-b");
        cache
            .check_and_insert_digest(first.clone())
            .expect("first structured digest");
        assert_eq!(
            cache.check_and_insert_digest(first),
            Err(InsertError::Replay)
        );
        cache
            .check_and_insert_digest(second)
            .expect("a distinct structured digest uses the second slot");
    }
}
