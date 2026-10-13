//! Per-token request and byte-rate quota tracking for SoraFS stream tokens.
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
const QUOTA_WINDOW: Duration = Duration::from_mins(1);
const BYTE_RATE_WINDOW: Duration = Duration::from_secs(1);
const DEFAULT_MAX_TRACKED_TOKENS: usize = 65_536;
const TOKEN_ID_HEX_LEN: usize = 32;
/// Tracks the number of requests served under each stream token.
///
/// State is deliberately bounded. Active entries are never evicted merely to
/// admit another token because doing so would reset their security budget.
#[derive(Clone)]
pub struct StreamTokenQuotaTracker {
    inner: Arc<StreamTokenQuotaInner>,
}
impl Default for StreamTokenQuotaTracker {
    fn default() -> Self {
        Self::with_max_entries(DEFAULT_MAX_TRACKED_TOKENS)
    }
}
impl StreamTokenQuotaTracker {
    fn with_max_entries(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(StreamTokenQuotaInner {
                max_entries,
                max_seen_epoch: AtomicU64::new(0),
                windows: Mutex::new(BTreeMap::new()),
            }),
        }
    }
    /// Attempt to reserve one request and its bytes within the signed token's windows.
    ///
    /// `token_fingerprint` must be the canonical hash of the complete signed
    /// token body. Binding the accounting entry to it prevents two distinct
    /// policies with a colliding token identifier from resetting one another.
    ///
    /// # Errors
    ///
    /// Returns [`StreamTokenQuotaError`] when the token policy is invalid, the
    /// request/byte quota or state capacity is exhausted, or accounting state is unavailable.
    #[allow(clippy::too_many_arguments)]
    pub fn try_acquire(
        &self,
        token_id: &str,
        token_fingerprint: [u8; 32],
        requests_per_minute: u32,
        rate_limit_bytes: u64,
        requested_bytes: u64,
        expires_at_epoch: u64,
        now_epoch: u64,
    ) -> Result<(), StreamTokenQuotaError> {
        self.inner.try_acquire(
            token_id,
            token_fingerprint,
            requests_per_minute,
            rate_limit_bytes,
            requested_bytes,
            expires_at_epoch,
            Instant::now(),
            now_epoch,
        )
    }
    #[cfg(test)]
    fn with_capacity_for_tests(max_entries: usize) -> Self {
        Self::with_max_entries(max_entries)
    }
    #[cfg(test)]
    fn try_acquire_at(
        &self,
        token_id: &str,
        token_fingerprint: [u8; 32],
        requests_per_minute: u32,
        expires_at_epoch: u64,
        now: Instant,
        now_epoch: u64,
    ) -> Result<(), StreamTokenQuotaError> {
        self.inner.try_acquire(
            token_id,
            token_fingerprint,
            requests_per_minute,
            u64::MAX,
            0,
            expires_at_epoch,
            now,
            now_epoch,
        )
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn try_acquire_bytes_at(
        &self,
        token_id: &str,
        token_fingerprint: [u8; 32],
        requests_per_minute: u32,
        rate_limit_bytes: u64,
        requested_bytes: u64,
        expires_at_epoch: u64,
        now: Instant,
        now_epoch: u64,
    ) -> Result<(), StreamTokenQuotaError> {
        self.inner.try_acquire(
            token_id,
            token_fingerprint,
            requests_per_minute,
            rate_limit_bytes,
            requested_bytes,
            expires_at_epoch,
            now,
            now_epoch,
        )
    }
}
struct StreamTokenQuotaInner {
    max_entries: usize,
    max_seen_epoch: AtomicU64,
    windows: Mutex<BTreeMap<String, TokenQuotaWindow>>,
}
impl StreamTokenQuotaInner {
    #[allow(clippy::too_many_arguments)]
    fn try_acquire(
        &self,
        token_id: &str,
        token_fingerprint: [u8; 32],
        requests_per_minute: u32,
        rate_limit_bytes: u64,
        requested_bytes: u64,
        expires_at_epoch: u64,
        now: Instant,
        now_epoch: u64,
    ) -> Result<(), StreamTokenQuotaError> {
        validate_token_id(token_id)?;
        if requests_per_minute == 0 {
            return Err(StreamTokenQuotaError::InvalidPolicy(
                "requests_per_minute must be greater than zero",
            ));
        }
        if rate_limit_bytes == 0 {
            return Err(StreamTokenQuotaError::InvalidPolicy(
                "rate_limit_bytes must be greater than zero",
            ));
        }
        let previous_epoch = self.max_seen_epoch.fetch_max(now_epoch, Ordering::SeqCst);
        if now_epoch < previous_epoch {
            return Err(StreamTokenQuotaError::ClockRollback {
                observed_epoch: previous_epoch,
                current_epoch: now_epoch,
            });
        }
        if expires_at_epoch <= now_epoch {
            return Err(StreamTokenQuotaError::Expired);
        }
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| StreamTokenQuotaError::StateUnavailable)?;
        windows.retain(|_, window| {
            window.expires_at_epoch > now_epoch
                && now.saturating_duration_since(window.last_seen) < QUOTA_WINDOW
        });
        if let Some(window) = windows.get_mut(token_id) {
            if window.token_fingerprint != token_fingerprint
                || window.limit != requests_per_minute
                || window.rate_limit_bytes != rate_limit_bytes
                || window.expires_at_epoch != expires_at_epoch
            {
                return Err(StreamTokenQuotaError::PolicyConflict);
            }
            return window.consume(now, requested_bytes);
        }
        if requested_bytes > rate_limit_bytes {
            return Err(StreamTokenQuotaError::ByteRateExceeded {
                retry_after_secs: 1,
            });
        }
        if windows.len() >= self.max_entries {
            return Err(StreamTokenQuotaError::CapacityExceeded {
                capacity: self.max_entries,
            });
        }
        windows.insert(
            token_id.to_owned(),
            TokenQuotaWindow::new(
                token_fingerprint,
                requests_per_minute,
                rate_limit_bytes,
                requested_bytes,
                expires_at_epoch,
                now,
            ),
        );
        Ok(())
    }
}
fn validate_token_id(token_id: &str) -> Result<(), StreamTokenQuotaError> {
    if token_id.len() != TOKEN_ID_HEX_LEN
        || !token_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StreamTokenQuotaError::InvalidTokenId);
    }
    Ok(())
}
#[derive(Debug, Clone)]
struct TokenQuotaWindow {
    token_fingerprint: [u8; 32],
    started_at: Instant,
    last_seen: Instant,
    bytes_started_at: Instant,
    expires_at_epoch: u64,
    limit: u32,
    used: u32,
    rate_limit_bytes: u64,
    bytes_used: u64,
}
impl TokenQuotaWindow {
    #[allow(clippy::too_many_arguments)]
    fn new(
        token_fingerprint: [u8; 32],
        limit: u32,
        rate_limit_bytes: u64,
        requested_bytes: u64,
        expires_at_epoch: u64,
        now: Instant,
    ) -> Self {
        Self {
            token_fingerprint,
            started_at: now,
            last_seen: now,
            bytes_started_at: now,
            expires_at_epoch,
            limit,
            used: 1,
            rate_limit_bytes,
            bytes_used: requested_bytes,
        }
    }
    fn consume(&mut self, now: Instant, requested_bytes: u64) -> Result<(), StreamTokenQuotaError> {
        let elapsed = now.saturating_duration_since(self.started_at);
        if elapsed >= QUOTA_WINDOW {
            self.started_at = now;
            self.used = 0;
        }
        if self.used >= self.limit {
            let remaining = QUOTA_WINDOW.saturating_sub(elapsed.min(QUOTA_WINDOW));
            let rounded_up = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .clamp(1, u64::from(u32::MAX));
            return Err(StreamTokenQuotaError::Exceeded {
                retry_after_secs: rounded_up as u32,
            });
        }
        let byte_elapsed = now.saturating_duration_since(self.bytes_started_at);
        if byte_elapsed >= BYTE_RATE_WINDOW {
            self.bytes_started_at = now;
            self.bytes_used = 0;
        }
        let next_bytes = self.bytes_used.checked_add(requested_bytes).ok_or(
            StreamTokenQuotaError::InvalidPolicy("byte-rate accounting overflow"),
        )?;
        if next_bytes > self.rate_limit_bytes {
            let remaining = BYTE_RATE_WINDOW.saturating_sub(byte_elapsed.min(BYTE_RATE_WINDOW));
            let retry_after_secs = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .clamp(1, u64::from(u32::MAX)) as u32;
            return Err(StreamTokenQuotaError::ByteRateExceeded { retry_after_secs });
        }
        self.used += 1;
        self.bytes_used = next_bytes;
        self.last_seen = now;
        Ok(())
    }
}
/// Error returned when stream-token quota admission fails.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum StreamTokenQuotaError {
    /// The token exhausted its request allowance for the active window.
    #[error("stream token request quota exceeded")]
    Exceeded {
        /// Seconds until the quota window resets.
        retry_after_secs: u32,
    },
    /// The token exhausted its aggregate byte allowance for the active second.
    #[error("stream token byte-rate quota exceeded")]
    ByteRateExceeded {
        /// Seconds until the byte-rate window resets.
        retry_after_secs: u32,
    },
    /// The bounded tracker is full of still-active token entries.
    #[error("stream token quota tracker capacity exhausted ({capacity} active tokens)")]
    CapacityExceeded {
        /// Maximum number of token entries retained by this process.
        capacity: usize,
    },
    /// The same token identifier was observed with a different signed policy.
    #[error("stream token identifier collides with a different signed policy")]
    PolicyConflict,
    /// The caller supplied a structurally invalid token identifier.
    #[error("stream token identifier must be exactly 32 lowercase hexadecimal characters")]
    InvalidTokenId,
    /// A zero or otherwise unsafe quota policy was supplied.
    #[error("invalid stream token quota policy: {0}")]
    InvalidPolicy(&'static str),
    /// The token is already expired at the accounting boundary.
    #[error("stream token has expired")]
    Expired,
    /// The accounting lock was poisoned; admission fails closed.
    #[error("stream token quota state is unavailable")]
    StateUnavailable,
    /// The wall clock moved backwards after a later request had been observed.
    #[error("stream token quota clock moved backwards from {observed_epoch} to {current_epoch}")]
    ClockRollback {
        /// Greatest epoch previously observed by this tracker.
        observed_epoch: u64,
        /// Epoch supplied for the current admission attempt.
        current_epoch: u64,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Barrier, thread};
    const TOKEN_A: &str = "0000000000000000000000000000000a";
    const TOKEN_B: &str = "0000000000000000000000000000000b";
    const TOKEN_C: &str = "0000000000000000000000000000000c";
    const START_EPOCH: u64 = 1_700_000_000;
    #[test]
    fn quota_allows_within_limit() {
        let tracker = StreamTokenQuotaTracker::default();
        let start = Instant::now();
        for second in 0..3 {
            tracker
                .try_acquire_at(
                    TOKEN_A,
                    [1; 32],
                    3,
                    START_EPOCH + 300,
                    start + Duration::from_secs(second),
                    START_EPOCH + second,
                )
                .expect("request within quota allowed");
        }
        let err = tracker
            .try_acquire_at(
                TOKEN_A,
                [1; 32],
                3,
                START_EPOCH + 300,
                start + Duration::from_secs(3),
                START_EPOCH + 3,
            )
            .expect_err("fourth request should exceed quota");
        assert!(matches!(
            err,
            StreamTokenQuotaError::Exceeded {
                retry_after_secs: 57
            }
        ));
    }
    #[test]
    fn quota_resets_after_window() {
        let tracker = StreamTokenQuotaTracker::default();
        let start = Instant::now();
        tracker
            .try_acquire_at(TOKEN_A, [1; 32], 1, START_EPOCH + 300, start, START_EPOCH)
            .expect("first request allowed");
        tracker
            .try_acquire_at(
                TOKEN_A,
                [1; 32],
                1,
                START_EPOCH + 300,
                start + Duration::from_secs(65),
                START_EPOCH + 65,
            )
            .expect("quota resets after window elapses");
    }
    #[test]
    fn zero_quota_fails_closed_without_retaining_state() {
        let tracker = StreamTokenQuotaTracker::with_capacity_for_tests(1);
        let err = tracker
            .try_acquire_at(
                TOKEN_A,
                [1; 32],
                0,
                START_EPOCH + 300,
                Instant::now(),
                START_EPOCH,
            )
            .expect_err("zero quota must not mean unlimited");
        assert!(matches!(err, StreamTokenQuotaError::InvalidPolicy(_)));
    }
    #[test]
    fn active_entries_are_not_evicted_at_capacity() {
        let tracker = StreamTokenQuotaTracker::with_capacity_for_tests(2);
        let start = Instant::now();
        for (token, fingerprint) in [(TOKEN_A, [1; 32]), (TOKEN_B, [2; 32])] {
            tracker
                .try_acquire_at(token, fingerprint, 1, START_EPOCH + 300, start, START_EPOCH)
                .expect("entry admitted");
        }
        let err = tracker
            .try_acquire_at(TOKEN_C, [3; 32], 1, START_EPOCH + 300, start, START_EPOCH)
            .expect_err("active state capacity must fail closed");
        assert_eq!(err, StreamTokenQuotaError::CapacityExceeded { capacity: 2 });
        let err = tracker
            .try_acquire_at(TOKEN_A, [1; 32], 1, START_EPOCH + 300, start, START_EPOCH)
            .expect_err("the original budget must remain enforced");
        assert!(matches!(err, StreamTokenQuotaError::Exceeded { .. }));
    }
    #[test]
    fn expired_entries_are_pruned_before_capacity_check() {
        let tracker = StreamTokenQuotaTracker::with_capacity_for_tests(1);
        let start = Instant::now();
        tracker
            .try_acquire_at(TOKEN_A, [1; 32], 2, START_EPOCH + 1, start, START_EPOCH)
            .expect("entry admitted");
        tracker
            .try_acquire_at(
                TOKEN_B,
                [2; 32],
                2,
                START_EPOCH + 300,
                start + Duration::from_secs(2),
                START_EPOCH + 2,
            )
            .expect("expired entry pruned");
    }
    #[test]
    fn colliding_identifier_cannot_reset_policy() {
        let tracker = StreamTokenQuotaTracker::default();
        let start = Instant::now();
        tracker
            .try_acquire_at(TOKEN_A, [1; 32], 2, START_EPOCH + 300, start, START_EPOCH)
            .expect("entry admitted");
        let err = tracker
            .try_acquire_at(TOKEN_A, [2; 32], 100, START_EPOCH + 600, start, START_EPOCH)
            .expect_err("colliding policy rejected");
        assert_eq!(err, StreamTokenQuotaError::PolicyConflict);
    }
    #[test]
    fn malformed_and_expired_tokens_fail_before_state_admission() {
        let tracker = StreamTokenQuotaTracker::with_capacity_for_tests(1);
        let start = Instant::now();
        assert_eq!(
            tracker
                .try_acquire_at("TOKEN", [1; 32], 1, START_EPOCH + 1, start, START_EPOCH,)
                .expect_err("malformed id rejected"),
            StreamTokenQuotaError::InvalidTokenId
        );
        assert_eq!(
            tracker
                .try_acquire_at(TOKEN_A, [1; 32], 1, START_EPOCH, start, START_EPOCH,)
                .expect_err("expired token rejected"),
            StreamTokenQuotaError::Expired
        );
        tracker
            .try_acquire_at(TOKEN_B, [2; 32], 1, START_EPOCH + 60, start, START_EPOCH)
            .expect("invalid attempts did not consume capacity");
    }
    #[test]
    fn concurrent_admission_never_exceeds_limit() {
        const THREADS: usize = 64;
        const LIMIT: u32 = 17;
        let tracker = StreamTokenQuotaTracker::default();
        let barrier = Arc::new(Barrier::new(THREADS));
        let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut joins = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let tracker = tracker.clone();
            let barrier = Arc::clone(&barrier);
            let successes = Arc::clone(&successes);
            joins.push(thread::spawn(move || {
                barrier.wait();
                match tracker.try_acquire(
                    TOKEN_A,
                    [1; 32],
                    LIMIT,
                    u64::MAX,
                    0,
                    START_EPOCH + 300,
                    START_EPOCH,
                ) {
                    Ok(()) => {
                        successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(StreamTokenQuotaError::Exceeded { .. }) => {}
                    Err(other) => panic!("unexpected quota error: {other}"),
                }
            }));
        }
        for join in joins {
            join.join().expect("quota worker");
        }
        assert_eq!(
            successes.load(std::sync::atomic::Ordering::Relaxed),
            LIMIT as usize
        );
    }
    #[test]
    fn aggregate_byte_rate_is_enforced_and_resets_after_one_second() {
        let tracker = StreamTokenQuotaTracker::default();
        let start = Instant::now();
        tracker
            .try_acquire_bytes_at(
                TOKEN_A,
                [1; 32],
                10,
                10,
                6,
                START_EPOCH + 300,
                start,
                START_EPOCH,
            )
            .expect("first byte reservation fits");
        let error = tracker
            .try_acquire_bytes_at(
                TOKEN_A,
                [1; 32],
                10,
                10,
                5,
                START_EPOCH + 300,
                start + Duration::from_millis(100),
                START_EPOCH,
            )
            .expect_err("aggregate byte rate must be enforced");
        assert_eq!(
            error,
            StreamTokenQuotaError::ByteRateExceeded {
                retry_after_secs: 1
            }
        );
        tracker
            .try_acquire_bytes_at(
                TOKEN_A,
                [1; 32],
                10,
                10,
                5,
                START_EPOCH + 300,
                start + Duration::from_secs(1),
                START_EPOCH + 1,
            )
            .expect("byte window resets after one second");
    }
    #[test]
    fn poisoned_accounting_state_fails_closed() {
        let tracker = StreamTokenQuotaTracker::default();
        let poisoner = tracker.clone();
        let poison_task = thread::spawn(move || {
            let _guard = poisoner.inner.windows.lock().expect("quota lock");
            panic!("poison quota state");
        })
        .join();
        assert!(poison_task.is_err(), "poisoning worker must panic");
        assert_eq!(
            tracker
                .try_acquire(
                    TOKEN_A,
                    [1; 32],
                    1,
                    u64::MAX,
                    0,
                    START_EPOCH + 300,
                    START_EPOCH,
                )
                .expect_err("poisoned state must fail closed"),
            StreamTokenQuotaError::StateUnavailable
        );
    }
    #[test]
    fn wall_clock_rollback_fails_closed() {
        let tracker = StreamTokenQuotaTracker::default();
        tracker
            .try_acquire(
                TOKEN_A,
                [1; 32],
                2,
                u64::MAX,
                0,
                START_EPOCH + 300,
                START_EPOCH + 10,
            )
            .expect("initial epoch admitted");
        assert_eq!(
            tracker
                .try_acquire(
                    TOKEN_A,
                    [1; 32],
                    2,
                    u64::MAX,
                    0,
                    START_EPOCH + 300,
                    START_EPOCH + 9,
                )
                .expect_err("clock rollback rejected"),
            StreamTokenQuotaError::ClockRollback {
                observed_epoch: START_EPOCH + 10,
                current_epoch: START_EPOCH + 9,
            }
        );
    }
}
