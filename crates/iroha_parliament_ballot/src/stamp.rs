//! The admission-stamp nonce search (integration decision 4).
//!
//! ```text
//! payload_digest = H(Frame("PARL/STAMP-PAYLOAD/v1"; Enc(authorization), Enc(context)))
//! work_digest    = H(Frame("PARL/STAMP-WORK/v1"; payload_digest, nonce))
//! ```
//!
//! A stamp is valid when `work_digest` has at least the frozen `stamp_difficulty_bits`
//! leading zero bits, counted most-significant bit first from byte zero. Both digests and
//! the check are the data model's ([`stamp_payload_digest_v1`], [`stamp_work_digest_v1`],
//! [`stamp_meets_difficulty_v1`], [`verify_stamp_v1`]); every verifier in this crate uses
//! them. This module only searches for a nonce: [`StampTargetV1`] absorbs the constant frame
//! prefix once and finishes the SHA3-512 sponge per candidate nonce, which yields exactly
//! [`stamp_work_digest_v1`] (the tests cross-check it).
//!
//! Candidate nonces are `start + offset` as 256-bit little-endian integers. The wallet starts
//! from a nonce drawn from the operating system ([`mine_stamp_v1`]); the sequential search
//! from a given start ([`StampTargetV1::mine_sequential`], [`mine_stamp_from_v1`]) is
//! deterministic, for fixtures and tests. Any nonce that reaches the difficulty is valid, so
//! the parallel search may return any of them.
//!
//! [`verify_stamp_v1`]: iroha_data_model::governance::anonymous_ballot::digests::verify_stamp_v1

use std::{
    num::NonZeroUsize,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
};

use iroha_data_model::governance::anonymous_ballot::{
    AdmissionNonceV1, AdmissionStampV1, AnonymousBallotAuthorizationV1,
    AnonymousBallotCodecErrorV1, AuthenticatedBallotContextV1, Digest512,
    digests::{
        STAMP_WORK_TAG_V1, leading_zero_bits_v1, stamp_meets_difficulty_v1, stamp_payload_digest_v1,
    },
    framing::frame_bytes,
};
use sha3::{Digest as _, Sha3_512};

use crate::entropy::{EntropySource, EntropyUnavailableV1, OsEntropy};

/// Candidates tried between two checks of the cancellation and stop flags.
const CHECK_INTERVAL: u64 = 256;

/// Why no stamp was produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StampErrorV1 {
    /// The caller requested cancellation before a nonce was found.
    #[error("the stamp search was cancelled")]
    Cancelled,
    /// The bounded or offset range was searched without success.
    #[error("no nonce among {attempts} candidates reaches the difficulty")]
    Exhausted {
        /// Candidates tried.
        attempts: u64,
    },
    /// The operating system's random source failed; no start nonce was drawn.
    #[error(transparent)]
    Entropy(#[from] EntropyUnavailableV1),
    /// A stamp digest could not be computed.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
    /// A search thread could not be created or panicked.
    #[error("a stamp search thread failed")]
    Worker,
}

/// A found stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinedStampV1 {
    /// The stamp.
    pub stamp: AdmissionStampV1,
    /// Leading zero bits of its work digest (at least the difficulty).
    pub work_bits: u32,
    /// Candidates tried by every search thread together.
    pub attempts: u64,
}

/// The nonce `start + offset`, as 256-bit little-endian integers, wrapping.
fn nonce_at(start: &AdmissionNonceV1, offset: u64) -> AdmissionNonceV1 {
    let addend = offset.to_le_bytes();
    let mut out = start.into_bytes();
    let mut carry = 0_u16;
    for (index, byte) in out.iter_mut().enumerate() {
        let add = addend.get(index).copied().map_or(0, u16::from);
        let sum = u16::from(*byte) + add + carry;
        *byte = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    AdmissionNonceV1::new(out)
}

/// The stamp target of one ballot: its payload digest and the frozen difficulty, with the
/// SHA3-512 state of the constant work-frame prefix.
#[derive(Clone)]
pub struct StampTargetV1 {
    payload_digest: Digest512,
    difficulty_bits: u8,
    prefix: Sha3_512,
}

impl core::fmt::Debug for StampTargetV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampTargetV1")
            .field("payload_digest", &self.payload_digest)
            .field("difficulty_bits", &self.difficulty_bits)
            .finish_non_exhaustive()
    }
}

/// Outcome shared by the search threads.
struct SharedSearch<'a> {
    cancel: &'a AtomicBool,
    stop: AtomicBool,
    found: Mutex<Option<(u64, AdmissionNonceV1, u32)>>,
    attempts: AtomicU64,
}

impl StampTargetV1 {
    /// The target of `payload_digest` at `difficulty_bits`.
    ///
    /// # Errors
    /// [`StampErrorV1::Codec`] if the frame cannot be built, which fixed-length fields
    /// never cause.
    pub fn new(payload_digest: Digest512, difficulty_bits: u8) -> Result<Self, StampErrorV1> {
        let zero = [0_u8; AdmissionNonceV1::LENGTH];
        let mut frame = frame_bytes(STAMP_WORK_TAG_V1, &[payload_digest.as_bytes(), &zero])?;
        // The nonce is the frame's last field: everything before it is constant.
        frame.truncate(frame.len() - AdmissionNonceV1::LENGTH);
        let mut prefix = Sha3_512::new();
        prefix.update(&frame);
        Ok(Self {
            payload_digest,
            difficulty_bits,
            prefix,
        })
    }

    /// The target of a ballot: its authorization payload with the authenticated context of
    /// its scope, at the context's frozen difficulty.
    ///
    /// # Errors
    /// [`StampErrorV1::Codec`] if an `Enc` cannot be produced.
    pub fn for_ballot(
        authorization: &AnonymousBallotAuthorizationV1,
        context: &AuthenticatedBallotContextV1,
    ) -> Result<Self, StampErrorV1> {
        Self::new(
            stamp_payload_digest_v1(authorization, context)?,
            context.policy.stamp_difficulty_bits,
        )
    }

    /// The payload digest.
    pub fn payload_digest(&self) -> &Digest512 {
        &self.payload_digest
    }

    /// Leading zero bits a stamp needs.
    pub fn difficulty_bits(&self) -> u8 {
        self.difficulty_bits
    }

    /// `work_digest` of `nonce`, equal to the data model's `stamp_work_digest_v1`.
    pub fn work_digest(&self, nonce: &AdmissionNonceV1) -> Digest512 {
        let mut sponge = self.prefix.clone();
        sponge.update(nonce.as_bytes());
        Digest512::new(sponge.finalize().into())
    }

    /// Leading zero bits of `nonce`'s work digest: the ingress priority of its stamp.
    pub fn work_bits(&self, nonce: &AdmissionNonceV1) -> u32 {
        leading_zero_bits_v1(&self.work_digest(nonce))
    }

    /// Whether `nonce` reaches the difficulty.
    pub fn accepts(&self, nonce: &AdmissionNonceV1) -> bool {
        stamp_meets_difficulty_v1(&self.work_digest(nonce), self.difficulty_bits)
    }

    /// Try `start, start + 1, ...` in order, at most `max_attempts` candidates, and return
    /// the first that reaches the difficulty. Deterministic.
    ///
    /// # Errors
    /// [`StampErrorV1::Exhausted`] if none of them does.
    pub fn mine_sequential(
        &self,
        start: AdmissionNonceV1,
        max_attempts: u64,
    ) -> Result<MinedStampV1, StampErrorV1> {
        for offset in 0..max_attempts {
            let nonce = nonce_at(&start, offset);
            let work = self.work_digest(&nonce);
            if stamp_meets_difficulty_v1(&work, self.difficulty_bits) {
                return Ok(MinedStampV1 {
                    stamp: AdmissionStampV1 { nonce },
                    work_bits: leading_zero_bits_v1(&work),
                    attempts: offset + 1,
                });
            }
        }
        Err(StampErrorV1::Exhausted {
            attempts: max_attempts,
        })
    }

    /// Search with `threads` scoped threads from `start`: thread `t` tries the offsets
    /// `t, t + threads, t + 2·threads, ...`. Every thread checks `cancel` (and whether
    /// another thread succeeded) every few hundred candidates; cancellation is cooperative
    /// and the call returns only after every thread has stopped.
    ///
    /// # Errors
    /// [`StampErrorV1::Cancelled`] if `cancel` was set before a nonce was found,
    /// [`StampErrorV1::Worker`] if a thread could not run, and
    /// [`StampErrorV1::Exhausted`] after `2^64` offsets.
    pub fn mine_parallel(
        &self,
        start: AdmissionNonceV1,
        threads: NonZeroUsize,
        cancel: &AtomicBool,
    ) -> Result<MinedStampV1, StampErrorV1> {
        let lanes = u64::try_from(threads.get()).unwrap_or(u64::MAX);
        let shared = SharedSearch {
            cancel,
            stop: AtomicBool::new(false),
            found: Mutex::new(None),
            attempts: AtomicU64::new(0),
        };
        let worker_failed = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(threads.get());
            let mut failed = false;
            for lane in 0..lanes {
                let shared = &shared;
                let spawned = thread::Builder::new()
                    .name("parliament-stamp".into())
                    .spawn_scoped(scope, move || self.search_lane(start, lane, lanes, shared));
                match spawned {
                    Ok(handle) => handles.push(handle),
                    Err(_) => {
                        failed = true;
                        shared.stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
            for handle in handles {
                failed |= handle.join().is_err();
            }
            failed
        });
        let attempts = shared.attempts.load(Ordering::Relaxed);
        let found = shared
            .found
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        match found {
            Some((_, nonce, work_bits)) => Ok(MinedStampV1 {
                stamp: AdmissionStampV1 { nonce },
                work_bits,
                attempts,
            }),
            None if worker_failed => Err(StampErrorV1::Worker),
            None if cancel.load(Ordering::Relaxed) => Err(StampErrorV1::Cancelled),
            None => Err(StampErrorV1::Exhausted { attempts }),
        }
    }

    /// One search lane: offsets `lane, lane + stride, ...` until success, a stop or the end
    /// of the offset range.
    fn search_lane(
        &self,
        start: AdmissionNonceV1,
        lane: u64,
        stride: u64,
        shared: &SharedSearch<'_>,
    ) {
        let mut offset = lane;
        let mut tried = 0_u64;
        loop {
            if tried.is_multiple_of(CHECK_INTERVAL)
                && (shared.cancel.load(Ordering::Relaxed) || shared.stop.load(Ordering::Relaxed))
            {
                break;
            }
            let nonce = nonce_at(&start, offset);
            let work = self.work_digest(&nonce);
            tried += 1;
            if stamp_meets_difficulty_v1(&work, self.difficulty_bits) {
                let mut found = shared.found.lock().unwrap_or_else(PoisonError::into_inner);
                // Of several lanes that succeed before stopping, keep the smallest offset.
                if found.is_none_or(|(best, _, _)| offset < best) {
                    *found = Some((offset, nonce, leading_zero_bits_v1(&work)));
                }
                shared.stop.store(true, Ordering::Relaxed);
                break;
            }
            match offset.checked_add(stride) {
                Some(next) => offset = next,
                None => break,
            }
        }
        shared.attempts.fetch_add(tried, Ordering::Relaxed);
    }
}

/// Mine the stamp of a ballot at its context's frozen difficulty, from a start nonce drawn
/// from the operating system, with `threads` search threads.
///
/// # Errors
/// [`StampErrorV1::Entropy`] if no start nonce could be drawn, and as
/// [`StampTargetV1::for_ballot`] and [`StampTargetV1::mine_parallel`].
pub fn mine_stamp_v1(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &AuthenticatedBallotContextV1,
    threads: NonZeroUsize,
    cancel: &AtomicBool,
) -> Result<MinedStampV1, StampErrorV1> {
    mine_stamp_with(authorization, context, threads, cancel, &mut OsEntropy)
}

/// [`mine_stamp_v1`] with the start nonce drawn from `entropy`.
pub(crate) fn mine_stamp_with<E: EntropySource>(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &AuthenticatedBallotContextV1,
    threads: NonZeroUsize,
    cancel: &AtomicBool,
    entropy: &mut E,
) -> Result<MinedStampV1, StampErrorV1> {
    let target = StampTargetV1::for_ballot(authorization, context)?;
    let mut start = [0_u8; AdmissionNonceV1::LENGTH];
    entropy.fill(&mut start)?;
    target.mine_parallel(AdmissionNonceV1::new(start), threads, cancel)
}

/// Mine the stamp of a ballot sequentially from `start`, trying at most `max_attempts`
/// candidates. Deterministic: for fixtures and tests.
///
/// # Errors
/// As [`StampTargetV1::for_ballot`] and [`StampTargetV1::mine_sequential`].
pub fn mine_stamp_from_v1(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &AuthenticatedBallotContextV1,
    start: AdmissionNonceV1,
    max_attempts: u64,
) -> Result<MinedStampV1, StampErrorV1> {
    StampTargetV1::for_ballot(authorization, context)?.mine_sequential(start, max_attempts)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroha_data_model::governance::anonymous_ballot::digests::{
        stamp_work_digest_v1, verify_stamp_v1,
    };

    use super::*;
    use crate::{
        entropy::ScriptedEntropy,
        test_support::{AYE_0, FIXTURE_BALLOTS, fixture_authorization, scoped_context},
    };

    fn threads(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("nonzero")
    }

    #[test]
    fn nonces_are_little_endian_offsets_that_wrap() {
        let start = AdmissionNonceV1::new([0; 32]);
        assert_eq!(nonce_at(&start, 0), start);
        let mut expected = [0_u8; 32];
        expected[..8].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(
            nonce_at(&start, 0x0102_0304_0506_0708),
            AdmissionNonceV1::new(expected)
        );
        // A carry runs through every byte and wraps at 2^256.
        assert_eq!(
            nonce_at(&AdmissionNonceV1::new([0xff; 32]), 1),
            AdmissionNonceV1::new([0; 32])
        );
        let mut carried = [0xff_u8; 32];
        carried[31] = 0x00;
        let mut result = [0_u8; 32];
        result[31] = 0x01;
        assert_eq!(
            nonce_at(&AdmissionNonceV1::new(carried), 1),
            AdmissionNonceV1::new(result)
        );
    }

    #[test]
    fn the_midstate_work_digest_is_the_data_model_digest() {
        let payload = Digest512::new([0x3c; 64]);
        let target = StampTargetV1::new(payload, 28).expect("target");
        assert_eq!(target.payload_digest(), &payload);
        assert_eq!(target.difficulty_bits(), 28);
        for byte in [0_u8, 1, 0x7f, 0xff] {
            let nonce = AdmissionNonceV1::new([byte; 32]);
            assert_eq!(
                target.work_digest(&nonce),
                stamp_work_digest_v1(&payload, &nonce).expect("work")
            );
            assert_eq!(
                target.work_bits(&nonce),
                leading_zero_bits_v1(&stamp_work_digest_v1(&payload, &nonce).expect("work"))
            );
        }
        assert!(format!("{target:?}").contains("difficulty_bits"));
    }

    #[test]
    fn the_sequential_search_is_deterministic_and_verifies_with_the_data_model() {
        let context = scoped_context();
        let authorization = fixture_authorization(AYE_0);
        // At a low test difficulty: the context's policy would refuse it, which is why the
        // data model's check is applied to a copy whose frozen difficulty is lowered.
        let mut easy = context.context().clone();
        easy.policy.stamp_difficulty_bits = 10;
        let start = AdmissionNonceV1::new([0x42; 32]);
        let mined = mine_stamp_from_v1(&authorization, &easy, start, 1 << 20).expect("mined");
        assert_eq!(
            mine_stamp_from_v1(&authorization, &easy, start, 1 << 20),
            Ok(mined)
        );
        assert!(mined.work_bits >= 10);
        assert!(verify_stamp_v1(&authorization, &easy, &mined.stamp.nonce).expect("stamp"));
        assert_eq!(mined.stamp.nonce, nonce_at(&start, mined.attempts - 1));
        // Every earlier candidate fails.
        let target = StampTargetV1::for_ballot(&authorization, &easy).expect("target");
        for offset in 0..mined.attempts - 1 {
            assert!(!target.accepts(&nonce_at(&start, offset)));
        }
        assert_eq!(
            target.mine_sequential(start, mined.attempts - 1),
            Err(StampErrorV1::Exhausted {
                attempts: mined.attempts - 1
            })
        );
    }

    #[test]
    fn the_parallel_search_finds_a_valid_nonce_and_counts_attempts() {
        let target = StampTargetV1::new(Digest512::new([0x5d; 64]), 12).expect("target");
        let cancel = AtomicBool::new(false);
        let mined = target
            .mine_parallel(AdmissionNonceV1::new([7; 32]), threads(4), &cancel)
            .expect("mined");
        assert!(target.accepts(&mined.stamp.nonce));
        assert!(mined.work_bits >= 12);
        assert!(mined.attempts >= 1);
        // One thread from the same start returns the sequential result.
        let sequential = target
            .mine_sequential(AdmissionNonceV1::new([7; 32]), u64::MAX)
            .expect("mined");
        let single = target
            .mine_parallel(AdmissionNonceV1::new([7; 32]), threads(1), &cancel)
            .expect("mined");
        assert_eq!(single, sequential);
        // A valid start nonce is found by lane zero first.
        let first = target
            .mine_parallel(sequential.stamp.nonce, threads(1), &cancel)
            .expect("mined");
        assert_eq!(first.stamp, sequential.stamp);
        assert_eq!(first.attempts, 1);
    }

    #[test]
    fn cancellation_stops_every_thread() {
        // A 255-bit difficulty is never reached in practice, so only cancellation ends the
        // search.
        let target = StampTargetV1::new(Digest512::new([1; 64]), u8::MAX).expect("target");
        let cancel = AtomicBool::new(true);
        assert_eq!(
            target.mine_parallel(AdmissionNonceV1::new([0; 32]), threads(3), &cancel),
            Err(StampErrorV1::Cancelled)
        );
        let cancel = AtomicBool::new(false);
        let result = thread::scope(|scope| {
            let search = scope.spawn(|| {
                target.mine_parallel(AdmissionNonceV1::new([0; 32]), threads(2), &cancel)
            });
            thread::sleep(Duration::from_millis(50));
            cancel.store(true, Ordering::Relaxed);
            search.join().expect("search thread")
        });
        assert_eq!(result, Err(StampErrorV1::Cancelled));
    }

    #[test]
    fn the_wallet_start_nonce_comes_from_the_entropy_source() {
        let context = scoped_context();
        let authorization = fixture_authorization(AYE_0);
        let pinned = FIXTURE_BALLOTS[AYE_0].nonce;
        // Starting at the pinned nonce, lane zero finds it on its first candidate.
        let mut entropy = ScriptedEntropy::new([Some(pinned.to_vec())]);
        let mined = mine_stamp_with(
            &authorization,
            context.context(),
            threads(1),
            &AtomicBool::new(false),
            &mut entropy,
        )
        .expect("mined");
        assert_eq!(mined.stamp.nonce, AdmissionNonceV1::new(pinned));
        assert!(mined.work_bits >= 28);
        // An entropy failure draws nothing and searches nothing.
        let mut failing = ScriptedEntropy::new([None]);
        assert_eq!(
            mine_stamp_with(
                &authorization,
                context.context(),
                threads(1),
                &AtomicBool::new(false),
                &mut failing,
            ),
            Err(StampErrorV1::Entropy(EntropyUnavailableV1))
        );
        // The operating-system entry point runs too (cancelled before any candidate).
        assert_eq!(
            mine_stamp_v1(
                &authorization,
                context.context(),
                threads(1),
                &AtomicBool::new(true)
            ),
            Err(StampErrorV1::Cancelled)
        );
    }
}
