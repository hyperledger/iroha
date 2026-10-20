//! Genuine unsigned staging refuses authority escape and preserves cold recovery.
use super::*;
use crate::managed::stream_token_custody::{
    bootstrap_test_support::NativeEnrollmentReads,
    renewal_tests::{Fixture, wait_until},
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    BeforePrepare,
    Prepared,
    ActivationWritten,
    AnchorWritten,
}
type Hook = Box<dyn FnMut(Point, &BodyHistory, Option<&PublishedBodyDelta>) -> Result<()>>;
thread_local! {
    static ORIGINAL: Cell<bool> = const { Cell::new(false) };
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    static LATE_LIMITS: Cell<Option<norito::DecodeLimits>> = const { Cell::new(None) };
}
pub(super) fn original_recipe() -> bool {
    ORIGINAL.get()
}
pub(super) fn take_late_limits() -> Option<norito::DecodeLimits> {
    LATE_LIMITS.take()
}
pub(super) fn with_original_recipe<T>(read: impl FnOnce() -> T) -> T {
    observe(true, None, None, read)
}
fn observe<T>(
    original: bool,
    hook: Option<Hook>,
    limits: Option<norito::DecodeLimits>,
    read: impl FnOnce() -> T,
) -> T {
    struct Restore(bool, Option<Hook>, Option<norito::DecodeLimits>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ORIGINAL.set(self.0);
            HOOK.with(|state| state.replace(self.1.take()));
            LATE_LIMITS.set(self.2);
        }
    }
    let _restore = Restore(
        ORIGINAL.replace(original),
        HOOK.with(|state| state.replace(hook)),
        LATE_LIMITS.replace(limits),
    );
    read()
}
fn hit(
    point: Point,
    history: &BodyHistory,
    publication: Option<&PublishedBodyDelta>,
) -> Result<()> {
    HOOK.with(|hook| {
        hook.borrow_mut()
            .as_mut()
            .map_or(Ok(()), |hook| hook(point, history, publication))
    })
}
pub(super) fn before_prepare(
    history: &BodyHistory,
    publication: &PublishedBodyDelta,
) -> Result<()> {
    hit(Point::BeforePrepare, history, Some(publication))
}
pub(super) fn after_prepare(
    history: &BodyHistory,
    _owner: &ManagedStreamTokenCustody,
) -> Result<()> {
    hit(Point::Prepared, history, None)
}
pub(super) fn after_write(point: Point, history: &BodyHistory) -> Result<()> {
    hit(point, history, None)
}
fn fixture() -> Fixture {
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    fixture
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}
struct CountedReads<'a> {
    fixture: &'a Fixture,
    calls: Cell<usize>,
}
impl EnrollmentReads for CountedReads<'_> {
    fn historical(
        &self,
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        self.calls.set(self.calls.get() + 1);
        NativeEnrollmentReads(&self.fixture.native).historical(owner, policy, checkpoint, deadline)
    }
}
fn assert_unsigned_successor(history: &BodyHistory) {
    let body = history.bodies.last().unwrap();
    assert!(body.original.is_none());
    assert!(history.dispatch().is_err());
    assert!(!body.directory.path().join("original.nrt").exists());
    assert!(!body.directory.path().join("attempts").exists());
}

#[test]
fn exact_closed_staging_removes_one_full_admission_and_preserves_final_cold_state() {
    let _resources = crate::managed::native_test_guard();
    let mut observations = Vec::new();
    for original in [true, false] {
        let fixture = fixture();
        let first = publication_tests::advance(&fixture, None, true).unwrap();
        let prepared = Rc::new(Cell::new(0));
        let seen = Rc::clone(&prepared);
        let capture = finish_timing::Capture::start();
        let finished = observe(
            original,
            Some(Box::new(move |point, history, _| {
                if point == Point::Prepared {
                    seen.set(seen.get() + 1);
                    assert_unsigned_successor(history);
                    assert!(history.nearest_closure.is_some());
                }
                Ok(())
            })),
            None,
            || publication_tests::advance(&fixture, Some(first), false),
        )
        .unwrap();
        let timing = capture.finish();
        let cold = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
            .unwrap()
            .unwrap();
        publication_tests::same_state(&finished, &cold);
        assert_eq!(finished.bodies.len(), 2);
        assert_eq!(
            finished
                .current_history()
                .unwrap()
                .cumulative_reserved_count(),
            1
        );
        assert_eq!(fixture.native.chain.height(), 4);
        observations.push((timing, prepared.get()));
    }
    let (old, old_prepared) = &observations[0];
    let (new, new_prepared) = &observations[1];
    assert_eq!((*old_prepared, *new_prepared), (0, 1));
    assert_eq!(
        old.sample(finish_timing::Phase::VerifyHistories).0,
        new.sample(finish_timing::Phase::VerifyHistories).0 + 1
    );
    assert_eq!(
        old.sample(finish_timing::Phase::ParserWallet).0,
        new.sample(finish_timing::Phase::ParserWallet).0 + 2
    );
    assert_eq!(
        old.sample(finish_timing::Phase::HistoricalRead).0,
        new.sample(finish_timing::Phase::HistoricalRead).0
    );
    assert_eq!(new.sample(finish_timing::Phase::HistoricalRead).0, 1);
}

#[test]
fn activation_staging_crash_cuts_leave_only_unsigned_canonical_recovery_prefixes() {
    let _resources = crate::managed::native_test_guard();
    for cut in [
        Point::Prepared,
        Point::ActivationWritten,
        Point::AnchorWritten,
    ] {
        let fixture = fixture();
        let first = publication_tests::advance(&fixture, None, true).unwrap();
        let fired = Rc::new(Cell::new(false));
        let seen = Rc::clone(&fired);
        let reads = CountedReads {
            fixture: &fixture,
            calls: Cell::new(0),
        };
        let result = observe(
            false,
            Some(Box::new(move |point, history, _| {
                if point == cut && history.anchor.highest == 2 {
                    seen.set(true);
                    assert_unsigned_successor(history);
                    return Err(crate::managed::Error::NativeDeadline);
                }
                Ok(())
            })),
            None,
            || publication_tests::advance_with_reads(&fixture, Some(first), false, &reads),
        );
        assert!(fired.get(), "cut {cut:?}");
        assert!(matches!(result, Err(crate::managed::Error::NativeDeadline)));
        assert_eq!(reads.calls.get(), 0);
        let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
            .unwrap()
            .unwrap();
        assert_unsigned_successor(&recovered);
        assert_eq!(
            recovered.bodies[1].activation.is_some(),
            cut != Point::Prepared
        );
        assert_eq!(
            recovered.anchor.pending.is_none(),
            cut == Point::AnchorWritten
        );
        assert_eq!(
            recovered.anchor.completed.is_none(),
            cut == Point::AnchorWritten
        );
        assert!(recovered.nearest_closure.is_some());
        assert_eq!(
            recovered
                .nearest_closure
                .as_ref()
                .unwrap()
                .cumulative_reserved_count(),
            1
        );
        assert_eq!(fixture.native.chain.height(), 4);
    }
}

#[test]
fn staged_wallet_mutation_is_refused_by_c_and_cold_recovery_before_signing() {
    let _resources = crate::managed::native_test_guard();
    let fixture = fixture();
    let first = publication_tests::advance(&fixture, None, true).unwrap();
    let restore = Rc::new(RefCell::new(None::<(std::path::PathBuf, Vec<u8>)>));
    let saved = Rc::clone(&restore);
    let reads = CountedReads {
        fixture: &fixture,
        calls: Cell::new(0),
    };
    let result = observe(
        false,
        Some(Box::new(move |point, history, _| {
            if point == Point::Prepared {
                let wallet = history
                    .nearest_closure
                    .as_ref()
                    .unwrap()
                    .retained_history()
                    .test_oldest_retained_history()
                    .last()
                    .unwrap()
                    .wallet_path();
                let path = wallet.join("retired.json");
                let bytes = std::fs::read(&path)?;
                let mut changed = bytes.clone();
                changed[0] ^= 1;
                std::fs::write(&path, changed)?;
                *saved.borrow_mut() = Some((path, bytes));
            }
            Ok(())
        })),
        None,
        || publication_tests::advance_with_reads(&fixture, Some(first), false, &reads),
    );
    assert!(result.is_err());
    assert_eq!(
        reads.calls.get(),
        0,
        "C refuses before sign_retained historical lookup"
    );
    let (path, bytes) = restore
        .borrow_mut()
        .take()
        .expect("actual retired wallet mutated");
    // Read the exact head through the original authority path, without accepting a BodyHistory.
    let operation = PrivateDirectory::open(
        fixture
            .owner
            .authority
            .directory
            .path()
            .join(CustodyPurpose::Renewal(2).directory_name().unwrap()),
    )
    .unwrap();
    let anchor: Anchor = read(&operation, "anchor.nrt", MAX_BODY_BYTES).unwrap();
    assert_eq!(anchor.active, Some(2));
    assert!(anchor.pending.is_none() && anchor.completed.is_none());
    assert!(operation.path().join("bodies/0002-activation.nrt").exists());
    assert!(!operation.path().join("bodies/0002/original.nrt").exists());
    assert!(!operation.path().join("bodies/0002/attempts").exists());
    assert!(BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)).is_err());
    std::fs::write(path, bytes).unwrap();
    let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_unsigned_successor(&recovered);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn late_decoder_staging_falls_back_before_any_activation_write() {
    let _resources = crate::managed::native_test_guard();
    let fixture = fixture();
    let first = publication_tests::advance(&fixture, None, true).unwrap();
    let prepared = Rc::new(Cell::new(false));
    let seen = Rc::clone(&prepared);
    let reads = CountedReads {
        fixture: &fixture,
        calls: Cell::new(0),
    };
    let result = observe(
        false,
        Some(Box::new(move |point, _, _| {
            if point == Point::Prepared {
                seen.set(true);
            }
            Ok(())
        })),
        Some(limits(0)),
        || publication_tests::advance_with_reads(&fixture, Some(first), false, &reads),
    );
    assert!(prepared.get());
    assert!(result.is_err());
    assert_eq!(reads.calls.get(), 0);
    let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_unsigned_successor(&recovered);
    assert!(recovered.anchor.pending.is_some());
    assert!(recovered.bodies[1].activation.is_none());
    assert!(recovered.nearest_closure.is_some());
    assert!(!norito::core::decode_limits_active());
}

#[test]
fn unused_staging_binds_exact_successor_digest_and_rejects_foreign_or_bounded_owners() {
    let _resources = crate::managed::native_test_guard();
    let fixture = fixture();
    let initial = observe(
        false,
        Some(Box::new(|point, history, _| {
            if point == Point::AnchorWritten && history.anchor.highest == 1 {
                return Err(crate::managed::Error::NativeDeadline);
            }
            Ok(())
        })),
        None,
        || publication_tests::advance(&fixture, None, false),
    );
    assert!(initial.is_err());
    let unsigned = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_unsigned_successor(&unsigned);
    let seen = Rc::new(Cell::new(false));
    let capture = Rc::clone(&seen);
    let finished = observe(
        false,
        Some(Box::new(move |point, history, publication| {
            if point != Point::BeforePrepare {
                return Ok(());
            }
            let publication = publication.unwrap();
            let PublishedBodyDelta::Unused {
                root,
                ordinal,
                value,
                observed,
            } = publication
            else {
                panic!("genuine unsigned predecessor must publish Unused");
            };
            capture.set(true);
            let body_root = history.body_root.as_ref().unwrap();
            let next = history.anchor.pending.as_ref().unwrap().ordinal;
            let digest = attempts::semantic_digest(value, MAX_SELECTION_BYTES)?;
            assert!(ActivationStaging::eligible(history, body_root, publication));
            ActivationStaging::bind(history, next, digest, publication)?;
            assert!(ActivationStaging::bind(history, next - 1, digest, publication).is_err());
            let mut wrong = digest;
            wrong[0] ^= 1;
            assert!(ActivationStaging::bind(history, next, wrong, publication).is_err());
            let changed = UnusedClosure {
                reservation: value.reservation,
                successor: [0; 32],
            };
            let changed_digest = attempts::semantic_digest(&changed, MAX_SELECTION_BYTES)?;
            let changed = PublishedBodyDelta::Unused {
                root: Arc::clone(root),
                ordinal: *ordinal,
                value: changed,
                observed: observed.clone(),
            };
            assert!(ActivationStaging::bind(history, next, changed_digest, &changed).is_err());
            let reopened = Arc::new(PrivateDirectory::open(body_root.path())?);
            assert!(!ActivationStaging::eligible(
                history,
                &reopened,
                publication
            ));
            for allocation in [0, 1, usize::MAX] {
                norito::core::with_decode_limits_scope(limits(allocation), || {
                    assert!(!ActivationStaging::eligible(
                        history,
                        body_root,
                        publication
                    ));
                });
            }
            Ok(())
        })),
        None,
        || publication_tests::advance(&fixture, Some(unsigned), false),
    )
    .unwrap();
    assert!(seen.get());
    assert!(finished.bodies[0].original.is_none());
    assert!(finished.bodies[0].unused.is_some());
    assert!(finished.bodies[1].original.is_some());
    let cold = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    publication_tests::same_state(&finished, &cold);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
#[test]
fn stage_preapply_failure_closes_the_actual_new_closed_owner_before_returning() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let fixture = fixture();
    let first = publication_tests::advance(&fixture, None, true).unwrap();
    let restore = Rc::new(RefCell::new(None));
    let saved = Rc::clone(&restore);
    let reads = CountedReads {
        fixture: &fixture,
        calls: Cell::new(0),
    };
    let result = observe(
        false,
        Some(Box::new(move |point, history, publication| {
            if point == Point::BeforePrepare {
                assert!(history.active.is_none());
                assert!(
                    history.nearest_closure.is_none(),
                    "new closure still lives only in receipt"
                );
                let PublishedBodyDelta::Closed { closure, .. } = publication.unwrap() else {
                    panic!("genuine signed predecessor must publish Closed");
                };
                let directory = closure
                    .retained_history()
                    .test_oldest_retained_history()
                    .last()
                    .unwrap()
                    .directory();
                let path = directory.path().to_path_buf();
                let permissions = fs::metadata(&path)?.permissions();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                *saved.borrow_mut() = Some((path, permissions));
                return Err(crate::managed::Error::NativeDeadline);
            }
            Ok(())
        })),
        None,
        || publication_tests::advance_with_reads(&fixture, Some(first), false, &reads),
    );
    let (path, permissions) = restore
        .borrow_mut()
        .take()
        .expect("actual original attempt changed");
    fs::set_permissions(path, permissions).unwrap();
    assert!(result.is_err());
    assert!(
        !matches!(result, Err(crate::managed::Error::NativeDeadline)),
        "original custody exit must outrank ordinary inner deadline"
    );
    assert_eq!(reads.calls.get(), 0);
    let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_unsigned_successor(&recovered);
    assert!(recovered.bodies[1].activation.is_none());
    assert!(recovered.nearest_closure.is_some());
}

#[cfg(unix)]
#[test]
fn staged_c_failure_closes_the_original_unsigned_body_owner_before_returning() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let fixture = fixture();
    let first = publication_tests::advance(&fixture, None, true).unwrap();
    let restore = Rc::new(RefCell::new(None));
    let saved = Rc::clone(&restore);
    let reads = CountedReads {
        fixture: &fixture,
        calls: Cell::new(0),
    };
    let result = publication_tests::with_hook(
        move |point, history, _| {
            if point == publication_tests::Point::Before(PublicationStep::Activated)
                && history.anchor.highest == 2
            {
                // C has begun using the staged owner. The pending body has no History/attempt
                // graph yet, so only its retained original directory can close this refusal.
                assert_unsigned_successor(history);
                let path = history
                    .bodies
                    .last()
                    .unwrap()
                    .directory
                    .path()
                    .to_path_buf();
                let permissions = fs::metadata(&path)?.permissions();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                *saved.borrow_mut() = Some((path, permissions));
                return Err(crate::managed::Error::NativeDeadline);
            }
            Ok(())
        },
        || publication_tests::advance_with_reads(&fixture, Some(first), false, &reads),
    );
    let (path, permissions) = restore
        .borrow_mut()
        .take()
        .expect("actual unsigned C owner changed");
    fs::set_permissions(path, permissions).unwrap();
    assert!(result.is_err());
    assert!(
        !matches!(result, Err(crate::managed::Error::NativeDeadline)),
        "original unsigned custody exit must outrank ordinary C refusal"
    );
    assert_eq!(reads.calls.get(), 0);
    let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_unsigned_successor(&recovered);
    assert!(recovered.bodies[1].activation.is_some());
    assert!(recovered.anchor.pending.is_none() && recovered.anchor.completed.is_none());
    assert!(recovered.nearest_closure.is_some());
}
