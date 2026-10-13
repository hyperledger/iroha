//! Genuine publication admission agrees with cold recovery and refuses changed original custody.

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
enum Point {
    Before(PublicationStep),
    After(PublicationStep),
}
type Hook = Box<dyn FnMut(Point, &BodyHistory, &ManagedStreamTokenCustody) -> Result<()>>;
thread_local! {
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}
pub(super) fn before_admission(
    step: PublicationStep,
    history: &BodyHistory,
    owner: &ManagedStreamTokenCustody,
) -> Result<()> {
    hit(Point::Before(step), history, owner)
}
pub(super) fn after_admission(
    step: PublicationStep,
    history: &BodyHistory,
    owner: &ManagedStreamTokenCustody,
) -> Result<()> {
    hit(Point::After(step), history, owner)
}
fn hit(point: Point, history: &BodyHistory, owner: &ManagedStreamTokenCustody) -> Result<()> {
    HOOK.with(|hook| {
        hook.borrow_mut()
            .as_mut()
            .map_or(Ok(()), |hook| hook(point, history, owner))
    })
}
fn with_hook<T>(
    hook: impl FnMut(Point, &BodyHistory, &ManagedStreamTokenCustody) -> Result<()> + 'static,
    action: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Hook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            HOOK.with(|hook| {
                hook.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(HOOK.with(|slot| slot.replace(Some(Box::new(hook)))));
    action()
}

fn same_state(actual: &BodyHistory, recovered: &BodyHistory) {
    actual.require_retained_prefix(recovered).unwrap();
    recovered.require_retained_prefix(actual).unwrap();
    assert_eq!(
        encode(&actual.anchor, MAX_BODY_BYTES).unwrap(),
        encode(&recovered.anchor, MAX_BODY_BYTES).unwrap()
    );
    assert_eq!(actual.reference_present, recovered.reference_present);
    assert_eq!(actual.bodies.len(), recovered.bodies.len());
    for (left, right) in actual.bodies.iter().zip(&recovered.bodies) {
        assert_eq!(
            left.directory.identity().unwrap(),
            right.directory.identity().unwrap()
        );
        assert_eq!(left.semantic, right.semantic);
        assert_eq!(
            encode(&left.reservation, MAX_BODY_BYTES).unwrap(),
            encode(&right.reservation, MAX_BODY_BYTES).unwrap()
        );
        assert_eq!(
            encode(&left.original, journal::MAX_ORIGINAL_BYTES).unwrap(),
            encode(&right.original, journal::MAX_ORIGINAL_BYTES).unwrap()
        );
        assert_eq!(
            encode(&left.activation, MAX_SELECTION_BYTES).unwrap(),
            encode(&right.activation, MAX_SELECTION_BYTES).unwrap()
        );
        assert_eq!(
            encode(&left.unused, MAX_SELECTION_BYTES).unwrap(),
            encode(&right.unused, MAX_SELECTION_BYTES).unwrap()
        );
    }
    assert_eq!(
        actual
            .active
            .as_ref()
            .map(|active| (active.index, active.history.cumulative_reserved_count())),
        recovered
            .active
            .as_ref()
            .map(|active| (active.index, active.history.cumulative_reserved_count()))
    );
    assert_eq!(
        actual
            .nearest_closure
            .as_ref()
            .map(VerifiedUnsignedClosure::digest),
        recovered
            .nearest_closure
            .as_ref()
            .map(VerifiedUnsignedClosure::digest)
    );
}

// This is an equivalence fixture, not the deep-history latency gate. Its original policy
// deliberately allows the additional cold recovery after each write. The existing deep64
// fixture retains its original ten-second bodies, nofile limit, stack limit and deadlines.
fn advance(
    fixture: &Fixture,
    previous: Option<BodyHistory>,
    request_only: bool,
) -> Result<BodyHistory> {
    if let Some(history) = previous.as_ref() {
        wait_until(
            history
                .bodies
                .last()
                .unwrap()
                .reservation
                .unsigned
                .statement
                .expires_at_unix_ms,
            Duration::from_secs(32),
        );
    }
    let mut turn = fixture.renewal_turn();
    let (checkpoint, current) = fixture.current();
    let terms = Terms::new(now_ms()? + fixture.policy.max_validity_ms, &fixture.options)?;
    let unsigned = fixture.owner.select_renewal_unsigned(
        2,
        &fixture.policy,
        &current,
        &checkpoint,
        &terms,
        fixture.options.deadline,
    )?;
    let (selected, authorization) = if let Some(previous) = previous {
        let authorization =
            turn.authorize_retained(&fixture.owner, &previous, fixture.options.deadline)?;
        let selected = previous.reserve_successor(
            &fixture.owner,
            unsigned,
            &current,
            authorization,
            fixture.options.deadline,
        )?;
        (selected, authorization)
    } else {
        let selected = BodyHistory::initialize(
            &fixture.owner,
            CustodyPurpose::Renewal(2),
            unsigned,
            &terms.fees,
            &SigningTurn::RenewalSelection(&turn),
            fixture.options.deadline,
        )?;
        let authorization =
            turn.authorize_retained(&fixture.owner, &selected, fixture.options.deadline)?;
        (selected, authorization)
    };
    let finished = selected.finish_pending_with_reads(
        &fixture.owner,
        &current,
        &SigningTurn::Generated(authorization),
        fixture.options.deadline,
        &NativeEnrollmentReads(&fixture.native),
    )?;
    if request_only {
        fixture.retain_generated_attempt(authorization, &finished, &current)?;
    }
    finished.reopen(&fixture.owner)
}

#[test]
fn every_successful_local_publication_matches_genuine_cold_recovery() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 30_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let observed = Rc::new(RefCell::new(Vec::new()));
    let capture = Rc::clone(&observed);
    let history = with_hook(
        move |point, history, owner| {
            if !matches!(history.purpose, CustodyPurpose::Renewal(2)) {
                return Ok(());
            }
            if let Point::After(step) = point {
                let recovered = history.read_current(owner)?;
                same_state(history, &recovered);
                capture.borrow_mut().push(step);
            }
            Ok(())
        },
        || {
            let first = advance(&fixture, None, true).unwrap();
            advance(&fixture, Some(first), false).unwrap()
        },
    );
    let steps = observed.borrow();
    for step in [
        PublicationStep::Anchor,
        PublicationStep::Reserved,
        PublicationStep::Closed,
        PublicationStep::Activated,
        PublicationStep::Signed,
    ] {
        assert!(
            steps.contains(&step),
            "missing genuine publication step {step:?}"
        );
    }
    assert_eq!(history.bodies.len(), 2);
    assert_eq!(
        history
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        1
    );
    assert_eq!(fixture.native.chain.height(), 4);
    // The old unsigned wallet is canonically retired; no carrier or paid envelope appeared.
    let first = history.bodies[0]
        .directory
        .open_child("attempts")
        .unwrap()
        .open_child("0001")
        .unwrap();
    assert!(!first.path().join("carrier.nrt").exists());
    assert!(!first.path().join("replay.nrt").exists());
    assert!(!first.path().join("transaction/payload.json").exists());
    assert!(history.bodies[0].original.is_some());
    assert!(history.bodies[1].original.is_some());
}

#[derive(Clone, Copy)]
enum Corruption {
    Immutable,
    Namespace,
    ImmutableAndProfile,
}

#[test]
fn original_source_and_profile_exit_refuse_after_native_publication_without_signing() {
    let _guard = crate::managed::native_test_guard();
    for corruption in [
        Corruption::Immutable,
        Corruption::Namespace,
        Corruption::ImmutableAndProfile,
    ] {
        let fixture = Fixture::enrolled_with_renewal_validity(4_000, 30_000);
        wait_until(
            fixture.initial.issued_at_unix_ms + 2_000,
            Duration::from_secs(4),
        );
        let restoration = Rc::new(RefCell::new(
            Vec::<(std::path::PathBuf, Option<Vec<u8>>)>::new(),
        ));
        let saved = Rc::clone(&restoration);
        let generation = fixture
            .prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .to_path_buf();
        let fired = Rc::new(Cell::new(false));
        let was_fired = Rc::clone(&fired);
        let result = with_hook(
            move |point, history, _owner| {
                if point != Point::Before(PublicationStep::Reserved)
                    || !matches!(history.purpose, CustodyPurpose::Renewal(2))
                    || was_fired.replace(true)
                {
                    return Ok(());
                }
                match corruption {
                    Corruption::Namespace => {
                        history.root.write_atomic(
                            "unexpected.nrt",
                            b"unexpected",
                            PublishMode::CreateNew,
                        )?;
                        saved
                            .borrow_mut()
                            .push((history.root.path().join("unexpected.nrt"), None));
                    }
                    Corruption::Immutable | Corruption::ImmutableAndProfile => {
                        let bytes = history.root.read("original.nrt", MAX_SELECTION_BYTES)?;
                        saved.borrow_mut().push((
                            history.root.path().join("original.nrt"),
                            Some(bytes.to_vec()),
                        ));
                        history.root.write_atomic(
                            "original.nrt",
                            b"changed original",
                            PublishMode::Replace,
                        )?;
                        if matches!(corruption, Corruption::ImmutableAndProfile) {
                            let root = PrivateDirectory::open_exact(&generation)?;
                            let bytes = root.read("peer3.toml", 1024 * 1024)?;
                            let mut changed = bytes.to_vec();
                            changed.extend_from_slice(b"\n# changed original profile bytes\n");
                            saved
                                .borrow_mut()
                                .push((generation.join("peer3.toml"), Some(bytes.to_vec())));
                            root.write_atomic("peer3.toml", &changed, PublishMode::Replace)?;
                        }
                    }
                }
                Ok(())
            },
            || advance(&fixture, None, false),
        );
        assert!(fired.get());
        assert!(result.is_err());
        if matches!(corruption, Corruption::ImmutableAndProfile) {
            assert!(
                matches!(result, Err(crate::managed::Error::Invalid(message))
                if message == "retained service profile input custody differs")
            );
        }
        for (path, bytes) in restoration.borrow_mut().drain(..).rev() {
            match bytes {
                Some(bytes) => PrivateDirectory::open_exact(path.parent().unwrap())
                    .unwrap()
                    .write_atomic(path.file_name().unwrap(), &bytes, PublishMode::Replace)
                    .unwrap(),
                None => std::fs::remove_file(path).unwrap(),
            }
        }
        let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
            .unwrap()
            .unwrap();
        assert!(recovered.has_pending());
        assert_eq!(recovered.bodies.len(), 1);
        assert!(recovered.bodies[0].original.is_none());
        assert!(recovered.bodies[0].activation.is_none());
        assert!(recovered.dispatch().is_err());
        assert_eq!(fixture.native.chain.height(), 4);
    }
}

#[test]
fn successful_unused_retirement_matches_cold_recovery_without_wallet_or_signature() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let fired = Rc::new(Cell::new(false));
    let capture = Rc::clone(&fired);
    let interrupted = with_hook(
        move |point, history, owner| {
            if matches!(history.purpose, CustodyPurpose::Renewal(2))
                && point == Point::After(PublicationStep::Activated)
            {
                same_state(history, &history.read_current(owner)?);
                capture.set(true);
                return Err(crate::managed::Error::NativeDeadline);
            }
            Ok(())
        },
        || advance(&fixture, None, false),
    );
    assert!(fired.get());
    assert!(matches!(
        interrupted,
        Err(crate::managed::Error::NativeDeadline)
    ));
    let unsigned = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert!(unsigned.bodies[0].activation.is_some());
    assert!(unsigned.bodies[0].original.is_none());
    assert!(
        !unsigned.bodies[0]
            .directory
            .path()
            .join("attempts")
            .exists()
    );
    let observed = Rc::new(Cell::new(false));
    let capture = Rc::clone(&observed);
    let completed = with_hook(
        move |point, history, owner| {
            if matches!(history.purpose, CustodyPurpose::Renewal(2))
                && let Point::After(step) = point
            {
                same_state(history, &history.read_current(owner)?);
                if step == PublicationStep::Unused {
                    capture.set(true);
                }
            }
            Ok(())
        },
        || advance(&fixture, Some(unsigned), false),
    )
    .unwrap();
    assert!(observed.get());
    assert_eq!(completed.bodies.len(), 2);
    assert!(completed.bodies[0].unused.is_some());
    assert!(completed.bodies[0].original.is_none());
    assert!(
        !completed.bodies[0]
            .directory
            .path()
            .join("attempts")
            .exists()
    );
    assert!(completed.bodies[1].original.is_some());
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
struct ReplacedDirectory {
    path: std::path::PathBuf,
    original: std::path::PathBuf,
}
#[cfg(unix)]
impl ReplacedDirectory {
    fn new(path: &std::path::Path) -> Self {
        let original = path.with_extension("published-original-owner");
        assert!(!original.exists());
        std::fs::rename(path, &original).unwrap();
        drop(PrivateDirectory::open_or_create(path).unwrap());
        Self {
            path: path.to_owned(),
            original,
        }
    }
}
#[cfg(unix)]
impl Drop for ReplacedDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir(&self.path).unwrap();
        std::fs::rename(&self.original, &self.path).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn published_records_refuse_current_attempt_replacement_after_one_wallet_callback() {
    let _guard = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(2);
    let attempt = history.bodies[0].directory.path().join("attempts/0001");
    assert!(attempt.is_dir());
    let armed = Rc::new(Cell::new(false));
    let arm = Rc::clone(&armed);
    let callback_armed = Rc::clone(&armed);
    let count = Rc::new(Cell::new(0));
    let callbacks = Rc::clone(&count);
    let changed = Rc::new(RefCell::new(None));
    let mutation = Rc::clone(&changed);
    let result = parser_handle_tests::with_hook(
        move |point| {
            if callback_armed.get()
                && matches!(point, parser_handle_tests::Point::WalletInspected(_))
            {
                callbacks.set(callbacks.get() + 1);
                if callbacks.get() == 1 {
                    *mutation.borrow_mut() = Some(ReplacedDirectory::new(&attempt));
                }
            }
            Ok(())
        },
        || {
            with_hook(
                move |point, history, _owner| {
                    if matches!(history.purpose, CustodyPurpose::Renewal(2))
                        && point == Point::Before(PublicationStep::Anchor)
                    {
                        arm.set(true);
                    }
                    Ok(())
                },
                || advance(&fixture, Some(history), false),
            )
        },
    );
    assert!(
        armed.get(),
        "actual successful anchor publication selected the new reader"
    );
    assert_eq!(
        count.get(),
        1,
        "current source closes before a second tail inspection"
    );
    assert!(changed.borrow().is_some());
    assert!(matches!(
        result,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::RetainedMaterial
        ))
    ));
    drop(changed.borrow_mut().take());
    let recovered = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert!(recovered.has_pending());
    assert_eq!(recovered.anchor.highest, 3);
    assert_eq!(
        recovered.bodies.len(),
        2,
        "no next-body publication after callback refusal"
    );
    assert_eq!(fixture.native.chain.height(), 4);
}
