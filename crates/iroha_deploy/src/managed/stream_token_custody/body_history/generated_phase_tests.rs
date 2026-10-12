//! Genuine generated read prefixes close native custody before callbacks or reservation.

use super::*;
use crate::managed::native_operation::authorization::DispatchAuthorization;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    rc::Rc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum Point {
    BeforeFirstRead,
    BeforeFinalRead,
    BeforeExit,
    BeforeClose,
    AfterClose,
}
type Hook = Box<dyn FnMut(Point, &History) -> Result<()>>;
struct State {
    points: Vec<Point>,
    hook: Option<Hook>,
}
std::thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

// Test observations may mutate test-owned files or refuse. They never manufacture a
// successful source receipt, wallet phase or live authorization for production code.
pub(in crate::managed) fn hit(point: Point, history: &History) -> Result<()> {
    let Some(mut hook) = STATE.with(|state| {
        let mut state = state.borrow_mut();
        let state = state.as_mut()?;
        state.points.push(point);
        Some(state.hook.take())
    }) else {
        return Ok(());
    };
    let result = hook.as_mut().map_or(Ok(()), |hook| hook(point, history));
    STATE.with(|state| state.borrow_mut().as_mut().unwrap().hook = hook);
    result
}

fn observe<T>(hook: Option<Hook>, read: impl FnOnce() -> T) -> (T, Vec<Point>) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|state| state.replace(self.0.take()));
        }
    }
    let _restore = Restore(STATE.with(|state| {
        state.replace(Some(State {
            points: Vec::new(),
            hook,
        }))
    }));
    let result = read();
    let points = STATE.with(|state| state.take().unwrap().points);
    (result, points)
}

// Capture every file and directory in the real body journal, including wallet records.
// Values stay private to the test; compare only equality so assertions do not print bytes.
struct Evidence(BTreeMap<PathBuf, Option<zeroize::Zeroizing<Vec<u8>>>>);
impl Evidence {
    fn capture(root: &Path) -> Self {
        fn visit(path: &Path, out: &mut BTreeMap<PathBuf, Option<zeroize::Zeroizing<Vec<u8>>>>) {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                out.insert(path.to_owned(), None);
                for entry in std::fs::read_dir(path).unwrap() {
                    visit(&entry.unwrap().path(), out);
                }
            } else {
                assert!(metadata.is_file());
                out.insert(
                    path.to_owned(),
                    Some(zeroize::Zeroizing::new(std::fs::read(path).unwrap())),
                );
            }
        }
        let mut records = BTreeMap::new();
        visit(root, &mut records);
        Self(records)
    }
    fn unchanged(&self, root: &Path) {
        assert!(
            self.0 == Self::capture(root).0,
            "read-only prefix changed retained custody"
        );
    }
}

struct ChangedRecord {
    directory: Arc<PrivateDirectory>,
    name: &'static str,
    original: zeroize::Zeroizing<Vec<u8>>,
}
impl ChangedRecord {
    fn replace(directory: &Arc<PrivateDirectory>, name: &'static str) -> Self {
        let value = Self {
            directory: Arc::clone(directory),
            name,
            original: directory.read(name, journal::MAX_ORIGINAL_BYTES).unwrap(),
        };
        let mut changed = value.original.to_vec();
        changed[0] ^= 1;
        directory
            .write_atomic(name, &changed, PublishMode::Replace)
            .unwrap();
        value
    }
}
impl Drop for ChangedRecord {
    fn drop(&mut self) {
        self.directory
            .write_atomic(self.name, &self.original, PublishMode::Replace)
            .expect("restore genuine source record");
    }
}
#[cfg(unix)]
struct ReplacedDirectory {
    path: PathBuf,
    held: PathBuf,
}
#[cfg(unix)]
impl ReplacedDirectory {
    fn replace(path: &Path) -> Self {
        let value = Self {
            path: path.to_owned(),
            held: path.with_extension("generated-original"),
        };
        assert!(!value.held.exists());
        std::fs::rename(&value.path, &value.held).unwrap();
        PrivateDirectory::open_or_create(&value.path).unwrap();
        value
    }
}
#[cfg(unix)]
impl Drop for ReplacedDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir(&self.path).expect("remove empty fixture replacement");
        std::fs::rename(&self.held, &self.path).expect("restore original native owner");
    }
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}
fn run(
    owned: History,
    authorization: &dyn DispatchAuthorization,
    inspector: &NativeClosureInspector<'_>,
    shared: bool,
    hook: Option<Hook>,
) -> (
    Result<(History, u8)>,
    Vec<Point>,
    (usize, usize, usize),
    u64,
) {
    let timing = finish_timing::Capture::start();
    let ((result, work), points) = observe(hook, || {
        History::test_validation_work(usize::MAX, || {
            owned.test_generated_empty_prefix(authorization, inspector, shared)
        })
    });
    let phases = timing.finish();
    (
        result,
        points,
        (
            work.visits,
            work.native_tree_visits,
            work.distinct_histories,
        ),
        phases.sample(finish_timing::Phase::GraphValidate).0,
    )
}

#[test]
fn native_generated_empty_prefix_shares_reads_and_preserves_inherited_decoders() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let mut turn = fixture.renewal_turn();
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let head = history.current_history().unwrap();
    assert_eq!(head.reserved_attempt_count(), 0);
    let account = fixture.owner.wallet().unwrap();
    let inspector = NativeClosureInspector::new(
        history.original().unwrap().unwrap(),
        &account,
        fixture.options.deadline,
    );
    let evidence = Evidence::capture(history.root.path());
    let mut outcomes = Vec::new();
    for shared in [false, true] {
        let (result, points, work, graphs) = run(
            head.test_owned_closure_history().unwrap(),
            authorization,
            &inspector,
            shared,
            None,
        );
        let (current, position) = result.unwrap();
        assert_eq!(position, 3);
        assert_eq!(current.reserved_attempt_count(), 0);
        current.test_require_current(6).0.unwrap();
        assert_eq!(
            points
                .iter()
                .filter(|point| **point == Point::BeforeFirstRead)
                .count(),
            1
        );
        assert_eq!(
            points
                .iter()
                .filter(|point| **point == Point::BeforeFinalRead)
                .count(),
            1
        );
        assert_eq!(points.contains(&Point::AfterClose), shared);
        outcomes.push((work, graphs));
    }
    assert!(
        outcomes[1].1 < outcomes[0].1,
        "actual full graph calls must decrease: {outcomes:?}"
    );
    assert!(
        outcomes[1].0.0 < outcomes[0].0.0,
        "actual visits must decrease: {outcomes:?}"
    );
    assert!(outcomes[1].0.1 > 0 && outcomes[1].0.2 >= 3);
    evidence.unchanged(history.root.path());

    for allocation in [0, 1, 256 * 1024 * 1024] {
        let mut results = Vec::new();
        for shared in [false, true] {
            let owned = head.test_owned_closure_history().unwrap();
            let ((result, points, work, graphs), usage) =
                norito::core::with_decode_limits_measured(limits(allocation), || {
                    run(owned, authorization, &inspector, shared, None)
                });
            assert!(
                !points.contains(&Point::AfterClose),
                "inherited decoder must bypass the shared owner"
            );
            let outcome = result
                .map(|(current, position)| (current.reserved_attempt_count(), position))
                .map_err(|error| error.to_string());
            if allocation <= 1 {
                assert!(outcome.is_err());
            } else {
                assert_eq!(outcome.as_ref().unwrap(), &(0, 3));
            }
            results.push((outcome, points, work, graphs, usage.total_allocated_bytes()));
        }
        assert_eq!(results[0].0, results[1].0);
        assert_eq!(results[0].1, results[1].1);
        assert_eq!(results[0].2, results[1].2);
        assert_eq!(results[0].3, results[1].3);
        if allocation <= 1 {
            assert_eq!(results[0].4, results[1].4);
        } else {
            for result in results {
                assert!(result.4 > 1 && result.4 <= allocation);
            }
        }
    }
    let reopened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    head.test_owned_closure_history()
        .unwrap()
        .test_generated_late_active(authorization, reopened.current_history().unwrap())
        .unwrap();
    evidence.unchanged(history.root.path());
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn native_generated_empty_prefix_closes_source_errors_before_any_effect() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let mut turn = fixture.renewal_turn();
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let head = history.current_history().unwrap();
    let account = fixture.owner.wallet().unwrap();
    let inspector = NativeClosureInspector::new(
        history.original().unwrap().unwrap(),
        &account,
        fixture.options.deadline,
    );
    let evidence = Evidence::capture(history.root.path());
    for name in ["original.nrt", "dispatch.nrt", "closing.nrt", "closed.nrt"] {
        for ordinary_error in [false, true] {
            let changed = Rc::new(RefCell::new(None));
            let saved = Rc::clone(&changed);
            let oldest = Arc::clone(&history.bodies[0].directory);
            let hook: Hook = Box::new(move |point, _| {
                if point == Point::BeforeFirstRead {
                    *saved.borrow_mut() = Some(ChangedRecord::replace(&oldest, name));
                    if ordinary_error {
                        return Err(invalid("ordinary generated prefix refusal"));
                    }
                }
                Ok(())
            });
            let (result, points, _, _) = run(
                head.test_owned_closure_history().unwrap(),
                authorization,
                &inspector,
                true,
                Some(hook),
            );
            let error = result
                .err()
                .expect("persistent source mutation must close the phase");
            assert_ne!(
                error.to_string(),
                invalid("ordinary generated prefix refusal").to_string()
            );
            assert!(!points.contains(&Point::AfterClose));
            assert!(changed.borrow().is_some());
            drop(changed.borrow_mut().take());
            evidence.unchanged(history.root.path());
        }
    }
    let (result, points, _, _) = run(
        head.test_owned_closure_history().unwrap(),
        authorization,
        &inspector,
        true,
        Some(Box::new(|point, _| {
            if point == Point::BeforeFirstRead {
                Err(invalid("ordinary generated prefix refusal"))
            } else {
                Ok(())
            }
        })),
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        invalid("ordinary generated prefix refusal").to_string()
    );
    assert!(!points.contains(&Point::AfterClose));

    // Sampling is deliberately lexical. A wholly restored older sibling can be unseen;
    // the original standalone graph observes that same mutation at its earlier census.
    for shared in [false, true] {
        let changed = Rc::new(RefCell::new(None));
        let saved = Rc::clone(&changed);
        let oldest = Arc::clone(&history.bodies[0].directory);
        let hook: Hook = Box::new(move |point, _| {
            if point == Point::BeforeFirstRead {
                *saved.borrow_mut() = Some(ChangedRecord::replace(&oldest, "original.nrt"));
            }
            if point == Point::BeforeFinalRead {
                drop(saved.borrow_mut().take());
            }
            Ok(())
        });
        let (result, points, _, _) = run(
            head.test_owned_closure_history().unwrap(),
            authorization,
            &inspector,
            shared,
            Some(hook),
        );
        assert_eq!(result.is_ok(), shared);
        assert_eq!(points.contains(&Point::AfterClose), shared);
        drop(changed.borrow_mut().take());
        evidence.unchanged(history.root.path());
    }
    #[cfg(unix)]
    for current in [false, true] {
        for ordinary_error in [false, true] {
            let replaced = Rc::new(RefCell::new(None));
            let saved = Rc::clone(&replaced);
            let path = history.bodies[if current { 2 } else { 0 }]
                .directory
                .path()
                .to_owned();
            let hook: Hook = Box::new(move |point, _| {
                if point == Point::BeforeFirstRead {
                    *saved.borrow_mut() = Some(ReplacedDirectory::replace(&path));
                    if ordinary_error {
                        return Err(invalid("ordinary generated prefix refusal"));
                    }
                }
                Ok(())
            });
            let (result, points, _, _) = run(
                head.test_owned_closure_history().unwrap(),
                authorization,
                &inspector,
                true,
                Some(hook),
            );
            assert_ne!(
                result
                    .err()
                    .expect("original handle replacement must refuse")
                    .to_string(),
                invalid("ordinary generated prefix refusal").to_string()
            );
            assert!(!points.contains(&Point::AfterClose));
            drop(replaced.borrow_mut().take());
            evidence.unchanged(history.root.path());
        }
    }
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn native_generated_reread_discovery_closes_before_first_wallet_callback() {
    let _resources = crate::managed::native_test_guard();
    for point in [Point::BeforeFirstRead, Point::BeforeFinalRead] {
        for corrupt_at_close in [false, true] {
            shared_snapshot_tests::history_with_bodies_in_final_turn(
                2,
                |fixture, history, authorization, current| {
                    let (directory, original, scope) = history.dispatch().unwrap();
                    let deadline = fixture.options.deadline;
                    let Action::Enroll { validity, .. } = &original.action else {
                        unreachable!()
                    };
                    let body_expiry = validity.expires_at_unix_ms;
                    let observation = fixture
                        .owner
                        .fresh_predecessor_observation(original, current, current, deadline)
                        .unwrap_or_else(|error| {
                            panic!(
                                "generated reread setup failed at {point:?}, corrupt_at_close={corrupt_at_close}: {error:?}; body_remaining_ms={}",
                                body_expiry.saturating_sub(now_ms().unwrap()),
                            )
                        });
                    let mut reservation = Some((
                        authorization.origin().unwrap(),
                        authorization.terms(deadline, Some(body_expiry)).unwrap(),
                        observation,
                    ));
                    let after_writer = Rc::new(RefCell::new(None));
                    let saved_writer = Rc::clone(&after_writer);
                    let changed = Rc::new(RefCell::new(None));
                    let saved = Rc::clone(&changed);
                    let oldest = Arc::clone(&history.bodies[0].directory);
                    let root = history.root.path().to_owned();
                    let closed = Rc::new(Cell::new(false));
                    let observed_closed = Rc::clone(&closed);
                    let hook: Hook = Box::new(move |at, head| {
                        if at == point {
                            let (origin, terms, observation) =
                                reservation.take().expect("writer runs once");
                            head.test_generated_reserve_observed(origin, terms, observation)?;
                            *saved_writer.borrow_mut() = Some(Evidence::capture(&root));
                        }
                        if at == Point::BeforeClose && corrupt_at_close {
                            *saved.borrow_mut() =
                                Some(ChangedRecord::replace(&oldest, "original.nrt"));
                        }
                        if at == Point::AfterClose {
                            observed_closed.set(true);
                        }
                        Ok(())
                    });
                    let account = fixture.owner.wallet().unwrap();
                    let inspector = NativeClosureInspector::new(original, &account, deadline);
                    let callbacks = Cell::new(0);
                    let (result, points) = observe(Some(hook), || {
                        attempts::generated_native(
                            directory,
                            original.dispatch_purpose().unwrap(),
                            original.digest().unwrap(),
                            scope,
                            authorization,
                            deadline,
                            Some(body_expiry),
                            &inspector,
                            |_| {
                                assert!(
                                    closed.get(),
                                    "wallet callback entered before all source exits"
                                );
                                callbacks.set(callbacks.get() + 1);
                                Err(invalid("wallet callback after generated prefix"))
                            },
                            |_| panic!("no retirement before discovered wallet inspection"),
                            |_, _, _| {
                                panic!("no request publication before discovered wallet inspection")
                            },
                            |_, _| {
                                panic!("no prerequisite effect before discovered wallet inspection")
                            },
                            |_| {
                                panic!(
                                    "no observation callback before discovered wallet inspection"
                                )
                            },
                        )
                    });
                    let error = result
                        .err()
                        .expect("callback or persistent source refusal must escape");
                    assert_eq!(callbacks.get(), usize::from(!corrupt_at_close));
                    assert_eq!(closed.get(), !corrupt_at_close);
                    assert_eq!(points.contains(&Point::AfterClose), !corrupt_at_close);
                    assert_eq!(
                        error.to_string()
                            == invalid("wallet callback after generated prefix").to_string(),
                        !corrupt_at_close
                    );
                    drop(changed.borrow_mut().take());
                    after_writer
                        .borrow()
                        .as_ref()
                        .expect("canonical writer ran")
                        .unchanged(history.root.path());
                    let head = history
                        .current_history()
                        .unwrap()
                        .test_owned_closure_history()
                        .unwrap();
                    assert_eq!(head.reserved_attempt_count(), 1);
                    let attempt = head.last().unwrap();
                    assert!(!attempt.directory().path().join("transaction").exists());
                    assert!(attempt.observation().is_ok());
                    // A subsequent existing-attempt call takes the literal Initial continuation.
                    let (result, points, _, _) = run(head, authorization, &inspector, true, None);
                    assert_eq!(result.unwrap().1, 0);
                    assert!(points.is_empty());
                    assert_eq!(fixture.native.chain.height(), 4);
                },
            );
        }
    }
}

#[test]
fn native_generated_exit_keeps_refresh_custody_and_original_error_closure() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let mut turn = fixture.renewal_turn();
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let head = history.current_history().unwrap();
    let account = fixture.owner.wallet().unwrap();
    let inspector = NativeClosureInspector::new(
        history.original().unwrap().unwrap(),
        &account,
        fixture.options.deadline,
    );
    let evidence = Evidence::capture(history.root.path());
    let mut observations = Vec::new();
    for original_exit in [true, false] {
        let (result, points, work, graphs) =
            History::test_original_phase_exit(original_exit, || {
                run(
                    head.test_owned_closure_history().unwrap(),
                    authorization,
                    &inspector,
                    true,
                    None,
                )
            });
        let (current, position) = result.unwrap();
        assert_eq!((position, current.reserved_attempt_count()), (3, 0));
        current.test_require_current(6).0.unwrap();
        observations.push((points, work, graphs));
        evidence.unchanged(history.root.path());
    }
    assert_eq!(observations[0].0, observations[1].0);
    assert_eq!(observations[0].1.0, observations[1].1.0 + 2);
    assert_eq!(observations[0].1.2, observations[1].1.2);
    assert_eq!(observations[0].2, observations[1].2);
    assert!(observations[1].1.1 > 0);
    assert_eq!(
        observations[1].0,
        [
            Point::BeforeFirstRead,
            Point::BeforeFinalRead,
            Point::BeforeExit,
            Point::BeforeClose,
            Point::AfterClose
        ]
    );

    for allocation in [0, 1, 256 * 1024 * 1024] {
        let mut observations = Vec::new();
        for original_exit in [true, false] {
            let owned = head.test_owned_closure_history().unwrap();
            let ((result, points, work, graphs), usage) =
                norito::core::with_decode_limits_measured(limits(allocation), || {
                    History::test_original_phase_exit(original_exit, || {
                        run(owned, authorization, &inspector, true, None)
                    })
                });
            let outcome = result
                .map(|(current, position)| (current.reserved_attempt_count(), position))
                .map_err(|error| error.to_string());
            if allocation <= 1 {
                assert!(outcome.is_err());
            } else {
                assert_eq!(outcome.as_ref().unwrap(), &(0, 3));
            }
            observations.push((outcome, points, work, graphs, usage.total_allocated_bytes()));
        }
        assert_eq!(observations[0].0, observations[1].0);
        assert_eq!(observations[0].1, observations[1].1);
        assert_eq!(observations[0].2, observations[1].2);
        assert_eq!(observations[0].3, observations[1].3);
        if allocation <= 1 {
            assert_eq!(observations[0].4, observations[1].4);
        } else {
            assert!(
                observations
                    .iter()
                    .all(|value| value.4 > 1 && value.4 <= allocation)
            );
        }
        evidence.unchanged(history.root.path());
    }

    // The original reverse entry still runs before any phase read. Install the
    // hook only after constructing the owned History so no earlier read consumes it.
    let mut entry_refusals = Vec::new();
    for original_exit in [true, false] {
        let owned = head.test_owned_closure_history().unwrap();
        let changed = Rc::new(RefCell::new(None));
        let saved = Rc::clone(&changed);
        let oldest = Arc::clone(&history.bodies[0].directory);
        let (result, points, work, graphs) = History::test_phase_entry_after_forward(
            move || {
                *saved.borrow_mut() = Some(ChangedRecord::replace(&oldest, "closed.nrt"));
                Ok(())
            },
            || {
                History::test_original_phase_exit(original_exit, || {
                    run(owned, authorization, &inspector, true, None)
                })
            },
        );
        assert!(
            points.is_empty(),
            "damaged entry cannot reach the first phase read"
        );
        assert!(changed.borrow().is_some());
        entry_refusals.push((
            result
                .err()
                .expect("entry reverse census must refuse")
                .to_string(),
            work,
            graphs,
        ));
        drop(changed.borrow_mut().take());
        evidence.unchanged(history.root.path());
    }
    assert_eq!(entry_refusals[0], entry_refusals[1]);

    struct AddedDispatch(Arc<PrivateDirectory>);
    impl Drop for AddedDispatch {
        fn drop(&mut self) {
            assert!(
                self.0
                    .remove_private("dispatch.nrt")
                    .expect("restore absent dispatch")
            );
        }
    }

    // A failed canonical refresh must retain the original full exit. When the
    // inner read succeeds, a bad current-head exit must still close the oldest
    // predecessor before returning: the shortened exit cannot stop at its head.
    for point in [Point::BeforeFinalRead, Point::BeforeClose] {
        let mut refusals = Vec::new();
        for original_exit in [true, false] {
            let changed = Rc::new(RefCell::new(Vec::new()));
            let saved = Rc::clone(&changed);
            let added = Rc::new(RefCell::new(None));
            let saved_added = Rc::clone(&added);
            let oldest = Arc::clone(&history.bodies[0].directory);
            let current = Arc::clone(&history.bodies[2].directory);
            let hook: Hook = Box::new(move |observed, _| {
                if observed == point {
                    current
                        .write_atomic(
                            "dispatch.nrt",
                            b"not a dispatch record",
                            PublishMode::CreateNew,
                        )
                        .unwrap();
                    *saved_added.borrow_mut() = Some(AddedDispatch(Arc::clone(&current)));
                    saved
                        .borrow_mut()
                        .push(ChangedRecord::replace(&oldest, "closed.nrt"));
                }
                Ok(())
            });
            let (result, points, work, graphs) =
                History::test_original_phase_exit(original_exit, || {
                    run(
                        head.test_owned_closure_history().unwrap(),
                        authorization,
                        &inspector,
                        true,
                        Some(hook),
                    )
                });
            assert!(!points.contains(&Point::AfterClose));
            assert_eq!(changed.borrow().len(), 1);
            assert!(added.borrow().is_some());
            let error = result
                .err()
                .expect("both original sources must close before refusal")
                .to_string();
            refusals.push((error, points, work, graphs));
            changed.borrow_mut().clear();
            drop(added.borrow_mut().take());
            evidence.unchanged(history.root.path());
        }
        assert_eq!(refusals[0].0, refusals[1].0);
        assert_eq!(refusals[0].1, refusals[1].1);
        if point == Point::BeforeFinalRead {
            assert_eq!(refusals[0].2, refusals[1].2);
            assert_eq!(refusals[0].3, refusals[1].3);
        } else {
            assert_eq!(
                refusals[1].2.0,
                refusals[0].2.0 + 1,
                "failed fast head census must be followed by the original predecessor exit"
            );
            assert_eq!(refusals[1].3, refusals[0].3 + 1);
        }
    }
    let reopened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    head.test_phase_graph_owner(reopened.current_history().unwrap(), &inspector)
        .unwrap();
    evidence.unchanged(history.root.path());
    assert_eq!(fixture.native.chain.height(), 4);
}
