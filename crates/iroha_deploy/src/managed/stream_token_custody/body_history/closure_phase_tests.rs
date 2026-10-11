//! Genuine native closure phases retain both wallet observations and close original custody.

use super::*;
use crate::managed::native_operation::attempts::UnsignedClosureVerification;
use iroha_wallet::operations::{NativePreparationPhase, VerifiedNativePreparation};
use std::{cell::RefCell, rc::Rc};

#[derive(Default, Debug, PartialEq, Eq)]
struct Calls {
    native: usize,
    retired: usize,
}
type Hook =
    Box<dyn FnMut(usize, &attempts::Attempt, &Result<VerifiedNativePreparation>) -> Result<()>>;
struct State {
    calls: Calls,
    hook: Option<Hook>,
}
std::thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

// The production inspector has already performed the original native wallet read here.
// This observer can corrupt test-owned custody or return an error, never create evidence.
pub(super) fn after_inspection(
    attempt: &attempts::Attempt,
    value: &Result<VerifiedNativePreparation>,
) -> Result<()> {
    let Some((ordinal, mut hook)) = STATE.with(|state| {
        let mut state = state.borrow_mut();
        let state = state.as_mut()?;
        state.calls.native += 1;
        state.calls.retired += usize::from(
            value
                .as_ref()
                .is_ok_and(|value| value.phase() == NativePreparationPhase::Retired),
        );
        Some((state.calls.native, state.hook.take()))
    }) else {
        return Ok(());
    };
    let result = hook
        .as_mut()
        .map_or(Ok(()), |hook| hook(ordinal, attempt, value));
    STATE.with(|state| state.borrow_mut().as_mut().unwrap().hook = hook);
    result
}

fn observe<T>(hook: Option<Hook>, read: impl FnOnce() -> T) -> (T, Calls) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|state| state.replace(self.0.take()));
        }
    }
    let _restore = Restore(STATE.with(|state| {
        state.replace(Some(State {
            calls: Calls::default(),
            hook,
        }))
    }));
    let value = read();
    let calls = STATE.with(|state| state.take().unwrap().calls);
    (value, calls)
}

fn complete(value: Result<UnsignedClosureVerification>) -> VerifiedUnsignedClosure {
    match value.unwrap_or_else(|error| panic!("genuine native closure refused: {error}")) {
        UnsignedClosureVerification::Closed(value) => value,
        UnsignedClosureVerification::Pending(_) => panic!("retired body unexpectedly pending"),
    }
}

fn same_receipt(actual: &VerifiedUnsignedClosure, expected: &VerifiedUnsignedClosure) {
    assert_eq!(actual.digest(), expected.digest());
    assert_eq!(actual.purpose(), expected.purpose());
    assert_eq!(actual.closed_semantic(), expected.closed_semantic());
    assert_eq!(actual.successor_selection(), expected.successor_selection());
    assert_eq!(
        actual.cumulative_reserved_count(),
        expected.cumulative_reserved_count()
    );
    actual.retained_history().test_require_current(4).0.unwrap();
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

fn run(
    owned: History,
    successor: &dyn SemanticSuccessor,
    inspector: &mut NativeClosureInspector<'_>,
    native: bool,
    hook: Option<Hook>,
) -> (
    Result<UnsignedClosureVerification>,
    Calls,
    (usize, usize, usize),
    u64,
) {
    let timing = finish_timing::Capture::start();
    let ((result, work), calls) = observe(hook, || {
        History::test_validation_work(usize::MAX, || {
            if native {
                owned.test_into_unsigned_closure_native(successor, inspector)
            } else {
                owned.into_unsigned_closure_with_pass(
                    successor,
                    |attempt| inspector.inspect(attempt),
                    None,
                )
            }
        })
    });
    let phases = timing.finish();
    (
        result,
        calls,
        (
            work.visits,
            work.native_tree_visits,
            work.distinct_histories,
        ),
        phases.sample(finish_timing::Phase::GraphValidate).0,
    )
}

struct Evidence {
    directories: Vec<(Arc<PrivateDirectory>, Vec<std::ffi::OsString>)>,
    records: Vec<(
        Arc<PrivateDirectory>,
        String,
        Option<zeroize::Zeroizing<Vec<u8>>>,
    )>,
}
impl Evidence {
    fn capture(history: &BodyHistory) -> Self {
        let mut value = Self {
            directories: Vec::new(),
            records: Vec::new(),
        };
        value.add(&history.root, &["original.nrt", "anchor.nrt"]);
        let container = history.body_root.as_ref().unwrap();
        value.add(container, &[]);
        for name in container.entries(32).unwrap() {
            let name = name.to_str().expect("canonical body entry");
            if name.ends_with(".nrt") {
                value.add(container, &[name]);
            }
        }
        for body in &history.bodies {
            value.add(
                &body.directory,
                &[
                    "reserved.nrt",
                    "original.nrt",
                    "dispatch.nrt",
                    "closing.nrt",
                    "closed.nrt",
                ],
            );
        }
        let old = history
            .current_history()
            .unwrap()
            .test_owned_predecessor_closure_history()
            .unwrap();
        let attempt = old.last().unwrap();
        let directory = Arc::new(PrivateDirectory::open(attempt.directory().path()).unwrap());
        value.add(
            &directory,
            &[
                "authorization.nrt",
                "observation.nrt",
                "committed.nrt",
                "retired.nrt",
                "carrier.nrt",
                "replay.nrt",
            ],
        );
        let wallet = Arc::new(
            directory
                .open_child_optional("transaction")
                .unwrap()
                .unwrap(),
        );
        value.add(
            &wallet,
            &[
                "preparation.json",
                "payload.json",
                "operation.json",
                "retired.json",
                "submission.json",
                "applied.json",
            ],
        );
        value
    }
    fn add(&mut self, directory: &Arc<PrivateDirectory>, names: &[&str]) {
        self.directories
            .push((Arc::clone(directory), directory.entries(32).unwrap()));
        for name in names {
            self.records.push((
                Arc::clone(directory),
                (*name).to_owned(),
                read_optional(directory, name, journal::MAX_ORIGINAL_BYTES)
                    .unwrap()
                    .map(zeroize::Zeroizing::new),
            ));
        }
    }
    fn unchanged(&self) {
        for (directory, names) in &self.directories {
            assert_eq!(directory.entries(32).unwrap(), *names);
        }
        for (directory, name, original) in &self.records {
            let actual = read_optional(directory, name, journal::MAX_ORIGINAL_BYTES).unwrap();
            assert_eq!(
                actual.as_deref(),
                original.as_ref().map(|bytes| bytes.as_slice()),
                "read phase changed {name}"
            );
        }
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
            .expect("restore original test-owned body record");
    }
}

#[cfg(unix)]
struct ReplacedDirectory {
    path: std::path::PathBuf,
    held: std::path::PathBuf,
}
#[cfg(unix)]
impl ReplacedDirectory {
    fn replace(path: &std::path::Path) -> Self {
        let value = Self {
            path: path.to_owned(),
            held: path.with_extension("native-closure-original"),
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
        std::fs::remove_dir(&self.path).expect("remove only empty fixture replacement");
        std::fs::rename(&self.held, &self.path).expect("restore exact original native handle");
    }
}

#[test]
fn native_closure_phase_shares_only_prefix_work_and_preserves_actual_wallet_reads() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let head = history.current_history().unwrap();
    let original = history.bodies[1].original.as_ref().unwrap();
    let successor = history.successor(1).unwrap().unwrap();
    let account = fixture.owner.wallet().unwrap();
    let evidence = Evidence::capture(&history);
    let mut inspect = NativeClosureInspector::new(original, &account, fixture.options.deadline);
    let (expected, old_calls, old_work, old_graphs) = run(
        head.test_owned_predecessor_closure_history().unwrap(),
        &successor,
        &mut inspect,
        false,
        None,
    );
    let expected = complete(expected);
    let (actual, calls, work, graphs) = run(
        head.test_owned_predecessor_closure_history().unwrap(),
        &successor,
        &mut inspect,
        true,
        None,
    );
    same_receipt(&complete(actual), &expected);
    assert_eq!(
        calls,
        Calls {
            native: 2,
            retired: 2
        }
    );
    assert_eq!(
        calls, old_calls,
        "whole wallet pass plus exact final tail inspection remain native"
    );
    assert!(
        graphs < old_graphs,
        "actual complete graph calls must decrease: {graphs} vs {old_graphs}"
    );
    assert!(
        work.0 < old_work.0,
        "actual local graph visits must decrease: {work:?} vs {old_work:?}"
    );
    assert!(work.1 > 0);
    assert!(work.2 >= 2, "both genuine body owners must be visited");
    evidence.unchanged();

    // An inherited owner retains the literal original physical recipe. A successful
    // allocation count is not a portable refusal threshold across separately built graphs.
    let ample = 256 * 1024 * 1024;
    let mut outcomes = Vec::new();
    for native in [false, true] {
        let owned = head.test_owned_predecessor_closure_history().unwrap();
        let ((result, calls, work, graphs), usage) =
            norito::core::with_decode_limits_measured(limits(ample), || {
                run(owned, &successor, &mut inspect, native, None)
            });
        same_receipt(&complete(result), &expected);
        assert_eq!(calls, old_calls);
        assert!(usage.total_allocated_bytes() > 1 && usage.total_allocated_bytes() <= ample);
        outcomes.push((work, graphs));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    for capacity in [0, 1] {
        let mut refusals = Vec::new();
        for native in [false, true] {
            let owned = head.test_owned_predecessor_closure_history().unwrap();
            let ((result, calls, work, graphs), usage) =
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    run(owned, &successor, &mut inspect, native, None)
                });
            refusals.push((
                result
                    .err()
                    .expect("original finite decoder must refuse")
                    .to_string(),
                calls,
                work,
                graphs,
                usage.total_allocated_bytes(),
            ));
        }
        assert_eq!(refusals[0], refusals[1]);
    }
    // A remembered immutable receipt may bind this exact predecessor without another
    // census inside the same parser owner. It cannot authorize a foreign Arc, standalone
    // call or decoder installed after that owner opened.
    let reopened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    let foreign = reopened.current_history().unwrap();
    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    EnrollmentReadPass::run(&snapshot, |pass| {
        pass.test_retain_predecessor(head)?;
        let (current, work) =
            History::test_validation_work(4, || head.test_require_predecessor_binding(Some(pass)));
        current?;
        assert_eq!((work.visits, work.native_tree_visits), (0, 0));
        for (selected, admitted) in [(head, None), (foreign, Some(pass))] {
            let (current, work) = History::test_validation_work(4, || {
                selected.test_require_predecessor_binding(admitted)
            });
            current?;
            assert_eq!((work.visits, work.native_tree_visits), (4, 4));
        }
        let ((current, work), usage) =
            norito::core::with_decode_limits_measured(limits(ample), || {
                History::test_validation_work(4, || {
                    head.test_require_predecessor_binding(Some(pass))
                })
            });
        current?;
        assert_eq!((work.visits, work.native_tree_visits), (4, 0));
        assert!(usage.total_allocated_bytes() > 1 && usage.total_allocated_bytes() <= ample);
        for capacity in [0, 1] {
            let mut refused = Vec::new();
            for admitted in [None, Some(pass)] {
                let (current, usage) =
                    norito::core::with_decode_limits_measured(limits(capacity), || {
                        head.test_require_predecessor_binding(admitted)
                    });
                refused.push((
                    current
                        .err()
                        .expect("late active owner must use its physical recipe")
                        .to_string(),
                    usage.total_allocated_bytes(),
                ));
            }
            assert_eq!(refused[0], refused[1]);
        }
        Ok(())
    })
    .unwrap();
    head.test_closure_phase_late_active(&inspect).unwrap();
    evidence.unchanged();
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn native_closure_phase_closes_callback_mutation_and_error_before_any_effect() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let head = history.current_history().unwrap();
    let original = history.bodies[1].original.as_ref().unwrap();
    let successor = history.successor(1).unwrap().unwrap();
    let account = fixture.owner.wallet().unwrap();
    let evidence = Evidence::capture(&history);
    let mut inspect = NativeClosureInspector::new(original, &account, fixture.options.deadline);
    let (baseline, _, _, _) = run(
        head.test_owned_predecessor_closure_history().unwrap(),
        &successor,
        &mut inspect,
        true,
        None,
    );
    let baseline = complete(baseline);

    for name in ["original.nrt", "dispatch.nrt", "closing.nrt", "closed.nrt"] {
        for ordinary_error in [false, true] {
            let changed = Rc::new(RefCell::new(None));
            let saved = Rc::clone(&changed);
            let oldest = Arc::clone(&history.bodies[0].directory);
            let hook: Hook = Box::new(move |ordinal, _, value| {
                assert!(
                    value.is_ok(),
                    "the mutation follows actual native wallet admission"
                );
                if ordinal == 1 {
                    *saved.borrow_mut() = Some(ChangedRecord::replace(&oldest, name));
                    if ordinary_error {
                        return Err(invalid("ordinary native inspector refusal"));
                    }
                }
                Ok(())
            });
            let (result, calls, _, _) = run(
                head.test_owned_predecessor_closure_history().unwrap(),
                &successor,
                &mut inspect,
                true,
                Some(hook),
            );
            let error = result
                .err()
                .expect("persistent oldest source change must close the phase");
            assert!(changed.borrow().is_some());
            assert_eq!(calls.native, if ordinary_error { 1 } else { 2 });
            assert_ne!(
                error.to_string(),
                invalid("ordinary native inspector refusal").to_string()
            );
            drop(changed.borrow_mut().take());
            evidence.unchanged();
        }
    }

    let (ordinary, calls, _, _) = run(
        head.test_owned_predecessor_closure_history().unwrap(),
        &successor,
        &mut inspect,
        true,
        Some(Box::new(|_, _, _| {
            Err(invalid("ordinary native inspector refusal"))
        })),
    );
    assert_eq!(calls.native, 1);
    assert_eq!(
        ordinary.err().unwrap().to_string(),
        invalid("ordinary native inspector refusal").to_string()
    );

    // Both callbacks still perform fresh wallet readback. Corrupting the exact terminal
    // record after the first read must fail the second native inspection, not reuse status.
    let changed = Rc::new(RefCell::new(None));
    let saved = Rc::clone(&changed);
    let hook: Hook = Box::new(move |ordinal, attempt, value| {
        if ordinal == 1 {
            assert!(value.is_ok());
            let wallet = Arc::new(
                attempt
                    .directory()
                    .open_child_optional("transaction")
                    .unwrap()
                    .unwrap(),
            );
            *saved.borrow_mut() = Some(ChangedRecord::replace(&wallet, "retired.json"));
        } else {
            assert!(
                value.is_err(),
                "fresh second native read must see changed retirement"
            );
        }
        Ok(())
    });
    let (result, calls, _, _) = run(
        head.test_owned_predecessor_closure_history().unwrap(),
        &successor,
        &mut inspect,
        true,
        Some(hook),
    );
    assert!(result.is_err());
    assert_eq!(
        calls,
        Calls {
            native: 2,
            retired: 1
        }
    );
    drop(changed.borrow_mut().take());
    evidence.unchanged();

    // This lexical owner is sampled, not atomic: an older immutable sibling changed
    // after entry and restored before exit is intentionally deferred. The literal
    // standalone verifier observes the intermediate change at its earlier full census.
    for native in [false, true] {
        let changed = Rc::new(RefCell::new(None));
        let saved = Rc::clone(&changed);
        let oldest = Arc::clone(&history.bodies[0].directory);
        let hook: Hook = Box::new(move |ordinal, _, value| {
            assert!(value.is_ok());
            if ordinal == 1 {
                *saved.borrow_mut() = Some(ChangedRecord::replace(&oldest, "original.nrt"));
            } else {
                drop(saved.borrow_mut().take());
            }
            Ok(())
        });
        let (result, calls, _, _) = run(
            head.test_owned_predecessor_closure_history().unwrap(),
            &successor,
            &mut inspect,
            native,
            Some(hook),
        );
        if native {
            assert_eq!(calls.native, 2);
            same_receipt(&complete(result), &baseline);
        } else {
            assert_eq!(calls.native, 1);
            assert!(result.is_err());
        }
        drop(changed.borrow_mut().take());
        evidence.unchanged();
    }

    #[cfg(unix)]
    {
        // Old native ancestor identity still closes every ordinary result, including
        // an inspector error. The current attempt is revalidated immediately instead.
        for current in [false, true] {
            for ordinary_error in [false, true] {
                let replacement = Rc::new(RefCell::new(None));
                let saved = Rc::clone(&replacement);
                let oldest = history.bodies[0].directory.path().to_owned();
                let hook: Hook = Box::new(move |ordinal, attempt, value| {
                    assert!(value.is_ok());
                    if ordinal == 1 {
                        let path = if current {
                            attempt.directory().path()
                        } else {
                            oldest.as_path()
                        };
                        *saved.borrow_mut() = Some(ReplacedDirectory::replace(path));
                        if ordinary_error {
                            return Err(invalid("ordinary native inspector refusal"));
                        }
                    }
                    Ok(())
                });
                let (result, calls, _, _) = run(
                    head.test_owned_predecessor_closure_history().unwrap(),
                    &successor,
                    &mut inspect,
                    true,
                    Some(hook),
                );
                let error = result.err().expect("replaced original handle must refuse");
                if current || ordinary_error {
                    assert_eq!(calls.native, 1);
                } else {
                    // A native ancestry check may reject a replaced sibling sooner
                    // than the final graph fence; either original refusal is valid.
                    assert!((1..=2).contains(&calls.native));
                }
                assert_ne!(
                    error.to_string(),
                    invalid("ordinary native inspector refusal").to_string()
                );
                drop(replacement.borrow_mut().take());
                evidence.unchanged();
            }
        }
    }
    let (retried, calls, _, _) = run(
        head.test_owned_predecessor_closure_history().unwrap(),
        &successor,
        &mut inspect,
        true,
        None,
    );
    same_receipt(&complete(retried), &baseline);
    assert_eq!(
        calls,
        Calls {
            native: 2,
            retired: 2
        }
    );
    evidence.unchanged();
    assert_eq!(fixture.native.chain.height(), 4);
}
