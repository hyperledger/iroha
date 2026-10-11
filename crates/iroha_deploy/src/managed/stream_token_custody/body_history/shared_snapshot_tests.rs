//! Real retained snapshots bound graph work while preserving original custody and decode refusal.

use super::*;
use crate::managed::stream_token_custody::{
    bootstrap_test_support::NativeEnrollmentReads,
    renewal_tests::{Fixture, wait_until},
};
use std::{cell::Cell, time::Duration};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    records: usize,
    snapshots: usize,
}
std::thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
pub(super) fn record_read() {
    COUNTS.with(|state| {
        if let Some(mut counts) = state.get() {
            counts.records += 1;
            state.set(Some(counts));
        }
    });
}
pub(super) fn snapshot_visit() {
    COUNTS.with(|state| {
        if let Some(mut counts) = state.get() {
            counts.snapshots += 1;
            state.set(Some(counts));
        }
    });
}
fn counted<T>(action: impl FnOnce() -> T) -> (T, Counts) {
    struct Restore(Option<Counts>);
    impl Drop for Restore {
        fn drop(&mut self) {
            COUNTS.with(|state| state.set(self.0));
        }
    }
    let _restore = Restore(COUNTS.with(|state| state.replace(Some(Counts::default()))));
    let result = action();
    let counts = COUNTS.with(|state| state.get().unwrap());
    (result, counts)
}

// Two genuine signed bodies, one naturally expired and canonically retired request, and
// unchanged native custody. No forged History, proof, signature or synthetic expiry clock.
pub(super) fn history() -> (Fixture, BodyHistory) {
    history_with_bodies(2)
}

pub(super) fn history_with_bodies(count: usize) -> (Fixture, BodyHistory) {
    assert!((2..=3).contains(&count), "small genuine parser fixture");
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let mut retained: Option<BodyHistory> = None;
    for ordinal in 1..=count {
        if let Some(history) = retained.as_ref() {
            wait_until(
                history
                    .bodies
                    .last()
                    .unwrap()
                    .reservation
                    .unsigned
                    .statement
                    .expires_at_unix_ms,
                Duration::from_secs(10),
            );
        }
        drop(retained.take());
        let mut turn = fixture.renewal_turn();
        let (checkpoint, current) = fixture.current();
        let (finished, authorization) = if ordinal > 1 {
            let previous = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
                .unwrap()
                .unwrap();
            let authorization = turn
                .authorize_retained(&fixture.owner, &previous, fixture.options.deadline)
                .unwrap();
            let terms = Terms::new(now_ms().unwrap() + 8_000, &fixture.options).unwrap();
            let unsigned = fixture
                .owner
                .select_renewal_unsigned(
                    2,
                    &fixture.policy,
                    &current,
                    &checkpoint,
                    &terms,
                    fixture.options.deadline,
                )
                .unwrap();
            let selected = previous
                .reserve_successor(
                    &fixture.owner,
                    unsigned,
                    &current,
                    authorization,
                    fixture.options.deadline,
                )
                .unwrap();
            let finished = selected
                .finish_pending_with_reads(
                    &fixture.owner,
                    &current,
                    &SigningTurn::Generated(authorization),
                    fixture.options.deadline,
                    &NativeEnrollmentReads(&fixture.native),
                )
                .unwrap();
            (finished, authorization)
        } else {
            let terms = Terms::new(now_ms().unwrap() + 8_000, &fixture.options).unwrap();
            let unsigned = fixture
                .owner
                .select_renewal_unsigned(
                    2,
                    &fixture.policy,
                    &current,
                    &checkpoint,
                    &terms,
                    fixture.options.deadline,
                )
                .unwrap();
            let selected = BodyHistory::initialize(
                &fixture.owner,
                CustodyPurpose::Renewal(2),
                unsigned,
                &Fees::from_options(&fixture.options).unwrap(),
                &SigningTurn::RenewalSelection(&turn),
                fixture.options.deadline,
            )
            .unwrap();
            let authorization = turn
                .authorize_retained(&fixture.owner, &selected, fixture.options.deadline)
                .unwrap();
            let finished = selected
                .finish_pending_with_reads(
                    &fixture.owner,
                    &current,
                    &SigningTurn::Generated(authorization),
                    fixture.options.deadline,
                    &NativeEnrollmentReads(&fixture.native),
                )
                .unwrap();
            (finished, authorization)
        };
        assert!(finished.original().unwrap().is_some());
        if ordinal < count {
            let selected = fixture
                .retain_generated_attempt(authorization, &finished, &current)
                .unwrap();
            assert!(
                !selected
                    .directory()
                    .path()
                    .join("transaction/payload.json")
                    .exists()
            );
        }
        drop(turn);
        retained = Some(finished.reopen(&fixture.owner).unwrap());
    }
    (fixture, retained.unwrap())
}

#[test]
fn genuine_graph_snapshot_pass_bounds_reads_and_preserves_mutation_and_decode_refusals() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = history();
    assert_eq!(history.bodies.len(), 2);
    assert_eq!(fixture.native.chain.height(), 4);
    let native = history.current_history().unwrap();
    let ((result, census), work) = counted(|| native.test_require_current(4));
    result.unwrap();
    assert_eq!(census.visits, 4);
    assert_eq!(census.distinct_histories, 2);
    assert_eq!(census.native_tree_visits, 4);
    // Two whole-head reads bracket the complete forward/reverse pair. Both mutable
    // directions still visit every History and retain their separate native brackets.
    // Each head contains three root records plus four records for each genuine body.
    assert_eq!(work.records, 2 * (3 + 4 * history.bodies.len()));
    assert_eq!(work.snapshots, 2 * (2 + history.bodies.len()));

    // A persistent immutable change between directions must lose to the final full
    // snapshot fence, both after successful reverse traversal and after ordinary error.
    let anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    for refuse_between_directions in [false, true] {
        let root = Arc::clone(&history.root);
        let mut changed = anchor.to_vec();
        changed[0] ^= 1;
        let (result, census) = native.test_require_current_after_forward(4, move || {
            root.write_atomic("anchor.nrt", &changed, PublishMode::Replace)?;
            if refuse_between_directions {
                Err(invalid("inner graph direction refused"))
            } else {
                Ok(())
            }
        });
        history
            .root
            .write_atomic("anchor.nrt", &anchor, PublishMode::Replace)
            .unwrap();
        assert_eq!(census.visits, if refuse_between_directions { 2 } else { 4 });
        assert_eq!(census.native_tree_visits, census.visits);
        assert!(
            matches!(result, Err(crate::managed::Error::Invalid(message))
            if message == "retained enrollment body material changed")
        );
        native.test_require_current(4).0.unwrap();
    }

    let evidence = native.test_enrollment_evidence().unwrap();
    let reopened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    let foreign = reopened
        .current_history()
        .unwrap()
        .test_enrollment_evidence()
        .unwrap();
    evidence
        .with_snapshot_read_pass(&mut |pass| {
            let pass = pass.unwrap();
            assert!(pass.covers(&history.bodies[0].snapshots));
            assert!(pass.covers(&history.bodies[1].snapshots));
            assert!(!pass.covers(&reopened.bodies[1].snapshots));
            let (result, work) = counted(|| foreign.revalidate_with_snapshot_read_pass(Some(pass)));
            result?;
            assert_eq!(work.records, 3 + 4 * reopened.bodies.len());
            // A nested decode owner cannot inherit a token created outside its budget.
            let limits = norito::DecodeLimits::new(
                MAX_BODY_BYTES,
                MAX_ALL_BODY_BYTES,
                MAX_ALL_BODY_BYTES,
                512 * 1024 * 1024,
                64,
            );
            let (result, nested) = counted(|| {
                norito::core::with_decode_limits_scope(limits, || {
                    assert!(!pass.covers(&history.bodies[1].snapshots));
                    evidence.revalidate_with_snapshot_read_pass(Some(pass))
                })
            });
            result?;
            assert_eq!(nested.records, 3 + 4 * history.bodies.len());
            Ok(())
        })
        .unwrap();
    drop(reopened);

    // The production graph's actual native bracket closes on every ordinary result.
    // Exercise the same genuine owners, then restore them before the original graph tests.
    native
        .test_native_read_tree(|tree| {
            let tree = tree.expect("ordinary graph owns native ancestry");
            let native_error = tree.read_scope(&history.bodies[0].directory, |reader| {
                reader.read("original.nrt", 1, |_| ())
            });
            assert!(native_error.is_err());
            Ok(())
        })
        .unwrap();
    let wide_tree = norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        512 * 1024 * 1024,
        64,
    );
    norito::core::with_decode_limits_scope(wide_tree, || {
        native.test_native_read_tree(|tree| {
            assert!(tree.is_none());
            Ok(())
        })
    })
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for outcome in ["success", "absence", "semantic_error"] {
            let result = native.test_native_read_tree(|tree| {
                let tree = tree.unwrap();
                let absent = tree.read_scope(&history.bodies[0].directory, |reader| {
                    reader.read_optional("missing-test-record", 1, |_| ())
                })?;
                assert!(absent.is_none());
                std::fs::set_permissions(
                    history.root.path(),
                    std::fs::Permissions::from_mode(0o777),
                )?;
                match outcome {
                    "success" => Ok(Some(())),
                    "absence" => Ok(None),
                    _ => Err(invalid("inner native graph observation failed")),
                }
            });
            assert!(result.is_err());
            assert!(
                !matches!(result, Err(crate::managed::Error::Invalid(message))
                if message == "inner native graph observation failed")
            );
            std::fs::set_permissions(history.root.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            native.test_require_current(4).0.unwrap();
        }
        let oldest = &history.bodies[0].directory;
        let path = oldest.path().to_owned();
        let held = fixture._temporary.path().join("held-oldest-native-tree");
        let result = native.test_native_read_tree(|tree| {
            tree.unwrap().read_scope(oldest, |reader| {
                reader.read("closed.nrt", attempts::MAX_RECORD_BYTES, |_| ())?;
                std::fs::rename(&path, &held)?;
                std::fs::create_dir(&path)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                Err::<(), _>(invalid("inner native graph suffix failed"))
            })
        });
        assert!(result.is_err());
        assert!(
            !matches!(result, Err(crate::managed::Error::Invalid(message))
            if message == "inner native graph suffix failed")
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&held, &path).unwrap();
        native.test_require_current(4).0.unwrap();
    }

    let oldest = &history.bodies[0].directory;
    let original = oldest
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let mut changed = original.to_vec();
    changed[0] ^= 1;
    let error = evidence.with_snapshot_read_pass(&mut |pass| {
        assert!(pass.is_some());
        oldest.write_atomic("original.nrt", &changed, PublishMode::Replace)?;
        Err(invalid("inner observation failed"))
    });
    assert!(matches!(error, Err(crate::managed::Error::Invalid(message))
        if message == "retained enrollment body material changed"));
    assert!(evidence.revalidate().is_err()); // No verdict survives the closed lexical pass.
    oldest
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    evidence.revalidate().unwrap();
    native.test_require_current(4).0.unwrap();

    // Closure records are not snapshot memoization candidates: original native metadata
    // and receipt verification must still refuse a changed oldest closed transition.
    let closed = oldest
        .read("closed.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let mut changed = closed.to_vec();
    changed[0] ^= 1;
    oldest
        .write_atomic("closed.nrt", &changed, PublishMode::Replace)
        .unwrap();
    assert!(native.test_require_current(4).0.is_err());
    oldest
        .write_atomic("closed.nrt", &closed, PublishMode::Replace)
        .unwrap();
    native.test_require_current(4).0.unwrap();

    // The reverse direction also rereads mutable predecessor closure bytes after a
    // successful forward census; the immutable snapshot pass cannot hide this change.
    let target = Arc::clone(oldest);
    let mut changed_closed = closed.to_vec();
    changed_closed[0] ^= 1;
    let (result, census) = native.test_require_current_after_forward(4, move || {
        target.write_atomic("closed.nrt", &changed_closed, PublishMode::Replace)?;
        Ok(())
    });
    oldest
        .write_atomic("closed.nrt", &closed, PublishMode::Replace)
        .unwrap();
    assert!(result.is_err());
    assert!(
        census.visits > 2,
        "reverse census must run after the mutation"
    );
    assert_eq!(census.native_tree_visits, census.visits);
    native.test_require_current(4).0.unwrap();

    let wide = norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        512 * 1024 * 1024,
        64,
    );
    let ((result, census), active) =
        counted(|| norito::core::with_decode_limits_scope(wide, || native.test_require_current(4)));
    result.unwrap();
    assert_eq!(census.visits, 4);
    assert_eq!(census.native_tree_visits, 0);
    // The active owner retains the complete old recipe: each History's local census
    // checks its whole snapshot prefix before and after, in both graph traversals.
    assert_eq!(active.records, 4 * ((3 + 4) + (3 + 8)));
    assert!(active.records > work.records);
    for allocation in [0, 1] {
        let limits = norito::DecodeLimits::new(
            MAX_BODY_BYTES,
            MAX_ALL_BODY_BYTES,
            MAX_ALL_BODY_BYTES,
            allocation,
            64,
        );
        assert!(
            norito::core::with_decode_limits_scope(limits, || native.test_require_current(4).0)
                .is_err()
        );
    }
    native.test_require_current(4).0.unwrap();
    assert_eq!(
        oldest
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
    assert_eq!(
        oldest
            .read("closed.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        closed
    );

    #[cfg(unix)]
    {
        let path = oldest.path().to_owned();
        let held = fixture._temporary.path().join("held-oldest-snapshot");
        let result = evidence.with_snapshot_read_pass(&mut |_| {
            std::fs::rename(&path, &held)?;
            let replacement = PrivateDirectory::open_or_create(&path)?;
            replacement.write_atomic("original.nrt", &original, PublishMode::CreateNew)?;
            Ok(())
        });
        assert!(result.is_err());
        std::fs::remove_file(path.join("original.nrt")).unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&held, &path).unwrap();
        native.test_require_current(4).0.unwrap();
    }
}

#[test]
fn genuine_parser_pass_bounds_prefix_rechecks_and_closes_persistent_errors() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = history();
    let native = history.current_history().unwrap();
    let ((parsed, optimized), optimized_reads) = counted(|| {
        History::test_validation_work(128, || {
            BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        })
    });
    let parsed = parsed.unwrap().unwrap();
    let wide = norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        512 * 1024 * 1024,
        64,
    );
    let ((full, original), original_reads) = counted(|| {
        History::test_validation_work(256, || {
            norito::core::with_decode_limits_scope(wide, || {
                BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
            })
        })
    });
    let full = full.unwrap().unwrap();
    assert_eq!(parsed.bodies.len(), 2);
    assert_eq!(full.bodies.len(), 2);
    assert!(optimized.visits < original.visits);
    assert_eq!(optimized.native_tree_visits, optimized.visits);
    assert_eq!(original.native_tree_visits, 0);
    assert!(optimized_reads.records < original_reads.records);
    // The complete two-body parser, including its final retained graph checks, must
    // stay within a fixed number of local censuses per body and full snapshot reads.
    assert!(optimized.visits <= 12 * parsed.bodies.len());
    assert!(optimized_reads.records <= 12 * (3 + 4 * parsed.bodies.len()));
    assert_eq!(
        parsed.selection.digest().unwrap(),
        full.selection.digest().unwrap()
    );
    for (actual, expected) in parsed.bodies.iter().zip(&full.bodies) {
        assert_eq!(actual.semantic, expected.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
    }

    let snapshot = SnapshotReadPass {
        head: &history.bodies.last().unwrap().snapshots,
    };
    EnrollmentReadPass::run(&snapshot, |pass| {
        pass.test_retain_predecessor(native)?;
        let (result, work) = History::test_validation_work(4, || pass.test_validate(native));
        result?;
        assert_eq!(work.visits, 1);
        assert_eq!(work.native_tree_visits, 1);
        // Equal bytes reopened from the same path do not share a retained predecessor.
        let foreign = parsed.current_history().unwrap();
        let (result, work) = History::test_validation_work(4, || pass.test_validate(foreign));
        result?;
        assert_eq!(work.visits, 4);
        assert_eq!(work.native_tree_visits, 4);
        let (result, work) = History::test_validation_work(4, || {
            norito::core::with_decode_limits_scope(wide, || pass.test_validate(native))
        });
        result?;
        assert_eq!(work.visits, 4);
        assert_eq!(work.native_tree_visits, 0);
        for allocation in [0, 1] {
            let limits = norito::DecodeLimits::new(
                MAX_BODY_BYTES,
                MAX_ALL_BODY_BYTES,
                MAX_ALL_BODY_BYTES,
                allocation,
                64,
            );
            let (result, work) = History::test_validation_work(4, || {
                norito::core::with_decode_limits_scope(limits, || pass.test_validate(native))
            });
            assert!(result.is_err());
            assert_eq!(work.native_tree_visits, 0);
        }
        Ok(())
    })
    .unwrap();

    // A successful local census grants no retained source verdict. The same genuine
    // parser must reread namespace and semantic bytes on its very next local check.
    let current = &history.bodies.last().unwrap().directory;
    let original = current
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    for change in ["namespace", "semantic"] {
        EnrollmentReadPass::run(&snapshot, |pass| {
            pass.test_retain_predecessor(native)?;
            pass.test_validate(native)?;
            if change == "namespace" {
                current.write_atomic("foreign.nrt", b"foreign", PublishMode::CreateNew)?;
            } else {
                current.write_atomic("original.nrt", b"changed original", PublishMode::Replace)?;
            }
            let (result, work) = History::test_validation_work(4, || pass.test_validate(native));
            // Restore before asserting so the pass can close its genuine original prefix.
            if change == "namespace" {
                std::fs::remove_file(current.path().join("foreign.nrt"))?;
            } else {
                current.write_atomic("original.nrt", &original, PublishMode::Replace)?;
            }
            assert!(matches!(result, Err(crate::managed::Error::Invalid(_))));
            assert_eq!(work.visits, 1);
            assert_eq!(work.native_tree_visits, 1);
            pass.test_validate(native)
        })
        .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let result = EnrollmentReadPass::run(&snapshot, |pass| {
            pass.test_retain_predecessor(native)?;
            pass.test_validate(native)?;
            std::fs::set_permissions(history.root.path(), std::fs::Permissions::from_mode(0o755))?;
            Err::<(), _>(invalid("inner parser-local observation failed"))
        });
        std::fs::set_permissions(history.root.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert!(matches!(result, Err(crate::managed::Error::Io(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied));
        native.test_require_current(4).0.unwrap();
    }
    assert_eq!(
        current
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
    assert!(!current.path().join("foreign.nrt").exists());

    let oldest = &history.bodies[0].directory;
    let closed = oldest
        .read("closed.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let mut changed = closed.to_vec();
    changed[0] ^= 1;
    let result = EnrollmentReadPass::run(&snapshot, |pass| {
        pass.test_retain_predecessor(native)?;
        oldest.write_atomic("closed.nrt", &changed, PublishMode::Replace)?;
        Err::<(), _>(invalid("inner parser observation failed"))
    });
    assert!(result.is_err());
    assert!(
        !matches!(result, Err(crate::managed::Error::Invalid(message))
        if message == "inner parser observation failed")
    );
    oldest
        .write_atomic("closed.nrt", &closed, PublishMode::Replace)
        .unwrap();
    native.test_require_current(4).0.unwrap();

    #[cfg(unix)]
    {
        let path = oldest.path().to_owned();
        let held = fixture._temporary.path().join("held-oldest-parser");
        let result = EnrollmentReadPass::run(&snapshot, |pass| {
            pass.test_retain_predecessor(native)?;
            std::fs::rename(&path, &held)?;
            let replacement = PrivateDirectory::open_or_create(&path)?;
            replacement.write_atomic("closed.nrt", &closed, PublishMode::CreateNew)?;
            Ok(())
        });
        assert!(result.is_err());
        std::fs::remove_file(path.join("closed.nrt")).unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&held, &path).unwrap();
        native.test_require_current(4).0.unwrap();
    }
    assert_eq!(
        oldest
            .read("closed.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        closed
    );
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn genuine_retained_handle_graph_shares_only_original_ancestry_and_closes_errors() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = history();
    let native = history.current_history().unwrap();
    let oldest = native.test_oldest_retained_history();
    assert_eq!(history.bodies.len(), 2);
    assert_eq!(native.reserved_attempt_count(), 0);
    assert_eq!(oldest.reserved_attempt_count(), 1);

    // These counters observe the actual handle walkers, not mutable-record validation.
    // They count native census recipes and ordered targets, not operating-system syscalls.
    let (result, shared) = native.test_retained_handle_census();
    result.unwrap();
    assert_eq!(shared.history_order.len(), 2);
    assert_eq!(shared.descendant_order.len(), 2); // Oldest attempt container and attempt.
    assert_eq!(shared.tree_brackets, 1);
    assert_eq!(shared.full_operations, 0);
    assert_eq!(shared.tree_operations, 2);
    assert_eq!(shared.operation_exits, 2);
    let (result, single) = oldest.test_retained_handle_census();
    result.unwrap();
    assert_eq!(single.history_order.len(), 1);
    assert_eq!(single.tree_brackets, 0);
    assert_eq!(single.full_operations, 1);
    assert_eq!(single.tree_operations, 0);
    assert_eq!(single.operation_exits, 0);
    for allocation in [0, 1, 512 * 1024 * 1024] {
        let limits = norito::DecodeLimits::new(
            MAX_BODY_BYTES,
            MAX_ALL_BODY_BYTES,
            MAX_ALL_BODY_BYTES,
            allocation,
            64,
        );
        let (result, original) =
            norito::core::with_decode_limits_scope(limits, || native.test_retained_handle_census());
        result.unwrap(); // Handle custody grants no decoder admission.
        assert_eq!(original.history_order, shared.history_order);
        assert_eq!(original.descendant_order, shared.descendant_order);
        assert_eq!(original.tree_brackets, 0);
        assert_eq!(original.full_operations, 2);
        assert_eq!(original.tree_operations, 0);
        assert_eq!(original.operation_exits, 0);
        if allocation <= 1 {
            assert!(
                norito::core::with_decode_limits_scope(limits, || {
                    native.test_require_current(4).0
                })
                .is_err()
            );
        }
    }

    let (result, refused) = native.test_retained_handles_after_descendants(|| {
        Err(invalid("inner retained handle census refused"))
    });
    assert!(
        matches!(result, Err(crate::managed::Error::Invalid(message))
        if message == "inner retained handle census refused")
    );
    assert_eq!(refused.history_order.len(), 1);
    assert_eq!(refused.operation_exits, 1);
    native.test_retained_handle_census().0.unwrap();

    // Successful handle custody must never suppress the later canonical source check.
    let attempt = oldest.last().unwrap();
    let original = attempt
        .directory()
        .read("authorization.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    attempt
        .directory()
        .write_atomic("authorization.nrt", b"changed record", PublishMode::Replace)
        .unwrap();
    let handles = native.test_retained_handle_census().0;
    let records = native.test_require_current(4).0;
    attempt
        .directory()
        .write_atomic("authorization.nrt", &original, PublishMode::Replace)
        .unwrap();
    handles.unwrap();
    assert!(records.is_err());
    native.test_require_current(4).0.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Each operation must close after its descendants, and the distinct original
        // enrollment root must also close after an ordinary inner refusal.
        for target in [
            Arc::clone(&history.bodies[1].directory),
            Arc::clone(&history.root),
        ] {
            let changed = Arc::clone(&target);
            let permissions = std::fs::metadata(target.path()).unwrap().permissions();
            let (result, census) = native.test_retained_handles_after_descendants(move || {
                std::fs::set_permissions(changed.path(), std::fs::Permissions::from_mode(0o755))?;
                Err(invalid("inner retained handle census refused"))
            });
            std::fs::set_permissions(target.path(), permissions).unwrap();
            assert!(matches!(result, Err(crate::managed::Error::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied));
            assert_eq!(census.history_order.len(), 1);
            assert_eq!(census.operation_exits, 1);
            native.test_retained_handle_census().0.unwrap();
        }

        // The next predecessor still checks its original attempt handle after the first
        // node completes. Same-path replacement never inherits the original native owner.
        let path = attempt.directory().path().to_path_buf();
        let saved = fixture
            ._temporary
            .path()
            .join("held-retained-handle-attempt");
        let change_path = path.clone();
        let change_saved = saved.clone();
        let (result, census) = native.test_retained_handles_after_descendants(move || {
            std::fs::rename(&change_path, &change_saved)?;
            let replacement = PrivateDirectory::open_or_create(&change_path)?;
            drop(replacement);
            Ok(())
        });
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        assert!(result.is_err());
        assert_eq!(census.history_order.len(), 2);
        assert_eq!(census.descendant_order, shared.descendant_order);
        assert_eq!(census.operation_exits, 2);
        native.test_retained_handle_census().0.unwrap();

        let reopened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
            .unwrap()
            .unwrap();
        let foreign = reopened.current_history().unwrap();
        let permissions = std::fs::metadata(history.root.path())
            .unwrap()
            .permissions();
        let result = native.test_native_read_tree(|tree| {
            std::fs::set_permissions(history.root.path(), std::fs::Permissions::from_mode(0o755))?;
            let result = foreign.revalidate_retained_handles_in_tree(tree);
            // Restore before the outer anchor exits: refusal must come from the foreign
            // owner's full ancestry fallback, not merely the common closing root fence.
            std::fs::set_permissions(history.root.path(), permissions)?;
            result
        });
        assert!(matches!(result, Err(crate::managed::Error::Io(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied));
        foreign.revalidate_retained_handles().unwrap();
        native.test_retained_handle_census().0.unwrap();
    }
    assert_eq!(
        attempt
            .directory()
            .read("authorization.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    native.test_require_current(4).0.unwrap();
}

pub(super) fn snapshot_work<T>(read: impl FnOnce() -> T) -> (T, (usize, usize)) {
    let (result, counts) = counted(read);
    (result, (counts.records, counts.snapshots))
}
