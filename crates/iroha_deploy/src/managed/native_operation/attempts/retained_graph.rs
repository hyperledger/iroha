//! Bounded borrowed revalidation of the original retained enrollment predecessor graph.
//!
//! No memoized result survives a call. Both passes read the same live native custody; local
//! History checks cannot descend recursively and no historical owner or receipt is discarded.
use super::*;
use crate::managed::stream_token_custody::body_history::SnapshotReadPass;
#[cfg(test)]
use crate::managed::stream_token_custody::body_history::finish_timing;

// The sole enrollment body owner admits at most 64 bodies, including this selected body.
// This is a graph traversal bound, separate from its cumulative paid reservation count.
const MAX_RETAINED_BODIES: usize = 64;

// Minted only by the closed graph traversal below, never by the parser pass.
// No callback, effect or returned receipt may retain this borrowed immutable coverage.
pub(super) struct OriginalReadPass<'pass, 'snapshot> {
    snapshot: &'pass SnapshotReadPass<'snapshot>,
}
impl OriginalReadPass<'_, '_> {
    pub(super) fn covers(&self, history: &History) -> bool {
        #[cfg(test)]
        if crate::managed::stream_token_custody::body_history::graph_original_tests::original_recipe(
        ) {
            return false;
        }
        if norito::core::decode_limits_active() {
            return false;
        }
        let covered = history.scope.covers_semantic_original(
            self.snapshot,
            &history.operation,
            history.purpose,
            history.semantic,
        );
        #[cfg(test)]
        if covered {
            crate::managed::stream_token_custody::body_history::graph_original_tests::record_covered();
        }
        covered
    }
}

// Borrowed only inside one closed callback-free graph direction. Its original directory
// is the exact object behind the enrollment root Arc, not a pathname or inode-equivalence key.
// No reader, scope or freshness result can escape the native root's ordinary-result exit.
pub(in crate::managed) struct GraphRootReadPass<'borrow, 'scope> {
    root: &'borrow PrivateDirectory,
    reader: &'borrow mut iroha_fs::PrivateReadScope<'scope>,
}
impl GraphRootReadPass<'_, '_> {
    pub(in crate::managed) fn covers(&self, root: &PrivateDirectory) -> bool {
        !norito::core::decode_limits_active() && std::ptr::eq(self.root, root)
    }
    pub(in crate::managed) fn read<T>(
        &mut self,
        read: impl FnOnce(&mut iroha_fs::PrivateReadScope<'_>) -> Result<T>,
    ) -> Result<T> {
        #[cfg(test)]
        crate::managed::stream_token_custody::body_history::graph_root_scope_tests::record(
            crate::managed::stream_token_custody::body_history::graph_root_scope_tests::Point::SharedInventory,
        );
        read(self.reader)
    }
}

// Each direction keeps its own existing tree bracket. This additional root read bracket
// replaces repeated full-ancestry checks for that same anchor, never its native inventories.
// Body/attempt suffix checks, leaf reads/decodes, permissions, identity and absence are intact.
// Root custody closes on every ordinary result before the outer tree/snapshot exits; its
// refusal wins an inner semantic error. A root change wholly restored within this read-only
// direction may be unseen. This is not atomic, retained authority or a scope across effects.
fn with_graph_root<T>(
    current: &History,
    snapshot: Option<&SnapshotReadPass<'_>>,
    read: impl FnOnce(Option<&mut GraphRootReadPass<'_, '_>>) -> Result<T>,
) -> Result<T> {
    #[cfg(test)]
    let original =
        crate::managed::stream_token_custody::body_history::graph_root_scope_tests::original_recipe(
        );
    #[cfg(not(test))]
    let original = false;
    if original || snapshot.is_none() || norito::core::decode_limits_active() {
        return read(None);
    }
    let root = current.scope.enrollment()?.root();
    root.read_scope(|reader| {
        #[cfg(test)]
        crate::managed::stream_token_custody::body_history::graph_root_scope_tests::record(
            crate::managed::stream_token_custody::body_history::graph_root_scope_tests::Point::DirectionBracket,
        );
        read(Some(&mut GraphRootReadPass { root, reader }))
    })
}

pub(super) fn validate(current: &History) -> Result<()> {
    validate_bounded(current, MAX_RETAINED_BODIES, None, false)
}

// A standalone body scope reserves one graph slot for its own not-yet-read History.
pub(super) fn validate_predecessor(prior: &VerifiedUnsignedClosure) -> Result<()> {
    validate_bounded(
        prior.retained_history(),
        MAX_RETAINED_BODIES - 1,
        None,
        false,
    )?;
    prior.require_receipt()
}

// Only a surrounding sealed native read owner lends this snapshot; every mutable graph
// direction and its independent native root/tree exits still execute. The existing semantic
// witness is stronger than required: it proves exact Snapshot membership and original body
// layout/identity. Foreign, unrecognized and late-active inputs retain the standalone recipe.
pub(super) fn validate_in_snapshot(
    current: &History,
    snapshot: &SnapshotReadPass<'_>,
) -> Result<()> {
    validate_bounded(current, MAX_RETAINED_BODIES, Some(snapshot), false)
}
pub(super) fn validate_predecessor_in_snapshot(
    prior: &VerifiedUnsignedClosure,
    snapshot: &SnapshotReadPass<'_>,
) -> Result<()> {
    validate_bounded(
        prior.retained_history(),
        MAX_RETAINED_BODIES - 1,
        Some(snapshot),
        false,
    )?;
    prior.require_receipt()
}
// Only the sealed native read phases construct this owner. Entry retains both original
// predecessor directions before the first callback. The owned scope keeps the exact old
// predecessor Arcs alive even when a canonical refresh replaces the current History.
// No native read bracket, authorization result or freshness result crosses the phase body.
pub(super) struct ReadPhaseGraph<'pass, 'snapshot> {
    scope: HistoryScope,
    purpose: Purpose,
    semantic: [u8; 32],
    snapshot: &'pass SnapshotReadPass<'snapshot>,
}
impl<'pass, 'snapshot> ReadPhaseGraph<'pass, 'snapshot> {
    pub(super) fn enter(
        history: &History,
        snapshot: &'pass SnapshotReadPass<'snapshot>,
        _native: &crate::managed::stream_token_custody::body_history::NativeClosureInspector<'_>,
    ) -> Result<Self> {
        history.revalidate_retained_handles()?;
        if let Some(prior) = history.scope.predecessor() {
            validate_predecessor_in_snapshot(prior, snapshot)?;
        }
        Ok(Self {
            scope: history.scope.retained_copy(),
            purpose: history.purpose,
            semantic: history.semantic,
            snapshot,
        })
    }

    pub(super) fn close(
        self,
        current: &History,
        head_admitted: bool,
        read_succeeded: bool,
    ) -> Result<()> {
        if !self.scope.same_original_owner(&current.scope)
            || self.purpose != current.purpose
            || self.semantic != current.semantic
        {
            // An unexpected replacement cannot discharge the original prefix's custody.
            if let Some(prior) = self.scope.predecessor() {
                let result = validate_predecessor_in_snapshot(prior, self.snapshot);
                prior.retained_history().revalidate_retained_handles()?;
                result?;
            }
            return Err(invalid(
                "native read phase changed its original history owner",
            ));
        }
        if !head_admitted {
            return self.scope.predecessor().map_or(Ok(()), |prior| {
                validate_predecessor_in_snapshot(prior, self.snapshot)
            });
        }
        #[cfg(test)]
        let original = ORIGINAL_PHASE_EXIT.with(std::cell::Cell::get);
        #[cfg(not(test))]
        let original = false;
        // Failed refreshes and every active decoder retain the original physical recipe.
        // Inactive successful reads retain two current-head censuses and the complete
        // reverse exit. Only the duplicate exit-forward predecessor walk is omitted.
        // Thus exit error order can differ between old siblings; a change wholly restored
        // between samples may be unseen. Pre-callback refusal and effect boundaries do not move.
        let shared = read_succeeded && !original && !norito::core::decode_limits_active();
        validate_bounded(current, MAX_RETAINED_BODIES, Some(self.snapshot), shared)
    }
}

fn validate_bounded(
    current: &History,
    maximum: usize,
    snapshot: Option<&SnapshotReadPass<'_>>,
    phase_exit: bool,
) -> Result<()> {
    let snapshot = snapshot.filter(|snapshot| {
        !norito::core::decode_limits_active()
            && current.scope.covers_semantic_original(
                snapshot,
                &current.operation,
                current.purpose,
                current.semantic,
            )
    });
    // Recheck admission at the actual traversal, including a late decoder owner.
    let phase_exit = phase_exit && snapshot.is_some();
    #[cfg(test)]
    let _graph_timing = finish_timing::phase(finish_timing::Phase::GraphValidate);
    #[cfg(test)]
    let _closure_timing = finish_timing::phase_in_closure(finish_timing::Phase::ClosureFullGraph);
    let mut predecessors = [None; MAX_RETAINED_BODIES - 1];
    let mut count = 0;
    let mut next = current.scope.predecessor();
    while let Some(prior) = next {
        if count + 1 >= maximum {
            return Err(invalid(
                "retained enrollment history graph exceeds its body bound",
            ));
        }
        let slot = predecessors
            .get_mut(count)
            .ok_or_else(|| invalid("retained enrollment history graph exceeds its body bound"))?;
        *slot = Some(prior);
        count += 1;
        next = prior.retained_history().scope.predecessor();
    }
    // The original local census already authenticates its own before/after state. With no
    // predecessor, preserve that common path without replaying it a second time.
    if count == 0 {
        return with_native_read_tree(current, |tree| {
            current.require_current_local_in_tree(snapshot, tree, None, None)
        });
    }
    // Standalone and entry checks authenticate ancestors before the selected node, then
    // recheck in reverse order. A sealed successful phase exit retains both current checks
    // and its complete reverse traversal of the exact prefix admitted at phase entry.
    // References keep every original File/Arc owner live across both directions.
    // The adjacent, read-only pair shares one full immutable snapshot entry/exit fence.
    // Its borrowed pass covers only pointer-identical immutable prefixes. Each direction
    // retains its own native ancestry bracket and selected local attempt censuses,
    // inventory and receipt checks, with no wallet callback or effect between directions.
    let mut directions = |pass: Option<&SnapshotReadPass<'_>>| {
        // Immutable leaf observations consolidate only inside this callback-free graph.
        // Persistent source/native refusal at the full snapshot exit overrides every
        // ordinary inner result. A leaf changed and restored inside may be unseen;
        // this does not retain interior leaf-error timing or an atomic snapshot.
        let originals = pass.map(|snapshot| OriginalReadPass { snapshot });
        with_native_read_tree(current, |mut tree| {
            with_graph_root(current, pass, |mut root_read| {
                if !phase_exit {
                    for prior in predecessors[..count].iter().rev().flatten() {
                        prior.require_retained_local(
                            pass,
                            tree.as_deref_mut(),
                            originals.as_ref(),
                            root_read.as_deref_mut(),
                        )?;
                    }
                }
                current.require_current_local_in_tree(pass, tree, originals.as_ref(), root_read)
            })
        })?;
        #[cfg(test)]
        after_forward_for_test()?;
        with_native_read_tree(current, |mut tree| {
            with_graph_root(current, pass, |mut root_read| {
                current.require_current_local_in_tree(
                    pass,
                    tree.as_deref_mut(),
                    originals.as_ref(),
                    root_read.as_deref_mut(),
                )?;
                for prior in predecessors[..count].iter().flatten() {
                    prior.require_retained_local(
                        pass,
                        tree.as_deref_mut(),
                        originals.as_ref(),
                        root_read.as_deref_mut(),
                    )?;
                }
                Ok(())
            })
        })
    };
    let result = match snapshot {
        Some(snapshot) => directions(Some(snapshot)),
        None => current.scope.with_snapshot_read_pass(&mut directions),
    };
    if phase_exit && result.is_err() {
        // A failed head or reverse census must not strand the original predecessor exit.
        // Replay the literal full exit before exposing the first refusal. Original custody
        // wins if that exit also refuses; otherwise preserve the first observed error.
        validate_bounded(current, maximum, snapshot, false)?;
    }
    result
}

// Each graph direction or parser-local census owns a separate native ancestry bracket.
// Standalone/full paths retain both complete directions. A sealed phase exit keeps its two
// head checks and reverse predecessor census, with full fallback on every ordinary error.
// Only the exact complete original native prefix can be shared; nonshared handles
// fall back in iroha_fs. Every ordinary Result closes the original anchor, including a local
// semantic refusal. A local bracket ends before any wallet callback or effectful operation.
pub(super) fn with_native_read_tree<T>(
    current: &History,
    read: impl FnOnce(Option<&mut iroha_fs::PrivateReadTreeScope<'_>>) -> Result<T>,
) -> Result<T> {
    if norito::core::decode_limits_active() {
        return read(None);
    }
    let anchor = match &current.scope {
        HistoryScope::FixedBody => &current.operation,
        HistoryScope::Enrollment(_) => current.scope.enrollment()?.root(),
    };
    anchor.read_tree_scope(|tree| read(Some(tree)))
}

// Instrument the actual local census only in tests. The fixed scratch records borrowed object
// addresses, not decoded authority or selected paths. It can refuse excess work in a test, but
// cannot manufacture successful validation.
#[cfg(test)]
#[derive(Default)]
pub(in crate::managed) struct TestRetainedHistoryCensus {
    pub(in crate::managed) visits: usize,
    pub(in crate::managed) distinct_histories: usize,
    pub(in crate::managed) native_tree_visits: usize,
}

#[cfg(test)]
struct VisitCounter {
    maximum: usize,
    census: TestRetainedHistoryCensus,
    histories: [usize; MAX_RETAINED_BODIES],
}

#[cfg(test)]
std::thread_local! {
    static ORIGINAL_PHASE_EXIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static VALIDATION_VISITS: std::cell::RefCell<Option<VisitCounter>> = const {
        std::cell::RefCell::new(None)
    };
}

// A one-shot test observer runs only after the first complete native bracket closes.
// It can mutate genuine retained files or refuse; it never supplies a custody verdict.
#[cfg(test)]
type AfterForward = Box<dyn FnOnce() -> Result<()>>;
#[cfg(test)]
std::thread_local! {
    static AFTER_FORWARD: std::cell::RefCell<Option<AfterForward>> = const {
        std::cell::RefCell::new(None)
    };
}
#[cfg(test)]
fn after_forward_for_test() -> Result<()> {
    let action = AFTER_FORWARD.with(std::cell::RefCell::take);
    action.map_or(Ok(()), |action| action())
}

#[cfg(test)]
pub(super) fn record_validation_visit(history: &History) -> Result<()> {
    VALIDATION_VISITS.with(|state| {
        if let Some(counter) = state.borrow_mut().as_mut() {
            counter.census.visits = counter
                .census
                .visits
                .checked_add(1)
                .ok_or_else(|| invalid("test retained-history visit count overflow"))?;
            if counter.census.visits > counter.maximum {
                return Err(invalid(
                    "test retained-history validation exceeded its visit bound",
                ));
            }
            let address = std::ptr::from_ref(history) as usize;
            let count = counter.census.distinct_histories;
            if !counter.histories[..count].contains(&address) {
                *counter.histories.get_mut(count).ok_or_else(|| {
                    invalid("test retained-history graph exceeds its body bound")
                })? = address;
                counter.census.distinct_histories += 1;
            }
        }
        Ok(())
    })
}

#[cfg(test)]
pub(super) fn record_native_tree_visit(shared: bool) {
    if shared {
        VALIDATION_VISITS.with(|state| {
            if let Some(counter) = state.borrow_mut().as_mut() {
                counter.census.native_tree_visits += 1;
            }
        });
    }
}

#[cfg(test)]
impl History {
    pub(in crate::managed) fn test_original_phase_exit<T>(
        original: bool,
        action: impl FnOnce() -> T,
    ) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ORIGINAL_PHASE_EXIT.with(|value| value.set(self.0));
            }
        }
        let _restore = Restore(ORIGINAL_PHASE_EXIT.with(|value| value.replace(original)));
        action()
    }

    pub(in crate::managed) fn test_phase_graph_owner(
        &self,
        foreign: &History,
        native: &crate::managed::stream_token_custody::body_history::NativeClosureInspector<'_>,
    ) -> Result<()> {
        let scope = self.scope.retained_copy();
        scope.with_snapshot_read_pass(&mut |snapshot| {
            let snapshot = snapshot.expect("genuine enrollment snapshot");
            let graph = ReadPhaseGraph::enter(self, snapshot, native)?;
            let (foreign, work) =
                Self::test_validation_work(usize::MAX, || graph.close(foreign, true, true));
            assert_eq!(
                foreign.expect_err("foreign scope must refuse").to_string(),
                invalid("native read phase changed its original history owner").to_string(),
            );
            assert!(
                work.visits > 0,
                "foreign scope must close original predecessors"
            );
            for capacity in [0, 1, 256 * 1024 * 1024] {
                // Construct before the newly installed decoder. Closing it must still use
                // exactly that decoder's original physical traversal and low-budget error.
                let graph = ReadPhaseGraph::enter(self, snapshot, native)?;
                let limits =
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, capacity, 64);
                let ((actual, actual_work), actual_usage) =
                    norito::core::with_decode_limits_measured(limits, || {
                        Self::test_validation_work(usize::MAX, || graph.close(self, true, true))
                    });
                let limits =
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, capacity, 64);
                let ((expected, expected_work), expected_usage) =
                    norito::core::with_decode_limits_measured(limits, || {
                        Self::test_validation_work(usize::MAX, || {
                            validate_in_snapshot(self, snapshot)
                        })
                    });
                assert_eq!(actual.is_ok(), capacity > 1);
                assert_eq!(expected.is_ok(), capacity > 1);
                assert_eq!(
                    actual.err().map(|error| error.to_string()),
                    expected.err().map(|error| error.to_string())
                );
                assert_eq!(actual_work.visits, expected_work.visits);
                assert_eq!(
                    actual_work.native_tree_visits,
                    expected_work.native_tree_visits
                );
                if capacity <= 1 {
                    assert_eq!(
                        actual_usage.total_allocated_bytes(),
                        expected_usage.total_allocated_bytes()
                    );
                } else {
                    assert!(
                        actual_usage.total_allocated_bytes() > 1
                            && actual_usage.total_allocated_bytes() <= capacity
                    );
                    assert!(
                        expected_usage.total_allocated_bytes() > 1
                            && expected_usage.total_allocated_bytes() <= capacity
                    );
                }
            }
            Ok(())
        })
    }

    pub(in crate::managed) fn test_phase_entry_after_forward<T>(
        action: impl FnOnce() -> Result<()> + 'static,
        read: impl FnOnce() -> T,
    ) -> T {
        struct Restore(Option<AfterForward>);
        impl Drop for Restore {
            fn drop(&mut self) {
                AFTER_FORWARD.with(|state| {
                    state.replace(self.0.take());
                });
            }
        }
        let _restore = Restore(AFTER_FORWARD.with(|state| state.replace(Some(Box::new(action)))));
        read()
    }

    pub(in crate::managed) fn test_native_read_tree<T>(
        &self,
        action: impl FnOnce(Option<&mut iroha_fs::PrivateReadTreeScope<'_>>) -> Result<T>,
    ) -> Result<T> {
        with_native_read_tree(self, action)
    }

    pub(in crate::managed) fn test_require_current_after_forward(
        &self,
        maximum_visits: usize,
        action: impl FnOnce() -> Result<()> + 'static,
    ) -> (Result<()>, TestRetainedHistoryCensus) {
        Self::test_phase_entry_after_forward(action, || self.test_require_current(maximum_visits))
    }

    // Counts actual local validation calls, including accidental nested full-walker reentry.
    // Only a test-local observer is installed; no successful custody result is manufactured.
    pub(in crate::managed) fn test_require_current(
        &self,
        maximum_visits: usize,
    ) -> (Result<()>, TestRetainedHistoryCensus) {
        Self::test_validation_work(maximum_visits, || self.require_current())
    }
    pub(in crate::managed) fn test_validation_work<T>(
        maximum_visits: usize,
        action: impl FnOnce() -> T,
    ) -> (T, TestRetainedHistoryCensus) {
        struct Restore(Option<VisitCounter>);
        impl Drop for Restore {
            fn drop(&mut self) {
                VALIDATION_VISITS.with(|state| {
                    state.replace(self.0.take());
                });
            }
        }
        let _restore = Restore(VALIDATION_VISITS.with(|state| {
            state.replace(Some(VisitCounter {
                maximum: maximum_visits,
                census: TestRetainedHistoryCensus::default(),
                histories: [0; MAX_RETAINED_BODIES],
            }))
        }));
        let result = action();
        let census =
            VALIDATION_VISITS.with(|state| state.take().expect("test observer retained").census);
        (result, census)
    }
}

#[cfg(test)]
impl History {
    // Adversarial tests may lend an independently parsed Snapshot; production construction
    // of OriginalReadPass remains solely inside validate_bounded's closed directions.
    pub(in crate::managed) fn test_original_local(
        &self,
        snapshot: Option<&SnapshotReadPass<'_>>,
    ) -> Result<()> {
        with_native_read_tree(self, |tree| {
            let originals = snapshot.map(|snapshot| OriginalReadPass { snapshot });
            self.require_current_local_in_tree(snapshot, tree, originals.as_ref(), None)
        })
    }
    pub(in crate::managed) fn test_original_binding(
        &self,
        snapshot: &SnapshotReadPass<'_>,
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
    ) -> bool {
        self.scope
            .covers_semantic_original(snapshot, operation, purpose, semantic)
    }
    pub(in crate::managed) fn test_fixed_original_binding(
        &self,
        snapshot: &SnapshotReadPass<'_>,
    ) -> bool {
        HistoryScope::FixedBody.covers_semantic_original(
            snapshot,
            &self.operation,
            self.purpose,
            self.semantic,
        )
    }
}

#[cfg(test)]
impl History {
    // Exercise owner rejection and a decoder installed after the real read scope entry.
    pub(in crate::managed) fn test_graph_root_scope<T>(
        root: &PrivateDirectory,
        read: impl FnOnce(&mut GraphRootReadPass<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        root.read_scope(|reader| read(&mut GraphRootReadPass { root, reader }))
    }
}
