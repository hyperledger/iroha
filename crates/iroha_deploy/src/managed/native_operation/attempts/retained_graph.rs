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

// Minted only by the closed complete graph traversal below, never by the parser pass.
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

// Borrowed only inside one complete callback-free graph direction. Its original directory
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
    validate_bounded(current, MAX_RETAINED_BODIES)
}

// A standalone body scope reserves one graph slot for its own not-yet-read History.
pub(super) fn validate_predecessor(prior: &VerifiedUnsignedClosure) -> Result<()> {
    validate_bounded(prior.retained_history(), MAX_RETAINED_BODIES - 1)?;
    prior.require_receipt()
}

fn validate_bounded(current: &History, maximum: usize) -> Result<()> {
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
            current.require_current_local_in_tree(None, tree, None, None)
        });
    }
    // Authenticate all ancestors before the selected node, then recheck in reverse order.
    // References keep every original File/Arc owner live across both complete passes.
    // The adjacent, read-only pair shares one full immutable snapshot entry/exit fence.
    // Its borrowed pass covers only pointer-identical immutable prefixes. Both complete
    // mutable traversals retain their own native ancestry bracket, local attempt census,
    // inventory and receipt checks, with no wallet callback or effect between directions.
    current.scope.with_snapshot_read_pass(&mut |pass| {
        // Immutable leaf observations consolidate only inside this callback-free graph.
        // Persistent source/native refusal at the full snapshot exit overrides every
        // ordinary inner result. A leaf changed and restored inside may be unseen;
        // this does not retain interior leaf-error timing or an atomic snapshot.
        let originals = pass.map(|snapshot| OriginalReadPass { snapshot });
        with_native_read_tree(current, |mut tree| {
            with_graph_root(current, pass, |mut root_read| {
                for prior in predecessors[..count].iter().rev().flatten() {
                    prior.require_retained_local(
                        pass,
                        tree.as_deref_mut(),
                        originals.as_ref(),
                        root_read.as_deref_mut(),
                    )?;
                }
                current.require_current_local_in_tree(
                    pass,
                    tree.as_deref_mut(),
                    originals.as_ref(),
                    root_read,
                )
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
    })
}

// Each full traversal or parser-local census owns a separate native ancestry bracket.
// Both graph directions, snapshot fences, local inventories and receipt checks retain their
// order. Only the exact complete original native prefix can be shared; nonshared handles
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
    let action = AFTER_FORWARD.with(|state| state.take());
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
        struct Restore(Option<AfterForward>);
        impl Drop for Restore {
            fn drop(&mut self) {
                AFTER_FORWARD.with(|state| {
                    state.replace(self.0.take());
                });
            }
        }
        let _restore = Restore(AFTER_FORWARD.with(|state| state.replace(Some(Box::new(action)))));
        self.test_require_current(maximum_visits)
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
    // of OriginalReadPass remains solely inside validate_bounded's complete closed pass.
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
