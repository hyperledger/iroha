//! One callback-free local census under its original enrollment root and operation owners.
//!
//! Every original leaf read, bounded inventory and binding comparison remains in order. Only
//! repeated ancestry observations share the existing native entry/ordinary-result exit. The
//! owner cannot run a wallet callback or effect, and no native view or freshness verdict escapes.
use super::*;
use crate::managed::stream_token_custody::body_history::SnapshotReadPass;
#[cfg(test)]
use crate::managed::stream_token_custody::body_history::local_census_tests;

pub(super) struct LocalHistoryCensus<'history, 'snapshot> {
    history: &'history History,
    snapshot: &'history SnapshotReadPass<'snapshot>,
}
impl<'history, 'snapshot> LocalHistoryCensus<'history, 'snapshot> {
    pub(super) fn admit(
        history: &'history History,
        snapshot: &'history SnapshotReadPass<'snapshot>,
    ) -> Option<Self> {
        #[cfg(test)]
        if local_census_tests::original_recipe() {
            return None;
        }
        let owner = Self { history, snapshot };
        owner.covers(history).then_some(owner)
    }
    pub(super) fn covers(&self, history: &History) -> bool {
        !norito::core::decode_limits_active()
            && reuse_operation_scope()
            && std::ptr::eq(self.history, history)
            && history.scope.covers_semantic_original(
                self.snapshot,
                &history.operation,
                history.purpose,
                history.semantic,
            )
    }
    pub(super) fn read(&self) -> Result<()> {
        if !self.covers(self.history) {
            return retained_graph::with_native_read_tree(self.history, |tree| {
                self.history
                    .require_current_local_in_tree(Some(self.snapshot), tree, None, None)
            });
        }
        let root = self.history.scope.enrollment()?.root();
        root.read_tree_scope_with_root(|tree, reader| self.read_in_scope(tree, reader))
    }
    // The root reader is lent only by its actual owning boundary. Neither this body nor
    // its operation census can invoke a wallet or effect. Recheck late decode ownership
    // before lending either reader to the original local validation recipe.
    fn read_in_scope(
        &self,
        tree: &mut iroha_fs::PrivateReadTreeScope<'_>,
        reader: &mut iroha_fs::PrivateReadScope<'_>,
    ) -> Result<()> {
        if !self.covers(self.history) {
            return self.history.require_current_local_in_tree(
                Some(self.snapshot),
                Some(tree),
                None,
                None,
            );
        }
        let root = self.history.scope.enrollment()?.root();
        #[cfg(test)]
        local_census_tests::record(local_census_tests::Point::RootBracket);
        let mut root_read = GraphRootReadPass::new(root, reader);
        self.history.require_current_local_admitted(
            Some(self.snapshot),
            Some(tree),
            None,
            Some(&mut root_read),
            Some(self),
        )
    }
    // The caller has already completed the original scope/binding entry. This is the sole
    // concrete operation body: there is no caller-supplied callback or effectful continuation.
    pub(super) fn read_contents(
        &self,
        tree: &mut iroha_fs::PrivateReadTreeScope<'_>,
        originals: Option<&retained_graph::OriginalReadPass<'_, '_>>,
        root_read: Option<&mut GraphRootReadPass<'_, '_>>,
    ) -> Result<()> {
        #[cfg(test)]
        local_census_tests::record(local_census_tests::Point::OperationBracket);
        tree.read_scope_with_tree(&self.history.operation, |tree, reader| {
            let mut operation_read = OperationRead {
                operation: &self.history.operation,
                reader,
            };
            let result = self.history.require_current_local_contents(
                Some(self.snapshot),
                Some(tree),
                originals,
                root_read,
                Some(&mut operation_read),
            );
            #[cfg(test)]
            let result = local_census_tests::before_exit(result);
            result
        })
    }
}

// Never constructed from a pathname, reopened equivalent handle, caller-provided bytes or
// another History. The only producer above retains both actual native ordinary-result exits.
pub(super) struct OperationRead<'borrow, 'scope> {
    operation: &'borrow PrivateDirectory,
    reader: &'borrow mut iroha_fs::PrivateReadScope<'scope>,
}
impl<'scope> OperationRead<'_, 'scope> {
    pub(super) fn covers(&self, history: &History) -> bool {
        !norito::core::decode_limits_active()
            && reuse_operation_scope()
            && std::ptr::eq(self.operation, history.operation.as_ref())
    }
    pub(super) fn reader(&mut self) -> &mut iroha_fs::PrivateReadScope<'scope> {
        self.reader
    }
}

#[cfg(test)]
impl History {
    pub(in crate::managed) fn test_local_census(
        &self,
        snapshot: &SnapshotReadPass<'_>,
    ) -> Result<()> {
        self.require_current_local(Some(snapshot))
    }
    // Exercise graph-local admission after the actual caller has acquired its native tree.
    // Optional/foreign snapshots remain negative inputs; none manufactures a valid owner.
    pub(in crate::managed) fn test_graph_local_census_in_tree(
        &self,
        snapshot: Option<&SnapshotReadPass<'_>>,
        tree: Option<&mut iroha_fs::PrivateReadTreeScope<'_>>,
    ) -> Result<()> {
        self.require_current_local_in_tree(snapshot, tree, None, None)
    }
    pub(in crate::managed) fn test_local_census_after_admission<T>(
        &self,
        snapshot: &SnapshotReadPass<'_>,
        run: impl FnOnce(&mut dyn FnMut() -> Result<()>) -> T,
    ) -> Result<T> {
        let census = LocalHistoryCensus::admit(self, snapshot).expect("genuine local census owner");
        let root = self.scope.enrollment()?.root();
        root.read_tree_scope_with_root(|tree, reader| {
            let mut read = || census.read_in_scope(tree, reader);
            Ok(run(&mut read))
        })
    }
    // Test-only literal reference for the previously nested native root bracket. Both
    // variants invoke the same sealed census body; only the duplicate root fence differs.
    pub(in crate::managed) fn test_local_census_nested_root_reference(
        &self,
        snapshot: &SnapshotReadPass<'_>,
    ) -> Result<()> {
        let census = LocalHistoryCensus::admit(self, snapshot).expect("genuine local census owner");
        retained_graph::with_native_read_tree(self, |tree| {
            let tree = tree.expect("genuine inactive native tree");
            self.scope
                .enrollment()?
                .root()
                .read_scope(|reader| census.read_in_scope(tree, reader))
        })
    }
}
