//! Callback-free current/active admission over one exact native enrollment owner.
//!
//! Current metadata is inspected before active binding. A complete forward/reverse mutable
//! graph closes every ordinary outcome, followed by the original snapshot exit. No read
//! token or freshness result reaches publication, wallet inspection or authorization calls.
use super::*;
use crate::managed::stream_token_custody::body_history::SnapshotReadPass;
#[cfg(test)]
use crate::managed::stream_token_custody::body_history::current_active_tests;

pub(super) struct CurrentActiveRead<'history, 'snapshot> {
    history: &'history History,
    snapshot: &'history SnapshotReadPass<'snapshot>,
}
impl CurrentActiveRead<'_, '_> {
    pub(super) fn covers(&self, scope: &HistoryScope) -> bool {
        !norito::core::decode_limits_active()
            && std::ptr::eq(scope, &self.history.scope)
            && scope.covers_semantic_original(
                self.snapshot,
                &self.history.operation,
                self.history.purpose,
                self.history.semantic,
            )
    }
    pub(super) fn snapshot(&self, scope: &HistoryScope) -> Option<&SnapshotReadPass<'_>> {
        self.covers(scope).then_some(self.snapshot)
    }
    fn read(&self) -> Result<()> {
        if !self.covers(&self.history.scope) {
            return self.history.require_current_and_active_original();
        }
        let result = self
            .history
            .require_current_local(Some(self.snapshot))
            .and_then(|()| {
                #[cfg(test)]
                current_active_tests::hit(current_active_tests::Point::BeforeActive)?;
                self.history.scope.require_active_in_current_read(self)
            });
        #[cfg(test)]
        let result =
            current_active_tests::hit(current_active_tests::Point::BeforeClose).and(result);
        // Neither a source failure nor inactive flag may strand mutable predecessor custody.
        // Keep both complete graph directions, and every original leaf/inventory/receipt check.
        // The delayed first predecessor observation can change ordinary sibling error order;
        // a predecessor changed and restored within this read-only phase may be unseen.
        retained_graph::validate_in_snapshot(self.history, self.snapshot)?;
        result
    }
}
impl History {
    fn require_current_and_active_original(&self) -> Result<()> {
        self.require_current()?;
        self.scope.require_active()
    }
    pub(super) fn require_current_and_active(&self) -> Result<()> {
        #[cfg(test)]
        current_active_tests::hit(current_active_tests::Point::Call)?;
        #[cfg(test)]
        let original = current_active_tests::original_recipe();
        #[cfg(not(test))]
        let original = false;
        if original || norito::core::decode_limits_active() || self.scope.predecessor().is_none() {
            return self.require_current_and_active_original();
        }
        self.scope.with_snapshot_read_pass(&mut |snapshot| {
            let Some(snapshot) = snapshot else {
                return self.require_current_and_active_original();
            };
            CurrentActiveRead {
                history: self,
                snapshot,
            }
            .read()
        })
    }
}

#[cfg(test)]
impl History {
    pub(in crate::managed) fn test_current_and_active(&self) -> Result<()> {
        self.require_current_and_active()
    }
    pub(in crate::managed) fn test_current_active_late<T>(
        &self,
        run: impl FnOnce(&mut dyn FnMut() -> Result<()>) -> T,
    ) -> Result<T> {
        let mut run = Some(run);
        let mut output = None;
        self.scope.with_snapshot_read_pass(&mut |snapshot| {
            let snapshot = snapshot.expect("inactive genuine snapshot admission");
            let owner = CurrentActiveRead {
                history: self,
                snapshot,
            };
            let mut read = || owner.read();
            output = Some(run.take().unwrap()(&mut read));
            Ok(())
        })?;
        Ok(output.unwrap())
    }
    pub(in crate::managed) fn test_current_active_foreign_scope(&self) -> Result<()> {
        let scope = self.scope.retained_copy();
        self.scope.with_snapshot_read_pass(&mut |snapshot| {
            let owner = CurrentActiveRead {
                history: self,
                snapshot: snapshot.expect("inactive genuine snapshot admission"),
            };
            assert!(!owner.covers(&scope));
            scope.require_active_in_current_read(&owner)
        })
    }
    pub(in crate::managed) fn test_current_active_transition(&self, terms: Terms) -> Result<()> {
        self.reserve_pending(&self.operation, Origin::Explicit, terms)?;
        let reserved = Self::read_retained(
            &self.operation,
            self.purpose,
            self.semantic,
            &self.scope,
            self,
        )?;
        reserved
            .finish_reserved(&reserved.operation, false)?
            .ok_or_else(|| invalid("test reservation was not published"))?;
        let published = Self::read_retained(
            &reserved.operation,
            reserved.purpose,
            reserved.semantic,
            &reserved.scope,
            &reserved,
        )?;
        published.retain_root(&published.operation)
    }
    pub(in crate::managed) fn test_closing_current_only(&self) -> Result<()> {
        self.finish_reserved(&self.operation, true).map(|_| ())
    }
}
