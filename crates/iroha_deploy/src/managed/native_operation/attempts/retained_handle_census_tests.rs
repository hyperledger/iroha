//! Observe actual retained-handle census recipes without substituting custody results.

use super::*;
use std::cell::{Cell, RefCell};

#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::managed) struct Census {
    pub(in crate::managed) history_order: Vec<usize>,
    pub(in crate::managed) descendant_order: Vec<(bool, usize)>,
    pub(in crate::managed) tree_brackets: usize,
    pub(in crate::managed) full_operations: usize,
    pub(in crate::managed) tree_operations: usize,
    pub(in crate::managed) operation_exits: usize,
}

type AfterDescendants = Box<dyn FnOnce() -> Result<()>>;
thread_local! {
    static ORIGINAL_OPERATION: Cell<bool> = const { Cell::new(false) };
    static CENSUS: RefCell<Option<Census>> = const { RefCell::new(None) };
    static AFTER_DESCENDANTS: RefCell<Option<AfterDescendants>> = const { RefCell::new(None) };
}
pub(super) fn original_operation_recipe() -> bool {
    ORIGINAL_OPERATION.get()
}
fn record(action: impl FnOnce(&mut Census)) {
    CENSUS.with(|state| {
        if let Some(census) = state.borrow_mut().as_mut() {
            action(census);
        }
    });
}
pub(super) fn record_tree_bracket(shared: bool) {
    record(|census| census.tree_brackets += usize::from(shared));
}
pub(super) fn record_history(history: &History) {
    record(|census| {
        census
            .history_order
            .push(std::ptr::from_ref(history) as usize)
    });
}
pub(super) fn record_full_operation() {
    record(|census| census.full_operations += 1);
}
pub(super) fn record_tree_operation() {
    record(|census| census.tree_operations += 1);
}
pub(super) fn record_operation_exit() {
    record(|census| census.operation_exits += 1);
}
pub(super) fn record_attempt_root(directory: &PrivateDirectory) {
    record(|census| {
        census
            .descendant_order
            .push((false, std::ptr::from_ref(directory) as usize))
    });
}
pub(super) fn record_attempt(directory: &PrivateDirectory) {
    record(|census| {
        census
            .descendant_order
            .push((true, std::ptr::from_ref(directory) as usize))
    });
}
pub(super) fn after_descendants() -> Result<()> {
    let action = AFTER_DESCENDANTS.with(std::cell::RefCell::take);
    action.map_or(Ok(()), |action| action())
}
fn counted<T>(action: impl FnOnce() -> T) -> (T, Census) {
    struct Restore(Option<Census>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CENSUS.with(|state| {
                state.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(CENSUS.with(|state| state.replace(Some(Census::default()))));
    let result = action();
    let census = CENSUS.with(|state| state.take().expect("retained census observer"));
    (result, census)
}
impl History {
    pub(in crate::managed) fn test_operation_handle_recipe<T>(
        original: bool,
        read: impl FnOnce() -> T,
    ) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ORIGINAL_OPERATION.set(self.0);
            }
        }
        let _restore = Restore(ORIGINAL_OPERATION.replace(original));
        read()
    }
    pub(in crate::managed) fn test_empty_operation_bracket(
        &self,
        tree: &iroha_fs::PrivateReadTreeScope<'_>,
    ) -> Result<()> {
        tree.revalidate_directory(&self.operation)?;
        Ok(())
    }
    pub(in crate::managed) fn test_handle_work<T>(action: impl FnOnce() -> T) -> (T, Census) {
        counted(action)
    }
    pub(in crate::managed) fn test_retained_handle_census(&self) -> (Result<()>, Census) {
        counted(|| self.revalidate_retained_handles())
    }
    pub(in crate::managed) fn test_retained_handles_after_descendants(
        &self,
        action: impl FnOnce() -> Result<()> + 'static,
    ) -> (Result<()>, Census) {
        struct Restore(Option<AfterDescendants>);
        impl Drop for Restore {
            fn drop(&mut self) {
                AFTER_DESCENDANTS.with(|state| {
                    state.replace(self.0.take());
                });
            }
        }
        let _restore =
            Restore(AFTER_DESCENDANTS.with(|state| state.replace(Some(Box::new(action)))));
        self.test_retained_handle_census()
    }
    pub(in crate::managed) fn test_oldest_retained_history(&self) -> &History {
        let mut current = self;
        for _ in 0..MAX_ATTEMPTS {
            let Some(prior) = current.scope.predecessor() else {
                return current;
            };
            current = prior.retained_history();
        }
        panic!("genuine test graph exceeds its bound");
    }
}
