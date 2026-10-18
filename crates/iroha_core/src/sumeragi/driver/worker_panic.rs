//! Bounded original worker joins and panic-payload destruction after physical completion.

use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind},
    thread::JoinHandle,
};

use super::Worker;

/// Exact original panic custody, including safe suppression during an existing unwind.
pub(super) struct OriginalWorkerPanic(Option<Box<dyn Any + Send>>);

impl OriginalWorkerPanic {
    pub(super) fn new(original: Box<dyn Any + Send>) -> Self {
        Self(Some(original))
    }

    /// Resume the unchanged first Box; no aggregate replaces its concrete identity.
    pub(super) fn resume(mut self) -> ! {
        std::panic::resume_unwind(self.0.take().expect("original worker panic"))
    }

    #[cfg(test)]
    pub(super) fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.as_ref().and_then(|original| original.downcast_ref())
    }
}

impl Drop for OriginalWorkerPanic {
    fn drop(&mut self) {
        // A payload destructor can itself panic. Catch that replacement inside
        // this Drop, including during an already-active outer unwind, then consume
        // it iteratively. Custody stays at one Box; no payload is leaked, wrapped
        // as a replacement primary, or recursively dropped by this helper.
        // Arbitrary user Drop may never terminate; cleanup cannot manufacture
        // completion for that case or for process abort.
        let mut pending = self.0.take();
        while let Some(original) = pending {
            pending = catch_unwind(AssertUnwindSafe(|| drop(original))).err();
        }
    }
}

/// Suppress a physically joined thread's panic without letting payload Drop escape.
pub(super) fn discard_join_result(result: std::thread::Result<()>) {
    drop(result.err().map(OriginalWorkerPanic::new));
}

/// Join the private Persist/Exec/Serve/Loop prefix before dropping any panic payload.
pub(super) fn join_original_workers(threads: Vec<JoinHandle<()>>) -> Option<OriginalWorkerPanic> {
    // The only production producers are PreparedWorkers' four role-specific
    // pushes and transfers of that same vector. This is the same role authority
    // as pending startup membership, not an independently configurable limit.
    assert!(threads.len() <= Worker::COUNT, "original worker role bound");
    let mut failures: [Option<OriginalWorkerPanic>; Worker::COUNT] =
        [const { None }; Worker::COUNT];
    for (index, thread) in threads.into_iter().enumerate() {
        #[cfg(test)]
        tests::before_join(index);
        let failure = thread.join().err().map(OriginalWorkerPanic::new);
        if cfg!(all(test, sumeragi_core_mutation = "HC427")) && failures.iter().any(Option::is_some)
        {
            // Deliberately destroy a secondary payload before the remaining joins.
            drop(failure);
        } else {
            failures[index] = failure;
        }
    }
    let first = failures.iter_mut().find_map(Option::take);
    // No original worker remains here. Each secondary wrapper contains a finite
    // destructor-panic chain before we return/resume the exact first payload.
    drop(failures);
    first
}

#[cfg(test)]
pub(super) mod tests;
