//! Observation-only counts of retained-ancestry work on the calling thread.
//!
//! Every revalidation walk of a retained directory chain is counted when it starts,
//! together with the number of ancestor links it reopens by name (one native open each).
//! Counts are public, kept in this thread's memory only, never persisted, and no custody
//! decision in this crate or any caller reads them.

use std::cell::Cell;

/// Retained-ancestry work started on the current thread since the thread began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CustodyWorkV1 {
    /// Revalidation walks of a retained directory chain (complete or descendant-only).
    pub ancestry_walks: u64,
    /// Ancestor links those walks reopen by name, one native open/openat each.
    pub ancestry_opens: u64,
}

impl CustodyWorkV1 {
    /// This thread's cumulative counts.
    #[must_use]
    pub fn current_thread() -> Self {
        // Thread-local teardown loses only observation, never a verdict.
        WORK.try_with(Cell::get).unwrap_or_default()
    }

    /// The work counted in `self` and not in `earlier` (field by field, saturating).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            ancestry_walks: self.ancestry_walks.saturating_sub(earlier.ancestry_walks),
            ancestry_opens: self.ancestry_opens.saturating_sub(earlier.ancestry_opens),
        }
    }
}

thread_local! {
    static WORK: Cell<CustodyWorkV1> = const {
        Cell::new(CustodyWorkV1 {
            ancestry_walks: 0,
            ancestry_opens: 0,
        })
    };
}

/// Record one started ancestry walk over `links` retained links.
pub fn record_ancestry_walk(links: usize) {
    let _ = WORK.try_with(|work| {
        let mut value = work.get();
        value.ancestry_walks = value.ancestry_walks.saturating_add(1);
        value.ancestry_opens = value
            .ancestry_opens
            .saturating_add(u64::try_from(links).unwrap_or(u64::MAX));
        work.set(value);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateDirectory;

    #[test]
    fn each_revalidation_counts_one_walk_and_every_reopened_link() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap().join("private");
        let directory = PrivateDirectory::open_or_create(&root).unwrap();
        let depth = root.components().count() as u64;
        let before = CustodyWorkV1::current_thread();
        directory.revalidate().unwrap();
        directory.revalidate().unwrap();
        let work = CustodyWorkV1::current_thread().since(before);
        assert_eq!(work.ancestry_walks, 2);
        assert_eq!(work.ancestry_opens, 2 * depth);
    }

    #[test]
    fn counts_stay_on_their_thread_and_differences_saturate() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap().join("private");
        let directory = PrivateDirectory::open_or_create(&root).unwrap();
        let before = CustodyWorkV1::current_thread();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let start = CustodyWorkV1::current_thread();
                    directory.revalidate().unwrap();
                    assert_eq!(
                        CustodyWorkV1::current_thread().since(start).ancestry_walks,
                        1
                    );
                })
                .join()
                .unwrap();
        });
        assert_eq!(CustodyWorkV1::current_thread(), before);
        assert_eq!(
            CustodyWorkV1::default().since(CustodyWorkV1 {
                ancestry_walks: 3,
                ancestry_opens: 9,
            }),
            CustodyWorkV1::default()
        );
    }
}
