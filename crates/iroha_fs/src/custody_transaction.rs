//! Thread-bound custody transactions for multi-step retained-custody work; the contract is
//! documented on [`custody_transaction()`].

use super::*;

/// Run `body` as one custody transaction of the calling thread.
///
/// Every operation on a retained directory checks the complete native ancestry from `/` before
/// and after its leaf work. A custody transaction moves those observations of a joined custody
/// root to the transaction's own boundaries:
///
/// - **entry**: the root's first [`PrivateDirectory::join_custody_transaction`] checks its
///   complete ancestry;
/// - **first use**: a descendant that retains the root's exact native chain is checked by its
///   own retained suffix when the transaction first walks it;
/// - **fences**: [`fence_custody_transaction`] checks the root completely, and every descendant
///   used so far by its suffix, before each effect outside the store (a key or anchor mutation,
///   a signature);
/// - **exit**: when this is the outermost transaction of the thread, the same observation runs
///   after `body` returns, whatever it returned, and before the result leaves; a refusal there
///   replaces that result. Unwinding closes the transaction without it, as a read scope does.
///
/// Every ancestry walk of a joined chain on the calling thread is consolidated this way,
/// including [`PrivateDirectory::revalidate`] and the per-call checks that methods on that chain
/// document, such as the entry and exit checks of [`PrivateDirectory::read_scope`],
/// [`PrivateDirectory::read_optional`], [`PrivateDirectory::compare_files`],
/// [`PrivateDirectory::remove_private`] and [`RetainedFile::revalidate`]: the transaction's
/// observations replace them. Tree scopes keep their own suffix walks. Removing or renaming a
/// directory itself acts on its own name, so those operations check their last link again.
///
/// Leaf work keeps every check and every sync. On Unix each leaf operation opens, validates and
/// re-opens names relative to a held directory descriptor with no-follow, so no path text is
/// used between two observations and an ancestry change cannot redirect one. A change made and
/// fully restored between two observations can go unseen, as it can today between the walks of
/// consecutive operations. A change that persists refuses the next fence or the exit; after a
/// refused observation the transaction's operations walk their complete ancestry again.
///
/// A transaction belongs to its calling thread. Other threads, directories that did not join and
/// operations outside a transaction keep their own complete walks. A transaction opened inside
/// another one on the same thread is part of it. The transaction holds its directories weakly:
/// between observations it never extends a directory's lifetime or changes its ownership counts,
/// and a directory that no owner retains any more, which no leaf can reach either, is no longer
/// observed. So the exit observes the custody that is still retained: keep the custody owner
/// alive until the transaction returns. Fences and the exit observe only roots that have joined,
/// so join before the work whose effects you fence. Windows leaf operations reopen names by path,
/// so there every operation keeps its own walks and these calls add none.
///
/// # Errors
/// Returns `body`'s error, or the exit refusal of changed or unsafe custody, which takes
/// precedence over every ordinary result, including a completed value or a typed body error.
pub fn custody_transaction<T, E>(body: impl FnOnce() -> Result<T, E>) -> Result<T, E>
where
    E: From<io::Error>,
{
    platform::custody_transaction::run(body)
}

/// Observe the calling thread's custody transaction now, before an effect outside the store.
///
/// Use this, not [`PrivateDirectory::revalidate`], for an observation that must happen now: inside
/// a transaction, a joined chain's own checks are consolidated.
///
/// Checks the complete ancestry of every joined root and the retained suffix of every descendant
/// used so far. Outside a transaction every operation checked its own ancestry, so this does
/// nothing.
///
/// # Errors
/// Refuses changed or unsafe custody; the effect must not be attempted. Later operations of the
/// same transaction then walk their complete ancestry again.
pub fn fence_custody_transaction() -> io::Result<()> {
    platform::custody_transaction::fence()
}

impl PrivateDirectory {
    /// Join this directory, as a custody root, to the calling thread's custody transaction.
    ///
    /// The first join of this exact retained chain checks its complete ancestry: the
    /// transaction's entry for this root. Later walks of the chain, and of descendants that
    /// retain it, are consolidated into the transaction's observations. Joining again, or joining
    /// a descendant of a joined root, adds no root. Outside a transaction this does nothing, and
    /// every operation keeps its own walks.
    ///
    /// # Errors
    /// Refuses changed or unsafe custody at the entry observation.
    pub fn join_custody_transaction(&self) -> io::Result<()> {
        platform::custody_transaction::join(&self.inner)
    }
}
