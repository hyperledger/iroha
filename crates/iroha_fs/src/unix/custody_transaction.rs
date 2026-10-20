//! Thread-local consolidation of descriptor-relative ancestry walks (`crate::custody_transaction`).
//!
//! Every leaf operation of this platform opens, validates and re-opens names relative to a held
//! directory descriptor with no-follow. That is what lets a transaction observe a joined chain
//! only at its entry, first uses, fences and exit: between two observations no operation follows
//! path text, so an ancestry change cannot redirect one.

use super::*;
use std::{
    cell::RefCell,
    sync::{Arc, Weak},
};

/// One retained chain, held weakly: between observations a transaction never extends a
/// directory's lifetime or changes the ownership counts that removal and publication checks
/// read. An observation holds the links it walks strongly only while it walks them.
type Chain = Vec<Weak<Link>>;

/// The calling thread's open custody transaction.
#[derive(Default)]
struct Frame {
    /// Open levels; a transaction opened inside another one on this thread is part of it.
    depth: usize,
    /// A refused observation ends consolidation: later walks are complete again.
    refused: bool,
    /// Joined custody roots, each checked completely when it joined.
    roots: Vec<Chain>,
    /// Descendants used so far, by root index; each suffix was checked at its first use.
    used: Vec<(usize, Chain)>,
}

thread_local! {
    static FRAME: RefCell<Option<Frame>> = const { RefCell::new(None) };
}

/// How one ancestry walk of a retained directory runs on this thread.
enum Walk {
    /// Outside a joined chain, or after a refused observation: the complete walk.
    Complete,
    /// The transaction observes this chain at its boundaries.
    Consolidated,
    /// First use of a descendant: only its own retained suffix below joined root `root`.
    Suffix { root: usize, first: usize },
}

fn chain(directory: &Directory) -> Chain {
    directory.links.iter().map(Arc::downgrade).collect()
}

/// Whether `directory` retains exactly the link objects of `prefix`, in order.
fn retains(directory: &Directory, prefix: &[Weak<Link>]) -> bool {
    directory.links.len() >= prefix.len()
        && directory
            .links
            .iter()
            .zip(prefix)
            .all(|(link, held)| std::ptr::eq(Arc::as_ptr(link), held.as_ptr()))
}

/// Whether `directory` is the retained chain `used`. A link object is pushed onto exactly one
/// chain, so the last link identifies the whole chain.
fn is_chain(directory: &Directory, used: &[Weak<Link>]) -> bool {
    directory.links.len() == used.len()
        && directory
            .links
            .last()
            .zip(used.last())
            .is_some_and(|(link, held)| std::ptr::eq(Arc::as_ptr(link), held.as_ptr()))
}

fn walk(directory: &Directory) -> Walk {
    FRAME
        .try_with(|frame| {
            let frame = frame.borrow();
            let Some(frame) = frame.as_ref().filter(|frame| !frame.refused) else {
                return Walk::Complete;
            };
            let Some(root) = frame.roots.iter().position(|root| retains(directory, root)) else {
                return Walk::Complete;
            };
            let first = frame.roots[root].len();
            if directory.links.len() == first
                || frame.used.iter().any(|(_, used)| is_chain(directory, used))
            {
                Walk::Consolidated
            } else {
                Walk::Suffix { root, first }
            }
        })
        .unwrap_or(Walk::Complete)
}

fn update(change: impl FnOnce(&mut Frame)) {
    let _ = FRAME.try_with(|frame| {
        if let Some(frame) = frame.borrow_mut().as_mut() {
            change(frame);
        }
    });
}

/// End consolidation after any fresh complete or suffix ancestry walk refuses, including a
/// tree-scope walk that does not pass through the transaction's ordinary revalidation wrapper.
/// Outside a transaction this leaves the same native result and has no state to change.
pub(super) fn observe_ancestry_result(result: &io::Result<()>) {
    if result.is_err() {
        update(|frame| frame.refused = true);
    }
}

fn state_unavailable() -> io::Error {
    io::Error::other("custody transaction state is unavailable on this thread")
}

/// The ancestry walk of `directory` on this thread (`Directory::revalidate`).
pub(super) fn revalidate(directory: &Directory) -> io::Result<()> {
    match walk(directory) {
        Walk::Complete => directory.revalidate_from(0),
        Walk::Consolidated => Ok(()),
        Walk::Suffix { root, first } => {
            let result = directory.revalidate_from(first);
            update(|frame| match &result {
                Ok(()) => frame.used.push((root, chain(directory))),
                Err(_) => frame.refused = true,
            });
            result
        }
    }
}

/// The walk of `directory` before an operation on its own name in its parent: removing or
/// renaming the directory itself. Such an operation acts on that name, so it must denote the
/// held directory now. A consolidated walk is therefore replaced by a fresh walk of the last
/// link; complete and first-use walks already end with it.
pub(super) fn revalidate_name(directory: &Directory) -> io::Result<()> {
    match walk(directory) {
        Walk::Complete | Walk::Suffix { .. } => revalidate(directory),
        Walk::Consolidated => {
            let result = directory.revalidate_from(directory.links.len().saturating_sub(1));
            if result.is_err() {
                update(|frame| frame.refused = true);
            }
            result
        }
    }
}

/// Join `directory` as a custody root of this thread's open transaction (entry observation).
pub fn join(directory: &Directory) -> io::Result<()> {
    let joined = FRAME
        .try_with(|frame| {
            frame
                .borrow()
                .as_ref()
                .map(|frame| frame.roots.iter().any(|root| retains(directory, root)))
        })
        .unwrap_or(None);
    match joined {
        // Outside a transaction every operation walks completely.
        None => Ok(()),
        // A joined root or one of its descendants: an ordinary walk of the chain, which is
        // consolidated, a first-use suffix, or complete again after a refusal.
        Some(true) => revalidate(directory),
        // A new root, also after a refusal, so that the exit observes it: its entry.
        Some(false) => {
            let result = directory.revalidate_from(0);
            update(|frame| match &result {
                Ok(()) => frame.roots.push(chain(directory)),
                Err(_) => frame.refused = true,
            });
            result
        }
    }
}

/// Observe this thread's open transaction now (`crate::fence_custody_transaction`).
pub fn fence() -> io::Result<()> {
    let open = FRAME
        .try_with(|frame| {
            frame
                .borrow()
                .as_ref()
                .map(|frame| (frame.roots.clone(), frame.used.clone()))
        })
        .unwrap_or(None);
    let Some((roots, used)) = open else {
        return Ok(());
    };
    let result = observe(&roots, &used);
    if result.is_err() {
        update(|frame| frame.refused = true);
    }
    result
}

/// Run `body` as one level of this thread's transaction (`crate::custody_transaction`).
pub fn run<T, E>(body: impl FnOnce() -> Result<T, E>) -> Result<T, E>
where
    E: From<io::Error>,
{
    let level = Level::enter()?;
    let result = body();
    let closed = level.close();
    let checked =
        closed.and_then(|frame| frame.map_or(Ok(()), |frame| observe(&frame.roots, &frame.used)));
    if let Err(error) = checked {
        // The exit refusal takes precedence over every ordinary result.
        drop(result);
        return Err(error.into());
    }
    result
}

/// Check every joined root completely and every used descendant by its retained suffix.
fn observe(roots: &[Chain], used: &[(usize, Chain)]) -> io::Result<()> {
    for (index, root) in roots.iter().enumerate() {
        // A chain that no owner retains any more cannot reach a leaf.
        let Some(links) = upgrade(root) else {
            continue;
        };
        Directory { links }.revalidate_from(0)?;
        for (_, descendant) in used.iter().filter(|(owner, _)| *owner == index) {
            if let Some(links) = upgrade(descendant) {
                Directory { links }.revalidate_from(root.len())?;
            }
        }
    }
    Ok(())
}

fn upgrade(chain: &[Weak<Link>]) -> Option<Vec<Arc<Link>>> {
    chain.iter().map(Weak::upgrade).collect()
}

/// One open level of the calling thread's transaction. Dropping it unclosed (unwinding) closes
/// it without an exit observation.
struct Level {
    open: bool,
}

impl Level {
    fn enter() -> io::Result<Self> {
        FRAME
            .try_with(|frame| {
                frame.borrow_mut().get_or_insert_with(Frame::default).depth += 1;
            })
            .map_err(|_| state_unavailable())?;
        Ok(Self { open: true })
    }

    /// Close this level. The outermost level hands back its frame for the exit observation.
    fn close(mut self) -> io::Result<Option<Frame>> {
        self.open = false;
        leave()
    }
}

impl Drop for Level {
    fn drop(&mut self) {
        if self.open {
            let _ = leave();
        }
    }
}

fn leave() -> io::Result<Option<Frame>> {
    FRAME
        .try_with(|frame| {
            let mut frame = frame.borrow_mut();
            match frame.as_ref().map_or(0, |open| open.depth) {
                0 => Err(state_unavailable()),
                1 => Ok(frame.take()),
                _ => {
                    if let Some(open) = frame.as_mut() {
                        open.depth -= 1;
                    }
                    Ok(None)
                }
            }
        })
        .map_err(|_| state_unavailable())?
}
