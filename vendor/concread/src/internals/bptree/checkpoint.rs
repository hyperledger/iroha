//! Stack-owned rollback of an original private cursor and its tracking storage.

use super::{checked_next_generation, CursorMode, CursorReadOps, CursorWrite};
use crate::bptree::{MapMode, NodeCloning};
use crate::internals::bptree::{node::Node, tracking::TrackingBuffer};
use std::{borrow::Borrow, fmt::Debug, mem, ptr::NonNull};

type Buffer<K, V, M> = <M as CursorMode<K, V>>::Buffer;

/// Original allocations displaced during the first growth in this checkpoint.
pub(crate) struct CheckpointBuffers<
    K: Clone + Ord + Debug,
    V: Clone,
    M: MapMode + NodeCloning<K, V>,
> {
    first: M::RetainedBuffer<*mut Node<K, V, M::Charge>>,
    last: M::RetainedBuffer<*mut Node<K, V, M::Charge>>,
}

impl<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> CheckpointBuffers<K, V, M> {
    pub(super) fn retain_first(&mut self, old: Buffer<K, V, M>) {
        M::retain_original_buffer(&mut self.first, old);
    }

    pub(super) fn retain_last(&mut self, old: Buffer<K, V, M>) {
        M::retain_original_buffer(&mut self.last, old);
    }

    // Move both ancestor originals before any excess charge may unwind.
    fn absorb(&mut self, mut child: Self) -> Self {
        M::inherit_original_buffer(&mut self.first, &mut child.first);
        M::inherit_original_buffer(&mut self.last, &mut child.last);
        child
    }
}

struct Saved<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> {
    root: NonNull<Node<K, V, M::Charge>>,
    txid: u64,
    length: usize,
    first_cut: usize,
    last_cut: usize,
    buffers: CheckpointBuffers<K, V, M>,
}

// The original parent root is retained by the checkpoint and its exclusive
// cursor borrow. Child generations cannot mutate it because their txid differs.
impl<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>>
    CursorReadOps<K, V, M::Charge> for Saved<K, V, M>
{
    fn get_root_ref(&self) -> &Node<K, V, M::Charge> {
        // SAFETY: this saved root remains owned until this checkpoint resolves.
        unsafe { self.root.as_ref() }
    }

    fn get_root(&self) -> *mut Node<K, V, M::Charge> {
        self.root.as_ptr()
    }
    fn len(&self) -> usize {
        self.length
    }
    fn get_txid(&self) -> u64 {
        self.txid
    }
}

/// Exclusive, move-only checkpoint; exclusive reborrows enforce LIFO resolution.
pub(crate) struct CursorCheckpoint<
    'a,
    K: Clone + Ord + Debug,
    V: Clone,
    M: MapMode + NodeCloning<K, V>,
> {
    cursor: &'a mut CursorWrite<K, V, M>,
    parent: Option<&'a mut CheckpointBuffers<K, V, M>>,
    saved: Option<Saved<K, V, M>>,
}

impl<'a, K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>>
    CursorCheckpoint<'a, K, V, M>
{
    // A supplied parent must be this cursor's own original saved buffer slot,
    // obtained together through edit_parts; never pair slots from other cursors.
    pub(crate) fn new(
        cursor: &'a mut CursorWrite<K, V, M>,
        parent: Option<&'a mut CheckpointBuffers<K, V, M>>,
    ) -> Option<Self> {
        cursor.assert_operable();
        cursor.funding.assert_funding_idle();
        let next = checked_next_generation(cursor.txid)?;
        let saved = Saved {
            root: NonNull::new(cursor.root).expect("original non-null cursor root"),
            txid: cursor.txid,
            length: cursor.length,
            first_cut: cursor.first_seen.as_slice().len(),
            last_cut: cursor
                .last_seen
                .as_ref()
                .expect("original retirement buffer")
                .as_slice()
                .len(),
            buffers: CheckpointBuffers {
                first: M::empty_retained_buffer(),
                last: M::empty_retained_buffer(),
            },
        };
        cursor.txid = next;
        Some(Self {
            cursor,
            parent,
            saved: Some(saved),
        })
    }

    pub(crate) fn as_ref(&self) -> &CursorWrite<K, V, M> {
        self.cursor.assert_operable();
        self.cursor
    }

    pub(crate) fn get_before<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.cursor.assert_operable();
        self.saved.as_ref().expect("live checkpoint").search(key)
    }

    pub(crate) fn edit_parts(
        &mut self,
    ) -> (&mut CursorWrite<K, V, M>, &mut CheckpointBuffers<K, V, M>) {
        self.cursor.assert_operable();
        self.joined_edit_parts()
    }

    /// Borrow live parts before a joint guard checks either cursor's failure.
    /// The caller must guard both returned cursors before planning or mutation;
    /// this permits a prefailed member to invalidate its whole borrowed pair.
    pub(crate) fn joined_edit_parts(
        &mut self,
    ) -> (&mut CursorWrite<K, V, M>, &mut CheckpointBuffers<K, V, M>) {
        (
            self.cursor,
            &mut self.saved.as_mut().expect("live checkpoint").buffers,
        )
    }

    pub(crate) fn checkpoint(&mut self) -> Option<CursorCheckpoint<'_, K, V, M>> {
        CursorCheckpoint::new(
            self.cursor,
            Some(&mut self.saved.as_mut().expect("live checkpoint").buffers),
        )
    }

    // The sealed mode hooks move custody only. No charge or payload destructor
    // runs while resolving this checkpoint or transferring ancestor originals.
    fn take_applied_buffers(&mut self) -> CheckpointBuffers<K, V, M> {
        let saved = self.saved.take().expect("live checkpoint");
        if let Some(parent) = self.parent.take() {
            parent.absorb(saved.buffers)
        } else {
            saved.buffers
        }
    }

    pub(crate) fn apply_retaining(mut self) -> CheckpointBuffers<K, V, M> {
        self.cursor.assert_operable();
        self.take_applied_buffers()
    }

    pub(crate) fn apply(mut self) {
        self.cursor.assert_operable();
        self.cursor.edit_failed = true;
        let excess = self.take_applied_buffers();
        // No rollback may run after transferring the saved owners to the parent.
        // A refund panic leaves the complete private cursor in a failed state.
        drop(excess);
        self.cursor.edit_failed = false;
    }
}

enum DrainBuffer<'a, K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> {
    Borrowed(&'a mut Buffer<K, V, M>),
    Owned(Buffer<K, V, M>),
}

struct SuffixDrain<'a, K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> {
    buffer: DrainBuffer<'a, K, V, M>,
    cut: usize,
}

impl<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> SuffixDrain<'_, K, V, M> {
    fn drain(&mut self) {
        let buffer = match &mut self.buffer {
            DrainBuffer::Borrowed(buffer) => &mut **buffer,
            DrainBuffer::Owned(buffer) => buffer,
        };
        while buffer.as_slice().len() > self.cut {
            // Remove custody before invoking any payload or charge destructor.
            // Node::free is nonrecursive; shared parent children stay untouched.
            let node = buffer.pop().expect("initialized child suffix");
            Node::free(node);
        }
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> Drop
    for SuffixDrain<'_, K, V, M>
{
    fn drop(&mut self) {
        self.drain();
    }
}

impl<K: Clone + Ord + Debug, V: Clone, M: MapMode + NodeCloning<K, V>> Drop
    for CursorCheckpoint<'_, K, V, M>
{
    fn drop(&mut self) {
        let Some(mut saved) = self.saved.take() else {
            return;
        };
        let was_failed = self.cursor.edit_failed;
        self.cursor.edit_failed = true;
        // Restore all parent metadata and retired-pointer bookkeeping before
        // arbitrary cleanup. Published or parent-private targets are not freed
        // through last_seen: only child first_seen allocations belong to abort.
        self.cursor.root = saved.root.as_ptr();
        self.cursor.txid = saved.txid;
        self.cursor.length = saved.length;
        let retired = self
            .cursor
            .last_seen
            .as_mut()
            .expect("original retirement buffer");
        let retired_replacement = M::take_original_buffer(&mut saved.buffers.last)
            .map(|original| mem::replace(retired, original));
        retired.truncate(saved.last_cut);
        let buffer: DrainBuffer<'_, K, V, M> =
            if let Some(original) = M::take_original_buffer(&mut saved.buffers.first) {
                let child = mem::replace(&mut self.cursor.first_seen, original);
                self.cursor.first_seen.truncate(saved.first_cut);
                DrainBuffer::Owned(child)
            } else {
                DrainBuffer::Borrowed(&mut self.cursor.first_seen)
            };
        let mut drain = SuffixDrain {
            buffer,
            cut: saved.first_cut,
        };
        drain.drain();
        drop(drain);
        drop(retired_replacement);
        self.cursor.funding.drop_unused_funding();
        // Caught edit panics remain failed even if rollback itself succeeded.
        // Successful abort restores the exact parent owners without admission.
        self.cursor.edit_failed = was_failed;
    }
}

#[cfg(all(test, not(miri)))]
#[path = "checkpoint_tests.rs"]
mod tests;
