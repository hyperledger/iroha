//! Finite structural row positions over an already retained immutable cursor.

use super::node::{Branch, Leaf, Node};
use std::fmt::Debug;

// The original completed-tree invariant and bound also used by LeafPath and
// Node::visit_tree: at least two children per branch, with usize-counted rows.
pub(crate) const PATH_CAPACITY: usize = usize::BITS as usize + 1;

// One next-position call follows the previous path, climbs its ancestors and
// descends the next subtree. Each part examines at most PATH_CAPACITY nodes.
// Admission precedes every examination, including rejection of damaged slots.
pub(crate) const NEXT_WORK_BOUND: usize = 3 * PATH_CAPACITY;

/// Private slots only: no reference or retained raw node pointer.
#[derive(Clone, Copy)]
pub(crate) struct RowPath {
    pub(crate) children: [usize; PATH_CAPACITY],
    pub(crate) depth: usize,
    pub(crate) row: usize,
}

impl RowPath {
    pub(crate) fn work_bound(&self) -> Option<usize> {
        (self.depth < PATH_CAPACITY).then(|| self.depth + 1)
    }
}

// These helpers accept only nodes reached from the live cursor's original
// root. The cursor owner pins both unpublished and shared predecessor nodes;
// the frozen facade prevents mutation while any resulting borrow exists.
fn child<K: Ord + Clone + Debug, V: Clone, C>(
    node: &Node<K, V, C>,
    slot: usize,
) -> Option<&Node<K, V, C>> {
    if !node.meta.is_branch() {
        return None;
    }
    // SAFETY: original node metadata selects its actual branch layout.
    let branch = unsafe { &*(std::ptr::from_ref(node).cast::<Branch<K, V, C>>()) };
    let pointer = branch.get_idx_checked(slot)?;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the checked original branch child remains pinned and immutable
    // for the same cursor borrow as its parent. No pointer escapes this call.
    Some(unsafe { &*pointer })
}

fn leaf<K: Ord + Clone + Debug, V: Clone, C>(node: &Node<K, V, C>) -> Option<&Leaf<K, V, C>> {
    if !node.meta.is_leaf() {
        return None;
    }
    // SAFETY: original node metadata selects its actual leaf layout, whose
    // initialized row prefix remains alive for this immutable cursor borrow.
    Some(unsafe { &*(std::ptr::from_ref(node).cast::<Leaf<K, V, C>>()) })
}

pub(crate) fn resolve<'a, K: Ord + Clone + Debug, V: Clone, C>(
    root: &'a Node<K, V, C>,
    position: &RowPath,
) -> Option<(&'a K, &'a V)> {
    position.work_bound()?;
    let mut node = root;
    for slot in &position.children[..position.depth] {
        node = child(node, *slot)?;
    }
    leaf(node)?.get_kv_idx_checked(position.row)
}

fn descend<K: Ord + Clone + Debug, V: Clone, C>(
    mut node: &Node<K, V, C>,
    mut path: RowPath,
) -> Result<Option<RowPath>, ()> {
    loop {
        if let Some(leaf) = leaf(node) {
            if leaf.count() == 0 {
                // Only a root leaf may be empty in a completed tree.
                return if path.depth == 0 { Ok(None) } else { Err(()) };
            }
            path.row = 0;
            return Ok(Some(path));
        }
        // Preserve one final slot for the leaf's finite resolve step.
        if path.depth + 1 >= PATH_CAPACITY {
            return Err(());
        }
        path.children[path.depth] = 0;
        path.depth += 1;
        node = child(node, 0).ok_or(())?;
    }
}

pub(crate) fn next_path<K: Ord + Clone + Debug, V: Clone, C>(
    root: &Node<K, V, C>,
    previous: Option<&RowPath>,
) -> Result<Option<RowPath>, ()> {
    let Some(previous) = previous else {
        return descend(
            root,
            RowPath {
                children: [0; PATH_CAPACITY],
                depth: 0,
                row: 0,
            },
        );
    };
    previous.work_bound().ok_or(())?;
    let mut ancestors = [None; PATH_CAPACITY];
    let mut node = root;
    for (depth, slot) in previous.children[..previous.depth].iter().enumerate() {
        ancestors[depth] = Some(node);
        node = child(node, *slot).ok_or(())?;
    }
    let current_leaf = leaf(node).ok_or(())?;
    if previous.row >= current_leaf.count() {
        return Err(());
    }
    if previous.row + 1 < current_leaf.count() {
        let mut next = *previous;
        next.row += 1;
        return Ok(Some(next));
    }
    for depth in (0..previous.depth).rev() {
        let ancestor = ancestors[depth].ok_or(())?;
        let slot = previous.children[depth].checked_add(1).ok_or(())?;
        if let Some(node) = child(ancestor, slot) {
            let mut next = *previous;
            next.children[depth] = slot;
            next.depth = depth + 1;
            return descend(node, next);
        }
    }
    Ok(None)
}
