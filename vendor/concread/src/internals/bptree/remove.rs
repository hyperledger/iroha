//! One canonical removal engine with checked original tracking custody.
//!
//! The caller admits node and payload copies before execution. This module
//! checks that all possible bookkeeping fits before the first raw node clone;
//! it never grows fixed buffers, obtains capacity or seals prepaid cleanup.

use super::*;

/// Additional new/retired pointers for a path with this many branch levels.
/// Path and one sibling per level contribute at most 2h+1 new nodes. Retiring
/// those originals, h merged nodes and one demoted root needs at most 3h+2.
/// A populated root leaf only clones/retires itself; absent removal needs no slots.
/// The planner and executor use this same checked bound.
pub(crate) fn remove_tracking_slots(height: usize) -> Option<[usize; 2]> {
    if height == 0 {
        return Some([1, 1]);
    }
    Some([
        height.checked_mul(2)?.checked_add(1)?,
        height.checked_mul(3)?.checked_add(2)?,
    ])
}

impl<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>> CursorWrite<K, V, M> {
    /// Remove with the original provider after membership and tracking preflight.
    /// An absent key does not clone or allocate, even with empty fixed buffers.
    /// As with `try_insert`, the caller retains the edit-failure scope until
    /// every mutation and unused-funding destructor has completed.
    pub(crate) fn try_remove(&mut self, k: &K) -> Result<Option<V>, ()> {
        if !self.remove_tracking_fits(k)? {
            return Ok(None);
        }
        let r = match clone_and_remove(
            self.root,
            self.txid,
            k,
            self.last_seen.as_mut().expect("original retirement buffer"),
            &mut self.first_seen,
            &mut self.funding,
        ) {
            CRRemoveState::NoClone(res) => res,
            CRRemoveState::Clone(res, mut nnode) => {
                mem::swap(&mut self.root, &mut nnode);
                res
            }
            CRRemoveState::Shrink(res) => {
                if self_meta_shared!(self.root).is_leaf() {
                    // No action - we have an empty tree.
                    res
                } else {
                    // Root is being demoted, get the last branch and
                    // promote it to the root.
                    self.last_seen
                        .as_mut()
                        .expect("original retirement buffer")
                        .push(self.root);
                    let rmut = branch_ref!(self.root, K, V, M::Charge);
                    let mut pnode = rmut.extract_last_node();
                    mem::swap(&mut self.root, &mut pnode);
                    res
                }
            }
            CRRemoveState::CloneShrink(res, mut nnode) => {
                if self_meta_shared!(nnode).is_leaf() {
                    // The tree is empty, but we cloned the root to get here.
                    mem::swap(&mut self.root, &mut nnode);
                    res
                } else {
                    // Our root is getting demoted here, get the remaining branch
                    self.last_seen
                        .as_mut()
                        .expect("original retirement buffer")
                        .push(nnode);
                    let rmut = branch_ref!(nnode, K, V, M::Charge);
                    let mut pnode = rmut.extract_last_node();
                    // Promote it to the new root
                    mem::swap(&mut self.root, &mut pnode);
                    res
                }
            }
        };
        if r.is_some() {
            self.length -= 1;
        }
        Ok(r)
    }

    fn remove_tracking_fits(&self, key: &K) -> Result<bool, ()> {
        // Read the original path without taking mutable aliases to shared nodes.
        // Membership is checked before any clone or fixed-buffer requirement.
        let mut node = self.root;
        let mut branches = 0usize;
        while !self_meta_shared!(node).is_leaf() {
            branches = branches.checked_add(1).ok_or(())?;
            if branches >= usize::BITS as usize {
                return Err(());
            }
            let branch = branch_ref_shared!(node, K, V, M::Charge);
            node = branch.get_idx_unchecked(branch.locate_node(key));
        }
        if leaf_ref_shared!(node, K, V, M::Charge)
            .get_ref(key)
            .is_none()
        {
            return Ok(false);
        }
        // At most b+1 original path nodes and b adjacent siblings are cloned.
        // Each clone retires its source; each of b rebalances can additionally
        // retire one merged node, and root demotion retires one final branch.
        // Removal never splits or allocates another kind of node.
        let [new_required, retired_required] = remove_tracking_slots(branches).ok_or(())?;
        if self
            .first_seen
            .remaining_capacity()
            .is_some_and(|n| n < new_required)
            || self
                .last_seen
                .as_ref()
                .expect("original retirement buffer")
                .remaining_capacity()
                .is_some_and(|n| n < retired_required)
        {
            return Err(());
        }
        Ok(true)
    }
}

fn clone_and_remove<K: Clone + Ord + Debug, V: Clone, M: CursorMode<K, V>>(
    node: *mut Node<K, V, M::Charge>,
    txid: u64,
    k: &K,
    last_seen: &mut M::Buffer,
    first_seen: &mut M::Buffer,
    funding: &mut M,
) -> CRRemoveState<K, V, M::Charge> {
    if self_meta_shared!(node).is_leaf() {
        leaf_ref_shared!(node, K, V, M::Charge)
            .req_clone(txid, funding)
            .map(|cnode| {
                first_seen.push(cnode);
                // println!("ls push 10 {:?}", node);
                last_seen.push(node);
                let mref = leaf_ref!(cnode, K, V, M::Charge);
                match mref.remove(k) {
                    LeafRemoveState::Ok(res) => CRRemoveState::Clone(res, cnode),
                    LeafRemoveState::Shrink(res) => CRRemoveState::CloneShrink(res, cnode),
                }
            })
            .unwrap_or_else(|| {
                let mref = leaf_ref!(node, K, V, M::Charge);
                match mref.remove(k) {
                    LeafRemoveState::Ok(res) => CRRemoveState::NoClone(res),
                    LeafRemoveState::Shrink(res) => CRRemoveState::Shrink(res),
                }
            })
    } else {
        // Locate the node we need to work on and then react if it
        // requests a shrink.
        branch_ref_shared!(node, K, V, M::Charge)
            .req_clone(txid, funding)
            .map(|cnode| {
                first_seen.push(cnode);
                // println!("ls push 11 {:?}", node);
                last_seen.push(node);
                // Done mm
                let nmref = branch_ref!(cnode, K, V, M::Charge);
                let anode_idx = nmref.locate_node(k);
                let anode = nmref.get_idx_unchecked(anode_idx);
                match clone_and_remove(anode, txid, k, last_seen, first_seen, funding) {
                    CRRemoveState::NoClone(_res) => {
                        unreachable!("Should never occur");
                    }
                    CRRemoveState::Clone(res, lnode) => {
                        nmref.replace_by_idx(anode_idx, lnode);
                        CRRemoveState::Clone(res, cnode)
                    }
                    CRRemoveState::Shrink(_res) => {
                        unreachable!("This represents a corrupt tree state");
                    }
                    CRRemoveState::CloneShrink(res, nnode) => {
                        // Put our cloned child into the tree at the correct location, don't worry,
                        // the shrink_decision will deal with it.
                        nmref.replace_by_idx(anode_idx, nnode);

                        // Now setup the sibling, to the left *or* right.
                        let right_idx = nmref
                            .clone_sibling_idx(txid, anode_idx, last_seen, first_seen, funding);
                        // Okay, now work out what we need to do.
                        match nmref.shrink_decision(right_idx, funding) {
                            BranchShrinkState::Balanced => {
                                // K:V were distributed through left and right,
                                // so no further action needed.
                                CRRemoveState::Clone(res, cnode)
                            }
                            BranchShrinkState::Merge(dnode) => {
                                // Right was merged to left, and we remain
                                // valid
                                debug_assert!(!last_seen.as_slice().contains(&dnode));
                                last_seen.push(dnode);
                                CRRemoveState::Clone(res, cnode)
                            }
                            BranchShrinkState::Shrink(dnode) => {
                                // Right was merged to left, but we have now fallen under the needed
                                // amount of values.
                                debug_assert!(!last_seen.as_slice().contains(&dnode));
                                last_seen.push(dnode);
                                CRRemoveState::CloneShrink(res, cnode)
                            }
                        }
                    }
                }
            })
            .unwrap_or_else(|| {
                // We are already part of this txn
                let nmref = branch_ref!(node, K, V, M::Charge);
                let anode_idx = nmref.locate_node(k);
                let anode = nmref.get_idx_unchecked(anode_idx);
                match clone_and_remove(anode, txid, k, last_seen, first_seen, funding) {
                    CRRemoveState::NoClone(res) => CRRemoveState::NoClone(res),
                    CRRemoveState::Clone(res, lnode) => {
                        nmref.replace_by_idx(anode_idx, lnode);
                        CRRemoveState::NoClone(res)
                    }
                    CRRemoveState::Shrink(res) => {
                        let right_idx = nmref
                            .clone_sibling_idx(txid, anode_idx, last_seen, first_seen, funding);
                        match nmref.shrink_decision(right_idx, funding) {
                            BranchShrinkState::Balanced => {
                                // K:V were distributed through left and right,
                                // so no further action needed.
                                CRRemoveState::NoClone(res)
                            }
                            BranchShrinkState::Merge(dnode) => {
                                // Right was merged to left, and we remain
                                // valid
                                //
                                // A quirk here is based on how clone_sibling_idx works. We may actually
                                // start with anode_idx of 0, which triggers a right clone, so it's
                                // *already* in the mm lists. But here right is "last seen" now if
                                //
                                // println!("ls push 22 {:?}", dnode);
                                debug_assert!(!last_seen.as_slice().contains(&dnode));
                                last_seen.push(dnode);
                                CRRemoveState::NoClone(res)
                            }
                            BranchShrinkState::Shrink(dnode) => {
                                // Right was merged to left, but we have now fallen under the needed
                                // amount of values, so we begin to shrink up.
                                // println!("ls push 23 {:?}", dnode);
                                debug_assert!(!last_seen.as_slice().contains(&dnode));
                                last_seen.push(dnode);
                                CRRemoveState::Shrink(res)
                            }
                        }
                    }
                    CRRemoveState::CloneShrink(res, nnode) => {
                        // We don't need to clone, just work on the nmref we have.
                        //
                        // Swap in the cloned node to the correct location.
                        nmref.replace_by_idx(anode_idx, nnode);
                        // Now setup the sibling, to the left *or* right.
                        let right_idx = nmref
                            .clone_sibling_idx(txid, anode_idx, last_seen, first_seen, funding);
                        match nmref.shrink_decision(right_idx, funding) {
                            BranchShrinkState::Balanced => {
                                // K:V were distributed through left and right,
                                // so no further action needed.
                                CRRemoveState::NoClone(res)
                            }
                            BranchShrinkState::Merge(dnode) => {
                                // Right was merged to left, and we remain
                                // valid
                                // println!("ls push 24 {:?}", dnode);
                                debug_assert!(!last_seen.as_slice().contains(&dnode));
                                last_seen.push(dnode);
                                CRRemoveState::NoClone(res)
                            }
                            BranchShrinkState::Shrink(dnode) => {
                                // Right was merged to left, but we have now fallen under the needed
                                // amount of values.
                                // println!("ls push 25 {:?}", dnode);
                                debug_assert!(!last_seen.as_slice().contains(&dnode));
                                last_seen.push(dnode);
                                CRRemoveState::Shrink(res)
                            }
                        }
                    }
                }
            }) // end unwrap_or_else
    }
}

#[cfg(all(test, not(miri)))]
#[path = "remove_tests.rs"]
mod tests;
