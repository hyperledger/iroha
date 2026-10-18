//! One allocation-free active scope chain for ordinary and prepared decoding.
//!
//! Contexts own their counters; this synchronous chain only borrows their layer
//! slices. No pointer escapes the closure or survives its unwind guard. Captured
//! resource errors separately retain the original counter control and attempt.

use super::*;

#[derive(Clone, Debug)]
pub(super) enum CounterOwner {
    Owned(Arc<DecodeBudgetCounters>),
    Prepared(iroha_allocation::ChargedShared<DecodeBudgetCounters>),
}
impl std::ops::Deref for CounterOwner {
    type Target = DecodeBudgetCounters;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(owner) => owner,
            Self::Prepared(owner) => owner,
        }
    }
}
impl CounterOwner {
    pub(super) fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Owned(left), Self::Owned(right)) => Arc::ptr_eq(left, right),
            (Self::Prepared(left), Self::Prepared(right)) => {
                iroha_allocation::ChargedShared::ptr_eq(left, right)
            }
            _ => false,
        }
    }
}

/// Deduplicated layers cached in a scope node for constant-time lookup.
const VISIBLE_LAYERS: usize = 8;

struct ScopeNode<'a> {
    previous: Option<&'a ScopeNode<'a>>,
    layers: &'a [ActiveDecodeBudgetLayer],
    prior_count: usize,
    count: usize,
    // The complete source-order view, computed once when the immutable chain
    // is installed. Valid when `count <= VISIBLE_LAYERS`; longer chains walk.
    visible: [Option<&'a ActiveDecodeBudgetLayer>; VISIBLE_LAYERS],
}

thread_local! {
    static ACTIVE: Cell<*const ScopeNode<'static>> = const { Cell::new(core::ptr::null()) };
}

/// Borrowed source-order view; each original counter is charged once even when
/// a lazy context is reapplied inside the same context.
#[derive(Clone, Copy)]
pub(super) struct BudgetLayers<'a> {
    head: Option<&'a ScopeNode<'a>>,
}
impl<'a> BudgetLayers<'a> {
    pub(super) fn len(self) -> usize {
        self.head.map_or(0, |head| head.count)
    }
    pub(super) fn is_empty(self) -> bool {
        self.len() == 0
    }
    fn contains(self, candidate: &ActiveDecodeBudgetLayer) -> bool {
        let mut node = self.head;
        while let Some(current) = node {
            if current
                .layers
                .iter()
                .any(|layer| layer.budget.counters.ptr_eq(&candidate.budget.counters))
            {
                return true;
            }
            node = current.previous;
        }
        false
    }
    fn get(self, index: usize) -> Option<&'a ActiveDecodeBudgetLayer> {
        if let Some(head) = self.head
            && head.count <= VISIBLE_LAYERS
        {
            return head.visible.get(index).copied().flatten();
        }
        self.walk(index)
    }
    /// Resolve `index` by walking the chain; the reference for the cached view.
    fn walk(self, index: usize) -> Option<&'a ActiveDecodeBudgetLayer> {
        let mut node = self.head;
        while let Some(current) = node {
            if index >= current.prior_count {
                let prior = Self {
                    head: current.previous,
                };
                let mut visible = current.prior_count;
                for (position, candidate) in current.layers.iter().enumerate() {
                    if prior.contains(candidate)
                        || current.layers[..position]
                            .iter()
                            .any(|layer| layer.budget.counters.ptr_eq(&candidate.budget.counters))
                    {
                        continue;
                    }
                    if visible == index {
                        return Some(candidate);
                    }
                    visible += 1;
                }
                return None;
            }
            node = current.previous;
        }
        None
    }
    pub(super) fn iter(self) -> impl ExactSizeIterator<Item = &'a ActiveDecodeBudgetLayer> {
        (0..self.len()).map(move |index| {
            self.get(index)
                .expect("active layer index was counted from the same borrowed chain")
        })
    }
}

pub(super) fn with_active<R>(body: impl for<'a> FnOnce(BudgetLayers<'a>) -> R) -> R {
    ACTIVE.with(|slot| {
        // SAFETY: only `with_layers` installs this pointer. Its stack node and
        // borrowed context remain live until the closure ends; the unwind guard
        // unlinks before either can drop. HRTB prevents returning a borrowed node.
        let head = unsafe { slot.get().as_ref() };
        body(BudgetLayers { head })
    })
}

pub(super) fn with_layers<R>(
    layers: &[ActiveDecodeBudgetLayer],
    depth: usize,
    body: impl FnOnce() -> R,
) -> R {
    let previous_depth = DECODE_NESTING_DEPTH.with(Cell::get);
    let previous = ACTIVE.with(Cell::get);
    // SAFETY: the previous synchronous scope encloses this call and cannot end
    // until it returns/unwinds. No mutable reference to its node is created.
    let parent = unsafe { previous.as_ref() };
    let prior = BudgetLayers { head: parent };
    let mut visible = [None; VISIBLE_LAYERS];
    for (slot, layer) in visible.iter_mut().zip(prior.iter()) {
        *slot = Some(layer);
    }
    let mut count = prior.len();
    for (position, candidate) in layers.iter().enumerate() {
        if !prior.contains(candidate)
            && !layers[..position]
                .iter()
                .any(|layer| layer.budget.counters.ptr_eq(&candidate.budget.counters))
        {
            if let Some(slot) = visible.get_mut(count) {
                *slot = Some(candidate);
            }
            count = count
                .checked_add(1)
                .expect("live layer slice count fits usize");
        }
    }
    let node = ScopeNode {
        previous: parent,
        layers,
        prior_count: prior.len(),
        count,
        visible,
    };
    struct Restore {
        previous: *const ScopeNode<'static>,
        depth: usize,
        _not_send: PhantomData<Rc<()>>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE.with(|slot| slot.set(self.previous));
            DECODE_NESTING_DEPTH.with(|slot| slot.set(self.depth));
        }
    }
    let restore = Restore {
        previous,
        depth: previous_depth,
        _not_send: PhantomData,
    };
    // The node stays in this stack place through `body`. The erased lifetime is
    // confined to TLS and every dereference is bounded by `restore` above.
    ACTIVE.with(|slot| slot.set(core::ptr::from_ref(&node).cast::<ScopeNode<'static>>()));
    DECODE_NESTING_DEPTH.with(|slot| slot.set(previous_depth.max(depth)));
    let value = body();
    drop(restore);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_cached_view_matches_walk() -> usize {
        with_active(|layers| {
            for index in 0..=layers.len() {
                let cached = layers.get(index).map(core::ptr::from_ref);
                let walked = layers.walk(index).map(core::ptr::from_ref);
                assert_eq!(cached, walked, "index {index} of {}", layers.len());
            }
            layers.len()
        })
    }

    fn nest(contexts: &[DecodeBudgetContext], visible: &mut Vec<usize>) {
        let Some((first, rest)) = contexts.split_first() else {
            return;
        };
        first.with(|| {
            visible.push(assert_cached_view_matches_walk());
            // Reapplying an active context adds no visible layer.
            first.with(|| visible.push(assert_cached_view_matches_walk()));
            nest(rest, visible);
        });
    }

    #[test]
    fn cached_layer_view_matches_chain_walk_with_duplicates_and_long_chains() {
        let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
        let contexts = (0..VISIBLE_LAYERS + 3)
            .map(|_| DecodeBudgetContext::new(limits))
            .collect::<Vec<_>>();
        let mut visible = Vec::new();
        nest(&contexts, &mut visible);
        let expected = (1..=contexts.len())
            .flat_map(|depth| [depth, depth])
            .collect::<Vec<_>>();
        assert_eq!(visible, expected);
        assert_eq!(assert_cached_view_matches_walk(), 0);
        // A multi-layer node mixes new, duplicated and previously active counters.
        let shared = DecodeBudgetContext::new(limits);
        shared.with(|| {
            let layers = [
                contexts[0].layer.clone(),
                shared.layer.clone(),
                contexts[0].layer.clone(),
                contexts[1].layer.clone(),
            ];
            with_layers(&layers, 0, || {
                assert_eq!(assert_cached_view_matches_walk(), 3);
            });
        });
    }
}
