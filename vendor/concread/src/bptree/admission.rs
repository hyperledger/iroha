//! Closed writer and edit admission for the existing synchronous map engine.

use super::*;
use crate::internals::bptree::cursor::checked_next_generation;
use crate::internals::bptree::node::{Branch, Leaf, Node};
use crate::internals::bptree::tracking::NodeTrackingBuffer;
use crate::internals::lincowcell::{
    InitialCharges, WriterAdmission, WriterAdmissionError, WriterCharges, WriterLayouts,
};
use crossbeam_utils::CachePadded;
use std::alloc::Layout;

#[path = "pair_admission.rs"]
mod pair_admission;
pub use pair_admission::PairInsertError;

#[path = "clear_admission.rs"]
mod clear_admission;

#[path = "delete_admission.rs"]
mod delete_admission;
pub use delete_admission::PairRemoveError;

// This guard must precede, and therefore outlive, every nested checkpoint. A
// caller may catch an unwind while keeping both physical writers: lock poison
// alone cannot protect their partly applied or failed private generations.
struct BorrowedPair<'c, 'u, K, V, P>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    current: &'c mut CursorWrite<K, V, Prepaid<P>>,
    undo: &'u mut CursorWrite<K, Option<V>, Prepaid<P>>,
    resolved: bool,
}
impl<K, V, P> Drop for BorrowedPair<'_, '_, K, V, P>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    fn drop(&mut self) {
        if !self.resolved {
            self.current.poison_joined_edit();
            self.undo.poison_joined_edit();
        }
    }
}

/// Checked sum of actual requested allocation layouts, not encoded sizes or RSS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationDemand {
    bytes: usize,
    allocations: usize,
}
impl AllocationDemand {
    /// Empty demand, with no planning allocation.
    pub fn new() -> Self {
        Self::default()
    }
    /// Requested bytes across the planned concrete allocations.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// Upper bound on nonzero allocation calls represented by this demand.
    pub fn allocations(&self) -> usize {
        self.allocations
    }
    /// Add one actual concrete layout with checked arithmetic.
    pub fn add_layout(&mut self, layout: Layout) -> Result<(), PlanningError> {
        self.add(
            Self {
                bytes: layout.size(),
                allocations: usize::from(layout.size() != 0),
            },
            1,
        )
    }
    /// Combine another checked demand before reserving shared operation credit.
    ///
    /// Both byte and allocation counts use checked arithmetic. Refusal leaves
    /// the original sum unchanged; combining observations grants no mutation
    /// authority and does not suppress each held writer's execution-time plan.
    pub fn add_demand(&mut self, other: Self) -> Result<(), PlanningError> {
        self.add(other, 1)
    }

    fn add(&mut self, other: Self, copies: usize) -> Result<(), PlanningError> {
        let bytes = other
            .bytes
            .checked_mul(copies)
            .and_then(|n| self.bytes.checked_add(n))
            .ok_or(PlanningError::Overflow)?;
        let allocations = other
            .allocations
            .checked_mul(copies)
            .and_then(|n| self.allocations.checked_add(n))
            .ok_or(PlanningError::Overflow)?;
        *self = Self { bytes, allocations };
        Ok(())
    }
    fn include_max(&mut self, other: Self) {
        self.bytes = self.bytes.max(other.bytes);
        self.allocations = self.allocations.max(other.allocations);
    }
}

/// Allocation-free description of the nested storage a payload copy may own.
///
/// Implementations enumerate actual layouts into the checked demand. They must
/// not clone, serialize or allocate while planning; key ordering and diagnostic
/// formatting must likewise allocate no unadmitted storage. A key's bound must also cover
/// a copy of that key made by this same policy: insertion and removal can use a
/// freshly cloned leaf key as a separator. Returned copies must preserve key ordering.
/// Values are copied at most once during a closed edit. Existing incoming
/// payloads already own their storage; the plan funds new copies only.
/// A successful bound must remain valid for the complete lifetime of the
/// immutable source borrow held by a preparation. Shared or interior-mutable
/// payloads whose copied allocation demand can increase during that lifetime
/// must return `UnsupportedPayload`; a read-only reference alone does not make
/// their nested allocation demand stable.
pub trait ClonePlanning<K, V>: NodeCloning<K, V> {
    /// Add all nested layouts owned by a key copy and copies of that key.
    fn plan_key(key: &K, demand: &mut AllocationDemand) -> Result<(), PlanningError>;
    /// Add all nested layouts owned by a value copy.
    fn plan_value(value: &V, demand: &mut AllocationDemand) -> Result<(), PlanningError>;
}

/// A complete allocation demand cannot be established before allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanningError {
    /// A count, layout, byte sum or generation exceeds its representable limit.
    Overflow,
    /// The payload policy cannot provide a concrete allocation bound.
    UnsupportedPayload,
}

/// Local refusal before constructing any acquisition or edit allocation.
#[derive(Debug)]
pub enum MapAdmissionError<E> {
    /// Another writer currently owns the original map lock.
    Busy,
    /// An earlier unwind poisoned the original writer lock.
    Poisoned,
    /// A retained successor belongs to another map or an obsolete generation.
    Changed,
    /// Planning failed before calling the admission provider.
    Planning(PlanningError),
    /// The original provider refused the complete checked demand.
    Refused(E),
}

struct WriterStartPlan {
    demand: AllocationDemand,
    tracking_layout: Layout,
}

fn plan_writer_start<K, V, P>(
    source: &SuperBlock<K, V, Prepaid<P>>,
    shells: WriterLayouts,
) -> Result<WriterStartPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: NodeCloning<K, V>,
{
    checked_next_generation(source.txid).ok_or(PlanningError::Overflow)?;
    writer_start_plan::<K, V, P>(shells)
}

fn writer_start_plan<K, V, P>(shells: WriterLayouts) -> Result<WriterStartPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: NodeCloning<K, V>,
{
    type Buffer<K, V, C> = FixedTrackingBuffer<*mut Node<K, V, C>, C>;
    let tracking_layout =
        Buffer::<K, V, P::Charge>::allocation_layout(0).map_err(|_| PlanningError::Overflow)?;
    let mut demand = AllocationDemand::new();
    for layout in [
        shells.cursor,
        shells.reader,
        tracking_layout,
        tracking_layout,
    ] {
        demand.add_layout(layout)?;
    }
    Ok(WriterStartPlan {
        demand,
        tracking_layout,
    })
}

struct InsertPlan {
    demand: AllocationDemand,
    tree_demand: AllocationDemand,
    first: usize,
    last: usize,
    first_layout: Layout,
    last_layout: Layout,
}

fn key_demand<K, V, P: ClonePlanning<K, V>>(key: &K) -> Result<AllocationDemand, PlanningError> {
    let mut demand = AllocationDemand::new();
    P::plan_key(key, &mut demand)?;
    Ok(demand)
}

fn plan_insert<K, V, P>(
    source: &SuperBlock<K, V, Prepaid<P>>,
    key: &K,
    shells: WriterLayouts,
) -> Result<InsertPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    checked_next_generation(source.txid).ok_or(PlanningError::Overflow)?;
    // SAFETY: the source is retained under its original writer lock.
    let mut plan = unsafe { plan_tree_insert::<K, V, P>(source.root, source.size, key) }?;
    for layout in [shells.cursor, shells.reader] {
        plan.demand.add_layout(layout)?;
    }
    Ok(plan)
}

// SAFETY: root and every reachable node must remain alive and immutable for this
// call, under the original writer lock. No tree pointer escapes the plan.
unsafe fn plan_tree_insert<K, V, P>(
    root: *mut Node<K, V, P::Charge>,
    length: usize,
    key: &K,
) -> Result<InsertPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    length.checked_add(1).ok_or(PlanningError::Overflow)?;
    let mut demand = AllocationDemand::new();
    let mut separator = key_demand::<K, V, P>(key)?;
    let mut branches = 0usize;
    let mut node = root;
    // All references belong to the original published or retained private tree
    // under its writer lock. Planning neither creates a reader nor mutates nodes.
    while !unsafe { &*node }.is_leaf() {
        branches = branches.checked_add(1).ok_or(PlanningError::Overflow)?;
        if branches >= usize::BITS as usize {
            return Err(PlanningError::Overflow);
        }
        let branch = unsafe { &*node.cast::<Branch<K, V, P::Charge>>() };
        for index in 0..branch.count() {
            let cloned = key_demand::<K, V, P>(branch.key_at(index))?;
            demand.add(cloned, 1)?;
            separator.include_max(cloned);
        }
        // A split may detach either of the final children, even when insertion
        // descends elsewhere. Include every original child minimum as a possible
        // new separator; fresh-child minima come from this path or incoming key.
        for index in 0..=branch.count() {
            let minimum = unsafe { &*Node::min_raw(branch.get_idx_unchecked(index)) };
            separator.include_max(key_demand::<K, V, P>(minimum)?);
        }
        node = branch.get_idx_unchecked(branch.locate_node(key));
    }
    let leaf = unsafe { &*node.cast::<Leaf<K, V, P::Charge>>() };
    for index in 0..leaf.count() {
        let (key, value) = leaf
            .get_kv_idx_checked(index)
            .expect("initialized leaf prefix");
        let cloned = key_demand::<K, V, P>(key)?;
        demand.add(cloned, 1)?;
        separator.include_max(cloned);
        P::plan_value(value, &mut demand)?;
    }
    // One leaf clone and singleton split; one clone and sibling per branch;
    // one possible new root. Each branch adds at most one separator and one
    // sibling separator, with one final root separator. These are counts of
    // real engine allocations/copies, not a guessed encoded-size multiplier.
    let branch_nodes = branches
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(PlanningError::Overflow)?;
    let first = branch_nodes.checked_add(2).ok_or(PlanningError::Overflow)?;
    let last = branches.checked_add(1).ok_or(PlanningError::Overflow)?;
    let mut leaf_layout = AllocationDemand::new();
    leaf_layout.add_layout(Layout::new::<CachePadded<Leaf<K, V, P::Charge>>>())?;
    demand.add(leaf_layout, 2)?;
    let mut branch_layout = AllocationDemand::new();
    branch_layout.add_layout(Layout::new::<CachePadded<Branch<K, V, P::Charge>>>())?;
    demand.add(branch_layout, branch_nodes)?;
    demand.add(separator, branch_nodes)?;
    type Buffer<K, V, C> = FixedTrackingBuffer<*mut Node<K, V, C>, C>;
    let first_layout =
        Buffer::<K, V, P::Charge>::allocation_layout(first).map_err(|_| PlanningError::Overflow)?;
    let last_layout =
        Buffer::<K, V, P::Charge>::allocation_layout(last).map_err(|_| PlanningError::Overflow)?;
    let tree_demand = demand;
    for layout in [first_layout, last_layout] {
        demand.add_layout(layout)?;
    }
    Ok(InsertPlan {
        demand,
        tree_demand,
        first,
        last,
        first_layout,
        last_layout,
    })
}

struct TrackingGrowth {
    capacity: usize,
    layout: Layout,
}

fn plan_tracking_growth<K, V, P>(
    initialized: usize,
    capacity: usize,
    required: usize,
    demand: &mut AllocationDemand,
) -> Result<Option<TrackingGrowth>, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: NodeCloning<K, V>,
{
    let needed = initialized
        .checked_add(required)
        .ok_or(PlanningError::Overflow)?;
    if needed <= capacity {
        return Ok(None);
    }
    // Geometric growth bounds cumulative pointer copies over a multi-edit
    // successor. Both the retained old buffer and its replacement remain paid
    // during construction; no capacity is borrowed from a future refund.
    type Buffer<K, V, C> = FixedTrackingBuffer<*mut Node<K, V, C>, C>;
    let enlarged = capacity.checked_mul(2).map(|n| n.max(needed));
    let (capacity, layout) = enlarged
        .and_then(|n| {
            Buffer::<K, V, P::Charge>::allocation_layout(n)
                .ok()
                .map(|l| (n, l))
        })
        .or_else(|| {
            Buffer::<K, V, P::Charge>::allocation_layout(needed)
                .ok()
                .map(|l| (needed, l))
        })
        .ok_or(PlanningError::Overflow)?;
    demand.add_layout(layout)?;
    Ok(Some(TrackingGrowth { capacity, layout }))
}

// A private execution plan never escapes the original exclusive cursor. Public
// demand observation returns only its checked size/count, not mutation authority.
struct EditPlan {
    demand: AllocationDemand,
    first: Option<TrackingGrowth>,
    last: Option<TrackingGrowth>,
}

fn plan_edit<K, V, P>(
    cursor: &CursorWrite<K, V, Prepaid<P>>,
    key: &K,
) -> Result<EditPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    cursor.assert_operable();
    // SAFETY: the original exclusive writer/checkpoint borrow retains the base
    // and every reachable private node for the entire read-only planning call.
    let plan = unsafe { plan_tree_insert::<K, V, P>(cursor.get_root(), cursor.len(), key) }?;
    let mut demand = plan.tree_demand;
    let [(first_len, first_capacity), (last_len, last_capacity)] = cursor.admitted_tracking();
    let first =
        plan_tracking_growth::<K, V, P>(first_len, first_capacity, plan.first, &mut demand)?;
    let last = plan_tracking_growth::<K, V, P>(last_len, last_capacity, plan.last, &mut demand)?;
    Ok(EditPlan {
        demand,
        first,
        last,
    })
}

// SAFETY: root is retained unchanged under its original physical writer.
unsafe fn plan_tree_clear<K, V, P>(
    root: *mut Node<K, V, P::Charge>,
    tracking: [(usize, usize); 2],
) -> Result<EditPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: NodeCloning<K, V>,
{
    let retired = unsafe { Node::tree_node_count(root) }.ok_or(PlanningError::Overflow)?;
    let mut demand = AllocationDemand::new();
    demand.add_layout(Layout::new::<CachePadded<Leaf<K, V, P::Charge>>>())?;
    let [(first_len, first_capacity), (last_len, last_capacity)] = tracking;
    let first = plan_tracking_growth::<K, V, P>(first_len, first_capacity, 1, &mut demand)?;
    let last = plan_tracking_growth::<K, V, P>(last_len, last_capacity, retired, &mut demand)?;
    Ok(EditPlan {
        demand,
        first,
        last,
    })
}

fn plan_clear<K, V, P>(cursor: &CursorWrite<K, V, Prepaid<P>>) -> Result<EditPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: NodeCloning<K, V>,
{
    cursor.assert_operable();
    checked_next_generation(cursor.get_txid()).ok_or(PlanningError::Overflow)?;
    // SAFETY: the original exclusive cursor owns its root and retained base.
    unsafe { plan_tree_clear::<K, V, P>(cursor.get_root(), cursor.admitted_tracking()) }
}

// Plan one original node's possible copy, and all source keys from which
// rebalancing can create a separator. Descendant minima are borrowed only;
// this never walks the complete subtree or constructs a speculative successor.
unsafe fn plan_removal_node<K, V, P>(
    node: *mut Node<K, V, P::Charge>,
    demand: &mut AllocationDemand,
    separator: &mut AllocationDemand,
) -> Result<(), PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    if unsafe { &*node }.is_leaf() {
        demand.add_layout(Layout::new::<CachePadded<Leaf<K, V, P::Charge>>>())?;
        let leaf = unsafe { &*node.cast::<Leaf<K, V, P::Charge>>() };
        for index in 0..leaf.count() {
            let (key, value) = leaf
                .get_kv_idx_checked(index)
                .expect("initialized leaf prefix");
            let copied_key = key_demand::<K, V, P>(key)?;
            demand.add_demand(copied_key)?;
            separator.include_max(copied_key);
            P::plan_value(value, demand)?;
        }
    } else {
        demand.add_layout(Layout::new::<CachePadded<Branch<K, V, P::Charge>>>())?;
        let branch = unsafe { &*node.cast::<Branch<K, V, P::Charge>>() };
        for index in 0..branch.count() {
            let copied_key = key_demand::<K, V, P>(branch.key_at(index))?;
            demand.add_demand(copied_key)?;
            separator.include_max(copied_key);
        }
        for index in 0..=branch.count() {
            let minimum = unsafe { &*Node::min_raw(branch.get_idx_unchecked(index)) };
            separator.include_max(key_demand::<K, V, P>(minimum)?);
        }
    }
    Ok(())
}

fn plan_remove<K, V, P>(
    cursor: &CursorWrite<K, V, Prepaid<P>>,
    key: &K,
) -> Result<EditPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    cursor.assert_operable();
    let mut demand = AllocationDemand::new();
    // An absent key does not clone a path, grow tracking, or call a payload
    // policy. In particular an unsupported payload cannot prevent a no-op.
    if !cursor.contains_key(key) {
        return Ok(EditPlan {
            demand,
            first: None,
            last: None,
        });
    }
    let mut separator = AllocationDemand::new();
    let mut branches = 0usize;
    let mut node = cursor.get_root();
    loop {
        // SAFETY: the exclusive cursor retains this original path and siblings
        // unchanged throughout planning; none of these pointers escapes.
        unsafe { plan_removal_node::<K, V, P>(node, &mut demand, &mut separator) }?;
        if unsafe { &*node }.is_leaf() {
            break;
        }
        branches = branches.checked_add(1).ok_or(PlanningError::Overflow)?;
        if branches >= usize::BITS as usize {
            return Err(PlanningError::Overflow);
        }
        let branch = unsafe { &*node.cast::<Branch<K, V, P::Charge>>() };
        let index = branch.locate_node(key);
        let sibling = if index == 0 { 1 } else { index - 1 };
        // This is the exact sibling chosen by clone_sibling_idx if the child
        // shrinks. It can be copied once; its descendants remain shared.
        unsafe {
            plan_removal_node::<K, V, P>(
                branch.get_idx_unchecked(sibling),
                &mut demand,
                &mut separator,
            )
        }?;
        node = branch.get_idx_unchecked(index);
    }
    // Rebalancing adds at most a bridge separator plus a parent separator at
    // each level. Both derive from one of the original minima or leaf keys
    // examined above, including a new minimum after deleting the old first key.
    demand.add(
        separator,
        branches.checked_mul(2).ok_or(PlanningError::Overflow)?,
    )?;
    // Each path node and at most one sibling per branch may clone. Retirement
    // additionally records one merged node per level and one demoted root.
    let [new_nodes, retired_nodes] =
        crate::internals::bptree::cursor::remove_tracking_slots(branches)
            .ok_or(PlanningError::Overflow)?;
    let [(first_len, first_capacity), (last_len, last_capacity)] = cursor.admitted_tracking();
    let first = plan_tracking_growth::<K, V, P>(first_len, first_capacity, new_nodes, &mut demand)?;
    let last =
        plan_tracking_growth::<K, V, P>(last_len, last_capacity, retired_nodes, &mut demand)?;
    Ok(EditPlan {
        demand,
        first,
        last,
    })
}

fn allocate_tracking<K, V, P>(
    growth: Option<TrackingGrowth>,
    provider: &mut P,
) -> Option<NodeTrackingBuffer<K, V, P::Charge>>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: NodeCloning<K, V>,
{
    growth.map(|growth| {
        let charge = provider.take_node_charge(growth.layout);
        FixedTrackingBuffer::try_new(growth.capacity, charge)
            .unwrap_or_else(|_| unreachable!("planned tracking growth layout"))
    })
}

impl<K, V, P> BptreeMap<K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: NodeCloning<K, V>,
{
    /// Exact layout-only demand for the original no-edit writer start.
    ///
    /// This grants no lock or generation authority. `try_write_admitted` repeats
    /// generation preflight and the same concrete plan under the original lock.
    pub fn writer_start_allocation_demand() -> Result<AllocationDemand, PlanningError> {
        Ok(
            writer_start_plan::<K, V, P>(MapCell::<K, V, Prepaid<P>>::writer_allocation_layouts())?
                .demand,
        )
    }

    /// Exact initial node/root/reader and notification control layouts.
    /// Native lock internals and pending waiter storage remain outside this demand.
    pub fn node_custody_allocation_demand() -> Result<AllocationDemand, PlanningError> {
        let initial = MapCell::<K, V, Prepaid<P>>::initial_allocation_layouts();
        let mut demand = AllocationDemand::new();
        demand.add_layout(Layout::new::<CachePadded<Leaf<K, V, P::Charge>>>())?;
        for layout in [initial.root, initial.reader, initial.notification] {
            demand.add_layout(layout)?;
        }
        Ok(demand)
    }

    /// Admit an original writer without inserting or copying any tree entry.
    ///
    /// The callback runs once under the original nonblocking writer lock, after
    /// checked generation preflight and before either shell is allocated. Its
    /// complete demand covers the original cursor and next-reader shells; both
    /// fixed tracking buffers have explicit zero capacity and zero allocation.
    /// The provider supplies their zero-layout charges without inventing an
    /// allocator event. A later closed insertion admits its own buffer growth,
    /// nodes and payload copies; no payload planning is needed to start a writer.
    ///
    /// Busy, poison, overflow or refusal leaves the published map unchanged and
    /// allocates nothing. Successful acquisition preserves the original root,
    /// length and contents. Nest another map's admission callback to reserve a
    /// combined demand while both original locks are held. Call `detach` to retain
    /// this same private cursor.
    /// The caller must keep acquisition, the returned writer and its cleanup in
    /// the original budget's synchronous refund-notification deferral scope.
    /// A panic while dropping unused funding aborts the new cursor and poisons
    /// the original writer lock; no partially sealed writer is returned.
    pub fn try_write_admitted<E>(
        &self,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> Result<BptreeMapWriteTxn<'_, K, V, Prepaid<P>>, MapAdmissionError<E>> {
        let Some(acquired) = self.try_acquire_writer() else {
            return Err(MapAdmissionError::Busy);
        };
        match acquired.try_write_admitted(admit) {
            Ok(writer) => Ok(writer),
            Err((acquired, error)) => {
                drop(acquired);
                Err(error)
            }
        }
    }
}

impl<K, V, P> BptreeMap<K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Construct an empty map with prepaid node, root and initial reader owners.
    ///
    /// The callback runs before all four charged allocations and supplies the
    /// original provider for their exact layouts. Platform-native mutex storage
    /// remains outside this demand.
    /// TODO: bind native lock/runtime storage before claiming complete map
    /// construction admission. This constructor does not claim that bound.
    pub fn try_new_with_node_custody<E>(
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> Result<Self, E>
    where
        P::Charge: Send + Sync + 'static,
    {
        let initial = MapCell::<K, V, Prepaid<P>>::initial_allocation_layouts();
        let demand = Self::node_custody_allocation_demand()
            .expect("four concrete initial layouts fit usize");
        let mut provider = Prepaid(Some(admit(demand)?));
        // The initial node takes its own original charge immediately before
        // allocation. The still-owned SuperBlock reclaims it if setup unwinds.
        let source = unsafe { SuperBlock::new_with_funding(&mut provider) };
        let charges = InitialCharges {
            notification: iroha_allocation::release::ReleaseNotification::new_charged(
                provider.take_node_charge(initial.notification),
            ),
            root: provider.take_node_charge(initial.root),
            reader: provider.take_node_charge(initial.reader),
        };
        Ok(Self {
            inner: LinCowCell::new_charged(source, charges),
        })
    }

    /// Acquire this original writer and admit clearing its exact published tree.
    ///
    /// One callback covers both shells, one empty leaf and all original-node
    /// retirement slots. It runs under the writer lock before any allocation;
    /// the returned empty successor is still private and held. This permits a
    /// caller to nest pair acquisition and reserve the full joint demand once.
    /// Retained readers keep the old nodes and payloads until their actual drop.
    /// Enclose this operation and writer lifetime in the original refund scope.
    pub fn try_clear_admitted<E>(
        &self,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> Result<BptreeMapWriteTxn<'_, K, V, Prepaid<P>>, MapAdmissionError<E>> {
        let Some(acquired) = self.try_acquire_writer() else {
            return Err(MapAdmissionError::Busy);
        };
        match acquired.try_clear_admitted(admit) {
            Ok(writer) => Ok(writer),
            Err((acquired, error)) => {
                drop(acquired);
                Err(error)
            }
        }
    }

    /// Plan and execute one insertion, retaining its exact unpublished successor.
    ///
    /// Contention, poison, overflow or admission refusal returns the same owned
    /// input before any new node, payload, shell or bookkeeping allocation. The
    /// callback receives a complete checked upper bound while the original
    /// writer lock is held. It must reserve once; its returned provider splits
    /// that owner without fresh pool acquisition during execution.
    ///
    /// The caller must enclose this synchronous operation in the original
    /// budget's refund-notification deferral scope. Incoming payloads already
    /// own their storage. A clone panic aborts the private cursor and preserves
    /// the published generation; a partly mutated cursor is never returned for
    /// retry. The returned owner has no unrestricted mutation interface.
    pub fn try_insert_admitted<E>(
        &self,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> AdmittedInsertResult<K, V, P, E> {
        self.insert_with_source(key, value, |_, demand| {
            admit(demand).map_err(MapAdmissionError::Refused)
        })
    }

    fn insert_with_source<E>(
        &self,
        key: K,
        value: V,
        admit: impl FnOnce(
            &SuperBlock<K, V, Prepaid<P>>,
            AllocationDemand,
        ) -> Result<P, MapAdmissionError<E>>,
    ) -> AdmittedInsertResult<K, V, P, E> {
        let Some(acquired) = self.try_acquire_writer() else {
            return Err(((key, value), MapAdmissionError::Busy));
        };
        match acquired.insert_with_source(key, value, admit) {
            Ok((writer, previous)) => Ok((writer.detach(), previous)),
            Err((acquired, input, error)) => {
                drop(acquired);
                Err((input, error))
            }
        }
    }

    /// Admit another insertion into the same original unpublished successor.
    ///
    /// Root, base generation and writer availability are checked before planning
    /// from the retained private tree. Any refusal returns that exact owner and
    /// input without allocations or mutation. Successful edits retain the same
    /// cursor, publication shell and base; only exhausted bookkeeping buffers
    /// are replaced, with their complete storage prepaid alongside the edit.
    /// No intermediate generation is published.
    ///
    /// Enclose this synchronous operation in the original budget's refund
    /// notification deferral scope. A panic under the writer lock aborts the
    /// entire private successor and poisons the writer; it cannot return a
    /// partly changed successor for retry.
    pub fn try_insert_owned_admitted<E>(
        &self,
        owned: BptreeMapOwned<K, V, Prepaid<P>>,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> OwnedInsertResult<K, V, P, E> {
        owned.inner.as_ref().assert_operable();
        let mut writer = match self.inner.try_write_owned(owned.inner) {
            Ok(writer) => writer,
            Err((inner, error)) => {
                let error = match error {
                    OwnedWriteError::Busy => MapAdmissionError::Busy,
                    OwnedWriteError::Poisoned => MapAdmissionError::Poisoned,
                    OwnedWriteError::Changed => MapAdmissionError::Changed,
                };
                return Err(((BptreeMapOwned { inner }, (key, value)), error));
            }
        };
        let previous = match edit_admitted(writer.as_mut(), key, value, admit, None) {
            Ok(previous) => previous,
            Err((input, error)) => {
                return Err((
                    (
                        BptreeMapOwned {
                            inner: writer.detach(),
                        },
                        input,
                    ),
                    error,
                ));
            }
        };
        Ok((
            BptreeMapOwned {
                inner: writer.detach(),
            },
            previous,
        ))
    }
}

// Consume only a plan made under this same held original writer. No caller can
// mutate its tree/tracking between planning and execution; a private checkpoint
// may advance only its generation, covered by the full-path clone bound.
fn execute_edit<'a, K, V, P>(
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    key: K,
    value: V,
    provider: P,
    plan: EditPlan,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
) -> Option<V>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    let (started, provider) = start_insert(cursor, saved, plan, provider);
    started.execute(key, value, provider, false)
}

impl<K, V, P> BptreeMapOwned<K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Observe the complete insertion demand of this original private generation.
    /// This does not acquire the map, allocate, copy payloads or authorize an edit.
    pub fn insertion_demand(&self, key: &K) -> Result<AllocationDemand, PlanningError> {
        plan_edit(self.inner.as_ref(), key).map(|plan| plan.demand)
    }

    /// Observe the complete removal demand without locking the original map.
    /// Absence is zero demand; every actual edit replans this same private cursor.
    pub fn removal_demand(&self, key: &K) -> Result<AllocationDemand, PlanningError> {
        plan_remove(self.inner.as_ref(), key).map(|plan| plan.demand)
    }

    /// Admit insertion into this exclusively owned private generation.
    ///
    /// The original root and base remain retained; no physical map lock is
    /// acquired. Refusal returns the original input without mutation. Success
    /// preserves the cursor and publication shell. Stale work may be edited but
    /// cannot publish: final reacquisition still checks the exact original base.
    /// A caught mutation/cleanup panic makes this owner unusable; drop it. Keep
    /// the edit and owner cleanup inside the original budget's refund scope.
    pub fn try_insert_admitted<E>(
        &mut self,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> EditResult<K, V, E> {
        edit_admitted(self.inner.get_mut(), key, value, admit, None)
    }

    /// Admit removal through the original private cursor and prepaid provider.
    /// No map lock is acquired. Absence skips admission; refusal preserves all
    /// original custody. A panic requires aborting the entire private owner.
    pub fn try_remove_admitted<E>(
        &mut self,
        key: &K,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> Result<Option<V>, MapAdmissionError<E>> {
        remove_admitted(self.inner.get_mut(), key, admit, None)
    }
}

impl<K, V, P> BptreeMapOwned<K, V, Prepaid<P>>
where
    K: Copy + Ord + Debug + Send + Sync + 'static,
    V: Copy + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Observe a checked required-reservation floor for this fixed-size owner.
    ///
    /// Counts the exact requested layouts of its original root, retained base
    /// reader and reachable base nodes, private cursor and next-reader shells,
    /// every still-owned private node, and both current tracking capacities.
    /// Nodes retired by a later private edit remain included until actually
    /// freed; retirement entries are never subtracted from the retained base.
    ///
    /// This allocates nothing and takes no lock. It scans only this cursor's
    /// private allocation list, so request it for refusal diagnostics rather
    /// than adding a cumulative scan to every edit. The base counts were
    /// captured from the actual original root at writer construction.
    ///
    /// Adding the next edit's complete demand gives a necessary reservation,
    /// not a shared-pool fit guarantee. It excludes other owners, refundable
    /// older readers, caller storage and opaque native mutex/runtime storage.
    /// A stale base can additionally pin a successor chain: that chain is also
    /// excluded, so this remains only a lower bound even after other readers
    /// drop. This observation grants no retry/publication authority; validate
    /// the original predecessor and handle `Changed` separately. A caught edit
    /// panic leaves the cursor unusable and this method panics just as edits do.
    pub fn required_allocation_floor(&self) -> Result<AllocationDemand, PlanningError> {
        let cursor = self.inner.as_ref();
        let (leaves, branches) = cursor
            .admitted_node_custody_counts()
            .ok_or(PlanningError::Overflow)?;
        let mut required = AllocationDemand::new();
        let initial = MapCell::<K, V, Prepaid<P>>::initial_allocation_layouts();
        let writer = MapCell::<K, V, Prepaid<P>>::writer_allocation_layouts();
        for layout in [
            initial.root,
            initial.reader,
            initial.notification,
            writer.cursor,
            writer.reader,
        ] {
            required.add_layout(layout)?;
        }
        let mut leaf = AllocationDemand::new();
        leaf.add_layout(Layout::new::<CachePadded<Leaf<K, V, P::Charge>>>())?;
        let mut branch = AllocationDemand::new();
        branch.add_layout(Layout::new::<CachePadded<Branch<K, V, P::Charge>>>())?;
        required.add(leaf, leaves)?;
        required.add(branch, branches)?;
        for (_, capacity) in cursor.admitted_tracking() {
            required.add_layout(
                crate::internals::bptree::tracking::FixedTrackingBuffer::<
                    *mut Node<K, V, P::Charge>,
                    P::Charge,
                >::allocation_layout(capacity)
                .map_err(|_| PlanningError::Overflow)?,
            )?;
        }
        Ok(required)
    }
}

impl<K, V, P> BptreeMap<K, V, Prepaid<P>>
where
    K: Copy + Ord + Debug + Send + Sync + 'static,
    V: Copy + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Admit a no-edit fixed-size successor with its exact current-tree floor.
    /// Both observations come from one original writer acquisition. The provider
    /// still funds the complete new cursor/shell demand; this floor grants no
    /// future edit or publication authority and excludes caller-owned allocations.
    pub fn try_write_admitted_with_footprint<E>(
        &self,
        admit: impl FnOnce(AllocationDemand, AllocationDemand) -> Result<P, E>,
    ) -> Result<BptreeMapWriteTxn<'_, K, V, Prepaid<P>>, MapAdmissionError<E>> {
        let Some(acquired) = self.try_acquire_writer() else {
            return Err(MapAdmissionError::Busy);
        };
        match acquired.try_write_admitted_with_footprint(admit) {
            Ok(writer) => Ok(writer),
            Err((acquired, error)) => {
                drop(acquired);
                Err(error)
            }
        }
    }

    /// Admit one fixed-size insertion with the original current tree's footprint.
    ///
    /// Both demands are observed under the same original writer lock. `existing`
    /// is the exact requested layout sum of the permanent root, current reader
    /// and reachable leaf/branch allocations. Copy payloads own no nested heap
    /// storage. It excludes refundable older generations, private successors,
    /// caller-owned map storage and unprovisioned native mutex/runtime storage.
    /// `additional` is the complete checked insertion reservation, just as for
    /// `try_insert_admitted`; no earlier demand is accepted as edit authority.
    ///
    /// If their checked sum exceeds an immutable pool limit, waiting for old
    /// readers to release cannot satisfy this operation's reservation. Otherwise
    /// unavailable credit can be classified against the pool's release owner.
    /// The planner obtains the footprint from original publication bookkeeping,
    /// without traversing the current tree. All refusal and unwind semantics of
    /// `try_insert_admitted` apply, including its refund-deferral requirement.
    pub fn try_insert_admitted_with_footprint<E>(
        &self,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand, AllocationDemand) -> Result<P, E>,
    ) -> AdmittedInsertResult<K, V, P, E> {
        self.insert_with_source(key, value, |source, additional| {
            let existing =
                current_footprint::<K, V, P>(source).map_err(MapAdmissionError::Planning)?;
            admit(existing, additional).map_err(MapAdmissionError::Refused)
        })
    }
}

impl<K, V, P> BptreeMapOwned<K, V, Prepaid<P>>
where
    K: Copy + Ord + Debug + Send + Sync + 'static,
    V: Copy + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Replace a fixed-size value only when its leaf is already private.
    ///
    /// First create the entry with a fully admitted insertion. This operation
    /// then copies a value into that original leaf without allocation, cloning,
    /// new credit, a map lock or a user mutation callback. It returns the previous
    /// value, or the unchanged supplied value if the key is absent or its leaf
    /// still belongs to an older generation. Copy payloads have no destructors.
    /// Key ordering must obey the allocation-free `ClonePlanning` contract.
    ///
    /// A borrowed snapshot excludes this mutable call. The original predecessor
    /// remains retained and must still authenticate at final publication. A
    /// caught key-comparison panic makes this private owner unusable; drop it.
    pub fn try_update_private(&mut self, key: &K, value: V) -> Result<V, V> {
        self.inner.get_mut().try_update_private(key, value)
    }
}

fn edit_admitted<K, V, P, E>(
    cursor: &mut CursorWrite<K, V, Prepaid<P>>,
    key: K,
    value: V,
    admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    saved: Option<&mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
) -> EditResult<K, V, E>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    let plan = match plan_edit::<K, V, P>(cursor, &key) {
        Ok(plan) => plan,
        Err(error) => return Err(((key, value), MapAdmissionError::Planning(error))),
    };
    let provider = match admit(plan.demand) {
        Ok(provider) => provider,
        Err(error) => return Err(((key, value), MapAdmissionError::Refused(error))),
    };
    let previous = execute_edit(cursor, key, value, provider, plan, saved);
    // Keep the existing single-map contract: cleanup must finish before clearing
    // edit_failed, including when callers catch a panic inside a borrowed writer.
    cursor.finish_admitted_funding();
    Ok(previous)
}

fn remove_admitted<K, V, P, E>(
    cursor: &mut CursorWrite<K, V, Prepaid<P>>,
    key: &K,
    admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    saved: Option<&mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
) -> Result<Option<V>, MapAdmissionError<E>>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    cursor.assert_operable();
    if !cursor.contains_key(key) {
        return Ok(None);
    }
    // An earlier observation grants no edit authority. Replan this original
    // private generation, then reserve the complete demand before allocation.
    let plan = plan_remove(cursor, key).map_err(MapAdmissionError::Planning)?;
    let mut provider = admit(plan.demand).map_err(MapAdmissionError::Refused)?;
    let first = allocate_tracking::<K, V, P>(plan.first, &mut provider);
    let last = allocate_tracking::<K, V, P>(plan.last, &mut provider);
    cursor.begin_admitted_edit();
    cursor.resume_admitted_funding(provider, first, last, saved);
    let previous = cursor
        .try_remove(key)
        .expect("complete original removal plan");
    cursor.finish_admitted_funding();
    Ok(previous)
}

/// One checked insertion retaining its exact original cursor, checkpoint and input.
///
/// Preparation allocates and mutates nothing. The exclusive borrow prevents any
/// intervening edit from invalidating the plan. Several disjoint preparations
/// may have their demands combined before one original reservation is split
/// into providers. A prepared insertion grants no allocation or publication
/// authority by itself. Dropping it releases its owned input without editing.
#[must_use = "consume the preparation with original funding or recover its input"]
pub struct BptreeMapPreparedInsert<'a, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    prepared: PreparedInsertCursor<'a, K, V, P>,
    input: (K, V),
}

impl<K, V, P> BptreeMapPreparedInsert<'_, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Complete checked demand for this retained insertion, before any allocation.
    pub fn demand(&self) -> AllocationDemand {
        self.prepared.plan.demand
    }

    /// Borrow the original incoming key without copying or releasing its owner.
    pub fn input_key(&self) -> &K {
        &self.input.0
    }

    /// Borrow the corresponding current preimage from this exact retained cursor.
    ///
    /// The reference retains the preparation's exclusive cursor borrow. A
    /// dependent copy preparation must complete or be dropped before this
    /// insertion can consume its input or edit the current tree.
    pub fn previous_value(&self) -> Option<&V> {
        self.prepared.cursor.search(&self.input.0)
    }

    /// Cancel without editing or allocating, returning the exact original input.
    pub fn into_input(self) -> (K, V) {
        self.input
    }

    /// Consume the preparation using a provider from the original prepaid demand.
    ///
    /// The provider must cover `demand()` and may only split its existing owner;
    /// it must not acquire more pool credit during this operation. Incoming
    /// payloads already own their storage. Every new node, nested copy and
    /// tracking buffer retains its own charge until actual reclamation.
    ///
    /// Keep the original writer and this operation inside the original budget's
    /// synchronous refund-notification deferral scope. An edit or cleanup panic
    /// poisons the original cursor; its checkpoint still owns rollback, and the
    /// parent writer must be abandoned rather than published.
    pub fn execute(self, provider: P) -> Option<V> {
        let (started, provider) = self.prepared.start(provider);
        started.execute(self.input.0, self.input.1, provider, true)
    }
}

/// An insertion borrowing its original key and owning its incoming value.
///
/// The checked demand includes the incoming key copy as well as the tree edit.
/// The source key stays borrowed until execution or cancellation; it cannot be
/// replaced after planning. No key copy occurs before original admission.
#[must_use = "consume the preparation with original funding or recover its value"]
pub struct BptreeMapPreparedKeyCopyInsert<'a, 's, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    prepared: PreparedInsertCursor<'a, K, V, P>,
    key: &'s K,
    value: V,
}

impl<K, V, P> BptreeMapPreparedKeyCopyInsert<'_, '_, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Checked tree demand plus the incoming key's actual nested copy layouts.
    pub fn demand(&self) -> AllocationDemand {
        self.prepared.plan.demand
    }

    /// Cancel without copying or editing, returning the exact owned value.
    pub fn into_value(self) -> V {
        self.value
    }

    /// Copy the retained key and insert using the original complete admission.
    ///
    /// The provider may only split already reserved credit. Keep execution and
    /// cleanup inside its original refund-notification deferral scope. Any
    /// copy, edit or cleanup unwind makes the original cursor unpublishable.
    pub fn execute(self, provider: P) -> Option<V> {
        let (started, mut provider) = self.prepared.start(provider);
        let key = provider.clone_key(self.key);
        started.execute(key, self.value, provider, true)
    }
}

/// An undo insertion retaining an original key and optional original preimage.
///
/// `None` is a real absent-value preimage, stored as an entry in the target tree.
/// It is distinct from the target having no entry. All source copies and the
/// target tree edit are planned before allocation. The two payload policies
/// share the provider's one original charge type and reservation.
#[must_use = "consume the preparation with original funding or drop it unchanged"]
pub struct BptreeMapPreparedOptionalCopyInsert<'a, 's, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    prepared: PreparedInsertCursor<'a, K, Option<V>, P>,
    key: &'s K,
    value: Option<&'s V>,
}

impl<K, V, P> BptreeMapPreparedOptionalCopyInsert<'_, '_, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Checked target-tree demand plus the incoming key and optional value copies.
    pub fn demand(&self) -> AllocationDemand {
        self.prepared.plan.demand
    }

    /// Construct the exact retained optional preimage under original admission.
    ///
    /// No substitute source is accepted. The provider may only split its original
    /// reserved credit, and returned copies must retain their nested charges.
    /// Execute and reclaim inside the original refund-notification deferral
    /// scope. Copy, edit or cleanup unwind poisons the original target cursor.
    pub fn execute(self, provider: P) -> Option<Option<V>> {
        let (started, mut provider) = self.prepared.start(provider);
        let key = <P as NodeCloning<K, Option<V>>>::clone_key(&mut provider, self.key);
        let value = self
            .value
            .map(|value| <P as NodeCloning<K, V>>::clone_value(&mut provider, value));
        started.execute(key, value, provider, true)
    }
}

// All input forms retain this same original cursor, checkpoint buffers and
// checked tree plan. There is one insertion executor and no input factory.
struct PreparedInsertCursor<'a, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
    plan: EditPlan,
}

// Starting marks the original cursor before any tracking or incoming copy can
// unwind. Dropping this owner cannot turn an interrupted edit into a retry.
struct StartedInsert<'a, K, V, P>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
    first: Option<NodeTrackingBuffer<K, V, P::Charge>>,
    last: Option<NodeTrackingBuffer<K, V, P::Charge>>,
}

fn start_insert<'a, K, V, P>(
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
    plan: EditPlan,
    mut provider: P,
) -> (StartedInsert<'a, K, V, P>, P)
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    cursor.begin_admitted_edit();
    let first = allocate_tracking::<K, V, P>(plan.first, &mut provider);
    let last = allocate_tracking::<K, V, P>(plan.last, &mut provider);
    (
        StartedInsert {
            cursor,
            saved,
            first,
            last,
        },
        provider,
    )
}

impl<'a, K, V, P> PreparedInsertCursor<'a, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    fn start(self, provider: P) -> (StartedInsert<'a, K, V, P>, P) {
        start_insert(self.cursor, self.saved, self.plan, provider)
    }
}

impl<K, V, P> StartedInsert<'_, K, V, P>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V>,
{
    fn execute(self, key: K, value: V, provider: P, finish: bool) -> Option<V> {
        self.cursor
            .resume_admitted_funding(provider, self.first, self.last, self.saved);
        let previous = self.cursor.try_insert(key, value).unwrap_or_else(|_| {
            unreachable!("complete tracking bound retained under original writer")
        });
        // Joint edits retain their failed state until both roots and all cleanup
        // complete. A standalone prepared insertion owns its complete cleanup.
        if finish {
            self.cursor.finish_admitted_funding();
        }
        previous
    }
}

fn prepare_insert_cursor<'a, K, V, P>(
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    key: &K,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
) -> Result<PreparedInsertCursor<'a, K, V, P>, PlanningError>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    let plan = plan_edit(cursor, key)?;
    Ok(PreparedInsertCursor {
        cursor,
        saved,
        plan,
    })
}

fn prepare_insert<'a, K, V, P>(
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    key: K,
    value: V,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
) -> PreparedInsertResult<'a, K, V, P>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    match prepare_insert_cursor(cursor, &key, saved) {
        Ok(prepared) => Ok(BptreeMapPreparedInsert {
            prepared,
            input: (key, value),
        }),
        Err(error) => Err(((key, value), error)),
    }
}

fn prepare_key_copy_insert<'a, 's, K, V, P>(
    cursor: &'a mut CursorWrite<K, V, Prepaid<P>>,
    key: &'s K,
    value: V,
    saved: Option<&'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, V, Prepaid<P>>>,
) -> Result<BptreeMapPreparedKeyCopyInsert<'a, 's, K, V, P>, (V, PlanningError)>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    let prepare = || {
        let mut prepared = prepare_insert_cursor(cursor, key, saved)?;
        P::plan_key(key, &mut prepared.plan.demand)?;
        Ok(prepared)
    };
    match prepare() {
        Ok(prepared) => Ok(BptreeMapPreparedKeyCopyInsert {
            prepared,
            key,
            value,
        }),
        Err(error) => Err((value, error)),
    }
}

fn prepare_optional_copy_insert<'a, 's, K, V, P>(
    cursor: &'a mut CursorWrite<K, Option<V>, Prepaid<P>>,
    key: &'s K,
    value: Option<&'s V>,
    saved: Option<
        &'a mut crate::internals::bptree::cursor::CheckpointBuffers<K, Option<V>, Prepaid<P>>,
    >,
) -> Result<BptreeMapPreparedOptionalCopyInsert<'a, 's, K, V, P>, PlanningError>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    let mut prepared = prepare_insert_cursor(cursor, key, saved)?;
    <P as ClonePlanning<K, Option<V>>>::plan_key(key, &mut prepared.plan.demand)?;
    if let Some(value) = value {
        <P as ClonePlanning<K, V>>::plan_value(value, &mut prepared.plan.demand)?;
    }
    Ok(BptreeMapPreparedOptionalCopyInsert {
        prepared,
        key,
        value,
    })
}

/// An exclusive transaction-start checkpoint of an original map writer.
///
/// Dropping this guard aborts its private edits without allocating or obtaining
/// new credit. Applying it keeps those edits private in the same writer. Nested
/// guards resolve in LIFO order through exclusive reborrows. Publication and
/// detachment are unavailable through the borrowed guard. Untracked checkpoints
/// permit ordinary edits; prepaid checkpoints permit only closed admitted edits.
///
/// Keep a prepaid writer and all its checkpoints inside its budget's synchronous
/// refund-notification deferral scope. An internal edit or cleanup panic makes
/// the original cursor unusable even if caught before its physical writer guard
/// unwinds; abort that writer instead of publishing it.
pub struct BptreeMapCheckpoint<'a, K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    inner: crate::internals::bptree::cursor::CursorCheckpoint<'a, K, V, M>,
}

/// Original displaced bookkeeping retained after applying a private checkpoint.
///
/// This move-only owner contains no edit or publication authority. Dropping it
/// frees its original buffers before refunding their charges. It allows a joint
/// owner to apply multiple already-checked checkpoints without invoking a user
/// destructor between them, then finish metadata and release this custody.
/// Keep the joint owner fail-closed until cleanup succeeds: a destructor panic
/// cannot roll back checkpoints whose original rollback buffers were consumed.
pub struct CheckpointRetirement<K, V, M = Untracked>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    _buffers: crate::internals::bptree::cursor::CheckpointBuffers<K, V, M>,
}

impl<K, V, M> BptreeMapWriteTxn<'_, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Begin an allocation-free private checkpoint under this original writer.
    ///
    /// Checked generation exhaustion refuses before changing any owner. Prepaid
    /// writers must remain inside their original budget's refund-deferral scope.
    pub fn checkpoint(&mut self) -> Result<BptreeMapCheckpoint<'_, K, V, M>, PlanningError> {
        self.inner
            .as_mut()
            .checkpoint()
            .map(|inner| BptreeMapCheckpoint { inner })
            .ok_or(PlanningError::Overflow)
    }
}

impl<K, V, P> BptreeMapWriteTxn<'_, K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Prepare an insertion while exclusively retaining this original writer.
    ///
    /// Returns the unchanged owned input on planning refusal. Successful
    /// preparation does not allocate, clone payloads, mutate or reserve credit.
    pub fn prepare_insert_admitted(
        &mut self,
        key: K,
        value: V,
    ) -> PreparedInsertResult<'_, K, V, P> {
        prepare_insert(self.inner.as_mut(), key, value, None)
    }

    /// Prepare an insertion borrowing its key and retaining its owned value.
    ///
    /// Planning includes the incoming key copy and returns the original value on
    /// refusal. The retained source is only copied after complete admission.
    pub fn prepare_key_copy_insert_admitted<'a, 's>(
        &'a mut self,
        key: &'s K,
        value: V,
    ) -> Result<BptreeMapPreparedKeyCopyInsert<'a, 's, K, V, P>, (V, PlanningError)> {
        prepare_key_copy_insert(self.inner.as_mut(), key, value, None)
    }

    /// Inspect the checked allocation upper bound for inserting this key.
    ///
    /// Planning borrows the original held writer without allocating, cloning,
    /// mutating, or acquiring credit. It includes nested source payload copies
    /// and any required tracking-buffer growth. Incoming payloads already own
    /// their storage. The result is not an edit authorization: every admitted
    /// insertion replans under this exclusive writer before its callback, so an
    /// observation made before another edit or checkpoint rollback may be stale.
    pub fn insertion_demand(&self, key: &K) -> Result<AllocationDemand, PlanningError> {
        plan_edit(self.inner.as_ref(), key).map(|plan| plan.demand)
    }

    /// Observe the complete bounded removal demand without cloning or allocating.
    /// Includes the original search path, possible siblings, separators and
    /// bookkeeping growth. An absent key has zero demand. This observation
    /// grants no mutation authority; the admitted operation always replans.
    pub fn removal_demand(&self, key: &K) -> Result<AllocationDemand, PlanningError> {
        plan_remove(self.inner.as_ref(), key).map(|plan| plan.demand)
    }

    /// Admit removal through this original writer and its allocation provider.
    ///
    /// Refusal preserves the exact private generation and bookkeeping. An
    /// absent key returns None without calling admission. Successful removal
    /// returns the original private value; it is not cloned to form the result.
    /// A panic makes this cursor unpublishable. Keep the complete writer
    /// lifetime inside its original budget's refund-notification scope.
    pub fn try_remove_admitted<E>(
        &mut self,
        key: &K,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> Result<Option<V>, MapAdmissionError<E>> {
        remove_admitted(self.inner.as_mut(), key, admit, None)
    }

    /// Inspect the checked demand for one empty leaf and whole-tree retirement.
    /// Planning is allocation-free and retains this original private tree.
    pub fn clear_demand(&self) -> Result<AllocationDemand, PlanningError> {
        plan_clear(self.inner.as_ref()).map(|plan| plan.demand)
    }

    /// Admit one closed insertion while retaining this original physical writer.
    ///
    /// Refusal returns the original input before mutation; successful edits
    /// release unused admission. A panic makes this cursor unpublishable. Keep
    /// this writer's lifetime inside the original refund-notification scope.
    pub fn try_insert_admitted<E>(
        &mut self,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> EditResult<K, V, E> {
        edit_admitted(self.inner.as_mut(), key, value, admit, None)
    }
}

impl<K, V, M> BptreeMapCheckpoint<'_, K, V, M>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Borrow an immutable value from this private checkpoint's current state.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.as_ref().search(key)
    }

    /// Borrow the original value at this checkpoint's start, without copying it.
    ///
    /// The parent root remains retained even after child edits remove or replace
    /// the entry. This reference cannot outlive the exclusive checkpoint guard.
    pub fn get_before<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.get_before(key)
    }

    /// Whether the checkpoint's current state contains this key.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.get(key).is_some()
    }

    /// Number of entries in the checkpoint's current state.
    pub fn len(&self) -> usize {
        self.inner.as_ref().len()
    }

    /// Whether the checkpoint's current state contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrow ordered entries directly from this checkpoint's original cursor.
    pub fn iter(&self) -> Iter<'_, K, V, M::Charge> {
        self.inner.as_ref().kv_iter()
    }

    /// Borrow ordered keys directly from this checkpoint's original cursor.
    pub fn keys(&self) -> KeyIter<'_, K, V, M::Charge> {
        self.inner.as_ref().k_iter()
    }

    /// Borrow ordered values directly from this checkpoint's original cursor.
    pub fn values(&self) -> ValueIter<'_, K, V, M::Charge> {
        self.inner.as_ref().v_iter()
    }

    /// Borrow entries within the requested key bounds.
    pub fn range<R, T>(&self, range: R) -> RangeIter<'_, K, V, M::Charge>
    where
        K: Borrow<T>,
        T: Ord + ?Sized,
        R: RangeBounds<T>,
    {
        self.inner.as_ref().range(range)
    }

    /// Borrow the current minimum key and value.
    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.inner.as_ref().first_key_value()
    }

    /// Borrow the current maximum key and value.
    pub fn last_key_value(&self) -> Option<(&K, &V)> {
        self.inner.as_ref().last_key_value()
    }

    /// Borrow a snapshot whose lifetime cannot escape this exclusive guard.
    pub fn to_snapshot(&self) -> BptreeMapReadSnapshot<'_, K, V, M> {
        BptreeMapReadSnapshot {
            inner: SnapshotType::W(self.inner.as_ref()),
        }
    }

    /// Begin a nested private checkpoint; overflow leaves the parent unchanged.
    pub fn checkpoint(&mut self) -> Result<BptreeMapCheckpoint<'_, K, V, M>, PlanningError> {
        self.inner
            .checkpoint()
            .map(|inner| BptreeMapCheckpoint { inner })
            .ok_or(PlanningError::Overflow)
    }

    /// Keep all child edits private in the original writer; does not publish.
    pub fn apply(self) {
        self.inner.apply();
    }

    /// Apply private edits while retaining displaced bookkeeping for cleanup.
    ///
    /// This transfer neither allocates nor invokes payload or charge destructors.
    /// A joint owner must check all participating checkpoints before consuming
    /// any, arm its own failed state, apply each, finish shared metadata, and only
    /// then drop the returned owners. Disarm that failed state only after every
    /// cleanup succeeds. This is private state resolution, not publication.
    pub fn apply_retaining(self) -> CheckpointRetirement<K, V, M> {
        CheckpointRetirement {
            _buffers: self.inner.apply_retaining(),
        }
    }
}

impl<K, V> BptreeMapCheckpoint<'_, K, V>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Insert or replace an entry, returning the previous private value.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.edit_parts().0.insert(key, value)
    }

    /// Remove an entry from this private checkpoint.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.edit_parts().0.remove(key)
    }

    /// Clone the original path before borrowing a private mutable value.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.edit_parts().0.get_mut_ref(key)
    }
}

impl<K, V, P> BptreeMapCheckpoint<'_, K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Prepare an insertion retaining this checkpoint's exact rollback ownership.
    ///
    /// The move-only result borrows the same original cursor and displaced
    /// tracking-buffer guards until execution or cancellation. It cannot be
    /// applied to another checkpoint or supplied a replacement key or value.
    pub fn prepare_insert_admitted(
        &mut self,
        key: K,
        value: V,
    ) -> PreparedInsertResult<'_, K, V, P> {
        let (cursor, buffers) = self.inner.edit_parts();
        prepare_insert(cursor, key, value, Some(buffers))
    }

    /// Prepare a key copy while retaining this checkpoint's exact rollback owner.
    ///
    /// No copy occurs during planning. Refusal returns the unchanged owned value;
    /// the source key stays borrowed until this preparation is consumed.
    pub fn prepare_key_copy_insert_admitted<'a, 's>(
        &'a mut self,
        key: &'s K,
        value: V,
    ) -> Result<BptreeMapPreparedKeyCopyInsert<'a, 's, K, V, P>, (V, PlanningError)> {
        let (cursor, buffers) = self.inner.edit_parts();
        prepare_key_copy_insert(cursor, key, value, Some(buffers))
    }

    /// Inspect insertion demand from this checkpoint's current private tree.
    ///
    /// This allocation-free observation retains the original parent and current
    /// owners. It includes payload copies and tracking growth, but grants no
    /// mutation authority. The subsequent admitted edit always replans before
    /// admission, even when this observation preceded an edit or nested abort.
    pub fn insertion_demand(&self, key: &K) -> Result<AllocationDemand, PlanningError> {
        plan_edit(self.inner.as_ref(), key).map(|plan| plan.demand)
    }

    /// Observe removal demand from this exact checkpoint without allocation.
    /// An absent key has zero demand; a later admitted removal always replans.
    pub fn removal_demand(&self, key: &K) -> Result<AllocationDemand, PlanningError> {
        plan_remove(self.inner.as_ref(), key).map(|plan| plan.demand)
    }

    /// Admit removal while retaining exact checkpoint rollback ownership.
    /// Refusal leaves the original root and buffers unchanged. Abort restores
    /// the original parent without allocation or an inverse insertion. Keep
    /// this operation inside the original budget's refund deferral scope.
    pub fn try_remove_admitted<E>(
        &mut self,
        key: &K,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> Result<Option<V>, MapAdmissionError<E>> {
        let (cursor, buffers) = self.inner.edit_parts();
        remove_admitted(cursor, key, admit, Some(buffers))
    }

    /// Inspect the checked clear demand while retaining the original parent.
    /// No payload copies, allocations or mutation occur during observation.
    pub fn clear_demand(&self) -> Result<AllocationDemand, PlanningError> {
        plan_clear(self.inner.as_ref()).map(|plan| plan.demand)
    }

    /// Admit one closed edit while retaining exact parent rollback ownership.
    pub fn try_insert_admitted<E>(
        &mut self,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> EditResult<K, V, E> {
        let (cursor, buffers) = self.inner.edit_parts();
        edit_admitted(cursor, key, value, admit, Some(buffers))
    }
}

impl<K, V, P> BptreeMapWriteTxn<'_, K, Option<V>, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Prepare an exact optional preimage copy under this original writer.
    ///
    /// Source key/value copies and the target-tree edit share one checked demand.
    /// An absent preimage produces an actual stored `None`, not a missing entry.
    pub fn prepare_optional_copy_insert_admitted<'a, 's>(
        &'a mut self,
        key: &'s K,
        value: Option<&'s V>,
    ) -> Result<BptreeMapPreparedOptionalCopyInsert<'a, 's, K, V, P>, PlanningError> {
        prepare_optional_copy_insert(self.inner.as_mut(), key, value, None)
    }
}

impl<K, V, P> BptreeMapCheckpoint<'_, K, Option<V>, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Prepare an optional preimage copy under this exact rollback checkpoint.
    ///
    /// Both source references remain retained through admission and execution.
    /// Dropping the preparation does not copy, mutate or acquire credit.
    pub fn prepare_optional_copy_insert_admitted<'a, 's>(
        &'a mut self,
        key: &'s K,
        value: Option<&'s V>,
    ) -> Result<BptreeMapPreparedOptionalCopyInsert<'a, 's, K, V, P>, PlanningError> {
        let (cursor, buffers) = self.inner.edit_parts();
        prepare_optional_copy_insert(cursor, key, value, Some(buffers))
    }
}

#[cfg(all(test, not(miri)))]
#[path = "admission_tests.rs"]
mod tests;

#[cfg(all(test, not(miri)))]
#[path = "owned_footprint_tests.rs"]
mod owned_footprint_tests;

impl<'a, K, V, P> BptreeMapWriterAcquisition<'a, K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    fn insert_with_source<E>(
        self,
        key: K,
        value: V,
        admit: impl FnOnce(
            &SuperBlock<K, V, Prepaid<P>>,
            AllocationDemand,
        ) -> Result<P, MapAdmissionError<E>>,
    ) -> AcquiredInsertResult<'a, K, V, P, E> {
        let mut input = Some((key, value));
        let acquired = self.inner.try_write_charged(|source, shells| {
            let plan =
                plan_insert::<K, V, P>(source, &input.as_ref().expect("original input").0, shells)
                    .map_err(MapAdmissionError::Planning)?;
            let mut provider = Prepaid(Some(admit(source, plan.demand)?));
            let first_charge = provider.take_node_charge(plan.first_layout);
            let first = FixedTrackingBuffer::try_new(plan.first, first_charge)
                .unwrap_or_else(|_| unreachable!("planned first buffer layout"));
            let last_charge = provider.take_node_charge(plan.last_layout);
            let last = FixedTrackingBuffer::try_new(plan.last, last_charge)
                .unwrap_or_else(|_| unreachable!("planned retirement buffer layout"));
            let charges = WriterCharges {
                cursor: provider.take_node_charge(shells.cursor),
                reader: provider.take_node_charge(shells.reader),
            };
            Ok(WriterAdmission {
                charges,
                input: (provider, first, last),
            })
        });
        let mut writer = match acquired {
            Ok(writer) => writer,
            Err((inner, error)) => {
                let error = match error {
                    WriterAdmissionError::Poisoned => MapAdmissionError::Poisoned,
                    WriterAdmissionError::Refused(error) => error,
                };
                return Err((
                    Self { inner },
                    input.take().expect("original refused input"),
                    error,
                ));
            }
        };
        let (key, value) = input.take().expect("original admitted input");
        writer.as_mut().begin_admitted_edit();
        let previous = writer.as_mut().try_insert(key, value).unwrap_or_else(|_| {
            unreachable!("complete fixed tracking bound planned under original writer")
        });
        // A further closed edit requires its own complete admission. Release the
        // unused remainder now, before potentially long handoff waits;
        // actual allocation charges remain attached to their original owners.
        writer.as_mut().finish_admitted_funding();
        Ok((BptreeMapWriteTxn { inner: writer }, previous))
    }
}

fn current_footprint<K, V, P>(
    source: &SuperBlock<K, V, Prepaid<P>>,
) -> Result<AllocationDemand, PlanningError>
where
    K: Copy + Ord + Debug + Send + Sync + 'static,
    V: Copy + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    let mut existing = AllocationDemand::new();
    existing.add_layout(MapCell::<K, V, Prepaid<P>>::initial_allocation_layouts().root)?;
    existing.add_layout(MapCell::<K, V, Prepaid<P>>::initial_allocation_layouts().notification)?;
    existing.add_layout(MapCell::<K, V, Prepaid<P>>::reader_allocation_layout())?;
    let (leaves, branches) = source.node_counts();
    let mut leaf = AllocationDemand::new();
    leaf.add_layout(Layout::new::<CachePadded<Leaf<K, V, P::Charge>>>())?;
    let mut branch = AllocationDemand::new();
    branch.add_layout(Layout::new::<CachePadded<Branch<K, V, P::Charge>>>())?;
    existing.add(leaf, leaves)?;
    existing.add(branch, branches)?;
    Ok(existing)
}

impl<'a, K, V, P> BptreeMapWriterAcquisition<'a, K, V, Prepaid<P>>
where
    K: Copy + Ord + Debug + Send + Sync + 'static,
    V: Copy + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Admit a no-edit successor while retaining the original acquired writer.
    /// The exact tree footprint and new cursor demand come from this guard.
    /// Refusal returns this same guard before any payload changes; success keeps
    /// it in the returned writer. The caller owns release and refund deferral.
    pub fn try_write_admitted_with_footprint<E>(
        self,
        admit: impl FnOnce(AllocationDemand, AllocationDemand) -> Result<P, E>,
    ) -> AcquiredWriteResult<'a, K, V, P, E> {
        self.write_with_source(|source, additional| {
            let existing =
                current_footprint::<K, V, P>(source).map_err(MapAdmissionError::Planning)?;
            admit(existing, additional).map_err(MapAdmissionError::Refused)
        })
    }

    /// Admit one fixed-size insertion while retaining the actual acquired writer.
    /// Both footprint and successor demand come from this guard's original tree.
    /// Refusal returns the same guard and input without allocating or editing;
    /// success retains the writer until the caller detaches or publishes it.
    /// Enclose callbacks and cleanup in the original refund-deferral scope.
    pub fn try_insert_admitted_with_footprint<E>(
        self,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand, AllocationDemand) -> Result<P, E>,
    ) -> AcquiredInsertResult<'a, K, V, P, E> {
        self.insert_with_source(key, value, |source, additional| {
            let existing =
                current_footprint::<K, V, P>(source).map_err(MapAdmissionError::Planning)?;
            admit(existing, additional).map_err(MapAdmissionError::Refused)
        })
    }
}

impl<'a, K, V, P> BptreeMapWriterAcquisition<'a, K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: NodeCloning<K, V>,
{
    /// Use the original admission engine under this actual writer acquisition.
    /// Refusal retains the same lock; callers own refund deferral and pair cleanup.
    pub fn try_write_admitted<E>(
        self,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> AcquiredWriteResult<'a, K, V, P, E> {
        self.write_with_source(|_, demand| admit(demand).map_err(MapAdmissionError::Refused))
    }

    fn write_with_source<E>(
        self,
        admit: impl FnOnce(
            &SuperBlock<K, V, Prepaid<P>>,
            AllocationDemand,
        ) -> Result<P, MapAdmissionError<E>>,
    ) -> AcquiredWriteResult<'a, K, V, P, E> {
        let acquired = self.inner.try_write_charged(|source, shells| {
            let plan = plan_writer_start::<K, V, P>(source, shells)
                .map_err(MapAdmissionError::Planning)?;
            let mut provider = Prepaid(Some(admit(source, plan.demand)?));
            let first_charge = provider.take_node_charge(plan.tracking_layout);
            let first = FixedTrackingBuffer::try_new(0, first_charge)
                .unwrap_or_else(|_| unreachable!("planned empty first buffer layout"));
            let last_charge = provider.take_node_charge(plan.tracking_layout);
            let last = FixedTrackingBuffer::try_new(0, last_charge)
                .unwrap_or_else(|_| unreachable!("planned empty retirement buffer layout"));
            let charges = WriterCharges {
                cursor: provider.take_node_charge(shells.cursor),
                reader: provider.take_node_charge(shells.reader),
            };
            Ok(WriterAdmission {
                charges,
                input: (provider, first, last),
            })
        });
        let mut writer = match acquired {
            Ok(writer) => writer,
            Err((inner, error)) => {
                let error = match error {
                    WriterAdmissionError::Poisoned => MapAdmissionError::Poisoned,
                    WriterAdmissionError::Refused(error) => error,
                };
                return Err((Self { inner }, error));
            }
        };
        // Seal this no-edit operation under the same panic discipline as an
        // insertion: cleanup must succeed before the cursor becomes operable.
        writer.as_mut().begin_admitted_edit();
        writer.as_mut().finish_admitted_funding();
        Ok(BptreeMapWriteTxn { inner: writer })
    }
}

impl<'a, K, V, P> BptreeMapWriterAcquisition<'a, K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V>,
{
    /// Use the original admission engine under this actual writer acquisition.
    /// Refusal retains the same lock; callers own refund deferral and pair cleanup.
    pub fn try_clear_admitted<E>(
        self,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> AcquiredWriteResult<'a, K, V, P, E> {
        let acquired = self.inner.try_write_charged(|source, shells| {
            checked_next_generation(source.txid)
                .ok_or(MapAdmissionError::Planning(PlanningError::Overflow))?;
            // SAFETY: this exact source is retained under the original writer.
            let mut plan = unsafe { plan_tree_clear::<K, V, P>(source.root, [(0, 0); 2]) }
                .map_err(MapAdmissionError::Planning)?;
            for layout in [shells.cursor, shells.reader] {
                plan.demand
                    .add_layout(layout)
                    .map_err(MapAdmissionError::Planning)?;
            }
            let mut provider = admit(plan.demand).map_err(MapAdmissionError::Refused)?;
            let first = allocate_tracking::<K, V, P>(plan.first, &mut provider)
                .expect("one empty leaf requires original first-seen storage");
            let last = allocate_tracking::<K, V, P>(plan.last, &mut provider)
                .expect("every tree has an original root to retire");
            let charges = WriterCharges {
                cursor: provider.take_node_charge(shells.cursor),
                reader: provider.take_node_charge(shells.reader),
            };
            Ok(WriterAdmission {
                charges,
                input: (Prepaid(Some(provider)), first, last),
            })
        });
        let mut inner = match acquired {
            Ok(writer) => writer,
            Err((inner, error)) => {
                let error = match error {
                    WriterAdmissionError::Poisoned => MapAdmissionError::Poisoned,
                    WriterAdmissionError::Refused(error) => error,
                };
                return Err((Self { inner }, error));
            }
        };
        inner.as_mut().begin_admitted_edit();
        inner
            .as_mut()
            .try_clear()
            .expect("complete original clear plan");
        inner.as_mut().finish_admitted_funding();
        Ok(BptreeMapWriteTxn { inner })
    }
}
