# Iroha allocation ownership patch

This is the source of the locked `concread` 0.5.10 crate (crates.io archive
SHA-256 `6588e9e68e11207fb9a5aabd88765187969e6bcba98763c40bcad87b2a73e9f5`),
with its MPL-2.0 license retained in `LICENSE.md`.

The vendored package is an explicit workspace member, but not a default member.
Its unit tests therefore use the checked-in workspace lockfile and the maintained
Cargo metadata/build gate without a temporary harness. MV production still
disables default features and selects `ebr` and `maps`; the release gate checks
shipping binaries separately from the broader test feature graph.

The maintained fork contains only the synchronous B+tree, linear cell and EBR
cell used by Iroha. Unused upstream hashmaps, hash tries, caches, CowCell and async
implementations, their benchmarks, abandoned unsound experiments, and direct
Serde adapters are removed. Norito integration remains in `mv`. The obsolete
SIMD/alternate-hasher/cache features and DHAT allocator replacement are removed
with their implementations and dependencies. The original allocation-observation
allocator now covers all supported test feature combinations. `skinny` remains
to exercise the same B+tree at reduced fanout. The duplicate integration-test
target is removed; every ordered-map property remains in `tests/bptree_map.rs`.

The generic strong-only shared shell and release observation kernel now belong to
`crates/iroha_allocation`, a standard-library-only crate below both models and runtime
storage. This engine consumes those original owners directly. The generic custody,
reservation and allocation-refusal tests moved with their implementation; B+tree and
linear-cell tests remain here. No retired module reexports are retained.

The local EBR change binds typed resource custody to the real allocated generation,
including abandoned writers and epoch-delayed reclamation. It does not measure
nested payloads or establish an aggregate Iroha memory quota. Consumer regression
tests live in `crates/mv/tests/ebr_allocation_custody.rs`.

Unpublished EBR generations can also detach and reacquire their exact original
allocation without cloning or allocating a successor. This low-level transfer
grants no semantic predecessor authority; the MV layer authenticates the exact
original current/undo pair while holding both writers. Its acquisition wrapper
also reports poison after a raw clone panic that occurs before a writer guard
can be returned. These paths are covered by allocator and MV regressions.

Synchronous B+tree writers now retain their original cursor through detach/adopt.
Because that cursor shares untouched nodes, its move-only owner retains both the
exact base reader and a shared root owner. Adoption rejects a foreign root or
changed base while holding the original writer mutex. Initial acquisition also
preallocates the next reader shell; publication initializes and links it
without allocating a replacement shell. Detached work drops before its base and
root. Existing node transfer still occurs only in `pre_commit`. Black-box controls
live in `crates/mv/tests/map_owned_generations.rs`. Node/nested-buffer charges and
complete State resource admission remain separate unfinished work.

The synchronous cursor block is allocated during initial writer acquisition and
moves unchanged through handoff. Reader links and B+tree retirement vectors use
write-once storage; both permanent mutexes are initialized at construction.
This removes observed macOS lazy native mutex allocation during commit without
prewarming locks after ownership transfer. Tests cover a retained reader and a
fresh map's first commit with no prior read, retaining strict zero-allocation
assertions for both paths.

B+tree clone construction now maintains an initialized prefix on every unwind
path. Separator replacement drops the old key; split/merge/redistribution finish
fallible separator clones before moving initialized slots. Redistribution moves
existing keys with their child pointers. New branches retain their Box through
debug verification so a user key comparison panic cannot orphan the allocation
before cursor registration. This removes actual nested-payload leaks and
invalid-prefix destruction without an invalid-node compatibility path.
The in-source `internals/bptree/clone_unwind_tests.rs` regressions track exact
nested payload and node custody, including writer poison, detached abort, ordinary
removal and retained reader chains. Typed node allocation charging is now
implemented below; nested allocations and complete State admission remain open.

The synchronous linear cell has one strong-only allocation owner whose concrete
control-block layouts are public to admission. An opaque move-only charge is
attached before each original shell is allocated. Both cursor and next-reader
shells exist before `create_writer`; publication initializes the same reserved
reader. No weak or raw ownership escape is exposed. The final strong reference
frees the exact control block before returning its moved payload and charge;
payload destruction precedes refund. Concurrent releases use release/acquire
reference counting. Payload unwind retains the charge conservatively.

The same `shared::Reserved` shell now exposes a consuming public preallocation
API. `try_new` allocates its exact concrete layout once and returns the original
opaque charge on allocator refusal. `initialize` moves a later payload into that
same shell without allocation, cloning or callbacks. Existing constructors keep
their allocation-error behavior through this one kernel. The sole existing test
allocator observes exact padded layouts, unused/partial shell cleanup, allocation
refusal and retry, payload lifetime and the free-before-refund order. Admission
must still be performed by the caller before constructing a shell; opaque charges
do not establish a pool limit or fund nested allocations. TODO: connect these
shells to the original hot-tip source/finalizer owners and complete State admission.

Charged writer acquisition has no untracked convenience path. Existing maps use
the explicit `Untracked` type until complete node/vector/payload funding exists.
Attached abort releases the lock before private work destruction while retaining
its base; construction unwind releases the poisoned lock before shell refunds.
Commit publishes and unlocks before invoking cursor-charge destruction. This
permits synchronous refund wakeups to reenter the original writer safely.
The initial synchronous root uses the same charged strong-only allocation as
its reader. Both exact layouts are admitted before initial construction; owned
writers retain that original root. Native mutex backing remains outside those
charges. Only the synchronous charged shell implementation is retained.

Final B+tree destruction uses original child pointers and a fixed stack bounded
by `usize::BITS + 1`; it performs no heap allocation. The committed tree's minimum
branch fanout and representable entry count bound its depth. Consumer controls
cover empty, leaf and multilevel trees, old-reader chains, source-map destruction
with detached work, and a detached base older than the final committed root.

Read iterators use that same valid-tree height bound for their two inline
traversal paths, replacing both `VecDeque` allocations. Paths retain original
node pointers and indices, never payload copies or mutable aliases. Iterator
construction, traversal and destruction need no heap credit; forward, reverse,
mixed-direction and borrowed-bound semantics stay on the same iterator engine.
The concrete read iterator types are exported by `bptree` for allocation-free
consumer wrappers. Allocator regressions cover empty and multilevel trees,
retained readers, removals, nested checkpoints and unsized `str` bounds.

Writer construction consumes an explicit associated input from the original
locked admission, joined with both shell charges in `WriterAdmission`. Unit-input
convenience methods require `WriterInput = ()`; non-unit untracked callers pass an
explicit callback. No default input, readmission on reattachment or second map
engine is provided. Input constructors/destructors may invoke callbacks during
unwind, so complete funded operations enclose physical guards in their original
pool's synchronous notification-deferral scope.

B+tree nodes now carry one statically typed charge in their original concrete
leaf/branch allocation. Every allocation path requests its exact padded layout
before allocation. The RAII owner covers clones and debug comparisons, transfers
the original raw pointer, and reconstructs the same padded Box for reclamation.
It returns credits after payload destruction and actual deallocation; payload
unwind retains credits conservatively. `Untracked` has no layout overhead.
Raw node `Sync` additionally requires `K: Sync`; a compile-time regression rejects
the former bound. The same cursor now carries its mode's funding and node charge type. Fixed
tracking buffers own exact admitted backing storage and move intact into retired
readers. Structural preflight refuses before node allocation when either buffer
lacks room. Shared reads and original clone probes use immutable references;
thread traits include the actual charges and writer provider. Fixed-buffer
construction is now connected to closed public insertion; its temporary
non-test dead-code expectation has been removed.

Every node-owned key/value copy now requires an explicit `NodeCloning` policy
from the original funding provider. This includes leaf and branch cloning,
new-root separators, left/right splits, replacement, merge and redistribution.
The only production ordinary-Clone policy is explicit `Untracked`; providing a
node charge alone grants no payload-cloning capability. Funded policies must
prepay each concrete nested allocation and retain its original owner in the
returned payload until actual free. Slot transfers keep existing payload owners.
Concrete regression payloads reject ordinary Clone and observe original nested
allocation frees/refunds and partial-construction unwind. This supplies the
engine boundary. The same public map/read/snapshot/owned wrappers now carry a
sealed mode: Untracked retains ordinary mutation; Prepaid<P> permits closed
admitted insertion and immutable handoff/publication. Its allocation-free planner
counts actual padded nodes, both fixed buffers, original shells and policy-declared
nested copies, including separator candidates from every child minimum along the
path. No second map engine or dynamic registry is introduced. Unused provider
remainder returns before handoff; original allocated charges remain attached.
A retained closed edit authenticates the original root/base, plans from the
private tree, and retains the exact cursor and publication shell. It reserves
replacement bookkeeping alongside the complete edit, grows geometrically only
when needed, copies existing pointers and frees the old buffer before refund.
Refusal returns the same successor/input before mutation. Panic aborts the whole
private successor. The constructor admits exact initial node/root/reader storage;
native mutex/runtime storage, actual model payload policies and MV undo/global
State admission remain required before production cutover.

A prepaid detached successor with `Copy` keys and values can replace an existing
value through `try_update_private` only when its leaf already belongs to that
exact private cursor generation. The update copies into the original slot and
returns its previous scalar; absent/shared entries return the unchanged supplied
value. It never clones a path, acquires funding or a physical map lock, grows
bookkeeping, or exposes a mutable payload reference/callback. Borrowed snapshots
exclude the update, and a caught comparison panic leaves the original cursor
fail-closed. This permits one admitted append or tip overwrite before execution,
followed by filling the final hash without another allocation. Final publication
still authenticates the original root and predecessor. Physical allocation,
stale-refusal and abort controls retain original charges through actual free.
This does not provision native mutex/runtime storage or supply complete State
resource admission.

For fixed-size Copy payloads, `try_insert_admitted_with_footprint` exposes both
that additional reservation and the original published tree's requested-layout
footprint while holding the same writer. Exact leaf/branch counts move with the
published root, derived from its original created/retired pointer lists; nodes
created and then retired privately cancel. Checkpoint abort restores those lists.
Admission adds the actual permanent-root/current-reader and padded-node layouts
without a whole-tree scan. A configured pool below this resident footprint plus
required reservation cannot make progress merely by freeing old readers; callers
must distinguish that bound from refundable old-generation/private-owner credit.
All sums are checked. The API neither counts unprovisioned runtime/native locks
nor grants authority from an earlier observation.

Attached writers in both sealed modes lend exclusive nested checkpoints. Fresh
private generation tags preserve parent nodes, and `get_before` borrows that
saved root directly. Prepaid buffer growth retains each original ancestor
allocation. Apply transfers both saved buffers before dropping excess charges.
Abort restores root/tag/length and prepaid original buffers, then pops each
child-owned pointer before nonrecursive destruction. Untracked vectors may keep
grown capacity; abort allocates nothing in either mode. Sealed mode hooks make
Untracked saved-buffer slots zero-sized while retaining actual prepaid buffers.
The original saved root is non-null, avoiding an extra resolved-state tag.
A cleanup guard drains
remaining child nodes during unwind. Rust borrows prevent parent publication,
mutation while borrowed or reference escape while a child is live. The logical
failed-edit flag covers both admitted and ordinary mutation, preventing use after
a caught mutation or cleanup panic even before the physical mutex unwinds.
Public commit and detach check this flag before consuming their original shells.
Prepaid checkpoints expose only closed admitted operations; unrestricted mutation
belongs to Untracked mode. The original funded writer and all checkpoint lifetimes
must remain inside the original refund-deferral scope.

Detached map owners expose borrowed ordered iteration directly from their retained
cursor. The full-tree iterator tracks its remaining length through both forward
and reverse consumption and implements `ExactSizeIterator`; its old size hint
incorrectly kept the original length after consumption. Range iteration retains
its separate conservative upper-bound contract. These operations support native
Storage undo ownership without cloning a separate standard-map read image.

### Closed prepaid current/undo insertion

`try_insert_with_undo_owned_admitted` reattaches both exact retained map owners,
plans the current edit and a missing first-preimage undo edit together, and
consumes one move-only provider under both original writer locks. Existing undo
entries, including `None`, are neither rewritten nor checkpointed. Checkpoints
retain original roots and tracking storage for allocation-free abort; final
provider cleanup and both private applies precede either returned owner.

Callers bind the intended map pair and common budget and retain the budget's
synchronous refund-notification deferral scope. This primitive covers closed
insertion, not removal, clear, arbitrary payload mutation, touch-key storage,
MV/World activation or complete carrier admission.

Borrowed writer/checkpoint `try_insert_with_undo_admitted` uses the same pair
planner and executor without releasing either physical writer. Nested applies
transfer original saved buffers to their matching parent checkpoints. A stack
failure guard outlives both child checkpoints and marks both cursors unusable on
unwind, including cleanup after one apply. Typed refusal preserves both inputs
and cursors. The caller must enclose the entire original writer lifetime in its
common budget's refund-notification deferral scope; a scope around only one edit
is insufficient. Ordered MV touch-key admission remains a separate prerequisite.

### Closed prepaid empty-root reset

`try_clear_admitted` on an original writer or checkpoint plans one empty root and
all required fixed bookkeeping replacements before its one admission callback.
A bounded stack visits the actual held tree without an allocating iterator or
payload copy. Every prior node remains in the original retirement chain; old
readers keep their preimages and charges until release. A child checkpoint retains
exact parent tracking buffers for no-credit abort. Caught callback, provider and
apply-cleanup panics leave the cursor unusable. The original physical writer's
whole lifetime stays inside its budget's refund-notification deferral scope.
This reset primitive does not activate MV/World or admit transaction touch keys.

The closed writer exposes read-only checked insertion/clear demand and real
nonblocking admitted acquisition. Map-level clear combines original shells and
actual whole-tree retirement under one callback, permitting joint MV admission
while both original locks are held. Shared allocation-free postorder traversal
counts retirement nodes and destroys the final tree without mutable aliasing.

Checkpoint `apply_retaining` transfers saved bookkeeping into an opaque cleanup
owner without invoking its destructor. Aggregate MV apply can therefore finish
both transfers while parent failure is armed before releasing either allocation.
Synchronous map publication has explicit prepared/published/retirement owners:
all lock and original-base checks precede node transfer; both physical guards and
all cursor/base/charge cleanup remain retained through publication. Release only
unlocks and returns cleanup. MV rotates its pair identity before unlocking and
runs all retirement and notifications afterwards. Existing synchronous map commit
uses this same engine; the retained-commit trait is sealed to the B+tree owner.
See joint Storage admission.

EBR cells use the same prepare/publish/release separation for ordinary and MV
publication. Exclusive writer custody protects the current load and atomic swap
without entering the epoch collector. The old allocation remains solely owned by
an opaque unscheduled retirement until all enclosing writers and visibility locks
release. Only then does retirement pin and defer reclamation through the original
reader grace period. Preparation and transfer invoke no user cleanup; existing
readers retain their exact values and charges until physical reclamation.

### Closed admitted removal

Held prepaid writers and borrowed checkpoints expose `removal_demand` and
`try_remove_admitted`. The planner borrows the original path and possible
rebalance sibling at each level, including nested copy and separator demands.
With `b` branch levels, capacity preflight requires at most `2b + 1` new-node
and `3b + 2` retirement slots. Checked admission precedes any clone or allocation;
an absent key skips admission entirely. The generic recursive removal engine
passes the same original funding provider through node clones, rebalancing and
separator updates. Ordinary removal delegates to this engine. Checkpoint abort
restores original roots and buffers without allocation or inverse edits.
`MapAdmissionError` is the common error for closed single-map operations.
Actual allocator and MV-credit regressions cover both edge directions, interior
removals, root demotion, retained readers, nested rollback at full capacity,
preflight refusal and clone unwind.

Borrowed writer/checkpoint `try_remove_with_undo_admitted` uses that same removal
planner and engine while admitting the missing first-preimage insertion and its
payload copies together. Missing current values require no current-tree allocation
but still record the first `None` in undo. One original provider covers both trees;
the pair remains failed through owned query, provider and checkpoint cleanup.
Touched-key storage is admitted by the enclosing Storage owner. This primitive
does not activate funded State or admit a complete carrier.

### Shared allocation custody

`shared::Shared` exposes the same strong-only allocation owner used by linear
cells. Its layout is the actual control block, including the retained charge;
callers admit that layout before construction. Cloning retains the original
allocation without acquiring credits. The last reference frees the control block,
destroys its moved payload, then drops its charge. Payload unwind conservatively
retains the charge. There is no weak-reference or raw-ownership API. MV uses this
owner for funded publication identities instead of guessing a standard-library
`Arc` layout. The internal reclamation operations remain private.

### Physical reader readiness

The canonical `release` module owns lock observations for Concread, MV and Core.
Linear cells expose `observe_reader_release` for their actual active-reader mutex;
all acquisitions notify after unlocking. Pinned immutable readers and writer
release do not substitute for that mutex. Published commit retirement retains the
same notification after releasing both physical locks and delivers it during
cleanup, allowing aggregate publishers to finish their visibility interval first.
Later cleanup unwind preserves the physical lock's earlier poison verdict. Native
notification/control allocations and complete aggregate abort ordering remain
separate obligations.

A release guard can transfer to a fallible prepared phase without notifying on
success or refusal. `release_deferred` returns the original retained value and
same notification owner after physical unlock. Native prepared tree commits can
abort while retaining the actual reader notification alongside their original
writer; EBR prepared commits can return their original writer. These primitives
allow MV to finish all physical preparation before component transfer and retain
successful cleanup through aggregate fences.

`DeferredReleaseBatch` retains actual releases from one original source in
constant space. Empty batches never notify; foreign guard transfers return the
unchanged guard. Repeated physical unlocks coalesce into a wake hint only after
the caller releases its enclosing fences. Actual physical poison is recorded
before any later cleanup unwind.

`try_acquire_owned` returns an opaque actual writer before predecessor validation.
Foreign roots and contention acquire nothing; stale or poisoned validation returns
the same held owner. Aggregate callers bind its original notification before
validation, then abort with deferred cleanup. Single-owner adoption composes the
same phases without another implementation or publication authority.

Fresh nonblocking writer construction likewise exposes its original acquired
mutex before planning or invoking admission. Poison and refused input remain
with that owner; success transfers it to the existing funded cursor. Standalone
insertion and the charged constructor compose the same phases, while aggregate
callers may bind their release source before callbacks. The fixed-payload current
footprint planner is shared.

Fresh acquired writers also expose the same no-edit and clear admission kernels,
plus blocking untracked construction. Paired release guards can transfer both
physical owners through one fallible conversion; callee failure releases both
before either original notification, while success transfers without signaling.
The shared pair release engine freezes actual poison before arbitrary wakes.

The EBR acquired phase now retains the original physical writer before any
admission or clone. Consuming charged cloning returns that same guard and exact
private allocation separately; refusal retains the guard, and callee unwind
still poisons the actual mutex. Owned attachment refuses poison without losing
either owner. Direct native construction delegates to the same clone kernel.
Writer Drop unlocks before private payload reclamation; aggregates must also
retain payloads until all sibling guards release.

Caller-owned aggregate acquisition can now retain actual consumed-phase unwind
notifications in the same original-source batch. Foreign batches preserve the
unchanged guard and do not call the transition. Observed release records physical
poison before later payload cleanup. `BptreeMapWriteTxn::abort_retaining` unlocks
into an opaque original cleanup owner even if an edit failed; unlike detach, it
exposes no read, edit, reattachment or publication capability.

The upstream `tests/bptree_map.rs` range, get and remove properties run as
fixed-seed randomized cases over `rand` instead of `proptest`, and the manifest
drops its `sptr` dependency (the sources use std strict-provenance APIs). This
keeps the vendored workspace member inside the reviewed dependency budget, which
denies `proptest` in every required graph.

Because the package is a workspace member, workspace Clippy lints it. The crate
root allows `clippy::type_complexity` for its upstream generic signatures, and
the two redundant `into_raw() as *mut Leaf` casts are removed.
