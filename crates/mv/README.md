Library provides single value and key-value map structures.

For the execution flow specific for the blockchains:
1. transactions are grouped in blocks and executed one by one (every transaction is atomic)
2. blocks are committed sequentially (every block is atomic as well so either effect of every successful transaction is visible or no effect)

Features:
- single writer/multiple readers
- transactional properties of transactions and blocks (rollback changes on drop or explicitly commit)
- ability to revert changes created in the latest block

The storage layer uses concread's synchronous B+tree maps and epoch cells. Its
dependency enables `maps` and `ebr` explicitly. Finite credits, charged buffers,
generic shared shells and release observations belong to the std-only sibling
[`iroha_allocation`](../iroha_allocation/README.md). `mv::allocation::map` retains
only the adapters that bind those credits to real storage-engine allocations.

Block and transaction overlays expose borrowed preimages and touched entries for
State projection. Storage entries are ordered by key; cell and map records keep
exact before/after values without making another value copy or change list.
Applied children retain the first block preimage, while dropped children leave
no block delta. A replacement block starts after reverting the discarded tip.
A caught direct Storage block-edit panic makes that owner unusable for value
reads, further edits, capture or publication. Both current and undo cursor states
are checked before either publishes, including a failure retained by an aborted
child checkpoint. Abandon the failed block; it cannot supply a partial successor.

These APIs report touches, including no-op mutation and absent-to-absent removal.
Consumers must compare their canonical value projections before committing a
semantic delta. The storage layer does not choose a serialization, hash, read
witness, or complete State commitment; a delta alone does not bind untouched data.

`Block::try_detach` consumes the actual Cell or Untracked Storage block after a caller
admission callback. The detached owner retains that callback's resource guard,
the original ordinary/replacement mode, the published current/undo identity,
and exact candidate touches. Capture moves the original current and undo
allocation owners without copying keys or values, then releases the physical
writers. A detached map retains its original base reader and root owner to keep
untouched shared nodes alive. Untouched reads remain tied to that original
owner/version even when no entry was changed.

Identity is private, local and non-serializable. Every actual MV publication,
including undo-only commits, direct insertion and current-only replacement,
rotates the opaque token while the current/undo publication is excluded from
identity observation. Restoring JSON or projecting history creates a new owner
while preserving the exact serialized values and undo. Equal values after a
later publication cannot recreate an earlier identity.

`Detached::try_prepare_publication` admits installation before reacquiring either
writer around the original current and undo owners. Acquisition does not clone
values or allocate successor generations. It acquires both original writers
without waiting and checks the exact captured identity under those writers;
Storage retains its next publication identity from block opening; Cell allocates
its next identity during capture.
A refusal returns `(journal, error, cleanup)`, retaining the unchanged journal and original notification/resource cleanup. The caller keeps cleanup until enclosing participants unlock. A prepared publication can be aborted
back to that journal without changing visible state. Publishing consumes the
prepared pair and returns both capture and installation reservations to the
aggregate caller; the caller owns their eventual transfer/release.

These are component operations, not cross-field finality or atomic visibility.
The aggregate owner must prepare every component and retain all writers before
publishing any component. Original execution and retained-reader allocation
custody require admission before those allocations occur; capture or installation
callbacks cannot fund them retroactively. Scalar controls verify allocation-free
detach, retry, abort and publication, including the first commit. Arbitrary
payload destructors may still allocate. Data writers precede the identity lock;
identity observation never acquires a data writer while holding that lock.

The underlying synchronous linear cell also accepts prepaid charges for its
exact cursor and reader control-block layouts. The original charges follow
detached and published allocations until physical free, with refunds outside
publication locks. Map teardown uses a bounded stack without heap allocation;
notification mutexes initialize before they can be needed by reclamation. See
[allocation ownership](ALLOCATION_OWNERSHIP.md) for the allocator controls and
remaining node, nested payload and aggregate-policy requirements. Production
maps still use explicit untracked allocation custody until those are complete.

`CellSeeded::deserialize_charged` consumes an already prepaid current/undo pair
before using the existing Norito parser. It moves both exact decoded values into
their real EBR allocations, preserving nonempty undo without dummy generations
or payload clones. Charged Cells and staged blocks use the same JSON encoding;
there is no implicit charged decoder. Admission refusal stays with the original
allocation budget, while parse failure releases the unused pair. The outer EBR
charges survive published readers and deferred reclamation. Seed payloads,
parser scratch, publication identities, notifications, collector bookkeeping
and later nested growth remain separate funding obligations.

Funded synchronous operations can use an original budget's
`with_deferred_refund_notifications` scope to return freed credits immediately
and wake retries after their physical guards are released. Other threads and
pools keep notifying normally. Notification also preserves the remaining
original waiters when one callback unwinds, without suppressing its panic.

`iroha_allocation::ChargedBuffer<T>` admits one exact fixed backing layout for `Copy`
elements before allocation. Appending, reordering the initialized slice and
truncating its prefix cannot grow the allocation or refund its charge early.
Logical capacity also applies to zero-sized elements. Snapshot payload reads use
this same owner with `u8`; ordered membership batches can use fixed-width hashes.
Referenced storage, comparison callbacks and surrounding control owners require
their own admission. This buffer alone does not fund membership publication.

`ChargedBuffer::try_from_charge` constructs this same backing from an original
charge split from a complete operation's prepaid reservation. It validates the
exact typed array layout, including alignment, before allocation. Refusal returns
the unchanged charge; a caller can retain already allocated siblings and retry
without refunding or reserving new capacity. The existing budget-taking `new`
constructor uses the same allocation kernel and retains its original refund and
error behavior. Tests combine the buffer with Concread's original reserved Shared
header and check exact aggregate demand, partial refusal, retry and last-owner
retirement. TODO: thread these original preparations from authenticated carrier
input through State staging and publication before replacing the hot-tip set.
This prerequisite adds no State, Queue or Kura admission authority by itself.

Writer admission carries original move-only input alongside exact shell charges.
The existing B+tree wrappers expose `Prepaid<P>` for closed admitted edits:
under the original writer lock, it plans node/buffer/shell layouts and an explicit
nested payload bound, reserves once, then returns its completed detached owner.
Unused admission returns before handoff; actual allocation charges remain until
physical free. Further admitted edits retain that same private cursor and
publication shell, replacing exhausted bookkeeping only after complete admission.
Refusal returns the original owner and input; intermediate edits stay private.
Initial root and reader blocks retain their exact charges through reclamation.
Exclusive checkpoints borrow current and saved-root values in either map mode.
Abort restores the original parent root without allocating; prepaid mode also
restores its exact tracking buffers, including at full capacity. Nested apply
keeps edits private; only the original writer can publish. A caught edit or
cleanup panic forbids further use of that cursor. Prepaid mutation remains closed.
Closed map removal admits the original search path, possible rebalance siblings,
separator copies and tracking growth before mutation. Missing keys require no
allocation or admission. Both map modes share this removal engine, including
merges and root demotion; refusal and checkpoint abort preserve original nodes.
`MapAdmissionError` covers acquisition and closed edit refusal.
Retained insertion preparations keep the original cursor, checkpoint and input
borrowed while their checked demands are combined and prepaid. Key and optional
preimage copies occur only after that admission. Prepared, direct and joint
insertions use the same planner and executor; joint edits retain their failure
guard until both roots and all cleanup complete. Cancelling a preparation does
not edit the tree or acquire new credit.
Real MV budget regressions exercise this public boundary. Production Storage
uses the same B+tree engine for current and block-undo data, retaining both
original generations through snapshots and publication retries. Ordinary block
opening no longer deep-clones prior undo values before clearing them. Transactions
retain both parent checkpoints and borrow their original preimages; abort restores
both roots without inverse edits, allocation or cloning. Apply resolves both
checkpoints only after checking failures and dropping transaction touch keys.
Both retained checkpoint successors transfer before either retired allocation is
destroyed; cleanup stays under the original parent failure guard.
`Storage<K, V, Prepaid<P>>::try_new_admitted` constructs this same storage family
with one original finite pool. Construction and writer startup each reserve one
checked sum for both maps and their original shared publication identities, then
partition that reservation without reacquiring credits. The canonical
`initial_allocation_demand` and `writer_start_allocation_demand` include the actual
identity layouts. Writer opening owns the successor identity before execution;
publication needs no new identity allocation. Captured predecessors retain the
original identity charges until their last reference releases them, even after
the storage is gone. Identity retirement releases credits after the visibility
lock and physical writers have unlocked. `try_with_admitted_block` holds both original writers inside the pool's
refund scope, clears the actual undo tree through admitted reset, and lends a
private block to a synchronous callback. `try_capture_admitted_block` uses the
same opening/edit path and returns the exact detached current/undo successors
with the callback result attached; capture neither allocates nor copies values. Its `try_insert_admitted` and
`try_remove_admitted` fund current and missing first-preimage edits together.
Removal records an explicit None for an absent key and marks dirty only when
a value was present. The owned query drops under the original pair failure guard.
Success publishes the original pair; refusal or callback error leaves the
published pair intact. Both successors and their shared identity become visible
before old owners are destroyed or retries wake. A caught edit panic makes the
aggregate unusable, including when the callback returns success.
`try_with_admitted_replacement` restores the held undo preimages before lending
the block to the same bounded callback. Each restoration admits incoming copies
and the map edit together; refusal discards the whole private restored prefix.
The new undo journal records preimages from the restored state, and even an empty
replacement retains replacement mode and advances publication identity.
`try_from_snapshot_admitted` copies exact current and undo images into a private
destination under one owned pool. Source entries remain borrowed for retry;
callers authenticate the snapshot schema and fence its acquisition by generation.
Read-only views and exclusive history retain original allocation owners.
`StorageReadOnly` exposes concrete double-ended iterators and range iterators
whose traversal state stays inline. Views, blocks and transactions can scan a
fully exhausted pool without copying payloads or allocating iterator storage.

`AllocationBudget::with_deferred_refund_notifications` lends a thread-bound scope
token. Prepaid detached journals require that same original pool token when they
`try_prepare_admitted`. Multiple pairs can prepare inside one scope. Prepared
physical owners cannot escape it or move to another thread; `abort` returns the
same journal without writer borrows and `publish` installs its original nodes.
Foreign/busy/poisoned ownership and stale current/undo generations preserve exact
retry custody. Capture and explicit abort release both physical writers before
either native release signal, including callbacks that unwind. Opening an ordinary
or admitted block and reattaching a prepared pair share one original writer owner.
It retains both locks through reset, replacement copies, execution and snapshot
restoration, and releases both before abandonment callbacks. It observes the
actual locks' poison states after destruction and freezes both verdicts before
notifying, so a later payload or wake panic cannot falsely poison a released
healthy writer. State still supplies complete resource policy, aggregate
visibility and QC/Kura authority; all aggregate physical preparation and cleanup
ordering remain required.

`Block::try_transaction_admitted` lends both original checkpoints to a private
transaction. Both admitted insertion and removal join the canonical current/undo
demand with the exact ordered touch-array growth and policy-owned key copy before one
reservation. Repeated touches preserve the first owned key. `touched_entries`
borrows a sorted slice without iterator allocation; no-op insertions and absent
removals remain explicit. Dropping the child restores both parent roots without
allocation.
Applying first destroys its touch keys under both rollback guards, then keeps
both private successors before retiring displaced checkpoint storage. Cleanup
panic also makes the original block unusable.

World storage remains Untracked pending native lock/runtime and release
control storage, mutable access, concrete model payload policies
and configured aggregate integration. Replacement and snapshot restoration admit
each edit; they do not bound aggregate restoration work or complete State admission.

Release observations use `iroha_allocation::release`, shared by physical storage
and finite allocation owners. Native active-reader contention has its own source; releasing a
writer cannot satisfy that wait. Published tree retirement retains the original
reader notification after physical unlock, so the enclosing publisher can drop it
after its visibility fences. Detached map preparation retains native active-reader
mutexes and the exact identity guard; Cell preparation retains its EBR owners and
identity. Their publish methods acquire no further lock and return cleanup with
caller reservations. Keep those returned owners until enclosing fences release.
Prepaid published cleanup cannot leave the original pool scope. Preparation abort
and whole-State cleanup still need aggregate ordering; these component APIs do
not establish that boundary.

TODO: compose these component publications with exact aggregate State predecessor
ownership, membership, hash history, archive/resource reservations and finality.
The production State publisher and its resource policy remain unfinished; no
State execution, native-output or publication guard is bypassed by these APIs.

Cell publication also retains both original writers through pair identity rotation.
Epoch reclamation and release callbacks run after physical unlock, including
current-only replacement that retains undo. A cleanup panic cannot poison the
release hint for a physical lock that was already released successfully.

Prepared publication abort returns `(journal, cleanup)`. Keep `cleanup` until all
participants of the enclosing publication attempt have released their physical
locks, then retry the same journal. Prepaid cleanup remains in its original
allocation scope. This API does not make acquisition failures across an entire
State aggregate callback-safe by itself.

Failed preparation uses the same MV-wide `PublicationCleanup` owner as explicit
abort. The preliminary identity observation, partially acquired writers/readers,
final identity refusal and installation reservation stay with that owner. Runtime,
TriggerSet and World return their aggregate cleanup, including failed World field
shells. A retained carrier releases its State/Queue/Kura fences before retiring
World/runtime refusal cleanup. This covers returned errors; panic propagation
during acquisition, earlier Kura/State/Queue probes and successor acquisitions
still require enclosing ownership.

Map publication binds release observations to Concread’s actual acquired writer
before validating its predecessor. A foreign/busy refusal emits no synthetic
release; stale/poisoned cleanup retains the original acquired notification through
the enclosing fences.

Fresh ordinary and admitted Storage opening acquires both native writer phases
before constructing either cursor. One pair transition retains both original
notifications through refusal and callee unwind; success transfers both guards
without a wake. Admitted opening reserves the whole pair and identity first,
checks both poison verdicts before policy callbacks, and remains inside the
original pool refund scope.

Synchronous infallible Cell opening and current replacement wait for the original
physical writer pair before enclosing publication fences. Explicitly admitted
`BlockAcquisitionSlot::try_initialize` remains nonblocking and reports the exact
pre-probe Busy source while retaining partial original custody. Both paths use
the same one-shot acquisition and clone/attachment/retirement kernel.

Cell opening acquires both original EBR writers before cloning either value. A
partial pair retains completed generations and unused charges until both guards
release; the complete pair keeps joint ownership through Block and
CurrentReplacement abandonment, detachment and publication-lock acquisition.
Known undo poison rejects before waiting for current; known current poison
rejects before either payload clone. Abandoned private payloads are destroyed
after both writers unlock, so a destructor panic cannot poison those released
writers. Canonical current/undo
JSON fields are unchanged.

Aggregates construct every `BlockAcquisitionSlot` before initializing any field.
`BlockAcquisition::initialize` stores each actual acquisition and completed
private generation in that caller-owned slot before further fallible work.
`BlockAcquisition::release` and `BlockRetirement::release_writers` unlock without
reclaiming retained values or notifying. Release all siblings first, then drop
their slots/blocks. Explicit retirement is terminal: it does not create detached
publication authority and cannot resume a failed edit. Ordinary standalone
constructors use this same kernel.

Capture aggregates install every inert `BlockCaptureSlot` before calling
`BlockCapture::try_capture`. Each slot retains its original block through checks
and admission; successful capture owns the exact detached journal and its original
`CaptureCleanup`. Release all sibling slots before destroying any failed attempt,
and retain successful cleanup through every enclosing writer. Standalone and
prepaid capture use this same kernel. World and TriggerSet now compose these slots;
consuming commit and enclosing State/runtime transfers remain open. See the
capture custody record.


The first-release JSON snapshot schema distinguishes undo presence from the
original value. A Cell emits `{"revert":null,"blocks":CURRENT}` when no
predecessor is retained and `{"revert":{"value":PREVIOUS},"blocks":CURRENT}`
when one is retained, including `PREVIOUS = null`. A Storage undo map omits
untouched keys, emits `"key":null` for an absent preimage and emits
`"key":{"value":PREVIOUS}` for a present preimage. Its current map retains the
ordinary value representation. The sole streaming parser requires exactly one
`value` member for a present undo and rejects unwrapped retired values. Nested
payload schemas remain responsible for distinguishing their own value states.
Live, attached and detached originals use this same framing without copying
their values. Admission and authenticated restoration remain separate.
