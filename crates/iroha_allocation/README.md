# Original allocation custody

`iroha_allocation` is the std-only owner of finite allocation budgets,
move-only reservations and charges, fixed charged buffers, charged shared
backing, and release-driven retry. Codecs, cryptography and immutable model
artifacts use this owner directly. Its normal dependency graph contains no
storage engine, codec or service runtime.

Enumerate the actual layouts before allocation, reserve their complete demand
from the caller's original pool, and retain each charge until its physical
allocation is reclaimed. Shared clones retain the same backing and charge.
Refusal returns the original owner for retry; it grants no publication or
consensus authority. Deferred refund and physical release notifications keep
callbacks outside the integrating caller's writer locks.

An `OwnedAllocationScope` admits its exact refund control before physical
writer acquisition. Retain `scope.control()` when detaching journals: the
`AllocationScopeControl` can cross threads and activate that same backing
without allocation or new capacity, even after the original pool limit shrinks.
Activation refuses while an earlier guard or its final callback cohort remains
active. The thread-bound guard must outlive all sibling releases and cleanup;
retaining an inactive control keeps its original charge for a later retry.
The control grants no publication authority.

The pool measures requested layout bytes. Nested payloads, allocator/runtime
bookkeeping and the budget's own control storage remain separately owned
obligations. Fixed buffers cannot grow or safely expose uncharged backing.

`mv` owns storage generations, transactions, publication and charged map
adapters. The vendored `concread` engine depends on this lower owner for generic
shared shells and release notifications. Neither is a normal dependency of
`iroha_allocation`; model compilation remains disconnected from runtime storage.

Validate unit tests and isolated physical allocator harnesses with
`cargo test -p iroha_allocation`; validate actual storage reclamation separately
with `cargo test -p mv`.

The allocation-budget modules retain the workspace Apache-2.0 license. The shared
backing and release kernel moved from the vendored Concread package retain its
MPL-2.0 license; its license text is included in `LICENSE-MPL-2.0.md`.
