# Original membership append ownership

`PreparedMembershipAppend` binds one actual prepared membership identity, its
original current/rollback roots, one Kura descriptor-bound range and one charged
allocation containing the workspace and replay state. Construction prepays that
exact allocation and the codec's temporary declared schema name. The caller keeps
the original memory-pool refund scope around acquiring and releasing State
writers. Original range completion and prune/canonical fence notifications stay in the
range across every operation and refusal. `take_cleanup` transfers their fixed
original bundle to the outer cleanup owner after completion; that owner releases
them only after all physical writers.

The hot demand is checked from the actual net changes: at most one height plus
257 path nodes per changed key. Counting visits the unchanged staged/latest sets,
not historical membership. Repeated commits have zero changes. Locations are
physical references excluded from logical commitments; restart does not recreate
an original in-process preparation identity or its BTreeSet iteration order.

A replay cursor identifies fixed record ordinals inside the one original range.
Completed ordinals are read and compared against the entire expected frame,
including physical child/value locations. The owner installs one exact pending
frame before a new write. Partial output, write errors, success-before-error and
unwinding leave that frame and its original offset intact. Retry rewrites only
that unpublished slot. Missing, corrupt or mismatching completed bytes are local
failures; they do not authorize new offsets or overwrite acknowledged records.

The complete high-water mark advances only after a whole frame was acknowledged.
It is separate from file length and from the Kura range's reserved capacity.
Children must lie within the exact complete prefix before their referencing node
is emitted. Root lookup continues to authenticate node hashes and canonical
heights; a local I/O failure never means transaction nonmembership.

Preparation succeeds only after replay consumes every completed and pending
ordinal. The resulting roots stay in that same owner. Sync retries use those
sealed bytes and do not repeat logical preparation. Only successful descriptor
sync and exact range completion set local durability. An already sealed attempt
cannot write further records. An already durable attempt performs no extra sync.

This boundary does not publish State. Complete State installation must retain
both roots and their read lease before releasing its original writer. Authenticated
restart, incomplete-range recovery, history reclamation, both incremental Apply
checkpoints and the production retained Validate-to-Apply consumer remain required.
The current single finite segment has an explicit hard capacity limit; neither
that limit nor abandoned bytes is an automatically retryable admission condition.
No compatibility decoder, fresh retry range or cold per-height rebuild is provided.
