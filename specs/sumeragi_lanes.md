---
title: Sumeragi multilane and autoscale lanes
sidebar_label: Multilane
description: Lanes as independent Sumeragi instances merged by the global chain, and deterministic lane autoscaling.
---

# Sumeragi multilane and autoscale lanes

Status: design, 2026-09-28; normative once implemented (goal S5 for lanes). Data spaces with their
own state and atomicity across data spaces are specified in `sumeragi.md` §11 (goal S6).

## 0. Summary

**Data spaces and lanes are distinct.** The data space catalog defines the
environments for data, authority, and policy. The lane catalog defines lanes,
each referencing one data space; several lanes may reference the same data space.
`DataSpaceId` identifies the data space and `LaneId` identifies its processing
lane. This specification describes lane certification and global execution.
Independent data space execution and local finality belong to `sumeragi.md` §11.
An institutional environment should be called a data space in articles and
diagrams; introducing its lanes does not replace that environment or identity.

A **lane** adds dissemination and certification capacity to the one global world state. Every lane
incarnation is a separate Sumeragi core instance with its own committee, pinned at creation. A
lane block is an ordered batch of transactions that the lane committee has checked for
*admission* (network, signature, deduplication) against a committed global block, its **anchor**;
a lane never mutates world state. The global chain `G` **merges** certified lane blocks by
reference: a `G` block names, per lane, the next contiguous certified lane heights, and executing
the `G` block executes those transactions against the world state in one canonical order. `G` is
the only place state changes, so transactions on different lanes need no cross-lane protocol:
their atomicity and ordering are those of the `G` block that merges them.

**Autoscale** is a deterministic rule in `G`'s execution. From committed load samples it opens a
new elastic lane (a fresh incarnation with a pinned committee, active two `G` heights later) or
closes the highest one. Closing is one committed height `c`; the **freshness bound** `A` makes
every lane block anchored before `c` unmergeable after `G` height `c + A`, so the lane's final
frontier is fixed at `c + A` with no drain vote, and the lane retires at `c + A + 1`.

Why this shape:

- The core is reused unchanged: a lane is just another instance (`I`, committee, parameters), so
  lane safety and liveness are the core's (`sumeragi.md` §7–§8).
- One world state, one execution order: no merge QC, merge leader, sidecar custody, relay
  settlement or drain certificate is needed, because `G`'s own CommitQC orders the merge.
- Every node follows every public lane (member or observer), so the bodies `G` executes are in
  every node's local lane stores through ordinary core sync.

## 1. Terms

- `G` — the global instance: the node's existing Sumeragi instance, height `h`.
- Lane `ℓ` — a `LaneId` of the committed lane catalog. Lane `0` (the anchor lane) is sequenced by
  `G` itself and has no instance. Every other active lane has one instance per incarnation.
- Incarnation `ι` — `H("iroha/sumeragi/lane/incarnation/v1" ‖ network_id ‖ be32(ℓ) ‖
  be64(dataspace) ‖ be64(creation_height) ‖ be64(creation_counter))`; the counter is the number
  of incarnations the chain has created, so `ι` is never reused.
- Lane instance id `I_ℓ,ι` — the core instance id (`sumeragi.md` §3.5) of kind `Lane` and index
  `ℓ` over the lane genesis hash (§2.3).
- Lane height `x` — height in the lane instance; lane genesis is `x = 0` (§2.3).
- Anchor `a(B)` — the `G` height named by lane block `B` (§3.2).
- Lane policy — the governed custom chain parameter `sumeragi_lane_policy`
  (`SumeragiLanePolicy`): freshness bound, merge bound, stall window, the chain parameters pinned
  into new lanes, the fixed lanes with their committees, explicit routes and the autoscale
  settings. Without it the chain has lane `0` only. `SetParameter` validates it (structure,
  pinned parameters, every fixed member's BLS-normal key and proof of possession).
- `A` — freshness bound: the policy's `anchor_freshness` (default 16), **pinned into each
  incarnation** at creation, so a policy change never alters an existing lane's rules.

An additive native data space catalog transition also registers its fixed Sumeragi lane in
the same transaction. The admitted manifest's exact live committee and proofs of possession
are pinned at the lane's activation height; existing policy bounds, routes and autoscale
settings are preserved. For a chain's first lane, the model-owned `for_chain` constructor
sets freshness to 16 blocks, maximum merged blocks per lane to 16 and the stall window to
64 blocks, and copies the chain's governed consensus parameters. This is on-chain policy,
not node-local configuration. Aborting the transition discards both catalog and lane policy.

Concrete native instruction or contract-address data space targets take precedence over
account and instruction-type routing rules. A non-universal target selects its first
admitted fixed lane, in lane-ID order, with matching pinned data space and committee. A
missing, unresolved, closing or not-yet-active private route is rejected; it is never
executed as universal work. Transactions without a concrete data space target keep the
explicit/default routing rules below. Concrete universal application targets may use only
lanes pinned to universal. Sharing an owner does not merge data space routes. Complete
control-plane batches (`SetParameter`, universal alias-registry and SCCP instructions)
route to lane `0` before logical lane rules. In particular, catalog registration at `h`,
bootstrap at `h + 1` and `EnsureAlias` at `h + 2` can complete without an unrelated
transaction to advance the activation boundary. Application work enters the native lane
only after the global chain has applied `active_from`.

## 2. Lane lifecycle in `G`'s state

### 2.1 Lifecycle record

World holds one `SumeragiLaneState` cell: the lane records (lanes ascending), the autoscale
samples (§6.1), the height of the last autoscale transition, the incarnation counter and the
original staking obligations below. A lane record is

```text
SumeragiLaneRecord {
    lane: LaneId, dataspace: DataSpaceId, incarnation: [u8; 32],
    params: SumeragiParameters,           // the lane's chain parameters, pinned
    committee: Vec<{peer, pop}>,          // canonical order, pinned for the whole incarnation
    created_at: u64,                      // G height of the creating block
    active_from: u64,                     // created_at + 2
    closing: Option<u64>,                 // G close height c
    anchor_freshness: u64,                // A, pinned
    merged: {height, block_hash, result}, // highest merged lane block (lane genesis at first)
    merged_at: u64,                       // G height of the last frontier advance
    rescued: u64,                         // lane-routed transactions G executed directly since
}
```

The state is committed by the `G` block that writes it. A fixed lane is created when the policy
lists it (genesis, or the first block after a `SetParameter` that adds it); an elastic lane by
autoscale (§6). Lane `0` has no record.

#### Original staking obligations

On an NPoS chain, creation also pins a `SumeragiLaneCustody` row to the exact native
instance and incarnation. Its sparse, strictly increasing signer indices support the native
core representation of up to 1024 members, with indices `0..n-1`. This representation does not relax the separate
authenticated lane-state committee-size and canonical-order checks. Each monetary
binding commits the original canonical staking owner, universal account, activation height,
peer and exact retained escrow asset. It never resolves a later registration by public key.
Missing positive custody makes that original signer forensic-only. Elastic lanes pin global
validator custody; fixed lanes pin the canonical staking owner selected for their physical
data space at creation. A fixed committee alone grants no authority over a reused global key.
Sparse signer bindings use immutable shared storage: production pinning admits the exact
backing and control from the original State execution pool before allocation. Cell/World
overlay copies retain that owner without copying the signer table. Decoded bindings remain
untrusted until resource admission; admission itself grants no history or monetary authority.
Fresh State construction and snapshot current/undo handoffs admit both generations before
replacement. Refusal preserves the borrowed source and refunds partial copies; snapshot
retry rereads its unchanged canonical field. The outer whole-State constructor still consumes
its input on failure and does not return a partially built State.

The row uses global creation and retirement heights; native lane heights are not global
occurrence heights. Live incarnations retain their original registration and pending-unbond
custody. Retirement at `r = c + A + 1` admits reports through `r + evidence_horizon`
inclusively, and releases custody only after the mandatory penalty phase at
`r + evidence_horizon + slashing_delay`. The installed evidence horizon and slashing delay are immutable, as specified in
`sumeragi_evidence_api.md`; obligation finalization defensively keeps maximum stored fences
without authorizing policy extensions. Unresolved
committed evidence retains the monetary obligation. All retained evidence records, including
terminal replay fences, keep the provenance row until record pruning; terminal records alone
do not extend monetary withdrawal fences. No later account/key registration inherits it.

The row also retains the last globally merged native `(height, hash, R)` frontier. The final
merge in the retirement carrier is captured before removing the live lane record. A retained
frontier cannot regress or change hash/result at the same native height. Monetary attribution
must authenticate every required parent and demotion header backwards from that exact global
anchor; an independently certified local fork cannot select its own branch. Native subjects
whose parent is beyond the retained frontier remain pending or forensic-only until independent
anchored coverage exists. This coverage rule supplies no global occurrence height.

At most 4096 original incarnation rows are retained. Exhaustion defers new lane creation while
existing closing, retirement and ordinary block execution continue. Expired rows are reclaimed
before creation, and the complete table is included in the ordinary lane-state commitment.

Production historical lane-store authority captures its exact original State view, allocation
pool and native tip before releasing State guards and opening the archive. It retains the
original archive read job across local refusal, including its acquired file and partial bytes. The complete authenticated global prefix
must match the captured native tip's carrier, core hash and execution result. Genesis-created
lanes acquire authority only after the actual H2 successor authenticates genesis execution.
The installed schedule retains the original complete creation frame and its prepaid selected
committee/key/epoch graph; immutable record comparison uses a streaming identity rather than a
second lane-record clone. A cancelled request is completed or explicitly rejected before a new
request can replace that original acquisition. Before advancing its certificate cursor, this
reader acquires the exact signed availability table, result witness and canonical resultless
proposal in the original State pool. Partial backing and completed archive bytes survive local
refusal; the independent historical committee still verifies every QC and signed RS16 relation.
Prefix/result graphs, certificate metadata, RS16/BLS scratch and caches, and schedule-returned
configuration clones still require separate resource accounting. A borrowed scan of the
authenticated tip payload checks retained custody identity, immutable policy fences, original
sparse signer bindings and retirement against the original creation owner. A missing reclaimed
row grants historical storage authority only; it supplies no monetary authority.

The production lane observer retains only bounded local reports. Proposer selection and follower
admission use the same retained original-cut reader: authenticate the global creation and
admission-parent carriers, restore the signed native branch backwards from the globally merged
frontier, and keep the original payload and demotion-header owners until verification finishes.
The installed attribution records a distinct lane scope and the original creation-time signer
custody. Native lane heights remain native subject identifiers; global admission height starts
the immutable penalty delay. Monetary effects revalidate the exact original registration,
activation height, peer and escrow. An originally unbound member remains forensic-only even if
that key later registers stake. A retired routing owner may still owe its original retained
liability, while a later registration never inherits it.

Pending and terminal records are authenticated against their original admission carrier when
restoring an existing State. Live incarnations keep terminal replay fences; retired incarnations
admit through the inclusive retirement-plus-horizon deadline, and only terminal records strictly
past that deadline can be pruned. Unknown or reclaimed custody rows cannot reopen admission.
The canonical 124-record and 16 MiB proof caps impose deterministic backpressure without eviction;
this bound does not establish sufficient offence availability for every native committee.

Autoscale sample clones retain their original immutable backing. State construction and snapshot
admission charge exact sample backing and its shared control to the original State pool; both
current and predecessor generations must succeed before replacing either. A sample update
precharges only its actual retained suffix and appended row, with the existing positive-u32
window policy unchanged. Refusal leaves the original samples intact. Snapshot retry retains raw
source bytes and redecodes; it does not retain partial decoder progress. Outer lane/custody
vectors and Cell controls remain separate owners.

**Open H3 boundary:** complete decoded-proof and prefix/result graphs, header/QC metadata,
RS16/BLS scratch and caches, outer lane/custody vectors and Cell controls, output model graphs and other World copies still
require complete original-pool allocation ownership. Existing-State restoration retains its
reader across local refusal, but the outer whole-State deserializer still does not retain a
partially initialized State; authenticated accelerated startup restoration remains H4 work.
Nonempty snapshot caches remain prohibited as consensus initialization authority. The connected
component path and its focused checks do not establish the complete H3 or whole-node gate.

### 2.2 States

`Created (G height < active_from) → Active → Closing (c set) → Retired (record removed)`.

- **Active** from `G` height `active_from`: nodes start the lane instance when they apply that
  height (§4.1); the lag of two gives every node the record before the first lane block can be
  merged.
- **Closing** from the `G` block that sets `c` (autoscale scale-in, stall close §6.4, a policy
  that no longer lists a fixed lane or lists it with another committee or data space, or a chain
  without a policy). A fixed lane the policy still lists is recreated, as a new incarnation, once
  its closing incarnation retires.
- **Retired** at `G` height `c + A + 1` (§6.3): the record is removed and the frontier is final.

### 2.3 The lane instance's configuration

The core needs `C_{x}`, `ChainParams_x` for every lane height and an `Init` (§12 of the core
spec). For a lane they are constants of the record:

- `C_{ℓ,x} = committee` for all `x` (BLS-normal keys with the pinned proofs of possession).
- `ChainParams_x = params` for all `x`; `R_x` still commits them (they never change).
- Lane genesis `x = 0`: `block_hash_0 = H("iroha/sumeragi/lane/genesis/v1" ‖ network_id ‖
  be32(ℓ) ‖ ι)`, `R_0 = H("iroha/sumeragi/lane/genesis-result/v1" ‖ norito(the fields fixed at
  creation))`. The record's `merged` frontier starts at this genesis.

A committee therefore cannot change within an incarnation; replacing members means closing the
lane and creating a new incarnation. A pinned member that loses its key stalls only this
lane, and §6.4 closes a stalled lane.

## 3. Lane blocks

### 3.1 Payload

A lane block's payload is the canonical Norito encoding of

```text
LaneBatch { anchor_height: u64, anchor_hash: Hash, transactions: Vec<TransactionEntrypoint> }
```

Each element preserves its complete external, sealed-commitment or sealed-reveal entrypoint.
Lane admission, recent-input deduplication and `LaneResult.tx_hashes` use the canonical
`HashOf<TransactionEntrypoint>`. Merge moves this same carrier into global execution, where
sealed-reveal commitment, salt, deadline and replay checks remain mandatory.

The queue-backed lane selection budget counts each complete cached entrypoint frame,
including its enum envelope, commitment and salt. The inner signed/variant size used
for transaction admission is a separate limit. The lane builder still checks its
actual complete encoded batch against the pinned payload limit.

It is never empty (work-driven, `sumeragi.md` §6.10): the lane's payload builder answers `EMPTY`
when the lane queue partition (§5) has nothing admissible. Future-only queued work instead
returns a local clock retry, preserving the original queue entries so the driver timer can
resume without unrelated network traffic.

The lane's effective timestamp is
`max(authenticated_anchor.creation_time_ms, max(tx.creation_time_ms + 1))`, using saturating
arithmetic at the timestamp limit. It is derived from the original authenticated anchor and
signed external or revealed transaction bytes; a commitment has no creation timestamp and
contributes no input time floor. No new time field or time commitment is introduced. The proposer
waits while that timestamp exceeds its injected local Unix clock, including after completed
payload encoding and after a clock rewind. It retains the same original batch and funded
encoding across this wait.

### 3.2 Admission execution (execute-before-vote for lanes)

A lane member executes a lane block `B` at lane height `x` as follows; `Valid(R)` or `Invalid`:

1. The anchor is a committed `G` block the node has applied: `anchor_hash` is the hash of `G`
   height `anchor_height`. If the node has not applied that height yet, execution is **pending**
   (the executor answers when it has; the core allows execution to take time, §6.3). If the node
   applied that height with another hash, `Invalid`.
2. Monotone anchors: `anchor_height ≥` the anchor of lane block `x − 1` (from its `R` preimage).
3. The lane is active at the anchor: `active_from ≤ anchor_height` and not
   (`closing = Some(c)` with `anchor_height ≥ c`).
4. Every entrypoint is for this network and its original signature verifies: the signed
   transaction for external/reveal inputs, or the signed commitment for a commitment.
   Limits, expiry and every
   state check belong to merge execution (§4.3), where `G`'s parameters of the merge height apply.
5. No transaction hash appears earlier in `B`, or in one of the last `W = 64` lane blocks
   (`LANE_DEDUP_WINDOW`) whose anchor is at least `a(B) − A` — a block `G` may still merge fresh
   together with `B`. Once every earlier carrier is stale for `B`, the transaction may be carried
   again: a stale carrier never executes it. Duplicates across lanes, or of transactions `G`
   already committed, are dropped at merge.

`R_x = H("iroha/sumeragi/lane/result/v1" ‖ norito(LaneResult))` with
`LaneResult { anchor_height, anchor_hash, tx_hashes, payload_bytes, next_committee_digest, next_params }`;
`next_*` are the pinned constants (§2.3), so the core's lag-2 rule holds trivially.

Admission is a pure function of the lane block, the lane's own chain (its previous anchor and the
last `W` blocks with their anchors) and permanent facts of `G` (the anchor block's hash and time,
and this lane's record fields, which never change once set),
so every honest lane member computes the same `R_x` whenever it executes. Before caching a
fresh `Valid`, the lane executor applies `sumeragi.md` CT1: with `certified = false`, it returns
local `Failed(ClockAhead)` while its effective timestamp exceeds the injected local Unix clock
plus `record.params.max_clock_drift_ms`. That allowance is bounded by CT4 and pinned for the
entire incarnation. It retains the original available body, one decoded batch and authenticated
admission facts, and rejoins the anchor identity on retry. This timing refusal is never `Invalid`.
A genuine certified re-proposal, CommitQC preparation and authenticated stored recovery bypass
the local guard; they reproduce the same deterministic result. Pure admission never reads
world state and never checks routing: routing is decided at merge (§4.3 step 3), where `G`'s
state is the single authority, so a lane's result cannot depend on how recent a node's view of
the lane set is.

## 4. Merging lanes into `G`

### 4.1 Nodes follow every lane

Every `G` node runs every active public lane's instance: as a member when its validator key is in
the pinned committee, otherwise as an observer (the core commits from CommitQCs and syncs bodies
as an observer, `sumeragi.md` §6.9). Lanes of restricted data spaces are followed by the nodes the
data space policy admits; `G` merges only lanes its validators follow (public lanes in the first
release). A node starts a lane instance when it applies `G` height `active_from` and stops it after
applying the retirement height.

### 4.2 The `G` payload

A `G` block payload carries, besides its ordinary transactions (lane 0):

```text
LaneMerge { lane: LaneId, incarnation: [u8; 32], from: u64, to: u64, tip_hash: Hash, tip_result: Hash }
```

for each lane with new certified blocks: the next contiguous lane heights `from = merged + 1 ..= to`
that the leader's node has committed. The payload carries them in its execution context
(`SumeragiLaneMergeSection`), lanes in ascending `LaneId`. Limits: at most `max_merge_blocks`
(policy) lane blocks per lane, and the block's own transactions plus the transactions of its
fresh merged blocks fit the block's transaction capacity (the on-chain transaction cap and the
execution output's network input capacity), so a `G` block's execution stays within its budget.
The leader reserves capacity for lane blocks first, lanes taking turns (rotating by height) so
none starves, and fills the rest with lane-0 transactions. A block with merges and no
transactions of its own is work: lanes never wait for lane-0 traffic.

The section also declares a **time floor**: one millisecond after the latest creation time among
the transactions of its fresh merged blocks. The block's canonical time is at least the floor
(besides the parent-plus-cadence rule and its own transactions), so every merged transaction
precedes the block that executes it, and the proposal alone still fixes the time. Execution
recomputes the floor from the lane blocks; a different declaration makes the block `Invalid`.

### 4.3 Merge execution

`G`'s executor, for a `G` block at height `h`, after its ordinary preamble:

1. For each `LaneMerge` in order, the node's lane store must hold committed heights
   `from ..= to` (the executor waits up to `E_max`; until then execution is pending and retried —
   lane sync fetches them, and a lane CommitQC for them exists, so bodies are available from the
   lane committee). A `LaneMerge` out of lane order, whose lane has no record, another
   incarnation, is not active (`h ≤ active_from`), whose `from` is not `merged + 1`, whose `to`
   block or result differs from the lane's committed block, or which violates a limit makes the
   `G` block `Invalid`. A certified lane block whose payload is not a lane batch (only a
   Byzantine lane quorum certifies one) is merged without effect.
2. **Freshness:** a merged lane block is *stale* when `anchor_height < h − A`. A stale block is
   merged — the frontier moves past it, so a lane never stalls behind an old block — but its
   transactions are not executed; they stay pending in the queue and are proposed again. (Lane
   members refuse blocks anchored at or after a closing height `c`, so no merged block is.)
3. The transactions of the fresh merged lane blocks are executed in order — lanes ascending,
   lane heights ascending, transactions in batch order — after lane 0's transactions, exactly as
   if they were one ordered list in the `G` block: the executed block is the proposal with these
   entrypoints appended (`merged_count` records how many; removing them recovers the proposal).
   Each transaction retains its complete `TransactionEntrypoint`: `External`, sealed
   commitment or sealed reveal. A merged transaction is dropped — no effect, no fee, not in
   the executed block — when `route(tx, state before h)` (§5.1) is not the lane that carried it
   (*misrouted*), the chain already committed its original carrier or the reveal's signed-work
   alias, or its work duplicates an earlier admitted entrypoint. External transactions and
   reveals with the same inner signed transaction are duplicates across the global prefix and
   all merged lanes; commitments are duplicates by commitment digest. A commitment's
   `reveal_after_height` must be strictly greater than `h`. Other stateless refusals are a
   signed creation time at or after the block time, or failure of the original network,
   signature, limit or expiry checks at that time. Commitments have no signed creation time.
   Dropping instead of invalidating keeps a lane committee from blocking `G` with a
   transaction `G` refuses. Every other original carrier executes and its outcome (accepted /
   rejected with reason, fees as usual) is committed in `R_h`. The original salt, reveal window
   and pending-commitment checks remain stateful execution checks; rejection retains the
   original carrier in the executed block. Admission at the lane does not guarantee acceptance:
   state may have changed since the anchor. Refusal of the original finite scratch budget
   defers the local merge for retry with the same source; it does not deterministically drop a
   transaction.
4. The **lane step** (in the execution output's finalizer, with the schedule step): the merged
   frontiers advance to `to` (`merged_at = h`, `rescued = 0`); the block's lane-0 transactions
   routed to another lane add to that lane's `rescued`; the load sample of §6.1 is recorded;
   lanes at their retirement height are removed; fixed lanes are reconciled with the policy;
   stalled lanes close (§6.4); at most one autoscale transition applies (§6.2–§6.3).

FASTPQ execution-source capture freezes these same committed native lane incarnations before
block-start effects. At height `h`, a nonzero lane uses its exact record only while it admits
anchor `h - 1`; lane 0 retains the global chain's original incarnation. Physical storage catalogs
do not grant execution-lane authority, and later lifecycle effects cannot change that frozen scope.

**Parallel execution.** Step 3 fixes the *result*: the canonical serial order above. The executor
may run merged lane batches concurrently with the deterministic parallel scheduler, which commits
a transaction only in canonical order and re-executes it on a read/write conflict with an earlier
one, so the result equals the serial order on every node and every machine. Lane key prefixes
(`LaneConfig::key_prefix`) and authority-based routing (§5.1) keep most lane batches disjoint, so
adding lanes adds execution parallelism as well as dissemination and certification capacity;
transactions that touch several lanes' state serialize on the conflict, never reorder.

A lane block that is stale when merged, or that is still unmerged when its lane retires, has no
effect; its transactions stay in the nodes' queues (§5.3) and are proposed again.

### 4.4 Why this is safe

- `G`'s CommitQC fixes the merge set and order; every honest `G` node executes the same
  transactions in the same order (the lane blocks are fixed by their lane CommitQCs, and the tip
  hash and result bind them). World state therefore stays a deterministic function of `G`'s
  committed chain.
- A lane's safety (one block per lane height) comes from its own core instance; `G` validators
  check nothing about lane signatures beyond their own nodes' lane commits, which are the core's
  commits under the pinned committee.
- A Byzantine `G` leader can only choose *how much* of each lane to merge (not reorder or alter
  it); honest leaders merge everything available, so every certified, fresh lane block is merged
  within one honest `G` leader's turn.

### 4.5 Storage and sync

The node's Kura stores `G` blocks as today and, per lane incarnation, a lane block store with one
certified frame per lane height (the same `KuraBlockStore` shape, under the lane instance's
storage identity). A `G` frame is committed only after the lane frames it merges are durable
(append order), so replay after restart re-executes `G` blocks from local lane frames. A syncing
node syncs each lane instance alongside `G` and executes a `G` block once its lanes reach the
merged tips; lane frames of retired incarnations are kept while any retained `G` block references
them and pruned with those `G` blocks.

Retirement releases the node's registry owners after stopping the driver and its recovery
job, including failed store openings that never started a driver. Their original funded
buffers and exclusive locks are released; outstanding authenticated readers keep their
ready-store ownership until finished. Historical openings after retirement keep their own
recovery progress across subsequent lifecycle checks. This owner cleanup does not delete
certified frames.

The registry map only selects or publishes a per-key owner. Directory establishment,
prefix authentication, RS16 restoration and native synchronization run outside that shared
map. A busy same-key recovery returns WouldBlock and retains its exact original opening;
ready disjoint lanes remain available. In-flight opening Arcs pin runtime retirement until
the caller returns, while a historical join records its interest under the map before
attempting recovery. An idle runtime-only refusal can then be cancelled by reconciliation.
A caller that retained the opening before Ready publication joins that same completed
store, without creating a new native lock or source graph. Original-pool notifications
follow both the map and per-key recovery guards.

Direct evidence ancestry reads likewise retain the original instance directory and every
ancestor across all frame reads and local refusals. Each frame opens through those retained
descriptors; a late namespace refusal keeps the exact completed funded body and CommitQC for
same-owner retry, and completed evidence rejoins the directory before attribution. This is
original namespace custody, not a deletion lock or an authenticated history-release permit.
TODO: physical retirement still requires authenticated complete-State restoration and an
existing native-history owner that durably releases the full transitive replay/evidence
interval. Startup currently replays genesis through the tip, so every referenced retired
lane frame remains required and is not deleted by registry cleanup.

## 5. Routing and the queue

### 5.1 Routing function

`route(tx, state) -> LaneId` at global height `h` uses only committed state. A lane is
*admitted* at `h` when its record admits blocks anchored at `h − 1`, the tip a block at `h` is
built on — so a lane receives traffic only once the global chain has applied its activation
height (and its instances run), and none from the height after its closing height. The policy's
explicit routes come first (an account matcher and/or an instruction matcher; the target is lane
`0` or a fixed lane, and a target that is not admitted sends the transaction to lane `0`);
otherwise the default route is sharded over lane 0 and the admitted elastic lanes by
`H(tx.authority) mod k` (authority-based sharding keeps one account's transactions in one lane,
preserving their order). A node routes new transactions with its latest applied `G` state; `G`
re-evaluates the route at merge (§4.3 step 3), so a transaction routed just before a lane opened
or closed is dropped as misrouted without effect, stays pending in the queue and is re-routed.

**Application policy.** A native lane determines ordering and execution provenance; the
transaction's physical application profile is independently selected by the deterministic Nexus
routing policy over the current execution state. Queue admission applies that physical profile,
and merge execution resolves it again. The physical plan must contain exactly one route; the
current executor rejects multi-route plans. Its data space must equal the authenticated native
execution route's data space. Manifest readiness, governance hooks, privacy, compliance and fraud
checks use the exact physical profile, including when its numeric lane identifier collides with
a native lane identifier. Execution source identity and output custody retain the native lane
and incarnation. Neither a catalog-order choice nor a sibling lane in the same data space
substitutes for the selected application profile.

The configured genesis signature authenticates bootstrap inputs before execution. Each input
carries a private admission capability bound to its exact header, transaction hash and position,
usable only while committed history is empty. This capability exempts that input from runtime
fraud-assessment metadata, which the canonical genesis envelope cannot carry. Ordinary execution,
including an isolated component with a height-one header, retains the configured fraud policy.

**Rescue.** `G` does not enforce routes on its own transactions. A leader includes a transaction
routed to another lane once it is older than `2A` global block times (by its creation time
against the parent block's): a stalled lane cannot hold transactions, and each rescued
transaction is committed evidence of load the lane is not serving (§6.4). A transaction both
rescued and carried by a lane executes once; the later carrier's copy is a duplicate. A rescue
is packed within `G`'s own selection budget (`max_block_bytes(G)` less the proposer reserve). A
coherent committed policy requires the transaction cap plus the global proposer reserve to fit
`G`'s payload limit, so every admitted transaction fits the full global selection budget. A
smaller lane budget or the space remaining after other global proposal contents can defer a
queued input; rescue carries it only when enough space remains
(`specs/zk_resource_contract.json`, `stage_decisions`).

### 5.2 Queue partitions

The transaction queue keeps one FIFO partition per lane (lane 0 is `G`'s). Gossip, admission
limits and expiry are per node as today; the partition is derived by `route` when a transaction
is admitted and recomputed when the catalog changes (after a lane opens or closes).

### 5.3 Retirement from the queue

A transaction leaves the queue when a `G` block that executed it (merged or directly) is applied.
It is not removed when a lane block containing it commits: until `G` merges that block the
transaction is still pending, and if the block is never merged it is proposed again. The lane
payload builder skips transactions already in committed-but-unmerged lane blocks of that lane.

## 6. Autoscale

All rules run in `G`'s execution with committed data only; every node computes the same decision.
Parameters are the policy's `autoscale` settings (elastic range `[min_lane, max_lane_exclusive)`,
data space, committee size, per-lane target throughput, window, scale-out and scale-in
utilization in per mille, cooldown); at most one autoscale transition per `G` block.

### 6.1 Samples

Each `G` block appends a sample `{height, time_ms, transactions, lanes}` — the transactions it
executed from lane 0 and the elastic lanes, and the number of default-route lanes (lane 0 plus
the admitted elastic lanes) — keeping the last `window + 1`. Utilization over the window is

```text
Σ transactions / Σ (interval_ms × lanes × per_lane_target_tps / 1000)      (per mille)
```

over the last `window` sample intervals. Blocks are work-driven (no empty blocks), so a long
block interval means idle time, not saturation: latency is not a load signal, and utilization
already counts the idle time as unused capacity.

### 6.2 Scale out

When utilization is at least `scale_out_permille`, the cooldown has expired and a free elastic id
exists, execution creates a lane record: the lowest free id, the autoscale data space, the
policy's lane parameters and `A`, a fresh incarnation, and a committee of `committee_size`
global validators live at `h` with their registered proofs of possession, ranked by
`H("iroha/sumeragi/lane/committee-rank/v1" ‖ ι ‖ key)` (so successive lanes spread over the
validator set) and stored in canonical order. If fewer validators are available, no lane is
created.

### 6.3 Scale in and retirement

When utilization is below `scale_in_permille` (strictly below `scale_out_permille`, so a
transition never immediately reverses) and the cooldown has expired, execution sets
`closing = Some(h + 1)` on the highest active, non-closing elastic lane. From `c`:
routing excludes the lane (§5.1), lane members refuse blocks anchored at or after `c` (§3.2
step 3), and `G` merges only its blocks anchored before `c` (§4.3). At `G` height `c + A` every
still-unmerged block of the lane is stale, so its frontier is final; at `c + A + 1` execution
removes the record and the lane retires. No drain vote or certificate exists: `G` alone decides
the frontier.

### 6.4 Stalled lanes

A lane with rescued load (`rescued > 0`, §5.1) whose frontier has not advanced for
`stall_window` `G` blocks (`h ≥ merged_at + stall_window`) is closed exactly like a scale-in
(fixed lanes too), so a lane whose pinned committee lost its quorum is replaced. A fixed lane is
then recreated with the committee the policy lists; governance replaces a broken committee by
changing the policy.

## 7. Fees and settlement

Lane transactions pay fees at merge execution like any transaction (the fee model of
`nexus_fee_model.md`). Fee admission uses the transaction's data space, which must agree between
the physical application policy and authenticated native execution route (§5.1). There are no
lane relay envelopes, settlement receipts or FASTPQ relay proofs: `G` executes the transactions
itself.

## 8. Status and telemetry

`/v1/sumeragi/status` stays the status of `G`'s instance. `/v1/sumeragi/lanes` serves one
`SumeragiLaneStatus` per lane of the committed state: its record (lane, data space, incarnation,
pinned committee and parameters, activation, closing, merged frontier, stall bookkeeping) and the
status of the node's instance of it (the same `SumeragiStatus` as `G`'s, or none before the
instance runs). Lane instances report through the node's log observer like `G`.

`/v1/sumeragi/diagnostics` reports pressure from its live Queue owner, committed NPoS
parameters and physical lane governance. It does not retain synthetic lane/data space
commitment or pipeline snapshots from the retired driver. A missing Queue owner is
unavailable rather than an empty queue. Account data space summaries expose bindings,
portfolio counters and manifest state; native lane incarnation/frontier information
comes from `/v1/sumeragi/lanes`. These diagnostics do not qualify RS16 availability.

## 9. What lanes do not have

There is no lane-level vote on world state, no second (merge) quorum certificate, no merge leader,
no side-channel custody of lane bodies, no drain vote or certificate, no relay envelope or relay
settlement proof, and no per-transaction queue reservation protocol: `G`'s CommitQC orders the
merge, the lane instances' own commits make lane bodies available to every node, and the closing
height plus the freshness bound fix a closing lane's frontier. Cross-lane atomicity is that of the
`G` block; atomicity across data spaces with separate state is §11's two-phase commit. The lane and
data space catalogs, `LaneConfig` geometry (key prefixes, visibility, storage profile), routing
rules, the `nexus.autoscale` parameters, lane validator pools and committee selection, and the
Kura per-instance storage identity are the inputs this design builds on.

## 10. Implementation plan

Done (`crates/iroha_core/src/sumeragi/lanes/`, `crates/iroha_data_model/src/sumeragi_lanes.rs`):

- **Lifecycle state and policy:** `SumeragiLaneState` in World, the `sumeragi_lane_policy`
  parameter and its validation, lane identity and `Init`/configuration from the record.
- **Lane executor and payload builder:** `LaneBatch`, admission and `R`, the anchor-aware
  dedupe window, the durable per-incarnation block store, routing from committed state.
- **`G` merge:** the merge section, pending-until-committed execution with the node's lane
  stores (also during Kura replay), freshness, dropping rules, canonical execution order,
  capacity reservation, rescue.
- **Lane step:** frontiers, samples, retirement, fixed-lane reconciliation, stall close,
  autoscale with committee selection.

Remaining:

1. **Multi-instance node (S5 core):** the node runs `G` plus one driver instance per active lane
   (per-instance records, bodies and the shared lane store; observer labels), started when `G`
   applies `active_from` and stopped after retirement; `net.rs` routes frames by instance id;
   O9 isolation tests.
2. **Status, telemetry, Torii and SDK DTOs; kagami/localnet lane policies.**
3. **Tests:** a P2P network soak with elastic scale-out and scale-in under load and restarts
   (in-process four-validator node tests and the simulator's F38 — a lane next to `G`, followed by
   every node — already pass).
