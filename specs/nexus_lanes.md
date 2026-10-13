---
title: SORA Nexus Lane Model
sidebar_label: Lane Model
description: Logical lane taxonomy, lane configuration geometry, and world-state merge rules for SORA Nexus.
---

# SORA Nexus Lane Model & WSV Partitioning

> **Status:** NX-1 production architecture — lane geometry, lifecycle storage,
> autonomous execution, and canonical merge are implemented; multilane release
> evidence remains open.
> **Owners:** Nexus Core WG, Governance WG  
> **Related roadmap item:** NX-1

This document captures the production architecture for SORA Nexus's multilane
consensus layer. Public routing and certification lanes feed one deterministic
global execution order. Each lane is assigned to a data space, and workload
names do not establish validator or storage topology. Independent data space
roots retain their own State and local finality.

> **Lane consensus:** This note focuses on geometry and storage. Lane instances, their certification and the global merge are specified in [sumeragi_lanes.md](sumeragi_lanes.md).

## Concepts

- **Data space:** The environment for data, authority, policy, and applications,
  identified by `DataSpaceId`. An independently signed data space root owns its
  State, storage, consensus instance, and local finality (`sumeragi.md` §11).
  The catalog identity alone does not establish that independent root.
- **Data space catalog:** `DataSpaceCatalog` / `[[nexus.dataspace_catalog]]`
  defines the data spaces, their aliases, and `fault_tolerance (f)` used to size
  consensus and relay committees (`3f+1`).
- **Lane:** Logical transaction routing, dissemination, certification, and
  backlog assigned to exactly one data space. `LaneCatalog` /
  `[[nexus.lane_catalog]]` defines lanes with separate `LaneId`s and explicit
  data space references. One data space may contain several lanes. A lane entry
  does not create a data space or a physical server boundary.
- **Namespace:** Independently governed naming scope bound explicitly to a
  data space. A namespace is neither a lane nor a data space, even when an
  alias happens to reuse the same text.
- **Lane Manifest:** Governance-controlled lane policy describing workload
  routing, gas, and settlement rules. The V1 file layout also projects
  validator and DA fields through lane manifests; those fields describe the
  owning data space and must be identical for every lane in that data space.
- **Lane certificate and global result:** A public lane certifies an ordered
  transaction batch for admission. The global chain merges and executes the
  batch, and its certificate binds the resulting global execution. The lane
  certificate does not establish successful asset movement or a new data space
  State root (`sumeragi_lanes.md`).

Articles and diagrams should introduce institutional data spaces first and use
lanes only to explain transaction processing or scaling. A bank operates in a
data space; several lanes can serve that data space without changing its identity.

## Lane Taxonomy

Lane types canonically describe their visibility, governance surface, and settlement hooks. The configuration geometry (`LaneConfig`) captures these attributes so nodes, SDKs, and tooling can reason about the layout without bespoke logic.

| Lane type | Visibility | Owning data space cohort | WSV exposure | Default governance | Settlement policy | Typical use |
|-----------|------------|---------------------------|--------------|--------------------|-------------------|-------------|
| `default_public` | public | Global staked cohort | Full state replica | SORA Parliament | `xor_global` | Baseline public ledger |
| `public_custom` | public | Public or stake-gated cohort | Full state replica | Stake weighted module | `xor_lane_weighted` | High-throughput public applications |
| `private_permissioned` | restricted | Fixed physical cohort (governance approved) | Commitments & proofs | Federated council | `xor_hosted_custody` | CBDC, consortium workloads |
| `hybrid_confidential` | restricted | Mixed physical cohort; wraps ZK proofs | Commitments + selective disclosure | Programmable money module | `xor_dual_fund` | Privacy-preserving programmable money |

All lane types must declare:

- Data space alias — explicit binding to the physical cohort that owns the
  lane. A namespace, governance module, or workload alias must not be inferred
  as a data space from matching text.
- Governance handle — identifier resolved through `Nexus.governance.modules`.
- Settlement handle — identifier consumed by the settlement router to debit XOR buffers.
- Optional telemetry metadata (description, contact, business domain) surfaced
  through `/v1/nexus/lifecycle`, metrics, and dashboards.

## Lane Configuration Geometry (`LaneConfig`)

`LaneConfig` is runtime geometry derived from the validated lane catalog. It supplies logical key prefixes and display/cache labels; authenticated network, incarnation and activation context remain necessary to identify physical consensus storage.

```text
LaneConfigEntry {
    lane_id: LaneId,           // stable identifier
    alias: String,             // human-readable alias
    slug: String,              // sanitised display/cache/metric label
    kura_segment: String,      // retained tiered/cache label, not a Kura locator
    merge_segment: String,     // display label, not a canonical merge locator
    key_prefix: [u8; 4],       // Big-endian LaneId prefix for WSV key spaces
    shard_id: ShardId,         // WSV/Kura shard binding (defaults to lane_id)
    visibility: LaneVisibility,// public vs restricted lanes
    storage_profile: LaneStorageProfile,
    proof_scheme: DaProofScheme,// DA proof policy (merkle_sha256 default)
    manifest_policy: DaManifestPolicy,
    confidential_compute: Option<ConfidentialComputePolicy>,
    scheduler: Option<LaneSchedulerPolicy>,
    settlement_buffer: Option<LaneSettlementBufferPolicy>,
}
```

- `LaneConfig::from_catalog` recomputes the geometry whenever configuration is loaded (`State::set_nexus`).
- Aliases are sanitised into lowercase slugs; consecutive non-alphanumeric characters collapse into `_`. If the alias yields an empty slug we fall back to `lane{id}`.
- Key prefixes ensure the WSV keeps per-lane key ranges disjoint even when the same backend is shared.
- `shard_id` is a typed lane-catalog field. When absent it canonically resolves to `lane_id`; an explicit value selects the persisted DA cursor/storage shard used across restarts and resharding.
- Manifest availability and confidential-compute settings are typed catalog fields. The latter
  carries an exact mechanism, positive key version, and canonical audience set and is only valid
  with `commitment_only` or `split_replica` storage. Retired functional metadata spellings are
  rejected rather than interpreted.
- Scheduler overrides and settlement buffers are typed catalog fields. Scheduler values are
  positive `u64` values; a settlement buffer binds an exact canonical universal account, asset
  definition, and positive XOR quantity. Raw scheduler and settlement-buffer metadata is rejected.
- Core derives deterministic physical Kura paths from the complete `LaneStorageIdentity`; a path or config label by itself is not authenticated active or historical authority.
- Per-instance merge files are currently empty geometry scaffolds. Canonical merge data has a separate stable storage owner.
- A lane alias rename does not relabel its exact Kura instance. Tiered/cache label changes are separate from authenticated consensus-storage identity.

## World-State Partitioning

- The logical SORA Nexus world state is the union of the data spaces' state spaces,
  with lane prefixes providing logical workload subdivisions inside each data
  space. Public data spaces persist full state; private/confidential data
  spaces export Merkle/commitment roots to the merge ledger.
- MV storage prefixes every key with the 4-byte lane prefix from `LaneConfigEntry::key_prefix`, yielding keys such as `[00 00 00 01] ++ PackedKey`.
- Shared tables (accounts, assets, triggers, governance records) therefore
  store entries grouped by lane prefix, keeping range scans deterministic.
  This is a logical subdivision within the owning data space and does not imply
  a distinct validator/server set.
- Canonical merge-ledger data belongs to the chain-scoped Kura journal and binds its actual lane/data space sources under that stable canonical owner. Lane-instance geometry scaffolds do not own canonical merge history or authorize its retirement.
- Cross-lane indexes (account aliases, asset registries, governance manifests) store explicit `(LaneId, DataSpaceId)` pairs. These indexes live in shared column families but use the lane prefix and explicit data space ids to keep lookups deterministic.
- The merge workflow combines public data with private commitments using `(lane_id, dataspace_id, height, state_root, settlement_root, proof_root)` tuples derived from merge-ledger entries.

## Kura & WSV Partitioning

- **Canonical storage** — `Kura::canonical_storage_paths` resolves the chain-owned block directory at `<store>/blocks/canonical` and merge journal at `<store>/merge_ledger/canonical.log`. They do not belong to a lane alias.
- **Lane-instance storage** — `LaneStorageIdentity` derives `<store>/blocks/instances/<identity-hash>` and `<store>/merge_ledger/instances/<identity-hash>.log` from the exact network, lane, data space, incarnation, and activation height. The merge path is an empty geometry scaffold, not the canonical merge journal. Configured aliases and slugs are display metadata and cannot reconstruct these identities.
- **Lifecycle authority** — Kura provisions and retires instance storage from authenticated State/catalog transitions and durable references. A configured lane's presence or absence does not authorize archiving any physical path. Tiered-state paths have their own storage owner and lifecycle.
- **Key prefixes** — the 4-byte prefix computed from `LaneId` is always prepended to MV encoded keys. No host-specific hashing is used, so ordering is identical across nodes.
- **Block log layout** — canonical block data, indexes, hashes, and the durable count marker (`blocks.count.norito`) are nested under the chain-owned canonical block directory. Lane instance artifacts are located by their immutable storage identity.
- **Retention policy** — public lanes retain full block bodies;
  commitment-only lanes may compact older bodies only after the checkpoint,
  finality, commit manifest, and every required Native application
  manifest/proof, receipt, and latest-index binding are durable. After body
  pruning, Native evidence revalidates against the QC-authenticated manifest
  root; a hash-only legacy marker is not authoritative by itself. Confidential
  lanes keep ciphertext journals in dedicated segments to avoid blocking other
  workloads.
- **Tooling** — `cargo xtask nexus-lane-maintenance --config <path>` emits a read-only physical inventory as JSON on stdout. It lists declared lane metadata separately from canonical paths, instance paths, and unclassified entries. It neither authenticates active/retired ownership nor opens Kura or moves files; symbolic-link entries are reported without following them, while linked store roots and storage namespaces are rejected. The report is an observation, not a consistent authenticated State snapshot. Neither file output nor `--compact-retired` is accepted; the command never creates a report file, and retirement remains with Kura's authenticated lifecycle owner.

## Storage Budgets

- `nexus.storage.local_budget_bytes` is the sole operator-facing aggregate on-disk budget for Nexus nodes. It covers Kura, cold WSV snapshots, and SoraFS storage; zero and the pre-release `max_disk_usage_bytes` alias are rejected.
- The actual configuration keeps the operator value separate from an actual-only `effective_local_budget_bytes`. An explicit operator value initializes both. When the operator value is omitted, `irohad` derives only the effective value at every startup and never rewrites the TOML file.
- Runtime derivation groups canonicalized managed roots by live filesystem identity and computes each filesystem cap as `(managed_bytes + available_bytes) - ceil(total_bytes * 20%)` with checked arithmetic. Underflow, zero, overflow, or a result below current managed usage aborts startup instead of activating an unenforceable cap.
- Every subsystem disk weight must be non-zero and the three weights must sum to `10_000` basis points. Operator budgets too small to give every component a non-zero cap are rejected because zero means unlimited to the component enforcers. Runtime application requires non-empty, strictly ordered, globally unique component sets, rejects zero component shares, and recomputes the aggregate with checked arithmetic from the per-filesystem budgets rather than accepting separate aggregate metadata. Proportional products use exact `u128` intermediates so `u64::MAX` budgets cannot saturate into incorrect shares.
- A symbolic link or Windows reparse point is allowed only strictly above a configured managed root. The exact root, any descendant, and dangling links/reparse points fail closed. Accepted ancestors are canonicalized before grouping and deduplication, and filesystem identity is rechecked while measuring every managed tree; crossing a mount boundary is fatal.
- Explicit budgets receive the same structural filesystem validation. Only a genuine low-space comparison is warning-only: the warning accounts for already-managed bytes and reports when additional growth required by the configured component caps exceeds available space.
- `nexus.storage.budget_enforce_interval_blocks` sets how often (in committed blocks) the storage budget scan runs; set to 0 to enforce every block.
- When the global disk budget is exceeded, eviction is deterministic: prune tiered-state cold snapshots oldest-first (offloading to `da_store_root` when configured), then Kura retired segments, and finally evict active Kura block bodies into `da_blocks/` for DA-backed rehydration on read. Blocks that exceed the Kura budget on their own are persisted directly into `da_blocks/` and indexed as evicted.
- `nexus.storage.max_wsv_memory_bytes` sets the hot WSV tier budget by propagating a deterministic weight into `tiered_state.hot_retained_bytes`: canonical Norito-encoded key bytes plus measured value footprints. This is not an allocator-exact resident-memory measurement. Grace retention or entries unavailable to an incremental snapshot may temporarily exceed the budget, but the total overflow is observable via telemetry (`state_tiered_hot_bytes`, `state_tiered_hot_budget_overflow_bytes`).
- `nexus.storage.disk_budget_weights` splits the disk budget across components using basis points (must sum to 10,000). Operator-explicit aggregate budgets use the existing global split. Auto-derived budgets first assign a budget per filesystem, then normalize the same weights across only the components present on that filesystem before deriving `kura.max_disk_usage_bytes`, `tiered_state.max_cold_bytes`, and `sorafs.storage.max_capacity_bytes`.
- Kura's storage budget enforcement sums block-store bytes across active +
  retired lane segments, including Native participant receipt,
  application-manifest/proof, and latest-index files, and includes queued blocks
  not yet persisted to avoid overshoot during write lag.
- Per-component limits still apply: when a component has an explicit non-zero cap, the smaller of the explicit cap and the derived Nexus budget is enforced.
- Budget telemetry uses `storage_budget_bytes_used{component=...}` and `storage_budget_bytes_limit{component=...}` to report usage/caps for `kura`, `wsv_hot`, and `wsv_cold`; `storage_budget_exceeded_total{component=...}` increments when a cap is exceeded (including retained WSV overflow) or enforcement rejects growth, and logs emit a warning for the operator.
- DA eviction telemetry adds `storage_da_cache_total{component=...,result=hit|miss}` and `storage_da_churn_bytes_total{component=...,direction=evicted|rehydrated}` to track cache activity and bytes moved for `kura` and `wsv_cold`.
- Kura reports the same accounting used during admission (on-disk bytes plus queued blocks, including merge-ledger entry payloads when present), so the budget gauges reflect effective pressure rather than just persisted bytes.

## Routing & APIs

- Torii REST/gRPC endpoints accept an optional `lane_id`; absence resolves via
  `nexus.routing_policy.default_lane` / `default_dataspace`.
- Lane relay admission fails closed when the lane id is absent from the
  authoritative lane catalog, when the derived runtime geometry is missing or
  disagrees with the catalog data space, when the relay data space does not match
  that active lane binding, or when the data space is not present in the active
  data space catalog. `State::record_lane_relay`, verified lane relay
  registration, and lane-relay emergency override registration all use this
  catalog + geometry + data space agreement before accepting lane-scoped state.
  Missing data spaces are reported separately from invalid validator rosters so
  operators can distinguish catalog drift from quorum shortages.
- Verified lane relay registration additionally shares the runtime relay
  finality verifier: it derives the canonical `3f+1` committee from the exact
  transaction snapshot, requires commit quorum, and verifies the aggregate BLS
  signature and proofs of possession. The QC mode tag is the strict canonical
  `lane-finality:v1` tag and signs a domain-separated statement containing the
  header hash, lane/data space/incarnation/height, DA commitment, standalone lane
  descriptor, manifest root, complete settlement commitment and hash, and RBC
  byte total. QC and proof carriers are excluded from that statement. The
  FastPQ proof is validity evidence, not authority: its old/new roots must equal
  the QC state roots, its transaction-set hash must equal the signed finality
  statement hash, and its DA and manifest commitments must equal the envelope.
  The submitting account is only a transporter; a missing or forged QC, a
  re-proved substituted settlement, or metadata-only FastPQ claim is rejected
  regardless of transaction authority and before contract state is mutated.
- `FindLaneRelayEnvelopeByRef` and runtime relay-cache hydration read verified
  relay records through the canonical `LaneRelayEnvelopeRef::relay_state_key()`
  and reject decoded records whose embedded `relay_ref` does not exactly match
  the requested or scanned key, so malformed contract state cannot spoof a
  different lane, data space, incarnation, or lane-local height under a valid
  key. The durable identity is exactly `(lane, dataspace, incarnation, height)`;
  a second finality effect at those coordinates is a conflict rather than a
  second settlement-hash-derived record.
- Merge-ledger commit validation and Space Directory-derived AXT policy snapshot
  derivation use the same active-lane agreement. A stale derived geometry entry
  cannot make a retired or removed lane merge-active, cannot select a target
  lane for AXT handle policy, and cannot populate cached AXT policy state when
  the authoritative catalog no longer contains that lane.
- DA commitment admission, DA pin-intent admission, Torii DA ingest proof-scheme
  resolution, Torii DA proof-policy endpoints, and block proof-policy hash
  validation are likewise derived from active catalog-backed Nexus lanes. Stale
  runtime geometry entries, removed catalog lanes, missing data spaces, or
  proof/confidential-policy drift cannot make a retired lane acceptable for DA
  commitments, pin intents, ingest receipts, or block header proof-policy
  hashes.
- Torii DA commitment and pin-intent list/prove endpoints apply the same
  active-lane filter before exposing query results. List responses omit records
  whose lane is no longer present in the authoritative lane catalog, and
  targeted prove requests for stale runtime-only lanes return no proof even if
  old DA indexes still contain matching rows.
- Authoritative lane validator resolution also requires the lane to be present
  in the active lane catalog, to have matching derived runtime geometry, and
  to bind a data space present in the active data space catalog. Stale manifest
  bindings or `Active` public-lane validator records for retired, rebound,
  unknown, geometry-only, or malformed lanes are ignored by lane relay, block
  sync, Torii proxy authority checks, and the global NPoS epoch stake snapshot.
  When Nexus is enabled, live NPoS active-topology and roster-unavailability
  recovery selection also intersect validator-derived lane scopes with the
  active lane/data space catalogs. State-backed commit stake snapshot
  construction and roster-validation caches apply the same active-lane filter
  to stake weights, so a larger stale stake record from a retired, geometry-only,
  or unknown lane cannot override the weight from a valid active lane.
  State-backed QC and block-sync validation fallback paths use that filtered
  snapshot recomputation too, so a missing cached snapshot cannot revive stale
  unknown-lane stake during quorum checks. Live NPoS commit quorum status,
  local quorum-completion checks, commit-root signer selection, NEW_VIEW
  aggregation, and repair fanout/coverage telemetry now also pass the active
  lane set into world-backed stake quorum math.
- When autoscale adds managed elastic lanes for the default data space, ordinary
  no-target default traffic is sharded deterministically across the configured
  default lane plus valid elastic lanes using the transaction hash. The default
  lane remains part of the candidate set, and explicit rules, routes targeting
  specific data spaces, settlements, and permission-scope routes keep their existing
  precedence. Valid elastic lanes must be public, autoscale-managed, correctly
  aliased, created at a positive height, and bound to the default data space.
  Their Torii route-authority set is inherited from the live commit topology
  after filtering for active consensus keys unless an explicit lane manifest
  binding exists, so consensus-created elastic lanes are immediately routable
  without giving ordinary public or restricted lanes a commit-topology fallback.
  Manifest validators and explicit bindings are exposed only when the declared
  validator list is duplicate-free, each binding names a declared validator, and
  the binding list has no duplicate validators or peers, so undeclared,
  duplicate validator, or duplicate peer entries cannot inflate route authority
  or public validator listings.
  The configured default lane itself must stay outside the autoscale-owned
  elastic id range so it remains a stable base anchor. Live-state routing also
  requires `autoscale.enabled = true` and filters
  managed elastic candidates to the configured
  `autoscale.min_lane_id..autoscale.max_lane_id_exclusive` id range, so disabled autoscale
  or corrupted out-of-range managed lanes cannot receive
  default traffic. If that active elastic range contains a manual lane,
  malformed autoscale-managed lane, or managed lane outside the default
  data space, live routing fails closed to the configured base default lane
  until the catalog is repaired. The integration router harness pins the same
  behavior at the fallible `LaneRouter::try_route_with_view` boundary, so
  in-range catalog corruption falls back to the base lane, stale managed lanes
  left in the catalog are ignored when autoscale is disabled, and enabled
  autoscale still shards over valid elastic lanes.
  Block autoscale application also requires enabled autoscale, so actual state
  with that subordinate gate disabled cannot create
  or retire elastic lanes. Autoscale catalog changes are staged inside the
  `StateBlock` and published to committed Nexus state and lane storage geometry
  only during `StateBlock::commit()` after transaction-height validation, so a
  transaction-height validation failure cannot publish a lane addition,
  retirement, runtime reset, or cooldown marker. Autoscale commit is serialized
  across transaction-height validation, lane storage reconciliation, and final
  publication: it first performs side-effect-free validation, then reconciles
  lane storage geometry outside the state writer lock, and only then publishes
  the committed Nexus catalog/runtime state under the writer lock. Manual lane
  lifecycle uses the same commit-serialization lock and lock order for geometry
  reconciliation and writer-locked catalog publication. World-backed cleanup for
  reset lanes runs after the block world overlay is committed, while state commit
  serialization is still active, so cleanup opens fresh committed-world
  transactions instead of re-entering through an uncommitted block overlay. DA
  commitment, shard/receipt cursor, confidential-compute receipt, pin-intent
  indexes, block-hash log entries, latest-header/query-index markers,
  commit-topology cells, and verified lane relay hydration prepared while
  applying a block are published only after a registered transaction block
  commits successfully, so those runtime, topology, and world indexes cannot
  leak from a block whose transaction commit later fails. Staged autoscale, DA,
  or verified-relay side effects with a missing inserted transaction block abort
  before geometry reconciliation, WSV cleanup, relay-cache hydration, or any
  world-state publication. Every committed WSV mutation therefore belongs to a
  canonical transaction block and advances through the same atomic commit path.
  Commit also
  completes fallible autoscale geometry reconciliation before the transaction
  commit and publishes the autoscale catalog/runtime reset before staged DA
  indexes, so a storage failure while reconciling elastic-lane geometry cannot
  partially publish DA runtime, query state, or block-local WSV cleanup for an
  uncommitted block. Lane lifecycle and config-swap retirements use the same
  storage preflight barrier: a failed Kura or tiered retire preflight preserves
  the committed WSV rows that would otherwise be reset for the retiring lane.
  Lane-geometry reconciliation dry-runs both Kura block/merge storage and
  tiered-state snapshot geometry before either backend is mutated. Kura then
  fsyncs a Norito intent containing the complete before/after geometry and
  incarnation bindings before it renames, archives, or provisions any path;
  tiered-state reconciliation runs behind that durable barrier. A failure before
  catalog publication rolls Kura back to the prior fingerprint, while restart
  after publication rolls it forward. Archive collisions, path traversal,
  symlinks, non-regular files, stale incarnation markers, and partial block/log
  pairs fail closed. The same commit boundary applies to deterministic autoscale
  scale-out and scale-in, including staged DA indexes in the block: a Kura or
  tiered conflict for a new or retiring elastic lane aborts before tiered
  artifacts or DA runtime/query indexes are published.
  Production startup authenticates the process-configured catalog in the
  canonical V5 geometry journal before opening any lane-derived Kura path, then
  binds the physical primary lane to its exact incarnation and storage paths.
  Replay restores the cursor before the first transition at genesis height, or
  to the snapshot's exact committed height, so multiple transitions at one
  height retain their durable sequence and cannot be skipped or replayed out of
  order. Checkpoints retain the last transition height and sequence; the first
  post-checkpoint transition uses checked height/sequence advancement. The
  published journal file is the commit point: only exact, regular, direct-child
  temporary files owned by an unfinished publication are consumed or removed.
  Configured-primary and journal-derived trees are traversed within fixed depth
  and entry bounds, every opened path is revalidated by filesystem identity,
  and paired geometry moves use atomic no-clobber renames. Before the first
  rename, the V2 lane-incarnation marker seals both intended target paths and a
  digest of the paired merge log. Mutable live pairs clear that move seal only
  after both halves arrive; retained archive pairs keep it, and GC validates
  the journal-owned logical target even after moving the archive into its
  quarantine name. Restart completes a block-before-merge partial move in
  either direction without overwriting an operator-created collision or
  adopting an unauthenticated path. Only a newly appended journal `Intent` may
  finish provisioning its journal-owned empty staging pair. Replay keeps
  `CatalogPublished` or `RolledBack` provenance until the inverse or forward
  move completes, and requires authenticated durable storage on every retry;
  losing that evidence can never be reinterpreted as authority to create an
  empty lane.
  Catalog-only routing without a live Nexus state view does not shard over
  elastic lanes; it keeps ordinary no-target traffic on the configured base
  default lane until live autoscale enablement and bounds are available.
  State-free router fast paths also defer unmatched no-target default traffic,
  including no-target IVM/proved-VM traffic, to live-state routing even when
  unrelated policy rules exist, so an unmatched rule cannot accidentally pin
  autoscaled default traffic to the base lane. State-free query routing,
  non-fallible state-free hints, and live non-fallible routing fallbacks reject
  autoscale-owned default or explicit-rule lanes instead of treating elastic
  lanes as operator-configured anchors.
  Fallible default-route resolution also rejects a corrupted policy whose
  configured default lane claims autoscale ownership, so elastic lanes cannot
  become the default anchor even when in-memory policy construction bypasses
  config validation.
  Canonical data space anchors used by writes targeting specific data spaces,
  settlements, and permission-scope routes ignore every lane that claims autoscale ownership,
  even when the claim is malformed, so elastic capacity cannot become the
  canonical lane for a data space. A data space with only autoscale-owned lanes
  fails closed with `no_lane_for_dataspace`.
  Corrupted runtime autoscale bounds or a default lane at or above
  `autoscale.min_lane_id` disable elastic sharding for routing and keep
  no-target default traffic on the configured default lane.
  Scale-out also requires a free id in the configured
  `autoscale.min_lane_id..autoscale.max_lane_id_exclusive` elastic range; hot windows fail
  closed without recording a transition once that range is exhausted, when the
  active elastic range is occupied by a manual or malformed managed lane, when
  the configured default route no longer resolves to the default data space, or
  when Kura cannot provide the complete historical sample window.
- When autoscale retires a managed elastic lane, the block-local lifecycle path
  prunes lane relay caches, lane-emergency-validator overrides, and
  verified relay contract-state records, merge-history checkpoints, DA
  commitment, confidential-compute, pin-intent, DA receipt cursor, and DA shard
  cursor indexes owned only by the retired lane in the same committed
  transition. Verified relay cleanup removes the canonical relay state key and
  its exact contract-map key for decoded records owned by the reset lane; if a
  canonical relay state row is undecodable, the lowercase exact key format is
  parsed and rows whose key lane is reset-owned are pruned as stale. Arbitrary
  prefixed siblings, uppercase digest variants, and opaque malformed
  contract-map rows remain inert state because they cannot be safely
  reverse-mapped to a lane. Verified-relay hydration likewise scans only
  lowercase exact canonical relay keys before decode, so arbitrary prefixed
  state cannot drive relay-cache admission attempts. Block-local resets also drop
  verified relay records staged earlier in the block for reset lanes before
  commit-time hydration, treating either the public relay reference lane or the
  embedded envelope lane as reset ownership. The same reset prunes AXT replay
  ledger entries keyed by a retired handle target lane while preserving
  cross-lane replay guards whose handles target surviving lanes. Public-lane
  cleanup reaches this point only after every owned tenure, custody balance,
  and pending unbond passes the retirement preflight. It then
  removes stake-share rows and reward records keyed by or carrying the reset
  lane, plus reward-claim cursors keyed by the reset lane, as live economic
  indices so a fresh incarnation can start reward epochs and claim accounting
  from its own state. Operator staking status snapshots for reset lanes are
  cleared at the same time, so status surfaces cannot continue reporting stale
  bonded or slash totals after a lane id is reused. It also
  refreshes the block-local AXT policy cache after the catalog change,
  retargeting Space Directory-derived entries when directory data is present and
  pruning explicit cache entries whose target lane no longer exists. Scale-in
  uses the same resolved
  default-route capacity and complete historical sample-window preconditions as
  scale-out, and only retires when router-owned capacity is strictly above the
  configured default-route lane, so stale routing state or unrelated manual
  lanes cannot retire an elastic lane. The `autoscale.min_lane_id` and
  `autoscale.max_lane_id_exclusive` values bound the autoscaler-owned elastic id range;
  they do not count unrelated public-profile base lanes as default-route
  capacity. Despite their compact names, these fields are not minimum and
  maximum active-lane counts: `min_lane_id` is the inclusive lane-id lower bound
  and `max_lane_id_exclusive` is the exclusive upper bound. The range may contain vacant
  ids, and it may start at the next id above the initial catalog namespace;
  lifecycle creation expands that namespace deterministically. The catalog's
  exclusive lane-id bound never shrinks when a lane is retired, so sparse lane
  identities and retained incarnation lineage cannot be silently recycled.
  Live
  default-route capacity is the configured base anchor plus valid managed
  elastic entries that currently exist inside the half-open range.
- WSV snapshots persist a versioned `nexus_runtime` section containing the
  effective lane catalog and `autoscale.last_transition_height`. On restart,
  those stateful values remain authoritative while static Nexus policy is
  refreshed from node configuration; this prevents a tip snapshot from
  silently recreating a retired lane, dropping an elastic lane, or clearing the
  cooldown. Snapshot decoding rejects unknown layout versions, invalid or
  duplicate catalogs, missing lane 0, malformed autoscale ownership metadata,
  future lane-creation markers, and transition heights beyond the snapshot
  height. Kura then reconciles the retained geometry journal to the snapshot
  catalog and atomically rebinds its in-memory lane map without deleting inactive
  rollback storage. It never fabricates an empty segment for a missing dynamic
  lane: the exact lane/incarnation/activation marker and both block and merge
  paths must be recoverable, otherwise startup fails closed.
  Snapshot payloads without `nexus_runtime` are rejected. A genuinely fresh
  state (with no snapshot lineage) derives its initial geometry from the
  configured catalog.
- Autoscale utilization samples count committed fragments, not just external
  transaction envelopes. Current-block decisions use the in-flight execution
  counter, and historical window samples read the persisted committed-fragment
  total from block results, with external transactions kept as a conservative
  lower bound.
  Block validation rejects non-zero committed-fragment totals that do not match
  re-execution, so peers cannot forge autoscale load history. Latency ratios
  and utilization are computed with widened deterministic integer intermediates
  and saturate only the final permille value, so extreme counters or timestamps
  cannot wrap or make an overloaded sample look cold. Utilization is divided by
  the same default-route capacity that the router can actually use:
  the configured default lane plus valid managed elastic lanes in the default
  data space and configured autoscale id range, not unrelated base/governance/zk,
  manually managed, malformed, or out-of-range lanes. The scale-out capacity
  bound uses the same default-route count, so unrelated manual catalog lanes and
  corrupted out-of-range managed lanes outside the autoscaler-managed candidate
  set do not inflate capacity or receive default traffic. Runtime autoscale
  prechecks also reject autoscale-owned out-of-range catalog corruption before
  plan construction, requiring an explicit repair retire instead of creating or
  retiring lanes around the corrupted entry. Missing historical Kura blocks,
  including gaps inside longer decision windows, and equal or backward block
  timestamps collapse the candidate window to no samples instead of
  extrapolating load or clamping bad timing evidence into synthetic hot/cold
  samples.
- Autoscale configuration fails closed before runtime: lane bounds, block
  targets, decision windows, cooldown, and per-lane TPS must be positive;
  `min_lane_id < max_lane_id_exclusive` so the elastic id range is non-empty; and scale-in
  thresholds must stay below scale-out thresholds so hysteresis cannot collapse
  into repeated lane churn. The block
  transition path repeats the lane-bound safety-cap and ratio sanity checks
  against the effective runtime state, so programmatic config swaps or
  corrupted actual state cannot raise `max_lane_id_exclusive` above the compiled cap or
  reinterpret non-finite, zero, sub-permille, or collapsed thresholds as
  permissive scale-out/scale-in triggers. Raw scale-in ratios must remain
  strictly below scale-out ratios after conversion to the permille thresholds
  used by block application. A future `last_transition_height` is treated as an
  active cooldown and suppresses create/retire transitions without overwriting
  the marker. If a hot/cold decision reaches the internal lifecycle helper but
  that helper rejects the add/retire plan, the catalog remains unchanged and
  `last_transition_height` is not advanced, so corrupted runtime state cannot
  pin cooldown after a failed scaling attempt. When configured windows
  conflict, a hot longer scale-out window takes precedence over a cold shorter
  scale-in window so capacity is added rather than retired in the same block.
  Scale-out treats either sustained p95 latency above the scale-out latency
  threshold or sustained p95 utilization above the scale-out utilization
  threshold as enough pressure to add managed capacity. Scale-in stays
  conjunctive and retires capacity only when both p95 latency and p95
  utilization are at or below their scale-in thresholds for the full cold
  window.
- Native AMX participant votes are prefiltered before they enter proposer
  session caches. The received vote message variant must match the signed
  attestation phase, remote sender `PeerId` must match the vote signer, the
  signer must use a BLS-normal consensus identity, and the individual signature
  must verify before the state-dependent live-PoP check and exact-body cache
  insertion run. QC assembly repeats the BLS-normal and individual-signature
  checks before aggregating, so polluted vote inputs fail closed even outside
  the normal ingress path. Only votes for an exact locally issued
  `(body, signer)` request may allocate a cache entry. Certified global-view
  changes retire stale body buckets and request authorizations. Vote caches are
  bounded by source sessions and exact attestation bodies, while request
  ownership is stored once per body with a compact expected-peer set. Delivery
  remains bounded by `sumeragi.queues.commands` and rotates fairly across
  bodies and missing committee members. An identical topology retry reuses its
  retained exact-output owner instead of consuming another corridor slot. If
  the worker cannot accept a request, compact catalog ownership releases that
  adapter delivery occurrence so a silent peer cannot pin every bounded slot;
  the fair cursor retries it after later peers.
  Revision 4 derives Native AMX cache
  geometry from `sumeragi.block.max_transactions`, the maximum participant-leg
  count, and the protocol lane bound. There are no separate operator-facing
  Native AMX cache switches. A certified global body lock or Decision retires
  adapter and exact-output Native ownership and rejects delayed resurrection.
- Any Torii ingress node may accept transactions and route them using the
  active routing policy, even if the target data space is not validated locally
  by that ingress node.
- SDKs surface lane selectors and map user-friendly aliases to `LaneId` using the lane catalog.
- Routing rules operate on the validated catalog and may pick both lane and data space. `LaneConfig` provides telemetry-friendly aliases for dashboards and logs.
- Nexus config swaps and lane lifecycle plans are validated before
  mutation: the configured default route and explicit rule targets must resolve
  against the candidate lane/data space catalogs. A rule that omits `dataspace`
  is validated against `nexus.routing_policy.default_dataspace`, and explicit
  rules cannot target autoscale-owned lanes. The router's fallible `try_route*`
  APIs enforce the same explicit-rule ownership boundary even if a corrupted or
  manually constructed policy bypasses config validation. Plans that would
  retire a policy lane, remove the default data space, rebind a lane without a
  matching routing-policy update, repeat an addition id or alias, or list the
  same retired lane more than once fail atomically.
- External Nexus config swaps and manual lane lifecycle plans must not claim
  autoscale-managed lanes or retire valid autoscale-managed lanes. The reserved
  `autoscale.managed` metadata key is written only by the consensus autoscaler,
  and valid managed elastic lanes are destroyed only through the internal
  autoscale lifecycle path. Invalid autoscale-owned lanes may be removed by an
  explicit lifecycle retire so operators can repair corrupted ownership state.
  While
  `autoscale.enabled = true`, manual lanes also cannot be added inside the
  configured `autoscale.min_lane_id..autoscale.max_lane_id_exclusive` elastic id range; base,
  governance, zk, or other operator-managed lanes must sit outside that range
  so they cannot consume deterministic scale-out capacity. The routing
  `default_lane` must also remain below `autoscale.min_lane_id`, giving the
  default route a base anchor below the autoscale-owned elastic range. Config
  swaps may preserve an active autoscale-managed lane unchanged, but swaps that
  add, mutate, omit, or replace one fail atomically instead of silently converting
  it into a manual lane change. Preserved autoscale-managed lanes must stay inside
  the configured `autoscale.min_lane_id..autoscale.max_lane_id_exclusive` id range and remain
  bound to `nexus.routing_policy.default_dataspace` so ownership cannot be
  stranded outside the autoscaler's create/retire range or default data space.
  Config swaps also cannot disable `autoscale.enabled` while owned elastic lanes
  exist; valid owned lanes must remain under the autoscaler, and invalid owned
  lanes must be explicitly retired before the owner is disabled. Static TOML
  parsing rejects both the reserved `autoscale.managed` lane metadata key and
  manual lanes in the enabled
  elastic id range before runtime for the same ownership boundary. The internal
  autoscale lifecycle path must create
  deterministic public elastic lanes in the configured default data space
  (`autoscale.managed = true`, `autoscale.created_height` equal to the current
  transition block height, and `elastic-lane-{id}` alias) and cannot add or
  retire unmanaged/manual lanes, malformed autoscale-owned lanes, or managed
  lanes outside the configured elastic id range or default data space. Internal
  transition metadata must also match the plan shape exactly: scale-out stages
  one addition for the logged lane, while scale-in stages one retirement for the
  logged lane. Its `active_lanes` and `autoscale_capacity_lanes` fields must
  also match the current default-route autoscale capacity before the plan is
  staged, and the same pending transition metadata is revalidated at block
  commit before storage geometry is published. Runtime
  lifecycle validation also checks every lane in the resulting catalog, so
  unrelated plans cannot preserve a pre-existing manual lane inside the active
  elastic range or an autoscale-owned lane with malformed metadata, a disabled
  autoscale owner, an out-of-range id, or a non-default data space binding.
  Operators may still repair manual elastic-range corruption by explicitly
  retiring the manual lane. Invalid autoscale-owned lanes can likewise be
  repaired by an explicit lifecycle retire, while valid autoscale-owned lanes
  remain protected from manual retirement and corrupted owned lanes cannot be
  hidden behind an unrelated lifecycle plan.
  Runtime `State::set_nexus` validates lane, data space, routing, autoscale,
  lane-relay emergency, and relay-worker configuration as one atomic Nexus
  policy. Relay worker configs must also use lane-relay-burn fee settlement at
  the state boundary.
  Authority-paid Nexus fees are rejected in this mode until an authenticated
  authority spend-lease protocol exists; sponsor receipts require a verified
  source allocation for the exact program revision and asset. Emergency relay
  multisig thresholds cannot exceed member count. Defaults for each data space name
  one exact `fee_sponsor_program_id` and require data space keys present in the
  active catalog; there is no sponsorship toggle or account
  fallback. Runtime config swaps also enforce the parser's fee-shape contract:
  the fee asset selector must be the exact canonical XOR asset definition id or
  the exact lowercase `xor#universal` alias after genesis binds it to that
  definition. Whitespace-padded and case-folded variants, along with aliases qualified
  by data space, are rejected, while the fee sink literal must be non-empty. Operation allow/deny
  selectors and asset budgets live on immutable on-chain sponsor-program
  revisions rather than in runtime configuration.
- Unresolved routing is deterministic: if a rule resolves to an unknown lane,
  unknown data space, or lane/data space mismatch, admission is rejected with an
  unresolved-route error (no fallback-to-default rewrite for ambiguous inputs).
- Every transaction executes in the global Sumeragi block, so the authority of
  an active route is the global committee that the lag-2 schedule names for the
  authority height (`sumeragi::schedule::scheduled_committee`): a QueuePlan
  admission context binds it for every route leg (at the proposal height), and
  Torii routes and proxies requests by it (`State::resolve_route_authority`, at
  the committed height). An unknown or inactive route has no authority. Lane
  validator pools (manifest bindings or public-lane stake) are not route
  authority; manifest bindings only add Torii URLs to committee members.
  Staking exists only on NPoS chains, and permissioned chains admit and route
  transactions with their genesis roster.
- State-aware Torii, gossip, admission, consensus requeue, and block-requeue
  routing first synchronize the queue router, routing policy, and cached
  catalogs from current Nexus state, then validate computed plans against those
  current lane/data space catalogs. Caller-provided or cached routing plans are
  accepted only when every coordinator and participant leg resolves against
  current catalogs and the full plan exactly matches a freshly recomputed full
  plan for the same transaction, so stale plans cannot survive a policy change
  merely because the old lane still exists. Fresh lanes are usable before an
  external cache refresh, and stale queue-local policies or lanes cannot remain
  authoritative after retirement or policy changes.
  Queue plan-journal replay applies the same committed-state synchronization and
  full-plan comparison, tombstoning stale Native AMX participant legs even when
  the old participant lane still resolves against the active catalog.
  Queue reconfiguration after committed Nexus changes also refreshes cached
  full Native AMX routing plans for pending transactions through both state-
  and view-backed reconfiguration entry points, so participant legs cannot
  remain stale behind an unchanged coordinator route.
  Block requeue carries the full plan owned by the returned queue guard; a
  failed reinsertion leaves no process-global shadow to replay on the next
  recovery pass. Commit event production consumes the block's committed full
  routing plan and derives its coordinator route from that plan.
  Queue-side expiry and unresolved-route rejection events apply the same
  exact-plan cleanup before terminal events are emitted. The queue instance is
  the sole owner of full plans, keyed by canonical entrypoint identity, with
  durable claims serving only as that instance's recovery authority.
  Lane TEU deferral also returns the full routing plan for consensus requeue, so
  deferred Native AMX transactions keep participant legs instead of requeueing
  as coordinator-only work.
  Transaction gossip route hints also resolve against the active data space
  catalog before broadcast or reinsertion, so dangling lane bindings left after
  data space removal are rejected alongside missing lanes and lane/data space
  mismatches. Gossip batch partitioning carries the full routing plan alongside
  the coordinator route and uses actual Norito length as a fallback for
  variable-size plans, so Native AMX participant legs are not requeued
  indefinitely or reduced to coordinator-only metadata. Outgoing gossip batch
  assembly also refreshes cached full routing plans from current Nexus state
  before emitting route hints, so Native AMX participant drift is corrected
  before serialization.
  Torii submit-transaction proxy receivers apply the same full-plan comparison
  to ingress hints, so Native AMX participant drift is rejected even when the
  coordinator route is unchanged. The receiver also validates canonical
  coordinator/participant roles and checks that a Native AMX hint's advertised
  `plan_digest` matches the digest recomputed from its route legs before queue
  admission, preventing forged proxy hints from being silently normalized.
- Proposal assembly refreshes stale routing vectors with the same live Nexus
  snapshot, including the active autoscale elastic range. Proposal sidecars and
  execution-context routes therefore cannot collapse autoscaled default-route
  assignments back to the base lane while the queue and committed state still
  route them to an elastic lane. The refresh compares the full routing plan, so
  Native AMX proposal vectors also replace stale participant legs even when the
  coordinator route is unchanged. Proposal size-cap trimming preserves full
  routing plans for removed transactions too, so overflow requeue keeps Native
  AMX participant metadata. Pending queue reconfiguration uses the same
  height-aware autoscale range, so queued default-route transactions and local
  queue-owned plan hints stay on the active default route until an elastic lane's
  creation height is committed. Proposal lookahead is enabled only when the
  committed Nexus snapshot has more than one policy-reachable active lane at the
  candidate block height. Valid default-route autoscale candidates, canonical
  data space routes, and valid explicit rule lanes count; autoscale-owned default
  anchors, off-default autoscale-owned rule targets, unrouted sidecar lanes in the
  same data space, and future-created autoscale lanes cannot trigger scan-budget
  overfetch before routing policy can select them.
- Block validation and block execution use that same live Nexus autoscale range
  when recomputing execution-context routing and per-lane transaction
  summaries. Validators therefore accept matching elastic execution contexts
  and reject stale base-lane contexts for transactions that the committed Nexus
  state routes to an elastic default lane. If the active elastic range contains
  a manual, malformed managed, or off-default managed lane, validators likewise
  reject stale elastic execution contexts
  because live routing falls back to the base default lane. Native AMX execution
  contexts also compare every committed coordinator and participant leg with the
  recomputed full plan, so a stale participant route cannot survive merely
  because the
  coordinator and plan digest still look current. Per-lane committed TEU
  telemetry is attributed from the same validated block routing vector, not from
  the queue-owned routing plan index, so stale hints cannot move slot
  load metrics onto the wrong lane.
- Global Torii pipeline-status reads treat the owning queue instance's
  routing-plan hints as probes only.
  A hinted route may short-circuit the fanout path only after returning a
  terminal status (`Applied`, `Rejected`, or `Expired`); non-terminal hinted
  successes (`Queued`, `Approved`, or `Committed`) and malformed hinted success
  bodies fall through to full fanout, so stale retired-lane caches cannot hide a
  newer terminal status on the active lane.
- Incoming Torii read and verified-query proxy requests still execute on the
  ingress-selected receiver when the route is active, avoiding multi-hop
  cascades during transient authority-view skew, but receivers first validate
  the hinted lane/data space against their current Nexus catalogs. Missing
  retired lanes and lane/data space mismatches return `route_unavailable` with
  `stale_route` diagnostics before any local read handler executes.
- Stateful transaction validation without a caller-supplied routing context also
  resolves the active Nexus full plan before taking the coordinator lane. Direct
  validation entrypoints therefore cannot fall back to catalog-only base-lane
  routing while autoscale is distributing default-route traffic across elastic
  lanes.
- Startup replay of the pending queue-plan journal uses the same current-state
  synchronization before comparing persisted plans. Journal records whose
  routed lane/data space no longer matches committed Nexus policy are tombstoned
  instead of being replayed under stale queue-local routing. A stale elastic
  default-route plan is tombstoned the same way if active elastic-range
  corruption makes live routing fall back to the base lane after restart.
- Runtime catalog updates apply the same fail-closed rule to already queued
  transactions: autoscale scale-in re-shards pending default-route traffic onto
  the surviving elastic/default candidates, and if any lifecycle change makes a
  pending transaction unrouteable, the queue rejects it and clears stale routing
  caches plus TEU backlog accounting instead of proposing it with retired-lane
  metadata.
- The V1 lifecycle-plan JSON object is closed and always carries both
  `additions` and `retire`, including explicit empty arrays. Omitted, duplicate,
  or unknown fields are invalid; there is no shortened pre-release plan shape.
- Merge-candidate synthesis requires the exact cached envelope to have a
  committed, revalidated FastPQ effect record and also rechecks it against the
  active Nexus lane catalog. Structural gossip metadata alone is progress data,
  never merge authority. Relays for lanes that no longer exist, or for
  lane/data space bindings that no longer match or no longer have a data space
  catalog entry, are ignored even if stale cache state survived outside the
  normal lifecycle pruning path.
  `State::commit_merge_entry` applies the same active-catalog check before it
  trusts a QC-backed merge snapshot, updates merge metadata, or settles Nexus
  fee receipts.
- Merge commits also require every lane snapshot to advance beyond the latest
  committed height remembered for the same `(lane_id, dataspace_id)`, even when
  that lane was omitted from the newest active-only merge entry because it was
  unchanged. A higher-epoch entry cannot replay the same lane height or regress
  to an older cached relay, even when the relay payload and merge QC are
  otherwise valid. Lane retirement, lane/data space rebinding (including
  rebinds that keep the same runtime DA shard id), and fresh lane-id additions
  reset the remembered merge height, verified relay contract-state records, and
  lane-scoped DA receipt cursors plus any DA shard cursor and public-lane
  economic index or operator staking status owned only by that lane. Verified
  relay contract-state pruning is exact-keyed to the canonical
  relay key and matching contract-map key, so spoofed prefixed siblings cannot
  expand reset scope or rehydrate relay evidence. A deliberately destroyed and
  recreated lane is not blocked by the previous
  incarnation's merge height or DA sequence cursors, including after startup
  rehydrates historical merge entries from Kura or persisted DA shard cursor
  journals. A lifecycle plan that retires and adds the same lane id in one
  transaction is treated as the same kind of fresh incarnation, even when the
  replacement keeps the same data space and runtime geometry.

## Settlement & Fees

- Every lane pays XOR fees to the global validator set. Lanes may collect native gas tokens but must escrow XOR equivalents alongside commitments.
- Settlement proofs include amount, conversion metadata, and proof of escrow (e.g., transfer to global fee vault).
- The unified settlement router (NX-3) debits buffers using the same lane prefixes, so settlement telemetry lines up with storage geometry.

## Governance

- Lanes declare their governance module via the catalog. `LaneConfigEntry` carries the original alias and slug to keep telemetry and audit trails readable.
- The Nexus registry distributes signed lane manifests that include the `LaneId`, data space binding, governance handle, settlement handle, and metadata.
- Runtime-upgrade hooks continue to enforce governance policies (`gov_upgrade_id` by default) and log diffs via the telemetry bridge (`nexus.config.diff` events).
- Lane manifests define the data space validator pool for admin-managed lanes
  using explicit `{ validator, peer_id }` bindings; stake-elected lanes derive
  their validator pool from public-lane staking records. In both modes,
  authoritative routing and roster selection use the stored `peer_id` rather
  than deriving peers from validator account signatories. Explicit manifest
  validators and bindings are exposed only when the declared validator list is
  duplicate-free, each binding names a declared validator, and the binding list
  has no duplicate validators or peers before public or routing authority reads
  consume them, so undeclared or duplicate manifest rows cannot multiply
  validator or peer weight. Protected governance admission and transaction
  state validation canonicalize the same duplicate-free validator set before
  authority or quorum checks, so duplicate validator rows fail closed instead
  of being silently collapsed at one boundary. A manifest that declares a
  quorum without an explicit validator set is contradictory and rejects.
  First-release manifest, validator-binding, governance-overlay, and overlay
  module objects are closed: unknown fields reject, as do unknown hook names
  and unknown fields inside the sole supported `runtime_upgrade` hook. A typo
  therefore cannot silently preserve the hook's permissive defaults.
  Governance quorum metadata
  (`gov_manifest_approvers`) is duplicate-free as well; duplicate approver
  claims reject the transaction instead of being collapsed into one approval.
  Manifest loading likewise rejects duplicate protected namespaces and duplicate
  runtime-upgrade allowlist ids after trimming. Duplicate manifest filenames
  that resolve to the same lane alias in one source directory invalidate that
  alias so the governed lane remains locked until the duplicate source is
  removed. The first-release loader scans directory entries incrementally and
  retains sources only for aliases in the active `LaneCatalog` (which is itself
  capped at 1,024 lanes), plus the single cache overlay
  `governance_catalog.json`. Unknown/future files are ignored before metadata,
  content, JSON, or canonicalization work; activating such a lane requires an
  explicit reload against the new active catalog, and an already frozen source
  set never revives it during rebind. Direct regular files are opened with
  no-follow semantics and max-plus-one reads. A lane manifest is limited to
  256 KiB, the overlay to 512 KiB, and all accepted source bytes to 16 MiB per
  materialization. Before typed JSON allocation, each source is limited to
  4,096 string literals, 4 KiB per string, 192 KiB of string bytes, 8,192
  structural/value units, and nesting depth 32; aggregate retained JSON limits
  are 131,072 strings, 8 MiB of string bytes, and 131,072 structural/value
  units. Typed manifests additionally cap validators at 256, protected
  namespaces at 512, hooks at 128, and privacy commitments at 256. The overlay
  caps modules at 256, parameters per module at 128, and total parameters at
  4,096. Canonical digest encodings are capped at 512 KiB per manifest and 1
  MiB for the overlay, and raw bytes are released before canonicalization so
  startup cannot retain raw, parsed, and canonical copies together.
- Public-lane staking mutations bind the transaction authority to the economic
  owner they mutate. Validator registration and exit must be submitted by the
  validator account itself, initial registration stake must come from that same
  validator account, and bond/schedule-unbond/finalize-unbond operations must
  be submitted by the staker account whose balance or pending withdrawal is
  being changed.
- Exact-height NPoS election and validation use each public-lane validator's
  retained half-open tenure `[activation_height, deactivation_height)` as the
  sole authority. `activation_height` is required and is the first eligible
  height; `deactivation_height`, when present, is the first ineligible height.
  A lifecycle label cannot rewrite a committee that was already frozen:
  pending records may enter the exact boundary for which they were scheduled,
  and an `Exiting` or slashed record remains binding through the last height
  before its deactivation boundary. Records whose tenure has ended remain
  available for audit and offence attribution but cannot enter later recovery
  elections or active topology selection. Live topology, stake-snapshot,
  election, due-activation, released-exit sweeping, penalty-locator,
  staking-admission, direct staking mutations, reward bookkeeping, slash
  handling, peer/account cleanup guards, multisig account-rekey rewrites,
  Soracloud runtime-authority, and host-finance stake-accounting derivations
  also ignore or reject public-lane validator rows unless the
  storage key `(lane_id, validator)` exactly matches the embedded
  `PublicLaneValidatorRecord`, so malformed or stale rows cannot auto-promote,
  exit-finalize, mutate bonded stake, receive reward epochs, enter a roster,
  reserve capacity or peer bindings, block account cleanup, get force-exited by
  peer cleanup, get repaired into a live row during account rekey, grant
  runtime authority, or redirect penalties through a mismatched peer binding.
  Torii's public-lane validator app API applies the same exact-key filter before
  serializing staking rows, falling back to manifest validator bindings only
  when no valid staking rows exist for the requested lane. Public-lane
  reward-claim, commit election profile, multisig account-rekey, and Torii
  stake-share/reward app API paths likewise consume or serialize only rows whose
  storage keys exactly match the embedded `(lane_id, validator, staker)` or
  `(lane_id, epoch)` economic record fields.
  A lane reset, rebind, or autoscale scale-in must not manufacture an early
  terminal state. It waits until every reset-owned validator tenure has reached
  its exact deactivation height and stake-share and pending-unbond custody is
  drained. Only then
  may reset cleanup remove the terminal records and economic indexes, treating
  either the storage key lane or embedded record lane as reset ownership. This
  prevents a recreated lane id from inheriting an old tenure without erasing a
  committee or slash liability that is still live. World-backed NPoS quorum, coverage, and
  commit-root stake selection paths use the same active-lane filter whenever
  Nexus is enabled. Public-lane stake-share rows, reward records, and
  reward-claim cursors are not audit records; after the tenure, custody, and
  evidence gates succeed, lane reset paths delete reset-owned rows (by storage
  key or embedded lane where present) and clear operator staking status for
  reset lanes while preserving unchanged-lane economic state and status.
  Lane-relay emergency overrides are pruned for
  reset lanes and for lanes absent from the updated catalog; an override
  pre-staged for a newly created lane id is treated as stale prior-incarnation
  state and must be reinstalled after the lifecycle update. Failed
  lane-retirement preflight
  keeps those live rows, emergency overrides, AXT replay entries, verified
  relay state, and validator activity in the committed WSV until the storage
  transition can complete.

## Telemetry & Status

- `/v1/nexus/lifecycle` exposes the lifecycle/catalog snapshot used to verify
  lane aliases, data space bindings, incarnations, activation/close heights, and
  autoscale transitions.
- `/v1/sumeragi/status` exposes only the authoritative global `SumeragiStatus`
  instance state; it does not carry lane evidence (`/v1/sumeragi/lanes` lists
  the node's lane instances).
- `/v1/sumeragi/diagnostics` exposes non-authoritative operational evidence
  including lane commitments/sessions. Its bounded Native
  participant-application records and bounded restart-stable autonomous
  execution stages are derived from durable State/Kura evidence (plus durable
  queue ownership for finalization). A Native same-height identity disagreement
  is `conflict`, never a silently selected winner.
- Scheduler metrics (`nexus_scheduler_lane_teu_*`) render lane aliases/slugs so operators can map backlog and TEU pressure quickly.
- `nexus_lane_configured_total` counts the number of derived lane entries and is recomputed when configuration changes. Telemetry emits signed diffs whenever lane geometry changes.
- Data space backlog gauges include the alias/description metadata to help operators associate queue pressure with business domains.

## Configuration & Norito Types

- `LaneCatalog`, `LaneConfig`, and `DataSpaceCatalog` live in `iroha_data_model::nexus` and provide Norito-format structures for manifests and SDKs.
- `LaneConfig` lives in `iroha_config::parameters::actual::Nexus` and is derived automatically from the catalog; it does not require Norito encoding because it is an internal runtime helper.
- The user-facing configuration (`iroha_config::parameters::user::Nexus`) continues to accept declarative lane and data space descriptors; parsing now derives the geometry and rejects invalid aliases or duplicate lane ids.
- `DataSpaceMetadata.fault_tolerance` controls every lane-consensus committee,
  not only relay fanout. The only valid first-release geometry is an exact
  `3f+1` committee with `f >= 1`. Authority resolution takes the exact
  `(lane_id, dataspace_id, height)` route, rejects inactive/rebound routes and
  pools smaller than `3f+1`, and samples exactly `3f+1` distinct peers from the
  canonical manifest or stake pool. Membership uses the consensus epoch seed
  bound with `(dataspace_id, lane_id)` and the resulting validator set is put in
  canonical peer order. An oversized pool never becomes an oversized voting
  committee. Autoscale incarnations instead use their immutable creation pin,
  which must itself contain exactly the data space's `3f+1` validators. New pins
  are selected from the same canonical manifest/stake authority inputs; commit
  topology is transport state and is never an authority fallback.

## Outstanding Work

- Integrate settlement router updates (NX-3) with the new geometry so XOR buffer debits and receipts are tagged by lane slug.
- Close the still-open multilane release-evidence gates: fresh unskipped
  four-peer suites; 10/10 fresh 13-peer global corridor seeds (twelve lane
  validators); the two-hour fault
  soak; five pinned-hardware one-versus-four-lane pairs meeting the throughput,
  latency, and resource bounds; SDK/formal evidence; and the prescribed
  locked/offline full-workspace build, test, strict Clippy, formatting, and
  legacy-codec checks. This document does not claim those runs have passed.
- Add compliance hooks for whitelists/blacklists and programmable-money policies (tracked under NX-12).

---

*This document will evolve as NX-2 through NX-18 tasks progress. Please capture open questions in the roadmap or governance tracker.*
