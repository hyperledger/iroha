# Iroha 3 Transaction Processing Pipeline

This document describes the end‑to‑end path a transaction follows through an Iroha node and the network, from submission at the API boundary to final commitment and post‑commit effects. It focuses on architectural steps, components involved, and how different transaction types flow through the system. Names in backticks refer to crates or major modules in this repository.

## Components & Responsibilities

- `iroha_torii` (Torii API): HTTP/WebSocket interface for clients to submit transactions, run queries, and subscribe to events and telemetry. WebSocket block/event streams send Norito-framed binary messages (header + checksum).
- `iroha_core` (Core): Orchestrates consensus, validation, execution, and state transitions.
  - `sumeragi`: Consensus and leader/proposer selection, block propagation, commit protocol.
  - `state` (World/State, StateBlock): Authoritative state and transactional view used for validation and application.
  - `kura`: Append‑only block store, on‑disk persistence, and block retrieval.
  - `smartcontracts::ivm`: Iroha Virtual Machine (IVM) integration and executor management.
  - `query::store::LiveQueryStore`: Live query/event distribution to connected clients.
- `iroha_data_model`: Instruction and query types, Norito serialization, permission tokens, triggers, and schema definitions.
- `ivm` (Iroha Virtual Machine): Deterministic execution of the on‑chain executor and smart‑contract bytecode (`.to`), including Kotodama‑compiled programs. SIMD/CUDA/NEON paths are feature‑gated and must not affect determinism.
- `norito`: Compact, deterministic codec for wire formats (tx, blocks, queries, etc.).
- `iroha_p2p`: Peer‑to‑peer networking, gossip, and topology management.

**Runtime target:** Iroha Core, Torii, and companion crates are built for the Rust standard library (`std`) only. WASM or other no-std variants are not supported, so plan integrations and tooling accordingly.

## Transaction Types

All transactions are signed requests to mutate state, carrying a list of instructions. Key categories:

- External user transactions: Signed by an account authority; contain one or more ISI (Iroha Special Instructions).
- Trigger‑driven transactions: Emitted by time‑based or data‑driven triggers executed by the on‑chain executor.
- Administrative transactions: E.g., parameter changes (`SetParameter`), role/permission assignments, etc.
- Executor upgrade transactions: Install a new on‑chain executor (IVM bytecode). Takes effect deterministically at the point defined by the upgrade semantics.
- Genesis (bootstrap): Special, out‑of‑band block 0 establishing initial state (not gossiped).

All of the above share the same validation and consensus pipeline once they become proposed content of a block.

## High‑Level Lifecycle (Single Node)

1) Admission (Torii)
- Client submits a signed transaction to `iroha_torii`.
- Torii performs basic checks: format/encoding (Norito decode), presence of
  signatures, canonical chain ID, mandatory positive TTL, and request size
  limits. Safe builders assign a 100-second TTL when callers omit a choice.
- If admission checks pass, the tx is forwarded to Core and enqueued in the local mempool (pending set). Torii returns an acknowledgement (not a finality signal).

2) Gossip (P2P)
- The receiving peer gossips the admitted tx to its neighbors using `iroha_p2p` according to the current `Topology`.
- Peers deduplicate by hash and run the same admission checks, adding the tx to their own pending sets.

3) Leader/Proposer Selection (Sumeragi)
- `sumeragi` determines the current round’s leader (proposer) and the validation/committee peers according to the topology and view/height.
- Roles rotate per round to ensure fairness and resilience.

4) Proposal Assembly (Leader)
- The leader pulls transactions from its pending set (mempool), typically ordered by policy (e.g., FIFO, size/complexity limits, TTL priority).
- For each candidate tx, the leader runs stateless validation (see below). Stateless‑invalid txs are dropped or quarantined.
- The leader tentatively runs stateful validation in a `StateBlock` (a transient view on top of the current committed state). This simulates applying the tx’s instructions using the on‑chain executor.
- If the tx passes both stateless and stateful checks, it is added to the proposal. The leader stops when block limits are met (size, instruction count, configured gas/time budget if applicable).

5) Trigger Evaluation (Leader)
- Time‑based triggers due in this round are materialized into additional internal transactions according to their schedules.
- Data‑driven triggers may be evaluated as a consequence of simulated tx effects; depending on configuration they are either collected for the current proposal or scheduled for the next height to ensure determinism and bounded execution.
- All trigger‑originated txs go through the same (stateless + stateful) checks inside the leader’s `StateBlock` view.

6) Block Construction (Leader)
- The leader seals the proposal into a block candidate with header fields: height, previous hash, merkle roots, timestamp, etc.
- The leader signs the block and broadcasts the proposal to validation peers.

7) Validation & Voting (Committee Peers)
- Each validator receives the proposal, verifies the leader’s signature and header linkage, and re‑executes validation deterministically:
  - Stateless validation for each tx (format, signatures, TTL/chain, size, instruction decode against the instruction registry).
  - Stateful validation in a local `StateBlock` view using the same executor version active for that height.
- On success, the validator signs the block (or the header) and sends an approval to the leader and/or other committee members depending on the consensus message pattern.

8) Commit (Quorum Reached)
  - Once the leader (or the network) observes a quorum of approvals, `sumeragi` finalizes the block after verifying the required conditions:
  - CommitQC: every validator sends its equal-weight `CommitVote` to
    the complete frozen committee. Any validator may aggregate exactly
    `q = 2f + 1` distinct equal-weight votes into a `CommitQC`; stake
    affects NPoS seat eligibility, not vote weight. A peer applies only when it
    holds both that exact certificate and the locally authenticated canonical
    body.
  - Data availability: revision 4 always uses the signed RS16
    `PayloadManifest`/`PayloadChunk` layout. A validator may Prepare-vote only
    after reconstructing, authenticating, durably storing, and deterministically
    validating the complete canonical body. There is no local DA-enable switch
    or separate RBC READY gate.
  - Payload recovery: the leader sends chunks to Set A first and expands to Set
    B on recovery. A peer finalizes only when it holds both the exact CommitQC
    and its locally authenticated canonical body.
  - State roots: commit QCs always bind `parent_state_root` and `post_state_root` derived from execution witness snapshots; there is no separate execution QC gate.
- After the required checks succeed, all committee peers persist the block to `kura` (append‑only block store) and advance their canonical state by applying the block contents in a single atomic commit.
- Non‑committee peers learn of the commit via gossip and catch up by fetching and applying the committed block(s).

9) Post‑Commit Effects
- Emit events to `LiveQueryStore` for subscriptions (transaction outcomes, block committed, domain/account changes, etc.).
- Update telemetry metrics, logs, and any plug‑in indexers.
- Clear included transactions from mempool; decrement TTL on remaining transactions and purge expired ones.
- If the block contains an executor upgrade, the new IVM bytecode becomes active at the defined point (typically next block), and the node updates the executor cache (`IvmCache`).
- Executor migration is guest-defined: every production upgrade runs the admitted
  IVM program and accepts only its canonical Norito migration result. Header
  fields, vector length, bytecode size, and other artifact shape do not select
  host-side migration or permission behavior. The host applies the declared
  executor data model exactly; it has no legacy permission-name purge or
  pre-release grant migration step. Synthetic executor emulation is
  available only in builds that explicitly enable the non-default
  `iroha-core-tests` feature.

## Validation Details

Stateless validation (performed by any peer before including or voting on a tx):
- Norito decode and schema checks of transaction, instructions, and metadata.
- Signatures present and valid for the authority.
- Chain ID matches exactly. TTL must be present in the signature-bound payload,
  must not be expired, and must not exceed the current governed
  `transaction.max_time_to_live_ms` value (one day by default). Counts and
  lengths must not overflow.
- Instruction existence in the instruction registry and parameter wire IDs are valid.

Stateful validation (performed in a transient `StateBlock` view):
- Permission checks for each instruction against the authority’s roles and permission tokens.
- Existence checks (accounts, domains, assets, definitions) and invariants (e.g., non‑negative balances, mint/burn limits, non‑duplicate IDs, etc.).
- Execution of instruction semantics via the on‑chain executor on IVM. The executor reads the current world state and produces deterministic effects or failures.
- If any instruction fails, the tx is rejected for this block; it may remain in mempool (subject to policy/TTL) for re‑try when preconditions change.

Determinism:
- IVM execution must be bit‑exact across hardware. SIMD/NEON/CUDA optimizations are behind feature flags and never alter observable outputs. Reductions and hashing are deterministic by design.

## Consensus (Sumeragi) View

- Round lifecycle: propose → validate → vote → commit.
- Leader responsibilities: gather txs, validate (stateless+stateful), include triggers, build and sign the block, collect approvals.
- Validator responsibilities: verify proposal integrity, independently re‑validate, vote.
- Commit rule: once a valid `CommitCertificate` and its exact locally
  authenticated canonical body are available, the block is finalized. The
  signed manifest/chunk layout is part of body authentication, not a second
  post-QC availability certificate.
- Lifecycle ownership: one crate-internal `LifecycleCoordinator` and durable
  `LifecycleLedgerV1` own admission, selection, launch, retry, completion,
  finalization, restart, and rollover. Retired Serve/witness/latch scheduling
  state is not a second authority.
- Fault handling: if the leader is faulty or slow, the round times out and leadership rotates; pending txs remain available for the next leader.

## Executor & IVM

- The on‑chain executor is IVM bytecode (`.to`) that defines how instructions mutate the world state.
- The executor version is part of the node parameters. An `Upgrade` instruction can install a new executor in a block; all peers apply the same rules for activation (e.g., next height) to remain in lock‑step.
- `IvmCache` caches decoded/validated bytecode for performance; cache keys include code hash and feature set, but cache contents never change outcomes.
- Kotodama programs compile to IVM bytecode and may be invoked by instructions or triggers. They run within the same determinism envelope.

## Triggers

- Time‑based triggers: carry a schedule (start, period). The scheduler materializes due triggers into internal transactions during proposal assembly.
- Data‑driven triggers: subscribed to events; when matching events occur (e.g., asset transfer), a trigger may produce follow‑up transactions. Depending on configuration, these may be included in the same block (if safe/bounded) or deferred to the next height.
- Trigger‑produced transactions undergo the same validation and consensus steps as user transactions.

## Storage & State

- `kura` persists committed blocks. Each block contains all transactions, signatures, and metadata required to reconstruct state.
- `state` maintains the in‑memory canonical view and provides `StateBlock` overlays for simulation/validation. Commit applies the overlay atomically.
- Kura retains canonical `SignedBlockWire` bodies with their native certified execution evidence. Startup verifies the original signed genesis and the complete certified replay range before applying state. The stable commit marker defines published history; missing or corrupt committed bytes stop startup without shortening that history. An interrupted compaction or rewrite is recovered only through its exact retained stage record.
- Signed snapshots are local exports. A signature authenticates the writer and bytes, while the native execution commitment authenticates witnessed writes rather than the complete `World`. Positive-height snapshots therefore require replay of the original signed genesis and native certified blocks. The supervised writer publishes only after native recovery reaches Ready. See [startup trust roots](startup_trust_roots.md) and [the native consensus contract](sumeragi.md).
- Indexes for queries (e.g., assets by account) are updated during application to serve consistent results.

## Error Paths & Retries

- Stateless‑invalid at admission: rejected immediately; client receives an error.
- Stateless‑invalid at proposal time: skipped by the leader; may be dropped or quarantined.
- Stateful‑invalid at proposal/validation time: not included; may stay in mempool for later rounds until TTL expires.
- Conflicts at commit: prevented by deterministic re‑validation on all voters against the same pre‑state; non‑deterministic proposals are rejected.

## End‑to‑End Summary (By Transaction Type)

- User transaction (regular ISI)
  1. Submit at Torii → gossip → leader selects → stateless check → stateful simulate → include in proposal → validators re‑validate → commit → events/telemetry → mempool cleanup.

- Trigger‑driven transaction
  1. Due trigger materialized during proposal assembly or after observed events → same stateless/stateful checks → included with user txs → commit.

- Administrative/parameter transaction
  1. Same as user txs; effects update parameters (e.g., limits, features). Some parameter changes (like executor upgrade activation height) take effect at defined boundaries to preserve determinism.

- Executor upgrade transaction
  1. Proposed and validated like any tx; on commit, new executor code recorded in state/parameters.
  2. Activation: new executor becomes effective at the agreed point (e.g., next height) for all peers; `IvmCache` updated.

## Notes for Operators/Integrators

- Torii acknowledgements do not imply finality. Use event subscriptions or query committed blocks/transactions to observe finalization.
- Large or complex transactions may be deferred across rounds based on block limits; keep instruction batches within reasonable size.
- Ensure all nodes run identical feature sets that affect execution paths (SIMD/CUDA flags) or keep hardware‑specific features disabled to avoid divergence.
- Recovery sidecars and warning events are best‑effort diagnostics. They are non‑forking and do not change scheduling or consensus outcomes. Treat them as observability signals and investigate mismatches for potential operator drift or tooling discrepancies.

## Recovery & Warning Events

- Core persists pipeline recovery sidecars under the Kura store directory (`pipeline/sidecars.norito` with `pipeline/sidecars.index`). Each entry captures:
  - The index is solely the first-release V1 layout: every present index, including one based at height 1, begins with the 32-byte `(MAX, MAX), (base_height, base_height ^ mask)` header. Absence is represented only by both files being absent; headerless or partial pre-release indexes fail closed and are not promoted or rewritten.
  - The admission sets (canonical read/write keys) per transaction in the block
  - A stable DAG fingerprint (SHA‑256) computed over interned key IDs, per‑tx access vectors, and call hashes
  - A block hash anchor (`pipeline.recovery.v1`) so fingerprints are only compared when the sidecar matches the exact block
  - Sidecar payloads are flushed before index updates and the directory is synced so offsets are crash‑consistent (orphaned payload bytes are ignored)
- During validation, if a sidecar for the same block hash is present and the recomputed fingerprint differs, Core:
  - Logs a warning (persisted vs recomputed)
  - Emits a pipeline warning event for subscribers: `PipelineEventBox::Warning { header, kind: "dag_fingerprint_mismatch", details }`
  - Continues with the recomputed schedule — this does not affect consensus or block outcomes.

Operator access (Torii)
- Read a recovery sidecar via: `GET /v1/pipeline/recovery/:height`
  - Requires a fresh, replay-resistant `OperatorSignature` over the exact
    genesis `NetworkId`, `GET`, substituted path, query, and empty body; token
    authentication is not a fallback
  - 200 application/json with the persisted sidecar, or 404 if not found
  - Helpful for tooling and dashboards to inspect access sets and DAG fingerprints
- Read full FASTPQ recovery artifacts via:
  `GET /v1/pipeline/recovery/:height/fastpq-proofs?offset=0&limit=16`.
  This is an operator-only route that requires Iroha's canonical,
  replay-resistant operator request signature. Pages are explicitly bounded
  (maximum 64 proofs), run under the heavy-query concurrency budget, and fail
  closed when proof, reconstructed-batch, aggregate-artifact, or
  encoded-response byte limits would be exceeded.

## Transaction & Witness Events

- Transaction pipeline events now retain the Nexus routing metadata. Each
  `PipelineEventBox::Transaction` carries the assigned `lane_id` (`LaneId`) and
  `dataspace_id` (`DataSpaceId`) alongside the existing `hash`, optional
  `block_height`, and `status`. Torii’s SSE/WS adapters surface the new fields
  single-lane traffic and Nexus multi-lane routing without extra lookups.
- The event filter DSL gained matching helpers for the new metadata:
  `TransactionEventFilter::for_lane_id` and `TransactionEventFilter::for_dataspace_id`.
  In Norito/JSON filters you can reference them via `tx_lane_id == <u32>` and
  `tx_dataspace_id == <u64>` expressions. Combined with the existing status and
  block-height predicates this allows precise subscription of per-lane or
  per-dataspace feeds.
- For API clients still consuming raw Norito payloads the schema in
  `iroha_data_model` reflects the additional fields; older decoders should be
  updated to avoid silently dropping the new metadata.

- After validating a proposal and capturing the execution witness (the source of
  `parent_state_root`/`post_state_root` bound into commit QCs), Sumeragi emits a
  `PipelineEventBox::Witness` containing block metadata (`block_hash`, `height`,
  `view`, `epoch`) and the execution witness (`reads`/`writes`). The ordinary
  pipeline event stream, Kura sidecar persistence, and background prover lane
  expose or consume that witness; it is not routed through a consensus collector
  set.
- Torii’s streaming/JSON adapters summarise the payload with read/write counts; clients that need the full witness should subscribe to the Norito-encoded stream and decode the `ExecWitnessMsg`.
- `ExecWitness` now also carries the per-transaction `fastpq_transcripts` bundles (entry hash plus transcripts) **and** a `fastpq_batches: Vec<FastpqTransitionBatch>` field. Each batch embeds `public_inputs` (dsid, slot, old/new roots, perm_root, tx_set_hash), making witness batches the canonical prover inputs instead of ad-hoc transcript re-encoding.
- Operators can fetch those batches via `iroha_cli audit witness --decode` (FASTPQ batches now emit by default; use `--no-fastpq-batches` to suppress them); `--fastpq-parameter` now asserts the expected parameter set and the CLI no longer synthesizes batches from transcripts.
- Every validator now runs the FASTPQ prover lane (`iroha_core::fastpq::lane`). The lane consumes each emitted witness’s `fastpq_batches` and invokes `fastpq_prover::Prover::canonical` in the background respecting `zk.fastpq.execution_mode` / `--fastpq-execution-mode`. Successes and failures are logged per entry hash without blocking consensus.
- New filters (`PipelineEventFilterBox::Witness`) support `WitnessEventFilter::for_block_hash`, `for_height`, and `for_view` predicates so dashboards can focus on specific blocks or views without post-filtering.
- The event stream complements the existing witness persistence path (`PipelineEvent::Merge` + Kura sidecars) and provides near-real-time observability for auditing SBV-AM recomputation.

## Lane-aware Telemetry Snapshots

- `/status` now exposes the latest per-lane scheduling summary through the
  `nexus_scheduler_lane_teu_status` payload. In addition to TEU capacity and
  deferral counters it reports the number of transactions (`tx_vertices`),
  intra-lane conflict edges (`tx_edges`), and overlay statistics (count,
  instruction total, byte total) for the most recently validated block.
- Detached apply status now separates prepared, merged, and sequential fallback
  counts. Fallbacks also carry reason counters for fee postprocessing,
  user-provided executors, durable contract state, unsupported detached
  instructions, rejected detached evaluation, and overlay build errors. The
  same aggregate reasons are exported through
  `pipeline_detached_fallback_reason{reason=...}` telemetry.
- Fee-bearing transactions add an implicit global fee write to their scheduling
  access set, so fee debits, gas settlement, and Nexus receipts cannot reorder
  around each other silently. The detached merge path now replays fee/gas/Nexus
  postprocessing for simple transparent single-transfer deltas in the same
  `StateTransaction`; unsupported fee-bearing detached effects continue to
  report the `fee_postprocessing` fallback reason.
- A block with active data triggers or any trigger-lifecycle mutation uses a
  candidate-wide serialization fence and reports detached fallback as
  `durable_state`. Accountable prepared-overlay gas reaches the parent block
  exactly once on commit or rollback, independently of
  `pipeline.parallel_apply`. The authored/base amount is precharged before a
  prepared effect can reach State, nested trigger/host work is retained rather
  than replaced during settlement, and no later transaction executes once the
  configured parent-block cap has been consumed. A mixed live batch that trips
  only the overlay-size/instruction bound remains fee-exempt but still adds its
  already-attempted gas to that same block budget.
- IVM dynamic access scheduling uses the overlay prepass output when available:
  the VM run that builds the overlay can also capture the host state access log,
  avoiding a separate dynamic access VM run before DAG construction.
- Each lane snapshot carries `dataspace_id`/`dataspace_alias` and the lane’s
  `storage_profile` (`full_replica`, `commitment_only`, `split_replica`) so dashboards
  can correlate scheduler data with storage/backlog metrics.
- The sister collection `nexus_scheduler_dataspace_teu_status` gains a
  `tx_served` field indicating how many transactions targeting each dataspace
  made it into the block, plus `fault_tolerance` (f) from the dataspace catalog
  to surface lane-relay committee sizing (`3f+1`) in the status payload.
  gauges when building Nexus dashboards.
- The same `/status` payload now includes `rbc_lane_backlog` and
  `rbc_dataspace_backlog` arrays that aggregate the RBC chunk backlog by lane
  and dataspace. Each entry reports the contributing transaction count, total
  and pending chunk estimates, and cumulative payload bytes so operators can
  pinpoint which lanes are throttled by data-availability retries.
  operators should transition dashboards to the per-lane snapshots to capture
  multi-lane behaviour once Nexus routing is enabled.

---

For deeper details, consult the code in:
- `crates/iroha_core` (consensus, state, execution)
- `crates/ivm` (virtual machine and executor runtime)
- `crates/iroha_torii` (API surface)
- `crates/iroha_data_model` (instructions, queries, triggers, serialization)

## Signature Batching (Deterministic)

Iroha can group signatures by scheme during block validation and verify them in deterministic “micro‑batches” with bisection to pinpoint bad signatures. This reduces repeated work per block while remaining deterministic across peers.

- Configuration (pipeline section; prefer `iroha_config` over envs in production):
  - `signature_batch_max_ed25519` (usize, default 64)
  - `signature_batch_max_secp256k1` (usize, default 16)
  - `signature_batch_max_pqc` (usize, default 8; ML‑DSA/Dilithium3)
  - `signature_batch_max_bls` (usize, default 16)
  - Each scheme uses only its own cap; there is no aggregate or cross-scheme fallback.

- BLS support is behind a compile‑time feature in Core:
  - Enable with: `cargo build -p iroha_core --features bls`
  - This forwards to `iroha_crypto/bls` and compiles the BLS path in `block.rs`.
  - Micro‑batching groups signatures deterministically: same‑message groups run fast‑aggregate verification, distinct messages use a multi‑message aggregate with deterministic bisection on failure. Telemetry records latest-block aggregate counters (`pipeline_sig_bls_agg_*`) and lane-labelled cumulative results (`pipeline_sig_bls_agg_{same,multi}_total`); cumulative lookups require the exact lane ID.
  - PoP requirement: batching expects a proof of possession in transaction metadata (`bls_pop` for BLS-normal, `bls_pop_small` for BLS-small). Missing or invalid PoPs fall back to individual verification while still enforcing the signature.
- Validators register with BLS-Normal keys only; `trusted_peers_bls` no longer exists. `trusted_peers_pop` and genesis topology `pop_hex` entries mark trusted BLS peers that participate in consensus. Trusted BLS peers without PoPs remain network-trusted observers and are excluded from consensus, while non-BLS peers are always dropped from validator rosters. Config parsing rejects invalid PoP entries and PoPs for keys outside `trusted_peers`.
  - Validator peers MUST set `signature_batch_max_bls > 0`; peer registration is rejected otherwise to ensure validators can batch BLS signatures (votes/commit certificates) by configuration.
- Ordinary signatures and every account controller use the canonical `CryptoAdmissionPolicyV1` from the original committed parameter view. Changes made while executing block N take effect for admission in block N+1. Curves are derived from that one algorithm list; a node-local list cannot change acceptance. Consensus votes use the validator BLS key and authenticated committee PoP independently, and BLS account controllers still require membership in the ordinary policy. See [ordinary crypto admission](crypto_admission_policy.md) for genesis initialization and policy ownership.

- Scheme specifics:
  - Ed25519 and ML‑DSA: use deterministic batch verification (not cryptographic aggregation). Security and outputs remain identical to per‑signature checks.
  - BLS: same‑message aggregates plus multi‑message aggregates over distinct payloads; deterministic per‑signature bisection remains the fallback when an aggregate fails.

- Determinism:
  - Batches derive a per‑batch seed from a stable tuple ordering of `(pk, msg, sig)` and use fixed hashing (`SHA‑256`).
  - On batch failure, a binary bisection over the same deterministic ordering identifies an offending transaction.

- Notes:
  - Setting any cap to `0` disables batching for that scheme.
  - These pre‑verifications do not skip per‑transaction validation yet; they are wired for early rejection and future fast paths.
### Torii Endpoints (Operator Aids)

- Committed evidence audit:
  - `GET /v1/sumeragi/evidence/count` — `{ "count": <u64> }` for the bounded evidence table retained in WSV.
  - `GET /v1/sumeragi/evidence` — `{ "total": <u64>, "items": [...] }` with the attributed context, offenders and native frame hash of committed `NativeSumeragiEvidence`.
  - Both routes are read-only projections of persisted consensus state. Node-local proofs awaiting block admission are deliberately excluded.
- Python SDK shortcuts: `iroha_python.ToriiClient.get_pipeline_recovery(height)` fetches the JSON sidecar, and `stream_pipeline_transactions`/`stream_pipeline_blocks`/`stream_pipeline_witnesses`/`stream_pipeline_merges` expose the SSE feeds with Norito-backed filters.
  - Purpose: quick inspection during development and operations.
