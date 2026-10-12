# Optimized Transaction Pipeline with IVM‑First Execution, AOT_SIMD Acceleration, and Parallelism

This document proposes a revised, high‑throughput transaction pipeline that
makes IVM the primary execution path, integrates built‑in ISIs cleanly, and
parallelizes validation and execution across all CPU cores while preserving
full determinism across heterogeneous hardware. It incorporates ideas from the
“Optimized Transaction Pipeline with IVM‑First Execution, AOT_SIMD Acceleration,
and Parallelism” design and harmonizes them with IVM, Kotodama, ISI, WSV,
Norito, and Sumeragi consensus semantics.

The design leverages IVM’s register‑based bytecode and introduces a
conflict‑aware scheduler driven by per‑transaction access sets. It is suitable
for both leaders (proposal assembly) and validators (re‑validation) and keeps
observable behavior identical on all honest nodes.

This pipeline underpins Iroha 3 deployments with either one or many configured
lanes. Both shapes use the same mandatory Nexus runtime and require no distinct
contract artifacts or execution environments.

---

## Goals and Non‑Goals

Goals
- Put IVM on the mainline execution path for most transactions (smart
  contracts and instruction semantics), while supporting non‑IVM built‑ins.
- Exploit all available cores via conflict‑aware parallelism at the
  transaction level, with optional intra‑tx acceleration (SIMD) for hot paths.
- Maintain determinism and safety: identical outputs across nodes; no
  race‑dependent outcomes; predictable memory usage and latency bounds.
- Reduce block latency and increase throughput with ahead‑of‑time decoding,
  caching, and stable scheduling.

Non‑Goals
- Introducing a JIT compiler. Execution remains interpreter/dispatch‑based
  with optional vectorized primitives under feature flags.
- Changing consensus semantics. The pipeline plugs into the existing Sumeragi
  propose/validate/commit stages.

---

## Architecture Overview

Key additions
- Static Analysis & Access Sets: derive read/write key sets for every
  transaction (and sub‑units when available) to drive safe concurrency.
- Deterministic Parallel Scheduler: builds a conflict DAG from access sets and
  executes ready tasks across worker threads using a stable policy.
- IVM‑First Executor: unify built‑in ISIs and IVM calls behind a common
  ExecutionPlan. IVM bytecode is pre‑decoded and cached (IvmCache) with stable
  feature‑gated acceleration.
- Two‑phase Validation per tx: stateless fast‑path (parallel) then stateful
  simulation in a `StateBlock` overlay managed by the scheduler.
- WSV Overlays: stateful execution uses write‑isolated overlays on a WSV
  snapshot, merged deterministically to maintain global state consistency.

Harmonization constraints
- Kotodama targets IVM bytecode (`.to`); it does not target RISC‑V as a
  standalone architecture. Any RISC‑V‑like encodings are internal to IVM and
  must not change observable behavior.
- Built‑in ISIs and IVM programs execute through the same executor boundary,
  with identical permission checks, metering, and event semantics.
- Acceleration (AOT_SIMD, CUDA/Metal) is feature‑gated and produces bit‑exact
  results with a canonical fallback path to preserve cross‑hardware determinism.
   for all public data structures and transactions.

Implementation status (current node)
- Access‑set derivation: static for built‑ins; IVM dynamic prepass honored when enabled; manifests can carry advisory hints.
- Deterministic scheduler: per‑wave stable order with conflict‑free layers; parallel apply path guarded by `pipeline.parallel_apply` (feature complete, parity‑tested).
- Recovery sidecars: Core persists admission sets and a stable DAG fingerprint per block; startup scan recomputes and logs mismatches.
- Warning events: a `PipelineEvent::Warning` is emitted on DAG fingerprint mismatches (non‑forking); Torii streams warning events and exposes a recovery sidecar endpoint.
- Overlay bounds/chunking: enforced via `overlay_max_*` and `overlay_chunk_instructions` of the committed `pipeline_validity_policy_v1` parameter (not node configuration); negative tests cover bounds.

Data flow (leader and validator nodes)
1) Admission → 2) Gossip → 3) Pre‑decode + Stateless validation → 4) Route:
   - Regular txs → mempool (pending set) until next proposal
   - Multisig txs → multisig pool (MST) until threshold or expiry
   - Invalid/expired → drop with diagnostics
   5) Static analysis (derive access sets for ready txs) → 6) Build conflict
   DAG → 7) Parallel stateful execution in `StateBlock` overlays on a WSV
   snapshot → 8) Deterministic merge/commit order → 9) Seal/sign/broadcast or
   vote → 10) Persist + post‑commit events.

Auxiliary service lanes (out‑of‑pipeline)
- Proof creation lane: long‑running, resource‑bounded workers produce ZK or
  other cryptographic proofs referencing committed state; results are submitted
  as regular txs for later verification/inclusion.
- Query processing lane: read‑only queries execute on WSV snapshots with
  pagination/streaming and strict time/compute limits; never blocks the block
  pipeline.

On‑node proof creation (bridges and advanced flows)
- Optional on‑node proving is supported under feature flags; it runs in a
  dedicated background lane entirely outside the consensus‑critical pipeline.
- Jobs consume only committed WSV snapshots (pin height and state root in the
  public inputs); they never depend on speculative overlays.
- Outputs are submitted as normal transactions carrying the proof and metadata
  (or as referenced artifacts by hash) and then follow the standard verify →
  schedule → include path.

Verification status
- Stateless ZK pre‑verification and non‑forking diagnostic consistency checks of traces are implemented and gated by config/feature flags. Background proving and attachments remain out‑of‑pipeline and are optional.

Acceptance (ZK verification)
- Native PIPA-R and STARK admission use their exact compiled relations and the `pipa_r` / `stark` bounds of the committed `zk_validity_policy_v1` parameter. `zk-preverify` controls advisory pre-verification; node-local `zk.trace` controls diagnostic scheduling. Diagnostics never grant ledger authority.
- Authority boundary: pre‑verification and deduplication are advisory diagnostics only. Their results cannot be installed into execution state or substitute for the normal guarded cryptographic verifier.
- Determinism: ordering and proposal selection remain unaffected; pre‑verification failures do not reorder transactions. Diagnostic trace checks report via Pipeline warnings and do not persist artifacts in block sidecars.
- Safety: proofs and envelopes are bounded (size, k) and verified deterministically; accelerators must produce bit‑exact results to scalar.

Consensus integration
- The leader forms proposals from its mempool; validators replay the analysis,
  scheduling, and stateful checks deterministically. The pipeline plugs into
  Sumeragi propose/validate/commit without changing consensus rules.

## Network Time Service (NTS)

Purpose
- Provide a robust, byzantine‑resilient estimate of “network time” used for
  trigger scheduling by watcher nodes and for Sumeragi timers.
- Do not change the OS clock; maintain a local `network_offset` that maps the
  monotonic clock to network time. Inspired by NEM’s Chapter 8 time sync,
  improved with trimmed‑median aggregation, RTT filtering, and smoothing.

Design
- Local basis: use a monotonic clock (`t_mono`) to avoid leap seconds and OS
  adjustments. Define `t_net = t_mono + network_offset`.
- Peer sampling: every few seconds (default 5s) select a rotating bounded batch
  of accepted, key-ACL-filtered configured logical peers (default cap 8) and
  send a ping `(id, t1)`. Peers reply with `(id, t2_recv, t3_send)`. Effective
  membership changes invalidate prior samples and unanswered probes as one
  generation; authenticated observers never become time authorities.
- NTP‑style estimation: when the reply is received at local time `t3_net`,
  compute offset `θ = ((t1_net_recv - t0_net) + (t2_net_send - t3_net))/2` and
  delay `δ = (t3_net - t0_net) - (t2_net_send - t1_net_recv)`.
- Quality filter: discard samples with RTT above 500 ms.
- Aggregation: compute a trimmed median (10% on each side) of remaining
  offsets and report a confidence bound via median absolute deviation (MAD).
- Smoothing: optional EMA with a slew cap (`smoothing_alpha`,
  `max_adjust_ms_per_min`). Disabled by default to keep raw median behavior.
- Confidence: track median absolute deviation (MAD) to expose an uncertainty
  bound alongside `t_net`.

Parameters (current defaults)
- `sample_interval_ms` ≈ 5000, `sample_cap_per_round` = 8
- `trim_percent` = 10%, `max_rtt_ms` = 500
- Smoothing (off by default): `smoothing_alpha` = 0.2, `max_adjust_ms_per_min` = 50

Interfaces
- Torii: `GET /v1/time/now` → `{ now, offset_ms, confidence_ms }`
         `GET /v1/time/status` → peer statistics and recent offsets
         (operator-only; fresh exact-network request signature required)
- Sumeragi: NTS provides timers/timeouts using `t_net`. Consensus validity
  never consults NTS.
- Consensus rules: TTL is height‑based; time‑based trigger validity is checked
  against the block header timestamp only (see Triggers section). Local clocks
  and NTS do not influence acceptance.

Security & behavior
- Multiple malicious configured peers cannot easily skew the trimmed median;
  one current sample per configured identity contributes to the aggregate and
  the health quorum prevents a single source from becoming authoritative.
- Observers run NTS for consistent query TTLs; light clients may fetch
  `time/now` as advisory only.

## Consensus Modes

- Closed‑Set Sumeragi: A governance‑managed, permissioned validator set. Nodes are added/removed via on‑chain transactions and governance policies. Sumeragi uses this fixed set for leader rotation, propose, validate, and commit. Recommended for consortium deployments and regulated networks.
- Nominated Proof‑of‑Stake (NPoS) Sumeragi (optional): Network participants stake and nominate validator candidates. At each epoch boundary the chain deterministically elects a validator set (parameters: `epoch_length`, `max_validators`, `min_self_stake`, nomination caps). Only the validator‑set selection mechanism differs; Sumeragi’s consensus protocol and finality remain unchanged. Misbehavior/offline penalties and unbonding periods are defined by governance. Mode is selected via chain parameters (e.g., `ConsensusMode = Closed | NPoS`) and can change only through governance.

## Node Roles

- Validators: Participate in Sumeragi (closed or NPoS‑elected), propose/vote, and sign blocks.
- Syncing‑Only Observers: Non‑validating full nodes that continuously sync blocks and maintain WSV, serve queries and proofs, but never propose/vote. They improve read scalability and auditability without affecting consensus.
- Light Clients: Header‑only clients that verify validator signatures and Merkle proofs; submit transactions but hold no full state.

Pipeline overlap (execute N−1 while proposing N)
- While consensus finalizes block N, nodes may pre‑validate and prepare
  execution for N+1 on a snapshot pinned at height N−1. Stateless checks,
  access‑set derivation, and prefetch are safe; no state mutation occurs until
  N commits. This reduces latency without changing semantics.

Ingress: Admission & Gossip
- Torii admission enforces strict, configurable limits before decode: max payload size (compressed and post‑decompress), max nesting/depth, max signatures per tx, and supported key/scheme sets. Document worst‑case acceptable sizes via named parameters (e.g., `MaxTxBytes`, `MaxDecompressedBytes`, `MaxSigCount`).
- Overload behavior is explicit. When admission queues exceed high‑watermarks, the node sheds lowest‑priority or oversized txs by a deterministic policy and returns canonical errors to clients (e.g., `Rejected(Overloaded)`) with a retry hint. Do not silently drop at ingress.
- Replay/TTL checks run at admission: height‑based `expires_at_height` and `(chain_id, sender, seq)` strictly increasing per sender.
- Gossip propagation batches transactions with size/time caps (e.g., a few ms or size N), compresses with a deterministic codec, and flushes promptly to avoid undue latency. Deduplication keys are canonical tx hashes (pre‑compression). Peer targets are shuffled per round to reduce structured censorship; integrity is preserved by per‑tx hashes.
- Telemetry surfaces admission/gossip throttling: queue depths, shed counts by reason, batch sizes/latencies. Policies are published in node config for reproducibility.

Mempool policy
- Transactions that pass stateless checks are enqueued in the pending set with
  TTL, priority, and size/fee policies. Inclusion order is deterministic
  relative to leader’s selection rules (e.g., hash, fee, age) and must be
  published in node configuration to aid reproducibility.

Sizing & eviction
- Cap mempool by configurable soft/hard limits. When above the soft cap, evict in a deterministic order (e.g., lowest fee class, then oldest by `expires_at_height`, then lexicographic `tx_hash`). Apply hysteresis so frequent churn is avoided.
- Periodically purge expired entries (height‑based TTL) and transactions invalidated by confirmed conflicting writes. Maintain O(log N) indexes by expiry and priority for efficient scans.
- Per‑origin quotas limit outstanding ready txs per account/domain to mitigate hotspot dominance; age low‑priority txs to avoid starvation.

Visibility & diagnostics
- Emit mempool events for `Admitted`, `Evicted{reason}`, and `Expired`. Expose `GET /mempool/status` and `GET /mempool/tx/{hash}` for operators/SDKs to query presence, queue, and rejection reasons.

---

## Unifying IVM and Built‑in ISIs

We represent each transaction as an ExecutionPlan:
- Nodes: one or more steps mapped to either:
  - IVM program node: a pre‑decoded bytecode segment + metadata (register use,
    syscalls, declared state accesses if available).
  - Built‑in node: a pure host operation (e.g., parameter set) with well‑known
    access set derivation and cost hints.
- Edges: in‑tx ordering constraints (as authored). We do not reorder inside a
  single tx; we only parallelize across distinct transactions—and, optionally,
  across independent sub‑segments of a single tx when safe and declared.

Most instructions resolve to IVM calls. Built‑ins remain host‑side but use the
same access‑set machinery so the scheduler can interleave them with IVM nodes.

Permissions and invariants
- Both built‑ins and IVM syscalls perform permission checks against the WSV
  (roles, ownership, domain/account policies) and enforce invariants (e.g.,
  asset conservation) via the same guard layer to avoid divergent semantics.
 - Stateless vs stateful: signature/format checks and basic auth run in the
   stateless phase; authority/role checks execute in the stateful phase against
   the same guard APIs to keep behavior identical across engines.
- Audit trail: when a denial occurs, emit minimal structured diagnostics
  (who/what/why: account, instruction id, permission id/reason code) for ops
  without leaking sensitive payloads.

ISO 20022 integration
- Envelope metadata: accept normalized ISO envelope fields in Norito metadata: `UETR` (uuid), `MsgId`, `CreDtTm`, `BizSvc` (market practice), `SchemaHash`.
- Idempotency & replay: bind `UETR` + `MsgId` to `(chain_id, sender, seq)`; enforce height‑based TTL; reject duplicates/regressions deterministically.
- Routing to JDGs: derive `JurisdictionId` from BIC/ClearingSystemId and route transactions requiring sovereign checks to JDGs for attestations.
- Validation: IBAN checksum, BIC format, ISO 4217 currency/decimals, structured party names/addresses with NFC normalization.
- Status mapping: map pipeline outcomes to pacs.002 (`ACTC/ACSP/ACSC`, `RJCT`, `PDNG`, `ACWC`) and emit reason codes from ISO code sets.
- Status derivation: keep the runtime state machine at `Pending/Accepted/Rejected`; derive `ACTC/ACSP/ACSC/PDNG/ACWC` deterministically from persisted flags (`ledger_tx_queued`, `settled_at`, `hold_flag`, `change_flags`) so all nodes emit identical pacs.002 payloads.
- ACWC usage: only emit `ACWC` when an accepted instruction requires a deterministic change set (e.g., value-date shift, remittance truncation); use `PDNG` for holds/conditional processing and keep `RJCT` for terminal failures.
- Status payload: Torii responses include the derived pacs.002 code plus `hold_reason_code`, `change_reason_codes`, and `rejection_reason_code` so operators can map transitions to SMPG/CBPR+ reason catalogues without inspecting raw bridge state.
- Fees/charges: support `ChargeBearer` (CRED/DEBT/SHAR/SLEV) when posting fees; JDGs attest regulatory/sanctions screening without PII leaks.
- IVM helpers: use `crates/ivm/docs/iso20022.md` opcodes/helpers for parsing/serialization under deterministic budgets.

ISO Envelope (Norito schema; illustrative)
```
struct IsoEnvelope {
  uetr: bytes              // UUID as 16-byte bytes
  msg_id: bytes            // BAH MsgId (NFC)
  cre_dt_tm_ms: u64        // Creation time (ms since epoch)
  biz_svc: option<bytes>   // Market practice (CBPR+/SEPA/HVPS+)
  schema_hash: [u8; 32]    // Message schema/version hash
  market_practice: option<bytes>
  payload: bytes           // Canonical message bytes (normalized XML or compact form)
}
```

Example mapping: pacs.008 → ledger
- Stateless: parse envelope, verify `schema_hash`, enforce `(uetr,msg_id)` idempotency and height TTL, IBAN/BIC/currency checks, normalize party fields.
- Route to JDGs by BIC/ClearingSystemId; verify JDG attestation presence (`JurisdictionAttestation`); reject if missing.
- Stateful: resolve debtor/creditor accounts; map currency to asset id; apply `ChargeBearer` fees; perform Transfer; annotate KV with `uetr/msg_id/schema_hash`.
- Events: map outcome to pacs.002 codes; include ISO reason codes on reject.

---

## Kotodama Smart Contract Lifecycle (IVM Bytecode)

> Historical proposal (non-normative): this section predates the first-release
> revisioned contract lifecycle. Retired instance registration, upgrade, and
> deprecation sketches below are retained only as design history. The current
> normative deployment and ownership model is specified in
> [`contract_deployment.md`](contract_deployment.md).

Historical phases (non-normative)

- Author: write Kotodama source (`.ko`) with explicit entrypoints and Norito‑typed parameters/returns. Avoid global mutable state; declare state keys via canonical key helpers when possible.
- Build: compile to IVM bytecode (`.to`) with a pinned toolchain. Produce a manifest:
  - `code_hash` (Blake2b‑32), `abi_hash`, `compiler_fingerprint` (rustc/LLVM), feature bitmap (e.g., `cuda=false`, `metal=false`), `access_set_hints` (advisory RW‑keys per entrypoint), and `schema_hash` for argument/return types. CPU SIMD capability is always reported automatically.
  - Reproducibility: CI builds must produce byte‑identical `.to` and manifest given the same inputs.
- Publish: distribute `ContractPackage { code_bytes, manifest, publisher_sig }` out‑of‑band or via Torii. Nodes verify manifest hashes/signatures; content‑address store by `code_hash`.
- Register code: `Register<SmartContractCode>` stores `code_hash → {manifest, (optional) code_bytes}` in WSV or artifact store. Large code MAY be stored off‑chain with a content‑addressed URL and hash.
- Deploy/Activate: `Register<SmartContractInstance>` creates an instance with `contract_id`, `version`, `owner`, `domain`, `code_hash`, parameters, and optional `state_namespace`. Permissions: only authorized roles may deploy to a domain.
- Invoke: `Call { contract_id, entrypoint, args }`. Stateless: verify `code_hash` exists, ABI/arg schema matches, and advisory `access_set_hints` present. Stateful: execute via IVM. Enforce permissions and gas limits. Scheduler uses hints; runtime enforces strict access‑set.
- Observe: emit events with `code_hash`, `contract_id`, `entrypoint`, `args_hash`, and `result`/`rejection` reason codes. Telemetry records gas/time.
- Upgrade: `Upgrade<SmartContractInstance> { contract_id, new_code_hash, activation_height }` with governance policy (quorum, notice). Support canary activation by domain. Old version remains callable until `sunset_height`.
- Deprecate/Retire: `Deprecate<SmartContractCode>` or `Unregister<SmartContractInstance>` per policy; triggers and scheduled calls must be drained or migrated. State migration entrypoints should be explicit.

ABI & Norito
- ABI is a Norito schema over entrypoints and their types. `abi_hash` binds to the manifest; invocation envelopes carry canonical Norito‑encoded args/returns.

Permissions & governance
- Register/Upgrade require domain‑level permissions (e.g., `CanRegisterSmartContract`, `CanUpgradeSmartContract`); calls may require `CanCall<contract_id.entrypoint>` role tokens.
- Default executor enforces upgrade windows, activation/sunset heights, and owner/domain policies.

Determinism & sandboxes
- No floating‑point, no nondeterministic syscalls. CPU SIMD paths must remain bit-for-bit equivalent to scalar fallbacks and are selected purely by runtime detection; GPU offload stays optional, with the scalar path defining gas/outputs. I/O limited to host-mediated syscalls with fixed semantics.

Access‑set hints
- Compiler emits per‑entrypoint advisory RW‑sets; scheduler prefers manifest `access_set_hints` and may fall back to per‑entrypoint hints for state‑only bytecode. Runtime enforces strict sets; violations abort deterministically.
- Contract manifests may include optional `access_set_hints { read_keys, write_keys }`. WSV-facing keys use canonical prefixes (`account:…`, `asset:…`, `domain:…`, `*.detail:…`), while contract-local durable state uses `state:<name>` or `state:<name>[*]`. Deployed state is stored only under the contract-instance namespace `sc/<address-hash>/…`; it never falls through to raw IVM state, and unscoped raw bytecode cannot address the reserved `sc` namespace. Dynamic/opaque access emits wildcard hints: `state:*` for unknown state paths and `*` for global ISI fallbacks. Hint keys are parsed into `CanonicalStateKey`/`StateAccessSetAdvisory`, canonicalized, and re-emitted into scheduler keys; invalid hint keys fall back to entrypoint hints or conservative scheduling. Derived access sets are cached by `(code_hash, entrypoint)` and invalidated when the manifest signing payload changes; disable with `pipeline.access_set_cache_enabled` for diagnostics.
- A dynamic prepass merges queued ISI keys with complete concrete host logs, but a block-start execution is not itself proof that a target stays unchanged. The scheduler therefore derives a second fence from validated bytecode: unproven durable-state access adds `state:*`, while ledger reads/writes, nested calls, and unclassified syscalls add `*`. Durable reads are fingerprinted by concrete contract scope and selectively re-executed when a predecessor changes them. Ledger access and opaque/nested calls are always re-executed against the ordered live state. Incomplete custom-host logs fingerprint the complete durable map and fail closed.

Torii contract APIs
- Artifact registration and deployment are client-signed native transaction operations.
- Account-signed `GET /v1/contracts/artifacts/{dataspace_id}/{code_hash}` and `/bytes` read the exact scoped artifact with network and artifact identity bindings.
- `POST /v1/contracts/call` prepares a caller-validated unsigned transaction; `POST /v1/contracts/view` executes a read-only invocation. See `torii_contracts_api.md` for authentication and response validation.

Testing & CI
- Golden vectors for ABI encoding/decoding; reproducible build checks; deterministic execution across backends. Access‑set coverage tests compare hints vs observed RW‑keys.
- Differential execution tests: execute identical blocks through single‑threaded and parallel schedulers and assert byte‑identical outputs (events, state roots, block hashes).
- Commit crash tests: simulate crashes during merge; verify WAL‑based recovery produces the same committed state/header.

---

## First-release Proposal and Runtime Upgrade Governance

The normative public contract is defined by
[`governance_api.md`](governance_api.md), while the consensus-owned attempt
lifecycle is defined by [`governance_pipeline.md`](governance_pipeline.md).
This section is only a pipeline summary.

- Iroha 3 has one ABI version: V1. Runtime-upgrade proposals target
  `abi_version = 1`; this document does not define a V2 compatibility path.
- Proposal-backed governance accepts the closed, typed ten-kind
  `ProposalKind`: `DeployContract`, `RuntimeUpgrade`, `SccpRouteGovernance`,
  `ValidationFeePolicy`, `ValidationFeePayoutLifecycle`,
  `MusubiRegistryGovernance`, `SorafsProviderGovernance`,
  `ContractLifecycleGovernance`, `ContractEmergencyHold`, and
  `GlobalDataTriggerPermissionGovernance`.
- A Parliament attempt owns its body pipeline, sortition evidence, results,
  policy and effect bindings, compare-and-set head, and
  `GovernanceCertificateV1`. Core constructs the certificate automatically
  when the final required result is accepted.
- Core derives `enact_at_height` from the certification height and configured
  minimum delay. At that exact height, the automatic block-start step
  revalidates the certificate and compare-and-set head. Head drift records
  `Superseded`; a matching head records `Enacted` after the typed effect
  succeeds, or rolls back the effect and records `ExecutionFailed`.
- A stored proposal has exactly `proposer`, `kind`, `created_height`, and
  `status`. Its closed statuses are `Proposed`, `Rejected`, `Enacted`,
  `Superseded`, and `ExecutionFailed`; there is no `Approved` compatibility
  state.
- Clients may create typed attempts, submit only the closed Parliament
  lifecycle transitions, and read attempts and results. Certificate creation,
  finalization, enactment, supersession, and execution-failure recording are
  consensus-owned. There is no public or manual finalize, enact, or
  certificate-submission path and no compatibility alias for one.
- Standalone referenda remain a separate election product. Their public or
  proof-backed ballots and tallies are not Parliament body results and cannot
  authorize a typed proposal or contribute to `GovernanceCertificateV1`.

Micro‑batch / multi‑call transactions
- Allow a single transaction to contain a small bundle of calls to the same
  key‑space (e.g., N transfers within one asset). Execution remains sequential
  as authored; gas is the sum; access‑set is the union. Caps: max calls/tx and
  max decoded size to prevent decode bombs. This reduces envelope/signature
  overhead and lowers scheduler conflicts for fan‑in/fan‑out workloads.

---

## Static Analysis & Access Sets

Purpose: enable safe parallel execution by ensuring that concurrently running
workloads have disjoint write sets and no read‑after‑write conflicts.

1) Instruction/Program‑level derivation
- Built‑ins implement `fn access_set(&self) -> StateAccessSet` (exact or
  conservative) using known semantics (e.g., asset transfer touches two
  balances; domain/account registration touches unique IDs).
- Core asset-definition registration reads the signed `owning_domain` and
  any alias routing domain independently. Opaque asset IDs do not supply
  domain ownership. Mint, burn, and asset-transfer instructions retain a
  global fence for their dynamic policy and routing accesses; trigger access
  sets retain that fence when they contain these instructions.
- IVM nodes derive access sets using:
  - Declared hints (preferred): Kotodama compiler and IVM metadata include
    read/write keys when available (e.g., IDs passed as immediate/parameters).
  - Dry‑run logging (fallback): a deterministic simulation in read‑only mode
    that logs all touched keys without mutating state. This executes with a
    bounded step limit to prevent DoS; outcomes are discarded after logging.
  - Execution context: dynamic prepasses and overlays use the candidate
    `StateBlock` timestamp, or an authenticated committed ledger timestamp.
    A fresh pre-genesis `StateView` supplies no authenticated time, so it is
    not an executable fixture. Contract fixtures must also materialize the
    canonical subject account and explicit lifecycle binding.

Kotodama integration
- Kotodama emits `.to` IVM bytecode and metadata describing static resource
  usage when derivable. When data‑dependent, the compiler marks uncertainty so
  the runtime switches to conservative access‑set unioning or dry‑run logging.

2) Granularity
- Default granularity is per‑transaction: a union of all instruction/node
  accesses. Optionally, enable “sub‑tx segments” (e.g., sequential IVM calls
  in the same tx) to reduce false conflicts. Segment boundaries are defined by
  the authoring toolchain or compiler hints; ordering is preserved.

3) Determinism & Safety
- Always prefer exact/hinted sets; fall back to conservative superset if any
  uncertainty is detected (e.g., data‑dependent key construction). Supersets
  reduce parallelism but never break safety.

- Access‑set metadata included on‑wire is optional and advisory; the canonical
  state transition remains the executed semantics. Nodes must not rely on
  external hints for correctness.

Wire/advisory format (implemented)
- Canonical keys and advisory RW‑sets live in `iroha_data_model::state`:
  - `CanonicalStateKey`: a Norito‑encoded enum naming concrete WSV keys, e.g.,
    `Domain(DomainId)`, `Account(AccountId)`, `Asset(AssetId)`, and metadata
    entries such as `AccountMetadata { id, key: Name }`.
  - `StateAccessSetAdvisory { reads: Vec<CanonicalStateKey>, writes: Vec<CanonicalStateKey> }`.
  - Canonical bytes are the Norito encoding of the enum value; sorting and
    deduplication are provided via `canonicalize()` to keep envelopes compact.
- Round‑trip tests are included in `crates/iroha_data_model` to preserve Norito

5) Enforcement (normative)
- During stateful execution, the executor MUST assert that all state reads and
  writes are within the pre‑derived access set. If a violation is detected:
  - Default: abort the transaction deterministically and emit diagnostics.
  - Optional: route to a sequential quarantine lane for re‑execution within
    block budget; if it still exceeds the set, reject. Quarantine lane does
    not run concurrently with other txs and preserves deterministic ordering.
  - Proposer‑local only: quarantine is a non‑consensus optimization. Results
    MAY be proposed only if re‑execution observes the strict access set; validators
    never relax the rule during replay.
- Budgeted analysis: dry‑run derivation has a fixed step/CPU budget. On budget
  exhaustion, mark access set as unknown and route to the conservative/quarantine
  path instead of executing in parallel.
- Tooling: provide an access‑set preview in CLI/SDK to help authors surface
  dynamic patterns and reduce conservative fallbacks.

Quarantine lane bounds (normative)
- The quarantine lane (sequential re‑execution) is optional; when enabled it is
  strictly bounded and never runs concurrently with other lanes. Classification
  is a pure consensus rule over authenticated transaction metadata: only an
  exact Norito JSON boolean `true` at the `quarantine` key enters the lane.
  Missing values, `false`, and string or numeric lookalikes do not classify.
  There is no process-local classifier hook. Limits (fields of the committed
  `pipeline_validity_policy_v1` parameter, not node configuration):
  - `quarantine_max_txs_per_block` (default: 0; a zero cap disables the lane
    and rejects transactions explicitly marked for quarantine)
  - `quarantine_tx_max_cycles` (default: 0; otherwise bounded by the ordinary
    IVM cycle ceiling)
  If a tx exceeds limits or still accesses keys outside its set, it MUST abort.
  Emit structured telemetry with code hash, offending keys, and decision.

Policy & incentives
- Transactions SHOULD declare their access sets in metadata. Nodes MAY enforce
  a policy of “declare or pay more”: higher base fees/gas premiums for unknown
  access sets, and strict abort/quarantine on mis‑declaration at runtime.
  Tooling (Kotodama compiler, SDK) can auto‑generate RW‑sets to ease adoption.

---

## Deterministic Parallel Scheduler

Inputs
- Ordered list of candidate txs (leader’s chosen order by hash/priority/TXS)
- For each tx (or segment): `StateAccessSet { reads, writes }`

Algorithm
1) Build Conflict Graph
- Edge from A→B if A and B conflict (write/write or write/read overlap). Use
  canonical key encoding for state items (domain/account/asset ids, queues,
  metadata keys, etc.).

2) Epoch Formation (Topological Levels)
- Compute a topological layering such that all nodes in an epoch are pairwise
  non‑conflicting. Deterministic tie‑breakers are clock‑free: primary is the
  transaction’s position in the leader’s proposal (proposal index), then tx
  hash as a stable tie‑breaker. No wall‑clock timestamps influence order.

3) Worker Assignment
- Within each epoch, assign tasks to `N` local workers via a stable
  round‑robin by `worker_index ∈ [0..N)`. This mapping is purely local and
  never depends on network identities. It is implementation‑defined but must
  be deterministic for a fixed `N`.
- Each task executes against an isolated `StateBlock` overlay branching from
  the epoch’s base view.

Declarative dependencies (optional)
- Authors MAY declare intra‑block dependencies between transactions (edges in
  the proposal DAG). The scheduler respects declared edges and may reorder only
  among independent txs to maximize parallelism. Declared edges are included
  in the signed proposal and replayed deterministically by validators.

4) Merge & Advance
- After all tasks in an epoch finish successfully, merge overlays into the base
  view in canonical order by `(proposal_index → tx_hash)` and begin the next
  epoch. No other key (arrival time, worker index, network node id) influences
  merge order.
- Failures (stateful validation errors) cause the task’s tx to be dropped for
  this block. They do not poison the epoch; overlays from successful tasks are
  unaffected.

Commit performance & crash safety
- Apply merges via database batches/transactions under a write‑ahead log (WAL) so that partial commits can be recovered idempotently after a crash. State roots and Merkle commitments must reflect exactly the merged overlays.
- Monitor commit latency. If the merge loop is a hotspot for very large blocks, consider safe optimizations such as batched writes or parallel application of overlays that are provably disjoint in key space. Any optimization MUST preserve determinism and the canonical order when overlaps exist.

WSV integration
- `StateBlock` overlays are applied to a read‑only WSV snapshot. Overlays
  contain deterministic write‑sets with conflict stamps. Merge applies writes
  in canonical order; MVCC/indexes update atomically to preserve invariants.

Properties
- Deterministic: graph, epochs, and merge order are identical on all peers.
- Scalable: embarrassing parallelism when txs target disjoint keys.
- Bounded: epoch barriers provide memory/latency control; size tuned by
  configured limits (e.g., max concurrent overlays, max write‑set size).

Scheduling policy & backpressure
- Priority tiers: define inclusion priority by policy (e.g., fee class,
  age/TTL, size). Ties break by canonical hash. Publish policy in node config.
- Per‑sender quotas: cap concurrent ready txs per principal to reduce spam and
  hotspot dominance. Age low‑priority txs upward over time to avoid starvation.
- Backpressure: when overlay pool or analysis threads saturate, throttle
  admission and gossip based on queue depth targets. Shed excess by dropping
  lowest‑priority or oversized txs first, with metrics.

### TTL and Replay Protection (normative)

- Height‑based TTL: each transaction MUST include `expires_at_height: u64` (or
  an equivalent height window). The expiry is exclusive: validation rejects a
  transaction when `current_height >= expires_at_height`, so it is eligible
  only while `current_height < expires_at_height`.
- Per‑sender sequence: each transaction MUST include `(sender, seq)` where `seq`
  is strictly increasing per `sender`. Stateless validation rejects duplicates
  or regressions. Replay checks bind to `(chain_id, sender, seq)`.
- Mempool deduplication is advisory; consensus rejection is enforced at
  validation and results in identical outcomes across nodes.

MEV considerations
- Leader selection follows published policy; validators deterministically
  replay. Avoid ambiguous heuristics that could invite reorder pressure.

---

## Two‑Phase Validation (Per Transaction)

1) Stateless (front‑loaded & parallel)
- Norito decode, schema checks, signature verification (batch/parallel), chain
  id/TTL/rate limits, instruction wire IDs.
- Pre‑decode IVM bytecode: translate to compact interpreter ops and cache in
  `IvmCache` (keyed by code hash + feature set). Decode once, reuse many.

Batch signature verification (per scheme)
- Group signatures by scheme (Ed25519, ECDSA, PQC). For each scheme, form
  micro‑batches with size/time thresholds (e.g., ≥64 sigs or 2–5 ms window).
  Batch windows are operational only and do not affect consensus: acceptance
  is equivalent to verifying each signature independently.
- ECC (Ed25519/ECDSA/Schnorr): use deterministic random‑linear combination to
  reduce to one fixed‑base multiply + one MSM over public keys and `R` points;
  derive coefficients from a hash of the sorted batch for determinism. On
  failure, bisect to locate bad signatures. Keep a per‑sig fallback path.
- PQC (Dilithium/ML‑DSA): no MSM analogue; batch at kernel level (multi‑NTT,
  fused Keccak/SHAKE) and reuse per‑key precomputations when many sigs share
  the same public key. Always provide scalar fallback; results are identical.

Normative transcript and coefficients (ECC)
- Partition by scheme. For each batch, build `transcript = Hash(domain_tag ||
  concat(sorted tuples))` where domain_tag = `"iroha:ecc_batch:v1" || scheme`
  (e.g., `":ed25519"`, `":ecdsa"`). Tuples `(pk_bytes, msg_hash, sig_bytes)`
  use fixed encodings (compressed points, canonical scalar encodings). Sort
  order: lexicographic over the concatenated tuple bytes. Coefficients
  `c_i = Hash(transcript || LE32(i)) mod q`, where `Hash` is the scheme’s
  hash‑to‑scalar with domain separation and `q` is the group order. All nodes
  derive identical `c_i`. On failure, perform deterministic bisection to
  attribute faulty signatures; reject only those transactions.

2) Stateful (scheduled)
- Execute in a `StateBlock` overlay with the current executor version. Enforce
  permissions, invariants, and semantic rules. Built‑ins and IVM follow the
  same API boundary; host syscalls are validated and side‑effect controlled.
- Record events and emitted triggers (buffered until epoch merge).

ZK verification placement
- Heavy zero‑knowledge proof verification MAY be performed in stateful
  overlays to reuse WSV‑resident verifying keys and circuit metadata. Nodes
  MAY perform optional pre‑verification during stateless phase under strict
  compute/time budgets to drop obviously invalid proofs early. Both paths
  must be deterministic and produce identical accept/reject outcomes.

Implementation notes (current)
- Executor performs stateless pre‑verification for `SignedTransaction::WithProofs` attachments: backend tag sanity, and per‑block dedup by `(proof hash, vk_commitment?)` when `vk_commitment` is present in the attachment or `vk_ref` resolves a registry commitment; falls back to `(proof hash, backend)`.
- `VerifyProof` records the outcome of the exact native PIPA-R or STARK
  relation in WSV. Native PIPA-R verifies the five compiled Kaigi/confidential
  relations against their canonical descriptor and processed key, using
  transparently derived pinned Pasta parameters. The data-model
  `OpenVerifyEnvelope` contains a Norito `NativePipaRProofV1` with one ordered
  public column and exact proof bytes. Unqualified demo, governance and IVM
  execution relations are rejected. See `specs/zk_envelopes.md` for current
  proof/key framing; the retired ZK1 decoder and helper APIs are deleted.
- VK lifecycle and registry are managed via `RegisterVerifyingKey`, `UpdateVerifyingKey`, and `DeprecateVerifyingKey` ISIs. Proof attachments reference registered VK records by `vk_ref`; verifying-key bytes are stored only in registry/external records and are not carried inline.

DoS hardening
- Set per‑tx compute, memory, and syscall caps; enforce step/time budgets for
  dry‑runs and stateful execution. Meter signature checks and decoding. Reject
  oversized access sets to prevent pathological conflicts.

Operational notes
- Micro‑batch windows for signature verification are operational conveniences only and never change acceptance outcomes versus individual verification. Implement deterministic partitioning and coefficient derivation as specified; on any batch failure, bisect deterministically and attribute faulty signatures. Instrument invalid‑signature rates and cap batch sizes under sustained invalid traffic to avoid DoS amplification.
- Document and enforce worst‑case acceptable payload sizes and decode depth; tests must demonstrate that no single well‑formed payload can exhaust CPU or memory beyond configured budgets.

---

## IVM Execution Engine (Register‑Based)

Interpreter Dispatch
- Use a direct‑threaded interpreter (jump table) where supported by Rust/LLVM,
  with a portable fallback. Pre‑decoded ops avoid per‑step decoding overhead.

Register File & Frames
- Keep a compact register file per frame, reusing stack slots aggressively.
- Avoid dynamic allocation in hot loops; pre‑allocate operand buffers.

Vectorization, AOT_SIMD, and Acceleration
- AOT_SIMD: ahead‑of‑time specialization of hot kernels (hashing/crypto,
  memory ops) into CPU‑feature‑specific variants selected at startup. All
  variants are bit‑exact; selection does not affect results.
- SIMD backends (NEON/PMULL, CLMUL, AVX2/512) and optional GPU offload
  (CUDA/Metal) are feature‑gated. A portable scalar path is always available
  and canonical.
- Word‑wise VM ops (vadd/vxor/etc.) use fixed lane policies with wrap‑around
  (mod‑2^N) per‑lane semantics for integer operations to ensure bit‑exact
  results across backends.

SIMD op exposure
- SIMD vectorization is an implementation detail for scalar opcodes unless and
  until vector opcodes are standardized as public IVM instructions. If vector
  opcodes are exposed, they MUST appear in the Opcode Reference with full
  semantics and gas pricing.
  - Current status: public vector opcodes exist (e.g., VADD32/64, VAND/VXOR/VOR,
    VROT32), and their semantics/gas are specified in the Opcode Reference.

Logical vector length and parallel markers (normative)
- `SETVL` sets a logical element count for subsequent vector ops. It does not
  expose hardware SIMD width and MUST NOT change results across hardware.
  Gas for vector ops is a function of the number of elements processed, not
  CPU width. Tails are handled by the scalar path; results are bit‑exact.
- `PARBEGIN`/`PAREND` are compiler markers with no runtime concurrency
  semantics. They are treated as no‑ops by the interpreter; scheduling and
  parallelism are driven by the block‑level scheduler only.

GPU targets & flags (if enabled)
- CUDA/PTX: target PTX ISA 7.8 with `sm_80` and `sm_86` (Ampere) as the
  initial support matrix; optionally add `sm_90` (Hopper) after validation.
  - Compiler flags: `--use_fast_math=false`/disable fast‑math, `--fmad=false`,
    `--prec-div=true`, `--prec-sqrt=true`, `--ftz=false`; integer‑only kernels.
  - Memory: no undefined behavior; coalesced accesses encouraged but not
    assumed; bounds checked in debug builds for kernels.
- Metal/MSL: target Apple GPU Family 7 (A14/M1) and newer with MSL 2.4+ on
  macOS 12+/iOS 15+. Use integer pipelines only; forbid FP in consensus paths.
- CI: golden vectors across at least two GPU backends (e.g., Apple AGX, Nvidia
  Ampere) plus scalar/SIMD CPU paths. Any mismatch disables the GPU backend.

Host Syscalls
- Side‑effecting syscalls (read/write state, emit events) go through a vtable
  with explicit capability descriptors. They are metered and logged for access
  set auditing in dry‑run mode.

- Kotodama/IVM ABI is stable across minor versions; deprecations follow a
  capability‑flag negotiation so old bytecode remains executable.

Normative VM semantics
- No floating‑point in consensus paths. All IVM ops use integer/bitwise
  semantics only. If FP is ever introduced, IEEE modes, MXCSR, DAZ/FTZ, and
  FMA settings MUST be fixed with conformance tests.
- Arithmetic semantics: default wraparound mod‑2^64; any opcode with
  non‑default behavior (e.g., saturating) is explicitly listed in the Opcode
  Reference. Wrap or saturation is part of the spec.
- Endianness & layout: multi‑byte scalars use little‑endian; misaligned
  loads/stores trap deterministically with `MisalignedAccess`; no undefined
  behavior. Out‑of‑bounds and uninitialized access is forbidden.
- SIMD chunking policy: process in fixed 64‑byte blocks; tails execute via
  scalar path. Misalignment handling is specified (byte‑wise loads if needed).

AOT artifacts
- Format: header with VM version, code hash, compiler fingerprint (Rust/LLVM),
  `target-cpu`/`target-feature` bitmap, and build flags. Body contains code and
  relocation data. Artifacts are reproducible given identical inputs.
- Validation: at load time, run translation‑validation traces against the
  interpreter; on any divergence, discard the artifact and fall back to the
  interpreter.

---

## Zero‑Knowledge Proofs (Proof Creation and Verification)

Scope
- Nodes verify proofs in‑pipeline; proving happens off‑chain or in an
  out‑of‑pipeline lane. Transactions may carry proofs and public inputs, or
  reference on‑chain commitments/verifying keys.

Proof creation (out‑of‑pipeline)
- Purpose: bridges and advanced workflows may require generating proofs that
  attest to properties of committed state. Proof generation is potentially
  expensive and non‑deterministic across machines; it MUST run outside the
  block pipeline.
- Inputs: committed WSV snapshot, circuit id/version, public inputs, and any
  necessary witness material derivable from state or local secrets (if the
  node is authorized). Outputs: proof bytes and metadata.
- Determinism: not required for creation; only verification is consensus‑
  critical. Nodes may produce different proofs that verify to the same public
  inputs and VK.
- Submission: produced proofs are wrapped into transactions (e.g., `VerifyProof`
  or application‑specific ISIs) and enqueued into the regular mempool for
  later inclusion.

On‑node prover lane (optional)
- Enabled via `zk_prove` feature and node configuration. Uses a bounded job
  queue with priority classes (e.g., bridge‑critical vs background).
- Resource isolation: fixed concurrency, CPU/GPU/memory quotas, and timeouts
  per job. OS‑level priority/nice and cgroups recommended to avoid contention
  with the block pipeline.
- Inputs must specify the pinned snapshot height/root; the lane reads WSV via
  a read‑only API. No writes to WSV occur during proving.
- Artifact store: proofs and intermediates are kept in a bounded local cache
  by hash with TTL; transactions reference artifacts by hash or inline them.
- Governance/allowlist: only approved circuits (by id/version hash) may be
  executed on‑node; jobs are authenticated/authorized.

WSV snapshot API (read‑only)
- Jobs consume an explicit `Snapshot` handle: `(height, state_root, timestamp)`
  plus read‑only iterators over key‑spaces (domains, accounts, assets, metadata)
  with range scans and pagination. Access requires explicit permissions and is
  audited. Snapshots are immutable and detached from in‑flight overlays.

Data model
- Proof payload: algorithm id (e.g., Groth16, Plonk), curve id (e.g.,
  BLS12‑381, BN254), circuit id/version, verifying key commitment/hash,
  public inputs, and proof bytes. All fields use canonical, unambiguous
  Norito encodings with explicit endianness and length bounds.
- Verifying keys: stored in WSV (optional) with governance and versioning, or
  supplied inline and checked against their on‑chain commitment hash.

Pipeline integration
- Stateless phase: enforce size/type/curve caps; hash and dedup proofs by
  (proof hash, vk hash); optionally pre‑verify under budget; otherwise defer.
- Static analysis: derive access set as READ on verifying key and any
  referenced commitments/registry entries. Proof verification is otherwise
  pure; it writes no state directly.
- Stateful phase: execute verification in a `StateBlock` overlay; read VK and
  circuit metadata from WSV; return boolean/accept‑reject and emit events.
- Scheduler: ZK verification is read‑only; it rarely conflicts and can run in
  parallel with unrelated stateful txs.

IVM/Kotodama/ISI alignment
- Kotodama exposes a `zk.verify(...)` primitive that compiles to an IVM host
  syscall `zk_verify` or a built‑in ISI `VerifyProof`. Both use the same
  executor path, permission checks, and metering.
- Access‑set metadata includes READs of the verifying key and circuit
  registry entries, enabling accurate conflict analysis.

Determinism and acceleration
- Arithmetic uses integer field/curve operations only; no floating‑point.
- Deterministic algorithms for MSM/pairing (fixed windows, canonical bucket
  order, fixed traversal). Parallel reductions must use a stable order.
- Feature‑gated acceleration: SIMD and optional GPU offload for MSM/pairings
  are permitted under `zk`, `zk_simd`, `zk_cuda`, `zk_metal` but must be
  bit‑exact with the scalar fallback.

Caching
- LRU caches for parsed/verifier‑prepared keys and SRS segments keyed by
  (vk_hash, algorithm, curve, params). Bounded sizes; eviction affects only
  performance, not results.

Security and DoS
- Strict caps on proof sizes, number of public inputs, curves/algorithms, and
  verification time per tx. Meter all operations. Reject unknown algorithms.
- Governance for verifying key lifecycle (publish, update, revoke) with event
  logs. Domain separation tags embedded in circuit definitions and messages.
- ZK tickets: limit pre‑verification budgets per peer/principal via a ticket
  system. Require declared size/curve in the envelope for constant‑time
  admission checks. Optionally fee‑gate large verifications based on scalar
  worst‑case cost to protect validator resources.
  - Current byte limits: `zk.preverify_max_bytes` and `zk.preverify_budget_bytes`.
    Native PIPA-R and STARK bind their curves through admitted proof profiles.
  - Reject codes: `ProofTooBig`, `UnsupportedBackend`, `PreverifyBudgetExceeded`,
    `MalformedProof`. Stateless pre‑verify ordering is deterministic and does
    not affect proposal ordering.

Testing
- Cross‑backend determinism: scalar vs SIMD vs GPU must produce identical
  outcomes for reference vectors. Include known‑good vectors for supported
  curves/algorithms and property tests for serialization round‑trips.

---

## Bridge Design (Light‑Client and ZK)

Goals
- Trust‑minimized, post‑quantum bridges between Iroha networks and external chains. Offer two patterns:
  1) ICS‑style light‑client bridge (hash‑based, no ZK) using ICS‑23/24 membership proofs.
  2) Transparent‑ZK light‑client bridge (zkBridge pattern) with periodic recursion to keep proofs succinct.

Recommended default
- Deploy a transparent‑ZK light‑client integrated in IVM (STARK/FRI family) with transparent recursion. Keep proofs PQ and avoid pairing‑based wrappers. All proving and verification live inside the IVM pipeline; no external zkVMs.

Statements proved (normative)
- Header/finality: `VerifyCommit(header, commit_certificate, validator_set_hash)` per i3.md certificate spec.
- Inclusion: `ICS23Verify(path, leaf, state_root)` for message/event/key/value inclusion.
- Rolling: `Fold(H[i..i+N]) → P'` transparent recursion compresses many headers/messages into a single proof.

Prover placement
- Use the out‑of‑pipeline Prover lane. Scale horizontally; optionally adopt distributed IVM proving for signature‑heavy headers. Emit `BridgeProof { range, proof_bytes, recursion_depth }` artifacts, addressed by hash and height range.

Verification paths
- Native: Iroha verifies counterparty proofs in ms‑scale and enqueues verified messages as regular transactions.
- On‑chain (external): provide a compact verifier library and a rolling‑proof model so counterparties store only the latest proof.

Data model & APIs
- Types: `BridgeHeader`, `BridgeMessage { src_chain, dst_chain, payload, inclusion_path }`, `BridgeProof { range, proof_bytes, scheme_id }`, `BridgeReceipt`.
- Torii:
  - `POST /bridge/proofs` — submit or pin a `BridgeProof`.
  - `POST /bridge/messages` — submit a `BridgeMessage` with proof/ref; node verifies and enqueues.
  - `GET /bridge/status/{id}` — status/receipt.

ICS‑style (hash‑only)
- Other chains embed an Iroha header client; verify commit certificate + ICS‑23 against `state_root`/`receipts_root`.
- Inbound: Iroha embeds a counterparty light client and performs symmetric checks.

ZK (transparent) details
- IVM circuits: implement light‑client constraints (commit certificate + ICS‑23) as IVM ZK circuits. Provide a transparent STARK‑style prover/verifier within IVM; support recursion schedules and batching. Target sub‑MB proofs with ms‑level native verification; seconds‑scale proving on server CPUs with optional deterministic SIMD/GPU acceleration.
- Recursion schedule: fold every N=64–256 blocks/events or when proof size > S bytes; publish new rolling proof artifact; consumers only need the latest proof.

Security posture
- PQ‑safe end‑to‑end (hash‑based commitments); no trusted setup. Avoid pairing‑based Groth16 wrappers on Iroha; if an external chain requires Groth16 on EVM, treat it as an isolated adapter not used in Iroha consensus paths.

SLOs & budgets
- Target ms‑scale verification; per‑batch proving < 20 s with horizontal scale; rolling proof size < 0.3–0.5 MB.

Conformance tests
- Deterministic verification of commit certificates and ICS‑23 paths in circuits; rolling recursion correctness; cross‑implementation vectors; failure cases (invalid sigs, wrong path, stale headers).

### IVM ZK Gadget Library (spec)

- Blake2b‑32 sponge gadget
  - Domain separation: prefix all inputs with a fixed domain tag (e.g., `"iroha:hash:v1\x00"`) unless the higher‑level spec already includes tags (Merkle leaves/inners).
  - Rounds/padding: implement standard Blake2b padding; expose `hash(bytes)` and `hash2(a,b)` helpers. Ensure transcript uses the same sponge with explicit labels.
  - API: `op HASH_LOAD ptr,len → h`, `op HASH_MERGE h1,h2 → h`, with host fallback.
- Signature gadgets
  - Ed25519: fixed‑base scalar mul precomputation table gadget; verifier API `ED25519_VERIFY(pubkey, msg, sig) → bool` with constant‑time checks.
  - secp256k1: windowed MSM gadget with constant‑time bucket adds; verifier API `SECP256K1_VERIFY(pubkey, msg, sig) → bool`.
  - Dilithium (optional, feature `pqc`): implement ML‑DSA verification gadget with NTT/keccak helpers; API `MLDSA_VERIFY(pk, msg, sig) → bool`.
- Mapping to IVM
  - Expose gadgets via IVM opcodes or host calls: `SCALL_ZK_HASH`, `SCALL_ZK_ED25519_VERIFY`, etc. All opcodes produce deterministic results and are measured in scalar‑based gas.
  - Provide CPU/SIMD/GPU backends with identical outputs (no FP).

Gadget APIs (deterministic host calls)
- Hash (Blake2b‑32) — mirrors `iroha_crypto::Hash::new`
  - `SCALL_ZK_HASH(data_ptr:u64, data_len:u32, out_ptr:u64) -> err:u8`
    - Writes 32‑byte Blake2b output with LSB set to 1 (as in `Hash::prehashed`). No domain tag is added here; higher‑level callers (Merkle, transcripts) prefix their own.
  - `SCALL_ZK_HASH2(h1_ptr:u64, h2_ptr:u64, out_ptr:u64) -> err:u8` concatenates two 32‑byte digests and hashes them.
- Ed25519 verify (RFC 8032 strict, ZIP‑215 encodings disabled)
  - `SCALL_ZK_ED25519_VERIFY(pk_ptr:u64[32], msg_ptr:u64, msg_len:u32, sig_ptr:u64[64]) -> ok:u8`
    - Canonical encodings enforced: `s < L`, `R` and `A` not small‑order; reject non‑canonical points/encodings; constant‑time.
- secp256k1 verify (low‑s, strict DER signature)
  - `SCALL_ZK_SECP256K1_VERIFY(pk_ptr:u64[33|65], msg32_ptr:u64[32], sig_ptr:u64[..]) -> ok:u8`
    - Require low‑s; reject non‑canonical DER; windowed MSM in circuit; constant‑time.
- Dilithium (optional, feature `pqc`)
  - `SCALL_ZK_MLDSA_VERIFY(param_id:u8, pk_ptr:u64[..], msg_ptr:u64, msg_len:u32, sig_ptr:u64[..]) -> ok:u8`
    - `param_id ∈ {0x2C,0x41,0x57}` for ML‑DSA‑44/65/87; NTT/Keccak helpers in gadget; constant‑time.

Transcript labels (lock for CI)
- All transcript challenges derive via Blake2b‑32 with ASCII labels + `\x00` suffix:
  - `IROHA_LC_V1 = "iroha:lc:v1\x00"`
  - `IROHA_LC_HEADERS_V1 = "iroha:lc:headers:v1\x00"`
  - `IROHA_LC_STATE_ROOTS_V1 = "iroha:lc:state_roots:v1\x00"`
  - `IROHA_LC_MSGS_V1 = "iroha:lc:msgs:v1\x00"`
  - `IROHA_LC_COMMIT_V1 = "iroha:lc:commitment:v1\x00"`

Rolling‑commitment format (normative; CI can golden‑test)
- Commitment `C = Hash32(IROHA_LC_COMMIT_V1 || chain_id_len:u16 || chain_id || start_height:u64_le || end_height:u64_le || Hh || Hs || Hm)`
  - `Hh = Hash32(IROHA_LC_HEADERS_V1 || concat(header_hash[i]))`
  - `Hs = Hash32(IROHA_LC_STATE_ROOTS_V1 || concat(state_root[i]))`
  - `Hm = Hash32(IROHA_LC_MSGS_V1 || concat(message_commit[i]))` (optional; empty if none)
  - `header_hash[i] = Hash32(header_bytes[i])` as in `iroha_crypto::Hash::new`
  - `state_root[i]` are 32‑byte roots from the headers
  - `message_commit[i]` are 32‑byte commitments to included bridge messages (if any)
- Endianness: all integers little‑endian; lengths as u16; concatenations unambiguous; no extra padding.

Merkle & domain tags (recap)
- Merkle leaf: `leaf = H(0x00 || leaf_bytes)`; inner: `H(0x01 || left || right)` (non‑commutative left||right). No other tags at the Merkle layer.
- Header signing domain: `"iroha:consensus_cert:header:v1\x00"` (unchanged).

### IVM Light‑Client Circuit Spec (commit‑cert + ICS‑23)

- Inputs
  - Public: `header_bytes`, `validator_set_hash`, `signer_bitmap`, `state_root`, `ics23_path`, `leaf_bytes`.
  - Private: `signatures[]`, `signer_pubkeys[]` (or references to a committed set), `header_hash` (derived inside circuit).
- Constraints (high level)
  1) Header hash: `H(header_bytes)` equals `header_hash` per data model (Blake2b‑32); parse `state_root` and `validator_set_hash` from `header_bytes`.
  2) Commit certificate: For each bit set in `signer_bitmap`, verify the corresponding signature on `header_hash` against `signer_pubkeys[i]`. Enforce ≥ quorum. Bind `signer_pubkeys[]` to `validator_set_hash` via a Merkle path or commitment.
  3) ICS‑23 inclusion: Recompute `leaf_hash = H(0x00 || leaf_bytes)` then fold siblings `(dir, sib)` to `root = H(0x01 || left || right)`. Constrain `root == state_root`.
  4) Domain tags and length prefixing follow the Merkle spec in this document. All hash invocations use the Iroha `Hash::new` sponge (Blake2b‑32) gadget.
- Recursion
  - Fold N proofs: expose `(prev_commitment, prev_height_end)` and verify the previous folded proof; then append `H[i..i+N]` constraints and update the rolling commitment (e.g., Fractal‑style transcript over `header_hashes` + `state_roots` + messages). Public output is the new `rolling_commitment` and end height.
- Batching & transcript
  - Use a STARK‑style Fiat–Shamir transcript over domain‑separated labels (`"iroha:lc:v1\x00"`) and inputs. Deterministic challenge derivation; no runtime randomness.
- Determinism
  - CPU/SIMD/GPU backends for hash/field ops must yield bit‑identical outputs. Disable non‑deterministic fast‑math and floating‑point.

### Bitcoin Optimistic Program: Parameters & Taproot Tree

- Parameters (suggested defaults)
  - `N_confirmations_deposit = 6` (mainnet), `challenge_window_K = 144` (≈ 1 day), `max_claim_amount_per_tx`, `fee_ceiling_sats`, `min_relay_fee`
  - Watchers: any party can challenge with a fraud proof; incentives set via `watcher_bounty` and `challenger_refund` fields.
- Taproot tree (sketch)
  - Key path: emergency pause (governance‑gated) — disabled by default.
  - Script leaves:
    1) Release path: `verify_ivm_commitment(proof_bytes, burn_tx_hash, amount, recipient)` AND `timelock >= now + K` (anyone can initiate; spend only after challenge window passes).
    2) Challenge path: `verify_fraud(proof_bytes, burn_tx_hash)` releases funds back to the origin (or a penalty bucket) immediately; closes claim.
  - The `verify_ivm_commitment` is an optimistic check: it verifies a succinct commitment (hash) to the IVM proof; the actual proof is verifiable off‑chain and enforced by the ability to present a fraud proof in the challenge path.
- State machine
  - Submit claim → start `K`-block challenge timer → if unchallenged, release on release path; if challenged with valid fraud proof, cancel claim (optionally slash claimant).
- Notes
  - This design targets a trustless, no‑custodian setup. A threshold‑signer fallback may exist under a non‑mainnet feature flag for testing only.

End‑to‑end timing (markdown diagram)
```
User            Iroha (bridge lane)             Bitcoin (Taproot program)       Watchers
 |  burn wBTC       |                                  |                           |
 |----------------->|                                  |                           |
 |                  | produce IVM proof + commit hash  |                           |
 |                  |------------------------------->  | claim(commit, amount,to)  |
 |                  |                                  |-------------------------->|
 |                  |                                  | start K‑block timer       |
 |                  |                                  |<--------------------------|
 |                  |                                  |    challenge? (fraud)     |
 |                  |                                  |<----- yes/no -----
 |                  |                                  | if no: after K, release   |
 |                  |                                  | if yes: cancel/slash      |
```

### Initial Supported Bridges (from day one)

- Bitcoin → Iroha (BTC into Iroha)
  - Pattern: Bitcoin SPV light client on Iroha with optional transparent‑ZK proof production for external consumers.
  - Finality: require N confirmations (configurable; e.g., N=6 mainnet). Verify PoW/difficulty chainwork and inclusion of deposit tx via Merkle path.
  - Deposit: user sends BTC to a bridge locking script (threshold MuSig2/FROST participants). Watchers submit SPV proof; Iroha mints `wBTC#btc` to the recipient.
  - Withdraw: burn `wBTC#btc` on Iroha; bridge signers release BTC from the locking script to the BTC destination. Phase‑1 uses threshold signing; future phases may adopt BitVM‑style proofs.
  - PQ posture: hash‑only SPV; threshold signing scheme can be PQ‑migrated later (ML‑DSA multisig) when wallets support it.

- Iroha ↔ Iroha
  - Pattern: commit certificate + ICS‑23 inclusion or transparent‑ZK rolling light client.
  - Finality: strict (Sumeragi) per commit certificate; no reorgs beyond proposal.
  - Asset flow: lock/mint and burn/unlock with canonical wrapped asset ids `w<ASSET>@<src_chain>`.

- Iroha ↔ TON
  - Pattern: TON light client on Iroha verifies masterchain signatures/finality and inclusion of shardchain messages via Merkle proofs; optional transparent‑ZK compression.
  - Finality: masterchain validator sigs + catchain rules; reorg window configured.
  - Asset flow: lock/mint burn/unlock with JDG attestations if jurisdictional rules apply.

- Iroha ↔ EVM (Ethereum/L2s)
  - Pattern: verify Iroha proofs in an EVM bridge contract via a SNARK‑wrapped transparent proof (~300k gas typical) initially, or native STARK if precompiles exist. On Iroha, verify Ethereum Beacon finality + receipt inclusion (or zk‑compressed) for inbound.
  - Finality: Beacon finalized checkpoints; require a minimum epoch delay; receipt Merkle (or Patricia) proof verification.
  - Asset flow: ERC‑20/721 canonical wrappers; lock/mint, burn/unlock; map to Iroha asset ids.

Lane‑common semantics (normative)
- Wrapped assets: `w<ASSET>@<src_chain>` definitions with metadata `origin_chain`, `origin_asset_id`, and `bridge_id`.
- Replay protection: per‑lane `(bridge_chain_id, nonce)`; height/epoch TTL windows; dedup at stateless phase.
- Reorg safety: per‑lane finality windows (Bitcoin N confs; Beacon finalized slots; TON masterchain finality).
- Events: `BridgeLock`, `BridgeMint`, `BridgeBurn`, `BridgeRelease`, `BridgeReceipt` with cross‑refs (uetr/msgid if applicable) and proof hashes.

Bridge roadmap (order)
- 1) Iroha↔Iroha (internal)
- 2) Bitcoin trustless lane (BitVM2‑style)
- 3) EVM adapter lane (initial SNARK wrapper OK on EVM)
- 4) TON lane

PQ posture (initial)
- It is acceptable that EVM and Bitcoin lanes are not PQ end‑to‑end at launch. Iroha‑side verification remains PQ‑capable (hash‑based), while counterparties MAY use non‑PQ wrappers (e.g., Groth16 on EVM) or threshold signatures. Plan migrations later.

Light‑Client Statements (normative per lane)
- Bitcoin → Iroha (SPV)
  - Constraints: `VerifyChainwork(headers[Nconf])`, `VerifyDifficultyAdjust(headers)`, `VerifyMerkle(tx_hash, merkle_path, block_merkle_root)`; `Nconf ≥ N_min`.
  - Finality/reorg bound: accept inclusion when depth ≥ Nconf; reorgs of depth < Nconf are handled by burn/proof invalidation rules.
- Iroha ↔ Iroha
  - Constraints: `VerifyCommit(header, commit_certificate, validator_set_hash)`; `ICS23Verify(path, leaf, header.state_root)`.
  - Finality: commit certificate is strict; reorgs past proposal are disallowed by protocol.
- Iroha ↔ TON
  - Constraints: `VerifyMasterSig(validator_set, signatures, header_hash)`; `VerifyShardMerkle(msg, proof, shard_root)`; link shard to master header.
  - Finality: masterchain finality rules; configured reorg window.
- Iroha ↔ EVM
  - Constraints (Iroha→EVM): verify Iroha commit + ICS‑23 via contract (SNARK‑wrapped transparent proof or precompile);
    (EVM→Iroha): `VerifyBeaconFinality(finality_proof)` and `VerifyReceipt(merkle_or_patricia, block_root)`.
  - Finality: Beacon finalized checkpoints with epoch delay; L2s: sequencer finality rules.

Norito Schemas (minimal)
```
struct WrappedAssetDef {
  origin_chain: bytes
  origin_asset_id: bytes
  bridge_id: bytes
}

struct BridgeReceipt {
  lane: bytes          // e.g., "btc→iroha", "iroha↔evm"
  direction: bytes     // "lock", "mint", "burn", "release"
  source_tx: [u8; 32]  // tx hash or message id
  dest_tx: option<[u8; 32]>
  proof_hash: [u8; 32]
  amount: u128
  asset_id: bytes      // canonical Iroha asset id
  recipient: bytes     // i105 account id / address
}

struct BridgeMessage {
  src_chain: bytes
  dst_chain: bytes
  payload: bytes         // Norito-encoded instruction or message
  inclusion_path: bytes  // ICS-23 or chain-specific inclusion path
  header_hash: [u8; 32]
}
```

Counterparty Verifier API (sketch)
- EVM (Solidity-ish):
  - `verifyIrohaProof(bytes header, bytes commitCert, bytes ics23Path, bytes leaf) returns (bool)`
  - `submitMessage(bytes msg, bytes proof) emits BridgeReceipt`
- TON (funC/TVM):
  - `op verify_master_sig(root, sigs, set) -> bool;`
  - `op verify_shard_proof(msg, proof, shard_root) -> bool;`

Example message (JSON-like shape; Norito on wire)
```

Bridge Events & Queries (feature `bridge`)
- When enabled, the `BridgeEvent` emits `Emitted(BridgeReceipt)` events per lane. Example filter (Norito-encoded) to subscribe to a specific lane:
```
BridgeEventFilter {
  id_matcher: Some(b"btcâiroha"),
  event_set: BridgeEventSet::Emitted,
}
```
- Basic example (CLI): `iroha bridge emit-receipt --lane "btc→iroha" --direction mint --source_tx 0x11.. --amount 1000 --asset_id wBTC#btc --recipient i105... --proof_hash 0x33..`

{
  "src_chain": "iroha-mainnet",
  "dst_chain": "evm-eth",
  "payload": { "Mint": { "asset": "wBTC#btc", "to": "<i105-account-id>", "amount": "100000" } },
  "inclusion_path": "0x...",
  "header_hash": "0x..."
}
```

---

## Data Availability (Mandatory Revision 4)

- Every proposal uses the signed revision-4 RS16 manifest and chunk geometry
  for its canonical body. A validator may Prepare-vote only after reconstructing,
  authenticating, durably storing, and deterministically validating that exact
  body; the resulting equal-vote PrepareQC is the availability certificate.
- Queue and payload caps are local resource bounds. They cannot disable DA,
  select another encoding, create a separate DA committee, or authorize commit
  without the exact locally available body.

---

## Fast Sync & Snapshot Distribution

- Snapshot streaming: distribute read‑only WSV snapshots addressable by chunk
  hashes, each accompanied by Merkle/ICS‑23 proofs bound to the advertised
  `state_root`. New nodes and light clients can sync quickly without full
  historical replay. Aligns with the read‑only WSV snapshot API.

## Multisig Transactions (MST)

Model
- Multisig transactions include a required threshold and a list/policy of
  signatories. Partial signatures are collected over time until the threshold
  is met or the tx expires.

Routing and queues
- After stateless checks, MST txs are routed to a dedicated multisig pool,
  separate from the regular mempool. The pool aggregates signatures arriving
  via additional submissions or off‑chain channels.
- When the threshold is satisfied before expiry, the fully signed tx moves to
  the regular mempool as “ready” and enters the normal scheduling/analysis
  flow. If expired, drop and emit an event.

Determinism and validation
- Stateless: verify each provided signature and policy well‑formedness.
- Stateful: once ready, process like any regular transaction; access‑set and
  conflict rules apply. The aggregation process itself is off the block path
  and has no effect on scheduling determinism.

Replay protection & policy hashing
- Canonical MST envelope hash includes: tx payload, threshold, ordered
  signatory set, and policy fields. Partial signatures are keyed by (envelope
  hash, signer). Duplicate or stale partials are ignored. Expiry removes the
  envelope and associated partials. Superseding envelopes (e.g., updated
  policy) use a new envelope hash; old ones are not merged implicitly.

Security and DoS
- Rate‑limit partial signature submissions; cap pending MST entries per
  account/domain. Provide clear telemetry and event logs for progress and
  expiry.

---

## Query Processing (Read‑Only)

Principles
- Queries must never block proposal/validation/commit. They execute in a
  separate lane against consistent WSV snapshots, typically at the latest
  committed height or a requested historical height (if available).

Execution model
- Use snapshot isolation; no locks that interfere with overlays or merges.
- Support pagination, streaming, and time/compute budgets per request.
- Provide index‑friendly search primitives and server‑side cursors that can be
  resumed by clients.

Integration
- Expose query APIs via Torii; requests are queued and executed by a bounded
  worker pool with per‑principal quotas and global concurrency limits.
  Results include the snapshot height to make staleness explicit.
- Optional caching of common query results is allowed but must be coherently
  invalidated on commit events.

Security and DoS
- Authenticate queries where required; rate‑limit per principal and per peer.
- Bound payload sizes and response windows; deny expensive unindexed scans by
  default or require elevated permissions.

## Triggers in the Parallel Flow

- Time‑based triggers (watcher‑driven): off‑chain watcher nodes monitor wall
  clocks (optionally aided by NTS) and generate a TriggerExec transaction near
  the scheduled time. Multiple watchers may submit duplicates; consensus
  deduplicates deterministically.
  - TriggerExec fields: `trigger_id`, `scheduled_time S`, `epsilon_early`,
    optional `epsilon_late`, optional `not_before_height`/`not_after_height`.
  - Validity in block B with header time `T(B)`: accept iff `Executed[trigger_id]`
    is false at start of B and `T(B) ≥ S − ε_early` (and if present,
    `T(B) ≤ S + ε_late`) and `H(B)` satisfies height bounds if provided.
  - Long gaps: if there is a real‑time gap between blocks, triggers due during
    the gap are accepted on the first subsequent block that satisfies
    `T(B) ≥ S − ε_early`.
  - Idempotence: on acceptance set `Executed[trigger_id] := {true, H(B), tx_hash}`;
    later duplicates are invalid.
- Data triggers: emitted by successful overlays; appended to the next epoch of
  the same block when bounded and safe, or deferred to height+1 as policy.
- Determinism: when multiple TriggerExec txs are valid in the same block,
  order them by `(scheduled_time S, trigger_id, emitter_tx_hash, local_index, tx_hash)`.

Bounds (normative)
- Per‑tx bounds: max triggers emitted per tx (configurable). If exceeded,
  excess triggers are deferred to height+1.
- Per‑block bounds: max total triggers and max aggregate trigger gas per block
  (configurable). Exceeding the bound defers remaining triggers to height+1.
- Publication: bounds are part of protocol configuration/versioning to ensure
  identical scheduling across nodes.

---

## Commit & Block Ordering

- Block tx order is the concatenation of epoch overlays in canonical merge
  order. This order is stable and used for hashing/signing, guaranteeing that
  all peers build identical blocks even though execution was parallel.
- Merkle roots: compute in parallel with a fixed reduction tree; chunking and
  concatenation order are canonical (e.g., lexicographic by tx hash).

Merkle Spec (normative)
- Consensus trees: a single hash function is used for all consensus Merkle
  trees (block payloads, results, state roots). For Iroha v2, this is
  `iroha_crypto::Hash` (Blake2b‑32), versioned under the protocol/VM.
- Domain separation and encoding:
  - Leaf hash = `Hash::new(0x00 || leaf_bytes)` where `leaf_bytes` are the
    canonical bytes of the leaf payload. If `leaf_bytes` are fixed‑length
    digests (e.g., `HashOf<TransactionEntrypoint>`), the prefix alone is
    sufficient; otherwise use length‑prefixing for variable‑length payloads.
  - Inner hash = `Hash::new(0x01 || left_hash || right_hash)`; both inputs are
    fixed‑length digests, so no additional length fields are necessary.
- No digest post‑processing: digest bytes are not modified beyond the
  definition of `Hash::new`. Type wrappers MUST NOT alter digest bits in a way
  that changes Merkle roots across nodes.
- Leaf payloads (blocks): `TransactionEntrypoint` and `TransactionResult`
  commitments computed from canonical Norito bytes and then wrapped as leaves
  via the leaf hash rule above.
- Pair order: non‑commutative `left||right`; no intra‑level sort.
- Odd leaf: promote lone left child unchanged (no self‑duplication/padding).
- Reduction: fixed, balanced reduction tree with canonical traversal; parallel
  building is allowed but MUST produce identical grouping and final root.
- Non‑consensus byte trees: byte‑Merkle helpers (e.g., IVM memory/registers)
  are explicitly non‑consensus and MUST NOT be used for block/tx/state roots.
  They use SHA‑256(left||right) with explicit domain tags where applicable.

Domain tags (consensus leaves)
- If additional semantic domain separation is desired, include a type‑specific
  domain tag inside `leaf_bytes` (e.g., Norito encodings already distinguish
  entrypoints vs results). The Merkle hash layer still applies the 0x00/0x01
  prefixes for leaf/inner as specified above.

Golden vectors (illustrative)
- Hash function: Blake2b‑32; roots and hashes are computed as `Hash::new(preimage)` with no additional post‑processing.
- Leaf payloads below are example canonical bytes for illustration only; real
  transactions/results use their Norito encodings.
  - Leaf1 (TxEntry): preimage = `0x00 || H(canonical(TX1))`
    - `leaf1 = 39E2385BD17D8EEB4E2D188E04462A667B63D05FD78AD83E8382448DA92586AF`
  - Leaf2 (TxEntry): preimage = `0x00 || H(canonical(TX2))`
    - `leaf2 = D4C9A98BD4B54A21D7B2FC3BAD664EE24744ECC1895FAA753A8C2781EB33464F`
  - Empty block: root = `None` (no leaves)
  - One‑leaf block: root = `leaf1`
    - `ROOT1 = 39E2385BD17D8EEB4E2D188E04462A667B63D05FD78AD83E8382448DA92586AF`
  - Two‑leaf block: root = `Hash::new(0x01 || leaf1 || leaf2)`
    - `ROOT2 = A81EF4E7656DEFA72CE9FF41A6117C7B437432B124BFCD9D06A3105486200C05`

State proofs (ICS‑23 style, normative)
- Key path encoding: state keys (domain/account/asset/metadata) map to bytes
  with domain separation tags to avoid ambiguity (e.g., `b"iroha:key:domain\0" || name`).
- Membership proof: ordered siblings (left/right) along the path from leaf to
  root using the consensus hash; verification recomputes parent = Hash(left||right)
  at each level. Deterministic and constant‑time.
- Non‑membership proof: includes neighbor leaf(s) and the branch necessary to
  prove the key’s exclusion in the canonical order.
- Golden vectors: publish membership and non‑membership proof vectors in
  `iroha_crypto` tests covering empty/odd/even/deep trees.

Canonical key normalization (normative)
- Normalize identifiers to NFC (or NFKC if chosen) and apply explicit
  case‑folding rules where applicable before Norito encoding. The mapping is
  fixed and versioned; inputs that differ only by normalization must resolve to
  identical canonical bytes. Document this in `iroha_data_model` and test
  round‑trips.

Parallel hashing
- Compute block payload roots, event log hashes, and optional WSV checkpoint
  digests in parallel using the same fixed reduction tree. Workers process
  disjoint chunks; the logical reduction shape and concatenation order are
  fixed, so parallel execution yields identical outputs.

---

## Block Header & Finality (Light Clients)

Header (consensus‑critical)
- prev_hash: hash of previous block header.
- height: block height.
- timestamp: informational metadata; MUST NOT influence execution ordering.
  Monotonicity: `T(B) ≥ T(parent(B))`. Implementations MAY bound forward jumps
  by `Δ_max` and reject if `T(B) − T(parent(B)) > Δ_max`.
- state_root: commitment to the WSV at end of block (consensus Merkle over
  state; see Merkle Spec). Used by state proofs.
- body_root: commitment to transaction entrypoints/results/events according to
  the Merkle Spec.
- receipts_root: commitment to per‑block receipts/events (for bridges/light
  clients to prove inclusion of events without scanning the body).
- validator_set_hash (or epoch id): commitment to the validator set for this
  block (enables light clients to track validator changes).
- consensus_certificate: finality proof by validators over this header (e.g.,
  threshold/aggregate signature). Aggregation is optional; if present, it
  reduces proof size for bridges and light clients.

Determinism & ordering
- Header fields do not alter the canonical proposal order; they are commitments
  and metadata only. All nodes compute identical roots (state/body/receipts)
  under the Merkle Spec.

Header (v2) struct (proposed)
- Norito‑encoded struct with fixed, deterministic field order; all integers are
  little‑endian; variable‑length fields use Norito length prefixes. Hashes are
  32‑byte Blake2b digests per `iroha_crypto::Hash`.

```text
struct BlockHeaderV2 {
  // Chain position
  height: u64                // NonZero; LE‑encoded
  prev_hash: Option<Hash>    // HashOf<BlockHeaderV2>, None for genesis

  // Commitments (see Merkle Spec)
  state_root: Hash           // Commitment to WSV at end of block
  body_root: Hash            // Commitment to tx entrypoints/results/events
  receipts_root: Option<Hash>// Commitment to receipts/events (optional)

  // Validator set & finality
  validator_set_hash: Hash   // Commitment to validator set (or epoch id)
  consensus_certificate: Bytes // Norito‑encoded certificate (e.g., threshold/
                              // aggregate signature over this header)

  // Metadata (non‑ordering)
  timestamp_ms: u64          // Unix time (ms), LE
  view_change_index: u32     // LE; used to resolve soft forks

  // Versioning
  protocol_version: u16      // Protocol gating for header/body/state semantics
}
```

Field encodings (normative)
- `u64`, `u32`, `u16`: little‑endian fixed‑width encodings.
- `Hash`: 32 bytes Blake2b‑32 as returned by `Hash::new(bytes)`; typed wrappers
  MUST NOT modify digest bytes.
- `Option<T>` and `Bytes`: Norito default encodings; `Option` uses a canonical
  tag+payload layout; `Bytes` are length‑prefixed.
- `consensus_certificate`: domain‑tagged Norito struct that carries the scheme
  id, signer set/epoch, and the signature bytes; must verify deterministically
  against the encoded `BlockHeaderV2` body.

Mapping to current data model
- Current `BlockHeader` (v1) fields: `height`, `prev_block_hash`, `merkle_root`
  (txs), `result_merkle_root` (results), `creation_time_ms`, `view_change_index`.
- V2 consolidates body commitments (`body_root`, `receipts_root`) and adds
  `state_root`, `validator_set_hash`, `consensus_certificate`, and
  `protocol_version`. Migration is protocol‑gated (see Upgrade & Rollout).

Consensus certificate (domain tags and Norito struct)
- Signing domain (normative):
  - Domain tag for header signing: `"iroha:consensus_cert:header:v1\x00"`.
  - Preimage to sign: `domain_tag || NoritoEncode(BlockHeaderV2_without_certificate)`.
    The `consensus_certificate` field itself is excluded from the signed body.
- Certificate schemes (examples; gated by features):
  - `ED25519_THRESHOLD` (id=1): threshold bundle of Ed25519 signatures with a
    canonical signer bitmap.
  - `BLS_AGG` (id=2): single aggregate BLS signature (if feature `bls` enabled).
- Minimal Norito struct (canonical field order):
  - `scheme_id: u16`       // 1=ED25519_THRESHOLD, 2=BLS_AGG (reserved: 0=UNKNOWN)
  - `epoch_id: u64`        // Leader/validator epoch id (LE)
  - `committee_hash: Hash` // Commitment to validator set for this block
  - `signer_bitmap: Option<Bytes>` // Present for threshold schemes; canonical
  - `signature: Bytes`     // Scheme‑specific signature encoding
- Verification (normative):
  - Recompute `preimage = domain_tag || NoritoEncode(header_without_certificate)`.
  - Verify `signature` against `preimage` under `scheme_id`, using `committee_hash`
    to obtain the validator set and `signer_bitmap` (if present) to determine
    which keys must be included.

ConsensusCertificateV1 (Norito type)
- Minimal canonical definition for on‑wire encoding (field order is normative):

```text
type ConsensusCertificateV1 = struct {
  scheme_id: u16           // LE; 1=ED25519_THRESHOLD, 2=BLS_AGG
  epoch_id: u64            // LE; validator/leader epoch id
  committee_hash: Hash     // 32‑byte Blake2b‑32 commitment to validator set
  signer_bitmap: Option<Bytes> // Threshold schemes: canonical bitset LSB‑first;
                               // None for aggregate schemes without bitmap
  signature: Bytes         // Scheme‑specific signature bytes
}
```

Notes
- Domain tag for header signing: `"iroha:consensus_cert:header:v1\x00"`.
- The header preimage excludes the `consensus_certificate` field itself.
- Implementations must validate that `signer_bitmap` (when present) selects a
  sufficient subset of keys in the committed validator set and that the
  `signature` verifies against the preimage under `scheme_id`.

---

## Data availability

The Sumeragi core disseminates the complete canonical block body to the frozen
committee. Every Prepare signer holds and deterministically validates that
body, and commit requires the exact `n - f` CommitQC together with the locally
authenticated canonical body (`sumeragi.md`).

There are no optional `da_*` headers, protocol-version gate, variable local
`N`/`k`, alternate Fountain/NMT scheme, sampling threshold, separate DA
committee, ACK certificate, or DA enable switch. Signed RS16 payload
availability is a first-release requirement that the core's full-body transport
does not integrate yet; see [`sumeragi_goals.md`](./sumeragi_goals.md).

---

## Networking & Admission Optimizations

- Gossip batching: aggregate admitted txs with size/time caps, compress with
  zstd (or Norito compressed form) where permitted.
- Operational only: time‑based gossip batching and compression policies do not
  influence consensus ordering; the proposal order is fixed by the leader and
  replayed deterministically by validators.
- Parallel signature verification and Norito decode on gossip receive path.
- Dedup by tx hash; enforce per‑peer rate limiting.
- Canonicalization: compute transaction canonical bytes and hash before any
  compression/transport encoding to prevent malleability issues.
- Early caps: enforce decoded/decompressed size limits before admission.
- Hotspot throttling: rate‑limit by key‑space hotspots (e.g., same asset or
  account) to reduce adversarial conflict inflation.

AOT artifact heat hints
- Gossip an optional “code‑heat” hint containing `(code_hash, artifact header
  fingerprint, use_count)` so peers can prefetch/compile hot programs
  opportunistically. Nodes still rebuild locally and perform translation
  validation; artifacts are never accepted off‑network. Hints are advisory and
  do not affect consensus.

---

## Memory, Caching, and Backpressure

- IvmCache tiers: (a) raw bytecode, (b) decoded ops, (c) immutable constants.
  Bounded by LRU keyed on code hash + feature set; eviction never changes
  outcomes, only performance.
- Overlay pool: cap concurrent `StateBlock` overlays; admission pauses forming
  larger epochs if overlays are exhausted.
- Backpressure: when epochs cannot form a large conflict‑free set (hotspots),
  fall back gracefully to smaller epochs; favour shorter latency over maximal
  packing.

WSV/cache alignment
- Overlay merges update WSV indexes and caches in lock‑step under a canonical
  ordering to avoid observer‑dependent views during block construction.

Overlay memory & crash recovery
- Copy‑on‑write: overlays are backed by a COW layer on top of a WSV snapshot.
  Hard caps: max concurrent overlays, max writes/overlay, and per‑tx memory.
- Atomic merge: apply merges as atomic batches with WAL/fsync semantics. On
  crash mid‑epoch, recover by replaying committed WAL entries and rebuilding
  the DAG; re‑execute the current epoch deterministically.
- Resource admission: reject or reschedule txs whose write‑sets or memory
  estimates exceed configured caps. Provide clear diagnostics and metrics.
  Per‑tx memory footprint MUST satisfy:
  `mem_est(tx) = base_mem + alpha * |write_set_bytes| + beta * |value_bytes|`
  with operator‑configurable `base_mem`, `alpha`, `beta`, and a hard ceiling
  `max_tx_memory`. Default: `base_mem=64KiB`, `alpha=1.0`, `beta=1.0`,
  `max_tx_memory=16MiB`.

Deterministic storage prefetch
- After access‑set derivation, issue bounded asynchronous prefetches for keys
  and ranges (RocksDB/KV) before the tx enters its epoch. Prefetch limits are
  configurable (max inflight ranges, total bytes). Use admission control to
  avoid cache thrash. Telemetry tracks hit rates and evictions. Prefetch order
  follows the canonical epoch/tx ordering to keep behavior deterministic.

---

## Determinism & Safety Notes

- All scheduling choices use stable, clock‑free orderings (proposal index →
  tx hash) with explicit tie‑breakers. No runtime measurements (e.g., work
  stealing) feed
  back into ordering.
- Acceleration flags are feature‑gated and never change bit‑exact results.
- Dry‑run access logging is purely local and read‑only; it cannot introduce
  side effects.

Feature flags
- `simd`, `cuda`, `metal`, `aot_simd`, `zk`, `zk_simd`, `zk_cuda`, `zk_metal`,
  `zk_prove`, `zk_prove_cuda`, `zk_prove_metal`, `zk_prove_simd`
  toggle acceleration paths. Curve/algorithm support is gated by explicit
  flags (e.g., `bls12_381`, `bn254`). All have deterministic fallbacks. Nodes
  on heterogeneous hardware must produce identical block/state outputs.

GPU offload
- Restrict GPU usage to integer/bitwise kernels with bit‑exact
  implementations (e.g., SHA‑2/Keccak/Blake2, Poseidon, MSM/pairings over
  finite fields). Prohibit floating‑point in consensus paths. Require golden
  vector conformance across scalar/SIMD/GPU backends. Any backend mismatch
  disables that GPU backend at runtime; scalar/SIMD fallbacks remain.

Determinism specification (normative, summary)
- No FP; explicit arithmetic semantics; fixed endianness and alignment;
  defined SIMD chunking/tail; stable reduction orders. Full details below.

---

## Determinism Specification (Normative)

- Arithmetic: default integer ops use mod‑2^64 wraparound; any opcode with
  non‑default semantics (e.g., saturating) is explicitly listed in the Opcode
  Reference. Bit‑operations are pure bitwise.
- Endianness: little‑endian for multi‑byte scalars on‑wire and in‑VM.
- Alignment/misalignment: misaligned loads/stores trap deterministically with
  `MisalignedAccess`. No undefined behavior; out‑of‑bounds and uninitialized
  reads are errors.
- SIMD policy: fixed 64‑byte block processing; scalar tail; no width‑dependent
  behavior. Parallel reductions use fixed traversal ordering.
- Floating‑point: disallowed in consensus code paths.
- Tooling: conformance tests and golden vectors validate all opcodes and hot
  kernels across architectures and backends.
- Canonical tie‑breakers: order within epochs and merges uses (proposal index
  → tx hash). No wall‑clock or arrival times affect ordering.

---

## Metering Specification (Normative)

- Hardware‑neutral: gas costs are derived from the scalar reference
  implementation, independent of wall‑clock time or acceleration.
- Opcode table: every IVM opcode defines a base gas cost and per‑byte/element
  increments; overflow checks and memory ops are accounted explicitly.
- Syscalls/precompiles: built‑ins and host syscalls specify fixed cost models
  (e.g., per key touched, per byte hashed); cryptographic intrinsics are
  priced as precompiles with published schedules.
- Enforcement: execution halts when gas exceeds the provided limit; partial
  effects are discarded with clear error codes.
- Reporting: nodes expose metrics for gas usage distributions and hit rates of
  accelerated vs scalar paths (acceleration does not change charged gas).

---

## Upgrade & Rollout Plan (Operational)

- Toolchain pinning & hermetic builds: pin Rust, LLVM, and critical flags
  (`target-cpu`, `target-feature`, LTO) and build via hermetic tooling (e.g.,
  Nix/Guix/Bazel with locked hashes). Publish a reproducibility manifest
  (compiler, linker, libc, flags, dep digests). Rebuild artifacts are
  byte‑reproducible.
- Capabilities & protocol version: on‑chain protocol/VM version gates behavior
  and feature negotiation; nodes refuse mismatched artifacts.
- Gas schedule version: gas pricing changes (e.g., SHA3BLOCK/AESDEC/ECDSAVERIFY)
  are introduced under a new protocol/VM version and activated via governance
  to preserve consensus; validators reject mixed schedules.
Derivation notes
- Gas constants are derived from the scalar reference implementation’s work
  (operation counts, byte costs) and validated by benchmarks. Any future
  changes require a gas schedule version bump and conformance updates.
- Translation validation: at startup/load, run deterministic differential
  traces for AOT kernels; fall back on mismatch.
- Rollout stages: shadow mode (disabled by default) → canary cohort → majority
  enablement. Provide kill‑switches per feature (`aot_simd`, `zk_*`, etc.).
- Rollback: disable features and clear AOT caches safely; interpreter path is
  always available.
- CI verification: build artifacts in two independent hermetic environments
  and assert byte identity and identical translation‑validation outcomes.

Initial defaults (proposed)
- Protocol version: `2` (draft). Default: disabled on mainnet; enabled on dev/test networks.
- VM version: `1.2` (draft) — clarifies determinism rules; no semantic opcode changes from 1.1. Activation via protocol v2 at `vm_activation_height`.
- Gas schedule: `v2` — updates `SHA3BLOCK=50`, `AESDEC=30`, `ECDSAVERIFY=1500` (others unchanged). Activation via `gas_schedule_v2_activation_height`.
- AOT_SIMD: default off on mainnet (shadow mode only) until post‑canary; on by default in dev/test.
- GPU backends (`cuda`, `metal`): default off (must be explicitly enabled by operators after conformance passes).
- ZK verify: on by default; ZK pre‑verify budgets off by default (operators opt‑in with `zk_preverify_*` settings).
- Triggers bounds: defaults `max_triggers_per_tx=8`, `max_triggers_per_block=1024`, `max_trigger_gas_fraction=0.10` (10% of block gas). Versioned under protocol v2.

Signature schemes (optional upgrades)
- Maintain Ed25519/ECDSA as defaults. Under a future protocol version, allow
  optional aggregate‑friendly keys (e.g., BLS12‑381) for block‑level
  aggregation in multisig/DAO workloads. Keep verification pricing hardware‑
  neutral and provide scalar fallbacks. Wallets may migrate per account.

---

## Threat Model (Selected Scenarios)

- Access‑set thrash: contracts attempt to alternate keys to defeat analysis.
  Mitigation: budgeted analysis, enforcement/quarantine, conservative sets.
- Overlay exhaustion: many large write‑sets to starve overlay pool.
  Mitigation: hard caps, admission refusal, and backpressure.
- Decode bombs: deeply nested Norito or oversized constants.
  Mitigation: early size caps, decode depth limits, and metering.
- SIMD edge cases: inputs targeting tail/unaligned behavior.
  Mitigation: fixed chunking, golden vectors, fuzzing.
- MEV pressure: policy ambiguity invites reorder incentives.
  Mitigation: explicit inclusion policy, aging, quotas, and transparency.

---

## Operational Limits (Caps)

- Max code size per tx; max decoded instruction count; max constant segment.
- Max overlays; max writes/overlay; per‑tx memory estimate cap.
- Dry‑run analysis budget (steps/CPU/time); verification/pre‑verify budgets.
- Mempool/MST limits per principal; gossip rate limits per peer.
- ZK proof size and public input count caps; allowed algorithms/curves.
## Implementation Plan (Phased)

Phase 1: Foundations
- Add `access_set()` to built‑in ISIs; extend Kotodama/IVM metadata to carry
  declared key sets where possible.
- Implement dry‑run read‑logging in IVM with step limits; integrate into a new
  analysis pass in `iroha_core`.
- Refactor executor boundary so built‑ins and IVM share the same execution API
  and event/trigger emission path.

Phase 2: Scheduler & Overlays
- Introduce conflict graph builder and epoch partitioner; ensure stable order
  across nodes. Provide a sequential fallback.
- Add overlay pool, deterministic worker mapping, and canonical merge.
- Validate determinism with differential tests on multi‑core vs single‑core.

Phase 3: Acceleration & Batching
- Batch signature verification; SIMD‑enable hot ops under existing feature
  flags (`simd`, `cuda`, `metal`, `aot_simd`), keeping CPU fallbacks.
- Parallel Merkle root computation; block hashing streamlining.

Phase 4: Triggers & Polishing
- Integrate trigger queues into the scheduler; bound concurrent trigger depth.
- Tune epoch sizing/limits; expose observability (epoch counts, conflicts) via
  telemetry.

- Validate Kotodama metadata emission and IVM pre‑decode cache stability.
- Add Norito round‑trip tests for any new/changed types and transaction forms.
- Document mempool selection policies and ensure leader reproducibility.

---

## Crate Integration Map

- `ivm`: interpreter, pre‑decoder, dry‑run access logging, vtable syscalls,
  AOT_SIMD kernel registry, feature detection and selection.
- `iroha_core`: scheduler, overlays/WSV integration, permissions, invariants,
  triggers, mempool and proposal assembly.
- `iroha_data_model`: Norito schemas, round‑trip tests, canonical key encoding
  for access‑set and conflict detection.
- `irohad`: node wiring, config for mempool policy, feature flags, and
  telemetry/observability endpoints.
- `iroha_cli`: submission path, developer tooling to preview access sets and
  analyze conflicts.
- `iroha_crypto`: curve/field backends, hash functions, and (optionally)
  portable ZK verification primitives selected via feature flags.
- On‑node proving (optional): background job manager in `irohad` and proving
  backends in `iroha_crypto` (or a dedicated `zk` crate if introduced later),
  exposing a read‑only WSV snapshot API for witness construction.
- Hermetic builds: reproducible AOT/SIMD artifacts produced via Nix/Guix
  definitions under `nix/` with pinned inputs; CI verifies byte identity.

---

## Security and DoS Considerations

- Bound compute, memory, code size, and syscall counts per tx; enforce
  exponential backoff on failing peers; rate‑limit gossip per peer.
- Use admission filters to reject malformed Norito payloads early; limit
  signature schemes and key sizes to supported sets.
- Ensure that conservative access‑set derivation cannot be abused to block
  parallelism indefinitely (detect hotspots; reschedule into smaller epochs).
- For ZK, employ algorithm allowlists and enforce per‑curve parameter bounds;
  disable unverifiable or experimental schemes by default.
- For on‑node proving, enforce quotas and per‑principal limits; require
  explicit permissions; default off. Bridge‑critical lanes should have strict
  admission controls and auditable logs.

---

## Testing Strategy

- Differential determinism tests: compare single‑thread vs multi‑thread runs
  and SIMD‑enabled vs scalar, ensuring identical state roots and block hashes.
- Norito round‑trip tests for all modified models and transaction forms.
- Trybuild/UI tests for any proc‑macros involved in metadata emission.
- Property‑based tests for conflict graph and epoch partitioner stability.
- ZK verification vectors across backends (scalar/SIMD/GPU), and concurrency
  tests to ensure scheduler stability when verifying many proofs in parallel.
- Prover lane soak tests under load to confirm it cannot starve the pipeline;
  snapshot pinning tests to ensure proofs bind to the intended state root.

ISO 20022 tests
- Positive/negative vectors for `pacs.008`, `pacs.002`, `camt.053`, `camt.056`, `pacs.004`, `camt.029` with schema/version checks and market‑practice profiles.
- IBAN/BIC validators: checksum/format; currency/decimal enforcement; structured party field normalization.
- Idempotency/replay: duplicate `(UETR, MsgId)` rejected deterministically; height TTL edge cases.
- JDG routing: BIC/ClearingSystemId → JurisdictionId mapping; attestation presence gates inclusion.
- Reason codes: pipeline rejections map to ISO external code sets and surface in events.

Deterministic proposal replay
- Given a serialized leader proposal, validators reconstruct identical conflict
  DAGs, epochs, and merges across machines. Compare state roots and block
  hashes to ensure determinism.

Observability & Metrics
- DAG size, epoch counts, overlay utilization, and merge times.
- Access‑set accuracy: declared vs observed (violations, quarantine rate).
- Acceleration path hit rates (scalar/SIMD/GPU) with determinism checks.
- Admission/gossip throttling stats; hotspot throttling activations.
- Optional per‑tx execution trace digests to aid differential debugging.
- Structured telemetry for enforcement: emit events with (contract/code hash,
  offending keys, lane used: abort vs quarantine) to aid developer feedback
  and operator tuning.
- AOT artifact validation: emit events when translation‑validation rejects an
  artifact (include code hash, compiler fingerprint, feature bitmap).
- DA metrics: fixed-RS16 manifest/chunk encoding, authenticated reconstruction,
  durable body-store, retransmission/fetch, and Prepare-gate outcomes.

Light clients & proofs
- Header chain conformance (validator set changes, certificates) and ICS‑23
  membership/non‑membership proof vectors (empty/odd/even/deep trees) verify
  deterministically.

Bridging
- End‑to‑end tests: “event X emitted in Iroha → verified on counterparty chain”
  with both light‑client and zk patterns (mock verifier acceptable initially).

Data Availability
- RS16 conformance: golden vectors cover the signed data/parity layout and
  authenticated manifest/chunk commitments.
- Erasure recovery reconstructs only at the signed data-shard threshold and
  rejects missing, mixed-subject, or unauthenticated chunks.
- Prepare gating requires the exact reconstructed body to cross the durable
  body-store and deterministic-validation boundaries; certified-body fetch and
  Set B retransmission recover packet loss without a separate DA certificate.

---

## Conformance Test Checklist

- IVM opcodes: golden vectors for every opcode (inputs/outputs/overflow) across x86‑64 and ARM64; identical results on scalar, SIMD, and (where applicable) GPU backends.
- Arithmetic semantics: explicit tests for mod‑2^N vs saturating behavior per opcode; wrap/saturate verified under boundary conditions.
- Endianness/alignment: misaligned loads/stores, byte‑order, and structure layout tests; no UB; out‑of‑bounds/uninitialized access rejected.
- SIMD chunking: 64‑byte block processing and scalar tails validated; unaligned/tail cases produce identical results to scalar path.
- AOT translation‑validation: for each AOT kernel, run deterministic traces vs interpreter at load; reject caches on mismatch.
- Toolchain reproducibility: rebuild AOT artifacts with pinned toolchains produce byte‑identical outputs; cache keys include VM version and compiler fingerprint.
- Access‑set enforcement: executions that touch keys outside derived sets are aborted or quarantined; violations counted and reported.
- Access analysis budgets: dry‑run time/step limits enforced; unknown sets routed to conservative/quarantine lanes.
- Scheduler determinism: identical conflict DAGs, epoch partitions, and merge order across runs/hardware; no dependence on runtime timing.
- Scheduler policy: fairness/aging/per‑sender quotas observed; starvation tests pass; backpressure triggers throttle admission/gossip as configured.
- Overlay limits: enforce caps on overlays, writes/overlay, and per‑tx memory; oversize txs rejected or rescheduled with diagnostics.
- Crash recovery: WAL/fsync atomic merges; simulated crash mid‑epoch recovers by rebuilding DAG and re‑executing current epoch deterministically.
- Metering neutrality: gas costs match scalar reference; acceleration paths do not change charged gas; gas limit halts with discarded side effects.
- Precompiles/crypto pricing: fixed schedules validated for hashing/crypto kernels; cost proportional to input size; denial of oversized inputs.
- ZK verification: cross‑backend vectors (scalar/SIMD/GPU) for the IVM transparent STARK‑style prover yield identical accept/reject; no pairing‑based algorithms required on Iroha. (External adapters may differ.)
- ZK pre‑verify budgets: optional stateless pre‑verify respects time/compute caps and never diverges from stateful verification outcome.
- VK governance: publish/update/revoke flows validated; on‑chain commitments match loaded keys; unauthorized circuits rejected.
- GPU offload: integer/bitwise kernels only; golden vectors match scalar; FP paths disabled in consensus; driver variance does not change results.
- GPU targets: CI builds for specified PTX/SM or Metal feature sets; flags disable fast‑math/FMA; memory model tests for no‑UB access patterns.
- Networking/admission: canonical hashing before compression; dedup works; early size/decode caps enforced; hotspot throttling activates under load.
- Mempool/MST: routing to mempool vs MST pool; threshold aggregation and expiry; duplicate/signature validation; promotion to ready set is deterministic.
  Replay protection: canonical MST envelope hash (payload+threshold+ordered signers+policy); partials keyed by (envelope, signer); expiry/supersedure rules.
  Vectors: equality/inequality cases (different signer order, policy tweaks) match expectations.
- Queries: snapshot isolation; correct height reported; budgets enforced; heavy queries do not impact block pipeline latency.
- Prover lane: snapshot root/height pinned in public inputs; quotas and priority classes enforced; kill‑switch disables safely; artifacts stored/evicted by policy.
- Serialization: Norito round‑trip for all modified types; canonical key encoding stable; compressed forms decode to identical canonical bytes.
- Upgrade gates: protocol/VM version negotiation works; unsupported features rejected; feature kill‑switches disable AOT/SIMD/ZK safely.
  Hermeticity: independent hermetic rebuilds produce byte‑identical AOT artifacts and identical translation‑validation outcomes.
- Cross‑arch CI: matrices for x86‑64 (SSE4.2/AVX2/AVX‑512) and ARM64 (NEON) with and without SIMD/AOT; determinism verified.
- Observability: metrics exported (DAG size, overlays, violations, acceleration hit rates); optional per‑tx trace digests are correct and bounded.

Additional consensus/determinism checks
- Range conflicts: partial overlaps (e.g., `asset/foo/*` vs `asset/foo/bar`) produce correct conflict edges; no parallel execution when unsafe.
- DAG scale: T=10k txs, avg K=8 keys, conflict‑graph build < 1s target; epoch partitioning stable.
- TTL/seq edges: `expires_at_height == current_height` is rejected while
  `expires_at_height == current_height + 1` remains eligible;
  duplicates/regressions on `(sender, seq)` are rejected at stateless validation.
- DA gating: mandatory signed RS16 geometry and exact-body availability are
  enforced before Prepare; missing or invalid manifest/chunk/body evidence is
  rejected deterministically.
- Triggers — boundary inclusion: craft blocks at `S−ε_early−1`, `S−ε_early`, `S+ε_late`, `S+ε_late+1`; verify validity decisions.
- Triggers — long gap: simulate real‑time gaps; first subsequent block admits due triggers exactly once based on header time.
- Triggers — duplicates: two watcher‑generated `trigger_id` txs; first valid wins; second rejected due to `Executed=true`.
- Timestamp jumps: enforce `T(B) ≥ T(parent)` and optional `T(B)−T(parent) ≤ Δ_max`; violations rejected deterministically.
- Mempool divergence: some validators miss the TriggerExec; block validity derives purely from header/state; all nodes agree post‑commit.

Signature batching & kernels
- ECC batch verify correctness vs per‑sig across batch sizes; deterministic
  coefficient derivation; divide‑and‑conquer attribution works.
- Dilithium: batched NTT/Keccak kernels produce identical results to scalar;
  same‑key matrix‑matrix path consistent; parameter sets (ML‑DSA‑44/65/87)
  covered under SIMD/GPU and scalar paths.

Prefetch & micro‑batches
- Prefetch hit/miss rates under load; no cache thrash beyond configured
  budgets; deterministic ordering. Micro‑batch tx caps enforced; gas equals
  sum; union access‑sets enforced.

AOT artifact hints
- Gossip heat hints do not alter determinism; local rebuild + translation
  validation occurs; ignoring hints does not change outcomes.

Quarantine lane
- Tests prove the lane never runs concurrently with other lanes, enforces
  `max_quarantine_txs_per_block` and per‑tx CPU/step/time limits, and aborts
  txs that still violate access sets.

---

## Node Configuration (Sketch)

- Proof creation:
  - enable: `zk_prove = false|true`
  - max_concurrency: integer
  - cpu_quota/mem_quota/gpu_quota per job and per lane
  - queue_limits: total jobs, per‑principal jobs
  - allowed_circuits: list of `(circuit_id, version, vk_hash)`
  - artifact_store: path, max_size, ttl
- Queries:
  - workers: count, per‑request time/row limits, per‑principal quotas
  - historical_snapshots: enable, retention policy
- Mempool/MST:
  - selection_policy, ttl, fee/priority weights
  - mst_pool_limits, expiry policy
- Batch verification (stateless):
  - ecc_min_batch_size: 64
  - ecc_max_batch_size: 2048
  - ecc_batch_max_wait_ms: 3
  - pqc_min_batch_size: 32
  - pqc_batch_max_wait_ms: 5
  - max_batches_inflight_per_scheme: 4
- Prefetch budgets (stateful prep):
  - prefetch_max_inflight_ranges: 1024
  - prefetch_max_bytes: "64MiB"
  - prefetch_per_tx_max_ranges: 32
  - prefetch_per_tx_max_bytes: "1MiB"
  - prefetch_ordering: "epoch_tx_order"
- Consensus data availability:
  - no local enable/disable or global scheme switch;
  - the signed chain context fixes the revision-4 RS16 manifest, validator set,
    quorum, and Set A/Set B assignment for each height;
  - local configuration may bound queues and payload size, but cannot change the
    wire geometry or bypass availability-certified commit.

---

## Glossary

- IVM: Iroha Virtual Machine executing `.to` bytecode.
- Kotodama: high‑level smart contract language targeting IVM.
- ISI: built‑in Instruction Set Items (host operations).
- WSV: World State View, canonical ledger state with indexes.
- Norito: serialization codec used for on‑wire data.
- AOT_SIMD: ahead‑of‑time specialization of SIMD‑accelerated kernels.
- ZK: zero‑knowledge proof systems (verification on‑chain).
- VK: verifying key used to verify a proof.
- SRS: structured reference string; proving/verifying parameters for some
  proof systems.

---

## Opcode and Gas Reference

IVM ABI V1 has one fixed-width instruction encoding. The canonical opcode set
is `crates/ivm_abi/src/instruction.rs`, executable semantics live in
`crates/ivm/src/ivm.rs`, and the consensus gas schedule is
`crates/ivm/src/gas.rs`. The synchronized human-readable table is
`crates/ivm/docs/opcodes.md`; this pipeline overview deliberately does not
duplicate those numeric definitions.

Deployable artifacts admit only opcodes accepted by
`instruction::wide::is_valid_opcode`. Reserved values have no gas entry and
trap if raw code bypasses artifact admission. RISC-V-like field names or
encodings elsewhere in the repository are implementation details, not an
alternate contract architecture. Hardware acceleration may change execution
time only: gas, output, traps, and state must remain byte-identical to the
scalar path.

## Appendix: Example Walkthrough

1) Leader receives 2,000 txs; stateless validation passes for 1,800.
2) Analysis derives access sets; 1,500 are conflict‑free enough to split into 6
   epochs for a 16‑core machine.
3) IVM decoding hits the cache for 70% of programs; others are decoded once.
4) Epoch 1 (300 txs) runs in parallel on 16 workers; overlays merge in canonical
   order; triggers enqueue 40 follow‑ups into Epoch 2.
5) After 6 epochs, the leader seals and signs the block; validators replay the
   same schedule deterministically and vote to commit.

The result is high throughput with identical final state and block content on
all honest nodes.
MVCC snapshots (evolution path)
- Promote overlays to first‑class MVCC snapshots with commit timestamps.
  Epochs execute on snapshots; commits produce new versions; overlays become
  delta logs. Benefits: cleaner conflict detection/merge, simpler crash
  recovery, improved I/O locality. This is a medium refactor aligned with the
  current overlay model.
CRDT/commutative precompiles (optional)
- Introduce carefully constrained precompiles for operations with true
  associativity/commutativity (e.g., counters, certain mints). The scheduler
  MAY combine writes within an epoch using a deterministic reduce. Each
  precompile MUST define algebraic laws, conflict rules, and gas. Disabled by
  default; gated by protocol version.


---

## KAGEMUSHA (offline wallet settlement)

The first release does not expose generic deposit, transfer, or withdrawal
instructions. The KAGEMUSHA V1 `TopUpKagemushaV1`, `TopUpKagemushaOrdinaryV1`
and `RedeemKagemushaV1` instructions, their Torii adapter, the reserve and the
hardware-bound recursion were deleted on 2026-10-05. The
[single implementation draft](kagemusha_single_design_proposal.md) §6 defines
load, unload and fee settlement; no ledger instruction implements it yet.
Device-to-device payments never touch consensus state.
