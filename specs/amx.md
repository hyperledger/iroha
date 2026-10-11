# AMX Execution & Operations Guide

**Status:** Current source-adjacent protocol and operations reference  
**Audience:** Core protocol, AMX/consensus engineers, SRE/Telemetry, SDK & Torii teams

## Summary

Atomic cross-data-space transactions (AMX) let a single submission touch
multiple data spaces (DS) while preserving deterministic failure codes and
confidentiality for private DS fragments. This reference records the
implemented timing controls, AXT proof and handle formats, error handling, and
operator evidence requirements alongside the Nexus design (`nexus.md`).

This guide describes transparent Native AMX/AXT. The governed, default-off
`AtomicPrivateSettlementV1` protocol is a separate path with fixed-shape private
notes, auditor-only capsule decryption, exact four-validator committees, and a
dedicated release-evidence contract; see `private_settlement.md`.

The proposed exact-consent `SettleAtomic` batch, its complete movement receipts,
and the matched confidential/transparent benchmark contract are specified in
[`native_atomic_settlement.md`](native_atomic_settlement.md). Native compilation
and network qualification remain pending for that candidate.

Key guarantees:

- Every AMX submission receives deterministic prepare/commit budgets; overruns abort with documented codes rather than hanging lanes.
- DA samples that miss the budget are logged as missing availability evidence and the transaction remains queued for the next slot instead of silently stalling throughput.
- Authenticated AXT proof envelopes bind proof bytes to a dataspace, its active
  manifest root, and the FastPQ V1 verifier metadata before the host caches the
  verification result for the configured slot window. Production
  `AXT_VERIFY_DS_PROOF` rejects every non-null standalone proof until it can bind
  the source roots and transaction set to authoritative finalized source state.
- IVM hosts derive per-dataspace AXT policy and issuer identity from committed Space Directory state. A handle must carry a valid domain-separated V1 signature from the single-key UAID account bound to the active `(dataspace, manifest root)`, target the catalog lane, use the exact authorization generation and next counter from the permanent per-dataspace ratchet, and satisfy expiry. Missing, ambiguous, multisignature, or inconsistent issuer indexes fail closed before FASTPQ verification.
- Slot expiry uses `nexus.axt.slot_length_ms` (default `1` ms, validated between `1` ms and `600_000` ms) plus the bounded `nexus.axt.max_clock_skew_ms` (default `0` ms, capped by the slot length and `60_000` ms). Hosts compute `current_slot = block.creation_time_ms / slot_length_ms`, apply the skew allowance to proof and handle expiry checks, and reject handles that advertise a larger skew than the configured limit.
- Proof cache TTL bounds reuse: `nexus.axt.proof_cache_ttl_slots` (default `1`, validated `1`–`64`) limits how long accepted or rejected proofs stay in the host cache; entries drop once the TTL window or the proof’s `expiry_slot` elapses so replay protection stays bounded.
- The issuer handle signature authenticates capability/asset identity but not
  `RemoteSpendIntent`, proof bytes, or effective amount. Those facts still rely
  on FASTPQ's roughly 32-bit binding ceiling, so handle-backed remote spend is
  not release-qualified until the binding is at least 128 bits or an independent
  finalized source-state statement authenticates the exact facts.
- Replay ledger retention: `nexus.axt.replay_retention_slots` (default `128`, validated `1`–`4_096`) sets the minimum slot window of handle-usage history retained for replay rejection across peers/restarts; align it with the longest handle-validity window you expect operators to issue. The ledger is persisted in WSV, hydrated on startup, and pruned deterministically once both the retention window and handle expiry have elapsed (whichever is later). A block carries the deterministic post-state policy snapshot. Kura idempotently applies post-snapshot envelopes without advancing counters or cumulative charges a second time; only replay from genesis reconstructs the complete ledger, and a checkpoint restore requires its authenticated pre-snapshot ledger.
- Debugging cache status: Torii exposes `/v1/debug/axt/cache` (telemetry/developer gate) to return the current AXT policy snapshot version, the most recent reject (lane/reason/version), cached proofs (dataspace/status/manifest root/slots), and reject hints (`active_handle_era`/`next_handle_counter`). Use this endpoint to confirm slot/manifest rotations are reflected in cache state and to refresh handles deterministically during troubleshooting.

## Slot Timing Model

### Timeline

```text
t=0ms           70ms             300ms              600ms       840ms    1000ms
│─────────┬───────────────┬───────────────────┬──────────────┬──────────┬────────│
│         │               │                   │              │          │        │
│  Mempool│Proof build + DA│Consensus PREP/COM │ IVM/AMX exec │Settlement│ Guard  │
│  ingest │sample (≤300ms) │(≤300ms)           │(≤250ms)      │(≤40ms)   │(≤40ms) │
```

- The operational budget is mempool 70 ms, DA commit ≤300 ms, consensus 300 ms,
  IVM/AMX 250 ms, settlement 40 ms, and a 40 ms guard.
- Transactions breaching the DA window are logged as missing availability evidence and retried in the next slot; all other breaches surface codes such as `AMX_TIMEOUT` or `SETTLEMENT_ROUTER_UNAVAILABLE`.
- The guard slice absorbs telemetry export and final auditing so the slot still closes at 1 s even if exporters lag briefly.
- Configuration tips for genesis or an explicit chain-boundary migration: defaults keep expiry strict (`slot_length_ms = 1`, `max_clock_skew_ms = 0`). For a 1 s cadence set `slot_length_ms = 1_000` and `max_clock_skew_ms = 250`; for a 2 s cadence use `slot_length_ms = 2_000` and `max_clock_skew_ms = 500`. Values outside the validated window (`1`–`600_000` ms or `max_clock_skew_ms` greater than the slot length/`60_000` ms) are rejected at config-parse time, and advertised handle skew must stay within the configured bound. Do not reinterpret existing handle expiry slots by changing these values on a live chain.

### Cross-DS swim lane

```text
Client        DS A (public)        DS B (private)        Nexus Lane        Settlement
  │ submit tx │                     │                     │                 │
  │──────────▶│ prepare fragment    │                     │                 │
  │           │ proof + DA part     │ prepare fragment    │                 │
  │           │───────────────┬────▶│ proof + DA part     │                 │
  │           │               │     │─────────────┬──────▶│ Merge proofs    │
  │           │               │     │             │       │ verify proof/DA │
  │           │               │     │             │       │────────┬────────▶ apply
  │◀──────────│ result + code │◀────│ result + code │◀────│ outcome│          receipt
```

Each DS fragment must finish its 30 ms prepare window before the lane assembles the slot. Missing proofs stay in the mempool for the next slot rather than blocking peers.

### Instrumentation checklist

| Metric / Trace | Source | SLO / Alert | Notes |
|----------------|--------|-------------|-------|
| `iroha_slot_duration_ms` (histogram) / `iroha_slot_duration_ms_latest` (gauge) | `iroha_telemetry` | p95 ≤ 1000 ms | Capture with the AXT acceptance evidence. |
| `iroha_da_quorum_ratio` | `iroha_telemetry` (commit hook) | ≥0.95 per 30 min window | Updated for every committed block after mandatory signed-RS16 admission. |
| `iroha_amx_prepare_ms` | IVM host | p95 ≤ 30 ms per DS scope | Drives `AMX_TIMEOUT` aborts. |
| `iroha_amx_commit_ms` | IVM host | p95 ≤ 40 ms per DS scope | Covers delta merge + trigger execution. |
| `iroha_ivm_exec_ms` | IVM host | Alert if >250 ms per lane | Mirrors the IVM overlay chunk execution window. |
| `iroha_amx_abort_total{stage}` | Executor | Alert if >0.05 aborts/slot or sustained single-stage spikes | Stage labels: `prepare`, `exec`, `commit`. |
| `iroha_amx_lock_conflicts_total` | AMX scheduler | Alert if >0.1 conflicts/slot | Indicates inaccurate R/W sets. |
| `iroha_axt_policy_reject_total{lane,reason}` | IVM host | Watch for spikes | Distinguishes manifest/lane/era/sub_nonce/expiry rejects. |
| `iroha_axt_policy_snapshot_cache_events_total{event}` | IVM host | Expect cache_miss only on startup/manifest change | Sustained misses indicate stale policy hydration. |
| `iroha_axt_proof_cache_events_total{event}` | IVM host | Expect mostly `hit`/`miss` | `reject`/`expired` spikes usually indicate manifest drift or stale proofs. |
| `iroha_axt_proof_cache_state{dsid,status,manifest_root_hex,verified_slot}` | IVM host | Inspect cached proofs | Gauge value is expiry_slot (with skew applied) for the cached proof. |

`/v1/debug/axt/cache` mirrors the `iroha_axt_proof_cache_state` gauge with a per-dataspace snapshot (status, manifest root, verified/expiry slots) for operators.

`iroha_amx_commit_ms` and `iroha_ivm_exec_ms` share the same latency buckets as
`iroha_amx_prepare_ms`. The abort counter tags every rejection with the lane id
and stage (`prepare` = overlay build/validation, `exec` = IVM chunk execution,
`commit` = delta merge + trigger replay) so telemetry can highlight whether
contention comes from read/write mismatches or post-state merges.

Operators archive these metrics with the corresponding slot acceptance
evidence.

### AXT golden fixtures

Norito fixtures for the descriptor, signed handle, policy snapshot, two-dimensional authorization counter, and incarnation-bound replay key live at `crates/ivm_abi/tests/fixtures/axt_golden.rs`, with a regeneration helper in `crates/ivm_abi/tests/axt_policy_vectors.rs` (`print_golden_vectors`). CoreHost consumes the applicable descriptor/handle/policy fields in `core_host_enforces_fixture_snapshot_fields` (`crates/ivm/tests/core_host_policy.rs`) to exercise lane binding, manifest root matching, expiry freshness, exact generation/sub-nonce matching, and missing-dataspace rejections.
- A multi-dataspace JSON fixture (`crates/iroha_data_model/tests/fixtures/axt_descriptor_multi_ds.json`) pins the descriptor/touch schema, canonical header-framed Norito bytes for the data-model type, and the Poseidon binding derived from the bare Norito payload (`compute_descriptor_binding`). Poseidon byte packing appends `0x01` and zero-pads to an eight-byte boundary before field-sponge padding. The `axt_descriptor_fixture` test guards the encoded bytes, and SDKs can use `AxtDescriptorBuilder::builder` plus `TouchManifest::from_read_write` to assemble deterministic samples for docs/SDKs.

### Lane catalog mapping and manifests

- AXT policy snapshots are built from the Space Directory manifest set, lane catalog, and permanent per-dataspace handle-counter records. Each dataspace is mapped to its configured lane; active manifests contribute the manifest hash and activation epoch, while both `active_handle_era` and `next_handle_counter` are projected from the non-resetting authorization ratchet. If one or more effective manifest, issuer key, lane/incarnation, active/placeholder, removal, or reactivation transitions affect a dataspace in one block, the durable authorization generation and counter advance exactly once for that dataspace at the block boundary. The sticky `BlockResult.axt_transitioned_dataspaces` set makes transient A→B→A changes visible to validation and deterministic replay. Handles from an earlier generation therefore remain invalid even when they were pre-signed with a future sub-nonce. Generation zero is the absent/inactive sentinel; the first active generation is at least one. A never-authorized UAID binding without an active manifest may emit a zeroed manifest root, era, and counter; if a ratchet already exists, the placeholder must carry its exact retained generation and next value.
- `current_slot` is derived from the exact candidate header timestamp during execution. Committed query/IVM views use a cached header only when its hash equals the current WSV tip, otherwise an authenticated matching-tip snapshot anchor; a non-genesis view without either source fails closed and never substitutes block height.
- `slot_length_ms` and `max_clock_skew_ms` are bound by the execution-policy hash. A coordinated timing-policy change is a state-format hard cut that must migrate the policy and invalidate every outstanding handle rather than reinterpret existing expiry slots.
- Telemetry surfaces the hydrated snapshot as `iroha_axt_policy_snapshot_version` (lower 64 bits of the Norito-encoded snapshot hash) and cache events via `iroha_axt_policy_snapshot_cache_events_total{event=cache_hit|cache_miss}`. Reject counters use the labels `lane`, `manifest`, `era`, `sub_nonce`, and `expiry` so operators can immediately see which field blocked a handle.

### Cross-dataspace composability checklist

- Confirm every dataspace listed in the Space Directory has a lane entry and an active manifest; rotation should refresh bindings and manifest roots before issuing new handles. Zeroed roots mean handles will stay denied until manifests are present, and hosts/block validation now reject handles that present zeroed manifest roots.
- On startup and after Space Directory changes, expect one `cache_miss` followed by steady `cache_hit` events on the policy snapshot metric; a sustained miss rate points to a stale or missing manifest feed.
- When a handle is rejected, look at `iroha_axt_policy_reject_total{lane,reason}` and the snapshot version to decide whether to request a refreshed handle (`expiry`/`era`/`sub_nonce`) or to repair the lane/manifest binding (`lane`/`manifest`). The Torii debug endpoint `/v1/debug/axt/cache` also returns `reject_hints` with `dataspace`, `target_lane`, `active_handle_era`, and `next_handle_counter` so operators can refresh handles deterministically after a policy bump.

### Remote spend availability

Production block, State and Core host admission reject every nonempty remote
spend before mutation. `AxtEnvelopeRecord.spends` carries only signed
`AxtAnchoredSpendV1` values; the earlier handle-fragment transport and IVM
handle accumulator have been removed. The signed shape binds a claimed
finalized source anchor, successful-execution receipt, exact ordered transfer
occurrence, intent, proof, amount and fresh nonce. These claims do not
authenticate source success. No SDK should submit a remote spend until
State-owned complete roots, verified source execution and transfer occurrence,
fresh issuer authorization, and durable atomic nonce/budget/effect consumption
are connected and qualified together.

## Operator Expectations

1. **Pre-slot readiness**
   - Ensure DA attester pools per profile (A=12, B=9, C=7) are healthy; attester churn is recorded in the Space Directory snapshot for the slot.
   - Validate `iroha_amx_prepare_ms` is below budget on representative runners before enabling new workload mixes.

2. **In-slot monitoring**
   - Alert on missing-availability spikes (>5% for two consecutive slots) and on `AMX_TIMEOUT` because both indicate missed budgets.
   - Track `iroha_axt_proof_cache_events_total{event}` and
     `iroha_axt_proof_cache_state` to verify cache hit, expiry, rejection, and
     eviction behaviour.

3. **Evidence capture**
   - Attach DA receipt sets, AMX prepare histograms, and AXT proof-cache
     snapshots to the run artefact bundle.
   - Record chaos drill outputs in `ops/drill-log.md` whenever DA jitter, oracle stalls, or buffer depletion tests run.

4. **Runbook maintenance**
   - Update the Android/Swift SDK runbooks whenever AMX error codes or overrides change so client teams inherit the deterministic failure semantics.
   - Keep configuration snippets in sync with the canonical `nexus.axt`
     parameters documented in `references/configuration.md`.

## Telemetry & Troubleshooting

### Telemetry quick reference

| Source | What to capture | Command / Path | Evidence expectations |
|--------|-----------------|----------------|-----------------------|
| Prometheus (`iroha_telemetry`) | Slot and AMX SLOs: `iroha_slot_duration_ms`, `iroha_amx_prepare_ms`, `iroha_amx_commit_ms`, `iroha_da_quorum_ratio`, `iroha_amx_abort_total{stage}` | Scrape `https://$TORII/metrics` or export from the dashboards described in `telemetry.md`. | Attach histogram snapshots and alert history to the run bundle so auditors can see p95/p99 values and alert states. |
| Sumeragi status and transport metrics | Authenticated revision-4 reducer state plus node-local transport pressure metrics such as `sumeragi_bg_post_queue_depth`, `sumeragi_dropped_block_messages_total`, and `p2p_queue_dropped_total`. | Capture `GET /v1/sumeragi/status` with an operator signature and scrape `/metrics`. | Store the signed height context, durable commit, queue state, and timestamped metrics with the incident bundle. Node-local metrics are operational observations, not consensus evidence. |
| AXT proof cache | `iroha_axt_proof_cache_events_total{event}` and `iroha_axt_proof_cache_state{dsid,status,manifest_root_hex,verified_slot}` | Scrape the Torii metrics endpoint and inspect `GET /v1/debug/axt/cache` when the telemetry/developer gate is enabled. | Capture the policy snapshot version, cache state, and last rejection without retaining proof payloads. |

### Troubleshooting playbook

| Symptom | Inspect first | Recommended remediation |
|---------|---------------|--------------------------|
| `iroha_slot_duration_ms` p95 creeps above 1 000 ms | Prometheus export from `/metrics`, authenticated Sumeragi status, consensus logs, and the preceding accepted run. | Lower AMX batch sizes or correct the diagnosed transport/capacity bottleneck, then repeat the acceptance workload and capture fresh status and metrics. |
| Missing availability spike | Transport ingress/drop metrics, authenticated Sumeragi status, consensus logs, and attester health dashboards. | Repair the unhealthy validator or transport path and attach updated status and metrics once availability recovers. |
| Frequent `PVO_MISSING_OR_EXPIRED` in receipts | AXT proof-cache state, policy snapshot version, and the issuer’s proof/handle generation logs. | Regenerate the expired proof or handle and ensure the client refreshes it before `expiry_slot`. |
| Repeated `AMX_LOCK_CONFLICT` or `AMX_TIMEOUT` | `iroha_amx_lock_conflicts_total`, `iroha_amx_prepare_ms`, and the affected transaction manifests. | Re-run the Norito static analyzer, correct the read/write selectors (or split the batch), and publish the updated manifest fixtures so the conflict counter returns to baseline. |
| `SETTLEMENT_ROUTER_UNAVAILABLE` alerts | Settlement router logs (`../docs/settlement-router.md`), treasury buffer dashboards, and the affected receipts. | Top up XOR buffers or flip the lane to XOR-only mode, document the treasury action, and rerun the slot acceptance test to prove settlement resumed. |

### AXT rejection signals

- Reason codes are captured as `AxtRejectReason` (`lane`, `manifest`, `era`, `sub_nonce`, `expiry`, `missing_policy`, `policy_denied`, `proof`, `budget`, `replay_cache`, `descriptor`, `duplicate`). Block validation now surfaces `AxtEnvelopeValidationFailed { message, reason, snapshot_version }`, so incidents can pin the rejection to a specific policy snapshot.
- `/v1/debug/axt/cache` returns `{ policy_snapshot_version, last_reject, cache, hints }`, where `last_reject` carries the lane/reason/version of the most recent host rejection and `hints` provide exact `active_handle_era`/`next_handle_counter` guidance alongside the cached proof state.
- Alert template: page when `iroha_axt_policy_reject_total{reason="manifest"}` or `{reason="expiry"}` spikes over a 5‑minute window, attach the `last_reject` snapshot + `policy_snapshot_version` from the Torii debug endpoint to the incident, and use the hint payload to request refreshed handles before retrying.

## AXT Proof Envelopes

### Structure

The canonical data-model types live in
`crates/iroha_data_model/src/nexus/axt.rs`:

| Type / field | Contract |
|--------------|----------|
| `ProofBlob.payload` | Canonical Norito bytes for an `AxtProofEnvelope`; empty payloads and payloads larger than 2 MiB are rejected before envelope decoding. |
| `ProofBlob.expiry_slot` | Outer mirror of the proof-bound expiry. `None` is the authenticated no-expiry value; verifiers require an exact match before applying freshness policy. |
| `AxtProofEnvelope.dsid` | Dataspace whose policy validates the proof. |
| `AxtProofEnvelope.manifest_root` | Non-zero outer mirror of the exact 32-byte `axt_fastpq_manifest_root_v1` proof metadata and, where required by admission, the active Space Directory policy root. |
| `AxtProofEnvelope.da_commitment` | Outer mirror of the proof-bound optional DA commitment. `axt_fastpq_da_commitment_v1` is always present as 33 bytes: `0 || 32*0` for `None`, or `1 || digest` for `Some(digest)`. |
| `AxtProofEnvelope.proof` | Non-empty backend proof bytes, limited to 1 MiB before FastPQ payload decoding or verification. |
| `AxtProofEnvelope.fastpq_binding` | Required FastPQ V1 source, claim, witness, policy, effect, verifier, and target-dataspace binding. |
| `AxtFastpqBinding.remote_spend_intent_commitments` | Canonical strictly ordered, duplicate-free set of at most 65,536 V1 commitments. Each commitment covers the exact authenticated handle replay key (dataspace, asset-definition incarnation, descriptor binding, era, sub-nonce, and target lane), exact `AssetDefinitionId`, `transfer` operation, canonical `from`/`to` accounts, and effective `Quantity`. Generic proofs may leave the set empty; every proof consumed by final signed-spend admission must contain and consume exactly one matching claim. |
| `axt_fastpq_source_transfer_occurrences_v1` | Canonical Norito proof-trace metadata containing one `AxtSourceTransferOccurrenceV1` per remote-spend claim and ordered transfer delta. Each occurrence commits the claimed successful-source-receipt digest, exact source transaction index, transcript/delta coordinate and pair ordinal, full public transfer facts (including before/after balances), and the exact handle/intent claim. The anchored FASTPQ verifier requires the metadata and checks the index against canonical finalized wires. |
| `committed_amount` | Optional non-zero scalar that must exactly match the canonical 16-byte little-endian `u128` in `axt_fastpq_committed_amount_v1` metadata inserted before the FastPQ batch seal and proof are generated. Missing or mismatched proof-bound metadata is rejected. |
| `amount_commitment` | Optional deterministic envelope/amount consistency digest. It does not hide or authenticate an amount, and recomputing it cannot replace the proof-bound `committed_amount`. |

V1 handle admission requires a non-zero clear `RemoteSpendIntent.op.amount`.
The host, persisted-fragment conversion, and block amount resolver reject a
redacted (`None`) amount even if the proof envelope carries a public
`committed_amount` scalar. That scalar is visible to every verifier and cannot
implement a private spend. The private-amount path remains a release blocker
until the proof binds a confidential value, conservation, and the authenticated
budget comparison without exposing the amount. A structurally signed anchored
spend draft or matching envelope digest alone does not authorize it.

The final anchored-spend wire is `AxtAnchoredSpendV1`. Its
`AxtFinalizedSpendAnchorV1` binds the genesis-derived network identity and exact
genesis hash, source dataspace, lane and lane incarnation, finalized height,
canonical block header, commit QC, ordered committee, pre/post state roots,
ordered transaction-set digest, and signed RS16 DA-manifest digest. The fresh
issuer signature additionally binds the complete reusable handle, exact
`RemoteSpendIntent`, canonical proof blob, clear or committed amount fields,
claimed successful-execution receipt digest, full ordered transfer occurrence,
expiry, and a non-zero `AxtSpendNonceV1`. The model checks that the claimed
receipt selects this anchor and source execution, and that the occurrence's
claim appears in the proof binding. These checks cannot authenticate source
success or the transfer against finalized State. The nonce replay key includes the full
issuer context, so key/policy, asset-incarnation, network, and dataspace changes
cannot alias an earlier spend. A submitted anchor is only a selector: block and
host admission must exact-match it to the immutable WSV record before checking
both issuer signatures. Until that shared resolver and durable nonce ledger are
wired into all admission paths, handle-backed authorization remains
release-blocked.

The ordered transaction-set digest is computed by the shared
`axt_ordered_transaction_set_digest_v1` over each complete
`TransactionEntrypoint::encode_wire_v1()` in execution order: external entries
first, then time-trigger entries. Its preimage is
`iroha:axt:ordered-transaction-wire-set:v1\0 || count_u64_le ||
each(wire_length_u64_le || exact_wire_bytes)`. The complete wires retain every
authorization proof. Sealed reveals retain their outer canonical wire here;
their separate execution identity is derived from that wire when checking the
exact source claim. Sorting execution hashes or replacing this commitment with
a transcript-derived set is invalid. Core's two execution pipelines use this
shared contract, and FASTPQ jobs reject a missing block-owned commitment.

Ordered-wire membership does not establish successful execution or authenticate
state updates. The immutable source resolver must also verify the finalized
result and exact transfer facts for the selected entry. Current per-bundle
transfer trees cover touched balances; they cannot replace authoritative WSV
roots in an anchor. Anchored admission remains unavailable until the proof
witnesses establish the required membership and updates against those roots.

`AxtSourceSuccessReceiptV1` gives the finalized State owner a claimed receipt
preimage: exact anchor digest, source execution commitment and transaction
index, post-transaction state root, and complete effect-set digest. The
proof-bound occurrence references its digest and selects one ordered transfer
delta. Altering its coordinate, claim, or full public transfer facts fails
FASTPQ verification; changing the receipt digest changes the sealed proof
trace. These are binding checks only. Neither constructing the receipt value
nor verifying the FASTPQ transcript proves that the source transaction
succeeded or that the claimed root and effects belong to authoritative State.

The signed AXT V1 wire directly carries the claimed source receipt and exact
occurrence in addition to the proof-trace metadata. The operational envelope
uses only `AxtAnchoredSpendV1` values. State and block replay refuse every
nonempty spend set before changing replay, budget, policy, or effects because
the finalized source resolver does not yet exist. TODO: State must resolve the
successful receipt and complete authenticated roots, then Core must apply the
fresh issuer nonce, budget, and effects atomically through one admission path.
Core maps local FASTPQ allocation failure to operational deferral in the block,
Core host, lane relay and fee sponsor vault consumers. The current-source
tests and a fresh compiler-captured schema baseline remain required for the
changed signed wire.

The proof metadata also always contains `axt_fastpq_expiry_slot_v1` as an
eight-byte little-endian `u64`, where zero means authenticated `None` and any
non-zero value means `Some(slot)`. The manifest and DA keys are required even
when DA is absent. Their exact canonical values, the optional committed amount,
and the expiry are inserted before the batch seal and proof are generated.
FastPQ first encodes the complete metadata map with canonical Norito default
flags. It computes raw Blake2b-256 over
`u64_le(domain_len) || domain || u64_le(metadata_len) || metadata_bytes`, where
`domain` is `fastpq:v1:metadata-commitment:blake2b-256` and both lengths count
bytes. The 256-bit digest is split into eight exact little-endian `u32` trace
limbs, and the AIR constrains every limb to remain stable.

The V1 Norito JSON layouts are closed and exact. Every nullable proof, handle,
effect, spend, and rejection-context field is present as either its value or an
explicit `null`; collections are present even when empty. Omitted fields,
unknown fields, and shortened pre-release binary layouts are malformed rather
than requests to synthesize defaults.

This is a first-release proof-format hard cut. Proofs and snapshots generated
without the required metadata, or with the retired single-field metadata
projection, are invalid and must be regenerated rather than relabelled.
`AssetHandleDraft.asset_definition_id`, `AssetHandle.asset_definition_id`,
`SpendOp.asset_definition_id`, and the claim's full `AxtHandleReplayKey` are
required wire fields. Every persisted `AxtReplayRecord` also carries the exact
normalized `AxtHandleBudgetKey` derived from the authenticated handle; replay
records from the earlier compact-key-only layout are invalid.
`AxtHandleIssuerContextV1.asset_definition_incarnation`
is also required and binds the signature to the exact registration lifecycle of
that asset. Core derives the non-zero token from the network, canonical asset
UUID, executing-header hash, deterministic execution identity, and lifecycle
ordinal at the exact absent-to-present registration event. Host use and final
block admission both require the current token to equal the immutable
block-start token, so registration, unregistration, or re-registration of the
same asset cannot be mixed with an AXT use in one block. Unrelated asset writes
do not rotate the token. The handle asset and its incarnation are part of the
canonical issuer-signature payload. Pre-change handles, claims, proofs, and
JSON fixtures either fail the new required-field decode or fail exact V1
claim, metadata, signature, or binding validation and must be regenerated
together.

One cryptographically verified proof may be reused for multiple handles in the
same dataspace only when its binding contains one distinct handle-bound claim
for every use. The canonical `axt_fastpq_remote_spend_claims_v1` metadata
carries the commitment preimages, and the verifier requires those preimages to
reconstruct the complete binding set exactly. It then matches their typed
`(AssetDefinitionId, AccountId, AccountId, Quantity)` facts one-for-one with
the proof's concrete `TransferDeltaTranscript` deltas. The effect binding,
every claim, and every delta must name the same exact source asset definition.
The `authorization` and `compliance` claim-type labels select an opaque-effect
profile only; they do not prove authority and cannot carry remote-spend claims.

Hosts and block admission derive each expected commitment from the actual
authenticated handle and require exact per-proof set consumption. Duplicate
use of one claim, a proof claim with no corresponding handle, or replay under a
different asset incarnation, era, sub-nonce, lane, dataspace, or descriptor
fails closed. The raw verifier may validate an empty remote-spend claim set, but
production CoreHost rejects every non-null standalone `VERIFY_DS_PROOF`; an
empty set cannot authorize a handle. The asset definition must also exist in committed world state, and its
current non-zero `AxtAssetIncarnationV1` must equal the issuer-signed context.
Core derives the token from a dedicated V1 domain separator, the exact
`NetworkId`, canonical asset-definition UUID, registration transaction's
executing header hash (`StateTransaction::_curr_block.hash()`), deterministic
execution identity, and big-endian lifecycle ordinal. The final two fields
distinguish exact events when autonomous executions share a header context. Only an
absent-to-present registration or re-registration installs a new token;
ordinary metadata, ownership, mintability, mint, or burn updates do not rotate
it. Signed-spend admission, commit revalidation, and block admission all require the
current token to equal both the issuer-signed token and the immutable block-start
token, so unregister/re-register and stale-handle use cannot coexist in one
block. An unrelated asset registration leaves other tokens and handles valid.
This prevents a same-ID re-registration from reviving an old handle without
allowing unrelated registry activity to revoke other tenants. A
dataspace-restricted definition selects the exact signed intent/proof dataspace
bucket; its owning domain is not balance-scope authority. A global definition
is valid only when that signed dataspace is universal.
For a transfer proof, `binding.source_dsid == intent.asset_dsid` is the balance
partition for both the `from` and `to` rows of every matched transcript delta.
No definition-home or account-alias routing is inferred. V1 transfer trace keys
omit an explicit scope component because the public `source_dsid` supplies that
single proof-wide partition.

Issuers construct an unsigned `AssetHandleDraft`; signing consumes that draft
and returns an admission-ready `AssetHandle` with a mandatory signature. The
signature binds the exact genesis-derived `NetworkId`, committed issuer UAID and
manifest root, executing code root, ABI version/hash, dataspace, descriptor
digest, exact `AssetDefinitionId`, scope, subject, budget, group/lane context,
exact active era/next counter, expiry, and skew allowance. The host reconstructs
this context from committed state and the executing IVM before any FASTPQ work,
and rejects a handle whose signed asset differs from the remote-spend intent or
matched proof transcript.

### Generation and use

1. Build and validate an `AxtDescriptor`, then derive its canonical Poseidon
   binding.
2. Derive the authoritative manifest root, optional DA commitment, optional
   committed amount, and optional expiry before proving. Insert their canonical
   FastPQ metadata encodings before sealing the batch. If the proof will
   authorize handles, construct one transfer claim from each exact signed
   handle use, attach its canonical preimage and concrete transfer transcript,
   then sort the resulting commitments before the same seal.
3. Prove the sealed batch, then package it with the checked bound-batch builder.
   The builder extracts or exact-compares the outer manifest, DA, amount, and
   expiry mirrors; callers cannot attach different values after proof
   generation.
4. Bind the proof, handle, source receipt and exact occurrence into one signed
   `AxtAnchoredSpendV1`, then place it in `AxtEnvelopeRecord.spends`. Production
   admission rejects this spend until the finalized State resolver and atomic
   nonce/budget/effect owner are available.
5. Refresh expired proof blobs or handles. The canonical error catalog retains
   `PVO_MISSING_OR_EXPIRED` as the machine-readable missing/expiry code.

### Developer checklist

- Declare read/write sets accurately so AMX can prefetch locks and avoid `AMX_LOCK_CONFLICT`.
- Bundle deterministic allowance proofs in the same UAID manifest update when cross-DS transfers touch regulated DSes.
- Retrying strategy: missing availability evidence → no action (the tx stays in mempool); `AMX_TIMEOUT` or `PVO_MISSING_OR_EXPIRED` → rebuild artefacts and back off exponentially.
- Tests should include both cache hits and cold starts (forcing the host to verify the proof with the same `max_k`) to guard against determinism regressions.
- Proof blobs (`ProofBlob`) MUST encode the complete V1 `AxtProofEnvelope { dsid, manifest_root, da_commitment, proof, fastpq_binding, committed_amount, amount_commitment }`; every nullable slot is encoded explicitly. Authenticated specialized consumers bind proofs to the Space Directory manifest root and cache pass/fail results per dataspace/slot with `iroha_axt_proof_cache_events_total{event="hit|miss|expired|reject|cleared"}`. Non-null standalone `AXT_VERIFY_DS_PROOF` fails before proof recording or cache mutation. Expired or manifest-mismatched authenticated artefacts are rejected before commit and subsequent retries in the same slot short-circuit on the cached `reject`.
- Proof cache reuse is bounded by the configured `proof_cache_ttl_slots` and the proof's own expiry: verified proofs may stay hot across envelopes and later slots through that exact deterministic window, then expire automatically.

### Static read/write analyzer

Compile-time selectors must match the contract’s actual behaviour before AMX can
prefetch locks or apply UAID manifests. The new `ivm::analysis` module
(`crates/ivm/src/analysis.rs`) exposes `analyze_program(&[u8])` which decodes a
`.to` artefact, tallies register reads/writes, memory ops, and syscall usage,
and produces a JSON-friendly report that the SDK manifests can embed. Run it
alongside `koto check` when publishing UAIDs so the generated R/W summary is
captured in the validation evidence bundle.

The durable-state control-flow proof is conservative around indirect branches:
every reachable `JR` or `JALR` makes the exact-access analysis incomplete except
the canonical protected return `JALR x0, x1, 0`. Prepared execution authenticates
that one terminal edge with strict return-stack integrity. A `JR`, non-zero link
register, different source register, or non-zero immediate remains an
unauthenticated computed edge and cannot support an exact scheduler access set.

## Space Directory policy enforcement

The following Space Directory checks define the required signed-spend admission
relation. CoreHost stages a canonical `AxtAnchoredSpendV1` through typed syscall
`0xB5` after checking public field consistency, but does not authenticate the
issuer or source. State refuses every nonempty spend before effects; it does not
consume a nonce or advance a budget. Per-dataspace
policy entries carry `manifest_root`, `target_lane`, `active_handle_era`,
`next_handle_counter`, and `current_slot`. Completed admission must enforce:

- lane binding: handle `target_lane` must match the Space Directory entry;
- manifest binding: non-zero `manifest_root` values must match the handle’s `manifest_view_root`;
- expiry: `current_slot` greater than the handle’s `expiry_slot` is rejected;
- counters: `handle_era` must be non-zero and equal the permanent per-dataspace authorization generation, and `sub_nonce` must equal its next value; stale and caller-selected future values must be rejected, and advancement must use checked arithmetic. The ratchet is required consensus state and is never reset or removed by manifest rotation, issuer-key changes, lane reassignment/incarnation, dataspace removal, or restart. One or more effective policy transitions in a block advance both generation and next counter exactly once per affected dataspace at the block boundary; the authenticated transition set preserves even transient A→B→A changes, so an earlier-generation handle cannot revive at any pre-signed sub-nonce;
- replay scope: the canonical replay key is `(asset_dsid, asset_definition_incarnation, descriptor_binding, handle_era, sub_nonce, target_lane)`, where `asset_dsid` and the non-zero incarnation come from the authenticated issuer/policy context. Re-registering the same asset identifier therefore cannot reuse a historical proof or replay entry. Distinct dataspaces retain independent per-dataspace counters even when they share a lane and identical counter values; optional `origin_dsid` is not replay authority;
- account identity: `HandleSubject.account` and `RemoteSpendIntent.op.{from,to}` must carry exact canonical I105 account identifiers; aliases, padded text, and alternate encodings are rejected before policy evaluation;
- issuer authentication: the signature must bind the exact asset definition, its current non-zero registration incarnation, and every V1 policy/network field, and verify with the single-key account resolved from the active manifest's committed UAID and dataspace binding;
- membership: handles for dataspaces absent from the snapshot are denied.

Local IVM policy tests cover field-level decisions, but they are not successful
remote-spend admission evidence. Production remote spend fails closed.
`AXT_COMMIT` is failure-atomic across host implementations: the host validates
the recorded descriptor, touches and proofs before clearing or
moving the active envelope. A validation error restores the active state so
required touches or proofs can be supplied and the same envelope retried; only
a successful commit ends that envelope.

The future source-anchored block path must authenticate unique signed spends
before FASTPQ verification,
scopes replay by the authenticated asset dataspace, and groups budgets by the
normalized V1 issuer-signed family key. `AxtHandleBudgetKey` contains every
`AssetHandleIssuerPayloadV1` field except `next_handle_counter`; signature bytes
authenticate the statement but do not identify the family. Validation
reconstructs each committed per-dataspace pre-state counter with checked
subtraction from the advertised post-state. It then requires exact ordered
counter progression and exact equality with the advertised post-state, with a
consensus ceiling of 65,536 authenticated handles per block. It also requires
non-empty proofs per dataspace with `expiry_slot` covering the policy slot (with
the configured skew allowance) and not expiring before the handle, enforces
descriptor binding plus touch manifests for declared specs (and rejects
out-of-prefix entries), and checks exact signed-handle/intent/proof asset
equality.
Normalized signed handle-family consumption must be consensus-persisted and
aggregate across completed transaction envelopes, all envelope records in a
block, and later blocks; splitting sequential `sub_nonce` values cannot reset
the cumulative `remaining` limit. The signed `per_use` limit applies to each
individual spend. Persisted cumulative records cannot reconstruct individual
amounts, so completed block admission must check `per_use` for each spend
before updating the family record. The current fail-closed path writes no
remote-spend budget or replay record.
V1 does not yet prune this ledger. The permanent dataspace generation and exact
asset incarnation provide the authority fences needed for a future deterministic
compactor, but the first-release implementation deliberately retains every
accepted family record until that compaction rule and its resource limits are
specified and tested. Operators must account for this authenticated state
growth.

Unexpired exact-use replay guards, policy state, and permanent per-dataspace authorization ratchets are also consensus-persisted. Lane retirement, reassignment, issuer/key change, and dataspace removal never reset or delete a ratchet; they monotonically revoke both its generation and current counter. Replay guards use this two-dimensional authority, so deterministic cleanup cannot make an older or pre-signed future handle current after an identity cycle. Block admission hydrates replay and family-budget records only for referenced handles from the pre-block MVCC undo view, so validation cost is proportional to touched handles rather than historical ledger size.

Each replay guard cross-links its compact replay identity to the complete signed
handle-family key. Normal host execution, transaction recording, and Kura
reconstruction derive that key only from the authenticated handle. World
restore rejects a replay/family shared-field mismatch or a missing or invalid
referenced budget record. Kura may skip an already-applied cumulative charge
only when the stored and recomputed family keys are exactly equal; presenting
the same compact replay key under a different signed budget, scope, subject,
asset, expiry, or issuer context fails closed.

Canonical and auxiliary tiered state both account for the policy, permanent
counter, live asset-incarnation, exact-use replay, and family-budget maps.
Incarnation rows track exactly the currently registered asset definitions and
are removed on unregister; counter and V1 family-budget rows are non-pruning.
Replay measured bytes include the dynamically sized authenticated family key,
not only the compact replay identity. Every tiered map entry separately charges
the canonical Norito-encoded map-key length plus its measured value footprint;
the replay value therefore owns and charges its embedded family key in addition
to the compact replay-map key. Tiered cold payloads retain those canonical keys
and Norito JSON values, so persistent security records remain visible to
state-tiering decisions without claiming allocator-exact resident-memory bytes.

These persisted AXT stores and transition evidence are a first-release state- and
block-format hard cut. The required, non-skipped World fields are
`axt_policies`, `axt_handle_counters`, `axt_asset_incarnations`,
`axt_replay_ledger`, `axt_spend_nonce_ledger`,
`axt_source_transfer_replay_ledger`, and `axt_handle_budget_ledger`. The two
anchored-spend replay ledgers must contain matching, one-to-one nonce and
physical-transfer records on snapshot restore. The required block-result
fields include `BlockResult.axt_policy_snapshot` and
`BlockResult.axt_transitioned_dataspaces`. They change WSV checkpoint or
block-result bytes even when their collections are empty. Snapshot restoration
additionally requires an exact bijection between live asset definitions and
valid non-zero incarnation records; missing, extra, or corrupt records are
rejected rather than backfilled. Pre-cut snapshots/checkpoints/blocks, including
replay records without an exact family key, must not be loaded by defaulting a
missing store or field to an empty value; deployments must re-genesis or rebuild
at a chain boundary that invalidates every pre-cut handle and family. Exact-use
replay rows remain deterministically prunable under the permanent generation
fence, while cumulative family-budget rows are deliberately non-pruning in V1.

## Error Catalog

Canonical codes live in `crates/iroha_data_model/src/errors.rs`. Operators must surface them verbatim in metrics/logs, and SDKs should map them to actionable retries.

| Code | Trigger | Operator response | SDK guidance |
|------|---------|-------------------|--------------|
| Missing availability evidence (telemetry) | Fewer than `q` attester receipts verified before 300 ms. | Inspect attester health, widen sampling parameters for next slot, keep the transaction queued, and capture the missing-availability counters for runbook evidence. | No action; retry happens automatically because the tx stays enqueued. |
| `DA_DEADLINE_EXCEEDED` | Δ window elapsed without meeting DA quorum. | Resign offending attesters, publish incident note, force clients to resubmit. | Rebuild transaction once attesters are back; consider splitting the batch. |
| `AMX_TIMEOUT` | Combined prepare/commit exceeded 250 ms per DS slice. | Capture flamegraphs, verify R/W sets, and compare against `iroha_amx_prepare_ms`. | Retry with smaller batch or after reducing contention. |
| `AMX_LOCK_CONFLICT` | Host detected overlapping write sets or unsignaled touches. | Inspect UAID manifests and static analysis reports; update manifests if missing selectors. | Recompile transaction with corrected read/write declarations. |
| `PVO_MISSING_OR_EXPIRED` | Referenced proof or handle is unavailable or past `expiry_slot`. | Inspect the AXT cache snapshot and regenerate the artefact. | Refresh the proof or handle and resubmit. |
| `RWSET_UNBOUNDED` | Static analysis could not bound a read/write selector. | Reject deployment, log selector stack trace, require developer fix before retry. | Update contract to emit explicit selectors. |
| `HEAVY_INSTRUCTION_DISALLOWED` | Contract invoked an instruction banned from AMX lanes (e.g., large FFT without PVO). | Make sure Norito builder uses the approved opcode set before re-enabling. | Split workload or add a pre-computed proof. |
| `SETTLEMENT_ROUTER_UNAVAILABLE` | Router could not compute deterministic conversion (missing path, buffer drained). | Engage Treasury to refill buffers or flip XOR-only mode; record in settlement runbook. | Retry after buffer alert clears; show user-facing warning. |

SDK teams should mirror these codes in integration tests so `iroha_cli`, Android, Swift, JS, and Python surfaces agree on error text and recommended actions.

### AXT rejection observability

- Torii surfaces policy failures as `ValidationFail::AxtReject` (and block validation as `AxtEnvelopeValidationFailed`) with a stable reason label, the active `snapshot_version`, optional `lane`/`dataspace` identifiers, and exact hint fields for `active_handle_era`/`next_handle_counter`. SDKs should bubble these fields to users so stale handles can be refreshed deterministically.
- Torii now also stamps HTTP responses with `X-Iroha-Axt-*` headers for quick triage: `Code`/`Reason`, `Snapshot-Version`, `Dataspace`, `Lane`, and optional `Active-Handle-Era`/`Next-Handle-Counter`. ISO bridge rejections carry matching `PRTRY:AXT_*` reason codes and the same detail strings so dashboards and operators can key alerts off the AXT failure class without decoding the full payload.
- Hosts log `AXT policy rejection recorded` with the same fields and export them via telemetry: `iroha_axt_policy_reject_total{lane,reason}` counts rejects, and `iroha_axt_policy_snapshot_version` tracks the hash of the active snapshot. Proof cache state remains available via `/v1/debug/axt/cache` (dataspace/status/manifest root/slots).
- Alerting: watch for spikes in `iroha_axt_policy_reject_total` grouped by `reason` and page with the `snapshot_version` from logs/ValidationFail to confirm whether operators need to rotate manifests (lane/manifest rejects) or refresh handles (era/sub_nonce/expiry). Pair alerts with the proof-cache endpoint to confirm whether rejects are cache-related or policy-related.

## Testing & Evidence

- Check the generated AXT fixtures with
  `cargo run --locked -p iroha_data_model --features dev-tools,test-fixtures --bin axt_fixtures -- --check`.
- Run the current grouped data-model and IVM targets:
  `cargo test --locked -p iroha_data_model --test iroha_data_model_group_01 axt -- --test-threads=1`,
  `cargo test --locked -p ivm --test ivm_group_01 'axt_host_flow::' -- --test-threads=1`, and
  `cargo test --locked -p ivm --test ivm_group_02 'core_host_policy::' -- --test-threads=1`.
- Exercise the protected-return analyzer regression with
  `cargo test --locked -p ivm --lib 'analysis::tests::protected_contract_return_requires_exact_jalr_encoding' -- --exact --test-threads=1`.
- Run both Core filters so the AXT paths and persistent-budget tests are covered:
  `cargo test --locked -p iroha_core --features app_api --lib axt -- --test-threads=1` and
  `cargo test --locked -p iroha_core --features app_api --lib budget_ -- --test-threads=1`.
- Run the FastPQ library, grouped integration, and CLI-unit targets separately:
  `cargo test --locked -p fastpq_prover --features dev-tools --lib -- --test-threads=1`,
  `cargo test --locked -p fastpq_prover --features dev-tools --test fastpq_integration -- --test-threads=1`, and
  `cargo test --locked -p fastpq_prover --features dev-tools --bin fastpq_json -- --test-threads=1`.
- Run the native integration target with
  `cargo test --locked -p integration_tests --test native_amx_routing -- --test-threads=1`.
- Archive chaos-drill evidence under `ops/drill-log.md`.
- Each acceptance record includes the slot SLO report, outstanding error spikes,
  policy snapshot version, and latest AXT proof-cache snapshot.

This file is the source-adjacent reference for AMX/AXT formats, runtime signals,
and validation evidence. Public tutorials and operator walkthroughs belong in
the sibling `iroha-docs` repository.
