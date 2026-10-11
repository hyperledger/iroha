//! Confidential Assets Phase C Tracker
//!
//! This document enumerates the outstanding work items for the Confidential
//! Assets Phase C milestones referenced in `roadmap.md`. Each section lists the
//! concrete tasks, owners, dependencies, and exit criteria so teams can thread
//! the remaining scope through their backlogs without repeatedly spelunking the
//! roadmap.

# Confidential Assets Phase C — Task Breakdown

## M1 — Encrypted Payload v1 Rollout *(🈴 Completed)*

| ID | Task | Owner(s) | Dependencies | Exit Criteria |
|----|------|----------|--------------|---------------|
| M1.1 | Finalise confidential memo-envelope utilities and specialized proof-bound transaction bindings; ensure parity tests cover success + failure paths without exposing generic Shield, ZkTransfer, or Unshield requests. | Swift Lead / Confidential Assets WG | Shared fixtures (`fixtures/confidential/encrypted_payload_v1.json`) | `swift test` parity suite green; doc snippets match the first-release protocol-bound surface. |
| M1.2 | Extend `iroha_cli` and docs with encrypted-payload ergonomics (build helpers, failure diagnostics) and add CLI smoke test. | CLI Maintainer / Docs | Torii `/v1/confidential/...` endpoints | CLI walkthrough + smoke test merged; docs updated. |
| M1.3 | Remove generic confidential wallet fixture bundles and add release-surface drift guards; prove native anonymous escrow remains absent. | SDK Council / DevRel | Instruction catalog, Norito encoder | Rust/Swift/JS guards reject every retired generic or anonymous wire. |
| M1.4 | Secure SDK Council approval for payload v1 rollout (decision memo + rollback plan) and record in `status.md`. | SDK Council Chair | Completion of M1.1–M1.3 | Signed decision logged; production flag flipped. |

### M1 Status

- ✅ SDKs expose confidential memo-envelope utilities and specialized
  transaction surfaces. Generic Shield, transfer, and withdrawal builders are
  intentionally absent. The KAGEMUSHA V1 top-up/redemption settlement was
  deleted on 2026-10-05; no first-release instruction moves value into an
  offline balance. Native anonymous escrow has no first-release
  instruction, record, query, event, or SDK surface.
- ✅ CLI ergonomics landed via the `iroha app zk envelope` helper, which encodes/prints confidential memo envelopes directly from hex/base64 inputs (`crates/iroha_cli/src/zk.rs:1256`).
- ✅ Deterministic encrypted-payload fixtures feed both Rust and Swift parity suites to keep Norito bytes in sync (`fixtures/confidential/encrypted_payload_v1.json:1`, `crates/iroha_data_model/tests/confidential_encrypted_payload_vectors.rs:1`, `IrohaSwift/Tests/IrohaSwiftTests/ConfidentialEncryptedPayloadTests.swift:73`).
- ✅ SDK Council rollout vote recorded in `specs/confidential_assets/approvals/payload_v1_rollout.md`; `status.md` logs the decision link so production flip now has auditable backing.

## M2 — Gas Schedule & Telemetry *(🈴 Completed)*

| ID | Task | Owner(s) | Dependencies | Exit Criteria |
|----|------|----------|--------------|---------------|
| M2.1 | Thread confidential gas knobs from `iroha_config` through Kiso into telemetry metrics (proof verification, nullifier checks, commitment updates). | Confidential Assets Team / Telemetry Ops | Existing `iroha_core::gas` constants | Config changes reflected in runtime + Prometheus gauges. |
| M2.2 | Add metrics for CommitmentTree depth, cache hit ratio, eviction behaviour, and SIMD-neutral cost modelling with Grafana/Alertmanager assets. | Telemetry Ops / SRE | Task M2.1 | Dashboards + alerts merged; docs show curl proof. |
| M2.3 | Extend benches/integration tests for adversarial workloads, reorg restores, and mempool prefilters; capture golden JSON/CSV perf artefacts. | Performance WG / QA Guild | Updated telemetry hooks | Bench artefacts checked in; CI gate enforces tolerances. |
| M2.4 | Update `specs/confidential_assets_calibration.md` with signed baselines and governance notes. | Docs Lead / Program Mgmt | Tasks M2.1–M2.3 | Calibration doc + `status.md` updated; governance acknowledgment filed. |

- [x] **M2.2 evidence captured** — `iroha_core` records confidential proof-verification and commitment-tree telemetry; `dashboards/grafana/confidential_assets.json` charts the series, alerts remain in `dashboards/alerts/confidential_assets_rules.yml`, and `specs/confidential_assets.md` documents the curl proof plus Grafana workflow.

### M2 Status

- ✅ Confidential gas knobs thread from `iroha_config` through Kiso into runtime + telemetry updates, so operators can dial proof-base/per-byte costs deterministically (`crates/iroha_core/src/kiso.rs:298`, `crates/iroha_telemetry/src/metrics.rs:5760`–`5815`).
- ✅ Grafana dashboards and docs show the new CommitmentTree metrics/alerting workflow, matching the roadmap references (`dashboards/grafana/confidential_assets.json:1`, `specs/confidential_assets.md:401`).
- ✅ Apple Silicon NEON calibration refreshed (2026-04-28) with averages/logs captured in `specs/confidential_assets_calibration.md` and `specs/confidential_assets_calibration_neon_20260428.log`, satisfying the bench artefact requirement for this milestone.
- ⚠️ SIMD-neutral + AVX2 runs waived by SDK Council pending access to x86_64 hosts; waiver + failure logs recorded alongside the calibration ledger (`specs/confidential_assets_calibration.md:7`). Follow-up action tracked via CI ticket GAS-214.

## M3 — Rotation & Wallet Tooling *(🈴 Completed)*

| ID | Task | Owner(s) | Dependencies | Exit Criteria |
|----|------|----------|--------------|---------------|
| M3.1 | Define rotation/upgrade policy (sunset windows, mempool/admission guards rejecting stale notes) and document process. | Confidential Assets Lead / Torii | Completion of M1, telemetry from M2 | Policy doc merged; guards merged with tests. |
| M3.2 | Extend wallet SDKs/CLI with key hierarchy + upgrade transaction tooling; publish operator + DevRel runbooks. | DevRel / Wallet SDK Leads | Task M3.1 | Samples + docs published; SDK smoke tests cover rotation flow. |
| M3.3 | Add KAGEMUSHA V1 top-up→aggregate recursive spend→redemption rotation suites covering partial redemption and double-spend rejection (deleted with KAGEMUSHA V1 on 2026-10-05). | QA Guild / SDK Council | Tooling from M3.2 | Tests in repo; nightly job reports metrics. |
| M3.4 | Assign runbook owners and schedule rehearsals (rotation playbook, escalation paths). | Program Mgmt / DevRel | Tasks M3.2–M3.3 | Owners listed in `status.md`; rehearsal evidence archived. |

### M3 Status

Status: ✅ All rotation policy, SDK/CLI tooling, and rehearsal ownership tasks are delivered; evidence references remain below for posterity.

- ✅ Rotation policy/runbook published (`specs/confidential_assets_rotation.md`) covering parameter lifecycles, governance scheduling, CLI/SDK helpers, and operator ownership.
- ✅ CLI + SDK surfaces already expose confidential policy metadata/pending transitions (CLI helper in `crates/iroha_cli/src/main.rs:1497`, Swift Torii client at `IrohaSwift/Sources/IrohaSwift/ToriiClient.swift:309` with tests in `IrohaSwift/Tests/IrohaSwiftTests/ToriiClientTests.swift:591`).
- ✅ End-to-end rotation coverage lives in the existing core tests:
  `crates/iroha_core/tests/confidential_policy_gates.rs:300` exercises
  schedule/cancel flows, and the release-surface regression rejects the
  retired generic confidential wires, native anonymous escrow, and the generic
  confidential event/filter family.

## M4 — Audit & Operations *(🈴 Completed)*

| ID | Task | Owner(s) | Dependencies | Exit Criteria |
|----|------|----------|--------------|---------------|
| M4.1 | Implement auditor workflows (selective disclosure APIs, telemetry without payload data) and document usage. | Security Lead / Telemetry Ops | Completion of M2/M3 instrumentation | APIs documented; sample auditor script in repo. |
| M4.2 | Commission external crypto/security review; capture findings/remediation in `status.md`. | Program Mgmt / Security | Tasks M4.1 + M3 readiness | Signed report + remediation log checked in. |
| M4.3 | Publish incident-response/runbook package (threat model, telemetry, escalation). | Ops Guild / Docs | Tasks M4.1–M4.2 | Runbooks approved; chaos drill scheduled. |
| M4.4 | Prototype confidential fee circuit (shielded gas payments), benchmark proving cost, specify validator reward accounting. | Confidential Assets Team / Economics WG | Gas telemetry from M2 | Prototype results + go/no-go decision documented. |

### M4 Status

Status: ✅ Operator/auditor runbooks, selective-disclosure APIs, calibration artefacts, and review tracking are all in-tree; milestone is now considered delivered pending the separate x86 waiver noted above.

- ✅ Auditor & operator workflows consolidated in `specs/confidential_assets_audit_runbook.md` (event feeds, telemetry surfaces, calibration evidence requirements, and external-review cadence).
- ✅ Selective disclosure APIs + SDK bindings are documented in
  `crates/iroha_torii/src/routing.rs` and
  `IrohaSwift/Sources/IrohaSwift/ToriiClient.swift`. Transparent native
  numeric escrow remains covered separately in
  `crates/iroha_core/src/smartcontracts/isi/escrow.rs`; it has no confidential
  or anonymous variant.
- ✅ Telemetry/dashboards + calibration artefacts logged in `specs/confidential_assets.md:401` and `specs/confidential_assets_calibration.md`, giving auditors deterministic references while x86 benchmarking hosts are pending.

---

**Coordination Notes**
- Decision log for the closed approvals (payload v1 rollout, gas telemetry, rotation ownership, audit scope) now lives in `roadmap.md:1609-1615`; keep follow-up waivers/updates mirrored here and in `status.md`.
- Keep this tracker and `status.md` aligned when follow-up actions land (e.g., clearing the x86 benchmarking waiver) so roadmap entries stay in sync.
