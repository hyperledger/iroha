//! Confidential assets audit & operations playbook referenced by `roadmap.md:M4`.

# Confidential Assets Audit & Operations Runbook

This guide consolidates the evidence surfaces auditors and operators rely on
when validating confidential-asset flows. It complements the rotation playbook
(`specs/confidential_assets_rotation.md`) and the calibration ledger
(`specs/confidential_assets_calibration.md`).

## 1. Selective Disclosure & Audit Records

- Confidential tree transitions do not have a public generic data-event or
  event-filter wire.
- Torii exposes transparent native numeric-escrow lifecycle events through the
  standard SSE/WebSocket pipeline and `EscrowEventFilter`. The first-release
  protocol has no native anonymous escrow and no producerless generic
  confidential event or event-filter wire.

- Policy metadata and pending transitions are available through
  `GET /v1/confidential/assets/{definition_id}/transitions`
  (`crates/iroha_torii/src/routing.rs:15205`), mirrored by the Swift SDK
  (`IrohaSwift/Sources/IrohaSwift/ToriiClient.swift:3245`) and documented in
  both the confidential-assets design and SDK guides
  (`specs/confidential_assets.md:70`, `specs/sdk/swift/index.md:334`).

## 2. Telemetry, Dashboards, and Calibration Evidence

- Runtime metrics surface tree depth, commitment/frontier history, root eviction
  counters, and verifier-cache hit ratios
  (`crates/iroha_telemetry/src/metrics.rs:5760`–`5815`). Grafana dashboards in
  `dashboards/grafana/confidential_assets.json` ship the associated panels and
  alerts, with the workflow documented in `specs/confidential_assets.md:401`.
- Calibration runs (NS/op, gas/op, ns/gas) with signed logs live in
  `specs/confidential_assets_calibration.md`. The latest Apple Silicon
  NEON run is archived at
  `specs/confidential_assets_calibration_neon_20260428.log`, and the same
  ledger records the temporary waivers for SIMD-neutral and AVX2 profiles until
  the x86 hosts come online.

## 3. Incident Response & Operator Tasks

- Rotation/upgrade procedures reside in
  `specs/confidential_assets_rotation.md`, covering how to stage new
  parameter bundles, schedule policy upgrades, and notify wallets/auditors. The
  tracker (`specs/project_tracker/confidential_assets_phase_c.md`) lists
  runbook owners and rehearsal expectations.
- For production rehearsals or emergency windows, operators attach evidence to
  `status.md` entries (e.g., the multi-lane rehearsal log) and include:
  `curl` proof of policy transitions, Grafana snapshots, and the relevant
  protocol receipts. Transparent native numeric escrow is audited
  separately through its authenticated lifecycle events and records.

## 4. External Review Cadence

- Security review scope: confidential circuits, parameter registries, policy
  transitions, and telemetry. This document plus the calibration ledger forms
  the evidence packet sent to vendors; review scheduling is tracked via
  M4 in `specs/project_tracker/confidential_assets_phase_c.md`.
- Operators must keep `status.md` updated with any vendor findings or follow-up
  action items. Until the external review completes, this runbook serves as the
  operational baseline auditors can test against.
