//! Confidential asset rotation playbook referenced by `roadmap.md:M3`.

# Confidential Asset Rotation Runbook

This playbook explains how operators schedule and execute confidential asset
rotations (parameter sets, verifying keys, and policy transitions) while
ensuring wallets, Torii clients, and mempool guards remain deterministic.

## Lifecycle & Statuses

Confidential parameter sets (`PoseidonParams`, `PedersenParams`, verifying keys)
lattice and helper used to derive the effective status at a given height live in
`crates/iroha_core/src/state.rs:7540`–`7561`. Runtime helpers sweep pending
transitions as soon as the target height is reached and log failures for later
rebroadcasts (`crates/iroha_core/src/state.rs:6725`–`6765`).

Asset policies embed
`pending_transition { transition_id, new_mode, effective_height, conversion_window }`
so governance can schedule upgrades via
`ScheduleConfidentialPolicyTransition` and cancel them if required. See
`crates/iroha_data_model/src/asset/definition.rs:320` and the Torii DTO mirrors
(`crates/iroha_torii/src/routing.rs:1539`–`1580`).

## Rotation Workflow

1. **Publish new parameter bundles.** Operators submit
   `PublishPedersenParams`/`PublishPoseidonParams` instructions (CLI
   `iroha app zk params publish ...`) to stage new generator sets with metadata,
   activation/deprecation windows, and status markers. Publishing or changing
   either parameter lifecycle requires the exact canonical typed unit capability
   `CanManageConfidentialParams`; a same-name token with any other JSON payload
   is rejected. The executor rejects
   duplicate IDs, non-increasing versions, or bad status transitions per
   `crates/iroha_core/src/smartcontracts/isi/world.rs:2499`–`2635`, and the
   registry tests cover the failure modes (`crates/iroha_core/tests/confidential_params_registry.rs:93`–`226`).
2. **Register/verifying-key updates.** `RegisterVerifyingKey` enforces backend,
   commitment, and circuit/version constraints before a key can enter the
   registry (`crates/iroha_core/src/smartcontracts/isi/world.rs:2067`–`2137`).
   Updating a key automatically deprecates the old entry and wipes inline bytes,
   as exercised by `crates/iroha_core/tests/zk_vk_deprecate_marks_status.rs:1`.
3. **Schedule asset-policy transitions.** Once the new parameter IDs are live,
   governance calls `ScheduleConfidentialPolicyTransition` with the desired
   mode, transition window, and audit hash. The executor refuses conflicting
   transitions or assets with outstanding transparent supply. Tests such as
   `crates/iroha_core/tests/confidential_policy_gates.rs:300`–`384` verify that
   aborted transitions clear `pending_transition`, while
   `confidential_policy_transition_reaches_shielded_only_on_schedule` at
   lines 385–433 confirms scheduled upgrades flip to `ShieldedOnly` exactly at
   the effective height.
4. **Policy application & mempool guard.** The block executor sweeps all pending
   transitions at the start of each block (`apply_policy_if_due`) and emits
   telemetry if a transition fails so operators can reschedule. During admission
   the mempool refuses transactions whose effective policy would change mid-block,
   ensuring deterministic inclusion across the transition window
   (`specs/confidential_assets.md:60`).

## Wallet & SDK Requirements

- Swift and other mobile SDKs expose Torii helpers to fetch the active policy
  plus any pending transition, so wallets can warn users before signing. See
  `IrohaSwift/Sources/IrohaSwift/ToriiClient.swift:309` (DTO) and the associated
  tests at `IrohaSwift/Tests/IrohaSwiftTests/ToriiClientTests.swift:591`.
- The CLI mirrors the same metadata via `iroha ledger assets data-policy get` (helper in
  `crates/iroha_cli/src/main.rs:1497`–`1670`), enabling operators to audit the
  policy/parameter IDs wired into an asset definition without spelunking the
  block store.

## Test & Telemetry Coverage

- `crates/iroha_core/tests/zk_ledger_scaffold.rs:288`–`345` verifies that policy
  transitions propagate into metadata snapshots and clear once applied.
- `crates/iroha_core/tests/zk_dedup.rs:1` proves that the `Preverify` cache
  rejects double-spends/double-proofs, including rotation scenarios where
  commitments differ.
- The release-surface regression in
  `integration_tests/tests/zk_confidential_localnet.rs` ensures the retired
  generic `zk::Shield`, `zk::ZkTransfer`, and `zk::Unshield` wires, native
  anonymous escrow, and producerless confidential event/filter wires cannot
  re-enter the registry.
- `dashboards/grafana/confidential_assets.json` and
  `specs/confidential_assets.md:401` document the CommitmentTree &
  verifier-cache gauges that accompany every calibration/rotation run.

## Runbook Ownership

- **DevRel / Wallet SDK Leads:** maintain SDK snippets + quickstarts that show
  how to surface pending transitions locally (tracked under
  `specs/project_tracker/confidential_assets_phase_c.md:M3.2`).
- **Program Mgmt / Confidential Assets TL:** approve transition requests, keep
  `status.md` updated with upcoming rotations, and ensure waivers (if any) are
  recorded alongside the calibration ledger.
