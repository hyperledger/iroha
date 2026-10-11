---
title: CBDC Lane Playbook
sidebar_label: CBDC Lane Playbook
description: Reference configuration, whitelist flow, and compliance evidence for permissioned CBDC lanes on SORA Nexus.
---

# CBDC Private Lane Playbook (NX-6)

> **Roadmap linkage:** NX-6 (CBDC private lane template & whitelist flow) and NX-14 (Nexus runbooks).  
> **Owners:** Financial Services WG, Nexus Core WG, Compliance WG.  
> **Status:** Drafting — implementation hooks exist across `crates/iroha_data_model::nexus`, `crates/iroha_core::governance::manifest`, and `integration_tests/tests/nexus/lane_registry.rs`, but the CBDC-specific manifests, whitelists, and operator runbooks were missing. This playbook documents the reference configuration and onboarding workflow so CBDC deployments can proceed deterministically.

## Scope & Roles

- **Central bank lane (“CBDC lane”):** Permissioned validators, custodial settlement buffers, and programmable-money policies. Runs as a restricted dataspace + lane pair with its own governance manifest.
- **Wholesale/retail bank dataspaces:** Participant DS that hold UAIDs, receive capability manifests, and may be whitelisted for atomic AXT with the CBDC lane.
- **Programmable-money dApps:** External DS that consume CBDC flows through `ComposabilityGroup` routing once whitelisted.
- **Governance & compliance:** Parliament (or equivalent module) approves lane manifests, capability manifests, and whitelist changes; compliance stores evidence bundles alongside Norito manifests.

**Dependencies**

1. Lane catalog + dataspace catalog wiring (`specs/nexus_lanes.md`, `defaults/nexus/config.toml`).
2. Lane manifest enforcement (`crates/iroha_core/src/governance/manifest.rs`, queue gating in `crates/iroha_core/src/queue.rs`).
3. Capability manifests + UAIDs (`crates/iroha_data_model/src/nexus/manifest.rs`).
4. Scheduler TEU quotas + metrics (`integration_tests/tests/scheduler_teu.rs`, `specs/telemetry.md`).

## 1. Reference Lane Layout

### 1.1 Lane catalog & dataspace entries

Add dedicated entries to `[[nexus.lane_catalog]]` and `[[nexus.dataspace_catalog]]`. The example below extends `defaults/nexus/config.toml` with a CBDC lane that reserves 1 500 TEU per slot and throttles starvation to six slots, plus matching dataspace aliases for wholesale banks and retail wallets.

```toml
lane_count = 5

[[nexus.lane_catalog]]
index = 3
alias = "cbdc"
description = "Central bank CBDC lane"
dataspace = "cbdc.core"
visibility = "restricted"
lane_type = "cbdc_private"
governance = "central_bank_multisig"
settlement = "xor_dual_fund"
scheduler = { teu_capacity = 1500, starvation_bound_slots = 6 }
settlement_buffer = { account_id = "<canonical-i105-account-id>", asset_definition_id = "61CtjvNd9T3THAR65GsMVHr82Bjc", capacity = "1500" }
metadata = { "telemetry.contact" = "ops@cb.example" }

[[nexus.dataspace_catalog]]
alias = "cbdc.core"
id = 10
manifest_hash = "0a00000000000000000000000000000000000000000000000000000000000000"
description = "CBDC issuance dataspace"
fault_tolerance = 1

[[nexus.dataspace_catalog]]
alias = "cbdc.bank.wholesale"
id = 11
manifest_hash = "0b00000000000000000000000000000000000000000000000000000000000000"
description = "Wholesale bank onboarding dataspace"
fault_tolerance = 1

[[nexus.dataspace_catalog]]
alias = "cbdc.dapp.retail"
id = 12
manifest_hash = "0c00000000000000000000000000000000000000000000000000000000000000"
description = "Retail wallets and programmable-money dApps"
fault_tolerance = 1

[nexus.routing_policy]
default_lane = 0
default_dataspace = "universal"

[[nexus.routing_policy.rules]]
lane = 3
dataspace = "cbdc.core"
[nexus.routing_policy.rules.matcher]
instruction = "cbdc::*"
description = "Route CBDC contracts to the restricted lane"
```

**Notes**

- The typed scheduler descriptor's `teu_capacity` and `starvation_bound_slots` values feed the TEU gauges exercised by `integration_tests/tests/scheduler_teu.rs`. Both values are positive integers. The settlement buffer requires an exact domainless I105 account, canonical asset-definition address, and positive canonical XOR quantity.
- Every dataspace alias above must appear in governance manifests and capability manifests (see below) so admission rejects drift automatically.

### 1.2 Lane manifest skeleton

Lane manifests live under the directory configured via `nexus.registry.manifest_directory` (see `crates/iroha_config/src/parameters/actual.rs`). File names should match lane aliases (`cbdc.manifest.json`). The schema mirrors the governance manifest tests in `integration_tests/tests/nexus/lane_registry.rs`.

```json
{
  "lane": "cbdc",
  "dataspace": "cbdc.core",
  "version": 1,
  "governance": "central_bank_multisig",
  "validators": [
    { "validator": "<i105-account-id>", "peer_id": "<peer-id>" },
    { "validator": "<i105-account-id>", "peer_id": "<peer-id>" },
    { "validator": "<i105-account-id>", "peer_id": "<peer-id>" },
    { "validator": "<i105-account-id>", "peer_id": "<peer-id>" }
  ],
  "quorum": 3,
  "protected_namespaces": [
    "cbdc.core",
    "cbdc.policy",
    "cbdc.settlement"
  ],
  "hooks": {
    "runtime_upgrade": {
      "allow": true,
      "require_metadata": true,
      "metadata_key": "cbdc_upgrade_id",
      "allowed_ids": [
        "upgrade-issuance-v1",
        "upgrade-pilot-retail"
      ]
    }
  },
  "composability_group": {
    "group_id_hex": "7ab3f9b3b2777e9f8b3d6fae50264a1e0ffab7c74542ff10d67fbdd073d55710",
    "activation_epoch": 2048,
    "whitelist": [
      "ds::cbdc.bank.wholesale",
      "ds::cbdc.dapp.retail"
    ],
    "quotas": {
      "group_teu_share_max": 500,
      "per_ds_teu_max": 250
    }
  }
}
```

Key requirements:

- Validators **must** be declared as explicit bindings with a canonical I105
  authority account plus a concrete `peer_id`. Legacy string-only validator
  arrays are rejected.
- Each manifest `peer_id` must resolve to a registered runtime peer with a live
  lane-eligible consensus key. Lane `0` requires an unbounded `Validator` key
  in the current global commit topology. Non-zero CBDC dataspaces require an
  unbounded `Committee` key; participant membership never expands global quorum. Torii
  routes only to authoritative peer bindings and fails closed when runtime
  truth disagrees with the manifest.
- Validator accounts should remain stable governance identities even if the
  underlying host or peer keys rotate; update the manifest `peer_id` binding
  when the serving peer changes. Set `quorum` to the multisig threshold (≥2).
- Protected namespaces are enforced by `Queue::push` (see `crates/iroha_core/src/queue.rs`), so all CBDC contracts must specify `gov_namespace` + `gov_contract_id`.
- `composability_group` fields follow the schema described in `specs/nexus.md` §8.6; the owner (CBDC lane) supplies the whitelist and quotas. Whitelisted DS manifests only specify the `group_id_hex` + `activation_epoch`.
- After copying the manifest, run `cargo test -p integration_tests nexus::lane_registry -- --nocapture` to confirm `LaneManifestRegistry::from_config` loads it.

### 1.3 Capability manifests (UAID policies)

Capability manifests (`AssetPermissionManifest` in `crates/iroha_data_model/src/nexus/manifest.rs`) bind a `UniversalAccountId` to deterministic allowances. Publish them via the Space Directory so banks and dApps can fetch signed policies.

```json
{
  "version": 1,
  "uaid": "uaid:5f77b4fcb89cb03a0ab8f46d98a72d585e3b115a55b6bdb2e893d3f49d9342f1",
  "dataspace": 11,
  "issued_ms": 1762723200000,
  "activation_epoch": 2050,
  "expiry_epoch": 2300,
  "entries": [
    {
      "scope": {
        "dataspace": 11,
        "program": "cbdc.transfer",
        "method": "transfer",
        "asset": "CBDC#centralbank",
        "role": "Initiator"
      },
      "effect": {
        "Allow": {
          "max_amount": "1000000000",
          "window": "PerDay"
        }
      },
      "notes": "Wholesale transfer allowance (per UAID)"
    },
    {
      "scope": {
        "dataspace": 11,
        "program": "cbdc.kit",
        "method": "withdraw"
      },
      "effect": {
        "Deny": {
          "reason": "Withdrawals disabled for this UAID"
        }
      }
    }
  ]
}
```

- Deny rules win even when an allow rule matches (`ManifestVerdict::Denied`), so place all explicit denies after the relevant allows.
- Use `AllowanceWindow::PerSlot` for atomic payment handles and `PerMinute`/`PerDay` for rolling customer limits.
- A single manifest per UAID/dataspace suffices; activations and expiries enforce policy rotation cadence.
- The lane runtime now expires manifests automatically once `expiry_epoch` is reached,
  so operations teams simply monitor `SpaceDirectoryEvent::ManifestExpired`,
  archive the `nexus_space_directory_revision_total` delta, and verify Torii shows
  `status = "Expired"`. The CLI `manifest expire` command remains available for
  manual overrides or evidence backfills.

## 2. Bank Onboarding & Whitelist Workflow

| Phase | Owner(s) | Actions | Evidence |
|-------|----------|---------|----------|
| 0. Intake | CBDC PMO | Collect KYC dossier, technical DS manifest, validator list, UAID mapping. | Intake ticket, signed DS manifest draft. |
| 1. Governance approval | Parliament / Compliance | Review intake pack, countersign `cbdc.manifest.json`, approve `AssetPermissionManifest`. | Signed governance minutes, manifest commit hash. |
| 2. Capability issuance | CBDC lane ops | Encode manifests via `norito::json::to_string_pretty`, store under Space Directory, notify operators. | Manifest JSON + norito `.to` file, BLAKE3 digest. |
| 3. Whitelist activation | CBDC lane ops | Append DSID to `composability_group.whitelist`, bump `activation_epoch`, distribute manifest; update dataspace routing if needed. | Diff of manifest, `kagami config diff` output, governance approval ID. |
| 4. Rollout validation | QA Guild / Ops | Run integration tests, TEU load tests, and programmable-money replay (see below). | `cargo test` logs, TEU dashboards, programmable-money fixture results. |
| 5. Evidence archive | Compliance WG | Bundle manifests, approvals, capability digests, test outputs, and Prometheus scrapes under `artifacts/nexus/cbdc_<stamp>/`. | Evidence tarball, checksum file, council sign-off. |

### Audit bundle helper

Use the `iroha app space-directory manifest audit-bundle` helper from the Space Directory
playbook to snapshot each capability manifest before filing the evidence packet.
Provide the manifest JSON (or `.to` payload) and dataspace profile:

```bash
iroha app space-directory manifest audit-bundle \
  --manifest-json fixtures/space_directory/capability/cbdc_wholesale.manifest.json \
  --profile fixtures/space_directory/profile/cbdc_lane_profile.json \
  --out-dir artifacts/nexus/cbdc/2026-02-01T00-00Z/cbdc_wholesale \
  --notes "CBDC wholesale refresh"
```

The command emits canonical JSON/Norito/hash copies alongside
`audit_bundle.json`, which records the UAID, dataspace id, activation/expiry
epochs, manifest hash, and profile audit hooks while enforcing the required
`SpaceDirectoryEvent` subscriptions. Drop the bundle inside the evidence
directory so auditors and regulators can replay the exact bytes later.

### 2.1 Commands & validations

1. **Lane manifests:** `cargo test -p integration_tests nexus::lane_registry -- --nocapture lane_manifest_registry_loads_fixture_manifests`.
2. **Scheduler quotas:** `cargo test -p integration_tests scheduler_teu -- queue_teu_backlog_matches_metering queue_routes_transactions_across_configured_lanes`.
3. **Manual smoke:** `iroha3d --sora --config configs/soranexus/nexus/config.toml --chain 0000…` with manifest directory pointing to the CBDC files, then hit `/v1/sumeragi/status` and verify `lane_governance.manifest_ready=true` for the CBDC lane.
4. **Whitelist consistency test:** `cargo test -p integration_tests nexus::cbdc_whitelist -- --nocapture` exercises `integration_tests/tests/nexus/cbdc_whitelist.rs`, parsing `fixtures/space_directory/profile/cbdc_lane_profile.json` and the referenced capability manifests to ensure every whitelist entry’s UAID, dataspace, activation epoch, and allowance list matches the Norito manifests under `fixtures/space_directory/capability/`. Attach the test log to the NX-6 evidence bundle whenever the whitelist or manifests change.

### 2.2 CLI snippets

- Generate UAID + manifest skeleton via `cargo run -p iroha_cli -- manifest cbdc --uaid <hash> --dataspace 11 --template cbdc_wholesale`.
- Publish capability manifest to Torii (Space Directory) using `iroha app space-directory manifest publish --manifest cbdc_wholesale.manifest.to` (or `--manifest-json cbdc_wholesale.manifest.json`); the submitting account must hold `CanPublishSpaceDirectoryManifest` for the CBDC dataspace.
- Remote publication and emergency revocation use the SDK's local signing
  context for `POST /v1/space-directory/manifests` and
  `/v1/space-directory/manifests/revoke`. Do not handcraft or persist canonical
  auth headers: the SDK signs the exact NetworkId, method, path, query, and raw
  body with a fresh nonce, and the signed account must equal the JSON
  `authority`. Torii returns a canonical unsigned transaction draft for local
  validation, signing, and submission; `CanPublishSpaceDirectoryManifest`
  remains enforced on-chain.
- Whitelist changes require an authorized policy transition or coordinated configuration rollout. The manifest poller accepts only unchanged consensus and materialized authority; it refreshes local diagnostics without installing policy changes.

## 3. Compliance Evidence Bundle

Store artefacts under `artifacts/nexus/cbdc_rollouts/<YYYYMMDDThhmmZ>/` and attach the digest to the governance ticket.

| File | Description |
|------|-------------|
| `cbdc.manifest.json` | Signed lane manifest with whitelist diff (before/after). |
| `capability/<uaid>.manifest.json` & `.to` | Norito + JSON capability manifests for each UAID. |
| `compliance/kyc_<bank>.pdf` | Regulator-facing KYC attestation. |
| `metrics/nexus_scheduler_lane_teu_capacity.prom` | Prometheus scrape proving TEU headroom. |
| `tests/cargo_test_nexus_lane_registry.log` | Log from the manifest test run. |
| `tests/cargo_test_scheduler_teu.log` | Log proving TEU routing passes. |
| `programmable_money/axt_replay.json` | Replay transcript demonstrating programmable-money interoperability (see section 4). |
| `approvals/governance_minutes.md` | Signed approval minutes referencing manifest hash + activation epoch. |

**Validation script:** run `ci/check_cbdc_rollout.sh` to assert the evidence bundle is complete before attaching it to the governance ticket. The helper scans `artifacts/nexus/cbdc_rollouts/` (or `CBDC_ROLLOUT_BUNDLE=<path>`) for every `cbdc.manifest.json`, parses the manifest/composability group, verifies each capability manifest has a matching `.to` file, checks for `kyc_*.pdf` attestations, confirms the TEU metrics scrape plus `cargo test` logs, validates the programmable-money replay JSON, and ensures the approval minutes cite the activation epoch and manifest hash. The latest rev also enforces safety rails called out in NX-6: quorum cannot exceed the declared validator set, protected namespaces must be non-empty strings, and capability manifests must declare monotonically increasing `activation_epoch`/`expiry_epoch` pairs with well-formed `Allow`/`Deny` effects. A sample evidence pack under `fixtures/nexus/cbdc_rollouts/` is exercised by the integration test `integration_tests/tests/nexus/cbdc_rollout_bundle.rs`, keeping the validator wired into CI.

## 4. Programmable-Money Interoperability

Once a bank (dataspace 11) and retail dApp (dataspace 12) are both whitelisted in the same `ComposabilityGroupId`, programmable-money flows follow the AXT pattern from `specs/nexus.md` §8.6:

1. Retail dApp requests an asset handle bound to its UAID + AXT digest. The CBDC lane verifies the handle via `AssetPermissionManifest::evaluate` (deny wins, allowances enforced).
2. Both DS declare the same composability group so routing collapses them into the CBDC lane for atomic inclusion (`LaneRoutingPolicy` uses `group_id` when mutually whitelisted).
3. The intended signed anchored-spend path binds the CBDC DS's AML/KYC proof and exact successful transfer occurrence before the dApp DS can update local business state. Production remote-spend admission is still closed pending complete finalized-state and execution-proof ownership.
4. Proof material (FASTPQ + DA commitments) stays confined to the CBDC lane.

The programmable-money replay archive should include:

- AXT descriptor + handle request/responses.
- Norito-encoded transaction envelope.
- Resulting receipts (happy path, deny path).
- Telemetry snippets for `telemetry::fastpq.execution_mode`, `nexus_scheduler_lane_teu_slot_committed`, and `lane_commitments`.

## 5. Observability & Runbooks

- **Metrics:** Monitor `nexus_scheduler_lane_teu_capacity`, `nexus_scheduler_lane_teu_slot_committed`, `nexus_scheduler_lane_teu_deferral_total{reason}`, `governance_manifest_admission_total`, and `lane_governance_sealed_total` (see `specs/telemetry.md`).
- **Dashboards:** Extend `specs/grafana_scheduler_teu.json` with a CBDC lane row; add panels for whitelist churn (annotations every activation epoch) and capability expiry pipelines.
- **Alerts:** Trigger when `rate(nexus_scheduler_lane_teu_deferral_total{reason="cap_exceeded"}[5m]) > 0` for 15 minutes or when `lane_governance.manifest_ready=false` persists beyond one poll interval.
- **Runbook pointers:** Link to protected-namespace guidance in `specs/governance_api.md` and programmable-money troubleshooting in `specs/nexus.md`.

## 6. Acceptance Checklist

- [ ] CBDC lane declared in `nexus.lane_catalog` with TEU metadata matching TEU tests.
- [ ] Signed `cbdc.manifest.json` present in the manifest directory, validated via `cargo test -p integration_tests nexus::lane_registry`.
- [ ] Capability manifests issued for every UAID and stored in Space Directory; deny/allow precedence verified via unit tests (`crates/iroha_data_model/src/nexus/manifest.rs`).
- [ ] Whitelist activation recorded with governance approval ID, `activation_epoch`, and Prometheus evidence.
- [ ] Programmable-money replay archived, demonstrating handle issuance, denial, and allow flows.
- [ ] Evidence bundle uploaded with cryptographic digest, linked from governance ticket and `status.md` once NX-6 graduates from 🈯 to 🈺.

Following this playbook satisfies the documentation deliverable for NX-6 and unblocks future roadmap items (NX-12/NX-15) by providing a deterministic template for CBDC lane configuration, whitelist onboarding, and programmable-money interoperability.
