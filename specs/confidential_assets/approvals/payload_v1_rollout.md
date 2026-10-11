//! Payload v1 rollout approval (SDK Council, 2026-04-28).
//!
//! Captures the SDK Council decision memo required by `roadmap.md:M1` so the
//! encrypted payload v1 rollout has an auditable record (deliverable M1.4).

# Payload v1 Rollout Decision (2026-04-28)

- **Chair:** SDK Council Lead (M. Takemiya)
- **Voting members:** Swift Lead, CLI Maintainer, Confidential Assets TL, DevRel WG
- **Observers:** Program Mgmt, Telemetry Ops

## Inputs Reviewed

1. **SDK bindings & submitters** — confidential memo-envelope utilities and
   proof-bound transaction builders landed with parity tests and docs. The
   retired generic `ShieldRequest` is not an approved first-release surface,
   and no generic public-to-confidential ingress instruction exists.
2. **CLI ergonomics** — `iroha app zk envelope` helper covers encode/inspect workflows plus failure diagnostics, aligned with the roadmap ergonomics requirement.【crates/iroha_cli/src/zk.rs:1256】
3. **Deterministic fixtures & parity suites** — shared fixture + Rust/Swift validation to keep Norito bytes/error surfaces aligned.【fixtures/confidential/encrypted_payload_v1.json:1】【crates/iroha_data_model/tests/confidential_encrypted_payload_vectors.rs:1】【IrohaSwift/Tests/IrohaSwiftTests/ConfidentialEncryptedPayloadTests.swift:73】

## Decision

- **Approve payload v1 memo-envelope rollout** for SDKs and CLI. This approval
  covers encrypted recipient payload handling only; it does not authorize a
  proofless Shield instruction or make an envelope an amount/commitment proof.
- **Conditions:** 
  - Keep parity fixtures under CI drift alerts (tied to `scripts/check_norito_bindings_sync.py`).
  - Document the operational playbook in `specs/confidential_assets.md` (already updated via the Swift SDK PR).
  - Record calibration + telemetry evidence before flipping any production flags (tracked under M2).

## Action Items

| Owner | Item | Due |
|-------|------|-----|
| Swift Lead | Announce GA availability + README snippets | 2026-05-01 |
| CLI Maintainer | Add `iroha app zk envelope --from-fixture` helper (optional) | Backlog (not blocking) |
| DevRel WG | Update wallet quickstarts with payload v1 instructions | 2026-05-05 |

> **Note:** This memo supersedes the temporary “pending council approval” call-out in `roadmap.md:2426` and satisfies tracker item M1.4. Update `status.md` whenever follow-up action items close.
