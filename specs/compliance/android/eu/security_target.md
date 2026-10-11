<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android SDK Security Target — ETSI EN 319 401 Alignment

| Field | Value |
|-------|-------|
| Document Version | 0.1 (2026-02-12) |
| Scope | Android SDK (client libraries under `java/iroha_android/` plus supporting scripts/docs) |
| Owner | Compliance & Legal (Sofia Martins) |
| Reviewers | Android Program Lead, Release Engineering, SRE Governance |

## 1. TOE Description

The Target of Evaluation (TOE) comprises the Android SDK library code (`java/iroha_android/src/main/java`), its configuration surface (`ClientConfig` + Norito ingestion), and the operational tooling referenced in `roadmap.md` for milestones AND2/AND6/AND7.

The baseline TOE supports software-backed signing and custody for ordinary
production, governance, build, test, deployment, and release workflows.
StrongBox, TEE, physical-device, and hardware-attestation coverage is an
optional qualification profile that applies only when a deployment explicitly
selects it; absence of that profile never fails the baseline evaluation.

Primary components:

1. **Configuration ingestion** — `ClientConfig` threads Torii endpoints, TLS policies, retries, and telemetry hooks from the generated `iroha_config` manifest and enforces immutability post-initialisation (`java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ClientConfig.java`).
2. **Key management / optional StrongBox** — Deterministic software-backed signing is the supported baseline. Applications may explicitly select hardware-backed signing through `SystemAndroidKeystoreBackend` and `AttestationVerifier`, with policies documented in `specs/sdk/android/key_management.md`. Conditional attestation capture/validation uses `scripts/android_keystore_attestation.sh` and the CI helper `scripts/android_strongbox_attestation_ci.sh`.
3. **Telemetry & redaction** — Instrumentation funnels through the shared schema described in `specs/sdk/android/telemetry_redaction.md`, exporting hashed authorities, bucketed device profiles, and override auditing hooks enforced by the Support Playbook.
4. **Operations runbooks** — `specs/android_runbook.md` (operator response) and `specs/android_support_playbook.md` (SLA + escalation) harden the TOE’s operational footprint with deterministic overrides, chaos drills, and evidence capture.
5. **Release provenance** — Gradle-based builds use the CycloneDX plugin plus reproducible build flags as captured in `specs/sdk/android/developer_experience_plan.md` and the AND6 compliance checklist. Release artefacts are signed and cross-referenced in `specs/release/provenance/android/`.

## 2. Assets & Assumptions

| Asset | Description | Security Objective |
|-------|-------------|--------------------|
| Configuration manifests | Norito-derived `ClientConfig` snapshots distributed with apps. | Authenticity, integrity, and confidentiality at rest. |
| Signing keys | Keys generated or imported through the software provider or, when explicitly selected, StrongBox/TEE providers. | Rotation and deterministic custody for the software baseline; attestation logging and no key export for the optional hardware profile. |
| Telemetry streams | OTLP traces/logs/metrics exported from SDK instrumentation. | Pseudonymisation (hashed authorities), minimised PII, override auditing. |
| Ledger interactions | Norito payloads, admission metadata, Torii network traffic. | Mutual authentication, replay-resistant requests, deterministic retries. |

Assumptions:

- Mobile OS provides standard sandboxing + SELinux; devices selected for the optional StrongBox profile implement Google’s keymaster interface.
- Operators provision Torii endpoints with TLS certificates signed by council-trusted CAs.
- Build infrastructure honours reproducible-build requirements before publishing to Maven.

## 3. Threats & Controls

| Threat | Control | Evidence |
|--------|---------|----------|
| Tampered configuration manifests | `ClientConfig` validates manifests (hash + schema) before applying and logs denied reloads via `android.telemetry.config.reload`. | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ClientConfig.java`; `specs/android_runbook.md` §1–2. |
| Compromise of signing keys | Rotation, deterministic software custody, and caller-selected StrongBox policies reduce exposure. Optional attestation harnesses and device-lab audits identify hardware-route drift without making hardware a release prerequisite; overrides are documented per incident. | `specs/sdk/android/key_management.md`; `specs/compliance/android/device_lab_reservation.md`; `scripts/android_strongbox_attestation_ci.sh`. |
| PII leakage in telemetry | Blake2b-hashed authorities, bucketed device profiles, carrier omission, override logging. | `specs/sdk/android/telemetry_redaction.md`; Support Playbook §8. |
| Replay or downgrade on Torii RPC | `/v1/pipeline` request builder enforces TLS pinning, noise channel policy, and retry budgets with hashed authority context. | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ToriiRequestBuilder.java`; `specs/sdk/android/networking.md` (planned). |
| Unsigned or non-reproducible releases | CycloneDX SBOM + Sigstore attestations gated by AND6 checklist; release RFCs require evidence in `specs/release/provenance/android/`. | `specs/sdk/android/developer_experience_plan.md`; `specs/compliance/android/eu/sbom_attestation.md`. |
| Incomplete incident handling | Runbook + playbook define overrides, chaos drills, and escalation tree; telemetry overrides require signed Norito requests. | `specs/android_runbook.md`; `specs/android_support_playbook.md`. |

## 4. Evaluation Activities

1. **Design review** — Compliance + SRE verify that configuration, key management, telemetry, and release controls map to ETSI security objectives.
2. **Implementation checks** — Automated tests:
   - For an explicitly selected hardware profile, `scripts/android_strongbox_attestation_ci.sh` verifies captured bundles for every StrongBox device listed in the matrix. Without that profile this check is not applicable and does not fail the baseline.
   - `scripts/check_android_samples.sh` and Managed Device CI ensure sample apps honour `ClientConfig`/telemetry contracts.
3. **Operational validation** — Quarterly chaos drills per `specs/sdk/android/telemetry_chaos_checklist.md` (redaction + override exercises).
4. **Evidence retention** — Artefacts stored under `specs/compliance/android/` (this folder) and referenced from `status.md`.

## 5. ETSI EN 319 401 Mapping

| EN 319 401 Clause | SDK Control |
|-------------------|-------------|
| 7.1 Security policy | Documented in this security target + Support Playbook. |
| 7.2 Organisational security | RACI + on-call ownership in Support Playbook §2. |
| 7.3 Asset management | Configuration, key, and telemetry asset objectives defined in §2 above. |
| 7.4 Access control | Provider-neutral signing plus caller-selected StrongBox policies and an override workflow requiring signed Norito artefacts. |
| 7.5 Cryptographic controls | Software key generation and storage form the baseline; AND2 attestation requirements apply only to an explicitly selected hardware profile. |
| 7.6 Operations security | Telemetry hashing, chaos rehearsals, incident response, and release evidence gating. |
| 7.7 Communications security | `/v1/pipeline` TLS policy + hashed authorities (telemetry redaction doc). |
| 7.8 System acquisition / development | Reproducible Gradle builds, SBOMs, and provenance gates in AND5/AND6 plans. |
| 7.9 Supplier relationships | Buildkite + Sigstore attestations recorded alongside third-party dependency SBOMs. |
| 7.10 Incident management | Runbook/Playbook escalation, override logging, telemetry fail counters. |

## 6. Maintenance

- Update this document whenever the SDK introduces new cryptographic algorithms, telemetry categories, or release automation changes.
- Link signed copies in `specs/compliance/android/evidence_log.csv` with SHA-256 digests and reviewer sign-offs.
