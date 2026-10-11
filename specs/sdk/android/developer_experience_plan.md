<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Developer Experience Plan (AND5)

**Status:** Completed 2026-05-02 (samples + manifests + publishing pipeline wired)  
**Roadmap Link:** AND5 — Developer Experience & Samples  
**Owners:** Android DX TL (engineering), Docs/DevRel Manager (content), Release Engineering (publishing), LLM (acting editor)

## 1. Goals & Scope

AND5 packages the Android SDK for external adoption once AND2 (key management) and AND4 (Torii networking parity) reach stability. Deliverables span sample applications, implementation-coupled documentation, and publication automation so partners can evaluate the SDK without bespoke support.

Objectives:

- Provide two canonical sample apps that demonstrate software-backed signing,
  optional secure-element posture, offline workflows, and `/v1/pipeline`
  networking behaviour.
- Publish developer guides that explain key management, offline signing, telemetry/observability hooks, configuration, and troubleshooting with explicit `iroha_config` mappings.
- Automate artifact distribution (signed AAR/Maven packages) with reproducible metadata, SBOMs, and provenance attestations aligned with the workspace release policy.
- Coordinate public guides and translations in the sibling `iroha-docs`
  repository.

## 2. Sample Applications

| Sample | Capabilities | Dependencies | Notes |
|--------|--------------|--------------|-------|
| **Operator Console** | Governance transaction builder with a software signing baseline and optional StrongBox posture, Torii `/v1/pipeline` retries, telemetry dashboards (AND7 hooks) | AND4 mock Torii harness; optional AND2 attestation harness; `specs/android_support_playbook.md` for ops alignment | Target audience: validator/operators. Must expose provenance hashes and the pending queue inspector; expose attestation upload only when the optional hardware profile is selected. Scaffold lives at `examples/android/operator-console`. |
| **Retail Wallet** | Offline signing envelope creation, device-to-device handoff, wire-framed instruction payloads (transfer/mint), recovery + rotation playbooks | AND2 fallback derivation, `TransactionBuilder.encodeAndSignEnvelopeWithAttestation`, Norito fixture regeneration SLA | Demonstrates sender-final, immutable device-to-device KAGEMUSHA handoff. Separate queued online envelopes may replay when connectivity returns; KAGEMUSHA ownership is never reconciled or reversed. Ships with mocked ledger + CLI to replay online envelopes. Scaffold lives at `examples/android/retail-wallet`. |

Implementation notes:

- Both samples live under `examples/android/` with shared Gradle configuration and Managed Device CI lanes.
- Telemetry observers must forward `android.telemetry.*` counters to the staging OTEL collector so readiness rehearsals reuse production dashboards.
- Each sample emits `sample_manifest.json` capturing SDK version, feature flags, and expected Torii endpoints; release automation copies the manifest into the artefact bundle for provenance.
- Detailed design notes for each experience now live under `specs/sdk/android/samples/` (see `operator_console.md` and `retail_wallet.md`) so engineering tickets can link to concrete acceptance criteria.
- The operator console now attaches a redaction-aware `TelemetryObserver` backed by a JSONL sink whenever `ANDROID_SAMPLE_TELEMETRY_LOG` is present, hashing authorities with the sample salt/version/rotation embedded in `BuildConfig` and the sample manifest so AND7 adoption harnesses can ingest the records without additional wiring.【examples/android/operator-console/src/main/java/org/hyperledger/iroha/samples/operator/env/TelemetryConfig.kt:1】【examples/android/operator-console/build.gradle.kts:21】

## 3. Tooling & Automation

1. **Gradle Tasks**
   - `./gradlew :examples:operator-console:managedDeviceDebugAndroidTest` gate tied to Buildkite.
   - `./gradlew :examples:retail-wallet:bundleRelease` produces signed bundle + SBOM using the workspace `cyclonedx` plugin.
2. **CLI scripts**
   - `scripts/android_sample_env.sh` bootstraps the Torii mock, multi-provider SoraFS fixture (via `ci/check_sorafs_orchestrator_adoption.sh`), and telemetry exporters so demos/rehearsals share the AND7 harness. Each run drops `artifacts/android/telemetry/<timestamp>/` containing the SoraFS scoreboard/summary plus `telemetry/load-generator.log`; DevRel must archive that directory with their enablement notes and follow up with `./ci/check_android_dashboard_parity.sh` so the portal-ready parity diff stays in sync with SRE governance evidence. The helper also records `ANDROID_SAMPLE_SORAFS_SCOREBOARD_SHA256` / `ANDROID_SAMPLE_SORAFS_SUMMARY_SHA256` inside the exported `.env` file so adoption gates and readiness packets can cite the exact digest that the SF-6c checks verified.
   - `scripts/publish_android_sdk.sh` runs the SDK + sample tests, generates SBOM/provenance bundles, publishes artifacts into `artifacts/android/maven/<version>` (and optionally a remote Maven repository), and writes `publish_summary.json` / `checksums.txt` so the release bundle has deterministic evidence. Example:

     ```bash
     scripts/publish_android_sdk.sh \
       --version 0.9.0 \
       --repo-url https://maven.example.org/releases \
       --username "$MAVEN_USER" \
       --password "$MAVEN_TOKEN"
     ```

   - `deploy/android/publish_ga.sh` wraps the publish script during the go/no-go window, copying the Maven repo + SBOM bundle into `artifacts/releases/android/<version>/` and producing the README that Release Engineering drops into the compliance packet. The Iroha 3 release pipeline accepts `--publish-android-sdk [--android-sdk-repo-url …]` to run the same flow automatically when `scripts/run_release_pipeline.py` is used.
   - `scripts/check_android_maven_repo.py` replays the hash/metadata validation described in `specs/sdk/android/maven_staging_plan.md`, ensuring `publish_summary.json`, `checksums.txt`, and `maven-metadata.xml` stay in sync before a staging drop is announced. Emit both the JSON and Markdown reports (`--json-out … --markdown-out …`) so AND5 evidence bundles have a machine-readable artefact and a governance-ready summary side-by-side.
   - `scripts/check_android_samples.sh` builds the SDK module plus both sample apps; wire it into CI once Gradle is available on runners.
3. **CI Hooks**
- `ci/check_android_samples.sh` shells out to `scripts/check_android_samples.sh` so manifest gating stays centralized, then runs the release lint/unit-test permutations for both samples and refreshes Gradle dependency locks (`gradle -q dependencies --write-locks`). CI fails if lockfiles drift; local runs can set `ANDROID_SAMPLES_SKIP_{BUILD,LINT_TEST,LOCKS}=1` when the Android toolchain is unavailable.

### Scaffold Status (2026-05-02)

- ✅ Gradle multi-module project under `examples/android/` with system-Gradle shim.
- ✅ Operator console + retail wallet wired to SDK components, sample env exports, and
  live harness artefacts (StrongBox posture, queue depth, SoraFS scoreboard/summary/receipt
  digests, telemetry, hand-off endpoints).
- ✅ Sample manifests now capture Torii endpoints, feature flags, policy overrides, POS asset
  hashes, harness artefacts/digests, and localization coverage; `scripts/check_android_samples.sh`
  + `ci/check_android_samples.sh` gate builds on manifest + lint/unit tests.

## 4. Documentation Deliverables

| Doc | Path | Status | Summary |
|-----|------|--------|---------|
| SDK quickstart refresh | `specs/sdk/android/index.md` | Update | Expand setup section with sample app references, Managed Device requirements, and Torii pipeline pointers. |
| Key management & attestation guide | `specs/sdk/android/key_management.md` | ✅ Published | Explains the software provider baseline, optional StrongBox preferences, alias lifecycle, and conditional attestation bundle handling with references to the device-lab lanes in `specs/compliance/android/device_lab_reservation.md`. |
| Offline signing & envelopes | `specs/sdk/android/offline_signing.md` | ✅ Published | Details the envelope schema, Norito payload reuse, recovery workflows, and CLI helpers for verification. |
| Networking & telemetry guide | `specs/sdk/android/networking.md` | ✅ Published | Captures `/v1/pipeline` HTTP client configuration, retry/queue plumbing, Norito RPC usage, and telemetry observer alignment with `telemetry_redaction.md`. |
| Configuration & manifest guide | `specs/sdk/android/configuration.md` | ✅ Published | Documents the `iroha_config` → `ClientConfig` pipeline, manifest hashing, telemetry redaction knobs, pending-queue wiring, and the schema diff/override workflows referenced by `android_runbook.md`. |
| Sample app walkthroughs | `specs/sdk/android/samples/{operator_console,retail_wallet}.md` | ✅ Drafted | Step-by-step guides for operator console and retail wallet, including `iroha_config` excerpts and troubleshooting tables. |

All guides must embed Norito snippets using canonical fixtures and link back to the relevant `iroha_config` struct or CLI flag for each configuration knob. Add `//!` crate docs where new helper crates are introduced for samples.

## 5. Enablement

- Enablement deliverables (recordings, office hours, knowledge checks) follow the format established for AND7 telemetry readiness; archive artefacts beside telemetry materials in `specs/sdk/android/readiness/`.
- Public guides and translations are maintained in the sibling
  `iroha-docs` repository and published at <https://docs.iroha.tech/>.

## 6. Release & Compliance Hooks

- Maven/AAR promotion follows the AND6 checklist: reproducible build hash, SBOM (CycloneDX JSON), Sigstore attestations, and signed provenance manifest stored under `specs/release/provenance/android/`.
- Publishing pipeline must fail if `scripts/check_android_fixtures.py` reports
   drift or if the Java consumer mirror diverges from the reviewed canonical
   manifest and `norito-rpc-verify` result.
- Update `status.md` and `android_support_playbook.md` whenever SLA tables, release cadence, or sample coverage change.
- Compliance review requires attaching the SBOM, provenance bundle, and RACI for on-call support transitions.
- Stage promotions must follow `specs/sdk/android/maven_staging_plan.md` so Release Engineering can cite the validation report emitted by `scripts/check_android_maven_repo.py` during governance reviews.

## 7. Timeline & Gates

| Phase | Target | Exit Criteria |
|-------|--------|---------------|
| Beta readiness (Q4 2026) | AND2/AND4 outputs integrated; sample apps compile with Managed Device CI | Operator console + retail wallet demos recorded; key-management/offline docs published; Maven dry-run promoted to staging. |
| GA hardening (Q1 2027) | Align with AND6/AND7 audits | Instrumentation alerts connected to AND7 dashboards; SBOM + provenance automation exercised twice; support playbook references sample coverage. |
| LTS support (post-GA) | Within 90 days of GA | Sample apps updated for LTS branch, docs note supported SDK/ABI versions, and release automation signed off by compliance. |

## 8. Dependencies & Risks

- **Dependencies:** AND2 key providers, AND4 networking mocks, AND7 telemetry hooks, and Release Engineering publishing scripts.
- **Risks & Mitigations:**
  - *Sample app regressions:* nightly Managed Device runs with flake triage; `ci/check_android_samples.sh` wired into `run_tests.sh`.
  - *Publishing failures:* staged promotions before GA; treat SBOM/attestation generation as blocking steps with artifact diffing.

## 9. Next Actions

1. Keep `scripts/check_android_samples.sh` / `ci/check_android_samples.sh` green (manifests +
   lint/unit tests) before publishing snapshots.
2. Regenerate sample manifests whenever `android_sample_env.sh` or POS/security assets change and
   attach them to release/readiness bundles; keep hashes mirrored in `status.md`.

Track completion status in `status.md` (Android DX section) and update `roadmap.md` when milestones advance.
