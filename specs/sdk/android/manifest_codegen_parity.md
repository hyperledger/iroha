<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Manifest & ISI Codegen Parity Inventory (AND3)

Roadmap item **AND3 — Scope manifest/ISI codegen parity** requires a single
reference describing which instructions already ship through the Android
codegen/export pipeline and what remains to be generated (especially fees,
manifest workflows, and governance payloads). This note captures the current
state of the artifacts under `target-codex/android_codegen/` and threads the
remaining work into concrete generator + fixture tasks so the Kotlin/Java
builders can stay aligned with the Rust data model.

## 1. Inputs & Evidence

- The exporter source now enumerates **112**
  `InstructionBox` entries with discriminants, schema hashes, enum layouts, and
  Rust type names exported by `norito_codegen_exporter`
  (`tools/norito_codegen_exporter/src/main.rs`). Each entry now carries a
  schema-derived summary when rustdoc text is unavailable, eliminating the
  earlier `TODO` placeholders. The tracked files under
  `specs/sdk/android/generated/` still describe the previous 110-entry run;
  rerun `make android-codegen-docs` from a settled Cargo workspace before
  treating those generated references as current.
- `target-codex/android_codegen/builder_index.json` lists the generated Kotlin /
  Java builders plus package names, feature gates, and stability annotations
  consumed by `scripts/android_codegen_docs.py` (and surfaced in
  `specs/sdk/android/generated/` via `make android-codegen-docs`).
- `target-codex/android_codegen/instruction_examples/` carries one Norito JSON
  example per discriminant. The file names mirror the Rust type paths, which
  lets CI diff fixture drift deterministically.
- `cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-fixtures --output-root <absent-absolute-external-root>` is the sole owner of
  canonical fixture publication. Each invocation writes one complete create-only
  publication beneath that external root without touching tracked files. Run
  it at two independent absent roots and, before any tracked update, require
  identical exact path sets, entry types, modes, completion manifests, and
  every file byte. Apply the reviewed identity-relative patch from either
  sealed root, then run `norito-rpc-verify` and the Android fixture checker.
  The publication contains the canonical corpus, the generated Java resource
  mirror, and descriptor-only Python and Swift mirrors; Android resources are
  outputs, never canonical inputs.

## 2. Instruction Coverage Snapshot

- The current 112-discriminant exporter set spans 18 generator families sourced from
  `crates/iroha_data_model/src/isi/`, and every discriminant has a builder
  entry. The four boxed helpers use the short wire IDs `iroha.grant`,
  `iroha.revoke`, `iroha.set_key_value`, and `iroha.remove_key_value` while
  mapping to their fully qualified Rust types.
- The previous 110-discriminant run has one Norito example per entry. The new
  `ReportKaigiRelayHealth` and `UnregisterKaigiRelay` entries still need the
  canonical generator rerun before fixture generation is complete. Android then
  needs to bundle the examples into a signed manifest per release (see §4).

| Module | Count | Example discriminants |
|---|---:|---|
| `transparent` | 23 | iroha.custom, iroha.execute_trigger |
| `register` | 16 | iroha.register, iroha.unregister |
| `zk` | 7 | CancelConfidentialPolicyTransition, CreateElection |
| `sorafs` | 15 | ApprovePinManifest, BindManifestAlias |
| `governance` | 6 | CastPlainBallot, ProposeDeployContract |
| `kaigi` | 9 | CreateKaigi, UnregisterKaigiRelay |
| `ministry` | 1 | SubmitAgendaProposal |
| `mint_burn` | 6 | iroha.burn, iroha.mint |
| `transfer` | 6 | iroha.transfer, iroha.transfer_batch |
| `smart_contract_code` | 8 | ActivateContractInstance, UploadSmartContractCodeChunk |
| `repo` | 3 | iroha.repo.initiate, iroha.repo.reverse |
| `runtime_upgrade` | 3 | iroha.runtime_upgrade.activate, iroha.runtime_upgrade.cancel |
| `settlement` | 3 | iroha.settlement.dvp, iroha.settlement.pvp |
| `verifying_keys` | 2 | RegisterVerifyingKey, UpdateVerifyingKey |
| `GrantBox` | 1 | iroha.grant |
| `RemoveKeyValueBox` | 1 | iroha.remove_key_value |
| `RevokeBox` | 1 | iroha.revoke |
| `SetKeyValueBox` | 1 | iroha.set_key_value |

The first-release Android projection intentionally omits the generic shield,
shielded-transfer, and unshield discriminants. The KAGEMUSHA V1
top-up/redemption instructions were deleted on 2026-10-05; KAGEMUSHA proof
artifacts are not generic transaction builders.

## 3. Fees, Manifest & Governance Payloads

### 3.1 Trading & Fee-Bearing Flows

- **Repo instructions (`repo.rs`).** `RepoIsi` carries the complete immutable
  proposal, while `ReverseRepoIsi` carries only the agreement identifier and
  settles the stored terms at maturity
  (`crates/iroha_data_model/src/isi/repo.rs`). Android codegen must emit
  builders for the proposal and the ID-only maturity instruction, with Norito
  examples covering bilateral and tri-party owner-issued consent. Fixture plan:
  extend the canonical fixture definitions and
  `tools/norito_codegen_exporter/src/norito_rpc.rs`, then run the xtask owner so
  repo-specific vectors enter `fixtures/norito_rpc/` and every generated SDK
  mirror in one publication. Do not introduce an Android-owned fixture path.
- **Settlement instructions (`settlement.rs`).** DVP/PVP payloads plus the
  generic `SettlementInstructionBox` are already exported, but Android still
  needs typed builders covering `SettlementPlan`, `SettlementLeg`, and metadata
  (see `crates/iroha_data_model/src/isi/settlement.rs`). Fee coverage relies on
  stitching both legs into a single Norito frame, so the fixture bundler must
  emit dual-leg samples with deterministic metadata.

### 3.2 Manifest / Pinning Surfaces

- **SoraFS pin manifests (`sorafs.rs`).** Instructions such as
  `RegisterPinManifest`, `IssueReplicationOrder`, and
  `RecordCapacityTelemetry` (all in `crates/iroha_data_model/src/isi/sorafs.rs`)
  depend on Norito manifests produced by `sorafs_manifest`. Android builders
  need to expose the same `ManifestV1`, `PinPolicy`, and telemetry fields that
  Rust serializes. Action items:
  1. ✅ `scripts/android_codegen_docs.py` now inlines the manifest field tables,
     so operator SDKs can audit rollout knobs without reading the Rust sources.
     The generator emits dedicated sections for `PinPolicy`, `ChunkerProfileHandle`,
     `ManifestAliasBinding`, and `StorageClass`, and the rendered reference captures
     the same table data that the roadmap called out.【scripts/android_codegen_docs.py:134】【specs/sdk/android/generated/instructions.md:903】
  2. ✅ Replay the shared fixture in `fixtures/sorafs_orchestrator/` via
     `scripts/android_codegen_replay_sorafs_fixture.py`. The helper calls
     `sorafs_manifest_builder` with the multi-provider payload, stores the full
     manifest report under
     `target-codex/android_codegen/sorafs_manifest/multi_peer_parity_v1.json`,
     emits the tracked sample at
     `specs/sdk/android/generated/fixtures/sorafs_register_pin_manifest_multi_peer_parity_v1.json`,
     and injects a `fixture_example` block into the RegisterPinManifest example
     so the Android builders can hydrate real manifest data. A dedicated pytest
     (`scripts/tests/android_sorafs_fixture_example_test.py`) loads the fixture,
     chunker profile, and generated example to ensure the digests, policy knobs,
     and canonical manifest bytes match the multi-peer scenario. The instruction
     intentionally omits a submission epoch because Core derives it from the
     block consensus timestamp.
  3. ✅ Manifest lifecycle coverage now includes approval, retirement, and alias
     binding: the Android SDK exposes typed builders for
     `ApprovePinManifest`, `RetirePinManifest`, and `BindManifestAlias`
     (`java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/ApprovePinManifestInstruction.java`,
     `java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/RetirePinManifestInstruction.java`,
     `java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/instructions/BindManifestAliasInstruction.java`).
     Registration, approval, and retirement builders do not accept lifecycle
     epochs; argument-map decoders reject those retired keys and Core records
     the corresponding consensus timestamp.
     Note: transaction encoding now requires wire-framed instruction payloads;
     the argument-map helpers are retained only for parity checks. Round-trip
     tests live under
     `java/iroha_android/src/test/java/org/hyperledger/iroha/android/sorafs/SorafsManifestInstructionBuilderTests.java`
     so CI will fail if the Norito arguments diverge from the Rust schema hashes.

- **Smart-contract uploads (`smart_contract_code.rs`).** The doc generator now
  renders the `ContractManifest`, `AccessSetHints`, and
  `EntrypointDescriptor` tables directly from
  `instruction_manifest.json` so the ABI/code-hash invariants baked into
  `crates/iroha_data_model/src/isi/smart_contract_code.rs` are spelled out
  alongside each instruction. The shared sample hash pair derived from
  `defaults/executor.to` is generated by
  `cargo run --locked -p ivm --features dev-tools --bin ivm_fixture_export -- --write` (and checked
  with the corresponding `--check` mode) under
  `specs/sdk/android/generated/fixtures/smart_contract_code_executor_hashes.json`,
  and `scripts/android_codegen_docs.py` links to that fixture so readers can
  verify their `.to` parsing logic without re-deriving the Blake2b/ABI digests.

### 3.3 Governance & Runtime Inputs

- **Kaigi governance (`kaigi.rs`).** `CreateKaigi`, `RecordKaigiUsage`, and
  relay-management instructions (see `crates/iroha_data_model/src/isi/kaigi.rs`)
  must be called out explicitly because they share telemetry proofs across SDKs.
  Builders should surface relay manifest hashes and usage counters so Kaigi
  audits stay deterministic.
- **Runtime upgrades (`runtime_upgrade.rs`).** `ProposeRuntimeUpgrade`,
  `ActivateRuntimeUpgrade`, and `CancelRuntimeUpgrade` discriminate runtime
  payloads with `abi_hash` gating. Android builders must embed the hash
  validation rules described in `specs/ivm.md` and reuse the Norito
  fixture used by the Rust admission tests.
- **Governance drafts (`governance.rs`).** ✅ Android now ships typed builders for
  certificate-only proposal instructions, `CreateParliamentGovernanceAttemptV1`,
  `SubmitParliamentLifecycleTransitionV1`, standalone `CastZkBallot` and
  `CastPlainBallot`. There is no caller-selected council roster, finalization,
  enactment, or equal public Parliament-ballot builder. The generated reference
  documents the permitted schema hashes, while
  `java/iroha_android/src/test/java/org/hyperledger/iroha/android/governance/GovernanceInstructionBuilderTests.java`
  exercises round-trip coverage so SDK integrations stay aligned with the Rust data model.

## 4. Generator & Fixture Outputs

1. **Doc extraction.** `norito_codegen_exporter` now accepts `--doc-json <path>`
   and uses the supplied rustdoc JSON to populate the `documentation` field for
   every instruction. Generate the JSON via
   `cargo +nightly rustdoc -p iroha_data_model -- -Zunstable-options --output-format json`
   (the file lands under `target/doc/iroha_data_model.json`) and pass that path
   when invoking the exporter so `scripts/android_codegen_docs.py` can drop the
   `TODO` placeholders automatically.
2. **Manifest-aware builder docs.** Update the generator to include enum layout
   tables (tags/payloads) for `sorafs`, `repo`, `settlement`, and governance
   instructions. This keeps the Kotlin/Java builders self-explanatory without
   reading the Rust source.
3. **Fixture bundler.** `scripts/android_codegen_fixtures.py` now zips the
   contents of `target-codex/android_codegen/instruction_examples/` into
   `artifacts/android/codegen_fixtures/<timestamp>/instruction_examples.zip`,
   writes the SHA-256 sidecar, and records `metadata.json`. CI can call this
   helper before publishing SDK parity fixtures.
4. **CI gate.** The OpenAPI release-input workflow runs
   `bash ci/check_android_codegen.sh`. The gate clones the exact clean commit
   twice without hard links, seals both source mirrors read-only, assigns each
   replay a fresh external `/private/tmp/.../target`, and routes both Cargo
   invocations through the shared pinned no-interference policy. Generated docs
   and parity summaries stay out of tree and must agree with each other and the
   checked-in files byte-for-byte. Standalone runs create an all-or-none
   authenticated artifact/cancellation channel pair; inherited runs must supply
   both. The retained work root contains the raw stages, while the log,
   deterministic archives, summaries, and final `COMPLETED.json` receipt remain
   below the authenticated artifact root. Completion publication is bracketed
   by cooperative cancellation checks that never interrupt an in-flight child.
   The gate reports both authenticated channel paths before replay begins.
5. **Recorded metadata.** `specs/sdk/android/generated/codegen_manifest_metadata.json`
   now stores the blessed SHA-256 digests and entry counts for the instruction
   manifest and builder index. The helper `scripts/check_android_codegen_parity.py`
   ingests those values and emits a parity summary (see `make android-codegen-verify`),
   failing the build when regenerated manifests drift from the recorded hashes.

## 5. Next Steps & Owners

Closed: the generator, fixtures, documentation, and CI gate are all in place.
Future schema changes should follow the change-log workflow
(`specs/sdk/android/norito_instruction_changes.md`). Generate reviewed candidate
outputs out of tree first; update recorded hashes and docs only after the two
independent sealed replays are byte-identical. The developer make targets use
`scripts/sumeragi_release_cargo_proxy.sh` and therefore require a fresh,
owner-private external `CARGO_TARGET_DIR`.
