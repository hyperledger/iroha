# KAGEMUSHA single design — evidence and migration inventory

Status: source inventory for the [implementation design](kagemusha_single_design_proposal.md), 2026-10-03.
This file records implementation evidence and the disposition of existing components.
The design fixes the required behavior; a retained component is not thereby qualified.
The irreversible Send and replay rules below are implementation requirements;
this documentation change implements none of them.

## 1. Baseline and evidence limits

The Git baseline is `ab6d83b7216f4e8ec00b29a31baeed0637929600`.
The files below were read in the working tree on top of that commit, including
staged and unstaged implementation changes. The hash alone does not reproduce
those changes. Each implementation or deletion
change records its commit and diff and repeats the affected dependency checks.

Paths and symbols identify the inspected sources; line numbers and historical
file counts are deliberately omitted. This is a capability inventory, not a
claim that every file has been audited. No build, proof run, network operation
or physical-device test was performed for this rewrite.

Evidence classes used below:

- **Source:** the named code implements or rejects a particular path.
- **Recorded:** an existing repository record describes a run or observation;
  it was not repeated here.
- **Required:** a property of the selected design, still needing implementation
  or qualification where the source and records do not establish it.

Primary reference links in §5 describe API contracts, not a qualified device.
The consolidation rechecked the AOSP attestation schema and Apple Keychain
guide on 2026-10-03; other links remain implementation references rather than
newly verified platform findings.
Historical research estimates and reviewer counts are not release evidence.

## 2. Current capability and remaining work

For compact source names, `R` means
`crates/iroha_core_zk/src/kagemusha_v1_recursion/`, and `S` means
`crates/iroha_core_zk/src/kagemusha_v1_state/`.

### 2.1 Monetary authority and physical devices

- **Selected trust model:** the released wallet runs on a stock vendor OS,
  unrooted, not jailbroken and without a rootkit or other OS compromise. Require
  locked verified boot where platform attestation exposes it. The POC assumes
  those conditions; the same conditions are the deployment trust boundary.
- **Required:** each monetary commit consumes one exact predecessor and
  authorizes at most one successor under that trust model. The primary provider
  is the shared software journal and marker on the trusted OS, with a
  hardware-backed key for signing custody. Produce and natively verify the step
  proof before `Advance` durably commits and signs its proof digest; prove the
  lineage proof and its wrap in the background after `Advance`, and require the
  predecessor's wrap wherever the design's §3.1 requires it. Verify the
  current receipt natively; successor lineage proofs verify predecessor and
  incoming receipts in the relation. Signing alone is not a second production
  payment mode.
- **Attestation boundary:** check available platform facts at enrollment and
  applicable refresh. Neither attestation nor the monetary proof proves the
  continuing absence of runtime OS compromise. Reject evidence that violates
  admission policy without describing successful admission as a live rootkit test.
- **Source:** `S/mod.rs`, `KagemushaStateMachineV1`, owns balance transitions,
  replay state and recovery projections. `KagemushaGuardBundleVerifierV1` and
  `RejectAllKagemushaGuardBundleVerifierV1` keep missing authority closed.
  `specs/kagemusha_guard_bundle_v1.md` and
  `specs/kagemusha_v1_phone_algorithm.md` describe a stronger hardware-provider
  contract. Rework those bindings for the selected software provider; their
  current checks do not already implement that integration.
- **Recorded:** `specs/kagemusha_v1_production_readiness.md`, Pixel 6 physical
  observations, reports StrongBox use-limit tag 405 in `softwareEnforced` and
  no hardware rollback-resistance tag. A successful first signature and refused
  second signature therefore did not qualify a hardware nonforking ratchet.
  The eSE observations did not establish a usable applet or recovery contract.
- **Source limitation:** `SingleUseProbeRunnerV1.run` in
  `kotlin/client-android/src/main/java/org/hyperledger/iroha/sdk/offline/probe/AndroidKeyMintSingleUseProbeV1.kt`
  returns when the hardware feature flag is absent, before generating a key.
  That probe cannot settle what an independently attempted TEE key would attest.
- **Recorded limitation:** `status.md` and the production-readiness record leave
  physical qualification open. The inspected records do not establish
  hardware-enforced nonforking against a compromised OS. That is optional
  strengthening research, not a dependency of the selected trust model or a
  restriction on integration and use. Software journal/marker durability and
  restore behavior remain useful measurements for the primary provider.
  Record further results in the [verification checklist](kagemusha_evidence_gate.md).

### 2.2 Proof implementation

- **Source:** `R/native_backend.rs`, `KagemushaAuthenticatedRecursiveVerifierV1`,
  implements authenticated proof verification, including
  `verify_payment_and_decide`. `R/artifacts.rs`,
  `KagemushaAuthenticatedArtifactSetV1`, authenticates the release artifacts.
  The retired node runtime verifier, release installation and pooled-reserve
  instruction implementation are removed. The selected wallet design still
  requires its authenticated node verification and ledger integration.
- **Source:** `R/production_prover.rs`, `KagemushaProductionProverV1`, requires
  release-pinned material and retained authority. The non-ordinary witness
  intake, `R/native_outgoing_witness.rs`, has the trait
  `KagemushaNativeOutgoingWitnessSourceV1` and registration function
  `register_kagemusha_native_outgoing_witness_source_v1`. The repository search
  found only its failing test implementation and no installation call.
  This finding applies to that intake, not every ordinary proof helper.
- **Source:** `R/composite.rs`, `RecursiveStateConstructionV1::Production`,
  still refuses an ordinary selection with the message that the complete Guard
  original and current-lease consumer are required. However,
  `R/ordinary_state_receive_consumer.rs` now implements
  `constrain_ordinary_receive_opening_v1`, and `composite.rs` calls it.
  An inventory saying ordinary ReceiveFold has no consumer is obsolete.
- **Source:** the P-256 equations and ordinary Guard composition exist in
  `R/ordinary_platform_equation.rs`, `R/ordinary_issuer_equation.rs` and
  `R/ordinary_guard_composition.rs`. Preserve useful equations while replacing
  their bindings to the retired per-operation online-control protocol.
- **Recorded:** `status.md` leaves complete recursive monetary proofs, funded
  State transitions, settlement and recovery unqualified. The genuine lineage
  test `real_payment_handoff_installs_original_sender_and_receiver_owners` in
  `R/real_payment_corridor/state_milestone.rs` is ignored. Source and component
  results do not establish a completed, qualified payment corridor.
- **Recorded resource blocker:** `status.md` reports 8,584 advice columns for
  ordinary credential generation against a 1,024-column guard.
  `R/artifact_resource_preflight.rs`, `KAGEMUSHA_HELPER_ADVICE_COLUMN_MAX_V1`,
  is a host allocation guard. The circuit's phone execution role is not
  established by that number. It must not be reported as measured phone RAM.
  The same module's Claim-circuit test computes a 192 MiB advice bank at k=16;
  that is a source-level bound, not a complete proving measurement.
- **Source:** Halo2/Pasta proving is mandatory in the current
  `crates/iroha_core_zk/Cargo.toml`. The bridge depends on that owner in
  `crates/connect_norito_bridge/Cargo.toml`. Earlier claims that removing a
  bridge feature would remove the prover do not describe these manifests.
  The design targets the Iroha-native PLONK/IPA stack
  ([PIPA-v1](plonk_ipa_v1.md)), in which vendored halo2-axiom is a test oracle
  only; moving these manifests to it is implementation work.

### 2.3 The ordinary path and ledger

- **Source:** `S/ordinary_outgoing_native_driver.rs`,
  `select_retained_outgoing_terminal`, requires an acknowledged Reserve before
  selecting the terminal approval. `S/ordinary_cash_state_commit.rs`,
  `advance_acknowledged_commit` and `acknowledge_state_advance`, require a
  global Commit and a subsequent FI-control capture before complete delivery.
  The bridge's `ordinary_outgoing_driver.rs` enumerates those phases under
  `crates/connect_norito_bridge/src/kagemusha_core_coordinator_v1/`.
  This representative payment path depends on an external service per operation.
- **Distinction:** `KagemushaAppOperationApprovalChallengeV1` is signed by the
  device. Its name alone does not establish an online issuer dependency.
  Reserve/Commit receipts and current FI control establish the dependency above.
- **Source:** the retired top-up/redemption execution family, ordinary Mint
  publication and Kura credit outbox are removed with their detached tests.
  State no longer installs that runtime verifier or persists its governed
  registry and pooled-reserve records. The retained operation indexes in
  `crates/iroha_core/src/state/kagemusha_operation_indexes.rs` remain part of
  State; their presence does not implement the selected wallet's ledger path.
- **Required:** implement and qualify the selected Load/Unload path, reserve
  receipts, replay protection and authenticated finality on the current
  canonical wallet objects. Removing retired execution does not complete that
  integration.

## 3. Retain, rework and delete

These are implementation dispositions for the selected design, not alternative
payment modes. The dependency checks in §4 guide each deletion. Retaining a module retains
only the capabilities used by the final protocol; it does not retain its old
wire format or authorize another production profile.

| Component and inspected owner | Disposition and destination | Integration work and checks |
|---|---|---|
| State machine and durable custody: `S/mod.rs`, `KagemushaStateMachineV1`, associated journal/recovery modules | **Rework in place.** This remains the Rust owner of monetary state, replay and recovery. Committed Send irreversibly subtracts `amount + fee`; Receive credits exactly `amount` once and permanently maps its credit ID to `(amount, receive sequence)` under `consumed_credit_root`, its receipt binds the full canonical Payment digest, and the lineage proof records that digest and a burn flag in the lineage-level credit-digest root. Order each operation as native verification and step proof, then `Advance`, then the background lineage fold; add the fold scheduler, fold-witness custody, `burned_total`, the lineage-adjusted values that Send, Unload and Retiring take from the predecessor wrap, and the burn/no-op branches. Bind these operations to the software journal/marker provider and fixed relations under the stock uncompromised-OS assumption. | Request is signed setup scoped to the payer's next send ordinal, receiver, amount and nonce; it creates no receiver monetary head. Retire OpenRequest, Refuse, Refund, AcknowledgeRefusal, Acknowledge and PruneOutcome from the target transition set. |
| Proofs: `R/`, P-256 gadget, Poseidon, stored polynomials and artifact authentication | **Retain and rework.** One artifact set and verifier family: per-operation single-parity step relations, the lineage relation and its single-parity transport wrap, on the Iroha-native PIPA-v1 stack. Remove obsolete profile branches after the final bindings work. | Both parities, genuine lineage, negative/mutation cases, native-vs-circuit acceptance equivalence, bounded resources and authenticated node verification. Protocol P-256 signatures use the final canonical low-S rule in native and circuit verification; raw platform evidence keeps its original bytes. |
| Crypto: `crates/iroha_crypto/src/kagemusha.rs`, `KagemushaRecoverySeedV1`, `seal_kagemusha_credit_bytes_v1` | **Retain.** Encryption/recovery primitives stay below protocol authority. Update domains only with canonical vectors. | Every retained caller binds inputs to the final transition and custody contract. |
| Native coordinator: `crates/connect_norito_bridge/src/kagemusha_core_coordinator_v1.rs` and directory | **Rework.** Preserve opaque handles, retained originals, durable retries and platform dispatch; replace online operation orchestration. Retain immutable Payment outbox bytes until verified Credited evidence permits ArchiveSent; retries resend those exact bytes to the same receiver. | Credited uses the Receive package or a CreditStatus membership opening in the credit-digest root of a folded receiver head, binding the exact Payment digest and burn flag. ArchiveSent verifies it before cleanup, keeps the Payment bytes until its step is folded on the archive branch and preserves any fee-claim copy. Delivery evidence neither establishes finality nor authorizes a refund. Swift/Kotlin adapters exercise that same lifecycle across crashes and restarts. |
| Ordinary online control: `S/ordinary_*`, `R/ordinary_*`, ordinary Torii routes and Python workers | **Split by capability.** The Rust SDK ordinary-native client and its development executables are removed. Retain enrollment, verified platform evidence, reusable equations and storage where still consumed. **Delete** per-payment Reserve/Commit/FI authority and its protocol-only types after moving shared consumers. | Offline payment needs no service response; inbound/outbound recovery and proof intake use the final authority. Do not delete by filename prefix. |
| Signature-only suite: Swift `KagemushaAttested/`, Kotlin `offline/attested/`, JS `kagemushaAttestedV1.js`, Python `attested_enrollment.py`/`attested_selection.py` | **Deleted** with its payment format and independent wallet API. The JS module had no device-key or platform role; SoraFS packaging tests now sample `crc64Xz.js`. Python donor behavior moved into `python/iroha_app_attestation`: hardware-enforced patch levels and the `PATCH_POLICY_MET` predicate (`attestation.py`); retryable `VerificationUnavailable` for revocation, Play Integrity decoder and OAuth outages (decoder HTTP 400 alone rejects), answered with 503 by the issuer routes and worker hardware phases; refusal of the repository's invented mock and demo roots as OEM anchors (`provider.py`). Deliberately dropped: up-to-24-hour revocation-list reuse (every check fetches the live list), S/T/F/A tiers, minimum-versionCode admission, optional Play Integrity at sync and OEM roots without live revocation. | Done for JS, Python, Swift and Kotlin. Swift: the Secure Enclave key code moved, with tri-state probes, into `KagemushaWalletApplePlatformV1` (the iPhone `Advance` adapter); the SQLite store is superseded by the Rust provider. Kotlin: `offline/attested` deleted; the payment-key, probe and backup rules live in `kagemusha-wallet-android` `sdk.offline.wallet` (the Android `Advance` adapter), and SEC1 key decoding in `KagemushaP256Codec`. Open: the Native-selected Android policy carries no patch floor, so `PATCH_POLICY_MET` is not yet recorded. |
| Stub crates: `crates/iroha_kagemusha_attested`, `crates/iroha_kagemusha_issuer` | **Deleted** after donor/dependency checks found no donor value, together with their workspace, lockfile, CI-lane and target-inventory references. | Workspace/manifests/lockfile, scripts and packaging refer to the canonical owners only. |
| Secure-element bridge and provider contracts: `kagemusha_device_bridge_v1.rs`, `KagemushaOmapiDeviceLifecycleV1`, Swift `KagemushaSecureElement*`, GuardBundle/provider specs | **Rework the shared commit interface for the primary software provider.** Delete obsolete mandatory OEM/applet dispatch after consumers migrate. Retain useful hardware probes and contract notes as optional strengthening research within the same protocol. | Journal/marker exact-successor, restore, retained-result and recovery tests use the trusted-OS boundary. Stronger hardware research is not an integration or deployment gate. |
| Testnet experiment value path: bridge `kagemusha_testnet_native_{value_ledger,mint_runtime,mobile_host,startup}_v1.rs`, `kagemusha_testnet_{finality_chain,publication}_v1.rs`, Swift/Kotlin `KagemushaTestnetValue*`, `KagemushaReleasePurposeV1::TestnetExperiment` | **Delete** after useful tests move to the single Load/Send path. A testnet runs the same protocol. | No second value ledger, release purpose or validation path remains. |
| Device probes and testnet observation tools | **Retain qualifying probes.** Move useful diagnostics into the single evidence harness; delete redundant one-off wrappers after coverage migrates. | Every retained support claim has reproducible device evidence and raw artifacts; diagnostic tokens/keys remain outside the repository. |
| Model wire and authority objects: `crates/iroha_data_model/src/kagemusha/` (`kagemusha_v1/exchange.rs`, `hardware*.rs`, `kagemusha_release_v1.rs`, `verifier_registry_v1.rs`, `kagemusha_ordinary_*`, retail/mobile-bootstrap modules), `iroha_core_zk/src/kagemusha_sender_wire.rs`, bridge `kagemusha_hardware_evidence_v1/`, `kagemusha_mobile_bootstrap*_v1.rs`, `kagemusha_sender_release_evidence.rs`, `kagemusha_contract_vector_v1.rs`, `platform_jni/kagemusha_*.rs` | **Replace with the G1 objects, then delete** the old wire, hardware profile/credential and per-operation authority types after consumers migrate. | Final codec fixtures; retired layouts rejected. |
| Ledger/model: canonical wallet objects, retained State operation indexes and finality commitments | **Implement the selected ledger path.** The retired node top-up/redemption family, governed verifier installation and ordinary Mint outbox are removed. One Load/Unload path must bind canonical reserve receipts and finality. Require completed Bootstrap activation before issuing a load voucher. Fees are earned at Send commit, with one payout per credit ID independent of delivery. | Atomic activation/reserve/replay behavior, canonical codec fixtures, authenticated Load/Unload and whole-node tests on the final candidate remain required. |
| Torii/client service: `crates/iroha_torii/src/kagemusha_commands.rs`, `kagemusha_state.rs`, shared API schemas | **Retain load/unload/status service ownership; rework schemas.** Torii has no enrollment route at HEAD; Two layers move into this family, as draft §9 assigns, for §2.2 credentials and renewal, §7 policy, time anchors and quota shares: the issuer service in `python/iroha_app_attestation` (`ordinary_service.py` serves `/v1/kagemusha/ordinary-app-credentials` and `/v1/kagemusha/ordinary-app-raw-attestations`), and the participant-facing enrollment contract `/v1/kagemusha/enrollment/ordinary/{prepare,raw-attestation,certificate,start,finish}` (`crates/iroha_data_model/src/kagemusha/kagemusha_ordinary_enrollment_http_v1.rs`, fixture `fixtures/kagemusha/participant_enrollment_http_v1.json`, clients in `crates/iroha`, Swift and Kotlin). No server in this repository serves the participant-facing routes; the replacement defines one route set and its server. Delete ordinary payment-control routes after their consumers migrate. | Generated clients and route tests match one schema; no removed endpoint remains a payment prerequisite. |
| Swift and Kotlin wallets, platform keys and UI | **Rework as adapters to the existing Rust core.** Preserve platform signing, transport and lifecycle tests; remove independent monetary state implementations. Android client and wallet/JNI ownership remain in their existing modules. | Native artifact + device tests, restore/retry behavior, canonical fixtures and Java-source consumer coverage. |
| JavaScript, Python and C# SDK surfaces | **Retain final wire/transport and online service clients.** Delete separate monetary engines and retired-profile APIs. A wallet-facing API delegates to the shared native owner. | Published exports, installed-package tests, fixtures and examples migrate together. |
| Java SDK duplicates under `java/` | **Delete through Kotlin consolidation**, preserving Java-source consumers of the canonical Kotlin API. | Every capability, fixture, generator, assertion and delivery path accounted for under `specs/jvm_consolidation_inventory.md`. |
| Transport: `IrohaPeerWireV1`, `IrohaPeerQRV1`, NFC/Nearby, `crates/iroha_petal` and SDK ports | **Retain carriers around one canonical monetary envelope.** Petal transports opaque payloads; it is not a monetary design. Consolidate obsolete QR framing after consumer migration. | Final payload bounds, corruption/duplicate handling and physical ordered-pair tests. Codec/simulator passes do not qualify cameras or radios. |
| Configuration: `crates/iroha_config/src/parameters/{user,actual,defaults}.rs` and `actual/kagemusha.rs` | **Rework through the existing configuration pipeline.** Keep artifact paths/resource limits; remove retired service/profile settings. Protocol authority is never an environment toggle. | Config parse/default tests and all constructors consume the final settings; removed names fail explicitly. |
| Formal model: none at HEAD | **Write a new model from the proposal.** The old `formal/kagemusha_v1/` model of the retired Rotate, hardware-counter and acknowledgement protocol was deleted (owner decision, 2026-10-04). State the one-successor assumption as a property of the honest-OS journal/marker provider. Model irreversible Send, identical Payment retries, permanent consumed-credit/digest membership, exactly-once Receive and ArchiveSent with verified CreditStatus or Receive evidence. Omit cancellation and refund transitions. | Check conservation, no restored sender value after commit, duplicate delivery and ordinary-user restore paths. Retiring preserves old receiving custody for unseen Payments; an empty balance or outbox cannot justify key deletion. Receipt loss cannot undo credit; do not present the provider assumption as resistance to a compromised OS. |
| Fixtures and release tools: `fixtures/offline/`, `fixtures/kagemusha/`, `fixtures/governance/kagemusha*`, `fixtures/petal/`, KAGEMUSHA scripts, `iroha_kagami` | **Retain generators and provenance; regenerate affected outputs.** Delete obsolete fixture families only after assertions migrate. Keep generic Petal fixtures. | One canonical producer per format, cross-SDK parity, retired-layout negatives and signed release evidence. |

## 4. Migration and verification checklist

1. **Dependency map:** enumerate Rust imports, generated schemas, SDK exports,
   scripts, fixtures, documentation, packaging and known external consumers for
   the exact component. Classify each symbol as retained, moved or removed.
   Do this on the recorded candidate, including changes since this inventory.
2. **Replacement:** the same patch connects the replacement and removes its
   obsolete consumers. Preserve useful assertions in tests for the final API.
   The first release keeps no compatibility alias, fallback decoder, protocol
   selector or signature-only payment branch.
3. **Validation:** run formatting and affected crate/SDK/packaging suites;
   consensus/codec changes also require their fixture, replay and network checks.
   Record the remaining release-matrix coverage. Preserve a unique security,
   recovery or delivery capability while migrating its consumers.
4. **Monetary boundary:** migrate authority consumers to the final owner before
   deleting their former implementation. Record genuine-proof, commit and
   recovery results separately from source integration. Unused stubs and
   duplicate transport wrappers follow their dependency and coverage checks.
5. **Artifact cutover:** freeze one final envelope, relation, key set and release
   identity. Test explicit rejection of retired objects and mixed releases.
   Include outstanding issued state in the integration assessment; this inventory
   did not query a live deployment and cannot establish that none exists.

Integration and verification work remains: the software journal/marker provider
on each platform, a complete proof-producing and verifying corridor, bounded
proof and witness storage with recovery, and physical throughput/durability
measurements. Record the stock, uncompromised-OS custody assumption for each POC
and deployment. Software-provider tests do not establish protection against a
compromised OS. Missing evidence changes what can be claimed, not permission to
integrate or use the implementation, and does not define a second protocol.

## 5. Primary references retained for implementation

| Subject | Primary reference | Use and boundary |
|---|---|---|
| Android key attestation | [Google guide](https://developer.android.com/privacy-and-security/security-key-attestation), [AOSP attestation schema](https://source.android.com/docs/security/features/keystore/attestation) | Chain and authorization-list verification; inspect the returned security levels and enforcement lists. |
| Android use limits | [KeyGenParameterSpec.setMaxUsageCount](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setMaxUsageCount(int)), [single-use feature](https://developer.android.com/reference/android/content/pm/PackageManager#FEATURE_KEYSTORE_SINGLE_USE_KEY) | Distinguish hardware enforcement from Keystore software behavior; test exact predecessor/transition binding as a separate obligation. |
| Android roots and revocation | [Google attestation repository](https://github.com/android/keyattestation), [revocation status](https://android.googleapis.com/attestation/status) | Verifier vectors and revocation input; neither is a device qualification report. |
| App Attest | [Establishing app integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) | Verify Apple's exact attestation/assertion subject. Do not infer nonforking monetary state from app identity or an increasing counter. |
| Secure Enclave keys | [Protecting keys](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) | Key custody API; a hardware-held signing key alone is not a state-commit primitive. |
| Apple storage | [Keychain protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web), [passcode-set device-only class](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) | Storage/lifecycle contracts to test, without promoting app-side checkpoint logic to compromised-OS protection. |
| NFC | [Android HCE](https://developer.android.com/develop/connectivity/nfc/hce), [CoreNFC ISO7816](https://developer.apple.com/documentation/corenfc/nfciso7816tag), [Apple NFC/SE platform](https://developer.apple.com/support/nfc-se-platform/) | Carrier capabilities and platform-access conditions; verify each intended pair on devices. |
| Recursive proof reference | [Pickles specification](https://o1-labs.github.io/proof-systems/specs/pickles/) | Reference construction; it does not establish this implementation's soundness, phone performance or artifact size. |

## 6. Specification migration

`kagemusha_single_design_proposal.md` is the implementation target. Update the
wire contract in `kagemusha_v1.md`, GuardBundle/provider/bridge specifications,
`kagemusha_v1_phone_algorithm.md`, and formal model with the implementation that
changes each contract. Mark `kagemusha_pixel6_ese_service_contract_v1.md`,
`sdk/android/readiness/android_strongbox_device_matrix.md`,
`peer_transport_v1.md`, the KAGEMUSHA kind tables in `qr_stream.md` and
`petal_stream.md`, and the KAGEMUSHA section of `new_pipeline.md` superseded
now. Remove release-approval requirements from the
compact-key and native-profile documents.
Keep compact-key, native-profile, physical-evidence and
release-runner documents only as codec and evidence records. In
`iroha_data_model::kagemusha::kagemusha_release_v1`, remove the review, fuzz,
reproducible-build and physical profile qualifications required by
`KagemushaInternalValidationReceiptV1`, the Production/TestnetExperiment split
and `settlement.kagemusha.allow_testnet_experimental_release`. The artifact
signer's signature authenticates the artifact set; no node, Torii or wallet
constructor requires recorded evidence. Withdraw the ordinary
online-control contract in `kagemusha_app_owned_hardware_v1.md` after its shared
enrollment material has one canonical home. Preserve useful device observations
in the readiness/physical evidence records, with source and artifact identity.
Update `status.md` and `roadmap.md` when actual health or remaining outcomes
change; routine test transcripts belong in the candidate's validation record.
