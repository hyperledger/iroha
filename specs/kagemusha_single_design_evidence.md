# KAGEMUSHA single design — evidence and migration inventory

Status: source inventory for the [implementation design](kagemusha_single_design_proposal.md), 2026-10-03;
the deletion of the superseded implementation was applied on 2026-10-05 (§§2–3).
The ordinary Load source account in §2.3 and the G5 rows was updated on 2026-10-06.
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

The superseded implementation inspected on 2026-10-03 was deleted on
2026-10-05 under the owner decision of 2026-10-04: this is the first release,
so no old code, layout or decoder is kept for compatibility. That covers the old
`kagemusha_v1_state` state machine, the halo2 recursion family, the bridge
coordinator and the per-operation online-control protocol. §3 records each
disposition. Deleted code remains in Git history; later goals rebuild from the
[design](kagemusha_single_design_proposal.md), not by restoring that code.

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
- **Source:** `crates/iroha_core_zk/src/kagemusha_wallet_advance_v1.rs` and its
  child modules implement the G2 provider (`Advance`). It keeps marker
  generations, recovery capsules, completion records and retained results under
  one non-backup custody root, with reconciliation, enrollment and a
  fault-injecting store simulator. It owns custody bytes and head selection,
  never monetary validity. The platform adapters are Kotlin
  `kagemusha-wallet-android` (`sdk.offline.wallet`) and Swift
  `KagemushaWalletApplePlatformV1`/`KagemushaWalletAppleAppAttestV1`. The
  bridge adapter between them and the Rust provider does not exist yet.
- **Recorded:** the withdrawn KAGEMUSHA V1 production-readiness record (Git
  history), Pixel 6 physical observations, reports StrongBox use-limit tag 405
  in `softwareEnforced` and no hardware rollback-resistance tag. A successful
  first signature and refused second signature therefore did not qualify a
  hardware nonforking ratchet. The eSE observations did not establish a usable
  applet or recovery contract.
- **Recorded limitation:** the inspected records do not establish
  hardware-enforced nonforking against a compromised OS. That is optional
  strengthening research, not a dependency of the selected trust model or a
  restriction on integration and use. Software journal/marker durability and
  restore behavior remain useful measurements for the primary provider.
  Record further results in the [verification checklist](kagemusha_evidence_gate.md).

### 2.2 Proof implementation

- **Source:** the PIPA-v1 stack (`crates/iroha_pasta`, `iroha_plonk`,
  `iroha_plonk_gadgets`; [PIPA-v1](plonk_ipa_v1.md)) is Iroha-owned.
  `crates/iroha_kagemusha_proof` implements the split-lineage step, operation,
  accumulation and transport relations over the G1 layout. The shared native
  wallet consumes these relations through its authenticated producer inventory.
  The complete current catalog, genuine funded exchange and final envelope
  qualification remain open; component implementation is not release evidence.
- **Deleted:** the old halo2 recursion family (`kagemusha_v1_recursion/`, including its mint-finality authority), with its
  authenticated verifier and artifact set, production prover, P-256 and Guard
  equations and the node runtime verifier. Retained consumers are migrated and
  re-keyed on the native stack. The three superseded vendor trees and temporary
  `iroha_plonk_oracle` are deleted; independent vectors and mutation tests remain.
  See the [native prover migration](native_prover_migration_inventory.md) for
  each consumer's validation scope and remaining rebuilt-delivery gates.
- **Recorded:** the in-circuit P-256 and IPA scaling measurements are in the
  [checklist](kagemusha_evidence_gate.md#8-recorded-results). Earlier records
  of 8,584 advice columns for ordinary credential generation and a 192 MiB
  Claim advice bank describe deleted circuits and bound nothing in this design.

### 2.3 Ledger, consensus residue and services

- **Deleted:** the `TopUpKagemushaV1`, `TopUpKagemushaOrdinaryV1` and
  `RedeemKagemushaV1` instructions and their node execution. The deletion also
  covers the reserve, the ordinary-mint family, the KAGEMUSHA World storages and
  prepaid operation-index pool, the Kura sidecars and ordinary credit worker,
  and the governed verifier registry with its Parliament proposals. Gone too:
  the executor permissions, the Torii `/v1/kagemusha/*` routes, the client
  ordinary-native and enrollment APIs, `kagami kagemusha`, and the
  `settlement.kagemusha`, `torii.kagemusha_v1_commands` and
  `nexus.storage.kagemusha_operation_index_bytes` settings.
- **Source — ordinary Load (G5):**
  `crates/iroha_data_model/src/isi/kagemusha_wallet.rs` defines `IssueLoad` with
  the exact scheme, wallet, asset digest, expected ordinal, request ID, amount
  and optional charge. `crates/iroha_core/src/kagemusha_wallet_v1/ledger.rs`
  checks activation, the asset and ordinal, and applies reserve funding, charge
  and ordinal advance atomically. Only the original transaction and height can
  recover an identical execution result; a newly signed or later transaction
  cannot reuse the request ID. Recover a lost response by querying the original
  `KagemushaWalletLoadReceiptV1`. The online Load-authorizer role, custody and
  publisher service, registration signer field, `PublishVoucher` and
  `RotateLoadAuthorizer` instructions are removed; there is no extra publication
  transaction.
- **Source — native finality and query:**
  `crates/iroha_data_model/src/isi/kagemusha_wallet/load_finality.rs` implements
  `verify_finalized_kagemusha_wallet_load_v1` and its opaque
  `VerifiedKagemushaWalletLoadV1`. It verifies native global scope and successful
  external transaction inclusion, exact payer, direct instruction index and
  approved terms; it derives the receipt with the original hash and height.
  `crates/iroha_core/src/kagemusha_wallet_v1/committed.rs` reads recovery data
  from one committed global State view, checking payer/scope, retained row
  integrity and original transaction hash/height membership under finite record
  and cumulative decode limits. It performs no historical QC reconstruction.
  `crates/iroha_torii/src/kagemusha_wallet.rs` returns that canonical receipt;
  old receipt recovery does not depend on local certificate availability.
  Neither this query nor decoding its data confers independent finality. Model native-certificate
  tests use synthetic execution rows and do not establish monetary execution;
  Core's execution tests own that boundary.
- **Consensus:** the paired-Pasta mint-finality authority, its genesis parameters,
  signing seeds, validator-key publication and KAGEMUSHA commit attestation are
  deleted. Ordinary Load uses the global chain's native finality and ordered BLS
  validator roster, with no KAGEMUSHA-specific consensus signer or mint seal.
  Deployment and fixture consumers use that same consensus model.
- **Offline Load source and integration:** the native wallet authenticates the
  receipt block's exact BLS CommitQC and counted Load-event inclusion against
  signed genesis and authenticated epoch changes before requesting Advance.
  The receipt is unsigned and binds the successful transaction, height, payer
  digest and complete approved terms. The four-A/three-W monetary Load relation
  binds those exact terms, replay insertion and the credential-bound Advance
  signature; it does not prove BLS verification inside PLONK. The finality
  circuits, recursive history prover and finality key inventories are deleted.
  Funding assurance relies on the selected released-application/stock-OS trust
  profile, not on a caller-supplied verification boolean. Current implementation
  and qualification criteria are tracked in
  [NF1-NF6](kagemusha_native_finality_goals.md).
  TODO(G3/G5): qualify the regenerated complete monetary catalog, genuine Load
  and downstream lineage, complete 10,000-byte payment envelopes, four-validator
  execution and physical-phone performance on the current candidate. Historical
  recursive-finality captures do not qualify this replacement.

## 3. Disposition of the inspected implementation

The 2026-10-03 inventory classified these components; the 2026-10-05 deletion
applied the dispositions below. Each rebuild is an implementation goal of the
design and keeps none of the deleted wire formats or production profiles.

| Component and former owner | Disposition | Rebuild requirements and checks |
|---|---|---|
| State machine and durable custody: `S/` (`crates/iroha_core_zk/src/kagemusha_v1_state/`), `KagemushaStateMachineV1` and its journal/recovery modules | **Deleted.** The G2 provider (§2.1) owns custody bytes and head selection; no monetary state owner exists yet. | The new state owner applies these rules. Committed Send irreversibly subtracts `amount + fee`. Receive credits exactly `amount` once and permanently maps its credit ID to `(amount, receive sequence)` under `consumed_credit_root`. Its receipt binds the full canonical Payment digest, and the lineage proof records that digest and a burn flag in the lineage-level credit-digest root. Order each operation as native verification and step proof, then `Advance`, then the background lineage fold. Add the fold scheduler, fold-witness custody, `burned_total`, the lineage-adjusted values that Send, Unload and Retiring take from the predecessor wrap, and the burn/no-op branches. A Request is signed setup scoped to the payer's next send ordinal, receiver, amount and nonce; it creates no receiver monetary head. No OpenRequest, Refuse, Refund, AcknowledgeRefusal, Acknowledge or PruneOutcome transition exists. |
| Proofs: `R/` (`crates/iroha_core_zk/src/kagemusha_v1_recursion/`), P-256 gadget, Poseidon, stored polynomials and artifact authentication | **Deleted**, including the mint-finality authority (§2.3). Rebuilt on PIPA-v1 in `iroha_kagemusha_proof`. | One artifact set and verifier family: per-operation single-parity step relations, the lineage relation and its single-parity transport wrap. Check both parities, genuine lineage, negative/mutation cases, native-vs-circuit acceptance equivalence, bounded resources and authenticated node verification. Protocol P-256 signatures use the final canonical low-S rule in native and circuit verification; raw platform evidence keeps its original bytes. |
| Crypto: `crates/iroha_crypto/src/kagemusha.rs`, `KagemushaRecoverySeedV1`, `seal_kagemusha_credit_bytes_v1` | **Deleted.** No kept consumer used it. | Define any credit encryption or recovery primitive the design needs with canonical vectors, below protocol authority. |
| Native coordinator: `crates/connect_norito_bridge/src/kagemusha_core_coordinator_v1/` and every KAGEMUSHA C/JNI export | **Deleted.** | The bridge adapter provides opaque handles, retained originals, durable retries and platform dispatch, without online operation orchestration. It retains immutable Payment outbox bytes until verified Credited evidence permits ArchiveSent; retries resend those exact bytes to the same receiver. Credited uses the Receive package or a CreditStatus membership opening in the credit-digest root of a folded receiver head, binding the exact Payment digest and burn flag. ArchiveSent verifies it before cleanup, keeps the Payment bytes until its step is folded on the archive branch and preserves any fee-claim copy. Delivery evidence neither establishes finality nor authorizes a refund. Swift/Kotlin adapters exercise that same lifecycle across crashes and restarts. |
| Ordinary online control: `S/ordinary_*`, `R/ordinary_*`, `crates/iroha/src/client/ordinary_native.rs`, ordinary Torii routes and Python workers | **Deleted**, including per-payment Reserve/Commit/FI authority and its protocol-only types. | Offline payment needs no service response. Enrollment and platform-evidence verification are rebuilt for G5 on the retained verifiers (`python/iroha_app_attestation`, Kotlin `sdk.crypto.keystore.attestation`). |
| Signature-only suite: Swift `KagemushaAttested/`, Kotlin `offline/attested/`, JS `kagemushaAttestedV1.js`, Python `attested_enrollment.py`/`attested_selection.py` | **Deleted** with its payment format and independent wallet API. The JS module had no device-key or platform role; SoraFS packaging tests now sample `crc64Xz.js`. Python donor behavior moved into `python/iroha_app_attestation`: hardware-enforced patch levels and the `PATCH_POLICY_MET` predicate (`attestation.py`), and retryable `VerificationUnavailable` for revocation, Play Integrity decoder and OAuth outages (decoder HTTP 400 alone rejects). Deliberately dropped: up-to-24-hour revocation-list reuse (every check fetches the live list), S/T/F/A tiers, minimum-versionCode admission, optional Play Integrity at sync and OEM roots without live revocation. | Swift: the Secure Enclave key code moved, with tri-state probes, into `KagemushaWalletApplePlatformV1` (the iPhone `Advance` adapter). Kotlin: the payment-key, probe and backup rules live in `kagemusha-wallet-android` `sdk.offline.wallet` (the Android `Advance` adapter), and SEC1 key decoding in `KagemushaP256Codec`. Open: the Native-selected Android policy carries no patch floor, so `PATCH_POLICY_MET` is not yet recorded. |
| Stub crates: `crates/iroha_kagemusha_attested`, `crates/iroha_kagemusha_issuer` | **Deleted** after donor/dependency checks found no donor value, together with their workspace, lockfile, CI-lane and target-inventory references. | Workspace/manifests/lockfile, scripts and packaging refer to the canonical owners only. |
| Secure-element bridge and provider contracts: `kagemusha_device_bridge_v1.rs`, `KagemushaOmapiDeviceLifecycleV1`, Swift `KagemushaSecureElement*`, GuardBundle/provider/eSE specifications | **Deleted.** The G2 provider's `Advance` interface is the one adapter boundary. | Stronger hardware research is optional and is not an integration or deployment gate. Journal/marker exact-successor, restore, retained-result and recovery tests use the trusted-OS boundary. |
| Testnet experiment value path: bridge `kagemusha_testnet_*` modules, Swift/Kotlin `KagemushaTestnetValue*`, `KagemushaReleasePurposeV1::TestnetExperiment` | **Deleted.** A testnet runs the same protocol; a testnet reset is its cutover. | No second value ledger, release purpose or validation path. |
| Device probes and testnet observation tools | **Deleted** with the retired protocol (KeyMint single-use probes, the App Attest probe app, physical-evidence and observation-bundle tooling). | New device results go into the [checklist](kagemusha_evidence_gate.md) with raw artifacts; diagnostic tokens/keys remain outside the repository. |
| Model wire and authority objects: `crates/iroha_data_model/src/kagemusha/` (`kagemusha_v1/`, `hardware*.rs`, `kagemusha_release_v1.rs`, `verifier_registry_v1.rs`, `kagemusha_ordinary_*`, retail/mobile-bootstrap modules), `iroha_core_zk/src/kagemusha_sender_wire.rs`, bridge hardware-evidence, mobile-bootstrap, sender-release, contract-vector and `platform_jni/kagemusha_*` modules | **Replaced by the G1 objects** (`kagemusha_wallet_v1`, [wire record](kagemusha_wallet_wire_v1.md)); the old types are deleted. The device public-key and signature types moved into G1. | Final codec fixtures; retired layouts rejected. |
| Ledger/model: `crates/iroha_data_model/src/isi/kagemusha_v1.rs`, node `isi/kagemusha*` and `state/kagemusha_*`, bridge `kagemusha_reserve_finality_v1.rs` | **Deleted**; the consensus mint-finality authority is also deleted (§2.3). | G5 ordinary `IssueLoad` and the original `KagemushaWalletLoadReceiptV1` query are implemented (§2.3), with exact asset/ordinal checks, activation and native finality. Recovery reads the original receipt; a different transaction cannot repeat its successful issuance. Native BLS admission and the complete monetary Load catalog require current-candidate integration qualification. Fees are earned at Send commit, with one payout per credit ID independent of delivery. Check whole-node execution and proof qualification on the final candidate. |
| Torii/client service: `crates/iroha_torii/src/kagemusha_commands.rs`, `kagemusha_state.rs`, shared API schemas, the issuer service in `python/iroha_app_attestation` (`/v1/kagemusha/ordinary-app-*`) and the participant enrollment HTTP contract (`kagemusha_ordinary_enrollment_http_v1.rs`, its fixture and clients) | **Deleted.** The generic ledger resource-name reads moved to the core route catalog. | G5 now exposes the authenticated original Load receipt query in `crates/iroha_torii/src/kagemusha_wallet.rs`; funding itself is an ordinary signed `IssueLoad` transaction, with no publisher or second transaction. The complete route/client set for §2.2 credentials and renewal, unload, status, §7 policy, time anchors and quota shares still needs qualification. Generated clients and route tests match one schema; receipt data alone is not finality evidence. |
| Swift and Kotlin wallets, platform keys and UI | **Old monetary implementations deleted.** Kept: Swift `KagemushaWalletWireV1` and `KagemushaWalletApple*V1`, Kotlin `KagemushaWalletWireV1`, `KagemushaP256Codec` and `kagemusha-wallet-android` `sdk.offline.wallet`. | Adapters to the shared Rust core: native artifact and device tests, restore/retry behavior, canonical fixtures and Java-source consumer coverage. |
| JavaScript, Python and C# SDK surfaces | **Monetary engines and retired-profile APIs deleted.** | A wallet-facing API delegates to the shared native owner once it exists. Published exports, installed-package tests, fixtures and examples migrate together. |
| Java SDK duplicates under `java/` | **KAGEMUSHA and IrohaPeer duplicates deleted.** | Remaining Java retirement is tracked in `specs/jvm_consolidation_inventory.md`. |
| Transport: `IrohaPeerWireV1`, `IrohaPeerQRV1`, NFC/Nearby, `crates/iroha_petal` and SDK ports | **Retained** as generic carriers of opaque payloads; the old KAGEMUSHA payload kinds are removed. The IPM1/IRQR framing and caps live in the [wire record](kagemusha_wallet_wire_v1.md). | Final payload bounds, corruption/duplicate handling and physical ordered-pair tests. Codec/simulator passes do not qualify cameras or radios. |
| Configuration: `crates/iroha_config/src/parameters/{user,actual,defaults}.rs` and `actual/kagemusha.rs` | **Old settings deleted**; removed names fail explicitly. | New settings go through user → actual → defaults. Protocol authority is never an environment toggle. |
| Formal model: none | **Write a new model from the proposal.** The old `formal/kagemusha_v1/` model of the retired Rotate, hardware-counter and acknowledgement protocol was deleted (owner decision, 2026-10-04). State the one-successor assumption as a property of the honest-OS journal/marker provider. Model irreversible Send, identical Payment retries, permanent consumed-credit/digest membership, exactly-once Receive and ArchiveSent with verified CreditStatus or Receive evidence. Omit cancellation and refund transitions. | Check conservation, no restored sender value after commit, duplicate delivery and ordinary-user restore paths. Retiring preserves old receiving custody for unseen Payments; an empty balance or outbox cannot justify key deletion. Receipt loss cannot undo credit; do not present the provider assumption as resistance to a compromised OS. |
| Fixtures and release tools: `fixtures/offline/`, `fixtures/kagemusha/`, `fixtures/governance/kagemusha*`, `fixtures/petal/`, KAGEMUSHA scripts, `iroha_kagami` | **Old fixture families, release/evidence tooling and `kagami kagemusha` deleted.** Kept: `fixtures/kagemusha/wallet_v1_vectors.json`, `fixtures/kagemusha/platform-original-container-v1/` (generic platform-evidence verifier test), `fixtures/native_prover/` and the generic `fixtures/petal/`. | One canonical producer per format, cross-SDK parity, retired-layout negatives and signed release evidence. |

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

`kagemusha_single_design_proposal.md` is the implementation target,
`kagemusha_wallet_wire_v1.md` the G1 wire record and `kagemusha_evidence_gate.md`
the verification checklist. The old KAGEMUSHA specifications were withdrawn on
2026-10-05 together with the code they described. They covered the V1 wire
contract; the compact-key, native-profile, phone-algorithm, physical-evidence,
production-readiness, provider-policy and release-runner records; the
GuardBundle, device-bridge, device-sender, receiver-admission, app-owned-hardware
and Pixel 6 eSE contracts; the Android hardware qualification matrix; and the
old peer-transport contract. The carrier framing formerly in the peer-transport
contract lives in the wire record. `qr_stream.md`, `petal_stream.md` and
`new_pipeline.md` no longer define KAGEMUSHA payload kinds or instructions.
Record new device observations in the checklist with source and artifact
identity. Update `status.md` and `roadmap.md` when actual health or remaining
outcomes change; routine test transcripts belong in the candidate's validation
record.
