# KAGEMUSHA first-release qualification goals

This execution plan closes the existing [single-design §10.1 requirements](kagemusha_single_design_proposal.md#101-first-release-completion-sequence).
It does not change the monetary, platform, size or performance requirements.
All goals remain open until their stated evidence exists for the candidate.
The [evidence gate](kagemusha_evidence_gate.md#8-recorded-results) records
qualification; the [native finality goals](kagemusha_native_finality_goals.md)
and [compact artifact contract](kagemusha_compact_artifact_goals.md) retain
their component ownership.

## Candidate and first-release rules

- Work in the existing checkout; preserve concurrent changes. Do not create a
  branch, worktree or commit without the owner's request. Use `git rm` for
  tracked-file deletions and format only changed Rust files with edition 2024.
- Finish implementation and focused regressions before the qualification
  capture. Obtain the owner's frozen-source window before building the shared
  release candidate; a merge or unresolved conflicts must be concluded first.
- Delete replaced implementations, unused dependencies, layouts, aliases,
  exports, fixtures and fallback decoders after migrating retained behavior and
  assertions. Keep one current implementation. Rejection tests for retired input
  remain useful; retaining an old decoder or key fallback does not.
- Keep exact commands, source/compiler inputs, lockfile, signed catalog, key,
  native-library and SDK hashes under `target/qualification/`. Retain failed and
  interrupted attempts. A changed consumed input requires affected evidence
  to be repeated; a historical pass never qualifies a new candidate.
- Keep software fixtures, local four-validator networks, live Taira and physical
  devices separate. No component test or host timing closes a phone requirement.

## Ordered goals

| ID | Owner / existing goals | Completion result |
| --- | --- | --- |
| KR0 — Coherent candidate | Release/native/SDK, G7 | Capture the frozen source and actual compiler dependency closure; regenerate and strictly admit both complete source profiles and registry DATA; rebuild CLI, Core, Core-ZK, Android, Apple and host native consumers; rerun host JNI and the complete host journey. Run the M3 `prepare` → `run` → `summarize` protocol with three fresh-process blocks, process CPU for one worker, observed elapsed time for four and kernel RSS. Record actual current route/program counts rather than copying an older catalog. |
| KR1 — iOS release and restore | Native/Swift, G2 | Trace Selected, journal, signature, anchor and exposed Payment through interrupted/ambiguous writes, concurrency, restart and replay. Exercise supported stock-device backup/restore and migration schedules. A released Payment must exclude an old head under the same usable key through a nonrollback authority, or make that key unusable. Retain the existing double-anchor-loss counterexample until an actual platform guarantee excludes it; Keychain readback and additional writes alone do not close it. |
| KR2 — Complete monetary lifecycle | Wallet/Core/SDK, G4/G5, NF1–NF6 | Execute enrollment → activation → funded Load → offline A→B→C → Unload → once-only ledger payout. Include receiver restart with a fresh-ID duplicate Receive, reverse-direction payments, Receive folding, ArchiveReceive, ArchiveStatus, fees, quota/lease controls, local blacklists and charge continuations. At every durable boundary cover crashes, lost acknowledgements, exact retries, duplicate credits, conflicting inputs, invalid proofs and stale state; preserve conservation and every committed payment. Run host, four local validators and live Taira separately. |
| KR3 — Physical phones | Android/Swift/carriers, G2/G4/G7 | On the specified Pixel 6 / Android 17 and iPhone 16 Pro Max, retain actual key attestation/App Attest, activation, funded Load, bidirectional offline payments over each supported NFC/QR/Nearby carrier, restart/interruption and Unload. Record actual model/OS/build/carrier; a different phone or a simulator does not close this goal. Request concrete unlock, biometric and tap actions when the device harness is ready. |
| KR4 — Complete envelopes and resources | Model/proofs/SDK, G1/G4/G7 | Retain genuine canonical Offer, Request, Payment, both Credited forms, CreditStatus and Lineage envelopes for every current supported selector. Every session envelope is ≤2,048 B and every monetary envelope ≤10,000 B. On a declared physical-device/OS/carrier population measure two-second p95 durable completion, cold opening, peak memory, retained storage, energy and separate time until received value is spendable. Preserve failed, cancelled and slow trials; calibration cannot convert a failure into a pass. |
| KR5 — Proof correctness and privacy | Proof owners/independent reviewer, G3 | Run genuine native/circuit binding mutations for every consumer, Ω opening and both exposed accumulator decisions. Discharge [C12](kagemusha_c12_composition_v1.md) for the actual setup, three-Q prefix, RP57 interfaces, exposed challenges, adaptive histories, retained private state, checkpoints, retries and joint folding/publication, with explicit assumptions and independent review. Regenerate descriptors, keys and catalog and rerun affected genuine proofs after any construction change. |
| KR6 — Retirement and generated delivery | Component/release owners, G6/G7 | Remove every confirmed superseded implementation and its unused build edges without losing assertions or runtime bindings. Regenerate OpenAPI manifests, `release/openapi-cargo-lock-v1.txt`, environment inventory, panic-boundary inventory and release feature-graph seal from the final source. Prepare a concrete dependency-budget baseline for owner review. Update concise source-adjacent truth and coordinate affected public documentation in `iroha-docs`. |
| KR7 — Verified delivery | All component owners, G7 | Rebuild matching consumers and pass focused regressions, required workspace tests, applicable strict clippy, Kotlin/Swift/Python/JavaScript/C# suites and release checks on the identified candidate. The final §10.1 report names defects/regressions, artifact identities, network/device measurements, cryptographic assumptions, and every remaining external dependency with its smallest necessary decision. No unexecuted or failed requirement is marked complete. |

KR1 and the independent proof, lifecycle, retirement and harness work may proceed
while the KR0 freeze or a physical dependency is unavailable. Final qualification
must still use matching inputs after those changes.

## Verified source starting points

The supplied older capture is not the current catalog or size authority:

- The current model's Payment overhead is **1,394 B**, its sigma capacity is
  **3,520 B**, and its Omega transport capacity is **5,086 B**. These are
  structural capacities, not newly measured genuine proofs. See
  [`kagemusha_wallet_v1.rs`](../crates/iroha_data_model/src/kagemusha/kagemusha_wallet_v1.rs)
  and its `size_tests` and role-capacity tests.
- Current `SigmaRelation` supports **four Send masks (0–3)** and **one Receive
  selector (0)**. Blacklists are local policy, not an additional proof selector.
  Ordinary and renewed Receive are distinct recursive variants and both require
  qualification. The current complete-batch test expects **22 routes / 16
  programs**; verify these against the newly admitted catalog rather than the
  historical 52-route / 32-program capture.
- The [native exchange procedure](../crates/iroha_core_zk/src/kagemusha_wallet_enrollment_v1/tests/native_exchange.md)
  and its `controls`, `fee`, `online_charge`, `send_recovery` and
  `message_census` modules provide artifact-dependent host entry points.
  The fresh-ID duplicate Receive after a fully folded receiver restart is
  already asserted in `native_exchange.rs`; the renewal continuation also
  exercises reverse B→A spending of received value and receiver renewal after
  the Request. Matching execution remains required for both.
- The real network owners are
  [`continuation.rs`](../integration_tests/tests/kagemusha_network_setup/continuation.rs)
  (`execute_four_validator_monetary_continuation`) and its `fee` module.
  Rebuild both daemon and harness from the same captured source.
- The iOS residual model is
  `wallet_advance_v1_crash_matrix_keychain_multiple_write_loss_remains_unqualified`
  in [`crash_matrix_tests.rs`](../crates/iroha_core_zk/src/kagemusha_wallet_advance_v1/crash_matrix_tests.rs).
  It is a counterexample under modeled storage loss, not proof that stock iOS
  permits that schedule. Physical adapter probes alone do not test native Payment
  release or establish the missing persistence guarantee.
- Apple's [Keychain data-protection contract](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
  excludes the selected `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` class
  from backups, synchronization and escrow, and makes its items unusable on
  passcode removal/reset. That supports the adapter's restore-policy choice;
  it does not establish durability of an acknowledged anchor update. Apple's
  [disk-write guidance](https://developer.apple.com/documentation/xcode/reducing-disk-writes)
  also describes `F_FULLFSYNC` as best effort under sudden power loss. Neither
  API acknowledgement closes the physical refinement required by KR1.

## External dependencies and owner decisions

The frozen-source window is required for the shared candidate rebuild. Source
inspection, implementation and component regressions can continue meanwhile.
Before the first signed live Taira operation, prepare the exact operation and
obtain the owner's approval under the repository's Taira skill; keep signing
inputs runtime-only. Minamoto remains read-only.

Physical authentication, transport contact, power-loss and supported restoration
steps require the actual specified devices and owner action. A different device
set, changed envelope/performance requirement, or replacement for an unavailable
iOS primitive requires an explicit design decision. New external crates, commits
and the proposed dependency-budget baseline also require the stated owner
decision. Do not request these decisions before the concrete work is reviewable.

The current iOS monetary-probe notes name an iPhone 17 Pro Max, whereas the
selected requirement names an iPhone 16 Pro Max. Reconcile actual hardware
identity before declaring the device population; do not transfer captures
between them. The four-validator monetary harness also requires an external
controller and a catalog built from that campaign's actual emitted genesis;
starting its ignored test alone cannot complete the campaign.
