# Native prover migration inventory

Status: native consumer migration and source retirement installed (2026-10-08);
focused post-retirement checks pass; full delivery qualification remains open.
The Iroha-native crates (`iroha_pasta`,
`iroha_plonk`, `iroha_plonk_gadgets`, `iroha_plonk_recursion`) own the migrated
proof implementation. The temporary differential oracle, three retired vendor
trees and their dependency edges are deleted. Cargo prunes 14 package identities,
adds none and preserves every retained package identity/checksum. The exact
transaction and deleted originals are retained under
`target/qualification/m7-retirement-port-1` and `m7-retirement-draft`.

Independent reference coverage remains: all 42 Sigma/Wide cases regenerate
matching native descriptors, keys and proof bytes at 1/2/4/7 workers on ARM and
x86 under Rosetta; all mutation checks pass. RP56 migration preserves all 822
parameter fields and 102 framed Kaigi cases, independently rederived in Python.
Affected native checks pass: Poseidon20, Kaigi5, SoraFS3, IVM units4 and IVM SIMD11.
Dependency, retirement, source-seal, codec and IVM-only guards pass, alongside
strict Plonk library/test lint and the three negative public-API doctests. The
IVM-only guard initially found an existing no-std bytes fork; its reviewed
native/std repair passes 1,007 tests with the custom custody implementation
unchanged (`target/qualification/bytes-native-only-port-1`).
These are component correctness results, not full protocol, release-package or
physical-device qualification. The tables distinguish retained consumers from
historical capture provenance; update a row when its current status changes.

## Historical oracle baseline

| Item | Value |
| --- | --- |
| Repository HEAD (`git rev-parse HEAD`) | `1de7210a74d62ae5232c67b910dbf4b6b1bcf757` |
| `git log -1 -- vendor/halo2-axiom` | `8f41274044c93ad7e363fdc8be30a671efb436d4` (2026-10-04) |
| `git log -1 -- vendor/halo2curves-axiom`, `vendor/halo2-base` | `48dcbb6683c0763f3f4f47915f969a0b96d484da` |
| `snark-verifier`, `halo2-ecc`/`halo2-base` git | rev `bbfcc721d714bea0d44a27c8fc6c4736e73ca853`, tag `v0.5.3` |
| Toolchain, host | Rust 1.93.1; native aarch64 and captured x86_64-apple-darwin executable under Rosetta. Current proof-byte parity: 45 non-timing cases on each; both targets also pass all 73 parameter/curve/constraint-system/KAT cases including ignored release cases |

Capture provenance (the named oracle sources are now deleted):

- `crates/iroha_plonk_oracle/tests/vendored_goldens.rs` ran
  `vendor/halo2-axiom/tests/golden_proof_bytes.rs` unchanged through `#[path]`.
  It covers 20 cases, each in Rayon pools of 1, 2, 4 and 7 threads; k = 11 is
  ignored and run in release.
- `fixtures/native_prover/kats_v1.json` holds the golden tables, `ParamsIPA`
  digests for k6-k16, generators, `w`/`u`, Blake2b and Poseidon transcript
  vectors, the RP57 constants, and the KAGEMUSHA and confidential hash vectors.
  `crates/iroha_plonk_oracle/tests/native_prover_kats.rs` generated and checked
  it; retained `fixtures/native_prover/verify_kats_v1.py` re-derives it independently.

## Method

The inventory was built with these commands; it is not regenerated automatically.

- Imports: `rg -l '\b<ident>\b' --type rust -g '!vendor/**'` for each of
  `halo2_proofs`, `halo2_base`, `halo2curves(_axiom)`, `snark_verifier`,
  `halo2_ecc`, `pasta_curves` and `orchard`; then `rg -l` over `IrohaSwift/`,
  `scripts/` and `python/` for `Halo2`, `Pasta` and `orchard`.
- Graph: `cargo tree --frozen --workspace -i <pkg> -e normal,build,dev
  --depth 1`, including the workspace member `python/iroha_python/iroha_python_rs`, and
  `ci/dependency_budget.json` package contracts.
- `vendor/` is excluded from the import search; vendored Pasta providers other
  than the halo2 stack are listed by hand (`vendor/vega-prover`).
- Exposure: `configs/soranexus/` and the `skills/sora-*` docs.

Historical imports used `halo2_proofs` for the renamed `halo2-axiom` package,
while the differential oracle used `halo2_axiom`. Current migrated consumers
have neither edge. The separate Zcash/Orchard package identities remain.

Use: **P** prove, **V** verify, **T** types/encodings, **H** native hashing.
Milestones follow the judge plan in its corrected form (see the notes at the
end); the labels are defined in the legend below.

## Milestone legend

| Label | Meaning |
| --- | --- |
| M0 | Contract capture: vendored goldens runnable from the workspace, per-family goldens, fixtures and tamper corpora, native-hash, hash-to-curve, transcript and snark-verifier KATs; `vendor/` bug-fix-only |
| M1 | First native σ: `iroha_pasta`, `iroha_plonk`, `iroha_plonk_gadgets` v0, `iroha_plonk_oracle`, σ_send/σ_recv. Exit criteria groups: |
| M1.a (M1a) | Engine parity: native proofs reproduce the vendored golden SHA-256 at 1/2/4/7 threads on aarch64 and x86_64; `ParamsIPA` bytes for k6-k16 and VK bytes identical; verifier verdicts match on the tamper corpora. The `iroha_pasta` parity suites and the `halo2curves` 0.9 encoding KATs belong here |
| M1.b (M1b) | Kernel timings on the M1 Ultra (MSM 2^16, fold, k11 σ-shaped prove) |
| M1.c (M1c) | Native σ: the 24 M7 relation cases, in-circuit digests equal the canonical wallet Poseidon hash, proof size, prove/verify time and RSS budgets |
| M1.d | Hygiene: no `vendor/` change; fmt, clippy and tests pass for the new crates |
| M2 | Ledger relations and the consensus verifier on the native stack, one family per change: (a) SoraFS PoP, (b) Kaigi, (c) confidential (re-keyed), (d) vote tally, `halo2_backend` and the `lib.rs`/`verification.rs` dispatch |
| M3 | Gadgets II: native ECC, P-256 ECDSA, SHA-256 lanes, SMT depth 256/128, App Attest DER |
| M4 | Recursion: succinct verifier (native and circuit), BGH19 accumulation, single-parity Ω, format decision memo |
| M5 | KAGEMUSHA on the native stack (σ, Λ, Ω, CreditStatus, artifact manifests, bridge handles); the old halo2 relations were deleted on 2026-10-05 |
| M6 | Engine tail and phones: aarch64 `asm`, deferred folds, GLV MSM, streaming and PolyStore spill, device qualification |
| M7 | Deletion: vendored stack, git dependencies, oracle crate and feature removed; CI guard added; audit closed |
| Step 1-8 | Migration steps of the plan: 1 M0 capture; 2 M1 crates beside the vendored stack; 3 native state hashes first (`kagemusha_v1_poseidon` and the confidential native Poseidon move to `iroha_pasta::poseidon`, Pasta imports switch to `iroha_pasta`; gate: KAT equality on every M0 vector); 4 M2 families; 5 M3-M5 KAGEMUSHA; 6 harnesses (`ram_lfe_*`; the KAGEMUSHA harnesses `g3_proof_scaling_measurement_tests.rs` and `prover_golden_tests.rs` were deleted with the old relations); 7 peripheral owners (fuzz manifests, scripts, pytests); 8 M7 deletion |
| T1-T21 | First-milestone tasks. Cited here: T7 `iroha_pasta::poseidon` with a KAT test against the M0 `kagemusha_v1_poseidon` vectors; T15 `iroha_plonk_oracle`; T16 `iroha_core_zk/src/prover_golden_parity_tests.rs` re-proving the σ golden natively (no longer possible: the old circuits were deleted on 2026-10-05; the goldens stay pinned in `kats_v1.json`) |

Outstanding outcomes and owners for the programme are tracked by C9 and S7
in `roadmap.md`. Retained consumers are migrated and re-keyed, and the shared
vendor trees and temporary oracle are deleted; no compatibility shim is shipped.
Post-retirement guards and rebuilt release consumers remain separate checks.

## Migrated consumers of the retired stack

| Consumer | Stack (direct) | Use | Live exposure | Milestone |
| --- | --- | --- | --- | --- |
| `iroha_core_zk` verify dispatch: `lib.rs`, `verification.rs`, `native_pipa_r`, `ivm_proof_identity` | Native PIPA-R and separately selected STARK | V T | Committed chain policy uses `pipa_r`/`stark`; deployed stored proofs and registered keys remain unknown offline | M2(d) source retirement installed: generic Halo2 dispatch, `zkparse`/ZK1, old VK readers, five proof fixtures and backend configuration selectors are deleted. `BackendTag` has exactly Native PIPA-R=0 and STARK=1; seven closed registry profiles, no old decoder. Raw IVM hosts reject unqualified envelopes. The test-only `halo2_backend` adapter and its Core_zk vendored dev-dependencies are also deleted after native RAM-LFE migration. Combined runtime/config/consumer checks and packaged SDK rebuilds remain in progress. |
| `iroha_core_zk::confidential_v2` (+tests): transfer v2, unshield v2/v3 circuits | Native PIPA-R; captured Poseidon vectors retain the independent oracle boundary | P V H | Taira `[confidential] enabled = true` (`config.toml:288`). Shielded notes and registered `CONFIDENTIAL_*_VK_DIGEST_V1`: unknown offline | Step 3 host hash uses the native RP57 implementation and passes all 35 hash/tree/proof regression tests, including both-field oracle, KAT and circuit parity. M2(c) production circuits and dispatch now use native PIPA-R with three new pinned keys, one native public column and consuming witnesses. The activated confidential suite passes 50 tests; ten independent host/relation/adversarial cases cover presence/public-input/layout/private-owner/path mutations and shared witness validation. All three depth-16 proof bodies are 3,680 B. Core/Torii/CLI test compilation passes before the final integration-fixture migration. The original 218-case both-field Poseidon parity corpus is captured in `confidential_poseidon_v1.json`; native replay and independent Python rederivation pass. Core_zk no longer imports the retired prover, even in tests. Captured native SDK integration has the JavaScript, installed Python, C# and earlier mobile-host coverage recorded below; release packaging and network qualification remain open. |
| Retired consensus Poseidon owner | — | — | None | Deleted with the mint-finality authority; the primitive KAT vectors stay in `kats_v1.json` and are checked by current native consumers. |
| Old KAGEMUSHA owners: `iroha_core_zk::kagemusha_v1_state`, `kagemusha_v1_recursion`, the `pasta_*`, `kagemusha_p256_curve_gadget.rs` and `app_attest_der_gadget.rs` gadgets, `kagemusha_polynomial_store_v1`, `prover_golden_tests.rs`, `g3_proof_scaling_measurement_tests.rs`, and `iroha_core` `isi/kagemusha.rs` and `kagemusha_v1_reserve.rs` | — | — | None in source | Deleted, including the paired-Pasta mint-finality authority and its consumers. M5 rebuilds KAGEMUSHA natively in `iroha_kagemusha_proof`; the golden table stays pinned in `kats_v1.json` |
| Retired paired-Pasta mint-finality authority | — | — | None | Deleted with its consensus, genesis, daemon and test-network integration. |
| `ram_lfe_*` (`#[cfg(test)]`) | `iroha_pasta`, `iroha_plonk` | P V | None | Native candidate preserves the word/byte/hash corpus with strict checking and consuming-witness PIPA-R proofs. All ten native Poseidon tests pass, including real proofs at ordinary and maximum input sizes. The initial complete word/byte/hash run passed 26 cases and found one degree-limit expectation error; repaired byte tests prove degrees5/8/9 and reject degree11/20 keys under the unchanged cap. The unused old-engine adapter and vendored dev-dependencies are deleted; all 27 native word/byte/hash cases pass, including genuine proofs and adversarial checks. No private execution relation is admitted. |
| `kaigi_*_v1_tests.rs` (in `iroha_core_zk`) | `iroha_pasta`, `iroha_plonk` | P V | Test | M2(b) native candidate: seven Kaigi and two native-dispatch tests pass with real proofs; all public-row, metadata, scalar, key and backend-confusion mutations retained. The key carrier binds the descriptor as well as the processed key; a foreign typed schema with identical processed key bytes is rejected. The 48 focused verifier/admission/guardrail tests also pass. All three rebuilt Core Kaigi lifecycle/admission integration tests pass; packaged SDK and network qualification remain open. |
| `iroha_core` Kaigi: `isi/kaigi/privacy{,/authorization_v1,/proof_fixture_v1}.rs`, `privacy_release_evidence/kaigi.rs`, `tests/kaigi_privacy.rs` | Native PIPA-R through `iroha_core_zk::native_pipa_r` | V | Kaigi VKs are committed policy refs (`kaigi_authorization_vk`, `kaigi_usage_vk`), unset in the Taira template. Live: unknown | M2(b) native candidate installed; exact relation, ledger public inputs, registry policy and replay checks remain mandatory. All three rebuilt Core lifecycle/admission integration tests pass; four-validator qualification remains open. |
| `iroha_core` vote tally and tooling: `tests/zk_vote_tally_audit.rs`, `tests/zk_testkit.rs` | Native PIPA-R structural/real-proof test fixtures | P V | Test | M2(d) source retirement installed: obsolete Pow5 benchmark, direct vendored dependency and feature forwarding removed. The replacement confidential proof fixture is explicitly not a qualified governance proof; role admission remains closed. Current-candidate consumer execution remains open. |
| `kaigi_zk` (native Grain RP56 constants) | `iroha_pasta`, `iroha_plonk` | P V H | Mandatory native Kaigi prover/verifier through Core and SDK host | M2(b) native candidate: new `pipa-r/pasta/kaigi-{authorization,usage}-v1` identities, consuming-witness PIPA-R proofs, separate verifier-only/proving caches and a canonical Norito key carrier binding both compiled descriptor and processed Vesta key (16,499 B authorization; 9,561 B usage). The installed native library passes all 23 circuit/KAT and real-proof tests; isolated strict Clippy passed. All three rebuilt Core lifecycle/admission integration tests pass; no old-key decoder or label normalization. Packaged SDK and network qualification remain open. |
| `sorafs_manifest::pop_credentials::zk` | `iroha_pasta`, `iroha_plonk`; native Grain RP56 constants | P V H | SoraFS PoP credentials (irohad runtime provider). Live: unknown | M2(a) native candidate: consuming-witness PIPA-R proving/full verification and verifier-only key generation; new circuit identity/key fingerprints, no old-key path. All 38 PoP tests pass, including unchanged RP56 constants/hash vectors and coordinated nonce/empty-leaf forgeries. Generated structural SDK fixtures and signed inventory pass their guard; all-target strict Clippy passes. All 25 Node PoP consumer tests pass. Rebuilt SDK consumer qualification remains open. |
| `iroha_js_host` (`kaigi_proof_v1.rs`; `confidential_wallet.rs` through `iroha_core_zk`) | Native PIPA-R for Kaigi and confidential | P | npm package | M2(b) Kaigi native candidate installed; rebuilt native host passes all 22 Kaigi tests, including genuine proofs and every public-row mutation. Packaged SDK and network qualification remain open. M2(c) confidential production is native; rebuilt host confidential execution remains open. Proof randomness remains engine-owned and hedged; SDK blindings are consumed and zeroized. |
| `xtask` `vote_tally.rs` (feature `dev-vote-fixture`) | `iroha_pasta`, `iroha_plonk` | P V | Fixture only | M2(d) native candidate passes the reproducibility/math, transcript mutation/truncation, metadata/digest drift and development-only admission tests. Canonical Norito proof/key artifacts replace the retired TLV files; production dispatch still rejects this development relation. |
| Retired differential oracle | No current dependency | Historical P V T H | None | Deleted after ARM/x86 differential checks and captured-vector replacement. Native unit tests retain historical transcript comparisons; no production configuration exposes their test hooks. |

## Other Pasta and halo2 implementations (not the vendored stack)

| Consumer | Stack | Use | Live exposure | Milestone |
| --- | --- | --- | --- | --- |
| `iroha_zkp_poseidon` (`pasta.rs`, `poseidon.rs`; native-field cross-check in `pasta/tests.rs`) | halo2curves 0.9; dev iroha_pasta | T H | Shared proof-system primitives; the paired-key authority helper is deleted | Direct vendored field and parameter-generator edges removed; all20 primitive tests pass with the independent field cross-check and captured RP56 banks. The retained Python implementation independently rederives every parameter field. |
| `iroha_zkp_halo2` (native Pallas/BN254 IPA, SHA3 transcript; used by `ivm`, `iroha_core` `zk-ipa-native`, `iroha_cli`, `iroha_torii`, `iroha_core_privacy`, `fastpq_prover`, `iroha_core_zk`, `iroha_python_rs`) | halo2curves 0.9 (optional) | P V T | Non-optional dependency of `iroha_core`, so every node | Owner: converge or keep separate |
| `iroha_core_privacy` `privacy_engines/orchard.rs`; `iroha_core` feature `privacy-release-evidence` | orchard 0.15.4 (git rev `9d07047d`, a non-optional dependency of `iroha_core_privacy`), Zcash `halo2_proofs` 0.3.4, `pasta_curves` 0.5.2 | V | Taira privacy catalog `orchard-halo2-actions-v1`, `activation_state: not-executed` (`privacy_bootstrap_plan.json`) | Carve-out: stays after M7; separate package identities retained by `scripts/check_no_vendored_halo2.py` |
| Orchard linkers (through `iroha_core_privacy`): `connect_norito_bridge` (iOS/Android), `irohad`, `iroha_torii`, `iroha_cli`, `iroha_kagami`, `iroha_js_host`, `zk_ace_prover`, `integration_tests`, and `python/iroha_python/iroha_python_rs` (`privacy_wallet_bundle.rs`, `privacy_native_actions.rs` build Orchard spend/change prover inputs) | orchard, Zcash `halo2_proofs` 0.3.4, `pasta_curves` 0.5.2 (linked, not imported) | P V T | Every node binary, the mobile bridge, npm and PyPI wheels | Carve-out with Orchard; binary-size and seal reports count it |
| `vendor/vega-prover` (Microsoft Vega; `src/provider/pasta.rs`) | Own `ff` 0.13 Pasta provider; not a workspace member | T | Reference for the `iroha_zkp_halo2` Vega fixtures (`vega/canonical_mc_exact.rs`, `vega/microsoft_mc/*`) | Out of the halo2 M7 scope; owner decides whether those KATs move to `iroha_pasta` |
| `ivm` (BN254 `poseidon.rs`, `bn254_vec.rs`); ZK verify syscalls reach `iroha_core_zk` through the `iroha_core` host | halo2curves 0.9 BN254 | H | All nodes | No direct change; follows M2(d) dispatch |
| `fastpq_prover` (BN254 Poseidon, Metal, CUDA bench) | halo2curves 0.9 BN254 | H | FASTPQ | Out of scope |
| `iroha_sccp` (optional, dev); `iroha_deploy` dev (`verify/finality/tests.rs`) | halo2curves 0.9 | T | Tests, SCCP | Out of scope |
| `iroha_pasta` | dev `pasta_curves` 0.5.2 (oracle) | T | None | Keep while orchard keeps `pasta_curves` |

## Transitive consumers (link `iroha_core_zk`)

| Consumer | What it reaches | Live exposure | Milestone |
| --- | --- | --- | --- |
| `irohad`, `iroha_torii` (`zk_prover.rs`, routing), `iroha_cli` (`zk.rs`), `iroha_kagami` (genesis), `iroha_test_network` | Verify dispatch and confidential | All nodes and operators | M2 (dispatch) |
| `iroha_deploy` (`localnet.rs` registers confidential VK records; `genesis/staging.rs`) | Confidential VKs | Localnet, staging | M2(c) fixtures |
| `connect_norito_bridge` (`confidential_prover_ffi`, `confidential_note_ffi`) | Confidential prover and note hash | iOS and Android apps (staticlib/cdylib) | Step 3, M2(c): captured source-admitted ABI-27 macOS JNI/C#/Swift consumers pass as recorded below; historical captures remain retained. Release artifacts, size reports and physical-device qualification remain open. |
| `iroha_python_rs` (`confidential_wallet.rs`), `iroha_js_host` | Confidential wallet | PyPI wheels, npm | M2(c) |
| `integration_tests` (dev) | Proof fixtures, `queries/proof.rs` | Test | M2 (4-peer cutover tests) |

The retired Core pooled-reserve execution and runtime verifier owners, and the
SDK ordinary-native tools, are removed. The SDK and its consumers no longer
admit `iroha_core_zk` through a dependency-budget exception; all configured
forbidden layers apply directly. The selected wallet's node integration
remains part of M5.

## SDKs and tools

| Surface | Halo2 dependence | Milestone |
| --- | --- | --- |
| Swift `Halo2Pasta.swift`, `Halo2Vesta.swift`, `Halo2IPA.swift` | Independent Swift Pasta/Vesta, `ParamsIPA` read/generate/serialize, IPA commit and opening prove/verify. Must match `params_ipa` and `generators` | Cross-check against `kats_v1.json` (M1a); keep the layout |
| Swift `Halo2Transcript.swift`, `Halo2EvaluationDomain.swift`, `Halo2VestaHashToCurve.swift` | Independent Blake2b `Halo2-Transcript` `Challenge255` transcript, FFT domain (`omega`), and Vesta hash-to-curve. Must match `blake2b_transcript`, the FFT omega and `generators` | Cross-check against `kats_v1.json` (M1a) |
| Swift `ConfidentialProver`, `ConfidentialNote`, `VerifyingKeyBackendTag` | Through the bridge; exact backend label `pipa-r/pasta` | M2(c) fixtures |
| Kotlin `core-jvm`/`client-android` (privacy native bridge, VK registry); Java `iroha_android` (retiring) | Through the bridge; labels | M2(c) fixtures |
| C# (`Zk/VerifyingKeyBackendTag.cs`, `Privacy/ConfidentialProver.cs`, `Kaigi`) | Through the bridge; exact native labels | M2(b)(c) positive registry/query/event/receipt fixtures use `pipa-r/pasta`, including domain-separated commitments and URL/circuit identities; retired labels stay rejected. The original-source combined suite passes **536/536**, zero failed/skipped/not-run: 482 registry/query/event/receipt cases, seven managed owner cases, six native confidential cases and 41 Kaigi cases. Native coverage includes real full-65,536-tree proofs with both evidence formats, change followed by redemption, wrong roots, duplicate/conservation rejection and disposal. The current captured ABI-27 rerun uses .NET SDK 8.0.419 and the actually loaded host `ae5589d0…`, with source, full toolchain and output binary pins unchanged throughout its 547.99 s run (`target/qualification/native-sdk/csharp-abi27-current/result.json`). Every observed bridge load resolves to that admitted dylib. The historical ABI-26 536-case pass and earlier SDK, old-label and broad-run failures remain recorded separately. This is captured native host component evidence; installed NuGet release-package and network qualification remain open. |
| JavaScript `iroha_js` (`kaigiScalarV1.js` Pasta Fp checks) | `iroha_js_host` napi | M2(b)(c) |
| Python `iroha_python` | `iroha_python_rs` | M2(c): five original nonskipping tests pass against actual installed sealed wheels, including a full-depth real proof and local verification, change redemption, adversarial rejection and GIL progress. Exact artifacts and scope are recorded below. |
| `fuzz/Cargo.toml`, `crates/fastpq_prover/fuzz/Cargo.toml`, `scripts/cargo_fuzz_locked_cargo.sh` | Native consumer dependencies; obsolete vendored Halo2 patches and proxy path requirements removed | Step 7 source cleanup complete. Locked/offline forwarding and fuzz-smoke inventory checks pass; this is not standalone sanitizer execution or a qualified locking proxy. Existing fuzz runtime/lock qualification remains open. |
| `scripts/norito_bridge_source_seal.py`, `scripts/check_ivm_only.py`, `pytests/scripts/norito_bridge_source_seal_reviewed_vendor_test.py`, `pytests/scripts/workspace_release_gate_test.py` | Name vendored paths or packages | Step 7, M7 |
| `ci/dependency_budget.json`, `scripts/check_release_feature_graph.py` (`proofs-halo2`, `zk-halo2`, `zk-halo2-ipa`), source-token guards in `pr.yml` | Pin the current graph and features. The reviewed native-consumer manifest baseline counts the native crates; all dependency edges forbid the retired proof packages | Update in each migrating change |
| Native instruction-target CI and independent reference fixtures | `native_prover_parity.yml` runs native arithmetic/proof/mutation suites, the explicit large GLV case, negative production-API doctests and dependency-retirement guards on ARM/x86. Standard-library Python checks retain proof, transcript, parameter and corruption coverage. The deleted oracle's last ARM/x86 captures each pass50 correctness cases; its historical companion/KAT receipts remain unchanged. Hosted execution of the replacement job remains unobserved. | Local component parity; release and physical-performance checks remain separate |
| Independent full-proof Python reference | `reference_verifier/` derives the complete individual PLONK/multiopen/IPA verifier and generator decision from the normative equations, using only the standard library. The 46-case frozen genuine fixture spans both curves, three transcript profiles and k6–k10. All 169 adversarial/parser/decision tests pass with source drift zero; a fresh exact Rust fixture recomputation passes with 2,743 pinned consumed inputs and no tool/runtime drift (`target/qualification/python-reference/current2`). Constructive false claims preserve the soft equation yet fail `decide`. Independent review accepted the bounded implementation. CI requires both genuine fixture equality and independent verification. Keep the reference and inputs after oracle deletion; this is not a production decoder. Batch weights, encoded accumulators, k16, recursion and full wallet catalog remain outside its scope | §15 individual-reference requirement; broader M7 gates remain open |

Current native source admission requires **ABI 27** because the wallet runtime
originals structure and JNI installation constructor now include the exact
registration source. ABI-26 and earlier artifacts are rejected before this
changed layout is called. The guarded ABI-27 macOS host capture
`target/qualification/native-sdk/host-abi27-universal-registration/` is admitted
with 341 exports (84 required), unchanged source/tool/dep-info inputs and unchanged
supplemental private-worker sources. Its dylib SHA-256 is
`ae5589d06b41027f1ccbd4924255c92164e3e2ee49b5a15a62b7852e58606090`.
The actual Kotlin/Java native consumer rerun passes **60/60**, zero skipped,
including seven wallet JNI cases and 53 Privacy/SoraFS/signer consumers. It forces
execution, rejects XML from earlier runs, and retains unchanged source/artifact
pins under `native-sdk/universal-abi27-kotlin-jni-2/`. The matching Swift producer
is retained under `native-sdk/swift-abi27-universal-registration/`. Its captured
original-source runtime passes **246/246**, zero failed/skipped, including five
genuine native confidential cases and 14 installation/registration-locator cases.
The exact XCTest binary and native producer stayed unchanged; a concurrent change
to `IrohaPeerQRV1Tests.swift` is retained as runtime source drift in
`native-sdk/universal-abi27-swift-runtime/runtime-summary.json`. C# independently
passes the unchanged 536-case consumer suite on the same dylib as described above.
These are captured host components;
subsequent source changes do not make them whole-checkout, release-package or
physical-device qualification.

The historical captured ABI-26 host in
`target/qualification/native-sdk/host-abi26-close-loads-current/` passed
compiler/source/tool/dep-info guards and the actual ABI/export probe with no
source drift; its retained dylib SHA-256 is
`3b51ff55359cdac26e917fd8b0e05192735b739e400f7728fedb4334075b0ee5`.
It includes the signed pre-key permit, exact E6 custody, Abandon, native Credited,
background scheduling, CloseLoads and shared immutable IPA parameter tables.
The matching local macOS Swift archive passed normalization, a real complete C
consumer link/run, packaging and final provenance verification. Its original-source
Swift runtime passes **133/133**, zero failures: 19 confidential and 114
wallet/load/platform/vector cases, with unchanged SDK source and producer pins
(`target/qualification/native-enrollment/close-loads-swift`). Actual JNI tests pass
4/4 and the managed wallet suite passes 86/86 without skips. Compiler and packaging scratch stays in private
capture directories under `target/qualification`; guard tests reject missing,
public, redirected and external scratch. The supplemental private attestation
worker source inventory also stayed unchanged through both captures; it is not
claimed to be a compiler input. Full capture records are in
`target/qualification/native-sdk/close-loads-capture/`. Subsequent source changes
make these captured component results, not qualification of the latest checkout,
release artifacts or physical devices. Earlier source-drift refusals remain
retained; no admission guard was bypassed.
The matching actual JavaScript addon consumer suite passes **six tests, zero
failures/skips**, including one genuine input at index 65,535 of a complete unique
65,536-leaf tree, native proof and local verification, wrong-root/duplicate/
conservation rejection, recovery and disposal. Its unchanged original assertions
ran through the normal source-admitted local loader; the captured addon SHA-256
is `5a65414711c06cc752a73042267f5c000763a0fd179680f925f001e613fd4b2b`.
The 881.02 s run is component correctness evidence, not a latency gate or an
installed release-package pass (`js-confidential-runtime-observed.json`).
The original Python confidential wallet suite passes **5/5**, zero skips, against
actual installed locally sealed wheels (150.88 s). The unchanged tests exercise
65,536 unique leaves with a real proof and local verification, change followed by
redemption, wrong roots, duplicate inputs, invalid change, owner recovery, and
Python progress during native proving. The native wheel SHA-256 is
`c8c712e042371cef5349f357303101b97cc213a1ecab02086fc021908ff84f82`;
all four wheel hashes, actual compiler inputs, installed artifact identity and
successful admission before/after execution are retained in
`target/qualification/native-sdk/python-current-source/`. The coherent warm build
has zero prospective/tool/supplemental drift. The preceding successful cold
compilation was refused for source drift; the first installed run was refused for
untracked generated bytecode in an authenticated source tree. Both refusals remain
recorded. The generated files were moved to a private hashed quarantine, leaving
original source and the verifier unchanged, before the successful run. Clean-source
installed-release preflight remains separate and unqualified; its earlier active
Git merge refusal is retained. These are native component correctness results,
not latency, network or phone qualification.

The captured ABI-25 macOS confidential host slice passes **15 Kotlin/Java tests**
(10 actual native-prover/full-tree cases and five Java note consumers) and
**26 Swift tests** (including five actual native-prover cases), with no skips or
failures. The cases include full 65,536-leaf input, retained change followed by
redemption, wrong roots, duplicate inputs and owner recovery. The Kotlin JVM's
mapped library was observed at the exact admitted path and hash; Swift executed
the exact XCTest bundle built by the ordinary source-admitted package. Native
artifact, SDK and selected fixture hashes stayed unchanged during execution.
The static archive and dylib came from one guarded ABI-25 build. Later KAGEMUSHA
artifact-loader edits are recorded as source drift, so this is a **captured host
component result**, not qualification of the latest checkout, release artifacts,
network or physical devices. Logs, XML, loaded-image observation, original source
checks and the separate path-kind audit correction are retained under
`target/qualification/confidential-native-current/`. Newer JavaScript and Python
component results are recorded above; release-package qualification remains open.

## Live networks

- **Taira:**
  - The checked-in config enables `[confidential]`; native PIPA-R verification uses the committed ZK validity policy. This source change does not describe the deployed binary.
  - The privacy rollout lists Orchard as not executed.
  - The deployed build may still serve the old KAGEMUSHA V1 Torii commands, which
    the source no longer has; the Taira reset is their cutover. The Digital Shekel
    asset stays in the genesis template.
  - The genesis templates register no halo2 VKs.
  - Unknown offline: registered VKs by backend label, stored proofs, shielded commitment and nullifier counts, Kaigi sessions, PoP credentials, current wallet artifacts and authenticated validator epochs.
- **Minamoto:** no checked-in config, and the skill lists no ZK surface. Everything is unknown offline; stay read-only.

Inventory deployed candidates before resetting them to the first-release protocol.
Retired formats, verifiers and compatibility paths are not retained in the release.

## Corrections applied to the judge plan

- The paired-Pasta mint-finality authority and its consensus integration are deleted;
  they are not part of the native proof implementation.
- Orchard and Zcash `halo2_proofs` 0.3.4 are a production dependency of
  `iroha_core_privacy` and stay after M7.
- Validator generations contain ordered BLS identities; the retired consensus Pasta
  key checks are deleted. Audit remaining non-consensus Pasta consumers separately.
- The KAGEMUSHA and confidential native hashes are byte-identical
  constructions: the same RP57 spec and the same `[domain, len, inputs]`
  preimage, with different domains. One `iroha_pasta::poseidon` sponge serves
  both.
- SoraFS PoP RP56 constants and four boundary/domain hash vectors are pinned in
  `pop_credentials::zk::migration_tests` against the old arithmetic baseline.
  The migrated circuit explicitly constrains the nonce accumulator initial zero
  and the empty revocation leaf; assigning zero as a witness alone was insufficient.
- Kaigi and SoraFS PoP generate their unchanged RP56 constants with native Grain.
  Both compare all 201 field elements against the independent upstream generator
  in dev-only tests; `poseidon-primitives` is absent from their normal dependency
  graphs. The immutable release capture at
  `target/qualification/retained-rp56-native-20261007/unit/provenance.json` passes
  23 Kaigi and 38 PoP tests without source or binary drift. Kaigi framing and raw
  field encoding retain their independent KATs.
- The PR guard walks actual all-feature Cargo normal/build edges for every workspace
  root and rejects the retired Axiom packages, parameter generator and any path
  into the temporary oracle. Only the exact nonpublishable oracle root is exempt;
  dev-only edges and the distinct Orchard/Zcash package identities remain allowed.
  The current graph and nine regression tests covering direct/transitive/build/platform/alias paths pass.
- The succinct oracle capture now compares all original snark-verifier and Halo2
  challenges, exact BGH19 accumulator G/xi fields, and both final decisions for
  eight Sigma/Wide cases across both Pasta curves and seeds 42/43. The frozen
  `fixtures/native_prover/succinct_v1.json` also retains complete proofs,
  descriptors, keys, instances and 40 mutation outcomes. Four live-original oracle
  tests and two independent native corpus replays pass on aarch64 and on actual
  x86_64 Mach-O executables under Rosetta, with unchanged consumed inputs, tools
  and runtime source (`target/qualification/snark-succinct-parity/{arm-tape,x86-tape}`).
  Strict lint passes for both owners. The native replay has no retired prover
  dependency and retains the corpus after oracle deletion. The original verifier's
  explicit invalid-equation panic and trailing-prefix acceptance are captured
  faithfully; native validation rejects those mutations normally. This captures
  the Sigma/Wide BGH19 succinct subset, not the intentionally distinct PIPA-AS-v1
  accumulation transcript or the deleted private KAGEMUSHA relation corpus.
- Still to capture (TODO): remaining per-family relation goldens and tamper corpora
  and the current complete KAGEMUSHA catalog. The earlier 45 non-measurement oracle
  tests and 73 companion cases passed on both instruction targets; hardware and
  timing gates remain separate. These component results do not authorize M7
  deletion while its retained-consumer, operation and release gates remain open.
