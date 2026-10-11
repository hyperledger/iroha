# Compile-time ownership and validation

The [optimization goals](../../specs/compile_bloat_optimization_goals.md)
separate compilation owners while preserving canonical wire formats,
deterministic execution, proof validation and runtime behavior. First-release
consumers use actual owners directly, without compatibility aliases, shims,
fallback decoders or parallel retired implementations.

| Boundary | Current design |
| --- | --- |
| VM and compiler | IVM and artifact admission use the compiler-independent ABI/surface. `kotodama_lang` owns compilation; `kotodama_toolchain` owns compiler tools. Core uses the compiler only for tests. Torii's contract-source API and JavaScript's `compileKotodama` API directly consume the compiler, so compiler edits can rebuild the daemon and JS host graphs. |
| Public call codec | `ivm_abi::arguments` owns schema-bound JSON-to-record conversion; `ivm_abi::numeric_tlv` and `pointer_abi` own static envelope encoding. Deploy, CLI, Core, Torii, JS and compiler-tool callers import the ABI owner directly. IVM retains byte decoding, gas metering, allocation and authenticated memory custody. Canonical wire bytes and fixture assertions are preserved. |
| Operation evidence | `iroha_operation_journal` owns the shared immutable request/prepared/applied bytes, original markers and private-directory locking. Wallet, SCCP, Musubi services and the daemon import the storage owner directly; Deploy tests use it directly. Signing, authorization, finality and replay checks remain in consumers. The old Wallet module is removed; native qualification remains pending. |
| Privacy verification | `iroha_core_privacy` owns state-free engines, profiles, proof records and verification. Core retains committed-state admission and authenticated authority construction. Fixtures and negative source controls follow the moved implementation. |
| Timed OVN | `iroha_core_timed_ovn` owns public evidence, archive/casting data and TLE verification. Core retains state reads, authenticated constructors, opaque authorizations and signing. Public data construction does not grant authority. |
| Executable metadata | Thin `irohad` and `iroha_cli` packages provide compiled metadata to `irohad_lib` and `iroha_cli_lib`, whose extern crate names remain `irohad` and `iroha_cli`. Source revision build scripts belong to executables; the daemon library only selects test-only mutations. Version, source and wire identity diagnostics use the injected metadata. The CLI library always includes Core/node, crypto/consensus and Norito/node-codec; `cli` and `dev-tools` select binary targets. |
| Test parsing | P2P network, Kotodama compiler, model block and model proof each have one out-of-line `#[cfg(test)]` module. Production parsing skips their bodies. Test names, fixture bytes and ownership remain covered by logical-source readers and negative controls. |
| Codec layouts | Norito accepts fixed-width and compact-length layouts. Generic arrays require exact element framing and charge actual owned allocations once; nominal raw-byte fields use explicit layouts. Retired packed-layout implementations and the last unused flag-name constant are removed. Header/layout and malformed-frame rejection controls remain required. |

Core retains committed-state authority, authenticated constructors, signers and
opaque authorizations. Public evidence and storage APIs grant no authority.
SDK custody and genuine proving qualification follow the canonical G1, Advance
and PIPA owners. Their bridge, SDK and ledger integration remains open under the
[single-design ownership plan](../../specs/kagemusha_single_design_proposal.md#9-implementation-ownership-and-retirement). Native/JS/Python verification consumers use state-free owners
without Core/P2P in their normal graphs. The applied boundary policy denies
shipping Oracle consumers and admits Oracle only in the dedicated development
aggregate; fresh maintained validation remains required.
Current boundary policies must preserve runtime, P2P, compiler and test-feature
denials and require canonical SDK, proving and SCCP/Wallet consumers. Hardware acceleration must preserve deterministic results and its
fallback behavior. Sumeragi remains under its separate owner; inspect SCCP before
adjacent changes. The unused direct daemon Sumeragi dependency is removed; Core
retains the same normal dependency and features. The reviewed cost ratchet
includes the model’s live Pasta field/hash dependency and development-only proof
timing dependency. SCCP’s journal uses admitted native filenames, but its separate
reader and dispatch paths do not inherit Wallet’s namespace audit guarantee.

Core's pool getter remains `pub(crate)`; its regression preserves cloned
handles and reservations. External lane fixtures use the Sumeragi test-chain
accessor. Core's ZK alias and committee/fee tests use actual owners without a
public State adapter. Preserve canonical Wallet schema/frame assertions and
storage record, lock, revalidation and publication order.

## Current scoped health

O3/O4/O5 are complete for their ownership scopes. O1/O2/O6/O7 remain open.
Recorded component and executable-metadata checks retain their source/feature
scope; earlier passes do not qualify later source. The recorded signed validation baseline
is `4486aa78661b8f289d21238e034fc2ece10600d8`. The recorded native
Primitives/P2P/Manifest and Norito/derive/Crypto runs preserve source. The latter
reports a successful Cargo exit but an outer failure caused by the merge changing
Git; that original failure remains preserved. Independent Source/Git comparison
joins both runs and the reviewed application to the genuine formatter baseline
at that recorded cut. Subsequent commits and selected-input changes require
fresh qualification. This does not qualify broader native tools, artifacts or
consumers.

| Scope | Recorded health and limit |
| --- | --- |
| Source graph and guards | Recorded static source-graph discovery lists 124 workspace members, with the inactive Wayland patch protected; current resolved Cargo metadata remains unqualified. Source-cost and feature-hygiene checks exited naturally on the recorded cut with all 72 limits exact, at manifest fingerprint `345a09e19a16565c9cb156d8563cbd0f1c4eb952312647fba36024a95ad9cf4d`. Recorded locked offline boundary, legacy-codec and checker-control passes retain their input cuts. Shipping Oracle denials and the sole aggregate-model test exception remain intact. Resolved metadata requires canonical `deps` and rejects malformed entries. |
| Compiler fixtures and CI | The compiler reader records 308 fixture includes and 616 test names; its 43 source-reader controls pass on their recorded cut. Rust CI has one `axum-core` owner and all 95 workflow/source controls pass. Compiler/toolchain native suites and actual CI execution remain pending. |
| Python | Earlier passes for the five complete affected source-scanner modules (527 tests and 315 subtests) and whole `pytests/scripts` retain their original input cuts and stock skips. Current full Python requalification remains pending. The whole-scripts run with source drift remains diagnostic; interrupted attempts with unknown exits remain unresolved. |
| Model, ABI and Surface | The earlier all-feature Model library, bin and test suite passed 5,591 tests with 148 stock ignores, and all seven doctests passed, resolving its preceding 45 failures. These results retain their original input cut; current full Model requalification remains pending. ABI/Surface receipts retain their recorded scopes; remaining native qualification is open. |
| Norito and foundational owners | Complete Primitives/P2P/Manifest suites on the recorded cut passed 2,259 tests with one stock ignore across eight harnesses, resolving all eight earlier assertion failures. Complete Norito/derive/Crypto suites passed 3,623 tests with five stock ignores across 21 harnesses, plus 39 nested UI cases. Both recorded intervals preserve source and their independent Source/Git join to the recorded formatter is complete. Later selected-input changes require fresh qualification. The latter Cargo exit is zero; its original outer exit two from the Git change remains preserved. Earlier passes, failures and unknown exits retain their original scope; broader native qualification remains open. |
| Journal and Wallet | Journal strict lint and all 11 unfiltered ordinary tests passed on their recorded selected inputs, with zero ignores; subsequent selected changes require requalification. Wallet's shared retained reader rejects unknown native material before decoding, signing or HTTP. Its prospective 218-case macOS registry retains all 191 earlier names, 15 custody controls and two byte-frame allocation controls; Wallet and SDK native qualification remain pending. |
| ABI and direct IVM consumers | The original 12 phases plus allocation and compact-call compiler/runtime phases remain unrun, 14 total. Eleven changed fixed inputs require current joins, including Torii and epoch-owner evidence. Preserve the three direct allocation and two compact-call controls, strict and complete ABI/Surface libraries, full IVM, direct SDK/integration consumers, canonical fixture producers and Deploy calls. |
| Core ZK | Pending qualification covers strict default/no-default libraries, `zk-tests`/`halo2-dev-tests` library and grouped integration coverage, and canonical Pasta/PLONK/G1/Advance/PIPA owners and consumers. Genuine Halo2/Pasta proving is mandatory in every build. Earlier results retain their pre-repair cuts; the retired real-proof-harness feature is not a target. |
| Crypto and FASTPQ | Crypto coverage on the recorded cut is included in the source-stable Norito/derive/Crypto run above, with its independent Source/Git join complete. Later selected-input changes require fresh qualification. Earlier five Crypto checkpoint and 18 Model AoS/DA controls and allocation/custody receipts retain their input cuts. The earlier interrupted unknown exit and drifted Crypto success are preserved. Current FASTPQ ordinary library/offline runtime and its raw-field regression remain pending. |
| Privacy | All 52 earlier failures remain ordinary tests; current regressions followed by the full unfiltered ordinary suite remain pending, with all stock ignores retained. The prepared controller is inactive. Registry discovery or a focused subset supplies no full-suite pass. |

The reviewed five-path application (`312971…`) and genuine formatter receipt
`c72908f34c010445a54bd5acb138a8ffb9bbce03f90684a1d562cad5dabacb95` record
the recorded application chain. Formatting, format checking, the codec guard and
diff checking exited naturally with unchanged source and Git. Independent
comparison joins that recorded source and signed Git baseline to this formatter
and both native source captures. Cargo/rustfmt binaries and the formatter helper
also match on that cut; this is not qualification of subsequent source, other
native tools or artifacts.

Exact commands, source maps, logs, diagnostic inventories and terminal receipts
belong in PR Testing or evidence artifacts, not this note.

## Remaining qualification

- Validate the applied source-cost policy with fresh maintained source/feature/
  target guards and all 21 locked offline boundaries.
  Preserve every denial and exact limit without unused headroom; working-tree
  observations do not qualify a staged subset.
- Close source and warm-lane intervals before native phases. Bind compiled
  source, runtime fixtures, rerun declarations, generated outputs, invocation
  and resources. Reuse `finish`, Cargo's native jobserver and Apple's default
  linker; review changed inputs before admission.
- Validate fresh Wallet listings and full ordinary runtime against its
  prospective 218-name source registry, all 15 custody controls and both
  byte-frame controls, including the unknown-native-material regression, plus
  SDK consumer checks. Requalify Journal after selected input changes.
- Execute all 14 ABI/IVM phases with fresh admission: preserve the original 12
  phases and add three allocation and two compact-call compiler/runtime controls.
  Retain strict and unfiltered ABI/Surface libraries, full unfiltered IVM,
  ordinary/ignored membership, original integration/SDK assertions, both
  fixture-producer checks and Deploy calls.
- Complete remaining affected-package validation after the applied and formatted
  Crypto, Model and Core/daemon repairs, including canonical roundtrips and
  explicit raw-field layouts; retain the passing Model command’s exact scope.
  Complete FASTPQ's raw-field regression and ordinary library/offline suites,
  plus the full `scripts` scope; retain earlier passes only on their recorded cuts.
- Complete strict Core ZK library checks with defaults and without defaults,
  `zk-tests`/`halo2-dev-tests` library and grouped integration coverage, and
  canonical Pasta/PLONK/G1/Advance/PIPA owner/consumer checks. The separate
  single-design plan retains genuine proof, SDK and ledger integration; do not
  restore retired APIs. Run Privacy's 52 ordinary regressions before the full
  unfiltered ordinary suite; preserve
  failures without retries, ignore conversion or subset claims. Maximum-proof
  time/RSS evidence and enforced address-space limits remain release gates.
- Resolve separately owned Core-wide unit failures and run applicable current
  workspace lint/tests. Component receipts do not establish whole-source
  equality, release readiness or workspace success.

Final moved-model controls must enable `transparent_api`, because preserved
block assertions are feature-gated. Run the retained model controls and all six
ordinary Norito grouped harnesses sequentially in the warm `finish` lane:

```sh
scripts/cargo_fast.sh --target-slot finish -- test --locked --offline -p iroha_data_model --features transparent_api --lib block::tests
scripts/cargo_fast.sh --target-slot finish -- test --locked --offline -p iroha_data_model --features transparent_api --lib proof::tests
scripts/cargo_fast.sh --target-slot finish -- test --locked --offline -p norito --lib \
  --test norito_group_01 --test norito_group_02 --test norito_group_03 \
  --test norito_group_04 --test norito_group_05 --test norito_group_06
```

Norito disables automatic test discovery: name all six grouped harnesses.
Preserve adaptive/default flags, flag restoration, derive/header/frame controls,
source-reader negatives and every original assertion.

O7 requires a qualified candidate and comparable warm timing against the
September 27 observation, with source, toolchain and competing load recorded.
Changing-cut timings are observational, not causal speedups. Roadmap A5 remains
open: measure introduced-unit limits, the 25% model-reduction target and 13-GiB
release ceiling on pinned supported Mac/Linux runners, including extracted
owners. Source-cost limits and debug checks do not satisfy resource qualification.
