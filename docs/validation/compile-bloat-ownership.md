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
| Codec layouts | Norito accepts fixed-width and compact-length layouts. Retired packed-layout implementations and the last unused flag-name constant are removed. Header/layout and malformed-frame rejection controls remain required. |

Core retains committed-state authority, authenticated constructors, signers and
opaque authorizations. Public evidence and storage APIs grant no authority.
Native SDK custody and genuine production proving remain mandatory even with
SDK defaults disabled; SDK assembly and certificate, attestation, preparation
and inventory tools remain explicit `dev-tools` targets under the unchanged
24-default ceiling. Native/JS/Python verification consumers use state-free owners
without Core/P2P in their normal graphs. The applied boundary policy denies
shipping Oracle consumers and admits Oracle only in the dedicated development
aggregate; fresh maintained validation remains required.
All 21 configured boundary policies retain their runtime, P2P, compiler and
test-feature denials, fixed SDK Native/proving paths and SCCP/Wallet consumer
requirements. Hardware acceleration must preserve deterministic results and its
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
scope; earlier passes do not qualify later source.

| Scope | Recorded health and limit |
| --- | --- |
| Source graph and guards | The merged manifest inventory has 129 manifests and 123 workspace members, with the inactive Wayland patch protected. The source-cost ratchet matches all 72 measurements exactly. Recorded locked offline boundary, feature hygiene, legacy-codec and checker-control passes retain their input cuts. Shipping Oracle denials and the sole aggregate-model test exception remain intact. Resolved metadata requires canonical `deps` and rejects malformed entries. Native qualification remains required. |
| Compiler fixtures and CI | The compiler reader records 308 fixture includes and 616 test names; all 43 reader controls pass. The Foundation/selection CI controls pass all 88 cases. These are scoped source/control receipts. |
| Model, ABI and Surface | The recorded coherent default-library cut passed 4,841 Model, 210 ABI and 33 Surface tests, retaining 135 original Model ignores and the distinct-supply Mint/Burn byte oracle. Subsequent model changes require fresh dependent validation. A later focused Model group receipt records 95 cases: 94 pass and one is ignored. Neither receipt establishes a current broad native result. |
| Norito | The recorded cut passes 581 ordinary tests, the original ignored snapshot utility and eight public heap controls. This precedes later Model/Torii changes and does not qualify their dependent code. |
| Journal and Wallet | Journal strict lint and all 11 unfiltered ordinary tests pass on their current selected inputs, with zero ignores. Strict lint preserves 1,476 protected inputs; the test interval preserves all 1,490 inputs, invocation, tools and executable custody. Wallet's shared retained reader rejects unknown native material before decoding, signing or HTTP. Its prospective 216-case macOS registry retains all 191 earlier names and 15 custody controls; Wallet and SDK native qualification remain pending. These results do not qualify workspace, release or O7. |
| ABI and direct IVM consumers | Strict ABI/Surface libraries, fresh unfiltered ABI/Surface and IVM runs, direct SDK/integration consumers, canonical fixture producers and Deploy calls remain pending. |
| Core ZK | Both current default and real-proof-harness strict frontends remain pending. Earlier checks retain their original cut; a prepared import repair is not current native evidence. |
| Privacy | All 52 earlier failures remain ordinary tests; current regressions followed by the full unfiltered ordinary suite remain pending. The latest native inventory has 68 ignores; prospective 72 ignores are source-only. No fresh native count or full-suite pass is claimed. |

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
  prospective 216-name source registry and all 15 custody controls, including
  the unknown-native-material regression, plus SDK consumer checks. Requalify
  Journal after subsequent selected input changes.
- Execute the ABI/IVM 12 phases with fresh admission: strict and unfiltered
  ABI/Surface libraries, full unfiltered IVM library, actual ordinary/ignored
  membership, original integration/SDK assertions, both fixture-producer checks
  and Deploy calls. Do not borrow the earlier coherent cut's pass.
- Complete current Core ZK default/proof-harness/strict checks. Run Privacy's
  52 ordinary regressions before the full unfiltered ordinary suite; preserve
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
