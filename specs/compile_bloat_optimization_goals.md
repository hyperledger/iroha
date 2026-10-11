# Compile-time and code-bloat optimization goals

Separate compilation owners while preserving all features, canonical wire
formats, deterministic execution and runtime behavior. First-release consumers
use actual owners directly; retired implementations and compatibility shims are
removed. Leave Sumeragi to its separate owner and inspect SCCP before changing
adjacent code.

| Goal | Status | Completion criteria |
| --- | --- | --- |
| O1: Finish compiler and Core ZK ownership | In progress | IVM's normal graph excludes the compiler; compiler/toolchain/VM and proof tests pass; source guards and consumers use actual owners; current default and proof-harness Core ZK checks and strict lint pass. |
| O2: Extract state-free privacy verification | In progress | Privacy owns state-free verification while Core retains state authority; original proof/wire fixtures and ordinary coverage remain; native/Python/JS graphs exclude validator execution; current repaired regressions and ordinary suite pass. |
| O3: Extract state-free timed-OVN verification | Complete | Evidence, casting archive and TLE verification have a separate owner; Core retains authenticated constructors, state reads and signers; bridge tests preserve authorization and replay checks. |
| O4: Isolate executable build metadata | Complete | Thin daemon/CLI packages supply compiled identity to metadata-free libraries; executable names/features remain coherent; the authenticated two-build metadata check preserves library freshness on its recorded source cut. |
| O5: Remove production parsing of large test bodies | Complete | Four cohesive P2P/compiler/model test modules moved without dropping tests or fixtures; source guards and preserved runtime harnesses pass. |
| O6: Complete current-source validation | In progress | Norito/IVM-only, feature, dependency and target guards, focused tests and applicable workspace lint/test gates pass on the current candidate; unresolved external failures are recorded. |
| O7: Measure improvements | In progress | One warm same-package check records actual timing, source/toolchain and competing load against the September 27 observation; further extraction requires measured benefit. |

The ownership changes are implemented. Current-source qualification remains
open. IVM and its artifact admission use the compiler-free
ABI/surface owners; compiler tools belong to Kotodama. Static argument/numeric
encoding belongs to `ivm_abi`, while VM decoding, gas and memory custody remain in
IVM. Privacy and timed-OVN verification have state-free owners; Core retains
committed-state reads and authenticated authority. Thin executables own build
metadata. Shared operation journaling has one owner consumed directly by Wallet,
SCCP, services and daemon, with signing and finality retained by consumers.

The merged manifest inventory contains 129 source manifests and 123 workspace
members, with the inactive Wayland patch protected. The source-cost ratchet
matches all 72 measurements exactly. Recorded locked offline dependency boundary,
feature hygiene, legacy-codec and checker-control passes retain their input cuts.
Shipping Oracle denials and the sole aggregate-model test exception remain intact.
The reviewed ratchet includes the model’s live Pasta field/hash dependency,
direct allocation-owner dependencies and the proof crate’s development-only
timing dependency. The daemon’s unused direct Sumeragi edge is removed; Core
retains consensus ownership. Resolved metadata requires canonical `deps`;
malformed entries are rejected instead of inferring an empty or alternate graph.
Native qualification and requalification of changed selected inputs remain required.
SDK Native custody and genuine production proving remain mandatory even with
SDK defaults disabled; assembly and admission tools require explicit `dev-tools`
selection under the unchanged 24-default ceiling.

The compiler fixture seal records 308 includes and 616 test names, with all
43 source-reader controls passing on their finite input cut. Foundation CI
selection passes all 88 controls. Norito passes 581 ordinary tests, the original
ignored snapshot utility and eight public heap controls on its recorded cut,
before later Model/Torii changes. Journal strict lint and all 11 unfiltered
ordinary tests pass on their current selected inputs, with zero ignores. Strict
lint preserves 1,476 protected inputs; the test interval preserves all 1,490
inputs, invocation, tools and executable custody. Wallet's shared retained reader
audits the fixed native namespace before decoding, signing or HTTP. Its
prospective macOS registry
retains all 191 earlier names and 15 custody controls across 216 cases; native
qualification remains open. Direct IVM/SDK and both Core ZK strict frontends also
remain required. Earlier component passes retain their source, feature and
artifact scope.

All 52 previously failed ordinary Privacy cases remain ordinary tests. They
must pass in the current harness, followed by its complete unfiltered ordinary
suite with the original ignores retained. A prepared runtime schedule, source
inventory or successful focused subset does not satisfy O2. Core-wide failures
and their repairs require separate current-source qualification.

The September 27 baseline checked `irohad`, `iroha_cli` and `iroha_kagami`
without incremental compilation after a data-model edit: 526 seconds overall,
including Torii 187.0, data model 126.1 and Core 119.5 seconds. A warm check on a
different source and toolchain is an observation; it does not establish a causal
speedup or memory reduction. Final timing requires a qualified current candidate.

The [ownership and validation note](../docs/validation/compile-bloat-ownership.md)
records the boundaries and remaining checks. Roadmap A5 separately requires
pinned Mac/Linux measurements for introduced units, the 25% model-reduction
target and the 13-GiB release memory ceiling. Source moves and debug component
checks do not satisfy those resource gates.
