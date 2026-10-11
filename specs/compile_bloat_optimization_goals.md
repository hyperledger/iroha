# Compile-time and code-bloat optimization goals

Separate compilation owners while preserving all features, canonical wire
formats, deterministic execution and runtime behavior. First-release consumers
use actual owners directly; retired implementations and compatibility shims are
removed. Leave Sumeragi to its separate owner and inspect SCCP before changing
adjacent code.

| Goal | Status | Completion criteria |
| --- | --- | --- |
| O1: Finish compiler and Core ZK ownership | In progress | IVM's normal graph excludes the compiler; compiler/toolchain/VM and proof tests pass; source guards and consumers use actual owners; current Core ZK strict checks and canonical proof-owner/consumer tests pass. |
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

The recorded signed validation baseline is `4486aa78661b8f289d21238e034fc2ece10600d8`.
Recorded static source-graph discovery lists 124 workspace members; it does not
establish a current resolved Cargo metadata graph. The inactive Wayland patch
remains protected. Source-cost and feature-hygiene checks passed on that recorded
cut, with all 72 cost limits matched exactly. Recorded locked offline dependency boundaries,
legacy-codec and checker controls retain their input cuts.
Shipping Oracle denials and the sole aggregate-model test exception remain intact.
The reviewed ratchet includes the model’s live Pasta field/hash dependency,
direct allocation-owner dependencies and the proof crate’s development-only
timing dependency. The daemon’s unused direct Sumeragi edge is removed; Core
retains consensus ownership. Resolved metadata requires canonical `deps`;
malformed entries are rejected instead of inferring an empty or alternate graph.
Native qualification and requalification of changed selected inputs remain required.
SDK custody and genuine proving qualification follow the canonical G1, Advance
and PIPA owners. Their bridge, SDK and ledger integration remains open under the
[single-design goals](kagemusha_single_design_proposal.md#9-implementation-ownership-and-retirement).

Rust CI now has one `axum-core` owner and its workflow/source controls pass.
Compiler fixture and source-reader controls retain their recorded input scope;
compiler/toolchain/VM and proof native tests remain required.
Earlier `pytests/scripts` and the five affected source-scanner module passes
retain their original input cuts and stock skips. Current full Python
requalification remains pending. The drifted whole-scripts run remains
diagnostic; interrupted attempts with unknown exits remain unresolved.

The generic Norito array correction is applied and formatted: element frames
must be consumed exactly, actual owned allocations are charged once, and nominal
raw-byte fields keep their explicit layouts. Complete Primitives/P2P/Manifest and Norito/derive/Crypto runs passed on the
recorded cut with stock ignores retained and stable source. The latter Cargo process exited successfully, but its outer controller
reported a changed Git baseline; that original outer failure is preserved. An
independent Source/Git join binds both runs to that recorded source and genuine
formatter baseline. Subsequent commits and selected-input changes require fresh
qualification. This join does not qualify broader native tools, artifacts
or consumers. Earlier Model library,
bin, test and doctest passes and Python passes retain their original inputs;
current full Model and Python requalification remain pending. The earlier
successful Crypto run with source/Git drift and interrupted unknown exits do not
qualify the current checkout. FASTPQ's raw-field regression remains pending.

Journal strict lint/runtime and earlier Crypto checks retain their selected
source and artifact scope. Wallet's shared retained reader audits the fixed
native namespace before decoding, signing or HTTP. Its prospective 218-case
macOS registry preserves all 191 earlier names, 15 custody controls and two new
byte-frame allocation controls; native qualification remains open. ABI/IVM
validation preserves the original 12 phases and adds allocation and compact-call
compiler/runtime phases, 14 total; these phases and direct consumers remain unrun.
Eleven changed fixed inputs still require current joins, including Torii and
epoch-owner evidence.

Current Core ZK qualification requires strict library checks with defaults and
without defaults, the `zk-tests`/`halo2-dev-tests` library and grouped integration
coverage, and canonical Pasta/PLONK/G1/Advance/PIPA owner and consumer tests.
Those checks and FASTPQ ordinary runtime remain pending. Genuine Halo2/Pasta
proving is mandatory in every build; the retired real-proof-harness feature is
not a qualification target. All 52 previously failed Privacy cases remain ordinary tests;
current regressions followed by the complete unfiltered ordinary suite are still
required, with stock ignores retained. Its prepared controller remains inactive.
A prepared schedule or successful focused subset does not satisfy O2. Core-wide
failures and their repairs require separate current-source qualification.

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
