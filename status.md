# Status

Reviewed 2026-10-07. Iroha 3 remains under implementation and qualification.
Component checks cover substantial portions of the system, but the combined
source has not passed the complete workspace, SDK, hardware and release gates.
The [roadmap](roadmap.md) lists outstanding outcomes; the linked specifications
hold detailed acceptance criteria. Routine repair receipts belong in PRs and CI.

## Current implementation

| Area | Current state | Remaining qualification |
| --- | --- | --- |
| Sumeragi | The sans-IO core, simulator and node driver are integrated; the previous consensus runtime is removed. Certified results bind World roots and ordered events. Restored body requests retain verified live Sync responders through source-list saturation; invalid deferred certificates trigger a bounded refresh. | Current-source qualification remains open: all simulator scenarios at 10,000 seeds, the complete current mutation registry with nonignored native controls, full workspace tests and strict lint, rebuilt native SDK artifacts, signed RS16 loss/withholding, lane isolation/restart and authenticated accelerated restoration. Test discovery and exact terminal accounting follow the [current validation contract](specs/sumeragi_goals.md#current-validation-contract-2026-10-12); earlier source results and fixed historical test counts do not qualify the current candidate. |
| Lanes and dataspaces | Fixed/elastic lanes run as Sumeragi instances; the global chain merges certified lane blocks. The daemon can host an independent signed dataspace root with its own State, Kura, allocation pool and native context archive. Explicit and managed Kagami AMX bootstrap retain the parent's original G1/H2 and stage the participant in private genesis. Explicit administrative parent registration retains its original signed request and authenticated native outcome; the resumable proof source can detach from its State view. Lifecycle/restart have component and node coverage. | Current-source qualification of managed registration and detached proof custody, complete outbound funding, durable validator relaying, network isolation, scale and restart. |
| Storage and execution | `lanes::LaneRunner` and `SumeragiLaneMerge` are the production path. Kura owns a shared fail-stop gate and authenticated native tips/journals. | Original funded execution custody through acquisition, certification, publication, replay and retained-generation reclamation. |
| Configuration and DPN | Private dataspace definitions are separate from validator settings. `iroha dataspace plan/apply/status` derives artifacts and retains once-only transactions under one budget. Kagami has an isolated BPNG catalog/paid-namespace genesis preset. | Profile-based generator closure, four-daemon paid deployment/readback and physical isolation. BPNG local contracts, fee authority and application provisioning remain incomplete. Owner-node provisioning is outside this path. |
| Kagami/Mochi developer experience | Shared config-free native localnet, owned processes and workspace contexts are implemented in `iroha_deploy`; Musubi provides source, artifact and package deployment with retained recovery. Matching macOS regressions pass for filesystem custody, continuous startup deadlines, worker handoff and failure cleanup, bootstrap selection and retained gateway projections. Installed release binaries pass private-root startup, restart and listener isolation. A native regression reproduces and fixes startup rejection when a certified descendant preserves the exact signed custody; revocation, renewal and changed-certificate controls still refuse. | Global deployment still exceeds the original 30-second startup deadline during native service provisioning. Matching release binaries also exceed the explicit 300-second diagnostic startup limit while authenticating current provider and signer discovery; complete runtime validation of the startup fix remains open. Provider-ingest State/archive publication retries and reader-contention regressions pass. The genuine deep-history test still expires a short-lived authorization during preparation; bounded retained-history completion remains unresolved. Failed attempts close all four owned peers. Combined paid provisioning, anchoring, payload isolation, renewal and publication need full validation. The public Taira installation profile is committed and both release packagers select its exact image. The previously retrieved checkpoint passed native signature and finality verification but has expired; a current authenticated checkpoint remains required for remote attachment. Current bootstrap publication requests to taira.sora.org return HTTP 404 from the validation host; fresh public readiness remains unverified. Recurring signed checkpoints, cold registry publication, native desktop interaction, signed OS matrices and reference-host latency remain open. Concurrent source changes are recorded separately from compiled-candidate results. See the [developer goals](specs/kagami_mochi_devex_goals.md). |
| Native multisig | [Occurrence identity](specs/multisig_proposal_occurrences.md) is being implemented across execution, rooted evidence, SDKs and applications; instruction commitments remain separate. Torii account history projects matching executed occurrences and applied batch receipts, excluding proposal intent and rejected legs; 21 focused tests pass, including nine certified-chain regressions. | Same-candidate replay, cancellation, controller-change, SDK and rollout validation remain open. |
| Kagami/Mochi developer experience | Shared config-free native localnet, owned processes and workspace contexts are implemented in `iroha_deploy`; Musubi provides source, artifact and package deployment with retained recovery. Matching macOS regressions pass for filesystem custody, continuous startup deadlines, worker handoff and failure cleanup, bootstrap selection and retained gateway projections. Installed release binaries pass private-root startup, restart and listener isolation. A native regression reproduces and fixes startup rejection when a certified descendant preserves the exact signed custody; revocation, renewal and changed-certificate controls still refuse. | Current runtime qualification requires validation of the integrated SCCP native server, CLI and authority consumers; the obsolete roster/rotation consumers are removed. The scoped Tokio entry for logger initialization passes its isolated actor regression; the installed runtime now starts all four validators and advances native bootstrap. Fresh startup still exceeds the original 30-second deadline before service provisioning completes. Provider-ingest State/archive publication retries and reader-contention regressions pass. The genuine deep-history test still expires a short-lived authorization during preparation; bounded retained-history completion remains unresolved. Failed attempts close all four owned peers. Combined paid provisioning, anchoring, payload isolation, renewal and publication need full validation. The public Taira installation profile is committed and both release packagers select its exact image. The previously retrieved checkpoint passed native signature and finality verification but has expired; a current authenticated checkpoint remains required for remote attachment. The compiled CLI passes public Taira readiness diagnostics, while the confirmed bootstrap publication URL still returns HTTP 404 from the validation host. The edge renderer and installer now support exact public checkpoint/profile routes; native nginx activation and fresh signed publication remain unqualified. Recurring signed checkpoints, cold registry publication, native desktop interaction, signed OS matrices and reference-host latency remain open. Concurrent source changes are recorded separately from compiled-candidate results. See the [developer goals](specs/kagami_mochi_devex_goals.md). |
| Rust client | Immutable account contexts, owned async transport, explicit blocking capabilities and typed fee quoting are implemented. | Remaining capability/consumer migration, unified errors and network cancellation/finality/authorization coverage. |
| Native payments | Single payments reuse `SettleAtomic`, payer-owned business identities and immutable successful-output receipts. Paid settlement, concurrent gateways, included-but-rejected recovery and linked full returns pass one source-bound four-validator candidate, including final-tip restart and no successor traffic. The bank inbox credits once. The Rust API separates explicitly paid `submit` from `resume`, which has no new-carrier signer or builder; rejected recovery stays unsettled, and a fresh paid retry needs explicit authorization. Full returns preserve the original success and authenticate their own reverse receipt. Unresolved AMX decisions retain authenticated epoch contexts through handoffs. AMX approval carriers expose a complete World inventory only to current full-ledger readers, with permission rechecked after proof production and before delivery. | Cross-SDK delivery and consensus-owned partial-return limits remain open. The 12-validator AMX fixture uses manifest-derived dataspace identities, authenticated executed Global H1/H2 and restricted full-replica private lane zero. Per-root listener isolation and signed SDK status authentication pass the local three-root fixture. Bootstrap still stops on transient State-busy status polling before the autonomous relay starts; the bounded retry repair remains under validation. Funded autonomous relay, delayed-rotation/restart and the remaining [three payment flows](roadmap.md#sora-nexus-payment-acceptance) still require network qualification. |
| Kotlin/JVM | Kotlin owns the SDK, HTTP/SSE/WebSocket, attestation tools and JNI API; Java consumers exercise that API. Host coverage includes native/confidential operations. Android Keystore alias existence is decided only by keystore2 `getKey` (API 31+); a Keystore error is never read as absence. | Remaining Java/publication retirement, signed packages, CUDA hardware and Android/device qualification. |
| Other SDKs | Shared prepared-operation, signing, account and native checkpoint contracts are being migrated across Swift, JavaScript, Python and C#. | Same-source native artifacts, complete fixtures/consumers and release OS/architecture matrices. |
| Torii collection queries | Seventeen collections and eleven explorer feeds share the [query contract](specs/torii/collection_queries.md) across Rust, Kotlin/Java, Swift, JavaScript, Python, C#, CLI and MCP. Identity-ordered reads seek and stream; authenticated history checkpoints bound deep reads. Global-state collections execute once per read for exact totals and aggregates. History and explorer feeds explicitly reject unsupported controls. Signed query selectors have one feature-independent layout; client network context is explicit. [Contract activity and native events](specs/torii/collection_queries.md#contract-activity-and-native-events) have separate sources: activity projects committed top-level `ContractCall`s and consensus-bound metadata; event rows expose successful execution outputs’ authenticated emissions with immutable definitions and `provenance: emitted`. | Current-candidate live multi-dataspace paging and full SDK/native delivery qualification remain open. Current ABI-29 Swift framework, complete native SDK suites, SwiftPM Release consumers and iOS demo simulator checks require matching rebuilt artifacts; physical-device and signed public-release qualification remain separate. See the [completion goals](specs/torii/query_completion_goals.md). |
| Norito | Declared identities own canonical frames; payload serialization/reconstruction and explicit JSON key contracts are integrated. | Consumer/feature closure, fallible allocation ownership, physical model extraction and workspace lint/runtime coverage. |
| IVM/Kotodama | IVM is the sole VM with ABI V1 and program header 1.1; header 1.0 is rejected. Compiler separation and state-free proof owners reduce normal dependency graphs. Source bundles support declaration includes and explicit module exports; authenticated error-message catalogs preserve nominal schemas. FASTPQ Metal uses one embedded-bundle admission owner; runtime source/path loading is removed. Ordinary Linux/Windows daemon dependencies include driver-loaded IVM CUDA; genuine bundle absence permits CPU build/startup, and supplied unapproved material is rejected. Original-pool idle-runtime rows and scoped committed/frozen account-rekey, trigger-contract and all four trigger-action captures are integrated; fresh compilation and runtime validation remain pending. | [Syntax and developer-experience completion](specs/kotodama_devex_goals.md): compiler/tooling integration, scoped authority, atomic call semantics, interfaces, emitted events and lifecycle behavior pass matching component/API regressions; examples and owned artifacts are regenerated and checked. Installed native SDK and whole-node qualification remain open. Lifecycle/custody closure, complete State/Kura publication, native execution proofs, anchored private invocation/AXT, coherent SDK regeneration and hardware validation. FASTPQ has no approved Metal bundle. IVM CUDA approval is `None`; genuine signed ten-family artifacts, driverless runtime checks and physical qualification remain open. |
| ZK delivery plan | The [plan](specs/zk_delivery_plan.md) and its [task graph](specs/zk_delivery_graph.json) own the ZK, privacy, authenticated-State and FHE work. Landed as source-checked contracts and inventories: plan and graph checks; the zk-X509 presentation interval with shared vectors; the FASTPQ `air` interface with the shared-backend inventory; the IVM proof-coverage inventory; the first-release history and cutover contract with regenerated native pinned history and declared ABI, State-layout and execution-root cutovers (ABI V1 hash golden and carriers regenerated); the FHE ownership inventory; the RAM-LFE V1 contract with a cleartext reference; the State table and root inventory with the keyed-commitment contract (`specs/sumeragi.md` §16); the unified resource contract; the operation and admission-route inventory; the primitive and workload audit; and the runtime-validity census. The ZK validity limits and windows (45 bounds), pipeline execution limits (15) and fraud assessment admission are committed chain policy (`zk_validity_policy_v1`, `pipeline_validity_policy_v1`, `fraud_admission_policy_v1`); each block freezes its predecessor policy. Fraud controls cover authored signed genesis, actual paid settlement outcomes, fees and roots across different local transport settings, and strict final-tip restart. Verification gas uses the schedule frozen in each block. Shared crates: `iroha_fhe` (exact RNS, NTT, basis-conversion and rounding arithmetic, and the RNS-BGV starting candidate `iroha_fhe::bgv` with independent vectors and a tape-level cost model) and `iroha_measurement` (phase and resource records, with `scripts/zk_resource_harness.py`). Four development-only State-commitment candidates are measured natively and in-circuit (`specs/state_commitment_candidates.json`). | Complete operation deliveries remain open; the RAM-LFE V1 types and BGV candidate do not yet provide a production encrypted-execution path. No BGV profile is qualified: recorded lattice estimates leave affine and refresh below 128 bits under ADPS16, and no candidate holds the maximum V1 class shape under instruction-by-instruction lowering; proved normalizing lowering with one fixed public schedule per class profile remains mandatory. No State-commitment candidate is selected, and the certified State root is still the World-only accumulator (inventory defects G1-D1 to G1-D11). The primitive audit leaves BN254 Poseidon and post-quantum findings open (F.5). Runtime validity is moved only in part (F.4): the `[nexus]` bounds (10) and the governance, crypto-algorithm, oracle, content, settlement-router, pipeline gas-identity and execution-policy digest families still read node configuration; the native PIPA-R, STARK and confidential switches remain; Cargo features (`zk-stark`, fault injection, test-network hooks) and activation, qualification, lifecycle and manifest gates still decide validity. The selected 16 MiB payload and canonical privacy budgets now accommodate measured structural maximum-proof carriers within the unchanged 10 MiB signed-transaction cap. Complete-invocation and restore policy checks are implemented. Native finality readers and consensus signing use the dedicated consensus suite, and focused Core consumers compile. The canonical decoder no longer overflows the default stack in the original AMX/attestation reproductions. Staged genesis now retains its original execution pool; private-root retained-artifact binding, concurrent snapshot-retry validation and downstream consumer qualification remain open. Gossip profile/shaping reconciliation, actual maximum native proofs and whole-network commit/restart/replay remain open. AVX2 on a physical x86-64 CPU, Metal/CUDA parity, Linux `RLIMIT_AS` enforcement, a complete X509 proof under the harness and four-validator evidence are unexecuted. |
| SoraFS | Software signing, canonical manifests and storage/billing/publication ownership are implemented; the ordinary Node library tests pass. | Matched daemon/harness, provider resilience and L1/L2 promotion. |
| SCCP | Native finality and request-funded proofs, committee generations, retained anchors, Keepalive/clock guards, fast-pause consumers, forgery accountability and reconciliation accounting are implemented. Original-pool native light-client/self-claim integration and coalition-floor reporting are implemented. Recorded Core/Torii/daemon, certified-clock and CLI recovery component checks pass, as do EVM/TON fixtures and genuine four-peer local EVM checkpoint replay. Both launch gates remain closed. | Requalify the merged clock/admission changes, current Core execution/mutations, genesis profiles, node/CLI/SDK integration and four-peer/EVM corridor on one candidate. Combined workspace validation, qualified Parliament authority, independent audits and live deployment evidence remain open. |
| KAGEMUSHA | G1 revision4, fixed64 quotas, Request-recorded controls, native PIPA-R/PIPA-AS, operation relations and durable wallet/C/JNI paths are implemented. Load authenticates ordinary Sumeragi finality before Advance. Funding assurance requires the released wallet and an uncompromised OS. Universal Dataspace tokens need no Parliament approval; regulated eligibility belongs to bank middleware. Controls default off; fees default to zero. Retired monetary engines and recursive/mint finality are removed. See [NF1–NF6](specs/kagemusha_native_finality_goals.md) and the [evidence gate](specs/kagemusha_evidence_gate.md). | Current release qualification is incomplete. An isolated source candidate now builds the node, CLI and integration harness with audited compiler inputs; final catalog/SDK qualification must use the completed successor candidate. Retained older genesis originals contain retired parameter layouts and require regeneration with current signed network inputs. JNI admission now checks the complete privacy and wallet export surface; ABI29 alone does not admit a matching SDK. Android and Apple physical drivers are integrated, with Pixel 6 / Android 17 and the connected iPhone 17 Pro Max / iOS 26.7 selected first. Genuine iPhone enrollment awaits an App Attest-enabled profile; Xcode currently has no signed-in developer account to provision it. The iOS provider requires acknowledged Selected and Released mutations, but stock-device power-loss/restore persistence remains unqualified. Required outcomes remain current-source 52-route catalog admission, matching SDK/node artifacts, genuine A→B→C→Unload on four validators, complete envelopes ≤10,000 B, physical two-second p95 durable completion, memory/storage bounds and full C12 joint privacy, including the exposed salted-fold carrier comparison. Component proofs and local algebra do not establish those outcomes. |
| Petal Stream | `iroha_petal` implements the [Petal Stream](specs/petal_stream.md) animated optical transport (`天` orientation field, katakana, tile polarity and ring dots as three Reed–Solomon lanes under a rateless fountain) with decoder, renderer, camera simulator and `iroha offline petal`. A gain-free tile read keeps lanes `P` and `K` alive under over-exposure, veiling light and shadows. Swift, Kotlin/JVM, JavaScript, Python and C# ports reproduce the shared fixtures and decode the golden captures to the recorded lanes. Three corner blossoms suffice (a thumb, glare or frame edge may hide the fourth) and sessions track the pose between frames (about 4× cheaper per frame). Simulated reads complete a 10,000-byte KAGEMUSHA message in 11.5 s (45 s from lanes `P` and `D` alone). | All evidence is simulated: physical-camera reads on the governed Android/iOS device matrix, lane `K` at 480p or soft focus, and the public guides in `iroha-docs`. |

## Immediate blockers

SCCP uses native finality, original committee/staking custody and the 199-byte
control leaf. Shared Keepalive and bounded due work, the native Prepare clock
guard, fast-pause lifecycle consumers, retained pruning and reconciliation
accounting are implemented. The latest genesis profile enforces original G1
staking bindings and non-reusable reset identities; focused profile and signing validation passes.
Original-pool native light-client admission, self-claim integration and the
coalition-floor projection are implemented, with recorded Core/Torii/daemon
component coverage. Certified-clock and causal controls, pinned TON registration,
CLI terminal proofs and concurrent journal-step recovery have passing component
results. The merged clock/admission changes require fresh combined-candidate
qualification; the full Core mutation gate and combined node/CLI/SDK/workspace
validation remain open.
The actual Parliament eligibility, draw, positioned shared pass, casting-open
anchor and qualified ballot remain unavailable, so both launch gates stay closed.
Component contract and Core results do not establish deployment readiness.
The current four-validator candidate publishes native finality and refuses unqualified
route governance; its authentic certificate passes local EVM checkpoint replay.
Monetary transfer and live deployment qualification remain gated.

The Nexus proposal/status repairs and original invocation binding are preserved.
The paid Nexus workload exposed an AMX retry defect: a completed State visibility
publication incorrectly invalidated retained decoded bytes and halted the node.
The repair separates immutable decode custody from State authority; every retry
still authenticates the current committed parent. Native retry and parent
authentication controls pass. An earlier rebuilt candidate passed ten fresh paid Nexus
workloads, serial restart/readback of all sixteen validators and disjoint-lane
stop/restart, with all expected peer processes closing cleanly. Subsequent source
changes require fresh qualification of the combined candidate.
The retired publisher-custody fixture
cannot supply current admission evidence.
Full fault/leakage campaigns, optimized-build resource qualification and the
complete original funded execution graph remain open.

Native ceremony handoff preserves overlapping descriptors and read-only phase pipes.
The committee fixture explicitly pays for the first E+1 successor before authenticating
preparation: stopping exactly at the E selection boundary cannot supply E+1 evidence.
Full paid 4→7→4, withdrawal, return-boundary liveness, restart and slashing qualification
remain open. Both rotation ceremonies must finish within their original transport and
overall runtime deadlines on the rebuilt candidate. Lane retirement component controls
now cover original reads, publications,
historical opening joins, final-reader release and authentication/refusal propagation.
Physical retirement and complete retained-history dependency closure remain open;
certified disk frames remain retained for global replay.

Actual original-library regressions reproduce generic snapshot undo loss: a present
previous null value is serialized indistinguishably from no previous value in Cell and
Storage. Writers and readers now use explicit present-value undo framing; current-source
qualification of the coordinated repair remains open.
Certified-history restoration keeps large genesis and successor authentication
temporaries in separate function frames. Its default-stack regressions pass without
raised stack limits. Strict startup still rejects nonempty snapshot caches and uses
certified replay; accelerated complete-State restoration remains open.

The runtime and trigger permission guards reject malformed recognized payloads before
delegation; decoder refusals preserve local deferral. Core strict lint remains
unqualified: unused production/resource graphs still fail, and removal of blanket
Clippy group suppressions requires a fresh strict run. Dependency and test-network
lint failures also remain open until
their repairs pass the actual affected commands. The repaired Rust SDK client source
passes its unit suite and strict lint; qualification of the final combined source, signed RS16
loss/withholding and release remains open. Exact finalized-carrier retries retain
original execution without requeueing or charging again; changed source requires fresh
evidence.

Core/World acquisition retains original frozen readers for verifier, proof-status
and validation-fee indexes. Complete authenticated State/Kura publication remains
unimplemented. The combined test graph, complete resource funding and original
Validate-to-Apply custody remain open. Component repairs do not establish one
retained execution through finality and restart.

The ordinary SoraFS Node library tests pass after correcting fixture permissions,
hedged-encryption assertions and cumulative quarantine decoding. The Core
selection has scoped coverage and Torii's unit-test target compiles. Production
qualification remains open under the
[reliability goals](specs/sorafs/first_release_reliability_goals.md) and
[closure ledger](specs/sorafs/v1_closure_ledger.md).

Native stream-token gateway admission combines protected consensus quotas, leases and
callback history with challenged readbacks, daemon software custody and a final serving
publication fence. Broker-supplied gateway authority and the generic local token-reputation
producer are retired. Native admissions own exact reputation append intents; certified current
readbacks and committed terminal dispositions govern callback completion. The token issuer uses
one bounded private receipt journal over shared Unix/Windows filesystem custody.
Broker observation continuations retain the original reply, socket, admission and
file-configured absolute deadline through publication; combined runtime qualification,
physical allocation ownership and durable recovery remain open. Native Windows
execution and release qualification remain open. Combined candidate
validation, native service closure and multi-replica recovery remain open. Component
coverage does not qualify cold registry fetches, the complete 64 MiB fetch-process RSS
bound, signed native releases or reference-host p95 latency.

The private-settlement five-second proof-through-settlement target is unmet.
Current-source happy-day settlements and serial restart have functional coverage;
fault, leakage, performance and release campaigns remain open. Earlier source or
component observations do not qualify the final combined candidate.
See the [protocol](specs/private_settlement.md).

Focused runs on 2026-10-06 on `13343a33c1` with the upstream merge
`23fae0094f` applied (the merge was not yet committed) pass `cargo check` for
`iroha_core` and `iroha_torii`; the workspace gates were not run. The rest was
measured before that merge and not re-run. On 2026-10-06, a complete
`iroha_core` lib run had 16 failing tests, each failing the same way on a
binary built before the ZK-plan wave: two block-sequence rejections, two
FASTPQ finalized-source and lane counters, a signer-check query, three MUSUBI
pin-outbox and publication-admission tests, the trigger contract-capture work
limits, an IVM host state-read gas test, two State authorization-reader tests,
a State capacity refusal, a state-certificate pairing refusal, the autoscale
elastic-lane liveness test and an autoscale-route validation test. `ivm`
`dead_numeric_register_cycle_executes_all_branches_on_both_hosts` fails
(`ActiveMemoryCapacity`); `iroha_config`
`musubi_private_tls_listener_rejects_retired_mount_configuration` fails; the
`iroha_core` benches `queries` and `validation` do not compile; 30 tests of
the `zk_verify`, `zk_ledger_scaffold`, `zk_proof_retention` and
`overlay_bounds` integration modules are stale and marked `TODO:`; and
`zk::PruneProofs` has no executor admission class, so no transaction can carry
it although the CLI builds one. On `d651d51715`: four `fastpq_prover` lib
tests fail (1,218 pass), in `axt_binding`, `compact_execution_effect_batch`,
the compact quantity artifact and the public-transfer execution effect, and
the four-quadrant tree capacity test fails (124 retained nodes against 127).
On 2026-10-05 before the upstream merges: Torii lib tests, 106 of 5,437 fail
repeatably and at least three more intermittently in a full parallel run; all
five `address_parsing::explorer` tests of `torii_core_routes` and 15 of 54
`agent_alias` tests of `torii_protocols` fail; `irohad_lib` aborts on a stack
overflow in `beacon_bootstrap::seat_attempt::aggregate_tests` after five
`durable::tests` failures, and two `musubi_publication_service::finality`
tests fail; four `ivm` Metal vector tests fail intermittently in a loaded full
run and pass alone. Three guards are red on the merged tree: the trusted
release-surface digest (stale across the upstream merges), the
generated-source registry (`crates/iroha_petal/src/glyph_templates.rs` has no
owner), and `scripts/check_state_commitment_candidates.py`, because the merge
removed State tables and the candidates were measured over the previous table
schema (to be measured again by G.2 or G.3).

## Deployment state

Taira is live at <https://taira.sora.org> on daemon source
`c30e0b18cd7f5b9e1d680abe6478aea7f37ea5b9`, network
`hash:47F0D781D98B119DB3DD130755BD806E08A5F81B1B5F4053601E9AD34D824297#9066`.
The fresh deployment's authenticated cutover and cleanup completed. October 8
02:52 UTC checks found all four validators at height 16, each with three peers
and an empty queue. Public and direct readiness returned HTTP 200; the matching
native client's basic doctor passed all fifteen checks, and authenticated
consensus reported committed/applied height 16 with a ready beacon provider.
The public MCP health call passed and exposed 164 tools. Idle chains create no
empty blocks. The network-time enforcement mode remains `warn`.

The preserved BPNG owner and direct `bpng` dataspace allocation are restored;
the corrected Kina registration committed at height 16. Genuine signed
checkpoint and network-profile artifacts are published under `/bootstrap/`
and were verified against their producer hashes. Obsolete staged public binary
copies were removed while preserving the current deployment and private state;
guest filesystem space available after cleanup was 4.31 GB.

Current source initializes fresh safety records before first startup and retires
completed execution after successful replay before strict native archive
attachment. Deployment preparation, transfer and the routine updater accept an
authenticated build-only candidate without a full regression gate. On-chain
governance owns deployment policy; no fixed 24-hour fault test is a prerequisite
for testnet or production. Release qualification remains open.

Current-source release qualification remains open; the live testnet observation
above applies to the deployed c30 candidate. BPNG application account/alias
restoration and newer wallet ordinary-Load finality commissioning remain open.
Private DPN, paid `dpn`/`admin@dpn` and clean-client completion remain open.
Validators run in a Linux guest on MacStadium in Dublin; use the approved
deployment tooling. Retained incident records describe the
[previous readiness failure](docs/incidents/2026-09-30-taira-readiness.md).


BPNG retained-history qualification, validator catch-up, additive catalog
activation and API22/FE17 application commissioning remain open. Basic acceptance
does not close crash/concurrency or advanced guest work. Infrastructure changes
require the explicitly approved OVH target.

## Build and release qualification

The current `optimizations` checkout includes uncommitted handoff repairs.
Fresh combined Core, node, workspace and SDK qualification remains open.
The repaired daemon and Nexus harness build with the original optimized compiler
settings. Their observed Core compiler invocations stay below the unchanged 13 GiB
kernel-measured ceiling, but both builds exceed the 20-minute target. Other feature
combinations and the complete release remain unqualified. Complete Core unit tests
and fresh native network consumers still require the same repaired candidate.
The earlier eighteen-target Core/Kagami build and all 262 selected native
executions passed with their recorded source and artifacts; they do not qualify
the changed combined candidate. They account for all original
247 obligations through genuine producer/consumer replacements and paired
identical captures, plus the corrected chronology and FASTPQ context controls.
The genuine producer reproduces all four canonical fixtures with actual genesis
and sequential/parallel parity. Both Mac and Linux scalar-CALL, callable, frame
and history selections pass all 61 ordinary controls on their recorded artifacts;
two heavy frame controls remain unexecuted. The locked, offline workspace all-target check passes on the combined X509,
fixture and arithmetic candidate. All 5,005 affected native tests pass: 35 artifact
admission, 4,633 data-model, two allocation-observer and 335 Primitives controls.
The original harness failure from 17 standard `should panic` annotations remains
retained; independent reconciliation verifies the exact actual native events.
The recorded strict Clippy run still fails on decoder visibility, unused CoreZK
items and one test pattern. Reviewed visibility, projection and receipt-method
repairs are now applied; fresh compiler and native validation remain required. These component
results do not qualify the integrated release. Exact evidence and remaining criteria are in the
[ZK goals](specs/zk_first_release_goals.md).

The X509 padding, private-u32 path-length, mandatory copy-census and canonical
EKU repairs are applied. Fresh Mac and Linux artifacts pass all 218 selected
controls, including all 29 profile fields, signed capacity cases and copy-omission
regressions, with unchanged measured source and artifacts. Authentic proof hashes
match across platforms. The standalone DER proof is 1,527,952 bytes and takes
268.12 seconds on Mac and 268.73 seconds on Linux; both verifier and mutation
suites pass. Its test-only format exposes terminal products and does not
establish complete-credential hiding. The complete maximum result below still
misses the proving-time gate; integrated and cryptographic qualification remain open.

The rebuilt Core artifact passes all five prior stack failures on the default
stack, all 72 selected certified-chain controls and all 246 still-existing controls
from the original 247-test request. Its retired control now has three passing
genuine producer/consumer replacements, including paired captures and bridge
verification. The original selection has no uncovered obligation. The complete rebuilt 66-control
group04 run now passes after seeding the initial fee-owning domain and regenerating
the canonical pin fixture with its genuine producer. The changed allocation-credit
control also passes. The repaired CoreZK libtest compiles and all eight bootstrap,
canonical-stream and shared-capacity controls pass. Its initial compiler-input
audit refusal is retained; a supplemental audit validates the actual IVM sample
inputs against every original compiler observation. The lifetime compile-fail test, Primitives 333, Norito derive
59 unit and 17 strict-JSON controls, and 32 compiler cases pass.
Complete Mint/Guard/receiver, genuine proof/export and full-State authority remain
open. The current inventory has 106 codec owners and 1,559 nominal identities,
preserving every prior owner; publication and reduced-feature qualification
remain required.

The fresh Linux and Mac optimized privacy artifacts pass all 133 private-dispatch
controls, including all eight direct-jump and eleven CALL descriptor/frame-work
controls, with zero failures or skips. Earlier RFC, FFT, nonce and auxiliary
oracle passes remain scoped to their recorded artifacts. The applied DER/RFC
canonical-zero inversion repairs and expanded public phase counters require fresh
native tests and compiled-caller review. Complete current ordinary privacy
coverage, IVM execution, initialization and finalized-State binding remain open.
RAM-LFE secure encryption, refresh and the full program relation remain unavailable.

The latest Linux maximum X509 proof on the corrected profile is 9,412,944 bytes.
Producer self-check, independent replay, wrong-genesis, corruption and all 32
nonce-byte substitutions pass; a separate fresh public verifier takes 7.977963
seconds. Conservative reported RSS is 7,163,871,232 bytes, within the unchanged
12 GiB cap, and the kernel-enforced hard/soft 32 GiB address-space gate passes.
These observations do not establish an exact physical or address-space peak.
Proving takes 1,437.185689 seconds against 300, so the complete run fails its
performance gate. The retained result and all 65 phase timers are source-bound;
later changes require fresh validation. The preceding Metal maximum also verified
the complete proof but failed its time and Darwin address-space gates. Relation,
adaptive transcript/hiding and whole-prover side-channel review remain open.
No maximum is qualified, and no cap or supported shape is relaxed.

Maximum FASTPQ ordinary and AXT production and fresh verifier replays pass on
their recorded candidate. Current hardware controls pass 57 tests, including all
nine mandatory Metal controls on the M1 Ultra. The four-validator finalized
transcript scenario passes after the exact authenticated query repair, preserving
contiguous genesis-rooted finality, source substitutions and restart checks.
This establishes transcript custody; complete q77/D7 source/spend admission,
concrete cryptographic qualification and other hardware remain open.
The complete-effect ordinary artifact, original-pool funding and move-only
finalized-source lane are now integrated for compiler/native validation. The
ordinary profile and canonical artifact layout changed; preceding transfer-only
maximum results do not qualify this candidate. Durable completion publication,
recovery and automatic dispatch remain unfinished.

Recorded script, Kotlin/Android, Swift, JavaScript and native fixture controls
provide component coverage. Fresh canonical generation, complete SDK consumers,
strict lint, workspace tests and four-validator recovery still require one
integrated candidate. Physical-device, cryptographic/side-channel and signed
release qualification remain open. The [ZK goals](specs/zk_first_release_goals.md)
retain the current acceptance boundaries.

The old KAGEMUSHA component controls (journal recovery, issuer keys, enrollment
floors, expired preparations, Guard generations and claim carriers) were deleted
with their code. Primary-owner Privacy library strict lint passes
with defaults, `privacy-release-evidence` and
`privacy-release-evidence,test-utils` in an unchanged source/Git interval.
The recorded debug-profile Privacy libtest build and all 22 selected controls
pass. Its registry contains 2,479 tests, including 61 ignored cases; independent
framing of all 29 native profile fields matches the recorded source pin. Genuine
IO, Projection and CA component proof checks pass once each sequentially at the
closed merged revision, with all 475 retained inputs unchanged through the runtime
endpoints. The CA check binds a synthetic paired MAIN record. The optimized
constructor, full ordinary suite, upstream strict lint and merged-source qualification
remain open. Maximum-proof external time/RSS evidence and enforced address-space
limits remain separate cryptographic release gates. The non-test real-proof frontend
remains under qualification. Later Privacy source additions have a separate
development libtest build and registry discovery (2,541 tests, 65 ignored,
433 dep-info inputs). The latest focused Privacy validation lists 2,628 tests,
including 2,560 ordinary cases and 68 ignores. All original 65 ignores remain;
three additional ignores are reviewed cost diagnostics. All five corrected
GETGAS/scalar-history regressions pass, with captured source, Git, toolchain,
managed inputs and artifacts unchanged through build and runtime. The earlier
ordinary suite closed naturally with 2,424 passes, 52 failures and 65 ignores,
with concurrent source changes. All 52 failed cases retain ordinary coverage
and require current-source validation. Full current ordinary and merged-source
qualification remain open. The derive library, strict JSON
and UI regressions pass, preserving diagnostics.
SDK custody and genuine proving qualification follow the canonical G1, Advance
and PIPA owners; their bridge, SDK and ledger integration remains open. FASTPQ
uses the existing STARK feature. The recorded signed optimization validation baseline is
`4486aa78661b8f289d21238e034fc2ece10600d8`. Recorded static source-graph
discovery lists 124 workspace members; current resolved Cargo metadata remains
unqualified. Source-cost and feature-hygiene checks passed on that recorded cut
with every cost limit exact.
Recorded dependency boundaries, legacy-codec and checker controls retain their
input cuts. Shipping Oracle denials and the aggregate-model test exception
remain intact. Core retains consensus ownership after the unused direct daemon
Sumeragi edge was removed.

ABI argument-record and static numeric encoding belong to `ivm_abi`; consumers
import the owner directly. Default-root record acquisition uses
`entrypoint_argument_record`; `trigger_event_json` retains the separate actual
firing JSON. IVM retains decoding, gas and memory custody.
Compiler/toolchain, all 14 ABI/IVM phases, direct SDK consumers and workspace
qualification remain open. Core ZK requires current strict default/no-default
libraries, test-feature library/group coverage and canonical proof-owner and
consumer checks. Its retired real-proof-harness feature is not a target.
FASTPQ's ordinary runtime and raw-field regression remain pending. Privacy's
previous failures remain ordinary tests and require current regressions followed
by the full ordinary suite with stock ignores retained.

The generic Norito array correction is applied and formatted, preserving explicit
raw-field layouts and charging actual owned allocations once. Complete
Primitives/P2P/Manifest and Norito/derive/Crypto suites passed on the recorded
cut with stable source.
The latter Cargo run succeeds; its original outer failure from a changed Git
baseline is preserved. Independent comparison now joins both native Source/Git
captures and the reviewed application to the genuine formatter baseline at that
recorded cut. Subsequent commits and selected-input changes require fresh
qualification. Broader native tool, artifact and consumer qualification remains
open. Earlier
Model and Python passes retain their
original inputs; full current requalification remains pending. Drifted script
runs remain diagnostic and interrupted unknown exits remain unresolved.
Journal's recorded selected checks require requalification after selected input
changes. Wallet rejects unknown native material before decoding, signing or
HTTP; its expanded registry preserves prior cases and custody/frame controls,
with Wallet and SDK native qualification pending. Compiler fixture/source-reader
and CI controls retain their recorded scopes; compiled bytecode and actual CI
execution remain unqualified. Executable metadata freshness passes on its
recorded cut. Current workspace, merged-candidate, release and O7 timing
qualification remain open. The
[optimization goals](specs/compile_bloat_optimization_goals.md) retain all seven
completion criteria and separate pinned-runner resource requirements.

Ordinary recursive credential generation is blocked by the Eq circuit requiring
8,584 advice columns against the 1,024-column limit. The complete-circuit
preflight and compact authenticated carrier layout still need fresh compiler,
layout, parity and proof qualification.


Dependency ownership and pinned compiler-memory measurements remain gates; see
the [architecture plan](specs/first_release_architecture_redesign.md) and
[compile-bloat goals](specs/compile_bloat_optimization_goals.md).

Memory qualification retains a 25% model-baseline reduction, measured limits for
introduced units and a 13-GiB per-unit release ceiling. Core/Torii test and daemon
baselines need complete successful builds; native release baselines exceeded the
ceiling in Core/model. Comparable candidate measurements need one pinned runner
and toolchain. The [profiler guide](docs/profile_build.md) defines the method.

Release requires one immutable candidate with complete workspace build/tests,
applicable strict Clippy, formatting, canonical codec/ABI fixtures, generated API
and artifact provenance, native/SDK matrices and authenticated release workflows.
CI routing has local source coverage; actual CI/corridor execution and final
aggregation need qualification. Missing artifacts, blocks and timeouts are not
passes.

## Remaining production risks

- **Consensus/staking:** complete [Sumeragi S1–S9](specs/sumeragi_goals.md), signed
  RS16 availability at whole-node/network scope, DS-local State/AMX, E+2/beacon
  custody and [paid 4→7→4 transitions](specs/staking_validator_completion.md)
  with restart, rewards, exits and slashing.
- **Privacy/crypto:** an earlier joint X509 maximum proof passes verification,
  size, RSS and enforced address-space checks but fails the 300-second limit.
  The corrected RFC profile and authentic component fixtures require a fresh
  complete proof. Complete relation, adaptive transcript/hiding and side-channel
  qualification remain open. Maximum q77 ordinary/AXT proofs, local
  M1 Ultra controls and four-validator transcript custody pass on their recorded
  candidates; complete source/spend admission and other hardware remain open.
  RAM-LFE secure encryption/full execution, IVM native
  execution/finalized-State binding and signed release evidence remain open under
  the [ZK goals](specs/zk_first_release_goals.md).

- **Parliament:** binding juries move to [anonymous on-chain ballots](specs/parliament_private_ballot_design.md):
  public votes and tally, voter-to-ballot linkage hidden by a PQ membership and
  nullifier proof, and no ballot custodian. No proof profile is selected,
  nothing is qualified and the ballot is not implemented in Core.
  Binding-governance mainnet launch is no-go. The
  [profile record](specs/parliament_ballot_proof_profile.md) states the
  construction under development: a proof of selection from the sealed
  credential list, whose bytes are published at seal, over SHAKE256
  credential functions (commitment, 128-byte nullifier, and registration and
  vote authorization values under one secret), in a VOLE-in-the-head backend
  derived from FAEST v3.0. The second-opinion review decided the ballot-mode
  backend: 112 fresh random bytes per proof with a public salt, a 20-bit
  counter range with a typed exhaustion outcome, and a wider leaf
  commitment; raw proofs are 160,148 B (registration) and 233,012 B (vote)
  on the candidate row, reproduced by the final independent vectors. The standalone
  experimental backend (`crates/iroha_zkp_vole`) reproduces the official
  FAEST v3.0.2 component vectors and all twelve official signatures in its
  reference mode. The ballot
  relations (`crates/iroha_parliament_ballot_proof`) implement the final
  registration and strengthened vote relations on the salted, affine-checked
  backend; both rows have independent Python vectors and portable/accelerated
  checks. [B6 evidence](docs/validation/parliament_ballot_b6.md)
  extends the standalone vectors with adversarial/parser campaigns, direct
  upstream CRT comparison, cold-input/late-invalid measurements, live-heap
  accounting and supplementary physical-device evidence. An executable
  security ledger, precise generator-interface analysis and primary-source
  review expose the remaining primitive and reduction gaps. A source-pinned
  standalone model bounds requested allocations under explicit layout/policy
  assumptions and inventories arithmetic/hash/loop work; both checkers fail
  qualification explicitly. The [resource proposal](specs/parliament_ballot_resource_contract.md)
  now implements whole-call/byte reservations and a bounded arena/native-stack
  worker; 120 source-bound calls pass. Request-stage primitive counts now
  reconcile with the conditional ledger; bounded-entry real-prover Keccak
  counts fit their component allowance. A bounded hybrid-driver proposal makes
  sampler, oracle-state and primitive-interface obligations explicit. A separate
  fixed-opening H5 derivation establishes a conditional initial transition at
  ideal-row entry, and both rows' zero fallback is verified. The conditional
  joint mask bijection preserves oracle/transcript state at an ideal-material
  public endpoint, with a separate [conditional adaptive deletion proof](specs/parliament_ballot_b6_hidden_assignment_deletion.md)
  reaching the unpatched ideal-material baseline. Primitive entry, a reverse
  material bridge and complete resource bounds remain open.
  The borrowed-input worker now publishes fatal debit through a counted shared
  page after reproducing a blocking stdout failure. Its new 122 observations
  and full/broken-output controls pass, with 41.109375 MiB reserved on this Mac;
  all-input completion and full native-memory coverage remain unqualified.
  Fresh stack captures decode both images after tested `STLUR`/`EON` support,
  retaining native, indirect, exceptional and recursive costs as unresolved.
  A [conditional adapter bound](docs/validation/parliament_ballot_adapter_bound/README.md)
  isolates the ordinary wrapper's stack, instructions and owned input block;
  native and complete verifier costs remain opaque.
  Subsequent lockfile/allocator edits make current-source reproduction refuse;
  the retained adapter evidence remains bound to its earlier source interval.
  A standalone finish-and-discard
  adapter passes both-mode lifecycle and selected-buffer cleanup tests; it
  does not establish prompt cancellation or comprehensive secret erasure.
  A [conditional arena proof](specs/parliament_ballot_arena_sufficiency.md)
  now covers retained classes with an all-length frontend spatial bound;
  native allocator parity and selected compiled layouts support its premises.
  Compiled stack evidence conditionally resolves seven backend provider/drop
  sites; remaining indirect/native/recursive paths and target-set premises keep
  the full bound unknown. Failure-entry separation narrows 31 indirect sites
  to explicit unknown-cost failure obligations; an activation check excludes
  four explicit System allocation arms only under unproved noninterference
  premises. Separate source-ownership and compiled free-routing checks retain
  all ten unconditional free frontiers. A separate normal-return analysis
  explains ordinary-flow gaps while retaining native and exceptional costs.
  A new borrowed-input entry moves file retrieval outside charged work; its
  caller lifetime and independent size admission are explicit. The older worker
  I/O frontier retains its original scope. An instrumented verifier
  matches 132 finite allocation streams and passes 14 controls; universal
  correspondence remains open. A separate native endpoint observer passes its
  controls and finite proof campaign with no named native calls in the charged
  intervals; it does not bound hidden paths or complete native memory.
  Complete compiler/runtime correspondence, stack sufficiency and physical cost
  calibration remain open.
  Complete envelope/work/allocation certificates and the named validator/phone
  baselines remain open; Intel measurements are deferred to the owner.
  Nothing is wired into Core. Selection is
  blocked: no section 5 gate is discharged. The review's arguments
  ([arguments record](specs/parliament_ballot_proof_arguments.md)) are
  written, conditional and awaiting independent review; they rest on two
  unproved credential assumptions (pseudorandomness with public leakage,
  and existential uniqueness of commitment and nullifier openings in
  selected contexts), frame-collision terms and the backend oracle model,
  none with a qualified bound, and no complete concrete-security ledger or
  attack-cost assessment exists. The review made two
  weakenings that await the owner's qualification record. Gate 1 is weakened
  from knowledge extraction to adaptive relation soundness, with
  authorization carried by gates 2, 3 and 8. The security contract is a
  complete proven bound
  below 1/2 at 2^64 quantum queries plus an independently assessed attack
  cost of at least 2^128 gates, which weakens the earlier 2^128-query floor
  and is not shown to be met. Until selection only standalone
  implementation, measurement and proof work proceeds; schemas, Core
  integration and timed-OVN retirement have not started. The epoch-seated
  fast pause
  panel is specified, not implemented. Availability isolation (ballot design
  section 9) is implemented in `iroha_core` and `irohad`: no Parliament state
  creates pulse demand, vetoes a pulse or block, or gates startup; a sortition
  request waits governance-locally for the first consensus-native pulse height
  at or above its minimum lead; the missing-pulse failure, its redraw and the
  unavailable-slot index are deleted; attempt creation needs an NPoS cadence.
  Core mutation `HC220` guards the split, and the four-validator isolation
  corridor passes. Real-peer qualification is incomplete: the
  `test-network-parliament-signers` beacon fixture fails to derive, so the
  mandatory-NPoS corridors and every corridor that installs a key session
  cannot run, and the committee-rotation corridor has not run. Open: the proof
  profile, schemas and ballot; retirement of timed-OVN, whose ballot now opens
  only when a native pulse sits at exactly its release height, so its four
  hidden-ballot corridors are ignored; and the governance-clock requirements of
  ballot design section 9 (bounded progress to the native slot, casting-clock
  due work, a finite qualified attempt latency for the SCCP hold rule), which
  are specified, not implemented. The draw seed stays attempt-independent by
  design. The
  state-table inventory generator fails at `45f112b1cc` on unrelated domains,
  so the Parliament rows of `specs/state_table_inventory.json` were aligned by
  hand.
- **Services:** Musubi publication/paid contracts, standalone elections,
  SoraNet/Linux helpers, SCCP live corridors and Inrou Linux/AArch64/KVM isolation
  remain unqualified.
- **Offline money/devices:** the [single KAGEMUSHA target](specs/kagemusha_single_design_proposal.md)
  uses a released wallet on a stock uncompromised OS, hardware-backed keys,
  a durable software provider and recursive proofs. Its Send is irreversible;
  recovery replays exact Payment bytes to the receiver, with no refund path.
  The old per-operation online-control implementation was deleted on
  2026-10-05. The accepted Q → A → Ω construction now has native proof,
  operation and shared-wallet components; original account admission and typed
  C/JNI/Swift/Kotlin integration are implemented. The structural Payment envelope
  is 9,979 bytes, pending acceptance under the complete authenticated producer
  catalog. Signed pre-key permits, native enrollment custody and the private verifier codec
  are implemented. The node journal now retains worker configuration and exact
  requests/results and freezes credential bodies before signing. Captured issuer,
  journal, private-worker protocol and universal-template Torii tests pass. The
  current Python enrollment package passes all 144 tests in a fresh Linux guest,
  with no skips and unchanged source/tool hashes. The new Rust descriptor-worker
  recovery test is implemented; its compiled Linux execution and deployment
  remain unqualified. Enrollment admits
  configured bank or asset/scheme-authorized
  operator providers. Every universal-dataspace token is eligible: no Parliament
  approval, named-token allowlist or legal asset-class gate. Exact asset authorization,
  reserve backing and applicable controls remain required.
  Asset-independent enrollment templates and finality-backed universal asset
  selection are implemented. Actual Core registration execution, native registration
  intake, CLI package publication and shared ledger recovery pass their component
  tests. CBSI/BPNG remain deployment authentication adapters. Bank-required policies
  retain bank KYC/freeze checks and never fall back after a bank failure. The rebuilt
  ABI27 host passes Swift, Kotlin/JNI and C# consumer suites. Captured source-drift
  records remain explicit; these results do not qualify the whole checkout or phones.
  Scoped proof-crate strict lint and workspace formatting pass; dependency-inclusive
  strict lint retains unrelated configuration failures.
  The signed compact catalogue measures 5,017,489 bytes including metadata;
  complete native catalogue and signed production-runtime import pass. Pixel 6
  strict source-graph inspection stores 7,224 KiB and passes all 32 Q programs
  and 52 routes in 701.473 seconds, peaking at 562.9 MiB RSS. The first independently
  generated built-in profile passes the same graph in 103.837 seconds, peaking
  at 691.4 MiB RSS, with 7,232 KiB carrier allocation and no expanded disk files.
  With bounded snapshots, batch reuse and pinned parameters, the c66 candidate
  completes the same graph in 57.735 seconds. The subsequent 5a62 candidate's
  generator-prefix memo and exact validated-metadata reuse reduce this to
  18.303 seconds. Packed selector validation and closing snapshot reuse in
  351234 reduce this to 14.201 seconds, peaking at 538.8 MiB RSS with 7,224 KiB
  carrier allocation and no expanded disk files. These are isolated
  loading diagnostics, not complete app startup or payment measurements. Public
  parameter assets add 9,699,600 bytes per native slice; catalogue size is not
  the total app download. Loading time and memory remain too high; further
  admission optimizations need fresh validation
  under the [compact artifact goals](specs/kagemusha_compact_artifact_goals.md).
  The engineering native Bootstrap/Activate, executed A funding and Load
  finality admission pass. The repaired fixture confirms the existing activation,
  passes Load recovery and forgery/duplicate controls, and completes Load and
  both recipient Bootstrap folds. Exact Send recovery now returns the completed
  Payment. The corrected continuation replays that exact completion under a
  signature outage with an unchanged sender snapshot. Recipient B Receive,
  retry, duplicate-credit checks and its full Receive fold pass. B→C Send/exact
  retry and C Receive/restart/exact retry/full fold pass, with 100 units conserved
  and zero burned. A's ArchiveReceive package and immediate exact retry pass,
  and the zero-fee proof-assembly repair now passes eight focused regressions
  plus the original failed Send checkpoint with unchanged capsule, Payment and
  money. The same retained Send sequence 2 completes all checkpoints and its
  final Omega fold. A's retained ArchiveReceive also completes all 22 checkpoints
  and final Omega, with exact replay after restart and unchanged monetary value.
  B's retained Send also completes all checkpoints and final Omega.
  After an external interruption at B's ArchiveStatus checkpoint 7, the exact
  retained-state continuation now completes ArchiveStatus/restart replay and
  the first C Unload/fold with a terminal native test pass. The next local Core
  test's earlier routing-expectation failure is preserved. Its test-only repair
  now passes exact model refusals and the real native bad-Sigma rejection,
  once-only C payout, certified replay and fresh-State conservation. Final online
  balances are A=900/B=0/C=100/reserve=0, supply=1,000. The same retained C owner
  passes native confirmation/reopen controls through height 9 with the exact
  height-6 result, unchanged money and zero new payment signatures. Core stage 13
  and native stage 14 both pass; no prior native monetary operation is repeated.
  This composes corrected Core 8d432c5 with the copied host-v5 e6/f798 native
  owner and software hardware/issuer/four-seat committee fixtures, not a live
  four-validator or physical-device payment. An explicit compiled-source
  registry is implemented with strict independent generation, exact graph and
  original matching, and build-input freshness checks. Production and engineering
  entries, complete host inspections and actual typed wrapper controls pass for
  the measured 351234 candidate, including 94 signature and 175 Receive batch
  controls, focused packed-selector/descriptor/key tests with real proof-byte
  parity and 20 encoded/snapshot adversarial tests.
  Both strict v8 profiles reproduce all 908 preceding members except source
  identity. Host-consumers-v6 passes the complete production/engineering graphs,
  typed wrapper and all 94 signature/175 Receive controls under Apple 8bf/7ddd.
  Android 38's Play-signed universal APK is 202,453,497 bytes, published with exact
  hashes and installed in place on the Pixel with the e6/v2 three-ABI native
  libraries. Apple 8bf/v3 provides both iOS 18 slices and the ancestor-search
  repair. The 2026-10-13 03:30 UTC handoff records iPhone build 20261013030704
  installed in place; its App Store/device IPAs are 59,463,699/45,220,858 bytes.
  At 03:54 UTC its native installation passed, but E1 enrollment refused the
  sandbox-denied boot UUID; a diagnostic confirmed the sleep-inclusive Mach
  clock remains available. E1 now uses private process-bound native elapsed
  readings, preserves checked exclusive deadlines and rechecks after phase
  adoption before hardware generation. Restart requires a fresh nonce-bound
  permit. Persisted time-anchor and monetary custody rules are unchanged. The
  boot-denied regression failed before repair; final focused tests and matching
  rebuilt-consumer results are retained under
  `output/iphone-offline-setup-20261013/`, not inferred from source review.
  By 03:48 UTC Android registration's three ledger steps, activation and session
  passed; the Pixel displayed KYC step 4/5, NotSubmitted. These dated observations
  do not prove offline wallet setup. The delivery contract packages all 1,029
  originals and metadata in the apps and retains strict native admission from
  local custody. Later complete-bundle, package and physical acceptance results
  are recorded by immutable `final-delivery-evidence-index-*.json` files under
  `../bpng/png2-deploy/output/compact-wallet-20261012/`, with exact app/native/
  carrier identities and operation scope.
  The 14.201-second measurement remains the separate source351234 diagnostic.
  Canonical registry maintenance strictly regenerates matching DATA from the
  finalized source census; exact source/DATA pairs remain in output records.
  Test/documentation changes do not relabel or require rebuilding these shipped
  artifacts. The compact download/storage result and local settlement/native
  confirmation do not close further opening measurements, four-validator
  monetary acceptance, the two-second durable-completion target, the full native
  release matrix or physical-device recovery.
  The [checklist](specs/kagemusha_evidence_gate.md) records verification without
  an approval gate; software markers claim no protection against OS takeover.

First-release contracts remain canonical APIs, domainless `AccountId`, Norito
wire formats and deterministic ABI V1. Sumeragi uses exact `3f + 1` global
committees, exactly `n - f` votes, signed RS16 availability and work-driven blocks.
Ordinary signing supports authenticated software custody. The first production
KAGEMUSHA target requires platform enrollment, genuine monetary proofs and
durable local state/replay authority under its stock-OS assumption; it has no
custom applet or one-use-key prerequisite.
