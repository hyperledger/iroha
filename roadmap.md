# Roadmap

Outstanding outcomes for Iroha 3's first release. [Status](status.md) records
current health and blockers. Owners below are code responsibilities; completion
requires the stated behavior on the same candidate. Detailed acceptance lives in
the linked specifications. Routine repair receipts belong in PRs and CI.

## Current priorities

1. Complete remaining Nexus fault/restart qualification and restricted lane isolation
   after the paid settlement, serial restart and disjoint-lane recovery controls;
   preserve original funded execution through publication and replay, qualify lane
   retirement ownership, and reclaim physical storage only after retained global
   history releases its certified dependencies.
2. Complete original funded execution through State/World acquisition,
   certification, Kura publication and restart; finish DS-local State and AMX.
3. Qualify Sumeragi and authenticated Linux artifacts; Taira's deployment
   owner manages cutover, live four-validator readiness, paid writes and restart
   evidence, including DPN/contracts. This coding task owns H1–H5 in the
   [Sumeragi handoff goals](specs/sumeragi_goals.md#active-handoff-completion-gates)
   and works only in `/Users/takemiyamakoto/dev/iroha` on `optimizations`.
4. Validate the combined fixture/runtime repairs through fresh workspace,
   genuine fixture and native SDK artifacts on one source candidate. Qualify the
   joint X509 relation and transcript privacy, and resolve its proving-time and
   hardware-specific address-space failures;
   produce current q77 maximum proofs without widening resource limits.

The [first-release goals](specs/first_release_completion_goals.md),
[IVM goals](specs/kotodama_ivm_completion.md) and [ZK goals](specs/zk_first_release_goals.md)
coordinate this work. Remove retired interfaces directly; production behavior
remains deterministic and configuration-owned, with mandatory protocol semantics.

## Architecture and build

The [architecture plan](specs/first_release_architecture_redesign.md),
[repository map](docs/repository_map.md), [SDK inventory](docs/sdk_inventory.md)
and [schema contract](specs/norito_schema_identity.md) define the boundaries.

| ID | Outcome | Owner | Completion criteria |
| --- | --- | --- | --- |
| A1 | Physical model boundaries | Model/Norito/schema | Extract remaining foundational/privacy/service owners with acyclic dependencies; qualify mandatory JSON, declared identities, exact frames and default-stack State coverage. |
| A2 | SDK/service separation | SDK/storage/Musubi | Remove service-runtime edges and standalone CLI duplication; one journal/clock/publication owner and typed storage adapter with shipping dependency gates and CLI packaging. |
| A3 | Async client closure | Rust SDK/callers | Complete capabilities, structured errors, streams and consumer migration; four-validator isolated contexts, cancellation, bounds and acceptance/finality qualification. |
| A4 | Core/Torii cohesion | State/storage/routes | Separate restore, merge, execution and caches while preserving atomic overlay/rollback; capability-owned routes without facade-only layers. |
| A5 | Compiler/resource budgets | Build/component owners | Complete [compile-bloat goals](specs/compile_bloat_optimization_goals.md); requalify test/daemon baselines and introduced units. Meet per-unit limits, 25% model reduction and 13-GiB release ceiling on pinned supported Mac/Linux hosts. |
| A6 | CI/generated ownership | CI/generators/SDKs | Execute affected/full selection, distinct message-control builds and network corridors with correct aggregation; one drift-checked Norito fixture producer and complete generated inventory. |
| A7 | One Kotlin/JVM SDK | Kotlin/Android/Java consumers | Migrate capability/fixture/native/publication gaps before deleting duplicates; preserve assertions, JDK 8 guard, Java-callable APIs, no reflection and Android isolation. |
| A8 | Current documentation | Component/docs owners | Concise status/outcomes, accurate source-coupled specs and working links; public guides in optional `iroha-docs`, with no mandatory development diary. |

## Ledger, consensus and configuration

Authoritative contracts: [Sumeragi](specs/sumeragi.md),
[S1–S9](specs/sumeragi_goals.md), [lanes](specs/sumeragi_lanes.md) and
[evidence API](specs/sumeragi_evidence_api.md).

| ID | Outcome | Owner | Completion criteria |
| --- | --- | --- | --- |
| N0 | Complete Sumeragi | Core/P2P/Kura | S1–S9: execute-before-vote, round overlay, signed RS16 acquisition, DS-local finality, AMX and evidence/committee scheduling; the KAGEMUSHA mint-finality authority is deleted. The generic consensus attestation extension is deleted. Qualify retained validator-generation identities, BLS committee proofs, exact quorums, committee-boundary progress, CommitQC safety, rejection of retired wire fields and original execution custody with named mutation tests and real networks. |
| N1 | Driver/storage closure | Driver/State/Kura/daemon | Sole driver passes conformance oracles, certified execution and retained custody; per-key safety records and remaining retired storage/SDK owner removal. |
| N2 | Consensus qualification | Simulator/CI/operators | Nightly fault scenarios at 10,000 seeds and every mutation killed; native authority and fresh Taira four-validator readiness/write/restart. Governance owns deployment policy. |
| N3 | Dataspace topology/SNS | Nexus/Core/deployment | Manifest-owned membership/privacy/DA/governance; additive activation preserves certified history and cold replay; prove physical server/storage isolation. |
| N4 | Bounded execution/query | State/triggers/query | Consensus-owned budgets, reverse permission index and one registry; deterministic benchmarks, rollback/restart and no production invariant-bypass mutators. |
| N5 | Accounts/fees/transactions | Model/executors/SDKs | Remove inert/redundant carriers; one executable/signing registry. Qualify Hijiri fees, 120,960-block delay, exact quotes and native transactions under stale/private/loss cases. |
| N6 | Authenticated recovery | Kura/startup | Emergency Fast read-only; Strict restores writes. Bound authentication without premature body/snapshot/World decode; positive-height replay and canonical export. |
| N7 | Identity/obligations | Nexus/Torii/Connect | Exact chain/genesis/network binding, snapshot pagination, authenticated renewals/tombstones, audited irreversible AXT retirement and per-issuer quotas. |
| N8 | Configuration closure | Config/runtime | Complete [C5/P2/P8 controls](specs/configuration_simplification.md), generators, aggregated errors and four-daemon paid DPN; qualify the BPNG local preset through contracts, fee authority and application provisioning; one default source without aliases, silent clamps or production environment controls. |
| N9 | Observable durable runtime | Telemetry/logger/Torii | Metric reachability, exporter isolation and immutable classified status; exact retries under crash/disk-full/half-close/permission and cancellation/timeout races. |
| N10 | Current fixtures | Governance/integration | Full feature matrix for catalog/genesis/history, compiler/Kura and callback repairs, preserving real finality and adversarial assertions. |
| N11 | Private settlement | Core/Nexus/native proofs | [Canonical settlement](specs/private_settlement.md), exact authority/publication/recovery and bounded proofs; ten fresh N=3 successes, five-second end-to-end target, N=2/3/4/8/16 faults and aligned leakage/resource campaigns; formal/independent release review. |
| N12 | Production lanes/AMX | Lanes/Queue/Kura/SDKs | Per-instance authority/records and O9 isolation, elastic scale/restart, SDK/OpenAPI and real-peer load; DS-local State and S6 prepare/escrow/decision/settle. |

Original-pool funding must cover retained inputs, projections, proof graphs and
scratch. State/World/membership/journal authority must survive partial publication,
recovery and reclamation. Qualify silent authors, saturation, authenticated
loss/replay, all-seat restart and final-transaction progress on one four/seven-peer
candidate. Geometry changes cannot silently remove or replace live lanes.

[Staking](specs/staking_validator_completion.md) requires real-XOR eligibility and
consent, immutable validator authority generations, E+2 elections, a full E+1 preparation
interval, per-seat beacon custody and atomic activation. Close paid 4→7→4,
rewards/exits/slashing/withdrawals and distinct-fee-asset bounds, then DA/liveness,
formal, SDK and workspace gates.

## SDK, native and physical delivery

See the [JVM inventory](specs/jvm_consolidation_inventory.md),
[native release contract](docs/norito_bridge_release.md),
[KAGEMUSHA design and goals](specs/kagemusha_single_design_proposal.md#10-goals-and-execution-order)
and [verification checklist](specs/kagemusha_evidence_gate.md).

| ID | Outcome | Owner | Completion criteria |
| --- | --- | --- | --- |
| S1 | Python delivery | Python/native SDK | One typed credential/session, cohesive routes and bounded import/response/codec; native vectors, wheel/install/typing and four-validator corridor. |
| S2 | JS codec/package | JS/native host | Exact options/exports/context, one `dist/` authority, exact module graphs, browser isolation and runtime-memory bounds; installed source custody, native/portable lanes and four-validator parity. |
| S3 | C# API/package | C#/native bridge | Canonical prepared operations, faucet metadata, immutable parsing, documented API/allocation checks and real Windows/native packaging. |
| S4 | Shared wire/activity | SDKs/Torii | Canonical signing/executable/account fixtures, multisig witnesses and snapshot-bound activity with bounded cursors and expiry. |
| S5 | Kotlin closure | Kotlin/Android | Finish Java/JNI/publication retirement; release transport/attestation/Nearby and CUDA hardware qualification with separate host/device evidence. |
| S6 | Native release matrix | Bridge/platform owners | Signed same-source current-bridge AAR/XCFramework/JNI/wheel/host packages; all SDK checkpoint/wire/alias/SNS and OS/architecture matrices; retired layouts fail closed. Swift framework construction, installation and native suite qualification follow the [completion goals](specs/sdk/swift/native_framework_completion_goals.md). |
| S7 | Recursive KAGEMUSHA | Core/coordinator/proofs | G3/G4 (G1 objects and vectors exist in `kagemusha_wallet_v1`, the native σ step relations in `iroha_kagemusha_proof`; G6 deleted the superseded refund paths and duplicate monetary engines): implement and qualify the accepted Q → A → Ω construction within the 10,000-byte bounds, re-keying and qualifying every staged producer under the fixed-stage immutable context and acyclic carried-scheme authorization, completing [native BLS finality goals NF1–NF6](specs/kagemusha_native_finality_goals.md), qualifying the approved direct signed-genesis/epoch receipt admission before Advance, four A_Load/three W stages and compact Load/Send/Receive/Archive catalogs under rebuilt keys and signed inventories, without transferring retired recursive-finality evidence; bind the tested native/circuit proof components into every operation relation and wrap consuming the G1 objects; qualify the concrete native startup/account-admission owner and typed SDK lifecycle against the complete installed graph; complete proof/receipt lineage, irreversible Send, exact Payment replay, permanent receive deduplication and offline onward spending through real A→B→C→unload. |
| S8 | Durable money | Native/platform/reserves | G2/G5: complete native background fold execution with cooperative payment preemption, canonical delivery receipts and durable CloseLoads signing; qualify the Rust stock-OS journal/marker `Advance` provider, retained collection, owner-bound custody deletion and typed Kotlin/Swift bridge against rebuilt artifacts and devices; qualify the node-owned E1/worker/signing journal and connect authenticated private platform verification, current account eligibility and the scheme-rooted Enrollment signer with exact E5/E6 recovery and Torii routes; qualify any universal-dataspace token through authenticated release/enrollment templates and finalized exact Global registration, without Parliament approval or a token allowlist; reserve-backed loads, one-use redemption/fee claims, optional controls default off. |
| S9 | Mobile/Nearby/NFC | SDKs/device providers | G4/G7: shared Rust core with Swift/Kotlin adapters and one envelope over NFC/radio/QR/Petal; record device recovery, replay/restore, memory/thermal, size and latency results while integrating and using the POC. |
| S10 | Private-file/ZK-ACE SDK | JS/privacy/native | Governed two-pass intent signing, nonserializable private witnesses/erasure; Windows secure storage and authenticated native packages. |
| S11 | Petal Stream devices | Petal/SDKs/device providers | [Device protocol](specs/petal_stream.md#8-qualification): 20 timed runs per device and distance on governed profiles including a low-end 480p–720p Android phone, a modern iPhone and a webcam; `ScanStats` lane rates filed per device with exposure compensation at 0, −1 and −2 EV, and the Swift/Kotlin/JS/Python/C# readers re-run against the same recorded camera captures. Field results tune the inferred-corner search and the 500 ms tracking window, and measure tracking on hand-held phones. |
| S12 | Collection query qualification | Torii/SDKs/CLI/MCP | Move remaining trigger list routes onto the collection contract. Qualify the [shared query contract](specs/torii/collection_queries.md) on current-source live peers: multi-dataspace visibility and exact totals/aggregates, deep history after restart, changing authorization between pages, bounded sparse scans and every SDK's installed/native suite. The [implementation completion goals](specs/torii/query_completion_goals.md) define the component contract; they do not establish release readiness. |

## Cryptography and VM

Contracts: [Norito](norito.md), [schema](specs/norito_schema_identity.md),
[IVM completion](specs/kotodama_ivm_completion.md),
[Kotodama syntax and developer experience](specs/kotodama_devex_goals.md),
[FASTPQ](specs/fastpq_plan.md)
and [privacy closure](specs/privacy_first_release_closure.md).

The [ZK delivery plan](specs/zk_delivery_plan.md) and its
[task graph](specs/zk_delivery_graph.json) own the ZK, privacy,
authenticated-State and FHE outcomes: the rows here state the release outcome,
and the graph holds the tasks, their status and their evidence. Three criteria
come from the [resource contract](specs/zk_resource_contract.json). For C5, the
maximum-proof transport (plan task X.2) closes the contract relations it owns,
including `private_settlement_carrier_within_includable_transaction`. For N5,
the signed attachment list frame, 8 MiB today, admits a ceiling-sized proof
(I.1). For N4 and N8, the 74 node-local validity bounds of the three
node-configuration policy catalogs, including the eight bound into a digest but
compared by no state transition, become committed State (F.4).

| ID | Outcome | Owner | Completion criteria |
| --- | --- | --- | --- |
| C1 | Norito/derive closure | Norito/derives/primitives/MV | Explicit archive context, fallible aligned/scalar/tree allocations and owned values; retire unused adapters, share emitters, meet compile budgets/UI tests. |
| C2 | Deterministic VM/compiler | IVM/Kotodama/hosts | G1–G8, ABI V1, fallible lifecycle/erasure and detached proof custody; qualify integrated trigger-action relations, complete Musubi and membership/frontier capture and State/Kura publication, then native execution/private invocation/AXT; identical gas/traps/state/proofs, complete cache/index/control and host/native scratch allocation custody, retained observation recovery and authenticated calibration. |
| C3 | Signature audit | Crypto/consumers | ML-DSA/SM2/GOST/FHE feature/lint/custody, mixed-torsion Ed25519, PoP and threshold-BLS beacon/side-channel review; Musubi State-reader prerequisites. |
| C4 | FASTPQ/backend | Prover/verifier/reviewers | Masked 301-column/77-query SHA3/SHAKE DEEP ordinary/AXT relations and bounded work/RSS; preserve current maximum ordinary/AXT component proof passes while completing finalized-source admission, AIR/FRI/hash/qROM/privacy review, hardware/four-peer parity, embedded authenticated Metal and driver-loaded CUDA host. |
| C5 | Privacy authority/degree | ZK-ACE/STARK/AXT/IVM | Finalized source State and signed amount/intent, six-lane/qROM/AIR/FRI and exact SDK parity; explicit terminal degree/geometry; qualify the joint X509 relation and transcript privacy, and complete its maximum proof within unchanged byte/RSS, literal address-space and 300-second limits; unsupported paths stay disabled. |
| C6 | FHE/MKHE/Figure 9 | Crypto/model/proofs | Complete native40 correspondence/full-size eight-party replay; qPCS redesign within fixed work bounds, governed Figure 9 keys and independent measured ordinary-stack proofs. |
| C7 | Acceleration | Native backends | Automatic target-appropriate daemon defaults, ten reproducible signed embedded CUDA PTX families, driverless daemon startup, actual CPU/Metal/CUDA KAT/root parity, authenticated library/device/calibration, fault quarantine, side-channel and RSS/throughput; unqualified T256/MKHE stay scalar. |
| C8 | Kaigi sessions | Model/crypto/Core/SDKs | Complete authorization/usage circuits and account lifecycle/undo; keys/fixtures, suite-tagged HPKE, bounded accounting and authenticated relay recovery. |
| C9 | Native PLONK/IPA prover | ZK/prover owners | Qualify the implemented source-bound VK-to-PK reconstruction and wallet admission records across real operation stages, releasing proving buffers between stages; captured engine/proof-consumer correctness, strict library lint, ordinary shared-wallet controls and historical Result1 proof parity pass. Requalify the current native-finality graph and whole wallet; the interrupted native9 recursive-history attempt has no terminal success. Qualify the implemented bounded public-table lookup commitments, retaining full-width random padding and exact proof bytes; ordinary library and compiled ARM/x86 correctness checks pass. The completed FFT-candidate M3 audit has seven passes and one borderline real-Q one-worker margin; preserve all15 invalid attempts and requalify the merged source closure under both worker counts. The first bounded-lookup campaign stopped on dependency drift; the second has seven passing configurations and incomplete real-Q one-worker coverage after a final Cargo-metadata change, with a missed time margin in block2. Preserve all invalid attempts. The applied eight-gate quotient grouping passes the serial oracle, native/x86 checks and proof-byte goldens. Complete all three M3 blocks with source and Cargo inventory held stable; the first real-Q diagnostic meets hard limits but misses the 27 s margin. Qualify owned-witness M3 with the process-wide 64 MiB MSM budget and fixed shared-host method; finish PIPA-R/PIPA-AS, KAGEMUSHA operation/lineage/transport/CreditStatus relations and soundness tests. Qualify current native artifacts for the migrated and re-keyed [inventoried consumers](specs/native_prover_migration_inventory.md); superseded vendor trees and the temporary oracle are deleted and focused retirement guards pass. Qualify rebuilt consumers and the final authenticated catalog, retaining independent vectors and mutation coverage. First release: no compatibility decoder, old-key fallback or parallel legacy production engine. |

## Services and deployment

| ID | Outcome | Owner | Completion criteria |
| --- | --- | --- | --- |
| P1 | Parliament | Governance/crypto/Torii | [Anonymous on-chain ballots](specs/parliament_private_ballot_design.md): seat-acceptance credentials frozen into a committee root; signerless, proof-authorized public ballots with nullifiers and a qualified PQ membership proof verified in ordinary execution; public tally and independently verifiable outcome evidence, no ballot custodian; actual small electorates, independent epoch-seated pause panel and Parliament availability isolation; retire timed-OVN/Parliament TLE as the canonical V1 replacement; atomic policy/confirmation, bounded sortition and governance-attempt retries with no ballot retry, and four-peer replay/rollback; independent proof review/signed API before binding-governance mainnet launch. |
| P13 | Standalone elections | Governance/circuits/SDKs | [Full statement](specs/zk_audit_matrix.md#election-statement-completion): credentials/nullifiers, weight/re-vote, encryption/custody and sound ballot/tally; V1 keys/fixtures and restore/finality. |
| P2 | SoraFS promotion | SoraFS/operators | [Reliability](specs/sorafs/first_release_reliability_goals.md), [V1 goals](specs/sorafs/v1_implementation_goals.md) and [closure](specs/sorafs/v1_closure_ledger.md); software signer, live multi-provider/dual-gateway L1, 17 summaries and authenticated L2. Load/resilience observations are optional diagnostics without a fixed deployment duration. |
| P3 | Governance DAG | DAG/broker | [Two services](specs/sorafs_governance_dag_plan.md), authenticated ingress/signing/CAS, failover/recovery/corruption and five-target SBOM/L1/L2 artifacts. |
| P4 | QUIC/relay/VPN | P2P/SoraNet/Linux | [Handshake](specs/soranet_handshake.md), bounded DATAGRAM/pre-auth/NAT and paid leases; real TUN/pidfd/DNS rollback, hostile peers/rotation/loss, fuzz/review. |
| P5 | Musubi/contracts | Service/Core/Torii/deploy | [Publication](specs/musubi.md): lock/retention, atomic no-follow cache/recovery, memory/soak/four-peer. [Paid Taira workflow](specs/musubi_taira_workflow_goals.md): wallet/funding, immutable code, alias, Applied/readback, quote/video. |
| P6 | DA/Taikai | Spool/publishers/CLI | [Transactional ingest](specs/taikai_ingest_plan.md), intent-before-effects, recovery/quarantine, immutable retry, shared builders, file-backed CAR/atomic summary and path-race/consumer closure. |
| P7 | SCCP | Core/attestor/contracts/CLI | [Corridors](specs/sccp.md): governance timing/re-anchoring, pending work without empty blocks, aged proofs and TRON energy; audited real-deployment proofs/value canaries per chain. |
| P8 | Inrou | Guest/runtime/deploy | Real Linux/AArch64/KVM escape/resource tests, authenticated bridge and four-replica canary; generated HF storage-only, governed guest compute. |
| P9 | Taira/DPN/BPNG | CLI/daemon/operators | Signed observer join, disposable four-peer convergence/guest tests; current reset/readiness/write/restart, beacon custody and paid physical DPN. BPNG retained-history/catch-up, anchored quorum reads, additive catalog and API22/FE17 commissioning. |
| P10 | Native Torii MCP | Routes/SDK/CLI | One protocol/listener, exact authority/mutation/retry registry, bounded prepare/external signing and scratch simulation; four-peer auth/cache/cancellation. |
| P11 | Governed compute/developer tools | Mochi/Kagami/deploy/Core | [One-command developer experience](specs/kagami_mochi_devex_goals.md): persistent config-free localnet, owner-private Taira attachment and contract deployment; shared services, native Windows/macOS/Linux bundles, exact recovery and measured startup. Qualify implemented interrupted-bootstrap authorization recovery and wallet cancellation; qualify automatic custody renewal with owned restart and the distinct-key ingest/activation graph, qualify the implemented native paid pin coordinator, qualify the implemented stock publication-service selection, generated runtime configuration and explicit generated publication API, qualify the implemented Kagami and Mochi publication handoff, qualify the publisher's full signed provider-inventory retention and original TLS selection, then qualify three-provider cold registry publication and dependency resolution with governed admission, normal TLS/DNS, revocation and the complete 64 MiB fetch-process RSS bound; retain signed native releases and reference-host p95 as separate gates. [Mochi](specs/mochi_architecture_plan.md): governed catalog/auth/replay, real IVM metering and Kiso pricing. |
| P12 | Economic Constitution | Economics/oracle/governance | Basket/oracle/intervention/reserve specification, bounded Phoenix/Producer Credit policies and reproducible default/capture/cartel simulations before stability claims. |

Taira qualification preserves signed genesis, native control keys, source/artifact
identity, aggregate deadlines, funding and ambiguous-submit recovery. Require
all-four StateApplied and anchored inclusion; retained-ledger recovery is separate
from fresh genesis. Follow the [reset runbook](specs/runbooks/sumeragi_taira_reset.md)
and [current incident](docs/incidents/2026-09-30-taira-readiness.md), without expired
leases or compatibility decoders. Reuse warm builds/Apple ld locally; qualify
immutable Linux preparation/runtime separately. BPNG infrastructure uses only the
explicitly approved OVH target.

## Candidate sealing and release

| ID | Outcome | Owner | Completion criteria |
| --- | --- | --- | --- |
| R1 | Clean audited candidate | Release/all owners | [Audit closure](docs/audit_closeout_matrix.md), Core/model identity and SoraCloud replay; locked workspace tests/build, strict applicable lint/features, format, wire/ABI and SDK/native matrices; [authenticated reproducible release](specs/release_runbook.md). |
| R2 | Generated API/approvals | Generators/operators | Clean double generation, synchronized manifests/inventory, signed OpenAPI and exact candidate-bound approvals; docs grant no live mutation authority. |
| R3 | Community ownership | Maintainers/public docs | Clear onboarding, repeat subsystem reviewers and official demos/Q&A/recaps; accurate implementation updates and independent release evidence. |

Ordinary signing permits authenticated software custody with runtime-only secrets,
rotation/revocation and recovery. The first production KAGEMUSHA app profile
uses platform enrollment, hardware-backed keys, genuine monetary proofs and
durable software state/replay authority on a stock uncompromised OS. KAGEMUSHA
verification records do not gate integration or use. Ordinary keys confer no
hardware journal or clock guarantee. IVM is the sole VM; Wasm/WASI is prohibited. Sumeragi requires exact
`3f + 1` global committees, exactly `n - f` votes and signed RS16 availability.
Idle chains create no blocks.
