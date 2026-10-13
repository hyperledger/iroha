# ZK delivery plan revision 8

**Status: ready for development.** Finalized 2026-10-04. The graph records each
task as `planned`, `in_progress` or `implemented`, and a non-planned status carries
its evidence. Neither finalizing this document nor recording a status establishes
cryptographic qualification, performance or live deployment.

This is the normative development plan for the ZK, privacy, authenticated-State and
FHE work described by the actual revision 6. It supersedes the incomplete revision 7
reconstruction and the earlier delivery graph. The four binding directions are:
use each implemented capability immediately on testnet without activation gates;
replace first-release designs directly; complete RAM-LFE with all three program
classes and proven opening/threshold behavior; and ship native ISIs with one-call
SDK operations for every supported algorithm.

The [task graph](zk_delivery_graph.json) contains 91 implementation/evidence
tasks and 32 named deliveries. The
[source reconciliation](zk_delivery_reconciliation.json) preserves 119 verbatim
revision-6 requirement units, all 23 revision-6 findings, all 133 earlier report IDs
and all 52 original graph tasks, with exact mappings and dispositions. Original
files under ignored `dist/reports/` are optional provenance; their relevant content
is embedded in the tracked ledger. No build or check depends on their presence.
A mapping establishes traceability, not proof that implementation satisfies it.

Planning checkout: `1c4f9014bc6f753ac5df08fdad1d71aedf9b8604`.
The original source observations were made at
`f94d3d9724f97ff3d579e2ca66ae3239f15b2850`; re-read the affected current code before
each implementation change. Existing [ZK goals](zk_first_release_goals.md),
[privacy closure](privacy_first_release_closure.md) and
[IVM goals](kotodama_ivm_completion.md) supply current facts. Their obsolete
activation prescriptions are replaced by this plan, while their unresolved
technical failures remain open.

## First-release rules and development order

There is no backwards-compatibility requirement. Replace schemas, semantic
relations, transcripts, policies, instructions and ABI V1 artifacts coherently;
regenerate all callers, fixtures and manifests. Do not introduce aliases,
fallback decoders, migration shims, old-verifier branches or a second authoritative
implementation for a replaced role. IVM is the sole VM; Wasm/WASI is prohibited.
Use Norito throughout. Kotlin owns the Java-consumer implementation.

Current canonical genesis/schema history must replay correctly. An intentionally
incompatible change defines a fresh-genesis testnet cutover or contract redeployment
as appropriate; it does not promise that the new binary reads obsolete history.
Authenticated snapshot restoration is separate implementation work, not an assumed
capability or a prerequisite for RAM-LFE. This planning request does not deploy,
reset a network or move live value.

Each functional delivery includes its own typed ISI, Kotodama binding, high-level
SDK method, advanced prepared form, canonical fixtures, actual proof/effect,
four-validator flow, cold restart and full current-genesis replay. It ships across
**Rust, Kotlin/Java/Android, Swift, JavaScript, Python and C#** in their supported
native environments. S.3–S.6 reconcile shared ports and aggregate evidence; they
cannot postpone a completed capability's SDK surface.

Start in parallel at **F.1, F.2, F.3, F.4, C.1, R.1, X.1, H.1, V.1, B.1, G.1, M.1, R.0, T.1, E.1**.
These are the graph's actual roots. Prioritize the shared arithmetic and affine
RAM-LFE path while the shared proof backend, WG prototypes, IVM coverage and X509
temporal/holder work proceed. Named staffing and external review are not prerequisites.
An edge means a concrete output is needed to complete the dependent task; preliminary
design can proceed against a defined interface sooner.

## Runtime validity without activation gates

Remove activation transactions/bits, lifecycle availability switches, qualification
signers/receipts, global all-protocol manifests, zero availability pins, audit approval
and production-versus-integration chain-ID conditions across Core, Torii, SDKs,
genesis and restore as each affected path is implemented. Ordinary deployment makes
a completed capability usable. Independent reviews produce findings and repairs,
never permission tokens. Normal signed deployment and operator authority remain;
this plan adds no mandatory audit, regression-suite or soak prerequisite to deployment.
A chain that cannot commit uses ordinary operator repair/redeploy or an explicitly
authorized reset, not an impossible on-chain approval.

Always enforce genuine proof semantics, signatures, permissions, current keys and
revocation, finality, nonce/replay rules, conservation and deterministic resource
limits. An unfinished operation has an accurate unsupported error and remains
mandatory unfinished work. Deleting a rejection cannot turn an insecure construction
or missing relation into success.

Validity-affecting policy, key/relation identities, windows, expiry/skew rules and
proof budgets come from committed protocol State. Source/executable/catalog hashes
are evidence metadata, not transaction truth. Node-local memory, serving retention,
cache state, environment variables, feature selection and wall-clock timeouts cannot
change the accepted effect, gas or certified root. Missing local resources defer
without rejection or voting; malformed carried transaction evidence rejects
deterministically. Accelerators preserve scalar semantics and deterministic fallback.

## One-call API and IVM composition

A configured client supplies network/account/signing and private-material custody.
One asynchronous operation owns authoritative context lookup, resource planning,
witness acquisition, encryption/proving, local verification, instruction construction,
signing, submission and final-result recovery. Callers provide business inputs,
not ring sizes, VK blobs, dummy witnesses or transcript internals. Missing authority,
issuer material or participant shares produces a typed failure or recoverable pending
operation; no secret or authority is fabricated.

Ordinary operation batches are one signed atomic transaction, without silent splitting.
Advanced prepare/build returns the same canonical ISI for external signing, batching
and contract composition. Genuine multi-round issuer, DKG and cross-lane processes
retain their real stages: the high-level call can await or return a durable handle
with progress/cancel/read-only recovery and explicit partial completion. A submission
timeout is an unknown outcome until readback resolves the original transaction.

Choose one typed operation-tag bridge under ABI V1, with typed Kotodama builtins.
The host invokes the same canonical executor and preserves the exact contract
subject, authorized call lineage, policy and replay domain. Administrative
instructions remain callable subject to their actual permissions.

Large proof/key payloads use typed **inline signed-transaction attachment occurrences**.
The host retains authenticated immutable bytes; the guest receives small
transaction/invocation-scoped handles. No multi-megabyte proof must fit inside the
existing guest heap/input window, and validators do not fetch proof bytes from an
external service. Intent binds an ordered proof-free descriptor to avoid circular
proof hashes; the transaction signature covers the complete proof-bearing bytes.
Wrong-role, substituted, cross-invocation, missing, duplicated or unused declarations
abort the transaction. All retained bytes and scratch count toward deterministic limits.

Keep ordered deferred effects. A contract call returns a `PendingAction` token;
the executor verifies and applies its queued instructions in the same atomic
transaction after VM execution. Actual results are correlated in the finalized
receipt. Contracts cannot branch within that invocation on an unapplied result.
A separate typed verify-only primitive establishes its exact statement and confers
no reusable authorization. A later failed action rolls back the transaction.

Regenerate the ABI descriptor/hash, manifests, typed bindings, syscall/pointer
metadata, relevant goldens and documentation. Remain ABI V1. Include every added
syscall in complete IVM proof coverage; there is no default exclusion list.

## Shared proof backend and complete IVM proof

B.1–B.3 build one reusable FASTPQ field/AIR/composition/DEEP/masking/commitment/FRI/
transcript/grinding/allocation/acceleration owner. Preserve the explicit r6 caller
inventory: ordinary effects and AXT, RaceV1/classed RaceV1, all IVM chips, generic
semantic verification, SoraCloud key/BFV checks, X509 MAIN/CA, private notes,
PQ-MASP, settlement, ZK-ACE and ZK-AMS qPCS if that PCS uses FASTPQ. Distinct Halo2,
Bulletproofs, lattice PCS and Spartan/Nova families retain their mathematical roles.
VOLE-in-the-head is a further distinct mathematical family with exactly one reusable
owner crate, `crates/iroha_zkp_vole`. It is experimental and unqualified, and only the
Parliament ballot relations use it.

Shared checked derivations include work-security, FRI and commitment error, including
missing fold/rate checks. Algebraic error sums do not establish Fiat–Shamir or hiding.
Select the shared transcript from actual security design; do not preserve obsolete
proof bytes for compatibility. Move still-used utility importers before deleting
drivers. Each caller adopts the canonical owner with its capability; aggregate
deletion never becomes a prerequisite for a consumer.

M.1–M.3 cover the whole IVM invocation: all 90 currently inventoried opcodes and
every final ABI syscall, typed state/memory/calls/gas/faults, cryptographic precompiles,
parallel/vector behavior, continuations/recursion and private-trace masking. Include
every trap and numeric fault. Bind actual initialized inputs, current code/manifest,
entrypoint, finalized context, complete reads, returns/effects/events/gas.
`VRF_EPOCH_SEED` needs authenticated point/range/absence reads, fallback and conflict
checks; a header field is insufficient. Later triggers require proof of their actual
later invocation. Replace the separate `IvmProved` executable with the canonical ISI.

Preserve the exact seeded differential and real-proof minima in M.3, not merely a
coverage list. Partial components remain useful in tests/tools; a transaction proof
must cover the complete claimed invocation.

## WG authenticated complete State and anchored AXT

WG is a complete State workstream. G.1–G.5 cover every authoritative persisted
execution table with one keyed commitment, inclusion/absence/complete-range witnesses,
atomic publication/recovery, committed root history and cache-independent admission.
Define a canonical result-root layout and update Sumeragi E51 without a circular
root/certificate dependency or an obsolete dual-root replay path.

Native prototypes start immediately. The reusable AIR interface enables exploratory
actual in-circuit witness measurements; those measurements inform tree/hash selection.
G.3 freezes the selected semantic profile before final measurements. Transactions
carry their historical witnesses and result openings; validation uses transaction
bytes and replicated State, never incidental local witness/Kura/DA retention.

Deliver the small WG witness-assertion operation before AXT or full IVM proofs.
Test all table mutations, complete-range omissions, age/cap boundaries, empty/different
caches, scheduled changes, retention warnings after replay, publication failures and
a named simulator mutation for local-validity dependence. Size history from actual
loaded and idle-chain proof-to-inclusion timing. Emergency Fast stays read-only.

AXT additionally proves D7's exact successful source execution, ordered transaction
set and transfer occurrence. For ordinary effects, `new_root` binds certified
`ordinary_writes_root`, not combined `post_state_root`; blocks that mix ordinary and
other certified writes test the distinction. At destination, check fresh issuer signatures and current
transaction-view policy/key/asset incarnation/code/ABI/generation/counter/expiry and
pending transitions. Consume nonce, occurrence, budget and effects atomically.
Preserve same-block revocation/rotation, equal-byte policy restoration and every
publication-boundary recovery case. Anchored delivery precedes obsolete-driver deletion.

## Mandatory RAM-LFE and phone claims

Deliver confidential inputs and a hidden committed function under explicit
owner/evaluator/encryption-key/opener/validator roles and collusion assumptions.
Use concrete circuit-private evaluation/sanitization, a mandatory proved normalizing
lowering with one fixed public schedule per class profile padded to the class maximum,
client ciphertext/key well-formedness proofs from the first slice, and a bounded
output/oracle leakage contract. Ordinary FHE alone does not establish hidden-program
privacy; ZK does not erase leakage in ciphertexts, outputs, access patterns or timing.

The canonical policy binds full function/initializer, class, exact plaintext semantics,
profile, encryption/evaluation/opening/PRF keys and relation identity. Logical function
identity survives encryption-key rotation. Current state lanes initialize within
each execution; persistent cross-request mutable state is not silently introduced.
Keep the identifier PRF key outside evaluator custody and test enumeration and
unauthorized queries.

Logical rank bounds ciphertext multiplication depth, not physical noise.
Instruction-by-instruction evaluation of the existing candidates does not hold the
maximum shape; acceptance requires semantic equivalence of the normalizing lowering
and maximum-shape physical noise, work and leakage evidence.

All three program classes remain mandatory:

| Class | Required execution |
| --- | --- |
| affine.v1 | LoadInput, LoadState, StoreState, LoadConst, Add, AddPlain, SubPlain, MulPlain, Output; no ciphertext multiplication or refresh. |
| bounded.v1 | All eleven instructions, including Mul and full SelectEqZero, with actual equality/operand-depth/noise accounting. |
| refresh.v1 | Bounded semantics plus genuine noise-reducing refresh and explicit between-refresh/count limits. |

R.12 delivers general affine execution/results independently of phone verification,
bounded programs, refresh, threshold, X509, full IVM proofs and SoraCloud. R.7 and
R.9 extend the same usable path as their classes land. Opening proves exact
ciphertext decryption to the committed output and PRF derivation under the registered
key. No opener/resolver/committee signature substitutes for those proofs. R.10 adds
verifiable threshold opening for each implemented class and gains bounded/refresh
vectors when those classes arrive; affine threshold does not wait for refresh.

The user selected **verification-provider credentials** for phone control. After a
fresh SMS/carrier challenge, the provider issues a short-lived credential bound to
the claimant AccountId, network, policy, nonce and validity. The provider learns the
number; the private proof binds that credential to the same encrypted canonical
E.164 input and keyed nullifier without disclosing it to resolver or ledger.
State the issuer-compromise/SIM-takeover trust limits honestly.

Preserve exclusive live binding, bounded expiry, revocation, renewal and recycled-number
reassignment. Use the earliest applicable expiry. Remove the old canonicality-attestor
schema/checks when the genuine relation replaces them. Number format and uniqueness
do not prove control. Phone-specific R.5 uses the same execution/opening owner and
one-call interaction/recovery semantics.

Retire the plaintext HKDF RAM-LFE backend, obsolete Signed execution mode and resolver
signing material across actual consumers, schemas, generators and SDKs. Preserve
unrelated HKDF derivation. Insecure algebra and failed cost projections require
construction work; they do not make bounded/refresh/threshold optional.

## Shared FHE and independent SoraCloud slices

One low-level `iroha_fhe` boundary owns reusable exact modular RNS/NTT, basis
conversion, polynomial arithmetic and explicit rounding. Create that crate only
as a real shared boundary, with acyclic dependencies and coherent manifests/lockfile.
RNS-BGV is the concrete starting candidate; cost full lowering, equality, packing,
noise, sanitization and proof work rather than renaming old exact-lift BFV.

ZK-AMS retains distinct BGV/MKHE collective semantics/wire while adopting shared
production arithmetic. Inventory test-only references separately; preserve independent
small oracles. Complete native40 source correspondence, full-size eight-party replay,
phases II/III, account provisioning and a PCS within fixed resources.

Shared bootstrap arithmetic/proof and threshold primitives live below applications.
SoraCloud add/multiply/rotate ships independently; full-bootstrap and threshold jobs
follow their own actual primitives, without RAM-LFE or mutual bootstrap/threshold
dependencies. C.9 owns ordinary job relations and shared role plumbing; C.8/C.6 own
genuine bootstrap relation/role completion. Together they cover four AIRs and all five
native registration roles, with model/Core/Torii/restored-State coverage and refreshed
refusal census. Worker signatures/replication are not execution proofs. Large keys
have authenticated bounded custody; incidental cache absence cannot decide validity.

## Privacy products and monetary invariants

Preserve the complete twelve-protocol inventory and additional confidential assets,
Kaigi, voting and atomic settlement. Each has an independent typed native/Kotodama/SDK
delivery with real maximum proofs and lifecycle tests. The task contracts retain
PGC bootstrap and payment, Vega Figure9/age proofs, Bootle/Lantern issuer lifecycle,
Jindo's extractor/count bounds, VeRange composition, Orchard turnstiles, complete
FCMP++ wallets, and full Kaigi authorization/usage and election ballot/tally semantics.

Separate hidden inflation, reserve theft and transparent issuance. Specify each
protocol's ownership/conservation/nullifier/asset-isolation relation and independent
ledger checks. Public withdrawals debit the exact reserve before equal credit;
deposits move existing assets; authorized issuance consumes its committed allowance.
Preserve existing private-IVM reserve checks. Current FCMP++/PQ-MASP paths do not
automatically imply a public bridge; any added bridge requires explicit economics.

Caps are ordinary committed transaction rules for the assets/pools whose policy
defines them, not activation gates. A public reserve cap does not prove hidden
conservation or protect every depositor from a broken relation. Test independent
ledger checks with test-only verifier-fault harnesses, never a node bypass.
Preserve PQ-MASP ML-KEM and distinguish IVM-note X25519 from the settlement hybrid
audit wrap; label security by the weakest actual claimed property.

## X509 transport holder custody and time

Select a 16 MiB block payload default, coordinated with genesis/committed parameters,
signed RS16 layout, transport/frame/sync/storage/proposer limits. Retain the
9,437,184-byte proof ceiling and 10 MiB transaction cap; measure the complete signed
maximum envelope, including signatures/context/framing. No payload can evade admission
through a hash-only proof reference. Redesign an oversized envelope or explicitly
document a parameter change rather than silently relaxing a limit.

All proof bytes travel in the canonical signed transaction and `SignedBlockWire`
availability path. X.4 exercises maximum proofs via direct/prepared and Kotodama
attachment-backed routes to finality, cold restart and independent exact-byte replay.

Retain complete MAIN/CA semantics, ECDSA/DER binding, differential fuzzing,
correlated-opening hiding and joint transcript analysis. Preserve q=136 unless a
full joint reduction updates every dependent descriptor, mask, degree, byte maximum
and fixture. P-256 authentication remains classical. Keep the 300-second target/CRL
age, 12 GiB server RSS and literal enforced 32 GiB address-space limits. The recorded
1,437-second maximum is a failure of its time target, not a current success claim.

Ship holder-controlled mobile/desktop/server proving with the subject signing key
kept in the wallet, paired-host enrollment, mutually authenticated encrypted handoff,
exact job binding, local verification, host revocation and witness erasure. Test
MITM, host substitution, replay and tampering and document compromised-host disclosure.

Presentation start is at least the latest chain `notBefore`; presentation end is
at most the earliest chain `notAfter` and strictly before each applicable CRL's
`nextUpdate`, preserving all other revocation predicates. Correct r6's latest-expiry
formula; do not discard its broader cadence requirements.

Implement newest-eligible selection across merged CRL/policy/anchor events, actual
publication spacing, skipped fast-issued CRLs, withholding, supersession and immediate
revocation. Budget the complete observe/prepare/prove/publish/submit/inclusion/clock
path. Resolve quiet-chain time semantics explicitly: blocktime and wallet TTL alone
cannot guarantee 300-second wall-clock freshness under a Byzantine proposer.
No empty blocks or unsupported freshness claim. X.4 owns final-candidate idle/advancing
four-peer measurements, at least 100 rotations/maximum-proof submissions and three
successful rollover cycles, including ordering/restart/livelock and permission cases.

## Evidence and development completion

E.1 supplies complete phase timing and resource instrumentation before measurements:
inclusive/exclusive CPU/wall time, workers/load, allocation/live buffers, key/ciphertext/
proof bytes, RSS and enforced address space, named hardware and applicable device
thermal state. Unattributed proving time is at most 1%. Never log private witnesses,
keys or hidden programs. Test clearing on success, error and unwind.

Bind observations to exact source, semantic profile, artifacts and configuration.
Separate exploratory projections, deterministic consensus bounds, local scheduling,
engineering targets and measured platform results. Salvage only unchanged scoped
evidence; retain failures. External review can demand repairs without creating
an activation service. Implemented slices remain usable while aggregate evidence,
independent assessment and physical-device qualification continue.

Use focused crate/SDK tests, genuine proofs and direct witness/constraint mutations.
Run Norito roundtrips and the legacy-codec guard for serialization changes; regenerate
ABI/pointer goldens and manifest mismatch controls where affected. Follow repository
formatting and strict affected lint; broaden to combined workspace and native/device
matrices as work lands. Builds use the repository twenty-minute allowance. Never
interrupt another agent's Cargo/Rust processes or bypass signed commits.

Consensus rules get named deterministic simulator mutations. Real networks use valid
3f+1 committees with at least four validators, exact n−f certificates and signed RS16;
idle chains produce no blocks. An enabled hardware feature is not device execution.
Record executed, failed and unexecuted checks explicitly.

Functional completion means every required algorithm and class delivers its real
operation through the canonical proof, native/Kotodama and SDK surface. Evidence
deliveries summarize what is implemented, tested, assessed and still unknown; they
do not grant runtime permission or turn failed targets into successes. Keep repository
status/roadmap concise and current; public in-depth guidance belongs in optional
`iroha-docs`, without making builds depend on that checkout.

## Task graph

Functional deliveries inherit the full `operation-v1` surface contract described
above. Evidence deliveries may aggregate products; functional deliveries cannot
depend on aggregate review, measurement, SDK reconciliation or deletion milestones.
Owners are accountable disciplines, not signature authorities.

| ID | Task | Owner | Requires |
| --- | --- | --- | --- |
| F.1 | Complete operation and admission-route inventory | Data model and protocol owners | — |
| F.2 | Unified end-to-end resource contract | Consensus, IVM and configuration | — |
| F.3 | Protocol economic invariant matrix | Ledger economics and protocol owners | — |
| F.4 | Committed validity and non-gating runtime | Core, SDK and documentation owners | — |
| I.1 | Ordered intents and signed attachment schema | Data model and executor | F.1, F.2 |
| I.2 | Invocation-scoped attachment and action handles | Executor and IVM host | I.1 |
| I.3 | Typed canonical native ISI bridge | IVM and Core executor | I.2, F.2 |
| I.4 | Deterministic charging and receipt correlation | IVM and transaction runtime | I.3, F.2 |
| I.5 | ABI V1 and typed Kotodama regeneration | IVM ABI and Kotodama | I.3, I.4 |
| I.6 | Atomic native and Kotodama composition | Core integration | I.5, P.1, P.5 |
| C.1 | FHE and plaintext consumer ownership map | Crypto and ZK-AMS owners | — |
| C.2 | Shared deterministic FHE arithmetic | Crypto and acceleration owners | C.1 |
| C.3 | Secure RNS-BGV candidate and cost model | FHE cryptography owners | C.1, C.2, F.2, E.1 |
| C.4 | Threshold key and share protocol | Threshold cryptography and custody | C.2, C.3 |
| C.5 | ZK-AMS native40 and MKHE completion | ZK-AMS and qPCS owners | C.2, C.4, B.2, F.2, I.5, S.1 |
| C.6 | SoraCloud full-bootstrap delivery | SoraCloud and FHE owners | C.8, F.4, I.5, S.1, C.9 |
| C.7 | SoraCloud threshold opening delivery | SoraCloud and threshold owners | C.4, B.2, F.2, F.4, I.5, S.1, S.2 |
| R.1 | Provider-backed phone-control contract | Identity and SDK owners | — |
| R.2 | Private phone-control and uniqueness relation | Identity cryptography | R.1, R.0, R.3, R.8, B.2 |
| R.3 | Program-hiding affine execution relation | RAM-LFE and FHE owners | R.0, R.11, B.2, F.2 |
| R.4 | Phone claim lifecycle and direct replacement | Core identity | R.2, R.12, F.3, F.4 |
| R.5 | One-call private phone claim delivery | Identity, SDK and integration | R.4, I.6, S.1 |
| R.6 | Retire plaintext and signed-receipt backends | Crypto, schema and SDK owners | C.1, R.12, R.5 |
| P.1 | Single Exact12 native dispatch owner | Privacy model and Core | F.1 |
| P.2 | Independent public monetary invariants | Core assets and privacy | F.3, P.1 |
| P.3 | Common private economic test contract | Value-bearing privacy protocol owners | F.3, P.1, B.1 |
| P.4 | Typed credential and proof composition contract | Credential and authorization owners | P.1, B.1, F.2, F.5 |
| P.5 | Remove activation and review predicates | Core, Torii and SDK | F.4, P.1 |
| P.6 | Exact12 and additional-product reconciliation | Privacy integration | P.2, P.3, P.4, P.5, C.5, X.4, P.7, P.8, P.9, P.10, P.11, P.12, P.13, P.14, P.15, P.16, P.17, P.18, P.19, P.20 |
| X.1 | Certificate and CRL interval semantics | X509 relation and SDK | — |
| X.2 | Implement canonical maximum-proof transport | Consensus, configuration and X509 | F.2, P.1 |
| X.3 | Complete bounded joint X509 construction | X509 cryptography and performance | X.1, B.2, F.2, E.1 |
| X.4 | Maximum X509 usable delivery | X509 and four-peer integration | X.2, X.3, X.5, X.6, I.5, S.1, P.5 |
| H.1 | Primitive candidate and workload specification | Cryptographic profile and benchmark owners | — |
| H.2 | Freeze semantic profiles before final measurements | Cryptographic profile owners | H.1, B.1 |
| H.3 | Final frozen-candidate measurements | Performance and hardware owners | H.2, G.3, E.1 |
| A.1 | D7 finalized source and current issuer contract | FASTPQ, AXT and State owners | F.1, F.3, G.1 |
| A.2 | Complete ordinary FASTPQ effect relation | IVM and FASTPQ proof owners | A.1, B.2, F.2, G.4 |
| A.3 | Anchored AXT and private invocation delivery | AXT, Core and integration | A.2, G.4, I.5, P.2, S.1 |
| A.4 | Retire all superseded proof drivers | Runtime, SDK and packaging owners | A.3, V.2, B.3 |
| S.1 | One-call and prepared SDK core | Rust client and shared native owners | F.1, I.1, F.2 |
| S.2 | Durable multi-round workflow APIs | SDK and service owners | F.1 |
| S.3 | Kotlin Java and Android delivery | Kotlin SDK and Android owners | S.1, S.2, I.5 |
| S.4 | Swift and C# delivery | Swift, C# and bridge owners | S.1, S.2, I.5 |
| S.5 | JavaScript and Python delivery | JavaScript, Python and native owners | S.1, S.2, I.5 |
| S.6 | Aggregate SDK conformance evidence | All SDK and integration owners | S.3, S.4, S.5, P.6, X.4, R.5, R.7, R.9, R.10, C.6, C.7, C.9, A.3, M.3, G.5 |
| V.1 | Plan source coverage and graph checks | Planning and tooling owners | — |
| V.2 | Four-peer atomic execution and recovery | Integration and runtime owners | I.6, S.1, P.5, A.3, T.1 |
| V.3 | Complete proof and relation evidence | Protocol testing owners | P.6, C.5, X.3, A.2, A.3, M.3, R.9, R.10, B.2 |
| V.4 | Independent security and hardware evidence | Independent reviewers and platform owners | V.3, H.3, C.2 |
| V.5 | Integrated product and retirement evidence | SDK, runtime and release owners | S.6, V.2, X.4, R.6, A.4, G.5, C.9, T.1 |
| V.6 | Candidate evidence and documentation reconciliation | Release and documentation owners | V.3, V.4, V.5, V.1 |
| B.1 | Reusable FASTPQ AIR interface and migration inventory | Proof backend | — |
| B.2 | Shared STARK engine and checked security accounting | Proof backend | B.1, H.2, F.2, E.1, F.5 |
| B.3 | Exhaustive shared-backend consumer replacement | Proof backend and all consumers | B.2, A.3, M.2, X.3, R.9, C.9, C.6, P.15, P.18, P.19, P.20, C.5, C.7, R.10 |
| G.1 | Complete authenticated State and root contract | State, Kura and Sumeragi | — |
| G.2 | Measure native and in-circuit State candidates | State and proof backend | G.1, B.1, E.1 |
| G.3 | Selected State commitment and publication | State, Kura and Sumeragi | G.2, F.4 |
| G.4 | Carried historical witnesses and committed bounds | State and transaction runtime | G.3, F.2, F.4 |
| G.5 | Independent WG witness assertion delivery | State and SDK integration | G.4, I.5, S.1, T.1 |
| M.1 | Complete IVM semantic and proof coverage inventory | IVM and proof owners | — |
| M.2 | Complete native IVM proved-invocation ISI | IVM, Core and proof backend | M.1, B.2, G.4, I.5, F.2, S.1 |
| M.3 | Full IVM differential and real-proof corpus | IVM validation | M.2, E.1 |
| R.0 | RAM-LFE roles leakage classes and policy | RAM-LFE cryptography and Core | — |
| R.11 | Circuit privacy and client well-formedness | RAM-LFE cryptography | R.0, C.3, B.1 |
| R.8 | Verifiable decryption opening and identifier PRF | RAM-LFE crypto and Core | R.0, C.3, B.2 |
| R.12 | General affine execution and opening delivery | RAM-LFE, Torii and SDK | R.3, R.8, I.6, S.1, F.4, T.1 |
| R.7 | Bounded RAM-LFE class and usable flow | RAM-LFE crypto and SDK | R.12, C.3 |
| R.9 | Refresh RAM-LFE class and usable flow | RAM-LFE crypto and SDK | R.7, C.8 |
| R.10 | RAM-LFE threshold opening delivery | RAM-LFE threshold and SDK | C.4, R.8, R.12, S.2 |
| C.8 | Shared bootstrap arithmetic and complete proof | FHE and proof backend | C.2, C.3, B.2, E.1 |
| C.9 | SoraCloud add multiply rotate and role integration | SoraCloud, model and SDK | C.2, C.3, B.2, I.5, S.1, F.4, T.1 |
| X.5 | Shipping holder-controlled X509 prover | Credentials and native SDK | X.1, S.1 |
| X.6 | X509 CRL publication and temporal lifecycle | Credentials, State and consensus | X.1, F.4, E.1 |
| T.1 | First-release history and coherent cutover | Core, genesis, SDK and deployment | — |
| E.1 | Reproducible phase and resource harness | Performance and tooling | — |
| P.7 | Kaigi authorization and usage delivery | Kaigi and privacy | P.4, F.4, I.5, S.1, P.5 |
| P.8 | Complete private election delivery | Voting and governance | P.4, F.4, I.5, S.1, P.5 |
| P.9 | Confidential asset delivery | Confidential assets and Halo2 | P.1, P.2, P.3, I.5, S.1, P.5, F.5 |
| P.10 | Anonymous PGC bootstrap and payment delivery | PGC and wallets | P.2, P.4, I.5, S.1, P.5 |
| P.11 | VeRange ledger composition delivery | Range proofs and ledger | P.1, P.4, I.5, S.1, P.5 |
| P.12 | Jindo polynomial commitment delivery | Jindo and ledger | P.1, P.4, I.5, S.1, P.5 |
| P.13 | Bootle Lantern credential delivery | Lattice credentials | P.1, P.4, I.5, S.1, P.5 |
| P.14 | Vega Figure 9 credential delivery | Vega and credentials | P.1, P.4, I.5, S.1, P.5 |
| P.15 | ZK-ACE authorization delivery | ZK-ACE and proof backend | P.4, B.2, I.5, S.1, P.5 |
| P.16 | Orchard shield transfer unshield delivery | Orchard and wallets | P.1, P.2, P.3, I.5, S.1, P.5 |
| P.17 | FCMP++ wallet transfer delivery | FCMP++ and wallets | P.1, P.2, P.3, I.5, S.1, P.5 |
| P.18 | IVM private note delivery | Private notes and proof backend | B.2, P.1, P.2, P.3, I.5, S.1, P.5 |
| P.19 | PQ-MASP delivery | PQ-MASP and wallets | B.2, P.1, P.2, P.3, I.5, S.1, P.5 |
| P.20 | Atomic private settlement delivery | Settlement and State | B.2, G.4, P.1, P.2, P.3, I.5, S.1, P.5 |
| F.5 | Canonical crypto primitives and dependency replacement | Crypto, model and SDK owners | H.2 |

| ID | Delivery | Requires |
| --- | --- | --- |
| D.ISI | Atomic native and Kotodama composition | I.6, S.1, T.1 |
| D.WG | Independent complete-State witness assertion | G.5 |
| D.RAM_AFFINE | General affine encrypted execution and opening | R.12 |
| D.PHONE | Verified private phone claim and backend replacement | R.5, R.6 |
| D.RAM_BOUNDED | Bounded encrypted program delivery | R.7 |
| D.RAM_REFRESH | Genuine refresh encrypted program delivery | R.9 |
| D.RAM_THRESHOLD | RAM-LFE threshold opening | R.10 |
| D.CLOUD_BASIC | SoraCloud add multiply rotate | C.9 |
| D.CLOUD_BOOTSTRAP | SoraCloud full bootstrap | C.6 |
| D.CLOUD_THRESHOLD | SoraCloud threshold opening | C.7 |
| D.X509 | Maximum X509 through holder prover and finality | X.4 |
| D.AXT | Anchored AXT with current issuer authority | A.3 |
| D.IVM_PROOF | Complete proved IVM invocation | M.2, M.3 |
| D.ACE | ZK-ACE authorization | P.15 |
| D.PGC | Anonymous PGC bootstrap and payment | P.10 |
| D.RANGE | VeRange verification and ledger composition | P.11 |
| D.AMS | ZK-AMS native40 and composite use | C.5 |
| D.VEGA | Vega Figure 9 credentials | P.14 |
| D.JINDO | Jindo polynomial commitment use | P.12 |
| D.BOOTLE | Bootle Lantern issue and present | P.13 |
| D.ORCHARD | Orchard monetary operations | P.16 |
| D.FCMP | FCMP++ wallet transfers | P.17 |
| D.IVMNOTE | Private IVM note operations | P.18 |
| D.PQMASP | PQ-MASP operations | P.19 |
| D.CONFIDENTIAL | Confidential asset operations | P.9 |
| D.KAIGI | Kaigi authorization and usage | P.7 |
| D.VOTING | Private ballot and tally | P.8 |
| D.SETTLEMENT | Atomic private settlement | P.20 |
| D.RETIREMENT | Completed first-release driver and backend replacement | A.4, R.6, T.1 |
| D.PROOFS | Combined current-candidate proof evidence | V.3 |
| D.SDK | Combined retained-SDK evidence | S.6, S.2 |
| D.EVIDENCE | Combined implementation and qualification record | V.6 |

## Task contracts

The graph is the machine-readable source for these exact output/acceptance records.
Every functional delivery inherits operation-v1 even when its task text uses that
short reference; aggregate SDK/evidence tasks do not provide a substitute.

### F.1 Complete operation and admission-route inventory

Deliverable: Map every r6 product, Exact12 protocol, general RAM-LFE class/opening, SoraCloud job, WG, AXT, IVM proof, Kaigi and voting operation through native ISI, handler, semantic relation, permissions and all SDK consumers; inventory generic verification, preverification, VK registration, genesis and restore.

Acceptance: Every retained source requirement and historical finding has a task mapping. Audit native versus in-circuit digest use, BN254 Poseidon parameters and obsolete PQ-library replacements with deterministic vectors. Unbound uploaded keys, source hashes and global catalog membership cannot choose a proof guarantee.

### F.2 Unified end-to-end resource contract

Deliverable: Define proof, signed attachments, transaction, block, RS16, transport, VM handles, decoded scratch, retained queued effects and deterministic work budgets including Norito overhead.

Acceptance: Actual maximum paths and exact/one-over tests agree across SDK admission, VM, proposer and follower. Missing local resources defer without rejection/vote; malformed carried evidence rejects deterministically. Derive RAM-LFE budgets from its full workload; preserve separately fixed X509 bounds and distinguish engineering time targets.

### F.3 Protocol economic invariant matrix

Deliverable: Classify private issuance, transparent supply changes, deposits, withdrawals, reserves, settlement and inter-pool movement for every value-bearing protocol. Define retained-state readability, cancellation/expiry, failure atomicity and asset exits under ordinary key/policy revocation and correction.

Acceptance: Name the independently checked invariant, authorized issuance source, remaining exposure after erroneous proof acceptance, and mutation test for each economic effect. A reserve cap is never labeled proof soundness. Root publication/history follow canonical policy without a generic suspension switch.

### F.4 Committed validity and non-gating runtime

Deliverable: Move validity-affecting windows, expiry/skew rules, proof limits and relation-selecting keys into committed State; remove review/activation prerequisites across Core, Torii, SDKs, genesis and restore as each path is rebuilt.

Acceptance: No environment, node-local configuration, feature, binary/source digest, chain-ID production flag, readiness certificate or all-protocol manifest changes validity or availability. Completed capabilities run through ordinary deployment. Preserve cryptography, permissions, key revocation, replay, finality and deterministic limits; feature/config parity tests compare roots, effects and gas.

### I.1 Ordered intents and signed attachment schema

Deliverable: Define canonical proof-free ordered intent descriptors, per-action statement/role/authority bindings and signed inline attachment occurrences for large proofs and admitted key material.

Acceptance: Proofs bind the normalized intent excluding generated proof bytes/digests to avoid circularity; the transaction signature covers the complete canonical proof-bearing payload. Reject reorder/substitute/omit/duplicate/replay. Specify attachment type, index, length and hash checks and regenerate all first-release fixtures without a fallback decoder.

### I.2 Invocation-scoped attachment and action handles

Deliverable: Retain immutable authenticated attachments under host custody and expose typed small handles scoped to transaction, authorized invocation and committed action index.

Acceptance: No large proof is copied into guest heap or fetched from an external RPC. Wrong type/role, cross-transaction/invocation, changed, reused, missing or unconsumed declarations fail atomically; nested calls preserve exact authority and lifetime. A proof attachment is data, never a reusable verification capability.

### I.3 Typed canonical native ISI bridge

Deliverable: Use typed operation tags on the canonical ABI V1 instruction bridge with typed Kotodama builtins; materialize signed attachment-backed payloads in the host and route every declared ISI through its existing executor.

Acceptance: Keep ordered queued execution in one StateTransaction. Return PendingAction tokens, not proof-success values; effects/results become authoritative only in the final receipt. No same-invocation branch on unapplied effects. Verify-only primitives grant no authorization; native/contract permissions and effects agree, including administrative calls.

### I.4 Deterministic charging and receipt correlation

Deliverable: Charge signed bytes, attachment acquisition, decode/verification scratch, retained queue memory, storage and gas under one deterministic budget; correlate each PendingAction with its actual finalized result.

Acceptance: Test full-size proofs with small guest handles across input/heap/literal paths, ownership cleanup on all faults, duplicate and oversized attachments, later-action rollback and recoverable pending outcomes. Local timeout or memory shortage never becomes a different certified transaction result.

### I.5 ABI V1 and typed Kotodama regeneration

Deliverable: Replace development-only bridge tags/docs, regenerate typed builtins, operation descriptors, ABI hash/manifests, syscall and pointer metadata and all affected SDK artifacts.

Acceptance: Remain ABI V1. Update abi_syscall_list order and number goldens if changed, abi_hash_versions, pointer_type_ids and policy tests when affected, manifest positive/mismatch admission tests and crates/ivm/docs/syscalls.md. Cover every exposed family and final added syscalls in M.1/M.2; first-release incompatible changes use T.1.

### I.6 Atomic native and Kotodama composition

Deliverable: Deliver several privacy actions mixed with ordinary ISIs in one signed atomic transaction, both directly and through typed Kotodama attachment handles.

Acceptance: Genuine proofs exercise exact intent/authority binding, nested invocation scopes, queued result semantics, duplicate/unconsumed actions and later-failure rollback on four validators. Large-payload coverage is owned by X.4; each product delivery extends this same contract rather than a new execution route.

### C.1 FHE and plaintext consumer ownership map

Deliverable: Inventory production RNS/NTT owners, BFV/BGV protocol logic, test oracles, HKDF RAM-LFE users and all generated consumers.

Acceptance: Assign each reusable primitive one lowest-layer owner. Record genuine plaintext PRF use separately from encrypted evaluation. Do not classify test-only key-generation references as a complete production stack.

### C.2 Shared deterministic FHE arithmetic

Deliverable: Establish the proposed iroha_fhe boundary for reusable RNS, modular polynomial arithmetic, NTT, basis conversion and explicit rounding; migrate callers.

Acceptance: Keep the dependency graph acyclic and manifests/lockfile coherent. Scalar, Metal, NEON/SIMD and CUDA paths used by supported targets match canonical vectors; provide deterministic fallback and retain independent mathematical test oracles.

### C.3 Secure RNS-BGV candidate and cost model

Deliverable: Implement and cost the genuine exact modular RNS-BGV starting candidate, secure key/encrypt/decrypt, relinearization, modulus switching and automorphisms; derive distributions, estimator assumptions and explicit rounding/noise failure bounds. Use secure randomness and bounded clearing owners for every secret buffer.

Acceptance: Compare F257 sparse-slot representation with a measured alternative/batching modulus, including equality exponentiation, broadcasts/key switching, scalar-subalgebra input proof, masking and unused-output zeroing. Use independent arithmetic/decryption vectors. No depth-16/+10 heuristic, exact-lift BFV, plaintext fallback or unmeasured flooding constants establish security. Verify secret erasure on success, error and unwind. Derive and measure physical noise/work bounds for the proved normalizing lowering under one fixed public schedule per class profile padded to the class maximum; logical rank bounds ciphertext multiplication depth, not physical noise, and instruction-by-instruction evaluation of the existing candidates does not hold the maximum shape.

### C.4 Threshold key and share protocol

Deliverable: Implement explicit participant threshold, key generation, epoch custody and verifiable decryption shares.

Acceptance: Reject malformed, replayed, wrong-epoch and wrong-ciphertext shares; insufficient participation fails and the declared threshold succeeds. Verify secret lifecycle and malicious-party cases without borrowing consensus quorum rules.

### C.5 ZK-AMS native40 and MKHE completion

Deliverable: Migrate shared production RNS/NTT/key-switch arithmetic while retaining distinct BGV/MKHE wire and collective semantics; complete native40 source correspondence, bounded qPCS, production composite verifier, phases II/III and account provisioning.

Acceptance: Genuine full-size eight-party replay, malicious collective keys/shares, full source/proof pairs and resource controls satisfy operation-v1. Preserve independent test-only oracles and distinguish them from production. Choose a PCS within unchanged whole-proof bounds; fixture proofs and arbitrary key uploads cannot substitute.

### C.6 SoraCloud full-bootstrap delivery

Deliverable: Deliver actual full-bootstrap jobs using C.8, complete bootstrap-key, SoraCloud full-execution and BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1 arithmetic role proofs/registration, exact bindings and removal of audit/activation predicates.

Acceptance: Operation-v1 covers genuine maximum bootstrap/noise reduction, role/key/input substitutions and every bootstrap-specific model/Core/Torii/restore refusal site from the refreshed census. Combine with C.9's ordinary relations to close all four AIRs/five roles; zero-refresh and worker signatures are insufficient. No RAM-LFE or threshold prerequisite.

### C.7 SoraCloud threshold opening delivery

Deliverable: Deliver authorized threshold opening with proofs of share correctness, consent, roster/key epoch, ciphertext/request binding and authenticated bounded key custody.

Acceptance: Operation-v1 includes malicious/duplicate/missing/wrong-epoch shares, insufficient threshold, revocation and interrupted recovery without audit artifacts. Incidental cache absence cannot change validity. No dependency on RAM-LFE application delivery or bootstrap completion.

### R.1 Provider-backed phone-control contract

Deliverable: Use the user-selected verification-provider credential: a fresh SMS/carrier challenge produces a short-lived credential bound to beneficiary AccountId, network, policy, nonce and validity.

Acceptance: Specify provider trust/key/revocation policy, challenge replay prevention, number recycling, issuer compromise and SIM takeover exposure. Provider learns the number; prove the credential privately against the encrypted canonical input. Canonicality alone is not control; no reviewer approval or canonicality-attestor gate returns.

### R.2 Private phone-control and uniqueness relation

Deliverable: Prove canonical E.164, current provider credential, encrypted input, authorized beneficiary and keyed phone-nullifier consistency under the same complete policy and opening statement.

Acceptance: Wrong beneficiary/network/policy/key, forged/revoked/expired credential, inconsistent ciphertext, replay and competing live claims fail. Randomized encryption preserves stable identity; key rotation preserves uniqueness. The identifier PRF key stays outside evaluator custody and unauthorized enumeration is tested.

### R.3 Program-hiding affine execution relation

Deliverable: Implement affine.v1 with LoadInput, LoadState, StoreState, LoadConst, Add, AddPlain, SubPlain, MulPlain and Output; prove hidden tape, initialization, all transitions, encodings, bounds and ordered outputs under the full authoritative policy. Implement and prove the normalizing lowering preserves these semantics.

Acceptance: No ciphertext multiplication/refresh enters this class. One fixed public schedule per class profile padded to the class maximum conceals the committed program within the specified leakage bound. Test class/policy/key/context substitutions, private-witness mutations and actual equality-free affine workloads; a binding-only receipt is not execution. Verify maximum-shape normalization, semantic equivalence and physical noise bounds independently of logical rank.

### R.4 Phone claim lifecycle and direct replacement

Deliverable: Apply verified identifier claims with exclusive live binding, mandatory bounded expiry, authorized renewal/revocation/reassignment; remove PhoneRetailCanonicalityAttestationV1 and pinned canonicality signatures when their genuine relation replacement lands.

Acceptance: Expiry uses the earliest relevant credential, opening, receipt, key and policy bound. Test competing claims, eviction, number recycling, key rotation and stale lookups; separate domainless AccountId registration from alias permissions. No permanent-squatting claim is assumed and no signature substitutes for decryption/PRF proof.

### R.5 One-call private phone claim delivery

Deliverable: Deliver provider challenge, encryption, execution proof, verified opening, ClaimIdentifier, lookup and actual account result in one call using operation-v1.

Acceptance: All supported SDK fixtures/examples plus direct/prepared/Kotodama four-validator effects, cold restart and full current-genesis replay pass. Test challenge denial, cancellation, unknown outcome/read-only resume and phone-payment resolution; ordinary Taira deployment exposes the implemented route without extra activation.

### R.6 Retire plaintext and signed-receipt backends

Deliverable: Remove HkdfSha3_512PrfV1, its RAM-LFE policy/evaluator/tag branches, obsolete Signed execution mode, resolver signing material and replaced exact-lift consumers across model, Core, Torii, bridge, generators, SDKs and fixtures.

Acceptance: Inventory every importer before deletion; all have genuine replacements and old tags reject without aliases. Preserve unrelated HKDF derivation and independent test oracles. Kotlin owns Java-consumer capability/fixture migration. Do not delete a real consumer merely to make the census empty.

### P.1 Single Exact12 native dispatch owner

Deliverable: Map all twelve registered protocols to one canonical envelope/dispatch path and one verifier/state executor per role.

Acceptance: Protocol-specific builders and adapters delegate to that path; retire duplicate authoritative routes. Distinguish enum presence, implemented verification, state effects and usable delivery instead of claiming twelve production-ready protocols.

### P.2 Independent public monetary invariants

Deliverable: Enforce exact reserve debits/credits, asset and namespace isolation, committed issuance allowances and cross-pool conservation where applicable.

Acceptance: Test underflow, wrong reserve/asset/scope, ordinary-transfer bypass, duplicate effects and batch rollback. Preserve existing private-IVM reserve controls. Any new FCMP++/PQ-MASP public bridge requires its own specified invariant and covered state transition.

### P.3 Common private economic test contract

Deliverable: Define reusable relation mutation and ledger-effect tests for ownership, range, nullifiers, issuance, asset isolation and private/public conservation, preserving existing reserve controls.

Acceptance: Each value-bearing product consumes these controls and supplies genuine protocol-specific proofs in its own task. Erroneous-verifier harnesses are test-only; distinguish private inflation, reserve theft and transparent minting without claiming a public cap proves hidden conservation.

### P.4 Typed credential and proof composition contract

Deliverable: Specify typed verify-only and ledger-composition behavior for credential, range and commitment roles, with authoritative key/issuer/context derivation and common privacy/resource controls.

Acceptance: Role/statement/parameter substitution and unbound VK uploads reject; primitive verification does not invent financial effects or reusable authorization. Product tasks own actual algorithms, maximum proofs, issuer lifecycle and independent deliveries.

### P.5 Remove activation and review predicates

Deliverable: Remove qualification receipts, reviewer signatures and activation-state prerequisites from runtime admission and SDK availability.

Acceptance: Transaction validity still enforces supported canonical profile, valid cryptography, permissions, committed key policy, replay and resource limits. Missing or invalid implementations return accurate typed errors; deleting a gate cannot turn an invalid proof or insecure backend into success.

### P.6 Exact12 and additional-product reconciliation

Deliverable: Reconcile exact twelve registered protocols plus confidential assets, Kaigi, voting and settlement against their independently delivered operation-v1 flows.

Acceptance: Every listed product has genuine positive, maximum, mutation, authorization, stale-context, replay and rollback evidence. Missing engines/platforms remain failures or unexecuted work; inventory completion never controls availability of another finished product.

### X.1 Certificate and CRL interval semantics

Deliverable: Align presentation bounds with every certificate and the existing CRL freshness predicates.

Acceptance: Test earliest expiry at leaf/intermediate/root, certificate boundary equality, one-unit overflow, CRL nextUpdate exclusion and builder/verifier agreement. Treat acceptance of expired credentials as a security defect.

### X.2 Implement canonical maximum-proof transport

Deliverable: Implement the selected 16 MiB block payload default with committed genesis parameters, RS16 geometry, frame/sync/storage/proposer bounds and 10 MiB signed-transaction cap; keep proof ceiling 9,437,184 bytes.

Acceptance: Measure maximum complete canonical envelopes with supported signatures and framing. The remaining 1 MiB over the proof ceiling must contain all required context; reject oversize atomically. If it cannot fit, redesign the canonical envelope or make an explicit documented parameter change rather than silently raising caps. Exact/one-over and inconsistent-parameter tests agree across peers.

### X.3 Complete bounded joint X509 construction

Deliverable: Complete MAIN/CA ECDSA-to-DER/RFC semantics, correlated-opening hiding, joint transcript reduction, holder linkability/nullifiers and certificate leakage; optimize actual maximum proof generation without reducing coverage.

Acceptance: Retain q=136 unless a full joint reduction coherently updates masks/descriptors/DER degrees/IO inequalities/CA digests/fixtures. Distinguish classical-ROM/qROM and work-normalized/absolute claims; P-256 is classical. Preserve proof 9,437,184 bytes, 300-second target/CRL age, server RSS 12 GiB and enforced address space 32 GiB; measure worker counts and full phase attribution.

### X.4 Maximum X509 usable delivery

Deliverable: Deliver maximum supported credentials through the shipping holder-controlled prover, signed attachment-based Kotodama/direct/prepared ISIs and all SDKs to four-validator finality, canonical persistence, cold restart and replay.

Acceptance: Operation-v1 verifies exact proof/statement after restart, wrong genesis/nonce/corruption and over-limit rejection without effects, recording proof/transaction/block sizes separately. On the final candidate run idle/advancing four-peer temporal cases, same-block order/restart/permission/livelock, at least 100 rotations and maximum-proof submissions and 3 successful rollover cycles; measure real supersession/deadline and privacy results without activation artifacts or external proof fetch.

### H.1 Primitive candidate and workload specification

Deliverable: Inventory native versus in-circuit digests and define exploratory security/cost comparisons for shared proofs and product-specific roles; WG candidate measurement is explicitly owned by G.2.

Acceptance: Select canonical native commitments consistently across catalog, Kaigi, spentness, MKHE, SDKs and fixtures; retain mathematically distinct families where needed. BN254 Poseidon and PQ dependency repairs get vectors. Exploratory measurements may guide choices and never count as final candidate qualification.

### H.2 Freeze semantic profiles before final measurements

Deliverable: Select the shared backend transcript and applicable native/in-circuit profiles from explicit security design and exploratory measurements; regenerate canonical semantic identities and fixtures.

Acceptance: Build/source hashes remain evidence metadata, not transaction truth. No old transcript is kept for proof-byte compatibility. WG tree/hash is selected separately after G.2, then frozen in G.3. Changed algorithms invalidate affected final measurements and never require a runtime reviewer token.

### H.3 Final frozen-candidate measurements

Deliverable: Measure final selected native and in-circuit workloads, including actual WG witnesses, on exact frozen source/profile/artifact/configuration and named hardware.

Acceptance: Record workload/worker/platform/load/warm-cold conditions and observed time/bytes/RSS. Distinguish projections, engineering targets, consensus bounds and actual enforced resources. This aggregate evidence does not block an independently complete usable product.

### A.1 D7 finalized source and current issuer contract

Deliverable: Bind exact successful source execution, ordered transaction set and transfer occurrence through D7/WG/certified-result openings; specify current destination issuer authority separately from historical anchors.

Acceptance: ordinary new_root is ordinary_writes_root, not combined post_state_root; test blocks that mix ordinary and other certified writes. Bind current transaction-view policy/key/asset incarnation/code/ABI/counter/generation/expiry/pending transitions, fresh issuer signature and atomic nonce/source-occurrence/budget consumption.

### A.2 Complete ordinary FASTPQ effect relation

Deliverable: Implement full-effect ordinary FASTPQ admission with authentic original funding/source custody and bounded hiding construction; migrate RaceV1/classed callers through the shared backend where applicable.

Acceptance: Real maximum proofs and independent replay reject source/spend/root/ordered-effect substitutions. Prove actual effects rather than commitments, preserve resource caps and current-State checks, and keep component, hardware and network evidence distinct.

### A.3 Anchored AXT and private invocation delivery

Deliverable: Deliver exact anchored source-to-destination spends and private invocation through current issuer checks, native ISIs and operation-v1; publish effects and recovery outcomes atomically and durably.

Acceptance: Test every publication crash boundary, duplicate/reordered requests, wrong source/amount/network/lane, expired anchors, revocation/rotation between anchor/inclusion and earlier same block, equal-byte restoration after revoke, mixed roots and once-only spend. Measure max batches, p99 prove/submit/inclusion, verify/bytes/RSS on four peers.

### A.4 Retire all superseded proof drivers

Deliverable: Delete superseded driver files and remaining wiring/config/exports/packaging after all source consumers, including anchored AXT, use canonical replacements.

Acceptance: No consumer or usable delivery depends on deletion. Move still-used IO/limit/CLI/observer/accelerator utilities before removal; preserve behavior tests and workspace compilation. No compatibility shim or live fallback remains for a replaced semantic role.

### S.1 One-call and prepared SDK core

Deliverable: Provide shared prepare/prove/local-verify/build/sign/submit/finality and durable-operation handling, with a mandatory high-level call and advanced prepared canonical ISI form for external signing, batches and contracts.

Acceptance: All six SDK families share semantic contracts, fixtures and typed errors; per-capability bindings ship in each functional delivery, without waiting for aggregate ports/conformance. Secure custody/randomness and correct pending/cancel/read-only recovery remain default; no silent batch splitting or private upload.

### S.2 Durable multi-round workflow APIs

Deliverable: Expose separately named bootstrap/DKG workflow calls with idempotent steps, durable progress and resumable transaction identities.

Acceptance: State cross-transaction partial completion explicitly. Test interruption before submission, after ambiguous submission and after irreversible progress; resume checks committed outcome before retrying and never fabricates cross-transaction atomicity.

### S.3 Kotlin Java and Android delivery

Deliverable: Implement common APIs through Kotlin-owned modules, Java-callable consumers and Android-specific adapters.

Acceptance: Preserve shared fixtures and every migrated Java assertion, JDK 8 API guard, no reflection and Android/core separation. Distinguish host JNI from physical-device qualification; remove replaced Java implementations only after migration.

### S.4 Swift and C# delivery

Deliverable: Implement common operation/workflow contracts and witness ownership through the canonical native bridge.

Acceptance: Same signed bytes, intent binding, typed errors, finality and recovery cases as Rust; actual Apple/Windows native artifacts and device/OS evidence are named separately. No managed fallback verifier with different semantics.

### S.5 JavaScript and Python delivery

Deliverable: Implement common operation/workflow contracts using supported native runtimes and coherent packaging.

Acceptance: Shared byte/error/finality vectors, cancellation, secure witness handling and installed-package smoke cases pass. No Wasm/WASI runtime or alternate codec path; do not claim unsupported browser-native proving.

### S.6 Aggregate SDK conformance evidence

Deliverable: Reconcile the per-capability Rust, Kotlin/Java/Android, Swift, JavaScript, Python and C# deliveries and their canonical examples, fixtures, installed native artifacts and recovery results.

Acceptance: Each capability already supplies operation-v1 when it lands. This aggregate catches drift across products/platforms and cannot delay any finished operation. Unsupported platform performance and physical-device qualification remain explicitly unexecuted.

### V.1 Plan source coverage and graph checks

Deliverable: Maintain the final plan, graph and self-contained r6 requirement/finding reconciliation with a single checker.

Acceptance: Validate true roots, cycles, delivery reachability, required/forbidden ancestry, per-delivery operation-v1, all 23 r6 findings, every earlier F report and original task mapping. Both output formats execute identical checks. Missing ignored dist sources do not break validation; mappings are traceability, not semantic proof.

### V.2 Four-peer atomic execution and recovery

Deliverable: Exercise representative real direct/prepared/Kotodama/SDK transactions and anchored AXT on a fixed four-validator candidate, extending each product's own network controls.

Acceptance: Verify finality, exact authority, replay, queued-result correlation, batch rollback, retained current history and crash/restart. Preserve signed RS16 and exact Sumeragi committees/quorums; protocol fault mutations run in the deterministic simulator. No aggregate test result grants activation authority.

### V.3 Complete proof and relation evidence

Deliverable: Re-run all retained product relations, complete IVM and ordinary/AXT proofs against exact current source/profiles and canonical fixtures.

Acceptance: Keep real maximum proofs, direct witness/constraint mutations, malformed input, serialization and resource cases; preserve every substantive assertion. Report passed/failed/unexecuted separately. A changed artifact cannot inherit an old pass or be qualified by enum counts.

### V.4 Independent security and hardware evidence

Deliverable: Review soundness, zero knowledge, Fiat-Shamir/qROM/composition and side channels, and measure actual supported scalar/accelerator platforms.

Acceptance: Findings identify source/profile/artifact and concrete attack or assumption. Missing evidence remains visible. This work does not supply an activation token, approve transactions or block unrelated implementation.

### V.5 Integrated product and retirement evidence

Deliverable: Run combined installed product flows and verify every retained requirement, old backend/driver/route retirement and first-release history boundary.

Acceptance: Actual native artifacts, four-peer effects/restart/replay, capability-scoped SDK results and remaining device gaps are recorded. No global manifest, source hash, review signoff or aggregate conformance result controls runtime availability.

### V.6 Candidate evidence and documentation reconciliation

Deliverable: Reconcile changed-source tests, build/lint/format/codec/ABI and SDK results, current blockers and public documentation.

Acceptance: An evidence record states what is implemented, tested, failed and unknown; no automatic release-readiness claim. Review completion is not a runtime admission predicate or deployment activation gate.

### B.1 Reusable FASTPQ AIR interface and migration inventory

Deliverable: Expose typed semantic AIR, field, public-IO, work-limit and observer interfaces over the current q77 engine; enumerate every production consumer and duplicate owner.

Acceptance: Inventory ordinary/AXT, RaceV1/classed RaceV1, all IVM step chips, generic verification, SoraCloud VK/BFV, X509 MAIN/CA, notes/PQ-MASP/settlement/ZK-ACE and conditional ZK-AMS qPCS. Keep Halo2, Bulletproofs, lattice PCS and Spartan/Nova distinct.

### B.2 Shared STARK engine and checked security accounting

Deliverable: Generalize actual field/AIR/composition-DEEP/masking/commitment-multiproof/FRI/transcript-grinding/allocation/acceleration code into one owner; unify checked work-security and FRI theorem accounting including commitment error.

Acceptance: Resolve fold/rate omissions; test transcript and relation/constraint mutations, honest/adversarial corpora, bounded allocation, device-failure cleanup and actual maximum shapes. CPU/ARM/Metal/CUDA semantic proof/root parity uses fixed randomness where defined; algebraic sums alone do not establish Fiat-Shamir or hiding.

### B.3 Exhaustive shared-backend consumer replacement

Deliverable: Migrate every B.1 source importer, helper, test/fuzz target, CLI trace builder, limit, observer and accelerator utility; delete each duplicate only after its actual callers move.

Acceptance: Per-role migration ships with that capability and no consumer waits for aggregate deletion. Final inventory is empty of duplicate production semantics, not empty through lost consumers; workspace builds and preserved behavioral assertions verify replacement. Refresh proof-byte goldens intentionally without old-verifier branches.

### G.1 Complete authenticated State and root contract

Deliverable: Inventory every authoritative persisted execution table and define one State-owned keyed commitment with inclusion, absence and complete-range witnesses, canonical result-root ordering and atomic publication custody.

Acceptance: Reuse the existing table catalog/publication owner. Specify Sumeragi E51 changes and non-circular result/header/certificate binding. All table mutations must affect the appropriate root; no unowned shadow root or compatibility layout survives.

### G.2 Measure native and in-circuit State candidates

Deliverable: Prototype candidate trees/hashes and measure native update/storage and actual in-circuit inclusion/absence/range witnesses using the AIR interface before selecting the construction.

Acceptance: Compare representative and maximum workloads, proof/verification time, bytes and memory under named hardware/load. Label projections and revise them when actual measurements disagree; benchmark identity freezes each experiment but does not predetermine the winning algorithm.

### G.3 Selected State commitment and publication

Deliverable: Choose and freeze the tree/hash and semantic root schema from G.2; implement complete table coverage, canonical E51/result layout and authenticated atomic publication/recovery.

Acceptance: Final measurements use the frozen selection. Differential dual-root calculation is test-only; no retained LtHash/old-root compatibility branch. Cover crash/publication boundaries, genesis replay, mutation of every table and randomized four-validator root agreement.

### G.4 Carried historical witnesses and committed bounds

Deliverable: Use committed root history, anchor ages and witness/work caps; validate carried witnesses and result openings solely against transaction bytes and current replicated State.

Acceptance: Missing/malformed carried evidence rejects deterministically; missing local Kura/DA/certificate/cache resources defer without rejection/vote and authenticated corruption enters recovery. Test ages 1/W/W+1, cap boundaries, range omissions, empty/different caches, policy changes, retention warnings after replay and W changes, and a named local-validity simulator mutation.

### G.5 Independent WG witness assertion delivery

Deliverable: Ship a small native witness-assertion operation with operation-v1 before AXT or full IVM proof completion.

Acceptance: Four-peer effects, restart/current-genesis replay, inclusion/absence/complete-range adversaries and cache independence pass. Size committed history from measured proving/preparation/submission/inclusion plus margins on loaded and idle chains; configured cadence is not a wall-clock bound. Emergency Fast stays read-only; unimplemented snapshot restore is not a prerequisite.

### M.1 Complete IVM semantic and proof coverage inventory

Deliverable: Inventory all 90 currently listed opcodes, every current and added abi_syscall_list entry, ABI_V1_SYSCALL_METADATA/syscall_name, VmTrapKind and NumericFault against whole-invocation relation obligations.

Acceptance: Default syscall exclusions are empty. Include typed values, initialization, ordering/pointers, calls/copyback, fault/gas/padding, vector/parallel/precompile/continuation/recursion and private masking. Distinguish prepare rejection, interpreter/syscall traps and host invariants; unknown/unmapped semantics keep completion open.

### M.2 Complete native IVM proved-invocation ISI

Deliverable: Prove complete invocation semantics from signed intent, active code/manifest/entrypoint, initialized arguments, finalized context, all read dependencies and exact returns/effects/events/gas; replace the separate IvmProved executable with one canonical native ISI.

Acceptance: Recheck reads against current State before effects. VRF_EPOCH_SEED proves authenticated point/range/absence reads, fallback and conflicts. Cover terminal/faulting outcomes, remove SM feature/local-config semantic switches, and require fresh actual-invocation proofs for later triggers. No re-execution, attestation, different zkVM or stored old-anchor proof substitutes.

### M.3 Full IVM differential and real-proof corpus

Deliverable: Preserve r6's seeded minimums and measure scalar/memory/calls/crypto/storage/AXT representation before optimizing it.

Acceptance: One million programs EACH for scalar/control, memory, calls, faults and whole invocation; at least 1,000 actual proofs per class;10,000 host comparisons per syscall plus an actual proof of each;100,000 random/edge precompile inputs and one million vector/parallel programs. Zero divergences, field/constraint mutations, hardware parity and operation-v1 four-peer invocation/restart; do not delete semantics to fit budgets.

### R.0 RAM-LFE roles leakage classes and policy

Deliverable: Specify program owner/evaluator, encryption-key owner, authorized opener and validators/collusion; exact plaintext/class semantics, function/initializer commitments, canonical V1 policy/receipt/opening and cleartext reference. Require a proved normalizing lowering with one fixed public schedule per class profile padded to the class maximum.

Acceptance: Bind full authoritative policy, function identity independent of key rotation, keys/profile/class/semantic relation, network/beneficiary, initialized memory, ciphertexts, receipt, expiry and replay. State resets within each execution; persistent cross-request mutation needs its own authenticated prior/next-state order and is outside this contract. Logical rank bounds ciphertext multiplication depth, not physical noise; instruction-by-instruction evaluation of the existing candidates does not hold the maximum shape. Specify semantic equivalence and fixed-schedule leakage obligations for the normalizing lowering.

### R.11 Circuit privacy and client well-formedness

Deliverable: Implement a concrete circuit-private evaluation/sanitization construction with one fixed public schedule per class profile padded to the class maximum and client proofs of admitted ciphertext/key well-formedness and input constraints from the first usable slice.

Acceptance: Separate encryption secrecy, hidden-function privacy, proof ZK, output authorization and opening guarantees. Test malicious/adaptive inputs, timing/access/proof-shape leakage and evaluator enumeration; keep the identifier PRF key outside evaluator custody and enforce authorized-query policy. Ordinary FHE or ZK alone cannot hide ciphertext/output leakage. Preserve secure randomness and clearing ownership; test key/witness/program erasure on success, error and unwind. Establish circuit privacy and the leakage bound for normalized evaluation under the fixed public schedule, including maximum-shape physical noise and sanitization.

### R.8 Verifiable decryption opening and identifier PRF

Deliverable: Prove that the exact evaluated ciphertext decrypts to the committed ordered output and registered opening/PRF key commitment; compose output authorization and phone-nullifier derivation under one statement.

Acceptance: Test swapped ciphertext/output/key/context/beneficiary, unauthorized opener, wrong PRF and canonicality. Opener/resolver/committee signatures never replace decryption, execution or derivation proofs. Verification uses the same semantic verifier at preflight, final ISI and persisted-state admission.

### R.12 General affine execution and opening delivery

Deliverable: Ship general ramLfe.execute through a native execution/result ISI, genuine proof, required verified opening and actual result using operation-v1; register supported policies without activation.

Acceptance: All SDK/direct/prepared/Kotodama routes cover local encryption, evaluation, proof/preflight/opening, four-peer result, cold restart/full canonical replay and pending/cancel/recovery. It does not depend on phone credentials, bounded programs, refresh, threshold, X509, full IVM proof or SoraCloud. Deliver proved normalized affine execution under one fixed public schedule per class profile padded to the class maximum, with maximum-shape correctness, physical noise and leakage evidence.

### R.7 Bounded RAM-LFE class and usable flow

Deliverable: Implement bounded.v1 with all eleven tape instructions including Mul and complete SelectEqZero lowering, actual operand depth/equality exponentiation/select multiplication and a derived leveled noise/work plan. Prove the normalizing lowering preserves bounded semantics under one fixed public schedule per class profile padded to the class maximum.

Acceptance: Prove class membership, all tape/slot/register/memory/depth/output limits, integer/RNS carries/quotients/rounding/key switching, malformed private transitions and class substitution. Extend operation-v1 immediately, including opening and any available threshold mode; refresh remains independent later work. Demonstrate maximum-shape correctness and physical noise/work bounds; logical rank bounds ciphertext multiplication depth, not physical noise.

### R.9 Refresh RAM-LFE class and usable flow

Deliverable: Implement refresh.v1 with genuine noise-reducing refresh plus its complete hidden-program proof, limits between refreshes and total refresh count; extend the same native/SDK path. Prove the normalizing lowering preserves refresh semantics under one fixed public schedule per class profile padded to the class maximum.

Acceptance: Demonstrate repeated refresh and correct output/noise on maximum supported workloads with opening, class-substitution and malformed-witness controls. Adding encrypted zero is not bootstrap. Failed cost projections trigger construction work; refresh stays mandatory and supported-class threshold tests extend with this slice. Prove physical noise bounds and fixed public refresh scheduling without exposing the private logical refresh schedule; logical rank bounds ciphertext multiplication depth, not physical noise.

### R.10 RAM-LFE threshold opening delivery

Deliverable: Integrate verifiable threshold shares, bounded combining, consent/custody and key epochs into the same RAM-LFE opening/PRF statement and operation-v1.

Acceptance: Support every implemented class, extend test vectors when bounded/refresh land, reject bad/missing/duplicate/wrong-epoch shares and bind request/ciphertext/policy. Threshold can ship for affine before refresh. Retire the superseded single-authority mode when committee mode replaces that role; no signature substitutes for proven shares.

### C.8 Shared bootstrap arithmetic and complete proof

Deliverable: Implement published genuine noise-refresh arithmetic with complete RNS/rounding/key-switch relation below RAM-LFE and SoraCloud applications.

Acceptance: Actual repeated-refresh decryption/noise vectors and maximum proof/work/custody tests validate one shared owner. Consumers keep distinct program/job statements; this task has no RAM-LFE application or threshold dependency.

### C.9 SoraCloud add multiply rotate and role integration

Deliverable: Ship genuine add/multiply/rotate with ordinary input-admission/public-key relations and shared role schema/dispatch. Inventory all four witness AIRs and five typed roles, assigning bootstrap key/full-execution/arithmetic implementation to C.8/C.6.

Acceptance: Operation-v1 covers ordinary job input/output/keys/profile/effects and model/Core/Torii/restored-State with a regenerated refusal census. Role substitution/public-padding proofs reject. Bootstrap-specific success/restore closure belongs to C.6 and does not delay this slice. Validator work is deterministic/bounded; offload needs genuine proof, and bounded key custody is cache-independent.

### X.5 Shipping holder-controlled X509 prover

Deliverable: Provide wallet/mobile/desktop/server proving with subject signing key retained by the wallet, paired-host enrollment, mutually authenticated encrypted handoff, exact job binding and local verification.

Acceptance: Test host substitution, MITM, replay/tampering, host revocation and witness erasure; document compromised authorized-host leakage. Measure actual supported-device memory and server worker configurations. A shipping holder-controlled path is part of X.4, not an optional benchmark tool.

### X.6 X509 CRL publication and temporal lifecycle

Deliverable: Implement deterministic newest-eligible CRL selection and supersession across merged CRL/policy/anchor events; derive end-to-end deadlines from signed CA times, earliest certificate expiry and public presentation window.

Acceptance: Budget observation/preparation/proving/publication jitter/submission/clock margin; test deterministic sequential/overlapped selection, spacing/skipped CRLs, withholding, slow issuers, near expiry and merged-event starvation. Resolve quiet-chain semantics: no empty blocks or claimed 300-second wall-clock freshness from blocktime/wallet TTL alone. Native temporal controls cover date boundaries, same-block order, revocation precedence and permissions; X.4 owns final maximum-proof/rollover network measurements.

### T.1 First-release history and coherent cutover

Deliverable: Preserve replay of the current canonical genesis/schema; deliberately incompatible first-release changes regenerate fixtures/manifests/ABI artifacts and define fresh-genesis testnet cutover or contract redeployment as appropriate.

Acceptance: Never add old-layout decoders/verifier branches/migration shims or claim old history replays in a new incompatible binary. Retain current-genesis cold restart/full canonical-block replay; authenticated snapshot restore is separate unfinished work and not a gate. Editing this plan authorizes no live reset/deployment. Retain diagnostic evidence of obsolete histories without shipping their decoders; a future authenticated checkpoint specifies its verified suffix and cannot retroactively validate discarded history.

### E.1 Reproducible phase and resource harness

Deliverable: Provide one complete phase tree for proof/verification/native/SDK flows with inclusive/exclusive wall and CPU times, worker count/load, allocations/live buffers, ciphertext/key/proof bytes, peak RSS and enforced address-space observations.

Acceptance: Unattributed proving time is at most 1%; record cache/warm-cold policy, named reference hardware, source/artifact/profile/config identity and raw failures. Separate projections, local scheduling and consensus limits. Salvage only unchanged scoped evidence; generated logs remain untracked and evidence cleanup cannot erase failures. Never record private witnesses, secret keys or hidden programs; include device thermal state where applicable.

### P.7 Kaigi authorization and usage delivery

Deliverable: Complete authorization/usage relations, retained account participation, canonical key/schema/HPKE binding, bounded accounting and authenticated relay recovery. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Test backend/semantic-role/key substitution, authorization/usage lifecycle, revoked participants, replay and rollback. Canonical native digests and committed relation-selecting VK identities cannot depend on local config; private material is never logged.

### P.8 Complete private election delivery

Deliverable: Complete credential-linked ballots and closed-corpus tally relations, correct backend/role dispatch, nullifiers, weights/revotes, encryption and key custody across the real election phases. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Replace the unconditional ballot rejection with real relations and permissions, not a removed safety check alone. Test invalid credential/weight/tally corpus, replay/revote rules, deadlines, custody and restoration; one call exposes durable distributed progress without pretending one consensus round.

### P.9 Confidential asset delivery

Deliverable: Complete the existing Halo2 circuits and native shield/transfer/unshield flows with amount, ownership, conservation and unlinkability semantics. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Preserve optional-input behavior without caller-supplied dummy witnesses. Exercise malicious amounts/authority, nullifier reuse, reserve/issuance limits, cross-asset attacks, full redemption and prepared/Kotodama batch rollback.

### P.10 Anonymous PGC bootstrap and payment delivery

Deliverable: Complete existing bootstrap AND payment relations and ledger integration with anonymity/recipient bounds, malicious-party controls and complete wallet behavior. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Exercise issuer/recipient/authority substitutions, malformed public keys, ranges, replay and lifecycle. Do not count bootstrap alone as PGC completion or use all-product readiness to hide an implemented payment path.

### P.11 VeRange ledger composition delivery

Deliverable: Deliver named typed range verification and a specified ledger-composition operation with bounded aggregation and explicit composition soundness. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Canonical statement/range/aggregation limits and adversarial witnesses reject; the native primitive returns typed verification without invented financial effects. The composed ledger use checks current authority and cannot reuse a prior generic verification token.

### P.12 Jindo polynomial commitment delivery

Deliverable: Complete native polynomial commitment/verification with checked qROM extractor loss, polynomial-count limits and a real typed ledger use. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Exercise count/degree/context/role substitution and false openings, maximum aggregation and verifier resources. State the actual security model; arithmetic thresholds or unbound uploaded keys cannot be advertised as a complete extractor/composition argument.

### P.13 Bootle Lantern credential delivery

Deliverable: Complete specialization reduction, parameter/sampling construction and native issuer register/rotate/revoke plus issue/present operations. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Test malicious samples/keys/issuers, credential binding, stale revocation, replay, custody and privacy. Registration creates immediately usable valid policy state; independent reduction/review evidence does not become a runtime activation switch.

### P.14 Vega Figure 9 credential delivery

Deliverable: Complete governed credential keys, rotation, independent vectors and full Figure 9/age-proof behavior with typed issuance/presentation. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Use authentic key/credential/proof vectors at maximum supported shape and test age/range/issuer/policy/context substitution, revocation, replay and private witness erasure. Scope security labels to the actual weakest property.

### P.15 ZK-ACE authorization delivery

Deliverable: Move every authorization caller to the shared FASTPQ adapter, complete qROM/multi-target derivation and select identity/replay in-circuit digests from actual server/device cost and security analysis. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Test full six-lane identity/replay semantics, malformed roles, private-witness/constraint attacks and authoritative current policy. Missing cryptographic evidence remains explicit; no qualification signer or all-protocol manifest gates completed runtime paths.

### P.16 Orchard shield transfer unshield delivery

Deliverable: Use canonical current Orchard vectors for full shield/transfer/unshield, exact per-pool turnstile and explicitly committed supply/issuance caps. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Test ownership/range/conservation, authorized issuance, reserve overdraw, wrong pool/asset, nullifier reuse and later-action rollback. A pool cap bounds its declared public exposure, not every hidden relation defect.

### P.17 FCMP++ wallet transfer delivery

Deliverable: Complete full wallet transfers, membership/range/linkability/conservation and all input/output boundaries; specify any added public bridge rather than assuming one exists. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Test cross-authority and cross-asset attacks, maximum rings/actions, nullifier/key-image reuse, malformed inputs and private conservation. If a bridge is implemented, exact reserve/issuance checks and isolated exposure bounds are mandatory.

### P.18 IVM private note delivery

Deliverable: Provide one shared FASTPQ adapter with in-relation spend authorization, unlinkability, action/asset conservation and complete note lifecycle; implement the chosen encryption design. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Preserve public reserve accounting and distinguish existing X25519 confidentiality from PQ claims. Test ownership/program/authority, dummy-free redemption, malformed note/proof, replay and cross-asset leakage; state the weakest combined security property.

### P.19 PQ-MASP delivery

Deliverable: Provide one shared FASTPQ adapter and complete spend authorization, unlinkability, action/asset conservation and wallet flow while preserving existing ML-KEM encryption. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Test all private action/asset boundaries, nullifier/range/ownership mutations, ciphertext/proof binding and cross-authority attacks. Any new public bridge gets a specified reserve/issuance contract; do not silently replace PQ encryption with a classical path.

### P.20 Atomic private settlement delivery

Deliverable: Complete the full settlement flow with in-relation authorization, balanced effects, source/custody binding, unlinkability, chosen encryption and native/SDK final-result recovery. Ship operation-v1 with genuine maximum proofs, direct witness/constraint mutations, all supported SDKs, four-peer effects and current-genesis restart/replay.

Acceptance: Distinguish the settlement hybrid audit wrap from note encryption. Test participant/amount/source substitutions, atomic failure, durability/replay and native four-peer recovery; measure actual proof-through-settlement latency and retain current targets without treating local elapsed time as consensus validity.

### F.5 Canonical crypto primitives and dependency replacement

Deliverable: Implement the selected canonical native digest consistently across catalog commitments, Kaigi authorization, confidential spentness, MKHE proof hashes, schemas, SDKs and fixtures; complete BN254 Poseidon parameter correction and replace obsolete PQ-library dependencies.

Acceptance: Independent deterministic vectors and role/context substitution tests cover actual consumers; update manifests/lockfile together and remove superseded implementations directly. Security labels reflect each actual weakest composition. Digest choice remains semantic committed profile data, never a source-file identity.

## Reconciliation and plan checks

The tracked reconciliation distinguishes retained requirements from corrected
requirements. Corrections include expiry semantics, graph edges and documented
first-release replacements; no required product is silently descoped. Finding
dispositions mean addressed in this development plan, not fixed in executable code.
The prior report ledger preserves carried and user-superseded dispositions without
treating all raw reviewer reports as distinct defects.

Run:

```sh
python3 scripts/check_zk_delivery_plan.py
python3 scripts/check_zk_delivery_plan.py --format json
python3 -m unittest discover -s scripts/tests -p check_zk_delivery_plan_test.py
```

A task leaves `planned` only with recorded `evidence`, which has four fields:

- `source`: text containing the observed 40-hex commit id.
- `paths`: repository files outside ignored build and archive trees (`dist`,
  `target`, `.git`, `__pycache__`, `node_modules`, `build`). Each is a regular file
  that resolves inside the repository. The checker does not examine Git tracking.
- `commands`: entries of `command` and `outcome` (`passed`, `failed` or `not_run`).
- `acceptance`: entries of `clause`, `state` (`met`, `partial` or `unmet`) and `proof`.

A clause is exactly one whole sentence of the task's Deliverable or Acceptance text,
recorded once. A proof cites at least one recorded path or command verbatim.
`in_progress` records any nonempty subset of sentences and admits partial, failed and
unexecuted items. A command entry may additionally contain `platform_todo` with
`platform` (`windows`, `linux`, `physical_x86_64` or `cuda`), `reason` explaining
required execution unavailable on the development Mac, `todo_site` containing `path`
and `marker`, and `owner` (`H.3` or `V.4`). The containing `command` is the exact runnable
command, including required working directory and configuration. The TODO path must
appear in evidence.paths; its marker must uniquely identify literal `TODO:` text in
that file. Only unavailable platform execution qualifies; implementation and runnable
checks must already exist. Outcomes remain `passed`, `failed` or `not_run`; acceptance
states remain `met`, `partial` or `unmet`. An unexecuted deferred check stays `not_run`.
`implemented` requires every sentence recorded, all implementation complete, every
required check recorded, every prerequisite implemented, and every recorded path and
command cited by a proof. Each sentence must be `met`, or `partial` solely because
its proof identifies valid platform TODO commands covering its entire remaining gap;
every other check must have passed. Failed checks prohibit `implemented`. A TODO
remains open until actual execution of its exact check on the required platform passes
with valid current-candidate evidence; retain failures and closure evidence. Neither
H.3 nor V.4 may be `implemented` while any TODO remains open anywhere in the graph.
Both checker formats validate these rules and print `open_platform_todos` counts for
every task, including zero, and a global total, counting each originating command once
without owner/dependent duplication; also list each open item's metadata and outcome.
TODOs never count as passed checks or platform qualification. Return a task to
`in_progress` when later changes invalidate its qualifying evidence. Graph status stays
`ready_for_development`; a recorded status is traceability and grants no runtime permission.

Both formats use one validator and exit status. Checks cover graph integrity,
true roots, reachability, required/forbidden ancestry, per-delivery SDK/ISI contracts,
exact plan/graph text including task headings and the roots and counts stated above,
each stated once word for word
(no other heading, emphasized line or first table cell may name a task or delivery ID),
recorded task status and evidence, all original requirement/report/task inventories
and their recorded counts, source provenance and valid replacement-task mappings.
The ignored originals are not read. The plan is read as lines of text: HTML blocks,
comments, code fences, multi-line titles, pipe-less table rows and restatements in
other words are not interpreted, so review still reads the rendered plan.
Passing these checks establishes structural and traceability consistency only;
semantic review and implementation acceptance tests remain necessary.

First development changes should consume this graph, re-read their current source
owners and implement the smallest complete capability slice. Keep the four settled
directions, user-approved phone-provider choice and first-release replacement policy
intact. Revise a task when actual construction or measurement disproves an assumption,
retaining the required outcome and recording the concrete change.

Outputs so far name where landed work lives. The graph alone records status and
evidence, and a listed path qualifies nothing. For V.1 they are
`scripts/check_zk_delivery_plan.py` and
`scripts/tests/check_zk_delivery_plan_test.py`. For X.1:
`specs/zk_x509_presentation_interval.md`,
`specs/zk_x509_presentation_interval_sites.json`,
`fixtures/zk/x509/interval_vectors_v1.json`,
`crates/iroha_data_model/src/privacy/zk_x509_interval.rs` and
`scripts/check_zk_x509_presentation_interval.py`. For B.1:
`crates/fastpq_prover/src/backend/air.rs`,
`specs/fastpq/shared_backend_inventory.json` with its guide
`specs/fastpq/shared_backend_inventory.md`, and the check
`crates/fastpq_prover/tests/shared_backend_inventory.rs`. For M.1:
`crates/ivm/src/proof_coverage.rs`, the generated
`crates/ivm/docs/proof_coverage_inventory.json` and its guide
`crates/ivm/docs/proof_coverage.md`. For T.1:
`specs/first_release_history_cutover.md`,
`specs/first_release_history_cutover.json`,
`scripts/check_first_release_history.py` and the pinned history under
`fixtures/core/first_release_history/`. For C.1:
`specs/fhe_ownership_inventory.json` and
`scripts/check_fhe_ownership_map.py`. For R.0:
`specs/ram_lfe_execution_proof.md`, the canonical types in
`crates/iroha_crypto/src/ram_lfe/canonical.rs` and
`crates/iroha_data_model/src/ram_lfe.rs`, and the cleartext reference
`crates/iroha_crypto/src/ram_lfe/reference.rs`. For G.1: section 16 of
`specs/sumeragi.md`, `specs/state_table_inventory.json` and
`crates/iroha_core/src/state/authority_registry/keyed_commitment.rs`. For C.2:
the crate `crates/iroha_fhe/`. For E.1: the crate `crates/iroha_measurement/`,
`scripts/zk_resource_harness.py` and
`crates/iroha_core_privacy/tests/fastpq_phase_tree_measurement.rs`. For F.2:
`specs/zk_resource_contract.json`, `scripts/check_zk_resource_contract.py` and
`crates/iroha_data_model/tests/resource_contract_v1.rs`. For C.3: the module
`crates/iroha_fhe/src/bgv/`, `specs/fhe_bgv_cost_summary.json`,
`scripts/fhe_bgv_cost_model.py` and the known-answer reference
`crates/iroha_fhe/tests/vectors/bgv_reference.py`. For G.2:
`specs/state_commitment_candidates.json`,
`scripts/check_state_commitment_candidates.py` and the development-only
prototypes in `crates/fastpq_prover/src/state_commitment_prototypes/`. For F.4:
`crates/iroha_data_model/src/zk_validity_policy.rs`,
`crates/iroha_data_model/src/pipeline_validity_policy.rs`,
`specs/zk_runtime_validity_census.json`, `scripts/check_zk_runtime_validity.py`
and `scripts/check_zk_feature_parity.py`. For F.1:
`specs/zk_operation_inventory.json` and
`scripts/check_zk_operation_inventory.py`. For H.1:
`specs/zk_primitive_workloads.json` and
`scripts/check_zk_primitive_workloads.py`.
