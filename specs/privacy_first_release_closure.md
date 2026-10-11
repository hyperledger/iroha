# First-release privacy and ZK closure

This ledger owns final V1 privacy implementation and qualification. It is not
an audit certificate or permission to activate an unqualified protocol. The
[ZK first-release goals](zk_first_release_goals.md) track current proof blockers;
[IVM-only policy](../docs/ivm_only_validation.md) governs the single VM and codec
surface. Independent reviews, complete authoritative source binding, fixed
resource limits and source-bound deployment qualification remain mandatory.

## Final interface contracts

- IVM is the sole Iroha virtual machine. Kotodama produces IVM bytecode (`.to`);
  Wasm/WASI runtimes, SDK adapters, compiler paths and build artifacts are
  prohibited. Final V1 interfaces have no compatibility aliases or decoders.
- One ordered Exact12 catalog, one V1 proof envelope, exact protocol/proof-system/
  engine tuples, and one weakest-composition security model per protocol.
- One native path for every Exact12 role. `PrivacyProofEnvelopeV1::bind_v1` is
  the only assembler of an envelope and derives the protocol, proof system,
  engine, artifact identities and statement digest from the typed statement.
  `SubmitPrivacyProofV1` is the only instruction that carries an envelope. Its
  handler resolves the one role of the envelope (`PrivacyActionRoleV1`,
  thirteen roles), calls the single verifier dispatch and applies the one
  effect sealed for that role. A role without a complete native verifier
  returns a typed `UnsupportedOperation` error from the dispatch; it never
  succeeds and does not depend on an activation record.
- Privacy STARK outer commitments and transcripts use SHA3-384 with one
  checked byte frame and opaque 48-byte digests. Fp4 values retain four canonical
  coefficients and an exact 32-byte encoding. Compiled privacy tuples admit
  only `stark-fri-sha3-384-goldilocks-v1` with
  `native-goldilocks-sha3-384-stark-fri-v1`. Execution STARK, FASTPQ, BFV and
  inner identity/replay constraints keep their separately specified primitives.
  SHA3-specific compiled values, complete proofs, SDK artifacts, CPU/ARM parity
  and commitment/Fiat--Shamir soundness require fresh qualification. The FRI
  algebraic bound is not a complete hash or qROM claim; ZK-ACE remains unavailable
  until its existing certification gate passes.
- The local compiled-profile catalog conveys build metadata. Production
  availability additionally requires committed activation and the complete
  signed release/deployment qualification matching that activation.
- The final privacy-intent validator requires the statement network to equal the
  transaction network domain, even after both intent and statement digests are
  recomputed. Genesis-only transactions cannot carry a final privacy submission.
- The capability archive keeps its 256 KiB outer limit. Nested decode budgets
  must admit the required 48 stage receipts, 54 proof artifacts, audit records,
  signatures, and four-validator deployment record while retaining explicit
  sequence, allocation, field, and depth ceilings. Catalog cardinality is checked
  separately from the nested sequence budget.
- The C bridge has six privacy symbols: compiled-profile getter and validator,
  Exact12 fixture getter and validator, capability-manifest validator, and buffer
  free. The capability validator accepts supplied bytes and returns the shared
  Rust validation status. It does not obtain or synthesize network state.
  Swift and C# must call it before projecting a manifest or issuing admission;
  an old library without the symbol is unavailable. No managed validation
  fallback can establish production qualification.
- IPA supports only the binding Pallas and BN254 commitment groups. The additive
  Goldilocks test module, public types and optional features are removed from
  the proof crate and all Core/IVM/Torii consumers. Goldilocks remains the STARK
  field identity; IPA decoding rejects it before group arithmetic.
- Retired layouts, aliases, signatures over obsolete payloads, and old proof
  artifacts cannot be accepted as alternate V1 paths.

See [proof envelopes](zk_envelopes.md), [FASTPQ](fastpq_plan.md), and
[audit dispositions](zk_cryptographic_audit.md) for implementation details.

## Exact12 implementation map

An implemented engine or available compiled profile in this table is not a
production-qualified protocol. All rows still require same-candidate release,
independent audit, SDK, hardware, and deployment evidence. The
[operation inventory](zk_operation_inventory.json) pins each row's dispatch
arm, native verifier, compiled-profile arm, ledger effect and named tests
against the source, and records for each protocol separately whether it is
registered, verified, effective and delivered, and whether a test that runs
by default calls its verifier. Its `exact12.roles` list repeats the typed
dispatch registry (`PRIVACY_ROLE_DISPATCH_TABLE_V1`) role by role, and
`exact12.single_route` fails the check when a second assembler, instruction,
dispatch call, native-verifier caller or effect consumer appears. The
[economic invariant matrix](zk_economic_invariants.json) records, for each
value-bearing row, the ledger checks that hold whatever its verifier returns,
what stays exposed when a proof is accepted wrongly, and the open defects of
its issuance, exits and suspension switches.

| Protocol | Current source observation | Remaining outcome |
| --- | --- | --- |
| ZK-ACE | Dedicated masked STARK; six identity lanes and six replay lanes, 8x LDE, Fp4 FRI and 136 distinct queries. Activation unavailable. | Complete qROM reduction, multi-target accounting, independent implementation review and final artifacts. |
| Anonymous PGC | Native P-256 bootstrap and payment relations, including twisted-ElGamal legality. | Full maximum-shape, malicious-party, resource and release qualification. |
| VeRange | Native P-256 range profile and typed component surface. | Same-candidate range, composition, resource and release qualification. |
| ZK-AMS | Native40 qPCS/FRI roots and staged transcript use the shared six-lane owner and [sole three-section V1 wire](crypto/zk_ams_rns_native_wire_v1.md). Source packing retains both native48 anchors. One 72,386-entry inventory replaces disconnected commitment owners; original fallible entropy continues through source and authenticated D/S preparation. The repaired fixture-based direct-proof suite passes all 34 tests on ordinary stacks, including four actual 16,384-gate proofs. Actual source replay and composite MKHE admission remain unavailable, and full qPCS hashing exceeds the unchanged work cap. | Complete actual source/prover and composite admission, a reviewed qPCS commitment/evaluation design within whole-proof resource bounds, malicious-party, decryption-share, phase-2/3 and full-size release-KAT gates. Fixture proofs do not qualify a production source. |
| Vega | Credential relation and Figure 9 key-install machinery exist; compiled profile unavailable. | Full-shape governed keys, independent proof vector and complete Figure 9 qualification. |
| ZK-X509 | The joint original-polynomial MAIN/CA relation removes public intermediate terminal values and retains source-bound key/digest joins. The recorded source17 maximum proof and fresh verifier pass byte and enforced address-space limits; proving time and RSS-observer consistency fail. Activation is unavailable. | Qualify the complete relation, nonce-scoped transcript privacy, regenerated profiles and current maximum proof under the unchanged 9,437,184-byte and resource limits. Component acceptance does not establish soundness or zero knowledge. |
| Jindo | Native Figures 2–7 implementation with 32 signed-monomial repetitions. | Reviewed qROM extractor certificate, exact adversarial/max-shape evidence and production qualification. |
| Bootle/Lantern | Native lattice anonymous credential and Falcon issuer implementation. | Independent arithmetic/sampling/custody review, issuer lifecycle, maximum-shape and release qualification. |
| Orchard | Sole Orchard/PostNu6_3 profile with two-pass preparation and authorization. | Audited parameter/proof provenance and full native/SDK/network qualification. |
| FCMP++ | Native membership, generalized Bulletproofs, ranges, linkability, conservation and wallet paths. | Complete maximum-shape, cross-authority, resource and release qualification. |
| IVM private note | Native profile and lifecycle integration exist. | Shared STARK soundness/qualification, program/authority adversaries, SDK and network evidence. |
| PQ-MASP | Native note/AIR/profile and lifecycle integration exist. | Shared STARK soundness/qualification, full action/asset conservation, SDK and network evidence. |

The X509 candidate uses the shared 136-query, eightfold-LDE profile. MAIN
retains six native groups under joined base and auxiliary roots with a log-22
LDE. CA pads 104 active rows to 4,096 native rows with a log-16 LDE. The
[joint relation contract](zk_x509_joint_private_relation.md) binds the original
MAIN and CA polynomials without public intermediate terminal products; the
required proof-instance nonce scopes dynamic commitments and transcripts.
Both auxiliary roots precede active composition challenges, and both
composition and FRI-mask roots precede the common DEEP point. All joint
openings precede local mixing. Independent relation and transcript-hiding
qualification remain required.

The canonical descriptors bind the current 192 endpoint, 17 key/digest,
20 SHA-union and 108 CA-link alpha phases after both original auxiliary roots.
They retain the claim-free joint wire and the 39-relation RFC lookup inventory.
The current profile pin and deterministic IO/Projection proof goldens bind this
sole descriptor. Complete current-candidate qualification remains required;
prior profile evidence does not qualify the merged descriptor.

The source17 Linux maximum proof is 9,412,912 bytes and passes native and fresh
verification, wrong-genesis rejection and tampering controls. Its proof and
verifier children stay under the enforced 32 GiB address-space limit. Proving
takes 2,275.987086 seconds against 300 seconds. Live and terminal RSS readings
are below 12 GiB but disagree by 659,456 bytes, failing observer consistency.
The changed nonce-scoped source, current native/SDK fixtures and full maximum
proof still require fresh qualification under the unchanged limits. See the
[current evidence and outstanding goals](zk_first_release_goals.md#zk05--zk-x509).

BFV arithmetic diagnostics reconstruct artifact-bound traces and bounds through
`bfv_full_bootstrap_diagnostic_execution_v1`. They share the witness relation and
retain its parameter, artifact, key and ciphertext checks, but confer no production
qualification. Audited execution rejects `KnownInsecureExactProfile`: the
plaintext-multiple public-key equation loses its noise modulo the plaintext
modulus. Signed review evidence cannot repair that mathematical defect. A secure
replacement and its independent qualification are required; rounded diagnostics
are not a qualified replacement.
The September 23 current-source correction encodes the complete 32-byte BFV
statement hash injectively in eight little-endian `u32` Goldilocks limbs across
38-column trace rows. The former four-`u64` modulo-field encoding aliased
different hashes. A collision regression, governed-trace test, conformance
negative and two byte-identical fixture regenerations pass; the canonical
two-slot material is 890,808 bytes. Core's dependent native-STARK fixture
test now passes. The artifact-aware Core native verifier also replays governed
material and rejects a self-consistent proof with an unselected blind-rotation
coefficient drift; the focused Soracloud test passes. Neither result supplies
hidden-trace low-degree soundness, a full relation, eight-party behavior or the
audited parameter/noise/qROM evidence; production qualification stays closed.
The BFV source-bound target-limb check
now rejects out-of-bound caller-supplied product residues before exact scale-round
or narrowing into target RNS limbs. Positive, negative, right-hand, and
cancelling aliases passed the focused regression, alongside the existing
positive scalar-boundary control. This closes only the source-bound admission
gap; it does not prove those residues came from the claimed BFV operands.

The compiled-profile owner is
[`privacy_profiles.rs`](../crates/iroha_core_privacy/src/privacy_profiles.rs). Engine
implementation markers must not be substituted for the qualification record in
[`release_manifest.rs`](../crates/iroha_data_model/src/privacy/release_manifest.rs).

## Coupled stack requirements

| Component | Completion criterion still required |
| --- | --- |
| Generic native STARK | Current Binding and Explicit paths reconstruct the complete public trace/composition roots and enforce a zero terminal value. A future hidden-trace AIR still needs a verified initial degree/proximity argument; binary fold consistency alone is insufficient. Standalone public-padding verification remains unavailable, and BFV/Soracloud callers must complete explicit material replay. |
| FASTPQ | Core ordinary and AXT wrappers select canonical masked DEEP artifacts with bounded verification, six-lane commitments and the complete typed statement. Current maximum ordinary and AXT component proofs and fresh retained-artifact verification pass unchanged byte/memory/work limits. Finish finalized-source admission/network behavior, independent AIR/FRI, witness-privacy and qROM review, and broader hardware evidence. Component proof acceptance does not qualify finalized authority. |
| AXT | Both Core execution pipelines now commit exact ordered canonical transaction wires; missing block-owned commitments cannot be synthesized from transcript identities. Anchor-bound proof verification checks ordered wire membership, exact public roots and context, and mandatory expiry. Consensus witness roots and transfer-batch trees still commit subsets, which cannot substitute for full persisted WSV roots. Complete successful-execution/transfer binding, rooted state witnesses, immutable anchor resolution and durable spend nonces. |
| BFV/Soracloud | Complete the full BFV-RNS relation, full-size/eight-party KAT, resource measurements and governed parameter/lattice/noise/qROM evidence. The artifact-aware native wrapper is a replay check, not production qualification. |
| MKHE | Complete the separate atomic 40-limb source/materialization/packing/cross-field/padding verifier and production composite within the unchanged qPCS resource limits. Unavailable stages cannot issue receipts. |
| Confidential assets and private settlement | Regenerated canonical proofs/keys, authority/amount/conservation adversaries, complete SDK routes and deployment evidence described by the owning settlement/asset specifications. |
| SoraFS | Complete the V1 closure ledger, live four-voter/multi-provider/dual-gateway L1, all 17 summaries and ordered L2 promotion evidence. Resilience/load observations are optional diagnostics; no fixed-duration soak or full regression suite blocks deployment. |
| Kaigi | Final 31-row authorization and 25-row usage proofs; retained original-account participation, exact keys/schema, suite-tagged HPKE, bounded accounting and authenticated relay recovery. |
| Elections | Complete Parliament private ballot/deadline/retry, finalized-beacon, rollback/restore and independent timed-OVN/threshold-BLS review on four validators. The separate standalone election product also requires final credential-linked ballot and closed-corpus tally relations, key custody, SDK fixtures and native/network qualification; see [the election statement boundary](zk_audit_matrix.md#election-statement-completion). |
| SDKs and fixtures | Rust, Kotlin/Java consumers, Swift, JavaScript, Python and C# use the same final canonical bytes and native admission; signed same-source native packages and target-platform execution. Structural parser/source tests alone cannot qualify an SDK. |
| Hardware | FASTPQ's masked producer dispatches bounded leaf batches through explicit CPU or required-device policy; parent hashes, transcript and polynomial work use CPU. Actual Metal tests cover every leaf oracle and readiness without a CPU fallback. Complete whole-proof hardware/resource evidence, device-buffer erasure, CUDA execution and target-specific side-channel review; earlier scalar-permutation/FFT preflights cannot qualify the final protocol. A feature build or selected mode is not device execution. |
| Release and deployment | Clean signed source/lock/toolchain identity, complete independent audit classes and finding dispositions, real 48-stage/54-artifact evidence, exact four-validator quorum, staged restart/canary/convergence and authenticated endpoint readback. |

The SDK release matrix retains ten consumers in this order: `kotlin_jvm`,
`kotlin_android`, `java_source_kotlin`, `swift_c_bridge`, `javascript_napi`,
`python_pyo3`, `csharp`, `cli`, `openapi`, and `genesis_tooling`.
`java_source_kotlin` requires the Java-source consumer suites against the
canonical Kotlin APIs on **both JVM and Android**, with the original fixture,
rejection, native JNI and platform assertions preserved. Its distinct package
artifact must bind the built Java consumers, exact Kotlin/JNI/Android artifacts,
shared fixture corpus and execution evidence from the same release candidate.
The distinct Java-consumer qualification artifact producer remains pending;
this is evidence about consumers of Kotlin, not a new Java SDK implementation.
Runtime host tests alone do not supply that artifact. Kotlin-only results or
compilation without native/platform execution do not satisfy this row. The
Kotlin JVM and Android rows remain separately required.

The canonical Java-source consumer uses Norito index 10. The retired mirrored
Java Android consumer index 2 and JSON tag `java_android` are rejected; there is
no alias. The other nine indices remain 0, 1 and 3 through 9. The nominal type
identity stays `PrivacyReleaseSdkConsumerV1`; its generated structural descriptor,
qualification artifacts and their dependent signatures must be regenerated and
validated against the changed wire contract. The explicit
`PrivacyExact12QualificationRecordV1` schema root publishes the complete native
qualification closure. A label/source update is not SDK or release qualification.

## Verification discipline

Core protocol fixtures bind the runtime `NetworkId` to their synthetic committed
genesis. Native payment and FCMP state tests exercise the shared submission
preparation and execution stages with an exact compiled activation; the shipping
instruction handler separately requires registered Exact12 qualification before
entering execution. A missing-qualification regression checks that an active
profile alone cannot mutate payment state or budgets. X.509 governance coverage
keeps block overlays in separate lifecycle stages to bound the default test-stack
footprint while retaining the complete atomicity and terminal-state assertions.

Anonymous-PGC bootstrap and payment range proofs retain their fixed-size point
and scalar arrays on the heap. Their codec uses the single canonical fixed-array
layout and charges the owned storage against the decode allocation budget. This
bounds the size of nested proof values during native verification; ordinary
worker stacks must suffice without increasing the thread stack or relaxing
proof dimensions, canonicality, or resource limits.

Focused regressions distinguish malformed geometry, layout-dependent transcripts,
noncanonical field representatives, invalid AIR stride, incomplete evidence and
missing native authority from honest canonical inputs. Synthetic signed manifests
test validation logic only; they never represent deployed validators, actual
proof runs, independent auditors or hardware measurements.

The full workspace/feature, SDK/native, audit and four-validator qualification
matrix remains open until it passes against one immutable candidate. Local tests
and extracted arithmetic harnesses are reported with their actual scope. Failed,
blocked, ignored, timed-out or unavailable runs cannot be recorded as passes.

## Current compact execution evidence

The 2026-09-08 coordinated locked/offline build passes all 16 selected test
artifacts without source drift. All 27 exact pre-proof checks pass, covering
fixed geometry, six-lane context/tape known answers, canonical coordinates,
permanent sampler abort, explicit decode budgets and unchanged AIR equations.
The primitive library passes 60 tests (one timing diagnostic ignored), and the
ordinary offline-consumer target passes all eight tests. These are scoped local
runs, not a complete workspace or release qualification.

The actual ordinary and AXT full-domain quantity-transfer proof tests both pass.
Retained proofs contain 3,994,619 and 4,015,551 bytes; proving takes 295.71 and
329.91 seconds, bounded verification 23.84 and 22.82 seconds, and each run peaks
at about 2.49 GB resident memory. Both verify 375 AIR openings and one terminal
degree check after private data is dropped; altered quantities, authority,
identity, truncation and allocation limits are rejected. Source and executable
hashes remain unchanged. The actual ordinary two-segment bundle also passes
with a separately retained 7,986,384-byte artifact: proving takes 608.46 seconds,
verification 43.84 seconds, and peak resident memory is 2.57 GB. Both child
transcripts, 750 AIR openings and two terminal degree checks are verified under
the bundle's own identity. The separate AXT bundle passes with 8,011,999 bytes,
560.55 seconds proving, 45.99 seconds verifying and 2.57 GB peak resident memory.
It checks its own two transcripts, 750 AIR openings and two terminal degree
checks. Fresh transport fixtures remain pending; single proofs cannot substitute
for bundle-bound artifacts.
The complete-row format exceeds the 512 KiB production and 1 MiB AXT limits:
even the necessary raw row openings account for 1,050,000 bytes. The default
32 MiB decode allocation budget is unchanged; a synthetic largest-shape test
uses an explicit 64 MiB diagnostic scope and proves default-budget rejection.
Neither that scope nor mathematical profile checks authorize production use.

The three mathematical checker entry points now share 28 exact executable,
specification and implementation inputs, with pre/post equality and seven
changed/omitted-input controls. Typed, all 128 bundle-size and historical theorem
checks pass privately; the live typed check reproduces the identical report.
Independent comparison preserves the reviewed arithmetic. These are conditional
model calculations and source provenance, not concrete cryptographic qualification.

Four saved-proof regression tests now pass in 136.85 seconds, checking each
retained single/bundle hash, canonical frame, ordered roots and exact work. They
also require precise rejection at the unchanged production byte/allocation
limits. Their individually emitted binary comes from the failed expanded
SoraFS build; the overall compilation failure remains recorded separately.

The final ordinary and AXT context owners each pass 1,635 actual Metal hash
comparisons, including all six lanes, every oracle level and all 931 field-tape
blocks. Three descriptor, thread-isolation and cleanup controls also pass.
The M1 Ultra runs take 9.63 and 15.00 seconds with 28.9 and 29.9 MB peak RSS.
Inputs are deterministic full-width payloads under the real statement contexts;
these are hash parity tests, not complete GPU proof or privacy qualification.
Both source and executable remain unchanged during execution. Evidence is in
`core-retry-14/retained-kats-result.json` and
`core-retry-15/compact-metal-result.json` under the recovery evidence directory.

The new [Kaigi lifecycle gate](kaigi_four_validator_lifecycle_v1.md) submits real
governed-key, authorization and usage instructions to four validators and checks
typed rejection, retained participation and two cold restarts. It is implemented
but the network harness and ordinary daemon still await a successful composed
build and execution. The retained Core fixture test passes with both governed
keys, all five generated authorization/usage proofs, and the malformed-envelope
control. This is local verifier evidence, not a deployment result.
