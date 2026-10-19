# Parliament ballot B6 requirement audit

Status, 2026-10-20: **no profile selected or qualified; production remains
gated**. This matrix maps the current [design](parliament_private_ballot_design.md)
§5, §12.2 and §13 to retained evidence and remaining work. It is a source and
requirements audit, not independent cryptographic review, owner acceptance,
or an activation authorization. Design §12.2 separately authorizes production
integration engineering alongside B6. The standalone engineering checkpoint is
complete; B6 qualification still requires the evidence below. A listed source test is not a claim of exhaustive coverage.

## Evidence and scope

- [B5](../docs/validation/parliament_ballot_standalone.md): exact standalone
  relations, twelve official reference-mode signature vectors, eight final
  independently implemented Python ballot vectors, negative tests and local
  measurements. The official vectors do not cover the ballot extensions.
- [B6](../docs/validation/parliament_ballot_b6.md): bounded adversarial/fuzz
  campaigns; source-bound cold-input, warm and late-invalid observations on
  Mac, iPhone 17 Pro Max and Samsung SM-S942B; digest/retry agreement; separate
  requested Rust heap and sampled process memory. These are supplementary
  devices, not the named launch baselines or cold-process/cache qualification.
- [Canonical-input resource observations](../docs/validation/parliament_ballot_canonical_resources/README.md):
  55 vote-validity cases per mode exercise the complete envelope/context,
  actual stamp/proof and cleanup. The later [typed context boundary and encoding
  bound](parliament_ballot_resource_contract.md#verification-and-debit-boundary)
  establish source-derived sizes of 233,455 envelope bytes and at most 130,995
  context bytes, 364,450 combined. Six [wire-size tests](../crates/iroha_data_model/src/governance/anonymous_ballot/context_wire_size_tests.rs)
  and nine [context decoder controls](../crates/iroha_data_model/src/governance/anonymous_ballot/context_decode_tests.rs),
  plus nine [envelope controls](../crates/iroha_data_model/src/governance/anonymous_ballot/envelope_decode_tests.rs),
  pass within the [captured boundary/refusal run](../docs/validation/parliament_ballot_canonical_resources/envelope-refusal-receipt.json):
  107 model tests, 79 protocol tests (two fixture helpers ignored), 25 example
  tests and 55 cases per worker mode. Inputs, full reports and debits agree across
  modes; 114 scoped inputs were unchanged around each successful build/test.
  Original local refusals remain unavailable through nested carriers, admission,
  block validation and seal replay. The context's 327,680-byte and envelope's
  233,012-byte allowances bound nominal codec charges, not physical heap. These
  are observations on that captured checkout. Subsequent carrier and shared decoder
  changes require their own validation; these results do not qualify the current
  integration source.
  Neither the decoder nor the encoder cap authenticates supplied chain history.
- [Node-representation engineering observations](../docs/validation/parliament_ballot_node_representation/observations.json):
  the real candidate-proof component suite passed 82 tests (two fixture-maintenance
  helpers ignored), and nine shared exact-slice decoder tests passed. The four
  runner-filter tests are a subset of those 82. The first model run passed 120
  tests and failed the nested decoder-state restoration check; that prompted a
  shared decoder change, while the model rerun failed to build on a full filesystem.
  The cross-crate node check exposed two Torii call sites, now edited but not
  recompiled, and also failed with ENOSPC. The selected source hashes were captured
  after the runs, not before and after every build; they do not establish complete
  candidate identity. These observations establish neither authenticated Core State
  execution, network finality, complete resource bounds nor qualification.
- [Security ledger](parliament_ballot_b6_security_review.md) and
  [generator interface](parliament_ballot_b6_generator_interface.md): checked
  arithmetic, precise missing primitive/reduction/resource terms and limited
  source-derived algebra. The [candidate request-stage check](parliament_ballot_b6_request_accounting.md)
  justifies the coupled nominal request/query allowance across all roster sizes;
  full physical/reduction resources and unknown premises remain open.
- [Bounded hybrid-driver proposal](parliament_ballot_b6_hybrid_driver.md):
  explicit bounded exhaustion sampling, opening caches, persistent oracle
  state and actual-IV component interfaces. A [fixed-opening H5 derivation](parliament_ballot_b6_h5_fixed_opening.md)
  supplies a conditional initial transition at ideal-row entry, and the
  [zero fallback](../docs/validation/parliament_ballot_zero_challenge/README.md)
  is verified for both rows/roles. A [joint mask-coordinate derivation](parliament_ballot_b6_mask_coordinate.md)
  now preserves the complete paired oracle state at an ideal-material public
  endpoint. The [hidden-assignment deletion derivation](parliament_ballot_b6_hidden_assignment_deletion.md)
  supplies conditional adaptive oracle removal at that same boundary. A distinct
  [direct public sampler](parliament_ballot_b6_ideal_public_sampler.md) exactly
  realizes the post-deletion public material under explicit fresh-slot premises,
  using one source-shaped reconstruction. Primitive entry, acceptance of this
  new simulator and full reduction resources remain open; equality to real-root
  `Sim+` has not been established.
  The separate [conditional root-entry lemma](parliament_ballot_b6_root_entry.md)
  supplies the source-use census, exact five-query slot reduction and
  `10/2^128` switching bound under the proposed chosen-input game. Equal
  numeric keys remain allowed. The [conditional material-entry extension](parliament_ballot_b6_material_entry.md)
  supplies the path/leaf/row reductions under the same game and reaches the
  independent-material boundary with real H5 processing. Each parent/leaf
  switching step precedes the next fresh-key embedding, and earlier replacement
  slots keep their prescribed status. The [conditional composition](parliament_ballot_b6_conditional_composition.md)
  joins that endpoint through H5, mask coordinates and deletion to the direct
  public sampler, with a separate fail-closed arithmetic report. The
  [initial-programming derivation](parliament_ballot_b6_initial_programming.md)
  supplies the real-prover entry samplers under the common QROM premises,
  including the global counterwise hybrid and `2*Q_all+T` query accounting.
  Quantitative AES premises, complete driver resources, dependent application
  reductions and acceptance of the proposed model remain open.
  Its separate [executable logical accounting](parliament_ballot_b6_ideal_sampler_accounting.md)
  checks bounded schedules, reads versus programming writes and persistent
  chronological records with 30 controls. A separate [explicit reversible log](parliament_ballot_b6_oracle_log_circuit.md)
  supplies conditional coherent lookup/append gate and wire bounds with 21
  controls. Full quantum and physical resources remain open; request count is
  not inferred from external query count, and base calls remain separately charged.
  The [clean admissibility circuit](parliament_ballot_b6_admissibility_circuit.md)
  separately prices the actual grinding/opening predicate with exact gates and
  reusable work wires. It excludes challenge sampling, first-success selection,
  the trial controller and every separate reconstruction pass.
  The [clean field-product kernels](../docs/validation/parliament_ballot_gf_circuit/README.md)
  separately price three source field APIs with exact reversible gates and
  clean work. Supplied operands/output/work must be disjoint; the atomic request
  composition below prices routing and cleanup within its declared boundary. These
  kernels do not close the full simulator or physical verifier resource gates.
- [Mathematical request machine](../docs/validation/parliament_ballot_request_machine/README.md):
  explicit atomic generation, programming, return and cleanup, with content and
  full-width length rejection families. Accepted-request gate/oracle/storage
  observations are source-bound cases, not a family-wide maximum. Adaptive
  lifetime accounting, primitive-entry assumptions, external review and native
  workspace qualification remain open; no production gate changes.
- [Conditional lifetime ledger](../docs/validation/parliament_ballot_lifetime_ledger/README.md):
  common log/oracle contracts, supported event-cost composition and disjoint
  retained-register accounting. Actual adaptive execution, unsupported families,
  initialization and primitive resources remain open.
- [Full-cap content observations](../docs/validation/parliament_ballot_content_resources/README.md):
  four exact bounded-content cases include validation, controlled writes, returns
  and cleanup. They do not establish a family maximum or extend the ledger's
  supported inputs automatically. The separate [ContentFamily ledger extension](../docs/validation/parliament_ballot_content_lifetime/README.md)
  adds their exact accounting with an explicit cap on all typed requests; valid-only
  theorem T cannot bound arbitrary invalid invocations.
- [Finite sequence composition](../docs/validation/parliament_ballot_sequence_composition/README.md):
  concrete static relocation into shared persistent state and clean workspace, with
  distinct retained interfaces and true reverse-call inverses. Adaptive selection,
  preparation and a complete joint-state theorem remain open.
- [Legal request domains](../docs/validation/parliament_ballot_family_domains/README.md) and
  [component-family arithmetic](../docs/validation/parliament_ballot_component_families/README.md):
  source-defined REG lengths and VOTE sizes, component bounds and explicit upstream
  error/witness/application obligations. A full experiment resource certificate is
  still absent. New frozen-source replay results do not qualify the changed current
  Cargo manifest or native candidate.
- [Standalone resource model](parliament_ballot_b6_standalone_resources.md):
  source-bound conditional requested-allocation ceilings and separated
  arithmetic/hash/loop counts, not complete work or process-memory bounds.
- [Implemented resource proposal](parliament_ballot_resource_contract.md) and
  [120-call campaign](../docs/validation/parliament_ballot_resource_contract/README.md):
  fixed whole-call/actual-byte reservations and an enforced heap/native-stack
  mapping. Calibration, complete runtime coverage and qualification remain open.
  The separate [in-memory entry](../docs/validation/parliament_ballot_memory_entry/README.md)
  reserves the actual borrowed length after retrieval and passes its own 122
  observations; original worker and disassembly evidence is not transferred.
  Its [shared-control successor](../docs/validation/parliament_ballot_fatal_control/README.md)
  fixes fatal stdout blockage and passes a fresh 122-observation campaign plus
  real full/broken-output controls, with the extra page included in workspace.
  [Fresh compiled stack captures](../docs/validation/parliament_ballot_fatal_stack_eon/README.md)
  now decode both complete images without frame-analysis errors, while retaining
  native/indirect/exceptional frontiers and recursion as unknown costs.
  A [conditional adapter bound](../docs/validation/parliament_ballot_adapter_bound/README.md)
  isolates 336 stack bytes, 5,298 issued instructions and one input block of at
  most 524,288 bytes around the opaque verifier. Native and verifier costs remain
  unresolved; 20 checker tests do not establish whole-call sufficiency. Subsequent
  lockfile/allocator edits are recorded as current-source drift; the earlier
  capture is retained and the live-input check refuses. Separate
  [historical-input recovery](../docs/validation/parliament_ballot_adapter_source_recovery/README.md)
  resolves all 2,081 original identities without replacing live files; twelve
  fault controls cover missing/changed identities and refusal paths. Recovery
  does not transfer the earlier bounds to the current checkout.
  The [historical frontend bound](../docs/validation/parliament_ballot_frontend_bound/README.md)
  adds conditional dispatcher/record contributions of 146 local instructions
  and 2,160 owned stack bytes, plus a separate fixed-count parser lemma.
  Twenty-seven checker tests pass; typed-decoder, crypto, allocator, cleanup and
  native costs remain unknown.
  Separate [profile](../docs/validation/parliament_ballot_profile_bound/README.md)
  and [typed-decoder](../docs/validation/parliament_ballot_typed_decoder_bound/README.md)
  checks now bound those outer coordinators with 18 and 24 passing tests. They
  retain lower constructor/hash/allocator/native terms, source/ABI premises and
  the registration trap continuation; no complete resource certificate follows.
  A separate [opaque-field constructor check](../docs/validation/parliament_ballot_opaque_field_bound/README.md)
  derives all four full-width length paths in both retained images, including
  guarded requests of at most 256 bytes and a 48-byte own frame. Returning paths
  cost 20/23/29 local instructions; the 18-instruction allocation-failure prefix
  retains its final error call and outside-body continuation as unknown. Native
  and complete workspace costs remain unresolved.
  The [retained-image exception audit](../docs/validation/parliament_ballot_exception_coverage/README.md)
  now checks compact/FDE mapping for all 228 LSDAs per mode and conservatively
  seeds every table-listed landing pad of reached owners. Its 182 staged tests
  and LLVM header comparison preserve a 46-instruction indirect-control gap
  per image relative to the independent whole-function census. CFI execution,
  loaded personality correspondence and exceptional stack/native costs remain
  unknown; no complete resource or current-checkout qualification follows.
  A [current-source rebuild](../docs/validation/parliament_ballot_current_candidate/README.md)
  separately passes both worker modes, 122 observations, four output controls
  and fresh stack diagnostics. The waker assertion correction passes 28 shared
  and nine custody tests without runtime changes. The separate
  [compiled correspondence check](../docs/validation/parliament_ballot_current_correspondence/README.md)
  binds 24 code ranges and seven source deltas, then reruns the four unchanged
  component analyzers on the new captures. Its 49 controls and 2,123 stable input
  guards preserve the original premises and unresolved terms; complete
  native/workspace costs remain open.
  Subsequent root-lock drift makes the build, allocation and correspondence
  results historical; exact originals remain archived. No qualification is
  transferred to the later checkout.
- Standalone source checks: [relations](../crates/iroha_parliament_ballot_proof/tests/relation.rs),
  [proofs](../crates/iroha_parliament_ballot_proof/tests/proofs.rs),
  [test decoder](../crates/iroha_parliament_ballot_proof/src/test_codec.rs),
  [sealed list](../crates/iroha_parliament_ballot_proof/src/sealed_list.rs),
  [tape/errors](../crates/iroha_parliament_ballot_proof/src/proving.rs),
  [extended backend](../crates/iroha_zkp_vole/tests/extended_variant.rs) and
  [campaign](../crates/iroha_zkp_vole/tests/fixtures/standalone_adversarial.md).

“Local” describes standalone evidence. Integration requirements below remain
unqualified by these component checks; their implementation and testing may
proceed under design §12.2. Already existing governance/SCCP machinery can have
its own evidence; this audit does not independently certify those paths.

## Section 5 security gates

| Gate | Available evidence | Still required |
| --- | --- | --- |
| 1. Adaptive relation soundness | Exact relation implementation, independent evaluators and constraint faults; conditional written adaptive argument | Reviewed applicable embedding, premises, full losses/resources and numerical substitution; no extraction claim |
| 2. Ballot unforgeability | Complete authorization fields and message-binding tests; conditional event split | Soundness, `P`, nullifier uniqueness at designated scopes, vote-frame bounds and joint ZK at full resources |
| 3. Nullifier uniqueness | Deterministic credential/scope nullifier; conditional batch counting argument | Soundness, commitment uniqueness at seals, `P`, frame and joint-ZK bounds; failed/exhausted honest disclosures must remain in the issued set |
| 4. Unlinkability and non-frameability | Explicit games and disclosure exclusions | Qualified `P` and joint ZK; gates 2 and 8 for non-frameability |
| 5. Joint quantum ZK and anonymity | Exact salted/affine implementation and independent vectors; explicit leaf interface and conditional bijection | Extended simulation/hiding proof; actual key/IV/auxiliary-state and request embedding; four generator bounds; privacy composition |
| 6. Concrete security | Exact/high-precision ledger, conditional thresholds and explicit unknowns | Complete applicable bound below `1/2` at `2^64` adversarial queries, full threshold reporting, all reduction resources, primitive/model justification and independent `2^128`-gate attack assessment |
| 7. Deterministic bounded verification | Fixed typed envelope and valid-context size formula; typed decoder controls pass in the scoped 94-test model run; bounded component tests, ARM-platform agreement and conditional resource model | Complete charged work and allocation/failure certificates, physical x86 parity, production mappings and baseline qualification |
| 8. Registration authorization | Exact registration relation and context-binding faults; conditional reduction | Soundness, `P`, commitment uniqueness at target contexts, registration-frame bounds and joint ZK |

No gate is cryptographically qualified. In particular, the written bound
containing `Z` cannot certify `2^-64` at any nonnegative external query budget
at lifetime `T=2^44`; this is a limitation of the bound, not an attack. Its
threshold at `1/2` remains unqualified because the primitive and full-resource
terms are missing. Owner approval cannot be inferred from an instruction to
continue engineering.

## Section 5 engineering limits and measurement contract

| Requirement | Current scope | Remaining work / owner |
| --- | --- | --- |
| Complete envelope ≤262,144 bytes; shared list context ≤163,840 bytes | Current typed envelope is exactly 233,455 bytes; the source-derived valid-context maximum is 130,995, or 364,450 combined. Boundary/prefix/maximal-roundtrip tests and fresh protocol/worker regressions pass in the scoped live-checkout run | Final integrated schemas and ingress/copy/verification costs remain; structural context validity does not authenticate chain history |
| Uncached verification ≤250 ms | Warm-process cold-input measurements and separate fresh-child canonical diagnostics; no calibrated uncached or named Xeon measurement | Owner-deferred Xeon Silver 4310 run: one physical core, 2.10 GHz, turbo off, idle SMT sibling, Linux x86-64; accelerated build judged against the limit |
| Verifier workspace ≤64 MiB | Bounded-copy/arena/stack workers and retained standalone campaigns; fresh typed workers pass 55 canonical calls per mode with 41.109375 MiB reserved on this Mac. The context entry caps nominal codec charges at 327,680 bytes and its model tests pass. Earlier conditional source/image bounds retain their original scope | Complete compiled allocation correspondence and indirect/native/recursive stack bounds for the actual candidate, runtime/System/TLS coverage, independent unsafe review, target execution and ingress allocation certificate; nominal codec charges do not bound physical heap; concurrency/caller scope is explicit |
| Phone proving p95 ≤10 s and peak ≤256 MiB | Supplementary iPhone 17 Pro Max and Samsung observations | Pixel 6a and iPhone SE third generation; native release apps, battery operation, sustained thermal runs and complete memory scope |
| Both proofs, all three roster sizes and each path | Registration and votes at 3/500/1,000 on both rows and feature modes | Physical x86/ARM result/byte/error/charge parity and baseline measurements; scalar timing need not meet 250 ms |
| Cold, warm, late-invalid and malformed measurements | Fresh list decoding/digest/transcript preparation, warm and canonical late-invalid samples retained; [malformed distributions/maxima](../docs/validation/parliament_ballot_b6/malformed-results.md) cover 164 selected classes per mode, with 31 repetitions each | Cold-process/cache methodology, complete malformed-input resource bounds and baseline qualification remain open; repeated selected mutants are not exhaustive coverage |
| Fresh randomness, exhaustion and cancellation | Explicit tape, entropy failure, deterministic test parity and typed exhaustion tests; [finish-and-discard lifecycle](parliament_ballot_prover_lifecycle.md) with eight tests per mode and selected still-live buffer cleanup observations | Named-phone cancellation latency/memory and independent randomness/constant-time/comprehensive-erasure review; process termination does not establish Drop cleanup |
| Deterministic budgets and admission capacity | Implemented one-whole-call plus actual-byte reservation, atomic admission and no refunds; feature-mode outcome/stage/debit parity | Complete `B_work`/`B_bytes` and stamp-cost derivation from qualified worst case; show 1,000 ballots for each of `K` attempts fit casting windows and per-block budgets at minimum cadence. Admission engineering is authorized; activation requires qualification |
| Source and execution identity | B5/B6 source snapshots, binary/toolchain identities and raw observations retained separately | Identify and validate each later candidate; do not silently retarget old measurements to changed source |

## Section 12.2 selection and implementation order

| Condition / step | Disposition |
| --- | --- |
| Step 1: isolate governance availability | Design records this as implemented with Core mutation HC224; not requalified by B6 |
| Step 2.1: exact construction and row | Holds for the frozen standalone candidate; production mappings remain outside the freeze |
| Step 2.2: complete written arguments | **Unmet**: missing adaptations, primitive premises and numerical substitution |
| Step 2.3: complete ledger and independent attack assessment | **Unmet**: arithmetic checks do not supply missing bounds or an assessment |
| Step 2.4: exact standalone implementation and meaningful checks | Component/adversarial evidence and the local checks below are recorded; independent implementation qualification remains open |
| Step 2.5: envelope/work/allocation evidence and three-roster measurements | **Unmet**: typed size/decoder tests, protocol/worker regressions and all-size observations pass within their recorded scopes; complete work/workspace certificates remain absent |
| Step 2.6: enumerate remaining obligations | This matrix and the profile/B6 record enumerate them; enumeration does not discharge them |
| Step 2.7: launch gate false | Current `parliament_binding_ballot_available()` returns false; qualified attempt latency remains `None` |
| Step 3: production schemas | In progress under the engineering authorization of design §12.2 (owner instruction of 2026-10-18): signerless envelope, stored records and authenticated context mappings; activation still requires qualification |
| Step 4: build paths and retire timed-OVN/TLE together | In progress under the same authorization: Core/State, admission, corpus/closure, Torii/CLI/canonical SDKs and wallet disclosure, with the timed-OVN/TLE retirement in the same candidate |
| Step 5: model, review and qualify | Postimplementation: formal model, independent review, lifecycle/load, real-peer restart/rollback, SDK parity and release evidence; owner records activation qualification |

**Envelope sequencing:** production envelope and authenticated-context
schemas are authorized during integration. Measure their actual canonical
encodings and include their complete framing, decoding, copying, verification
and allocation costs in the qualification evidence. Standalone `TEST_RECORD`
measurements do not certify production envelopes. Complete production-envelope
compliance and the remaining security, resource, independent-review and
named-hardware obligations are required before activation, but no longer block
schema or integration engineering. The owner's qualification record must
identify the final schemas, implementation, parameters and evidence. No
qualification is inferred from this sequencing amendment.

## Section 13 validation mapping

The row identifiers below follow the order within each design §13 table.
Standalone evidence establishes only the local observation described. It does
not supply node authentication, duplicate handling or wallet policy.

### Registration and credentials

| ID / case | Evidence and remaining requirement |
| --- | --- |
| R1: copied commitment or registration proof | Standalone verifier can accept an exact authorized statement. Rejection of an unauthorized copy and protection of the honest registrant require account/assignment admission in integration |
| R2: replay under another seat, body or account | Changed registration authority/body/assignment/attempt tests exist in `proofs.rs`; actual authenticated seat/account admission remains unqualified |
| R3: incorrect registration authorization | Relation/output faults and changed-`auth` proof tests exist; production decode/authentication remains unqualified |
| R4: unseated alternate excluded | Pending integration: assignment-to-sealed-list transition and digest tests |
| R5: duplicate sealed commitments | Standalone list validation rejects duplicates; sealing/restore transition evidence remains unqualified |
| R6: roster size 1 or 2 | Standalone list lower bound rejects; `NoRoster` outcome/retry and absence of a seal remain unqualified |
| R7: losses beyond `S-Q` | Pending integration: `NoQuorum` lifecycle test; no replacement policy inferred |

### Ballot validity and admission

| ID / case | Evidence and remaining requirement |
| --- | --- |
| V1: zero/multiple/out-of-range selectors | Relation selector faults and invalid-witness proof tests exist |
| V2: duplicate/misordered list | Standalone `SealedList`/decoder validation exists; seal and restore enforcement remains unqualified |
| V3: length/digest mismatch or unvalidated list | Decoder/public-statement validation tests exist; authentication of `S`, `R` and shared list remains unqualified |
| V4: unconstrained/second secret | Relation semantic faults and unchecked-prover rejection tests exist; these are finite constraint checks, not a soundness theorem |
| V5: wrong vote authorization | Authorization-half/state and changed-message proof faults exist |
| V6: wrong nullifier/authorization lengths | Fixed-length standalone decoding and frame faults exist; production Norito decoder remains unqualified |
| V7: wrong proof length | Exact-size/trailing/truncation tests cover both standalone roles/rows |
| V8: counter above `0x000fffff` | Extended-backend and ballot tests require refusal before reconstruction |
| V9: valid non-minimal counter | [Four constructive tests](../docs/validation/parliament_ballot_b6/nonminimal-counter-results.md) pass in both modes, covering both rows/roles (vote `S=3`): original and second-valid proofs accept; changing only the counter rejects. One verifier challenge evaluation is source-inspection evidence, not an instrumented test result |
| V10: changed vote/nullifier/authorization/list/context/policy/profile | Relation, proof-binding and decoder faults exist; authenticated production mappings remain unqualified |
| V11: exact ballot relayed before creator | Standalone exact-proof acceptance exists; first-in-canonical-order and later duplicate handling remain unqualified |
| V12: replay into another body scope | Changed body/scope proof rejection exists; chain authentication remains unqualified |
| V13: unknown/mismatched profile | Standalone retired-descriptor, role/row and descriptor checks exist; production profile admission remains unqualified |
| V14: concurrent/same-block duplicate nullifier | [Canonical output correction](../docs/validation/parliament_ballot_node_representation/pending-validation.json) permits identical anonymous envelopes at distinct ordered input positions; the setter/wire and malformed-index regression is written and source-reviewed but unexecuted after disk exhaustion. Atomic admission, actual canonical-order execution and network tests remain pending integration |
| V15: invalid proof claims honest nullifier | Invalid proof rejection exists; proving that later honest admission remains available requires integration state tests |
| V16: rerandomized pending flood | Pending integration: admission/dedup/queue test before verification |
| V17: stamp reused with altered proof bytes | Pending integration: stamp binding and cheap-rejection test |
| V18: invalid ballot from Byzantine proposer | Standalone verification rejects tested faults; block validity across honest validators remains unqualified |
| V19: invalid/stamp-bearing saturation | Pending integration: quantified attack-budget, inclusion and unrelated-transaction progress tests, using complete charge/capacity accounting |

### Clock, closure and outcomes

All these observations concern the replacement's authenticated state machine;
standalone proof tests do not discharge them.

| ID / case | Remaining requirement |
| --- | --- |
| C1: closing-block/late ballot, rollback/restore | Pending integration: cutoff and unchanged-corpus restore tests |
| C2: future timestamps, fast blocks, idle opening/closure | Qualified governance-clock bounds; no premature transition or empty-block production |
| C3: `K` attempts and a closure freeing capacity | Closures before deferred openings; oldest eligible ordering; `s0` at actual opening |
| C4: omitted/reordered/replayed corpus or altered counts/roots | Full authenticated verification rejection |
| C5: outcome arithmetic boundaries | Checked-integer boundary tests in the replacement reducer |
| C6: strategic abstention at `S=3` | `NoQuorum`, with no ballot retry |
| C7: voter disappears after acceptance | Accepted ballot persists and counts without further participation |
| C8: `RecordAttemptAbsence` for binding body | Rejection in production admission/state |
| C9: narrow result without disjoint Confirmation capacity | Atomic terminal failure and no partial certificate |
| C10: roster/entropy retry exhaustion | Terminal status persists through Norito restore |

### Sortition, SCCP, hardware and wallet

| ID / case | Evidence and remaining requirement |
| --- | --- |
| S1: missing Parliament pulse | Availability split recorded by design step 1; full replacement lifecycle/restart still needs its own evidence |
| S2: delayed pulse after beacon rotation | Governing SCCP/beacon evidence and replacement consumption must establish original-height key binding |
| S3: idle chain with admitted future slot | SCCP ticket bounds/no missing-pulse loop; retain explicit joint integration evidence |
| S4: persisted exact-slot pulse after restart/deferral | Late consumption without late pulse production; joint SCCP/replacement tests |
| S5: admission beyond `K` | Reject before attempt allocation; integration test |
| S6: idle chain after opening | Casting clock due at `h_open+1`, frozen closing time and unchanged `s0`; joint integration test |
| S7: pause/opening order and stale holds/heads | Position-aware lift rule and rejection of stale/older decisions; joint integration test |
| S8: CPU versus acceleration | Standalone ARM byte/accept/reject evidence exists; physical x86 and production consensus-output/charge parity remain |
| S9: wallet anonymity mode | Pending integration: SDK/wallet traffic tests excluding account/session/entry/nullifier-labelled requests |
| S10: two proofs, distinct fresh 112-byte tapes | Tape layout and distinct deterministic test-tape proofs exist; production wallet entropy generation and nonreuse enforcement remain unqualified |
| S11: unavailable random source | Standalone tape/secret fill tests fail without a value; production wallet no-fallback behavior remains unqualified |
| S12: forced counter exhaustion and fresh retry | Backend bounded-grinding and typed error propagation tests exist; complete wallet retry on an unchanged statement with a fresh tape remains unqualified |
| S13: same explicit tape across paths | Fixed-tape vectors and ARM feature/platform digest agreement exist; physical x86 proof-byte/exhaustion parity remains |

The formal model must replace timed-release phases with credential sealing,
casting, verified unique-nullifier append, deterministic closure and terminal
outcomes, preserving the listed quorum/retry/capacity/rollback rules. Its crypto
checks remain assumptions, not anonymity proofs. Consensus changes require
named deterministic simulator regressions/mutations, and later real-peer tests
use a legal committee of at least four validators. These are integration
obligations authorized by design §12.2; their completion does not establish
activation qualification.

## Concrete remaining work and ownership

| Work | Owner / current state |
| --- | --- |
| Bidirectional signature cross-verification against pinned official FAEST | Local reference-mode checkpoint complete for twelve sets; [record](../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/cross_verification.md) separates original source-guard publication rejection, retained negative logs and the recovery's 84 positive checks. Regenerated C proofs and missing original raw C return values are explicit; no ballot-extension or current-tree qualification |
| Constructive valid-nonminimal-counter acceptance | Local component check complete: four tests and strict lint pass in each feature mode; [receipt](../docs/validation/parliament_ballot_b6/nonminimal-counter-receipt.json) pins the 92-file source scope and binaries. Vote cases use `S=3`; no production or hardware qualification inferred |
| Malformed-encoding time/allocation distributions and maxima | Selected local campaign complete: 10,168 observations across both modes, expected refusal and 164-class input/outcome/diagnostic parity; [receipt](../docs/validation/parliament_ballot_b6/malformed-receipt.json) pins the new 225-file source scope. Shared warm-process observations only; complete malformed-input bounds and baseline qualification remain open |
| Standalone charge and workspace contract | Owner-authorized research/proposal implemented: [fixed reservation and bounded worker](parliament_ballot_resource_contract.md), 10 Rust tests per mode, 33 supervisor tests and 120 source-bound worker calls pass. Full physical cost and runtime/workspace certificates remain open; the prior front-end inventory remains a distinct frozen worksheet |
| Typed envelope/context sizes, bounded decode and local refusals | Maximum valid pair 364,450 bytes; context per-sequence/combined limits 1,000/1,010 and nominal charge cap 327,680. Envelope decoding permits zero sequence elements and one 233,012-byte proof charge. Local shortages remain unavailable through nested carriers, admission, block validation and seal replay. The captured run passed 107 model, 79 protocol and 25 example tests, with 55 worker cases per mode. Later carrier/decoder changes require matching validation. No physical-workspace or authentication claim |
| Actual generator driver, remaining reductions and full resource vectors | Cryptographic author and independent reviewer; open. The [post-entry conditional composition](parliament_ballot_b6_conditional_composition.md), [conditional real-prover entry](parliament_ballot_b6_initial_programming.md) and [application joins](parliament_ballot_b6_application_reconciliation.md) are written. The application joins require the newly specified `P_F` experiment; old `Sim+` bounds do not transfer automatically. Quantified premises, adversary-to-aggregate query conversion and whole-driver resources remain unresolved. The captured fixed-scan request construction has a repeated-body lifetime cost above `2^151` elementary gates; this is not an attack or a lower bound on all reductions. The [write-frame component](parliament_ballot_b6_write_framing.md) and [admissibility circuit](parliament_ballot_b6_admissibility_circuit.md) price their stated boundaries. The separate [static-slot writer](parliament_ballot_b6_static_overlay.md) removes that construction's append scan with nine circuit tests and retains the prior cost record. Root/material ordinary semantic reads are bounded by `Q_all+1445*T`; source generation, controller, base/coherent-read realization and full reductions remain unresolved. Reference games do not accept new premises |
| Primitive/model qualification and independent attack-cost assessment | Independent cryptographic reviewers; open |
| Both security weakenings and approved premises | Design owner with required independent review; open. Schema and integration development/testing are authorized by §12.2; envelope sequencing is not a remaining engineering permission gate |
| Exact Xeon and named phone evidence, physical x86 parity, battery/thermal/cancellation conditions | Hardware/qualification owners; open; Intel run explicitly deferred by owner |
| Capacity/admission derivation | Resource and governance-policy owners; open, using complete qualified worst-case costs; no policy parameter silently chosen |
| Captured integration source-contract reconciliation | Scoped structural checkpoint complete. Queue/Kura, phase, construction, Torii release, daemon startup, beacon-witness and execution-result guards bind the reviewed owners and order. The full Python capture passed 1,755 tests on its recorded sources; a later constructor migration changed two observed Rust files. Their originals remain archived, and the [post-merge source check](../docs/validation/parliament_ballot_post_merge_source_check/README.md) passes across 402 stable inputs. Prior tests are not transferred to those changed files. The later anonymous carrier migration changes observed owners again and requires fresh source-contract checks. Resolver/compiler/runtime premises remain; no Rust runtime or production qualification follows |
| Production implementation, retirement and launch qualification | Integration owners may implement schemas, paths and coordinated retirement alongside B6 under design §12.2; binding production activation requires every qualification condition and the owner's qualification record |

The three focused accounting suites pass 38 tests and six subtests on the
recorded source and its [isolated reconstruction](../docs/validation/parliament_ballot_b6/frozen-accounting-recheck.json).
A subsequent unrelated root-lock edit and later Norito source edit are retained
with exact provenance; resource/front-end guards refuse the changed live input.
The frozen reconstruction remains separate from these later sources. On the frozen source, the
security check intentionally returns exit 2 with qualification false; the
resource and front-end checks return exit 1 with complete certificates false.
The [source-contract capture](../docs/validation/parliament_ballot_execution_result_guard/source-check.json)
passed after scoped beacon borrowing and execution-result assertion repairs.
The matching [complete regression capture](../docs/validation/parliament_ballot_source_guard_regressions/README.md)
passed all 1,755 collected Python tests. Their source scope precedes two later
constructor-migration edits; the separate post-merge source check passes on
those changed inputs without transferring the full regression result. Earlier queue, Kura, start-phase,
construction, Torii, daemon and execution-assertion failures remain historical evidence. New local work has
separate source identities and receipts; the
B6 artifact manifest records the final retained files. No full-workspace pass,
independent human review or owner approval is asserted.

## Resource proposal and remaining certificates

The owner requested research, a proposal and implementation. The
[implemented contract](parliament_ballot_resource_contract.md) chooses one
indivisible cold-verification reservation plus actual copied bytes, with
atomic admission and no refund. This avoids adding unequal primitive/byte
counts into an invented CPU unit. The entry point, bounded caller copy,
serialized invocation, arena/native stack, cleanup, concurrency and failure
semantics are explicit. The 120-call campaign passes on both feature modes.

The mapping enforces a bounded allocation/stack subset; verification-caused
System/native/TLS work and all-valid-input completion still need a certificate.
The [native runtime source audit](../docs/validation/parliament_ballot_resource_contract/native-runtime-audit.md)
traces ordinary paths and identifies concrete bypasses and excluded pthread
infrastructure. Its source review does not authenticate the installed native
runtime or establish a complete byte bound. A subsequent, separate
[native endpoint experiment](../docs/validation/parliament_ballot_native_probe/README.md)
implements controlled interposition and actual-process runtime UUID capture.
Its 14 controls and 120 proof cases pass, including required native-positive
System/thread/TLS controls before proof observations. The 82 charged intervals
(including 16 terminal incomplete prefixes) observe no named endpoint calls;
38 other cases are unadmitted. Hidden native paths, complete native-byte bounds
and installed-source correspondence remain unproved.
The [conditional sufficiency argument](parliament_ballot_arena_sufficiency.md)
now combines an all-length frontend spatial bound with 135,064 exact
retained-class replays and actual-arena parity controls. Selected compiled
layouts support its premises. The separate
[compiled stack audit](../docs/validation/parliament_ballot_compiled_stack/README.md)
retains unknown complete bounds and names the indirect/native/recursive
frontiers. A [provider-target catalog](../docs/validation/parliament_ballot_indirect_targets/README.md)
conditionally resolves seven backend sites with 21 edges per image. The
remaining 32 indirect-call frontiers, native edges and positive recursive
component still prevent a complete stack bound; source target-set premises
also remain explicit. Complete allocation correspondence and justified
target/path bounds remain local work; the source model does not certify
compiled execution.
The [compiled allocation-stream experiment](../docs/validation/parliament_ballot_allocation_trace/README.md)
matches all 132 selected corpus observations and passes 14 controls, with
2,041 guarded inputs unchanged. It validates actual layouts, offsets, order
and cleanup against the model, including malformed prefixes and charged reads.
Its separate recorder mapping and post-interval serialization are additional
overhead. Complete all-input/original-binary correspondence and native/runtime
coverage remain unmet; the finite experiment does not select a profile.
The later [failure-entry report](../docs/validation/parliament_ballot_stack_frontiers/README.md)
places 31 indirect sites behind three named failure entries. Excluding those
entries breaks positive recursion and leaves no reservation-root indirect
sites, while retaining every excluded edge as an unknown-cost obligation.
One worker I/O destructor, native/failure costs and exceptional control-flow
contracts remain. This separates obligations; it proves neither panic absence
nor full stack sufficiency.
The [activation analysis](../docs/validation/parliament_ballot_allocator_activation/README.md)
checks true-store dominance and four false-only System allocation arms in
each image. With explicit noninterference, source/compiler and ABI premises,
System frontiers narrow from 14 to 10; all ten frees remain. Unconditional
activation and arbitrary alias/callback behavior remain unknown. This is
another conditional boundary, not a full allocation or stack certificate.
The [source ownership audit](../docs/validation/parliament_ballot_ownership/README.md)
and [compiled free predicates](../docs/validation/parliament_ballot_free_predicates/README.md)
now separate source-owned allocations from the exact null/range and
same-pointer checks. All ten unconditional free sites still need machine
provenance/noninterference evidence. The
[I/O error guard](../docs/validation/parliament_ballot_io_error_guard/README.md)
similarly establishes a local non-Custom return condition and charged-read
source lemma, while leaving whole-worker variant flow and its frontier open.
The full service needs qualified worst-case calibration before resource and
governance owners derive committed budgets, stamps and `1,000 * K` casting
capacity. Neither the abstract unit nor the finite Mac runs supply those costs.
The 64 MiB requirement remains unchanged, and independent review/qualification
is not inferred from authorization to implement the proposal.

The cryptographic source audit has reached a different boundary: the required
salted/affine, bounded-retry multiquery hybrid driver is not supplied by the
reference games. Its key/auxiliary-state distribution, IV embedding, query
mode/count, output projection and failed-call/opening effects require an actual
adapted proof. Implementation counts cannot determine the missing quantum
emulation, advice or state resources. The existing interface note records the
omission; independent review and owner acceptance of any strengthened premises
remain requirements. Additional interoperability or performance observations do
not establish those premises.

The [implemented-prover component calculation](parliament_ballot_b6_prover_accounting.md)
now bounds logical non-counter Keccak work at two explicit entries. The largest
candidate ordinary/bounded-setup totals are 14,916/19,112, and comparator totals
59,657/63,849. The counter costs `2 + 2A <= 4A` for `A >= 1`, including failed
attempts. Arbitrary governance-preimage construction is excluded and can exceed
the allowance. The complete honest-game/simulator schedule, non-Keccak costs,
quantum resource accounting and independent assessments remain unmet.
