# Parliament ballot B6 requirement audit

Status, 2026-10-13: **no profile selected or qualified; production remains
gated**. This matrix maps the current [design](parliament_private_ballot_design.md)
§5, §12.2 and §13 to retained evidence and remaining work. It is a source and
requirements audit, not independent cryptographic review, owner acceptance,
or an authorization to begin production integration. The standalone engineering
checkpoint is complete; B6 qualification remains blocked on the requirements
below. A listed source test is not a claim of exhaustive coverage.

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
- [Security ledger](parliament_ballot_b6_security_review.md) and
  [generator interface](parliament_ballot_b6_generator_interface.md): checked
  arithmetic, precise missing primitive/reduction/resource terms and limited
  source-derived algebra. The [candidate request-stage check](parliament_ballot_b6_request_accounting.md)
  justifies the coupled nominal request/query allowance across all roster sizes;
  full physical/reduction resources and unknown premises remain open.
- [Standalone resource model](parliament_ballot_b6_standalone_resources.md):
  source-bound conditional requested-allocation ceilings and separated
  arithmetic/hash/loop counts, not complete work or process-memory bounds.
- [Implemented resource proposal](parliament_ballot_resource_contract.md) and
  [120-call campaign](../docs/validation/parliament_ballot_resource_contract/README.md):
  fixed whole-call/actual-byte reservations and an enforced heap/native-stack
  mapping. Calibration, complete runtime coverage and qualification remain open.
- Standalone source checks: [relations](../crates/iroha_parliament_ballot_proof/tests/relation.rs),
  [proofs](../crates/iroha_parliament_ballot_proof/tests/proofs.rs),
  [test decoder](../crates/iroha_parliament_ballot_proof/src/test_codec.rs),
  [sealed list](../crates/iroha_parliament_ballot_proof/src/sealed_list.rs),
  [tape/errors](../crates/iroha_parliament_ballot_proof/src/proving.rs),
  [extended backend](../crates/iroha_zkp_vole/tests/extended_variant.rs) and
  [campaign](../crates/iroha_zkp_vole/tests/fixtures/standalone_adversarial.md).

“Local” means permitted standalone work. “Postselection” means the production
requirement is not implemented or discharged by these component checks and
must wait for selection. Already existing governance/SCCP machinery can have
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
| 7. Deterministic bounded verification | Fixed standalone encodings, bounded tests, ARM-platform agreement and conditional resource model | Complete charged work and allocation/failure certificates, physical x86 parity, production mappings and baseline qualification |
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
| Complete envelope ≤262,144 bytes; shared list context ≤163,840 bytes | Raw proof sizes and standalone preimage/test-record formulas exist | Complete authenticated envelope and context accounting; owner/reviewer must resolve the sequencing obligation below |
| Uncached verification ≤250 ms | Cold-input measurements start in a warm process; no named Xeon measurement | Owner-deferred Xeon Silver 4310 run: one physical core, 2.10 GHz, turbo off, idle SMT sibling, Linux x86-64; accelerated build judged against the limit |
| Verifier workspace ≤64 MiB | Implemented bounded-copy/arena/stack proposal; 120 calls pass within the 41.09375 MiB mapping on this Mac. Conditional all-length source-model arena sufficiency and selected compiled layout/stack evidence retained | Complete compiled allocation correspondence and indirect/native/recursive stack bounds, runtime/System/TLS coverage, independent unsafe review, target execution and ingress allocation certificate; concurrency/caller scope is explicit |
| Phone proving p95 ≤10 s and peak ≤256 MiB | Supplementary iPhone 17 Pro Max and Samsung observations | Pixel 6a and iPhone SE third generation; native release apps, battery operation, sustained thermal runs and complete memory scope |
| Both proofs, all three roster sizes and each path | Registration and votes at 3/500/1,000 on both rows and feature modes | Physical x86/ARM result/byte/error/charge parity and baseline measurements; scalar timing need not meet 250 ms |
| Cold, warm, late-invalid and malformed measurements | Fresh list decoding/digest/transcript preparation, warm and canonical late-invalid samples retained; [malformed distributions/maxima](../docs/validation/parliament_ballot_b6/malformed-results.md) cover 164 selected classes per mode, with 31 repetitions each | Cold-process/cache methodology, complete malformed-input resource bounds and baseline qualification remain open; repeated selected mutants are not exhaustive coverage |
| Fresh randomness, exhaustion and cancellation | Explicit tape, entropy failure, deterministic test parity and typed exhaustion tests; [finish-and-discard lifecycle](parliament_ballot_prover_lifecycle.md) with eight tests per mode and selected still-live buffer cleanup observations | Named-phone cancellation latency/memory and independent randomness/constant-time/comprehensive-erasure review; process termination does not establish Drop cleanup |
| Deterministic budgets and admission capacity | Implemented one-whole-call plus actual-byte reservation, atomic admission and no refunds; feature-mode outcome/stage/debit parity | Complete `B_work`/`B_bytes` and stamp-cost derivation from qualified worst case; show 1,000 ballots for each of `K` attempts fit casting windows and per-block budgets at minimum cadence; production policy/admission follows selection |
| Source and execution identity | B5/B6 source snapshots, binary/toolchain identities and raw observations retained separately | Identify and validate each later candidate; do not silently retarget old measurements to changed source |

## Section 12.2 selection and implementation order

| Condition / step | Disposition |
| --- | --- |
| Step 1: isolate governance availability | Design records this as implemented with Core mutation HC224; not requalified by B6 |
| Step 2.1: exact construction and row | Holds for the frozen standalone candidate; production mappings remain outside the freeze |
| Step 2.2: complete written arguments | **Unmet**: missing adaptations, primitive premises and numerical substitution |
| Step 2.3: complete ledger and independent attack assessment | **Unmet**: arithmetic checks do not supply missing bounds or an assessment |
| Step 2.4: exact standalone implementation and meaningful checks | Component/adversarial evidence and the local checks below are recorded; independent implementation qualification remains open |
| Step 2.5: envelope/work/allocation evidence and three-roster measurements | **Unmet** despite all-size measurements; complete certificates remain absent |
| Step 2.6: enumerate remaining obligations | This matrix and the profile/B6 record enumerate them; enumeration does not discharge them |
| Step 2.7: launch gate false | Current `parliament_binding_ballot_available()` returns false; qualified attempt latency remains `None` |
| Step 3: production schemas | Blocked on selection, including signerless envelope, stored records and authenticated context mappings |
| Step 4: build paths and retire timed-OVN/TLE together | Postselection: Core/State, admission, corpus/closure, Torii/CLI/canonical SDKs and wallet disclosure; no premature retirement |
| Step 5: model, review and qualify | Postimplementation: formal model, independent review, lifecycle/load, real-peer restart/rollback, SDK parity and release evidence; owner records activation qualification |

**Envelope sequencing:** step 2.5 requires complete envelope sizes before
selection, while step 3 supplies production schemas and step 2 forbids them
before selection; §5 also defers complete-envelope compliance until the schema
exists. The design owner and independent profile reviewer must record the
permitted preselection certificate and its relation to the later schema, or
explicitly amend the contract. No waiver or schema authorization is inferred.

## Section 13 validation mapping

The row identifiers below follow the order within each design §13 table.
Standalone evidence establishes only the local observation described. It does
not supply node authentication, duplicate handling or wallet policy.

### Registration and credentials

| ID / case | Evidence and remaining requirement |
| --- | --- |
| R1: copied commitment or registration proof | Standalone verifier can accept an exact authorized statement. Rejection of an unauthorized copy and protection of the honest registrant require postselection account/assignment admission |
| R2: replay under another seat, body or account | Changed registration authority/body/assignment/attempt tests exist in `proofs.rs`; actual authenticated seat/account admission remains postselection |
| R3: incorrect registration authorization | Relation/output faults and changed-`auth` proof tests exist; production decode/authentication remains postselection |
| R4: unseated alternate excluded | Postselection assignment-to-sealed-list transition and digest tests |
| R5: duplicate sealed commitments | Standalone list validation rejects duplicates; sealing/restore transition evidence remains postselection |
| R6: roster size 1 or 2 | Standalone list lower bound rejects; `NoRoster` outcome/retry and absence of a seal remain postselection |
| R7: losses beyond `S-Q` | Postselection `NoQuorum` lifecycle test; no replacement policy inferred |

### Ballot validity and admission

| ID / case | Evidence and remaining requirement |
| --- | --- |
| V1: zero/multiple/out-of-range selectors | Relation selector faults and invalid-witness proof tests exist |
| V2: duplicate/misordered list | Standalone `SealedList`/decoder validation exists; seal and restore enforcement remains postselection |
| V3: length/digest mismatch or unvalidated list | Decoder/public-statement validation tests exist; authentication of `S`, `R` and shared list remains postselection |
| V4: unconstrained/second secret | Relation semantic faults and unchecked-prover rejection tests exist; these are finite constraint checks, not a soundness theorem |
| V5: wrong vote authorization | Authorization-half/state and changed-message proof faults exist |
| V6: wrong nullifier/authorization lengths | Fixed-length standalone decoding and frame faults exist; production Norito decoder remains postselection |
| V7: wrong proof length | Exact-size/trailing/truncation tests cover both standalone roles/rows |
| V8: counter above `0x000fffff` | Extended-backend and ballot tests require refusal before reconstruction |
| V9: valid non-minimal counter | [Four constructive tests](../docs/validation/parliament_ballot_b6/nonminimal-counter-results.md) pass in both modes, covering both rows/roles (vote `S=3`): original and second-valid proofs accept; changing only the counter rejects. One verifier challenge evaluation is source-inspection evidence, not an instrumented test result |
| V10: changed vote/nullifier/authorization/list/context/policy/profile | Relation, proof-binding and decoder faults exist; authenticated production mappings remain postselection |
| V11: exact ballot relayed before creator | Standalone exact-proof acceptance exists; first-in-canonical-order and later duplicate handling remain postselection |
| V12: replay into another body scope | Changed body/scope proof rejection exists; chain authentication remains postselection |
| V13: unknown/mismatched profile | Standalone retired-descriptor, role/row and descriptor checks exist; production profile admission remains postselection |
| V14: concurrent/same-block duplicate nullifier | Postselection atomic admission and canonical-order tests |
| V15: invalid proof claims honest nullifier | Invalid proof rejection exists; proving that later honest admission remains available requires postselection state tests |
| V16: rerandomized pending flood | Postselection admission/dedup/queue test before verification |
| V17: stamp reused with altered proof bytes | Postselection stamp binding and cheap-rejection test |
| V18: invalid ballot from Byzantine proposer | Standalone verification rejects tested faults; block validity across honest validators remains postselection |
| V19: invalid/stamp-bearing saturation | Postselection quantified attack-budget, inclusion and unrelated-transaction progress tests, using complete charge/capacity accounting |

### Clock, closure and outcomes

All these observations concern the replacement's authenticated state machine;
standalone proof tests do not discharge them.

| ID / case | Remaining requirement |
| --- | --- |
| C1: closing-block/late ballot, rollback/restore | Postselection cutoff and unchanged-corpus restore tests |
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
| S5: admission beyond `K` | Reject before attempt allocation; postselection integration test |
| S6: idle chain after opening | Casting clock due at `h_open+1`, frozen closing time and unchanged `s0`; postselection joint test |
| S7: pause/opening order and stale holds/heads | Position-aware lift rule and rejection of stale/older decisions; postselection joint test |
| S8: CPU versus acceleration | Standalone ARM byte/accept/reject evidence exists; physical x86 and production consensus-output/charge parity remain |
| S9: wallet anonymity mode | Postselection SDK/wallet traffic tests excluding account/session/entry/nullifier-labelled requests |
| S10: two proofs, distinct fresh 112-byte tapes | Tape layout and distinct deterministic test-tape proofs exist; production wallet entropy generation and nonreuse enforcement remain postselection |
| S11: unavailable random source | Standalone tape/secret fill tests fail without a value; production wallet no-fallback behavior remains postselection |
| S12: forced counter exhaustion and fresh retry | Backend bounded-grinding and typed error propagation tests exist; complete wallet retry on an unchanged statement with a fresh tape remains postselection |
| S13: same explicit tape across paths | Fixed-tape vectors and ARM feature/platform digest agreement exist; physical x86 proof-byte/exhaustion parity remains |

The formal model must replace timed-release phases with credential sealing,
casting, verified unique-nullifier append, deterministic closure and terminal
outcomes, preserving the listed quorum/retry/capacity/rollback rules. Its crypto
checks remain assumptions, not anonymity proofs. Consensus changes require
named deterministic simulator regressions/mutations, and later real-peer tests
use a legal committee of at least four validators. These are postselection
integration obligations, not new standalone work authorized by this audit.

## Concrete remaining work and ownership

| Work | Owner / current state |
| --- | --- |
| Bidirectional signature cross-verification against pinned official FAEST | Local reference-mode checkpoint complete for twelve sets; [record](../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/cross_verification.md) separates original source-guard publication rejection, retained negative logs and the recovery's 84 positive checks. Regenerated C proofs and missing original raw C return values are explicit; no ballot-extension or current-tree qualification |
| Constructive valid-nonminimal-counter acceptance | Local component check complete: four tests and strict lint pass in each feature mode; [receipt](../docs/validation/parliament_ballot_b6/nonminimal-counter-receipt.json) pins the 92-file source scope and binaries. Vote cases use `S=3`; no production or hardware qualification inferred |
| Malformed-encoding time/allocation distributions and maxima | Selected local campaign complete: 10,168 observations across both modes, expected refusal and 164-class input/outcome/diagnostic parity; [receipt](../docs/validation/parliament_ballot_b6/malformed-receipt.json) pins the new 225-file source scope. Shared warm-process observations only; complete malformed-input bounds and baseline qualification remain open |
| Standalone charge and workspace contract | Owner-authorized research/proposal implemented: [fixed reservation and bounded worker](parliament_ballot_resource_contract.md), 10 Rust tests per mode, 33 supervisor tests and 120 source-bound worker calls pass. Full physical cost and runtime/workspace certificates remain open; the prior front-end inventory remains a distinct frozen worksheet |
| Actual generator driver, remaining reductions and full resource vectors | Cryptographic author and independent reviewer; open. Reference games do not accept new premises |
| Primitive/model qualification and independent attack-cost assessment | Independent cryptographic reviewers; open |
| Both security weakenings, approved premises and envelope-order resolution | Design owner with required independent review; open |
| Exact Xeon and named phone evidence, physical x86 parity, battery/thermal/cancellation conditions | Hardware/qualification owners; open; Intel run explicitly deferred by owner |
| Capacity/admission derivation | Resource and governance-policy owners; open, using complete qualified worst-case costs; no policy parameter silently chosen |
| SCCP start-phase source-contract mismatch | SCCP and Parliament integration owners; open. The [latest actual recheck](../docs/validation/parliament_ballot_resource_contract/source-contract.json) still fails after further concurrent hooks. Historical 1,115/92 totals and in-memory isolation describe their earlier source snapshot |
| Production implementation, retirement and launch qualification | Postselection owners; gated by unmet selection conditions and eventual owner qualification record |

The three focused accounting suites pass 38 tests and six subtests on the
recorded source and its [isolated reconstruction](../docs/validation/parliament_ballot_b6/frozen-accounting-recheck.json).
A subsequent unrelated root-lock edit and later Norito source edit are retained
with exact provenance; resource/front-end guards refuse the changed live input.
The frozen reconstruction remains separate from these later sources. On the frozen source, the
security check intentionally returns exit 2 with qualification false; the
resource and front-end checks return exit 1 with complete certificates false.
The actual source-contract guard still rejects the current Core start-phase
ordering. New test-only work has separate source identities and receipts; the
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
