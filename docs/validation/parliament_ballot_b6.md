# Parliament ballot B6 qualification evidence

Status, 2026-10-13: **experimental; no profile selected or qualified; production
remains gated.** This record extends the [B1–B5 evidence](parliament_ballot_standalone.md)
and tracks the [B6 goals](../../specs/parliament_ballot_implementation_goals.md).
It records completed local work and concrete remaining obligations, not an
independent reviewer or owner's approval.

The [requirement audit](../../specs/parliament_ballot_b6_requirement_audit.md)
maps every design security gate, selection condition and validation-table row
to its evidence and remaining work, including obligations that must wait for
production implementation after selection.

## Security accounting

The [source-hypothesis review](../../specs/parliament_ballot_b6_security_review.md)
and [executable ledger](../../scripts/check_parliament_ballot_security_ledger.py)
reproduce exact soundness crossings, the opening-size expectation and retry
bound, high-precision loss arithmetic, resource subtotals and residual budgets.
Missing bounds remain `null`; `--require-qualified` exits 2. Fifteen tests cover
independent small-heap enumeration, adjacent exact threshold inequalities,
precision stability and fail-closed reporting.

The written bound containing `Z` cannot certify advantage `2^-64` at any
nonnegative external query budget when lifetime `T = 2^44`: already
`epsilon_P1(0) = 6 * 2^-64`. This is an upper-bound limitation, not an attack.
The recalibrated requirement of a complete bound below `1/2` at `2^64`
queries plus an independently assessed `2^128`-gate attack cost also remains
unestablished. The review identifies unresolved leaf-generator query and
switching interfaces, primitive-to-model bridges, and omitted reduction work;
the nominal substitutions do not fill them. The full theorem, primitive
assessment and both owner acknowledgements are still required. The
[generator-interface note](../../specs/parliament_ballot_b6_generator_interface.md)
pins the implemented key/IV/tweak call matrix, two reference oracle games,
conditional leaf postprocessing and the missing hybrid embedding. It also
shows why arbitrary IV/tweak pairs cannot be treated as independent labels
under one key. None of these local facts supplies the unresolved primitive
bound.

The [candidate request-stage calculation](../../specs/parliament_ballot_b6_request_accounting.md)
reconciles the nominal primitive subtotal without changing its number. The
4,096 term alone does not bound preparation; it is the intercept of a coupled
request/query inequality. All 998 vote sizes and maximum registration satisfy
the reviewed stage bounds when every induced backend call includes `H_mu`.
Six tests cover the calculation and its refusal behavior; the comparator is
explicitly outside this coefficient. This closes one component attribution,
not the complete physical, reduction or cryptographic resource bound.

The separate [real-prover calculation](../../specs/parliament_ballot_b6_prover_accounting.md)
checks the non-counter `2^16` Keccak allowance at explicit typed-input and
bounded-setup entries. Candidate registration/vote maxima are 9,996/14,916
permutations, or 10,767/19,112 with one bounded setup. Comparator maxima with
setup are 55,683/63,849. The counter contributes exactly `2 + 2A <= 4A` for
`A >= 1`, including failed attempts. Nineteen tests and a 76-file source receipt
support this component calculation. Arbitrary governance-preimage setup can
exceed the allowance; a complete honest-game/simulator driver and its resource
bound are still missing. These source counts are neither an attack-cost
assessment nor independent cryptographic review.

The [bounded hybrid-driver proposal](../../specs/parliament_ballot_b6_hybrid_driver.md)
repairs a missing worst-case sampler boundary in the proposed experiments:
use bounded auxiliary sampling already before material replacement, when its
exhaustion value is private unused bookkeeping. It specifies opening caches,
whole-lifetime oracle state and actual-IV component interfaces. Local algebra
supports every fixed opening. A separate [conditional fixed-opening H5 derivation](../../specs/parliament_ballot_b6_h5_fixed_opening.md)
now supplies a gate-domain adaptive-reprogramming bound at the explicit ideal-row
entry, including one own-label-equality charge. The
[zero-challenge certificate](parliament_ballot_zero_challenge/README.md) verifies
the fallback for both actual rows and roles. The separate
[joint mask-coordinate derivation](../../specs/parliament_ballot_b6_mask_coordinate.md)
preserves the full oracle/transcript state through the ten-mask change of
variables, under explicit ideal-row, independent high-mask and prescribed-challenge
premises. Actual table checks cover both rank-256 maps and all 127,488 bilinear
basis pairs. Its endpoint retains ideal commitment material; a finite support
argument rules out identifying that distribution exactly with real-root `Sim+`.
A separate [hidden-assignment deletion derivation](../../specs/parliament_ballot_b6_hidden_assignment_deletion.md)
now removes the patches at that same ideal-material boundary. It proves joint
pad/query independence in the unpatched baseline and applies a full-state
lookup comparison across adaptive requests and exhaustion. This conditional
result does not supply the ideal-entry or reverse material bridges, complete
reduction resources or the complete simulator proof.
The existing arguments and ledger are unchanged; local consistency review does
not supply independent cryptographic review or qualification.

## Standalone adversarial and conformance evidence

The [fatal-control revision](parliament_ballot_fatal_control/README.md) fixes a
resource-failure write that blocked charged verification on full stdout pipes.
Both frozen binaries reproduce the defect. Fresh binaries publish exact debit
through a counted shared page before exiting, and the external supervisor
formats the failure afterward. All 122 new observations and full/broken-output
controls pass; 17 Rust tests per mode, strict Clippy and 61 focused Python tests
pass. The reserved mapping is now 41.109375 MiB on this Mac. Earlier images and
their compiled analyses remain historical; this is not a complete stack/work,
native-memory or physical-cost certificate.

The [fresh stack captures](parliament_ballot_fatal_stack_eon/README.md) bind the
same shared-control binaries. The analyzer now handles their scalar `STLUR` and
`EON` instructions, with 62 passing regressions and no frame-decoding errors in
either image. It exposes two additional portable AES native-copy calls rather
than treating them as zero cost. Local worker/fatal frames are 176/16 bytes;
the finite resolved regions are 15,984/13,440 bytes by mode, excluding opaque
costs. Native calls, indirect targets, exceptional edges and the 63-function
recursive component still prevent a complete stack bound.

The separate [adapter bound](parliament_ballot_adapter_bound/README.md) isolates
the code around `Reservation::verify` in these two images. Under its explicit
ownership, ordinary-flow and native premises, that region uses at most 336
stack bytes including the red zone, 5,298 issued instructions outside opaque
callees, and one 524,288-byte input block inside the existing arena. All 20
checker tests pass. The verifier and native routine costs remain unknown;
this does not supply a whole-call work or workspace certificate.
After capture and passing tests, concurrent edits changed `Cargo.lock` and four
allocator files. The [post-analysis check](parliament_ballot_adapter_bound/post-analysis-source-check.json)
retains their exact hashes, and the [current-source refusal](parliament_ballot_adapter_bound/current-source-refusal/report.json)
correctly reports UNKNOWN. The recorded binaries, reports and source interval
remain unchanged; no result is transferred to those later source revisions.

The [campaign inventory](../../crates/iroha_zkp_vole/tests/fixtures/standalone_adversarial.md)
records deterministic malformed-input campaigns in portable and accelerated
release modes: 3,100 backend cases and 5,656 ballot cases, with identical
outcome digests across modes. These include parser boundaries, trailing and
truncated records, row/profile confusion, bounded lists, counters, padding and
late-invalid full verification. Every designated invalid full proof rejects.
A parser may accept a syntactically valid mutated object; the inventory's
`true` count must not be interpreted as full-proof acceptance.

The [direct upstream CRT comparison](../../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/upstream_crt_comparison.txt)
checks every table word in all eight profiles against unmodified upstream C++
at the pinned FAEST commit. The [driver and provenance](../../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/README.md)
make this distinct from Rust table regeneration. Official reference-mode
signatures and project-generated ballot vectors remain separate constructions.

The [bidirectional FAEST cross-verification record](../../crates/iroha_zkp_vole/tests/fixtures/faest_v3_0_2/cross_verification.md)
covers all twelve reference parameter sets. The original campaign completed its
functional cases, including negative inputs, but rejected publication after
concurrent root-lock drift. Its retained logs establish the checked outcomes;
the individual C rejection codes and original C proof bytes were lost. A separate
recovery retained the Rust proofs, regenerated explicitly labelled C proofs and
passed 84 positive verification calls against the unchanged executables and
library, including 48 cross-implementation exchanges. It did not rerun negatives
or invent the missing data. The diagnostic driver now preserves completed cases
and rejected reports. This evidence covers plain FAEST, not the ballot extensions,
and does not qualify the changed live checkout.

The separate [ASan/libFuzzer parser workspace](../../crates/iroha_parliament_ballot_proof/fuzz/README.md)
completed bounded 61-second runs: 1,038,579 portable inputs and 958,154
accelerated inputs without a crash. Its 124-input retained union is archived
with input/source hashes; portable and accelerated replay has the same
syntactic outcome digest. The fuzz target parses bounded raw proofs and test
records; it does not run full cryptographic verification or prove exhaustive
malformed-input coverage. Full-verifier mutation coverage is the separate
deterministic campaign above.

The [non-minimal-counter tests](parliament_ballot_b6/nonminimal-counter-results.md)
construct a second acceptable opening/challenge for registration and a three-seat
vote on both rows. Original and later valid proofs accept; a counter-only change
rejects. All four tests and strict lint pass in both feature modes. This fills
the constructive acceptance case without changing the proof implementation.

The [malformed-encoding campaign](parliament_ballot_b6/malformed-results.md)
adds 10,168 timed rejection observations: 164 selected classes, 31 repetitions
per class in each feature mode. All input digests, lengths, rejection outcomes
and untimed diagnostic classes match across modes. Raw records retain timing
and requested-heap distributions and maxima. Each fixed mutant is repeated in
a warm process after preflight; construction/proving/diagnostics are untimed,
and the shared host was not isolated. These are neither exhaustive adversarial
coverage nor worst-case or hardware-baseline certificates.

## Measurements and identity

The [runner and method](../../crates/iroha_parliament_ballot_proof/examples/QUALIFICATION.md)
measure input setup, actual proving, test-record encoding, fresh input decode
and verification, decode alone, warm verification and late-invalid fresh-input
verification. Maximum registration fields and 3-, 500- and 1,000-seat lists
are used. Every proof has fresh deterministic **test-only** tape bytes, recorded
retry counts and a proof digest. These are cold-input tests in a warm process,
not cold-process/cache tests. The encoded test record is not a production
Norito envelope. All result headers explicitly keep qualification false.

The [source manifest](parliament_ballot_b6/mac-source.sha256) identifies 223 files,
including the standalone implementation, runner and transitive local sources.
Its SHA-256 is
`044ecda041aefe175861344d821d019d88d38004b9c2297e68d6dafb8b8e65cb`.
Normal revision metadata was retained for these builds. The older B5 manifest
is a historical snapshot; adding the B6 runner's Norito JSON development
dependency changes its manifest/lock entries without changing its recorded
measurement program. Do not overwrite old evidence to make that snapshot match.

All recorded device runs finished before a subsequent root-lock change: the
final Android source check passed at 03:00:48 UTC, and a later check observed
the change at 03:02:07 UTC. At that check, only `Cargo.lock` differed among the 223 manifest
entries: the unrelated `integration_tests` dependency list gained `iroha_sccp`.
The [measured lock](parliament_ballot_b6/measured-root-Cargo.lock.template)
was recovered in memory and matches the previously frozen SHA-256 exactly;
the [provenance record](parliament_ballot_b6/post-measurement-lock-change.json)
retains both hashes. The live lock was left unchanged. A subsequent qualification audit narrowed
overstated erasure Rustdoc in three ballot files; executable code is unchanged.
The [exact comment patch](parliament_ballot_b6/post-measurement-rustdoc.patch)
and [before/after hashes](parliament_ballot_b6/post-measurement-rustdoc.json)
retain that difference. The later malformed subcommand has a separate
[runner patch and source identity](parliament_ballot_b6/post-measurement-malformed-runner.json).
Reversing both patches only in a temporary reconstruction, with the recovered
lock, [verified all 223 measured source hashes](parliament_ballot_b6/measured-source-reconstruction.json).
These results identify the measured sources/binaries, not a qualification of
the later checkout; future candidates require fresh source identification and
checks.

A [later root-lock change](parliament_ballot_b6/post-qualification-lock-change.json)
added `iroha_allocation` only to `iroha_sccp` at 04:18:41 UTC. It occurred after
the malformed/counter/accounting checks and during the longer upstream
cross-verification run. Removing that one edge only in memory reproduces the
[qualification lock snapshot](parliament_ballot_b6/qualification-root-Cargo.lock.template)
exactly. No live lock was changed. All 225 malformed and 92 counter source
entries reconstruct with that lock. The three accounting reports reproduce
byte for byte in an isolated reconstruction, whose [38 tests and six subtests
pass](parliament_ballot_b6/frozen-accounting-recheck.json). The resource and
front-end guards correctly refuse the subsequently changed live lock; their
recorded reports and tests concern the frozen source, not this later tree.
A further [Norito source edit](parliament_ballot_b6/post-qualification-norito-change.json)
was observed at 04:42 UTC, after that reconstruction. Its earlier hash-verified
source is retained in a separate template. The 225-file malformed scope and
223-file device scope need that additional substitution; the 92-file counter
scope does not contain Norito. These preserved snapshots do not validate the
later concurrent code. The [final reconstruction receipt](parliament_ballot_b6/checkpoint-source-reconstruction.json)
verifies all three recorded scopes with the exact substitutions listed.

The [artifact manifest](parliament_ballot_b6/B6_ARTIFACTS_SHA256SUMS) covers the
retained reports, raw observations, templates and accounting tools. Its paths
are repository-relative: run `shasum -a 256 -c
docs/validation/parliament_ballot_b6/B6_ARTIFACTS_SHA256SUMS` from the repository
root. The separately pinned fuzz corpus has its own source/evidence manifest.

[Mac results](parliament_ballot_b6/mac_results.md) retain raw records, exact
commands, build identities and all phase distributions for both modes:
31 samples per candidate case and three per comparator case, 136 proofs per
mode. Every paired proof digest and retry count matches. The host was shared
with builds, so timing contention is disclosed; it is not the Intel baseline.

[Attached iPhone results](parliament_ballot_b6/ios_results.md) retain 272 proofs,
136 matching feature-mode digest/retry pairs and 272 matching same-mode Mac
comparisons, together with the native host source,
device observations and feature-specific binary identities. The usable device
is an iPhone 17 Pro Max (`iPhone18,2`, iOS 26.7), not the required iPhone SE
third generation. USB-connected charging measurements do not establish
battery-operation qualification. The other attached phone reports `iPhone8,4`
and an unsupported Xcode connection even after trust, so it supplied no run.
The Samsung connection was initially ADB-unauthorized and became authorized
after reconnecting. It identifies as SM-S942B, Android 16/API 36, ARM64;
its native shell benchmark supplies separate device evidence, not Pixel or
native-application qualification.
[Samsung results](parliament_ballot_b6/android_results.md) retain all 272
successful samples, 136 matching feature-mode digest/retry pairs and 272
matching same-mode Mac comparisons, with battery, thermal and process-memory
observations. Across the Mac and both attached phones, all 816 benchmark
samples completed; corresponding public test tapes intentionally repeat
across modes/platforms for parity.

Requested Rust heap measurements include retained encoded inputs and runner
bookkeeping; stack, allocator overhead and native heaps are excluded. The iOS
host additionally samples process footprint, resident memory, battery and
thermal state every 250 ms. Sampled process maxima can miss instantaneous
peaks. These different memory measures must not be combined into a claimed
deterministic production ceiling.

## Encoding and standalone resource model

[Resource accounting](../../scripts/check_parliament_ballot_resource_accounting.py)
checks all eight raw proof lengths and frame-size formulas, plus the
[source-bound standalone model](../../specs/parliament_ballot_b6_standalone_resources.md)
for both rows and roles. It inventories CRT work, relation arithmetic and degree
alignment, complete transcript sponge counts, PRG construction and separated
loop units. Its 11 tests include independent serialized frames, sponge byte
schedules, matrix application, vector growth and source-change rejection.
`--require-complete` exits 1 until every full-certificate term is established.

The separate [front-end worksheet](../../scripts/parliament_ballot_frontend_accounting.py)
adds source-pinned logical parsing, copy, framing, initialization and CRT-encoding
charges, with [retained output](parliament_ballot_b6/frontend_accounting.json).
Twelve focused tests check independent bytes and decoder traces, including a
1,000-entry list that falsely declares three entries. Rejection bounds use
actual input length. This closes a finite front-end inventory gap; backend,
provider, allocator, stack and full charge semantics remain unqualified.

The conditional allocation model pins Rust 1.93.1's requested-allocation
policy and 81 source/build-identity files, separately from the older measured
snapshot. Phase lifetimes retain live statement, VOLE, gate, mask and relation
buffers. The [compile-only provider probe](parliament_ballot_b6/provider-layout.md)
adds the 960-byte AES provider allocation for all eight target/mode pairs;
it is not physical x86 testing. The largest modeled verifier-owned requested
heap is 6,278,911 bytes (comparator vote, 1,000 seats), or 6,565,569 bytes
including an exactly sized canonical test-record allocation. Candidate
1,000-seat figures are 3,708,058 and 4,069,654 bytes respectively. These bounds
exclude arbitrary caller spare capacity, stack, allocator overhead, native
heaps, compiler temporaries and concurrency; they do not establish a process
memory ceiling.

The candidate proof sizes remain 160,148 bytes for registration and 233,012
bytes for a vote. At 1,000 seats the vote test statement is 128,576 bytes and
the full test record is 361,596 bytes, including its eight-byte framing and
shared list. This is not a violation or a certification of the 262,144-byte
production ballot-envelope cap: shared seal/list context has its own
163,840-byte cap. The combined allowed cold input is 425,984 bytes. After the
vote proof and 467 fixed cryptographic field bytes, 28,665 envelope bytes
remain for the other fields, admission stamp and framing.

The maximum registration transcript frame is 5,946 bytes; its test statement
is 6,016 bytes. The list digest frame is `128 S + 114` bytes, and vote
authorization digest frame is `128 S + 536`. These are standalone protocol
preimages, not proposed production wire schemas.

Selected source loops bound candidate-vote verification by 2,750,672 AES
blocks, 85,292,332 small-VOLE fold byte-XORs, and 60,282 bytes of conversion
scratch payload. Mixed field-product counters combine full-field and scalar
multiplications and are not equal-cost operation counts. The
[allocation inventory](../../crates/iroha_zkp_vole/tests/fixtures/standalone_adversarial.md)
and expanded model explain lifetimes and separate candidate/comparator payloads.
Finite byte-copy, initialization, encoding/decoding, zeroization and scalar
control work are not fully charged. These components are not the complete
`B_work`, full heap/stack bound or stamp difficulty.

## Implemented reservation and workspace proposal

The owner requested research and implementation to resolve the undefined
charging and workspace boundary. The [proposal](../../specs/parliament_ballot_resource_contract.md)
and [new validation record](parliament_ballot_resource_contract/README.md)
define one complete cold-verification reservation plus actual input bytes,
atomic admission and no refunds, bounded input copying, a reclaiming heap and
an explicitly supplied native stack. Ten Rust tests per feature mode, strict
Clippy and the original 33 supervisor tests pass. A later supervisor-only scope
check rejects incomplete build inventories; all 35 updated tests and revalidation
of the 120 retained observations pass. All 120 source-bound worker calls pass,
with 60 matching outcome/stage/debit pairs. The fixed mapping is 41.09375 MiB
on this Mac; runtime/System/TLS coverage, all-valid-input sufficiency and
physical-cost calibration remain open. This does not supply a complete 64 MiB
certificate or qualified block/stamp/casting budgets.

The [native runtime audit](parliament_ballot_resource_contract/native-runtime-audit.md)
traces the ordinary cold path and identifies System/TLS/panic bypasses and
pthread infrastructure excluded from the application control partition. It
does not establish installed-runtime allocation coverage or a native byte bound.
The subsequent [native endpoint experiment](parliament_ballot_native_probe/README.md)
implements a separate derived worker, controlled interposition and installed
runtime UUID capture. Its counters record named endpoint calls and requested
arguments, not unique live bytes or complete native coverage. Required
System/thread/TLS positive controls precede proof observations; failures remain
in the retained report. All 14 controls and 120 proof cases pass with unchanged
guarded inputs. The 66 completed charged intervals and 16 terminal incomplete
intervals observe no calls to the named endpoints; 38 cases are unadmitted.
Hidden paths and complete native-memory bounds remain open. This does not modify
the frozen resource evidence.

The [conditional arena argument](../../specs/parliament_ballot_arena_sufficiency.md)
now proves spatial admission inside an explicit source-allocation model:
an order-independent frontend bound plus 135,064 retained-layout replays.
The [new evidence](parliament_ballot_arena_sufficiency/README.md) includes
88 actual-allocator trace controls and fail-closed publication checks.
Conditional rounded-live bounds are 5,017,216 bytes for the candidate and
7,211,136 bytes for the comparator. Representative allocation counts are
not universal all-length work bounds. Selected
[compiled layouts](parliament_ballot_arena_layout/README.md) support three
private-type premises and return-object drop order in the frozen workers.

The separate [compiled allocation-stream campaign](parliament_ballot_allocation_trace/README.md)
now matches 132 observations and passes 14 controls, with 2,041 guarded inputs
unchanged. The 132 corpus streams contain 8,943,472 ordered allocation/free
events from newly instrumented workers, checking layouts, offsets, cleanup,
debit and stages.
All 66 feature-mode pairs agree on outcomes and charges. Recorded peaks reach
the conditional source-model ceilings. The recorder reserves another 16 MiB;
dump serialization occurs outside the charged interval. This establishes
finite grammar membership for the instrumented binaries, not universal
correspondence or complete native/runtime coverage. Invalid recorder controls
and terminal missing streams remain explicit failures of complete observation.

The [compiled stack audit](parliament_ballot_compiled_stack/README.md) retains
26 analyzer tests and exact instruction evidence. The separate
[provider-target catalog](parliament_ballot_indirect_targets/README.md), with
36 passing tests, extracts three AES tables and resolves seven backend sites
conditionally through 21 edges per frozen image. Source-supported target
completeness is not whole-binary points-to analysis. Resolved regions remain
15,984 bytes portable and 13,232 accelerated; each graph retains 32 indirect-call
frontiers, 169/163 native edges and one 69-function positive recursive component,
alongside exceptional/fallthrough gaps. Complete bounds remain unknown; neither
8 MiB stack nor 64 MiB workspace sufficiency is established. Complete compiler
allocation correspondence, native/runtime coverage and calibration remain open.

A separate [failure-entry analysis](parliament_ballot_stack_frontiers/README.md)
now identifies 31 of those 32 indirect sites behind three explicit panic or
allocation-failure entries. Cutting those entries, while retaining each as an
unknown-cost obligation, removes positive recursion from the remaining graph.
The reservation root has no indirect calls there; the worker retains one I/O
error destructor. Conditional caller-frame contributions are 15,648/13,056
bytes at reservation entry and 15,984/13,392 at worker entry. These are not
complete stack bounds: every native/failure callee, trap, unwind continuation
and fallthrough obligation remains. The analysis does not prove malformed or
valid inputs avoid panic, and does not modify the older reports.

The [allocator-activation check](parliament_ballot_allocator_activation/README.md)
further checks the worker's true flag store and four explicit System allocation
branches per frozen image. Activation dominates the verification call, and
those branches require a false flag. Under explicit private-state
noninterference, source/compiler and ordinary-ABI premises, System frontiers
narrow from 14 to 10 per mode; ten frees remain. The resolved reference catalog
does not prove absence of arbitrary alias writes or callbacks. Unconditional
activation remains unknown, and no complete stack or workspace bound changes.

The separate [ownership audit](parliament_ballot_ownership/README.md) checks
81 source identities and 65 excerpts: no setup heap owner crosses reservation
entry, and its owned containers are constructed below that entry. The
[compiled free predicates](parliament_ballot_free_predicates/README.md) check
the ten remaining sites per image, including alternative capacity guards and
same-pointer forwarding. An observed non-null arena routes a pointer away from
System only when `P >= heap && P - heap < bytes`. These facts support a
conditional ownership argument; they do not establish universal machine
provenance, intact state or noninterference. All ten unconditional free
frontiers remain open.

The [I/O error guard](parliament_ballot_io_error_guard/README.md) separately
checks the worker destructor's fourteen-instruction non-Custom return path in
both images. Seven pinned Rust sources support OS/static-EOF error construction
for ordinary charged File reads. Whole-worker variant flow is unproved, so its
indirect frontier also remains open. Native, exceptional and full resource
requirements are unchanged; no old binary or graph was rewritten.

The dev-only native dependency addition and later unrelated lock changes have
explicit before/after provenance. The [new historical reconstruction](parliament_ballot_resource_contract/dependency-change/reconstruction-receipt.json)
reproduces the original 223/225/92 source scopes with archived substitutions,
including the pre-dependency ballot manifest. Earlier measurements and reports
are unchanged; the new campaign has its own executable/source identity.

## Standalone cancellation and cleanup

The [lifecycle contract](../../specs/parliament_ballot_prover_lifecycle.md) and
[adapter/tests](../../crates/iroha_parliament_ballot_proof/examples/prover_lifecycle/job.rs)
now define finish-and-discard behavior for the existing synchronous prover.
One synchronized publication decision makes an accepted cancellation
irreversible. Waiting joins computation and cleans input owners; finishing or
dropping a cancelled job also clears the unpublished proof. Cancellation does
not stop computation or establish prompt completion.

[Retained validation](parliament_ballot_prover_lifecycle/README.md) covers both
rows and roles (votes at `S=3`), ordinary fixture parity, cancellation at an
actual witness-allocation milestone, cancellation after computation, publication
races, unfinished-handle drop, ordinary errors and partial entropy-fill errors.
Eight release tests pass in each feature mode. A calibrated allocator probe
reads selected secret, tape, witness and proof ranges while still allocated,
immediately before release; both all-zero and last-byte-nonzero controls pass.
These observations do not cover every scratch buffer, compiler-created copy,
register, stack spill or abort path, and do not qualify phone latency or memory.

Concurrent Norito edits interrupted attempts to keep the entire build/lint/smoke
sequence on one unchanged source inventory. The retained records identify the
clean before/after source intervals for the passing tests and separately label
later checks. They do not claim a single unchanged-source full campaign.
Earlier resource and device measurements retain their original identities.

## Remaining requirements and explicit TODOs

| Requirement | Remaining evidence / owner |
| --- | --- |
| Cryptographic selection | Reviewed adaptive embeddings; explicit multiquery generator interfaces; quantified `P`, `U`, generator, frame and backend-model premises; complete reduction resources and independent attack-cost assessment |
| Owner decisions | Record extraction-to-soundness and security-contract weakenings, approved premises and eventual qualification; engineering instructions are not those attestations |
| Intel validator | **TODO: owner deferred this run.** Exact Xeon Silver 4310, one physical core at 2.10 GHz, turbo off, idle SMT sibling; an arbitrary Intel machine does not silently replace it |
| Android baseline | **TODO:** Pixel 6a native release application, battery and sustained thermal runs; authorized attached Samsung supplies separate native-shell evidence |
| iOS baseline | **TODO:** iPhone SE third generation, battery and sustained thermal runs; the attached iPhone 17 Pro Max is supplementary evidence |
| Platform coverage | Physical x86/ARM parity, cold-process/cache conditions, named-phone cancellation latency/memory and independent constant-time/erasure implementation review. Standalone finish-and-discard semantics and selected-buffer cleanup tests are implemented; process termination does not establish Drop cleanup. |
| Deterministic accounting | Standalone charge/boundary proposal and conditional source-model arena sufficiency implemented. Complete compiled allocation correspondence, indirect/native/recursive stack bounds, runtime/System/TLS coverage, independent unsafe review and physical-cost calibration remain open. Complete authenticated envelope/shared-context mapping follows the resolved selection order; block budgets, stamps and casting capacity need qualified costs. |
| Selection ordering | Owner and independent reviewer must resolve the documented dependency between preselection complete-envelope accounting and postselection schemas; no requirement is waived by the standalone size inventory. |
| Production implementation | Selection must precede schemas, Core/State, signerless admission, Torii/SDK and timed-OVN/TLE retirement; lifecycle/network/release qualification follows that implementation |

The binding-ballot availability function remains false and qualified attempt
latency remains unavailable. No experimental crate has been connected to Core.
The complete workspace suite was not run for this standalone work; unrelated
concurrent changes and repository signing/staging state were preserved.

## Current-tree checks and concurrent failure

The [in-memory worker](parliament_ballot_memory_entry/README.md) moves retrieval
outside the charged interval and checks the actual borrowed length before its
arena copy. Its separate binaries pass 16 release Rust tests, strict Clippy and
builds per mode; all 122 observations pass with matching outcomes/stages/debits.
The final campaign checker passes 20 tests after its JSON-overflow correction.
The original resource worker and its disassembly remain frozen under their
original scope. The separate [normal-return analysis](parliament_ballot_noreturn_frontiers/README.md)
explains 50/52 ordinary continuations and 23/26 traps under explicit premises;
native unwind, unconditional frontiers and complete resource costs remain open.

The [memory-entry/frontier checks](parliament_ballot_b6/memory-driver-checks.json)
pass 51 focused Python tests, diagnostic Rust formatting and the codec guard
for their retained source interval. The [fresh Core source-contract check](parliament_ballot_b6/adapter-deletion-source-check.json)
after a concurrent queue edit still first fails on `queue.rs` missing the modeled `Executable::IvmProved(proved)`
binding. That is a later source identity than the historical start-order
failures below; it does not establish that subsequent guard sections pass.
Availability remains false, qualified latency remains `None`, and neither Core
nor Torii depends on the experimental ballot/backend crates.

The [ownership/guard checks](parliament_ballot_b6/ownership-guards-checks.json)
pass 60 focused Python tests. Separate peer reviews found and repaired
pointer-origin and frozen-identity gaps before the new reports were finalized.
The ownership audit rechecks 81 source hashes and 65 excerpts. These checks
retain all ten unconditional free frontiers per mode and the worker I/O
frontier. The Core source-contract ordering failure remains; the production
gate is false and qualified attempt latency is still `None`.

The [allocation/frontier/prover checks](parliament_ballot_b6/allocation-frontier-prover-checks.json)
pass 120 Python tests and 182 subtests. Both allocation-trace builds separately
pass 17 release Rust tests, strict Clippy and builds. The 132-observation,
14-control trace campaign passes, and the activation analysis retains its
conditional result with 39 focused tests. Diagnostic source formatting and
the codec guard pass. The real Core source-contract check still fails on
block-start ordering; availability is false and qualified latency is `None`.
No complete workspace test or qualification pass is claimed.

The subsequent [native/call-target checks](parliament_ballot_native_probe/final-checks.json)
pass 60 Python tests and three subtests, diagnostic Rust formatting and the codec
guard. The native adapter separately passes 15 release Rust tests, strict Clippy
and builds in each mode. Its 134-observation campaign passes. Current repository
formatting has unrelated SCCP/Mochi differences, and the Core source-contract
failure remains. These are scoped results, not a complete workspace pass.

The earlier scoped arena/stack validation passes 99 Python tests, six Rust
oracle tests, strict release Clippy, formatting and the codec guard. Its
[receipt](parliament_ballot_arena_sufficiency/validation-receipt.json) again
records the separate Core source-contract failure described below. A later
unrelated lock change is archived separately from the oracle's clean build
interval; neither its source identity nor older worker measurements were repinned.

The three focused accounting suites passed 38 tests and six subtests before
the later lock change ([transcript](parliament_ballot_b6/accounting-requirement-audit-tests.txt)),
and repeat that result in the [frozen reconstruction](parliament_ballot_b6/frozen-accounting-tests.txt).
All three reconstructed qualification/certificate checks refuse qualification
as intended; current-tree resource/front-end checks separately refuse source drift.
Runner helper tests, bridge host
tests, strict standalone lint, formatting and codec checks are recorded with
their respective artifacts. The broader Python Parliament regression run
completed with **1,115 passed, 92 failed and six subtests passed**. All 92
failures are in the source-contract suite, whose initial current-tree check
fails on `crates/iroha_core/src/state.rs`: the concurrently added
`sccp::governance_clock::advance_reconciliation(&mut sb)?` call occurs in a
region that the guard still requires to contain exactly four start-phase calls.
The remaining mutation tests inherit that baseline mismatch.

This broader check is **not passing**. A read-only diagnostic that omitted the
single new call in memory allowed the complete guard to pass, including the
current B6 documents. No Core source or guard was changed for that diagnostic;
it is not a fix or validation of the reconciliation hook. The SCCP integration
must reconcile its hook, ordering contract and tests before combined validation
can pass. See the [test transcript](parliament_ballot_b6/python-regression.txt)
and [diagnostic](parliament_ballot_b6/source-contract-diagnosis.txt). The
[post-accounting diagnostic](parliament_ballot_b6/source-contract-post-accounting-diagnosis.txt)
repeats only that in-memory isolation against the revised documents; the real
source-contract check still fails.

The [requirement-audit recheck](parliament_ballot_b6/source-contract-requirement-audit.json)
and the [later resource-contract recheck](parliament_ballot_resource_contract/source-contract.json)
fail on the actual start-phase ordering. Concurrent Core work has since
also added `sccp::pause_lifecycle::lapse_after_enactments`; its source identity
differs from the earlier diagnostic. The earlier in-memory isolation and
1,115/92 broad-suite totals describe their recorded snapshots, not this later
tree. No Core or ordering guard changes were made by the B6 work.
