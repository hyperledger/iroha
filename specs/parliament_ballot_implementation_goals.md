# Parliament anonymous-ballot implementation goals

This record continues the interrupted “SORA Parliament anonymous ballot
implementation” session. It tracks engineering completion of the standalone
construction fixed in [the proof profile](parliament_ballot_proof_profile.md)
section 6. The [ballot design](parliament_private_ballot_design.md) section
12.2 remains the authority for selection, integration and qualification.

No profile is selected or qualified. The binding-ballot launch gate remains
false, and no finite qualified governance-attempt latency is supplied by this
work. The owner must still record both requirement weakenings: knowledge
extraction to adaptive soundness, and the earlier security-contract
recalibration. Implementation agreement does not establish the conditional
[security arguments](parliament_ballot_proof_arguments.md).

| Goal | Owner | Completion criterion | State |
| --- | --- | --- | --- |
| B1 — recover and reconcile | Ballot maintainers | Recover the final decisions and unfinished reviews; preserve concurrent work and the existing merge. | Complete |
| B2 — extended backend | VOLE backend | Implement salt in challenge 1 and H5, the bounded 20-bit counter, and the affine 112-byte leaf; retain all twelve official reference-mode signatures; pass portable and accelerated tests and strict lint. | Complete |
| B3 — strengthened relation | Ballot proof crate | Implement the 128-byte nullifier, vote authorization and third permutation, the final descriptor and 112-byte tape; reject obsolete encodings and malformed inputs. | Complete |
| B4 — independent vectors | Reference and ballot maintainers | Generate final Python vectors independently of Rust and reproduce both roles and rows, including 3-, 500- and 1,000-seat votes, with negative tests and deterministic parity. | Complete |
| B5 — measurement and review | Ballot maintainers | Record source-bound local timing, sizes and memory, resolve implementation-review findings, and reconcile specs and source-contract checks. | Complete; local engineering evidence only |
| B6 — select and qualify | Independent cryptographic reviewers and owner | Establish or explicitly accept quantified primitive premises, complete the concrete-security ledger and attack-cost assessment, finish envelope accounting and the named validator/phone measurements, then record qualification. | Blocked on proof, review, full resource certificates and hardware requirements; standalone charge/workspace proposal implemented; production remains gated |

The owner's 2026-10-18 authorization in design section 12.2 permits production
schemas, Core verification and State changes, Torii/CLI/SDK paths, coordinated
timed-OVN/TLE retirement and automatable qualification work alongside B6.
Implement the actual candidate relations; binding production use remains
disabled until qualification. Engineering completion does not replace B6's
missing evidence.

The owner's subsequent 2026-10-18 instruction explicitly enables development
testing before qualification. Run `scripts/test_parliament_ballot_local.sh`
for genuine candidate registration, wallet admission/execution/closure and
independent replay; `--full` runs the typed protocol crate's complete suite.
The board, registration authority and block anchors are fixtures, so this is
local protocol testing. Core, Torii and client integration are not present in
the current checkout, despite earlier crate comments describing them as wired.

| Development goal | Completion criterion | State |
| --- | --- | --- |
| E1 — runnable candidate tests | One command exercises the actual registration and vote proofs, stamped admission, execution decisions, corpus closure and replay without requiring qualification | Complete; all three focused protocol tests pass |
| E2 — node integration | Canonical signerless input/result variants, Core registration and ballot state, bounded admission and gossip, rollback-safe execution, authenticated publication/replay, Torii and client paths | Open; these are missing implementation, not an approval blocker |
| E3 — network testing | Run the integrated candidate through ordinary four-validator execution and restart with real finality and API submissions | Open; depends on E2 |

The [standalone validation record](../docs/validation/parliament_ballot_standalone.md)
retains the source-bound measurements, conformance scope, reproduction commands
and remaining limitations; [B6 evidence](../docs/validation/parliament_ballot_b6.md)
records subsequent qualification work. B1–B5 complete the interrupted session's authorized
implementation work; B6 remains an independent qualification outcome.

## B6 qualification work

The owner requested continued qualification on 2026-10-13, with production
gated until every requirement holds. Intel-machine measurements are explicitly
deferred to the owner; attached iPhones may supply device evidence, subject to
their actual models and the named baseline. No substitute machine is silently
treated as the Xeon, Pixel 6a or iPhone SE (third generation).

| Goal | Completion criterion | State |
| --- | --- | --- |
| B6.1 — security accounting | Executable loss/resource ledger; verify imported theorem hypotheses against primary sources; justify all primitive terms at actual resources and obtain independent attack-cost review | Executable arithmetic, source-hypothesis review, generator-interface analysis and candidate request-stage and bounded-entry real-prover primitive-count reconciliation complete; a [bounded hybrid-driver proposal](parliament_ballot_b6_hybrid_driver.md) specifies the sampler/interface/state contract; the [fixed-opening H5 derivation](parliament_ballot_b6_h5_fixed_opening.md) and [zero-fallback certificate](../docs/validation/parliament_ballot_zero_challenge/README.md) support the conditional initial transition; the [joint mask bijection](parliament_ballot_b6_mask_coordinate.md) and [adaptive hidden-assignment deletion](parliament_ballot_b6_hidden_assignment_deletion.md) reach an unpatched ideal-material baseline. A distinct [direct public sampler](parliament_ballot_b6_ideal_public_sampler.md) exactly realizes that endpoint under fresh-slot premises. Primitive entry, proposal acceptance, full reduction resources and independent assessment remain open; no equality to real-root `Sim+` is claimed |
| B6.2 — adversarial verification | Reproducible bounded parser/mutation campaigns, targeted late-invalid cases and portable/accelerated parity with retained corpus identity | 8,756 deterministic cases per mode, two bounded ASan fuzz runs, 124 retained corpus cases with replay parity, four constructive non-minimal-counter tests per mode and twelve-set upstream reference interoperability evidence with explicit publication/recovery provenance; not exhaustive or independent implementation review |
| B6.3 — resource measurements | Source-bound cold-input and warm verification, late-invalid and malformed cases, actual proving samples/retries, bounded maximum public inputs and explicit memory scope | Local runner and Mac/attached-device evidence delivered; separate malformed campaign adds 10,168 observations across 164 selected classes per mode; complete production bounds and named-baseline conditions remain open |
| B6.4 — exact accounting | Inventory standalone encoding/work/allocation bounds and every unresolved production envelope/authentication term | Source-pinned inventories plus [researched resource contract](parliament_ballot_resource_contract.md) implemented: atomic reservations, arena and supplied stack; 120 original worker calls pass. The separate [borrowed-input worker](../docs/validation/parliament_ballot_memory_entry/README.md) excludes file retrieval from charged work. Its [shared-control successor](../docs/validation/parliament_ballot_fatal_control/README.md) fixes fatal stdout blockage and passes 122 observations plus real output controls with its extra page counted. [Conditional arena sufficiency](parliament_ballot_arena_sufficiency.md) checks retained classes with a universal frontend bound; actual-allocator parity and selected compiled layouts support the model. A separate [instrumented verifier campaign](../docs/validation/parliament_ballot_allocation_trace/README.md) matches 132 finite allocation streams and passes 14 controls. A source-conditional catalog covers seven backend indirect sites, with remaining indirect/native/recursive paths unresolved. The separate [native endpoint observer](../docs/validation/parliament_ballot_native_probe/README.md) preserves control and coverage failures. Complete compiler/runtime correspondence, calibration and production mapping stay open; binding production use stays gated |
| B6.5 — platform evidence | Named hardware and device results, cross-architecture parity and phone thermal/battery/memory evidence | iPhone 17 Pro Max and Samsung SM-S942B supplementary runs; standalone finish-and-discard contract and selected-buffer cleanup tests pass. Named Pixel 6a/iPhone SE 3, physical x86/ARM and battery/cancellation qualification open; Intel TODO deferred by owner |
| B6.6 — independent and owner decisions | Independent cryptographic/implementation review, quantified premise acceptance, both weakening acknowledgements and eventual qualification record | Open; design section 12.2 resolves engineering sequencing, while complete envelope accounting and qualification remain required; automation cannot supply another reviewer's or owner's attestation |
| B6.7 — requirement reconciliation | Map every design security gate, selection step and validation-table case to retained evidence, deferred production work or an explicit unmet requirement | [Requirement audit](parliament_ballot_b6_requirement_audit.md) complete; final qualification remains unmet |

B6 is complete only when the selection and qualification evidence actually
meets the design. Local experiments, generated review notes and fail-closed
checkers do not by themselves meet that condition.

The current standalone engineering checkpoint includes the owner-requested
resource proposal and implementation, with [retained validation](../docs/validation/parliament_ballot_resource_contract/README.md),
candidate request-stage primitive accounting, and a [standalone cancellation lifecycle](parliament_ballot_prover_lifecycle.md).
Further certificates need complete runtime coverage and cost calibration,
complete production-envelope accounting, an adapted cryptographic proof and independent
assessments, and deferred physical-hardware evidence. These remain unmet
requirements, not waived work or claims that further analysis is impossible.

The [source-model arena check](parliament_ballot_arena_sufficiency.md) now
establishes conditional fragmentation-free completion across retained shape
classes, with an independent all-length frontend bound. The
[compiled stack audit](../docs/validation/parliament_ballot_compiled_stack/README.md)
and [provider-target catalog](../docs/validation/parliament_ballot_indirect_targets/README.md)
retain an unknown complete bound after conditionally resolving seven backend
sites. The separate [failure-entry analysis](../docs/validation/parliament_ballot_stack_frontiers/README.md)
places 31 other indirect sites behind explicit unknown-cost failure boundaries;
it leaves one worker I/O destructor and native/failure/exceptional costs open.
The separately instrumented verifier now matches 132 selected allocation streams
against the source grammar, with 14 controls; this is finite correspondence only.
The [activation analysis](../docs/validation/parliament_ballot_allocator_activation/README.md)
conditionally excludes four explicit System allocation arms per frozen image;
noninterference remains an obligation, not inferred from finite traces. The
[source ownership audit](../docs/validation/parliament_ballot_ownership/README.md)
and [compiled free predicates](../docs/validation/parliament_ballot_free_predicates/README.md)
establish conditional source origin and local routing facts while retaining
all ten unconditional free frontiers. The
[I/O tag guard](../docs/validation/parliament_ballot_io_error_guard/README.md)
checks a local return path and charged-read source lemma for the frozen worker.
A separate in-memory entry moves retrieval before invocation and reserves the
actual borrowed length before its arena copy; its separate build and 122-call
campaign pass with all qualification flags false. Its shared-control successor
also removes fatal output from charged work after reproducing a blocked-pipe
failure; fresh builds, 122 observations and full/broken-output controls pass.
Its [fresh stack analysis](../docs/validation/parliament_ballot_fatal_stack_eon/README.md)
adds tested `STLUR`/`EON` decoding and has zero frame-analysis errors in either
image; native, indirect, exceptional and recursive costs remain open.
The [adapter-only argument](../docs/validation/parliament_ballot_adapter_bound/README.md)
now bounds its own ordinary compiled region under named premises, with 20
checker tests; native and full-verifier work/stack remain opaque.
Later concurrent lockfile/allocator edits cause a retained historical-input refusal;
the captured adapter result is not repinned to those sources.
The [historical recovery](../docs/validation/parliament_ballot_adapter_source_recovery/README.md)
resolves all 2,081 original identities, including four inputs recovered separately
from exact Git revisions. Twelve fault controls protect identity and refusal
behavior; this recovers historical content without certifying the current source.
The [historical frontend argument](../docs/validation/parliament_ballot_frontend_bound/README.md)
adds a conditional 146-instruction/2,160-byte dispatcher and record-parser
contribution, with a separate bounded field-parser loop and 27 checker tests.
Its symbolic composition retains typed decoders, cryptography, cleanup,
allocation and native calls as unknown costs. Separate
[profile](../docs/validation/parliament_ballot_profile_bound/README.md) and
[typed-decoder](../docs/validation/parliament_ballot_typed_decoder_bound/README.md)
arguments now cover their complete outer ordinary paths, bounded role loop,
guarded copy/split requests and partial cleanup, with 18/24 checker tests.
Remaining terms include CRT serialization, bounded constructors/public validation,
hashes and allocation/native/exceptional costs; the retained registration trap
is not relabeled a return or discharged by the local instruction bound.
The [opaque-field constructor](../docs/validation/parliament_ballot_opaque_field_bound/README.md)
now has derived returning-path local bounds of 20/23/29 instructions and a
48-byte frame in both retained images. Its 18-instruction allocation-failure
prefix retains the error callee and outside-body continuation as unknown.
Allocation/copy requests are at most 256 bytes; lower native work, provenance
premises and complete resource certificates remain open.
The separate [current-source worker](../docs/validation/parliament_ballot_current_candidate/README.md)
passes both-mode builds/tests/Clippy, 122 observations, four output controls and
fresh stack diagnostics. A test/comment-only waker correction passes 28 shared
and nine custody tests. The separate
[compiled correspondence check](../docs/validation/parliament_ballot_current_correspondence/README.md)
binds 24 code ranges and seven source deltas, with 49 controls and 2,123 stable
input guards. It reruns the four unchanged component analyzers on current
captures under their original premises. TODO: discharge the remaining lower
callee, native and complete workspace obligations.
Later root-lock changes are recorded separately; these build and correspondence
results apply to their captured sources. A package-membership comparison does
not qualify the later dependency graph or current checkout.
The [normal-return analysis](../docs/validation/parliament_ballot_noreturn_frontiers/README.md)
justifies conditional ordinary-flow cuts while retaining native unwind and every
original unconditional resource obligation. Next local B6.4 work includes universal target-specific
allocation/provenance correspondence, discharge of target/noninterference
premises, and justified native and exceptional path bounds. Native endpoint observations now pass their
14 controls and 120 proof cases, with no named endpoint calls in the 82 charged
intervals; hidden paths and a complete native-byte bound remain unresolved.
Finite replay and resolved stack regions do not close runtime coverage or
physical calibration.

The [retained-image exception audit](../docs/validation/parliament_ballot_exception_coverage/README.md)
checks compact/CIE/FDE/LSDA correspondence and conservatively expands landing-pad
control coverage, with 182 staged tests and an independent LLVM header comparison.
The whole-function census retains 46 additional instructions per image behind
unresolved indirect control. TODO: resolve those targets and establish CFI,
loaded personality and exceptional stack/register/native-cost semantics before
claiming complete exception coverage or a full resource certificate. All
qualification and current-checkout applicability flags remain false.

The [direct sampler accounting](parliament_ballot_b6_ideal_sampler_accounting.md)
now inventories bounded logical request/lifetime work and persistent programming
records, with 30 controls. The separate [reversible log construction](parliament_ballot_b6_oracle_log_circuit.md)
now gives explicit coherent lookup/append costs and passes 21 controls.
The separate [write-frame construction](parliament_ballot_b6_write_framing.md)
prices preparation and cleanup of supplied canonical field registers, with
11 controls. It reuses append staging and adds no oracle calls. Its supplied-field
boundary excludes generation, validation and trial selection; the atomic
request-machine implementation below now joins those stages.
TODO: compose its two base calls per lookup and explicit gate/wire vector with
the remaining reduction/primitive resources. This conditional upper bound and
partial payload sums do not establish the verifier's 64 MiB physical workspace.

The [clean admissibility circuit](parliament_ballot_b6_admissibility_circuit.md)
now prices the supplied-challenge grinding and opening-size predicate, including
fixed-address tree marks, frontier counting and full uncomputation. Both actual
row circuits are checked against an independent ancestor/frontier model.
Its per-trial gate and scratch counts close that component of the `2M`-trial
schedule. The request machine below adds trial control, selected-value access
and reconstruction; complete reductions and primitive entry remain open. The
separate component
capture preserves prior document identities without repinning old execution
evidence. Production remains gated.
The [clean field-product kernels](../docs/validation/parliament_ballot_gf_circuit/README.md)
now give explicit reversible implementations and exact gate/work-wire counts
for three inventoried field APIs. The full and low-scalar products use the
256-bit modulus; the wide product uses the source's 768-bit modulus. Disjoint
registers and zero initial work are premises. These component counts alone
do not establish a complete simulator or physical-workspace bound.

The [mathematical request machine](../docs/validation/parliament_ballot_request_machine/README.md)
now joins public preparation, sampling, opening/VOLE, responses, chronological
programming, return and cleanup, including content and full-width length
rejection families. Exact accepted-request observations and local reviews
retain explicit oracle and input premises. The [conditional lifetime ledger](../docs/validation/parliament_ballot_lifetime_ledger/README.md)
now checks shared-log capacity, known event costs and logical register ownership
for four accepted shapes, rejected-size VOTE and L0. Separate [full-cap content observations](../docs/validation/parliament_ballot_content_resources/README.md)
cover four bounded-content cases. A separate [ContentFamily ledger extension](../docs/validation/parliament_ballot_content_lifetime/README.md)
now prices them in mixed traces, under an explicit additional cap on all typed
requests rather than assuming that the valid-request theorem budget covers invalid
calls. The [finite sequence binder](../docs/validation/parliament_ballot_sequence_composition/README.md)
implements shared-log circuit relocation and inverse composition for a sequence
chosen in advance. The [domain audit](../docs/validation/parliament_ballot_family_domains/README.md)
and [component bounds](../docs/validation/parliament_ballot_component_families/README.md)
establish the legal length families and P0/P1/R1 arithmetic, while separating raw
entry, witness and application errors. These checks replay frozen source bytes;
the changed current Cargo manifest remains outside their qualification scope.
TODO: finish the adaptive T/Q driver and theorem, upstream invalid-call accounting,
preparation/purification resources, complete family/experiment bounds and the
primitive-entry assessment. Physical verifier
and independent qualification requirements remain separate; production stays gated.

The current integration source contract is reconciled with the captured
changes. Scoped queue/Kura checks now bind signed gas, complete pre-quote
structure, unconditional owners and original deferred release custody. The
initial queue guard's 36 controls were insufficient; its counterexample and
replacement regressions are retained. The [current phase guard](../docs/validation/parliament_ballot_current_candidate/source-guard-controls/README.md)
binds all seven same-block calls and the original returned batch with 74 controls.
The separate [construction guard](../docs/validation/parliament_ballot_construction_guard/README.md)
binds original acquisition, exact conditional DA custody, handoff and retirement.
Import-substitution and raw-macro shadowing counterexamples found in review are
now refused; 121 focused controls passed on the captured sources. After six
source-check inputs changed, those results retain their original source scope.
The subsequent [Torii release guard](../docs/validation/parliament_ballot_torii_release_guard/README.md)
passes 136 controls for private service routing, physical permit custody and
closed recovery; the [boxed daemon entry](../docs/validation/parliament_ballot_daemon_startup_guard/README.md)
passes 181 controls with the original prepared handoff and awaited preflight.
The [borrowed beacon-witness guard](../docs/validation/parliament_ballot_beacon_borrow_guard/README.md)
passes 182 controls; the [execution-result guard](../docs/validation/parliament_ballot_execution_result_guard/README.md)
passes 204 and binds complete original assertion owners. The captured source
check and all 1,755 matching Python regressions passed. Two observed Rust files
then changed in a constructor migration; the [post-merge source check](../docs/validation/parliament_ballot_post_merge_source_check/README.md)
passes on those inputs, while the full regression result retains its original
source scope. The shared qualification dispatch repair separately passes both
host feature modes' strict lint and 17 shared/bridge tests. No runtime or
physical-device qualification follows from these checks. Earlier source-check failures
and the combined run's 92 start-order failures retain their historical scope.
See the B6 record for exact evidence and remaining owner/hardware actions.
