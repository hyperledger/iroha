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
for genuine candidate registration, wallet admission/execution/closure,
independent replay and canonical block input/output roundtrips; `--full` runs the typed protocol crate's complete suite.
The board, registration authority and block anchors are fixtures, so this is
local protocol testing. The canonical signerless input/result representation is
implemented, but authenticated Core State execution and end-to-end Torii/client
submission remain open. A local-unavailable boundary protects those unfinished
paths; it is not a committed ballot rejection.

| Development goal | Completion criterion | State |
| --- | --- | --- |
| E1 — runnable candidate tests | One command exercises the actual registration and vote proofs, stamped admission, execution decisions, corpus closure and replay without requiring qualification | Implemented; resumed run passes 83 tests (two fixture helpers ignored), including all five runner selections. Genuine identical ballots produce verified success and `DuplicateNullifier` results in a canonical block roundtrip. Corrected model/output suite passes 147 tests |
| E2 — node integration | Canonical signerless input/result variants, Core registration and ballot state, bounded admission and gossip, rollback-safe execution, authenticated publication/replay, Torii and client paths | Open; these are missing implementation, not an approval blocker |
| E3 — network testing | Run the integrated candidate through ordinary four-validator execution and restart with real finality and API submissions | Open; depends on E2 |

E2 requires a coordinated first-release migration. The following components track
its implementation boundaries; none changes the qualification or activation gate:

| Component | Required implementation boundary |
| --- | --- |
| Canonical input/result representation | Implemented; model/output tests and an initial six-package all-target check pass after disk recovery. Focused Torii transport/outcome validation passes 16 tests; Core and consumer validation remains in progress. `TransactionEntrypoint::AnonymousBallot` carries the exact canonical envelope at tag 4; rejection tag 5 carries either ballot reason. Output shape requires empty success or a ballot rejection and no triggers, completions, receipts, fees or emissions. Arbitrary inputs expose optional authority. Canonical block construction and genuine candidate-proof roundtrips cover identical inputs with distinct result positions. Node admission remains locally unavailable until authoritative context and State execution exist. |
| Canonical model and seal identities | Replace the existing 32-byte roster-root preimage with the specified 64-byte anonymous-ballot roster root, and migrate body-identity derivation, certificates, restore checks and authenticated seal-publication outputs together. No truncated root, compatibility form or old-root seal may stand in for this binding. |
| Registration publication and compact State | Proposed ownership: retain the complete proof in its original signed acceptance input and authenticated finalized block history; retain compact assignment-to-credential records with the exact source binding in State. Require a private direct-signed-input origin; an execution authority alone does not prove the registration was published in that input. Bind compact locators to finalized canonical history and test retrieval after restart and DA sidecarring; unavailable retained bytes remain unavailable. Do not duplicate every 160,148-byte proof into the 16 MiB attempt snapshot or replace proof verification with a digest. |
| Core acceptance, sealing and restore | Derive body context and assignment from authoritative State and transaction authority; require real registration verification for binding acceptance; reject duplicate commitments across accepted primaries and alternates and failed registrations atomically. Acceptance and sealing are one functional slice: the read-only due planner must predict the same credential-aware transition that signed execution applies. Seal exactly the ranked seated credentials, publish the complete canonical list, and validate restored mappings, roots and source bindings. Preserve public-body acceptance and decline semantics. |
| Authenticated seal publication | Proposed ownership: add bounded typed publication artifacts to the existing `BlockResult` sealing path through `StateBlock::seal_execution_outputs`. Reserve capacity before mutation and bind the exact artifact bytes to canonical wire, finality and replay. Preserve Network/Pipeline/Time call ownership; a seal artifact is not an invented invocation. Reconcile the anonymous output module's proposed fourth phase with this actual owner before implementing the coordinated slice. |
| Development authorization and production effects | Signed-source selection is implemented in `anonymous_ballot::candidate_testing`, pending compiled validation: an explicit bounded candidate/profile policy is read from `AuthenticatedSignedGenesisV1` or authenticated and extracted from the same immutable native genesis source. Both routes check the independently selected `NetworkId` and retain the exact input hash and direct instruction position. Absence returns no selection. Codec/extraction and native-source tests are authored, including altered authorization with identical intent/header hashes, nested-policy exclusion, foreign networks and original decoder refusals. Core installation is implemented, pending compiled validation: the reserved identity rejects every later installation/update, including when absent at genesis; a one-use native marker binds the exact original direct instruction, authority, network and input. Final genesis output must reproduce the original optional parameter. Selection is stored once on the captured source and attached only to its exact input. Eleven new Core controls cover installation/replay, malformed and duplicate policies, source substitution, local refusals, preseeded state, executor boundaries, compact rows and input attachment. Runtime ballot use remains open. The schema export registers the policy value without making authenticated selection a decodable authority. Carry candidate purpose through attempts and certificates so test results cannot reach production certification or proposal effects; the SCCP availability seam alone does not gate generic Parliament enactment. |
| API and client migration | Update the explicit proof-carrying acceptance model, instruction registry, Torii/OpenAPI, CLI, canonical Kotlin, Swift, JavaScript and Python consumers, plus shared schema fixtures and roundtrip tests. Do not introduce compatibility shims or a new Java duplicate. |
| Signerless execution and network testing | Connect canonical ballot inputs/results, isolated bounded admission and verified gossip, rollback-safe State execution, corpus/closure publication and authenticated replay. Then exercise ordinary four-validator API submission, finality, restart and rollback for E3. |

TODO: complete immutable installation and runtime consumption of the development
selection above with the coordinated State adapter. `NetworkId` is derived from the
genesis header hash: bind the capability to the authenticated source rather than
embedding the resulting hash in its own genesis policy. `GenesisExecutionScope`
also permits nested effects, so it alone cannot authenticate a direct policy
installation. The generic `execute_due_parliament_certificate_v1` path does not
consult the anonymous-ballot qualification record; keep candidate provenance out
of production certification and enactment in the same integration slice.
Candidate testing must retain the real proof rules. A node-local flag, chain-name
convention or serialized snapshot field cannot grant this authority.

The representation reserves explicit entrypoint tag `4`; retired Time tag `3`
stays rejected. Ballot-only reasons are refused for ordinary and internal
outputs. Node routing, admission and execution must retain the local-unavailable
classification until the authenticated State adapter exists, including lane
processing and wrapped errors; they must not manufacture a committed rejection.

The genuine [canonical-input resource diagnostic](../docs/validation/parliament_ballot_canonical_resources/README.md)
retains 55 cases per mode with exact portable/accelerated parity for its captured
source. The separate [resumed engineering observations](../docs/validation/parliament_ballot_node_representation/resume-20261020/observations.json)
retain 83 passing typed protocol tests (two fixture helpers ignored), the five
default runner selections from that suite, and 147 passing model/output tests.
The broader output controls first exposed an extra random-access lookup; the
implementation now shares the input lookup and preserves the original bounded
lookup assertion. An initial six-package all-target check passed on the
concurrently changing checkout; this is component evidence, with focused node
and consumer tests still in progress. The [earlier observations](../docs/validation/parliament_ballot_node_representation/observations.json)
and [pending-validation record](../docs/validation/parliament_ballot_node_representation/pending-validation.json)
retain the original source identities and disk failures. The coordinated runtime
migration remains open; there is no partial acceptance path feeding the obsolete
seal and no relaxed production activation gate.

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
| B6.1 — security accounting | Executable loss/resource ledger; verify imported theorem hypotheses against primary sources; justify all primitive terms at actual resources and obtain independent attack-cost review | Executable arithmetic, source-hypothesis review, generator-interface analysis and candidate request-stage and bounded-entry real-prover primitive-count reconciliation complete; a [bounded hybrid-driver proposal](parliament_ballot_b6_hybrid_driver.md) specifies the sampler/interface/state contract; the [fixed-opening H5 derivation](parliament_ballot_b6_h5_fixed_opening.md) and [zero-fallback certificate](../docs/validation/parliament_ballot_zero_challenge/README.md) support the conditional initial transition; the [joint mask bijection](parliament_ballot_b6_mask_coordinate.md) and [adaptive hidden-assignment deletion](parliament_ballot_b6_hidden_assignment_deletion.md) reach an unpatched ideal-material baseline. A distinct [direct public sampler](parliament_ballot_b6_ideal_public_sampler.md) exactly realizes that endpoint under fresh-slot premises. The [conditional root-entry lemma](parliament_ballot_b6_root_entry.md) and [material-entry extension](parliament_ballot_b6_material_entry.md) supply root/path/leaf/row reductions under the proposed chosen-input game, reaching independent slot material with real H5 processing while preserving aliases and earlier replacements. The [conditional composition](parliament_ballot_b6_conditional_composition.md) joins this entry to `IdealFrontierSim` and separately computes its known loss contributions with exact rational enclosures. The [initial challenge-programming derivation](parliament_ballot_b6_initial_programming.md) supplies explicit whole-lifetime samplers and counterwise entry under the common QROM premises, with a separate exact-enclosure calculator. The [application reconciliation](parliament_ballot_b6_application_reconciliation.md) derives conditional privacy and authorization joins with a newly specified credential premise `P_F`. A [static-slot programming writer](parliament_ballot_b6_static_overlay.md) removes the lifetime-sized append scan with nine passing circuit tests; a root/material source census bounds semantic ordinary reads by `Q_all+1445*T`. Quantitative premises, game acceptance, adversary-to-aggregate query conversion, base-oracle/coherent-read realization, whole-driver integration/resources and independent assessment remain open; old `Sim+` bounds do not transfer automatically |
| B6.2 — adversarial verification | Reproducible bounded parser/mutation campaigns, targeted late-invalid cases and portable/accelerated parity with retained corpus identity | 8,756 deterministic cases per mode, two bounded ASan fuzz runs, 124 retained corpus cases with replay parity, four constructive non-minimal-counter tests per mode and twelve-set upstream reference interoperability evidence with explicit publication/recovery provenance; not exhaustive or independent implementation review |
| B6.3 — resource measurements | Source-bound cold-input and warm verification, late-invalid and malformed cases, actual proving samples/retries, bounded maximum public inputs and explicit memory scope | Local runner and Mac/attached-device evidence delivered; separate malformed campaign adds 10,168 observations across 164 selected classes per mode; complete production bounds and named-baseline conditions remain open |
| B6.4 — exact accounting | Inventory standalone encoding/work/allocation bounds and every unresolved production envelope/authentication term | Source-pinned inventories plus [researched resource contract](parliament_ballot_resource_contract.md) implemented: atomic reservations, arena and supplied stack; 120 original worker calls pass. The separate [borrowed-input worker](../docs/validation/parliament_ballot_memory_entry/README.md) excludes file retrieval from charged work. Its [shared-control successor](../docs/validation/parliament_ballot_fatal_control/README.md) fixes fatal stdout blockage and passes 122 observations plus real output controls with its extra page counted. [Conditional arena sufficiency](parliament_ballot_arena_sufficiency.md) checks retained classes with a universal frontend bound; actual-allocator parity and selected compiled layouts support the model. A separate [instrumented verifier campaign](../docs/validation/parliament_ballot_allocation_trace/README.md) matches 132 finite allocation streams and passes 14 controls. The [canonical-input diagnostic](../docs/validation/parliament_ballot_canonical_resources/README.md) passes 55 genuine-input/control cases per mode with exact report parity and zero live owners on every normal arena exit. The [typed boundary and local-refusal regression](../docs/validation/parliament_ballot_canonical_resources/envelope-refusal-receipt.json) tests the 364,450-byte maximal valid envelope/context pair, exact 233,012-byte envelope proof charge and 327,680-byte context nominal budget. Original local refusals remain unavailable through carriers, admission, block validation and seal replay; 107 model, 79 protocol and 25 example tests and 55 fresh worker cases per mode pass. A source-conditional catalog covers seven backend indirect sites, with remaining indirect/native/recursive paths unresolved. The separate [native endpoint observer](../docs/validation/parliament_ballot_native_probe/README.md) preserves control and coverage failures. Complete compiler/runtime correspondence, calibration and production mapping stay open; binding production use stays gated |
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
physical calibration. The
[historical fixed-descriptor SHA3 remainder review](../docs/validation/parliament_ballot_remaining_sha3/README.md)
is now accepted as internal finite model evidence: eight separately reaped
fixtures, 119,168 comparisons and 576 conditional substitutions, with a distinct
closing custody assessment. Universal hash/native correspondence, current-source
applicability and the complete workspace certificate remain open; this result
does not qualify the canonical-input worker or complete B6.4.

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

The earlier integration source-contract records cover their captured
changes. Scoped queue/Kura checks bind signed gas, complete pre-quote
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
source scope. Reconciliation against the current checkout is in progress,
including source guards for the retired public TLE service and broker operations;
the historical counts do not validate the changed checker or current source.
The shared qualification dispatch repair separately passes both
host feature modes' strict lint and 17 shared/bridge tests. No runtime or
physical-device qualification follows from these checks. Earlier source-check failures
and the combined run's 92 start-order failures retain their historical scope.
See the B6 record for exact evidence and remaining owner/hardware actions.
