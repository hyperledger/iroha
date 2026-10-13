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

Production schemas, Core verification and State changes, Torii/SDK paths and
timed-OVN/TLE retirement retain the selection preconditions of the ballot
design. They are subsequent work, not substitutes for B6's missing evidence.

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
| B6.1 — security accounting | Executable loss/resource ledger; verify imported theorem hypotheses against primary sources; justify all primitive terms at actual resources and obtain independent attack-cost review | Executable arithmetic, source-hypothesis review, generator-interface analysis and candidate request-stage and bounded-entry real-prover primitive-count reconciliation complete; a [bounded hybrid-driver proposal](parliament_ballot_b6_hybrid_driver.md) now specifies the missing sampler/interface/state contract; a separate [fixed-opening H5 derivation](parliament_ballot_b6_h5_fixed_opening.md) and [zero-fallback certificate](../docs/validation/parliament_ballot_zero_challenge/README.md) support the conditional initial transition; the [joint mask bijection](parliament_ballot_b6_mask_coordinate.md) gives an exact middle equality at an ideal-material public endpoint, and [adaptive hidden-assignment deletion](parliament_ballot_b6_hidden_assignment_deletion.md) reaches its unpatched baseline; primitive entry, reverse material bridge, full reduction resources and independent assessment remain open |
| B6.2 — adversarial verification | Reproducible bounded parser/mutation campaigns, targeted late-invalid cases and portable/accelerated parity with retained corpus identity | 8,756 deterministic cases per mode, two bounded ASan fuzz runs, 124 retained corpus cases with replay parity, four constructive non-minimal-counter tests per mode and twelve-set upstream reference interoperability evidence with explicit publication/recovery provenance; not exhaustive or independent implementation review |
| B6.3 — resource measurements | Source-bound cold-input and warm verification, late-invalid and malformed cases, actual proving samples/retries, bounded maximum public inputs and explicit memory scope | Local runner and Mac/attached-device evidence delivered; separate malformed campaign adds 10,168 observations across 164 selected classes per mode; complete production bounds and named-baseline conditions remain open |
| B6.4 — exact accounting | Inventory standalone encoding/work/allocation bounds and every unresolved production envelope/authentication term | Source-pinned inventories plus [researched resource contract](parliament_ballot_resource_contract.md) implemented: atomic reservations, arena and supplied stack; 120 original worker calls pass. The separate [borrowed-input worker](../docs/validation/parliament_ballot_memory_entry/README.md) excludes file retrieval from charged work. Its [shared-control successor](../docs/validation/parliament_ballot_fatal_control/README.md) fixes fatal stdout blockage and passes 122 observations plus real output controls with its extra page counted. [Conditional arena sufficiency](parliament_ballot_arena_sufficiency.md) checks retained classes with a universal frontend bound; actual-allocator parity and selected compiled layouts support the model. A separate [instrumented verifier campaign](../docs/validation/parliament_ballot_allocation_trace/README.md) matches 132 finite allocation streams and passes 14 controls. A source-conditional catalog covers seven backend indirect sites, with remaining indirect/native/recursive paths unresolved. The separate [native endpoint observer](../docs/validation/parliament_ballot_native_probe/README.md) preserves control and coverage failures. Complete compiler/runtime correspondence, calibration and production mapping stay open; schemas stay gated |
| B6.5 — platform evidence | Named hardware and device results, cross-architecture parity and phone thermal/battery/memory evidence | iPhone 17 Pro Max and Samsung SM-S942B supplementary runs; standalone finish-and-discard contract and selected-buffer cleanup tests pass. Named Pixel 6a/iPhone SE 3, physical x86/ARM and battery/cancellation qualification open; Intel TODO deferred by owner |
| B6.6 — independent and owner decisions | Independent cryptographic/implementation review, quantified premise acceptance, both weakening acknowledgements and eventual qualification record | Open, including resolution of the preselection envelope/schema ordering; automation cannot supply another reviewer's or owner's attestation |
| B6.7 — requirement reconciliation | Map every design security gate, selection step and validation-table case to retained evidence, deferred production work or an explicit unmet requirement | [Requirement audit](parliament_ballot_b6_requirement_audit.md) complete; final qualification remains unmet |

B6 is complete only when the selection and qualification evidence actually
meets the design. Local experiments, generated review notes and fail-closed
checkers do not by themselves meet that condition.

The current standalone engineering checkpoint includes the owner-requested
resource proposal and implementation, with [retained validation](../docs/validation/parliament_ballot_resource_contract/README.md),
candidate request-stage primitive accounting, and a [standalone cancellation lifecycle](parliament_ballot_prover_lifecycle.md).
Further certificates need complete runtime coverage and cost calibration,
envelope-sequencing resolution, an adapted cryptographic proof and independent
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
The [normal-return analysis](../docs/validation/parliament_ballot_noreturn_frontiers/README.md)
justifies conditional ordinary-flow cuts while retaining native unwind and every
original unconditional resource obligation. Next local B6.4 work includes universal target-specific
allocation/provenance correspondence, discharge of target/noninterference
premises, and justified native and exceptional path bounds. Native endpoint observations now pass their
14 controls and 120 proof cases, with no named endpoint calls in the 82 charged
intervals; hidden paths and a complete native-byte bound remain unresolved.
Finite replay and resolved stack regions do not close runtime coverage or
physical calibration.

TODO: reconcile the current Core source contract with concurrent integration
changes. Its current first failure is the missing `Executable::IvmProved(proved)`
queue binding. The earlier B6 combined Python run retains 92 failures from its
then-current block-start ordering mismatch; this new failure does not qualify
other guard sections. Standalone additions do not repair or waive this check. See the B6 record for the source-bound evidence
and remaining owner/hardware actions.
