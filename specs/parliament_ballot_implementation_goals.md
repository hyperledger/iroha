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
| B6 — select and qualify | Independent cryptographic reviewers and owner | Establish or explicitly accept quantified primitive premises, complete the concrete-security ledger and attack-cost assessment, finish envelope accounting and the named validator/phone measurements, then record qualification. | Active; production remains gated |

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
| B6.1 — security accounting | Executable loss/resource ledger; verify imported theorem hypotheses against primary sources; justify all primitive terms at actual resources and obtain independent attack-cost review | Executable arithmetic, source-hypothesis review and explicit generator-interface analysis complete; primitive/reduction/resource gaps and independent assessment remain open |
| B6.2 — adversarial verification | Reproducible bounded parser/mutation campaigns, targeted late-invalid cases and portable/accelerated parity with retained corpus identity | Local campaign complete: 8,756 deterministic cases per mode, two bounded ASan fuzz runs and 124 retained corpus cases with replay parity; not exhaustive or independent implementation review |
| B6.3 — resource measurements | Source-bound cold-input and warm verification, late-invalid cases, actual proving samples/retries, bounded maximum public inputs and explicit memory scope | Local runner and Mac/attached-device evidence delivered; complete production bounds and named-baseline conditions remain open |
| B6.4 — exact accounting | Inventory standalone encoding/work/allocation bounds and every unresolved production envelope/authentication term | Standalone inventory and fail-closed checker complete; full deterministic certificates and production mapping remain open; schemas stay gated |
| B6.5 — platform evidence | Named hardware and device results, cross-architecture parity and phone thermal/battery/memory evidence | iPhone 17 Pro Max and Samsung SM-S942B supplementary runs; named Pixel 6a/iPhone SE 3, physical x86/ARM and battery/cancellation qualification open; Intel TODO deferred by owner |
| B6.6 — independent and owner decisions | Independent cryptographic/implementation review, quantified premise acceptance, both weakening acknowledgements and eventual qualification record | Open, including resolution of the preselection envelope/schema ordering; automation cannot supply another reviewer's or owner's attestation |

B6 is complete only when the selection and qualification evidence actually
meets the design. Local experiments, generated review notes and fail-closed
checkers do not by themselves meet that condition.

TODO: the concurrent SCCP reconciliation hook and Parliament source-contract
guard disagree on the block-start call sequence. The B6 combined Python run
retains 92 failures from that mismatch; the standalone additions do not repair
or waive the integration check. See the B6 record for the source-bound evidence
and remaining owner/hardware actions.
