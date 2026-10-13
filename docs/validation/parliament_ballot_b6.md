# Parliament ballot B6 qualification evidence

Status, 2026-10-13: **experimental; no profile selected or qualified; production
remains gated.** This record extends the [B1–B5 evidence](parliament_ballot_standalone.md)
and tracks the [B6 goals](../../specs/parliament_ballot_implementation_goals.md).
It records completed local work and concrete remaining obligations, not an
independent reviewer or owner's approval.

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

## Standalone adversarial and conformance evidence

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

The separate [ASan/libFuzzer parser workspace](../../crates/iroha_parliament_ballot_proof/fuzz/README.md)
completed bounded 61-second runs: 1,038,579 portable inputs and 958,154
accelerated inputs without a crash. Its 124-input retained union is archived
with input/source hashes; portable and accelerated replay has the same
syntactic outcome digest. The fuzz target parses bounded raw proofs and test
records; it does not run full cryptographic verification or prove exhaustive
malformed-input coverage. Full-verifier mutation coverage is the separate
deterministic campaign above.

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
retain that difference. Reversing it only in a temporary reconstruction, with
the recovered lock, [verified all 223 measured source hashes](parliament_ballot_b6/measured-source-reconstruction.json).
These results identify the measured sources/binaries, not a qualification of
the later checkout; future candidates require fresh source identification and
checks.

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

## Encoding and selected work inventory

[Resource accounting](../../scripts/check_parliament_ballot_resource_accounting.py)
independently checks all eight raw proof lengths and frame-size formulas, plus
selected AES, hashing, folding and allocation payload bounds. Its five tests
include an independent serialized frame and actual binary-merge schedule.
`--require-complete` exits 1 until every full-certificate term is established.

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
explains lifetimes and separate candidate/comparator payloads. These components
are not the complete `B_work`, full heap/stack bound or stamp difficulty.

## Remaining requirements and explicit TODOs

| Requirement | Remaining evidence / owner |
| --- | --- |
| Cryptographic selection | Reviewed adaptive embeddings; explicit multiquery generator interfaces; quantified `P`, `U`, generator, frame and backend-model premises; complete reduction resources and independent attack-cost assessment |
| Owner decisions | Record extraction-to-soundness and security-contract weakenings, approved premises and eventual qualification; engineering instructions are not those attestations |
| Intel validator | **TODO: owner deferred this run.** Exact Xeon Silver 4310, one physical core at 2.10 GHz, turbo off, idle SMT sibling; an arbitrary Intel machine does not silently replace it |
| Android baseline | **TODO:** Pixel 6a native release application, battery and sustained thermal runs; authorized attached Samsung supplies separate native-shell evidence |
| iOS baseline | **TODO:** iPhone SE third generation, battery and sustained thermal runs; the attached iPhone 17 Pro Max is supplementary evidence |
| Platform coverage | Physical x86/ARM parity, cold-process/cache conditions, cancellation and independent constant-time/erasure implementation review. Current proving is synchronous; a cancellation/cleanup experiment needs defined cooperative cancellation or finish-and-discard semantics. Process termination does not establish Drop cleanup. |
| Deterministic accounting | Full verifier operation schedule, allocation lifetimes/stack/provider overhead, complete authenticated envelope and shared-context mapping after selection |
| Selection ordering | Owner and independent reviewer must resolve the documented dependency between preselection complete-envelope accounting and postselection schemas; no requirement is waived by the standalone size inventory. |
| Production implementation | Selection must precede schemas, Core/State, signerless admission, Torii/SDK and timed-OVN/TLE retirement; lifecycle/network/release qualification follows that implementation |

The binding-ballot availability function remains false and qualified attempt
latency remains unavailable. No experimental crate has been connected to Core.
The complete workspace suite was not run for this standalone work; unrelated
concurrent changes and repository signing/staging state were preserved.

## Current-tree checks and concurrent failure

The focused accounting suites pass 20 tests. Runner helper tests, bridge host
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
and [diagnostic](parliament_ballot_b6/source-contract-diagnosis.txt).
