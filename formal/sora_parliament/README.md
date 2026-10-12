# SORA Parliament V1 lifecycle model

`SoraParliamentV1.tla` is a finite safety model of the attempt reducer in
`crates/iroha_core/src/governance/parliament.rs` and its native execution
boundary in `crates/iroha_core/src/smartcontracts/isi/world.rs`.

The model covers these consensus bindings:

- the eligible-citizen snapshot is frozen before a strictly future finalized
  threshold-beacon pulse, and the initially required bodies are consumed as one
  simultaneous draw batch. The wait for that pulse is governance-local.
  Consensus owes Parliament no pulse: a request freezes one slot, the first
  consensus-native pulse height (`(h + 1) % EpochLengthBlocks = 0`) at or
  above `request height + SortitionPulseDelayBlocks` and strictly above every
  earlier generation slot of the attempt. The pulse of a slot is committed in
  its own block, so it cannot be known before that height; consumption may
  happen at any later height. An `AwaitingPulse` election leaves that state
  only by consuming the pulse of exactly its frozen slot. There is no
  unavailable-pulse classification, fallback pulse, fresh height, redraw or
  retry for it, and it may wait indefinitely. The only failure before the
  first consumed pulse is the hidden-capacity evidence described below. It
  records `NoRoster`; a retry supersedes the
  complete failed initial generation, freezes a fresh snapshot and a fresh
  later slot, uses the exact next sequence in a later block, and the final
  permitted sequence rejects the governance attempt. The model's single sortition
  generation stands for every body whose active generation ended `NoRoster`:
  the reducer admits a retry batch only when it contains every such body,
  before and after the first consumed pulse, so one retry never strands
  another failed body, and each generation owns a fresh pulse slot with one
  frozen snapshot. For a hidden body, an empty or
  live electorate below three instead records typed `NoRoster` capacity evidence
  for the whole generation at the request height without revealing or
  consuming a pulse. A capacity
  retry must use the exact next generation in a later block, and exhaustion of
  that same bounded sequence rejects the attempt. Per-body stages are
  abstracted: a later-stage body's terminal failure rejects the attempt even
  while an earlier stage is in progress. Independently of each nested
  retry counter, one proposal-wide redraw budget covers every fresh randomness
  choice: a successor governance attempt's first sortition, every later
  sortition generation (including Confirmation), and every timed-OVN ballot
  retry. The first proposal attempt's simultaneous initial draw and each
  body's sequence-zero ballot are baselines. Exact request/session transport
  replays are state-idempotent and consume no redraw unit. Reaching the shared
  ceiling makes the next objective no-roster or ballot failure terminal, and a
  required Confirmation draw at an already exhausted ceiling fails closed as
  terminal `NoResult` without committing a partial Policy binding;
- active timed-OVN ballots reserve both heavy-work windows in one global
  checked set. Admission rejects a duplicate, an intersecting reservation, or
  the first entry beyond the exact capacity without changing the committed
  set; terminal release returns the slot. The model explores both a conflicting
  pair and a nonconflicting pair, while the source-bound Core tests additionally
  exercise deterministic derived-index rebuild after restore;
- an absence is an authority-bound declaration for the member's exact seated
  assignment, is immutable, and never lowers original-seat quorum; each seated
  public-body assignment can endorse only one immutable result root, and Core
  finalizes only at the original-seat two-thirds quorum while binding the
  strict canonical endorser sequence, its derived root, count, and quorum into
  the later certificate. After either a self-absence or endorsement, Core also
  computes `eligible = original roster - absences`, `remaining = eligible -
  immutable endorsements`, and the strongest existing root; if that root plus
  every remaining seat cannot reach quorum, it deterministically sets the body
  to `NoResult` and rejects the governance attempt;
- entry into a public body's Reflection phase freezes an exact endorsement
  deadline. Endorsements and any still-eligible self-absence declaration are
  accepted through that height; after it, the payload-minimal permissionless
  failure trigger derives `DeadlineExpired`, sets the body to `NoResult`, and
  rejects the attempt;
- registration and survivor freeze close only at their exact derived heights.
  The modeled policy requires at least `max_corpus_entries + 1` registration
  blocks, at least `max_corpus_entries` survivor blocks, and enough commitment
  blocks for `ceil(max_corpus_entries / 32)` maximum-size chunks; the corpus
  bound also covers every original seat.
  During `(survivor_freeze_height, commitment_close_height]`, the concrete
  reducer accepts contiguous chunks of 1 through 32 records and terminalizes
  only when the rolling accepted count exactly equals the frozen survivor
  count. `FreezeCommitmentInWindow` abstracts intermediate
  prefixes as stuttering and represents only the terminal append; the
  structural source contract separately pins the window, chunk cap,
  contiguous-prefix state, capacity bound, and terminal-only reducer advance.
  An incomplete prefix after the close remains `TimedCommitment` and is
  objectively eligible for `CommitmentDeadlineExpired`. Release consumption
  and aggregate finalization remain inside the inclusive
  `release_height + opening_phase_blocks` window;
- a missed deadline becomes `NoResult`. The timed-release phases are unchanged
  in this revision and are replaced in a later one. Their release slot is no
  longer consensus demand either: a timed ballot opens only if a pulse is
  committed at exactly its release height, and otherwise ends through the
  modeled absent-release-pulse `NoResult` branch. Finalized-pulse
  availability is authoritative, a still-awaiting
  or opening ballot becomes eligible for deadline failure after the frozen
  window, an invalid aggregate opening is rejected without mutating state, and
  no plaintext, manual-opening, or fallback transition exists;
- a retry uses the exact next sequence, remains within the frozen retry bound,
  and consumes a fresh TLE session no earlier than its predecessor failure;
  failure of either the final permitted ballot sequence or the final shared
  proposal redraw rejects the governance attempt instead of leaving an
  unretryable active attempt;
- a narrow approved Policy tally with fewer than three fresh candidates outside the
  sealed Policy Jury becomes terminal `NoResult` in the same transition: the
  Policy binding, Confirmation requirement, and Confirmation request all
  remain uncommitted. With at least three fresh candidates, the same transition
  commits the Policy binding and Confirmation requirement together with the
  sequence-zero Confirmation request, whose request height equals the Policy
  result height and whose pulse is strictly future, but only while one shared
  redraw unit remains. Exhaustion instead atomically records terminal
  `NoResult` and leaves all three bindings uncommitted. The finite model uses
  the value `3` as the equivalence class for “three or more” candidates;
- Core automatically constructs a certificate only from an approved aggregate
  result and fixes `enact_at_height = certified_at_height +
  min_enactment_delay` in the native execution boundary; and
- enactment happens only at that exact height and only when the current
  compare-and-set head equals the certified head. A different head yields
  `Superseded` without applying the effect. With an equal head, the automatic
  block-start step applies the effect in a rollback-isolated transaction. An
  effect error drops that transaction, then a fresh transaction records
  `ExecutionFailed` with a deterministic root derived by Core from the retained
  certificate and exact due height. Certificate construction and all terminal
  execution outcomes are absent from the public lifecycle transition enum.
  The latter use the separate, domain-separated
  `ParliamentAutomaticExecutionOutcomeV1` audit payload, which is not
  submit-able. The automatic step cannot advance a still-certified attempt
  past its due height.

The abstraction treats domain-separated identifiers, canonical roots,
zero-knowledge proofs, finalized beacon pulses, Das--Ren partial proofs, and
the final threshold-BLS release signature as already verified inputs. It does
not prove those primitives, network liveness, coercion resistance, receipt
freeness, side-channel resistance, or operational key custody. TLC success is
bounded counterexample-search evidence only, not deductive proof or release
approval.

The model admits split endorsements, but mirrors the reducer's deterministic
terminal rule: once `max endorsements on one existing root + remaining
eligible, uncommitted seats < ceil(2N/3)`, the body becomes `NoResult` and the
attempt becomes `Rejected`. This closes mathematically irreversible splits
without allowing a manager to choose a root. The model also covers
post-deadline non-response rejection after the frozen Reflection window.
Progress still depends on a
permissionless caller eventually submitting the deadline trigger; TLC checks
safety and does not prove that weak-fairness assumption.

The small configuration uses two abstract bodies, two seated assignments, two
competing public-finding roots, a two-block public-finding deadline, three TLE
sessions (two with an authoritative release pulse and one modeling the
absent-release-pulse branch), a two-block commitment
window, a two-block opening window, a native pulse cadence of three blocks
with a one-block sortition pulse delay, and
two permitted sortition retries plus two permitted ballot retries. Its three
abstract resource reservations include one symmetric conflict pair and an exact
capacity of two. A shared redraw ceiling of two is explored from both the first
attempt's zero prefix and abstract successor-attempt prefixes; the latter model
whether the inherited proposal history has consumed zero or one unit before
the successor's initial draw. `AttemptPrefixFrame` keeps those inherited
coordinates immutable within each finite trace; successor attempts are the
separate bounded `Init` alternatives, not an in-trace reset. It is
intentionally large enough to explore self-absence, early impossible-root
rejection, conflicting and quorum-matching endorsements, post-deadline
non-response rejection, consumed and never-known sortition pulses, slot
alignment and same-window retry slots, fresh
sortition retries, sub-three hidden-electorate capacity failures,
exhausted sortition rejection, both terminal and successful atomic
Policy-to-Confirmation capacity branches, private deadline/release failure,
exhausted ballot retry rejection, stale-head supersession, and rollback-isolated
effect-failure paths.

The exact-pulse wait is checked by four state invariants and two action
properties. `NativeSortitionPulseSlots` requires every frozen slot, including
the Confirmation request's, to be a native pulse height.
`StrictlyIncreasingGenerationSlots` requires the generation slots of one
attempt to increase strictly. `FrozenSortitionRequestSlot` binds the live
request to its registered, derived slot and a consumed pulse to that slot.
`ExactPulseWaitIsGovernanceLocal` requires that no failure, redraw or retry
transition is enabled for an `AwaitingPulse` election and that it cannot be
consumed while its pulse is not known. The `PROPERTIES` block adds
`AwaitingPulseLeavesOnlyByExactConsumption` and
`SortitionSlotNeverChangesAfterRegistration`.

The model is safety-only: it has no fairness condition and runs with
`CHECK_DEADLOCK FALSE`. An indefinite `AwaitingPulse` is therefore an allowed
behaviour, not a violation, and the model says nothing about consensus. That a
missing Parliament pulse never blocks block production, replay or an unrelated
transaction is evidenced by the Core mutation `HC220` and its named test
(`specs/sumeragi.md` section 13.4), not by this model.

Run it with a compatible TLA2Tools installation:

```text
java -cp /path/to/tla2tools.jar tlc2.TLC \
  -config formal/sora_parliament/SoraParliamentV1.cfg \
  formal/sora_parliament/SoraParliamentV1.tla
```

The PR workflow uploads `sora-parliament-formal-pr` with stable
`inputs/SoraParliamentV1.{tla,cfg}`, `run-metadata.json`,
`source-contract.log`, and `tlc.log` paths plus separate exit-status files. TLC
runs the archived input copies. The metadata binds the input and output byte
sizes and SHA-256 digests, both recorded exit statuses, the checkout commit,
and the pinned TLA2Tools JAR digest. A separate always-run closure check rejects
missing, altered, or internally inconsistent evidence before upload.

The checked configuration must be exhaustively rerun with pinned TLA2Tools
v1.7.4 (TLC2 2.19) whenever this refinement or its commitment-window constant
changes. Bounded TLC results are revision-specific counterexample-search
evidence, not a proof about larger deployments.

Run the deterministic implementation/model binding check independently:

```text
python3 scripts/formal/check_sora_parliament_source_contract.py
```

The checker follows sortition registration and broker dispatch into their
current implementation helpers and validates the explicit broker frame schema
identities. Its regression suite runs the complete checker and verifies that
guard removal, altered ordering, substituted candidates and disconnected broker
validation still fail:

```sh
python3 -m pytest -q scripts/tests/check_sora_parliament_source_contract_test.py \
  scripts/tests/check_sora_parliament_broker_source_contract_test.py
```

The source contract is deliberately structural. It detects accidental removal
of the code-side guards represented by the model and separately pins the
authority-bound registration/dropout and reducer-derived registration/survivor
boundaries, authority-bound absence and public-finding endorsements. The model
contract also fails if sub-three hidden-electorate evidence starts
consuming a pulse, or if a narrow Policy result can commit only part of its
Confirmation handoff. It pins the proposal-wide redraw ceiling, exact successor
prefix lineage, the derived sortition/ballot accounting, and the separate
guards for fresh sortition, Confirmation, and timed-OVN retries. It requires
exact committed transport replay to remain state-idempotent and binds
shared-budget exhaustion to terminal rejection without adding a plaintext
fallback. It also
structurally pins the opaque Core release authorization, independently verified
runtime partial, canonical combiner, authenticated bodyless local-partial route,
non-enumerable multi-session software custody seam, and bounded public broker
projection whose independently validated form cannot mint Core authorization.
It now also pins the immutable session-to-ordered-roster store, startup's
active-plus-deadline-retained session projection, exact local-seat capability
lookup, and the authenticated broker operation's independent
key-session/transcript/seat checks. The projection is not evidence of
committed-state origin, and the capability reply is only a point-in-time lookup
rather than proof of future liveness. Those operating seams are outside the TLA
state machine and the check is not a refinement proof.
For this formal-model corridor, release qualification still requires a settled
source revision, an exhaustive same-source pinned TLC 2.19 run and archive, and
qualification of finalized-pulse production and consensus-enforced
global-beacon key rotation. The
[ballot decision](../../specs/parliament_private_ballot_design.md) retires the
timed-OVN and TLE phases modeled above. The governance-local exact-pulse wait
already replaces the consensus-mandatory pulse and the unavailable-pulse
branch. The model must still be revised to cover
credential sealing, casting open, verified unique-nullifier append,
deterministic closure and the terminal outcome, while preserving immutable quorum, bounded
sortition and governance-attempt retries (ballot retries are removed), public
findings, disjoint Confirmation and atomic capacity failure. The repository-wide gate inventory in the
[SORA Parliament hardening roadmap](../../roadmap.md#services-and-deployment)
additionally requires focused and four-peer execution evidence and independent
review of the anonymous-ballot relation.
