% Governance Pipeline (SORA Parliament V1)

The broader target doctrine, economic model, and mechanism maturity matrix are
defined in [`sora_adversarial_constitution.md`](./sora_adversarial_constitution.md).
This file describes the attempt reducer and native execution boundary that are
present in the source tree. It does not declare the current checkout or a binary
release qualified.

The [first-release ballot decision](parliament_private_ballot_design.md) replaces
timed-OVN and the Parliament TLE with anonymous on-chain voting: seat-acceptance
credentials frozen into a committee root, signerless proof-authorized public
ballots with nullifiers and a post-quantum membership proof, a public tally and
no ballot custodian. It keeps variable, possibly small membership and the
independent epoch-seated pause panel. Binding-governance mainnet launch is no-go
until that ballot is qualified. The timed-OVN and TLE behavior documented below
describes current source, which is a retirement target. Parliament availability
is isolated from consensus (ballot design section 9): no Parliament state
creates pulse demand, vetoes a pulse or a block, or gates node startup.

# Canonical proposal attempt lifecycle

1. A typed `ProposalKind` is admitted into governance storage. Its canonical
   fingerprint becomes the immutable `ProposalContentId`; a retry derives a
   new `GovernanceAttemptId` from that content id and the exact next sequence.
2. Core derives the risk tier, required-body order, policy version, exact effect
   preimage hash, and compare-and-set head. A caller cannot supply those fields.
   First-release proposal semantics require both the Monetary Policy Committee
   and Financial Markets Authority for `ValidationFeePolicy` and
   `ValidationFeePayoutLifecycle`: their complete order is Rules, Agenda,
   Interest, Review, Coordination, MPC, FMA, Oversight, Policy Jury. This
   reflects their network-wide fee-schedule and governed treasury-payout
   effects. SCCP route governance retains the same order without MPC; all other
   proposal mappings are unchanged.
3. For each body election, Core freezes the complete canonically ordered
   eligible-citizen snapshot in the containing block. The corresponding
   `SortitionRequestV1` commits that snapshot before the one exact finalized
   threshold-beacon pulse of its frozen slot, for the network's stable logical
   beacon identifier. The slot is a consensus-native pulse height: a height
   `h` with `(h + 1) % L == 0`, where `L` is the NPoS `epoch_length_blocks`.
   It is the first such height at or above both `request_height +
   parliament_sortition_pulse_delay_blocks` (default 4, a minimum lead) and
   one above the highest slot of an earlier generation of the same attempt.
   The attempt freezes the nonzero delay and `L` at creation; `L` comes from
   the genesis-immutable NPoS policy, and attempt creation is rejected on a
   chain without an NPoS cadence. Core uses checked arithmetic and rejects any
   other pulse height during live admission and persistence validation. The
   request creates no consensus demand: it waits, possibly indefinitely, for
   exactly that pulse, and no missing-pulse failure or redraw exists.
   The first pulse consumption covers every initially required body in one
   simultaneous batch; a later no-roster retry or a newly required Confirmation
   Jury consumes a fresh pulse slot. `ConsumeSortitionPulseBatch` is a
   permissionless progress trigger, but its relayer cannot choose entropy or
   split the pending set: Core verifies the exact finalized pulse and requires
   the complete strictly ordered request family before deriving assignments.
   `RegisterSortitionRequest` is manager-gated request intent outside SCCP
   route governance and permissionless for an SCCP attempt. Either way Core
   fixes every field, so a submitter chooses only whether to submit. After the
   first consumed pulse, a retry generation contains exactly every body whose
   active generation ended `NoRoster`, each at its next sequence, in one batch
   for one fresh pulse slot. One redraw unit therefore retries every failed
   body, and a retry can never strand another failed body that a later block
   could no longer afford to redraw. Without a failed body, the batch holds
   only the one newly required body. No batch may join a slot that an earlier
   batch registered, so every request awaiting one slot shares one frozen
   snapshot and the pulse batch can always consume it; persistence rejects a
   slot whose awaiting requests froze different snapshots. The Parliament
   driver plan lists this exact generation as an exact-height transition at
   its execution height, so an attempt without a manager does not stall after
   a no-roster failure. The plan omits a generation that a hidden body's
   sub-floor electorate would only record as capacity evidence again: that
   spends a sortition sequence and a redraw unit without drawing, and a driver
   repeating it every block would exhaust the proposal while citizens are
   still registering. Any submitter may still record that evidence, for
   example to terminate an attempt whose electorate does not grow. The
   plan keeps any transition only when the reducer accepts it and the
   persistence audit (`validate`) accepts the successor state. A due batch
   executes as one transaction, so it never carries a step that would abort
   the others. If a generation includes a hidden-ballot body and the live
   electorate has fewer than three members, Core records typed pre-request
   capacity evidence for every body of the generation instead of admitting an
   invalid `SortitionRequestV1`. The exact snapshot, request slot, target, and
   sequence are frozen; no beacon pulse is reserved or consumed. A later block
   may request only the exact next bounded generation, and the final failed
   generation rejects the governance attempt as `SortitionRetriesExhausted`.
   Bodies are drawn together, so a body serving a later stage can exhaust its
   retries, or meet the exhausted proposal-wide redraw budget, while an
   earlier stage is still in progress. That failure rejects the attempt at
   once; the persisted audit then requires body results for exactly the
   stages before the current one. The special atomic Confirmation-capacity
   result described below remains separate.
   Threshold key rotation is independent of that logical request identifier.
   Its exact-roster certificate compare-and-sets the expected active predecessor,
   and a global key change in block `H` takes effect at `H + 1`. The certificate
   roster fields and `2f + 1` signatures remain bound to the exact authenticated
   block-`H` authorization roster. For a global-beacon install, the signed
   canonical public state independently commits the target DKG roster and
   committee size; the producer at `H + 1` accepts that key only when the target
   exactly matches the authenticated `HeightContext` roster. This permits a
   terminal epoch block to install the successor committee's key while a wrong
   target fails closed, with no stale-key or alternate-entropy fallback.
   Parliament TLE differs deliberately: its release-share roster is
   session-fixed and is persisted as the exact certificate roster. Retirement
   actions carry no public state and remain block-`H`-roster-authorized,
   compare-and-set operations. Consequently an NPoS pulse produced from the
   parent state is verified against the key session active at its own height,
   not the successor pointer visible after the block's transactions execute.
   A sortition request that consumes the pulse in a later block, typically
   after the boundary rotation, re-verifies it against that same retained
   session. No pulse is produced or carried for an elapsed slot, and no
   alternate entropy source or detached roster record is accepted as a fallback.
4. The future pulse deterministically ranks primaries and alternates. Candidates
   accept or decline their own invitations under their transaction authority;
   `BeginInvitationAcceptance` is permissionless and carries only the election
   id; containing-block height and the consensus configuration determine its
   window. After that fixed response window, either permissionless
   `SealBodyRoster` derives the nonempty accepted assignments, roster root, and
   body id, or permissionless `FailBodyElectionNoRoster` proves from the reducer
   that the accepted roster is empty. An election that still awaits its pulse
   has no failure transition: it leaves `AwaitingPulse` only by consuming the
   pulse of exactly its slot, so an omitted pulse cannot become a redraw and
   never holds block production. Neither trigger accepts a caller-selected
   window, failure reason, assignment list, root, or body id. The
   `RecordAttemptAbsence` lets the same authority declare only its exact seated
   assignment absent. Absence is attempt-local and immutable, does not slash or
   change the original-seat quorum denominator, and must precede that body's
   endorsements or ballot. Once Reflection opens, the same inclusive frozen
   public-finding deadline also gates new absence declarations. If the
   authenticated absence makes the immutable original-seat public-finding
   quorum mathematically unreachable, Core sets that body to `NoResult` and
   rejects the governance attempt.
   Every member of a frozen candidate snapshot retains its citizenship bond
   while its election is `AwaitingPulse`, `Drawing`, or
   `AcceptingInvitations`. `NoRoster` and superseded elections release unseated
   candidates; sealed body assignments retain their members through the active
   attempt. An active retryable singleton pre-request capacity failure likewise
   retains its one candidate until a later generation supersedes it or final
   exhaustion rejects the attempt. Eligibility therefore cannot be withdrawn
   after request intent but before retry, draw, or roster sealing.
   The complete citizen registry is limited to 65,536 entries and each canonical
   candidate-snapshot payload to 8 MiB. Crossing either limit fails the
   transaction; snapshots are never truncated or sampled, and restore enforces
   the same bounds before rebuilding derived Parliament indexes.
   Compact casting-snapshot selection is likewise derived, not discovered by
   scanning historical evidence. A snapshot-skipped ballot index retains only
   the active hidden-ballot `Registration`, `SurvivorFreeze`, or
   `TimedCommitment` row and its exact half-open phase window. Replacement,
   terminalization, and restore update that row from validated attempt state;
   an in-window row without its exact timed-OVN evidence fails closed.
5. For a nonbinding body, `EndorsePublicFinding` lets each nonexcluded seated
   authority endorse exactly one root of the public evidence, deliberation, and
   dissent record. Core automatically finalizes only when one identical root
   reaches `ceil(2 * original_seats / 3)`, then binds the canonical
   strictly ordered `endorsing_assignments` list, its recomputed endorsement
   root, exact endorsement count, and immutable quorum into the body
   certificate. Context-free certificate validation requires the list to be
   nonempty and strictly increasing and requires
   `list.len == endorsements == quorum`. No manager can choose or finalize a
   finding. The Policy Jury, and a fresh disjoint Confirmation Jury when a
   narrowly approved result requires one, must use the mandatory private
   zero-knowledge timed-OVN ballot. A public finding is not a formal ballot and
   cannot replace a required private jury result. Hidden-ballot bodies and their
   eligible candidate snapshots require at least three members, the canonical
   V1 exact-tally anonymity floor. Before a narrow
   Policy result is committed, Core removes every sealed Policy Jury member from
   the current eligible-citizen snapshot. Fewer than three remaining candidates
   terminalize the verified opening as
   `ConfirmationJuryCapacityUnavailable`; the Policy binding and unfillable
   Confirmation requirement are not committed. At the proposal-wide redraw
   ceiling, at least three candidates instead terminalize the same verified
   opening as `RandomnessRedrawBudgetExhausted` before committing either the
   Policy binding or a Confirmation draw. Otherwise, that same finalization
   transaction freezes and registers the exact disjoint snapshot, configured
   target, current request height, and deterministic future pulse slot. The
   sequence-zero request height must equal the Policy result height, and restore
   rejects a missing or differently timed initial request.
   Eligibility cannot race a separate initial Confirmation request. If
   later invitation responses leave fewer than three accepted hidden-ballot
   seats, Core records an objective insufficient-roster election failure and
   follows the bounded fresh-sortition retry path rather than sealing a
   cryptographically unusable body.
   After each endorsement, Core derives `eligible = original roster -
   authenticated absences` and `remaining = eligible - immutable
   endorsements`. If the strongest existing root plus every remaining seat is
   below quorum, the body becomes `NoResult` and the governance attempt becomes
   `Rejected`; a manager cannot choose a root to break the split. Entry into
   Reflection freezes an inclusive endorsement deadline from the consensus
   `parliament_public_finding_phase_blocks` value (default 3,600). Endorsements
   after it are invalid; once `current_height > deadline`, the payload-minimal
   permissionless `FailPublicFindingNoResult` trigger derives
   `DeadlineExpired`, marks the body `NoResult`, and rejects the attempt.
6. A private ballot attempt freezes one configuration-derived schedule:
   registration close, survivor freeze, masked-ballot commitment close, and
   earliest release height, plus an inclusive opening deadline equal to the
   release height plus `opening_phase_blocks` (default 600). The first three
   transitions are accepted only at their exact heights; release consumption
   and aggregate finalization are rejected after the opening deadline.
   Registration, survivor, and ballot corpora are bounded by the frozen
   per-attempt limit; the default and hard ceiling are 1,000.
7. A registration or dropout is accepted only from the exact seated authority
   named by its canonical timed-OVN record. At close and freeze, Core derives
   the ordered registration corpus, survivor subset, and roots from those
   accepted records; a manager cannot submit replacement registration corpora
   or survivor subsets. The survivor set is immutable before ballots are
   accepted. A freeze with fewer than three survivors is rejected atomically;
   no survivor, ballot, opening, or exact tally is persisted, and the ordinary
   permissionless survivor-deadline transition then records deterministic
   `NoResult` with the existing retry semantics. The complete accepted corpus
   and every public tally are independently required to meet the same floor.
   `FreezeTimedOvnCorpus` is a permissionless exact-next append. Core
   derives the committed survivor offset and checks the active ballot, exact
   phase and containing-height window, body and predecessor bindings, nonempty
   chunk width, canonical record widths, capacity, and every one-hot proof
   before advancing the replay-checkable prefix. A relayer therefore cannot
   forge, omit, overlap, reorder, or alter one member's ballot, and only the
   terminal prefix seals the complete survivor-ordered corpus. Payload-minimal
   close, survivor freeze, release, failure, and finalization triggers remain
   permissionless.
   Before registration close, survivor freeze, or a corpus append, Core checks
   the reducer-owned active ballot, exact phase, body binding, predecessor
   checkpoint, and containing height using only bounded scalar state. Wrong-
   height and replayed checkpoint traffic therefore fails before proof work;
   an exact-height append still verifies every new record. Aggregate
   finalization first verifies the fixed-size public TLE/session/release binding
   and final threshold signature, then verifies the committed public aggregate
   transcript before mutation. Snapshot restore replays the complete raw
   evidence instead of trusting the cache. Core persists no secret shares or
   individual openings. A finalized release pulse and verified threshold-BLS
   signature open only the aggregate Aye/Nay/Abstain tally.
8. If a phase deadline is missed, Core derives the eligible `NoResult` reason
   and evidence commitment from persisted state and the containing block
   height. The timed-OVN release slot creates no consensus demand, and the
   ballot schedule is not aligned to native pulse heights. Until timed-OVN is
   retired (ballot design section 12.2 step 4), a ballot therefore opens only
   if a consensus-native pulse is committed at exactly its release height;
   otherwise it ends `ReleasePulseUnavailable` through this governance-local
   path once the release height is committed.
   `OpeningDeadlineExpired` is available after the immutable opening
   deadline whether the ballot is still awaiting release or is opening. Core
   rejects an unavailable classification for a slot that holds a finalized
   pulse, and neither release consumption nor a result can
   arrive after the deadline. The transition carries only the ballot id, not a
   failure reason or root. An invalid threshold release or aggregate opening is
   rejected without mutation and is not itself terminal evidence. A retry uses
   the exact next sequence, a fresh ballot id, and a fresh TLE session.
   `NoResult` on the final permitted sequence rejects the governance attempt
   instead of leaving it active without a legal retry. There is no plaintext,
   manual-opening, public-ballot, or post-freeze recovery fallback.
   Committed audit events classify sortition retry exhaustion, both
   public-finding outcomes, the five phase/release private-ballot failures, and
   insufficient fresh Confirmation capacity or proposal-wide redraw exhaustion
   with the closed ten-variant
   `ParliamentNoResultKindV1`; callers cannot supply that
   classification. `SortitionRetriesExhausted` is emitted when the final
   permitted body-election sequence fails before a body instance exists, or
   when a no-roster failure meets the exhausted proposal-wide redraw budget.
9. Core automatically constructs one `GovernanceCertificateV1` when the final
   required result is accepted, from the exact
   persisted body, sortition, roster, authority-endorsed public-finding,
   private-ballot, TLE, release, policy, effect, and expected-head bindings. The
   native boundary requires
   `enact_at_height = certified_at_height + gov.min_enactment_delay`.
10. At that exact due height Core's automatic block-start step re-derives the
    governed subject head. A mismatch atomically records `Superseded` without
    applying the effect. A match applies the typed proposal effect in a
    rollback-isolated state transaction and records `Enacted`. On an effect
    error Core drops that transaction, then uses a fresh transaction to record
    `ExecutionFailed` and the deterministic failure root derived from the exact
    retained certificate and due height. None of certificate construction,
    enactment, supersession, or execution failure is a public lifecycle
    transition. Core emits the terminal result as a separate canonical
    `ParliamentAutomaticExecutionOutcomeV1` audit payload with a
    domain-separated digest; that payload is not submit-able.

An emergency contract hold is deliberately sticky after its exclusive expiry:
expiry restores execution but does not erase the incident record or authorize a
second hold. The append-only `ContractLifecycleGovernanceActionV1` variant
`CompleteEmergencyHoldRetrospective` (Norito index 5) is the sole clear path.
Its proposal binds the retained hold's proposal-content id, governance-attempt
id, and incident digest, plus a non-zero retrospective finding root. A bonded
citizen may submit that proposal only once the exclusive expiry height has been
reached. Automatic certificate enactment repeats every binding and expiry
check against the compare-and-set lifecycle head, clears only the matching
hold, advances the lifecycle revision, and emits the prior hold, finding root,
revision, and complete post-state. A zero finding, an early request, any
substituted hold coordinate, a missing hold, or a replay fails closed. No direct
instruction, timer sweep, owner shortcut, or expired-record fallback can clear
the hold; a later independent emergency hold becomes possible only after the
certified retrospective is committed.

Validation-fee policy and payout-lifecycle proposals additionally bind their
canonical `proposal_operator` into the proposal fingerprint. Their protected
registry authorization retains the complete Parliament certificate and its
canonical `GovernanceCertificateId`; a standalone referendum tally is not a
validation-fee authorization. Both proposal kinds follow the same attempt,
certification, exact-due-height enactment, and rollback-isolated terminal
lifecycle above. The verified protected-registry projection binds the
certification and enactment heights and requires
`effective_from_height = enacted_at_height + 120,960`; it is not activated by a
client finalization call or a public ballot.

# Cryptographic claim boundary

Timed OVN provides aggregate-only opening under the implemented transcript and
threshold-release checks. It does not, by itself, establish voter anonymity
against network metadata, receipt freeness, coercion resistance, endpoint
security, or side-channel resistance. In particular, modern coercion analyses
show that blockchains, delay encryption, privacy-preserving contracts, and
trusted hardware can strengthen coercers or vote sellers under threat models
that older definitions omit. No documentation or UI may label this protocol
receipt-free or coercion-resistant without a separate construction and proof.
Michalas's July 2026 SACMAT construction obtains coercion resistance through a
specific anamorphic-encryption voting design. Timed OVN neither implements nor
analyzes that construction, so its publication does not support a coercion-
resistance claim for Parliament.
The August 2026 `somewhat deniable voting` construction instead assumes a
trusted teller and deliberately trades away part of individual verifiability
to obtain its stated deniability boundary. The 2026 journal version of Yin et
al.'s scalable blockchain construction likewise proves its claims for a
different dummy-voting and liquid-democracy protocol. Timed OVN implements
neither construction nor threat model, so those publications strengthen the
requirement for a protocol-specific proof rather than extending their claims to
Parliament.

“Aggregate-only” is not “winner-only” and does not make participation
unlinkable. The timed-OVN implementation in source publishes the exact Aye/Nay/Abstain counts and the accepted
corpus size, while the per-ballot participant hash is deterministically derived
from the public account and ballot attempt. Small panels and auxiliary knowledge
can therefore reveal individual choices. The V1 floor of three eliminates the
reachable two-survivor exact-tally disclosure, but is not a general anonymity
proof. Material describing that retired path must describe it as ballot-value
confidentiality with an exact public tally and linkable participation, and must
not present it as the V1 ballot. The canonical V1
[anonymous ballot](parliament_private_ballot_design.md) does not pursue
winner-only disclosure: it publishes every vote value and the exact running
tally, and its ballots carry no account identifier, within the limits stated in
that document's section 4.

The threshold-release profile implements the three-polynomial Das--Ren design
with a proof on every non-key-unique partial. V1 fixes `n = 3f + 1`, threshold
`f + 1`, and at most `f` distinct signing-share exposures over an unrefreshed
key session. It has no proactive refresh; a cumulative exposure beyond that
budget requires a fresh DKG and purpose-distinct session. Zeroizing Rust buffers
are defense in depth, not a compiler, OS, or hardware erasure guarantee.
The cited Das--Ren result is in the random-oracle model under DDH and co-CDH;
code conformance and replay tests are not a proof that an implementation meets
that theorem.
The ePrint 2025/943 key-uniqueness impossibility result does not directly cover
this non-key-unique profile, but it makes the per-partial representation proof
and a precise corruption model mandatory. “Adaptive” in a type name is not a
generic standard-assumption security claim.

The chain cannot observe a share compromise. V1 therefore persists separate
consensus lifecycle metadata beside (and outside) the cryptographic transcript:
an activation height, immutable expiry height, rotation-shortened inclusive
selection deadline, committed fresh-ballot counter, and immutable use ceiling.
An install or rotation committed at `H` leaves the predecessor selectable
through `H` and makes the successor selectable at `H + 1`. Fresh ballot
registration fails closed before activation, after expiry/cutover, and at the
use ceiling; restart recounts committed ballot bindings and rejects mismatched
counters or session/roster/lifecycle bindings. Already committed ballots retain
their historical public session and custody requirement through their own
inclusive opening deadline. These bounds limit exposure but cannot detect a
compromise; proactive or silent refresh remains a separately specified protocol
revision with explicit secure-erasure assumptions.

RFC 9380 standardizes the hash-to-curve building block used by the fixed
domain separators. It does not standardize the Das--Ren threshold composition,
its corruption model, or the complete timed-OVN release protocol; the BLS suite
label in source remains explicitly draft-derived. The July 2026 CFRG BLS
document is still an Internet-Draft and specifies base BLS signatures and
aggregation, not this threshold protocol or its lifecycle.

NIST IR 8214C's January 2026 Threshold Call asks submitters for a technical
specification, reference implementation, and experimental report, followed by
public analysis and a possible characterization report. It is an evidence-
gathering process, not a standardization or approval of Parliament's Das--Ren
profile. The January 2026 BBDL tBLS item is explicitly a version-0.1 preview of a
planned later package, whose team and technical scope may still change; it is
not a completed NIST submission, standard, validation, or approval of this
different threshold-release profile. The MPTS 2026 workshop likewise records
previews and current research on BLS security, adaptive and proactive
corruption, post-quantum threshold schemes, and threshold ZK; a workshop
preview is not a conformance or security certificate.

The 13 August 2026 Berkeley report on practical witness encryption says that
general-NP constructions remain prohibitively expensive and rest on strong,
comparatively lightly scrutinized assumptions, while its practical results are
special-purpose pairing constructions. Its silent and batched threshold-
encryption designs are research alternatives, not drop-in replacements for the
implemented timed-OVN transcript, release identity, corruption model, or
consensus lifecycle. Adopting one would require a separately specified,
reviewed, and enacted protocol change.

Recent beacon work also prevents a broader claim than the implementation makes.
A VDF establishes construction-specific sequential work, not a fixed amount of
civil time or economic resistance to specialized hardware. A VRF proves one
key's evaluation, not resistance to key grinding, selective withholding,
proposer choice, forks, or bias accumulated when one epoch feeds another.
Parliament instead freezes one network/session/height pulse slot before drawing,
has no missing-pulse classification for sortition (a request waits for exactly
its pulse), and bounds retries. Release qualification must still exercise
selective withholding and repeated-retry bias; single-round uniformity is not
sufficient evidence.
Independent per-stage retry caps likewise do not bound the conditional advantage
of nested governance, roster, and fresh-ballot redraws. A release candidate must
account for fresh entropy consumption with one proposal-level budget, keep
idempotent transport retries outside that budget, and quantify the resulting
capture bound under selective aborts.

Ballot presentation is a separate governance-security boundary. A July 2026
observational DAO study reports associations between voting-power share and an
author's selected choice, approval-oriented wording, and first-list position;
the authors explicitly do not claim that those associations establish
causation. Parliament removes caller-selected body order, derives all initially
required bodies in one canonical simultaneous batch, and uses a fixed binary
body ballot, so a proposal author cannot choose the body sequence or reorder
ballot options. Those protocol rules do not eliminate interface framing,
author cues, vote-visibility effects, or client rendering defects. Release
qualification must therefore verify canonical rendering across clients and
must not describe deterministic ordering or private opening as proof that
human presentation bias is absent.

Likewise, a replicated ledger is only the bulletin board. It does not by itself
prove cast-as-intended, recorded-as-cast, tallied-as-recorded, client integrity,
or ballot privacy. The V1 transcript therefore binds the exact proposal,
attempt, body, participant, survivor corpus, release identity, option, and proof
domain; every partial and aggregate is independently verified before use. This
does not claim an ElectionGuard-compatible voter-verification ceremony or close
the endpoint and coercion boundaries above.

Nor does an `AccountId` establish one-human-one-vote. Unless a separately
governed uniqueness-assurance profile is bound into the eligibility snapshot
and certificate, the accurate claim is equal weight per eligible account or
pseudonym. The current formal model treats cryptographic verification as a
trusted input and is not a composed proof of eligibility, beacon bias,
adaptive corruption, abort/retry behavior, ballot secrecy, finality, and
enactment.

The BLS12-381 threshold release, pairing-based timed-OVN ballot, and classical
beacon are not post-quantum. Versioned sessions and domain-separated algorithm
identities provide a migration boundary, but using ML-DSA elsewhere in Iroha
does not make Parliament post-quantum. The
[ballot decision](parliament_private_ballot_design.md) retires the threshold
release and timed-OVN ballot in favor of a post-quantum membership/nullifier
proof, as the canonical V1 replacement with new fixtures and no versioned
coexistence. The classical beacon remains; current lattice DKG/beacon proposals
are research inputs, not standards or drop-in implementations.

Research boundary reviewed through 2026-08-30:

- Das and Ren, [*Adaptively Secure BLS Threshold Signatures from DDH and
  co-CDH*](https://eprint.iacr.org/2023/1553).
- Ciampi, Crites, Komlo, and Maller, [*On the Adaptive Security of Key-Unique
  Threshold Signatures*](https://eprint.iacr.org/2025/943).
- Finogina, Herranz, and Rønne, [*Expanding the Toolbox: Coercion and
  Vote-Selling at Vote-Casting Revisited*](https://eprint.iacr.org/2024/1167).
- Michalas, [*Coercion-Resistant Voting via Anamorphic
  Encryption*](https://doi.org/10.1145/3750555.3811888), ACM SACMAT 2026,
  published 8 July 2026.
- Jia, Shi, Ye, Huang, and Peng, [*Somewhat Deniable Voting:
  Coercion-Resistant Electronic Voting Scheme with Privacy Preservation
  Property*](https://doi.org/10.32604/cmc.2026.084123), *Computers, Materials
  & Continua* 89(1), published 13 August 2026. Its trusted-teller and reduced
  individual-verifiability boundary is not the Timed OVN threat model.
- Yin, Zhang, Nastenko, Oliynykov, and Ren, [*A Scalable Coercion-Resistant
  Voting Scheme for Blockchain Decision-Making*](https://doi.org/10.1109/TDSC.2026.3651473),
  *IEEE Transactions on Dependable and Secure Computing*, 2026. Its
  construction and proof do not apply to Timed OVN without implementing and
  analyzing that protocol.
- IRTF, [RFC 9380: Hashing to Elliptic
  Curves](https://www.rfc-editor.org/rfc/rfc9380).
- CFRG, [*BLS Signatures*, draft-irtf-cfrg-bls-signature-07
  (work in progress, 6 July
  2026)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/07/).
- NIST, [*NIST First Call for Multi-Party Threshold Schemes*, NIST IR
  8214C](https://doi.org/10.6028/NIST.IR.8214C), January 2026.
- Bacho, Boldyreva, Das, and Loss, [*tBLS: Threshold BLS Signature Scheme,
  Preview Writeup version 0.1*](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/BBDL-tBLS-PW01.pdf),
  19 January 2026.
- NIST, [*MPTS 2026: NIST Workshop on Multi-Party Threshold Schemes
  2026*](https://csrc.nist.gov/Events/2026/mpts2026), January 2026.
- Policharla, [*Practical Witness Encryption Schemes and
  Applications*](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2026/EECS-2026-243.html),
  UCB/EECS-2026-243, 13 August 2026.
- Glaeser, Seres, Zhu, and Bonneau,
  [*Cicada: A Framework for Private Non-Interactive On-Chain Auctions and
  Voting*](https://eprint.iacr.org/2023/1473).
- Shang and Chen, [*Economic Security of VDF-Based Randomness Beacons: Models,
  Thresholds, and Design Guidelines*](https://arxiv.org/abs/2604.04744), 6
  April 2026.
- Gaži, Quader, and Russell, [*Taming Iterative Grinding Attacks on
  Blockchain Beacons*](https://eprint.iacr.org/2025/1974), ASIACRYPT 2025.
- [*SoK: Distributed Randomness Beacons*](https://eprint.iacr.org/2023/728),
  IEEE Symposium on Security and Privacy 2023.
- [*Enforcing Winner-Only Disclosure: Verifiable Tally Hiding for Weighted DAO
  Governance*](https://eprint.iacr.org/2026/1773),
  revised 26 August 2026. Its honest-trustee assumptions do not establish the
  malicious sub-threshold privacy required here.
- [*PQKryvos: Post-Quantum Secure E-Voting With Flexible Ballot Formats and
  Public Tally-Hiding*](https://eprint.iacr.org/2026/1004), PoPETs 2026.
- [*Audit-or-Cast: Enforcing Honest Elections with Privacy-Preserving Public
  Verification*](https://arxiv.org/abs/2604.18163), revised 21 April 2026.
- [*Threshold Receipt-Free Voting with Server-Side Vote
  Validation*](https://eprint.iacr.org/2025/1321),
  E-Vote-ID 2025.
- [*FiltrumVote: Scalable, Verifiable, and Coercion-Resistant Internet
  Voting*](https://eprint.iacr.org/2026/1435), July 2026.
- [*On the Necessity of Pre-agreed Secrets for Thwarting Last-minute Coercion:
  Vulnerabilities and Lessons From the Loki E-voting
  Protocol*](https://arxiv.org/abs/2604.00188),
  CSF 2026 extended version.
- [*Proactive Refresh for Accountable Threshold Signatures*](https://eprint.iacr.org/2022/1656).
- [*Quadratic Asynchronous DKG from Plain Setup*](https://eprint.iacr.org/2026/1159),
  June 2026.
- [*Anchor-DKG: Distributed Key Generation with Repeating
  Parties*](https://eprint.iacr.org/2026/1570), CCS 2026.
- [*Practical Silent Threshold Signatures and Silent Threshold Encryption for
  Dynamic Committees*](https://eprint.iacr.org/2026/1820),
  CCS 2026.
- [*Beyond Blockchain Ballots: UC-Secure Layer-2 Voting and
  Governance*](https://eprint.iacr.org/2026/1521), CSF 2026.
- [*Proof-of-Uniqueness: Sybil-Resistant Privacy-Preserving Decentralized
  Identity through Threshold-OPRF and zk-SNARK
  Registry*](https://eprint.iacr.org/2026/1725), August 2026.
- Balietti, Saggese, and Strohmaier, [*Voting Biases in Decentralized
  Autonomous Organization (DAO) Governance*](https://arxiv.org/abs/2607.09435),
  10 July 2026.
- Microsoft Research, [*ElectionGuard Specification
  2.1*](https://electionguard.vote/spec/).
- Cortier, Debant, and Gaudry, [*Breaking Verifiability and Vote
  Privacy in CHVote*](https://eprint.iacr.org/2025/080), ESORICS 2025.
- NIST, [*Considerations for Achieving Crypto Agility: Strategies and
  Practices*, CSWP
  39upd1](https://doi.org/10.6028/NIST.CSWP.39-upd1), 29 June 2026.

As of 30 August 2026, the NIST Threshold Call remains in its three-round
preview phase; package submissions are expected in November 2026. The BBDL
tBLS document above is a preview writeup, not a completed package, NIST
standard, or approval of Parliament's construction.

# Standalone referendum boundary

The repository still contains a standalone referendum subsystem with public
PLAIN and proof-backed ZK ballot routes, conviction locks, and tally reads.
Those routes are not Parliament body ballots, cannot stand in for a timed-OVN
jury result, and are not inputs to `GovernanceCertificateV1`. Independent epoch
council records and detached roster state do not exist in the first-release
schema. The first-release public contract contains no proposal approval
snapshot, equal Parliament stage ballot, caller-selected referendum window or
mode, client finalization, or client enactment path.

An exact 32-byte typed proposal fingerprint is reserved across this boundary in
lower-, upper-, or mixed-case hexadecimal form, with or without an exact `0x`
or `0X` prefix. Standalone ballot/state admission, typed-proposal admission, and
snapshot restoration all reject such cross-subsystem aliases. Standalone
closure emits `ReferendumDecided` with the original selector and exact tally;
it never emits a proposal lifecycle event, and the Torii governance stream
therefore publishes only referendum/lock/tally updates for that decision.

PLAIN uses a required `PlainVotingContextV1::Conviction` supplied by authoritative
creation/bootstrap before voting. Its asset ID, smallest-unit scale, custody,
minimum bond, conviction step/cap, approval fraction and minimum turnout are
immutable. There is no first-voter initialization or live-policy fallback.
Weight is `floor(sqrt(exact_smallest_units)) * min(1 + duration / step, cap)`;
conversion and aggregate arithmetic reject fractional frozen units and overflow.
Every positive PLAIN bond transfers actual funds into escrow, including when the
minimum is zero. `CastPlainBallot` creates one immutable choice and cannot act
as an update. `UpdatePlainConviction` has no choice field: Core reads it from the
existing authority-owned lock. The update cannot reduce quantity, requested
duration or absolute expiry; it must increase quantity or absolute expiry. A
shorter remaining duration representing the same absolute expiry is rejected.
Only the latest retained position contributes, and only an increase in quantity
transfers an additional escrow delta. Slash/restitution retain exact
frozen units even if a live asset specification permits more precision.
Restitution rechecks the complete retained corpus before moving funds because
later ballots may have consumed the aggregate headroom freed by a slash; it
does not recompute a closed decision.

PLAIN accepts direction `0` (Aye), `1` (Nay), or `2` (Abstain). Its corpus is capped
at 1,000; owner/custody bindings, each category and total turnout are checked in
one canonical Core tally consumer shared by Torii. Restore validates the required
context/result pairing and the same arithmetic without applying PLAIN rules to
ZK bonds. Minimum turnout includes abstentions; the approval fraction is
`Aye / (Aye + Nay)`, with an empty decisive tally rejecting and exact 192-bit
threshold comparisons. Closure stores a required immutable `Decided` result
before unlock, including for an empty proposed referendum. Torii reads that
result after funds and live lock records are released. Missing closed results
are invalid, and current policy cannot recompute or change a retained decision.

These public-account correctness rules do not implement anonymous standalone
ballots, credential-linked confidential positions or the reviewed complete-corpus
tally relation. Production creation/admission of that private protocol remains
unresolved. For standalone ZK voting,
closure without a finalized tally durably records `Closed` and emits no
decision; a later verified finalization emits that deferred
`ReferendumDecided` exactly once, while finalization before closure leaves the
decision to the one-shot close transition.

`CastPlainBallot`, `UpdatePlainConviction` and `CastZkBallot` must be the sole direct instruction in a
signed transaction; contracts, triggers, IVM programs, and mixed instruction
lists receive no ballot entrypoint binding. A penalized ballot still returns
its normal transaction error. If the rejected overlay prevalidated a nonzero slash,
the block rejection corridor replays that exact amount in a fresh state
transaction before rejected-fee settlement, committing `LockSlashed` and
`BallotRejected` while emitting no `BallotAccepted`. A later fee failure cannot
roll that penalty back. Rejections for which no slash was applied persist no
penalty. Rejected ZK verification attempts still consume the block's
confidential operation, verifier-call, proof-byte, confidential-gas, and
ordinary gas budgets. The same exactly-once block accounting applies to
ordinary prepared overlays, trigger work, detached fallback, and early
mixed-batch rejection. Same-block trigger lifecycle changes execute in
canonical order, so a newly registered trigger can affect a later transaction
and a failing trigger rolls that transaction and its trigger effects back
atomically. Every sealed reveal commits its outer carrier; only a reveal
authenticated against pre-carrier pending-commitment state also commits the
exact enclosed signed replay alias. Autonomous merge persists that decision in
its certified execution transcript, and recovery does not reclassify it from
post-state. Public transaction lookups accept either committed identity and
project the canonical outer carrier.

# SCCP-owned governance mechanisms

The SCCP workstream owns this section under the cross-workstream agreement in
[`sccp.md`](sccp.md) §14 D17–D18. It covers the fast pause track, the
governance clock with its due-work keepalive, and the SCCP launch gate. The
Parliament workstream owns the ballot sections of this file and the
[ballot design](parliament_private_ballot_design.md). `sccp.md` §4.7, §4.14.7
and §10 are normative for SCCP state, events, parameters and fixtures; this
section states how those mechanisms sit in the governance pipeline and what
they require of it. None of it is implemented yet (`sccp.md` §12: WP-S3, WP-S5,
WP-S9, WP-S10 and WP-C3). Until it lands, the attempt lifecycle above describes
current source, including its height-based windows.

## Fast pause track

1. **Scope.** The track can only pause SCCP. An enacted fast pause holds one
   external network's Taira part (recording, inbound settlement and refunds of
   every non-`Retired` revision) and the destination parts of its live
   revisions until it lapses by time (`sccp.md` §4.14.7). It cannot move value,
   raise caps, register, activate or resume routes, clear faults, attest
   deployment progress, quarantine, or authorize any permanent change. It is
   not a proposal kind: it creates no `ProposalContentId`,
   `GovernanceAttemptId` or `GovernanceCertificateV1`, and it changes only the
   automatic SCCP head `FastHold(network)`, never the expected head of a
   full-track subject, so it cannot supersede a full-track proposal.
2. **Standing panel outside the attempt reducer.** One standing panel serves
   every network. A single draw without replacement over the canonical
   eligible-citizen snapshot of the parent state fills `k` primary seats, `k`
   disjoint backup seats and up to `k` reserve members, with
   `k = fast_pause_panel_seats` (5, 7 or 9) and quorum
   `parliament_quorum_seats_v1(k)` (4, 5 or 6). It uses the citizen-eligibility
   predicate and the governance draw that sortition uses.
   - The draw is step G0 of the block-start pass (below) of a block that
     carries the NPoS global-beacon pulse at the native pre-boundary height
     (`last_height - 1`, one block before the committee boundary), which consensus already
     requires, when no panel is seated or the seated panel's term has ended.
     It happens only in that block and is never deferred.
   - It registers no `SortitionRequestV1`, adds no Parliament pulse demand or
     consensus-mandatory slot, and consumes no sortition sequence, redraw unit
     or proposal-wide entropy budget. The attempt reducer, its sortition chain,
     the planner and `validate` never see it; a fast pause only reads the
     seated panel.
   - A missing pulse leaves the previous panel seated and extends its term.
     That is a governance-local wait: it never stops block production and is
     never due work. Fewer than `2k` candidates, or a snapshot over the 8 MiB
     ceiling of lifecycle item 4, likewise leaves the seated panel in place.
   - The term is `fast_pause_panel_term_ms`. A draw at every epoch boundary is
     the parameter value equal to the epoch duration. The selected default is
     7 d (`sccp.md` §4.14.7).
   - Seating freezes and retains no bond. The bond-retention rules of
     lifecycle item 4 apply to Parliament elections only; a seat holder whose
     bond falls below the floor, or who is slashed or suspended, only stops
     counting at the next eligibility recheck.
   - Drawn members accept their seats; from the acceptance deadline an
     unaccepted seat passes to the next accepted, eligible reserve member. Seat
     holders are a pure function of state and time (`sccp.md` §4.14.7).
   - The boundary pulse is a unique threshold signature, but an `f + 1` beacon
     coalition that includes the parent proposer can withhold or delay it and
     so choose among draws. That is beyond the BFT bound; the mitigation is
     Parliament suspension of the track.
3. **Endorsements.** `EndorseSccpFastPauseV1` is a public, account-signed
   transaction from a seat holder that pays the ordinary fee. It is a public
   finding, like the endorsements of public-finding bodies, not a binding-jury
   ballot: no credential, nullifier or anonymous admission applies. It binds
   the live `network_id` and the external `network` (the route), the
   `panel_id` (primary or backup of the seated panel), `head =
   rev(FastHold{network})` and a nonzero `incident_digest` (the incident
   commitment). The head serves as both the current-head binding and the
   endorsement nonce: every enactment, renewal and lift changes it, so no
   endorsement replays against a later state. Each panel keeps one round per
   network with an immutable `closes_at_ms = opened_at_ms +
   fast_pause_endorse_window_ms`; certification after that time ends
   `NoResult`, so no approval outlives its window, even across a halt.
4. **Eligibility rechecks.** Seat holding and citizen eligibility are checked at
   admission and at execution of every endorsement, at certification and again
   at enactment, after every Parliament enactment earlier in the same pass.
   Only endorsers that still hold a seat and are eligible count toward quorum.
   A failed recheck ends the round `NoResult`; it never certifies on a stale
   count.
5. **Failover.** Both panels decide. Each keeps its own round, the first round
   to reach quorum certifies, and enactment deletes both rounds of the
   network. If both certify in one pass, the primary enacts first and the
   backup ends `NoResult` at its head recheck. The backup therefore takes over
   whenever the primary cannot reach quorum from its eligible members, which is
   the automatic failover of the cross-workstream agreement (`sccp.md` §14
   D13), with no timeout and no eligibility trigger. A decline, a blocking
   minority or a `NoResult` in one panel never blocks the other; disabling the
   brake needs a blocking minority, or absent members, in both panels, and the
   capture figures of `sccp.md` §4.14.7 use the union of the two panels. The
   Parliament workstream confirmed this reading on 2026-10-05 (`sccp.md` §10.1
   item 4).
6. **Certification and enactment.** Quorum sets a due pause-panel conclusion
   (G2a rank 3). It builds an `SccpFastPauseCertificateV1`, which is not a
   `GovernanceCertificateV1`, so the Policy Jury requirement of that type does
   not apply. Enactment runs in G3 after every Parliament certificate due in
   the same pass, in its own rollback-isolated transaction, records its
   block-start position in `enacted_at`, and bumps `rev(FastHold{network})`.
7. **Hold lifetime.** `fast_pause_hold_ms ≥ parliament_sccp_attempt_latency_ms()`
   ([ballot design](parliament_private_ballot_design.md) section 11). The
   pipeline provides the function: the configured latency of one full-track
   SCCP attempt, including a single sortition-retry generation, derived from
   the committed windows (the stages listed in `sccp.md` §4.14.5 "Latency",
   including one Confirmation Jury round and the enactment delay). The ballot
   has no ballot retries, so the bound covers one attempt; a longer outage,
   such as a rejected attempt followed by a retry attempt, is covered by
   renewal before the lapse (item 9). While SCCP exists, every path that
   changes an input of the function (genesis validation, node start-up against
   the pinned consensus execution policy, and any committed governance-policy
   change) rechecks the rule against the current `fast_pause_hold_ms` and
   refuses a value that breaks it (`TODO:` WP-S5, with the owner of the
   Parliament parameters). The bound cannot guarantee that the full track
   finishes before expiry, because exact-pulse waits are unbounded (ballot
   design section 9); renewal covers the gap while the panel is honest.
8. **Lapse.** A fast pause stops holding as soon as the block time, or the
   destination's own time, reaches `until_ms`; no transaction, leaf or block is
   needed. Step G4 deletes the expired record. A lapse is neither due work nor
   a head change, and it never touches Parliament pause state, forgery holds or
   quarantine.
9. **No re-pause cooldown.** A panel may pause again as soon as a pause lapses,
   and a renewal round may open `fast_pause_renew_lead_ms` before the lapse, so
   protection has no gap. There is deliberately no cooldown: an attacker who
   forced one lapse could otherwise disable the honest brake. A captured panel
   can therefore keep a network paused while it is seated; the Parliament
   bounds it with `SetFastPauseSuspended` and a lift.
10. **Lift rule.** A full-track resume (`SetTairaPaused{…, false}` or
    `SetDestinationPaused{…, false}`) clears the matching part of the
    network's fast-pause instance `H` only if:
    - `H` is the current head of `FastHold(network)`; the active record always
      is, because every enactment, renewal and lift bumps that head; and
    - `H.enacted_at = (height, position)` is lexicographically smaller than
      `(s0.height, s0.position)` of the approving Policy Jury ballot.

    Otherwise the part is retained, so a resume decided before an emergency
    never undoes a later pause.
    `s0 = GovernanceAnchorV1 { height, position, timestamp_ms }` is the anchor
    triple of the [ballot design](parliament_private_ballot_design.md)
    section 3.4: the finalized height, the opening transition's position in
    that block's pass (G2c), and the block's time. The timestamp is carried but
    never compared, because two transitions in one block share a time but not a
    position. Openings precede enactments in a pass, so a ballot that opens in
    the block of a fast-pause enactment can never lift it. A Confirmation Jury
    ballot, outcome evidence and enactment do not move `s0`; a successor
    governance attempt has its own. To answer a captured panel the Parliament
    suspends the track first, then resumes: a resume ballot that opens after the
    suspension is enacted lies after every pause the panel could still enact.

## Governance clock

1. **Time base.** Governance deadlines are canonical block times in
   milliseconds. A due item is applied by the block-start pass of the first
   block `B` with `t(B) ≥ due_ms`, never by block count. Beacon pulse slots,
   recorded `*_at_height` fields and the validation-fee activation offset stay
   height-based. Converting the invitation, deliberation and public-finding
   windows and the enactment delay (`enact_not_before_ms = certified_at_ms +
   delay`) is part of this work (`TODO:` WP-S3, coordinated with the Parliament
   workstream).
2. **Intents in transactions, transitions at block start.** Transactions record
   facts and intents only. Lifecycle transitions, including early closes, panel
   conclusions, ballot openings and closures, certification and enactment, are
   applied by Core's block-start pass. Only transitions applied by the pass take
   a time anchor, each the `t(B)` of its block: body draws, Reflection entry,
   ballot openings (`s0`), certifications and fast-pause enactments. Every other
   deadline is a fixed offset from an anchor, computed when the anchor is
   applied, and never moves.
3. **Block-start pass.** It runs on the global chain's ordinary carrier only,
   after SCCP's begin-block step S0 and before any transaction:

   | Step | Items | Order |
   |---|---|---|
   | G0 | Pause-panel draw | At most one per native pre-boundary pulse carrier |
   | G1 | Parliament sortition at its exact pulse slot | Request order of the Parliament pipeline |
   | G2a | Ranks 0–2: Parliament lifecycle transitions. Rank 3: pause-panel conclusions and reconciliation-window ends (`sccp.md` §4.10) | `(due_ms, kind_rank, item key)`; SCCP's common item key is `(network tag, kind, subkey)`, with kind 0 and primary 0/backup 1 for pause conclusions, kind 1 and revision for window ends |
   | G2b | Rank 4: binding-ballot closures whose closing time `t(h_open + 1) + casting_window_ms`, with `h_open = s0.height`, has been reached | `(closing time, governance_attempt_id, body_role)` |
   | G2c | Rank 5: binding-ballot openings with `opening_at ≤ t(B)`, deferred ones included, while fewer than `K` casting windows are open | `(opening_at, governance_attempt_id, body_role)` |
   | G3 | Enactments: Parliament certificates, then fast pauses | `(enact_not_before_ms, governance_attempt_id)`, then `(network tag, panel role)` |
   | G4 | Fast-pause lapse cleanup | Network tag |

   - Closure is anchored to the first block executed after the opening block,
     not to `s0`, so an opening that is already stale when it commits never
     shortens voting ([ballot design](parliament_private_ballot_design.md)
     sections 3.4 and 3.7). The closing time is fixed when block `h_open + 1`
     executes and never moves.
   - The Parliament workstream fixes the item kinds, keys and costs of ranks
     0–2. Ranks 6–8 are reserved and have no item kind; adding one changes this
     section and the ballot design together. The ballot needs exactly ranks 4
     and 5 ([ballot design](parliament_private_ballot_design.md) section 8).
   - Each step reads the state that the earlier steps of the pass left. Due
     closures therefore free their slots before openings are considered in the
     same pass, and a Reflection entry whose `opening_at` has already been
     reached opens its ballot in the same pass. An item that a transition makes
     due in its own step or an earlier one waits for the next pass.
   - A casting window counts as open until its closure is processed. The first
     opening that finds no free slot ends G2c; it keeps its place, and its
     deferral consumes no retry.
   - **Budget.** G1–G3 share `gov.governance_block_start_work_units` (default
     64, minimum 43). The minimum funds one recurring height-progress ticket
     (1), one largest Parliament item, a complete generation draw (32), all six
     possible SCCP conclusions (1 each) and one enactment (4), so
     recertification alone cannot starve every enactment.
     Genesis and parameter updates enforce this floor. Each item has a fixed cost set by its owner; an enactment costs 4,
     and a pause-panel conclusion or a reconciliation end costs 1. The first
     item of a pass is always processed; after that, processing stops at the
     first item whose cost exceeds the remaining budget, order is never
     skipped, and leftover items stay due. G0 and G4 are outside the budget.
     A closure that the budget defers changes no corpus: block validation
     checks each ballot against its own block's timestamp (ballot design
     section 3.6), so a ballot in a block at or after the closing time is late
     whether or not the closure has run. A deferred opening takes its `s0` at
     the pass that actually opens it.
     A fast pause deferred between G2 certification and G3 enactment keeps its
     round due. The next pass recertifies it against current eligibility, head
     and time; the certificate itself never survives the pass or extends the
     endorsement window.
   - **Positions.** Every processed G1–G3 item gets its 0-based index among
     the items processed in that pass. Ballot openings record theirs in `s0`,
     and fast-pause enactments in `enacted_at`. S0, G0 and G4 are not
     positioned. `governance_due_applied` holds iff at least one G1–G3 item was
     processed.
4. **Due predicate.** SCCP owns `governance_due` (`sccp.md` §4.7.3):

   ```text
   governance_due(parent, h, t) :=
        ∃ unconsumed Parliament pulse request with pulse_height = h
     ∨ ∃ G2a or G2b item with due_ms ≤ t
     ∨ ∃ ballot opening with opening_at ≤ t while fewer than K casting windows are open
     ∨ ∃ certified attempt with enact_not_before_ms ≤ t
     ∨ ∃ fast-pause round with certify_due
     ∨ ∃ item carried over by the block-start budget
   ```

   - A pulse request is due only at its exact slot. A slot that passes without
     its pulse leaves the request waiting for that exact pulse; the wait is not
     due work, so a missing beacon never manufactures blocks. The slot is a
     consensus-native pulse height, and no pulse is produced or carried for an
     elapsed slot (ballot design section 9). A late request is therefore one
     whose exact-slot pulse is already committed and not yet consumed.
     `TODO:` (WP-S3, with the Parliament workstream): add the matching due leg;
     under the progress invariant it may make a request due only in a pass
     that consumes it.
   - Fast-pause lapses and pause-panel draws are not due work.
   - **Progress invariant**, binding on every present and future term: an item
     may appear in `governance_due` only if the pass that finds it due consumes
     or terminalizes it. An item that waits for external material is not due.
5. **Clock bounds.** Certified block time is bounded by the Sumeragi
   Prepare-vote clock guard ([`sumeragi.md`](sumeragi.md) §4.5, CT1–CT5;
   `sccp.md` §4.3). `max_clock_drift_ms` is a committed chain parameter capped
   at 60 000 ms. An honest voter withholds its Prepare vote while a block's
   time exceeds its own wall clock by more than `max_clock_drift_ms`, the rule
   that ballot design section 3.4 relies on. Allowing for the skew between
   honest clocks, which the liveness assumption bounds by
   `max_clock_drift_ms`, a deadline can fire up to `2·max_clock_drift_ms`
   early relative to an individual honest clock (`sumeragi.md` §4.5, "Upper
   bound"; ballot design section 3.4). Wallets, jurors and panelists submit at
   least `2·max_clock_drift_ms` plus inclusion latency before a deadline
   (ballot design section 6; `sccp.md` §4.3). CT5 bounds how stale an anchor
   is at its first honest Prepare by `sumeragi.due_work_max_lag_ms` (default
   60 000, at least `2·max_clock_drift_ms + 4·block_cadence_ms`), but view
   changes or a hidden PrepareQC can add commit lag. A ballot opening that is
   already stale when it commits never shortens voting, because closure is
   anchored to the block after the opening (item 3, G2b), and a stale
   fast-pause enactment holds for less time and can be renewed (`sccp.md`
   §4.3). Until WP-C3 lands and is qualified, the clock blocker of ballot
   design section 3.4 stands.

## Due-work keepalive

`Keepalive {}` (wire id `iroha.chain.keepalive.v1`) is the shared
permissionless due-work transaction that the
[ballot design](parliament_private_ballot_design.md) section 3.4 relies on. It
is one chain-level instruction with no fields and a no-op execution, and a
transaction that carries it carries nothing else. `sccp.md` §4.7.4 is
normative for its block rules.

- **Due.** `keepalive_due(parent, h, t) := sccp_due(parent, t) ∨
  governance_due(parent, h, t)`, where `sccp_due` is the SCCP heartbeat leg.
  Admission evaluates it on the committed tip with `h = tip + 1` and
  `t = c + 1`, where `c` is the keepalive's `creation_time_ms`, and also
  requires `c ≤ local_wall_ms + max_clock_drift_ms` (K5).
- **Block rules.** A block carries at most one keepalive (K1), and a block that
  carries one is valid only if its pass applied due governance work
  (`governance_due_applied`), or SCCP exists, its heartbeat trigger `BEAT`
  holds at that block and the parent's degraded run is below 2 (K2);
  otherwise the block is `Invalid`. An honest proposer includes a keepalive
  only when its candidate block satisfies K2, and replaces a stale one with a
  fresh one of its own (K4).
- **Who and fees.** Anyone may submit, from any Ed25519 authority, registered or
  not; an eligible keepalive is fee-exempt. Validators' in-node keepers submit
  it with a stagger; juror and panel wallets may too.
- **Guarantees.** No block exists without due work, so idle chains create no
  empty blocks: an idle chain produces one block per due governance item and
  one per SCCP heartbeat. A keepalive cannot advance chain time (CT1), and due
  work is anchored within `sumeragi.due_work_max_lag_ms` of honest time (CT5, K4).
  No external transaction has to land at an exact height. The Parliament
  driver stays an optional convenience for attempt creation and manager
  intents, and the attempt plan is advice, not a reservation (`sccp.md`
  §4.14.5 item 4).

## SCCP launch gate

- `RegisterRoute` requires both `parliament_binding_ballot_available()`,
  provided by the Parliament workstream and true once the qualified
  post-quantum ballot is active on the chain (ballot design section 5), and
  `sccp_reconciliation_available()`, provided by SCCP and true once
  reconciliation of quarantined revisions is implemented (`sccp.md` §4.10).
  Both are stubs that return `false` (`TODO:` WP-S9; `sccp.md` §10.2).
- While the ballot leg is closed, `ProposeSccpRouteGovernance` is refused for
  every SCCP action with `ParliamentBallotUnavailable`. There is no interim
  governance, the SCCP parameters keep their genesis values, and genesis and
  Kagami create no route.
- SCCP machinery that needs no route still runs: committee generations,
  heartbeats, keepalives, finality headers, anchors, the liability clock,
  forgery evidence and pause-panel draws. The fast pause track stays inert,
  because an endorsement needs a route. The standing panel therefore never
  stands in for the binding ballot and does not make binding governance ready
  for mainnet (ballot design section 11).
- SCCP launch additionally needs the SCCP-owned work above (`sccp.md` §12):
  the governance clock and keepalive (WP-S3), the clock guard (WP-C3,
  [`sumeragi.md`](sumeragi.md) §4.5), the fast pause track (WP-S5),
  reconciliation (WP-S10) and the gate itself (WP-S9).

# Outstanding release gates

- Re-run the already-green focused data-model/Core/Torii and source/model gates
  from one clean immutable candidate, then pass workspace tests, strict Clippy,
  formatting, and the remaining release matrix with archived provenance.
- Qualify the implemented live threshold-beacon partial-share transport,
  per-session runtime custody, threshold aggregation, candidate-effect
  assembly, and authoritative finalized-pulse persistence on at least four
  peers, including missing/invalid shares, restart, idempotent retransmission,
  mandatory NPoS boundary slots, key rotation, and Parliament pulse waits held
  as governance-local pending work rather than consensus-mandatory slots
  ([ballot design](parliament_private_ballot_design.md) section 9).
- Qualify canonical carrier publication and retirement on every nonproducer
  follower. Cover an `author = false` live follower retiring a losing carrier
  from the exact FIFO-only/no-Queue-owner state, plus strict cold-start replay
  at the all-`ReleasePending` and partial-`Released` cuts. Require unchanged
  Queue/FIFO journal bytes, no fabricated Queue owner, complete Kura/Queue
  terminal cleanup, a still-live follower runner, and fail-before-mutation
  rejection of missing or misordered FIFO evidence.
- Implement and qualify the [anonymous ballot](parliament_private_ballot_design.md):
  credential registration with possession proofs at seat acceptance, the
  credential root frozen at seal, signerless proof-authorized admission with
  nullifier uniqueness and bounded verification work, deterministic block-start
  closure, public tally, certificate binding, and independent full verification
  from finalized block data, on at least four peers with restart and rollback.
  The TLE release, custody and coordinator path is retired with timed-OVN; no
  custodian remains to qualify.
- Qualify voter-side credential custody and proving: a wallet-held credential
  secret, whole-roster path construction from public state, proof generation
  within the profile targets, and account- and session-free submission, with
  native and SDK fixtures. Select and qualify the canonical V1 proof profile
  first ([ballot design](parliament_private_ballot_design.md) section 5).
- The feature-isolated four-validator target contains a corridor for two
  independently validated global-beacon DKG transcripts. It installs the
  predecessor, applies
  a `2f + 1` compare-and-set rotation in an epoch-boundary block, verifies that
  the same block's pre-boundary pulse still uses the parent session, and verifies
  that the next pre-boundary pulse and epoch seed use the activated successor.
  The same corridor covers exact-height enactment and normal restart/restore;
  its proof-valid timed release is retired with timed-OVN and needs an
  anonymous-ballot replacement corridor. The target also contains stale-head supersession
  and rollback-isolated execution-failure corridors; all require fresh
  same-source four-validator evidence before promotion.
- The four-validator public-finding target contains authority-bound self-absence,
  early impossible-quorum `NoResult`, a fresh governance retry, immutable
  competing roots, post-deadline endorsement rejection, permissionless
  `PublicFindingDeadlineExpired`, a second retry, four-peer state equality, and
  normal validator restore. Progress still assumes an eligible transaction
  eventually submits the deterministic deadline trigger.
- Candidate-qualify the implemented Torii, MCP, CLI, OpenAPI,
  Rust/JavaScript/Kotlin/Java/Swift SDK, and shared-fixture coverage for the
  typed attempt and certificate surface. Regenerate signed OpenAPI provenance,
  execute candidate-native SDK artifacts, verify canonical ballot rendering
  across clients, and keep the already-retired equal Parliament ballot and
  proposal-backed finalize/enact surfaces absent.
- Candidate-qualify the implemented aggregate-only transition/failure counters,
  committed status/stage gauges, and reviewed stuck-attempt/deadline alarms
  across restart and four-peer execution. Keep identifiers, roots, registrations,
  ballots, shares, individual openings, and account labels out of metrics.
- Candidate-qualify the existing focused automatic-enactment, stale-head
  supersession, and rollback-isolated `ExecutionFailed` coverage on four peers,
  including restart validation and rejection of every signed terminal-outcome
  draft.
- Obtain an independent review of the anonymous-ballot relation: credential
  membership and nullifier statement, context binding, post-quantum soundness
  and zero-knowledge parameters, constant-time/side-channel boundary,
  implementation, build artifacts, and target matrix. No external audit report
  or evidence archive is embedded or claimed by this repository.
- Run the bounded model as counterexample search, exhaustively check the
  configured state space with pinned TLC 2.19, and archive both same-source
  outputs. These are complementary evidence, not replacements for proof review,
  cryptographic test vectors, implementation tests, or multi-peer execution.
- Complete the candidate-native ABI-23 Swift and Android replay, capacity/rekey/
  validation-fee restore scenarios, same-source benchmark archive,
  chaos/soak qualification, and external release signing.
