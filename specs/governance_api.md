---
title: Governance App API — Endpoints
---

Status: first-release canonical contract, not release-qualified.
Determinism and RBAC policy are normative constraints; Torii returns unsigned
instruction skeletons for governance transaction-producing flows. Request
schemas exclude private signing material and reject unknown fields before
constructing a request object. Clients sign locally and submit via
`/v1/pipeline/transactions`.

Important: the attempt reducer does not use a standing council, default roster,
or roster derived at proposal creation. Each body election freezes the complete
eligible-citizen snapshot in its `SortitionRequestV1`; that request is committed
before a strictly future finalized threshold-beacon pulse. The first consumed
pulse covers all initially required bodies as one simultaneous draw batch.
Roster sealing follows authenticated invitation responses. Reads never derive a
missing roster from assets, module names, configuration, or another attempt.
The first-release state schema contains no standing council or detached
Parliament-roster snapshot; the attempt reducer is the sole roster authority.
Every governance lock likewise carries its immutable asset, escrow, and slash
custody binding; missing-custody JSON/Norito records are rejected and runtime
configuration is never used to reconstruct retained lock custody.
A citizen is an account that posted the configured minimum bond; the bond is
an anti-Sybil/collateral floor and does not increase Parliament draw odds or
vote weight above the minimum. There is no baked-in multisig, secret key, or
privileged council account in this repository.

Overview
- Endpoints return JSON except where an endpoint explicitly documents a typed
  Norito proof response. For transaction-producing flows, responses include
  `tx_instructions` — an array of one or more instruction skeletons:
  - `wire_id`: registry identifier for the instruction type
  - `payload_hex`: Norito payload bytes (hex)
- Governance endpoints do not server-sign and their request types have no
  private-key fields. Clients assemble a `SignedTransaction` using their
  authority and exact genesis-derived `NetworkId`, then sign locally and POST to
  `/v1/pipeline/transactions`.
- Runtime/governance routes that read committed state, derive a principal-bound
  draft, or perform bounded proof work require canonical account request
  authentication. The signature commits the exact genesis-derived `NetworkId`,
  HTTP method, origin-form URI (including the query), bounded raw body, timestamp,
  and one-shot nonce. Torii verifies the account against committed state before
  path/query/body extraction or computation, rejects wrong-network signatures
  and nonce replay, and serves successful authenticated responses with
  `Cache-Control: private, no-store` and the canonical-auth `Vary` fields.
  Catalog paths use strict normalization: clients sign and send the declared path
  exactly, without a trailing-slash redirect.
- This boundary covers the ZK roots, Merkle-path and vote-tally reads; active ABI,
  runtime-metrics, node/privacy-capability and projection-checkpoint reads; the
  Ministry draft/read routes; governance proposal, capability, citizen, lock,
  referendum, tally, protected-namespace, unlock, and governed-contract
  reads/drafts; and all typed validation-fee proof/proposal routes.
  The Ministry agenda `authority`, citizenship-draft `owner`, and validation-fee
  proposal-draft `proposal_operator` must equal the verified account before
  state access.
  Operator and protocol-handshake routes retain their stronger dedicated
  boundaries. The fixed ABI-v1 hash calculator remains public in this
  authenticated route family.
- Proposal-backed governance has one client contract: typed proposal drafts,
  Parliament attempt creation, closed lifecycle-transition drafts, complete
  attempt reads, and consensus-owned certificate execution. The retired
  finalize/enact helpers and proposal-backed public Parliament ballot are not
  registered and have no compatibility aliases. Standalone referendum reads
  and ballots are a separate election product and cannot authorize a typed
  proposal. Validation-fee summary responses carry certificate identity and
  heights; the independent-validation response retains the complete canonical
  Parliament certificate.

## SoraFS Governance DAG read authority

The `/v1/sorafs/governance/dag/*` read routes do not trust mutable authority
filenames. Publish-index and CAR-queue handlers consume one canonical typed
publication snapshot from `NodeHandle`; runtime handlers consume one typed
head/index snapshot authenticated by the exact sealed producer checkpoint. The
dashboard, head, block, and node routes consume only the supervised Governance
DAG service's mirror-read capability, which irohad installs exactly once before
the first `NodeHandle` clone is shared. A configured node without that
capability has no mirror authority, and there is no loose-file fallback.

Successful JSON projections identify the authority with `source`,
`source_generation`, and `source_record_blake3`. Mirror and runtime projections
also include `source_checkpoint_generation` and
`source_checkpoint_revision`. They never expose a mutable authority
`source_path` or runtime `head_path`; root-relative immutable artifact paths may
still appear where a response identifies a content-addressed source, block, or
CAR object. Representation ETags commit the typed record identity and, for
mirror/runtime reads, the sealed checkpoint identity before conditional
matching, so changed authentication metadata cannot be hidden by `304 Not
Modified`.

Endpoints

- GET `/v1/gov/capabilities`
  - Exact-network account-authenticated readiness projection. Returns schema
    `iroha.governance.capabilities.v1`, version `1`, one mandatory typed
    `network_id`, current height, ABI/data-model versions, standalone
    referendum settings, configured body targets, supported proposal kinds, and
    supported routes.
  - Configured body sizes are targets, not a minimum citizen count. Each actual
    draw is capped by its frozen eligible-citizen snapshot. A nonempty
    undersubscribed snapshot can therefore seal a smaller roster while keeping
    its immutable original-seat quorum denominator; an empty snapshot rejects
    the sortition request.
  - Capability metadata is descriptive only. Its standalone referendum fields
    do not configure or select a Parliament body, private ballot, certificate,
    or alternate proposal authorization path.
  - Every governance integer other than the fixed response `version: 1` is a
    canonical unsigned decimal JSON string. This includes heights, windows,
    thresholds, body targets, and quorum/count fields; clients must parse the
    complete string before applying any bounded UI conversion.

- POST `/v1/gov/citizens/draft`
  - Strict request: `{ "version": 1, "owner": "<i105-account-id>" }`.
  - Returns the exact configured citizenship amount and one
    `RegisterCitizen` instruction skeleton. Unknown fields and unsupported
    versions are rejected; the node never signs the draft.

- POST `/v1/validation-fee/policy/current/proof`
  - Accepts the strict Norito V1 request containing `version` and a non-zero
    `trusted_checkpoint_height`. It returns the complete protected registry
    when configured, its synthetic ordinary-write witness, and a consecutive
    Sumeragi-v2 finality page beginning at that checkpoint.
  - A page contains at most 64 finality proofs and advances at most 63 blocks.
    While `more_available` is true, clients promote `evaluated_context_id` and
    request the next page; an incomplete, skipped, reordered, rollback, or
    equivocal chain is not deployable evidence.
  - Clients verify locally with the immutable chain id, genesis hash,
  policy-chain genesis hash, checkpoint height, and checkpoint context id.
    The resulting verified projection includes, for both the policy and payout
    lifecycle proposals, the canonical `proposal_operator`, exact proposal
    fingerprint, canonical `governance_certificate_id`, complete
    `governance_certificate`, certification height, and certified enactment-due
    height. Verification requires the certificate content id to equal the exact
    operator-bound proposal fingerprint, the certificate id to equal the
    canonical hash of the retained certificate, enactment to occur at the
    certificate's due height, and the exact
    `effective_from_height = enacted_at_height + 120,960` relation.
- GET `/v1/validation-fee/proposals`
  - Lists only typed native validation-fee policy and payout-lifecycle
    proposals. Records retain the exact typed operator-bound payload and ordered
    pipeline. Certified records expose the canonical certificate id,
    certification height, enactment-due height, and enacted height as a bounded
    summary; they do not duplicate the full certificate.
- GET `/v1/validation-fee/proposals/{proposal_id}`
  - Returns the exact proposal summary, current committed height, and the full
    canonical Parliament certificate when the proposal has been certified and
    retained in the protected registry. This is the independent-validation
    endpoint: clients must validate the certificate before trusting its id or
    outcome. All projected height fields are canonical unsigned decimal strings.
- POST `/v1/validation-fee/proposals/draft`
  - Builds exactly one native validation-fee proposal instruction for
    local signing. The authenticated strict request requires
    `proposal_operator` to equal its canonical request signer. That account is
    embedded in the exact native policy or payout-lifecycle proposal preimage,
    so changing the signer changes the proposal fingerprint. The request does
    not accept a public referendum mode, window, electorate, or finalization
    shape; those are not validation-fee authorization inputs.
  - `/v1/validation-fee/proposals/{proposal_id}/plain-ballot/draft` is retired
    and is not registered. Requests to that path fail at routing. Validation-fee
    authorization is produced only by the canonical Parliament attempt
    lifecycle and its complete certificate (in current source, the timed-OVN
    ballot that the [ballot decision](parliament_private_ballot_design.md)
    retires); Torii does not translate a public
    ballot into that protocol.

## Attempt-based Parliament native surface

The canonical proposal-backed protocol is submitted through the ordinary
locally signed transaction pipeline using two closed Norito instructions:

- `iroha.governance.parliament.attempt.create.v1` carries only the exact typed
  `ProposalKind` and the zero-based end-to-end attempt sequence. Core derives
  the proposal-content id, attempt id, risk tier, required-body pipeline, policy
  version, effect hash, and expected compare-and-set head. Both native
  validation-fee kinds derive a constitutional pipeline containing MPC
  immediately before FMA, because they govern the network fee schedule or its
  treasury payout lifecycle. SCCP remains FMA-only at that specialist segment;
  clients cannot add, remove, or reorder either committee.
- `iroha.governance.parliament.transition.submit.v1` carries the attempt id and
  one `ParliamentLifecycleTransitionV1`. Containing-block height and order are
  never caller fields. Invitation response, attempt absence, public-finding
  endorsement, timed-OVN registration, and dropout are authority-bound to the
  affected seated assignment. `ConsumeSortitionPulseBatch`,
  `BeginInvitationAcceptance`, `FailBodyElectionNoRoster`, and `SealBodyRoster`
  are permissionless election-progress triggers: their payloads identify only
  precommitted requests, pulse coordinates, or one election. Core verifies the
  finalized pulse and complete pending request set, derives the draw and
  configured invitation window, derives whether expiry has no roster, and
  derives the accepted roster, root, and body-instance identifier. A relayer
  cannot supply any of those results. Deterministic ballot checkpoint, release,
  failure, and aggregate-finalization variants are likewise permissionless but
  cannot select their consensus result: Core accepts them only when the exact
  persisted height, corpus, pulse, proof, and state bindings match. Attempt
  creation, risk/qualification intent, sortition-request registration, body
  phase intent, and ballot creation retain the exact unit
  `CanManageParliament` permission. Proof-heavy ballot-corpus chunks are
  permissionless progress triggers because Core derives their exact next
  survivor offset and accepts them only after verifying every record.

Sortition requests must carry `request_height` equal to the containing block,
the complete Core-derived eligible-citizen snapshot, and the Core-derived pulse
height for the network's canonical logical beacon: the first consensus-native
pulse height (`(h + 1) % L == 0` for the NPoS epoch length `L` frozen in the
attempt) at or above both `request_height +
parliament_sortition_pulse_delay_blocks` and one above the highest slot of an
earlier generation of the same attempt. Any other height is rejected. Attempt
creation is rejected on a chain without an NPoS cadence
(`Parliament sortition requires the consensus-native NPoS pulse cadence`). A
registered request creates no consensus pulse demand. It waits, possibly
indefinitely, for exactly that pulse; there is no missing-pulse failure, and
`FailBodyElectionNoRoster` is rejected while an election awaits its pulse.
That logical Parliament
identifier is independent of the threshold key session that will be active at
the requested height, so a valid key rotation cannot strand an already
committed request. Initial pulse consumption is a complete, strictly ordered
batch for all initially required bodies. A Confirmation Jury, when added by a
narrow Policy Jury approval, excludes every Policy Jury member. Finalization
atomically commits its exact Core-derived candidate snapshot, configured target,
current request height, and deterministic future logical-beacon slot alongside
the Policy result. Later eligibility changes therefore cannot strand the active
attempt before its first Confirmation draw. Hidden-ballot sortition requires at
least three eligible candidates; the Policy and Confirmation Jury configuration
sizes therefore also have a minimum of three.
The first-release citizen registry is capped at 65,536 entries, and one
canonical Norito candidate-snapshot payload is capped at 8 MiB. Core checks the
registry cardinality before collection and the running encoded size before
cloning each eligible account. These are fail-closed complete-electorate bounds:
Core never truncates, samples, or otherwise biases the eligible set, and restore
plus reducer admission revalidate the same limits.

The public threshold-key lifecycle instruction carries an exact-roster
`2f + 1` certificate over the network, ordered roster, threshold, complete
public transcript, containing height, action, and `expected_active_session_id`.
The roster for containing height `h` is the committee that World's lag-2
consensus schedule holds for `h` (committed in `R_{h−2}`, canonical key order),
so execution and Torii admission read the same committed entry on every node.
Core compare-and-sets that predecessor before applying the action. For the
global beacon, an install or retirement included in block `H` is effective at
`H + 1`; the session active at pulse height `H`, rather than the singleton
successor pointer after transaction execution, verifies and persists a pulse
authorized from `H`'s parent state. This prevents a same-block rotation from
invalidating or reinterpreting an NPoS pulse, including one that a Parliament
sortition request consumes in a later block: consumption re-verifies the pulse
against the session retained for the pulse's own height. TLE lifecycle
changes use the same one-block boundary: an instruction in block
`H` keeps the predecessor selectable through `H` and activates its successor at
`H + 1`. Predecessor public state remains available for ballots already bound
to it.
The fail-safe Initial executor admits this proof-carrying instruction, and the
validation-fee guard classifies it as balance-neutral control-plane state. This
does not delegate lifecycle authority to the transaction signer: Core always
authenticates the exact current-roster certificate before changing either key
family.

`RecordAttemptAbsence` names one assignment but no member account: Core requires
the signed transaction authority to own that exact seated assignment. The
record is attempt-local, immutable, allowed only before endorsements or
balloting, and never reduces `original_seats` or its quorum. For a public,
nonbinding body, `EndorsePublicFinding` carries only the body id and proposed
result root. Each nonexcluded seated authority may bind exactly one immutable
root. Core, rather than a manager-supplied finalization payload, approves the
body only when one root reaches `ceil(2 * original_seats / 3)` and commits the
strictly ordered `endorsing_assignments` list, its recomputed endorsement root,
actual endorsement count, and immutable quorum into
`ParliamentPublicFindingCertificateBindingV1`. Context-free validation rejects
zero or non-increasing assignment ids and requires
`endorsing_assignments.len == endorsements == quorum`.
After a self-absence or endorsement, Core derives `eligible = original roster
- authenticated absences` and `remaining = eligible - immutable endorsements`.
If the strongest existing root plus every remaining seat is below quorum, Core
sets the body to `NoResult` and rejects the governance attempt. Entry into
Reflection freezes an inclusive deadline using
`parliament_public_finding_phase_blocks` (default 3,600). Endorsements after it
are rejected, as are new absence declarations after Reflection has opened.
Once the current height is greater than that deadline, any submitter may
trigger payload-minimal `FailPublicFindingNoResult`; Core derives
`DeadlineExpired`, sets the body to `NoResult`, and rejects the attempt. No
manager may select a winner, though progress assumes an eligible transaction
eventually submits the permissionless deadline trigger.

The timed-OVN and Parliament TLE ballot surface in this and the following
sections describes current source. The
[anonymous-ballot decision](parliament_private_ballot_design.md) retires it; it
is not the release target.

Private jury ballot transitions carry exact canonical timed-OVN registration
or dropout records only from the exact seated authority named by the record.
The registration-close and survivor-freeze transitions carry no caller-selected
registration corpus or survivor subset: Core derives those ordered collections
and their roots from accepted authority-bound records. `FreezeTimedOvnCorpus`
appends the next nonempty contiguous survivor-ordered masked-ballot chunk. Each
payload carries at most 32 exact canonical records; Core derives its starting
offset from committed state, verifies only those new proofs, and advances a
replay-checkable public aggregate and duplicate-ephemeral set. The lifecycle
remains internally corpus-open until the accepted prefix reaches the exact
frozen survivor count; only that terminal chunk seals the corpus and advances
the Parliament reducer to `AwaitingRelease`. Chunks are admitted throughout
`(survivor_freeze_height, commitment_close_height]`, and the actual terminal
completion height is retained while the configured release and opening heights
remain unchanged. Policy validation reserves at least
`max_corpus_entries + 1` registration blocks (one admission-boundary block plus
one maximum-cost registration per block), at least `max_corpus_entries`
survivor-freeze blocks, and at least `ceil(max_corpus_entries / 32)` commitment
blocks. A standard default-genesis block can therefore carry the worst-case
bounded transition traffic and still complete every policy-valid corpus.
Every chunk is permissionless, but the relayer cannot forge, omit, reorder,
overlap, or alter a survivor's ballot: Core derives the exact next offset and
enforces fixed record widths, every one-hot proof, the 32-record chunk cap, the
frozen 1,000-survivor total, exact coverage, and immutable roots. Snapshot
restoration discards trust in the cache: it replays the raw registration and
ballot evidence and rejects any cached mask, prefix aggregate, or duplicate set
that differs. Before
registration close, survivor freeze, or a corpus append, Core checks the
reducer-owned active ballot, lifecycle phase, body binding, predecessor
checkpoint, and containing-height window using bounded scalar state.
Out-of-window and replayed checkpoint traffic therefore fails before proof
work. A prefix still incomplete after the commitment close stays in
`TimedCommitment`, making `CommitmentDeadlineExpired` objectively derivable by
the permissionless no-result transition rather than leaving a stuck ballot.
The frozen schedule also fixes an inclusive opening deadline as
`release_height + opening_phase_blocks` (default 600 blocks).
Release consumes the exact finalized pulse and a public threshold-BLS final
release bound to the dedicated TLE identity, and both release consumption and
result finalization reject after that deadline. Aggregate finalization first
checks the fixed-size public TLE/session/release binding and final threshold
signature before inspecting either corpus. It then verifies the committed
public aggregate/transcript cache, verifies the release again while opening the
aggregate, and mutates only after the bounded tally succeeds. Raw proof replay
is mandatory when a snapshot is restored, so the live cache never replaces the
persisted evidence as consensus truth. Only the aggregate tally is opened;
there is no instruction variant for a plaintext ballot, individual opening,
manual release, or fallback electorate.

`FailBallotNoResult` carries only the ballot attempt id. Core derives the
eligible failure class and evidence commitment from persisted phase state and
current height; the caller cannot select either. In particular, Core derives
release-pulse availability from the authoritative committed
network/session/height pulse lookup. The timed-OVN release slot creates no
consensus pulse demand, and the ballot schedule is not aligned to native pulse
heights. Until timed-OVN is retired
([ballot design](parliament_private_ballot_design.md) section 12.2 step 4), a
ballot opens only if a consensus-native pulse is committed at exactly its
release height; otherwise it ends `ReleasePulseUnavailable` once the chain is
past that height. Core rejects that classification for a slot that holds a
finalized pulse. A ballot still awaiting release or opening after its deadline
produces `OpeningDeadlineExpired`. A retry must use the exact next sequence and fresh
TLE session and cannot exceed the frozen retry limit (default three retries
after the initial attempt; protocol cap 16). `NoResult` on the final permitted
sequence rejects the governance attempt, so an exhausted attempt cannot remain
active without a legal retry.

Core constructs the certificate automatically when the final required result
is accepted and derives `enact_at_height` as the containing block height plus
`gov.min_enactment_delay`. There is no certificate-construction variant in the
public lifecycle transition enum.
At that exact due height, Core's automatic block-start step revalidates the
retained certificate, proposal fingerprint, effect hash, and current
compare-and-set head. Head drift produces `Superseded` without effect. With an
equal head, Core applies the typed effect in a rollback-isolated transaction and
records `Enacted`. If the effect rejects, Core drops that transaction and uses a
fresh transaction to record `ExecutionFailed` with a deterministic failure root
derived from the certificate and due height. A snapshot-skipped index maps exact
enactment heights to certified attempt ids; it is rebuilt from validated attempts
on restore and updated with every attempt transition, so block construction does
not scan historical reducer payloads to discover the current due set.

Certificate construction and all three terminal outcomes are consensus-owned;
none is a manager action or a variant accepted by
`POST /v1/gov/parliament/transitions/draft`. Core represents the terminal result
with the separate, non-submit-able `ParliamentAutomaticExecutionOutcomeV1`
audit payload (`Enacted`, `Superseded`, or `ExecutionFailed`) and its own
domain-separated digest. The authenticated
`GET /v1/gov/parliament/attempts/{governance_attempt_id}` projection exposes
`terminal_height`, `superseding_head`, and `execution_failure_root` alongside
the exact reducer payload so clients can distinguish and independently audit
all three outcomes. One attempt's canonical framed reducer state has an
authoritative 16 MiB V1 protocol ceiling: reducer admission and both strict and
emergency-fast snapshot restore count the exact Norito frame before accepting
it, while Torii retains the same bounded-serialization defense. Each ordered
body-state row also carries nullable
`timed_ovn_progress`. It is absent until that body has an active hidden ballot;
otherwise its exact four fields bind `ballot_attempt_id`, reducer `status`,
`frozen_survivor_count`, and `accepted_ballot_prefix_count`. Both counts are
null before survivor freeze. After freeze the survivor count is positive and
the prefix count is the proof-verified next contiguous corpus offset: zero
before the first chunk, strictly below the survivor count while
`TimedCommitment` remains open, and exactly equal after the corpus seals or the
aggregate releases. A terminal `NoResult`/`Superseded` retry preserves the
progress shape reached before failure. Clients therefore recover the next
offset after restart or an ambiguous submission without receiving participant
identifiers, registration or ballot records, roots, shares, individual
openings, or secrets. The opaque Norito reducer payload remains an audit
artifact; clients do not pretend to recompute its content-derived roots from
this count-only projection.

`GovernanceParliamentLifecycleTransitionApplied` carries the closed transition
kind, an optional `no_result_kind`, and an optional typed
`automatic_outcome`. The ten-variant `ParliamentNoResultKindV1` distinguishes
final sortition retry exhaustion, public-finding quorum impossibility/deadline
expiry, the five phase/release private-ballot failures, and
`ConfirmationJuryCapacityUnavailable`, and proposal-wide randomness-redraw
exhaustion before a required Confirmation draw. Before committing a narrow Policy Jury
approval, Core derives the current eligible citizen snapshot, removes every
sealed Policy Jury member, and requires at least three remaining candidates. A
count below three persists with the verified narrow opening and terminally
rejects the attempt as typed `ConfirmationJuryCapacityUnavailable`; it does not
commit the Policy body binding or append an unfillable Confirmation stage. At
the proposal-wide redraw ceiling, a count of at least three instead persists the
same opening as typed `RandomnessRedrawBudgetExhausted` before the fresh draw is
attempted. Otherwise, the same atomic transition freezes and registers the
disjoint Confirmation snapshot and future pulse request. Its sequence-zero request height must equal the Policy
result height; restore rejects a missing, backdated, or delayed initial request.
Ordinary initial-body and retry request intent remains manager-gated. Core sets
the classification only when the accepted transition
terminalizes sortition or a body without a result; `SortitionRetriesExhausted`
applies before a body instance exists. The
transition digest binds the submitted transition while that separate field
records the Core-derived classification.
Consensus-owned enactment,
supersession, and execution failure instead set `automatic_outcome` and bind
its complete evidence with the automatic-outcome digest. Every other event has
both options unset. Telemetry projects only the bounded kind and failure class
from the committed event and does not turn identifiers or digests into labels.

The public evidence codec contains no threshold secret share. It does not make
network metadata anonymous and does not establish receipt freeness or coercion
resistance. In particular, it does not implement or analyze the anamorphic-
encryption voting construction published at ACM SACMAT in July 2026, so that
research does not transfer a coercion-resistance claim to timed OVN. The
threshold-BLS profile has no proactive share refresh and must be
rotated before cumulative exposure exceeds `f` distinct shares. The official
publication manifest validator is a release-tooling gate, not a runtime feature
switch; no independent audit report or evidence archive is bundled or claimed.
The BLS12-381 threshold release, pairing-based timed-OVN ballot, and classical
beacon are not post-quantum; ML-DSA use elsewhere in Iroha does not change that
claim boundary. The [ballot decision](parliament_private_ballot_design.md)
replaces the threshold release and timed-OVN ballot with a canonical V1
post-quantum membership/nullifier ballot; the classical beacon remains.
The authenticated
`GET /v1/gov/parliament/ballots/{ballot_attempt_id}/release-context` endpoint
returns Core's exact opening authorization as public data, including the full
proof-revalidated DKG transcript needed to verify partials independently. The
app-signed, rate-limited
`POST /v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release` endpoint
accepts no body or caller-selected identity, height, transcript, or participant
seat. It asks the injected runtime signer only after Core authorizes committed
state, discards signer diagnostics, and independently verifies the returned
proof before exposing it. The in-process coordinator canonicalizes a supplied
partial set, combines and final-verifies it, and builds the existing
`FinalizeOpenedBallot` transition for submission through the ordinary
authenticated transaction path; there is no parallel release-mutation route.
The operator CLI adds the bounded network corridor: it accepts at most 31
distinct signer-peer root URLs, permits HTTP only on loopback, and rejects
credentials, paths, queries, and fragments. It validates the primary full
public transcript and identity, requires every peer context to match that
immutable release statement, independently verifies and de-duplicates shares,
rejects conflicting valid shares for one participant, and combines the lowest
canonical threshold. After peer collection it re-fetches the primary context,
requires the statement to remain identical and finalized height not to regress,
revalidates the `Opening` inclusive height window, and final-verifies the
aggregate against that refreshed projection immediately before ordinary
operator-signed submission. Peer failures may be tolerated only while an exact
valid threshold remains; there is no plaintext or manual-release fallback.

Software deployments may inject the non-enumerable multi-session custody
registry. It validates imported zeroizing scalar components against the exact
committed public transcript, selects only the context's key session, and drops
retired shares only after the session is no longer consensus-selectable and the
committed height is strictly past the maximum opening deadline across every
referencing ballot and retry. Consensus stores every admitted public session
with its exact ordered `PeerId` roster, a certified-head pointer, and separate
V1 lifecycle metadata containing activation, expiry, inclusive cutover, and
fresh-ballot use bounds. Admission and restore require a bijection among all
three per-session records, reject empty or duplicate-seat rosters, rederive both
committee size and roster hash, and recount use counters from committed ballot
history. An install or rotation committed at `H` retains the predecessor for
new ballots through `H` and activates the successor at `H + 1`; registration
fails closed outside the selected interval or at the use ceiling. Replacement
or explicit retirement retains the public transcript, frozen roster, and
historical lifecycle record for already committed ballots. Validator startup
scans the session selectable at the committed height plus every historical
session whose greatest committed opening deadline has not passed, using an
inclusive deadline boundary. It derives the local one-based seat from
each session's frozen roster rather than the current topology. A seated local
validator must obtain a live, non-signing capability attestation from the same
runtime signer later used for release; the returned key-session id, transcript
hash, and participant index must all match independently. The authenticated
external-provider operation requalifies before and after the lookup and poisons
the session on a substituted result. The active session must additionally match
the exact startup network and topology. This attestation proves only a
point-in-time exact custody lookup, not future availability, hardware backing,
or secure erasure. An opaque Core
authorization can produce one bounded Norito broker projection containing the
complete public transcript and exact fixed release payload, digest, and height
bindings. The broker revalidates those bindings into a nonserializable projected
signer input, but that public projection does not prove committed-state origin;
an operational transport must authenticate and scope the daemon, and the daemon
must independently verify the returned share. This is not an OS-custody,
hardware-backed, secure-erasure, or operational-availability guarantee.
This release path is retired by the ballot decision; its signer, restart and
four-peer collection evidence are no longer release gates. Signer implementation
details are deployment-owned, and neither signer mode permits a plaintext ballot
or manual-release fallback.

The app-signed
`GET /v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context` source path
calls Core's one-view authorization for the pre-seal `Registered`,
`RegistrationClosed`, or `SurvivorsFrozen` lifecycle only. It returns public
session/schedule/TLE transcript/registration material and, only after survivor
freeze, the public survivor hashes and release identity. Core accepts the read
only when its finalized height `H` lies in the exact reducer window:
`registered_at <= H < registration_close`,
`registration_close <= H < survivor_freeze`, or
`survivor_freeze <= H < commitment_close`, respectively. A persisted schedule
that is not strictly increasing through the release height is rejected. Compact
snapshot construction reads a snapshot-skipped
`BallotAttemptId -> ParliamentTimedOvnCastingCandidateV1` index derived from the
active hidden-ballot reducer state. Each row carries the exact governance
attempt and one of those half-open phase windows; attempt replacement and
restore rebuild keep it exact. Core filters the window before point lookups,
then rejects a missing or cross-bound attempt/evidence row instead of scanning
all historical timed-OVN evidence.
The response also
carries the sole padded-standard-base64 encoding of the canonical
`ParliamentTimedOvnCastingContextArchiveV1`, whose complete header-framed Norito
encoding is bounded at 4,194,304 bytes. The archive's public validator replays
the TLE transcript, exact timed-OVN session, registration proofs, phase/option
coherence, and frozen prepared attempt. It contains no registration secret,
keystore seed, dropout set, masked ballot, release share, or opening. This
source surface does not make the archive a ledger authorization and is not yet
workspace-qualified. Deadlines are not duplicated into the V1 archive, so its
independent validator proves the recorded point-in-time snapshot rather than
freshness at a later height. A client must refresh an aged archive; every ledger
mutation independently rechecks current lifecycle and height. The public archive
is therefore diagnostic material, not wallet authorization. Wallets instead use
the app-signed
`/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof` response and exact
ABI 23 proof-only native entry points. Every call supplies an immutable trust
anchor containing a raw 32-byte network ID, nonzero trusted checkpoint height,
exact 32-byte checkpoint height-context ID, and exact expected ballot-attempt ID;
there are no defaults or process-global network values. The proof-page native
entry point canonical-decodes and authenticates every page without reading the
keystore seed. An intermediate page must strictly advance the checkpoint,
contain no casting state, and returns only its authenticated height, context id,
and `more_available = 1` for durable promotion. A terminal page may leave the
height unchanged, but must contain the fixed casting witness and membership
proof; the verifier replay-validates the embedded Core archive, rederives its
compact binding, and requires exact binding equality. Seed-bearing registration
and ballot entry points accept terminal pages only, so intermediate pages can
never authorize secret access.
Archive-only C and JNI wallet exports have been removed so an untrusted public
archive cannot remain a callable authorization path. The builders then derive
purpose-, session-, participant-, survivor-, release-, and choice-separated
randomness from the exact 32-byte caller-keystore seed, regenerate and compare
the committed registration, and return only public registration or masked-ballot
bytes.

The Swift, Android Kotlin, and delegating Java Android APIs snapshot all mutable
anchor and proof inputs and require the immutable trust anchor explicitly.
Android Kotlin keeps the seed behind a generation-bound opaque handle, persists
only an AES-GCM envelope protected by a non-exportable AndroidKeyStore key,
rejects stale handles after delete/recreate under the per-alias lock, zeroes each
borrowed seed after one JNI operation, and returns only fixed-width public
records. Focused Kotlin, isolated Java, JavaScript, static native-contract, and
Swift parse checks cover legitimate proofs plus malformed, fake-chain,
wrong-network, wrong-context, wrong-ballot, intermediate-page, and archive-binding
tampering. These checks are not native artifact execution. These timed-OVN
wallet entry points are retired by the ballot decision rather than qualified;
the packaged ABI-21 XCFramework is intentionally not relabeled. No OS-backed erasure of caller or
cryptographic-library temporaries is claimed.

- POST `/v1/gov/proposals/deploy-contract`
  - Request (JSON):
    {
      "contract_alias": "router::universal"?,
      "contract_address": "irohac1..."?,
      "code_hash": "…64-lowercase-hex",
      "abi_hash": "…64-lowercase-hex",
      "abi_version": 1,
      "manifest_provenance": { "signer": "ed0120…", "signature": "…" }?
    }
  - Response (JSON):
    { "proposal_id": "…64-lowercase-hex", "tx_instructions": [{ "wire_id": "…", "payload_hex": "…" }] }
  - Validation:
    - exactly one of `contract_address` or `contract_alias` must be provided;
    - aliases resolve to the current active canonical contract address before the proposal id is derived;
    - `code_hash` and `abi_hash` are exact typed Blake2b-32 values encoded as
      64 lowercase hexadecimal digits without a scheme or `0x` prefix;
    - only the numeric value `abi_version = 1` is accepted, and `abi_hash`
      must equal the canonical ABI hash for that version
      (`hex::encode(ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1))`).
      Referendum windows and voting modes are not request fields; the certificate
      lifecycle and enactment height are consensus-derived.
  - Submission model: this endpoint is draft-only. Its strict request schema
    contains neither authority nor private-key material; clients consume
    `tx_instructions`, sign locally, and submit via
    `/v1/pipeline/transactions`.

Contracts API (locally signed deployment)
- Torii does not expose a server-side deployment endpoint and never accepts a
  deployment private key.
- Clients upload/finalize bytecode, register a locally signed manifest, and
  submit `CommitContractDeployment` through the standard transaction pipeline.
- Client tooling records the result as `DeployContractBundleReceiptDto`: its
  `contracts[]` entries preserve the per-contract address, hashes, nonce, and
  outcome instead of flattening a multi-contract deployment into one response.
- The commit instruction atomically checks the expected deployment nonce and
  previous alias target before activation or rotation.
- Related reads:
  - GET `/v1/contracts/artifacts/{dataspace_id}/{code_hash}` → stored manifest
  - GET `/v1/contracts/artifacts/{dataspace_id}/{code_hash}/bytes` → `{ network_id, artifact_id, code_b64 }`

Alias Service
- POST `/v1/aliases/resolve`
  - Request: { "alias": "merchant@paynet" }
  - Response: { "alias": "merchant@paynet", "account_id": "<i105-account-id>", "index": 12, "source": "on_chain" }
  - Notes: This is an exact public mapping, not a search endpoint. The request must contain the canonical fully-qualified alias. Torii routes through the alias dataspace, independently rate-limits the route, and accepts unsigned requests. If canonical-signature headers are supplied they must verify; invalid or partial signing headers never downgrade to anonymous access. Returns `404` for an unknown exact alias and `503` when its authoritative route cannot be reached.
- POST `/v1/aliases/resolve-index`
  - Request: { "index": 0 }
  - Response: { "index": 0, "alias": "merchant@paynet", "account_id": "<i105-account-id>", "source": "fanout" }
  - Notes: Canonical request signing is required. Because the index alone does not encode a dataspace, Torii fans this lookup out across the signed caller's visible dataspace routes, dedupes identical results, and returns `source = "fanout"` when the response comes from multi-route merging. Returns `409 route_conflict` if multiple dataspaces return incompatible bindings, `401 alias_auth_required` for missing signing, `403` for partial/invalid supplied signing or inaccessible routes, `404` when reachable routes miss, and `503` when no route can be reached.
- POST `/v1/aliases/by-account`
  - Request: { "account_id": "<i105-account-id>", "dataspace": "paynet"?, "domain": "merchant"?" }
  - Response: { "account_id": "<i105-account-id>", "total": 2, "items": [{ "alias": "merchant@paynet", "dataspace": "paynet", "domain": null, "is_primary": false }], "source": "fanout" }
  - Notes: This is the exact public reverse mapping for one canonical I105 account, not prefix/index enumeration. Torii queries the target account's routes, merges and deterministically sorts at most 64 deduplicated public alias rows, and recomputes `total`. The route is independently rate limited and accepts unsigned requests; supplied canonical-signature headers must verify. Returns `404` when the exact account has no reachable alias result, `409` for conflicting account roots, and `503` when no route can be reached.

Code Size Cap
- Custom parameter: `max_contract_code_bytes` (JSON u64)
  - Controls the maximum allowed size (in bytes) for on-chain contract code storage.
  - Default: 16 MiB. Nodes reject `RegisterSmartContractBytes` when the `.to` image length exceeds the cap with an invariant violation error.
  - Operators can adjust by submitting `SetParameter(Custom)` with `id = "max_contract_code_bytes"` and a numeric payload.

- POST `/v1/gov/ballots/plain`
  - Request: { "authority": "<i105-account-id>", "network_id": "hash:<64-uppercase-hex>#<CRC16>", "referendum_id": "r1", "owner": "<i105-account-id>", "amount": "1000", "duration_blocks": "6000", "direction": "Aye|Nay|Abstain" }
  - Success (`200`): { "drafted": true, "tx_instructions": [{…}] }
  - Invalid requests return the standard Torii `ErrorEnvelope` with HTTP `400`;
    a failed draft never returns a successful response with an embedded rejection.
  - Scope: standalone referenda only. This route builds
    `CastPlainBallot`; it does not cast a Parliament body ballot and its tally
    cannot authorize a typed proposal or be embedded in
    `GovernanceCertificateV1`.
  - Notes: This route drafts an initial cast only. A second `CastPlainBallot`
    is rejected; the explicit `UpdatePlainConviction` instruction increases
    an existing bond or extends its lock without carrying a new choice. Its
    `owner` must equal the transaction authority.
    Minimum duration is `conviction_step_blocks`, and the resulting lock must
    remain active through the referendum's inclusive `h_end`.
    Both conviction parameters are non-zero, and one standalone PLAIN
    referendum retains at most 1,000 voter locks; conviction updates do not
    consume another slot. This bounds the exact pre-admission tally scan.
    Context identifiers use the canonical first-release governance selector
    grammar: 1–128 RFC 3986 unreserved ASCII bytes without a leading dot.
    `amount` uses the same
    canonical Kotodama V1 `Quantity` grammar as ZK lock hints, while
    `duration_blocks` is a canonical decimal string in `0..=u64::MAX`.
    Torii verifies a canonical exact-network account signature over the bounded
    raw body before JSON decoding, requires its account to equal `authority`,
    and rejects redirects/replays. The first-release request has no alternate
    chain-selector fields.

- POST `/v1/gov/finalize` and POST `/v1/gov/enact` are absent and are not
  registered. Parliament derives its terminal result, constructs its
  certificate, and executes the bound proposal at the exact due block height;
  no client-supplied finalization or enactment instruction exists.

- `ContractLifecycleGovernance` action tag
  `CompleteEmergencyHoldRetrospective` is the only transition that removes a
  retained emergency hold. Its strict payload is
  `hold_proposal_content_id`, `hold_governance_attempt_id`,
  `incident_digest`, and `retrospective_finding_root`, each exactly 32 bytes;
  the finding root must be non-zero. This action is append-only Norito variant
  index `5`. Admission and exact-due certificate execution both require the
  first three fields to equal the stored hold and require the containing height
  to have reached the hold's exclusive `expires_at_height`. Enactment clears
  only that hold, increments the lifecycle revision, and emits
  `EmergencyHoldRetrospectiveCompleted` with the complete prior hold, finding
  root, revision, and post-state. There is no direct clear instruction or
  expired-hold garbage-collection path; a later independent emergency hold is
  admissible only after this certified retrospective completes.

- GET `/v1/gov/proposals/{id}`
  - Path `{id}`: exact lowercase proposal id hex (64 chars); `0x`, uppercase,
    whitespace, and control-character aliases are rejected before lookup.
  - Response: `{ "found": bool, "proposal": { "proposer": "<i105-account-id>",
    "kind": { "kind": "<ProposalKind>", "payload": { … } },
    "created_height": <u64>, "status": "<ProposalStatus>" }? }`.
  - The stored proposal record has exactly those four fields. The closed
    first-release statuses are `Proposed`, `Rejected`, `Enacted`, `Superseded`,
    and `ExecutionFailed`; `Approved` is not a status. `ProposalKind` is closed
    over `DeployContract`, `RuntimeUpgrade`, `SccpRouteGovernance`,
    `ValidationFeePolicy`, `ValidationFeePayoutLifecycle`,
    `MusubiRegistryGovernance`, `SorafsProviderGovernance`,
    `ContractLifecycleGovernance`, `ContractEmergencyHold`,
    and `GlobalDataTriggerPermissionGovernance`.
    Unknown fields, unknown tags,
    externally tagged legacy kinds, and retired proposal
    pipeline/snapshot/finalization fields are rejected rather than projected.
    Every proposal-owned `u64` emitted as a JSON number, plus
    `created_height`, is bounded by `9,007,199,254,740,991` at draft,
    admission, storage, and restore. Fields whose canonical JSON layout is a
    decimal string retain the full `u64` range.

- GET `/v1/gov/locks/{rid}`
  - Path `{rid}`: exact non-empty referendum token; whitespace and control
    characters are rejected rather than trimmed or treated as a cache-miss.
  - Response: { "found": bool, "referendum_id": "rid", "locks": { … }? }

- GET `/v1/gov/referenda/{id}` and GET `/v1/gov/tally/{id}`
  - Path `{id}` follows the same exact non-empty referendum-token grammar as
    the locks endpoint. Noncanonical variants fail before state lookup.
  - These are standalone referendum projections. A finalized tally is projected
    from its retained finalization evidence, so later lock expiry cannot change
    the result. Live/post-window PLAIN tallies use the same inclusive `h_end`
    eligibility boundary as consensus, and finalized ZK projections include
    the optional abstain slot. None is a Parliament certificate projection.
  - A selector that is exactly a stored typed-proposal fingerprint is rejected
    in lower-, upper-, or mixed-case hexadecimal form, with or without `0x` or
    `0X`; typed-proposal admission and restore enforce the inverse collision
    guard across standalone referenda, locks, slashes, and elections.
    Standalone closure emits `ReferendumDecided` under the original selector and
    produces referendum/lock/tally stream updates only, never a typed
    `ProposalUpdated` identity.
  - PLAIN directions are the closed numeric set `0 = Aye`, `1 = Nay`, and
    `2 = Abstain`. Core uses checked category and turnout accumulation and an
    exact wide threshold comparison. `min_turnout` counts all three categories,
    but approval is measured over `Aye + Nay`; an empty decisive tally rejects.
    Restored locks are rejected if their owner/key, direction, integer amount,
    or configured aggregate tally is invalid.
  - A standalone ZK referendum that reaches `h_end + 1` without a finalized
    tally becomes durably `Closed` without a decision. A subsequently verified
    tally emits the deferred `ReferendumDecided` once; replay is rejected by the
    finalized election state. If tally finalization happens first, normal
    closure emits the same event instead.

- POST `/v1/gov/parliament/ballots` is retired and is not registered. Parliament
  jury participation uses only the canonical Parliament attempt lifecycle above
  (timed-OVN in current source, retired by the ballot decision);
  Torii does not translate an equal public stage ballot into that protocol.

### Governance defaults (iroha_config `gov.*`)

Governance execution is parameterised via `iroha_config`:

```toml
[gov]
  min_enactment_delay = 20
  parliament_sortition_pulse_delay_blocks = 4
  parliament_invitation_phase_blocks = 3600
  parliament_public_finding_phase_blocks = 3600
  parliament_alternate_size = 21
  citizenship_asset_id = "79jULkZVMgnbzxBe6NvqeDxVEeEk"
  citizenship_bond_amount = "10000"

  # Standalone referendum settings; not Parliament ballot inputs. The ballot
  # and tally verifying keys are not configuration: each election commits its
  # own (`CreateElection.vk_ballot` / `vk_tally`).
  plain_voting_enabled = true
  conviction_step_blocks = 100
  max_conviction = 6
  approval_threshold_q_num = 1
  approval_threshold_q_den = 2
  min_turnout = 0
  voting_asset_id = "61CtjvNd9T3THAR65GsMVHr82Bjc"         # governance bond asset (Sora Nexus default)
  min_bond_amount = "150"              # exact Quantity of voting_asset_id
  bond_escrow_account = "<i105-account-id>"
  slash_receiver_account = "<i105-account-id>"
  slash_double_vote_bps = 0            # percentage (basis points) to slash on double-vote attempts
  slash_invalid_proof_bps = 0          # percentage (basis points) to slash on invalid ballot proofs
  slash_ineligible_proof_bps = 0       # percentage (basis points) to slash on stale/invalid eligibility proofs

[gov.parliament_timed_ovn]
  registration_phase_blocks = 3600
  survivor_freeze_phase_blocks = 1000
  commitment_phase_blocks = 3600
  release_delay_blocks = 600
  opening_phase_blocks = 600
  max_ballot_retries = 3
  max_corpus_entries = 1000

[gov.parliament_tle_key_lifecycle]
  session_lifetime_blocks = 37600
  max_fresh_ballots_per_session = 1
```

`registration_phase_blocks` must be at least `max_corpus_entries + 1`,
`survivor_freeze_phase_blocks` must be at least `max_corpus_entries`, and
`commitment_phase_blocks` must be at least
`ceil(max_corpus_entries / 32)`. The corpus bound must cover both configured
jury sizes and must itself be at least the canonical V1 hidden-ballot floor of
three. Policy and Confirmation targets, candidate snapshots, sealed rosters,
frozen survivors, accepted ballot corpora, openings, and exact tallies must all
meet that same floor. Configuration, reducer admission, restored state, and
certificate validation fail closed when any window cannot carry its maximum
bounded work.
Every active hidden ballot also reserves its closed registration-through-
commitment and release-through-opening windows globally. A new or restored
ballot whose reservation intersects another nonterminal ballot is rejected, so
nominally valid per-ballot schedules cannot oversubscribe consensus transition
capacity.

`parliament_tle_key_lifecycle` is also consensus-critical and has no
environment-variable overrides. Both values must be non-zero. The lifetime is
an inclusive finalized-height span beginning at mandatory next-height
activation; the use limit counts first-time committed ballot registrations,
not later transitions or idempotent replay. The conservative V1 default
requires a fresh certified DKG session for each fresh ballot.

Governance monetary parameters are canonical non-negative `Quantity` values. TOML
uses their exact decimal string form (for example `"150"` or `"0.5"`), so the
configured asset precision is explicit and no host integer width or implicit
"smallest unit" convention is involved.

Standalone referendum ballots lock `min_bond_amount` of `voting_asset_id` into
the configured escrow account. Locks are created or extended when those ballots
land and released on expiry; their bond lifecycle is emitted via
`governance_bond_events_total` telemetry. Timed-OVN Parliament ballots instead
use the sealed body roster and immutable original-seat quorum denominator; they
do not derive weight from a public conviction lock.

Attempt sortition freezes its own complete eligible-citizen snapshot and one
future pulse slot: the first consensus-native pulse height at or above
`request_height + parliament_sortition_pulse_delay_blocks` and above every
earlier generation slot of the attempt. It does not reuse any standing roster.
The delay is a minimum lead. It is consensus-hashed, nonzero and frozen into
the attempt together with the NPoS epoch length, and the slot is rechecked from
those frozen fields with overflow rejection at admission and restore.
`parliament_invitation_phase_blocks` fixes the response window;
`parliament_public_finding_phase_blocks` independently fixes the endorsement
window from entry into Reflection. Both are nonzero and have no environment
override. The five timed-OVN height spans plus retry/corpus limits in
`parliament_timed_ovn` fields are frozen into every ballot attempt and validated
again after persistence restore. Every duration is nonzero, the retry limit is
at most 16, and the corpus limit is in `1..=1000`. Extra bond above
`citizenship_bond_amount` adds neither draw tickets nor vote weight.

Standalone referendum VK verification has no bypass: those ZK ballots require an
`Active` inline verifying key. Parliament timed-OVN proof verification likewise
has no runtime bypass or environment-variable feature switch, but uses its
fixed intrinsic proof profile rather than `vk_ballot`/`vk_tally`.

RBAC
- On-chain execution requires permissions:
  - Attempt creation, risk/qualification intent, sortition-request registration,
    body-phase intent, ballot creation, and timed-OVN corpus upload: exact unit
    `CanManageParliament`.
  - Sortition-pulse consumption, invitation-window start, objective election
    failure, and canonical roster sealing are permissionless liveness triggers.
    Their payloads contain no caller-selected draw, window, failure class,
    assignment list, roster root, or body id.
  - Invitation response: the authenticated authority must be the exact invited
    primary or alternate; member and assignment ids are Core-derived.
  - Attempt absence and public-finding endorsement: the authenticated authority
    must own the exact seated assignment affected by the transition.
  - Timed-OVN registration: the authenticated authority must be the exact
    seated member whose attempt-bound participant hash is in the record.
  - Dropout: the authenticated authority must be the exact registered seated
    member being removed, and only before survivor freeze.
  - Registration close, survivor freeze, release-pulse consumption, objective
    ballot failure, and aggregate finalization are permissionless liveness
    triggers. Core accepts them only when their exact persisted height, corpus,
    pulse, proof, and state bindings match.
  - The containing finalized block supplies transition height/order. Manager
    authority does not let a caller select roots, results, failure classes,
    execution height, or a compare-and-set head.
  - Certificate-only proposal creation and standalone governance operations:
    - Proposals: `CanProposeContractDeployment{ contract_address }`
    - Runtime-upgrade proposals: `CanProposeRuntimeUpgrade{ abi_version, abi_hash }`
    - SCCP proposals: a registered citizen or `CanProposeSccpRouteGovernance`
    - Global data-trigger permission proposals: a registered bonded citizen
    - Standalone ballots: `CanSubmitGovernanceBallot{ referendum_id }`
    - Slashing/appeals: `CanSlashGovernanceLock{ referendum_id }`, `CanRestituteGovernanceLock{ referendum_id }`
    - Remaining managed Parliament and standalone ZK-election transitions:
      `CanManageParliament`
- Scoped governance capabilities are bootstrapped by genesis and thereafter
  delegable only by an existing holder of the exact same scope. In particular,
  direct native ISIs require the exact encoded target (not only the permission
  name). `CanEnactGovernance`, where required by separately governed contract
  or privacy operations, is not a grant root for proposal scopes and cannot
  submit or accelerate a Parliament terminal outcome.
- Automatic certificate execution carries no caller authority or enactment
  permission. Core validates the complete retained certificate, exact due
  height, proposal effect, and compare-and-set head before applying it.
- The fail-safe Initial executor admits the public native proposal, ballot,
  slashing, and restitution instructions only because Core
  enforces those exact scopes before mutation. The lower-level
  `zk::SubmitBallot` vendor instruction is not part of that signed native
  surface: an IVM host must first consume the one-shot
  `ZK_VOTE_VERIFY_BALLOT` latch before enqueueing it, and Core rechecks its exact
  ballot scope as defense in depth.
- Slashing/appeals:
  - Double-vote/invalid/ineligible ballots apply configured slash percentages against the bond escrow, moving funds into `slash_receiver_account`, updating the slashing ledger, and emitting typed `LockSlashed` events (reason + destination + note).
    Both ballot instructions must be the sole direct instruction in their
    signed transaction; nested and mixed carriers fail closed. The ballot
    retains its ordinary instruction-error result. When the rejected overlay
    prevalidated a nonzero slash, Core applies the exact amount in a fresh block
    rejection transaction before rejected-fee settlement, so `LockSlashed` and
    `BallotRejected` persist even if fee settlement later fails; no
    `BallotAccepted` event is emitted. Rejected proof attempts retain their
    block operation/verifier/proof-byte and gas charges across live and prepared
    overlay execution, and sealed reveals replay-protect both the carrier and
    enclosed signed transaction identities in ordinary and autonomous-merge
    admission. Transaction reads resolve either identity to the canonical outer
    carrier.
  - Manual `SlashGovernanceLock`/`RestituteGovernanceLock` instructions support operator-driven penalties and appeals; restitution is capped by recorded slashes, restores funds to the bond escrow, updates the ledger, and emits `LockRestituted` while keeping the lock active until expiry.

Protected Namespaces
- Custom parameter `gov_protected_namespaces` (JSON array of strings) enables admission gating for deploys into listed namespaces.
- Each namespace is an exact non-empty printable-ASCII token (`[!-~]+`). Torii
  rejects whitespace, control characters, non-ASCII text, and unknown request
  fields; it never trims or silently drops an entry.
- Clients must include transaction metadata key `gov_contract_address` for deploys targeting protected namespaces.
- `gov_manifest_approvers`: optional JSON array of <i105-account-id> account IDs. When a lane manifest declares a quorum greater than one, admission requires the transaction authority plus the listed accounts to satisfy the manifest quorum.
- Telemetry exposes holistic admission counters via `governance_manifest_admission_total{result}` so operators can distinguish successful admits from `missing_manifest`, `non_<i105-account-id>_authority`, `quorum_rejected`, `protected_namespace_rejected`, and `runtime_hook_rejected` paths.
- Telemetry surfaces the enforcement path via `governance_manifest_quorum_total{outcome}` (values `satisfied` / `rejected`) so operators can audit missing approvals.
- Lanes enforce the namespace allowlist published in their manifests. Any transaction that sets `gov_contract_address` must resolve into a protected dataspace alias present in the manifest's `protected_namespaces` set. `RegisterSmartContractCode` submissions without this metadata are rejected when protection is enabled.
- Admission enforces that an Enacted governance proposal exists for the tuple `(contract_address, code_hash, abi_hash)`; otherwise validation fails with a NotPermitted error.

Runtime Upgrade Hooks
- Lane manifests may declare `hooks.runtime_upgrade` to gate runtime upgrade instructions (`ProposeRuntimeUpgrade`, `ActivateRuntimeUpgrade`, `CancelRuntimeUpgrade`).
- The first-release manifest schema is closed. `runtime_upgrade` is the only
  accepted hook name, its object accepts exactly the fields below, and any
  unknown top-level, validator-binding, overlay, module, hook, or hook-field
  key rejects the manifest.
- Hook fields:
  - `allow` (bool, default `true`): when `false`, all runtime-upgrade instructions are rejected.
  - `require_metadata` (bool, default `false`): require the transaction metadata entry specified by `metadata_key`.
  - `metadata_key` (string): metadata name enforced by the hook. Defaults to `gov_upgrade_id` when metadata is required or an allowlist is present.
  - `allowed_ids` (array of strings): optional allowlist of metadata values (after trimming). Rejects when the provided value is not listed.
- When the hook is present, queue admission enforces the metadata policy before the transaction enters the queue. Missing metadata, blank values, or values outside the allowlist produce a deterministic `NotPermitted` error.
- Telemetry tracks enforcement outcomes via `governance_manifest_hook_total{hook="runtime_upgrade", outcome="allowed|rejected"}`.
- Transactions satisfying the hook must include metadata `gov_upgrade_id=<value>` (or the manifest-defined key) alongside any <i105-account-id> approvals required by the manifest quorum.

Convenience Endpoint
- POST `/v1/gov/protected-namespaces` — applies `gov_protected_namespaces` directly on the node.
  - Request: { "namespaces": ["apps", "system"] }
  - Response: { "ok": true, "applied": 1 }
  - Notes: The closed request accepts only `namespaces` and optional
    `authority`; it contains no signing secret. Intended for admin/testing and
    requires an API token if configured. For production, prefer submitting a
    signed transaction with `SetParameter(Custom)`.

CLI Helpers
- Both standalone ballot modes take `authority` and the exact canonical
  `network_id` from the client configuration and authenticate that request
  through the configured account signer. Public-input files cannot override
  either identity or introduce alternate chain selectors.
- `iroha --output-format text app gov deploy audit --contract-address irohac1...`
  - Fetches the active binding for the governed contract address and cross-checks that:
    - Torii stores bytecode for the active `code_hash`, and its canonical
      `contract_code_hash` matches: the domain-separated Blake2b-32 digest
      covers the complete deployable artifact, including its execution header.
    - The manifest stored under `/v1/contracts/artifacts/{dataspace_id}/{code_hash}` reports matching `code_hash` and `abi_hash` values.
    - An enacted governance proposal exists for `(contract_address, code_hash, abi_hash)` as derived by the same proposal-id hashing the node uses.
- `iroha app gov deploy meta --contract-address irohac1... [--approver <i105-account-id> --approver <i105-account-id>]`
  - Emits the JSON metadata skeleton used when submitting deployments into protected namespaces, including `gov_contract_address` and optional `gov_manifest_approvers` for satisfying manifest quorum rules.
- `iroha app gov vote --mode zk --referendum-id <id> --backend <tag> --envelope-b64 <b64> [--owner <i105-account-id> --nullifier <32-byte-hex> --amount <Quantity> --duration-blocks <u64> --direction <Aye|Nay|Abstain>]`
  - Submits the canonical flat ZK V1 envelope for a standalone
    referendum. It does not submit a Parliament timed-OVN ballot. It validates canonical
    I105 account ids, canonicalizes 32-byte nullifier hints, and merges the
    closed optional hint set from `--public <path>` into the request.
  - The nullifier is derived from the proof commitment (public input) plus `domain_tag`, exact `network_id`, and `election_id`; `--nullifier` is validated against the proof when supplied.
  - The one-line summary now surfaces a deterministic `fingerprint=<hex>` derived from the encoded `CastZkBallot` along with any decoded hints (`owner`, `amount`, `duration_blocks`, `direction` when provided).
  - CLI responses annotate `tx_instructions[]` with `payload_fingerprint_hex` plus decoded fields so downstream tooling can verify the skeleton without reimplementing Norito decoding.
  - When any lock hint is provided, ZK ballots must supply `owner`, `amount`, and `duration_blocks`; partial hints are rejected. When `min_bond_amount > 0`, lock hints are required. Direction remains optional and is treated as a hint only.
- `iroha app gov vote --mode plain --referendum-id <id> --owner <i105-account-id> --amount <Quantity> --duration-blocks <u64> --direction <Aye|Nay|Abstain>`
  - Standalone referendum helper only. `--owner` accepts canonical I105
    literals; pass domain context through the surrounding scoped interface when
    required.
  - Summary output mirrors `vote --mode zk` by including the encoded instruction fingerprint and human-readable ballot fields (`owner`, `amount`, `duration_blocks`, `direction`), providing quick confirmation before signing the skeleton.

Governed Contract Lookup
- GET `/v1/gov/contracts/{contract_address}` — returns the retained revisioned lifecycle for a canonical contract address, including inactive addresses.
  - `found` reports whether the address has ever been deployed; `active` reports whether `lifecycle.active_code_hash_hex` is present.
  - Found responses expose immutable deployment origin, current and pending owner, revocable Parliament delegation, lifecycle revision, active-code hash, retained emergency-hold evidence, and whether that hold is active at the queried height. Expiry makes the hold inactive but does not erase it; the record remains visible until its exact certified retrospective clears it.
  - Artifact-only `code_hash_hex`, `abi_hash_hex`, and `public_entrypoints` are present only while the address is active and the authenticated artifact cross-check succeeds.

Unlock Sweep (Operator/Audit)
- GET `/v1/gov/unlocks/stats`
  - Response: { "height_current": H, "expired_locks_now": n, "referenda_with_expired": m, "last_sweep_height": S }
  - Notes: `height_current` is the committed ledger height captured atomically with the persisted audit cells; `last_sweep_height` is the most recent successful non-empty due-lock sweep, while the bounded count fields are the persisted result of the most recent attempted due-lock sweep (or zero before any attempt), and this endpoint never scans lock history.
- POST `/v1/gov/ballots/zk-v1`
  - Scope: standalone ZK referendum ballot; not a Parliament timed-OVN
    ballot or certificate input.
  - Request (v1-style DTO):
    {
      "authority": "<i105-account-id>",
      "network_id": "hash:<64-uppercase-hex>#<CRC16>",
      "election_id": "ref-1",
      "backend": "halo2/ipa",
      "envelope_b64": "AAECAwQ=",
      "root_hint": "0x…64hex?",
      "owner": "i105…",          // canonical AccountId (domainless encoded literal; no @domain suffix)
      "amount": "100?",
      "duration_blocks": 6000?,
      "direction": "Aye|Nay|Abstain?",
      "nullifier": "blake2b32:…64hex?"
    }
  - Success (`200`): { "drafted": true, "tx_instructions": [{…}] }
  - Invalid requests return the standard Torii `ErrorEnvelope` with HTTP `400`.
  - Notes:
    - `network_id` is the mandatory typed canonical hash of the genesis header.
      `authority`, `election_id`, and `backend` are exact non-empty tokens;
      whitespace/control variants are rejected rather than trimmed.
      `envelope_b64` must be canonical, non-empty standard base64.
    - The bounded raw request is exact-network account-authenticated before DTO
      decoding; the authenticated account must equal `authority`. The request
      has no alternate chain selectors or label-based signature format.
    - `amount` is an exact canonical non-negative Kotodama V1 `Quantity`
      string. Fractional values through scale 28 are supported; JSON numbers,
      signed/trimmed spellings, leading zeroes, and redundant fractional zeroes
      are rejected. `duration_blocks` spans the complete `u64` domain.
    - When any lock hint is provided, the ballot must supply `owner`,
      `amount`, and `duration_blocks`; partial hints are rejected. Unknown
      fields and private-key aliases fail before a draft is constructed. A
      supplied owner must be the same canonical account as `authority`.
    - ZK re-votes are monotonic: attempts to shrink amount or expiry are
      rejected with `BallotRejected` diagnostics.
    - Contract execution must call `ZK_VOTE_VERIFY_BALLOT` before enqueuing
      `SubmitBallot`; hosts enforce a one-shot latch.

- POST `/v1/gov/ballots/zk-v1/ballot-proof`
  - Accepts a `BallotProof` JSON directly and returns a `CastZkBallot` skeleton.
  - Request:
    {
      "authority": "<i105-account-id>",
      "network_id": "hash:<64-uppercase-hex>#<CRC16>",
      "election_id": "ref-1",
      "ballot": {
        "backend": "halo2/ipa",
        "envelope_bytes": "AAECAwQ=",   // base64 of ZK1 or H2* container
        "root_hint": null,                // optional 32-byte hex string (eligibility root)
        "owner": null,                    // optional canonical AccountId (domainless encoded literal; no @domain suffix)
        "nullifier": null,                // optional 32-byte hex string (nullifier hint)
        "amount": "100",                  // optional lock amount hint (decimal string)
        "duration_blocks": 6000,          // optional lock duration hint
        "direction": "Aye"                // optional direction hint
      }
    }
  - Response:
    {
      "drafted": true,
      "tx_instructions": [
        { "wire_id": "CastZkBallot", "payload_hex": "…" }
      ]
    }
  - Notes:
    - The strict request has no private-key field; Torii returns only an
      unsigned instruction skeleton for local signing.
    - Invalid ballot fields return the standard Torii `ErrorEnvelope` with
      HTTP `400`; `drafted: true` is emitted only when the skeleton exists.
    - A supplied ballot owner must equal the authenticated request authority;
      Torii rejects mismatches before returning a skeleton.
    - The server maps optional `root_hint`/`owner`/`amount`/`duration_blocks`/`direction`/`nullifier` from the ballot to `public_inputs_json` for `CastZkBallot`.
    - The envelope bytes are re-encoded as base64 for the instruction payload.
    - This endpoint is part of every V1 app API build.

Standalone `CastZkBallot` Verification Path
- `CastZkBallot` decodes the supplied base64 proof and rejects empty or malformed payloads (`BallotRejected` with `invalid or empty proof`).
- If `public_inputs_json` is supplied, it must be a JSON object; non-object payloads are rejected.
- The host resolves the ballot verifying key from the election's own committed `vk_ballot` (there is no node-configured default; an election that commits none is rejected with `election commits no ballot verifying key`) and requires the record to exist, be `Active`, and carry inline bytes.
- Stored verifying-key bytes are re-hashed with `hash_vk`; any commitment mismatch aborts execution before verification to guard against tampered registry entries (`BallotRejected` with `verifying key commitment mismatch`).
- Proof bytes are dispatched to the registered backend via `zk::verify_backend`; invalid transcripts surface as `BallotRejected` with `invalid proof`. The instruction fails deterministically; when it applied a configured nonzero slash, the block rejection corridor commits the exact penalty separately from the failed ballot and subsequent fee settlement.
- The proof must expose a ballot commitment and eligibility root as public inputs; the root must match the election’s `eligible_root`, and the derived nullifier must match any provided hint.
- Successful proofs emit `BallotAccepted`; duplicate nullifiers, stale eligibility roots, or lock regressions continue to produce the existing rejection reasons described earlier in this document.

## Validator Misbehaviour & Joint Consensus

### Slashing and Jailing Workflow

Consensus records only exact Sumeragi-v2 equivocation proofs. Each `Evidence`
contains the immutable height context, roster-ordered BLS proofs of possession,
and two complete signed proposals, phase votes, or timeout votes that conflict
for one consensus slot. A node may retain a validated proof locally while it is
pending, but it becomes penalty-eligible only after canonical admission by a
prior committed block. Retired global-v1 offence enums and summary payloads are
not a first-release archive format and fail decode.

Governed `SumeragiNposParameters.reconfig.evidence_horizon_blocks` (default
`7200` blocks) bounds accepted record age; `activation_lag_blocks` and
`slashing_delay_blocks` in the same on-chain record delay enactment. No
instruction cancels a consensus-evidence penalty. These are governed chain
values, not local `[sumeragi]` configuration. The first-release evidence
horizon, slashing delay, and epoch length become immutable after their initial
signed installation; horizon plus delay cannot exceed three epochs, so the
bounded WSV table can always retain four complete validator rosters.

Legacy VRF participation records and penalty effects are retired; production
derives no VRF jail action. Automatic delayed slashing applies only to canonical
Sumeragi-v2 equivocation evidence admitted by a prior committed block, and only
after the `slashing_delay_blocks` window.

Operators and tooling can inspect the bounded audit projection through:

- Torii: exact-`NetworkId` operator-signed `GET /v1/sumeragi/evidence` and
  `GET /v1/sumeragi/evidence/count`.
- CLI: `iroha --operator-private-key-file /absolute/runtime/operator.key ops sumeragi evidence list`
  and `… evidence count`. Torii and the CLI expose no evidence mutation or
  re-broadcast command; admission remains on the authenticated consensus-peer
  path.

Governance must treat the evidence bytes as canonical proof:

1. **Collect the payload** before it ages out. Archive the raw Norito bytes alongside height/view metadata.
2. **Stage the penalty** by embedding the payload in a referendum or sudo instruction (e.g., `Unregister::peer`). Execution re-validates the payload; malformed nor stale evidence is rejected deterministically.
3. **Schedule the follow-up topology** so the offending <i105-account-id> cannot immediately rejoin. Commit the governed successor-mode and activation-height record with the updated roster; do not attempt to express the transition through local Sumeragi configuration.
4. **Audit results** via `/v1/sumeragi/evidence` and `/v1/sumeragi/status` to ensure the evidence counter advanced and governance enacted the removal.

### Joint-Consensus Sequencing

Joint consensus guarantees that the outgoing <i105-account-id> set finalises the boundary block before the new set starts proposing. The runtime enforces the rule via paired parameters:

- The governed `next_mode` and `mode_activation_height` staging fields must be committed in the **same block**. `mode_activation_height` must be strictly greater than the block height that carried the update, providing at least one-block lag. An incomplete pair is rejected with `mode_activation_height requires next_mode to be set in the same block`.
- Governed `SumeragiNposParameters.reconfig.activation_lag_blocks` (default `1`) prevents zero-lag hand-offs.
- Governed `SumeragiNposParameters.reconfig.slashing_delay_blocks` (default `3600`) delays consensus slashing; no instruction cancels a consensus-evidence penalty.

```rust
use iroha_config::parameters::defaults::sumeragi::npos::RECONFIG_ACTIVATION_LAG_BLOCKS;
assert_eq!(RECONFIG_ACTIVATION_LAG_BLOCKS, 1);
```

- The runtime and CLI expose staged parameters through `/v1/sumeragi/params` and `iroha sumeragi params --summary`, so operators can confirm activation heights and <i105-account-id> rosters.
- Governance automation should always:
  1. Finalise the evidence-backed removal (or reinstatement) decision.
  2. Queue a follow-up reconfiguration with `mode_activation_height = h_current + activation_lag_blocks`.
  3. Monitor `/v1/sumeragi/status` until `effective_consensus_mode` flips at the expected height.

Any script that rotates <i105-account-id>s or applies slashing **must not** attempt zero-lag activation or omit the hand-off parameters; such transactions are rejected and leave the network in the previous mode.

## Telemetry surfaces

- Prometheus metrics export governance activity:
  - `governance_parliament_transitions_total{transition}` counts accepted
    Parliament transitions using the closed transition-kind vocabulary.
  - `governance_parliament_no_result_total{class}` counts the ten bounded
    sortition/public-finding/private-ballot `ParliamentNoResultKindV1` classes
    only.
  - `governance_parliament_attempts_by_status{status}` and
    `governance_parliament_attempts_by_stage{stage}` are recomputed from
    committed state at startup and after accepted attempt mutations. These
    families have no identifier, root, account, registration, ballot, share,
    or opening labels.
  - A sortition request legitimately waits for its native pulse slot: up to
    `delay + epoch_length_blocks - 1` blocks when no earlier generation slot
    of the attempt lies at or above `request_height + delay`, otherwise until
    the next boundary after that slot (one further epoch), and without bound
    in wall time on an idle chain. No transition is counted during that wait, so
    `SoraParliamentActiveAttemptStalled`
    (`dashboards/alerts/sora_parliament_rules.yml`: an active attempt with no
    transition for 45 minutes) can fire on a healthy attempt.
  - `governance_proposals_status{status}` (gauge) tracks proposal counts by status.
  - `governance_protected_namespace_total{outcome}` (counter) increments when protected namespace admission allows or rejects a deploy.
  - `governance_manifest_activations_total{event}` (counter) records manifest insertions (`event="manifest_inserted"`) and namespace bindings (`event="instance_bound"`).
- `/status` includes a `governance` object mirroring the proposal counts, reporting protected namespace totals, and listing recent manifest activations (namespace, contract id, code/ABI hash, block height, activation timestamp). Operators can poll this field to confirm that enactments updated manifests and that protected namespace gates are enforced.
- A Grafana template (`specs/grafana_governance_constraints.json`) and the
  telemetry runbook in `telemetry.md` show how to wire alarms for stuck
  proposals, missing manifest activations, or unexpected protected-namespace
  rejections during runtime upgrades.
