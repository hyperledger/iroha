# Parliament ballot design: anonymous on-chain voting

Status: owner decision of 2026-10-05, superseding the 2026-10-04 requirements
that sought hidden vote values without any custodian. The construction is
selected; it is neither implemented nor qualified. Binding Parliament
governance, and every mainnet capability that depends on it, remains no-go until
the proof profile, lifecycle and evidence in this document are qualified.
Source baseline: `22b4689e6b`.

[governance_pipeline.md](governance_pipeline.md) inventories the timed-OVN and
Parliament TLE implementation still in source. This document specifies its
replacement. The first release has one canonical V1 ballot: retire timed-OVN,
the Parliament TLE and their schemas, workers, configuration and clients
together. Do not introduce a V2, dual operation, compatibility decoders, an
old-ballot fallback or a migration prerequisite.

## 1. Decisions

The owner has decided:

- **No ballot custodian.** The protocol neither requires nor distributes any
  voter's credential secret, or equivalent impersonation, opening or recovery
  material, to any other party: validator, trustee, juror, relayer, coordinator,
  prover or time-lock holder. Renaming such material a share, recovery
  credential, mask or MPC state does not change this. Public inference,
  voluntary credential disclosure and endpoint compromise remain possible
  (section 4).
- **Validators only produce blocks.** In the ballot process they provide no
  secret custody, opening or tally service. Ordinary block execution verifies
  ballots, maintains the public counts and derives the result. Validators need
  not generate any ballot or outcome proof. Their existing threshold-beacon duty
  for sortition is not a ballot role (section 9).
- **Binding juries vote on chain.** Citizens seated by sortition on the Policy
  and Confirmation juries cast anonymous ballots that are written into blocks.
- **Votes are public; the ballot carries no voter identity.** Every vote value,
  the exact counts and the running tally are public. A ballot carries no account
  identifier. Its zero-knowledge authorization proves that some sealed seat cast
  it without revealing which. Choices and participation can still be inferred
  from the public record, auxiliary knowledge, credential disclosure or network
  metadata (section 4).
- **Outcomes are provable from block data.** Anyone can recompute the tally and
  check it against the authenticated board without any secret.
- **Membership is variable.** A sealed jury may have only a few seats. The
  configured targets (Policy 500, Confirmation 1,000) are caps, not minimums.
- **Enrollment stays bond-only.** The electorate consists of bonded accounts,
  with no claim of one person per account.
- **Public-finding bodies are unchanged.** They keep authority-authenticated,
  account-signed findings.

Outside the ballot claim: receipt freeness, coercion resistance,
one-human-one-account, protection of a compromised voter device, and network
anonymity beyond the transport requirements in section 6.

## 2. Why votes are public

No known construction meets the previous hidden-vote requirements under the
allowed standard post-quantum assumptions: no custodian, accepted voters free to
disappear, and only the decision published. The counterfactual attack applies
whenever an adversary can obtain everything needed to evaluate alternative
corpora:

- **Prefixes, with no corrupt juror, under the ordinary policy tier.** Take
  `S = M = 4`, `Q = 3`. The honest casting orders `Aye, Aye, Nay, Nay` and
  `Aye, Nay, Nay, Aye` both reject. Their legal three-ballot prefixes give
  `Approve` and `Reject`.
- **Substitution, with one corrupt juror at `S = 3`.** Re-running the decision
  with the corrupt juror's ballot switched from Aye to Nay separates honest votes
  `Aye, Aye` from `Aye, Nay`, although the authorized outputs are identical.

This does not establish impossibility for every cryptographically gated
architecture. No qualifying custody-free construction has been established, and
the owner rejected validator custody and every other custodian. The design
therefore publishes votes and keeps account identity out of the ballot.

## 3. Construction

### 3.1 Notation

| Symbol | Meaning |
| --- | --- |
| `S` | Sealed seats of the binding body; frozen at seal, at least 3 |
| `M` | Accepted ballots in the frozen corpus |
| `A`, `N`, `X` | Public Aye, Nay and Abstain counts, `A + N + X = M` |
| `Q` | Quorum, `ceil(2*S/3)` |
| `sk` | A voter's credential master secret, generated on the voter's device |
| `C` | Credential commitment registered for one seat |
| `R` | Credential root of the sealed body |
| `body_context` | `(network_id, governance_attempt_id, election_attempt_id, body_role)` |
| `scope` | Nullifier scope of the body's ballot |
| `nf` | Nullifier of one credential in one scope |
| `policy_hash` | Fingerprint of the immutable policy snapshot frozen on the governance attempt |
| `s0` | Casting-open anchor: finalized block height, canonical position of the opening transition in the block-start pass, and block timestamp |
| `casting_window_ms` | Committed casting duration |
| `P`, `profile_id` | The single V1 proof profile and its constant identifier |

`body_context` contains only identifiers that exist when seats are accepted. It
excludes `BodyInstanceId`, which is derived at seal. `policy_hash` covers the
risk tier, body role, casting parameters (section 3.10), floors and
`profile_id`. It cannot change during an attempt.

V1 has exactly one proof profile `P`, compiled into every node. `profile_id` is a
constant domain tag, and a ballot whose `profile_id` differs is invalid.
Changing the profile is a new protocol release, not a state transition.

`P` fixes every hash, PRF, field, in-relation encoding, tree and proof
parameter, and instantiates these abstract functions under the gate in
section 5:

```text
C       = CredentialCommit_P(PARLIAMENT_CREDENTIAL_V1, body_context, sk)
nf      = NullifierPRF_P(sk, scope)
R       = CredentialRoot_P(sorted real leaves, S, profile_id)
pi_reg  = Possession_P(sk; C, m_reg)
pi_vote = Ballot_P(sk, i, path; m)
```

`sk` is one high-entropy secret. Derived secrets are domain-separated
derivations of `sk`, and each relation constrains all of them. An unconstrained
second secret would permit repeated voting. The possession proof and the ballot
proof use distinct transcript domain tags.

### 3.2 Credential registration at seat acceptance

For a binding-jury body, `RecordInvitationResponse` with `Accept` carries the
credential commitment `C` and a possession proof `pi_reg`. Acceptance for a
binding body is invalid without them. Core derives the member and assignment
from the transaction authority, as it does today (`record_invitation_response`
in `crates/iroha_core/src/governance/parliament/reducer_sortition.rs`).

- **Possession proof.** `pi_reg` is a post-quantum, simulation-extractable,
  zero-knowledge signature of knowledge of `sk` opening `C`, under the message
  `m_reg = (network_id, authority, assignment_id, election_attempt_id,
  body_role, C)`. Its zero knowledge holds jointly with every later ballot proof
  under the same `sk`. Without it, an invited attacker could copy an honest
  candidate's pending commitment and register it first. Section 5 gates
  `pi_reg` together with the ballot proof.
- **Uniqueness.** One credential per seat. Core rejects a commitment already
  registered for any seat of the same election attempt.
- **Freshness.** Credentials are fresh per body. A Confirmation Jury registers
  its own credentials at its own seat acceptance.
- **Seated set only.** Accepted alternates who are not seated
  (`accepted_roster` truncates to the target) contribute nothing to `R`.
- **No replacement or revocation.** Credentials are immutable after seal and
  are never replaced; no revocation removes a leaf from `R`. There is no
  account-based recovery.
- **Lost credential.** A lost `sk` means that seat cannot vote. If more than
  `S - Q` sealed credentials are lost or withheld, quorum is unreachable and the
  ballot closes `NoQuorum`.
- **Disclosed credential.** A disclosed `sk` lets its holder:
  - cast the seat's ballot first, so the honest holder's later ballot is
    rejected as a duplicate;
  - recompute the nullifier, revealing the seat's participation and vote;
  - hand a briber a receipt.
- **Public mapping.** The account-to-commitment mapping and `pi_reg` are public
  state. Anonymity comes from the ballot proof hiding which commitment was used.
- **Authentication.** Acceptance is authenticated by the account's transaction
  signature. Unless that account uses a post-quantum scheme, seat registration
  is only classically authenticated (section 4).

### 3.3 Credential root at seal

`SealBodyRoster` for a binding body requires `S >= 3`. An accepted roster of one
or two seats is the existing objective `NoRoster`
(`InsufficientHiddenBallotRoster`) and follows the retry generation in
section 10. A binding body therefore never seals below the floor.

At seal:

- Real leaves are the commitments of the sealed assignments, encoded as typed
  real-leaf values and sorted bytewise.
- The tree has 1,024 positions: the body-target ceiling
  `MAX_PARLIAMENT_BODY_TARGET_SEATS_V1` (1,000), rounded up to a power of two.
  Real leaves occupy positions `[0, S)`.
- Every other position holds a deterministic, domain-tagged empty leaf. The
  ballot relation proves `i < S` and a correct real-leaf encoding, so padding
  can never be an eligible credential.

The roster-root preimage is extended to cover `(R, S, profile_id)`.
`BodyInstanceId` derivation and restore validation change with it; there is no
compatibility form. `R` and `S` are also stored in the body state, and bound
into every ballot, closure record and certificate.

### 3.4 Opening, scope and windows

The governance clock is the canonical block timestamp. Under the Sumeragi
block-time rule (`crates/iroha_core/src/block.rs`), a block's time is at least
its parent's time plus the block cadence, and at least the creation time plus
one of every timed input it includes.

- **Ballots are not timed inputs.** Anonymous ballots carry no creation time,
  TTL or account or transaction sequence nonce, so they cannot move the clock.
  The admission stamp's nonce (section 3.6) is permitted.
- **Clock qualification blocker.** The canonical timestamp is a logical clock.
  `max_clock_drift` does not bound ordinary block timestamps against honest wall
  time: block validation enforces wall-clock checks only for genesis and checks
  transaction times relative to the block timestamp, so a Byzantine proposer
  can include a future-dated transaction and advance a deadline. On an idle
  chain the clock can also lag wall time without bound. The governance-clock
  revision must specify, implement and qualify bounds against premature
  opening and closure before activation. Queue admission checks alone cannot
  establish them. The remedy is the Sumeragi application clock guard on Prepare
  votes ([sumeragi.md](sumeragi.md) section 4.5, rules CT1–CT5): an honest
  validator does not vote Prepare on an uncertified block whose canonical time
  exceeds its local wall clock plus `max_clock_drift_ms`, a committed chain
  parameter capped at 60 s. Once qualified, certified time is at most
  `2·max_clock_drift_ms` ahead of an individual honest clock, so a deadline can
  fire up to that much early, but no earlier. Late or delayed transitions
  remain a liveness matter for the due-work transaction. Wallets submit with the
  margin in section 6.
- **No empty blocks.** Due governance work never creates a block by itself.
  Opening and closure run in the block-start pass of the first block produced
  for any transaction whose timestamp reaches the due time. Anyone may submit
  the shared permissionless due-work transaction (`Keepalive`,
  [sccp.md](sccp.md) section 4.7) to cause such a block. It is specified, not
  implemented. Queue admission may accept a ballot for an attempt due to
  open by the node's local clock, and execution rechecks against committed
  state.
- **Opening time.** When the binding body enters its final deliberation phase
  (Reflection) at block timestamp `t_r`, Core records
  `opening_at = max(t_r, sealed_at + vote_notice_ms)`.

Casting opens at the block-start pass of the first block whose timestamp
reaches `opening_at`, subject to the concurrency bound in section 3.6. That
block's height, the opening transition's position in its block-start pass and
the block's timestamp form `s0` (`GovernanceAnchorV1 { height, position,
timestamp_ms }`). Casting is open from the opening pass, so ballots in the
opening block count.

**Stale openings.** Anchors can be older than wall time at commit, because view
changes, a hidden PrepareQC or a halt can delay the commit after the first
honest Prepare ([sumeragi.md](sumeragi.md) section 4.5). So that a stale opening
never shortens voting, closure is anchored to the first block executed after
the opening block, `h_open + 1`, not to `s0`. Closure is due at the first
block-start pass whose timestamp reaches `t(h_open + 1) + casting_window_ms`.
`s0` remains the opening anchor for the lift rule.

Invitation and deliberation windows remain height-based in current source.
Converting them to the millisecond clock belongs to the SCCP-owned governance
clock work.

```text
scope = fingerprint(PARLIAMENT_BALLOT_SCOPE_V1,
                    (network_id, proposal_content_id, governance_attempt_id,
                     body_instance_id))
```

Every component is Core-derived, immutable and canonically encoded:

- `network_id` distinguishes deployments, including reset and genesis
  domains.
- Each body instance has exactly one ballot (there are no ballot retries;
  section 8), so each credential has exactly one scope.
- The scope never includes the vote, the relayer, fee terms, proof randomness
  or any caller-variable value. Otherwise one credential could produce several
  accepted nullifiers.

### 3.5 Anonymous ballot

```text
AnonymousBallotV1 {
    scope:      [u8; 32],
    vote:       Aye | Nay | Abstain,
    nullifier:  NullifierV1,
    profile_id: ProofProfileIdV1,
    stamp:      AdmissionStampV1,
    proof:      bounded bytes,
}
```

The ballot proof is a signature of knowledge over the message:

```text
m = (scope, R, S, nf, vote, policy_hash, profile_id)
```

It proves knowledge of `sk`, an index `i < S` and a path such that:

- the real-leaf encoding of `C = CredentialCommit_P(PARLIAMENT_CREDENTIAL_V1,
  body_context, sk)` sits at position `i` under `R`;
- `nf = NullifierPRF_P(sk, scope)`;
- `vote` is one of the three choices.

The full message is bound. A copied proof cannot carry a different vote, root,
scope, policy or profile. Ballots are identified in queues, APIs and wallets by
`(scope, nf)`, not by transaction hash.

### 3.6 Submission, admission and block validity

No signerless transaction path exists today: every transaction has a
single-key authority (`crates/iroha_core/src/tx/authority_admission.rs`). An
anonymous ballot uses a dedicated entrypoint.

**Entrypoint.** It is signerless and fee-exempt, authorized only by its proof.
It carries exactly one ballot in a header-framed Norito envelope bound to the
chain id, with validity bounded by the casting window. It cannot invoke other
instructions, contracts or triggers, and it references no account, session or
reimbursement identifier.

**Admission cost.** Because admission is signerless, an outsider could flood
verifiers with plausible invalid proofs at negligible cost. Admission therefore
requires an identity-free cost checked before proof verification. The V1
candidate is a hash-based work stamp over a domain-separated digest of the
complete canonical ballot authorization payload, including the proof bytes and
the immutable verification context and excluding the stamp itself. Its
difficulty is committed in policy and frozen per attempt. Verifier queues
prioritize by stamp work. Nodes coalesce identical in-flight payloads and keep
bounded exact-payload verification caches. A stamp does not guarantee fresh
work for every verification invocation; qualification covers replay after cache
eviction and amplification across nodes.

**Queue admission checks, in order:**

1. exact size bound;
2. decode the fixed header (scope, vote, nullifier, profile id, stamp);
3. the scope maps to an attempt with an open (or locally due) casting window;
4. `profile_id` equals the V1 profile;
5. stamp work;
6. nullifier unused in committed state;
7. no verified pending ballot already holds this `(scope, nf)`.

Only after every preceding check passes does the node decode and verify the
proof body.

**Nullifier rules:**

- A nullifier is never reserved or blacklisted before a ballot carrying it
  verifies, so an invalid submission cannot block the legitimate holder.
- Once a verified ballot for `(scope, nf)` is pending, later submissions with
  that `(scope, nf)` are dropped before verification. This defeats floods of
  rerandomized copies.
- A nullifier with no verified pending ballot is never blocked.

**Resource bounds:**

- **Node-local.** Limits on ingress bytes, verifier concurrency, queued work
  and verification rate are isolated from consensus and ordinary transactions.
  Gossip forwards only verified ballots, and caches are bounded.
- **Per block.** Each block admits at most `B_work` verification units and
  `B_bytes` ballot bytes, committed in policy. Verification charges are the
  deterministic worst case, including for malformed proofs. Wall-clock timeouts
  never decide validity.
- **Concurrent attempts.** At most `K` casting attempts are open at once. An
  attempt that falls due while `K` are open opens at the first block-start pass
  with capacity, in order of `(opening_at, governance_attempt_id, body_role)`.
  Its `s0` is taken at that actual opening. Deferral never consumes a retry.
- **Capacity rule.** Parameter validation enforces necessary ballot-packing
  constraints: `casting_window_ms` must admit 1,000 ballots for each of `K`
  concurrent attempts within the per-block budget at the minimum block cadence.
  This is necessary, not sufficient: minimum cadence bounds maximum
  throughput, not inclusion opportunities. Inclusion qualification additionally
  requires explicit post-synchrony bounds on useful block production, delivery,
  execution and scheduling under the stated fault and attacker-load
  assumptions, including clock advancement, unavailable leader views and every
  concurrent casting window.

**Block validation.** Every validator, when validating and executing a block,
verifies each included ballot completely: encoding, scope, open window at that
block's timestamp, `profile_id`, stamp, nullifier unused in committed state, and
proof. A cache may be reused only for byte-identical ballots under the same
`(R, S, policy_hash, profile_id)`.

- **Invalid ballot.** A block that includes a ballot with an invalid encoding,
  stamp or proof is invalid.
- **Valid but late or duplicate.** A ballot with a valid proof that fails only
  the window or nullifier recheck is recorded as rejected and changes nothing.
  This covers a ballot in the closing block and a same-block duplicate.
- **Which ballot wins.** The first otherwise-valid ballot in canonical execution
  order wins its nullifier. Conflicting choices under the same nullifier are
  rejected, and pending-queue order never decides the finalized choice.

**Lane.** Anonymous ballots execute only against the Parliament state of the
global chain. Ordering and nullifier uniqueness are defined on that one serial
state.

**Acceptance.** A ballot is accepted when the block that executed it is
finalized. Queue admission never mutates committed state; speculative effects
follow normal rollback rules. After acceptance the voter may disappear; no
later action, acknowledgement or complaint can revoke it. Any party may relay,
and relaying confers no authority.

**Residual risks:**

- **Saturation.** Sustained floods can still exclude ballots. The admission
  cost raises the price of a flood but does not guarantee inclusion.
- **Selective censorship.** Pending vote values are public, so relayers and
  proposers can drop ballots by their visible vote. The casting window is sized,
  under the inclusion bounds of the capacity rule, to outlast the maximum run of
  consecutive Byzantine leader slots plus inclusion latency. Wallets resubmit
  through several peers until `(scope, nf)` is accepted.
- **Proposal veto.** Exclusion can push turnout below the floor, and a
  turnout failure rejects the governance attempt. Qualification must
  demonstrate a quantified attacker budget at which all honest ballots are still
  included (section 13).

### 3.7 Corpus and closure

Successful canonical block execution of a ballot atomically updates the
nullifier set, the public counters and the corpus. The corpus is ordered by
finalized height, then transaction position, and its root is maintained
incrementally.

Closure runs in the block-start pass of the first block whose timestamp reaches
`t(h_open + 1) + casting_window_ms` (section 3.4):

- It freezes the corpus before that block's transactions execute, so a ballot
  in the closing block is late.
- It derives the outcome deterministically. No result-production service or
  proving step sits between closure and the decision.
- There is no early close, including after quorum or a decisive lead appears.
- There is no ballot replacement and no manager-selected ordering or subset.
- The running tally is public throughout the window.

The quorum, approval, emergency and narrow arithmetic of
`ParliamentAggregateTallyV1` and `validate_ballot_outcome`
(`crates/iroha_data_model/src/governance/types.rs`) is retained. The floor of
three becomes part of the turnout rule instead of a malformed-tally error.
Integers are checked:

```text
Q     = ceil(2*S/3)
floor = max(3, Q)

if M < floor:
    outcome = NoQuorum
else if body == PolicyJury and risk_tier == Emergency:
    outcome = Approved if A > N and A >= Q else Rejected
else:
    outcome = Approved if A > N else Rejected

narrow = outcome == Approved and 100*(A-N) < 5*(A+N)
```

`narrow` is evaluated only for an approval, when `A > N`, so `A - N` cannot
underflow. Abstentions count toward turnout, and a tie rejects. The emergency
threshold applies only to the Policy Jury. Confirmation is required only for an
approved narrow Policy result.

### 3.8 Closure record and certificate

Every closure writes a **closure record** in state. It binds:

- network, proposal, governance attempt, body instance and body role;
- `scope`, `R`, `S`, `profile_id` and `policy_hash`;
- a registration root over the sealed `(assignment_id, C)` pairs;
- `s0` (height, pass position and timestamp), `casting_window_ms` and the
  closure anchor (height and timestamp);
- the corpus root, `M`, `A`, `N`, `X`, the outcome and `narrow`.

The nullifier-set root is derivable from the corpus. If it is bound, it must be
verified for consistency with the corpus.

An approved body produces an immutable result binding that commits its closure
record. A governance certificate is produced only after every attempt-level
prerequisite is met, including the required public findings and any mandatory
disjoint Confirmation approval; each required ballot binding commits the
corresponding closure record. The binding replaces every timed-OVN and TLE
field: `tle_session_id`,
`tle_key_session_id`, the registration, dropout, survivor, corpus, no-recovery
and timed-commitment roots, release slots and pulses, and the opening root. The
result root is redefined over the closure record. Exact counts are public
outputs now, so closure records, certificates, events, queries and SDK
projections carry them.

### 3.9 Outcome evidence

Every evidence artifact declares its mode and starts from a closure record.

| Mode | Inputs | Checks | Still trusts |
| --- | --- | --- | --- |
| Authenticated summary | Closure record (and certificate) with finalized inclusion evidence | Inclusion | Consensus execution of the tally |
| Independent full verification | Authenticated finalized seal and attempt context; closure record; every block from the `s0` height to the closure height; every ballot and proof in them | Frozen parameters; window inclusion; scope, root and profile; every proof; nullifier uniqueness; corpus completeness and order, including re-verified rejections; counts; outcome | Finality and authenticity of the board; registration eligibility and seat assignment, unless the verifier also replays the authenticated eligibility, sortition, invitation, registration and seal history, including account authorization and possession proofs |
| Succinct verification (optional) | A qualified proof of the full-verification relation, bound to the authenticated corpus | As full verification | As full verification |

Independent full verification is the mandatory baseline. It needs no private
witness, because every input is public, but it needs durable availability of
the proof-bearing blocks. A supplied record, root or corpus cannot authenticate
its own completeness.

The succinct mode is an optimization. It must not delay the outcome or create a
failure path.

### 3.10 Parameters

| Parameter | Source |
| --- | --- |
| `vote_notice_ms`, `casting_window_ms` | Genesis or committed governance policy; bound into `policy_hash` |
| `B_work`, `B_bytes` (per-block ballot budget) | Genesis or committed governance policy |
| `K` (maximum concurrently open casting attempts) | Genesis or committed governance policy |
| Admission stamp difficulty | Genesis or committed governance policy |
| Ingress bytes, verifier concurrency, queued work, verification rate | Node-local `iroha_config`, with working defaults |

`B_work`, `B_bytes` and `K` are global chain limits with one authoritative value
at each height, not values selected from competing attempt snapshots. Updates
must preserve existing casting-window capacity commitments. The stamp difficulty
and casting parameters stay frozen per attempt. None of these has an environment
override. `[gov.parliament_timed_ovn]` and
`[gov.parliament_tle_key_lifecycle]` are retired without a successor carrying
their fields.

## 4. Privacy claim and its limits

The claim is stated against an ideal functionality. The adversary may control
any set of sealed credentials, validators, relayers and Torii nodes. The
ballot proofs, nullifiers and possession proofs give that adversary nothing
beyond what the functionality publishes:

- every ballot exposed to the adversary through submission, gossip or
  publication, including pending, rejected and never-finalized ballots: its
  scope, its vote, an opaque per-credential and per-scope handle that preserves
  nullifier equality, and its observable inclusion or rejection status and
  canonical block position where one exists;
- `R`, `S` and the account-to-commitment registrations;
- the closure record and outcome;
- whatever the corrupted credentials themselves know, including their own
  ballots.

The functionality models adversarial delivery and censorship. Handles disclose
nullifier equality, not the mapping from credential to registration; actual
nullifiers and proofs must be simulated consistently with the handles. A
malicious Torii node therefore learns a submitted vote even when it prevents
finalization; that is vote-content exposure, not only metadata. Network
metadata is outside the claim.

**Not hidden by the protocol:**

- **Choices implied by the counts.** A unanimous result reveals every
  participant's choice. At `M = S` every sealed seat participated, and at
  `S = 3` every result that clears the floor of three needs every seat. A
  juror knows their own vote and can infer the others' multiset.
- **Network metadata.** Source address, timing, relayer choice and identifying
  sessions or queries (section 6).
- **A voter's own receipt.** Disclosing `sk` lets anyone recompute the voter's
  nullifier and find their ballot, so a briber can demand it.
- **Multiple seats per actor.** Bond-only citizenship lets one actor hold
  several seats.
- **Cross-attempt inference.** A successor governance attempt seats new bodies
  under fresh scopes, so its nullifiers are not linked to earlier ones.
  Rosters, tallies and timing can still correlate attempts, so the privacy
  analysis covers all attempts jointly.
- **Last-mover strategy.** The running tally is public, so late voters vote
  knowing it.
- **Strategic abstention at `S = 3`.** Each seat is pivotal to the floor and
  can block by not voting after seeing the other two public votes.
- **Vote-selective censorship** (section 3.6).

**Post-quantum scope.** Ballot authorization and anonymity rest on the
post-quantum primitives of `P`. These dependencies remain classical:

- the sortition beacon (threshold BLS), so jury draws carry a classical
  unpredictability assumption;
- consensus finality (BLS);
- the authentication SCCP destinations rely on: secp256k1 bridge attestations
  today, BLS CommitQC verification in the SCCP redesign;
- account signatures authenticating seat acceptance and credential
  registration, unless the citizen account uses a post-quantum scheme (ML-DSA).

These belong to separate migration workstreams.

**Board assumption.** The claim assumes an authentic finalized bulletin board.
Full verification can reject a false outcome relative to that board. It cannot
make a corrupt consensus publish an authentic board or include a ballot.

## 5. Proof-profile qualification gate

The relations stay instantiation-neutral until the single V1 profile is
selected. Evaluate first a hash-based Merkle-membership signature of knowledge,
and compare it with a post-quantum linkable ring signature. A family name is not
a qualification. The profile covers both `pi_reg` and `pi_vote`.

`P` must establish:

1. **Authorization.** Knowledge of a registered credential, real-leaf
   membership with `i < S`, a correct nullifier, a valid choice, and binding of
   the complete message `m`.
2. **Unforgeability.** Quantum chosen-message security despite observed honest
   ballots and adversarial credential registrations.
3. **Nullifier uniqueness.** For a fixed scope and sealed root, let the
   adversary control `k` sealed credentials and obtain honest ballots whose
   nullifiers form the set `H`. Except with negligible probability it cannot
   produce valid ballots with more than `k` distinct nullifiers outside `H`.
   Exclusion is by nullifier, not proof encoding: same-message replay and
   rerandomization are permitted, while authorizing a different message under
   an honest nullifier remains forbidden by item 2. Separately, the nullifier is
   deterministic for a credential and scope, independent of the vote.
4. **Cross-scope unlinkability and non-frameability.** Observing other scopes
   cannot identify or impersonate an honest credential holder.
5. **Full quantum zero knowledge and anonymity.** A multi-theorem definition
   covering the complete transcripts of `pi_reg` and `pi_vote` under the same
   `sk`, adaptive queries, public registrations and corrupt credentials. It
   states exactly which later credential disclosures are excluded.
6. **Concrete security.** At least 128-bit effective post-quantum security,
   including Fiat–Shamir losses, grinding, hash attacks and lifetime
   multi-target use. Statistical soundness error and its accumulation are
   quantified separately. Hash output lengths follow the actual reduction;
   256-bit outputs are not assumed adequate for every role.
7. **Deterministic bounded verification.** Fixed encodings, maximum
   allocations, bounded hash and field work, defined malformed-proof behaviour
   and identical results across hardware.
8. **Registration.** `pi_reg` is a simulation-extractable signature of
   knowledge of `sk` for `C` under `m_reg`, and is zero knowledge jointly with
   every ballot proof.

Multi-theorem QROM simulation-extractability is one sufficient route to
properties 1 and 8. Do not require extraction properties that forbid harmless
same-message rerandomization; section 3.6 handles rerandomized copies. Any QROM
Fiat–Shamir argument must apply to the actual protocol and its reduction.

Initial engineering targets are proposals, not measurements:

| Item | Target |
| --- | ---: |
| Complete ballot proof | ≤ 256 KiB |
| Uncached verification on the pinned minimum validator CPU | ≤ 250 ms |
| Verifier workspace | ≤ 64 MiB |
| Phone proving, supported baseline Android and iOS devices | p95 ≤ 10 s |
| Phone peak prover memory | ≤ 256 MiB |

Measure both proofs at `S = 3`, 500 and 1,000, with cold runs, late-failing
invalid proofs, thermal effects and cancellation. Derive `B_work`, `B_bytes` and
the stamp difficulty from the qualified worst case. A missed target requires an
explicit profile and resource review; limits are never raised silently.

The evaluation of 2026-10-11 is recorded in
[parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md). It
selects no profile: gates 1, 2, 5 and 8 lack an applicable published argument
for every candidate family, and it lists the owner decisions that selection
needs.

Repository reference components are not qualified profiles:

- **PQ-MASP** (`crates/iroha_core_privacy/src/privacy_engines/pq_masp/`)
  proves SHA-256 depth-32 membership with a stable nullifier in a transparent
  Goldilocks STARK. It is unqualified.
- **ZK-ACE** proves an identity commitment and a nullifier, without
  membership.
- **FASTPQ** has only an honest-verifier answer-view argument. Adaptive
  Merkle/Fiat–Shamir simulation and quantum assumptions remain open
  ([fastpq_deep_hiding_construction.md](fastpq_deep_hiding_construction.md)).

## 6. Submission transport and wallet

The wallet submits through an account- and session-free endpoint. For a ballot
it must not use:

- account signatures, authenticated sessions, identifying cookies or tokens,
  or account-specific tracing;
- account-linked reimbursement or reward references;
- leaf-specific roster queries; fetch the whole small roster and build paths
  locally;
- nullifier-keyed status queries from an identifying origin; confirm
  acceptance by downloading the scope's public corpus, or only over a qualified
  anonymity transport;
- creation times, TTLs or account or transaction sequence nonces in the ballot
  (the admission stamp's nonce is permitted);
- silent fallback from an anonymity mode to direct submission.

Keep submission traffic separate from identified registration traffic.
Resubmit through several peers until `(scope, nf)` is accepted, and submit
at least `2·max_clock_drift_ms` plus inclusion latency before the deadline
(section 3.4).

Network-origin hiding needs a qualified anonymity transport. SoraNet is a
candidate, not an assumed guarantee: its relay exit to Torii currently fails
closed (`tools/soranet-relay/src/exit.rs`), and its account-authenticated VPN
product is not unlinkable ballot transport. Until a transport profile is
qualified, release material describes network metadata as unprotected.

Before casting, the wallet tells every voter:

- that choices and running counts are public;
- the roster size `S`;
- that small rosters and unanimous results reveal choices.

It does not present any roster size as an anonymity guarantee.

## 7. Membership, quorum and participation

- **Three quantities.** Eligible citizens, sealed seats `S` and accepted ballots
  `M` are distinct. Neither the validator count nor a body target determines
  `S`. Quorum uses the frozen `S`.
- **Floors.** Sealing requires `S >= 3` (section 3.3). At closure, turnout
  below `max(3, Q)` is `NoQuorum` (section 3.7). A `NoQuorum` outcome does not
  retract ballots already published.
- **Absence.** `RecordAttemptAbsence` is invalid for anonymous binding bodies.
  Non-participation appears only in turnout and never changes `S`, `R` or the
  quorum. Invitation declines before seating remain.
- **Incentives.** V1 has no per-account voting rewards, no no-show penalties
  and no per-account record of binding-jury participation. Bond retention and
  release depend only on draws, seats and attempt state, never on whether or how
  a seat voted. Audit every reward, refund and unlock path for linkage.
- **Public-finding bodies.** They keep account-signed endorsements, their
  absence declarations and their quorum and split-failure rules.
- **Confirmation.** The Confirmation electorate excludes all sealed Policy
  members. Preserve atomic `ConfirmationJuryCapacityUnavailable`; never overlap
  the juries, lower the floor or certify without Confirmation.

## 8. Lifecycle and outcomes

```text
AcceptingInvitations -> Sealed(R, S >= 3) -> Deliberating -> Reflection
    -> AwaitingOpening -> Casting [s0, s0 + casting_window_ms) -> Closed
    -> Approved | Rejected | NoQuorum
AcceptingInvitations -> NoRoster (S < 3 or no roster)     [section 10]
```

There are no ballot retries. A binding body has exactly one ballot, and every
closure outcome is final for that body:

| Situation | Body outcome | Governance attempt | Successor |
| --- | --- | --- | --- |
| Accepted roster `< 3` | `NoRoster` (no seal) | Continues under the section 10 retry generation | Sortition retry consumes the sortition and proposal-wide entropy budgets |
| `M < max(3, Q)` at closure | `NoQuorum` | Rejected | Only a new governance attempt, within existing proposal-wide budgets |
| Quorate, rule not met | `Rejected` | Rejected | Same as above |
| Approved, not narrow (or Confirmation Jury) | `Approved` | Proceeds to certification | — |
| Approved narrow Policy | `Approved`, Confirmation required | Atomic capacity and budget check | Capacity or budget failure is terminal `ConfirmationJuryCapacityUnavailable` |

Successful decisions are immutable. Different but semantically equivalent
proposals remain a potential grinding channel; fingerprints alone do not bound
it. No `Active` attempt may remain after every legal retry is exhausted.

**Block-start ordering.** Each block-start pass completes due ballot closures
before allocating newly free casting slots. It then considers eligible openings,
including previously deferred ones, in `(opening_at, governance_attempt_id,
body_role)` order in that same pass. Each transition's position in the pass is
recorded; section 11's lift rule compares it. [sccp.md](sccp.md) section 4.7
specifies the full pass, the positions of these items relative to other
transitions, and the due-work predicate (`governance_due`), which reads the due
ballot items. The ballot needs exactly these two item kinds.

**Clock rules.** Windows are half-open. Local wall clocks never choose
consensus outcomes. No external transaction must land at exactly one height.
There is no node-local consensus toggle.

## 9. Sortition waits belong to governance

Parliament pulse demand has left consensus.
`iroha_core::sumeragi::epoch_beacon::required` is the NPoS pre-boundary rule
only. No Parliament state can require, veto or invalidate a pulse or a block.
Daemon startup reads no Parliament TLE custody; its global-beacon custody check
stays. The TLE signer slot is deleted with the TLE.

There are two separate paths:

- **Consensus beacon.** Consensus-native epoch and NPoS beacon obligations keep
  their own Sumeragi rules.
- **Parliament sortition.** Parliament sortition is pending governance work. A
  missing Parliament pulse never prevents block production, state replay, node
  startup or an unrelated transaction.

The beacon signing that produces sortition pulses is the validators' existing
consensus-adjacent duty, not a ballot role. Parliament slots are aligned to
consensus-native pulses, so validators do no Parliament-specific work.

A sortition request freezes its eligible snapshot, proposal content, attempt
and election identities, exact sequence, request height and one future logical
pulse slot, computed by checked arithmetic. No relayer, timeout, key rotation,
restart, membership change or manager action can change the slot.

The slot is a consensus-native pulse height. Native pulse heights are those `h`
with `(h + 1) % L == 0`, where `L` is the NPoS `epoch_length_blocks`. The
attempt freezes `L` at creation from the genesis-immutable NPoS policy, beside
its frozen `parliament_sortition_pulse_delay_blocks` `d`, which is a minimum
lead. A request at height `r` takes the first native pulse height at or above
`max(r + d, g + 1)`, where `g` is the highest slot of an earlier generation of
the same attempt. Creating a Parliament attempt on a chain with no NPoS cadence
is rejected with a stable error before anything is stored.

A late pulse is one consumed late. It was committed on time in the block of
its slot and is verified against the key session retained for its own height,
not against the current key pointer. Rotation cannot change a resolved slot.
No pulse for an elapsed slot is produced or carried later.

```text
Requested -> AwaitingExactPulse -> Drawing -> AcceptingInvitations
                                   -> Sealed | ObjectiveRosterFailure
```

`AwaitingExactPulse` can wait indefinitely. An election leaves it only by
consuming the pulse of exactly its slot. No fallback pulse, fresh height,
alternate source, cancellation-and-redraw or unavailable-pulse certificate may
substitute another draw. Pending requests and snapshot bytes are bounded at
admission: 65,536 citizens and 8 MiB snapshots. An indefinitely pending
election can retain candidate bonds; releasing them is a separate
economic-policy change.

Two consequences follow, and one decision is open:

- Sortition latency is height-based. A generation waits up to `d + L - 1`
  blocks when no earlier generation slot of the attempt lies at or above
  `r + d`. Otherwise it takes the next boundary after that slot, one further
  epoch. Each `NoRoster` retry and the Confirmation Jury wait for a further
  boundary. On an idle chain the wait is unbounded in wall time. This bears on
  the section 11 hold rule and on `parliament_sccp_attempt_latency_ms()`.
- Requests that share a pulse, candidate snapshot, body set and sizing
  configuration draw identical panels. Alignment widens that from one block to
  one epoch window.
- Open owner decision: binding the governance attempt id into the draw seed. It
  trades correlated capture for a proposal-multiplicity grinding channel.

## 10. NoRoster, Confirmation and enactment

Retain the liveness contract now in source (`9ab23c1229`):

- The planner derives the complete retry generation for every active
  `NoRoster` body together.
- Core rechecks the snapshot, targets, containing height and remaining budget.
- Persistence validates the successor.
- SCCP retries are permissionless.

Unseated candidates are released after an objective `NoRoster`; sealed members
of other bodies keep their attempt-local obligations.

Confirmation admission is atomic with accepting the Policy result. Retain
`narrow_policy_at_randomness_redraw_ceiling_persists_terminal_no_result` as a
regression, including its restore assertions.

Automatic delayed enactment, supersession and rollback-isolated execution
failure remain Core-owned. A standalone referendum cannot authorize a
Parliament proposal.

## 11. SCCP boundary

The owner chose a pause-only fast track on 2026-10-04. [sccp.md](sccp.md)
specifies the SCCP side: the fast pause track and standing panel (section
4.14.7), the governance clock, keepalive and `governance_due` (section 4.7),
and the Parliament dependency, launch gate and trust statement (sections
10.1–10.3). This section fixes what the ballot provides and what it requires of
that side.

**Standing pause panel.** The panel is SCCP-owned and drawn outside governance
attempts and their sortition chains. The ballot requires that:

- it uses the epoch-boundary pulse that consensus already requires and
  registers no Parliament pulse demand;
- if that pulse is missing, the seated panel stays seated;
- it decides by public, account-signed endorsements, which are a public
  finding like other public bodies, not a binding-jury ballot;
- it is pause-only: it cannot transfer value, raise caps, register routes,
  clear faults or authorize permanent policy changes;
- holds lapse by time, with mandatory expiry and head-bound replay checks and
  no re-pause cooldown.

The draw cadence, seat acceptance, reserve, panel size and quorum belong to
`sccp.md` section 4.14.7. A draw cadence other than once per epoch needs owner
confirmation, because this document's owner-committed 2026-10-04 version
recorded once per epoch.

**What the ballot provides to SCCP:**

- the 32-byte `GovernanceCertificateId::derive_v1` and the certificate's
  `effect_preimage_hash`;
- deterministic, rollback-isolated block-start enactment, calling
  `sccp::governance::enact(certificate_id, effect_hash, s0, proposal)`. Here
  `s0` is the `GovernanceAnchorV1` of the approving Policy Jury ballot;
- the recorded block-start position of each ballot opening;
- `parliament_binding_ballot_available()`, false until the section 5 profile is
  qualified and the ballot is active;
- `parliament_sccp_attempt_latency_ms()`: the latency of one full-track SCCP
  attempt, including a single sortition-retry generation, derived from the
  committed windows;
- the citizen-eligibility predicate and the governance draw, for reuse by the
  panel;
- a read-only iterator over due ballot items, for `governance_due`.

The certificate's control leaf binds the track, certificate id and effect hash.
Destinations verify finalized control evidence; they need no Parliament key and
never parse ballot internals.

**Lift rule.** A full-track decision clears pause instance `H` only if:

- `H` is the current head; and
- `H` was enacted at a block-start position strictly before the opening
  transition (`s0`) of the approving Policy Jury ballot, comparing
  `(height, position in pass)`.

Confirmation, outcome evidence and enactment do not move `s0`. A successor
governance attempt has its own `s0`.

**Hold rule.** The ballot has no ballot retries. SCCP requires
`hold_lifetime_ms ≥ parliament_sccp_attempt_latency_ms()`. Longer outages are
covered by renewing the fast pause before it lapses, which has no cooldown.

The standing panel does not make binding ballots ready for mainnet.

## 12. Retirement and implementation order

### 12.1 Retire

**Cryptography and Core:**

- `iroha_core_timed_ovn`, `iroha_crypto::timed_ovn` and `iroha_crypto::tle`.
  Threshold BLS stays for the beacon.
- `iroha_core::tle_release` and its casting, custody, runtime and test-signer
  modules.
- The timed-OVN data model (`parliament_casting`) and the ballot reducer
  phases.
- The transitions `RegisterBallotAttempt`, `RegisterBallotParticipant`,
  `RecordBallotDropout`, `CloseBallotRegistration`, `FreezeBallotSurvivors`,
  `FreezeTimedOvnCorpus`, `BeginBallotOpeningBatch`, `FailBallotNoResult` and
  `FinalizeOpenedBallot`.
- Ballot retries and `MAX_PARLIAMENT_BALLOT_RETRIES_V1`.
- The certificate fields listed in section 3.8.

**Keys, configuration and the daemon:**

- Parliament TLE key sessions and their install and retire certificates.
- The `[gov.parliament_timed_ovn]` and `[gov.parliament_tle_key_lifecycle]`
  configuration.
- The irohad broker signer slot. The custody preflight is already deleted
  (section 12.2 step 1).

**Torii and clients:**

- The casting-context, casting-proof, release-context and partial-release
  routes in Torii and MCP.
- The Torii capability descriptor fields `private_ballot_protocol` and
  `mandatory_private_ballots`, and their OpenAPI entries.
- The CLI `gov parliament ballot` timed-OVN commands.
- The timed-OVN wallet paths in Kotlin, JavaScript, Swift, Python and the FFI,
  with their fixtures and schema captures. Remove the Java duplicates rather
  than migrate them; mark their JVM inventory entries retired.

**Tests, models and release tooling:**

- The shared timed-OVN corridor support in
  `integration_tests/tests/sora_parliament_lifecycle_support.rs`, and the
  corridors that depend on it.
- The formal model's timed-release phases. Its unavailable-pulse branch is
  already removed (section 12.2 step 1).
- The release pipeline's timed-OVN audit inputs
  (`scripts/run_release_pipeline.py`). They are replaced by audit inputs for the
  section 5 relations.

Keep beacon machinery still required for consensus or sortition.

### 12.2 Order

1. **Isolate governance availability.** Split Parliament from native beacon
   demand and the daemon preflight. Prove unrelated transactions and restart
   stay live while an exact pulse is absent. This does not depend on the
   ballot. It is implemented; Core mutation `HC224`
   ([sumeragi.md](sumeragi.md) section 13.4) guards the split.
2. **Qualify the proof profile.** Discharge section 5 and select `P`. Do not
   begin integration around a placeholder relation.
3. **Specify the schemas.** The Norito stored and wire forms are:
   - the credential registration and `pi_reg`;
   - the scope;
   - the signerless ballot envelope;
   - `AnonymousBallotV1` and `AdmissionStampV1`;
   - accepted-record ordering;
   - the closure record and certificate binding;
   - ballot events and queries.

   `P` defines the in-relation leaf, node and padding encodings, with a fixed
   bijection to the Norito form. Anonymous records and events omit account and
   session identifiers.
4. **Build the paths together.** Build in one candidate:
   - registration and the credential root;
   - signerless admission and block validation;
   - corpus, closure, closure record and certificate;
   - the verification modes;
   - Torii, CLI and the canonical SDKs (Kotlin owns JVM and mobile);
   - the wallet disclosure.

   Retire section 12.1 in the same candidate. Introduce no Wasm target.
5. **Model and qualify.** Revise the TLA+ model (section 13), then complete
   proof review, adversarial lifecycle and load tests, real-peer restart and
   rollback, SDK parity and release evidence. Update public documentation in
   `iroha-docs` when implementation claims change.

Hardware acceleration may speed up identical deterministic verification. It
cannot choose a different relation, result, charge or acceptance rule.

## 13. Required validation

These are obligations for the implementation, not tests this document passed.

**Registration and credentials**

| Case | Required observation |
| --- | --- |
| Copied registration commitment or `pi_reg` | Rejected; the honest registrant is unaffected |
| `pi_reg` replayed for another seat, body or account | Rejected |
| Accepted but unseated alternate | Its credential is absent from `R` |
| Accepted roster of 1 or 2 seats | `NoRoster`, then the section 10 retry generation; no seal |
| Credentials lost beyond `S - Q` | `NoQuorum`; no replacement path exists |

**Ballot validity and admission**

| Case | Required observation |
| --- | --- |
| Padded-leaf membership or `i >= S` | Rejected |
| Unconstrained or second nullifier secret | Rejected by the relation |
| Copied proof with changed vote, root, scope, policy or profile | Rejected |
| Ballot replayed into another body's scope | Rejected |
| Unknown or mismatched `profile_id` | Rejected before proof verification |
| Duplicate nullifier, including concurrent and same-block races | Exactly one accepted, the first in canonical order |
| Invalid proof claiming an honest nullifier | Rejected; the honest ballot is later accepted |
| Flood of rerandomized copies of a pending ballot | Dropped before verification |
| Valid stamp reused with altered proof bytes | Stamp verification fails before proof verification |
| Byzantine proposer includes an invalid-proof ballot | Block rejected by every honest validator |
| Invalid-proof and stamp-bearing saturation at a quantified attacker budget, under the stated post-synchrony inclusion bounds | Unrelated transactions progress; all honest ballots are included before closure |

**Clock, closure and outcomes**

| Case | Required observation |
| --- | --- |
| Ballot in the closing block, late ballot, rollback and restore | Late ballot excluded; the corpus survives restore unchanged |
| Byzantine proposer includes a future-dated transaction near opening or the deadline; fast-block clock advancement; idle chain at opening or closure | The qualified governance-clock bounds reject premature opening and closure; no empty block is produced |
| `K` casting attempts open when another falls due; a closure frees a slot in the same pass | Closures run first; the oldest eligible deferred opening opens in that pass; `s0` set at actual opening |
| Omitted, reordered or replayed corpus entry; altered counts or roots | Full verification rejects |
| Outcome arithmetic at boundaries (`S = 3`, ties, emergency `A = Q`, narrow edge, `M = max(3, Q) - 1`) | Exact checked-integer results |
| Strategic abstention at `S = 3` | `NoQuorum`; no ballot retry |
| Voter vanishes after acceptance | The ballot counts; nothing requires the voter |
| `RecordAttemptAbsence` for a binding body | Rejected |
| Narrow result without disjoint Confirmation capacity | Atomic terminal failure with no partial certificate |
| Final roster or entropy retry exhausted | Terminal status survives Norito restore |

**Sortition, SCCP, hardware and wallet**

| Case | Required observation |
| --- | --- |
| Missing Parliament pulse for many heights | Blocks and restart succeed while the request waits for its frozen native slot; no Parliament state creates pulse demand at any height |
| Delayed pulse consumption after beacon rotation | The pulse is verified against the key session retained for its own height; substitution fails |
| Pause and casting open in the same block-start pass; older decision against a newer hold; stale head | Lift rule applied by `(height, position in pass)`; stale or older decisions rejected |
| Pure CPU versus supported acceleration | Identical verification and consensus outputs |
| Wallet anonymity mode | No account, session, leaf-specific or nullifier-keyed request is observable |

**Formal model.** The unavailable-pulse branch is removed and the
governance-local exact-pulse wait is modelled (section 12.2 step 1). Replace
the timed-release phases with:

- credential sealing (`S >= 3`);
- casting open;
- verified unique-nullifier append;
- deterministic closure;
- the terminal outcome.

Preserve immutable quorum, the sortition retry generation, public findings,
disjoint Confirmation, atomic capacity failure and the enactment and rollback
rules. Cryptographic verification is a modelling assumption. The lifecycle
model is not an anonymity proof.

**Consensus changes.** Changes to Sumeragi safety or liveness need named
deterministic simulator regressions and mutations under
[sumeragi.md](sumeragi.md) section 13. Real-peer tests use a legal `3f+1`
committee with at least four validators; this places no size requirement on
Parliament.

Primitive references do not qualify their composition:
[SHA-3 / SHAKE](https://csrc.nist.gov/pubs/fips/202/final),
[KMAC](https://csrc.nist.gov/pubs/sp/800/185/final),
[zero knowledge for STARKs](https://eprint.iacr.org/2024/1037),
[QROM Fiat–Shamir](https://arxiv.org/abs/1902.07556).
