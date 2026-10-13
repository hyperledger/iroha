# Parliament ballot design: anonymous on-chain voting

Status: owner decision of 2026-10-05, superseding the 2026-10-04 requirements
that sought hidden vote values without any custodian. The ballot design of
section 3 (public votes, anonymous proof-authorized ballots, sealed-list
membership) is decided. No proof profile is selected, the ballot is not
implemented in Core, and nothing is qualified. Binding Parliament governance, and every mainnet
capability that depends on it, remains no-go until the proof profile, lifecycle
and evidence in this document are qualified.
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
  identifier. Its zero-knowledge authorization proof shows that the ballot
  statement is consistent with one sealed credential, without revealing which.
  It does not show who submitted the ballot or that the submitter knows the
  credential (section 5 item 1). Choices and participation can still be
  inferred from the public record, auxiliary knowledge, credential disclosure
  or network metadata (section 4).
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
| `auth` | Registration authorization value published with `C` (section 3.2) |
| `auth_v` | Vote authorization value published in the ballot (section 3.5) |
| `L` | Sealed credential list: the `S` sealed commitments in strictly increasing bytewise order |
| `R` | Sealed-list digest: the digest of the ordered list `L` (section 3.3) |
| `body_context` | `(network_id, governance_attempt_id, election_attempt_id, body_role)` |
| `B` | Body-context digest: the digest of the canonical `body_context` |
| `scope` | Nullifier scope of the body's ballot |
| `nf` | Nullifier of one credential in one scope |
| `policy_hash` | Digest of the immutable policy snapshot frozen on the governance attempt |
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

`P` fixes every hash, PRF, field, domain tag, canonical list and preimage
encoding, digest length and proof parameter, and instantiates these abstract
functions under the gate in section 5:

```text
B       = BodyContextDigest_P(body_context)
C       = CredentialCommit_P(body_context, sk)
auth    = RegistrationAuth_P(sk, D_reg)
nf      = NullifierPRF_P(sk, scope)
auth_v  = VoteAuth_P(sk, D_v)
R       = SealedListDigest_P(B, S, L)
pi_reg  = Registration_P(sk; C, m_reg)
pi_vote = Ballot_P(sk, selector; B, L, m)
```

`sk` is one high-entropy secret. Derived secrets are domain-separated
derivations of `sk`, and each relation constrains all of them. An unconstrained
second secret would permit repeated voting. Fresh proof coins that a profile
carries inside its witness are not credential secrets: no commitment,
authorization value or nullifier depends on them. `D_reg` is the profile's
digest of the registration statement (section 3.2) and `D_v` its digest of
the vote statement (section 3.5). The registration proof and the ballot proof
use distinct transcript domain tags.

**Proof randomness and the counter.** In the construction under development,
each invocation of either prover consumes a proving tape of 112 fresh,
uniformly random bytes, which the wallet supplies from the device's
cryptographic random source. The layout and uses of the tape are defined in
[parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md)
section 6.7 and are not restated here.

- **One tape per invocation.** A tape is never reused and is never derived
  from `sk`, the message or an earlier tape. There is no deterministic
  fallback. Fixed tapes are permitted for reproducible tests only.
- **Counter range.** The prover tries the counters `0` through `0x000fffff`
  (a 20-bit range) in increasing order and never wraps. A proof carries its
  counter as four little-endian bytes.
- **Typed exhaustion.** If no counter in the range succeeds, the prover
  returns the typed outcome `GrindingExhausted` and no proof. The wallet must
  handle it: it invokes the prover again on the unchanged statement with an
  entirely fresh tape. The profile's analysis counts invocations, so an
  exhausted invocation is a fresh proof generation under the per-credential
  ceiling of section 5. The second-opinion review bounds the exhaustion
  probability for the candidate row; for the real prover that bound is
  conditional (profile section 6.7), and the wallet handles the outcome
  whatever its probability.
- **Verification.** A verifier rejects a proof whose counter exceeds
  `0x000fffff` before any reconstruction work, evaluates the supplied counter
  once and does not establish that it is minimal.

The membership contract is fixed and does not depend on the proof backend.
The statement of `pi_vote` is selection of one entry of the sealed ordered
list `L`. Its witness is `sk` and a hidden selector. There is no membership
tree, padding entry or path witness. A verifier of `pi_vote` needs the list,
not only `R` (section 3.5).

### 3.2 Credential registration at seat acceptance

For a binding-jury body, `RecordInvitationResponse` with `Accept` carries the
credential commitment `C`, the public authorization value `auth` and a
registration proof `pi_reg`. Acceptance for a binding body is invalid without
all three. Core derives the member and assignment from the transaction
authority, as it does today (`record_invitation_response`
in `crates/iroha_core/src/governance/parliament/reducer_sortition.rs`).

- **Registration authorization.** `pi_reg` is a message-bound, post-quantum
  registration-authorization proof for
  `C = CredentialCommit_P(body_context, sk)` and
  `auth = RegistrationAuth_P(sk, D_reg)` under the same `sk`. It satisfies
  adaptive multi-user credential-origin unforgeability jointly with ballot
  proving, and is zero knowledge jointly with every ballot proof. Observing an
  honest commitment, authorization value or registration or ballot proofs must
  not authorize a fresh registration message for that uncorrupted credential.
  Core separately enforces registration uniqueness.
  The registration message is `m_reg = (network_id, authority, assignment_id,
  governance_attempt_id, election_attempt_id, body_role, B, C, auth,
  profile_id)`.
  Without `pi_reg`, an invited attacker could copy an honest candidate's
  pending commitment and register it first. Core checks registration
  authority, invitation and assignment eligibility, freshness, uniqueness and
  the sealed subset itself; `pi_reg` does not prove them. Section 5 gates
  `pi_reg` together with the ballot proof. Its item 1 requires soundness of
  the registration statement: a secret that opens `C` and produces `auth`
  exists. It does not require that the registrant knows that secret.
- **Authorization value.** `auth` is a public value of the registration
  statement, 64 bytes in the construction under development and defined in
  [parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md)
  section 6. It binds `sk` to the digest `D_reg` of the complete registration
  statement other than `auth` itself: the profile descriptor, the
  authoritative body context, `network_id`, `authority`, `assignment_id`,
  `governance_attempt_id`, `election_attempt_id`, `body_role`, `B` and `C`.
  `D_reg` excludes the proof bytes and the prover's randomness. The
  statement of `pi_reg` is that one `sk` both opens `C` and produces `auth`,
  and the complete `m_reg`, `auth` included, is bound into the proof
  transcript. A registration whose `auth` does not verify under `pi_reg` is
  invalid. The ballot carries the analogous value `auth_v` (section 3.5).
  `auth` supports the argument for
  section 5 item 8; it does not establish that item. It is not a Core check
  and replaces none: duplicate-commitment rejection and the authority,
  invitation, eligibility and freshness checks are unchanged.
- **Uniqueness.** One credential per seat. Core rejects a commitment already
  registered for any seat of the same election attempt.
- **Freshness.** Credentials are fresh per body. A Confirmation Jury registers
  its own credentials at its own seat acceptance.
- **Seated set only.** Accepted alternates who are not seated
  (`accepted_roster` truncates to the target) are absent from `L` and
  contribute nothing to `R`.
- **No replacement or revocation.** Credentials are immutable after seal and
  are never replaced; no revocation removes an entry from `L`. There is no
  account-based recovery.
- **Lost credential.** A lost `sk` means that seat cannot vote. If more than
  `S - Q` sealed credentials are lost or withheld, quorum is unreachable and the
  ballot closes `NoQuorum`.
- **Disclosed credential.** A disclosed `sk` lets its holder:
  - cast the seat's ballot first, so the honest holder's later ballot is
    rejected as a duplicate;
  - recompute the nullifier and the vote authorization value, revealing the
    seat's participation and vote;
  - hand a briber a receipt.
- **Public mapping.** The account-to-commitment mapping, `auth` and `pi_reg`
  are public state. Anonymity comes from the ballot proof hiding which
  commitment was used.
- **Authentication.** Acceptance is authenticated by the account's transaction
  signature. Unless that account uses a post-quantum scheme, seat registration
  is only classically authenticated (section 4).

### 3.3 Sealed credential list at seal

`SealBodyRoster` for a binding body requires `S >= 3`. An accepted roster of one
or two seats is the existing objective `NoRoster`
(`InsufficientHiddenBallotRoster`) and follows the retry generation in
section 10. A binding body therefore never seals below the floor.

At seal:

- **Ordering.** `L = (C_0, ..., C_(S-1))` is the commitments of the sealed
  assignments in strictly increasing bytewise order. It has exactly `S`
  entries, at most `MAX_PARLIAMENT_BODY_TARGET_SEATS_V1` (1,000). There are no
  padding entries.
- **Duplicates.** Two equal commitments make the ordering non-strict. Sealing
  rejects them, independently of the registration uniqueness check of
  section 3.2.
- **Digest.** `R = SealedListDigest_P(B, S, L)` is a domain-separated digest
  over the profile's construction identifier, `B`, `S` and the concatenated
  commitments. There is no leaf hashing, node hashing or tree.
- **List object.** Core constructs and persists the canonical
  `SealedCredentialListV1 { profile_id, body_context_digest, S,
  commitments[S] }`. The object binds the profile, the body context, the seat
  count and every sealed commitment in order.
- **Publication.** The finalized block data of the seal carries the bytes of
  that object durably. A pointer to a mutable service is not sufficient.
- **Registration mapping.** A separate, domain-separated registration-mapping
  digest covers the sealed `(assignment_id, C)` pairs in a precisely defined
  encoding. It authenticates which assignment registered which commitment. `R`
  authenticates the anonymous membership list. Neither replaces the other.

The roster-root preimage is extended to cover `(R, S, profile_id)`. Through
`R` it binds the list object into the roster root, `BodyInstanceId` and the
sealed state. `BodyInstanceId` derivation and restore validation change with
it; there is no compatibility form. Restore validation decodes the list, checks
its length, strict ordering and uniqueness, recomputes `R` and matches the
restored seal. `R` and `S` are also stored in the body state, and bound into
every ballot, closure record and certificate.

The cost is explicit. The list is `S` commitments of public data, and each
ballot verification does work linear in `S` over it. The list-context object
is capped at 160 KiB, separately from the ballot envelope (section 5).
Verification of a ballot proof against `R` alone is deliberately not provided.

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
scope = ScopeDigest_P(network_id, proposal_content_digest,
                      governance_attempt_id, body_instance_id)
```

`P` fixes the digest, its domain tag and its length. The scope, `policy_hash`
and the proposal-content digest are collision-sensitive, so their lengths
follow section 5 item 6. A collision-sensitive content fingerprint bound here
has that length or is replaced by its canonical preimage; hashing a shorter
fingerprint again does not repair it. An opaque, authenticated state identifier
need not be widened.

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
    scope:      BallotScopeV1,
    vote:       Aye | Nay | Abstain,
    nullifier:  NullifierV1,
    auth_v:     VoteAuthorizationV1,
    profile_id: ProofProfileIdV1,
    stamp:      AdmissionStampV1,
    proof:      bounded bytes,
}
```

The ballot proof is a message-bound proof over the message:

```text
m = (scope, R, S, nf, auth_v, vote, policy_hash, profile_id)
```

`BallotScopeV1` has the scope length fixed by `P` (section 3.4). In the
construction under development `nf` is 128 bytes and `auth_v` is 64 bytes;
both are defined in
[parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md)
section 6. The statement of the proof is that a secret `sk` and exactly one
selector position `i` exist such that:

- `i < S`: the selector selects exactly one position of the sealed list `L`;
  it cannot select no entry, several entries or a position at or beyond `S`;
- the selected entry equals `CredentialCommit_P(body_context, sk)`;
- `nf = NullifierPRF_P(sk, scope)`;
- `auth_v = VoteAuth_P(sk, D_v)`.

All three equations use the same `sk`. Section 5 item 1 requires soundness
for this statement. That is existence: an accepted proof does not show that
the submitter knows `sk`. Public validation, outside the relation, requires
that `vote` is one of the three choices, enforces the exact field lengths and
the complete statement encoding, and recomputes `D_v`.

**Vote authorization value.** `auth_v` binds `sk` to the digest `D_v` of the
complete vote statement other than `auth_v` itself: the profile identifier,
the vote role tag, the profile descriptor digest, `B`, `scope`, `R`, `S`, the
bytes of the sealed list `L`, `nf`, `vote` and `policy_hash`. `D_v` excludes
`auth_v`, the proof bytes and the prover's randomness. No account, authority or selected
position enters it. A verifier recomputes `D_v` from the validated list and
the ballot's fields; a supplied digest is never trusted, and `D_v` is not
carried in the ballot. `auth_v` is not a signature and not an account
identity: it is a public value of the statement. A ballot whose `auth_v` does
not verify under `pi_vote` is invalid. `auth_v` supports the argument for
section 5 item 2; it does not establish that item. It is not a duplicate key: exclusion stays by nullifier
(section 3.6).

**Validated list.** The relation is stated over `L`, so the verifier must hold
the right list. Every verifier of `pi_vote` does one of:

1. decode the `SealedCredentialListV1` bytes, check the length, the strict
   ordering and uniqueness, recompute `R`, and match it and `S` against the
   authenticated seal; or
2. use an immutable verification context that was constructed by those checks
   and is authenticated to that same seal.

An unvalidated caller-supplied list is never sufficient. Binding `R` in `m`
does not connect an arbitrary supplied list to `R`.

The full message is bound, and the proof transcript also binds `B`, the
canonical list bytes and the relation identifier. A copied proof cannot carry
a different vote, nullifier, vote authorization value, list, list digest,
scope, policy or profile. Ballots are
identified in queues, APIs and wallets by `(scope, nf)`, not by transaction
hash.

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
2. decode the fixed header (scope, vote, nullifier, `auth_v`, profile id,
   stamp), each field at its exact length: the nullifier and `auth_v` have
   the lengths fixed by `P` (128 and 64 bytes in the construction under
   development), and any other length is rejected;
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
- `auth_v` keys no admission or duplicate rule. Two ballots under one
  nullifier with different votes are different statements and are still
  excluded by the nullifier.

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
verifies each included ballot completely: encoding and exact field lengths,
scope, open window at that block's timestamp, `profile_id`, stamp, nullifier
unused in committed state, and proof, including the recomputation of `D_v`
that binds `auth_v` to the complete statement. A cache may be reused only for
byte-identical ballots under the same
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
later action, acknowledgement or complaint can revoke it. Any party may relay
an already authorized ballot, including delivering it before its creator
does, and relaying confers no authority: it cannot change any field of the
statement (section 4).

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
nullifier set, the public counters and the corpus. The nullifier set is keyed
by `(scope, nf)`, with the nullifier at the length fixed by `P` (128 bytes in
the construction under development). Each corpus entry carries the ballot's
public fields, `nf` and `auth_v` included, and its proof, so that full
verification (section 3.9) can check every ballot again; `auth_v` keys no
state. The corpus is ordered by finalized height, then transaction position,
and its root is maintained incrementally.

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
- `scope`, `S`, `profile_id` and `policy_hash`;
- `R`, the seal's list digest (section 3.3). The record references the sealed
  list by this digest and does not duplicate the list; no ballot duplicates it
  either;
- the registration-mapping digest over the sealed `(assignment_id, C)` pairs
  (section 3.3): separately defined, domain-separated and 512 bits;
- `s0` (height, pass position and timestamp), `casting_window_ms` and the
  closure anchor (height and timestamp);
- the corpus root, `M`, `A`, `N`, `X`, the outcome and `narrow`.

The record carries no nullifier and no `auth_v`; both are in the corpus
entries. The nullifier-set root is derivable from the corpus. If it is bound,
it must be verified for consistency with the corpus.

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
| Independent full verification | Authenticated finalized seal, the `SealedCredentialListV1` bytes it carries, and attempt context; closure record; every block from the `s0` height to the closure height; every ballot and proof in them | List length, strict ordering, uniqueness and digest against the seal; frozen parameters; window inclusion; scope, list digest and profile; every proof; nullifier uniqueness; corpus completeness and order, including re-verified rejections; counts; outcome | Finality and authenticity of the board; registration eligibility and seat assignment, unless the verifier also replays the authenticated eligibility, sortition, invitation, registration and seal history, including account authorization and registration proofs |
| Succinct verification (optional) | A qualified proof of the full-verification relation, bound to the authenticated corpus | As full verification | As full verification |

Independent full verification is the mandatory baseline. It needs no private
witness, because every input is public, but it needs durable availability of
the proof-bearing blocks and of the seal's list bytes. The seal precedes the
`s0` height, so the ballot-bearing block interval does not contain the list;
the authenticated seal and its list bytes are a separate required input. A
supplied record, list, root or corpus cannot authenticate its own completeness.

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
ballot proofs, nullifiers, vote authorization values and registration proofs
give that adversary nothing beyond what the functionality publishes:

- every ballot exposed to the adversary through submission, gossip or
  publication, including pending, rejected and never-finalized ballots: its
  scope, its vote, an opaque per-credential and per-scope handle that preserves
  nullifier equality, its vote authorization value `auth_v` as released or
  simulated by the functionality (below), and its observable inclusion or
  rejection status and canonical block position where one exists;
- `R`, `S`, the sealed list `L` and the account-to-commitment registrations
  with their authorization values;
- the closure record and outcome;
- whatever the corrupted credentials themselves know, including their own
  ballots.

The functionality models adversarial delivery and censorship. A malicious
Torii node therefore learns a submitted vote even when it prevents
finalization; that is vote-content exposure, not only metadata. Network
metadata is outside the claim.

Handles disclose nullifier equality, not the mapping from credential to
registration; actual nullifiers and proofs must be simulated consistently
with the handles. The public values of a ballot include `auth_v`. The
functionality releases or simulates it consistently with complete-statement
equality and nullifier equality. `auth_v`, the nullifier, the commitment and the registration value
`auth` are functions of the same `sk`, so the claim concerns the joint public
outputs under one secret; hiding the nullifier alone is not sufficient
(section 5 items 4 and 5). The second-opinion review's privacy argument with
`auth_v` among those outputs is written. It is conditional on unproved
assumptions, awaits independent review and establishes nothing yet
(section 5).

**Authorization is not control over delivery.** Anyone may relay an already
authorized ballot, including delivering it before its creator does; the
signerless entrypoint always permitted this. The statement that nobody can
cast for an honest member therefore means that nobody can produce an accepted
ballot with a fresh statement the member's credential did not authorize
(section 5 item 2). It does not mean exclusive control over when, by whom or
whether an authorized ballot is delivered. Censorship, credential disclosure
and a holder who knowingly authorizes conflicting choices keep the limits
stated in sections 3.2 and 3.6.

**Not hidden by the protocol:**

- **Choices implied by the counts.** A unanimous result reveals every
  participant's choice. At `M = S` every sealed seat participated, and at
  `S = 3` every result that clears the floor of three needs every seat. A
  juror knows their own vote and can infer the others' multiset.
- **Network metadata.** Source address, timing, relayer choice and identifying
  sessions or queries (section 6).
- **Linkage at a scope.** Equal nullifiers link ballots at one scope by
  design, including ballots that carry different votes. `auth_v` does not
  conceal that link. Once a credential's nullifier at a scope has been
  identified, no anonymity remains for that credential at that scope.
- **A voter's own receipt.** Disclosing `sk` lets anyone recompute the voter's
  nullifier and vote authorization value and find their ballot, so a briber
  can demand it.
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

The relations stay neutral about the proof backend until the single V1 profile
is selected. The membership contract is not open: it is selection from the
sealed ordered list (sections 3.3 and 3.5). A family name is not a
qualification. The profile covers both `pi_reg` and `pi_vote`.

`P` must establish:

1. **Adaptive relation soundness.** In the common adaptive quantum-oracle
   environment, with authenticated public contexts, malicious registrations,
   permitted corruptions and both honest proof interfaces available, every
   accepted fresh registration or ballot statement belongs to its specified
   language, except with the deployment-wide error bounded under item 6. A
   registration has a secret that opens its commitment and produces its
   registration authorization value. A ballot has a secret and exactly one
   selector position below `S` such that the selected entry of the
   authenticated sealed list is that secret's commitment, and the stated
   nullifier and vote authorization value are the specified functions of that
   same secret. Public validation enforces the permitted choice and the
   complete statement encoding and binding. This is an existence requirement:
   it requires neither efficient witness extraction nor knowledge of the
   secret by the submitter. Exact-statement relaying, replay and proof
   rerandomization remain permitted, subject to admission and duplicate
   checks.

   Item 1 replaces the earlier requirement of knowledge of a registered
   credential. It is a weakening, decided by the second-opinion review, and
   not an equivalent reformulation of knowledge soundness. The system
   therefore does not promise an efficient procedure that recovers a
   credential from an adversary producing a fresh valid proof. The definition
   permits a party to produce a proof of a true statement without knowing its
   witness; an adversarial registrant to establish a credential whose opening
   exists but which it cannot later use; proof transformations that preserve
   an already authorized complete statement; and failure of any future
   protocol that silently treats a ballot or registration proof as proof of
   possession, extractable knowledge or a simulation-extractable credential.
   The last is a composability limitation: a later protocol that needs
   knowledge must prove its own theorem or change the construction, and no
   general non-malleability or universal-composability claim is made. Items
   2, 3 and 8 must carry the authorization guarantees independently. The
   owner's qualification record must state this weakening.

   For the construction under development the second-opinion review has
   written an argument for this item: an adaptive soundness theorem in the
   backend's quantum random-oracle model, with its premises, loss terms and
   query accounting, recorded in
   [parliament_ballot_proof_arguments.md](parliament_ballot_proof_arguments.md)
   section 6.1. It awaits independent review and establishes nothing before
   that review. By its own statement it gives no extraction, no possession
   guarantee and no restriction on proofs of true statements, and it does
   not establish authorization prediction, uniqueness, anonymity, joint zero
   knowledge, security of the concrete SHAKE256 functions or deployment
   readiness.
2. **Unforgeability.** Quantum chosen-message security despite observed honest
   ballots and adversarial credential registrations. The complete authorized
   statement includes `auth_v`.
3. **Nullifier uniqueness.** For a fixed scope and sealed list, let `k` be
   the number of adversarially registered or corrupted sealed entries,
   including entries whose registrant knows no opening, and let the adversary
   obtain honest ballots whose nullifiers form the set `H`. Except with
   negligible probability it cannot
   produce valid ballots with more than `k` distinct nullifiers outside `H`.
   Exclusion is by nullifier, not proof encoding: same-message replay and
   rerandomization are permitted, while authorizing a different message under
   an honest nullifier remains forbidden by item 2. Separately, the nullifier is
   deterministic for a credential and scope, independent of the vote.
4. **Cross-scope unlinkability and non-frameability.** Observing other scopes
   cannot identify or impersonate an honest credential holder. The public
   auxiliary information of both endpoints includes `auth_v`.
5. **Full quantum zero knowledge and anonymity.** Two requirements, each
   with its own game.
   - *Joint zero knowledge.* An adaptive multi-theorem definition covering the
     complete transcripts of `pi_reg` and `pi_vote` under the same `sk`,
     adaptive queries, public registrations with their authorization values,
     public ballots with their vote authorization values, and corrupt
     credentials. It holds for arbitrary application witnesses
     (`sk` for `pi_reg`; `sk` and the selected position for `pi_vote`) and
     arbitrary auxiliary information about them, the witness itself included.
     It is not restricted to honestly generated, undisclosed credentials. The
     honest prover samples the proof's own coins fresh for every proof. Those
     coins are excluded from disclosure, and a prover that accepts
     adversarially fixed or disclosed coins is outside the claim.
   - *Anonymity.* A separate left-or-right game with one hidden bit. A
     challenge names two candidate credentials and the public vote fields,
     and is admissible only if all of these hold:
     - both candidates are honest and uncorrupted and sit in the same body
       and the same authenticated sealed list;
     - neither candidate's nullifier at the challenge scope has been exposed
       by an identified vote or nullifier query, earlier ones included;
     - both candidates become protected against corruption, so later
       disclosure of either is excluded, and both candidate-and-scope pairs
       are blocked against identified disclosure;
     - several challenges show the same nullifier-equality pattern in both
       worlds;
     - the vote authorization entry of each candidate at the digest `D_v`
       of the statement actually returned has never been exposed. The digest
       is computed once, from the returned nullifier; no second digest is
       formed from the other candidate's hidden nullifier;
     - several challenges show the same authorization-equality pattern in
       both worlds, and both candidates' authorization entries at that
       digest are then blocked, including against an interface that would
       disclose them without returning a nullifier;
     - every other observable field, policy outcome, quota and error is
       treated symmetrically for the two candidates, and no identity-labelled
       log of challenge issuance is revealed. A challenge rejected by a late
       check keeps its protections and blocks and exposes no tentative
       value.

     Registration authorization values and vote authorization values at
     other digests stay available to the adversary. The definition states
     exactly these exclusions; zero knowledge alone does not give anonymity,
     because the public commitments, registration authorization values, vote
     authorization values and nullifiers under one `sk` must also be shown
     unlinkable. Both authorization families are part of the correlated
     outputs in these privacy games. One linkage remains by design and is
     outside the claim: equal nullifiers link ballots at a scope, including
     ballots with different votes, and `auth_v` does not conceal it. The
     claim is cross-scope privacy under these exclusions, with no
     retrospective protection after a challenge credential is disclosed.
6. **Concrete security.** A complete proven deployment-wide bound and an
   independently assessed attack cost, as read below, including Fiat–Shamir
   losses, grinding, hash attacks and lifetime multi-target use. Statistical
   soundness error and its accumulation are quantified separately. Hash output
   lengths follow the actual reduction; 256-bit outputs are not assumed
   adequate for every role.
7. **Deterministic bounded verification.** Fixed encodings, maximum
   allocations, bounded hash and field work, defined malformed-proof behaviour
   and identical results across hardware.
8. **Registration authorization.** Establish adaptive multi-user
   credential-origin unforgeability in the QROM against malicious registrations
   and corrupt credentials, with access to both honest proof types. An
   adversary cannot authorize an uncorrupted honest credential under a fresh
   registration message, including recontextualization into another body. The
   registration message is the complete `m_reg` of section 3.2, the
   authorization value included. Joint zero knowledge is required.
   Simulation-extractability is sufficient but is not required by this item.

**The item 8 game.** It must:

1. publish honest commitments before registration, so front-running is
   covered;
2. permit adaptive registration-proof and ballot-proof queries, malicious
   credentials, corruption and quantum oracle access;
3. record the exact messages authorized by honest provers;
4. declare a win on a valid fresh registration message that uses an
   uncorrupted honest credential, including a commitment of that credential
   recontextualized under another body context;
5. exclude exact-message replay and rerandomization from the winning
   condition;
6. keep the target secret uncorrupted through the forgery.

Duplicate rejection prevents reuse after registration. The game protects the
period before the honest registration lands.

Item 8 carries no separate knowledge obligation: item 1 requires soundness,
not extraction. An anti-copy theorem alone is not the `k`-entry bound of
item 3. Simulation-extractability would suffice for items 1 and 8 and is
required by neither. Do not require properties that forbid harmless
same-message rerandomization; section 3.6 handles rerandomized copies. Any
QROM Fiat–Shamir argument must apply to the actual protocol and its
reduction.

**Authorization without extraction.** With item 1 weakened, the
authorization guarantees rest on items 2, 3 and 8, by the second-opinion
review's reductions recorded in
[parliament_ballot_proof_arguments.md](parliament_ballot_proof_arguments.md).
They are conditional and none is established. The owner's qualification
record must state every premise they use. The profile record defines each
premise exactly; in the review's summary wording they are:

- **Assumption P: selective-entry pseudorandomness with public leakage.**
  Selected nullifier and authorization outputs (registration and vote) of
  honest credentials that are protected from corruption are
  indistinguishable from independent random function values. The adversary
  meanwhile holds the real commitment of every credential (commitments are
  never replaced), the real values of every other output of both
  authorization families and of the nullifier, the secrets of adaptively
  corrupted other credentials, both honest proof interfaces answered by the
  common simulator, and all public quantum computation of the concrete
  functions. The advantage is at most a recorded `α_P` at the reduction's
  actual resources. P is stronger and more specific than single-key
  pseudorandom-function security and is not a consequence of generic
  SHAKE256 security. It is an unproved assumption, and its bound is not yet
  supplied.
- **Assumption U: selected-context existential uniqueness.** In every
  context the adversary designates, no two distinct secrets have the same
  commitment and, for a designated scope, no two distinct secrets have the
  same nullifier, except with a recorded probability `δ_U`. The experiment
  is the common environment with real proofs: all preprocessing, adaptive
  context exploration, malicious registrations, both honest proof interfaces
  and permitted corruptions are charged. The adversary need not output, know
  or find either secret. The designated commitment contexts include the
  authenticated seals, the adversarially selected target body context of
  item 8 (a recontextualization that has never been sealed included) and
  every further context the deployment-wide reduction needs. U is an
  existential structural assumption about the fixed
  functions. It does not follow from P, from collision resistance, from
  output length or from secrecy of the openings. It is an unproved
  assumption, and its bound is not yet supplied.
- **Frame collisions.** No two distinct legal authorization frames of the
  registration statement, or of the vote statement, have the same digest
  `D_reg` or `D_v`, except with recorded probabilities `F_R` and `F_V`.
  These are terms for the concrete digest function and have no values yet.
- **Backend oracle model.** The reductions treat the backend's hash
  functions as quantum-accessible random oracles and carry the backend's
  generator terms. The concrete justification of that model and the values
  of those terms are not supplied.

P and U are independent clauses with separate bounds: P does not imply U.

With `s` the item 1 bound, `Z` the joint zero-knowledge bound of item 5,
`ρ` the bound on a repeated honest secret and `g` the blind-guessing terms,
the review's deployment-wide inequalities are:

```text
ε_2 ≤ s       + u_N        + F_V       + Z + α_P + ρ + g_V
ε_3 ≤ s_batch + u_C,seal   + F_V,batch + Z + α_P + ρ + g_batch
ε_8 ≤ s       + u_C,target + F_R       + Z + α_P + ρ + g_R
```

`u_N`, `u_C,seal` and `u_C,target` are the restrictions of `δ_U` to the
designated scopes, the authenticated seals and the registration-origin
targets. `s`, `Z`, `α_P`, the three `u` terms and the frame terms have no
qualified value. Item 3 is argued by counting: outside a false accepted
statement and an ambiguous sealed commitment, each controlled entry explains
at most one nullifier, so more than `k` distinct nullifiers outside `H`
include a ballot whose witness is the secret of an uncorrupted honest entry,
which carries a fresh correct vote authorization value. The argument charges
`Z` and `α_P` once for the batch and uses commitment uniqueness at the seal,
not nullifier uniqueness. `H` must include the nullifiers whose
authorization values were disclosed by proving requests that failed or
exhausted the counter. No algorithm selects or extracts a witness. A batch
has at most 1,001 outputs (`k = S = 1,000` is allowed).

**Reading of item 6.** The security metric and lifetime envelope are:

| Quantity | Requirement |
| --- | ---: |
| Computational break | Forgery success ≥ 1/2, or anonymity distinguishing gap ≥ 1/2 |
| Proven bound | Every required computational game has a complete, applicable deployment-wide bound below 1/2 at an adversary budget of 2^64 quantum queries |
| Scope of the proven bound | Both relations, all lifetime ceilings, concrete primitive terms, and all actual proving, simulation, verification and reduction query and time overhead. No extractor is required, so none is accounted |
| Recorded thresholds | The largest budgets the complete ledger justifies at advantage 2^-64 and at advantage 1/2 |
| Attack cost | Independent cryptanalysis finds no break below 2^128 total elementary gates |
| Attack-cost accounting | Classical and quantum work, preprocessing, memory access (coherent lookup, QRAM construction and use) and all parallel processors; primitive evaluations expanded into circuits; queries, depth and memory reported separately |
| Accounting | Deployment-wide, including reduction overhead and all targets |
| Archive horizon | 100 years per network and profile instance |
| Body scopes | At most 2^24 |
| Sealed seats per body | At most 1,000 |
| Registrations, including alternates | At most 2^34 |
| Honest prover transcripts per credential | At most 2^10, counting fresh proof generations |
| Total registration plus ballot transcripts | At most 2^44 |
| Accepted ballots | One per credential and body |
| Unconditional statistical bad-event budget | At most 2^-128 over the lifetime |

Repeated transmission of identical proof bytes is not a new prover transcript.
The ceilings are analysis ceilings, not consensus lifetime counters. Exceeding
one requires reassessment. Changing profiles does not erase archived privacy
exposure.

This contract weakens the earlier one, which required at least 2^128 total
quantum queries for a break, counted through the actual reduction. The split
into a 2^64-query proven bound and a 2^128-gate attack cost is a policy
decision of the second-opinion review
([parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md)
section 8.8), not a theorem and not an equivalent restatement, and the owner's
qualification record must restate it. The statistical budget and the lifetime
ceilings are unchanged.

The proven bound counts queries through the actual reduction. The attack-cost
requirement is additional and never replaces it. Comparison formulas, omitted
terms, incomplete reductions and nominal primitive security levels satisfy
neither requirement. Compliance is unestablished for every parameter row: no
complete proven bound and no complete attack-cost assessment exists today.

For the construction under development the second-opinion review has written
a consolidated ledger (profile record and
[parliament_ballot_proof_arguments.md](parliament_ballot_proof_arguments.md)).
It is not a complete proven bound. Its generator terms, `α_P`, the
uniqueness terms, the frame terms and the concrete justification of the
backend oracle model have no values at the complete resource vectors. The
review also evaluated the ledger under a hypothetical nominal substitution
for those terms. That substitution is an arithmetic illustration, not a
derived bound and not a certificate of all costs: under it every listed game
stays below 1/2, and every bound that contains `Z` stays above 2^-64. The
second statement does not depend on the substitution: at 2^64 queries and
the ceiling of 2^44 transcripts, one programming term of the written bound
on `Z` alone is about 2^-51.4, so no assignment of the unvalued terms makes
those written bounds reach 2^-64. That is a limit of the written bounds, not
an attack. The global
leaf-ambiguity term of the item 1 argument is within the 2^-128 statistical
budget by the review's calculation; the query-dependent soundness bound is a
separate quantity and is not claimed to be below 2^-128.

**Admissible primitives.** Arithmetisation-oriented hashes are not admissible
in this profile, in its commitments or its transcript. Algebraic universal
hashes inside the proof protocol are a different category and remain subject
to their proved error bounds.

The engineering limits are requirements, not measurements. They apply to
`pi_reg` and to `pi_vote`, identically at every roster size:

| Item | Limit |
| --- | ---: |
| Complete canonical proof envelope | ≤ 256 KiB (262,144 B) |
| Uncached verification on the minimum validator baseline | ≤ 250 ms |
| Verifier workspace | ≤ 64 MiB |
| Phone proving, baseline Android and iOS devices | p95 ≤ 10 s |
| Phone peak prover memory | ≤ 256 MiB |

The ballot envelope comprises the proof, the public fields, the stamp and the
framing. The shared seal and list evidence is separate: the list-context
object is capped at 160 KiB. The envelope limit is therefore not a claim that
every cold verification input fits in 256 KiB; the total cold input is
disclosed with the measurements.

For the implemented standalone construction, the raw proof is 160,148 B for
`pi_reg` and 233,012 B for `pi_vote` on the row carried as the integration
candidate, and 109,498 B and 158,074 B on the comparison row. These are the
second-opinion review's figures, derived in
[parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md)
section 9.7 and confirmed by the final implementation's proof lengths. Against the 262,144 B envelope
limit the candidate row leaves 101,996 B for a registration
(`262,144 − 160,148`) and 29,132 B for a ballot (`262,144 − 233,012`): the
ballot proof alone is 89% of the limit.
The ballot's fixed cryptographic fields (`B`, `scope`, `R`, `S`, the 128-byte
`nf`, the 64-byte `auth_v`, `vote`, `policy_hash` and the profile
identifier) total 467 B if all are carried, which leaves 28,665 B
(`29,132 − 467`) for the
other envelope fields, the stamp and the framing; a registration likewise
carries its 64-byte `auth`. `D_v` is derived and not carried, and the list is
shared seal data, not part of any ballot. The sizes are therefore compatible
with the 256 KiB and 160 KiB caps, and no limit changes. Complete-envelope
compliance is unqualified until the production schema exists and the
complete envelope is measured against it; no exact framed size is stated
before then. Final-construction measurements cover both rows, registration
and votes at `S = 3`, 500 and 1,000 in portable and accelerated release builds.
The [B5 record](../docs/validation/parliament_ballot_standalone.md) retains its
seven-sample, decoded-input measurements; the
[B6 record](../docs/validation/parliament_ballot_b6.md) adds fresh-input and
late-invalid verification, actual proving/retry distributions, requested live
heap including inputs, bounded adversarial campaigns and attached-device
evidence. These runs do not establish complete work/allocation bounds,
cold-process/cache behaviour or the named validator and phone qualification.
The 250 ms, 64 MiB and phone limits are unchanged.

The hardware baselines are:

| Role | Baseline |
| --- | --- |
| Minimum validator | One physical core of an Intel Xeon Silver 4310 at its 2.10 GHz base frequency, turbo disabled, idle SMT sibling, Linux x86-64. AES-NI, PCLMUL and AVX2 are allowed. AVX-512 is not required |
| Android | Pixel 6a, Tensor, 6 GB RAM |
| iOS | iPhone SE, third generation, A15 |

Each record states the OS, compiler, build flags and device conditions. Phone
tests use native release applications, battery operation and sustained thermal
runs. The portable scalar path must be correct and bounded: it produces the
same results, the same proof bytes under fixed randomness, the same work
charges and the same memory limits. It need not meet 250 ms. The 250 ms limit
is judged on the accelerated build of the minimum validator baseline. Slower
hardware receives no claim that it supports the qualified validator
throughput. A measurement on other hardware describes that hardware and build
only; it does not qualify a baseline.

Measure both proofs at `S = 3`, 500 and 1,000, with cold runs, late-failing
invalid proofs, thermal effects and cancellation. Verification measurements
include fresh list decoding and digest validation and transcript preparation,
and exclude network and disk retrieval. Memory includes list and transcript
buffers. Record distributions and the maximum observed valid and late-invalid
times, not only averages. Derive `B_work`, `B_bytes` and the stamp difficulty
from the qualified worst case. A missed limit requires an explicit profile and
resource review; limits are never raised silently, digests are never shortened
and the security metric is never weakened to meet one.

The evaluation is recorded in
[parliament_ballot_proof_profile.md](parliament_ballot_proof_profile.md). No
profile is selected and nothing is qualified. That record states the
construction under development: a proof of selection from the sealed list
over SHAKE256 credential functions (commitment, nullifier, and registration
and vote authorization values under one secret) in a VOLE-in-the-head
backend. No section 5 gate is discharged for it. By the second-opinion
review's own status, every argument below is written, conditional and
awaiting independent review:

| Gate | Status |
| --- | --- |
| 1 | An adaptive soundness argument in the backend oracle model; its bound holds only under that model and its stated premises |
| 2, 8 | Reductions to item 1, assumptions P and U, the frame terms and joint zero knowledge; P, U and the frame terms are unproved and unvalued |
| 3 | A conditional counting argument over a batch, on the same premises |
| 4 | Unlinkability has a conditional bound from joint zero knowledge and P under the stated disclosure exclusions; non-frameability reduces to gates 2 and 8 |
| 5 | Joint zero knowledge has a conditional simulation argument whose generator terms are unvalued; anonymity is conditional on it and on P |
| 6 | No complete ledger at the actual resources and no attack-cost assessment; the written bounds that contain `Z` cannot justify advantage 2^-64 |
| 7 | Standalone component evidence and development-machine measurements exist; complete deterministic bounds, production envelopes and baseline qualification remain open |

The standalone Rust implementation now matches the strengthened relation and
the salted, affine-checked backend. All eight final proof cases match an
independently implemented Python prototype: registration and all three roster
sizes on both rows. Portable and accelerated component suites exercise the final
relations and backend; exact vector coverage and source-bound results are in
[the standalone validation record](../docs/validation/parliament_ballot_standalone.md).
The twelve official FAEST v3.0.2 signature vectors remain conformance checks
for reference mode, a separate construction. These results do not provide
independent cryptographic review or cross-architecture qualification. Later
bounded parser campaigns and supplementary device measurements are tracked in
[B6](../docs/validation/parliament_ballot_b6.md); they discharge no section 5 gate.
Selection follows section 12.2 step 2.

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
- entry-specific list queries; fetch the whole sealed list and build the
  selector locally;
- nullifier-keyed status queries from an identifying origin; confirm
  acceptance by downloading the scope's public corpus, or only over a qualified
  anonymity transport;
- creation times, TTLs or account or transaction sequence nonces in the ballot
  (the admission stamp's nonce is permitted);
- silent fallback from an anonymity mode to direct submission.

For every registration proof and every ballot proof the wallet supplies the
fresh proof randomness of section 3.1 from the device's cryptographic random
source: 112 bytes per invocation in the construction under development. It
never reuses a tape, never derives one from the credential or the message
and has no deterministic fallback; if the random source is unavailable it
does not prove. On the typed counter-exhaustion outcome it retries with an
entirely fresh tape and the same statement. It erases the tape and the
prover's secret working buffers after every invocation, including a failed
or exhausted one.

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

Two consequences follow:

- Sortition latency is height-based. A generation waits up to `d + L - 1`
  blocks when no earlier generation slot of the attempt lies at or above
  `r + d`. Otherwise it takes the next boundary after that slot, one further
  epoch. Each `NoRoster` retry and the Confirmation Jury wait for a further
  boundary. On an idle chain the wait is unbounded in wall time unless blocks
  are caused; the bounded-progress requirement below addresses that. This bears
  on the section 11 hold rule and on `parliament_sccp_attempt_latency_ms()`.
- Requests that share a pulse, candidate snapshot, body set and sizing
  configuration draw identical panels. Alignment widens that from one block to
  one epoch window.

**Draw seed.** The draw seed is attempt-independent by design. It binds the
verified persisted governance seed of the exact native pulse, the network, the
pulse height and the body role. Accounts are ranked by a per-body score in
descending order, with the canonical `AccountId` order breaking ties
(`ranked_body_candidates` in `crates/iroha_core/src/governance/draw.rs`). The
seed contains no proposal identity, attempt identity, request sequence,
admission order or nonce, and none enters indirectly through a candidate-root
digest. The snapshot, body set and sizing policy are frozen and authenticated
in the request and evidence records instead.

The reason is proposal multiplicity. Enrollment is bond-only and no reliable
rule decides that two proposals are semantically equivalent. A per-attempt
seed would let a proposer redraw the panel by submitting another proposal and
keeping the favourable draw. Fees or a one-proposal-per-account rule do not
remove that channel. Under the attempt-independent seed, proposal-identity
multiplicity has multiplier exactly 1 for a fixed pulse, snapshot, body set and
sizing policy. Correlated capture and concentrated juror workload remain.
Candidate-set manipulation, policy manipulation and waiting for a later epoch
also remain.

**Requirements on the governance clock.** [sccp.md](sccp.md) section 4.7 owns
the governance clock, the due predicate, the progress invariant and their
wording. The ballot requires the following of them. None is implemented.

- **Bounded progress to the slot.** A governance progress item
  `AdvanceToNativeSlot` exists for the nearest admitted future slot. Its
  immutable target and the current cursor define a remaining-height potential.
  Each ordinary or keepalive block consumes the current progress ticket and
  decreases the potential. A successor ticket is created only while the target
  is still in the future. Requests coalesce, so at most one advancing ticket
  exists per height. The SCCP progress invariant, which today is consume or
  terminalize, must be amended in `sccp.md` to permit this strictly
  decreasing, admission-bounded potential. `sccp.md` still states the
  consume-or-terminalize invariant and describes the latency function as a
  configured total with a single sortition-retry generation. Changing them is
  SCCP-owned work.
- **At the target.** Only the exact authenticated native pulse permits
  drawing. A missing pulse produces no continuing keepalive loop. Parliament
  creates no consensus beacon obligation. No late-produced pulse, substitute
  source, alternate slot or redraw is permitted.
- **Late processing.** An awaiting request is due when its already
  authenticated, persisted exact-slot pulse is available and unconsumed,
  including after a restart or a budget deferral. This permits late
  processing, never late pulse production.
- **Admission cap.** Nonterminal governance attempts are capped at `K`, the
  section 3.10 parameter. One casting position is reserved per admitted
  attempt, and Policy and Confirmation use it sequentially. Once `sccp.md`
  adopts this cap, the reservation replaces the section 3.6 deferral of an
  attempt that falls due while `K` are open; until then the deferral rule
  applies. Excess admission is rejected before any
  attempt state is allocated. There is no unbounded admission queue.
- **Casting clock.** One-shot due work `EstablishCastingClock` exists for
  `h_open + 1`. It makes the successor block due on an otherwise idle chain, so
  that the permissionless keepalive can cause it; due work still creates no
  block by itself (section 3.4). It freezes
  `closing_ms = t(h_open + 1) + casting_window_ms`. `s0` is preserved for the
  lift rule.
- **Latency.** `parliament_sccp_attempt_latency_ms()` is an `Option` and is
  `None` until a qualified bound exists (section 11).

Capacity exhaustion and consensus or beacon outages remain availability risks.
No design under the section 1 decisions can promise completion during a
consensus or native-beacon failure. A latency bound concerns a terminal
outcome, which may be `NoRoster` or `NoQuorum`. The progress rules need
lifecycle, mutation and real-peer qualification (section 13).

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
- `parliament_binding_ballot_available()`, false until the owner records
  qualification of the section 5 profile and the ballot is active
  (section 12.2 step 2);
- `parliament_sccp_attempt_latency_ms()`, an `Option<u64>`: the worst-case
  latency of one full-track SCCP attempt to a terminal outcome. It is `None`
  until a qualified bound exists, and `None` never means zero. It may return
  `Some(checked_worst_case_ms)` only under a qualified post-synchrony service
  contract that covers:
  - every permitted draw and retry generation, at the actual retry ceiling,
    and Confirmation;
  - native pulse availability and useful-block commit intervals;
  - every invitation, deliberation, notice, casting and enactment window;
  - shared block-start work and inclusion delays;
  - the successor block that establishes the casting clock (section 9);
  - the clock margin.

  A target or minimum block interval is not an upper latency bound;
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
`hold_lifetime_ms ≥ parliament_sccp_attempt_latency_ms()` once the function
returns a bound. While it returns `None` the lower bound is deferred, not
zero. Binding SCCP activation requires a finite qualified bound and a hold at
least that long. Longer outages are covered by renewing the fast pause before
it lapses, which has no cooldown.

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
- The timed-OVN contributions to the read index
  `parliament_required_beacon_pulse_slots`. The retained index is renamed
  `parliament_awaited_sortition_slots` when timed-OVN is retired. It stays
  derived, rebuildable and inaccessible to consensus pulse-validity decisions.

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
2. **Select the proof profile.** Profile selection and activation
   qualification are distinct. Selection of `P` and steps 3–5 may proceed only
   when all of these hold:
   1. one exact construction and parameter row are frozen, and no relation or
      transcript choice is unresolved;
   2. every section 5 gate has a complete written argument;
   3. the complete deployment-wide ledger meets the section 5 reading of
      item 6: every required computational game has advantage below 1/2 at
      2^64 adversarial quantum queries with every primitive and reduction
      cost included, the independent attack assessment meets the 2^128-gate
      requirement, the unconditional statistical budget stays at most 2^-128,
      and the ledger's thresholds at advantages 2^-64 and 1/2 are recorded.
      Comparison formulas, omitted terms, incomplete reductions and nominal
      primitive security levels do not satisfy this condition;
   4. the standalone prover and verifier implement that exact protocol and
      pass meaningful adversarial and component checks;
   5. complete envelope sizes, deterministic work and allocation bounds, and
      measurements at all three roster sizes are recorded;
   6. every remaining independent-review, external-conformance, hardware,
      phone, lifecycle and network qualification obligation is enumerated;
   7. `parliament_binding_ballot_available()` remains false.

   A written argument is complete when it gives the exact protocol, relations,
   encodings and randomness behaviour; the security game, corruption model,
   oracle access and winning condition; the primitive assumptions, kept
   distinct from the properties proved; every simulator, any extractor the
   argument relies on, and every game transition; precise citations with
   every imported theorem's hypotheses
   verified; the quantitative losses; their numerical substitution into the
   item 6 contract; and the exclusions and remaining obligations. A complete
   argument may await independent review. A missing reduction may not: an
   unresolved theorem is a gap, and a lemma that assumes the property it is
   meant to prove does not count.

   Measurements on hardware other than the section 5 baselines can support
   construction feasibility and selection. They do not satisfy the validator
   or phone launch measurements.

   Selection and integration stop again if any of these occurs:
   - a foundational game, simulator or reduction, or an extractor that an
     argument relies on, is missing or fails;
   - the ledger fails the item 6 contract;
   - the implementation needs an unproved protocol deviation;
   - adversarial tests expose an unconstrained witness, a transcript
     substitution or a determinism defect;
   - the final secure parameters exceed a hard resource limit;
   - a primitive assumption is stronger than the recorded approved design.

   A performance experiment may continue to investigate such a blocker,
   labelled experimental. Do not begin integration around a placeholder
   relation.

   Until `P` is selected, only standalone work on this step is permitted:
   - completing the backend, its conformance with the official plain-FAEST
     vectors, and the exact experimental ballot prover and verifier;
   - the profile-local relation encodings and codecs needed to specify and
     test that standalone protocol;
   - adversarial tests, independent relation checks, deterministic parity
     checks, resource accounting and measurements at `S = 3`, 500 and 1,000;
   - writing and reviewing the missing cryptographic arguments.

   Not permitted before selection: production schemas, a Core verifier
   bridge, signerless envelope integration, sealed-list or nullifier state
   transitions, Torii or SDK paths, and retirement of any section 12.1 item.
   That retirement stays in step 4, in the candidate that carries the
   replacement. The launch gate being false does not remove the selection
   precondition.

   Conditions 2, 3 and 5 remain unmet, so steps 3 and 4 have not started.
   The second-opinion review's arguments for items 1, 2, 3, 4, 5 and 8 are
   written, conditional and awaiting independent review, but none has its
   numerical substitution into the item 6 contract: the generator terms,
   `α_P`, the uniqueness terms, the frame terms and the concrete
   justification of the backend oracle model have no values (condition 2).
   Assumptions P and U of section 5 are unestablished. No complete ledger at
   the actual resources and no attack-cost assessment exists, and a
   hypothetical nominal substitution does not satisfy condition 3. The
   standalone prover and verifier now implement the exact construction, with
   meaningful adversarial and component-conformance evidence for condition 4
   in [the validation record](../docs/validation/parliament_ballot_standalone.md).
   The [B6 evidence](../docs/validation/parliament_ballot_b6.md) adds bounded
   parser campaigns, cold-input/late-invalid measurements and supplementary
   attached-device evidence. Physical x86/ARM qualification and independent
   implementation review remain open. Measurements cover both rows and all
   three roster sizes, but complete envelope sizes, deterministic work and
   allocation bounds, and named-hardware qualification remain open (condition
   5 and the later activation obligations). The executable security ledger
   preserves unknown terms and fails qualification; its arithmetic and source
   review do not establish the missing premises.
   Activation qualification is step 5 together with the owner's
   qualification record; `parliament_binding_ballot_available()` stays false
   through selection, implementation and review until the owner records it.
3. **Specify the schemas.** The Norito stored and wire forms are:
   - the credential registration, `auth` and `pi_reg`;
   - `SealedCredentialListV1` and the registration-mapping digest;
   - the scope;
   - the signerless ballot envelope;
   - `AnonymousBallotV1`, with its nullifier and `auth_v`, and
     `AdmissionStampV1`;
   - accepted-record ordering;
   - the closure record and certificate binding;
   - ballot events and queries.

   `P` defines the canonical list encoding and the canonical preimage
   encodings of `B`, `R`, `scope`, `policy_hash`, `D_reg`, `m_reg`, `D_v` and
   `m`.
   It fixes layout flags, field order and length bounds, and rejects
   alternative encodings, trailing bytes and non-canonical values. A preimage
   definition
   is not an alternative wire codec: stored and wire records stay header-framed
   Norito. There are no in-relation tree encodings. Anonymous records and
   events omit account and session identifiers.
4. **Build the paths together.** Build in one candidate:
   - registration, the sealed credential list and its publication at seal;
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
| `auth` or `pi_reg` replayed for another seat, body or account | Rejected |
| `auth` that is not the value `pi_reg` proves for the registered `C` and statement | Rejected |
| Accepted but unseated alternate | Its credential is absent from the sealed list and from `R` |
| Two equal commitments among the sealed assignments | Sealing rejects the list |
| Accepted roster of 1 or 2 seats | `NoRoster`, then the section 10 retry generation; no seal |
| Credentials lost beyond `S - Q` | `NoQuorum`; no replacement path exists |

**Ballot validity and admission**

| Case | Required observation |
| --- | --- |
| Selector with no active position, several active positions, or a position at or beyond `S` | Rejected by the relation; no entry beyond `S` is selectable |
| Duplicate or misordered sealed list, at seal, restore or verification | Rejected |
| List whose length or digest does not match the authenticated `S` and `R`; unvalidated caller-supplied list | Rejected before proof verification |
| Unconstrained or second secret behind the commitment, the nullifier or `auth_v` | Rejected by the relation |
| `auth_v` that is not the value `pi_vote` proves for the complete statement | Rejected |
| Nullifier or `auth_v` of any length other than the profile's (128 and 64 bytes in the construction under development) | Rejected at decoding, before proof verification |
| Proof whose length is not the profile's for its relation and row (160,148 B for `pi_reg` and 233,012 B for `pi_vote` on the candidate row of the construction under development) | Rejected at decoding |
| Proof whose counter exceeds `0x000fffff` | Rejected before any reconstruction work |
| Proof with a valid but non-minimal counter | Accepted if otherwise valid; verification evaluates the supplied counter once |
| Copied proof with changed vote, nullifier, `auth_v`, list, list digest, scope, policy or profile | Rejected |
| Exact authorized ballot relayed by another party, including before its creator submits it | Accepted once, unchanged; the creator's later copy is a duplicate |
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
| Idle chain with an admitted future slot | Keepalive blocks consume the progress ticket and reach the slot; at most one advancing ticket per height; no ticket outlives the target; a missing pulse leaves no keepalive loop |
| Authenticated exact-slot pulse persisted but unconsumed after restart or budget deferral | The request is due and is processed late; no pulse is produced late |
| Admission beyond `K` nonterminal attempts | Rejected before attempt state is allocated |
| Idle chain after the opening block | `EstablishCastingClock` makes `h_open + 1` due; the closing time is frozen from `t(h_open + 1)`; `s0` is unchanged; no empty block is produced |
| Pause and casting open in the same block-start pass; older decision against a newer hold; stale head | Lift rule applied by `(height, position in pass)`; stale or older decisions rejected |
| Pure CPU versus supported acceleration | Identical verification and consensus outputs |
| Wallet anonymity mode | No account, session, entry-specific or nullifier-keyed request is observable |
| Two proofs of one statement by the wallet | Each consumes its own fresh 112-byte tape; no tape byte is reused or derived from the credential, the message or an earlier tape |
| Random source unavailable to the wallet | No proof is produced; there is no deterministic fallback |
| Prover exhausts the counter range `0` through `0x000fffff` (forced in test) | Typed `GrindingExhausted` outcome, no proof bytes and no wrap; the wallet retries with an entirely fresh tape on the unchanged statement |
| Same explicit tape and statement on the portable and accelerated builds (test only) | Identical proof bytes or identical exhaustion outcome |

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
