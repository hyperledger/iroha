# Atomic Private Cross-Dataspace Settlement V1

## Status

`AtomicPrivateSettlementV1` is a first-release, governed, fail-closed protocol
path. It is separate from transparent Native AMX DvP/PvP. Configuration keeps
it disabled by default. Enabling the flag is necessary but not sufficient:
admission also requires a governed activation height, the active compiled
`IrohaIvmPrivateNoteStarkV1` capability, adequate fixed-slot limits, V1 policy
permission, and the independent pool-policy governance notice period.

Privacy protocol registration stores only a nonzero proposal execution height.
The proposal remains pending until `TransitionPrivacyProtocolLifecycleV1`
explicitly activates the exact compiled profile under governance authority.
Registration and initial activation may execute in the same transaction,
including the authorized signed genesis transaction. Both recorded heights
must equal the executing block height. There is no protocol activation delay,
automatic height promotion, or compatibility decoding for a scheduled proposal.
Suspension, resumption and retirement retain strictly increasing lifecycle
history. Governed consensus-policy and protocol-resource tightening choose an
explicit effective height strictly after their admission block; the next block is
allowed. There is no fixed minimum block delay and no wall-time guarantee. Limits
change at the start of that block only after the scheduling transaction commits.
Pending lower root-retention limits already constrain new histories, preserving a
deterministic transition. Pool-policy notice remains an independent constraint.

The implementation is not production-qualified until every release gate in
this document and `specs/private_settlement_threat_model.md` is satisfied.
Independent cryptographic review and DOI publication are external gates and
cannot be satisfied by repository tests alone.

## Guarantees and intentional disclosure

One bundle contains 2 through 255 ordered legs, with at most one leg for each
dataspace. Every route is `(dataspace_id, lane_id, lane_incarnation)` and legs
are canonically sorted by that tuple with ordinals `0..N-1`. Every dataspace
authority has exactly four validators and every availability, Prepare, and
Commit certificate contains exactly three distinct valid signatures from that
authority. Observers cannot pad a quorum.

The authority is not a caller-selected set of four keys. At the manifest's
`authority_context_height`, every validator resolves the exact canonical
ordered roster and proofs of possession pinned by the committed
`SumeragiLaneRecord`. The record must bind the exact dataspace and incarnation,
admit that global anchor (`active_from <= height < closing`, when closing),
and contain exactly the V1 `f = 1` four-validator committee. Each supplied BLS
proof of possession is verified and must equal its pinned native record.
Physical lane catalogs and manifest registries grant no participant authority.
Pool bootstrap, governance rotation, Prepare registration, and receipt application
also require the same native incarnation to admit the committed global anchor
preceding their execution block, matching native transaction routing.
Private-settlement and all participant-lane authorities require a live
`Committee` key for every member. A Committee-only peer is registered in WSV
and trusted P2P state but is never
added to lane `0`'s signed topology, NPoS candidate set, or global quorum.
Restricted upload, Prepare voting, and global receipt admission all use this
same state-anchored authority boundary.

Ordinary validators receive the proof and opaque fixed-shape delta, not audit
plaintext. Authorized local auditors decrypt and approve the exact plaintext;
the governed default is one approval from N authorized auditors. The global
carrier applies every leg in one state transaction or applies none.

The public record deliberately reveals:

- network and bundle identifiers;
- ordered participant routes and count;
- authority, expiry, lifecycle, and finality heights;
- opaque pool identifiers, epochs, roots, nullifiers, commitments, and fixed
  ciphertext slots;
- availability, statement, proof, capsule, policy, authority, and QC digests;
- committee authorities and exact 3-of-4 QCs through a deduplicated catalog;
- sponsor, public fee intent, reimbursement commitment, and terminal status.

It does not carry literal account identifiers, literal asset identifiers,
amounts, memos, or business results outside encrypted audit material. V1 does
not hide timing, participant count, dataspace identity, stable-pool activity,
or possible asset inference when one dataspace hosts only one CBDC.

## Canonical Norito objects

The implementation lives in
`crates/iroha_data_model/src/nexus/private_settlement.rs`. All objects advertise
V1 explicitly and are encoded with canonical Norito.

- `AtomicPrivateSettlementV1` binds the network, derived bundle id, authority
  context and expiry, sponsor, exact public fee intent and digest, private
  reimbursement commitment, reimbursement leg ordinal, and canonical leg
  commitments.
- `PrivateSettlementLegPayloadV1` contains the restricted proof statement,
  proof bytes, opaque public delta, encrypted audit capsule, and certified
  restricted-availability metadata.
- `PrivateSettlementDeltaV1` contains one route and opaque pool, old/new
  roots and epochs, exactly two nullifiers, exactly three output commitments
  with aligned ciphertexts, and statement/proof/capsule/policy bindings.
- `PrivateSettlementAuditPolicyV1` carries distinct auditor signing and hybrid
  encryption keys, key epoch and height validity, and `min_approvals`.
- `PrivateSettlementAuditApprovalV1` is a purpose-separated signature over the
  exact bundle, leg, route, roots, statement/proof/capsule/policy digests, key
  epoch, authority context, and expiry.
- `PrivateSettlementReceiptV1` carries the exact manifest plus a compact,
  deduplicated authority catalog and per-leg delta, Prepare-QC, and Commit-QC
  references. `PrivateSettlementAbortReceiptV1` carries only opaque identifiers
  and a public reason class.
- `RegisterAtomicPrivateSettlementPrepareV1` is the sponsor-authorized direct
  instruction carrying the exact complete all-Prepare barrier into the
  replicated control-lock map. It is distinct from the later
  `FinalizeAtomicPrivateSettlementV1` financial carrier.

The Prepare barrier, commit bundle, and receipt share the same two-level
`PrivateSettlementAuthorityCatalogV1`. Its `rosters` contain route-free
validator identities and aligned BLS proofs of possession, deduplicated in
canonical first-use order. `leg_roster_indices[i]` selects the roster for
manifest leg `i`. A phase certificate's `authority_catalog_index` remains the
logical manifest-leg ordinal, not the roster index. Before authority-digest or
QC verification, validators combine that manifest leg's exact route and active
lane incarnation with the selected roster to reconstruct the route-bound
`PrivateSettlementCommitteeAuthorityV1`.

Reserved all-zero values, duplicate routes or state keys, noncanonical order,
wrong ordinals, wrong participant bounds, expiry before/at authority context,
oversized carriers, and mismatched derived digests are rejected before state
mutation. A receipt is self-contained enough for every global validator to
verify it without fetching confidential material.

## Private-note proof profile

The settlement profile is implemented under
`crates/iroha_core_privacy/src/privacy_engines/atomic_private_settlement/` and reuses the
pinned IVM private-note STARK machinery. Its relation has exactly two input and
three output slots. Activity is canonical from the private value: a positive
input must prove membership in the old root, while a zero input is a virtual
dummy and does not require a pre-existing leaf. Both slots retain the same
hash/path topology and nonzero secret material. The AIR multiplies each of the input's 16 range-constrained value bytes
by each computed-to-public root-byte difference and requires every product
to be zero. A virtual dummy cannot
contribute value, and its memo binds the current bundle, leg, slot, and private
dummy domain. The wallet therefore spends a prior positive output with a fresh
virtual dummy without bootstrapping another pool or depending on an earlier
zero output's role memo. Output roles remain recipient, optional payer change,
and sponsor reimbursement; inactive output slots carry zero value.

`prepare_atomic_private_settlement_funding_note_v1` derives a positive funding
commitment before a bundle exists. The release harness funds each pool with
that input and an unspent reserve note, waits for state-resolved Applied
activation, and only then chooses an observed committed authority height and
generates the proof. The virtual dummy remains bound to the resulting bundle;
its fixed-shape path does not spend the reserve note. Smoke, fault, leakage and
performance preparation share this ordering. They do not predict how many
admission blocks precede activation or require a later capability query to
equal the activation transaction's block height. Exact historical committee
authorization, governance validity, root membership for positive inputs and
explicit activation of the exact compiled protocol remain mandatory. Current runtime
qualification of this harness correction is pending.

The required public `audit_input_commitment` binds the exact two ordered input
openings with SHA-256 inside the AIR. The statement stores the exact raw 32-byte
digest; no hash-wrapper marker bit or normalization may alter it. Its private
preimage contains each input's
128-bit big-endian value, spending-authority digest, rho, blinding, and memo.
The auditor recomputes the same commitment from the capsule and verifies that
each `active` flag is equivalent to a positive value. Including honestly random
rho and blinding prevents a public observer from testing pairs of public note
commitments against this binding. A self-consistent capsule and a cooperating payer's signature
cannot substitute different funding notes for those proved by the AIR.

The sole APZ1 V1 proof wire has one exact public-profile length, derived by
`maximum_encoded_proof_with_deep_bytes_v1` from the admitted parameters and
statement-derived layout, including the DEEP openings. Query-dependent Merkle
frontiers remain minimal and canonical; after those frontiers the encoder
fills the remaining fixed wire with zeros. The decoder requires that exact
length before proof-vector allocation, derives frontier sizes from valid unique
query indices, and rejects nonzero padding, short/unpadded encodings, truncation
and extra suffixes. The eight-MiB protocol ceiling remains an admission bound;
it is not the padding target. Proof digests, restricted uploads and retained
sidecars bind the complete padded bytes. The shared profile descriptor commits
this mandatory wire rule. Fixed proof length does not by itself qualify packet
boundaries, other capture surfaces or the secret-only differential release gate.

The relation enforces a balanced confidential transition and rejects the
directional public-balance bridge. It binds the network, manifest proof-binding
digest, bundle and leg ordinal, exact route, salted opaque asset/pool binding,
old/new root and epoch, fixed nullifiers and output ciphertexts, capsule and
policy digests, key epoch, sponsor, public fee intent, and reimbursement terms.
When honestly generated, one-time recipient/view keys reduce on-ledger account
linkability. A proof is accepted only after native verification of the exact
public statement.

Every fixed encrypted output's public `recipient` identifier is derived from
its authorized one-time output view key. The statement and delta require all
three identifiers in one leg to be distinct. The complete Prepare barrier and
receipt reject an identifier reused by any other leg. Before voting Prepare,
each committee validator also rejects an identifier already present in
finalized WSV. Global finalization checks a deterministic recipient index over
all finalized bundle history. That derived index is excluded from snapshot
payloads and rebuilt from canonical encrypted outputs during restore, so a
duplicate in persisted canonical output state fails closed. These checks
enforce one-time identifier use at protocol admission; they do not prevent a
malicious sender or network observer from correlating traffic before
publication.

The Rust wallet owns witness material in an owner-only APWB V1 envelope, exposes
only public inspection, and consumes the envelope on every terminal proof
attempt. Its secret input type is deliberately not cloneable, debuggable, or
serializable. After proof self-verification, the native completion boundary
derives the exact fixed-shape delta from the proved statement and an
authenticated successor root. A second native boundary binds each completed leg
to its governed audit policy, exact four-validator authority, and retention
height, then derives every payload/delta content address and one identical
all-leg provisional manifest. Callers cannot supply those post-proof digests as
trusted values. The Python native worker retains the envelope in a native vault
addressed by an opaque one-shot handle; Python supplies only the public
successor root and receives the statement, proof, derived delta, and encrypted
capsule. No witness enters Python.

Privacy STARK outer commitments, transcript derivation, query sampling and
nonce grinding use SHA3-384 through `privacy_engines/privacy_outer_hash.rs`.
Every digest is an opaque 48-byte string; canonical Goldilocks decoding applies
to actual field openings only. The frame binds the exact catalog, protocol,
compiled profile, role, phase, level, index, counter and ordered length-prefixed
fields with checked big-endian widths. The compiled proof-system and engine
labels are `stark-fri-sha3-384-goldilocks-v1` and
`native-goldilocks-sha3-384-stark-fri-v1`. The note relation's SHA-256 constraints
and ZK-ACE's inner identity/replay Poseidon constraints retain their own owners.

The scalar challenge accepts a nonzero canonical first big-endian 64-bit word.
The Fp4 challenge accepts the first four words only when every coefficient is
canonical; zero is allowed unless the caller states a deterministic public
predicate. Both reject at most sixteen candidates without changing transcript
state, then absorb the complete accepted digest and advance a checked counter.
Queries use sparse Fisher--Yates sampling with rejection from the full `2^64`
source space and at most 256 attempts per draw. Ordered nonce intervals choose
the smallest satisfying nonce independently of Rayon scheduling.

Private row preparation retains at most 4,096 frames and 32 MiB of complete
framed bytes per batch. Exact length admission precedes allocation; payload
buffers, cloned hash cores and partial block buffers are wiped on drop. Ordered
CPU/Rayon hashing uses the existing Core `simd` feature for the SHA3 dependency's
runtime-detected ARM acceleration, with the deterministic software path on
other supported hardware. The prover has one outer suite and no digest-device
option. Local batch limits do not change the proof profile. The ignored N=3
smoke is selected with `atomic-private-settlement-smoke`.

The aggregate descriptor's 197-bit minimum is an interactive FRI algebraic
error bound. It does not account for Merkle binding, Fiat--Shamir composition
or quantum queries. SHA3-specific protocol soundness and independent review,
current compiled profile/SDK fixtures, native proofs and network qualification
remain required before activation.

Global timeout certificates are delivered to the immutable union of the global roster and usable current-height participant committees resolved from one preceding-State view. Only global-roster senders expand this delivery audience; ordinary votes keep their original global destinations. An unpopulated optional lane or an oversubscribed lane awaiting its first beacon pulse contributes no guessed committee. Other authority inconsistencies remain errors. Existing certificate authentication, exact-view admission and retained retransmission govern observer progress.

## Audit capsule and approval

`crates/iroha_core_privacy/src/privacy_engines/atomic_private_settlement/audit.rs` pads the canonical plaintext
to one configured class and encrypts it under a random 256-bit DEK with
XChaCha20-Poly1305. The same DEK is independently wrapped to every auditor in
the exact policy order using the existing X25519/ML-KEM-768 hybrid KEM and an
independent authenticated nonce. Capsule and wrap AAD bind the network,
dataspace route and incarnation, bundle, leg, policy, key epoch, and canonical
plaintext commitment. They also bind the digest of the exact state-anchored
four-validator authority and its `authority_context_height`. The capsule AEAD
authenticates the canonical complete AAD; each DEK-wrap AEAD authenticates that
same AAD plus its exact auditor identity, recipient hybrid key, and KEM
ciphertext. A capsule or wrapped DEK therefore cannot be transplanted to a
different historical roster or authority height.

The capsule includes the exact parties, asset, amount, memo, policy references,
view data, note openings, and output-encryption openings required for audit. It
contains spending-authority digests but no spending secrets. Decryption returns
a zeroizing buffer. The auditor recomputes every public binding, including the
AIR input-opening commitment, validates policy and height, then
signs through `crates/iroha_core/src/private_settlement/auditor.rs`. A
deployment-owned credential-provider boundary keeps encryption and signing keys
outside Iroha; Iroha independently checks the provider's governed public keys and
returned approval signature.
Capsule access is a read-only authenticated `POST`, not a bearer read keyed only
by the payload digest. Its strict `PrivateSettlementAuditorCapsuleRequestV1`
body contains the complete access policy, and the canonical Norito JSON body is
covered by the identity-bound request signature. The server treats that policy
as evidence rather than authority: one committed `StateView` supplies the
network, authoritative height, and exact route/pool governance projection. An
O(log n) content-addressed lookup reads one durable sidecar, then core binds the
sidecar policy to the governance revision effective at the manifest's
`authority_context_height` and the requested access policy to the revision
effective at the current height. Missing, expired, or unauthorized reads all
return the same unavailable result.

A same-revision read requires the exact historical policy. A successor-policy
read requires a later pool-governance revision in the same `policy_id` lineage,
strictly higher policy revision and key epoch, and an authenticated current
signing key that maps to an auditor identity present in both the historical
policy and the capsule's wrapped-DEK set. Consensus-key reuse is rejected.
This stable-identity rule lets an authorized auditor inspect a retained capsule
after rotation without letting a newly added auditor inherit old ciphertext.
The response attestation binds both the historical `audit_policy` and the
current `access_audit_policy`. Approval submission additionally requires those
policies to be identical, so a successor-policy auditor may read retained
evidence but cannot add an approval to an old-policy in-flight leg.

The Rust production transport accepts a separately governed
`PrivateSettlementCommitteeAuthorityV1` and contacts exactly four distinct
endpoints in that authority's canonical validator order. Every auditor response
carries a purpose-separated BLS attestation by the validator at its endpoint's
roster index. The signed body binds the network, payload digest, authority
digest (including route/incarnation and roster), complete restricted-view
digest, exact lifecycle, node-authoritative height, and responder peer ID.
The transport excludes an authority mismatch, an endpoint serving as another
roster member, or the same responder identity appearing through multiple URLs
from quorum counting. One Byzantine or unavailable endpoint therefore cannot
veto three aligned responders. It requires three canonically identical views
after normalizing only the retry-equivalent Collecting/Audited lifecycle and
height, then returns the actually signed middle-height response; it never
rewrites an authenticated height after verification. The authority-bootstrap
compatibility method is not a production trust anchor. Approval delivery is
then attempted at all four authority-ordered endpoints. Each durable
acknowledgement carries a separate purpose-separated BLS responder attestation
binding the network, exact signed approval digest, payload, authority/roster,
complete acknowledgement view, lifecycle, node-authoritative height, and
responder peer ID. The production client accepts only three unique
roster-aligned responders. It normalizes `newly_recorded` and height solely for
retry-equivalent grouping, keeps `collected`, `required`, and lifecycle exact,
and returns an actually signed middle-height response without rewriting any
authenticated field. Misaligned or duplicate responses are excluded rather
than giving one Byzantine endpoint a veto. The authority-bootstrap approval
method remains compatibility-only.
Missing, stale, unauthorized, split-view, or insufficient approvals prevent
Prepare.

The shipping online-auditor CLI uses only the authority-pinned transport. It
requires the exact current governed policy through an explicit
`--audit-policy` owner-only file, the ordered committee authority as a separate
absolute, owner-only, non-symlink governance trust-anchor file without
unapproved xattrs or extended ACL entries, and an owner-only strict
business-policy file under the same descriptor-bound custody rules in addition
to an explicit local `approve` decision. Restricted files
are opened nonblocking so a checked-path replacement with a FIFO cannot stall
admission before the post-open inode and file-type checks. That
policy binds one exact network, route,
pool, audit-policy lineage and key epoch, canonical payer/recipient/sponsor and
asset allowlists, amount and reimbursement limits, memo bounds, policy
references, and a maximum remaining-height window. Empty identity or asset
allowlists are not wildcards, unknown fields fail closed, and an operator's
`approve` decision cannot bypass a policy mismatch. The business-policy,
decryption-key, and restricted pool-governance inputs have no production
environment-variable fallback.

Restricted files are xattr-free on Linux. On macOS only the exact
`com.apple.provenance` metadata attribute is permitted; the platform ACL
authority attribute `com.apple.system.Security`, every other xattr, and every
extended ACL entry fail closed. Descriptor-bound xattr and ACL checks run both
before and after the bounded read.
Operators must place these files on a qualified local filesystem whose
descriptor-bound xattr and ACL APIs expose every effective access grant. The
release qualification matrix includes native macOS APFS, Linux filesystems
with and without SELinux labels, and rejects unqualified NFS/SMB custody rather
than assuming mode `0600` fully represents remote ACL semantics.

Retired decryption keys must be retained, or retained capsules must be rewrapped,
for the applicable regulatory retention period. The software online-auditor
path accepts repeatable `--auditor-retired-decryption-key-file` inputs and
constructs a nonempty, duplicate-free current-plus-retired runtime keyring. It
selects the exact historical hybrid key named by the governed sidecar policy;
it never tries keys until authentication succeeds. Key files remain runtime
only. Retention or rewrapping is still an operator/governance obligation and a
release recovery test, not an implicit property of AEAD.

## Governed pool activation and policy rotation

`ActivatePrivateSettlementPoolV1` creates the public projection of one
restricted route/pool/asset binding and its canonical initial commitments.
A transaction activating pools in more than one private dataspace uses the
universal dataspace's configured coordinator lane and retains every private
participant leg. Catalog-only ingress and State-based admission apply the same
settlement-target normalization, including instruction vectors and executable
batches. Instruction order cannot select a different coordinator. One or more
activation instructions confined to one private dataspace retain its local
route. The precomputed routing-plan comparison remains exact; stale plans are
rejected rather than repaired during admission.

`RotatePrivateSettlementPoolPolicyV1` is the privacy-governance-authorized
replacement boundary for its auditor policy and key epoch. A rotation must name
the exact current `governance_digest`, preserve the route, pool, asset-binding
commitment, frontier, roots, nullifiers, outputs, and receipts, advance the
governance revision by exactly one, use a strictly newer key epoch and different
policy/governance digests, and activate at the block that contains the rotation.
The predecessor must still be active at the preceding height. A rotation is
rejected if a receipt touching the same exact route/pool is finalized at that
activation height; policy activation and pool finalization cannot share that
height.

The globally replicated projection retains a gap-free public lineage of every
superseded policy digest, key epoch, lifecycle, and governance digest. Snapshot
and restart validation resolve the revision effective at both a finalized
receipt's `authority_context_height` and finalization height, so a receipt
finalized before rotation remains valid as historical evidence while its exact
replay is rejected without mutation. This history does not grandfather pending work: a bundle prepared
under the old policy that crosses the activation boundary fails closed before
any global mutation. Operational recovery still requires retaining old
decryption keys for retained capsules or governing and testing capsule
rewrapping before those keys are destroyed.

## Restricted confidential availability

`PrivateSettlementFileSidecarStoreV1` persists provisional and certified
encrypted records addressed by the committed payload digest. The store enforces
owner-only directories and files, non-followed single-link regular files,
same-effective-user ownership, a single-writer process lease, create-new temp
files, canonical decode/re-encode, fsync before rename, and directory fsync.
Startup scanning rejects unknown, noncanonical, substituted, or capacity-
violating records and reconstructs staged pool/nullifier/output reservations.
Those locks use exact-route keys: pool heads are reserved by
`(route, pool_id, old_epoch, old_root)`, nullifiers by
`(route, pool_id, nullifier)`, and outputs by
`(route, pool_id, commitment)`. Equal opaque values on different routes do not
alias, while a conflict on the same full route cannot be bypassed by reusing a
pool identifier.

Access views are least privilege:

- the exact four-validator authority may fetch proof, approvals, and opaque
  delta material;
- a currently governed auditor may fetch the padded encrypted capsule through
  the exact state-bound policy and stable-identity authorization described
  above; decryption additionally requires the exact historical key retained by
  that identity;
- public and authenticated client status views expose only lifecycle metadata;
- missing, unauthorized, and retention-expired restricted reads share one
  unavailable result class.

Nonterminal `Collecting`, `Audited`, `Prepared`, and `CommitCertified` records
are never pruned. Terminal records may be pruned only after their signed
retention height. A finalized global receipt or authoritative abort/expiry is
required before staged reservations are released. Torii's supervised finality
worker runs retention pruning against its synchronously snapshotted
authoritative height on every reconciliation page, including an empty page;
any reconciliation or pruning error stops the worker and fails the service
closed.

## Prepared Rust SDK operation

`AccountClient::private_settlement` uses the existing durable workflow owner for
caller-retained prepared artifacts. It persists the exact availability snapshot
before promotion, recovers committee certificates, and signs the exact Register
and Finalize carriers through the normal account context. The returned
`VerifiedPrivateSettlementReceipt` requires successful original Finalize
input/output under pinned-genesis finality; a query receipt alone is insufficient.
Read-only resume reauthenticates that original block, including at the final tip.
No plaintext witness or restricted proof/capsule bytes enter its public journal.
The caller still owns proving and retention of the prepared artifacts. Promotion
retains the exact availability certificate and attempts every authorized replica;
it requires `q = n - f` bound upload acknowledgements before Prepare. Upload
acknowledgements are transport preflight, not an authenticated quorum; the
independent Prepare QC remains authoritative. Recovery to a replica missing the
original provisional material is still being qualified. The new SDK tests use
synthetic outputs with real certificates; genuine localnet integration remains an
acceptance requirement. See [the workflow contract](zk_durable_workflow.md).

## Protocol state machine

The durable lifecycle is:

```text
Collecting -> Audited -> Prepared -> CommitCertified -> Finalized
     |           |          |               |
     +-----------+----------+---------------+-> Aborted / Expired
```

1. The client creates the proof and encrypted capsule locally, uploads exact
   provisional material to all four validators, and obtains a canonical exact
   3-of-4 availability certificate. A certified sidecar is fsynced before the
   provisional file is removed.
2. An authorized auditor fetches and decrypts its capsule, recomputes all
   bindings, applies local policy, and submits a signed approval.
3. Every committee validator independently verifies the proof, approvals,
   current governed pool head, nullifier/output uniqueness, expiry, fixed shape,
   and durable availability. It fsyncs the verified delta and reservations
   before returning its Prepare vote.
4. The coordinator selects the canonical lowest exact three valid votes and
   persists the resulting Prepare QC on every successfully staged responder.
   Once every leg has a Prepare QC, the complete Prepare barrier is immutable.
5. The sponsor submits that complete barrier in one exact
   `RegisterAtomicPrivateSettlementPrepareV1` control carrier through the
   ordinary bounded public-fee path. Global consensus atomically installs one
   bundle row plus opaque pool-head, nullifier, output, and recipient resource
   rows in WSV. Certified-body-equivalent barrier retries are
   WSV-write-idempotent even when valid signer subsets differ (each accepted
   transaction remains subject to ordinary fee admission); substituted,
   conflicting, terminal, or expired barriers fail closed. Registration must
   finalize strictly before expiry so at least one successor height remains for
   the financial carrier. The Rust
   `register_private_settlement_prepare_and_wait_v1` coordinator API waits for
   the exact signed transaction to reach global, state-resolved `Applied`
   finality; block-height advancement or cache-only status is not sufficient.
   Registration and finalization are two separately admitted ordinary
   transactions, so an enabled fee schedule may charge both. The designated
   reimbursement leg's private amount and terms commitment binds the exact
   public fee intent and the V1 constant of two successful fee-bearing
   carriers, and local auditor policy must accept the agreed aggregate
   sponsorship cost in that leg's CBDC. V1 does not introduce a fee-free
   control transaction or silently infer a second reimbursement. Failures
   before registration incur no settlement-carrier fee. If an already
   registered bundle expires, the sponsor bears its one registration fee; if
   the sponsor submits an abort carrier, it bears both registration and abort
   fees. Neither failure path creates the private reimbursement output.
6. Every validator verifies that the barrier's certified-body identity and its
   complete replicated WSV lock set are live before voting Commit. The canonical
   Commit QC binds the exact complete-bundle digest and is persisted on every
   successful responder. Commit certification does not mutate WSV.
7. The sponsor signs and submits one carrier containing exactly one
   `FinalizeAtomicPrivateSettlementV1` instruction. The carrier binds the
   sponsor and exact public fee intent and carries the complete certified
   bundle. Coordinator and WSV preflight measure the complete boxed
   finalization instruction, including its registered instruction framing.
   Torii admission and the core transaction-scoped carrier binding additionally
   measure the exact canonical sponsor-signed transaction--including authority,
   metadata, fee intent, and signature--for `max_carrier_bytes` before any WSV
   mutation. Consensus-assigned `finalized_height` is not signed carrier
   material. Torii rejects already stale ingress and requires room for at least
   the next block within the manifest expiry window. Before finalization, the
   same sponsor may instead submit one
   `AbortAtomicPrivateSettlementV1` carrier that binds the complete public
   manifest and a stable public reason class; it never carries a delta or
   confidential sidecar material.
8. Global receipt planning verifies every authority/QC/delta, the registered
   certified-body identity and exact resource rows, and every current
   WSV invariant. Only after all fallible checks succeed are all pool heads,
   root provenance entries, nullifiers, encrypted outputs, replay receipt, and
   public receipt inserted and the complete replicated lock set removed in one
   overlay. Dropping or rejecting the transaction leaves the parent state
   byte-identical.
9. Local stores reconcile the immutable public receipt or abort marker after
   finality and on restart. Only then do they mark the sidecar terminal and
   release its staged reservations.

An exact still-live signed carrier retry is acknowledged by Torii after fresh
ingress authentication and bounded authentication of the original complete native
execution. The membership hash alone is insufficient: the authorization proof and
entire entrypoint must match the original carrier. Acknowledgment neither queues
the carrier nor charges another fee or repeats its effects. Unavailable or changed
history fails closed. A newly signed intent remains a new transaction subject to
current fees and the WSV replay rules.
This acknowledgment does not waive instruction-specific current admission policy:
for example, threshold-key lifecycle certificates still require their exact next-height slot.

When participant transactions travel on a lane, the lane only certifies their
admission; the global block that merges the lane block executes them against
the world state in its one canonical order
([`sumeragi_lanes.md`](sumeragi_lanes.md)). A State or Kura frontier advance
during candidate revalidation makes that round unavailable and preserves the
durable signing journal for retry; it does not turn the already valid
private-settlement effect into a semantic failure. The private-key action occurs
only after the validator rechecks the exact State generation and durable Kura
parent while both publication leases are held.

The complete prepared-bundle digest commits to every certified Prepare body and
authority-catalog index, but normalizes away the signer bitmap and aggregate
signature. Every exact three-of-four subset over the same body is therefore
quorum-equivalent: a coordinator restart cannot fork Commit digests merely
because a different honest validator is unavailable. Certificate cryptography
is still verified independently before the normalized digest is accepted.
Participant nodes expose a sponsor-authenticated, leg-scoped recovery read for
their locally durable Prepare and Commit QCs. Restart-safe clients query at
least three committee members, canonically select any recovered equivalent QC,
re-fan it out, and verify that the certified body remains durably recoverable.
The finalized carrier and receipt still retain the exact certificate bytes the
sponsor presented; an authenticated coordinator transcript is the evidence for
historical signer-subset collection when a deployment requires that provenance.

Height-based block-start expiry removes expired replicated WSV lock sets;
expiry reconciliation or an authoritative abort also releases local staged
locks without applying any leg. Exact terminal replay, conflicting replay, finalized-after-abort,
abort-after-finalized, or expired finalization is rejected deterministically
without changing any root, nullifier, output, receipt, or terminal marker.

## Torii interfaces

The canonical route catalog is
`crates/iroha_torii_shared/src/route_catalog/private_settlement.rs`.

| Route | Principal | Result |
|---|---|---|
| `POST /v1/nexus/private-settlements/legs` | canonical account signature | encrypted leg upload |
| `POST .../legs/availability-shares` | canonical account signature | one validator availability share |
| `POST .../phases/prepare-votes` | canonical account signature | one independently verified Prepare vote |
| `POST .../phases/commit-votes` | canonical account signature | one complete-barrier Commit vote |
| `POST .../phases/certificates` | canonical account signature | persist exact Prepare/Commit QC |
| `GET .../legs/{payload_digest}/phase-certificates` | canonical sponsor signature | locally durable Prepare/Commit QCs for recovery |
| `GET .../legs/{payload_digest}/status` | canonical account signature | redacted leg lifecycle |
| `GET .../legs/{payload_digest}/committee-proof` | identity-bound exact validator | proof, approvals, opaque delta |
| `POST .../legs/{payload_digest}/audit-capsule` | identity-bound governed auditor plus exact governed-policy body | padded encrypted capsule plus historical/access-policy bindings |
| `POST .../legs/{payload_digest}/audit-approvals` | identity-bound governed auditor | record approval |
| `POST /v1/nexus/private-settlements/bundles` | canonical sponsor signature | submit exact Prepare-lock registration, finalization, or abort carrier |
| `GET .../bundles/{bundle_id}` | public | redacted bundle status |
| `GET .../bundles/{bundle_id}/receipt` | public | finalized receipt, abort marker, or `Pending { bundle_id }` |

Receipt polling reads the active service configuration and public terminal records
from one committed WSV view. Finalized receipts take precedence over abort markers;
otherwise the response is HTTP 200 `Pending { bundle_id }`. Pending means only that
this node has no public terminal record for the identifier. It does not establish
that the bundle is known, accepted, or locally stored, and carries no lifecycle.
Malformed identifiers and unavailable/inactive service configuration remain errors.
Receipt polling never reads encrypted sidecars. The separate bundle-status route
aggregates the node's validated local ordinal subset; advanced all-leg lifecycle
states still require every manifest leg to be present locally.

All restricted and authenticated settlement responses advertise private
`no-store` behavior. The ordinary leg-status response exposes lifecycle and
public route/timing fields only; audit approval counts and the governed
threshold remain restricted committee/auditor material. Handlers return
bounded stable error classes rather than echoing identifiers, plaintext,
parser detail, or policy internals. SDKs retain a server reject-code header only
when it matches the bounded public grammar `[A-Za-z0-9_.:-]{1,128}`. Response
decode and validation failures discard parser causes as well as body text, so
cause-aware logging cannot recover attacker-controlled field names or response
documents.
Carrier admission returns only the bundle identifier, observed admission
height, and signed carrier hash. It does not claim that a queued abort is
already durable; the public status and receipt routes are the authoritative
terminal projection. Every SDK requires both identifiers to be canonical,
checksummed Norito `Hash` JSON literals and the height to be an unsigned
64-bit integer; missing, additional, mistyped, non-canonical, or overflowed
fields fail closed before the response reaches application code.
Success status is part of the exact V1 contract: carrier admission requires
HTTP `202`, while every other private-settlement operation requires HTTP `200`.
SDKs reject an alternate successful `2xx` code before accepting its body and
do not echo that unexpected response body through client errors.

Restricted response acceptance is a native cryptographic boundary, not a
schema-only SDK check. Rust performs the authoritative validation directly;
Python, JavaScript, Kotlin/JVM, mirrored Java Android, and Swift call the same
Rust rules through their shipping native bridge. Committee-proof verification
binds the exact response bytes to the configured network and requested payload
digest and validates the complete authority roster, proofs of possession,
signatures, proof statement, opaque delta, approvals, availability, and
lifecycle. Auditor-capsule verification additionally binds the exact governed
auditor signing key, while approval acknowledgement verification also binds the
exact request bytes sent by the client and verifies the local approval
signature. Missing bridge symbols, an ABI mismatch, or any native rejection
fails closed with a fixed redacted error; restricted HTTP dispatch does not
begin until bridge availability is established. Public redacted status and
receipt queries do not depend on access to restricted verification material.

## Configuration

Production behavior is sourced from `[nexus.atomic_private_settlement]`; no
environment variable enables the feature. The actual configuration includes:

- `enabled` and `activation_height`;
- `minimum_activation_notice_blocks` and `proof_profile_version`;
- `max_participants` (hard V1 maximum 255) and `max_expiry_blocks`;
- audit, Prepare, and Commit height timeouts;
- strictly increasing capsule padding classes;
- proof, whole-canonical-capsule, carrier, per-record, and retention bounds;
- `sidecar_max_records` and `sidecar_max_total_bytes`, which are consensus-
  committed governed capacities passed to every Torii sidecar store at open;
- `default_min_auditor_approvals`, which is the governed minimum threshold
  accepted for every newly admitted policy, and permitted audit-policy versions.

`max_capsule_bytes` limits the canonical Norito encoding of the complete
`PrivateSettlementAuditCapsuleV1`, including AAD, nonce, ciphertext, vector
framing, auditor identifiers, and every wrapped-DEK row; it is not a
ciphertext-only allowance. Configuration parsing proves that each enabled
padding class can fit the conservative complete-capsule envelope for at least
`default_min_auditor_approvals` auditors. Admission then rejects any policy
whose `min_approvals` is below that governed floor and any actual capsule whose
whole canonical encoding exceeds `max_capsule_bytes`.

`max_carrier_bytes` limits the complete canonical sponsor-signed direct
transaction, including registered instruction framing, authority, metadata,
fee intent, and signature. Coordinator/WSV receipt preflight reconstructs and
measures the boxed finalization instruction, while Torii and the transaction-
scoped core binding enforce the exact signed-transaction size. Ordinary network
transaction bounds remain independent.

Invalid zero values, unsupported V1 versions, duplicate/unsorted padding or
policy lists, enabled-without-activation configurations, and values above hard
protocol limits are configuration errors.

## Determinism and recovery invariants

- All hashes and signatures cover canonical Norito objects with explicit domain
  separation; no JSON or platform-native layout enters consensus.
- Committee choice is canonical and independent of arrival timing once at least
  three valid votes exist.
- Expiry is height based, not wall-clock based.
- A QC is never returned before the corresponding sidecar/delta/certificate is
  durably persisted.
- Commit votes require the complete all-Prepare certified-body identity to be
  present in the globally replicated WSV lock map. Independently valid 3-of-4
  aggregate encodings over the same bodies are accepted without rewriting the
  original lock; transaction admission, height advancement, and local sidecars
  alone do not satisfy this gate.
- Commit QCs are evidence only and never mutate state. The separately finalized
  registration carrier changes only opaque global control-lock state; every
  confidential financial effect occurs together in the single finalization
  `StateTransaction`.
- Every global leg is validated before the first overlay write.
- A staged recovery checkpoint includes the exact post-commit replay ledger and prepared DA quota writes, including first-touch MV undo history. The projection is read-only; ordinary expiry remains a commit operation and autonomous retention semantics are unchanged. Immutable checkpoint/post-commit hash parity remains mandatory.
- Loading verified relay caches never mutates canonical contract storage. Stale or mismatched-incarnation records remain ineligible; canonical removal occurs only through the committed lane lifecycle transition.
- Replay markers and terminal receipts survive snapshots, Kura replay, and
  restart; ambiguous local state fails closed and reconciles from immutable WSV.
- Snapshot decoding accepts exactly the current `World` schema,
  including all eight private-settlement maps. Missing, reordered, renamed,
  additional, or retired fields are rejected; V1 has no predecessor-schema
  migration path. A positive-height signed snapshot remains an export rather than
  execution authority; startup requires the original signed genesis and complete
  native certified replay history.
- Governed pool projections retain exact policy-revision lineage so historical
  finalized receipts remain restart-valid after a rotation while exact replay
  is rejected byte-silently and old-policy in-flight bundles remain inadmissible.
- Signed RS16 `PayloadManifest`/`PayloadChunk` availability is mandatory for
  deployment qualification. The native core's full-body transport does not yet
  integrate that contract; private-settlement qualification fails closed until
  the actual signed availability path is exercised. Full-body delivery is not
  substitute evidence; see `sumeragi_goals.md`, open question 8.

## Verification and publication gates

### Correctness and cryptography

- Roundtrip and negative Norito fixtures cover 2 and 255 legs, ordering,
  duplicates, authority catalogs, exact quorum, and all digest substitutions.
- Proof tests cover real/dummy selector combinations, balanced two-input/
  three-output transitions, salted asset binding, audit binding, sponsor
  reimbursement, fee substitution, root/nullifier/output replay, and witness
  terminal zeroization.
- State tests assert byte-identical roots, nullifiers, commitments, outputs,
  receipts, and balances after any invalid leg; success advances every leg
  exactly once.
- The count-symmetry TLC model covers atomicity, idempotency, expiry, crash
  recovery, and bounded liveness for 3 and 255 legs, with negative controls
  that must violate safety when the atomic guard is removed. The complementary
  committee-indexed refinement covers independent exact four-validator
  committees, static `f=1` Byzantine/unavailable identities, local auditors,
  authenticated channel faults, global quorum, and every named durability
  boundary. The indexed model uses a canonical representative for exchangeable
  validator identities. Concrete Hold, Drop, and Delay controller modes refine
  to one common delivery-blocking formal state; kind-specific delay delivery,
  retry timing, and hold release remain real-process obligations. This quotient
  is part of the specification rather than TLC `SYMMETRY` or `VIEW`, preserving
  sound liveness checking with the pinned tool while the real-process matrix
  retains every concrete controller mode. Durability is a temporal action
  property over every transition, with abort/expiry as the sole staged-lock
  release. A dedicated indexed mutation must violate that property by losing a
  staged record on crash. Exact signer sets are retained until certification;
  a second temporal action property checks every new sidecar, Prepare QC, and
  Commit QC against its authenticated pre-state quorum before that no-longer-
  observable vote history is discarded. Durable QCs are opaque markers rather
  than retained signer bitmaps, and recovered-state initialization would need
  an explicit provenance witness. Faults are injected at the first clock-free
  phase where they can affect voting or delivery, and future-inert local state
  is canonicalized after Commit. Aggregate weak fairness is justified by
  finite fault budgets, state-changing recovery, and monotonic progress; any
  future unbounded retry cycle requires per-instance fairness. Fault budgets
  are independent per committee rather than shared across the bundle. The
  indexed expiry action abstracts crossing the configured height and does not
  claim to model block-height passage or timing. The release runner requires the N=2
  validator-focused and full bounded-fault configurations, paper-primary N=3
  fault configuration, N=4 clean path, and N=3 expiry/replay configuration.
  Current mutable-checkout runs pass all five indexed positive rows, including
  58,085 distinct states for full N=2 and 8,898,534 for paper-primary N=3, and
  the staged-loss mutation produces the required action-property violation at
  status 13. These are frozen-input development results, not clean-candidate
  release evidence.
- Complete formal-release evidence is fail-closed over one exact ordered
  `(configuration, expected outcome, model)` matrix. Its source-sealed digest
  binds both TLA+ models, every configuration, and a separate evidence-code
  digest for the report producer, runner, result-contract helper, and Java
  resolver. The archived transcript uses canonical metadata and exact ordered
  model-qualified sections; the DOI verifier independently replays SANY and
  TLC parsing, rejects injected/reordered headers, noncanonical run controls,
  unexpected diagnostics, duplicate JSON keys, and report/transcript row
  drift. The report also records the resolved Java executable byte digest and
  bounded version output. Independent release review must match that runtime
  identity to the declared builder environment; recording it is not itself a
  trusted-runtime attestation.
- Independent review must cover the revised AIR, dummy selectors, asset/capsule
  bindings, reimbursement relation, hybrid encryption, approval/QC domains,
  and state machine.

### Real-network fault matrix

Run exact four-validator processes for every dataspace at N=2,3,4,8,16, using
N=3 as the paper's primary configuration. The canonical participant profile is
one non-universal public dataspace followed by N-1 restricted dataspaces; the
global coordination dataspace remains public and is not a settlement leg. The
primary N=3 capture therefore contains eight public P2P validator ports (four
global plus four public-participant validators) and eight restricted P2P
validator ports. Both the frozen configuration and each harness request bind
this ordered visibility vector, and any omission, reordering, substitution, or
all-restricted profile fails closed. Stop/restart one validator in every
committee plus coordinator/global nodes. Use only the authenticated consensus
message controller, acknowledge each hold/drop, and exercise 5%, 10%, and 20%
loss, phase-cut partitions, delayed delivery, healing, and crashes after
sidecar, staged delta, Prepare QC, Commit QC, receipt publication, and both the
Kura-append and WSV-application boundaries of the all-Prepare registration and
finalization carriers. Continuously assert that no strict subset becomes
visible or spendable and that every node converges after healing. Keep signed
RS16 DA/RBC enabled.

The feature-isolated adversarial daemon exposes one-shot process cuts for the
distinct durability boundaries above. Each command binds the exact public bundle
id, is stored in the peer's owner-only control directory, and is acknowledged
with an fsynced canonical record before the process aborts. The sidecar,
staged-delta, and committee-certificate cuts occur only after the corresponding
record and directory entry are durable; the Kura cut follows the block and V2
finality append; the WSV cut follows atomic state publication; and the receipt
cut follows durable committee reconciliation. Shipping binaries do not compile
these abort hooks. Presence of a hook is not evidence: the release harness must
retain its exact command/acknowledgement and demonstrate restart convergence.
For every trial whose nonfinalized checkpoint is after Prepare registration
(all route-loss/phase-cut trials, Commit-QC cuts, both registration cuts, and
all finalization cuts), the retained snapshot must show the complete `1 + 9N`
replicated reservation rows with one identical commitment on every validator.
Global validators must have an empty committee-local lock plane; every one of
the four validators in each participant committee must expose exactly one pool
head, two nullifiers, and three output reservations with an identical
committee-local commitment. Sidecar, staged-delta, and Prepare-QC cuts occur
before global registration and therefore retain the empty replicated plane.
Every terminal snapshot must restore both lock planes to their exact empty
commitments.

Release execution first requires a completed
`scripts/private_settlement_smoke_campaign.py` campaign: ten consecutive fresh
N=3 runs, each with sixteen distinct validators, explicit governed protocol
activation, continuous financial-state observations, signed RS16
finality, idempotent acknowledgment of the exact finalized carrier, and restart of every validator. The driver builds
the exact signed clean source and retains requests, process inventories,
state/certificate/finality artifacts, command logs, and source/executable
digests outside the checkout. Skipped tests, failed runs, reused identities,
changed bytes, or incomplete evidence invalidate the campaign. Synthetic
validator tests do not satisfy this prerequisite.

The smoke waits for sponsor-side `Applied` registration, then for every
validator's replicated reservation plane to match the sponsor's complete
`1 + 9N` map before requesting Commit certificates. The bounded wait requires
the exact original peer inventory, an empty replicated baseline and unchanged
financial state throughout convergence; partial or different maps fail.
It preserves three-of-four committee-local Prepare semantics and does not
require a local Prepare copy at a validator that did not answer that phase.

`scripts/private_settlement_release_runner.py execute` requires
`--smoke-campaign <retained-campaign-directory>` at the exact plan commit. It
revalidates the campaign and execution source before starting any job and
again before completing the output fragment. A bound prerequisite receipt
records the ten-run gate in the fragment; raw smoke evidence stays in its
owner-only directory. This gate does not establish an independent audit or
complete the other release requirements.

Execution uses a fresh owner-only output directory and permanent
`attempts/<ordinal-request-id>/` directories. Each retains the request, raw
stdout/stderr, response bytes, evidence and immutable process/response/semantic
outcomes, including malformed responses and unsuccessful commands. A failed
campaign retains its frozen plan, completed jobs, failed job, unstarted request
IDs and failing reports. A new campaign is required for another attempt.
The completion fragment is atomically linked from fully synced pending bytes
after final source and smoke revalidation; a failed publication preserves those
pending bytes and its failure record without a success filename.

Each real-process fault run emits one strict JSONL record for
`scripts/private_settlement_fault_report.py`. The reporter requires the exact
N=2,3,4,8,16 matrix across at least ten seeds per N, one validator restart in
every committee, coordinator/global restarts, acknowledged 5/10/20-percent
loss for restricted DA, Prepare, and Commit, all phase cuts and persistence
boundaries, convergence, byte-identical invalid-leg state, exactly-once success,
`exact_retry_idempotent` evidence (the original acknowledgment, unchanged fees,
receipt and complete financial state), and zero partial visibility or spendability
observations.
Every run binds the same full source commit and archived hardware-description
SHA-256, plus the archived N-specific configuration SHA-256. A canonical
configuration manifest covers N=2,3,4,8,16 in order and binds every exact
configuration file while asserting four validators, 3-of-4 quorum, and
mandatory signed RS16 DA/RBC. It also binds the exact bounded coordinator/
prover Rayon width and validator scheduler, Rayon, and pipeline worker width.
The real-process launcher must override any ambient `RAYON_NUM_THREADS` value
with the recorded coordinator/prover width; the localnet builder must write the
recorded validator width into every peer configuration; and the Rust harness
must reject either mismatch before starting a validator. The execution record
also fixes Cargo build jobs, release codegen units, and incremental compilation.
The launcher removes caller-provided Rust flags, compiler wrappers, build
targets, target-specific flags, and profile overrides before applying those
canonical build settings. The summary binds
every raw JSONL file by length and SHA-256. Every individual loss, phase-cut,
and crash row also identifies
one globally non-reusable record reference inside a SHA-256-bound archived
authenticated-controller transcript and one inside an archived atomicity
observation capture. The final DOI verifier resolves both digests to unique
manifest artifacts and requires each referenced JSONL row to match its raw
participant count, seed/run, collection, trial index and fault parameters. It
also checks the exact controller acknowledgement/recovery fields and the
capture's positive continuous-check count plus zero partial visibility and
spendability observations before regenerating the summary from the archived raw
runs rather than trusting a detached matrix claim.
Synthetic or simulated records are test fixtures only and must never be
published as real-process evidence.

N=17 through 255 are deterministic state-machine, codec, carrier-size, and TLC
tests. They must not be labeled real-network latency measurements.

### Leakage and performance

Capture Torii, restricted/public P2P, block wire, Kura/merge artifacts,
snapshots, queries, events, logs, and telemetry. Plant account, asset, amount,
memo, and capsule canaries in multiple encodings. Differential runs in which
only secrets change must preserve public shapes and traffic counts; only
cryptographic values may differ. Publish the residual metadata listed above.
`scripts/private_settlement_leakage_audit.py` enforces this with byte-level
canary scans, exact public file/size/JSON-shape comparison, and mandatory paired
V1 traffic-count manifests covering Torii requests/responses,
public/restricted P2P packets, blocks, queries, events, logs, and telemetry.
Its report binds the canary manifest, every scanned artifact, and both
traffic-count manifests by byte length and SHA-256.
The restricted source archive also carries a separately raw-bound registration
checkpoint for every validator, captured only after the exact registration
transaction reaches state-resolved finality. Independent replay requires the
checkpoint height to lie within that validator's retained observation interval,
the financial ledger to remain byte-identical to baseline, the same complete
`1 + 9N` replicated lock on all validators, no local locks on global validators,
and one exact six-row local leg lock on every member of each participant
committee. State responses must be canonical compact JSON and every Iroha hash
literal must have a valid checksum; syntactically shaped but noncanonical or
checksum-corrupted evidence is rejected.
Canonical account and asset canaries are expanded into their protocol-native
I105-controller and asset-UUID byte encodings as well as ordinary text, integer,
hex, Base64, URL, and JSON representations. The real loopback capture is split
by the exact per-run Torii, public-lane P2P, and restricted-lane P2P port
manifest with `scripts/private_settlement_capture_split.py`; packet payloads and
timestamps are copied unchanged into canonical pcapng surfaces, and an empty
declared channel fails closed. The unfiltered classic pcap is retained as an
owner-only `restricted_packet_source`; final capture provenance binds its exact
bytes, the canonical port manifest, and the raw `tcpdump` stderr. Validation
reparses the capture statistics, requires a nonzero capture with no kernel
drops, rejects truncated/fragmented packets, scans the complete raw capture for
canaries before filtering, and reconstructs all four published pcapng surfaces
byte-for-byte from that retained source.

Non-packet evidence is retained once more in an owner-only
`restricted_audit_source` archive. Its canonical rows preserve the exact source
bytes for block wire, queries, events, operator/coordinator logs, telemetry,
Kura/merge/snapshot inputs, confidential DA, and all 16 peer atomicity
observations. Replay verifies each public digest projection against those raw
bytes. Atomicity replay additionally requires a common byte-identical baseline
and terminal state across every peer, bounded nondecreasing heights, no baseline
or terminal staged locks, and exactly the expected N=3 pool/root/nullifier/
output/receipt transition with no partial visible or spendable state.
The DOI-bundle verifier independently requires those bindings to cover every
archived public and restricted capture, Kura/merge and snapshot artifact,
query/event/log/telemetry record, both retained raw-source archives, and both
traffic-count manifests; a clean report from another capture set cannot satisfy
the gate. It reloads each archived capture-provenance response and reruns the
release runner's complete raw-pcap, restricted-source, and atomicity validator
against the archived left/right directories. It also reloads the canary
manifest and independently rescans every archived privacy surface, so a
digest-rebound report with suppressed findings still fails. A separate
canonical differential-pair manifest binds the left and right artifact paths,
kinds, lengths, and SHA-256 digests for every required privacy surface. The
verifier requires the declared left/right roots to contain exactly that paired
archive inventory and loads every pair itself. Public/fixed-shape surfaces must
have equal byte lengths and JSON shapes. The entropy-bearing raw pcap and
restricted-source archive are explicit whole-file size exceptions; instead the
verifier requires equal packet link types and per-packet length sequences, equal
restricted row identities, and equal lengths for the restricted fixed-shape
groups. Changing a same-size public field name, a packet boundary, a
capture-provenance claim, or an unpaired differential file cannot be hidden by
rewriting summary reports and their digests.

Qualification requires at least five actual warmups on each persistent network
session contributing measurements, and at least thirty measured bundles for
each profile/N across independent network seeds on pinned hardware. Report
p50/p95/p99 with confidence intervals
for proof, upload/availability, auditor response, committee verification,
Prepare QC aggregation, all-Prepare registration finality, Commit QC
aggregation, financial finalization, and end-to-end latency, plus throughput,
CPU, RSS, network bytes, proof/receipt size, and storage growth. Transparent AMX
is the control. The first release publishes its measured envelope; later releases fail
when p95 regresses by more than `max(10%, 3 MAD)` or p99 by more than 20% against
the signed baseline.

`scripts/private_settlement_benchmark_report.py` validates the raw JSONL matrix
and emits deterministic bootstrap intervals. The final release verifier parses
the retained raw samples again, regenerates every p50/p95/p99, MAD, and
deterministic confidence interval, and requires the published measured-run and
seed identities, stage/resource shapes, counts, and passing regression result
to match exactly. Every raw sample and the generated report bind the same full
release commit, archived hardware-description digest, stable hardware-profile
digest, and exact N-specific configuration digest, so results from another
build, host profile, network configuration, or altered summary cannot be
relabeled. The stable profile is the canonical hash of the validated host,
operating-system, kernel, architecture, CPU/core, memory, storage, network,
clock, power, and virtualization fields; only the release-specific commit,
collection timestamp, and validation marker are excluded. This lets a later
candidate carry its own commit-bound hardware artifact while still proving that
it ran on the same pinned environment. Later-release regression comparisons
reject a baseline captured with a different stable hardware profile,
configuration matrix, or benchmark requirements before applying the p95/p99
thresholds.

Benchmark execution uses one mandatory V1 terminal envelope. It binds the exact
request ID, nonce, request-byte digest, commit and participant count before the
request moves into the Rust worker. Its outcome is either a complete successful
measurement, a bounded worker failure, or a typed exhausted completion deadline.
Only existing declared stage deadlines produce `timed_out`; diagnostic strings
and transient polling failures do not classify a timeout. Failure and panic
terminals are published durably before the worker's unsuccessful exit is
preserved. They contain no successful measurement payload.

The Python adapter retains `evidence/benchmark-protocol/rust-result.json` and
`adapter-outcome.json` even after a nonzero Rust exit. Missing terminals remain
incomplete; malformed, substituted or contradictory terminals are invalid.
Successful publication requires the exact two-file transport inventory and a
response matching the retained Rust measurement. The pure protocol checks live
in `scripts/private_settlement_attempt_accounting.py`; they do not confer
release qualification.

The planner freezes the outer deadline and all seven Rust deadline budgets in
`benchmark_accounting`. `register-scope --campaign <id>=<plan> --output <scope>`
registers the complete ordered campaign set before execution. `execute` requires
`--scope` and `--campaign-id`; its only output locator is
`<scope-parent>/campaigns/<id>`. A durable start binds scope, campaign, exact plan,
request and nonce; a retry cannot overwrite that locator or replace its outcome.
The execution timeout comes from the frozen plan, without an execution override.

Every accepted benchmark retains `benchmark-sample.json` before the next job.
Its acceptance record binds exact sample and response bytes. Canonical JSONL and
CSV rows carry `attempt_id`; identical workload coordinates from different
registered campaigns remain distinct. Destination publication I/O is a typed
job-invocation failure, without asserting that a financial settlement rolled back.

`account-scope` authenticates every registered campaign and its quiescent closure,
including process closure for preceding fault/leakage jobs. It rechecks retained
record bytes, metadata, missing records and directory inventories after collection.
The shared pure reducer requires exact successful-row joins and computes
`planned = not_started + attempted` and
`attempted = succeeded + failed + timed_out + incomplete`. It preserves separate
profile/N/warmup cohorts. Missing authoritative terminals remain incomplete;
malformed or contradictory evidence is rejected. Campaigns must share source,
hardware and declared deadlines, including unsuccessful predecessors.

`close-unstarted` exclusively claims a registered campaign directory and retains
the original frozen plan and all transitive input bytes before closing it as
`not_run`. An existing or partially prepared execution directory cannot be
reclassified through this command. Missing process outcomes require recovery;
elapsed wall time does not establish quiescence.

`execute` publishes `campaign-artifacts.json` after its own completed closure.
`finalize-scope --scope <scope> --qualification-campaign-id <id>` requires all
registered campaigns to have complete accounting and selects one completed
campaign for the fault/leakage evidence. It reconstructs every retained request
from its canonical frozen plan, replays accepted measurement semantics, and
archives the exact controlled records below `accounting/campaigns/<id>`.
The `benchmark_scope`, `benchmark_accounting_record`, and
`benchmark_accounting_report` artifact kinds are mandatory. The release verifier
requires the exact controlled inventory and independently recomputes the counts
and statistical report from these original records. Failed predecessors and
accepted samples preceding a later failure remain in the same registered scope.

The reporter requires the registered scope; benchmark JSONL rows alone cannot
produce a report. Statistics use successful measured jobs, while public job
accounting separates measured and warmup cohorts and includes failed, timed-out,
and unstarted jobs. The paper importer exports only those aggregate counts and
statistical summaries after complete canonical release verification. It does not
export attempt identifiers, diagnostic text, canaries or retained request data.
The diagnostic `account-scope` command alone does not qualify measurements or a
release. Synthetic accounting tests are not empirical benchmark evidence.

The current per-job adapter still starts a fresh network for every benchmark
invocation. It does not implement persistent warmed sessions. The pure
`build_benchmark_session_plan` helper assigns contiguous warmup/measurement
attempts to each profile/N/seed, with adjacent counterbalanced profile pairs and
a common economic-workload commitment. The grouped and paired bootstrap helpers
in the reporter resample complete session groups, preserve empty groups and
undefined replicates, and condition quantiles on successful measured attempts.
These planning/statistics helpers have no production call sites yet.

TODO: replace benchmark process ownership coherently with separate durable
session-process and per-attempt evidence. A live warmed network cannot be called
quiescent after each attempt. Qualify exact consented N-leg transparent economic
flows, common initialization/finality/convergence windows, proof-worker resources,
complete sampling and workload-attributed network bytes before accepting real
measurements. The current N-1 bilateral transparent star transfers and private N
independent legs are not an equivalent payment graph; a single-bundle latency
reciprocal is not sustained throughput.

### Release artifact

Focused suites, workspace tests, strict clippy, format verification, ten strict
randomized seeds, two-hour soak, serial privacy-release checks, release
inventory, reproducible build, SBOM, and every real-network matrix must pass.
Archive raw CSV/JSON, exact configurations, sanitized captures, plots, logs,
manifest hashes, commit id, hardware description, threat model, protocol
argument, limitations, and independent audit reports in a DOI-backed artifact
for the BCK26 paper.

Validate the final, already-published artifact with
`scripts/private_settlement_release_evidence.py <bundle>/release-manifest-v1.json`.
The V1 manifest binds every file by byte length and SHA-256, rejects unlisted
files and symlinks, and requires the exact real-network participant/loss/crash
matrix, four-validator 3-of-4 committees, ten randomized seeds, a two-hour
soak, benchmark sample minima, reproducible-build/SBOM evidence, a complete
independent-audit scope, an auditor key-custody/rotation report, and a canonical
DOI. Focused/workspace tests, strict Clippy, format verification, SDK,
inventory, ten-seed randomization, two-hour atomic soak, and serial
privacy-release gates are structured V1 reports bound to the exact source
commit and to distinct separately archived operator transcripts; a one-line
placeholder cannot satisfy them. Reproducible-build evidence must contain at
least two distinct builder/environment records that produce byte-identical
archived release binaries, and the CycloneDX 1.5/1.6 SBOM must bind the same
commit and SHA-256 hashes. The hardware description is a commit-bound structured
record and derives the stable hardware-profile binding used for cross-release
benchmark comparison. The configuration manifest must bind every archived
N=2,3,4,8,16 configuration used by both the fault and benchmark matrices. This
verifier deliberately does not manufacture or waive any of those external
results.

The release inventory is derived, never ratcheted to a literal count. The
candidate producer must first prove a clean `HEAD`, index, and worktree, then
archive the raw Git commit object, canonical recursive
`(path, mode, object_type, object_id)` tree rows, the exact binary source path
list, the deterministic `iroha-workspace-source-seal-v1` archive, and the
candidate `Cargo.lock`. The verifier hashes the raw commit object to the
release commit, reads its tree header, reconstructs that root tree from the
rows, derives the file count, compares the path list byte-for-byte, streams and
rehashes every regular file or symlink in the source seal to its Git object,
checks gitlink shape, recomputes the full-permission workspace manifest, and
requires the sealed `Cargo.lock` bytes to equal the separately archived
lockfile. Missing, unexpected, or changed paths are reported by name; two
matching self-reported counts cannot satisfy the gate.

Both the producer and the independent verifier resolve the complete archived
symlink graph before acceptance. A target that is lexically in-root but escapes
after another archived link is followed, a cycle, `.git` traversal, or a
Windows-drive/backslash target fails closed before any link is materialized.
Valid deeply nested inventory paths are reconstructed iteratively rather than
through the host language's recursion stack. The source manifest and every
structured command-gate report are reread through a stable bounded file handle
and authenticated against the exact artifact digest and length at the point of
JSON parsing. Exactly one archive, raw commit, lockfile, path list, source
manifest, and release-inventory report may appear in a release bundle.

Generate those source artifacts from the final clean checkout before assembling
the DOI bundle:

```sh
python3 scripts/private_settlement_source_evidence.py \
  --repository-root . \
  --bundle-root /absolute/path/to/release-bundle
```

The command refuses an output directory inside the checkout, any staged,
unstaged, untracked, or unmerged source, an existing destination, non-canonical
tree rows, or source identity drift during capture. It publishes
`evidence/source` by one directory rename only after repeating the source and
inventory checks. Add every artifact declaration printed in its JSON result to
the final release manifest; the final verifier remains the authority for the
complete DOI bundle.
