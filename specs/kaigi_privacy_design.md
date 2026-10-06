# Kaigi final V1 authorization and retained state

This is the implementation-coupled specification for the first-release Kaigi
cutover. Core, model and SDK integration is being validated; the source changes
are not a deployment qualification. Current evidence and outstanding release
gates are recorded in [privacy_first_release_closure.md](privacy_first_release_closure.md).

## Security statement

Private Kaigi actions prove knowledge of a full canonical nonzero Pasta Fp
blinding and bind the exact authenticated ledger context. Transaction signers,
original participation accounts, roster commitments, mutation counts/timing,
and the submitted duration/gas tuple are ledger-visible. This relation does
not claim anonymous transaction submission, hidden roster membership, hidden
billing amounts, or attestation of an encrypted media log.

The circuit uses the same deterministic Pasta Poseidon construction on every
host. Its canonical identity adapter hashes complete canonical Norito identities
with the shared six-lane Goldilocks construction. It includes every multisig
member, weight and threshold; display prefixes, aliases, low-word projections
and field reduction are not identity adapters.

Multisig construction orders complete public keys by canonical algorithm name
and unsigned key bytes. External I105, Norito and JSON policies must already
carry that exact order, V1, distinct members with nonzero weights, and a
reachable nonzero threshold. Decoders reject malformed policies instead of
normalizing them into another identity. The canonical member-count capacity
is 65,535 (u16); the shared `multisig-accounts-v1` fixture generator includes
all eleven signing algorithms and a 256-member account.

## Wire and circuit catalog

`KaigiParticipantCommitment` contains only `commitment` and
`KaigiParticipantNullifier` contains only `digest`. Both fields, and each usage
commitment, have type `KaigiAuthorizationScalarV1`: exactly 32 little-endian
canonical Pasta Fp bytes. Zero is a valid public output; values at or above the
modulus are rejected. These fields never pass through `Hash` or its reserved
marker bit. JSON uses exact 32-byte arrays. The removed alias and issuance-time
fields are rejected, including empty or zero-valued instances.

The authorization circuit ID is `halo2/pasta/ipa/kaigi-authorization-v1`, with
schema `kaigi-authorization-v1`, domain size `k = 13`, and exactly one instance
column containing these 31 rows:

| Rows | Meaning |
| --- | --- |
| 0–3 | Genesis-derived network bytes as four little-endian u64 limbs |
| 4–9 | All six canonical call-identity Goldilocks limbs |
| 10–15 | All six original host-identity Goldilocks limbs |
| 16–21 | All six original subject-identity Goldilocks limbs |
| 22 | Ledger-owned participation sequence |
| 23 | Closed action: host create 0, join 1, leave 2, host end 3 |
| 24–27 | Authenticated pre-roster root as four little-endian u64 limbs |
| 28–30 | Commitment C, action nullifier N, authorization A |

Host actions require subject = original host and sequence zero. Join and leave
require a different subject and a positive sequence. C binds network, call,
host, subject, sequence and private blinding. N binds the same identities and sequence to the
action, without a blinding or caller-selected nullifier seed. A binds the entire context,
including action and pre-root, to C, N and the same blinding. The framed sponge
constrains domain, length, terminator, padding and persistent capacity state.
All integer limbs are range checked; identity limbs are strictly below the
Goldilocks modulus.

The usage circuit ID is `halo2/pasta/ipa/kaigi-usage-v1`, with schema
`kaigi-usage-v1`, domain size `k = 12`, and one 25-row column: network 0–3, call
4–9, original host 10–15, pre-root 16–19, ledger segment 20, positive duration
21, billed gas 22, stored host C 23 and usage commitment U 24. Segment is u32;
other integer limbs are u64. It proves the same host C opening established by
host create. U binds this complete context and private opening. Core compares
every row against trusted state and the signed usage instruction.

Both families require the full canonical outer circuit ID, exact public-input
schema, canonical `OpenVerifyEnvelope`, empty auxiliary bytes, exact proof
column dimensions, and the matching compiled circuit/key geometry. A trailing
zero instance row is rejected. Governed keys must be active, include a gas
schedule and nonzero proof-size bound, and match the envelope key commitment.
`proofs.kaigi_authorization_vk` of the committed `zk_validity_policy_v1`
parameter selects the sole authorization key for all four actions;
`proofs.kaigi_usage_vk` selects the distinct usage key. Both are chain policy,
set in genesis or by an authorized `SetParameter`, never node configuration. Retired per-action
configuration and roster circuits are not aliases. Unit tests and production
use the same verifier; the mock-verifier feature has been removed.

## Lifecycle and ownership

A call's permanent identity is its genesis-derived network and canonical
`KaigiId`. Create rejects an existing call, including an ended call. Protected
native metadata cannot be overwritten or deleted through generic metadata
instructions, and the containing domain cannot be unregistered while it retains
that state. Reusing the call name cannot create a second proof incarnation.

Private create requires C, N, the empty roster root and a real host-create
proof. Host end requires the same stored host C and a distinct host-end proof
against the current root. A host signature alone does not replace either proof.
An active canonical rekey successor may exercise the original host's authority
with that private opening.

`KaigiRecord.private_participation` is a mandatory bounded ledger of complete
original `AccountId` values, current sequences and optional live commitments.
It is sorted by canonical account identity and validated against the complete
roster in both directions. A subject starts at sequence one, owns at most one
live C, and consumes its sequence on leave. The original account and advanced
sequence remain after departure. Rejoin uses the next sequence; rekeying or
alias reassignment cannot reset it. Join at the maximum sequence is rejected
so leave can always advance without overflow.

Join and leave must be signed by the instruction participant and its unique
registered active rekey endpoint. Core resolves that component to exactly one
retained original subject and rejects the host component. Leave verifies the
opening of the exact stored C, then removes it atomically and appends its
nullifier. The public roster and authoritative ownership map provide membership;
the circuit makes no hidden Merkle-path claim.

While the call is active, the derived account-dependency index retains the
original host, every original private subject including departed subjects,
transparent participants and pinned relays. Snapshot reconstruction includes
current and undo projections. Current restored private owners must resolve to
unique registered endpoints; independent components receive independent lineage
work bounds. End releases active dependencies while retaining permanent call
history. Full rekey/undo/lifecycle qualification remains a release gate.

## Bounds and accounting

V1 allows at most 4,096 concurrent participants, 4,096 retained private subjects,
8,194 action nullifiers, and 4,096 usage commitments. Counts are upper bounds:
the encoded record must also fit the 1-MiB protocol JSON ceiling and configured
metadata limit. History is never evicted to permit proof replay.

Admission reserves one nullifier for every live departure and one for host end.
Every active private record also reserves 256 JSON bytes per live departure and
256 for end. All record updates preserve those reservations; departure or end
releases its reservation. The budget covers the bounded scalar nullifier,
sequence growth and end timestamp/status. Usage duration, billed gas and segment
totals use checked arithmetic. Governance must consider retained active state
when changing storage limits; price policy and externally attested billing are
separate qualification requirements.

## Relay scope and remaining qualification

A manifest contains 3–8 unique ordered relays with positive weights and future
expiry. Relay descriptors require nonempty keys of at most 4 KiB and positive
bandwidth class. V1 bounds registry and allowlist membership at 500 identities;
restoration rejects an over-cap registry. Registration, rotation, health reports
and removal authenticate the relevant active account lineage. Exact repeated
descriptors produce no mutation event. A relay's registered HPKE key cannot rotate
or be removed while a live call references it. Host-authorized end releases the
call's live dependencies. Historical manifests remain self-contained after
retirement; future admission requires live registered descriptors.

The current opaque HPKE key carrier still needs its final explicit suite tag and
actual three-hop interoperability/transport recovery qualification. Circuit
and SDK unit results do not establish relay anonymity, hardware parity, an
external cryptographic audit, pricing/settlement assurance, or four-validator
release readiness. These gates remain open until their concrete evidence is
captured against the same final source and artifacts.
