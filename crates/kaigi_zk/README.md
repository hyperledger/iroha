# Kaigi authorization and usage V1

`authorization_v1` defines one fixed native PIPA-R relation over Pasta Fp. The circuit
identifier is `pipa-r/pasta/kaigi-authorization-v1`, public-input schema is
`kaigi-authorization-v1`, and domain size is `k = 13`. The native frontend
uses checked assignment offsets; the circuit reserves 5,774 disjoint rows.

The sole instance column has exactly 31 rows:

| Rows | Meaning |
| --- | --- |
| 0–3 | Exact network bytes, four little-endian u64 limbs |
| 4–9 | Six canonical Goldilocks limbs of the call identity |
| 10–15 | Six canonical Goldilocks limbs of the host identity |
| 16–21 | Six canonical Goldilocks limbs of the subject identity |
| 22 | Ledger-owned participation sequence |
| 23 | Closed action: HostCreate 0, Join 1, Leave 2, HostEnd 3 |
| 24–27 | Exact authenticated pre-roster root, four little-endian u64 limbs |
| 28–30 | Stable commitment C, deterministic nullifier N, authorization A |

All network, root, identity and sequence limbs have 64-bit circuit constraints.
Every identity limb additionally satisfies `x < 0xffffffff00000001`. Host
actions require subject equal to host in every limb and sequence zero.
Participant actions require a distinct subject and a positive sequence. A
nonzero full Pasta scalar is the private blinding; no reduced u64 secret or
arbitrary nullifier seed is accepted.

Let `I` be rows 0–22 and `b` the private blinding. The fixed payloads are
`C = sponge_C(I || b)`, `N = sponge_N(I || action)`, and
`A = sponge_A(I || action || pre_root[4] || C || N || b)`. C is stable between
Join and Leave within one participation; N is independent of the blinding.
Every public context row is absorbed inside the relation.

RP56 round constants and the MDS matrix come from `iroha_pasta::poseidon::grain`;
all 201 field elements are checked against the dev-only independent generator.
The parameter bytes and circuit identities are unchanged.

Each sponge uses width three, rate two, x⁵ S-box, eight full rounds and 56
partial rounds with the crate's pinned Poseidon parameter generator. The initial
state is `[0, 0, domain]`, with domains `0x4b41494749563143` (C),
`0x4b4149474956314e` (N), and `0x4b41494749563141` (A). Its rate frame is
`[payload_scalar_count, payload..., 1]`, followed by one zero only when needed
for an even word count. Each pair is added to the rate coordinates and followed
by the complete permutation. The output is state coordinate zero. C/N/A use
exact canonical 32-byte Pasta representations; they do not use Hash marker
packing.

Core must authenticate the network, canonical identities, permanent call
namespace, pre-state and participation sequence, check exact signed authority,
and maintain active commitments and consumed nullifiers. This circuit does not
prove membership in a hidden Merkle tree. Ledger checks must also reserve
sequence and nullifier capacity for future leaves and host termination.

Core's verifier registry selects this fixed circuit and `k = 13`, compares the
packaged verifier key with the compiled constraint system, and requires exactly
one 31-row instance column. Retired roster circuit identifiers have no admission
entry. Generic `pipa-r/pasta` and the exact authorization registry label use the
same authenticated outer-envelope and canonical-key checks. The canonical Norito
`NativePipaRProofV1` contains one ordered vector of canonical 32-byte field values
and the exact native transcript. Registered keys use Core’s canonical Norito `CompiledVerifyingKeyV1`, containing
the complete compiled descriptor and processed key bytes, with curve `vesta`.
The descriptor binds the transcript, parameter identity and typed public schema;
processed key bytes alone cannot distinguish those properties and are rejected.
Verifier initialization constructs only the pinned descriptor and verifying key.

`KaigiAuthorizationWitnessV1::take_blinding` securely clears its caller-owned
32-byte input on success and failure. Owned witness storage, and named CPU
sponge state/payload storage, are erased with volatile-write/fence cleanup.
Debug output redacts the witness. The native prover consumes witness advice buffers. Compiler/register temporaries
and transient field-operation storage are outside this erasure guarantee. Callers must
sample a nonzero scalar using a cryptographically secure full-field sampler.

The implementation has focused native constraint adversarial tests and a real PIPA-R
roundtrip with every public row mutated. These are local correctness evidence,
not independent cryptographic audit or hardware qualification. The reference
framing is also checked against the dependency's separate Poseidon permutation.
No GPU proof execution is claimed here.

## Final usage relation

`usage_v1` uses full canonical circuit ID `pipa-r/pasta/kaigi-usage-v1`, schema
`kaigi-usage-v1`, and `k = 12`. It reserves 4,037 absolute assignment rows and
accepts one column of exactly 25 public scalars:

| Rows | Meaning |
| --- | --- |
| 0–3 | Network bytes as four u64 limbs |
| 4–9 | Complete call identity digest |
| 10–15 | Complete original host identity digest |
| 16–19 | Authenticated pre-roster root as four u64 limbs |
| 20 | Ledger-owned u32 segment counter |
| 21–22 | Positive u64 duration and u64 billed gas |
| 23–24 | Stored host C and usage commitment U |

The prover must open the same host C established by authorization V1: identical
network/call/host identity, subject equal to host, sequence zero, and the same
nonzero full-field blinding. Both circuits call one commitment construction and
share the frame, permutation and range gadgets. U uses domain
`0x4b41494749563155` and payload `rows[0..23] || C || blinding`, with the same
length/terminator/rate-padding contract. All 12 identity limbs are canonical
Goldilocks words; the segment is constrained to 32 bits, and the remaining
context limbs to 64 bits. U and C use raw canonical Pasta encodings.

Core requires the full canonical CID for both authorization and usage envelopes
and verifier records. Short circuit names and dispatcher keys are not accepted
as those wire fields. Usage selects its new compiled key, `k = 12`, and exact
1×25 shape; the earlier one-output, `k = 8` usage relation has no admission path.
The ledger must compare C with the stored host commitment and authenticate the
current segment and metrics. The proof binds those metrics; it does not attest
an encrypted log or independently measure off-ledger traffic or gas.

Only the final authorization and usage APIs are exported. Retired roster
circuits, single-output usage circuits, seed-u64 helpers and scalar/Hash marker
conversions are absent. The Core ledger and SDK adapters must be verified
together against this compiled source; runtime deployment and independent
audit evidence remain separate release requirements.
