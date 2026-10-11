# RAM-LFE semantic commitment design

Date: 2026-09-29. Status: proposed, not adopted. This record proposes a Poseidon
role table as the hash an execution relation would constrain. It does not enable
proof mode or qualify a cryptographic primitive. Both insecure BFV backends are
unavailable in production.

The commitments that code and validators use are the
[canonical V1 contract](ram_lfe_execution_proof.md#canonical-v1-contract):
Norito frames under fixed domains, Blake2b for public records and BLAKE3
derive-key for the private preimages. That contract is implemented and is
authoritative. Where this proposal differs from it, the contract holds:

- The V1 function identity binds the tape, program key, class, plaintext
  semantics and lifetime query limit only. It binds no chain, program or owner;
  the receipt binds those.
- The V1 policy has no verification mode and no resolver or attestation key. A
  signature over a receipt or an opening is not evidence, so every passage below
  that describes signed receipts or a signed opening describes the superseded
  design, not a mode to keep.
- The V1 receipt binds the beneficiary, the initialized memory and a replay
  nonce, which role 8 below does not. It identifies the network by its genesis
  hash, not by the chain label. Its initialized-memory commitment is blinded
  for each execution from the program key, so it confirms no guessed lanes.
- A V1 opening commits the 64 padded output slots, the ordered output followed
  by zeros, so the `output_count` of its ordered-output frame is always 64 and
  no output length reaches the opener or the recipient. Role 7 below takes a
  private `output_count`, and the text after the table says the resolver and
  the recipient see output lengths; under V1 neither holds.

Whether the relation constrains the V1 BLAKE3 frames or a Poseidon role table is
an [open construction question](ram_lfe_execution_proof.md#open-construction-questions)
owned by the execution-relation task. If a Poseidon table is adopted, it
replaces the V1 descriptor, frames and pinned vectors together. There is one
representation and no fallback reader.
The complete interpreter relation, resource qualification and independent review
remain [ZK03](zk_first_release_goals.md) acceptance requirements.

Encryption architecture gate: the current exact-residual construction uses
`q = 257 * 2^48` and plaintext-multiple errors. Reducing its public-key relation
modulo 257 removes that error, exposing the noiseless relation `b = -a*s` in
the plaintext ring. If a is invertible there, the residue of s is directly
recoverable; ciphertext relations must be audited under the same reduction.
This is a concrete algebraic leakage mechanism, not merely an uncompleted
security review. Route reachability and reproduction are being audited
separately. High-entropy program keys, commitments and zero-knowledge proofs
cannot repair encryption leakage. Do not optimize or adopt the full exact-BFV
relation as secure RAM-LFE until the encryption design is replaced and qualified.
The unused native Pasta and generic circuit experiments may proceed independently.

## Decision and parameter identity

Use original Poseidon with the exact upstream Pasta `P128Pow5T3` permutation:
width 3, rate 2, exponent 5, eight full rounds and 56 partial rounds. Use its
actual `ConstantLength<L>` sponge for the fixed-capacity records below. Do not
retain the repository's generated 8 + 57 instance merely to preserve outputs.
Do not call this algorithm Poseidon2.

The source pin is Zcash Halo2 commit
`68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b`. Its
[parameter specification](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/p128pow5t3.rs),
[Fp constants](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/fp.rs),
[Fq constants](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/fq.rs)
and [test vectors](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/test_vectors.rs)
are the parity references. Pin the constants, not just the round counts or the
name of a parameter generator.

Concatenate the 192 round constants in round-major order, followed by the nine
MDS entries in row-major order, each as a canonical 32-byte little-endian field
element. The resulting SHA-256 pins are:

| Field | Modulus | Parameter SHA-256 |
| --- | --- | --- |
| Fp | `40000000000000000000000000000000224698fc094cf91b992d30ed00000001` | `a9a13cf048dcb1fdc90989307b50514fc8454fc53853f704d4a5b395b9b98812` |
| Fq | `40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001` | `d9109b12201af2f77bbc633144d986007fcf290ada7bf51cbb1ba79172108a16` |

RAM-LFE uses Fp. Fq belongs to the separate paired-recursion migration below.
These moduli have 255-bit canonical representations, but their logarithms are
approximately 254. A single-field output and one-field capacity therefore have
approximately a 127-bit generic collision margin. The upstream name is not a
claim that this complete protocol supplies exactly 128-bit security. The
[Poseidon paper](https://www.usenix.org/system/files/sec21-grassi.pdf) gives the
sponge capacity bound and its length-dependent domain construction. Independent
review must assess this exact instance and composition, including current
[round-reduced cryptanalysis](https://eprint.iacr.org/2025/950); that work alone
does not establish a break of the full selected instance.

The upstream [sponge implementation](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/lib.rs)
initializes `[0, 0, L * 2^64]`, absorbs into coordinates 0 and 1, pads with zeros
only to an even length, and returns coordinate 0 after the final permutation.
There is no additional padding block for an even positive length. This differs
from the current Core helper's capacity-first, variable-length, one-then-zero
padding contract. Replacing only its round constants would not implement the
chosen hash. Every record below has positive compile-time length.

## Canonical semantic encoding

All arithmetic in this section is in Fp unless an integer bound is stated.
`u64le(s)` interprets an exact eight-byte ASCII string as a little-endian u64.
For role `r` and a fixed list of `n` payload fields, define:

```text
M = [u64le("IRAMLFE1"), u64le("PSTAFPV1"), r, n] || payload
H_r(payload) = P128Pow5T3::ConstantLength<4 + n>(M)
```

Each role below has one fixed arity. Neither a caller-selected domain nor a
generic variable-length hashing API is part of the protocol. Role and length
are absorbed data as well as being covered by the fixed-length sponge domain.
Role IDs are disjoint from every other protocol's full prefix. Cross-role
collision resistance remains a cryptographic assumption, not an assertion that
the field outputs cannot coincide.

Unsigned values are injected only after proving their integer bounds. A public
32-byte Iroha hash is represented by its low and high 16-byte little-endian
integers, in that order; each is below `2^128 < p`. Never reduce a 256-bit hash
modulo p. A semantic commitment has its own type containing a canonical
32-byte little-endian Fp representation. Strict decoding rejects values at or
above p. Do not use `Hash::prehashed`, its marker-bit convention, or a zero
sentinel. Zero is a valid commitment; absence uses an explicit option.

`ProgramKey` is a clearing owner for a uniformly generated, nonzero Fp element.
Explicit imports accept only a canonical 32-byte nonzero representation. They
cannot establish the caller's entropy; the default builder generates a fresh
key per policy. Arbitrary passwords, byte truncation and modular reduction are
not key import operations. The generic `RamLfeSecret` remains owned by the
separate HKDF/affine paths and is not an alias for this key. The implemented
`RamLfeProgramKeyV1` is 32 nonzero bytes with the same import rules; it is not
required to be a canonical Fp element, which this proposal would add.
The relation proves `K != 0`, for example with a constrained multiplicative
inverse; a native import check alone does not constrain the private witness.

### Public contexts and dependency order

Public hashing remains Iroha's canonical Norito/Blake2b hashing. These inputs
are already public and the verifier owns their derivation. Define exact new
Norito schema identities and field order for these records at implementation:

- `RamLfeSemanticContextV1`: chain ID, program ID, canonical domainless owner
  `AccountId`, backend and execution descriptor hash, in that order.
- `RamLfeMathParametersV1`: registered encryption parameters and public key,
  relinearization material, the fixed ordered Galois-key roles required by the
  [scalar-packing candidate](ram_lfe_plaintext_packing.md), and the complete
  execution/encoding profile. The earlier scalar diagnostic's no-Galois bundle
  is not this replacement schema. Authenticate exponents 5, 25, 625, 5601, 4033,
  3969 and 8191, with every selected level/basis variant and key-switch digit.
  Exact profile/key encoding, refresh/sanitization algorithms and any additional
  authenticated key roles remain unresolved. Reject undeclared material; a
  refresh mask is not a bootstrap. This candidate contract does not change the
  current diagnostic validator or enable encryption.
- `RamLfePublicParametersV1`: math-parameters hash and logical-function commitment.
- `RamLfeAuthorityContextV1`: semantic-context hash, policy commitment,
  full-public-parameters hash, resolver key, output-opening key and verification
  mode, in that order.

The descriptor commits this entire semantic grammar, parameter pins, canonical
field encoding, role table, exact initializer and interpreter profile. It is a
compiled value, not caller-selected transcript metadata. Math-parameters and
full-public-parameters hashes cover canonical validated values, not received
bytes or ambient Norito flags. Existing parameter and evaluation-key digest
algorithms remain canonical public hashes and are recomputed by the verifier.

Remove duplicated verification mode and arbitrary proof-verifier metadata from
the public math bundle. Attestation mode belongs once to the policy; compiled
relation/key admission belongs to the purpose verifier. This removes circular
dependencies between key selection, program commitment and initialization:

```text
key + semantic context -> private program blinder
blinder + tape -> stable logical-function commitment
math parameters + logical-function commitment -> full public parameters
logical function + semantic context + full public parameters -> policy commitment
key + logical-function commitment + associated-data hash -> initializer seed
```

Changing an attestation key or mode changes the authority context and receipt
statement, without changing the initialized function. Encryption/relinearization
keys change `Pmath`, `Pfull`, `Cpolicy`, ciphertexts and the receipt statement;
they do not change `B`, `Cfunction` or initialized plaintext lanes. The relation
still proves possession of the key and tape behind `Cfunction`, while native
policy admission and verifier-owned instances authenticate all current math keys.
The policy builder exposes an explicit encryption-key rotation operation that
preserves the registered profile and logical-function commitment. Changing the
program key, tape, semantic owner/context or execution profile is a separate
new-function operation with a new logical commitment. Correct BFV key admission
and output opening remain necessary to preserve plaintext semantics on rotation. `active` remains a
mandatory native state-admission check and is not part of function derivation.
The human note has no cryptographic authority. Every future policy field must
be classified explicitly; it cannot silently escape either context binding or
native admission.

### Fixed role table

In this table, `limbs(h)` means the two canonical hash limbs above. `K` is the
private program key; `S`, `A`, `Pmath` and `Pfull` are the public semantic-context,
authority-context, math-parameters and full-public-parameters hashes.

| ID | Output | Fixed payload, in order | Fields |
| ---: | --- | --- | ---: |
| 1 | Private blinder `B` | `K, limbs(S)` | 3 |
| 2 | Logical-function commitment `Cfunction` | `B, instruction_count, instruction[0..256]` | 258 |
| 3 | Policy commitment `Cpolicy` | `Cfunction, limbs(S), limbs(Pfull)` | 5 |
| 4 | Private seed `Z` | `K, Cfunction, limbs(associated_data_hash)` | 4 |
| 5 | Private initializer element `z_i` | `Z, i`, separately for `i = 0..31` | 2 |
| 6 | Input commitment `Cinput` | `Cpolicy, 64, input_coefficients[0..2048]` | 2,050 |
| 7 | Output commitment `Coutput` | `Cpolicy, output_count, output_coefficients[0..2048]` | 2,050 |
| 8 | Receipt statement `Cstatement` | `limbs(A), Cpolicy, Cfunction, limbs(parameter_digest), limbs(evaluation_key_digest), limbs(Pfull), Cinput, Coutput, limbs(associated_data_hash), executed_at_ms, expiry_present, expires_at_ms_or_zero, verification_mode` | 18 |

Slice notation in the table is end-exclusive and denotes that exact number of
fields. Instruction count is 1..256; output count is 1..64. Timestamps are u64,
expiry presence is Boolean, an absent expiry has value zero, and verification
mode has one canonical integer encoding (`Signed = 0`, `Proof = 1`). Proof
admission requires the latter. Native admission additionally enforces policy
activation, expiry ordering, current time and the existing replay rules.

All private arrays occupy their fixed maximum capacity. Counts are private
witnesses, not circuit shape choices. Inactive tape slots and unused output
slots are exactly zero. The public commitment thus binds a logical length
without exposing it in the proof shape. The resolver and recipient still see
the lengths they already receive in private program/output frames; this is not
a length-hiding transport claim.

### Instruction and coefficient packing

Keep the sole validated immutable hidden-program owner and its bounded typed
builder. Each active instruction has the current six canonical words from
`ram_lfe/program.rs`, but the semantic commitment packs the words as:

```text
instruction[j] = sum(words[j][i] * 2^(16*i), i = 0..5) < 2^96 < p
```

The relation proves each word fits 16 bits, tag 0..10, exact opcode-specific
register/input/state/scalar bounds and every reserved word is zero. Scalars
are 0..256. This representation is injective on valid tapes; a host-only
16-bit cast is insufficient. Fixed version/register/state metadata are supplied
by the descriptor and constrained profile. `instruction_count` distinguishes
an active all-zero instruction from padding. Wire serialization remains the
one canonical Norito frame; the semantic hash does not introduce a second
private wire format or bypass header/schema/checksum validation.

For ciphertexts, fix `q = 257 * 2^48 = 72,339,069,014,638,592 < 2^57`. Flatten
slots in ascending order, each slot's c0 then c1 polynomial, with coefficients
in ascending order. Every slot has exactly two degree-64 polynomials. Pack:

```text
packed[j] = sum(coefficient[4*j+i] * 2^(57*i), i = 0..3)
0 <= coefficient < q
0 <= packed < 2^228 < p
```

The input has exactly 64 slots (8,192 coefficients, 2,048 packed fields).
Output uses the same maximum capacity, with all coefficients past the private
output count constrained to zero. Range constraints and the linear packing
equations bind every coefficient; modular field equality alone is insufficient.
Canonical wire decoding occurs before this typed semantic operation. It still
rejects malformed, noncanonical or oversized ciphertext frames.

### Initializer reduction and canonicality

For each of the 32 fixed lane indices compute role 5, obtain the canonical
integer `x_i` represented by `z_i`, and set `lane_i = x_i mod 257`. The circuit
must decompose `z_i` into 32 range-proven little-endian bytes, constrain their
integer to be below p, and perform 32 fixed byte folds in reverse byte order.
The top byte can contain a bit at position 254; these are 255-bit canonical
values. A field equation `z_i = 257 * quotient + remainder` plus a quotient
bound alone can admit modular aliases and is prohibited. In particular,
`quotient <= floor((p - 1)/257)` and `remainder <= 256` still admit the integer p
for this modulus, represented as zero in the circuit field. Native
`to_repr()` canonicality does not prove circuit witness canonicality.

Require direct negatives for decompositions representing p, p + 1, maximum
quotient with an overflowing remainder, fractional byte witnesses and changed
lane indices. For an ideal uniform Fp element, `p mod 257 = 256`; the exact
statistical distance after reduction is `256 / (257*p)`, approximately
`3.441e-77`. This arithmetic fact does not prove that the keyed Poseidon
construction is a PRF. There is no private BLAKE3 XOF, rejection sampler or
caller-selectable initialization mode in the proposed contract.

## Statement ownership and disclosure

The purpose verifier accepts authoritative typed policy and receipt values,
not a raw instance array supplied by the prover. It derives `S`, `A`, `Pmath`,
`Pfull` and the registered public digests itself, validates canonical receipt
metadata, then derives `Cstatement`. It compares the commitments required by
the policy and request. Statement-root hashing never substitutes for proving
the tape, initializer or arithmetic relation.

The circuit also needs authentic evaluation-key coefficients. A root alone
does not bind a prover's chosen arithmetic key. The exact proposed internal
instance order is:

```text
[Cstatement,
 limbs(S), limbs(A), limbs(Pmath), limbs(Pfull),
 limbs(parameter_digest), limbs(evaluation_key_digest),
 Cpolicy, Cfunction, Cinput, Coutput,
 limbs(associated_data_hash), executed_at_ms,
 expiry_present, expires_at_ms_or_zero, verification_mode,
 packed_relinearization_key[0..160]]
```

This is 183 Fp values. The registered 12-bit decomposition has five key entries;
flatten each entry's b then a polynomial, ascending coefficient order, and pack
four coefficients per field using the same 57-bit construction. The verifier
derives these 160 values from the existing authoritative public key bundle.
The circuit unpacks, ranges and copies them into every relinearization. Hash
payloads copy the corresponding instance cells, rather than accepting unrelated
private copies. A changed policy key must change the instances and invalidate
the old proof. Optional native Fourier preprocessing may use only these already
public coefficients; its exact transform and instance schema require a separate
review before replacing the coefficient interface above.

No ciphertexts, tape, blinder, key or private initializer values become public
sidecars. Public instances add only derived forms of already public policy
material. Input/output semantic commitments replace their existing hashes;
they are deterministic and can reveal equality. They are not hiding
commitments for arbitrarily low-entropy ciphertext values. Existing ciphertext
randomness and encryption claims require their own qualification.

The program commitment is blinded because an unkeyed digest of a low-entropy
private tape supports offline guessing. `B` remains private and is derived
from a high-entropy key plus policy context. Domain separation does not supply
entropy. Reusing a key across policies invokes a related-context keyed-Poseidon
assumption; prefer a fresh key. Repeated identical key/context/tape intentionally
gives the same commitment. Neither blinding nor ZK hides information obtainable
from chosen execution queries or the externally opened result.

The canonical receipt replaces generic `Hash` program/input/output fields with
typed semantic commitments, adds `Cpolicy` and `Cstatement`, and removes the
duplicate `output_hash`. Its public canonical Norito bytes remain signed or
hashed outside the private relation. Identifier `opaque_id` must derive from a canonical typed public record of the
stable logical-function commitment and authenticated opened-plaintext hash,
under a new identifier-specific domain. The stable identifier binding must not
include policy/encryption keys or ciphertext commitments. Execution receipt IDs
separately hash the complete canonical policy-bound receipt. The current
identifier helper
`identifier_hashes_from_output_hash` already consumes an externally opened
plaintext hash in Torii; preserve that semantic boundary and make its logical
function context explicit. Do not feed `Coutput` into the plaintext identifier
operation or conflate a stable identifier binding with an execution receipt ID.
The signed output opening must bind `Cfunction`, `Cpolicy`, `Cstatement`,
`Cinput`, `Coutput`, parameter/evaluation-key digests and the current authority
context, alongside its plaintext hash, opening timestamp and expiry. The
verifier checks that exact execution receipt and the current opening-authority
key. A valid execution proof alone cannot authorize the plaintext claim.
Execution proofs do not prove decryption or replace the separately trusted
opening authority; a dishonest authorized opener remains inside that explicit
trust boundary. Signed and proof evidence remain separate types/trust modes.

## Capacity evidence and remaining arithmetic

Word and byte prototypes remain isolated primitive implementations, including
constrained BLAKE3 compression. They establish no normal Core build, complete
execution relation or proof-mode admission.

For the role table above, upstream fixed-length padding requires:

| Work | Permutations |
| --- | ---: |
| Private program blinder | 4 |
| Logical-function commitment | 131 |
| Policy commitment | 5 |
| Initializer seed | 4 |
| 32 initializer elements | 96 |
| Input commitment | 1,027 |
| Output commitment | 1,027 |
| Statement | 11 |
| **Total** | **2,305** |

Adapting the existing native-round architecture to 64 rounds plus an endpoint
row gives 149,825 round rows. Four ideally balanced permutation lanes require
37,505 rows before bridge/absorption/packing/range work. This is a source-based
estimate, not synthesized 56-round geometry. The existing
`zk/pasta_native_poseidon.rs` supports at most two lanes: its measured 57-round
two-lane geometry uses seven advice columns, five fixed columns, degree seven,
no lookups, one equality bus, six blinding rows and nine minimum rows. Its
current advice queries cover 24 column/rotation pairs. Changing 66-row jobs to
65-row jobs changes endpoint bridge rotations and must be measured again.
Two explicit two-lane groups are a candidate; silently raising `MAX_LANES` is
not a layout design.

Existing FlexGate absorption/output plumbing adds approximately 25,355 cells
for these 2,305 permutations, before hash input packing. Four-term dynamic
packing costs 13 assigned cells per pack (53,248 for both ciphertexts); six-term
tape packing costs 19 cells per instruction (4,864). Range and private-count
constraints are additional. A custom linear packing gate could reduce this,
but no such measured implementation is claimed here.

BFV remains the main feasibility risk. The earlier straightforward FlexGate
FFT composition estimates 80,412,672 cells before range/routing/hash work. At
k = 16 this already requires at least 1,227 advice columns; its four queried
rotations imply at least 235,584 proof bytes before other commitments. This
estimate even omits the interpreter's final multiply by encrypted constant one
inside exponentiation. It therefore cannot qualify the 192 KiB proof cap.

A custom butterfly gate can express `out0 = u + twiddle*v` and
`out1 = u - twiddle*v` using four advice cells and fixed twiddles. A 64-point
transform then has 192 butterflies/768 cells before routing, with negacyclic
twist/scale folded into boundary gates only after proving equivalence. The
candidate schedule retains intermediate c0/c1 frequency values, reconstructs
and ranges c2 before five-digit relinearization, then reconstructs the final
two outputs. Ten transforms per square and twelve per general multiply are
an architectural estimate, not synthesized cost. All signed integer lifts,
quotient/remainder bounds, no-wrap proofs, depth, initialized reads, selector
evaluation, state/register routing and output order remain mandatory. Host
FFT callbacks or field-only modular equations cannot replace these constraints.

Current config defaults remain k <= 16, proof bytes <= 192 KiB, total Norito
envelope <= 1 MiB and a 20 ms soft verification budget
(`iroha_config/src/parameters/defaults.rs`, `zk::halo2`). There is no new public
sidecar. Use checked total-length arithmetic and reject configured `max_k`,
envelope, proof, key and instance limits before parsing, allocation, parameter
construction or MSM work. Public policy preprocessing is bounded and cached by
canonical policy identity; the proof cannot supply replacements. Prover time,
peak memory, verifier latency and full proof/envelope sizes must be measured
on the maximum complete circuit. No full-budget success is established here.

## First-release ownership and developer API

The lowest suitable existing owner is `iroha_zkp_poseidon`; do not add a crate
or make crypto depend on Core/Halo2 circuit machinery. Store the pinned Fp/Fq
canonical parameter bytes once and provide narrow field-specific native
operations. Its current `halo2curves` Pasta types and Core's vendored
`pasta_curves` types are distinct Rust types; strict canonical-byte parity must
be tested rather than assuming a type alias or reducing bytes. Circuit adapters
must consume the same parameter source, with no independent generator choice.

Application developers use the typed program builder, a generated `ProgramKey`,
one policy builder and typed encrypted input/output owners. Replace the generic
`EvalResponse` surface/doc claiming every backend returns plaintext: programmed
execution returns a typed ciphertext output, and authenticated opening returns
a separate typed plaintext result. The policy builder
computes every context, program commitment and descriptor internally. Remove
the standalone unkeyed `HiddenRamFheProgram::digest` path on adoption. A purpose
verifier consumes policy plus receipt and returns typed signed/execution
evidence. A distinct verified-opening type authorizes an opened output. A
high-level resolve facade can perform both stages and return a resolved
identifier only after both pass; it never silently uses a ciphertext hash or an
unverified opening. The API does not expose generic hash domains, circuit IDs, field elements,
instance arrays, proof-mode fallback or caller-provided verification keys.
Native SDK endpoints own computation and admission; managed SDKs expose typed
canonical metadata without recreating cryptographic hash implementations.

Preserve the current bounded clearing tape, shared redacted clone, explicit
private codec and clearing serialization. Add exact clear-on-success/error/
unwind tests for the key, seed, blinder, packed tape and owned prover witness
buffers. Do not claim erasure of caller-owned instruction copies, compiler
temporaries or opaque Halo2 allocations without evidence. Deterministic native
batching is the first acceleration boundary; any Metal/NEON/SIMD/CUDA path must
consume the same constants and pass byte-for-byte parity with the scalar path.
No accelerated production capability is implied by this design.

## Separate global 57-round hard cut

Adding an unused native primitive candidate does not authorize changing existing
admitted circuits. Inventory and regenerate the complete affected family in a
separate coherent cut, after current frozen builds finish. There must be no
parallel accepted 57/56 layouts, legacy decoder, alias or fallback.

| Current source | Affected behavior |
| --- | --- |
| `zk/kagemusha_v1_poseidon.rs` | Fp/Fq generated 8 + 57 commitments and native/circuit sponge helpers; current comments claiming reviewed 128-bit security also need correction |
| `zk/pasta_native_poseidon.rs` | 65-round permutation jobs, endpoint bridges, KATs and native layout/proof geometry |
| `zk/kagemusha_v1_recursion/mod.rs`, `deferred_parent.rs` | Recursive IPA Poseidon transcript parameters and dependent protocol/key identities |
| `zk/pasta_cycle_loader.rs` | Explicit `new::<8, 57, 0>` verifier transcript construction |
| `zk/confidential_v2.rs` | Fp/Fq confidential commitments, Merkle roots and admitted transfer/unshield circuit keys |

Follow transitive consumers through Kagemusha sparse Merkle/state/replay roots,
empty-tree constants, native jobs, deferred-parent/claim-fold transcripts,
Apple/KeyMint leaf and recursive parents, protocol hashes, admission registries,
PK/VK generation, cached keys, encoded fixtures, genesis/restoration and SDK
metadata. Confidential circuit families currently include
`confidential-transfer-2x2-merkle16-axiom-poseidon-v3`,
`confidential-unshield-full-merkle16-axiom-poseidon-v3` and
`confidential-unshield-change-merkle16-axiom-poseidon-v4` under `halo2/pasta/ipa/`.
Choose one final canonical circuit/profile naming scheme for the first release;
these existing v3/v4 names are inventory facts, not a compatibility obligation.
Do not add v5 alternatives while accepting old identifiers. Retired IDs, keys
and roots must reject, and the final ABI remains V1. Their old keys and roots
cannot be relabeled as qualification of the replacement.

For each hash role, choose the exact new sponge framing and regenerate all
roots. Fiat-Shamir transcripts require an explicit transcript contract and
native/circuit parity; they are not automatically `ConstantLength` record
hashes. One canonical permutation source may serve these distinct, explicitly
framed roles. Regenerate every dependent key, protocol digest and transcript
fixture together and reject the retired artifacts at admission/restoration.

Do not replace unrelated occurrences of 57. The Goldilocks digest in
`fastpq_isi/src/poseidon_digest384.rs` uses a different field, exponent and
multi-lane construction; `iroha_zkp_halo2` resource assertions referring to it
are outside this Pasta parameter cut.

### BN254 naming correction is a distinct change

The leaf now names its original BN254 permutation accurately. The exported
`Bn254PoseidonParams` and `bn254_poseidon_params_width3/6` replace the misnamed
Poseidon2 parameter API, with no aliases. GPU parameter staging and the AXT
fixture generator use the new exports. Private two/six-input helper names
explicitly describe arity. The dense MDS, generated constants, byte framing,
field arithmetic and existing output fixtures are unchanged.

The [Poseidon2 paper](https://eprint.iacr.org/2023/323) and
[authors' implementation](https://github.com/HorizenLabs/poseidon2) describe a
different permutation and linear layers. This correction does not select those
algorithms or establish independent security qualification. Existing IVM opcode
mnemonics, numeric assignments, compiler lowering and hardware kernels retain
their arithmetic contract; a separate ABI surface change requires its own
canonical specification and golden updates.

The parameter-byte digests are derived independently from the existing AXT
capture, and the leaf has positive typed API and retired-name compile-fail
controls. All 19 native controls and four documentation tests pass on the frozen
ordinary build; actual GPU parameter staging and AXT fixture-generator consumers
also compile. These API controls do not qualify hardware execution or a complete proof protocol.

## Smallest next implementation and acceptance gates

1. The unused leaf candidate for the pinned Fp/Fq permutation and exact upstream
   fixed-length sponge is implemented; its ordinary native suite passes 18/18
   controls.
   It pins source provenance, canonical parameter
   fingerprints and all upstream permutation/`ConstantLength<2>` vectors.
   Independently check odd/even fixed lengths, domain/length separation and
   strict scalar decode at 0, p - 1, p and p + 1. Compare bytes across the leaf
   and Core field libraries. This first step changes no production contract.
2. The private test-only circuit candidate uses the same constants and exact
   sponge. Its test controls cover arbitrary-field round/input/copy/padding mutations, genuine proof
   tampering/wrong-instance controls, clearing and measured 56-round geometry.
   The paired-partial layout passes ten isolated controls. Its maximum single
   hash uses 40,062 total rows at the unchanged k=16 cap and yields a 2,688-byte
   genuine IPA proof. Verification takes 238.840 ms, above the unchanged 20 ms
   soft budget. Normal Core integration and the complete bounded relation remain
   unqualified. Keep admitted helpers unchanged until their separately
   inventoried replacement is complete.
3. Review the complete semantic role/key/privacy design. Then implement one
   native RAM path and all policy/config/data-model/Torii/Core/SDK migrations,
   regenerate descriptor/KAT/receipt/opening fixtures, and delete the replaced
   BLAKE3/private-wire-hash contracts. HKDF/affine semantics stay separately
   owned; no old programmed mapping remains accepted.
4. Implement the complete arithmetic/routing relation and maximum-profile
   resource controls. Test every semantic field, policy/key/context swap,
   private length/padding word, modular alias, opcode, register/state transition,
   evaluation-key coefficient and output ordering with adversarial witnesses.
   Qualify native interpreter/circuit equality over generated valid programs.
5. Deliver the independent cryptographic review, parameter/framing/PRF review,
   integer-lift argument, replacement encryption with its tests, full native
   proof and network/SDK execution controls. These are implementation
   requirements of the change that replaces the refusal. The V1 policy has no
   proof mode to admit: no activation step, qualification record or approval
   stands between the implemented relation and its use.

Rekey acceptance must include two independently valid BFV encryption and
relinearization bundles for the same fixed profile. Holding program key, tape,
semantic context and associated data constant must preserve `B`, `Cfunction`,
initialized plaintext lanes, authenticated opened output and opaque identifier,
while the ciphertext-policy commitment and execution receipt change. Changing
the program key, tape or semantic profile must follow the explicit new-function
operation. Attestation-key rotation must preserve the function while invalidating
old-context evidence at current-policy admission. Negative controls must swap an
opening between different receipts/policies, alter its ciphertext or plaintext
hash, use the wrong opening key, swap relinearization coefficients while keeping
the old digest, and replay an old proof against updated public instances. A
signature from the configured trusted opener remains an attestation, not a
proof that its claimed plaintext decrypts the ciphertext.

TODO: the native leaf and test-only circuit are unused candidates; the semantic
contracts and complete relation described here are not implemented. The
fixed-length role design needs independent review of
injectivity, collision and hiding assumptions, key reuse, initialization bias,
Fiat-Shamir separation, proof soundness and the unchanged disclosure boundary.
Existing primitive use, upstream naming, mock satisfaction and source estimates
are not substitutes for that review or maximum-profile measurements.

Design calculations, pinned upstream snapshots and the exact source inventory
are retained under ignored
`dist/zk-remediation/2026-09-29/ram-lfe-circuit/semantic-design/`.
Its public Python reference audit reproduces all 44 pinned upstream vectors
(11 permutation and 11 fixed-length hash vectors for each field) and both
parameter fingerprints. This checks extraction and the design's sponge
interpretation; it is not native implementation or circuit qualification.
