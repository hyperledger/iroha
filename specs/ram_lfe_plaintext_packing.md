# RAM-LFE scalar packing over F257

Date: 2026-09-29; RNS-BGV section added 2026-10-05. Status: public algebra
candidate, no encryption profile selected or enabled. The encoding is
implemented for every ring degree and measured against a fully splitting
modulus in the [RNS-BGV section](#rns-bgv-instantiation-and-measured-comparison).
This refines the packing question in the
[replacement plan](ram_lfe_encryption_replacement.md). It changes no production
code, security claim, admission limit or proof relation.

## A fixed scalar subalgebra

For the illustrative ring `R = F257[x]/(x^4096+1)`,
`257^k = 1+256k mod8192`, so the multiplicative order of 257 modulo 8192 is 32.
The finite-field cyclotomic factorization theorem therefore gives 128 distinct
irreducible factors of degree 32. The theorem and factor count are stated in
[Mathlib's cyclotomic factorization source](https://leanprover-community.github.io/mathlib4_docs/Mathlib/RingTheory/Polynomial/Cyclotomic/Factorization.html).
This agrees with the general extension-field slot model documented by
[HElib](https://ibm.github.io/fhe-toolkit-linux/html/helib/classhelib_1_1_ptxt.html);
it is not a claim that SEAL's BFV `BatchEncoder` supports these parameters.

The following explicit encoding is a derivation for this ring. Fix `zeta=3` in
F257, whose order is 256, and `beta_j = zeta^(2j+1)` for `0 <= j < 128`. Then

```text
x^4096 + 1 = product_j (x^32 - beta_j)
R = product_j F257[x]/(x^32-beta_j) = product_j F_(257^32)
```

Each root of `x^32-beta_j` has order 8192, hence minimal polynomial degree 32;
the degree-32 factor is irreducible. The factorization follows by substituting
`y=x^32` in the split polynomial `y^128+1`. Embed a scalar `v_j` as the constant
element of each factor field. All 128 scalars can then be encoded as

```text
encode(v) = g(x^32),       degree(g) < 128
g(beta_j) = v_j
g_k = (1/128) * sum_j v_j * beta_j^(-k) mod257
decode(g)_j = sum_k g_k * beta_j^k mod257
```

Only 128 coefficient positions, the multiples of 32, can be nonzero. This is an
injective ring embedding of `F257[y]/(y^128+1)` into `R`, so componentwise addition,
subtraction and multiplication preserve scalar F257 semantics. There is no need
to increase the plaintext modulus merely to obtain scalar packing.

The scalar subalgebra is exactly the Frobenius-fixed part: `m^257=m`. Every
multiple-of-32 monomial is fixed; each other monomial's Frobenius orbit contains
its negative, forcing its coefficient to zero in odd characteristic. This also
gives a direct encoding/well-formedness condition, independently of a library
slot numbering convention.

## Selection, movement and output disclosure

For admitted scalar slots, `1-c^256` is one exactly when `c=0` and zero otherwise.
The existing eight squarings, final multiply by one and branch multiplication
therefore implement `SelectEqZero` componentwise without changing its F257
semantics. This statement does **not** hold for arbitrary extension-field slots.
For example, the nonzero element `c=x` in `F257[x]/(x^32-beta_0)` has
`c^256=beta_0^8 != 1`; its purported zero indicator equals 122. A decoder accepting
arbitrary ciphertexts cannot assume that their unknown plaintext is scalar.

Admission must establish the encoded plaintext's subalgebra membership, byte and
length ranges, and zero unused slots. A client can possess plaintext/encryption
coins for an input well-formedness proof; the evaluator generally cannot supply
that witness. Select and review this separate input-admission mechanism and its
binding to the execution statement, rather than silently requiring the evaluator
to know the client's plaintext. Similarly, trusted policy must authenticate
appropriate key material; shape checks alone do not establish its security.

The current tape accesses independent scalar inputs/registers, not a uniform SIMD
program. One possible adapter keeps scalar intermediate values broadcast in all
128 slots. Loading input slot `j` first multiplies by the public algebra's fixed
idempotent `e_j=encode(one_hot_j)`, then sums its orbit. On the scalar subalgebra,
automorphisms `x -> x^a` act as the permutation
`j -> ((a*(2j+1)-1)/2) mod128`. The exponents
`5,25,625,5601,4033,3969,8191` support seven doubling additions that broadcast a
single selected scalar. Actual encrypted rotations need seven authenticated
Galois/key-switch keys and incur their full noise, work and proof costs. The
hidden input index and choice of mask must be constrained inside the private
execution relation; this algebra does not provide an uncosted random-access gate.

Outputs can be assigned to fixed slots by idempotent masks and summed into one
packed plaintext. Force every undeclared output slot to zero and prove the masks
and order. Masking plaintext slots does not sanitize ciphertext noise or establish
hidden-function privacy. The opening authority must authenticate only the exact
declared output sequence and context, with no alternate decode of extension-field
coordinates. Function identity and rekey stability still follow the semantic
commitment design.

## Noise, representation and proof costs

Centered coefficients of a generic encoded scalar vector are bounded by 128 and
have at most 128 nonzero positions, giving an `l1` bound of 16,384. A single-slot
idempotent has all 128 centered absolute coefficient magnitudes `1..128`, so its
exact `l1` norm is 8,256. Under the elementary convolution inequality,
`||e_j * noise||_infinity <= 8,256 * ||noise||_infinity` before any additional
modulus/rounding contribution. Plaintext masking is therefore not a unit-cost
scalar multiply with negligible noise. Slot broadcast adds seven key switches
and additions. The planner must derive bounds for the complete selected BFV-RNS
algorithm; these public polynomial norms are only inputs to that derivation.

Ciphertext components and errors still live in the full degree-4096 ring. Do not
compress ciphertext coefficient arrays to the 128 sparse plaintext positions or
substitute 128 for the ring dimension in ciphertext multiplication/noise terms.
The plaintext embedding also does not authorize sampling keys or encryption
randomness from that smaller subalgebra; their reviewed distributions stay
separate from message encoding.
For illustration only, two components with two 64-bit RNS limbs consume 131,072
bytes per ciphertext before framing, versus 8,388,608 bytes for 64 such separate
ciphertexts. Two limbs are not a recommended or qualified modulus. Evaluation
keys, masked/broadcast intermediates, input admission, output packing and the
complete proof may still exceed current budgets.

Pin root choice, slot order, plaintext coefficient representatives, sparse
embedding, ciphertext residue order and exact bounded Norito framing as one
profile contract if this design is adopted. Each residue still requires canonical
range checks; no alternate sparse ciphertext decoder or extra public sidecar is
introduced. Input admission and execution must share the same encoding identity.
The full relation must constrain the transform, slot masks, automorphisms, key
switches, output-zero policy and all ordinary BFV arithmetic. Recompute complete
rows/cells/lookup, proof/envelope and memory costs; the prior degree-64 estimate
does not qualify this representation.

## Evidence and next decision

`dist/zk-remediation/2026-09-29/ram-lfe-encryption-replacement/packing-algebra.json`
records public integer/F257 checks: order/factor facts, all 128 basis roundtrips,
four mixed product/selection vectors, all 257 scalar zero indicators, all 128
fixed broadcasts, an extension-field counterexample and output masking. Its
companion script generates no key or ciphertext and performs no encryption,
decryption or recovery experiment. The test matrix fingerprint is not a wire
profile commitment or an independently reviewed cryptographic artifact.

The unused Rust [plaintext candidate](../crates/iroha_crypto/src/fhe_bfv/plaintext_packing_candidate.rs)
now implements clearing fixed-size scalar/coefficient owners, transforms, masks,
plaintext ring arithmetic and automorphisms under `cfg(test)`. Its exact-source
isolated Cargo harness passes seven native controls and strict Clippy, including
the independent vector, canonical bounds and observed live-cell erasure on
success, error and unwind. Evidence is retained in
`dist/zk-remediation/2026-09-29/ram-lfe-plaintext-candidate/20260929T110759Z/`.
The first attempt's native passes and one formatting-idiom Clippy failure remain
separate. Normal whole-crypto integration is pending; this module defines no
encryption, wire frame or supported profile.

Prefer evaluating this fixed F257 scalar packing before changing plaintext
semantics. It resolves an algebraic packing obstacle, not the replacement's
parameter, noise-depth, circuit-privacy or proof-capacity gates. The comparison
of one complete masked and broadcast `SelectEqZero` against a fully splitting
modulus has been measured on the RNS-BGV starting candidate (next section);
maximum-shape programs, the parameter review and every proof are still open.
Production remains unavailable until all replacement-plan milestones pass.

## RNS-BGV instantiation and measured comparison

Task C.3 implemented the encoding in
[`iroha_fhe::bgv::SlotEncoding`](../crates/iroha_fhe/src/bgv/encoding.rs) for any
plaintext prime and ring degree, and measured it. This section states what the
code does and what the host measured; it selects no profile.

**One encoding, two cases.** Let `S` be the largest power of two with
`t = 1 (mod 2S)` and `S <= N`, `zeta` the primitive `2S`-th root
`g^((t-1)/2S)` for the smallest `g >= 2` that makes it primitive, and
`Y = X^(N/S)`. A slot vector is the polynomial `g(Y)`, `deg g < S`, with
`g(zeta^(2j+1)) = v_j`.

- `t = 257`: `S = 128` at every `N >= 128` and `zeta = 3`, the encoding of the
  first section with stride `N/128` (128 at `N = 2^14`, 512 at `N = 2^16`).
  The illustrative `N = 4096` constants above are that case with stride 32.
- `t = 1 (mod 2N)`: `S = N`, ordinary fully split batching. At `N = 2^16` the
  smallest such prime is 786,433.

`F257` does not embed into the slots of another prime: a larger `t` is another
plaintext language, not a faster encoding of this one.

**Movement.** `X -> X^a` moves slot `pi(j)` to slot `j` with
`2*pi(j) + 1 = a*(2j+1) (mod 2S)`. One selected slot is broadcast by
`log2(S)` steps `x <- x + x(X^g)`, `g = 5^(2^i) mod 2N` for
`i < log2(S) - 1` and then `g = 2N - 1`: seven key switches for `F257`,
sixteen for 65,536 slots. Each needs its own Galois key.

**Masks.** The idempotent of one slot has coefficients `S^-1 * zeta^(-(2j+1)k)`.
Its centered `l1` norm is the same for every slot: 8,256 for `F257` and
12,903,442,129 for `t = 786433` at `N = 2^16`. A plaintext multiplication
multiplies the public noise bound by that norm, so a mask costs 14 bits for
`F257` and 34 bits for the fully splitting prime. Masks are built without
branching on the slot index, which may be hidden.

**Scalar-subalgebra check.** For `F257` a plaintext is a slot vector exactly
when every coefficient off the stride is zero: `N - 128` zero conditions plus
128 range conditions, against `N` range conditions for a fully splitting
prime. `SlotEncoding::decode` enforces it on a plaintext. An evaluator cannot
see the plaintext, so admission needs the client's proof of this predicate
(task R.11). That proof does not exist. Two things stand in for it here: the
measurement below times the plaintext-side predicate, and the following table
projects the size of the proof relation for both encodings.

**Input proof relation (projection).** Layout assumed, which task R.11 may
replace: the witness is the ternary mask, the two errors and the slot
scalars. Per main prime the relation transforms the mask, multiplies it
point-wise by the two public-key components and transforms both products back
(three transforms and `4N` further residue multiplications), then checks the
two ciphertext equations coefficient by coefficient. The plaintext is tied to
its slots by one inverse slot transform modulo `t`. Every residue
multiplication is range-checked through a quotient and a remainder in 16-bit
limbs over a 64-bit proof field.

<!-- fhe-bgv-input-proof-projection:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Projected quantity of the input relation | F257 sparse, 22 primes | t = 786433, 25 primes | batching / sparse |
| --- | ---: | ---: | ---: |
| Mask and error coefficients range-checked | 196,608 | 196,608 | 1.00 |
| Plaintext slots range-checked | 128 | 65,536 | 512.00 |
| Plaintext coefficients fixed to zero by the encoding | 65,408 | 0 | 0.00 |
| Butterflies of the slot transform | 448 | 524,288 | 1170.29 |
| Bits of the slot-transform modulus | 9 | 20 | 2.22 |
| Ciphertext coefficient equations | 2,883,584 | 3,276,800 | 1.14 |
| Residue multiplications over the chain | 40,370,176 | 45,875,200 | 1.14 |
| 16-bit limb products | 645,923,264 | 736,100,352 | 1.14 |
| Range-checked 16-bit limbs | 326,042,624 | 372,637,696 | 1.14 |
| log2 of the rows at one multiplication per row | 25.27 | 25.47 | 1.01 |
| Range-checked limbs that depend on the encoding | 1,024 | 2,162,688 | 2112.00 |
| Their share of all range-checked limbs (parts per million) | 3 | 5,803 | 1934.33 |
<!-- fhe-bgv-input-proof-projection:end -->

- The encryption relation dominates both: it is the same for either encoding
  and grows with the number of primes. The table uses the chains of the
  measured workload below: the 22 main primes of the bounded candidate and
  the 25 of the fully splitting comparator.
- What depends on the encoding is small beside it: 128 range-checked slots
  and a 128-point transform modulo 257 against 65,536 slots and a
  65,536-point transform modulo 786,433. For `F257` the `N - 128` zero
  conditions are structural: those coefficients are not witness cells.
- At one multiplication per row either relation is about `2^25` rows. That is
  a size, not a measured proving time; no prover for it exists.

**Equal workload.** The same instructions ran over both encodings at
`N = 2^16`: encode and check a 64-slot input, encrypt, two `LoadInput`s (mask,
broadcast, modulus switch), one `SelectEqZero` (exponentiation to `t - 1`, the
multiplication by the embedded one of the V1 tape contract, the indicator and
the select multiplication), two masked outputs, the unused-output zeroing
mask, decryption and decoding. Each chain is the shortest on which the
worst-case noise rules admit the workload: 13 of the bounded candidate's 22
main primes for `F257` (the run used all 22), and 25 sixty-bit main primes
with three special primes for `t = 786433`. Times are single-threaded on the
scalar path, measured with `iroha_measurement` under
`scripts/zk_resource_harness.py`:

<!-- fhe-bgv-encoding-comparison:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Part of the equal workload | F257 sparse, 128 slots | t = 786433, 65,536 slots | batching / sparse |
| --- | ---: | ---: | ---: |
| Scalar-subalgebra and range check of the plaintext | 0.1 ms | 6.4 ms | 84.79 |
| Slot masks of two loads | 228.8 ms | 275.7 ms | 1.21 |
| Broadcasts of two loads (14 and 32 key switches) | 8,743.1 ms | 27,797.5 ms | 3.18 |
| Equality exponentiation (8 and 20 multiplications) | 4,864.2 ms | 10,565.0 ms | 2.17 |
| Multiplication by the embedded one | 392.8 ms | 93.3 ms | 0.24 |
| Select multiplication | 563.8 ms | 485.4 ms | 0.86 |
| Output masks of two outputs | 348.6 ms | 457.0 ms | 1.31 |
| Unused-output zeroing | 59.0 ms | 17.3 ms | 0.29 |
| Evaluation total | 15,269.7 ms | 39,761.9 ms | 2.60 |
| Evaluation-key generation | 10,222.6 ms | 31,657.8 ms | 3.10 |
| Evaluation total, fastest to slowest of 3 and 3 runs | 15,240.6 ms to 16,756.1 ms | 38,850.0 ms to 39,861.2 ms | |
| Evaluation keys (canonical frames) | 2,112.0 MiB | 6,188.0 MiB | 2.93 |
| Input ciphertext (canonical frame) | 22.0 MiB | 25.0 MiB | 1.14 |
| Process peak resident memory | 2,651.2 MiB | 6,809.9 MiB | 2.57 |
| Main and special primes | 22 + 2 of 50 and 60 bits | 25 + 3 of 60 and 60 bits | |
| System load at the start of the run | 13.2 | 11.1 | |
<!-- fhe-bgv-encoding-comparison:end -->

- The equality costs 8 multiplications for `F257` (`x^256`) and 20 for
  `t = 786433` (`x^(3*2^18)`), each followed by one modulus switch.
- The fully splitting prime needs a longer chain of larger primes for the same
  instructions, 2.9 times the evaluation-key bytes and 2.6 times the peak
  memory, and takes about two and a half times as long to evaluate.
- Its ciphertext carries 65,536 slots against 128; the V1 input and output
  need 64. The extra slots buy nothing for this tape.
- The two late multiplications and the zeroing mask are cheaper for the
  fully splitting run only because that run has two primes left at that
  point and the `F257` run has eleven.
- The host ran other builds during the measurement; the load is in the table
  and in the summary. Each configuration ran three times; the table uses the
  run with the median evaluation time and gives the fastest and the slowest.
  The ratios, not the absolute times, are the result.
- The chains differ in prime size as well as in length: 50-bit main primes
  for `F257` and 60-bit ones for the fully splitting prime. The workload
  switches one prime per multiplication, and at `t = 786433` a product of two
  values at the rounding floor is about 87 bits, which one 50-bit prime
  cannot bring back. Both sizes are four 16-bit limbs and one machine word.
- The measured runs take the zero branch of the select. One more run of the
  `F257` configuration takes the non-zero branch
  (`select_branch_comparison_n16` in the summary); the two branches perform
  the same operations.
- The unused-output zeroing mask is redundant when every output is placed by
  a slot idempotent, because the accumulator is then already zero elsewhere.
  It is implemented and measured as the conservative lowering.

On these measurements the sparse `F257` encoding is the cheaper one for the V1
tape and keeps its plaintext semantics. That is a cost result. The security of
both parameter sets is unknown until the estimator has been run, and neither
has circuit privacy or proofs.

**Every instruction, modelled and measured.** The costing harness
([`tests/support/machine.rs`](../crates/iroha_fhe/tests/support/machine.rs))
lowers all eleven instructions by the table of the
[lowering contract](#one-explicit-lowering-for-all-eleven-operations) below,
with the BGV operations of this crate in place of the symbolic ones. The
table gives, for one instruction of each opcode on operands loaded at the top
level, the operations the harness charges, their model work units on the
affine and the bounded candidate, and the wall time of the same instruction in
an encrypted run on each candidate. Copies, constants and plaintext additions
cost no work unit; an addition or an output is charged the modulus switches
that align its operands.

<!-- fhe-bgv-instruction-costs:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Instruction | Operations (bounded candidate) | Work units, affine candidate | Work units, bounded candidate | Measured, affine candidate | Measured, bounded candidate |
| --- | --- | ---: | ---: | ---: | ---: |
| LoadInput | 1 plaintext multiplication, 7 key switches | 55,099,392 | 1,795,227,648 | 144.1 ms | 4,518.0 ms |
| LoadState | none charged | 0 | 0 | 0.7 ms | 12.0 ms |
| StoreState | none charged | 0 | 0 | 0.7 ms | 10.2 ms |
| LoadConst | none charged | 0 | 0 | 0.7 ms | 10.0 ms |
| Add | none charged | 0 | 0 | 3.5 ms | 46.5 ms |
| AddPlain | none charged | 0 | 0 | 1.6 ms | 23.8 ms |
| SubPlain | none charged | 0 | 0 | 1.6 ms | 23.9 ms |
| MulPlain | 1 plaintext multiplication | 3,833,856 | 63,438,848 | 8.0 ms | 132.6 ms |
| Mul | 1 key switch, 1 ciphertext multiplication, 2 modulus switches | not admitted | 339,345,408 |  | 869.1 ms |
| SelectEqZero | 10 key switches, 10 ciphertext multiplications, 24 modulus switches | not admitted | 2,468,478,976 |  | 6,285.7 ms |
| Output | 1 plaintext multiplication, 7 modulus switches | 3,833,856 | 109,182,976 | 8.7 ms | 198.6 ms |
| final zeroing mask | 1 plaintext multiplication | 3,833,856 | 40,370,176 | 7.5 ms | 78.8 ms |
<!-- fhe-bgv-instruction-costs:end -->

- `LoadInput` is the costliest affine instruction by a factor of about
  fourteen to twenty-eight over a plaintext multiplication: its seven key
  switches dominate.
- The harness also tracks the live buffers. With the input, four registers,
  32 state lanes and the output accumulator the bounded candidate holds 38
  ciphertexts, about 0.8 GiB of residues, before any scratch; the evaluation
  keys are 2.1 GiB more. The measured peak resident memory of the encrypted
  run on the bounded candidate is within a few percent of the projected keys
  plus working set (`tape_instruction_measurements` in the summary).
- What fits at the maximum shape, and what does not, is in the
  [encryption replacement plan](ram_lfe_encryption_replacement.md#rns-bgv-starting-candidate).

Every number is in
[`fhe_bgv_cost_summary.json`](fhe_bgv_cost_summary.json), classified as
measured, projection or parameter; `make check-fhe-bgv-cost` checks it and the
tables above, and a Rust test recomputes the sizes, work units, instruction
costs and tape plans from the crate. Raw harness runs stay untracked.

## Complete scalar-tape lowering contract candidate

This is a private structural planning contract, not a selected encryption
profile. It preserves the source interpreter's eleven instructions and admits
no alternate evaluator. The test-only plaintext candidate in `iroha_crypto`
covers N=4096; `iroha_fhe::bgv::SlotEncoding` covers every degree. The RNS
dimension, primes and distributions of the starting candidate are those of
the [RNS-BGV section](#rns-bgv-instantiation-and-measured-comparison); the
level schedule of a tape and sanitization are still unselected. Symbolic polynomial counts below must be instantiated and checked
against a reviewed profile before any encryption or production admission.

### Input, output and private owners

The input is one packed scalar vector: slot 0 is length `0..63`, slots
`1..=length` are bytes `0..255`, and all other slots through 127 are zero. The
first 64 logical slots preserve `encode_identifier_slots` exactly; a value of
256 is invalid in a byte slot. Message normalization and identifier-specific
canonicality remain separate checks. The client owns the message and encryption
coins. Its well-formedness proof must establish those bounds, the exact scalar
embedding and encryption relation under the authenticated policy key, binding
the same input commitment/context as the evaluator's execution proof. The
evaluator must not be required to know the client's plaintext or coins.

Both proof relations must be verified and bound to the identical typed input
commitment; an unchecked client assertion or token is insufficient. A proposed
compound envelope must count both proofs and their public instances in its
limits. This does not prescribe recursive verification or authorize a new
trusted input issuer. The input-admission relation is not implemented.

Four registers start at scalar zero. Reads before the first load are valid:
the source initializes these registers, rather than treating them as undefined.
Thirty-two memory lanes are rederived for each evaluation from the private key,
function identity and associated data; `StoreState` persists only within that
tape invocation. No cross-request state transition is introduced. The
[canonical V1 contract](ram_lfe_execution_proof.md#exact-plaintext-semantics)
fixes these semantics, and its cleartext reference is the oracle any lowering
below must match.

Preserve 1..256 tape instructions, four registers, 32 lanes and 1..64 ordered
outputs. Scalars and immediates range over `0..256`. An output is a scalar, not
a byte: never truncate 256. `Output` snapshots the source at that instruction;
later writes cannot alter earlier outputs. Pack the ordered outputs in slots
`0..output_count`, with all remaining slots zero, including slots 64..127.
The opening authority must check this exact output encoding, declared count and
context before hashing the opened scalar sequence. Its authenticated plaintext
opening remains distinct from the execution proof and ciphertext commitment.

The existing outer request cap is 1 MiB; associated data is `0..512` bytes. The
hidden tape owner reserves 12,288 instruction bytes and its explicit frame cap
remains `RAM_LFE_HIDDEN_PROGRAM_MAX_BYTES`. Existing generic secrets remain
`1..4096` bytes for their separate backends. The program key
`RamLfeProgramKeyV1` is exactly 32 nonzero bytes; arbitrary old secret bytes
are not silently converted into that key. Planning consumes no secret key,
plaintext input or randomness. It borrows the validated clearing tape, keeps
its program-dependent counts/indices private, and clears owned plan scratch.
No raw program, private count report or planning trace is added as a public
sidecar. Detailed errors belong to the policy owner's local builder; public
execution refusal must not reveal hidden opcodes or instruction positions.

### Test-only typed shape and public-statement boundary

The existing plaintext module now has `ClientInput` and `ScalarOutput` owners.
They reuse `ScalarSlots`/`ClearingWords`, move an existing allocation when
validating decoded slots, and reject byte 256, nonzero undeclared slots, input
length 64 and output counts outside 1..64. An output owns its ordered snapshot;
its count and full 128-word allocation clear on drop. These local checks do not
prove an encryption relation or establish oblivious validation. Borrowed and
compiler-created copies remain outside the owners' erasure claim. No private
plaintext wire format or hash is introduced.

`InputAdmissionStatementCandidateV1` is a test-only public Norito grammar with
this exact order: version, policy hash, parameter digest, encryption-public-key
digest, evaluation-key digest, encryption-profile digest, semantic-context hash,
packing-contract hash, associated-data hash, input-ciphertext hash and input
byte length. This is only the already-public ciphertext frame length, never
slot 0 or the private plaintext byte count. A selected fixed-profile ciphertext
codec must enforce its fixed shape; the local input owner does not publish its
length. The canonical frame is 348 bytes. All nine hashes use the existing
public Iroha `Hash` representation, never reduction into Fp. The policy hash is
explicit; the current production receipt, which lacks that field, is unchanged.

The semantic context must bind chain, program, owner and backend under the
selected future policy grammar. The profile and key digests must cover their
complete canonical authenticated contents. A future purpose verifier must derive
the expected statement from authoritative policy/context and the actual submitted
input, then bind both proof relations to that same statement. This code only
hashes bounded opaque input bytes and compares public fields. It neither checks
ciphertext canonicality nor authenticates the caller-supplied identities. There
is no trusted input issuer, admitted-ciphertext type or execution capability.
The future semantic Fp input commitment, if adopted, must additionally be
constrained to this exact ciphertext binding; this public hash is not an alias
for that field commitment.

The packing-contract hash covers its candidate V1 schema, N=4096, t=257,
128 scalar slots, the 63-byte/64-output limits, all seven ordered Galois roles,
and required relinearization. It selects neither a refresh algorithm nor a
bootstrap prohibition; any refresh/sanitizer and its extra authenticated keys
belong to the unresolved encryption profile. This is an encoding/key-role
contract, not a selected BFV-RNS security profile. The planner imports the same
Galois-role constant. Exact level/basis variants, primes, key distributions,
key ownership and admission proofs remain unresolved.

The checked proof-envelope inventory includes the 348-byte statement, both
nonempty proof byte counts and declared remaining envelope bytes. The separate
encrypted-input cap remains 1 MiB; an input hash does not place the ciphertext
in the proof envelope. The inventory rejects arithmetic overflow, combined proofs
above 192 KiB and proof-envelope totals above 1 MiB. Remaining bytes must include
all additional framing/instances and any input/output/key bytes actually carried;
separately owned input/output/key material is not silently duplicated. This is
a declared-size calculation, not an implemented complete envelope codec:
completeness, policy-key loading, algorithm/prover scratch and actual proof
verification remain required.
All nine existing `UnqualifiedPlan` blockers remain; no production caller uses
these candidate owners or statements.

### One explicit lowering for all eleven operations

Use a uniform broadcast-scalar representation for each register and memory
lane. `Embed(v)` denotes the selected BFV scheme's exact trivial plaintext
embedding, not fresh encryption or sanitization. Those intermediate values
remain private evaluator/prover material. `CMul` includes its full tensor
product, scale/round and relinearization; `Galois(a)` includes a full key switch.
Neither is a host callback exempt from the final proof.

| Tape instruction | Required semantic lowering | Logical multiplication rank |
| --- | --- | --- |
| `LoadInput(dst,j)` | Mask packed input by `e_j`; for each of the seven fixed exponents, apply Galois then add to the running value; replace dst with the broadcast scalar. | 0 |
| `LoadState(dst,lane)` | Copy the lane's immutable value into dst, without changing the lane. | lane rank |
| `StoreState(lane,src)` | Snapshot src into the lane, without changing src. | src rank |
| `LoadConst(dst,v)` | `Embed(v)` broadcast to every scalar slot. | 0 |
| `Add(dst,a,b)` | Align immutable operand copies, add, replace dst. | `max(a,b)` |
| `AddPlain(dst,a,v)` | Exact canonical scalar plaintext addition. | a rank |
| `SubPlain(dst,a,v)` | Exact canonical scalar plaintext subtraction. | a rank |
| `MulPlain(dst,a,v)` | Exact canonical scalar plaintext multiplication. | a rank |
| `Mul(dst,a,b)` | Align copies, `CMul(a,b)`, replace dst. | `max(a,b)+1` |
| `SelectEqZero(dst,c,z,n)` | Full expansion below; source values are captured before replacing dst. | `max(c+10,z+1,n+1)` |
| `Output(src)` | Multiply captured src by next output mask; align and add to the packed output accumulator, preserving order. | max emitted rank |

The table's ranks are dependency depths, **not RNS modulus levels or noise
budgets**. A physical level scheduler may map ranks to a reviewed chain only
when its exact switching/rounding semantics and correctness bounds are supplied.
Addition or plaintext multiplication can exhaust noise without changing rank.
The logical rank ceiling 16 is the `bounded.v1` class limit and the
`refresh.v1` limit between refreshes. It is a recorded candidate, not a
promise that any encryption profile supports that depth. The same rank rules
are implemented once, in `RamLfeClassV1::membership`.

For `SelectEqZero`, perform exactly eight repeated ciphertext squarings of c,
then one ciphertext multiplication by `Embed(1)` as in the source exponentiation
schedule. Form `indicator = Embed(1) - powered`, `delta = z - n`, then
`result = n + CMul(indicator, delta)`. This is ten ciphertext multiplications,
two ciphertext subtractions, one ciphertext addition and two explicit one
embeddings; constant folding is not part of this initial lowering. Squarings
require relinearization too. Aliasing dst with any source is safe only because
all sources remain immutable until the result is complete. This expansion is
correct only for scalar F257 inputs; the client admission and subsequent
scalar-preserving transitions are essential.

Each input load costs one polynomial plaintext mask, seven automorphisms with
key switches and seven ciphertext additions. Each output costs one polynomial
plaintext mask, and outputs after the first cost an accumulator addition.
A mask has centered l1 norm 8,256. A broadcast scalar has one nonzero polynomial
coefficient bounded by 128; a general scalar-packed message has centered l1 at
most 16,384. Intermediate partially broadcast/accumulated messages must retain
the appropriate message-shape bound. These facts are inputs to a noise proof,
not replacements for encoding/rounding and key-switch error terms.

The seven Galois-key roles and relinearization role must be authenticated from
the typed policy. The old diagnostic bundle's prohibition of rotation keys
cannot be reused for this replacement. Required actual level/basis variants,
decomposition digits, special primes and key sizes remain explicit unresolved
profile requirements. No bootstrap/refresh algorithm is implemented. The
`refresh.v1` class fixes only where a refresh occurs and how many are allowed:
its schedule is a function of the tape and is private with it. A future reviewed
encryption profile must specify the complete refresh/sanitization algorithm,
extra authenticated keys, exact arithmetic and resource/noise rules. A refresh
mask is not a bootstrap, and no implicit modulus reset is permitted.

### Resource accounting and unresolved qualification

The planner must separate three outputs: exact structural counts, symbolic
profile-dependent requirements, and measured proof/backend limits. It may
produce an `UnqualifiedPlan`; it must not produce an executable/qualified token
while any noise, input-admission, key, physical-level, sanitization, codec or
proof requirement is absent. Unknown costs never become zero.

Track each register/lane's current value and rank, instruction/output counts,
all primitive counts, required key roles and checked live storage. Process all
256 possible tape positions; the universal relation constrains inactive positions
to preserve state and emit nothing. Private instruction count, opcode and index
selectors must not select a smaller public circuit, proof or key. Active-work
counts alone therefore underestimate the fixed hidden-program relation. Native
timing/allocation leakage needs a separately stated and qualified policy; this
planner does not establish oblivious execution.

The structurally valid worst cases are material: 255 independent selects followed
by an output require 2,550 ciphertext multiplications even though each select
has rank 10. Conversely, 255 input loads followed by an output require 1,785
Galois key switches. These are separate extrema, not one jointly attainable
program. Sixty-four outputs require 64 masks and 63 accumulator additions.
Initialized zero registers do not justify removing private instructions from
the proof relation. A complete feasibility estimate must cost the universal
selection/routing machinery and inactive positions as well as real arithmetic.

Let `C(level)=2*N*L(level)*8` bytes for a two-component residue owner and
`T(level)=3*N*L(level)*8` for an unrelinearized tensor, using canonical u64
residues. These are checked storage formulas, not selected N or limb counts.
Keep the input owner, 32 lane owners, four register owners, optional output
accumulator and all operands live until each replacement commits. Count
alignment copies, old destination, running broadcast plus rotated/add result,
select intermediates, three-component multiplication buffers, decomposition,
basis-extension/NTT scratch and clearing transfers separately. Immutable sharing
may reduce allocations only when a liveness proof counts the actual owners;
logical aliases do not authorize destructive mutation or early erasure.

The selected RNS implementation must provide a checked workspace inventory and
physical-level/noise transfer rule for every primitive. Plaintext masking needs
its coefficient norm **and** the scheme's plaintext-embedding/rounding terms;
`E'=8256*E` alone is not a complete BFV bound. Key switches, scale-and-round and
modulus switches need their actual error terms and temporary bases. A missing
rule yields a typed unresolved requirement, not a conservative-looking guessed
number. No planner may invoke the old scalar-modulus reconstruction owner as a
genuine Q-product profile.

After output packing, require an explicit reviewed circuit-privacy/sanitization
stage even for constant-only programs. Its fresh randomness, distribution,
noise cost, buffers, key material, proof constraints and lifetime/query limits
belong in the plan. Adding an encryption of zero is not accepted as a generic
sanitizer. A proof can constrain bounded coins and the transformation; it does
not prove that an honest random sampler supplied entropy. That assumption and
the clearing RNG owner require independent review and implementation evidence.

Input and output frames, both proof relations, verification keys, authenticated
evaluation-key material and any public-instance encodings must have exact
bounded canonical sizes. The combined proof budget remains 192 KiB, proof envelope
1 MiB and k<=16. The encrypted-input cap is separately 1 MiB;
inputs/evaluation keys already owned by the consumer must not be
duplicated as sidecars. Policy-key storage/loading is also bounded separately,
not hidden outside the accounting. Profile-specific maxima and prover-memory
ceilings remain to be supplied rather than invented here. The maximum single
Poseidon prototype already measured 233–239 ms complete IPA verification,
exceeding the existing 20 ms soft budget; no complete execution/admission budget
has passed.

The test-only planner implements tape/rank/count/alias bookkeeping and
symbolic primitive requirements without keys or encryption. It models no
refresh, so it accepts `bounded.v1` tapes only. Required controls
cover all eleven operations, all register/lane alias cases, zero-initialized
reads, exact 256/257 and 64/65 boundaries, rank-16/17 cases, all ten select
multiplications, the two extrema above, output snapshots, checked byte arithmetic
and actual scratch erasure on success/error/unwind. It remains structurally
unqualified until the replacement plan supplies and independently reviews every
profile-dependent rule and the complete proof budget.
