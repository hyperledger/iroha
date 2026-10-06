# RAM-LFE encryption replacement plan

Date: 2026-09-29; RNS-BGV section added 2026-10-05. Status: source-coupled
design work, no qualified replacement. Both BFV production backends remain
unavailable. An exact modular RNS-BGV starting candidate is implemented in
[`iroha_fhe::bgv`](../crates/iroha_fhe/README.md#rns-bgv) and costed
[below](#rns-bgv-starting-candidate); it is not wired into any consumer and no
profile is qualified. This plan refines
the encryption prerequisite of [ZK03](zk_first_release_goals.md) and the
[execution relation](ram_lfe_execution_proof.md); it does not enable a profile,
change admission limits or establish a security level.

## What the existing arithmetic establishes

The exact profile is known insecure. The rounded diagnostic path instead uses
small centered errors and scaled plaintexts, but has no independent security
qualification. The following are implementation facts, not evidence that either
profile protects encrypted inputs or hidden functions.

| Source owner | Current contract and replacement consequence |
| --- | --- |
| [`BfvParameters::validate`](../crates/iroha_crypto/src/fhe_bfv.rs) | One `u64` ciphertext modulus, divisible by plaintext modulus, with `n*q*q*t <= i128::MAX`. The same owner constrains rounded arithmetic. A larger genuine RNS modulus needs a new internal representation; relaxing this overflow guard is not an implementation. |
| `ram_lfe_bfv_parameters_v1` | Ring degree 64, `t = 257`, `q = 257*2^48`, decomposition base `2^12`. Registration recognizes this exact diagnostic shape; it supplies no security qualification. |
| `keygen_bounded_noise_with_relinearization_from_seed` and `encrypt_bounded_noise_from_seed` | Diagnostic ternary secrets/masks, centered errors bounded by one, public-key relation `b = -a*s-e`, plaintext scale `q/t`, and matching noisy relinearization material. These private constructors are available through explicit test fixtures only. |
| `multiply_ciphertexts_bounded_noise` and `multiply_ciphertexts_bounded_noise_rns_exact` | Centered raw products, deterministic coefficient scale-and-round, then relinearization. RNS bridges accelerate exact reconstruction around the scalar modulus; their reconstruction-prime product is not the ciphertext modulus `Q`. |
| [`iroha_fhe`](../crates/iroha_fhe/README.md) | Owns the reusable exact arithmetic these owners call through private adapters: modular scalars, radix-2 transforms, CRT reconstruction, basis extension, digit decomposition, automorphisms and explicit rounding (ties away from zero). For these BFV owners it defines no scheme, parameter set or security profile. The genuine RNS profile is the separate `iroha_fhe::bgv` module with its own arbitrary-chain kernels; it was built beside the BFV adapters, not by renaming them, and it does not call the `u128` reconstruction they use. [`specs/fhe_ownership_inventory.json`](fhe_ownership_inventory.json) records each owner and is checked against the source. |
| `BfvIdentifierCiphertext::slots` | 64 separate scalar ciphertexts, including the input-length slot. This is not 64 SIMD positions inside one ciphertext. |
| [`eq_zero_indicator`, `pow_ciphertext`, `select_eq_zero`](../crates/iroha_crypto/src/ram_lfe.rs) | `1-c^256` over the field of 257 elements, evaluated with eight squarings, a final multiply by encrypted one, then a multiply by the branch difference. A planner must charge the entire expansion. |

The current rounded bound already prevents dispatching that last operation to
the rounded evaluator. With `N=64`, `t=257`, `q=257*2^48`, base `B=4096`, five
decomposition digits and coefficient error bound one, the public functions give

```text
fresh E = 2*N + 1 = 129
capacity = floor((q/t - 1)/2) = 140,737,488,355,327
mul(Ea,Eb) = N*(t-1)*(Ea+Eb) + ceil(N*Ea*Eb*t/q)
             + N*N + N + 1 + N*5*(B-1)
```

| Consecutive squaring | Output bound | Within current capacity |
| --- | ---: | --- |
| 1 | 5,541,634 | yes |
| 2 | 181,589,577,480 | yes |
| 3 | 5,950,334,773,774,910 | no |

These values reproduce `bfv_fresh_bounded_noise_ciphertext_bound`,
`bfv_multiply_bounded_noise_output_bound`,
`bfv_key_switch_extra_residual_multiple_bound` and
`rounded_plaintext_decoding_capacity`. They show rejection by the current
conservative bound, not a measured decryption failure or a security experiment.
The source hashes, excerpts and integer-only reproduction are retained under
`dist/zk-remediation/2026-09-29/ram-lfe-encryption-replacement/`.

## Architectural decision before implementation

The [delivery plan](zk_delivery_plan.md) fixes exact modular RNS-BGV as the
concrete starting candidate: the scheme of
[Brakerski, Gentry and Vaikuntanathan](https://eprint.iacr.org/2011/277) with the
plaintext in the low bits, `c0 + c1*s = m + t*e (mod Q)`. It is neither BFV
scaling nor the exact-lift construction above. A starting candidate is not a
selected cryptographic profile. Approximate arithmetic does not supply the exact equality
and identifier mapping required by this interpreter. A genuine noise-reducing
bootstrap would require a separate algorithm, parameter and proof qualification;
adding an encryption of zero does not supply it.

Resolve packing and plaintext semantics before choosing parameters. Ordinary
fully split prime-field BFV batching requires `t = 1 mod 2N`, as documented in
[Microsoft SEAL's encoder example](https://github.com/microsoft/SEAL/blob/main/native/examples/2_encoders.cpp).
For the existing `t=257`, this cannot hold for power-of-two `N>128`. Retaining
257 therefore needs a different reviewed representation or costly separate
ciphertexts; choosing a larger batching prime changes arithmetic and equality
semantics and must be an explicit first-release language/profile decision.
Packing coefficient positions is not interchangeable with independent scalar
slots under polynomial multiplication. Unused output positions must not expose
intermediate plaintext or hidden-function information.

The [F257 scalar-packing candidate](ram_lfe_plaintext_packing.md) supplies a
specific alternative: constants in extension-field CRT slots, encoded in a fixed
sparse subalgebra. It preserves scalar F257 operations without requiring fully
split degree-one slots. Its input-admission, masking, rotation, noise and complete
proof costs remain unqualified; no modulus/profile is selected by this algebra.

For scale only, an **unselected** representation with `N=4096`, two 64-bit RNS
limbs, two ciphertext components and 64 separate ciphertexts consumes
`64*2*4096*2*8 = 8,388,608` bytes before framing. This is not a parameter proposal
or security estimate; it demonstrates why the current scalar envelope cannot
simply be widened under the existing 1 MiB total-envelope default. The complete
input, output, keys, proof and private witness costs need a new measured budget.

## Milestones and acceptance evidence

1. **Fix the threat model and plaintext contract.** The roles, their collusion
   assumptions, the output and oracle leakage bound, the committed lifetime
   query limit and who may request an opening, the exact plaintext semantics,
   the three classes and the canonical policy, receipt and opening are
   specified and implemented in the
   [canonical V1 contract](ram_lfe_execution_proof.md#canonical-v1-contract).
   Still open: who may choose malformed keys or ciphertexts and how they are
   rejected, enforcement of the query limit in State, visible errors, timing
   and padded lengths, and a concrete circuit-private or sanitizing
   construction with its assumptions. Input confidentiality does not imply hidden-circuit privacy.
   [Hwang, Min and Song](https://eprint.iacr.org/2025/203) is relevant research,
   not an adopted implementation or qualification. An execution proof alone
   cannot authorize a claimed plaintext, and neither can a signature: the
   opening needs its own decryption and PRF proofs.

2. **Create a genuine RNS parameter and residue owner.** *Implemented for the
   starting candidate in `iroha_fhe::bgv` and `iroha_fhe::rns_chain`; see
   [below](#rns-bgv-starting-candidate). The level schedule of a tape and the
   review of the parameters remain open.* Introduce one immutable validated internal profile with pinned
   `Q = product(q_i)`, ring dimension, plaintext encoding, secret/error
   distributions, decomposition and any special-prime basis, level schedule and
   NTT roots. Define residue ordering, canonical ranges, basis extension,
   relinearization, modulus switching and every rounding tie exactly. Residues
   remain in the specified RNS domain; the old scalar reconstruction chain does
   not become `Q` by renaming it. Reject unsupported shapes and overflow before
   allocation. No caller-selected primes and no weakened old `i128` checks.

3. **Select and independently review complete parameters.** Pin the actual
   distribution, estimator version and assumptions, classical/quantum cost
   model, key-switch material, decryption-failure target and lifetime/query
   budget. Security, correctness and operation capacity must be evaluated jointly,
   following the [HE implementation guidelines](https://eprint.iacr.org/2024/463).
   Do not invent a bit-security claim from ring degree or use a library's default
   as a qualification certificate. Review malicious-input and circuit-privacy
   requirements separately from IND-CPA encryption. The chosen representation
   must also meet the existing envelope/proof resource contract; otherwise record
   the unsatisfied requirement without raising limits to declare success.

4. **Compile a bounded typed operation/noise plan.** Expand every instruction
   into its actual arithmetic, including `SelectEqZero`'s full exponentiation,
   constant and branch multiplications, operand levels and relinearization.
   Track initialized reads, live ciphertexts, output count, modulus level,
   conservative noise/failure bounds and checked memory/work costs. Supporting
   add/subtract/plain operations alone is not programmed-backend completion.
   If the final semantics change, regenerate the equality expansion and prove it
   correct for all admitted plaintexts. A count named "depth 16" is not a noise
   proof. Reject unplannable programs before key generation or private allocation;
   give a typed error naming the offending operation and exhausted budget.

5. **Implement the smallest internal arithmetic slice.** *Implemented for the
   starting candidate, unused by production admission; cross-library parity
   with a third-party BGV library has not been run.* First build the genuine
   RNS owner, canonical bounded codec and deterministic reference arithmetic,
   then encryption/decryption, addition, plaintext multiplication, ciphertext
   multiplication and relinearization for one reviewed candidate profile.
   Keep it unused by production admission. Use independently generated vectors
   and cross-library plaintext/arithmetic parity with the same parameters and
   explicit fixture randomness. Require byte parity only where the reference
   specifies the same coins, rounding and canonical representation; equivalent
   randomized ciphertexts need not have identical library serialization. Test
   zero/boundary residues, rounding ties, wrong levels/keys, malformed lengths,
   arithmetic overflow and canonical re-encoding. Seeded helpers stay in test
   fixtures; the public facade owns secure randomness.

6. **Qualify ownership and deterministic acceleration.** Keep private keys,
   randomness, CRT/NTT intermediates, rounding scratch, temporary ciphertexts and
   execution witnesses in clearing owners with bounded allocation. Verify live
   cell erasure on success, error and unwind, including partially decoded values
   and ownership transfers. Do not promise to erase caller-owned copies. Pin
   the scalar reference semantics, then test NEON/SIMD/Metal/CUDA implementations
   against it where supported. Backend selection must not affect canonical
   outputs or consensus results; no floating-point or scheduling-dependent
   reductions. Accelerator absence must retain the same deterministic behavior.

7. **Bind the complete execution relation.** After the arithmetic/privacy design
   is reviewed, constrain every limb range, integer lift, carry, quotient,
   remainder, rounding decision, modulus level and relinearization transition,
   as well as the program, initialized state, registers, memory and outputs.
   A field equation alone cannot prove an integer equation modulo `Q`. Bind any
   adopted randomized evaluation/sanitization step and its coins to the specified
   relation. Adopt the [semantic commitment proposal](ram_lfe_semantic_commitments.md)
   only after its independent review, updating packing and cost estimates for the
   actual RNS profile. The verifier derives instances and evaluation-key material
   from authoritative typed policy; no prover-selected replacement sidecar.
   Keep the stable logical `Cfunction` independent of encryption-key rotation,
   while `Cpolicy` and the receipt bind every math/key/profile identity. An opaque
   identifier derives from the authenticated opened function output and context,
   never from a ciphertext hash or an unverified opening.

8. **Measure and integrate one final profile.** Synthesize the maximum complete
   relation and measure rows/cells/lookups, native proof bytes, prover time/peak
   memory and verifier latency. Recheck configured `max_k` before parameter work
   and total proof/envelope/key/instance sizes before decoding or allocation.
   Current defaults remain `k <= 16`, proof `<= 192 KiB`, total Norito envelope
   `<= 1 MiB` and a 20 ms soft verification budget. The old degree-64 estimate of
   2,305 Poseidon permutations/149,825 round rows is not an estimate for the new
   encryption profile. Require real proofs, arbitrary-field witness mutations,
   modular aliases, malformed frames, policy/key swaps, rekey stability and wrong
   opening-authority/output tests. Test registration, restoration,
   stateless/identifier receipt consumers and a four-validator network. The
   genuine relation replaces the refusal in the change that delivers it, with
   no activation or qualification step in between. Retire old profiles, keys,
   roots and frames with no aliases or fallback; ABI remains V1.

## Developer boundary and first implementation gate

The eventual facade accepts a typed program and inputs, compiles a resource plan
and chooses a qualified fixed profile. Developers do not choose noise,
transcripts, rings or seeds. Key generation, encryption, evaluation, authenticated
opening and proof verification return distinct typed results; a higher-level
resolve operation may compose them without hiding their different authorities.
An unavailable or over-budget program fails before private/network work.

The immediate determinate slice is the [complete eleven-operation lowering
and resource contract](ram_lfe_plaintext_packing.md#complete-scalar-tape-lowering-contract-candidate):
a test-only structural planner may track the real tape, ranks, buffers and
unresolved primitive obligations without choosing a security profile. It must
return an unqualified plan while physical levels, noise, input admission,
sanitization, key ownership or proof costs remain unknown. The next arithmetic
slice is milestone 2's genuine RNS profile/residue owner and scalar reference,
after milestones 1 and 3 supply reviewed encoding/parameter inputs. Small arithmetic fixtures may validate code earlier
but cannot select a production profile. Full `SelectEqZero` capacity, hidden
function privacy and the complete proof relation remain hard gates. Do not switch
the current interpreter to rounded dispatch, promote diagnostic refresh as a
bootstrap, or increase limits as a substitute for any gate.

## RNS-BGV starting candidate

Task C.3 of the delivery plan implemented the candidate in
[`crates/iroha_fhe/src/bgv`](../crates/iroha_fhe/src/bgv/mod.rs). What follows
are implementation facts and measurements. None of it is a security
qualification, and nothing is wired into RAM-LFE, Torii or SoraCloud.

**Construction.** `R = Z[X]/(X^N + 1)`. Main primes `q_0..q_L` and special
primes `p_0..p_(K-1)` are the first primes of their bit length congruent to one
modulo `2*N*t`; each is pinned with a primitive `2N`-th root. A ciphertext at
level `l` lives modulo `Q_l = q_0*...*q_l`.

- Basis conversion is exact: mixed-radix (Garner) digits and a digit-wise
  comparison with `(Q-1)/2` give the centered representative, so there is no
  `u128` reconstruction, no approximate conversion and no floating point.
- A modulus switch and the division by `P` in key switching use
  `c' = (c - t*w)/D` with `w` the centered representative of `c*t^-1` modulo
  the odd `D`. The division is exact, no tie exists, and because `D = 1 mod t`
  the plaintext is unchanged and no correction factor is carried.
- Key switching is hybrid RNS with digits of two consecutive main primes.
  Relinearization keys encrypt `P*s^2` and Galois keys `P*s(X^k)` digit by
  digit; publishing them relies on a circular-security assumption that a
  parameter review has to state.
- The secret and the encryption mask are uniform ternary. Errors are centered
  binomial with `eta = 21` (support `[-21, 21]`, variance 10.5).
- Every key generation and encryption draws 64 bytes from the operating system
  and fails when that fails. The seed is expanded by BLAKE3 `derive_key` with
  the profile identity and a purpose tag. Entry points that take a seed or
  coins exist only behind the `bgv-test-fixtures` feature.
- Keys, coins, plaintexts and decryption scratch are held in owners that
  clear on drop. The seed of an operation, the BLAKE3 state that absorbs it,
  the stream state and the buffered stream bytes regenerate everything the
  operation samples; they live in one heap block that is overwritten whole
  before it is released. An allocator probe observes every such block and
  every polynomial-sized buffer after success, an error return and an unwind.
  The stack frames of the hash function and values in registers are outside
  what the probe can see.
- Every public object has a canonical encoding and a decoder that rejects
  another profile, any other length and a non-canonical residue: parameter
  sets, ciphertexts, public keys, switching keys and evaluation keys. The
  secret key has a custody frame (two bits per coefficient) that is produced
  in, and accepted from, a clearing buffer. A decoded key or ciphertext is
  well formed as an encoding only; nothing here authenticates a frame, and the
  Norito wire types and bounded admission belong to the consumers.
- The level, the component count and the noise bound of every result come
  from one owner, `iroha_fhe::bgv::plan`, which works on public shapes alone.
  A sequence of operations can therefore be planned without a key or a
  ciphertext, and is admitted on ciphertexts exactly when its plan is.

**Noise and failure bound.** Each ciphertext carries an exact public upper bound
`V` of `||c0 + c1*s||_inf`, computed from `N`, `t`, the error bound and the
operation history only (worst case, `||s||_1 <= N`):

| Operation | Bound |
| --- | --- |
| fresh encryption | `(t-1)/2 + t*21*(2N+1)` |
| addition | `V_a + V_b` |
| plaintext multiplication by `p` | `V * W`, `W >= ||p||_1` public |
| ciphertext multiplication | `N*V_a*V_b + E_ks` |
| automorphism | `V + E_ks` |
| key switch `E_ks` | `floor((t*N*21*sum_j floor(Q_j/2) + t*(P-1)/2*(1+N)) / P)` |
| modulus switch dropping `q` | `floor((V + t*(q-1)/2*(1+N)) / q)` |

An operation whose bound would exceed `(Q_l-1)/2` is refused. Decryption fails
exactly when a coefficient of the true `m + t*e` exceeds that capacity. Because
every sampled error has magnitude at most 21 with certainty, the derived
failure probability of an admitted sequence over honestly sampled keys and
ciphertexts is zero; the bound makes no statement about inputs that were not
produced by these samplers. The bound is pessimistic by many bits (a fresh
ciphertext of the toy vectors has exact noise 5,098 under a bound of 178,229),
and that cost is part of every number below. Tests attain the fresh bound
exactly with worst-case coins, attain the modulus-switch bound within one unit,
and compare the bound with the exact noise over random operation sequences.

**Candidates.** `BgvCandidate` pins three parameter sets over `t = 257`:

<!-- fhe-bgv-candidates:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Candidate | Class shape | log2 Q*P | Ciphertext frame | Evaluation keys | Multiplication work units | Core-SVP classical / quantum | BDGL16-style classical |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `bgv.f257.n14.q6x50.p2x60` | affine.v1 | 412.0 | 1.5 MiB | 48.0 MiB | 12,828,672 | 102.8 / 93.3 bits | 137.2 bits |
| `bgv.f257.n16.q22x50.p2x60` | bounded.v1 | 1196.0 | 22.0 MiB | 2,112.0 MiB | 338,231,296 | 161.8 / 146.8 bits | 198.2 bits |
| `bgv.f257.n16.q32x50.p2x60` | refresh.v1 | 1686.0 | 32.0 MiB | 4,352.0 MiB | 616,431,616 | 99.0 / 89.8 bits | 135.4 bits |
<!-- fhe-bgv-candidates:end -->

- Sizes and work units are computed from the profile geometry. One work unit
  is one multiplication of two word residues; the measured scalar path spends
  about 2 to 4 ns per unit on the host of the summary.
- The core-SVP columns are a sanity calculation (primal uSVP on `Q*P`, 2016
  estimate). It reproduces the 128-bit rows of the 2018 Homomorphic Encryption
  Standard within one bit in the BDGL16-style column. It is **not** the Lattice
  Estimator: no dual or hybrid attack is costed.
  [`scripts/fhe_bgv_lattice_estimator.sage`](../scripts/fhe_bgv_lattice_estimator.sage)
  pins the estimator commit and the invocation; it has **not been run**
  (SageMath is not installed on the measurement host). Until it is, the
  security level of every candidate is unknown. Against a target of 128 bits
  the sanity numbers already show that the affine and refresh candidates fall
  short in the core-SVP metric (102.8 and 99.0 bits) and pass only in the
  BDGL16-style metric.

**Does each class fit?** The costing harness of the crate's tests
([`tests/support/machine.rs`](../crates/iroha_fhe/tests/support/machine.rs))
lowers each of the eleven tape instructions onto the scheme, once over public
shapes and once over ciphertexts; the two runs agree on every level and noise
bound, and the encrypted run computes the tape. Its level policy is lazy: a
value is switched down only to align two operands or, before a product, while
that leaves more capacity above the product. The table plans tapes of the
maximum V1 shape (256 instructions, 64 outputs, rank 16) on each candidate
and gives the fewest main primes of the candidate's size that would hold
each. The last column adds one projected noise flood to the output (below).

<!-- fhe-bgv-class-fit:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Candidate (main primes) | Family | Planned result | Main primes needed | With flooding (2^20 releases, 2^-80) |
| --- | --- | --- | ---: | ---: |
| `bgv.f257.n14.q6x50.p2x60` (6) | `affine.loads` | fits: output at level 5 with 75 of 294 bits | 2 | 4 |
| `bgv.f257.n14.q6x50.p2x60` (6) | `affine.scale_chain` | refused at instruction 36 (MulPlain) | 38 | 41 |
| `bgv.f257.n14.q6x50.p2x60` (6) | `affine.scale_then_outputs` | refused at instruction 36 (MulPlain) | 29 | 32 |
| `bgv.f257.n14.q6x50.p2x60` (6) | `affine.state_and_registers` | fits: output at level 5 with 84 of 294 bits | 2 | 5 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `affine.loads` | fits: output at level 21 with 77 of 1078 bits | 2 | 4 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `affine.scale_chain` | refused at instruction 147 (MulPlain) | 38 | 41 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `affine.scale_then_outputs` | refused at instruction 147 (MulPlain) | 29 | 32 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `affine.state_and_registers` | fits: output at level 21 with 86 of 1078 bits | 2 | 5 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `bounded.alternating_rank_chain` | fits: output at level 5 with 103 of 294 bits | 19 | 21 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `bounded.rank_chain_outputs` | fits: output at level 5 with 96 of 294 bits | 18 | 21 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `bounded.scaled_rank_chain` | refused at instruction 147 (MulPlain) | 52 | 55 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `bounded.select_then_products` | fits: output at level 6 with 96 of 343 bits | 17 | 20 |
| `bgv.f257.n16.q22x50.p2x60` (22) | `bounded.selects` | fits: output at level 15 with 152 of 784 bits | 10 | 12 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `affine.loads` | fits: output at level 31 with 77 of 1568 bits | 2 | 4 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `affine.scale_chain` | refused at instruction 217 (MulPlain) | 38 | 41 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `affine.scale_then_outputs` | fits: output at level 31 with 1420 of 1568 bits | 29 | 32 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `affine.state_and_registers` | fits: output at level 31 with 86 of 1568 bits | 2 | 5 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `bounded.alternating_rank_chain` | fits: output at level 15 with 103 of 784 bits | 19 | 21 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `bounded.rank_chain_outputs` | fits: output at level 15 with 96 of 784 bits | 18 | 21 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `bounded.scaled_rank_chain` | refused at instruction 217 (MulPlain) | 52 | 55 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `bounded.select_then_products` | fits: output at level 16 with 96 of 833 bits | 17 | 20 |
| `bgv.f257.n16.q32x50.p2x60` (32) | `bounded.selects` | fits: output at level 25 with 152 of 1274 bits | 10 | 12 |
<!-- fhe-bgv-class-fit:end -->

- **No candidate holds the maximum shape of its class when the tape is lowered
  instruction by instruction.** A multiplication by a hidden constant
  multiplies the bound by `(t-1)/2 = 128`, seven bits, and does not raise the
  logical rank, so the class limits do not bound it. The families
  `affine.scale_chain` and `bounded.scaled_rank_chain` need more primes than
  any candidate has, at a ring degree where that many primes cannot be secure.
- What the candidates do hold: every family without a long run of constant
  multiplications. The bounded candidate holds 255 independent selects, a
  rank-16 chain with 64 outputs, and a select followed by six products.
  `sequential_constant_multiplications_that_fit` in the summary gives the
  longest run beside 64 outputs after a chain of rank 0, 10 and 16.
- A lowering that folds each run of plaintext operations into one constant
  (the evaluator knows the constants) removes that growth. For `affine.v1` it
  is the affine map: one row product and one trace of seven key switches per
  output, which the summary projects at three primes. Nothing here implements
  either; they are proposals for the tasks that build the execution relation.
- `refresh.v1` has no refresh algorithm. Its 32-prime candidate is planned as
  one segment between two refreshes. A rank-16 segment leaves fewer primes
  than a chain of the depth the design memo cites for thin bootstrapping
  would need (`refresh_room_projection`); that depth is a cited figure, not a
  derivation, and the comparison is a projection.

**Sanitization headroom (projection).** No circuit-privacy construction
exists. To show what one would cost in modulus, the summary projects noise
flooding on the packed output: with `E = ceil(V/t)`, a uniform flood of
half-width `F = H*N*E*2^kappa` hides a shift of `2E` per release at distance
`2^-kappa` over `H` releases, and the flooded, re-randomized output has the
bound `V + t*F + V_fresh`. For `H = 2^20` that is 116 more bits at
`kappa = 80` and 76 at `kappa = 40` when `N = 2^16`, two to three 50-bit
primes. `H` and `kappa` are illustrative, nobody has selected them, flooding
alone does not hide the second ciphertext component, and none of this
establishes privacy; the construction and its proof are task R.11.

**Proof work (projection).** No proof exists. The summary projects the size
of two relations under a stated layout with 16-bit limbs: the client's input
well-formedness relation (compared for both encodings in the
[packing specification](ram_lfe_plaintext_packing.md#rns-bgv-instantiation-and-measured-comparison))
and a relation that constrains every residue multiplication of an evaluation,
whose count is the model work units. For the bounded candidate that is about
`2^32` to `2^33` multiplications for a rank-16 tape and `2^39` for 255
selects. The tasks that own the relations decide what is actually constrained.

**Resource-contract inputs.** The values of the six inputs that
[`zk_resource_contract.json`](zk_resource_contract.json) leaves open for this
task are in `resource_contract_inputs` of
[`fhe_bgv_cost_summary.json`](fhe_bgv_cost_summary.json), one set per candidate.
`ram_lfe.plain_operation_work_units` is the cost of `LoadInput`, the costliest
`affine.v1` instruction under the lowering (one mask multiplication and seven
key switches), not of a plaintext multiplication. With that value the
contract's affine and bounded budget formulas cover every planned family that
fits; the summary records each comparison. The ciphertext of the bounded
candidate alone is 22 times the 1 MiB request envelope and its evaluation keys
are about 2 GiB; nothing here raises a limit, and the budgets that have to
hold them are still to be derived by the tasks that own them.

**Drift checks.** `make check-fhe-bgv-cost` runs
`python3 scripts/fhe_bgv_cost_model.py`, its unit tests and the reference
vector check. The script recomputes every projection of the summary with its
own model, compares the constants it restates with
`iroha_crypto::ram_lfe::class` and the harness, and compares the tables this
repository embeds with the summary. It also renders the candidates' geometry,
sizes and work units, the instruction costs, every family plan, the longest
chains and the contract inputs into
[`bgv_cost_model_v1.txt`](../crates/iroha_fhe/tests/vectors/bgv_cost_model_v1.txt),
which `cargo test -p iroha_fhe --test bgv_cost_model_vectors` recomputes with
the Rust cost model, noise rules and harness. A change of a rule, a formula, a
frame, a candidate or a class limit fails one of the two. The proof-work
projections, the affine-map proposal and the core-SVP sanity numbers are
computed by the script alone.

TODO: run the pinned Lattice Estimator invocation and review the parameters;
build the circuit-private evaluation and client well-formedness proofs (R.11),
the verifiable opening (R.8), the threshold protocol (C.4) and a genuine
refresh (C.8); bind the execution relation (milestone 7) and measure the final
profile (milestone 8). The genuine relation replaces
the production refusal in the change that delivers it, as milestone 8 states.
The current arithmetic, unused Poseidon candidates and this plan do not
complete ZK03 or establish a secure encrypted product.
