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
- The core-SVP columns are this repository's own sanity calculation (primal
  uSVP on `Q*P`, 2016 estimate). It reproduces the 128-bit rows of the 2018
  Homomorphic Encryption Standard within one bit in the BDGL16-style column.
  It is kept beside the Lattice Estimator numbers below and agrees with the
  estimator's primal uSVP result within one bit for every profile.

**Lattice Estimator result (an estimate, not a qualification).**
[`scripts/fhe_bgv_lattice_estimator.sage`](../scripts/fhe_bgv_lattice_estimator.sage)
was run with SageMath 10.9 and the estimator at the commit the script pins.
Its raw output is tracked in
[`fhe_bgv_lattice_estimator_output.txt`](fhe_bgv_lattice_estimator_output.txt)
with the versions, host, dates and exact commands, and
`security_estimate.lattice_estimator` of the summary restates it;
`make check-fhe-bgv-cost` holds the summary to the record and the record to
the code of the script. What is estimated:

- plain LWE of dimension `n = N` with the exact modulus of the profile, a
  uniform ternary secret and the centered binomial error with `eta = 21`. A
  sample is `b = -a*s + t*e` with `t` invertible, so the error of the
  estimate is `e`, not `t*e`. The script derives the moduli by the first-prime
  rule and refuses to run unless they are the primes
  [`profile.rs`](../crates/iroha_fhe/src/bgv/profile.rs) pins;
- three instances per profile: the public key (modulus `Q`, `m = n` samples),
  one switching-key polynomial (modulus `Q*P`, `m = n`) and modulus `Q*P`
  with unlimited samples. A key set publishes `n * digits * (1 + Galois keys)`
  samples modulo `Q*P` under one secret (`published_samples` in the summary),
  and a sample modulo `Q*P` reduces to one modulo `Q`, so the unlimited-sample
  instance is the conservative one for the secret key. A fresh ciphertext is
  `2n` samples modulo the smaller `Q` under its own ternary mask and has no
  instance of its own;
- the attacks of the estimator's `LWE.estimate`, one process each with a time
  and a memory limit: primal uSVP, primal BDD, the two primal hybrid attacks,
  dual and dual hybrid under BDGL16 (classical), ADPS16 (classical core-SVP)
  and ADPS16 in quantum mode, and Arora-GB and coded BKW. A self-check in the
  record shows these calls equal `LWE.estimate` on Kyber512.

The cheapest attack that returned a cost, over the three instances:

<!-- fhe-bgv-lattice-estimator:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Profile | Role | BDGL16 classical | ADPS16 classical | ADPS16 quantum | 128 bits under BDGL16 | 128 bits under ADPS16 | Sanity: core-SVP classical / BDGL16-style | Attacks with a result |
| --- | --- | ---: | ---: | ---: | --- | --- | ---: | ---: |
| `bgv.f257.n14.q6x50.p2x60` | candidate for affine.v1 | 136.9 (bdd, Q*P, m = n) | 102.5 (dual_hybrid, Q*P, m = n) | 93.0 (dual_hybrid, Q*P, m = n) | met (+8.9) | **not met** (-25.5) | 102.8 / 137.2 | 46 of 60 |
| `bgv.f257.n16.q22x50.p2x60` | candidate for bounded.v1 | 197.9 (bdd, Q*P, m = n) | 161.5 (dual_hybrid, Q*P, m = n) | 146.8 (bdd, Q*P, m = n) | met (+69.9) | met (+33.5) | 161.8 / 198.2 | 42 of 60 |
| `bgv.f257.n16.q32x50.p2x60` | candidate for refresh.v1 | 135.3 (bdd, Q*P, m = n) | 99.0 (bdd, Q*P, m = n) | 89.8 (bdd, Q*P, m = n) | met (+7.3) | **not met** (-29.0) | 99.0 / 135.4 | 42 of 60 |
| `bgv.derive.n16.t786433.q25x60.p3x60.d2` | measured batching comparator; not a candidate | 138.3 (bdd, Q*P, m = n) | 101.9 (dual, Q*P, m = n) | 92.5 (dual, Q*P, m = n) | met (+10.3) | **not met** (-26.1) | 101.9 / 138.3 | 36 of 60 |
| `bgv.derive.n14.t257.q13x50.p2x60.d2` | measured timing configuration; not a candidate | 73.2 (bdd, Q*P, m = ∞) | 38.8 (dual, Q*P, m = n) | 35.2 (dual, Q*P, m = n) | **not met** (-54.8) | **not met** (-89.2) | 38.8 / 73.2 | 36 of 60 |
<!-- fhe-bgv-lattice-estimator:end -->

Every attack on the largest modulus `Q*P`, as `m = n` / unlimited samples
(bits; a word instead of a number says why the record has no cost):

<!-- fhe-bgv-lattice-estimator-attacks:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Profile | Cost model | primal uSVP | primal BDD | primal hybrid | primal hybrid with meet in the middle | dual | dual hybrid | Cheapest on Q, m = n |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `bgv.f257.n14.q6x50.p2x60` | BDGL16 | 137.1 / 137.1 | 136.9 / 136.9 | 136.9 / 136.9 | 169.3 / 169.3 | 137.2 / 137.2 | 136.9 / 136.9 | 199.4 (dual_hybrid) |
| `bgv.f257.n14.q6x50.p2x60` | ADPS16 | 102.8 / 102.8 | 102.8 / 102.8 | 102.8 / 102.8 | 151.0 / stopped | 102.8 / 102.8 | 102.5 / 102.5 | 165.3 (dual_hybrid) |
| `bgv.f257.n14.q6x50.p2x60` | ADPS16-quantum | 93.3 / 93.3 | 93.3 / 93.3 | 93.3 / 93.3 | stopped | 93.3 / 93.3 | 93.0 / 93.0 | 150.0 (dual_hybrid) |
| `bgv.f257.n16.q22x50.p2x60` | BDGL16 | 198.1 / 198.1 | 197.9 / 197.9 | 197.9 / 197.9 | stopped | 198.2 / 198.2 | 197.9 / 197.9 | 222.7 (dual_hybrid) |
| `bgv.f257.n16.q22x50.p2x60` | ADPS16 | 161.8 / 161.8 | 161.8 / 161.8 | 161.8 / 161.8 | stopped | 161.8 / 161.8 | 161.5 / 161.5 | 186.3 (dual_hybrid) |
| `bgv.f257.n16.q22x50.p2x60` | ADPS16-quantum | 146.8 / 146.8 | 146.8 / 146.8 | 146.8 / 146.8 | stopped | 146.8 / 146.8 | 146.8 / 146.8 | 169.3 (bdd) |
| `bgv.f257.n16.q32x50.p2x60` | BDGL16 | 135.3 / 135.3 | 135.3 / 154.8 | 135.4 / 150.4 | stopped / not started | 135.4 / 135.4 | 135.4 / 135.4 | 146.4 (bdd) |
| `bgv.f257.n16.q32x50.p2x60` | ADPS16 | 99.0 / 99.0 | 99.0 / 138.4 | 99.0 / 138.4 | not started | 99.0 / 99.0 | 99.0 / 99.0 | 110.1 (bdd) |
| `bgv.f257.n16.q32x50.p2x60` | ADPS16-quantum | 89.8 / 89.8 | 89.8 / 125.6 | 89.8 / 125.6 | not started | 89.8 / 89.8 | 89.8 / 89.8 | 99.9 (bdd) |
| `bgv.derive.n16.t786433.q25x60.p3x60.d2` | BDGL16 | 138.3 / 138.3 | 138.3 / 138.3 | not attempted | not attempted | 138.3 / 138.3 | 138.3 / 138.3 | 156.7 (bdd) |
| `bgv.derive.n16.t786433.q25x60.p3x60.d2` | ADPS16 | 101.9 / 101.9 | 101.9 / 101.9 | not attempted | not attempted | 101.9 / 101.9 | 101.9 / 101.9 | 120.3 (bdd) |
| `bgv.derive.n16.t786433.q25x60.p3x60.d2` | ADPS16-quantum | 92.5 / 92.5 | 92.5 / 92.5 | not attempted | not attempted | 92.5 / 92.5 | 92.5 / 92.5 | 109.2 (bdd) |
| `bgv.derive.n14.t257.q13x50.p2x60.d2` | BDGL16 | 73.2 / 73.2 | 73.2 / 73.2 | not attempted | not attempted | 73.2 / 73.2 | 73.2 / 73.2 | 86.4 (bdd) |
| `bgv.derive.n14.t257.q13x50.p2x60.d2` | ADPS16 | 38.8 / 38.8 | 38.8 / 38.8 | not attempted | not attempted | 38.8 / 38.8 | 38.8 / 38.8 | 52.3 (bdd) |
| `bgv.derive.n14.t257.q13x50.p2x60.d2` | ADPS16-quantum | 35.2 / 35.2 | 35.3 / 35.3 | not attempted | not attempted | 35.2 / 35.2 | 35.2 / 35.2 | 47.4 (bdd) |
<!-- fhe-bgv-lattice-estimator-attacks:end -->

- **Target.** The design target of task C.3 is at least 128 bits classically
  under BDGL16, with quantum costs reported separately. Under BDGL16 every
  candidate meets it on the attacks that returned a cost: the affine and the
  refresh candidate with less than ten bits to spare, the bounded candidate
  with about seventy. Under ADPS16, the core-SVP count without the polynomial
  factors of BDGL16, only the bounded candidate reaches 128 bits: the affine
  candidate is about 25 bits short and the refresh candidate about 29. No
  quantum target is set; under ADPS16 in quantum mode the affine and the
  refresh candidate are below 100 bits.
- **Which attacks have a cost.** Primal uSVP, primal BDD, dual and dual
  hybrid returned a cost for every profile, instance and cost model. The
  primal hybrid attack was run on the three candidates at `Q*P` and returned
  a cost in all eighteen runs: it guesses no coordinate and costs what primal
  BDD costs, except for the refresh candidate under BDGL16, where it guesses
  18 coordinates with `m = n` (135.4 bits) and 71 with unlimited samples
  (150.4 bits) and stays above primal uSVP. The meet-in-the-middle hybrid
  returned a cost in three runs, all for the affine candidate (169.3 bits
  under BDGL16, 151.0 under ADPS16 with `m = n`), far above primal BDD; of
  its fifteen other runs on the candidates ten were stopped when the job
  ended and five never started. Arora-GB reports an infinite cost for the
  affine candidate with `m = n` and exceeded the 16 GiB memory limit in its
  five other runs; coded BKW reached the 60-minute limit for all three
  candidates. Hybrid attacks, Arora-GB and BKW were not attempted on the
  modulus `Q` or on the measured configurations.
- **Attacks without a cost.** A cell that holds a word has no cost in the
  record, and the summary gives the reason attack by attack. An attack
  without a cost is not evidence that the attack is expensive: the verdicts
  are over the attacks that returned a cost. The limits are wall-clock limits
  on a host that other builds kept far above its core count (the record has
  the load at the start of each invocation), so a run on an idle host may
  finish more.
- **Comparison with the sanity calculation.** The estimator's primal uSVP
  block sizes are those of the sanity calculation (352, 554 and 339) and the
  costs agree within 0.1 bit, so there is no large discrepancy. The dual
  hybrid attack, which the sanity calculation does not cost, is up to 0.3
  bits cheaper than primal uSVP. For the refresh candidate with unlimited
  samples the estimator's BDD and primal hybrid figures are higher than with
  `m = n` (it selects a larger final SVP dimension); the minimum over attacks
  is the same for both sample counts.
- **Measured configurations.** The last two rows are not candidates. The
  timing configuration (13 main primes at `N = 2^14`) is far below any
  target and exists to time affine instructions only.

**Proposals (not applied).** No pinned parameter set was changed. For the
task C.3 owner, the record also estimates shapes that differ from a candidate
in the length of its chain or in its ring degree:

<!-- fhe-bgv-lattice-estimator-proposals:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->
| Shape (not pinned) | Differs from | BDGL16 classical | ADPS16 classical | ADPS16 quantum | 128 bits under BDGL16 | 128 bits under ADPS16 | Attacks with a result, of those run |
| --- | --- | ---: | ---: | ---: | --- | --- | ---: |
| `bgv.derive.n14.t257.q4x50.p2x60` | `bgv.f257.n14.q6x50.p2x60`: 4 main primes | 185.1 (dual_hybrid, Q*P, m = n) | 151.0 (dual_hybrid, Q*P, m = n) | 137.0 (dual_hybrid, Q*P, m = n) | met (+57.1) | met (+23.0) | 28 of 28 |
| `bgv.derive.n14.t257.q5x50.p2x60` | `bgv.f257.n14.q6x50.p2x60`: 5 main primes | 157.3 (dual_hybrid, Q*P, m = n) | 123.0 (dual_hybrid, Q*P, m = n) | 111.8 (dual_hybrid, Q*P, m = n) | met (+29.3) | **not met** (-5.0) | 24 of 24 |
| `bgv.derive.n15.t257.q6x50.p2x60` | `bgv.f257.n14.q6x50.p2x60`: N = 2^15 | 302.0 (dual_hybrid, Q*P, m = n) | 266.9 (dual_hybrid, Q*P, m = n) | 242.5 (dual_hybrid, Q*P, m = n) | met (+174.0) | met (+138.9) | 24 of 24 |
| `bgv.derive.n16.t257.q26x50.p2x60` | `bgv.f257.n16.q32x50.p2x60`: 26 main primes | 166.9 (bdd, Q*P, m = n) | 130.5 (dual_hybrid, Q*P, m = n) | 118.5 (dual_hybrid, Q*P, m = n) | met (+38.9) | met (+2.5) | 24 of 24 |
| `bgv.derive.n16.t257.q27x50.p2x60` | `bgv.f257.n16.q32x50.p2x60`: 27 main primes | 160.7 (bdd, Q*P, m = n) | 124.4 (bdd, Q*P, m = n) | 112.9 (bdd, Q*P, m = n) | met (+32.7) | **not met** (-3.6) | 24 of 24 |
| `bgv.derive.n17.t257.q32x50.p2x60` | `bgv.f257.n16.q32x50.p2x60`: N = 2^17 | 297.0 (dual_hybrid, Q*P, m = n) | 259.9 (dual, Q*P, m = n) | 235.8 (dual, Q*P, m = n) | met (+169.0) | met (+131.9) | 14 of 24 |
<!-- fhe-bgv-lattice-estimator-proposals:end -->

- A shortfall exists under ADPS16 only: 25.5 bits for the affine candidate
  and 29.0 bits for the refresh candidate. The summary records, per candidate,
  the smallest change the record supports
  (`security_estimate.lattice_estimator.proposals`): the longest chain at the
  same ring degree that reaches 128 bits, bracketed by the next longer chain
  that does not, and the same chain at the next ring degree.
- **Affine candidate.** Four main primes instead of six at `N = 2^14` reach
  151.0 bits under ADPS16; five do not (123.0). Four primes still hold the
  two affine families the candidate holds today, which need two, and the
  projected affine map, which needs three, but not
  `affine.state_and_registers` with the projected flood, which needs five.
  The alternative is the same six-prime chain at `N = 2^15`.
- **Refresh candidate.** Twenty-six main primes instead of thirty-two at
  `N = 2^16` reach 130.5 bits under ADPS16, a margin of 2.5 bits; twenty-seven
  do not (124.4). Twenty-six primes hold a rank-16 segment and leave less
  room for a refresh than the thirty-two that already do not hold the cited
  bootstrapping depth beside it. The alternative is the same chain at
  `N = 2^17`, for which the record has primal uSVP, dual and part of the dual
  hybrid results only.
- A shorter chain holds fewer of the tape families of the next table, and a
  larger ring degree doubles every size and roughly doubles the work. Neither
  is applied here: choosing between them, or accepting the BDGL16 reading of
  the target, is a decision for the task C.3 owner and the parameter review.
  The shapes above are as unqualified as the candidates.

**What the estimate does not cover.** The profiles remain **unqualified**
pending review. The numbers above are the output of one tool under its
heuristics, for plain LWE. They do not cover:

- the ring structure: the estimator treats ring-LWE as LWE of the same
  dimension;
- the circular-security (key-dependent message) assumption of publishing the
  relinearization and Galois keys, which encrypt `s^2` and `s(X^k)` under `s`;
- keys or ciphertexts that were not sampled honestly: nothing proves a
  published key well formed;
- side channels of the implementation;
- the class fit: no candidate holds the maximum shape of its class when a
  tape is lowered instruction by instruction (below), and an estimate does
  not repair that. Meeting a bit target and holding a class are separate
  conditions, and no candidate has both established.

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
  output, which the summary projects at three primes. The canonical contract
  now requires this
  [normalizing lowering](ram_lfe_execution_proof.md#normalizing-lowering) for
  every class, under one fixed public schedule for each class profile padded
  to the class maximum, and `iroha_crypto` holds its cleartext oracle. Nothing
  evaluates it on ciphertexts. The three-prime figure stays a projection, and
  the worst-case noise and work of the complete padded schedule, with key
  switches, masking and sanitization, are still to be derived and measured
  (obligation `NL-L3` of that contract). Folding does not qualify a candidate.
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

TODO: have the parameters and the Lattice Estimator record reviewed, decide the
proposals recorded for the candidates that fall short under ADPS16, and finish
the attacks the record has no cost for;
derive and measure the physical noise and work of the normalizing lowering
under one fixed public schedule for each class profile padded to the class
maximum (C.3 with R.3, R.7 and R.9);
build the circuit-private evaluation and client well-formedness proofs (R.11),
the verifiable opening (R.8), the threshold protocol (C.4) and a genuine
refresh (C.8); bind the execution relation (milestone 7) and measure the final
profile (milestone 8). The genuine relation replaces
the production refusal in the change that delivers it, as milestone 8 states.
The current arithmetic, unused Poseidon candidates and this plan do not
complete ZK03 or establish a secure encrypted product.
