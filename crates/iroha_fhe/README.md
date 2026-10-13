# iroha_fhe

Deterministic exact arithmetic shared by Iroha's homomorphic-encryption
protocols. This crate is the single owner of the reusable ring arithmetic below
the protocol layers; `specs/fhe_ownership_inventory.json` records which
function owns each primitive and `scripts/check_fhe_ownership_map.py` checks
that record against the source.

For the consumers below it holds arithmetic only. Their schemes, parameter
sets, key and ciphertext formats, wire codecs, noise accounting and proofs stay
with their protocols:

| Consumer | Location | What it keeps |
| --- | --- | --- |
| BFV and RAM-LFE | `crates/iroha_crypto/src/fhe_bfv.rs` | wire types, parameter policy, guard order, diagnostics, key switching flows |
| ZK-AMS multi-key BGV | `crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe*` | profile, wire, collective protocols, test-only references |
| Jindo | `crates/iroha_core_privacy/src/privacy_engines/jindo` | pinned primes and roots, RNS polynomial type |
| Bootle-Lantern | `crates/iroha_core_privacy/src/privacy_engines/bootle_lantern` | pinned Montgomery constants and CRT profile, ring types |

Consumers call the kernels by their own names: a renamed import of a function
or type hides call sites from the ownership inventory, and its tests reject one.

The crate also owns `bgv`, the exact modular RNS-BGV scheme that RAM-LFE and
SoraCloud are to share (see [RNS-BGV](#rns-bgv)). Nothing consumes it yet.

Production dependencies are `zeroize`, `thiserror`, `blake3` (coin expansion and
profile identities) and `getrandom` (operating-system entropy); a test fails
when that list changes. No policy, node or SDK crate can be reached from here,
so the dependency graph stays acyclic.

## Modules

| Module | Content |
| --- | --- |
| `modular` | add, subtract, multiply, power and inverse modulo a word modulus; Miller-Rabin; primitive-root search |
| `constant_time` | branch-free selects, canonical add/subtract, fixed-modulus Montgomery arithmetic, centered three-prime CRT |
| `ntt` | radix-2 cyclic transform, negacyclic twist and product, exact CRT convolution |
| `polynomial` | coefficient-wise arithmetic and the schoolbook negacyclic products, one residue kernel generic over word and fixed-modulus arithmetic |
| `rns` | modulus-chain validation, residue decomposition, CRT reconstruction, basis extension |
| `rounding` | centered lift, nearest division, scale-and-round, modulus-switch rounding |
| `key_switch` | digit decomposition and the digit/key inner product |
| `automorphism` | the signed coefficient permutation of `X -> X^k` |
| `accel` | accelerated slice kernels, their dispatch and scalar references |
| `natural` | arbitrary-precision non-negative integers for public quantities |
| `rns_chain` | exact mixed-radix basis conversion and congruence-preserving scale-down over chains of any length |
| `ntt_plan` | precomputed constant-time negacyclic transform of one prime below `2^62` |
| `bgv` | the RNS-BGV scheme: profiles, keys, encryption, leveled operations, canonical encodings, noise bounds and shape planning, slot encodings, cost model |

## RNS-BGV

`bgv` is the scheme of Brakerski, Gentry and Vaikuntanathan with the plaintext
in the low bits: `c0 + c1*s = m + t*e (mod Q_l)`, `gcd(Q_l, t) = 1`. It is not
BFV scaling and not the exact-lift construction of `iroha_crypto`. It is a
starting candidate: no profile has a reviewed security estimate, and circuit
privacy, client well-formedness proofs, verifiable opening, threshold
decryption and refresh belong to later tasks.

- **Chain.** Any number of main primes and special primes below `2^62`, all
  `1 mod 2*N*t`. Basis extension is exact (mixed radix, centered): no `u128`
  reconstruction, no approximate conversion, no floating point.
- **Rounding.** A modulus switch and the division by the special modulus use
  `c' = (c - t*w) / D` with `w` the centered representative of `c * t^-1`
  modulo the odd `D`. No tie exists; the plaintext is unchanged because
  `D = 1 mod t`.
- **Key switching.** Hybrid RNS: digits of consecutive main primes, exact
  centered extension, congruence-preserving division by the special modulus.
- **Coins.** 64 bytes of operating-system entropy per operation, expanded by
  BLAKE3 `derive_key` with the profile identity and a purpose tag. Uniform
  ternary secrets and masks, centered binomial errors with `eta = 21`
  (support `[-21, 21]`, variance 10.5), uniform residues by rejection. The
  seed, the hash state that absorbs it and the buffered stream live in one
  heap block that is overwritten whole before it is released.
- **Noise.** Every ciphertext carries an exact public upper bound of its
  noise, computed from profile constants and the operation history only. An
  operation whose bound would exceed `(Q_l - 1) / 2` is refused. The bound is
  worst case; with the bounded error sampler an admitted sequence over honest
  coins never fails to decrypt.
- **Planning.** `bgv::plan` applies the same rules to the public shape of a
  ciphertext (level, components, bound). Every operation takes the shape of
  its result from there, so a sequence can be planned without a key or a
  ciphertext and is admitted on ciphertexts exactly when its plan is.
- **Canonical encodings.** Parameter sets, ciphertexts, public keys, switching
  keys and evaluation keys encode to canonical words and fixed byte frames
  and decode from them, rejecting another profile, any other length and a
  non-canonical residue. The secret key has a custody frame of two bits per
  coefficient in a clearing buffer. A decoded object is well formed as an
  encoding only; authentication, proofs of well-formedness, Norito wire types
  and bounded admission belong to the consumers.
- **Encodings.** `SlotEncoding` gives the scalar slots a plaintext modulus
  admits in the ring: 128 sparse slots for `t = 257` at any `N >= 128`, or `N`
  slots for a fully splitting modulus.
- **Candidates.** `BgvCandidate` pins three parameter sets over `t = 257`.
  `specs/fhe_bgv_cost_summary.json` holds their sizes, work units, the plan of
  every maximum-shape tape family, host measurements, projections of
  sanitization headroom and proof work, and a core-SVP sanity calculation.
  `make check-fhe-bgv-cost` checks it with `scripts/fhe_bgv_cost_model.py`,
  and `tests/bgv_cost_model_vectors.rs` recomputes its sizes, work units,
  instruction costs, tape plans and contract inputs with this crate. No
  candidate holds the maximum shape of its class when a tape is lowered
  instruction by instruction; the summary says what each holds.
- **Security estimate (unreviewed).** `scripts/fhe_bgv_lattice_estimator.sage`
  ran the Lattice Estimator at a pinned commit on every candidate; the raw
  output is `specs/fhe_bgv_lattice_estimator_output.txt` and the summary
  restates it (`security_estimate.lattice_estimator`). For plain LWE of
  dimension `N` on the largest modulus `Q * P`, the cheapest attack that
  returned a cost is, in bits under BDGL16 classical / ADPS16 classical /
  ADPS16 quantum: affine 136.9 / 102.5 / 93.0, bounded 197.9 / 161.5 / 146.8,
  refresh 135.3 / 99.0 / 89.8. The design target of 128 classical bits under
  BDGL16 is met by all three on the attacks that returned a cost, with 8.9 and
  7.3 bits of margin for the affine and refresh candidates; some attacks
  returned none (the summary lists them). Under the core-SVP count of ADPS16
  only the bounded candidate meets it. The estimate does not cover the ring structure,
  the circular-security assumption of the published switching keys, keys
  that were not sampled honestly or side channels, and it leaves the class
  fit as it is. No candidate is qualified; the parameters await review.

## Rounding rules

No floating point is used. Every rule is stated in `rounding` and tested at
exact halves and range boundaries:

- centered lift of `x` modulo `m`: `x` when `x <= floor(m / 2)`, else `x - m`
  (the even midpoint is positive);
- nearest division and scale-and-round: nearest integer, ties away from zero;
- modulus switching: centered lift, scale by `to / from` with the rule above,
  then the least non-negative residue modulo the target.

## Determinism and acceleration

Every function returns an exact integer result, so equal inputs give equal
words on every target. The scalar implementation is the semantic reference.

The `simd` feature adds NEON (AArch64) and AVX2 (x86-64, detected at run time)
kernels for modular addition, subtraction, multiplication and the transform
butterflies. They require canonical operands; sums require a modulus below
`2^62` and products an odd modulus below `2^32`. Any other input takes the
scalar path, and each dispatching function is tested word-for-word against its
`_scalar` reference. No environment variable or configuration value selects a
backend.

`simd` is a default feature of this crate, so its own tests cover the kernels.
Workspace consumers depend on it with `default-features = false`;
`iroha_crypto/bfv-accel` is the one feature that turns the kernels on in a
node build.

The NEON kernel runs natively on every AArch64 host. The AVX2 kernel runs with
the CPU's instructions on x86-64 hosts that have AVX2. Test builds on other
hosts compile the same kernel source over `accel/avx2_model.rs`, a lane model
of the twelve intrinsics it uses, and compare it with the scalar reference; on
x86-64 a test compares each modelled intrinsic with the CPU. The model checks
the kernel's schedule. It is not a run of the instructions.

Metal and CUDA kernels for word-modulus arithmetic do not exist yet. The GPU
transforms in `crates/fastpq_prover` are specialised to the Goldilocks proof
field and sit above this crate. The dispatch site in
`ntt::cyclic_ntt_in_place` carries the `TODO`.

## Secrets

Kernels hold copies of operands and partially built results in clearing
buffers, which are cleared on return, on a rejected input and on unwind.
`tests/clearing.rs` installs an allocator that inspects freed blocks and
asserts this for each of those exits. A value a kernel returns belongs to the
caller. `constant_time` is branch-free in operand values; `modular` is not.

## Tests

```sh
cargo test -p iroha_fhe                         # accelerated kernels and scalar references
cargo test -p iroha_fhe --no-default-features   # scalar-only build
make check-fhe-bgv-cost                         # cost summary, its view and the known answers are current
```

The BGV tests use two references that share no code with the crate:
`tests/vectors/bgv_reference.py` (Python integers, its own BLAKE3) generates
`tests/vectors/bgv_kat_v1.txt` from master seeds, and `tests/support/oracle.rs`
recomputes every pipeline at run time with `num-bigint`. `tests/bgv_vectors.rs`
and `tests/rns_chain_vectors.rs` require the crate to reproduce every pinned
word; `tests/bgv_noise.rs` compares the public noise bound with the exact
noise the oracle computes; `tests/bgv_clearing.rs` observes released memory,
the block that holds the seed and the stream state included;
`tests/bgv_surface.rs` checks that seeded entry points stay behind the
`bgv-test-fixtures` feature.

`tests/support/machine.rs` is the costing harness: one lowering of the eleven
V1 tape instructions that runs over public shapes and over ciphertexts.
`tests/bgv_tape_plan.rs` checks that the two runs agree instruction by
instruction and that the encrypted run computes the tape;
`tests/bgv_cost_model_vectors.rs` holds the tracked cost summary to the Rust
model; `tests/bgv_cost_measurement.rs` holds the measured workloads.

`tests/canonical_vectors.rs` pins known-answer vectors for every primitive.
The answers were derived with Python integers, and the test re-derives each one
with an independent `num-bigint` oracle built from the textbook definitions
(quadratic DFT, schoolbook negacyclic product, constructive CRT, exact rational
rounding), so neither the kernels nor the vectors can drift unnoticed.
