# iroha_plonk_gadgets

Chips for the Iroha-native PIPA-v1 PLONKish engine (`iroha_plonk`,
`specs/plonk_ipa_v1.md`) on the Pasta fields of `iroha_pasta`. Stage GADGETS
(task T17).

- `poseidon::pow5`: the RP57 width-3 Pow5 permutation lane, ported from the
  M8 custom gate: three state columns and one auxiliary column, 37 rows and
  148 cells per permutation (4 full rows, 28 rows of two partial rounds, one
  partial row, 4 full rows), absorption fused into the first full round, the
  sponge output squeezed by the last round's gate. Six round-constant columns,
  shareable between lanes (blocks start at multiples of 37 rows).
- `poseidon::sponge`: the KAGEMUSHA sponge, bit for bit
  `iroha_pasta::poseidon::{hash, hash_with_domain}` and the
  `kagemusha_v1_poseidon` vectors of `fixtures/native_prover/kats_v1.json`
  (domain and arity prefix, `[x, 1]` and `[1, 0]` padding, output word 1). A configured `(domain, arity)` prefix starts from
  its constant post-prefix state and saves one permutation.
- `pow5_fq` (M3): the lane over Fq (`P_Fq`, the pinned `RP57_FQ` table), the
  same 37 rows and 148 cells per permutation, with nine pinned full-state
  permutation vectors computed independently from the vendored constants;
  `pow5_fq::duplex` is the transcript mode (squeezes carry the state on, as
  the native `Sponge`): `floor(m / 2) + 1` blocks per squeeze of `m` words
  plus one tap cell (`q_tap (x - s1[next])`, degree 2), the final squeeze
  through the squeeze gate.
- `range::running_sum`: range checks of 1 to 252 bits with `b`-bit limbs
  against a `2^b`-row table, with a shifted top-limb row (10 rows for 128 bits
  at `b = 15`, the M8 inventory).
- `range::u128`: checked add, subtract, add-constant, `<=`, `<` and the `<`
  bit on `Uint<BITS>` cells (`U128`, `U64`); an overflow or underflow has no
  satisfying assignment.
- `arith`: the glue gate `q_m a b + q_a a + q_b b + q_c c + q_d d + q_k` with
  boolean, select and is-zero gates (`select_constant`: `bit ? x : c` in one
  standard-gate row).
- `bytes` (M3): byte linking. A one-row-per-byte tape on two advice columns
  (little-endian running sums over `P_bytes` chunk segments, every byte in a
  256-row table; a second column recomposes the same bytes little- or
  big-endian, linked by a degree-3 gate): 1 cell per packed byte, 2 per
  linked byte. `PBytes` builds `P_bytes(d, b)` (length element, 31-byte
  zero-filled chunks) from constants, tape runs, opaque chunks (18 cells at
  `b = 15`) and bounded pieces, splitting pieces that cross a chunk
  boundary; `export_length_prefixed` cuts `LE32 len(sigma) || sigma` into the
  107 pieces a leaf exports. 32-byte messages decode to `lo`, `hi` and bit
  255: compressed points link to `(x, parity(y))` with canonical `x` and
  canonical parity (99 cells at `b = 15`), scalars to canonical limbs (39
  cells); hard forms are unsatisfiable on a mismatch, soft forms return a
  bit. Soft point decoding has two verdicts: `decode_point_soft` is
  `GroupEncoding::from_bytes` (accepts the identity encoding), and
  `decode_pipa_point_soft` is the PIPA-v1 point decoder
  (`iroha_plonk::transcript::decode_point`, which rejects it: verdict
  `canonical q`), returning the curve point `(-1, 2)` on a rejection so that
  soft verifiers of PIPA proofs feed total arithmetic. Its tests (`src/bytes/tests.rs`) reproduce the `P_bytes`,
  `proof_digest` and Payment vectors of `fixtures/kagemusha/wallet_v1_vectors.json`.
- `sha256` (M3): one SHA-256 compression per block on two-row spread units
  (13 advice columns: a `(dense, spread)` lookup pair, 7 bit and 4 word
  columns; one lookup `(2^33 + w, spread(x), x)` into a 2,433-row table;
  degree 5, rotations 0 and 1 only) and the codec of a Poseidon digest as the
  32-byte canonical little-endian message of one padded block with the
  `m < |D|` canonicity check. 2,062 rows and 23.3k cells per compression,
  2,094 rows with the codec (`hash_digest`, `HASH_DIGEST_ROWS`). With its
  own table it owns one argument; on the shared table it is the guest of a
  foreign-field range argument (`configure_shared`).
- `ff` (M3): FF-CRT foreign-field arithmetic for Pasta `q` in `Fp`, Pasta `p`
  in `Fq` and P-256 `p` and `n`: three 87-bit limbs (top 82), a fused gate
  proving `a b = c + q m` over the integers (four signed carries below
  `2^104` and the native residue; `|a b - c - q m| < 2^537 < N 2^348`),
  division and inversion (a witness and one fused multiplication), canonical
  comparison, and limb-wise add/sub/neg/scale/select on the glue chip with
  tracked limb bounds. One multiplication is 70 cells in 7 rows of 10
  columns (10 width-1 range lookups into one 15-bit column `V`, `2^15` rows,
  `k >= 16`; a top sublimb of `w < 15` bits is looked up as `v` and as
  `2^(15-w) v`; operands on block row 0, running sums on rows 1-6); the
  `C`/`Q` lookups have degree 6 (ternary patterns), the `U` lookups 5, gates
  3. The carry-bound memo is re-checked by
  `ff_carry_memo_bounds_hold_for_every_modulus`.
- `ecc` (M3): native Pasta ECC for in-circuit verifiers, Pallas in `Fp`
  (`PallasChip`) and Vesta in `Fq` (`VestaChip`), on 10 advice columns (4
  equality-enabled), degree 6. Points are `(x, y)` with the identity
  `(0, 0)`; complete addition (identity, equal, opposite) in one row;
  GLV variable-base multiplication `[W mod r] P` of limbs
  `W = lo + 2^128 hi`: split `W = (2^128 + K1) + zeta (2^128 + K2)` checked
  by one CRT gate (mod `p_N` and mod `2^136`), joint signed-digit chain
  from `[2] (P + phi(P))` with 124 incomplete iterations (exception-free by
  the GLV lattice sup-norm minimum `2^126.21`), 4 complete iterations and a
  complete even-digit correction: 141 rows (1,410 cells) per chain plus a
  3-row split and 29 range rows at `b = 15`, 1,469 cells per multiplication
  (G3.5 <= 1.6k); identity-guarded inputs (one more row), Horner chains
  sharing one split with joins read in place (142 rows per term), MSM, and
  fixed-base 3-bit windows with a complete final window (89 rows, 16 fixed
  columns).
- `p256` (M3): P-256 ECDSA verification in `Fq` on the `ff` chip
  (`SHA256withECDSA` over the 32-byte canonical encoding of a Poseidon
  digest: one SHA-256 block, `e` its big-endian integer mod `n`; low-S,
  `1 <= r < n`, canonical on-curve keys, `x(R) mod n = r`) for witness keys
  and fixed (issuer, root) keys, in hard mode (unsatisfiable unless the
  native verifier accepts) and soft mode (a bit equal to the native verdict,
  satisfiable for every input; failing inputs are replaced by defaults).
  `[u1] G` and fixed keys use 8-bit fixed-base windows (Orchard offsets,
  incomplete partial sums proven exception-free, a complete top window); a
  witness key uses a per-proof table of `[1..16] Q` behind one `lookup_any`
  argument (degree 6) with offset 4-bit digits and an incomplete
  double-and-add chain proven exception-free for every nonzero `u2`; the
  joins use affine complete addition with soft zero tests. Per
  verification: 115,787 cells and 10,003 rows for a witness key (18 advice
  columns; G3.1), 20,057 cells and 1,659 rows for a fixed key (G3.2),
  139,208 cells in 12,097 rows in the 17-column Q-leaf layout with the
  message's SHA block; 7,940 fixed rows per fixed base (8-bit windows). The
  window lookup and dynamic-table rows take separate cursors.
- `table` (M3b): the shared lookup table `[T, x_0..x_2, y_0..y_2, V]` of the
  Q leaf (eight fixed columns) and the guest interface through which the
  SHA-256 and window lookups ride on foreign-field range arguments, with
  its soundness conditions (fixed, row-disjoint activation; disjoint tag
  namespaces; every `V` entry below `2^15`).
- `q_leaf` (M3b): the Q-leaf layout of the P-256 and SHA-256 chips: 17
  advice columns (10 foreign-field, also SHA-256 below the split row; 4
  glue, also the window lookups below the split and the dynamic tables
  above the table rows; 3 SHA-only), 12 equality columns (three
  permutation sets), 10 lookup arguments (eight width-1, one width-3, one
  width-8), degree 6, 26 raw fixed columns; the row plan with bounded
  cursors; and `QLeafConfig::audit`, which checks the shared-table
  conditions on synthesized tables. Five witness-key and one fixed-key
  verification with their SHA blocks span 64,238 of 65,530 rows.
- `statement`: the G1 step statement encoding of the split-lineage step
  relations: 28 elements under `kgwstmt1`, in the order of the G1
  `KagemushaWalletStatementV1::field_items` (wire record section 3.2; not yet
  wired into a protocol path): version, the scheme-level relation identity
  (two limbs, witness cells bound by the public digest), scheme, asset,
  credential, successor lifecycle, sequence and `next_load`, the
  enabled-controls mask, the lineage inputs of a Send, both state
  commitments, the effect tag and a 10-element effect union (`credit_id` is
  one element). Its tests reproduce the G1 statement vectors of
  `fixtures/kagemusha/wallet_v1_vectors.json` natively and in circuit. Also
  the canonical cross-field limb encoding of spec S6 (`lo < 2^128`,
  `hi < 2^127`, `lo + 2^128 hi < modulus`) and the decomposition of an
  own-field word into those canonical limbs.
- `cells`: typed cells (`Word`, `Bit`, `Uint`) and row cursors; `tamper`: the
  per-cell tamper harness.

Every gate has degree at most 6 (`MAX_GATE_DEGREE`). The `iroha_plonk` floor
planner starts every region at row 0, so each chip owns its columns and a row
cursor.

Each chip has typed cells, a native reference, shared vectors, a per-cell
tamper suite (each assigned advice cell, changed alone, makes the strict
constraint checker fail) and an inventory test. The tamper suite shows that
every cell is pinned by a gate, a lookup or a copy. It does not show that a
composed relation binds what it should: a free witness that is only copied
into a hash is pinned by that copy whatever value it claims, so relations
need their own consistent-forgery tests.

- `tests/pow5_tamper.rs`: parity with `iroha_pasta::poseidon::permute`, every
  `m8_custom_gate_checks` Poseidon case, 37 rows / 148 cells / degree 6, lane
  sharing, misuse errors;
- `tests/digest_parity.rs`: the `kagemusha_v1_poseidon` vectors of
  `fixtures/native_prover/kats_v1.json` and the `iroha_pasta` raw-sponge
  known answers in circuit, folded and unfolded, on both fields; M7 hash
  shapes;
- `tests/glue_tamper.rs`, `tests/u128_tamper.rs`: every operation against its
  native reference, the M8 u128 cases (a sum of exactly `2^128`, a
  subtraction below zero, a wrong sum) and the M7 u64 windows;
- `tests/statement_digest.rs`: the in-circuit statement digest equals
  `StatementV1::digest`; non-canonical foreign limbs are unsatisfiable; an
  own-field word decomposes only into its canonical limbs;
- `tests/real_proofs.rs`: PIPA-v1 proofs on Pallas and Vesta with both
  transcripts.
- `src/ff/tests.rs`: products, quotients, inverses and linear operations
  against `num-bigint` for all four moduli
  (`ff_mul_matches_bigint_{fq_in_fp,fp_in_fq,p256_p,p256_n}`), carry overflow
  and field-solved wraparound forgeries rejected by the range lookups alone
  (`ff_carry_bound_overflow_is_unsatisfiable`), non-canonical limb splits
  and top sublimbs that only the scaled membership rejects
  (`ff_noncanonical_limbs_rejected`), the same attacks on the Q leaf's
  shared table (`ff_adversarial_blocks_rejected_on_the_shared_table`), the
  block patterns, the comparison at `m - 1`, `m`, `m + 1`, the inventory,
  and ignored release-only tamper sweeps and the k = 16 measurement
  (`ff_gate_shape_measurement_release`).
- `src/q_leaf/tests.rs`: the leaf's column, argument and degree counts, the
  table rows, 8-bit windows and capacity, the bounded cursors, and the
  audit rejecting a foreign-field block inside the SHA rows and window
  lookups on foreign-field rows.
- `tests/sha256.rs`: the FIPS 180 vectors (one and two blocks), the degree
  (`sha256_gate_degree_at_most_six`), SHA-256 of Poseidon digests against
  `sha2` (`sha256_of_poseidon_digest_matches_native`), the G3.3 measurement
  at the 17-column Q-leaf width, and ignored Pallas proofs at k = 12 and 16;
  `src/sha256/tests.rs` tampers every cell of each unit kind and forges
  splits and non-canonical digest encodings.
- `tests/pow5_fq_lane.rs`: the Fq lane against the pinned RP57 Fq vectors
  with the full output state exposed (`pow5_fq_lane_matches_rp57_fq_vectors`),
  the `poseidon_constants.fq` table, the `kagemusha_v1_poseidon.fq` vectors,
  the Pallas `poseidon_transcript` scripts in duplex mode, tamper suites,
  consistent forgeries that only the tap or squeeze gate rejects, a Pallas
  proof, and the ignored k = 16 measurement (1,771 permutations, 65,527
  rows).
- `src/ecc/tests.rs`: the exact GLV lattice KAT
  (`glv_lattice_sup_norm_minimum_pallas_vesta`), multiplication parity on
  both curves with edge scalars and bases (`glv_mul_matches_native_{pallas,vesta}`),
  alternative splits with a half `>= 2^128` that the CRT gate accepts and the
  chain rejects (`glv_split_rejects_halves_ge_2_128`), adversarial bases and
  digit sequences, including one that makes iteration 125 exceptional and
  the complete tail absorbs
  (`glv_incomplete_iterations_never_exceptional_on_adversarial_bases`),
  `complete_add_handles_identity_equal_opposite`,
  `identity_guarded_horner_matches_native_msm`,
  `fixed_base_mul_matches_native`, tamper suites, a Vesta proof and the G3.5
  inventory (`glv_inventory_at_the_gate_shape`).
- `src/p256/tests.rs`: the native reference against the `p256` crate; the
  210 64-byte Wycheproof P1363 P-256/SHA-256 vectors in soft mode
  (`p256_soft_bit_equals_native_on_wycheproof_prehashed`, fixture
  `tests/fixtures/wycheproof_ecdsa_secp256r1_sha256_p1363.json`); high `s`,
  `r` or `s` zero or at least `n`, and invalid keys in soft and hard modes
  (`p256_rejects_high_s_r_ge_n_zero`); constructed edge cases (keys `+-G`,
  `2G`, `G / 2`, smallest and largest `x`, `x >= n`; doubling and identity
  joins, `u1 = 0`, `e >= n`, `x(R) >= n`, `s` at both low-S ends, `u1` and
  `u2` at the digit extremes) for witness and fixed keys
  (`p256_complete_for_native_accepted_edge_keys`); SHA-256 of Poseidon
  digests in-circuit; forged soft-test witnesses; the degree; the G3.1 and
  G3.2 inventory; every cell of the soft tests tampered, and (ignored,
  release) every window cell plus evenly spaced glue and foreign-field
  cells of accepted and rejected verifications; the Q-leaf layout matches
  native verdicts and keeps the shared-table conditions
  (`p256_leaf_keeps_the_shared_table_conditions`), and (ignored, release)
  its window, SHA and sampled cells are pinned; a k = 16 Pallas proof of a
  witness-key and a fixed-key verification with their SHA blocks in the
  17-column leaf (`p256_proof_measurement_release`).
- `tests/m3_gates.rs`: the M3 proof gates G3.6 and G3.7 at k = 16 (ignored,
  release; one process per `RAYON_NUM_THREADS`, peak RSS from
  `/usr/bin/time -l`): a Q leaf in the `q_leaf` layout filled with the P-256
  and SHA-256 chips (five witness-key and one fixed-key verification with
  their messages, 739,458 cells, 17 / 26 / 12 / 10), an A load of six Pow5 lanes running depth-32 IMT-like paths
  (156 paths, 1.58M cells), and the design's exact shapes (22 / 32 / 8 / 3 and
  32 / 44 / 10 / 3) filled with degree-6 S-box chains and range lookups. Each
  prints the shape, key generation, synthesis, proving and verification
  times, proof bytes, `load1`, the peak resident set and CPU time per
  phase, the compiled (hash-consed) expression-DAG size, with the design's
  64 MiB MSM budget per kernel; pinned parameters come from a cache in the
  target directory, accepted only when they hash to the pinned digest
  (`pinned_params_cache_load_time` times derivation and loading). Debug-sized tests check the harness circuits against native
  references, reject forged roots and out-of-order keys, and tamper every
  cell.

Validate:

```sh
cargo test -p iroha_plonk_gadgets
cargo test -p iroha_plonk_gadgets --release -- --include-ignored
cargo clippy -p iroha_plonk_gadgets --all-targets -- -D warnings
```
