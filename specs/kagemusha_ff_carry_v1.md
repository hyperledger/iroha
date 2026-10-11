# KAGEMUSHA FF-CRT carry bounds V1

Chip: `iroha_plonk_gadgets::ff` (`crates/iroha_plonk_gadgets/src/ff/mod.rs`).
Moduli: Pasta `q` in an `Fp` circuit (Fq-in-Fp), Pasta `p` in an `Fq` circuit
(Fp-in-Fq), P-256 `p` and P-256 `n` (in either native field).
Executable form: `ff::tests::ff_carry_memo_bounds_hold_for_every_modulus`
(exact `num-bigint` interval arithmetic, and Lemma 1 exhaustively).
Adversarial ("tamper") tests of the memo's premises:
`ff_carry_bound_overflow_is_unsatisfiable`, `ff_noncanonical_limbs_rejected`
(including top sublimbs that pass the plain membership and fail only the
scaled one, rejected on the block's operand row),
`ff_adversarial_blocks_rejected_on_the_shared_table` (the same attacks on the
Q leaf's shared table) and `ff_range_patterns_follow_the_block_layout`.
The boundary tests `ff_final_usable_row_binds_fused_and_comparison_blocks` and
`ff_carry_endpoints_are_range_checked_through_the_final_row` exercise the final
usable row, the first forbidden blinding row, and both signed carry endpoints
with immediately invalid neighbors, on private and shared tables in both fields.

**What changed in M3b (D1).** Only the range-check mechanism and the block
rows: the `(tag, value)` table with 15/12/7-bit sub-tables became one 15-bit
column `V`, a top sublimb is checked by two memberships, and the operand row
moved from block row 6 to row 0. Limb geometry (87/87/82), quotient
capacity (`2^261`), carry offset and width (`2^104`, seven 15-bit
sublimbs), padding and every numeric bound below are unchanged.

## 1. Parameters

| Symbol | Value | Enforced by |
|---|---|---|
| `B` | `2^87` | limb radix |
| proper limbs `c_0, c_1, c_2` | `< 2^87, 2^87, 2^82` (so `c < 2^256`) | running sums, 6 sublimbs, top 12/12/7 bits (two memberships) |
| quotient limbs `q_0, q_1, q_2` | `< 2^87` each (so `q < 2^261`) | running sums, top 12 bits (two memberships) |
| carries `u_0..u_3` | `u_k + 2^104 in [0, 2^105)` | running sums, seven 15-bit sublimbs (top: one membership) |
| operand limbs | nonnegative integers `<= 2^94 - 1` (tracked bounds) | chip bound tracking (Section 6) |
| `N` | native order, `p` or `q` of Pasta; `2^254 < N < 2^254 + 2^126` | field |
| `m` | odd, `2^252 <= m < 2^256` | `ForeignModulus::new` |

The range table is one fixed column `V` with `V = v` on row `v` for every
`v < 2^15` (32,768 rows, `k >= 16`). In the Q leaf it is `V` of the shared
table, every entry of which on a usable row is below `2^15` (Section 11).

## 2. Lemma 1 (running sums, two-membership tops)

Block rows (7 per block, rows `0..6` from the block start):

| group | row 0 | rows 1..5 | row 6 |
|---|---|---|---|
| `C`, `Q` | operand (copy or constant) | `z_0..z_4` | `z_5` (top) |
| `U` | `z_0` | `z_1..z_5` | `z_6` (top) |

Lookups (every input into `V`; the pattern columns are fixed, so the set of
checks is the same for every witness):

- `C`/`Q` column with top width `w` and ternary pattern `h` (1 on rows 1..5,
  2 on row 6, 0 elsewhere): input `s (z - 2^15 z_next) + t z + e 2^(15-w)
  z_(+6)` with `s = h (2 - h)`, `t = h (h - 1) / 2`, `e = t(h at +6)`.
  For `h in {0, 1, 2}`, `(s, t) in {(0,0), (1,0), (0,1)}`, and `e = 1`
  exactly on a row whose row `+6` has `h = 2`, i.e. a block's row 0, whose own
  `h` is 0 (blocks are 7 contiguous rows; `ff_range_patterns_follow_the_block_layout`
  checks `h(r) = 0` wherever `h(r + 6) = 2`). So rows 1..5 check the steps
  `z_j - 2^15 z_{j+1}`, row 6 checks `z_5`, row 0 checks `2^(15-w) z_5`, and
  every other row checks 0.
- `U` column with binary patterns `s` (rows 0..5) and `t` (row 6), never
  both 1: input `(s + t) z - 2^15 s z_next`.

**Lemma 1.** A running sum `z_0..z_{L-1}` with step lookups
`z_j - 2^15 z_{j+1} in V` for `j < L-1` and top lookups `z_{L-1} in V` and,
for a top width `w < 15`, `2^(15-w) z_{L-1} in V`, forces `z_0 = sum_{j<L-1}
s_j 2^{15j} + 2^{15(L-1)} z_{L-1}` with every `s_j < 2^15` and `z_{L-1} <
2^w` integers.

*Proof.* `V` holds exactly the integers `[0, 2^15)`. The plain top
membership makes `z_{L-1}` an integer `v < 2^15`. Then `2^(15-w) v` is an
integer below `2^(15-w) 2^15 <= 2^23 < 2^30 < N`, so its field value is that
integer, and its membership gives `2^(15-w) v < 2^15`, i.e. `v < 2^w`
(conversely every `v < 2^w` passes both). Backward induction as before: if
`z_{j+1}` is a small integer and `z_j - 2^15 z_{j+1} = s_j` is a table
value, `z_j = s_j + 2^15 z_{j+1}` is a small integer; every quantity stays
below `2^105 < N`. So `z_0` is an integer in `[0, 2^{15(L-1)+w})`: `2^87`
(top 12), `2^82` (top 7), `2^105` (seven 15-bit sublimbs). The test checks
the equivalence exhaustively for `w in {7, 12}` and the widths
`15 * 5 + {12, 12, 7} = 87, 87, 82`, `15 * 5 + 12 = 87`, `15 * 7 = 105`.

Degrees: `C`/`Q` inputs have degree 3 (lookup degree `2 + 3 + 1 = 6`), `U`
inputs degree 2 (5). Advice queries per operand column: rotations 0, 1, 6
(three, as before: blinding stays 5; a `Rotation::prev` design would have
needed a fourth query and six blinding rows).

## 3. Lemma 2 (no column equation wraps)

Every gate is enabled on a block's row 0 and reads operands at rotation 0,
the `C`/`Q` running-sum roots `z_0` at rotation 1 and the `U` roots at
rotation 0, so the values below are the Lemma 1 integers of that block.
The multiplication gate (`P = a`, `R = b`, `S = c`, `K = 0`) and the division
gate (`P = b`, `R = c`, `S = a`, `K = k m` with limbs `K_i`) enforce, for `k = 0..3`
(with `u_{-1} = 0`, `S_3 = K_3 = 0`):

`E_k:  t_k + u_{k-1} - u_k B = 0 (mod N)`, `t_k = sum_{i+j=k} (P_i R_j - q_i m_j) - S_k + K_k`.

For every assignment satisfying the range checks (not only honest ones),
`|t_k + u_{k-1} - u_k B| <= spread_k + 2^104 (B + 1)`, where `spread_k` is the sum
of the maximal positive and negative parts of `t_k`. With operand limbs `<= 2^94`
the worst `spread_k + 2^104 (B+1)` is `2^191.46` for every modulus (table), far
below `N > 2^254`. So each `E_k` holds over the integers.

## 4. Lemma 3 (CRT)

Summing `E_0 + B E_1 + B^2 E_2 + B^3 E_3` over the integers gives
`sum_{k<=3} t_k B^k = u_3 B^4`, so `X := P R - S + K - q m = (u_3 + t_4) B^4`
with `t_4 = P_2 R_2 - q_2 m_2`: `X = 0 (mod 2^348)`.

The native-residue constraint is `X = 0 (mod N)` (all limbs recomposed with
`B^i mod N`). Since `N` is odd, `X = 0 (mod N 2^348)`.

For every range-checked assignment, with the operand envelope value
`A = (2^94 - 1)(1 + 2^87 + 2^174) < 2^268 (1 + 2^-86)` and the padding
`K < 2^269`: `X <= max(A^2, A (2^256 - 1) + K) < 2^537` and
`-X <= max(2^256 + (2^261 - 1) m, A + (2^261 - 1) m) < 2^518`, so
`|X| < 2^537 < 2^602 < N 2^348`. Hence `X = 0`:

- multiplication: `a b = c + q m`, `c` proper, so `c = a b (mod m)`;
- division: `b c = a + q m - K = a (mod m)`, so `c = a / b (mod m)` when `b` is
  invertible, and no assignment exists when `b = 0 (mod m)` and `a != 0 (mod m)`.

The 65-bit margin (`2^602` against `2^537`) makes the argument independent of the modulus beyond
`m < 2^256` and `N > 2^254`; it does not need `m` prime or `m` vs `N` ordering
(the 3-carry variant, `T = 261`, would need `q_max m + c_max < N 2^261`, which
for Fq-in-Fp (`m > N`) forces `q < 2^260`; four carries remove that case split).

## 5. Per-modulus table (both native fields; exact values from the script)

| modulus | m limbs (bits) | div `K = k m` | mul carries `u_0..u_3`, envelope operands | div carries | worst wrap bound | `m 2^261` |
|---|---|---|---|---|---|---|
| Pasta q (Fq-in-Fp) | 85, 39, 81 | k = 16385 (2^268.00), limbs 95/95/95 bits | [-2^84.37, 2^101.00], [-2^84.37, 2^102.00], [-2^84.44, 2^102.58], [-2^80.00, 2^102.00] | [-2^84.37, 2^94.00], [-2^84.37, 2^95.00], [-2^84.44, 2^95.02], [-2^80.00, 2^94.04] | 2^191.46 | 2^515.00 |
| Pasta p (Fp-in-Fq) | 87, 39, 81 | k = 16385 (2^268.00), 95/95/95 | [-2^86.27, 2^101.00], [-2^86.27, 2^102.00], [-2^86.28, 2^102.58], [-2^80.00, 2^102.00] | [-2^86.27, 2^94.00], [-2^86.27, 2^95.00], [-2^86.28, 2^95.02], [-2^80.00, 2^94.04] | 2^191.46 | 2^515.00 |
| P-256 p | 87, 9, 82 | k = 4097 (2^268.00), 95/95/95 | [-2^87.00, 2^101.00], [-2^87.00, 2^102.00], [-2^87.04, 2^102.58], [-2^82.00, 2^102.00] | [-2^87.00, 2^94.00], [-2^87.00, 2^95.00], [-2^87.04, 2^95.02], [-2^82.00, 2^94.04] | 2^191.46 | 2^517.00 |
| P-256 n | 85, 87, 82 | k = 4097 (2^268.00), 95/95/95 | [-2^84.56, 2^101.00], [-2^87.24, 2^102.00], [-2^87.28, 2^102.58], [-2^87.04, 2^102.00] | [-2^84.56, 2^94.00], [-2^87.24, 2^95.00], [-2^87.28, 2^95.02], [-2^87.04, 2^94.04] | 2^191.46 | 2^517.00 |

`log2 N = 254.000000` for both `Fp` and `Fq`; `N 2^348 > 2^602` (rounded log2: 602.00); the largest
`|X|` over all range-checked assignments is below `2^537`.

## 6. Completeness (honest provers)

- Carries: for operand limbs `<= 2^94 - 1` the honest carry intervals above lie in
  `[-2^104, 2^104)` with at least 1.4 bits of margin (largest `2^102.58`).
- Quotient: `q = floor(a b / m) < 2^261` iff `a b < m 2^261` (the chip's
  `mul_admissible`, checked at synthesis from structural bounds; inadmissible
  operands are reduced first). Proper x proper `< 2^512 < m 2^261` always (this is
  why `m >= 2^252` is required). Sums of two proper values (`< 2^257`):
  `2^514`, admissible for every modulus. Subtraction results `x - y + K`
  (`K` dominating proper `y`): `2^257.17` (Pasta, `k = 5`) and `2^257.58` (P-256,
  `k = 2`); their products `2^514.34` and `2^515.17` are admissible
  (`< 2^515.00` resp. `2^517.00`).
- Division: `q = (b c + K - a) / m` with `c < m` canonical, `0 <= q <= b + k`; the
  chip requires `max(b) + k < 2^261` (`div_admissible`). Strict `q < b + k`
  requires `b > 0`; at `a = b = 0`, the honest quotient is `q = k`.
- Canonical comparison: `x <= m - 1` gives `d = m - 1 - x` with standard limbs
  (`< 2^87`) and a borrow `beta in {0, 1}` of the low 174 bits.

## 7. Canonical comparison

Constraints (with `x` proper and `d` range-checked to `2^87, 2^87, 2^87`;
`x` is the copy on the `Q` operand row or, for a canonical witness, the `C`
root, `d` the `Q` root, both read from row 0):
`beta := (m-1)_2 - d_2 - x_2`, `beta (1 - beta) = 0`, and
`(d_0 + x_0 - (m-1)_0) + (d_1 + x_1 - (m-1)_1) B - beta B^2 = 0`.
`beta` is 0 or 1, and `|(m-1)_2 - d_2 - x_2 - beta| < 3B < N`,
so the high-limb equality lifts to `d_2 = (m-1)_2 - x_2 - beta` over the integers; the low
equation is bounded by `4 B + 4 B^2 < 2^177 < N`, so it is an integer equation.
Adding: `d + x = m - 1`, and `d >= 0` gives `x <= m - 1`. A value `x >= m` makes
`d` negative, which no running sum represents (tests at `m - 1`, `m`, `m + 1`).

## 8. Bound tracking (operands are proven bounded integers)

Every `FfValue` comes from (i) a range-checked running sum, (ii) constant limbs
pinned through the constants column, or (iii) a limb-wise linear combination of
values with nonnegative integer coefficients plus a padding `K = k m` whose limbs
dominate the subtracted value's tracked bounds (`ForeignModulus::padding`). The
tracked bound of every result limb is the integer maximum of that combination,
stays `<= 2^94 - 1` (otherwise inputs are reduced first), and is far below `N`, so
the field values are exactly those integers. Bounds are structural (circuit
shape), never witness-dependent.

## 9. Gate shape (measured)

- Exact (synthesis inventory, `ff_inventory_per_operation`): 70 advice cells per
  multiplication or division (7 rows x 10 columns, no idle cell); proper witness
  18; canonical witness 36; comparison of an existing value 21. Gates degree 3,
  `C`/`Q` lookups degree 6 and `U` lookups degree 5 (10 width-1 range lookups,
  one per column), 4 fixed pattern columns plus one table column (32,768
  rows, `k >= 16`), 3 queries per operand column (blinding 5, unchanged).
  G3.4 threshold <= 100 cells: met (70).
- M3 release measurement (`ff_gate_shape_measurement_release`, before D1, with
  the tagged table and 6 pattern columns; P-256 `p` in `Fq`, Pallas proof,
  KAGEMUSHA transcript, Direct instances): 9,000 chained products in 63,014 rows
  at k = 16 (630,036 FF cells), 14 advice / 15 fixed columns, proof 6,944 B,
  keygen 2.7 s, prove 6.96 s on 20 threads, verify 62 ms, process peak RSS
  0.92 GiB; with `RAYON_NUM_THREADS=1`: keygen 10.5 s, prove 30.4 s wall,
  verify 0.45 s, peak RSS 0.84 GiB, at load1 ~50 (indicative only; counts
  exact).

## 10. Residual assumptions and flags

- Engineering argument, not a published proof (design C4 flag); the integer
  argument above is elementary and fully quantified, and every inequality is
  re-checked by the named test and the script.
- The chip trusts `iroha_plonk`'s lookup and permutation arguments (C1).
- `m < 2^256` is required for canonical values to be proper; P-256 `m + 1 <
  2^256` holds, so `witness_canonical(m)` exercises the comparison, not the limb
  ranges.

## 11. The shared table of the Q leaf (M3b decision D2)

In the Q-leaf layout (`iroha_plonk_gadgets::q_leaf`) `V` is the last column
of the shared table `[T, x_0, x_1, x_2, y_0, y_1, y_2, V]`. Eight range
arguments read `V` alone; the `c_0` argument also carries the SHA-256 spread
lookup (tuple `(T, x_0, V)`), the `u_0` argument the P-256 window lookup
(all eight components). Lemma 1 needs only "a range input matches only a
value `< 2^15`":

- width-1 arguments: every `V` entry on a usable row is below `2^15` (range
  rows `v`, SHA dense values `< 2^11`, window digits `< 2^8`, dynamic entry
  indices `1..16`, zero elsewhere);
- merged arguments: on foreign-field rows the guest is inactive (fixed,
  witness-independent patterns: SHA and window rows are below the split row,
  the foreign-field patterns start at it), so the tuple is `(0, .., 0, R)`,
  which matches only rows with `T = 0`; those are the range rows (all other
  components zero) and all-zero rows. SHA tags are `2^33 + w`, dynamic window
  tags `2^32 + row`, fixed window tags in `[1, 2^32)`.

`QLeafConfig::audit` checks these conditions on the synthesized fixed
columns (row-disjoint activation of host and guest in both merged arguments,
the tag namespace of every table row, `V < 2^15`, and the window's
dynamic-entry enable `q_dyn` zero on every fixed row and boolean above, so
no advice is added to a fixed entry); the leaf tests run it on
key-generation and proving syntheses and on deliberately malformed layouts,
which it rejects. (Codex's implementation review found the `q_dyn` gap in
a first version of the audit; it found no soundness issue in the
`QLeafConfig::chips` layout itself.)

## Review boundary

The original independent Codex review accepted all four modulus bounds for
source digest `fb786437051f425862895196d64e59610fe2aade700a6c7abfdd9b1f00cae1b4`
of `ff/mod.rs`, before the M3b range layout. The original four-item wording
checklist has not been recovered, so an item-by-item match is not established.
The fresh numbered review below records the current clarifications explicitly.
That earlier acceptance covers the interval/CRT argument, not the
whole P-256 gadget, prover, or a changed range-check implementation.

The M3b implementation must additionally establish the running-sum and shared-table
premises of §§2 and 11: every result, quotient, carry and comparison difference
is range-checked, copied to the arithmetic cell, and enabled at the correct
rows through the final usable row. Tests must exercise both native fields,
all moduli, terminal digits, carry endpoints, quotient overflow and malformed
shared-table layouts. Passing only the integer-bound calculation is insufficient.

Qualification records bind this review to the measured source and binary. A
change to widths, radix, carries, padding or operand provenance requires new
numerical bounds; a pure range-layout change requires a new range/binding proof.
Independent engineering review on 2026-10-06 accepted the current M3b arithmetic,
two-membership range binding, canonical comparison and shared-table argument
for all four moduli in both native fields. The original 20 FF cases, the two
new boundary cases and four Q-leaf layout-audit cases passed; the three ignored
FF measurement/exhaustive cases are not included in that result. Exact integer
rederivation matched the bounds above. The reviewed implementation hashes are:

- `ff/mod.rs` SHA-256 `1ec6cf5a17146a07af5d5f1f4a45bd8752fef691f311ef225e6a0d49cca8bfc5`.
- `q_leaf/mod.rs` SHA-256 `ac22585f76976b554d8a5a4ecb765eaf3f3ae89cb09e1cbf17b5a6f7701ab2d5`.

This closes the scoped carry/range implementation review. It is not an external
cryptographic audit, proof-engine qualification, performance/device result or
deployment authorization; those gates remain separate.

### Current fused-leaf review (2026-10-09)

The two 2026-10-09 source reviews and an independent 2026-10-10 source/integer
re-review found no carry/range-binding defect in the actual M3
`G3.6/q_leaf_chips` path, descriptor
`0ffa6d0a7a3a2449e092b21dcb9201c75f2c6fdf3305717b955b67a72e724070`.
Its Q-leaf source still matches `ac22585f…ab2d5`; the current FF source is
`d9fac96aab07d5af33921651c720530e26a7ddbed9d75d8bdac2eef5ea520a5b`.
Eighteen arithmetic, range, configuration and copy functions match the earlier
reviewed FF source. Inspection of the changed wrappers confirms that this leaf
selects `serialized=None`, retaining the fused bounds and gates.

The current independent acceptance is confined to this fused arithmetic,
two-membership range binding, canonical comparison and shared-table construction.
Its self-contained exact-integer rederivation matches all four modulus padding
multipliers and carry intervals against both native orders: the largest local
residual bound has approximate log2 `191.459441`, far below either native order,
and the global residual remains below `2^537`.
The script checks these inequalities with integers; it does not establish the
source-to-equation correspondence, which was separately reviewed. No Rust tests,
proofs or builds were rerun. Serialized, shortened-carry, rotated and independent
range-bus implementations do not inherit this fused-path acceptance.

These are fresh clarity findings, not a reconstruction of the missing four:

1. Proper integers below `2^256` need not be canonical modulo `m`. Canonical
   comparison supplies that stronger property. CRT proves `b c = a (mod m)`;
   interpreting `c` as `a / b` requires invertible `b`, which means nonzero `b`
   modulo each of the four shipped prime moduli.
2. Plain top membership precedes the no-wrap argument for scaled membership.
   Range-checked witnesses, pinned constants and constrained operations establish
   operand bounds; host witness values or unchecked labels cannot establish them.
3. CRT soundness covers every satisfying assignment. Honest quotient and carry
   completeness additionally depends on the structural admission checks. In
   particular, division uses `q <= b + k`, allowing equality when `a = b = 0`.
4. Operand copies/constants are bound to their source values. The arithmetic
   gate reads operands at row 0, C/Q result/quotient roots at row 1, and U roots
   at row 0. Canonical comparison also binds its input and range-checked
   difference to the boolean-borrow equations.
5. The scaled top check is active six rows before the top, including the final
   usable row. Fixed seven-row placement supplies this premise; an overrun must
   be refused rather than leave a terminal digit unchecked.
6. Shared-table acceptance depends on disjoint activation and tag namespaces,
   bounded usable V entries, and `q_dyn = 0` on fixed rows. Ten lookup arguments
   alone establish none of these properties.
7. The M3 circuit's `chips`/`load_tables` construction supplies those fixed-layout
   premises. It does not call `audit` on every proof. The independent audit and
   malformed-layout tests check the construction; the audit is not a new circuit
   constraint or authority for arbitrary shared-table callers.
8. The retained raw output establishes 22 FF and four Q-layout passes for the
   reviewed sources, with three expensive FF cases ignored. The whole historical
   gadget run failed (284 passed, one failed, eight ignored). The malformed-layout
   audit circuit uses `Fq` only and exercises SHA/window overlap and `q_dyn` on a
   fixed row; explicit `ValueRange`, `Namespace` and nonboolean dynamic-row
   rejection cases remain uncovered there. Final-row tests exercise four
   representative modulus/field/table combinations, not the full Cartesian
   matrix. Both fused every-cell mutation sweeps remain ignored. These are
   coverage limits, not demonstrated carry forgeries. Positive M3 proofs do not
   replace adversarial coverage or qualify other FF backends, recursive Q,
   complete P-256, privacy, devices or the whole candidate.

The retained source correspondence packet is
`target/qualification/m3b-current-source-review-20261009-1/manifest.json`, SHA-256
`5a274a766a7db262cd62464af65e68a9bc7f4c3115d8f5af497ce7d6c400630c`.
Its independent second review is `integration-independent-review.json`, SHA-256
`d64cf598ca775e96ccf818c2583f8385fd48add9a5a8a59bccfa85b0355294c6`.
Both bind the pre-edit memo and exact reviewed sources; neither ran new tests.
The current independent packet is
`target/qualification/m3-fused-carry-independent-review-1/manifest.json`; it
retains reviewed source snapshots and hashes, the exact-integer script/output,
accepted premises and the remaining proof/test obligations. It does not recover
the historical four-item wording checklist or qualify a measured binary.

## 12. Recursive scalar adapter and canonical S6 certificates

The 2026-10-06 adapter revision keeps the seven-row fused gate, radix, quotient,
carry ranges and its admission checks unchanged. It changes operand provenance
and reuses already proved integer ranges. The earlier carry review does not by
itself establish these adapter properties.

Internal recursive scalar addition, subtraction and negation may retain an
unreduced integer congruent to the scalar. For limb bounds `A_i,B_i`, addition
tracks `A_i+B_i`. Subtraction chooses the existing fixed multiple `K=t m` with
`K_i>=B_i`, and tracks `0<=a_i+K_i-b_i<=A_i+K_i`; negation tracks
`0<=K_i-b_i<=K_i`. Each limb remains at most `2^94-1`, or the existing reduction
path is used before retrying. These native-field equations therefore cannot
wrap. Multiplication still invokes `make_admissible`, including
`max(a) max(b)<m 2^261`, and division retains its padding/quotient admission.
The value's native-field residue is not its foreign scalar: equality, zero
testing, the guarded inverse's zero test, S6 export, scalar-bit transfer and
transcript/public transfer canonicalize the integer before interpreting it.

`CanonicalS6` is an opaque certificate for the same bounded cells
`x=lo+2^128 hi<m<2^255`. It has no public unchecked constructor. Import to FF
splits `lo=a+2^87 b0` and `hi=b1+2^46 c`, with widths `87/41/46/81`, then sets
`b=b0+2^41 b1`. The equalities are integer equalities: their nonnegative sides
are below `2^128`, and `b<2^87`. Export first proves the three-limb FF integer
canonical. Since `x<m<2^255`, its nonnegative high limb satisfies `c<2^81`;
splitting the middle limb into 41 and 46 bits yields the same integer and
proves `lo<2^128, hi<2^127` without duplicate range lookups. Changing a
certificate's modulus checks the narrower bound when needed; widening retains
the original constraints. `ScalarCells` additionally requires the exact curve
scalar modulus, so a foreign certificate cannot silently change meaning.

The root implementation reviewer independently checked this import/export
integer argument and modulus handling. Exact-cell caches live only for one
chip/synthesis and retain the earlier constraints. Structural constant folding
recognizes pinned constant cells, never witness values. General operation
reuse is keyed by both operands' proving-cell identities. Fixed small-scalar
multiplication uses the existing bounded `scale` operation and its reduction
checks, not a wider carry envelope.

Validation at this source snapshot passed:

- both-direction S6 roundtrips, every assigned-cell mutation, modulus/top-bit
  aliases, explicit widening/narrowing and known/unknown layout equality;
- seven recursive verifier tests on both curves, including all malformed proof
  messages, modular aliases at each semantic boundary, a nonconstant long
  arithmetic chain, and distinguishing a witness one from a pinned constant;
- all three uniform Omega source choices and frame/proof mutations;
- strict gadget and recursion all-target clippy.

The snapshot is based on shared checkout HEAD
`e5c89263b05d82efdc11127f5d9418373f4f4382` plus the ongoing changes. Its SHA-256
source bindings are:

| Source | SHA-256 |
| --- | --- |
| `iroha_plonk_gadgets/src/ff/mod.rs` | `5d9056a03e935490f144674b2300e8e256578f787b9855cfa32c08031941aedc` |
| `iroha_plonk_gadgets/src/ff/s6.rs` | `2769230d3c6d6749874613a2970774499ac67c7cd8f8b770d3b35e23c50a7b55` |
| `iroha_plonk_recursion/src/verifier/scalar.rs` | `dd1c4c6f1a7d462f0942e774727a712e96e931d41796392c9794373bf9f21e56` |
| `iroha_plonk_recursion/src/codec.rs` | `d239c30a30c84ef8776578c910ed0db765aaaa5aa1fb328bff6ce273c9516d41` |

The `ff/mod.rs` change from the reviewed M3b hash adds the S6 module/export
and an explicitly selected serialized backend; the original fused gate
polynomials and their admission checks are unchanged. The Q-leaf source remains bound
to the earlier `ac22585f…` hash. This scoped adapter/range review is neither
an external audit nor a recursive release qualification. The measured generic
Omega descriptor still exceeds the transport cap; none of these tests changes
that verdict.


## 13. Serialized CRT lowering and shared range certificates

The explicit serialized backend retains the same result limbs (87/87/82),
quotient limbs (87/87/87), four offset carries (105 each), division padding,
and tracked operand admission from the fused backend. It lowers each of the
four carry equalities and the independent native-residue equality to ordinary
Glue rows. Intermediate field-valued partial sums are not treated as bounded
integers: only the complete original carry residuals use the established
non-wrapping bounds. The native-residue constraint is retained separately, so
satisfying only the four low-radix equalities cannot accept a CRT alias.
Canonical comparison retains its proper limbs, three 87-bit difference limbs,
boolean borrow and both original integer comparison equalities.

Every emitted result, quotient, carry and comparison difference is checked by
the existing running-sum predicate and copied to the exact arithmetic cell.
Independent range buses share only their fixed table. Each has its own
activation pattern and a full scalar membership argument; a tuple is never
interpreted as independent membership. The deterministic scheduler chooses
the least occupied bus from structural widths and prior row counts, with ties
resolved by fixed bus order. No witness value changes this selection.

The optional range certificate map is fresh for each synthesis and keyed by
physical advice cell (column and absolute row). It is populated only after a
range predicate and any necessary equality copy have been emitted. A proved
bound of `b` bits discharges a request for `b' >= b`; a narrower request emits
new constraints. Equal witness values in distinct cells do not share a
certificate. Cloned chips share both reservations and certificates, preserving
the original constrained cells. The ordinary retained layout does not enable
this optimization implicitly.

Validation includes all four foreign moduli in both native fields, multiply,
divide, zero-divisor and modulus mismatch rejection, noncanonical aliases,
carry overflow, a low-radix-only forgery rejected by the native residue,
every-cell mutation and known/unknown layout equality. The current FF unit
slice passed 35 tests (three explicitly ignored exhaustive/measurement cases
excluded). The certificate/banked-range tests passed in both fields; the full
parallel interpreter additionally matched native verdicts with two and three
buses, including malformed encodings and lengths. Scoped strict gadget and
recursion all-target clippy passed. These are implementation checks; this
section does not claim an external cryptographic sign-off. The root
implementation reviewer separately read the serialized equations, per-bus
range arguments, exact-cell certificates and structural scheduler. That scoped
source review found no local range/binding gap and confirmed the original
carry/result/quotient widths and four carry plus native-residue equalities. It
does not establish current M3 qualification, whole-recursion soundness or
release readiness.

Serialized/range source bindings for this snapshot:

| Source | SHA-256 |
| --- | --- |
| `iroha_plonk_gadgets/src/ff/serialized.rs` | `18cdc38ccbb796297f0e980fbc040c1df1b649451d5e1b9b401709ddeb4a040f` |
| `iroha_plonk_gadgets/src/range/running_sum.rs` | `b6b62eea7f55a42c2275f4a57b393facfa481dcad181dcc97d273187de141906` |
| `iroha_plonk_gadgets/src/arith.rs` | `24f870b3d4efb161e0d29355c6ad9d543665acb2f75963edb04fd186222d5c75` |
| `iroha_plonk_gadgets/src/phase.rs` | `a7ab721dc06249afe4bffdc776e780320c2b0a8579dbfab7d13aab365f45da1a` |


## 14. Four-row CRT placement

`RotatedFfConfig` places the exact sixteen existing roots on four equality
ports over four physical rows: three left limbs, three right limbs, three
result limbs, three quotient limbs and four offset carries. The gate anchors
at the second row and queries rotations `-1..2`. It invokes the original five
fused residuals; division retains `(right,result,left,padding)`. Result bounds
remain **87/87/82**, quotient bounds **87/87/87**, and each offset carry remains
**105 bits**. A review message initially misstated the limb widths as 86/86/84;
the reviewer explicitly corrected that summary. No width change was requested
or implemented.

Every result/quotient/carry root comes from its exact range certificate and is
copied into its assigned port/rotation. The chip rejects a fused-only backend,
wrong ports, or a different/multiple configured modulus before attaching the
kernel. All four rows are reserved together. The selector at global row zero
is off, so the negative rotation cannot introduce a wraparound relation.
The last block may end at the final usable row; a block crossing into blinding
rows is rejected by both the bounded cursor and the assembly.

The shared phase layout uses ECC payload5 codes3/4 for multiplication/division;
its guard/split indicator domain includes those codes, so ECC constraints stay
disabled on CRT rows. The independent reviewer checked these exact root/copy,
phase and unchanged arithmetic-bound premises. This is a scoped source review,
not current M3 qualification or acceptance of a different integer envelope.

Validation passed all four moduli in both native fields: arithmetic/reference
parity, every-cell mutation, known/unknown shape, bad modulus/profile/ports,
unchanged admission rejection, first/final physical blocks, every copied root
and rotation, and final usable/blinding boundaries. The complete compact and
parallel interpreters passed native differential tests. The actual phased
Glue/CRT/ECC/Poseidon component passed every-cell mutations on both curves.
At the preceding four-row snapshot, the centered compact descriptor was 4,960 transport bytes and the genuine
pooled-source Bootstrap needs 74,597 shared rows and 152,850 range rows;
these remain explicit failures of the 4,821-byte and k16 gates. Pinning its
single complete source key reduces shared rows to 71,964 without changing the
range or transport failures; the complete catalog is not yet qualified.

Current rotated/pooled source bindings (shared HEAD `e5c89263b05d82efdc11127f5d9418373f4f4382`
plus ongoing changes; prior snapshot hashes above remain historical):

| Source | SHA-256 |
| --- | --- |
| `iroha_plonk_gadgets/src/ff/rotated.rs` | `27a117c097eae7652594d4793ac1cc4683e02024ee268029fd5f891937bbccdc` |
| `iroha_plonk_gadgets/src/ff/serialized.rs` | `679c556a9791dba7a8a63e26e4e846b575e1d26db587734e52afcaf4b19923aa` |
| `iroha_plonk_gadgets/src/range/running_sum.rs` | `b6b62eea7f55a42c2275f4a57b393facfa481dcad181dcc97d273187de141906` |
| `iroha_plonk_gadgets/src/phase.rs` | `a7ab721dc06249afe4bffdc776e780320c2b0a8579dbfab7d13aab365f45da1a` |
| `iroha_plonk_gadgets/src/arith.rs` | `5875082946b7a59ac6ed4590622fe28a0c2aafbf5e38990bd68310f6d52db560` |
| `iroha_plonk_gadgets/src/ecc/gates.rs` | `b52d9ce6317dd7a407d15619a9bb10082f73c96f6f90cd00bd6815a0c14f7f40` |

## 15. Unsigned Proper dot batches

The new standalone `UnsignedDot` predicate admits a fixed batch of one to eight
pairs, each with proven Proper or Canonical 87/87/82-bit limbs and one common
supported modulus. It rejects signed/lazy forms, mixed moduli and counts0/9.
The common admission routine also explicitly rejects `m<=2^254`; the broader
`ForeignModulus` constructor alone permits smaller odd custom moduli and
does not establish this dot-specific quotient bound. Both lowerings reject
`2^252+1` and `2^254-1` in known/unknown synthesis, and accept the maximum
eight-term workload at `2^254+1`, in both native fields.
Let `S=sum_t a_t b_t`, `B=2^87`, and `m` be the foreign modulus. Since each input
is below `2^256`, `S<2^515`; every supported `m>2^254` therefore gives the honest
quotient `q=floor(S/m)<2^261`. The result is Proper and congruent to the sum;
canonical interpretation still requires the separate comparison.

For `j=0..3`, define
`D_j=sum_t sum_{r+s=j} a_tr b_ts - sum_{r+s=j}q_r m_s - c_j`, with `c_3=0`.
The equations are `D_0-Bv_0=0` and `D_j+v_(j-1)-Bv_j=0`, plus the independent
native residue of `S-c-qm`. Result, quotient and offset carry ranges are exactly
those above. Each honest `|D_j|<28B^2`; induction gives `|v_j|<29B<2^92`, inside
the existing signed104-bit carry interval. Even malicious105-bit offset roots
make each local residual smaller than `2^194`, below either native prime.
Telescoping therefore proves divisibility by `B^4`. The global residual is below
`2^518`, whereas `B^4*p>2^602`, so the two congruences imply integer equality.
The root reviewer independently re-derived this specific unsigned Proper
argument. It does not cover a signed/lazy or larger batch.

The component tests passed batch1..8 with zero and maximum256-bit inputs in
both native fields for all four moduli; batch1/8 every-cell and known/unknown
shape tests; malformed batch/form/modulus rejection; quotient/carry overflow;
and a low-radix-only forgery rejected by the native residue. The initial
lowering uses `20+11(n-1)` Glue rows and one set of result/quotient/carry checks
(70 range rows at15-bit table width). The shared-profile S11 and multiopen
Horner folds now use fixed unsigned batches; negative terms are materialized
through the separately admitted subtraction/negation path. This does not
extend the unsigned kernel to signed or lazy operands.

## 16. Staged products, streaming dots and fixed-coefficient constants

The explicit compact profile retains the same sixteen roots and the same
four physical rows for multiplication/division. It binds the four low
convolutions and native product on five spare advice columns, then checks
the original carry/native residuals on the following row. Its queries use
only rotations `-1,0,1`. Division first orders its operands as
`(right,result,left,padding)`, including the unchanged fixed padding.
Neither the range envelopes nor the integer argument in the earlier sections
changes: the intermediate products are field elements, and the complete
residuals still have the established non-wrapping bounds.

For a fixed unsigned batch of `n=1..8`, the streaming version starts all five
partial sums at constrained zero, adds each operand product, copies each sum
to the next state, and finishes with the same result/quotient/carry residuals.
It consumes `2n+3` arithmetic rows and one set of range certificates. Its
admission remains exactly the Proper/Canonical, common-modulus predicate in
§15. The explicit reference backend retains the Glue lowering.

The phase coding separates every predicate: multiplication/division use ECC
payload5 codes3/4, final residuals use payload2 code4, zero initialization
uses payload2 code3, product steps use payload1 code3 and state carry uses
payload3 code3. Algebraic15 uses payload0 code3. The corresponding ECC
indicator domains include those exact extra codes, disabling ECC gates on
these arithmetic rows. No witness value selects a phase or row span.

The compact Glue profile constrains a constant with the fixed-coefficient
equation `x-c=0`, removing its standalone equality-enabled fixed column.
ECC coordinates and Poseidon constant inputs copy these exact constrained
cells. Attaching this source requires matching copy ports and a shared,
bounded cursor; unbounded, unrelated-port and ordinary fixed-column profiles
are rejected. The shared cursor reserves constant rows with all other Glue
and CRT rows, so these copies cannot silently collide with another phase.

The root implementation reviewer read the staged operand ordering, padding,
zero/product/carry/final equations, unchanged admissions, coefficient-only
constant constraints and bounded cursor/port checks. That scoped source
review found no local gap. It is not a new M3 qualification, an external
audit or a proof of whole-recursion soundness.

The staged kernels passed both native fields and all four foreign moduli,
including all batch sizes, endpoint/admission and alias attacks, every-cell
mutation, first/final usable and blinding-row boundaries, and known/unknown
shape parity. The final mixed-phase component passed both fields with
Glue, multiplication/division, an eight-pair dot, ECC, Poseidon and
Algebraic15 together, including every-cell mutations and exact public
binding attacks. The complete compact interpreter passed native differential
tests, and scoped strict gadget/recursion all-target lint passed.

The five-bus authenticated Bootstrap source is 8,960 proof bytes. The complete
compact descriptor has 11 advice columns, 11 fixed queries, 26 advice queries,
three instance queries, five permutation columns in one set, exactly one
lookup, degree9 and five blinding factors. Its 3,680-byte proof plus the
1,088-byte accumulator is **4,768 bytes**. This descriptor meets the byte
formula only. At the first staged five-bus snapshot, its pinned one-key
predicate still needed **73,829 shared rows and 148,816 range rows**, exceeding
the 65,530 usable rows at k16; the full predicate passed only a diagnostic
larger-domain synthesis. No complete compact proof or final catalog is
qualified by this inventory. Later arithmetic measurements supersede these
row counts only when recorded against their tested source.

The public-input evaluator factors
`L_i(x)=((x^n-1)/n) * omega^i/(x-omega^i)` before unsigned dot batching. It
retains an independently constrained guard `g=[x^n-1 != 0]` in the global
verdict and caches weights only by exact fixed index within one proof
evaluation. A narrowly scoped guarded division proves
`(x-omega^i)*inverse = g (mod m)` using the unchanged FF division predicate,
and constrains `(1-g)*inverse_limb=0` for all three Proper result limbs.
When `g=1`, `omega^(i*n)=1` implies `x-omega^i != 0`, so this is the exact
inverse. When `g=0`, all inverse limbs equal zero; the relation is total even
at a zero denominator, while the global verdict is already false. This
reuses the single vanishing proof rather than repeating canonical zero tests
for each root. The generic inverse retains its original independent nonzero
predicate and guarded-one behavior.

The direct regression tests `x=1`, another nontrivial root and an ordinary
non-root, first/last and matching/nonmatching root indices, each inverse limb
and guard/verdict mutation, index-cache cell identity, and known/unknown
shape on both curves. Factoring and sharing this root-specific guard change
neither the accepted native predicate nor total malformed-proof handling.
Large structural constants are included in unsigned batches unless their
product has an existing cheap lowering (both constants, or zero, one, minus
one or an unsigned constant at most128). A witness equal to one never
acquires constant metadata. Both-field constant/witness output-limb mutations
and known/unknown shape checks pin this distinction.

The resulting genuine five-bus Bootstrap inventory is **70,488 shared rows
and 124,750 range rows** with a pinned one-key catalog, still failing k16.
Its descriptor remains4,768 transport bytes. The complete verifier's13-test
slice passed, including both-field native differentials and total message
corruption coverage. A genuine Load terminal proof previously passed the
complete ordinary outer predicate/native proof path (10,944 transport bytes,
over cap); its earlier compact snapshot used72,376 shared/130,406 range rows.
Those Load counts precede the last guarded/constant changes and canonical
selector/task-schema migration, so they are historical component evidence,
not current final-catalog qualification. The later C4 scope review also
identified omitted current credential/certificate authorization in that Load
fixture; its proof results establish a partial operation relation only.

The root reviewer independently read the guarded weight and its caller guard,
including the nth-root implication, false-guard limb equalities and global
verdict binding, and the structural constant dispatch with Proper conversion.
That narrow source review found no gap; it is not a blanket sign-off on a new
carry layout or complete recursion. The scoped latest recursion all-target
strict lint passed.

Staged/constant/guard source snapshot at shared HEAD
`c2e5bd8978d4ae931b8beef54392bb10a33ad3a6` plus ongoing changes:

| Source | SHA-256 |
| --- | --- |
| `iroha_plonk_gadgets/src/ff/mod.rs` | `35dbfd653b75660b590b78309941278cec8fb09d976c6f5bc3b5da09db3e83f4` |
| `iroha_plonk_gadgets/src/ff/rotated.rs` | `3ba5992ebd3d2f4da94401e0bc97d37c52350d40fbe30ba4aa33bc12203e4f85` |
| `iroha_plonk_gadgets/src/ff/dot.rs` | `f3dfbc8c757d962252c96ed10953447d59b9b4f4eccb41923f8633e8c39d3344` |
| `iroha_plonk_gadgets/src/arith.rs` | `8f8f9b4a48c817366236aafeedbdc009abaf911096051ed6bb9928b351cebf3e` |
| `iroha_plonk_gadgets/src/ecc/gates.rs` | `8ed1743c9873b089f321d43245648c2a09ad4f06b413ede5d728cda5e8b9ff4a` |
| `iroha_plonk_gadgets/src/ecc/mod.rs` | `d450f5c53f3e86bcfa4c63dc43cdd6bf757e427be57b0570c728efecfebe5476` |
| `iroha_plonk_gadgets/src/poseidon/pow5.rs` | `2c0fc66ee124ec129bf8461cc06ade94ae644ec2ccb738305786e09d1ad9009d` |
| `iroha_plonk_recursion/src/verifier/scalar.rs` | `02a127c06fad302f1587c0fde172940ac9447aca60bb6ac0dd8c56f0c300a13f` |
| `iroha_plonk_recursion/src/verifier/expressions.rs` | `9c728a189b5f3f83a2ba24674ffa6bda2596ca82d78d9cdf0bdbce2a47c03e65` |
| `iroha_plonk_recursion/src/verifier/multiopen.rs` | `7c57d5608e706ec96ddd4483988b9fb1fa8574285af7eedb6ab73481d356837a` |
| `iroha_plonk_recursion/src/verifier/compact.rs` | `fa161ae19ec1b466e0e0d5c4c105512fbe9b17146c3f81b2c47851c48bad9a14` |


## 17. Checked GLV split reuse and fixed identity folds

`VerifierChip` caches the opaque `GlvScalar` returned by an actual constrained
multiplication, keyed by the complete exported S6 `(lo_cell,hi_cell)` pair.
This frontend's `Cell` is a column plus an **absolute** row; named regions do
not reset the retained chip cursor. Every constructor creates an empty cache,
so no certificate crosses synthesis. Hits call the existing `mul_with`, whose
copy constraints bind the same digit/sign/high cells to the new point's chain.
Equal values assigned to distinct cells never share a split.

The quotient and static point-set Horner folds additionally take their first
commitment directly: their earlier accumulator was the circuit-fixed identity.
Only fixed iteration order chooses this branch; no point or scalar witness is
examined. Every subsequent multiplication/addition and every incoming decoded
commitment constraint is unchanged.

The root reviewer independently checked the constructor lifetimes, absolute
cell-pair keys, opaque split/link constraints and static first-slot order, and
found no local gap in this scope. Both-field tests cover reuse on opposite
points, equal values in fresh cells across named regions, different scalar
values, scalar and cached split-limb mutations and known/unknown shape. The
complete compact interpreter matched native verdicts and strict recursion
all-target lint passed. These checks do not qualify a final recursive artifact.

The genuine four-bus Bootstrap source remains8,480 bytes. This snapshot's
pinned compact predicate uses **66,933 shared and 117,937 range rows**, with
**4,768 transport bytes** from the descriptor. Both k16 row gates still fail;
Load and the complete uniform catalog have not qualified this profile.

GLV/fold source snapshot at shared HEAD
`793a13d8ee9271035a0ae91ee0c53ca99430a607` plus ongoing changes:

| Source | SHA-256 |
| --- | --- |
| `iroha_plonk_recursion/src/verifier/mod.rs` | `e48fac54b919f4a155f4c8c5ed3306b2850cbe5d23a10e8f7dfca38a5af06a19` |
| `iroha_plonk_recursion/src/verifier/compact.rs` | `7fec93f62b133e5c017471b069b49db8602ac9d829af6d304123f10caeef4367` |
| `iroha_plonk_recursion/src/verifier/multiopen.rs` | `d14dfa1d69f99925b8f89d0cc3c7f444e5276fd1a3da87ec2fad5fba95137adc` |
| `iroha_plonk_gadgets/src/ecc/glv.rs` | `c86ca1404e1de06cbe3bf8ffc64d5c79e40712a1fc00c99041b69c0d9523798c` |

## 18. Three-carry unsigned Proper product

This separate staged finish admits only a single unsigned product whose two
operands already have Proper or Canonical form and limb bounds at most
`(87,87,82)` bits, or pinned constants satisfying those same bounds. The fixed
modulus must satisfy `2^254 < m < 2^256`. These tests use structural metadata,
never witness values. Bounded/lazy inputs, widened limb bounds, smaller custom
moduli, division and unsigned batches retain the earlier four-carry finish.

Let `B=2^87`. Proper operands are below `2^256`, so the honest quotient
`floor(ab/m)` is below `2^258`. The new finish range checks the quotient as
`(87,87,84)`, the result as `(87,87,82)`, and three offset carries as90-bit
integers with offset `2^89`. Write

```
D_j = sum_{i+l=j} a_i b_l - c_j - sum_{i+l=j} q_i m_l,
D_0 - B u_0 = 0,
D_1 + u_0 - B u_1 = 0,
D_2 + u_1 - B u_2 = 0,
ab - c - qm = 0 mod N.
```

For `j<=2`, each unsigned convolution and the result limb give
`|D_j|<3B^2`: at column2 the product bound is `(1+1/16)B^2`, and the quotient
convolution is below `(1+1/8+1/32)B^2`. Induction gives honest
`|u_j|<4B=2^89`, fitting the stated offset. Malicious admitted carries are
still in `[-2^89,2^89)`; each local residual is below `2^178`, below either
native prime. Thus the three low equations hold over the integers and make
`ab-c-qm` divisible by `B^3`. Its native equation adds the coprime factor `N`.
For any admitted witnesses, `|ab-c-qm|<2^515`, while `B^3 N>2^515` strictly
for both native fields. The integer equality follows. The output remains
Proper; no canonicality claim is inferred from the product equation alone.

The implementation reuses the existing constrained product prelude and its
five sums. ECC payload5 adds finish code5; every other enable sharing that
payload has the full0..5 indicator domain. Fifteen copied roots occupy the
same four physical rows. Queries remain at rotations-1,0,1, and the full
compact descriptor still has degree9, one lookup, 11 advice, 11 fixed,
26 advice queries and five permutation columns: **4,768 transport bytes**.
At15-bit lookup width, an eligible product uses60 range rows instead of70.
This is a descriptor/component result, not an outer k16 gate pass.

The root reviewer independently re-derived the quotient, local-carry and CRT
bounds for this unsigned Proper scope before implementation. That review does
not cover division, padding, signed/lazy operands or batched products and is
not a qualification of the new layout. The targeted release test
`staged_proper_product_bounds_aliases_and_all_cells_both_fields` passes all
four protocol moduli in both native fields, maximum/zero operands, quotient
and carry overflow, the two independent CRT equations, every assigned-cell
mutation, known/unknown shape, and retention of the original route for lazy,
widened and small-modulus inputs. Strict gadgets/recursion all-target lint
passes. The staged boundary suite also passes both fields/all four moduli,
including every copied root at the final usable row and the global-row-zero
negative-rotation boundary. The root reviewer subsequently checked the actual
structural admission, range roots, product/native staging and complete payload5
indicator domain and found no gap in that scope. The genuine Bootstrap source
A2 remains8,480 bytes. Its larger-domain compact predicate passes with
**66,933 shared and 113,717 range rows**, saving4,220 range rows across422
eligible products. Both k16 row gates still fail. This snapshot predates the
hard-forward optimization below. The complete mixed-phase component suite now
passes both fields, including Glue/ECC/Poseidon/CRT/dot coexistence and all-cell
mutations in the mixed algebraic-15/running-sum range layout
(`proper-product-mixed-components-v2.log`, two tests, 983.26 seconds). This
functional runtime is not a performance-gate measurement.

## 19. Hard verifier forwards its already checked claim

After hard verification constrains the complete aggregate validity bit to one,
the succinct verifier returns the exact decoded finite suffix and canonical
round challenge cells already used by its transcript and IPA equation. The
hard AS verifier does the same after checking salt/length/source metadata,
every finite point, every nonzero round and its full group equation. It keeps
the descriptor/source k and round order unchanged. Downstream zero-prefix
normalization, source-k binding and obligation registration are unchanged.

This removes only the subsequent conditional dummy selection and repeated S6
export. The soft path still selects the same fixed deciding dummy on failure.
Hard malformed inputs must still synthesize a fixed shape whose aggregate
validity assertion is unsatisfied; this change creates no alternate acceptance
path. It changes no foreign multiplication, carry bound, wire format or proof
length. Layout changes still require regenerated keys and proofs.

The root reviewer independently traced both aggregate validity constructions
and the returned suffix/round cells, including typed instances, decoding,
nonzero inverses, full equations and static round order, and found no gap in
that scope. The expanded native-differential verifier corpus passes all 16 tests
including hard-invalid classes and hard known/unknown shape. Before the bridge
reuse below, the actual Bootstrap compact predicate uses 66,549 shared and
113,061 range rows, with the same 4,768-byte descriptor transport. Both row
gates still fail. The full AS malformed-input, forged-suffix, native-equation
and burn regressions pass in the subsequent combined snapshot described below.
This scoped source review is separate from the earlier M3b carry sign-off and
does not qualify a final artifact or a current-source performance gate.

## 20. Bidirectional exact S6/canonical-FF bridge reuse

The existing per-synthesis cache now records both directions of an already
constrained integer bridge. Import binds the original two S6 cells to a
canonical three-limb FF value, so exporting those exact three cells can return
the original S6 cells. Export first checks the modulus and canonicalizes the FF
input, then records its returned S6 cells as an import of the canonical FF
value. A lazy source is never stored as the inverse import result. An original
lazy-source cache key may share the canonical export only after that exact
reduction has been constrained.

Keys contain every absolute cell identity: all three FF limbs or both S6 limbs.
No witness-value comparison selects reuse; equal values assigned to fresh cells
do not hit the cache. Cache lifetime is one `Arithmetic` instance in one
synthesis. The canonical bridge retains the exact split/recomposition and
foreign-modulus checks established in the earlier S6 section. No multiplication,
carry or limb-admission bound changes.

The root reviewer independently traced import/export against `ff/s6.rs`, including
the canonicalization-before-inverse insertion and complete cell keys, and found
no gap in that scope. This is an internal source review, not an external audit
or extension of the original M3b sign-off. The release test
`inverse_bridge_cache_keeps_exact_cells_and_only_canonical_integers` covers both
curves, repeated hits without new assignments, distinct same-value cells across
regions, a lazy value plus the modulus, all recorded FF/S6 limb mutations, and
known/unknown layout. The full verifier corpus passes 17 tests; the full ignored
AS circuit corpus passes three tests, including total malformed-accumulator
burn, hard/soft native differential checks and forged suffixes.

Current authenticated Bootstrap source A2 remains 8,480 bytes. Its pinned-key
compact predicate uses **66,361 shared rows** (12,173 sponge, 26,102 arithmetic,
28,086 curve) and **112,378 range rows**; the descriptor still yields **4,768
transport bytes**. The predicate passes in the diagnostic larger domain, while
both k16 row gates fail. No production compact proof or final catalog is claimed.
Reproducible local logs are `target/qualification/inverse-bridge-cache.log`,
`inverse-bridge-verifier.log`, `inverse-bridge-accumulation-v2.log`, and
`inverse-bridge-four-bus-bootstrap-omega.log`; timings from these contended
functional tests are not gate measurements.

Source snapshot after these tests at shared HEAD
`793a13d8ee9271035a0ae91ee0c53ca99430a607` plus working changes (the verifier
configuration additionally contains the separately measured explicit Q byte-tape
profile; the reviewed carry/bridge predicates are unchanged):

| Source | SHA-256 |
| --- | --- |
| `iroha_plonk_gadgets/src/ff/mod.rs` | `4eab53bf06723e63754365ab44ee092286e45c71f053367de7fdeb0f8510430a` |
| `iroha_plonk_gadgets/src/ff/rotated.rs` | `9e75dfe3b43965e78f3424a60eae400feb74027d5702a31a6ac4c9fb574f2772` |
| `iroha_plonk_gadgets/src/ecc/gates.rs` | `4339e218e86883963d3d2484a78f4fe091208a682d8fb917064668655fcf59f0` |
| `iroha_plonk_recursion/src/verifier/scalar.rs` | `dae08edf7130b907710d474696e22084e2f8a63f0c1ff1391d6a96a570822dd5` |
| `iroha_plonk_recursion/src/verifier/mod.rs` | `2feacbd8ae512d24239db675cdbce6e026149417479a773bcb5ceb295ed2b2d3` |
| `iroha_plonk_recursion/src/accumulation_circuit.rs` | `40a9171fdb712dd0fce91dde284492d344713022d528b22eb66ef58b35b0899a` |

## 21. Exact tagged top-limb membership

The compact range bus now uses one two-column tuple lookup against
`T={(t,v): 3<=t<=15, 0<=v<2^t}`. Its 65,528 rows fit the compact k16 usable
budget of 65,530. Width15 is loaded first, so the first/default tuple is
`(15,0)`; both table columns have identical lengths and their padding preserves
that tuple. This is one authenticated-width membership. A scalar union of
shifted intervals would permit cross-tag aliases and is not used.

Let circuit-fixed pattern `p` be zero for idle rows, one for a 15-bit step,
two for a tagged top, three for a one-bit top, and four for a two-bit top.
Write `I_j(p)` for its exact degree-four Lagrange indicator on `0..4`, and
let circuit-fixed `t` be the top width on tagged-top rows. The lookup input is

```
(15 + I_2(p)*(t-15), I_1(p)*(z-2^15*z_next) + I_2(p)*z).
```

Additional equations are `I_3(p)*z*(z-1)=0` and
`I_4(p)*z*(z-1)*(z-2)*(z-3)=0`. Idle and algebraic-top lookup rows use the
existing tuple `(15,0)`. Thus every step is an exact 15-bit digit, and the last
state has its exact top width. Telescoping gives the same integer bound below
`2^bits<=2^252<N`; neither integer wrap nor a different tuple tag can weaken it.
Checks now use `ceil(bits/15)` rows. The lookup input degree is five, its
argument degree is eight, and the narrow-root gates have degree at most eight.
The complete compact degree remains nine. Direct-public overlays multiply by
all four active-pattern roots and therefore remain disabled on every range row.

The root reviewer checked these equations and then independently read
configuration, table loading, assignment and public-overlay code, finding no
gap in that scope. The two-field targeted suite passes every width1..252,
zero/upper-bound/wrapped values, cross-tag offset attacks, every assigned-cell
mutations, known/unknown shape, first/last/default table tuples, and final usable
row acceptance/overflow rejection. The complete compact interpreter differential
suite passes on both curves. These functional tests do not replace current-source
performance qualification. Native tuple-lookup proof regression also passes
on both curves (`tagged-range-native-v2.log`, 9.75 seconds).

The actual descriptor has 12 fixed queries and 25 advice queries: the added tag
query and removed shifted-top previous-row query cancel, so transport remains
**4,768 bytes**. Enabling equality on one existing spare advice port produces
**4,800 bytes** in a query-count experiment; that experiment is not yet an
implemented parallel range predicate.

With the explicit Q2/A3 source profile, a genuine authenticated Bootstrap chain
produces 7,872-byte A proofs; its busiest A2 range lane has 65,283 rows. The
complete pinned compact predicate uses **63,889 shared and 97,993 range rows**.
Shared rows fit, while the range gate exceeds 65,530 by 32,463. Both the complete
Q2 relation (single k12/k14, two-sigma plus AS, Accept/Trivial and mutations) and
its actual 7,008-byte native proof pass. This remains a Bootstrap component
profile, not a frozen complete operation catalog. Evidence is in
`tagged-range.log`, `tagged-range-descriptor-v2.log`,
`tagged-compact-interpreter.log`, `serialized-q-two-bus.log`, and
`tagged-reduced-q-three-bus-bootstrap-omega.log` under `target/qualification`.


## 22. Three-carry dots with a structural strict 255-bit bound

The compact staged dot kernel now has an additional unsigned envelope. The
common admission still requires one to eight Proper/Canonical terms and
`m>2^254`; the narrow route additionally requires `m<2^255` and every operand
strictly below `2^255`. This last condition is structural: either Canonical form
retains its proved integer comparison with this modulus, or Proper form carries
limb bounds at most `(2^87-1,2^87-1,2^81-1)`. Honest witness values do not select
the route. Lazy/Bounded values, wider Proper bounds and both P-256 moduli keep
the wider predicate or fail the original admission.

For `B=2^87` and at most eight products, `S<2^513` and
`q=floor(S/m)<2^259`. The narrow output is checked at widths `87/87/81`, the
quotient at `87/87/85`, and the three offset carries at width93 with offset
`2^92`. The first three low-column equations and native residue are

```
D_j + u_(j-1) - B*u_j = 0       (j=0,1,2; u_-1=0)
S - c - q*m = 0 mod N.
```

As in the unsigned wide-dot argument, `|D_j|<28 B^2`, and induction gives
`|u_j|<29 B<2^92` for honest witnesses. Arbitrary checked offset carries give
signed `u_j` in `[-2^92,2^92)`; each local residual is below `2^180<N`.
The three exact low equalities make the integer residual divisible by `B^3`.
The native equality adds the coprime prime `N`. With the explicit input,
result and quotient bounds, the global residual is below `2^515`, whereas
`B^3*N>2^515`, so the residual is exactly zero. The result remains Proper;
this argument does not assert canonicality and does not cover signed sums.

Every staged result under a modulus in `(2^254,2^255)` now explicitly ranges
its top limb to81 bits and reports exactly that stronger Proper metadata.
This includes products, division and wider admitted dot results; their input,
quotient and carry admission remains unchanged unless the separate narrow-dot
check succeeds. Other layouts and moduli retain87/87/82. Selection takes the
maximum bounds and weaker form of both arms, so choosing an honest narrow
value from a wide arm cannot manufacture a narrow certificate. Constants are
canonical and pinned; constants at or above the modulus are rejected.

The fixed phase encoding reuses the existing dot-finish and carry codes on the
same row. The latter still copies all five accumulated sums to the already
reserved final row. On finish rows, fixed `payload3/3` is exactly zero for the
wide predicate or one for the narrow predicate. It selects the carry offset
and disables only the fourth low residual; the native equation remains active.
No phase domain, advice query, fixed query or row reservation is added, and
the complete descriptor remains4,768 bytes at degree9 with one lookup.

The root reviewer independently checked both the above CRT bounds and the
implementation: exact range roots, copied dot sums, fixed flag, retained native
residual, and matching result metadata on multiplication/division paths. No gap
was found in that scoped review. This is a new layout review, not a blanket
extension of the M3b sign-off and not current-source release qualification.

`narrow-dot-tests-v2.log` passes3/3 (464.14 seconds), covering both native fields,
both Pasta moduli, all batch sizes1..8, zero/max inputs, canonical and explicitly
narrow Proper inputs, copied/select outputs, wide-arm selection, invalid
constants, P-256 exclusion, forged result/quotient/carry/native residuals,
every assigned-cell mutations, known/unknown shapes, and final usable-row
acceptance/overflow rejection. `narrow-dot-compact-interpreter.log` passes the
complete native differential verifier on both curves (94.01 seconds), and
`narrow-dot-descriptor.log` confirms the unchanged byte gate. The retained four-carry staged regression also passes all four protocol moduli
and both native fields, including every-cell and final-row tests
(`narrow-dot-wide-regression.log`, 2/2, 280.75 seconds). The mixed
ECC/Glue/Poseidon/kernel suite also passes on both fields with every-cell
mutations (`narrow-dot-mixed-components.log`, 2/2, 952.28 seconds). No row-fit
or performance pass follows from these component results.


The fresh Q2/A4 Bootstrap candidate (`narrow-dot-reduced-q-four-bus-bootstrap-omega.log`)
passes its native A proofs and full diagnostic outer predicate (188.19 seconds).
A proofs are8,480 bytes. The pinned compact run uses66,347 shared rows
(12,173 Poseidon +26,088 arithmetic +28,086 ECC) and100,203 range rows, with
unchanged4,768-byte transport. **Both k16 row gates fail.** Its actual pure Glue
rows are22,840;12,083 Poseidon rows have six unused advice cells. Even an
optimistic87-bit secondary range placement would cover only4,868 checks,
before scheduling overhead, saving29,208 main-bus rows versus the required
34,673. This is capacity evidence for further implementation, not an installed
secondary range stream. Separately, genuine corrected Load with Q2/A3 reached
70,910 range rows and failed its source-A k16 budget, so the smaller Bootstrap
A3 profile cannot be frozen as the uniform operation catalog.


## 23. Reuse of exact fixed arithmetic constants

The compact arithmetic lane now shares a synthesis-local cache of explicit
field constants across its Glue, ECC and Poseidon constant sources. The first
`constant(c)` still assigns and constrains `x-c=0` through the fixed standard
gate. The first `enforce_constant(x,c)` retains its original fixed constraint.
A later request for that exact explicit constant returns the already constrained
root, or copy-binds its input to that root. Witness values never select cache
keys. Only bounded, shared row owners may opt in; fresh chip construction starts
a new cache, while its clones retain the same constraints and cursor. Cross-region
reuse uses the complete cell identity and an explicit permutation equality.

The root reviewer independently checked the first-use gates, hit paths, explicit
constant keys and synthesis ownership, finding no gap in that scope. This is an
internal source review and does not extend the original M3b sign-off. The
`compact-constant-cache-v2.log` regression passes on both fields, covering fresh
equal-valued witness cells, wrong first/hit constants, cross-region copies,
fresh synthesis/cache ownership, every assigned-cell mutation and known/unknown
shape. `compact-cache-interpreter.log` passes all three descriptor, query-trade
and full native differential tests on both curves.

The fresh authenticated Q2/A4 Bootstrap component
(`compact-cache-reduced-q-four-bus-bootstrap-omega.log`, 128.01 seconds) produces
8,480-byte source A proofs. Pinned one-key compact verification now uses
**64,928 shared rows** (12,173 Poseidon + 24,669 arithmetic + 28,086 ECC),
which fits 65,530, and **100,203 range rows**, which exceeds that limit by
34,673. Its exact descriptor remains **4,768 transport bytes**, degree nine,
11 advice columns, 12 fixed queries, 25 advice queries, five equality columns
and one lookup. This is a complete predicate inventory under a diagnostic
larger domain, not an actual k16 outer proof or a frozen release catalog.
The constant reuse removes 1,419 shared rows and does not remove range checks.
Contended functional runtimes are not performance-gate measurements.


## 24. Small-quotient unsigned lazy reduction

The serialized `FfChip::reduce` path now normalizes an admitted nonnegative
three-limb integer directly. The fused seven-row layout is unchanged. The
entry first verifies that the exact modulus is configured, then rechecks each
tracked limb bound against `2^94-1` and the modulus interval
`2^252<=m<2^256`. Public constructors retain opaque bounded cells: witnesses
range their limbs; constants pin exact integers; add/subtract/negate and P-256
linear combinations check their calculated envelope before emitting limb
equalities; selection takes maximum bounds; S6/table imports retain their
exact range certificates. Admission depends on that metadata, never values.

For `B=2^87`, `x=x0+B*x1+B^2*x2<2^269`, so the honest quotient
`q=floor(x/m)<2^17`. The output `c` has checked limbs `87/87/81` when
`m<2^255`, otherwise `87/87/82`. One checked 17-bit quotient and one checked
18-bit offset carry `w=u+2^17` enter the existing Glue equations:

```
x0 - c0 - q*m0 - B*w + B*2^17 = 0
(x0+B*x1+B^2*x2) - (c0+B*c1+B^2*c2) - q*m = 0 mod N.
```

Honest `u=(x0-c0-q*m0)/B` lies in `(-2^17,128)`, inside the offset
certificate. Every checked local residual is below `2^106<N`, so its native
equality is an integer equality and gives divisibility of `x-c-q*m` by `B`.
The second equation gives divisibility by the coprime native prime `N`.
The complete residual is below `2^274`, while `B*N>2^341`, forcing exact
integer equality. The returned form remains **Proper**: a congruent `c>=m`
can satisfy reduction and must still fail the separate canonical comparison
at semantic boundaries. There is no signed quotient or multiplication change.

The root reviewer independently rederived the bounds and read the implemented
low/native equations, admission, range widths, offset signs and Proper return,
finding no gap in that narrow scope. The two-field adversarial suite passes
for all four protocol moduli and the smallest admitted custom modulus, including
zero/max/m±1 inputs, native-only/low-only forgeries, quotient/carry overflow,
rejected wider metadata, a noncanonical Proper alias followed by a rejected
canonical comparison, every-cell mutation, known/unknown shape and final-row
boundaries (`unsigned-lazy-reduction-final.log`, 3/3, 0.54 seconds, additionally checking
unconfigured moduli and numeric envelope inequalities). The full compact native
differential and exact descriptor suite passes 3/3 in 78.32 seconds. Actual Q2/A4
Bootstrap source proofs and outer predicate pass in 123.70 seconds; the pinned
inventory is 64,928 shared / 97,137 range rows with unchanged 4,768-byte transport
(`unsigned-lazy-reduction-four-bus-bootstrap-omega.log`). Thus 73 specialized
reductions remove 3,066 range rows, but the range gate still fails by 31,607.
This scoped review is not release qualification. No advice/fixed query, lookup
or gate degree is added.

## 25. Bounded unsigned Pasta products and padded division

The staged kernel can select three offset-92, 93-bit carries and quotient
limbs of 87/87/85 bits only after the ordinary admission and these additional
structural conditions have been checked:

- `2^254 < m < 2^255`;
- multiplication: each operand limb is strictly below `2^88`, and the product
  of the tracked integer maxima is strictly below `2^512`;
- division `b*c + K = a + q*m`: numerator limbs retain the checked 94-bit
  envelope, divisor limbs are below `2^89`, the tracked divisor integer is
  below `2^257`, and each exact fixed padding limb is below `2^95`.

The result is range checked with 87/87/81-bit limbs in this staged Pasta
layout. It remains Proper, and canonical comparisons are still required at
semantic boundaries. Metadata widening takes the full four-carry predicate;
an honest small value never grants the shorter envelope. P-256 and custom
moduli outside the stated interval cannot select this bounded layout.

For either admitted mode, each of the first three unsigned column residuals
has absolute value below `14*B^2`. Induction bounds honest signed carries by
`15*B < 2^91`, within the chosen offset-92 certificate. Malicious checked
offset carries lie in `[0,2^93)`, so every local residual remains below
`2^180 < N` and is an exact integer equality. For multiplication the admitted
product is below `2^512`; for division `b*c < 2^512`, while the numerator and
exact padding are below `2^270`. The checked quotient is below `2^259` and
`q*m < 2^514`. Consequently the complete signed residual has absolute value
below `2^515`. The three low equalities make it divisible by `B^3`; the
unchanged native residue makes it divisible by `N`. Since both Pasta native
primes are strictly above `2^254`, `B^3*N > 2^515`, proving equality over the
integers. All five staged product sums include the same exact padding, and
the finish/carry gates bind their copied final-row values.

The root reviewer independently rederived these bounds and inspected the
actual admissions, ordered division roots, padding, quotient/carry widths and
staged copies. After the adversarial results, the reviewer accepted this
scoped implementation together with Section 24. This does **not** qualify
subsequent ordinary serialized lowering, compact capacity, timing/memory
gates, the release catalog or the complete construction.

The reviewed pre-lowering source snapshot is retained in the diagnostic
directory; its hashes are:

| Reviewed source | SHA-256 |
|---|---|
| `target/qualification/bounded-pasta-reviewed-mod.rs` (then-current `ff/mod.rs`) | `5cf4bbe5c3062e9fa5f520a14c736581fe41a15bd75a4dc3b6e8ed94ab85ff45` |
| `ff/rotated.rs` | `a50e5af85abb0ff903c4f5136a7435553badd68cab3b939a74ba8db947f0162d` |
| `ff/reduction.rs` | `3d70e5bc2957dc7dbc9dd23c6b9c2c07618e004fd2631305b08b5b12346882d0` |
| `ff/bounded_tests.rs` (staged-only snapshot) | `a272dce9eb31e2943469a8b463c240f8182d86939690219fdccd57ad3d7a17df` |

`bounded-pasta-tests-v2.log` passes all three targeted tests, including both
native fields, maximum tracked limbs, zero numerator/divisor, forged result,
quotient and carry, every-cell mutations, known/unknown layout, final usable
rows, metadata widening and excluded moduli. The full compact differential
passes 3/3 (`bounded-pasta-interpreter.log`, 77.99 seconds); scoped strict lint
passes. The retained staged corpus passes after its boundary test was updated
to mutate the three carry roots actually present in Pasta division, rather
than a nonexistent fourth root (`bounded-pasta-retained-boundary-fixed.log`).

The genuine Q2/A4 Bootstrap diagnostic produces 8,480-byte source proofs and
passes the full outer predicate in 142.90 seconds. The pinned compact layout
uses **64,928 shared / 94,792 range rows**, with unchanged **4,768-byte**
transport (`bounded-pasta-four-bus-bootstrap-omega.log`). Its 335 newly short
blocks remove 2,345 range rows. It still exceeds the k16 range capacity by
**29,262 rows**; there is no actual compact k16 outer proof or release claim.

## 26. Three-carry lowering onto ordinary Glue rows

The ordinary serialized profile now shares the structural `carry_layout`
selection with the staged profile. It lowers the chosen low equations onto
the existing Glue multiplication/linear rows, rather than defining another
gate. The full 94-bit envelope still selects four offset-104 carries. Proper
products use three offset-89, 90-bit carries and quotient widths 87/87/84;
the bounded Pasta envelope of Section 25 uses three offset-92, 93-bit carries
and quotient widths 87/87/85. Ordinary admission precedes selection. This
lowering explicitly rechecks mode/modulus restrictions before assigning roots.

Result limbs remain checked at 87/87/82 bits and retain the **Proper** form.
This is wider than the staged Pasta result, and needs a separate bound:
bounded division has `b*c < 2^513`, `q*m < 2^514`, and exact fixed padding
below `2^269`, so the global signed residual still has magnitude below
`2^515 < B^3*N`. Its first three coefficients remain below `14*B^2`, giving
the same honest carry and malicious local-residual bounds. Proper products
retain their Section 18 bounds. The native recomposition includes every
operand/result/quotient limb and the full fixed padding; only the fourth low
equation is absent. Offset witnesses are rebased from the original offset-104
representation before applying their narrower range certificates. A short
block uses 16 ordinary Glue rows instead of 19, without adding any query,
column, lookup or degree.

The root reviewer separately inspected this lowering and independently
rederived the wider-result bound, offset rebasing, exact padding/native
recomposition and metadata-only selection, finding no gap in that scope.
The required test corpus now passes 5/5 in 2.53 seconds
(`serialized-short-carry-tests-v2.log`): both native fields, all four protocol
moduli, maximum 256-bit Proper operands, small-custom-modulus exclusion,
bounded numerator/divisor limits, widened metadata, zero division, forged
result/quotient/carry, canonical aliases, every-cell mutation, known/unknown
shape and final usable-row boundaries. Strict all-target lint for the gadgets,
recursion and proof crates passes (`serialized-short-carry-clippy.log`).

| Current reviewed lowering source | SHA-256 |
|---|---|
| `ff/mod.rs` | `d9fac96aab07d5af33921651c720530e26a7ddbed9d75d8bdac2eef5ea520a5b` |
| `ff/serialized.rs` | `cd54a496ec1cf5f397ec49548bd0d633154fc16a818f85e26dfb402a2831cb13` |
| `ff/serialized/tests.rs` | `e6417d38fae751a3b7e2cf9d43ef73227f03d3d69edfb49ce7b235d02b28cb5e` |
| `ff/bounded_tests.rs` | `6e69b7ee1ce95814d572ee8496fc3b31fa33a5a7927e2902b7478b9949958a41` |

After receiving those results and exact hashes, the root reviewer accepted
this ordinary lowering as a source-level component. Actual A3/compact
capacity and current-source performance qualification remain separate gates;
earlier fixed-key artifacts must be regenerated for the new fixed schedule.
In particular, the parallel source profile attaches the direct four-row
rotated kernel, which still uses its four-carry predicate: ordinary Glue
lowering must not be credited with reducing all source product blocks.

The subsequent Q2/A3 Bootstrap diagnostic passes with actual 7,872-byte A
proofs and a pinned outer inventory of 62,500 shared / 91,862 range rows
(`serialized-short-q2-a3-bootstrap-omega.log`, 174.69 seconds). The transport
estimate remains 4,768 bytes, but the range limit fails by 26,332 rows and no
compact k16 proof is produced. The independently run complete Load candidate
still fails its A2 source stage at 68,760 range rows, so this is not a uniform
source profile or release-catalog result.

## 27. Exact tagged tables in parallel source range banks

The explicit tagged bank retains independent lookup arguments for independent
range buses. Each argument uses the same fixed `(width, value)` table; its tag
is circuit-fixed, so an out-of-range top cannot move into another width's
interval. The 65,528 rows enumerate widths 3 through 15; widths 1 and 2 use
exact algebraic roots. Default and padding tuples are `(15, 0)`. This replaces
shifted-top rows without weakening a limb bound or changing CRT admission.
The default source profile remains available as a separately named layout;
artifact acceptance does not fall back between profiles.

Both-field bank tests pass every-cell mutations, exact width failures,
known/unknown shape, same-cell certificate reuse and rejected mixed-table or
duplicate-column construction (`tagged-bank-tests.log`, 51.96 seconds). The
full interpreter differential passes both curves with two and three buses,
honest and malformed proofs, hard/soft behavior and known/unknown shape
(`tagged-bank-interpreter.log`, 43.63 seconds). Scoped strict lint passes.

The actual Q2/tagged-A3 Load diagnostic completes all four native proof stages
(`/tmp/kg-load-q2-a3-tagged.log`, 511.01 seconds). Their maximum occupied rows
are 55,611 / 61,808 / 57,646 / 58,164, and every source proof is 7,744 bytes.
The common source descriptor has degree 8, 23 advice columns, 51 fixed
queries, 57 advice queries, 16 equality columns and four lookups, with digest
`4c9ed1f762bbad39623dd865a5c72876d5482d1ddf20bf15f6facf3259d9233b`.
The rooted Bootstrap predecessor uses the matching source profile. This
establishes Bootstrap/Load source feasibility; final catalog rebinding, Send,
all remaining operations and release qualification remain open.

The matching actual Bootstrap-to-compact diagnostic
(`tagged-q2-a3-bootstrap-omega.log`, 202.90 seconds) uses 62,849 shared rows
and 94,033 range rows. The 4,768-byte transport is descriptor-derived only;
the range lane exceeds k16 by 28,503 rows and no compact k16 proof is produced.
Its single Bootstrap key is not a release catalog.

| Tagged source component snapshot | SHA-256 |
|---|---|
| `crates/iroha_plonk_gadgets/src/range/running_sum.rs` | `156044f14acd73e86d520ee43d5bd1317e1194ba90aa86586277a2afe2c548aa` |
| `crates/iroha_plonk_gadgets/src/range/running_sum/cache_tests.rs` | `5e4a7977a05caf8d750c88367ae4ce550db235899686aa91a54c4ddf24457e8d` |
| `crates/iroha_plonk_recursion/src/verifier/mod.rs` | `f80d9e1b22b7f09332e81264af89954fdd75ecd4596902db3f5f6d979b96ab6e` |
| `crates/iroha_plonk_recursion/src/verifier/tests.rs` | `07e805c532e20203e588f5a67122aac2953b9591c10b40700b8860890ed95c70` |

## 28. Secondary algebraic range and checked replay (qualification open)

`range/secondary.rs` adds an experimental range stream on spare existing
compact advice ports. It retains the single authenticating tuple lookup;
its digits are constrained by polynomial roots. The named experimental phase
encoding makes zero fixed bits the idle ECC phase, so the linear digit enable
vanishes on unused/blinding rows. Existing production profiles keep their
original phase encoding. An explicit compact candidate now connects this component
to the complete interpreter through a fixed replay plan; its full predicate,
proof and admitted-catalog qualification remain open.

The second running state uses port 4 at rotations 0/+1. Glue packs digits of
widths 3/3/2/2/2 (12 bits); Poseidon packs five 3-bit digits (15 bits). Exact
termination widths are Glue 9/Poseidon 6 for 81-bit inputs, Glue 9 for 93-bit
inputs, Glue 3/Poseidon 12 for 87-bit inputs, and 8 bits in either phase for 128.
The Glue 9-bit top explicitly constrains its last digit to one bit. Every
unused top digit is zero. Telescoping yields the exact requested integer
bound below 2^128, strictly below either native modulus; field wrap cannot
provide an alternative representation. A fixed primary tagged-top row keeps
its own width control and forces a secondary step. Other rows reuse the
otherwise unused control for a step or exact top. The shared metadata is
circuit-fixed and never selected by a witness value.

The independent root review caught a missing one-bit gate in the first
81/93-bit extension: honest witness masking did not constrain a coordinated
forgery. The corrected source includes that gate and a regression replacing
all running states and the public input consistently by 2^81/2^93, with top
digit 2. The malformed construction must fail specifically in the digit gate.
The corrected pre-guard component suite passes 5/5, including both native proof
curves, all assigned component cells, all supported widths/phases, zero/max/
field-wrap boundaries, final usable rows and known/unknown layout
(`secondary-range-expanded-fixed.log`, 253.29 seconds). Its actual descriptor
still estimates 4,800 transport bytes, degree 9, eleven advice columns, twelve
fixed queries, 25 advice queries, six equality columns and one lookup
(`secondary-range-expanded-fixed-descriptor.log`). These are component
results; they do not establish full-interpreter placement or an actual
compact outer proof.

Opt-in frontend guards now require existing/future/final fixed values to
agree and reserve each secondary advice cell for exactly one assignment.
Missing assignments and collisions are rejected in both known and unknown
synthesis. Every native Assignment adapter forwards the guards. The focused
frontend suite passes 18/18 (`guarded-placement-frontend-tests.log`). The
guarded component suite passes 6/6 in 309.58 seconds
(`secondary-range-guarded-v2.log`), including earlier/later fixed and advice
collisions under known and unknown witnesses. Strict all-target lint for the
three owning crates passes (`guarded-placement-owned-clippy.log`, 12.70 seconds).
The root reviewer independently checked the corrected exact-top induction,
nonnegative unused sums, explicit high-bit gate and frontend guard lifecycle,
accepting this scope only. That review does not sign off the scheduler, full
Omega circuit, key catalog or release qualification.

Actual tagged-A3 Bootstrap placement analysis finds 20,501 wholly free Glue
rows and 11,565 free Poseidon rows in 1,101 disjoint segments. A first greedy
placement saves 26,598 primary rows, leaving 67,435 before exact primary-top
alignment (`secondary-tagged-a3-placement.log`, 147.04 seconds). Reserving
extra empty-Glue rows from the remaining shared capacity is under evaluation.
TODO: finish the checked structural event schedule, guard all successor query
neighborhoods and shared-control agreement, replay known/unknown synthesis,
and generate/verify the actual compact k16 proof before claiming fit.

| Reviewed secondary/guard component snapshot | SHA-256 |
|---|---|
| `crates/iroha_plonk_gadgets/src/range/secondary.rs` | `0d91d439a088754ad58072e7f17474505faf0a4adb86f1c6d83d608d28161c75` |
| `crates/iroha_plonk_gadgets/src/range/secondary/tests.rs` | `a804c18381f125404640ae1f1aabbba1c6409d0b3630e6a2f2ed3dfcea4a22f3` |
| `crates/iroha_plonk_gadgets/src/phase.rs` | `706f80d9dd269a3f5e875fe6441d78bdca3cbb2c849a48d821e6e5a19cecd701` |
| `crates/iroha_plonk/src/frontend/assignment.rs` | `65da85c473dc8f41428c62a7c460e3a399eb023226e9b6141b809d83e277b2a1` |
| `crates/iroha_plonk/src/frontend/layouter.rs` | `87c59e305305b90eefc0c9c5bb0b558664138d31e81ce23b45afd856f70e881d` |
| `crates/iroha_plonk_gadgets/src/tamper.rs` | `89c425e73c73ec2935ff01acc667ac64b092f2df54430941b22c0ba373b8b7e3` |
| `crates/iroha_plonk_gadgets/src/ecc/tests.rs` | `e21b46d487e7a5dfd693273f85f108f972d55b26265578c6465d2dae7a071e12` |

A subsequent fixed-point structural projection includes primary-top alignment,
37 rows reserved for the direct public prefix, and 2,644 additional empty-Glue
rows. It projects 65,377 primary rows, with 153 rows remaining
(`secondary-tagged-a3-aligned-placement.log`, 199.90 seconds). This does not yet
model every forced successor collision or perform circuit assignments. The
complete candidate must reject collisions through the guards, bind every
recorded range event and source, and close an actual native proof before this
projection can become a row-fit result.

The successor-aware structural projection inserts primary gaps at every eligible
segment endpoint so forced secondary steps cannot read a neighboring owner's state.
It projects 65,472 primary rows for the pinned Bootstrap key (58 remaining)
and 64,975 for the witnessed-key trace
(`secondary-tagged-a3-neighborhood-placement.log`, 127.38 seconds). These remain
structural estimates, without a checked replay or an actual compact proof.

The opt-in replay represents every noncached range request by its exact width
and a fixed primary/secondary location. A real secondary check emits its
range predicate immediately; a copied source is joined by permutation equality.
All clones share the request cursor and exact-cell certificates. Finishing
requires every request exactly once and rejects missing, extra or mismatched
requests; no typed result comes from an unchecked deferred constraint.

On Glue rows, the five digit ports and state port lie outside the four Glue
ports; ECC and staged CRT predicates are disabled by the guarded phase. On
Poseidon rows, the secondary ports lie outside state/aux ports; Glue/ECC/CRT
predicates are disabled. The primary pattern is active wherever the secondary
control is reused, disabling the direct-public overlay. The real public prefix
retains zero primary activity and idle ECC phase, and the Poseidon lane starts
after a fixed 37-row prefix. Secondary checks cannot cross radix/owner boundaries,
and primary tagged tops are excluded at segment endpoints because they force a
secondary next-state query. Cell and fixed guards validate these promises during
actual assignments; known/unknown compiled layouts must still match.

Unclaimed dummy steps are filled backward with zero digits, using the already
assigned successor state. Their field values carry no application meaning and
may have harmless degrees of freedom; only real requested roots receive source
and public bindings. No dummy result is returned as a range certificate. The
primary successor cell is explicitly assigned, and a last-usable-row step is
rejected. Checked tape growth prevents malformed alternating one-row phase
inventories from indexing beyond the allocated program. These are implementation
contracts, not yet a complete Omega/catalog qualification statement.


The complete replay now passes on an authentic full-C4 Q2/tagged-A3 Bootstrap
terminal proof. Both witnessed-key and pinned-one-key programs produce an
actual **3,712-byte PIPA-R proof**, natively verify/decide it, and satisfy k16
with known/unknown fixed columns, assignment masks and permutation equality.
Including the two transported accumulators gives **4,800 bytes**, at degree
nine, one lookup, 11 advice columns, 25 advice queries, 12 fixed queries and
six equality columns. Real primary spans are **64,997** (witnessed) and
**65,508** (pinned); the successful combined component run is
`secondary-replay-real-bootstrap3.log`, 208.71 seconds on the busy host.

The checked replay suite passes 5/5 in `secondary-replay-tests2.log` (280.62 s),
including actual native proofs on both curves and all meaningful-cell mutations.
The prefix integration initially exposed a continuing duplex tap that still
used a relative block address. It now uses the lane's absolute block start;
0/16/37-prefix native parity passes on both fields
(`secondary-duplex-offset-tests2.log`). Bounded offset reservation also passes
(`secondary-pow-offset-tests.log`). Strict three-crate all-target lint passes
(`secondary-replay-current-clippy.log`, 14.64 s).

This first actual compact component snapshot was not the final admitted Ω:
it contained one Bootstrap terminal key without rebuilding its carried lineage.
The subsequent one-terminal rooted run below closes that specific continuity
check. Complete catalog/root continuity, every operation, recursive adversaries
and the prescribed loaded-host measurements remain open.
Earlier 4,768-byte descriptors and oversized generic layouts are superseded
profile diagnostics, not produced proofs or current release qualification.

| Actual compact proof snapshot (`secondary-replay-real-bootstrap3.log`) | SHA-256 |
|---|---|
| `range/secondary.rs` | `78c29c5e300297c35c6dff6ab18266fdd81da4743d91dd00e9411c63ba902068` |
| `range/secondary/schedule.rs` | `6871ff1a358133dc34482c90b84365053bcb28df580dc754994f78968816fcc4` |
| `range/secondary/schedule_tests.rs` | `fc9e560b5f940a19f6301c08a7d735a840667c750235f051b96af4829e880692` |
| `range/running_sum.rs` | `aa594e4c3e853e81bfe50ec79008926ef66b82cb36c8b3ffee2269a135ca957f` |
| `poseidon/pow5.rs` | `7f49423e9620a9aceb8ca7e0eafdbcd202efca7c8bdc5511c67a0d946d2b258c` |
| `pow5_fq/duplex.rs` | `c70eb25daa1645048260559d4a437df3a26661a7160aa8248af0c73ea5c5baa9` |
| `iroha_plonk_recursion/src/verifier/compact.rs` | `05f40fa8bec829ee3f5ca9015e413e83866f978002214bbfd9dbe5e208fc3c69` |
| `iroha_kagemusha_proof/src/omega.rs` | `a3ef0d67c9863f04f7106004a40ec1cb477b0cbab6f21f035a8ac1a169c4e62f` |

The later hard allowlist predicate uses
`prod_i(computed_complete_key_digest - fixed_digest_i) = 0` in Fq, with the
same nonempty/distinct/at-most-32 metadata checks. Every factor and product is
constrained by existing Glue gates; a field has no zero divisors, making this exactly key
membership. No exported selector is needed here; Q_sigma retains its separate
one-hot selector/index. All 32 positions, foreign digests, metadata limits,
every intermediate cell and known/unknown shape pass three focused tests.
Actual k12/k14/k16 source proofs also reject another admitted key substituted
under the original proof/public input, and reject an unauthorized complete
digest (`omega-real-key-membership-tests.log`, 87.57 s). Strict proof all-target
lint passes (`omega-membership-rooted-clippy.log`, 23.95 s).

`rooted-compact-bootstrap.log` passes in 384.49 s: all signed objects,
sigma/Q/A1/W/A2 proofs are rebuilt with the actual compact Omega digest,
then the source A and Omega descriptor/VK bytes are checked unchanged. The
actual 3,712-byte outer proof and transported Vesta accumulator both decide;
changed public columns and proof bytes reject. Transport remains 4,800 bytes,
k16/degree9/one lookup. The pinned single-key schedule has primary end 65,458
and shared baseline 62,844 plus prefix 37 and explicit padding 2,649.
This closes **one Bootstrap terminal's** immutable-key continuity, not the full
catalog or any release/performance gate. Its observed owned-source/binary hashes
are in `rooted-compact-bootstrap.owned-source-and-binary-sha256`; Omega source
is `5768b457b2b56ea5d66f932c3a3de9bb503af5b8c5c9a056b2a4f27f8d07bb1b`
and the executable is
`c2858721b9fa187e55a0fc6a2781f44c0b25308f76bfe4f4b5ffd8937c332e34`.


The captured witnessed-key two-terminal Bootstrap/Load and three-terminal
Bootstrap/Load/Send-mask0 component catalogs also pass immutable-key continuity.
Every signed source chain is rebuilt under its actual common Omega digest;
source and outer VK bytes remain unchanged, all outer proofs verify and both
transported obligations decide. The schedules use 64,991 and 64,996 primary
range rows; each outer proof is 3,712 bytes / 4,800 bytes transported. The full
three-terminal test passes in 2,754.43 seconds on the busy host, with source and
binary provenance in `target/qualification/compact-three-terminal-catalog-merged2-source.json`
and outcomes in the matching `.log`. This is not timing qualification.

The current compact helper has replaced that witnessed-key multi-terminal source
with the canonical native pinned-catalog circuit. It derives the catalog's exact
layout and keys afresh, imports the original PK through the native producer, and
uses native terminal-fold selection, proving and canonical checkpoint restoration.
Its reusable seed/extension path rebuilds the payer and receiver under each new
immutable catalog key. The helper compiles, but fresh layout, size, actual proof
and signed-source rebuild results remain pending. The earlier 4,800-byte result
belongs to the captured source; matching descriptors cannot establish source
identity or transfer qualification to the pinned-catalog producer.

These captured Load-derived component chains use the superseded dedicated-publisher
voucher trust model. The native and recursive Load producers now consume an
ordinary transaction receipt and its compact block-finality evidence. Their
integration helpers require genuine original proving artifacts and finality
evidence; the retired issuer fixture is removed. Installing that fixture and
rebuilding the complete source/catalog remain open. No measured component key
is an admitted release key.
The other seven Send masks and full fourteen-terminal composition remain open.

Fresh merged-wire size tests pass 2/2 in
`target/qualification/payment-current-encoding-size.log`: the fixed Payment
overhead remains 1,723 bytes and explicitly structural 3,456-byte sigma /
4,800-byte Omega samples encode to 9,979 bytes. The joint proof budget is 8,277
bytes, leaving 4,821 bytes for Omega with that sigma size and a 21-byte margin
for this component. Encoding fit does not establish proof acceptance under a
completed current catalog or the two-second durable-completion requirement.

## 29. Retained hard integer bounds on canonical S6

`CanonicalS6` now distinguishes its declared arithmetic modulus from a private
strict integer upper bound proved for its exact retained low128/high127 cells.
Every limb, native-word and hard decoder constructor records its actual hard
comparison/decomposition bound. Widening the declared modulus preserves the
tighter bound; narrowing adds the existing hard comparison only when necessary.
Cloning preserves both cells and metadata. FF export first canonicalizes and
conservatively records that FF modulus; it does not inherit a tighter bound from
an unrelated earlier value or an unproved witness observation.

Soft decoding retains the source scalar modulus for both selected branches:
the valid original is constrained canonical, and the invalid branch is fixed
zero. Its validity bit remains separate. In particular, a small Fq witness or
an invalid Fq message selecting zero does **not** create an Fp-bound certificate.
There is no public unchecked constructor or general branch-selection escape.

The typed `Bounded` predicate can return constrained true when this retained
hard upper bound is at most Fp. This extends the previous Vesta-native case to
the exact Fp word embedded in Fq without repeating its comparison. All other
values use the existing full comparison; all `Bits` checks remain intact.
This changes no FF carry or CRT equation or admission envelope.

The root's independent source review checked all constructors, widening,
narrowing, conservative export and the two soft branches, finding no gap in
this scoped reuse. Full codec tests pass6/6 (`s6-retained-bound-codec-tests.log`,
24.06 s). An explicit both-field hard/soft decoder regression passes at
0,1,m−1,m,m+1 and 2^255, including invalid/small metadata assertions,
every-cell mutation, source-cell identity and unknown shape
(`s6-soft-bound-tests.log`, 0.63 s). Strict all-target lint for gadgets,
recursion and proof passes (`s6-retained-bound-clippy2.log`, 12.41 s).
The k16 bridge suite passes 3/3, including every assigned cell on both fields
and both bridge directions (`s6-retained-bound-bridge-tests.log`, 316.79 s).
Composed profile capacities and measurement
qualification must be rerun on the resulting candidate before claims of benefit.

| Retained-bound source | SHA-256 |
|---|---|
| `iroha_plonk_gadgets/src/ff/s6.rs` | `bf463cb3fb0964f3a03086cdfdd69c67a7401e7701c296e891c0cead8824486b` |
| `iroha_plonk_gadgets/src/ff/s6/tests.rs` | `a66bb861175d3e335ad3c0f0b6618de3e9420acb08246627d953448c477ca4d4` |
| `iroha_plonk_recursion/src/codec.rs` | `71379a178375258b7cc99a36f7536609a0152a0e17f9920d67afd31a8a47f485` |
| `iroha_plonk_recursion/tests/codec.rs` | `9b67d43e0314789c79f621bd4ca28e9c20e90838430cc59b91211e120fc25ac8` |
