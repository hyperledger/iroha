# PIPA-v1: Pasta PLONKish/IPA proof format and verifier

Status: first draft (task T14), 2026-10-04. Owner: `crates/iroha_plonk` (arithmetization, keys,
transcripts, prover, verifier) on `crates/iroha_pasta` (fields, curves, hash-to-curve, MSM, fold,
FFT, `ParamsIpa`, RP57 Poseidon).

PIPA-v1 is the only Pasta PLONK/IPA format of the first release; there is no fallback decoder.
The retired independent prover survives only as captured public reference data. Native unit
tests and an independent standard-library verifier retain its correctness checks; no second
prover dependency or shipping compatibility decoder remains.

Markers:

- **[V]** reproduces captured independent bytes or behaviour at the baseline in
  `specs/native_prover_migration_inventory.md`.
- **[P]** is a PIPA-v1 production deviation: a stricter rejection or the descriptor binding.
  Section 14 registers them all.

## 1. Conventions

- **Curves.** Pallas `Ep` has base `Fp` and scalars `Fq`; Vesta `Eq` has base `Fq` and scalars
  `Fp`; `p < q < 2p`. A proof uses one curve `C`, with scalar field `F` and base field `B`.
- **Encodings.** A scalar is 32 bytes, little-endian and canonical (values `>= modulus` are
  rejected). A point is a 32-byte compressed `x` with the parity of `y` in bit 255, byte-identical
  to `pasta_curves` 0.5.2; all-zero bytes are the identity `O`. Integers are little-endian and
  fixed-width.
- **Domain and rows.** `n = 2^k` and `omega = ROOT_OF_UNITY^(2^(32-k))`. `DELTA = 5^(2^32)` and
  `ZETA` are the `ff` constants. `d` is the degree, `b` the blinding factors and `u = n - b - 1`
  the usable rows. Row `u` is `l_last`, and rows `u+1..n` are `l_blind`. Rotation `r` reads row
  `(i + r) mod n` and is evaluated at `omega^r x`.
- **Counts.** `n_a` is the number of advice columns and `m` of equality columns;
  `n_z = ceil(m / (d-2))` is the number of permutation sets and `n_l` of lookups. `q_a`, `q_f` and
  `q_i` count advice, fixed and instance queries, `n_s` counts opening point sets and `n_sel`
  original selectors.
- **Names.** Params points are `g[i]`, `g_lagrange[i]`, `W` and `U`; the IPA challenges are
  `u_0..u_{k-1}`.
- **Bounds.** `1 <= k <= 28` and `3 <= d <= 9`. The `d` bound is the format cap. Ordinary standalone gadget chips
  target `d <= 6`; the explicitly measured compact recursive layout uses up to degree 9. Each count is at most 65,535, the descriptor
  frame at most 16 MiB and the expression stack at most 1,024. Node policy may be stricter but
  never looser; admitted native relations pin their exact domain exponent and descriptor. All size arithmetic is checked, and an
  overflow is a rejection.
- **Scope.** A proof covers one circuit instance and one advice phase, with no challenges, using
  IPA and halo2 permuted lookups only. Unsupported: KZG, shuffle, the Keccak transcript, the
  vendored Hybrid instance mode and multi-circuit proofs.

## 2. Arithmetization [V]

**Queries and gates.** A query is `(column, rotation: i32)`. Each column kind (fixed, advice,
instance) has an ordered query table in which a pair occurs once, because halo2 interns them.
`enable_equality(c)` adds the query `(c, 0)`.

Expressions are trees over `Constant`, `Fixed(q)`, `Advice(q)`, `Instance(q)`, `Negated`, `Sum`,
`Product` and `Scaled(e, constant)`, where `q` indexes a query table. Degree is 0 for a constant
and 1 for a query or virtual selector; a `Product` adds degrees and a `Sum` takes the maximum.
Every gate has at least one polynomial, each of degree `<= d`.

**Selector compression.** This is an exact port of halo2's `compress_selectors::plan`.

- A simple selector may appear only as a factor, at most once per gate polynomial, and never in a
  lookup.
- `deg(s)` is the maximum degree of the gate polynomials whose simple selector is `s`. Complex and
  unused selectors have `deg = 0`.
- `first` is the number of fixed columns `configure` allocated, table columns included.

If `compress_selectors = 0`, selector `s` becomes fixed column `first + s`, holding 1 on active
rows and queried at rotation 0, appended in selector order.

If `compress_selectors = 1`, the plan runs with `D = d`:

1. Each selector with `deg = 0` becomes a singleton combination, in index order.
2. Simple selectors `i` and `j < i` are excluded from each other (`excl[i][j]`) when they share an
   active row.
3. Each not-yet-added simple selector `i`, in index order, starts a combination `{i}` with
   `t = deg(i) - 1`. Later selectors `j` are scanned in order:
   - stop when `t + |comb| == D`;
   - skip `j` if it was added, is excluded by a member, or `max(t, deg(j) - 1) + |comb| + 1 > D`;
   - otherwise add `j` and set `t = max(t, deg(j) - 1)`.
4. Combination `c`, in creation order, becomes fixed column `first + c`, and its query
   `(first + c, 0)` is appended in that order.
5. The `j`-th member (1-based) gets root `j`: the column holds `j` on that member's rows. Its
   selector is replaced by `q * prod_{r = 1..|comb|, r != j} (r - q)`, built left to right as
   `Product(acc, Sum(Constant(r), Negated(q)))`.

Substitution rebuilds every gate and lookup expression node for node.

**Masks.** `b = max(3, max_c |advice queries of c|) + 2`; the inner maximum is 1 when there are no
advice columns. `n >= b + 3` is required. The masks are `l_0`, `l_last = l_u` and
`l_blind = sum_{i=u+1}^{n-1} l_i`, with `l_i(x) = omega^i (x^n - 1) / (n (x - omega^i))`.

**Permutation.** Equality columns are taken in `enable_equality` order. With `ch = d - 2`, set `s`
covers columns `[s*ch, min((s+1)*ch, m))`. Then `sigma_j(omega^i) = DELTA^{j'} omega^{i'}` for
`(j', i') = mapping(j, i)`.

The vendored union-find builds `mapping` over cells `j*n + i`. `copy(l, r)` is a no-op within one
cycle. Otherwise the smaller cycle merges into the larger (on a tie the left survives), it is
relabelled, and `mapping[l]` and `mapping[r]` are swapped.

Constraints, in order (none when `m = 0`):

1. `l_0 (1 - z_0(x))`;
2. `l_last (z_{n_z-1}(x)^2 - z_{n_z-1}(x))`;
3. for `s >= 1`, `l_0 (z_s(x) - z_{s-1}(omega^{-(b+1)} x))`;
4. for each set, with `j` the global column index and `v_j` its rotation-0 evaluation:

```text
(1 - l_last - l_blind) * ( z_s(omega x) * prod_j (v_j + beta*sigma_j(x) + gamma)
                         - z_s(x) * prod_j (v_j + beta*DELTA^j*x + gamma) )
```

**Lookup (halo2 permuted).** A lookup has inputs `a_0..a_{w-1}` and tables `s_0..s_{w-1}`,
`w >= 1`. They compress as `A = fold(acc * theta + a_i)`, so `a_0` carries `theta^{w-1}`, and `S`
likewise. The prover commits `A'` and `S'`, then `z`.

Constraints, in order:

1. `l_0 (1 - z)`;
2. `l_last (z^2 - z)`;
3. `(1 - l_last - l_blind) (z(omega x)(A'+beta)(S'+gamma) - z(A+beta)(S+gamma))`;
4. `l_0 (A' - S')`;
5. `(1 - l_last - l_blind)(A' - S')(A' - A'(omega^{-1} x))`.

The required degree is `max(4, 2 + max(1, deg a) + max(1, deg s))`.

The permutation is the vendored one. The usable rows of `A` are grouped by value, in ascending
canonical-integer order. Group `g` (value `v`, count `c`) emits `(v, v)`, then `c - 1` leftovers
from the slice `[start_g - g, end_g - g - 1)`. Leftovers are the sorted usable table values that
repeat their predecessor or are absent from the input. An input missing from the table is a prover
error.

**Degree and vanishing.** `d = max(3, lookup degrees, gate degrees, minimum_degree)`.
`h = (sum_j y^{N-1-j} c_j(X)) / (X^n - 1)` runs over the `N` constraints in order: gate
polynomials, then permutation items 1-4, then lookups.

`h` is split into exactly `d - 1` pieces `h_i`. Piece `i` holds coefficients `[in, (i+1)n)` and
has its own blind. `R`, of degree `< n`, is committed before `y` and masks `h(x_3)`. The prover's
evaluation over exactly `d - 1` cosets is internal and yields the same `h`.

## 3. Parameters and the params digest

`ParamsIpa<C>` is the transparent derivation of `crates/iroha_pasta/src/params.rs` **[V]**:

- `g[i] = hash_to_curve("Halo2-Parameters", 0x00 || u32_le(i))`;
- `W` and `U` hash the messages `[0x01]` and `[0x02]`;
- `g_lagrange = n^-1 IFFT(g)`.

Its bytes are `u32_le(k) || g || g_lagrange || W || U`.

**[P]** `params_digest(C, k) = SHA-256(params bytes)`.

- Every verifier compiles the table `PINNED_PARAMS_V1[(curve, k)]`, seeded from
  `fixtures/native_prover/kats_v1.json` (`params_ipa[*].sha256`, `k = 6..16`). CI recomputes each
  entry from the derivation.
- A verifier derives the params, or accepts only bytes that hash to the pinned entry. The digest
  covers `g_lagrange`.
- Signatures on params artifacts help provers only; they never authorize verifier inputs.
- `g[0..2^j)` is equal for every `k >= j`, so accumulators of different `k` share a prefix of `g`.

## 4. CircuitDescriptorV1 [P]

The descriptor is the canonical, source-level statement of everything the verifier evaluates (hash
what you verify).

- Verification depends only on `(D, VK bytes, params, instances, proof)`.
- The verifier never calls `configure()`, so nodes verify against pinned descriptor blobs without
  linking chips.
- `D` is the `configure()` output after selector substitution, with expression trees as written:
  no CSE, simplification or compiled form.

`D = norito::encode_canonical(&CircuitDescriptorV1)`, with schema name
`iroha.plonk.pipa.circuit_descriptor.v1`. Digests cover the complete canonical frame, header
included. The schema is frozen: any change is a new type and version.

| Field | Type | Rule |
| --- | --- | --- |
| `protocol_version` | `u16` | `1` |
| `curve` | enum `{Pallas, Vesta}` | proof curve |
| `base_modulus`, `scalar_modulus` | `[u8; 32]` | the curve's moduli |
| `params_digest` | `[u8; 32]` | `PINNED_PARAMS_V1[(curve, k)]` |
| `k` | `u8` | |
| `transcript` | enum `{Blake2bChallenge255, KagemushaPoseidonRp57}` | 6.1, 6.2 |
| `instance_mode` | enum `{Committed, Direct}` | 6.3 |
| `proof_suffix` | enum `{None, FoldedGenerator}` | section 11 |
| `degree`, `blinding_factors` | `u8`, `u16` | `d`, `b` |
| `permutation_chunk_len`, `quotient_pieces` | `u8`, `u8` | `d - 2`, `d - 1` |
| `lookup_kind` | enum `{Halo2Permuted}` | |
| `num_fixed_columns`, `num_advice_columns` | `u32` | fixed count after substitution |
| `instance_lengths` | `Vec<u32>` | exact length of each instance column |
| `fixed_queries`, `advice_queries`, `instance_queries` | `Vec<{column: u32, rotation: i32}>` | halo2 order |
| `selectors` | `{compress: bool, first_column: u32, entries: Vec<{max_degree: u8, combination: u32, root: u8}>}` | one entry per original selector |
| `gates` | `Vec<Vec<ExprV1>>` | after substitution |
| `permutation` | `Vec<{kind: {Advice, Fixed, Instance}, index: u32}>` | equality order |
| `lookups` | `Vec<{inputs: Vec<ExprV1>, tables: Vec<ExprV1>}>` | |

`ExprV1 = Vec<ExprNodeV1>` lists nodes in postfix order. The node kinds are `Constant([u8; 32])`,
`Fixed(u32)`, `Advice(u32)`, `Instance(u32)`, `Negated`, `Sum`, `Product` and `Scaled([u8; 32])`,
where each `u32` indexes a query table. Decoding and evaluation use an explicit stack. Names of
gates, columns and lookups are diagnostics and are not part of `D`.

**Validation.** Each failure is `DescriptorInvalid(rule)`.

1. Admission decode (`decode_canonical_for_admission`) consumes the whole frame, re-encoding
   reproduces `D`, and the section 1 bounds hold.
2. The version, moduli and pinned params digest match.
3. `d` is in range and at least the computed degree, and the chunk and piece fields agree with it.
   The extended domain `2^e`, the least with `2^e >= n(d-1)`, satisfies `e <= 32`.
4. `b` follows the masks formula (section 2), `n >= b + 3`, and every instance length is `<= u`.
5. Queries name existing columns, and no `(column, rotation)` repeats. All rotations are distinct
   modulo `n`. That includes the implied rotations: `0`; `1` when `n_z + n_l > 0`; `-1` when
   `n_l > 0`; and `-(b+1)` when `n_z >= 2`.
6. Every postfix expression is well formed and yields exactly one value. Indices are in range,
   constants are canonical, and degrees are `<= d`. No gate is empty, and each lookup has
   `|inputs| = |tables| >= 1` and a required degree `<= d`.
7. Permutation columns are distinct and exist, and each has a rotation-0 query.
8. `first_column + #combinations = num_fixed_columns`. Roots are `1..=|comb|`, every combination
   column has its rotation-0 query, and uncompressed entries are `(s, 1)`.
9. The S7 zero-knowledge budget holds.

```text
descriptor_digest = BLAKE2b(32, person "PIPA-v1-CircDesc", D)
transcript_repr   = F::from_uniform_bytes(
    BLAKE2b(64, person "Iroha-PlonkVK-v1", descriptor_digest || vk_bytes))
```

This one scalar binds the relation, params, instance shape and keys, and it is absorbed first
(6.3).

Registry obligation (M2): a PIPA-v1 VK record carries `D`, or its digest, beside `vk_bytes`, so
`hash_vk` covers both. It uses new `pipa-v1` backend labels and circuit IDs; a vendored-halo2
label never names a PIPA-v1 proof.

### 4.1 CircuitDescriptorV2 and PIPA-R [P]

PIPA-R uses canonical schema `iroha.plonk.pipa.circuit_descriptor.v2` while
`protocol_version` remains 1. It has the V1 fields in the same semantic order,
with `transcript: TranscriptV2`, followed after `lookups` by
`instance_types: Vec<InstanceType>`. The transcript enum adds
`KagemushaPoseidonRp57Base`; this profile requires Direct instances and the
FoldedGenerator suffix. There is exactly one type per instance column:

- `Field`: canonical proof-scalar field element, transcript type code 0.
- `Bounded`: additionally strictly below the smaller Pasta modulus p, code 1.
- `Bits(b)`: additionally strictly below `2^b`, for `0 <= b <= 253`, code `2+b`.
  Bits(0) admits only zero; wider declarations are invalid descriptors.

The V1 validation rules still apply to the common arithmetization. A shared
`ProtocolDescriptor` is an internal representation, not another wire encoding.
Admission uses explicit V1 or V2 constructors/decoders; a failed decode never
tries another profile. KAGEMUSHA consumers are re-keyed to PIPA-R and reject
the retired scalar-field KAGEMUSHA profile.

```text
descriptor_digest = BLAKE2b(32, person "PIPA-v2-CircDesc", canonical V2 frame)
transcript_repr   = B::from_uniform_bytes(
    BLAKE2b(64, person "Iroha-PlonkVK-v2", descriptor_digest || vk_bytes))
```

`B` is the proof curve's base field for PIPA-R. The key API distinguishes
`TranscriptRepr::Base` from retained `TranscriptRepr::Scalar` profiles; it
never reduces one through the other field. V2 retained scalar profiles use
the V2 domains with their scalar-field representation and typed frame.
These distinct profiles are explicit protocols, not fallback decoders.

## 5. Verifying key bytes (0x02) [V]

```text
0x02 || u32_le(k) || u8 compress (0 or 1) || u32_le(F_c)
     || F_c fixed commitments || m permutation commitments (sigma_j)
     || [compress] n_sel activation bitmaps of ceil(n/8) bytes each
```

The length is `10 + 32(F_c + m) + [compress] n_sel ceil(n/8)`, and bit `i` of bitmap byte `j` is
row `8j + i`. Commitments are `sum_i v_i g_lagrange[i] + W`, since the vendored `Blind::default()`
is one.

**[P]** Decoding against `D` is stricter than the vendored `read_checked`:

- `k`, `compress` and `F_c` must equal `D`;
- points must be canonical, on the curve and not `O`;
- bitmap padding bits must be zero;
- no bytes may follow the last field.

At registration, rerunning selector compression on the bitmaps with `D`'s `max_degree` entries
must reproduce `D.selectors`.

## 6. Transcripts

### 6.1 BLAKE2b Challenge255 [V]

The transcript is one BLAKE2b state with a 64-byte output, personalization `"Halo2-Transcript"`
and no key. Each operation updates it as follows:

- `common_point(pt)` rejects `O`, then absorbs `0x01 || x || y` (affine, canonical).
- `common_scalar(s)` absorbs `0x02 || s`.
- `squeeze` absorbs `0x00`, then returns `F::from_uniform_bytes` of a finalized copy; the state
  continues.
- `write_*` absorbs like `common_*` and appends the encoding.
- `read_*` decodes canonically (section 7), then absorbs.

KATs: `kats_v1.json` `blake2b_transcript`.

### 6.2 KAGEMUSHA Poseidon RP57 [V], injective absorption [P]

The sponge is `iroha_pasta::poseidon::Sponge` over `F`: width 3, rate 2, `x^5`, `R_F = 8`,
`R_P = 57`, MDS 0, starting from `[2^64, 0, 0]`.

- `common_scalar` buffers its input.
- `squeeze` absorbs the buffer in rate-2 chunks into words 1 and 2, and pads a short chunk with a
  single 1. An even buffer length (zero included) adds an extra `[1]` block. The challenge is word
  1; the state carries over.
- `common_point` rejects `O`.
- Proof bytes and `read_*` are as in 6.1.

A point `(x, y)` with canonical integer coordinates is buffered as:

- **Oracle mode:** `[x mod |F|, y mod |F|]`. This is snark-verifier `fe_to_fe`, which is not
  injective on Vesta (`q > p`).
- **Production:** `[x mod |F|, [x >= |F|] + 2 (y mod 2)]`. Since `|B| < 2|F|`, `x` is recoverable,
  and `(x, y mod 2)` fixes the point. The encoding is injective and costs the same two elements.
  The M4 format memo may replace it only with another injective encoding.

KATs: `kats_v1.json` `poseidon_transcript` (oracle mode). TODO (T11): production KATs.

### 6.2b PIPA-R base-field RP57 [P]

The RP57 sponge runs over B, starts at `[2^64, 0, 0]`, and first buffers the
native element `B::from(u64::from_le_bytes(*b"pipa-rb1"))`. Padding and state
continuity are the same as §6.2. Canonical nonidentity points absorb `[x, y]`
directly, and proof scalars have an injective integer encoding:

- Vesta (`F = Fp`, `B = Fq`): one base element, without reduction.
- Pallas (`F = Fq`, `B = Fp`): low 128 bits then high 127 bits, including
  zero limbs. No instance type changes this generic scalar encoding.

For sponge output w, the scalar challenge is w for Pallas, and `w-p` if
`w >= p` else w for Vesta. Both are full-width; no short challenge or byte
reduction is substituted. The Vesta map has only the statistical bias caused
by `q-p`; its boundary cases are pinned in `fq_to_fp_challenge_map_kat`.
Zero/degenerate challenge rejection follows the existing protocol equations.

Native KATs for both curves, profile/type mutations and proof/schedule parity
are in `crates/iroha_plonk/src/pipa_r_tests.rs`. The constrained duplex state
and metadata frame in `iroha_plonk_recursion::transcript` match both fields.
Full circuit scalar decoding, challenge conversion and total succinct
verification remain separate M4 work; transcript parity alone does not
establish those properties.

### 6.3 Prelude and instance modes

The prelude has three steps:

1. `common_scalar(transcript_repr)`, using the vendored value in oracle mode.
2. **[P]** The instance frame: `common_scalar` of `F::from(u64::from_le_bytes(*b"pipainst"))`,
   then of the column count, then of each `instance_lengths[c]`.
3. The instances, by mode.

- **Committed:** absorb `common_point(sum_i v_{c,i} g_lagrange[i] + W)` per column, computed by
  the verifier from the zero-padded values. The proof carries the instance evaluations, and the
  columns are opened.
- **Direct:** absorb `common_scalar` of each value, column-major. The verifier computes
  `I_c(omega^r x) = sum_{j < len_c} v_{c,j} l_{j-r}(x)` (indices mod `n`). Nothing is committed or
  opened.

**[P]** Both modes require the column count and every length to equal `D`. The vendored verifier
checks lengths only in Committed mode and absorbs none.

For V2 the frame is key representation, `pipainst`, column count, all column
lengths, then all column type codes, before the instance values. PIPA-R
absorbs the representation and framing integers as native base-field
elements; the actual instance values use §6.2b scalar encoding. Both prover
and verifier reject any value outside its descriptor type. Mixed-type public
statements use homogeneous columns (Ω has lengths 1, 2 and 16), rather than
silently mixing encodings inside a column.

### 6.4 Historical reference framing (unit tests only)

Native unit tests retain four historical reference choices solely to replay
independently captured fixtures:

- The captured `transcript_repr` is the original `Halo2-Verify-Key` BLAKE2b of
  the length-prefixed key `Debug` rendering.
- Point absorption uses `fe_to_fe`.
- The transcript omits the instance frame.
- The prover accepts a fixed synthetic seed to reproduce the original proof.

These hooks are compiled only under `cfg(test)` in `iroha_plonk`. There is no
external oracle cfg, Cargo feature, shipping-root assertion or alternate
production implementation. Public-API compile-fail tests keep fixed-seed
proving and historical verification unavailable to normal library consumers.

The native Sigma/Wide frontend circuits regenerate every witness, descriptor,
key and proof against `fixtures/native_prover/golden_sources_v1.json`: 42
independent cases cover both Pasta curves, both historical transcript
profiles, Sigma k6/k9/k11 and Wide k8/k10 with two seeds, plus both Wide k13
cases. Each case runs at 1, 2, 4 and 7 workers, verifies its proof and rejects
changed proof bytes, truncation, suffix extension and changed public values.
The frozen original 20 Blake2b proof hashes remain unchanged. Captured
transcript and succinct-verifier tests, native mutation cases and the
independent standard-library full verifier remain separate checks.

`native_prover_parity.yml` runs the native arithmetic/proof suites and public-API
checks on ARM and x86 instruction targets, plus independent proof and Poseidon
reference tests. Captured local results are not hosted-CI or device qualification.
The all-edge dependency guard rejects retired prover dependencies, including
new test-only edges; separate Orchard/Zcash package identities remain outside
this retirement.

Assignment-table import (`keygen_from_tables`, `Witness::from_columns`) is public API, not an
oracle hook. It has no soundness effect, because the verifier evaluates only `D` and the key.
Imported key tables obey the frontend's row rule: no copy, enabled selector or nonzero fixed
value at or beyond `u` (`KeyError::UnusableRow`).

## 7. Proof layout and canonical decoding

The proof is a sequence of 32-byte messages in transcript order; `->` marks a squeeze.

| # | Messages | Count |
| --- | --- | --- |
| 1 | advice commitments, column order; `-> theta` | `n_a` points |
| 2 | per lookup `A'`, `S'`; `-> beta, gamma` | `2 n_l` points |
| 3 | permutation products `z_s` | `n_z` points |
| 4 | lookup products `z` | `n_l` points |
| 5 | `R`; `-> y` | 1 point |
| 6 | `H_0..H_{d-2}`; `-> x` | `d - 1` points |
| 7 | Committed only: instance evaluations, query order | `q_i` scalars |
| 8 | advice, then fixed evaluations, query order | `q_a + q_f` scalars |
| 9 | `R(x)`, then each `sigma_j(x)` | `1 + m` scalars |
| 10 | per set: `z_s(x)`, `z_s(omega x)`, and `z_s(omega^{-(b+1)} x)` unless last | `max(3 n_z - 1, 0)` scalars |
| 11 | per lookup: `z(x)`, `z(omega x)`, `A'(x)`, `A'(omega^{-1} x)`, `S'(x)`; `-> x_1, x_2` | `5 n_l` scalars |
| 12 | multiopen `q'`; `-> x_3` | 1 point |
| 13 | `q_t(x_3)` per point set; `-> x_4` | `n_s` scalars |
| 14 | IPA commitment `C_s`; `-> xi, zeta_ipa` | 1 point |
| 15 | per round, `L_j` and `R_j`; `-> u_j` | `2k` points |
| 16 | `c`, `f` | 2 scalars |
| 17 | `FoldedGenerator` only: suffix `G'_0`, not absorbed | 1 point |

The exact length depends only on `D`:

```text
32 * (n_a + 3n_l + n_z + d + 2 + 2k + [suffix])
  + 32 * ([Committed] q_i + q_a + q_f + 1 + m + max(3n_z - 1, 0) + 5n_l + n_s + 2)
```

Decoding:

- **[P]** Any other length, trailing bytes included, is rejected with `ProofLength`.
- A scalar must be `< |F|` (`NonCanonicalScalar`).
- A point needs `x < |B|` with `x^3 + 5` square, and the sign bit selects `y` (`InvalidPoint`).
- `O` is rejected (`IdentityPoint`).
- Every count, including the number of `h` pieces, comes from `D`, never from the proof.

## 8. Verifier checklist

`verify_full` and `accumulate_succinct` share steps 1-8. Each failure is a typed rejection; the
verifier never panics.

1. Validate `D`, derive the params or check their pinned digest, and decode the VK.
2. Compute `transcript_repr`, and check the instance shapes and the exact proof length.
3. Run the prelude, then read and squeeze rows 1-6.
4. **[P]** Reject `x = 0` and `x^n = 1` with `DegenerateChallenge`; the vendored verifier panics
   on `x^n = 1`.
5. Read rows 7-11, or compute the Direct instance evaluations. Compute `l_0`, `l_last` and
   `l_blind`.
6. Fold the constraints in section 2 order, `E = fold(acc * y + c_j)`, by interpreting the
   constraint-term table (S11); then `expected_h = E / (x^n - 1)` and `H = sum_i x^{n i} H_i`.
7. Multiopen (9.1): reject if `x_3` equals a query point.
8. IPA (9.2): reject if any `u_j = 0`.
9. `verify_full` accepts iff the equation below holds, with `G'_0 = <s, g>`. A `FoldedGenerator`
   suffix must also equal `G'_0`. `accumulate_succinct` follows section 11 instead and never
   accepts.

   ```text
   P' + sum_j (u_j^{-1} L_j + u_j R_j) - c*G'_0 - c*b(x_3)*zeta_ipa*U - f*W = O
   ```

## 9. Opening

### 9.1 Multiopen with static grouping [V bytes, P rule]

A query is `(slot, rotation, eval)`. A slot names a polynomial by kind and index, never by
commitment value. Queries come in this order:

1. instances (Committed only);
2. advice;
3. `(z_s, 0)` and `(z_s, 1)` for each set, then `(z_s, -(b+1))` for `s = n_z - 2` down to 0;
4. per lookup: `(z, 0)`, `(A', 0)`, `(S', 0)`, `(A', -1)`, `(z, 1)`;
5. fixed;
6. `(sigma_j, 0)`;
7. `(h, 0)` and `(R, 0)`.

Grouping is static, so `n_s` and every set depend only on `D`:

- point indices follow the first appearance of each rotation;
- slots are ordered by first appearance;
- a slot's point set is its sorted list of point indices;
- sets are numbered by first appearance in slot order, and each lists its points by point index.

The verifier walks the slots in reverse. Each set `t` keeps its own power:
`Q_t += x_1^{e_t} C_slot`, the evaluations combine the same way, and `e_t` increments. With `qv_t`
read from the proof, and `r_t` interpolating the combined evaluations of set `t`:

```text
msm_eval = fold_t(acc * x_2 + (qv_t - r_t(x_3)) / prod_{p in t} (x_3 - p))
P_open   = x_4^{n_s} q'       + sum_t x_4^{n_s-1-t} Q_t
v        = x_4^{n_s} msm_eval + sum_t x_4^{n_s-1-t} qv_t
```

### 9.2 BGH19 IPA [V]

This follows the vendored `poly/ipa/commitment`. The prover folds `g` with `iroha_pasta::fold` and
returns `G'_0`.

```text
P'     = P_open - v g[0] + xi C_s
b(x_3) = prod_{i<k} (1 + u_{k-1-i} x_3^{2^i})
s_i    = prod_j u_j^{bit_{k-1-j}(i)}        (u_0 pairs with the top index bit)
```

## 10. Prover obligations

**BlindingScheduleV1 [V].** The prover consumes one RNG stream on the calling thread. Each draw is
`F::random`: eight `next_u64` words `w_i`, reduced as `sum w_i 2^{64i} mod |F|`. The order is:

1. advice rows `u..n`, column by column, then one blind per advice column;
2. per lookup: `A'` rows `u..n`, `S'` rows `u..n`, the `A'` blind, then the `S'` blind;
3. per permutation set: `z_s` rows `n-b..n`, then its blind;
4. per lookup: `z` rows `n-b..n`, then its blind;
5. the `n` coefficients of `R`, then its blind;
6. the `d - 1` blinds of the `h` pieces;
7. the `q'` blind;
8. the `n` coefficients of the IPA `s` polynomial and its blind, then, for each round, the
   randomness of `L_j` and of `R_j`.

The thread count changes no draw and no output byte.

**ProverRandomness [P].** Randomness is an opaque value with exactly three sources:

- the OS CSPRNG;
- a hedged derivation over fresh entropy, the witness digest and the statement. It protects
  against a weak or repeating OS generator that still returns bytes; a failing one is an error;
- a caller-held secret recovery seed, such as a wallet's. The prover computes
  `context = BLAKE2b(32, "PIPA-v1-Recovery", statement || witness)`, draws 32 bytes `r` from the
  stream the caller's derivation returns for `context`, and proves with
  `ChaCha20(BLAKE2b(32, "PIPA-v1-RecovKey", r || context))`. The binding happens inside the
  prover, so a derivation that ignores the context cannot make two witnesses share blinds.
  Secrecy still needs a secret seed: with a public derivation the blinds are a public function of
  the witness.

Fixed seeds exist only under `cfg(test)` or in oracle mode, and no seed crosses FFI. Two witnesses
proved under one recovery seed get unrelated blinds (named test:
`a_constant_recovery_derivation_still_separates_witnesses`). Proving keys are local caches, not an
interchange format.

## 11. Accumulation

**Encoding.** `AccumulatorV1 = transcript_repr || u8 curve || u8 k || G || u_0..u_{k-1}`, which is
`66 + 32k` bytes. It decodes canonically: `G != O`, every `u_j != 0`, and no trailing bytes.

**Succinct accumulation.** `accumulate_succinct` requires the `FoldedGenerator` suffix. It runs
steps 1-8, decodes `G` from the suffix, and checks step 9 with `G` in place of `<s, g>`; the MSM
size does not depend on `n`. It returns a `#[must_use]` pending accumulator, which is not an
acceptance.

Its `Ok` is satisfiable for false statements. `G` is read after every challenge (the round
challenges, `c` and `f`) and is not absorbed, so a prover can write well-formed messages for any
statement and solve the equation for
`G = c^-1 (P' + sum_j (u_j^-1 L_j + u_j R_j) - c b(x_3) zeta_ipa U - f W)`. `Ok` therefore
carries no evidence until the accumulator is decided. The API is named for accumulation, not
verification, and its documentation says so. `#[must_use]` does not stop
`accumulate_succinct(..).is_ok()`, so it is not an enforcement. Named test:
`a_folded_generator_solved_from_the_equation_is_accumulated_but_never_accepted`. The forgery passes
succinct accumulation and is rejected by `decide`, `batch_decide`, `verify_full`
(`FoldedGeneratorMismatch`) and `batch_verify` (`BatchRejected`).

**Acceptance.** `decide` accepts iff `G = <s(u), g[0..2^k)>`. Only `verify_full`, `batch_verify`,
`decide` and `batch_decide` accept.

**Absorption.** A consumer absorbs `transcript_repr`, `G` and every `u_j` before any challenge
that depends on them. An appended `G` is never trusted until it is decided.

**[P] Deterministic batch weights** replace the vendored `OsRng`. They are derived only after
every item is fixed:

```text
I_i   = BLAKE2b(64, "PIPA-v1-BatchItm", kind || body)
seed  = BLAKE2b(64, "PIPA-v1-BatchWgt", u64_le(N) || I_0 || ... || I_{N-1})
rho_0 = 1
rho_i = F::from_uniform_bytes(BLAKE2b(64, "PIPA-v1-BatchWgt", seed || u64_le(i)))
```

- Kind `0x00` (a full proof) has body `descriptor_digest || transcript_repr || u32_le(columns)`,
  then `u32_le(len) || values` for each column, then `u64_le(len) || proof`.
- Kind `0x01` (an accumulator) has the `AccumulatorV1` bytes as its body.
- `batch_verify` accepts iff the weighted sum of the step-9 left-hand sides is `O`, with one
  merged `g` MSM.
- `batch_decide` accepts iff `sum_i rho_i (G_i - <s(u^i), g>) = O`.
- If any `rho_i = 0`, every item is verified individually.
- A batch uses one curve and may mix values of `k`.

TODO (audit, before the KAGEMUSHA section 3.3 freeze): a PCD security statement covering per-hop
error, the oracle model and unbounded lineage depth (BCMS20 ePrint 2020/499; BCLMS21 ePrint
2020/1618).

## 12. Soundness invariants (mandatory)

- **S1 Static grouping.** Opening queries are grouped by `(column kind, index, rotation)` from the
  descriptor (9.1), never by commitment value. This holds in native and in-circuit verifiers, so
  equal advice commitments stay separate slots.
- **S2 No duplicate queries.** Duplicate `(column, rotation)` queries are rejected at
  constraint-system build, and rotations are injective mod `n` (section 4, rule 5).
- **S3 No overwrite.** A repeated `(slot, point)` is dropped only if its evaluation is
  bit-identical; otherwise it is rejected. Vendored grouping relies on pointer identity, so a port
  that compares values could overwrite.
- **S4 Exact instances.** Instance counts and lengths equal `D` in both modes, are `<= u`, and are
  framed before any instance data (6.3).
- **S5 Pinned params.** The params digest is pinned per `(curve, k)` and covers `g_lagrange`.
  Signatures never authorize verifier inputs (section 3).
- **S6 Cross-field encodings.** Deferred values that cross the cycle use canonical injective
  encodings:
  - foreign scalars are `(lo < 2^128, hi < 2^127)` with `lo + 2^128 hi < modulus`, never
    `s mod |F|`;
  - points are canonical limbs, checked on-curve and non-identity.

  Each such value is bound into a digest absorbed before the folding challenge, and its cells
  count in the recursion gates. The constraint checker must find these unsatisfiable: absorbing
  `pt` while binding `pt' != pt`; passing `s >= p` as `s mod p`; an identity source.
- **S7 Zero-knowledge budget.** For every witness polynomial (advice, `A'`, `S'`, lookup `z`,
  permutation `z_s`), the number of distinct query rotations plus one for `x_3` is `<= b - 1`. The
  masks formula guarantees it; the check catches mis-ports, and new witness types such as LogUp
  must join it.
- **S8 Randomness.** Provers follow BlindingScheduleV1 and ProverRandomness (section 10).
- **S9 Binding and decoding.**
  - Only the decoded `D` is evaluated, and `transcript_repr` is absorbed first.
  - Every input decodes canonically with an exact length.
  - `O` is rejected everywhere, including a verifier-computed instance commitment.
  - The degenerate challenges of section 8 are rejected.
- **S10 Verdict determinism.** Architecture, threads, features, `asm`, budgets and `iroha_config`
  never change a verdict. Limits stop or slow work but never reject a valid proof. Every verifier
  MSM runs `msm_complete`: the instance commitments, the opening and batch equations, `G'_0`,
  `decide` and `batch_decide`. `msm_complete` is a portable Pippenger whose buckets, running sums
  and window combination use only complete projective formulas. It has no batch-affine or
  incomplete-formula path, so prover-chosen bases never meet an exceptional case, and the budget
  only narrows its window. The batch-affine `iroha_pasta::msm::msm_public` stays prover-only until
  it is audited and differentially qualified for consensus.
- **S11 One acceptance predicate.** In-circuit verifiers implement sections 6-9 under these rules
  and report malformed input as unsatisfiable, never as a panic. Every adversarial case runs
  through both the in-circuit and the native verifier. Both walk the same declarative tables,
  derived from `D` alone:
  - `Protocol::constraint_terms()`: the section 2 fold. The native verifier folds by interpreting
    it term by term, and the prover's quotient uses the same order.
  - `Protocol::transcript_schedule()`: every absorb, message and squeeze of sections 6.3 and 7.
    The native prover and verifier are tested against it operation for operation, and a tampered
    proof stops on a prefix of it.

  An in-circuit verifier interprets the same tables instead of re-deriving the walk. TODO(T18): a
  parity test of the native and the loader-based walk over the same proofs and tamper corpora.

## 13. Zero-knowledge argument (summary)

- **Witness polynomials.** Each has at least `b` fresh random rows and reveals at most `b - 1`
  evaluations (S7). Commitments carry random blinds, so the revealed values are uniform given the
  statement (the halo2 argument).
- **The quotient `h`.** It is never opened alone. Its pieces are blinded, and `R` shares the point
  set `{x}`, so `q(x_3)` masks `h(x_3)`.
- **The opening.** The BGH19 `s` polynomial and the `L_j`/`R_j` randomness hide it.
- **Exact cosets.** They leave `h` unchanged.
- **`G'_0`.** It is a public function of the challenges and params, so a simulator can compute it.
- **The transport wrap.** Its public deferred values are functions of a transcript of hiding
  commitments, so they reveal nothing beyond the inner statement. They are deterministic per inner
  proof, so each use needs a fresh inner proof to stay unlinkable.

The transport-wrap argument here concerns hiding PIPA proofs. KAGEMUSHA also exports
accumulators from private non-hiding PIPA-AS folds; their joint distribution with
Omega needs the separate [C12 composition argument](kagemusha_recursion_soundness_v1.md#composition-keys-and-disclosure).
The polynomial blinding budget alone does not establish that argument.

TODO (M4): a formal memo on the wrap's deferred values, LogUp and endoscalar options before
adoption.

## 14. Historical reference and production deviation registry

**[V]** Native reference tests enforce captured byte identity for:

- parameter and key bytes, with native generation at 1, 2, 4 and 7 workers;
- selector compression and permutation key generation;
- both historical transcript profiles and their transcript known-answer tests;
- freshly generated Sigma/Wide proof bytes under an equal seed, including the
  RP57 Poseidon profile with `fe_to_fe` and the `FoldedGenerator` suffix;
- `BlindingScheduleV1`, multiopen and IPA behavior.

The KAGEMUSHA goldens themselves (`sigma_native_k11`, `p256_k16`, `rec_*`) cannot be re-proved
natively: their circuits were deleted with the old `iroha_core_zk` KAGEMUSHA code on 2026-10-05.
Their pinned values stay in `fixtures/native_prover/kats_v1.json`. The native KAGEMUSHA relations
in `iroha_kagemusha_proof` need their own goldens once their artifact set is frozen (G3).

Every verdict difference from the captured original verifier is a stricter
rejection listed below and covered by native mutation tests. Historical
captures retain the original verdicts and challenges; normal native verification
rejects malformed public input and noncanonical or extended proof encodings.
The original augmented wrapper already required exact length, while the raw
succinct reader accepted a valid prefix with trailing bytes and could panic on
malformed statements. The frozen succinct corpus preserves those observations.
These individual reference checks do not establish equality with the distinct
PIPA-AS accumulation transcript or discharge the recursive composition memo.

| ID | Item | Vendored | PIPA-v1 | Modes |
| --- | --- | --- | --- | --- |
| DEV-01 | `transcript_repr` | `Debug` hash of the pinned VK | descriptor binding (4) | production |
| DEV-02 | Instance frame | none | 6.3 | production |
| DEV-03 | Poseidon point absorption | `fe_to_fe` | injective (6.2) | production |
| DEV-04 | Instance lengths | Committed `<= u`; Direct unchecked | exact | both |
| DEV-05 | Proof length | trailing bytes ignored | exact | both |
| DEV-06 | VK decoding | identity allowed; prefix only | section 5 | both |
| DEV-07 | `x = 0`, `x^n = 1` | usually an opening error; panic | typed rejection | both |
| DEV-08 | Params | trusted as given | pinned digest | both |
| DEV-09 | Batch weights | `OsRng` | deterministic (11) | both |
| DEV-10 | Descriptor rules | none | section 4, at build time | both |
| DEV-11 | Hybrid mode, multi-circuit proofs, phases | supported | rejected | both |
| DEV-12 | PIPA-R transcript field | proof scalar field | explicit V2 base-field profile, §6.2b | production |
| DEV-13 | PIPA-R instance types | untyped field values | descriptor-pinned Field/Bounded/Bits bounds, §6.3 | production |

## 15. Conformance tests and open items

The owners are `iroha_pasta`, `iroha_plonk` and the retained independent reference
verifiers. Every check has a named test that asserts its typed rejection.

- **Native reference replay.** Captured independent goldens are re-proved natively at 1, 2, 4 and 7 threads, on the Blake2b
  path and on the KAGEMUSHA path. VK and params bytes match, and native keygen is checked at the
  same thread counts. Verdicts match on the tamper corpora of both paths, apart from registered
  deviations. The deleted `iroha_core_zk` KAGEMUSHA goldens are not re-proved (section 14).
- **Malicious prover.** The harness rewrites one message, recomputes every later message and
  challenge, and expects one specific reason. Its cases:
  - equal advice commitments with different evaluations (S1, S3);
  - a wrong Direct length and an inconsistent `g_lagrange`;
  - identity points, trailing bytes and injected degenerate challenges;
  - `G` substituted after its challenge (a suffix solved from the equation);
  - cancelling invalid accumulators and a swapped history;
  - forged lookup permutations: an input missing from its table with sorted `A'`/`S'`, with
    `S' = A'`, and an honest witness with sorted columns.

  The lookup cases leave exactly the violated constraint (`Step` or `Last`) out of the prover's
  quotient, so the forged `h` is a polynomial. The verifier rejects, and a verifier filtered to
  omit that term accepts, so each rejection is attributable to one constraint term.
- **Verifier mutation gate.** Modelled on `scripts/sumeragi_mutation_gate.py`; a named test must
  kill each mutation.

  | ID | Mutation |
  | --- | --- |
  | MV1 | skip an absorb |
  | MV2 | skip the length check |
  | MV3 | group by value |
  | MV4 | per-accumulator weights |
  | MV5 | drop `l_last` |
  | MV6 | drop `l_blind` |
  | MV7 | take the `h` count from the proof |
  | MV8 | overwrite evaluations |
- **Descriptor.** `configure()` yields an identical `D` on every build and architecture.
  Decode-then-encode is the identity. Changing any field changes both the digest and the
  verifier's behaviour. Production circuit IDs pin their digests.
- **Zero-knowledge.** Two seeds change every witness commitment and evaluation, and S7 runs on
  every relation.
- **Constraint checker.** A naive interpreter over the uncompressed source expressions flags
  unassigned cells, wraparound, and queries at or beyond row `u`. It is differentially tested
  against the compiled evaluator.

Open items:

- The independently derived standard-library Python reference lives in
  `fixtures/native_prover/reference_verifier`, with adversarial tests in
  `pytests/scripts/native_prover_reference_test.py`. It implements complete individual
  proof verification and generator `decide` for the existing pins at k6 through k10,
  both curves, Blake2b and scalar RP57, and the V2 base-field RP57 profile. The frozen
  46-proof matrix is checked by an isolated standard-library command and regenerated
  in memory by a genuine Rust oracle test. Parser/type/identity mutations and false
  succinct claims that preserve the soft IPA equation exercise full rejection.
  Keep this reference and its frozen inputs after M7. Its documented scope excludes
  batch weights, encoded accumulators, k16 and recursive PIPA-AS; it is not a
  production fallback decoder or full-release qualification.
- TODO: production Poseidon and instance-frame KATs, and `PINNED_PARAMS_V1` beyond `k = 16`.
- TODO: Fiat-Shamir soundness memos (target and hash-query bound) before any format option: LogUp,
  128-bit endoscalar challenges or a base-field transcript.
