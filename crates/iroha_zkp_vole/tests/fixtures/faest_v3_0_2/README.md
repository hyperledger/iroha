# FAEST v3.0.2 reference test vectors

Official component and full-signature test vectors of the FAEST reference
implementation, converted to a line-oriented text format. **The values are
unmodified**: every byte and integer is the one in the upstream header.

These vectors establish conformance of the building blocks in `iroha_zkp_vole`
with the FAEST reference implementation. They say nothing about the Parliament
ballot relations, which are FAEST-derived and have no official vectors.

## Provenance

| | |
|---|---|
| Source | <https://github.com/faest-sign/faest-ref>, directory `tests/` |
| Tag | `v3.0.2` |
| Commit | `4fb6b71143` |
| Tag object | `6ac9156d28e39b499c2908f0f2e3cff9883274cf` |
| Licence | MIT, copied verbatim in `LICENSE.faest-ref` (SHA-256 `5f07c9c790f30a355fef7a7fb100f74207725a8e302505bae3c8e119e99f51e6`) |

SHA-256 of the upstream headers the fixtures were converted from:

| Fixture | Upstream file | Upstream SHA-256 |
|---|---|---|
| `bavc_tvs.txt` | `tests/bavc_tvs.hpp` | `a6f22b1123c34cfcabeec8a55a458072afe087f4e06535467cf016dc096b971e` |
| `crt_vole_commit_tvs.txt` | `tests/crt_vole_commit_tvs.hpp` | `abf2576f0d109fd32580983d16055c93bcf0bfc2f9be546d856f477a8f08d4cc` |
| `faest_tvs.txt` | `tests/faest_tvs.hpp` | `fe87f2cd21e8b72632998081b335b20ace578f0bf12d987dfac8f4557c5b61c9` |
| `field_tvs.txt` | `tests/field_tvs.hpp` | `6002f276b12d852d5efcb685376fa8c797624a0153dac46037c1675ebc0cb9b3` |
| `owf_tvs.txt` | `tests/owf_tvs.hpp` | `46271517a6e5371bcb7f77a00e73279545fd031cdf05cf4a0b10b40bfea8cb34` |
| `prg_tvs.txt` | `tests/prg_tvs.hpp` | `de8c12046f16462fe50d761f26c773a26ffeeec9b605a8b1130f290615f277ae` |
| `universal_hashing_tvs.txt` | `tests/universal_hashing_tvs.hpp` | `b292d000697680caddd5e44b420d26a3bbe11fd51b1416167a43827ba0f1b75b` |
| `vole_tvs.txt` | `tests/vole_tvs.hpp` | `058a9988a92ce7d033b993033a71d8a7cff94dcd500a73bdf0f031917aab78f8` |

The generator sources whose semantics are summarised below were read at the same
tag and are not copied here:

| Upstream file | SHA-256 |
|---|---|
| `tests/generate_bavc_tv.cpp` | `a4b88a500f0e37c6d0fb38aa1563a503f6e1293457fcb8e7dc6864391b002150` |
| `tests/generate_faest_tv.cpp` | `c9f8189eb50387ae1fd3776e00b0e87790fd855d48ff2f9c4c5873818c9c175d` |
| `tests/generate_faest_tv.cpp.in` | `7f5dcd22f51d3087761bbd1afd7ae7aef5743fe9b26159c0abf20e35efd0afd0` |
| `tests/generate_field_tvs.cpp` | `30c6cf776bd55ea6cdb45a258587e85d6124c0637d4a5c97feefc0ed8aa04ae3` |
| `tests/generate_owf_tv.cpp` | `fe400918f9008e802aa4cc3c75f559662559cebe290f8ef61e8b30dc424776e8` |
| `tests/generate_prg_tv.cpp` | `384e6c18ab7306d5798bbceee98d906ed1f77734aa6a86a03fbdf84f3317a954` |
| `tests/generate_universal_hashing_tv.cpp` | `76653caa58ced0f7a46aba2224de97e0de0e03a5b6c4f74a48b9660da4dcaa03` |
| `tests/generate_vole_tv.cpp` | `7412ccd84e2ebd98a68749e5215ab8a9e6dcbe42bfcd766c926b762fe3b2ad9d` |
| `tests/utils.hpp` | `da6c23caf6ddb886ed7e53a0b5be68cecc6eaa591849ddac9b0bd9181318e35f` |
| `tests/instances.hpp` | `d2eb9d19abbb9b25045c42d95c4f039141a026a0e5585d6e67853b32a8553a6a` |

## Conversion

A standalone Python script parsed the headers **as text**; nothing from the
upstream tree was compiled or executed. It checks each header against the
SHA-256 above, then accepts only this grammar and aborts on anything else:

```text
namespace NAME { ... }
constexpr std::array<uint8_t|uint16_t, N> NAME{ 0x.., 0x.., };
constexpr <integer type> NAME = <decimal | identifier> ((+|-) <decimal | identifier>)* ;
```

The declared array length `N` must equal the number of elements. Each header
becomes one `<stem>.txt` with one declaration per line, in upstream order:

```text
<namespaces joined by '.'>.<name> = <lowercase hex>        uint8_t array
<namespaces joined by '.'>.<name> = [<dec>,<dec>,...]      uint16_t array
<namespaces joined by '.'>.<name> = <decimal>              integer constant
```

Lines starting with `#` are comments. The only `uint16_t` arrays are
`bavc_tvs.*.i_delta`. The only computed integers are
`universal_hashing_tvs.vole_hash_*_7_tv.ell_prime`, which upstream writes as
`ell + d_zk - 1` and the converter evaluates to `11`.

`tests/common/mod.rs` loads a fixture (`Fixture::load("prg_tvs")`) and returns
`bytes(name)`, `integer(name)` or `u16_list(name)`, panicking on a missing name.

Sizes: all eight fixtures total 311,274 bytes. `faest_tvs.txt` is 260,051 bytes
(upstream header: 847,251 bytes) and keeps all twelve parameter sets.

## What each vector is

Notation: `lb = lambda / 8`. `<SET>` ranges over the twelve parameter sets in the
upstream order `FAEST_128S, FAEST_128F, FAEST_192S, FAEST_192F, FAEST_256S,
FAEST_256F, FAEST_EM_128S, FAEST_EM_128F, FAEST_EM_192S, FAEST_EM_192F,
FAEST_EM_256S, FAEST_EM_256F` unless stated otherwise. Function names are those of
the reference implementation.

Inputs marked *random* came from a fixed-seed `std::mt19937_64`; they are plain
test inputs and need not be reproduced.

`hash_array(x)` is a 64-byte digest of `x` that the generators use to keep large
intermediate values short: SHAKE256 of `x` squeezed to 64 bytes, with no domain
separation (upstream `tests/test_utils.cpp`, SHA-256
`1c4db626ee046cd21bcf634f9a0500905d322512344b08e20942079dd5c933cc`). `tests/common/mod.rs` provides it as
`hash_array`. Every `hashed_*` entry is such a digest.

Further known answers that upstream keeps inline in its test sources
(`tests/fields.cpp`, `tests/universal_hashing.cpp`, `tests/hash_shake.cpp`) are in
`../faest_v3_0_2_extracted/upstream_test_kats.txt`, whose header gives their
provenance and meaning; `Fixture::load_extracted()` loads them.

### `prg_tvs.txt` (from `generate_prg_tv.cpp`)

`<L>` is `128`, `192` or `256`.

| Name | Meaning |
|---|---|
| `prg_tvs.key_<L>` | input: PRG key, `L/8` random bytes |
| `prg_tvs.iv_<L>` | input: 16 random bytes |
| `prg_tvs.tweak_<L>` | input: 32-bit tweak |
| `prg_tvs.expected_<L>` | expected: `prg(key, iv, tweak, L, 232)`, the first `14 * 16 + 8 = 232` output bytes |

### `owf_tvs.txt` (from `generate_owf_tv.cpp`)

Only the six `F` sets appear (`FAEST_128F` … `FAEST_EM_256F`); upstream skips the
`S` sets.

Consumed by `tests/conformance_owf.rs` (every entry; each vector is checked on
the `f` and the `s` set of its family and level).

| Name | Meaning |
|---|---|
| `owf_tvs.<SET>.key` | input: `lb` random bytes |
| `owf_tvs.<SET>.input` | input: `owf_input_size` random bytes (16 for the AES sets; `lb` for the EM sets) |
| `owf_tvs.<SET>.output` | expected: `owf_<L>(key, input)` for AES sets, `owf_em_<L>(key, input)` for EM sets; `owf_output_size` bytes (16, 32, 32 for AES-128/192/256; `lb` for EM) |

### `universal_hashing_tvs.txt` (from `generate_universal_hashing_tv.cpp`)

| Name | Meaning |
|---|---|
| `universal_hashing_tvs.leaf_hash_<L>.uhash` | input: `3 * lb` random bytes |
| `universal_hashing_tvs.leaf_hash_<L>.x` | input: `4 * lb` random bytes |
| `universal_hashing_tvs.leaf_hash_<L>.expected_h` | expected: `leaf_hash_<L>(uhash, x)`, `3 * lb` bytes |
| `universal_hashing_tvs.vole_hash_<L>_7_tv.ell` | constant `5` |
| `universal_hashing_tvs.vole_hash_<L>_7_tv.d_zk` | constant `7` |
| `universal_hashing_tvs.vole_hash_<L>_7_tv.ell_prime` | `ell + d_zk - 1 = 11` |
| `universal_hashing_tvs.vole_hash_<L>_7_tv.sd` | input: seed, `8 * lb + 8` random bytes |
| `universal_hashing_tvs.vole_hash_<L>_7_tv.x` | input: `(ell_prime + 4) * lb` random bytes |
| `universal_hashing_tvs.vole_hash_<L>_7_tv.digest` | expected: `vole_hash(sd, x, ell, L)`, `4 * lb` bytes. The generator passes `ell` (5), not `ell_prime`, as the length argument |

### `field_tvs.txt` (from `generate_field_tvs.cpp`)

| Name | Meaning |
|---|---|
| `field_tvs.<SET>.lhs` | input: binary polynomial of `w_grind` random bits in `ceil(w_grind / 8)` bytes, bits at and above `w_grind` cleared |
| `field_tvs.<SET>.res` | expected: `bf2_poly_mul(lhs, w_grind, params.M_TREE, lambda - w_grind + 1)`, `lb` bytes |
| `field_tvs.<SET>.deg` | `bavc_max_node_depth(0, tau1, k)` |
| `field_tvs.<SET>.unreduced` | input: binary polynomial of `2 * deg` random bits in `ceil(2 * deg / 8)` bytes, higher bits cleared |
| `field_tvs.<SET>.reduced` | expected: `bf2_poly_reduce(unreduced, 2 * deg, params.TREE_MODULI[0], deg + 1)`, same length as `unreduced` |

### `bavc_tvs.txt` (from `generate_bavc_tv.cpp`)

Fixed inputs that are **not** in the fixture: `iv` is 16 zero bytes and the root
key buffer is the 32 bytes `00 01 02 … 1f`, passed to `bavc_commit(root_key, iv,
params)`. `com_size` is `3 * lb` for AES sets and `2 * lb` for EM sets.

| Name | Meaning |
|---|---|
| `bavc_tvs.<SET>.h` | expected: commitment `h` after `bavc_commit`, `2 * lb` bytes |
| `bavc_tvs.<SET>.hashed_k` | expected: `hash_array` of all GGM node keys `k`, `(2 * L - 1) * lb` bytes |
| `bavc_tvs.<SET>.hashed_sd` | expected: `hash_array` of all leaf seeds `sd`, `L * lb` bytes |
| `bavc_tvs.<SET>.i_delta` | input: `tau` hidden indices, one per repetition, each below `bavc_max_node_index(i, tau1, k)`; resampled until `bavc_open` succeeded |
| `bavc_tvs.<SET>.hashed_decom_i` | expected: `hash_array` of the opening from `bavc_open(i_delta)`, a zero-initialised buffer of `com_size * tau + T_open * lb` bytes |
| `bavc_tvs.<SET>.hashed_rec_sd` | expected: `hash_array` of the `(L - tau) * lb` seed bytes from `bavc_reconstruct(decom_i, i_delta, iv)` |
| `bavc_tvs.<SET>.leaf_commit_key` | input: `lb` random bytes |
| `bavc_tvs.<SET>.leaf_commit_iv` | input: 16 random bytes |
| `bavc_tvs.<SET>.leaf_commit_uhash` | input, AES sets only: `3 * lb` random bytes (absent for EM sets) |
| `bavc_tvs.<SET>.tweak` | input: 32-bit tweak |
| `bavc_tvs.<SET>.leaf_commit_expected_sd` | expected: seed from `leaf_commit(key, iv, tweak, uhash)`, `lb` bytes |
| `bavc_tvs.<SET>.leaf_commit_expected_com` | expected: commitment from the same call, `com_size` bytes |

### `vole_tvs.txt` (from `generate_vole_tv.cpp`)

Fixed inputs not in the fixture: `iv` is 16 zero bytes and the root key buffer is
`00 01 02 … 1f`. With `d0 = bavc_max_node_depth(0, tau1, k)` the commitment length
is `ell_hat = ell + N_MASK * d0`. The generator calls `vole_commit(root_key, iv,
ell_hat, params)`, then draws `chall` until `decode_all_chall_3` and `bavc_open`
succeed, then calls `vole_reconstruct`.

`V` and `Q` are hashed after repacking: only the first `ell` columns are kept, and
bit `col * lambda + r` of the packed buffer is bit `col` of row `r`
(`0 <= r < lambda`), giving `ell * lb` bytes.

| Name | Meaning |
|---|---|
| `vole_tvs.<SET>.h` | expected: BAVC commitment `h`, `2 * lb` bytes |
| `vole_tvs.<SET>.hashed_c` | expected: `hash_array` of corrections `c`, `(tau - 1) * ceil(ell / 8)` bytes |
| `vole_tvs.<SET>.hashed_u` | expected: `hash_array` of `u`, `ceil(ell / 8)` bytes |
| `vole_tvs.<SET>.hashed_c_mult` | expected: `hash_array` of `c_mult`, `N_MASK * ceil(n_mult / 8)` bytes |
| `vole_tvs.<SET>.hashed_v` | expected: `hash_array` of repacked `V` |
| `vole_tvs.<SET>.hashed_barU` | expected: `hash_array` of the mask values, `N_MASK * lb` bytes |
| `vole_tvs.<SET>.hashed_barV` | expected: `hash_array` of the mask tags, `N_MASK * lb` bytes |
| `vole_tvs.<SET>.hashed_q` | expected: `hash_array` of repacked `Q` from `vole_reconstruct(chall, decom_i, c, c_mult)` |
| `vole_tvs.<SET>.hashed_barQ` | expected: `hash_array` of the verifier mask keys, `N_MASK * lb` bytes |
| `vole_tvs.<SET>.chall` | input: the accepted challenge, `lb` random bytes |

### `crt_vole_commit_tvs.txt`

**No generator for this header is in the upstream `tests/` directory, so the
semantics below are inferred from the names only.** Namespaces are
`crt_tvs_128s`, `crt_tvs_128f`, `crt_tvs_192s`, `crt_tvs_192f`, `crt_tvs_256s`,
`crt_tvs_256f`, `crt_tvs_em_192s` and `crt_tvs_em_192f` (eight sets, not twelve).

| Name | Meaning |
|---|---|
| `crt_tvs_<set>.delta_bytes` | input: the concatenated small-VOLE challenge `Delta` (`lb` or `lb - 1` bytes) |
| `crt_tvs_<set>.expected_crt_delta_bytes` | expected: its CRT encoding as an element of the `lambda`-bit field, `lb` bytes |

### `faest_tvs.txt` (from `generate_faest_tv.cpp` and `generate_faest_tv.cpp.in`)

Namespaces are lower-case here, in header order: `faest_128s`, `faest_128f`,
`faest_192s`, `faest_192f`, `faest_256s`, `faest_256f`, then the same six with the
`faest_em_` prefix.

Consumed by `tests/conformance_faest.rs` (every entry: public key, extended
witness, exact signature bytes and verification for all twelve sets) and by
`tests/conformance_signature_fields.rs` (every entry: the signature fields that
do not depend on the one-way-function relation).

| Name | Meaning |
|---|---|
| `faest_tvs.random_seed` | input: signing randomness, the 16 bytes `00 01 … 0f` |
| `faest_tvs.message` | input: 76 ASCII bytes, "This document describes and specifies the FAEST digital signature algorithm." |
| `faest_tvs.<set>.sk` | input: secret key from `faest_<set>_keygen` (system randomness, so only reproducible from this value) |
| `faest_tvs.<set>.pk` | expected: public key of `sk`; also the verification input |
| `faest_tvs.<set>.witness` | expected: extended witness from `faest_<set>_unpack_private_key(sk)` |
| `faest_tvs.<set>.signature` | expected: `faest_<set>_sign_with_randomness(sk, message, random_seed)`; `verify(pk, message, signature)` must accept |

Signature lengths are 4066, 5170, 9410, 11738, 16626, 20856 bytes for
128s/128f/192s/192f/256s/256f and 3466, 4170, 7874, 9818, 14554, 18084 bytes for
the EM sets.
