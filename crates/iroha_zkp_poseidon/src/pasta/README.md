# Pinned Pasta native candidate

This internal source record covers original Poseidon P128Pow5T3 over Pasta Fp
and Fq: width 3, rate 2, exponent 5, eight full and 56 partial rounds. It has no
production protocol callers. Existing admitted 57-round constructions are
unchanged. The one-field generic collision margin is approximately 127 bits;
the upstream parameter name is not a qualification of a complete protocol.

Parameters and public test vectors come from Zcash Halo2 commit
`68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b`, under its Apache-2.0 license option:

- [P128Pow5T3](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/p128pow5t3.rs).
- [Fp parameters](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/fp.rs).
- [Fq parameters](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/fq.rs).
- [Public vectors](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/test_vectors.rs).
- [Sponge contract](https://github.com/zcash/halo2/blob/68bdb6e2fe549112971fd8a1a8d1f4b9c880ee7b/halo2_poseidon/src/lib.rs).

`fp.bin` and `fq.bin` each contain 192 round constants in round-major order,
then nine MDS coefficients in row-major order. Each element is a canonical
32-byte little-endian integer. They contain no header, private material or
application serialization. They are fixed compile-time constant tables, not
an alternate network codec. Native and future circuit adapters must consume
these same bytes rather than regenerate independently chosen parameters.

Each `*_permute_kats.bin` contains all 11 upstream permutation vectors, with
three initial fields followed by three final fields (192 bytes per record).
Each `*_hash_kats.bin` contains all 11 upstream `ConstantLength<2>` vectors,
with two input fields followed by one output (96 bytes per record). All fields
use the exact canonical bytes from upstream. Tests pin these SHA-256 values:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `fp.bin` | 6,432 | `a9a13cf048dcb1fdc90989307b50514fc8454fc53853f704d4a5b395b9b98812` |
| `fq.bin` | 6,432 | `d9109b12201af2f77bbc633144d986007fcf290ada7bf51cbb1ba79172108a16` |
| `fp_permute_kats.bin` | 2,112 | `160528fb278c1962889d5a05e705f0ecaaf34c8452297dd44794a7dc412419e6` |
| `fq_permute_kats.bin` | 2,112 | `ed40801dcf95d2b0ad2fa21a6cf2e9e60f7add5f40146082eae2be40ccbb4245` |
| `fp_hash_kats.bin` | 1,056 | `d2a6b9e89ae5f3a4d081cc8c7d7832cfffd2697a817c3f737dd50aa5f409c1fe` |
| `fq_hash_kats.bin` | 1,056 | `29338f2785060486e3619345c7b9b08b58b4c932a4d0f0c0bf971e816c48202e` |

For positive fixed length L, initialize `[0, 0, L * 2^64]`, absorb into the
first two coordinates, pad an odd final block with zero, and return the first
coordinate. Even inputs do not gain another block. Empty inputs return a typed
error; the upstream implementation cannot finalize an unfilled empty block.
Applications still need their own reviewed domain/role/length composition.

The byte API rejects values at or above the corresponding modulus without
reduction. On permutation input error, the caller's state is unchanged. Native
scratch clears through `zeroize`'s volatile default write on every exit. This
covers owned state and matrix buffers, not borrowed inputs, returned outputs,
arithmetic temporaries or compiler copies. Tests observe actual owned cells
after clearing on normal, partial-decode-error and unwinding paths.

Tests additionally compute the public vectors and odd/even/max-record hashes
using `iroha_pasta`, the field implementation used by Core's native proof
engine. The test-only edge does not introduce a production prover dependency.
This native parity does not qualify a circuit or protocol relation.
