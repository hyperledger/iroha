# Independent Poseidon test corpus

The BN254 banks use the H.2-selected original Poseidon permutations: width
three with 8 full/57 partial rounds and width six with 8 full/60 partial rounds.
Every constant and MDS field matches pinned circomlibjs v0.1.7; provenance is
in `bn254-provenance.json`. The Iroha fixed-arity sponge mode is specified
separately in `specs/zk_primitive_workloads.json` and tested against independent
integer vectors. The prior BN254 banks are removed.

Fields are canonical 32-byte little-endian hex, one field per line. Each bank
contains all round-major constants followed by row-major MDS entries. BN254
contains 204 + 444 fields. The separate 201-field Pasta Fp RP56 bank and its
Kaigi/SoraFS framing controls remain unchanged. KAGEMUSHA's RP57 transcript
has a separate parameter owner.

`kaigi-framed-rp56.hex` captures upstream `Hash::permute` results for each of
the commitment, nullifier and authorization domains, at every payload length
from 0 through 33. Each row is `domain_hex length_decimal result_hex`.
Payload word `i` is `2^190 + 987654321 + i` in Pasta Fp. The frame contains
the length, payload, a one-field delimiter and a zero pad if needed; it is
absorbed at rate 2 into `[0, 0, domain]`.

| File | Fields/cases | SHA-256 of exact text |
| --- | ---: | --- |
| `bn254-w3-rp57.hex` | 204 | `42aef4c7c7a01489c71b7a737c17d569285144e2eafdf3ea2d4e717620255e5f` |
| `bn254-w6-rp60.hex` | 444 | `23fc9edd2a86db59837055b279d39df6edf36aeef34bb2b425a6bc89155bcbc6` |
| `pasta-fp-w3-rp56.hex` | 201 | `1cb71721fdaf658cdb359e2337b8dbc71e99a50b0f7a709c8d8d7f6d2f76918a` |
| `kaigi-framed-rp56.hex` | 102 | `a4ade8dc7a8134f2728d03c8cbce1995a9e390a84c0d5537784955be135ffc0c` |

Run `python3.12 scripts/check_poseidon_reference.py` to independently rederive
every byte using a single-bit Grain register and Python integer arithmetic.
It imports no native crate, does not read production constants, and has no
write mode. The Rust test-only reader checks exact field widths, bank shapes
and canonical text. Consumer tests additionally decode canonical field
representations, compare all fields, check full SIMD permutation states,
and retain the framing and output-binding regressions.
