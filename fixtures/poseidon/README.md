# RP56 independent test corpus

These test fixtures preserve the complete parameter and framing comparisons
previously supplied by the `poseidon-primitives` 0.2.0 dev dependency. They do
not change any production parameter, transcript or proof format. KAGEMUSHA's
RP57 transcript uses its own parameter set.

The capture uses the upstream `Spec::constants` generator with prime fields,
the fifth-power S-box, 8 full rounds, 56 partial rounds and `secure_mds = 0`.
Fields are exact 32-byte canonical little-endian values, one lowercase hex
line per field. Each bank contains 64 round-major rows followed by row-major
MDS entries. The banks cover all 621 BN254 fields (widths 3 and 6) and all
201 Pasta Fp fields (width 3) used by Kaigi and SoraFS PoP.

`kaigi-framed-rp56.hex` captures upstream `Hash::permute` results for each of
the commitment, nullifier and authorization domains, at every payload length
from 0 through 33. Each row is `domain_hex length_decimal result_hex`.
Payload word `i` is `2^190 + 987654321 + i` in Pasta Fp. The frame contains
the length, payload, a one-field delimiter and a zero pad if needed; it is
absorbed at rate 2 into `[0, 0, domain]`.

| File | Fields/cases | SHA-256 of exact text |
| --- | ---: | --- |
| `bn254-w3-rp56.hex` | 201 | `e810aae64667b8f1f705211bc247f659f6f040958dbdfcbe84a45064fcae9eac` |
| `bn254-w6-rp56.hex` | 420 | `8a62ec6ea258b5caeaa19a0a95070a8d392c9ce26b3b3e04ee78625df1dfe72b` |
| `pasta-fp-w3-rp56.hex` | 201 | `1cb71721fdaf658cdb359e2337b8dbc71e99a50b0f7a709c8d8d7f6d2f76918a` |
| `kaigi-framed-rp56.hex` | 102 | `a4ade8dc7a8134f2728d03c8cbce1995a9e390a84c0d5537784955be135ffc0c` |

Run `python3 scripts/check_poseidon_reference.py` to independently rederive
every byte using a single-bit Grain register and Python integer arithmetic.
It imports no native crate, does not read production constants, and has no
write mode. The Rust test-only reader checks exact field widths, bank shapes
and canonical text. Consumer tests additionally decode canonical field
representations, compare all fields, check full SIMD permutation states,
and retain the framing and output-binding regressions.
