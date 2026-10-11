# Native prover known-answer vectors

`kats_v1.json` pins the behaviour of the vendored halo2 stack that the
Iroha-native crates (`iroha_pasta`, `iroha_plonk`, `iroha_plonk_gadgets`) must
reproduce. These vectors stay after `vendor/halo2-axiom`,
`vendor/halo2curves-axiom`, `vendor/halo2-base`, `halo2-ecc` and
`snark-verifier` are deleted. The migration plan and consumer list are in
`specs/native_prover_migration_inventory.md`.

Field elements are canonical little-endian `to_repr` hex. Points are compressed
`to_bytes` hex.

| Section | Contents |
| --- | --- |
| `oracle_baseline` | Commits, crate versions and toolchain the vectors were recorded from. |
| `golden_proofs` | Proof SHA-256 tables of `vendor/halo2-axiom/tests/golden_proof_bytes.rs` (Blake2b, regenerated) and of the eight KAGEMUSHA Poseidon-transcript goldens (`iroha_core_zk_kagemusha`). This file is the pinned authority for the KAGEMUSHA table: it was recorded from `crates/iroha_core_zk/src/prover_golden_tests.rs` at `oracle_baseline.repository_head`, and the generator carries it over unchanged, checking only its case names and digest format. |
| `params_ipa` | `ParamsIPA::new(k).write` length and SHA-256 for k = 6..=16 on Eq and Ep, plus digests of the `g` and `g_lagrange` sections. |
| `generators` | The first 64 `Halo2-Parameters` hash-to-curve generators, and `w` and `u`, per curve. |
| `blake2b_transcript` | `Blake2bWrite` with `Challenge255`: per-operation challenges, absorbed bytes, written stream, decoding rejections. |
| `poseidon_transcript` | snark-verifier `PoseidonTranscript<C, NativeLoader, _, 3, 2, 8, 57>::new::<0>` (the KAGEMUSHA transcript): challenges, absorbed elements, stream, rejections. |
| `poseidon_constants` | Unoptimized round constants and MDS matrix of the width-3, rate-2, 8 + 57 round Poseidon for Fp and Fq. |
| `kagemusha_v1_poseidon` | Vectors of the KAGEMUSHA domain hash `hash([domain, len, inputs...])` on the vendored sponge, and the empty depth-256 replay root. The shared sponge is anchored through the confidential section; `production_anchors` names the native consumers that assert every vector. |
| `confidential_v3_poseidon` | Vectors of the oracle reproduction of `confidential_poseidon_hash_v3` for every V3 domain, and the empty subtree roots up to depth 16. `production_anchors` names the three production KATs the reproduction is checked against. |

Consumers: `crates/iroha_plonk_oracle/tests/pasta_parity/` checks
`iroha_pasta` against the `params_ipa` digests, the `poseidon_constants`
tables, the `poseidon_transcript` challenges and the `kagemusha_v1_poseidon`
and `confidential_v3_poseidon` vectors, besides comparing it with the vendored
crates directly. `iroha_plonk` replays both transcript sections
(`src/transcript/kat_tests.rs`) and checks its pinned params against the
`params_ipa` digests (`tests/pinned_params.rs`). The `iroha_plonk_gadgets`
sponge chip and `iroha_kagemusha_proof` assert the `kagemusha_v1_poseidon`
vectors (`tests/digest_parity.rs` in each).

`confidential_poseidon_v1.json` retains the complete pre-retirement Core_zk
Poseidon parity corpus: 218 outputs across both Pasta fields, seven production
domains, and input lengths 0 through 33 under three boundary domains. Inputs
include zero, one, minus one and the position index. The source and capture
hashes identify the original vendored-oracle run; the Python checker independently
re-derives every output from the pinned RP57 constants. The native Core_zk test
`native_confidential_poseidon_matches_captured_oracle_on_both_pasta_fields`
checks the same corpus without importing the retired prover. The corpus and
its mutation tests remain after oracle deletion.

## Regenerate and check

The generator is `crates/iroha_plonk_oracle/tests/native_prover_kats.rs`. By
default it rebuilds every vector from the vendored stack and requires the file
to match. A changed vector means the vendored behaviour changed. Review that
change before you regenerate. The pinned KAGEMUSHA golden table is the one
exception: the generator reads it from this file and writes it back
unchanged, so rewriting needs the existing file.

```sh
cargo test -p iroha_plonk_oracle --test native_prover_kats
cargo test --release -p iroha_plonk_oracle --test native_prover_kats -- --include-ignored  # adds k = 15 and 16
IROHA_UPDATE_NATIVE_PROVER_KATS=1 cargo test --release -p iroha_plonk_oracle --test native_prover_kats native_prover_kats_match_fixture
```

`verify_kats_v1.py` is an independent check that uses only the Python standard
library. It re-derives every Blake2b challenge, every Poseidon hash and
transcript challenge (from the pinned constants), the absorbed encodings,
`ParamsIPA` lengths and point validity, and checks that every recorded
transcript rejection is a distinct malformed input (a scalar at least the
modulus; a point that is the identity, non-canonical or off the curve). It does
not re-derive hash-to-curve. It also checks all 218 captured confidential boundary
outputs and their exact domain/input matrix.

```sh
python3 fixtures/native_prover/verify_kats_v1.py
```

## Succinct verifier and BGH19 obligations

`succinct_v1.json` freezes eight independently captured snark-verifier results:
Sigma at k6 and Wide at k8, on both Pasta curves, with prover seeds 42 and 43.
Each record retains the complete original proof, native descriptor and processed
key, public inputs, historical transcript scalar, every squeezed challenge, and
the returned generator point and round challenges. The corpus names its original
snark-verifier revision and source hashes. It covers these generic golden
circuits, not the deleted private KAGEMUSHA operation circuits or a current
source-qualified operation catalog.

The oracle compares every challenge with the original Halo2 full verifier and
compares the returned generator obligation with native succinct verification.
Both generator decisions must pass. Five mutations per record retain the exact
original outcome: wrong instance, changed proof point, changed suffix, trailing
byte and truncation. The original native loader panics on a false group equation;
its reader accepts a valid prefix followed by trailing bytes (DEV-05). These
outcomes are recorded rather than hidden by a wrapper. The native verifier must
reject all five normally. A cheap verification result alone is never acceptance.
The separate PIPA-AS-v1 accumulation transcript is intentionally different and is
not a byte-parity claim of this corpus.

```sh
RUSTFLAGS='--cfg iroha_plonk_oracle' cargo test --release -p iroha_plonk_oracle --test vendored_goldens succinct_parity::
cargo test --release -p iroha_plonk captured_succinct_tests::
```

The second command links no retired prover. It replays all eight exact retained
proofs through native verification, checks the complete case matrix and retained
hashes, compares each generator and round vector, and then decides the claim.
A separately mutated well-formed accumulator must fail its decision. These tests
and the frozen originals remain after temporary-oracle retirement. Fixture changes
require an independently reviewed recapture; ordinary tests never rewrite it.

## Independent full-proof verification

`reference_v1.json` retains 46 genuine full proofs, both Pasta curves, all three
transcript profiles and ten pinned parameter sets at k6 through k10. The
standard-library-only implementation in `reference_verifier/` checks the complete
PLONK, multiopen and IPA equations, including the generator decision. Its
production entry point has no historical oracle fallback. The separate explicit
oracle entry point checks retained original proofs.

```sh
python3 -I -B -S fixtures/native_prover/verify_reference_v1.py
python3 -B -m pytest -q pytests/scripts/native_prover_reference_test.py
```

The exact matrix, genuine recapture command, adversarial coverage and limits are
documented in [the reference README](reference_verifier/README.md). This evidence
does not establish batch, recursive, full-catalog or physical-phone acceptance.
