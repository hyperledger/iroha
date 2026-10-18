# Native prover known-answer vectors

`kats_v1.json` retains the behaviour of its recorded vendored halo2 source.
Unchanged arithmetic, parameter and RP57-constant components remain parity
anchors. The current total challenge roles, norm-product equations and
committed-mask construction require new source-bound full-proof captures;
historical proof bytes are not authority for the changed protocol. Retained
fixtures do not enable a shipping seeded prover or compatibility decoder.
These vectors stay after `vendor/halo2-axiom`,
`vendor/halo2curves-axiom`, `vendor/halo2-base`, `halo2-ecc` and
`snark-verifier` are deleted. The migration plan and consumer list are in
`specs/native_prover_migration_inventory.md`.

Field elements are canonical little-endian `to_repr` hex. Points are compressed
`to_bytes` hex.

| Section | Contents |
| --- | --- |
| `oracle_baseline` | Commits, crate versions and toolchain the vectors were recorded from. |
| `golden_proofs` | Proof SHA-256 tables of `vendor/halo2-axiom/tests/golden_proof_bytes.rs` (Blake2b, regenerated) and of the eight KAGEMUSHA Poseidon-transcript goldens (`iroha_core_zk_kagemusha`). This file is the historical authority for that source's KAGEMUSHA table: it was recorded from `crates/iroha_core_zk/src/prover_golden_tests.rs` at `oracle_baseline.repository_head`, and the generator carries it over unchanged, checking only its case names and digest format. |
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

## Capture and check

The retained `kats_v1.json` baseline was emitted by the retired oracle's
`native_prover_kats.rs` test. That source and its original revision describe
provenance, not a current workspace command or a shipping proof engine. Keep
unchanged arithmetic/parameter/Poseidon KATs separate from proof corpora whose
protocol has changed.

The maintained native capture owner is
`captured_goldens::export::export_current_native_corpora` in `iroha_plonk`'s
unit-test build. After the source and shared build hold is released, the
bootstrap capture uses the existing worktree lane:

```sh
IROHA_NATIVE_PROVER_CAPTURE_DIR=/absolute/new/private/capture-directory \
  scripts/cargo_fast.sh --target-slot kagemusha-cohort --stable-local-metadata -- \
  test --locked --release -p iroha_plonk --lib \
  captured_goldens::export::export_current_native_corpora -- \
  --exact --ignored --nocapture --test-threads=1
```

Choose a new absolute directory outside the checkout, beneath an existing
owner-only parent. The producer
writes `golden_sources_v1.json`, `succinct_v1.json`, `capture-start.json` and
`capture-result.json`; it does not install canonical fixtures. The golden
matrix retains all 42 Sigma/Wide cases and the succinct matrix all eight cases.
Ordinary native framing, full proof and generator decisions, exact replay,
1/2/4/7-worker checks and adversarial assertions remain required. Native-generated
bytes are regression evidence, not an independent implementation oracle.
The producer, receipts, output hashes and exact source must be reviewed together
before installation. Admission also requires the actual successful test exit,
unchanged original output pins and the terminal marker
`NATIVE_CORPUS_CAPTURE_COMPLETE golden_cases=42 succinct_cases=8`. The complete
compiled source census includes bootstrap seed fixtures and catalog DATA; those
inputs do not qualify a final source/catalog candidate. Review captures before
installation, then freeze and rebuild that final candidate. This command is a
capture recipe, not a completed run.

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

The selected `succinct_v1.json` consumer requires eight current native cases:
Sigma at k6 and Wide at k8, both Pasta curves, with test seeds 42 and 43. Each
retains the complete proof, descriptor, processed key, public inputs, raw squeeze
schedule, generator point and mapped round challenges. Fixed streams are confined
to the native unit-test capture; they are not a production randomness API.
The current format is `iroha.native_prover.succinct.v1`. Its challenge tape records
scalars after transcript field conversion and before role maps; each IPA round
uses `u = nz(raw)`. It does not record raw base-field Theta values. The recorded
transcript representation must equal the descriptor-bound value and never
authorizes an override.

The prior snark-verifier corpus belongs to its recorded source and equations.
Replacing it requires actual generation and replay of the complete current matrix,
full generator decisions and the existing wrong-instance, changed-point,
changed-suffix, extension and truncation controls. A well-formed false generator
claim must still fail its independent decision. No cheap verification result alone
is acceptance. Preserve predecessor originals and provenance outside the selected
fixture; never promote them by changing a format label or source hash.

`pytests/scripts/native_prover_reference_test.py` also reads `succinct_v1.json`.
Installing the native corpus therefore requires the independent Python reader and
its equations to match that corpus, with all prior mutation assertions retained.
The new native capture alone cannot establish that Python suite passes.

## Independent full-proof verification

`reference_v1.json` currently retains the ancestor's 46 full proofs and ten
parameter sets at k6 through k10. The selected standard-library verifier implements
the current total challenge roles, norm-product constraints and scoped-generator
rule, with one descriptor-bound verification API and no transcript override.
Current-source full-proof validation still requires an actual native 46-case
capture. The separate maintained owner is
`native_reference_capture::export_current_reference_corpus`; the 42/8 exporter
does not produce this document.

The [reference README](reference_verifier/README.md) gives the exact matrix,
current capture command, external-file check and artifact requirements. The fast
role/equation/codec controls can run before genuine proof recapture:

```sh
python3 -I -B -S pytests/scripts/test_native_reference_roles.py
```

After matching current reference and succinct fixtures are independently checked
and installed together, run:

```sh
python3 -I -B -S fixtures/native_prover/verify_reference_v1.py
python3 -B -m pytest -q pytests/scripts/native_prover_reference_test.py
```

The pytest suite consumes both the 46-case reference and the eight-case succinct
corpus. The succinct records must agree with the independent reader’s scalar
squeeze tapes and mapped rounds. No recapture, native/Python parity, batch,
recursive, full-catalog or physical-phone acceptance is established by these
source changes alone.
