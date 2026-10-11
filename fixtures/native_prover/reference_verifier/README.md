# Independent full-proof reference

This test implementation derives its parser, integer field arithmetic, point
arithmetic and verifier equations from `specs/plonk_ipa_v1.md` and `norito.md`.
It does not load Rust, a native module, a circuit builder or a cryptographic
Python package. `kats_v1.json` supplies the retained RP57 constants and pinned
parameter digests; it does not supply proof acceptance results.

The public `verify` entry point takes an explicitly selected V1 or V2 descriptor,
processed verifying-key bytes, complete parameter bytes, public instances and
proof bytes. It checks descriptor semantics and identity, exact key and instance
layouts, all gate/permutation/lookup constraints, multiopen reduction and the
complete IPA equation. A folded-generator suffix must independently satisfy
`G = <s(u), g>`. Standalone `decide` admits the same pinned parameter bytes and a
canonical nonidentity encoded claim; caller-created Python parameter or point
objects are not an admission boundary. Neither entry point returns soft success.

Supported profiles are Blake2b/Challenge255, scalar RP57 and V2 base-field
RP57 PIPA-R on both Pasta curves, using the existing parameter pins at k6 through
k10. Direct and committed instances, compressed and uncompressed selectors,
permutation constraints, lookups, and absent/folded-generator suffixes are
covered where the selected profile permits them. V2 Field, Bounded and Bits
instances retain their specified transcript encodings. The separate
`verify_captured_oracle` entry point accepts only an explicit historical oracle
transcript binding; production verification never falls back to that framing.

`reference_v1.json` freezes 46 genuine full proofs and ten complete public
parameter sets. The temporary Rust oracle test
`reference_fixture::reference_verifier_inputs_match_genuine_sources` recomputes
the complete document from genuine key generation, proving and full verification.
It compares native parameter bytes with the original vendored serialization.
The ignored maintenance printer never rewrites the fixture. Review a recapture
independently before changing the frozen document. Retain the document and this
reference after temporary-oracle deletion.

Run from the original checkout:

```sh
python3 -I -B -S fixtures/native_prover/verify_reference_v1.py
python3 -B -m pytest -q pytests/scripts/native_prover_reference_test.py
RUSTFLAGS='--cfg iroha_plonk_oracle' cargo test --release -p iroha_plonk_oracle \
    --test vendored_goldens reference_fixture::reference_verifier_inputs_match_genuine_sources
```

The first command uses only the standard library and enforces an exact
descriptor-bound fixture matrix. The adversarial suite covers altered proof,
key, public input and parameter bytes; missing/duplicate/mislabeled fixture
cases; explicit descriptor versions; canonical Norito spans; malformed points;
typed-instance limits; and Python boolean/float aliases. Constructive false
generator claims preserve the succinct IPA equation yet must fail the complete
generator decision. The suite also compares every retained challenge and G/u
against the independently captured original succinct corpus.

This is individual proof and generator-decision evidence. It does not implement
batch verification weights, encoded `AccumulatorV1` admission, k16 verification,
recursive PIPA-AS, wallet catalog qualification or production fallback decoding.
Its variable-time arithmetic and test resource bounds are not a proving-time,
memory, side-channel or physical-device qualification.
