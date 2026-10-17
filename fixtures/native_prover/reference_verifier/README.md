# Independent full-proof reference

This test implementation derives its parser, integer field arithmetic, point
arithmetic and verifier equations from `specs/plonk_ipa_v1.md` and `norito.md`.
It does not load Rust, a native module, a circuit builder or a cryptographic
Python package. `kats_v1.json` supplies retained RP57 constants and pinned
parameter digests, not proof acceptance results.

The retained `reference_v1.json` contains 46 ancestor proofs. Current-source
qualification requires a new native-generated corpus plus matching independent
norm-product, total-role and scoped-generator equations. The selected Python
implementation now implements those equations without an override API, but
source-only changes or unchanged parameter pins do not establish full-proof
parity. Preserve the original capture and its provenance separately; do not
relabel historical proof bytes.

The selected public `verify` contract takes an explicit V1 or V2 descriptor,
processed key bytes, complete parameter bytes, public instances and proof bytes.
It checks descriptor identity, exact key and instance layouts, all constraints,
multiopen reduction and the complete IPA equation. A folded suffix independently
satisfies `G = <s(u), g>`. Only deferred generator `G` carriers admit canonical
identity; ordinary proof points remain finite and nonidentity. Standalone `decide`
uses the same pinned parameters and scoped generator rule. Caller-created Python
parameter/point objects or a historical transcript override are not admission
boundaries; neither entry point returns soft success. Returned challenge tapes
contain scalars after transcript field conversion and before role maps, with
mapped nonzero IPA round challenges returned separately.

The replacement document uses `iroha.native_prover.reference.v1`, ten complete
parameter sets (`ep` and `eq`, k6 through k10), and exactly 23 cases per curve:

- Eight V1 combinations: Blake2b/scalar RP57, Committed/Direct instances, and
  selector compression off/on.
- Four V2 combinations: Blake2b/scalar RP57 and Committed/Direct Field instances.
- Seven base-field RP57 cases: Direct Field, Bits(4), and typed instances at
  every k6 through k10.
- Four ordinary native Sigma/Wide cases: Blake2b/scalar RP57 at k6/k8, named
  `{ep|eq}/native/{blake|poseidon}/{6|8}`. These replace the old oracle labels;
  they do not accept `oracle_repr` or override descriptor-bound transcripts.

Every descriptor, key, public input, parameter and proof must come from actual
native construction and pass native full verification before the independent
reference checks it. Native output is a test input, not an independent oracle.
The separate 42/8 producer described in [the fixture README](../README.md) does
not generate this 46-case document.

## Capture the current reference

The maintained owner is the ignored native test
`native_reference_capture::export_current_reference_corpus`. It rebuilds the
source circuits and parameters, proves the exact matrix and uses full native
verification to check every original plus wrong-instance, altered-proof,
trailing-byte and truncation mutations. The eight `native` records use the same
Sigma k6/Wide k8 public source families as the succinct matrix. Test-only fixed
seeds do not expose a shipping randomness option.

After the source/build hold is released and the combined source and lock are
reviewed, run from that checkout. The output directory must be new, absolute and
outside the checkout, beneath an existing owner-only parent. It must be distinct
from the 42/8 output directory:

```sh
IROHA_NATIVE_PROVER_CAPTURE_DIR=/absolute/private-parent/native-reference-current \
  scripts/cargo_fast.sh --target-slot kagemusha-cohort --stable-local-metadata -- \
  test --locked --release -p iroha_plonk --lib \
  native_reference_capture::export_current_reference_corpus -- \
  --exact --ignored --nocapture --test-threads=1
```

The exporter never installs fixtures. Retain `capture-start.json`,
`reference_v1.json`, `capture-result.json`, the exact source/executable/output pins
and the actual successful process exit with terminal
`NATIVE_REFERENCE_CAPTURE_COMPLETE cases=46 parameters=10`. Its complete compiled
source census includes bootstrap seed fixtures and generated catalog DATA;
those inputs do not qualify the binary as a final catalog or release artifact.
Top-level `capture` provenance is custody metadata and never a proof-acceptance
input to the independent reader. Review captures before installation, then
freeze and rebuild the final source/catalog candidate.

## Independent checks

The fast role, norm-product, descriptor and scoped-identity controls do not need
a generated proof corpus:

```sh
python3 -I -B -S pytests/scripts/test_native_reference_roles.py
```

Verify the captured reference directly before installation:

```sh
python3 -I -B -S fixtures/native_prover/verify_reference_v1.py \
  /absolute/private-parent/native-reference-current/reference_v1.json
```

Review and install all matching current native captures together, then run:

```sh
python3 -I -B -S fixtures/native_prover/verify_reference_v1.py
python3 -B -m pytest -q pytests/scripts/native_prover_reference_test.py
```

These commands require the matching current corpus and reader. The adversarial
suite must retain wrong proof/key/public/parameter rejection; exact case matrices;
canonical Norito spans, points and typed-instance bounds; and boolean/float alias
rejection. Constructive false generator claims may preserve the succinct IPA
equation but must fail the complete decision. The suite also reads the eight-case
`succinct_v1.json`; replacing that input requires its reader and raw/mapped
challenge comparisons to migrate coherently. Current native and independent
Python execution remains pending until those inputs are actually regenerated.

This is individual proof and generator-decision validation. It does not establish
batch weights, encoded `AccumulatorV1` admission, k16 verification, recursive
PIPA-AS, wallet catalog qualification or a production fallback decoder. Variable-
time arithmetic and test resource limits do not qualify proving latency, memory,
side channels or physical devices.
