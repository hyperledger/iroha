# Contract code readback fixture

`code_readback.ko` is a public, read-only contract returning the integer 7.
`code_readback.to` is its complete V1 artifact, including the execution header
and authenticated interface. `code_readback.manifest.json` is its canonical
compiler manifest, checked against independent native admission. These public
fixtures contain no signing material or deployment authority.

The SDK includes the artifact and manifest directly and checks their code-hash
binding without requiring a compiler. The IVM suite additionally recompiles the
source, compares every artifact byte, performs native admission and checks the
complete admitted manifest. Both consumers use this single generated identity.
Validation results belong to the candidate's test receipts, not a fixture file.

Build the canonical producers:

```sh
cargo build --locked -p kotodama_toolchain --bin koto -p ivm_artifact_admission --features ivm_artifact_admission/dev-tools --bin ivm_artifact_admit
```

Use `scripts/regenerate_kotodama_goldens.py --write --output-root <absolute-new-target-directory>`
to produce the complete fixture set. The owner compiles and admits all mapped
contracts twice, checks exact compiler/admission manifest equality and publishes
a sealed tree. Apply the reviewed artifact and manifest together, then run the
owner's `--check` mode against the repository. Generated outputs are registered
in `generated-files.toml`; the manually maintained `provenance.json` is retired
and rejected by the owner.

Run both native consumers on the same candidate:

```sh
cargo test --locked --offline -p ivm --test ivm_group_01 contract_artifact::
cargo test --locked --offline -p iroha --lib contract_code_artifact
```
