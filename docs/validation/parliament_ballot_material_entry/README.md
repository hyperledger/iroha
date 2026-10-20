# Conditional material-entry validation

The [material-entry argument](../../../specs/parliament_ballot_b6_material_entry.md)
extends the conditional root hop through marked paths, selected affine leaves
and selected expanded rows under the proposed chosen-input AES/`Γ` game.
It reaches independent material with real H5 processing. Each parent/leaf
permutation output is switched to independent blocks before the next key
embedding; previous replacement slots and each game's own programming
addresses are preserved as specified in the argument.

The shared invocation schedule has a safe ceiling of 327 component slots.
Its separately derived switching bound is `T * 2,892,601 / 2^128`, in
addition to unquantified whole-driver primitive advantages. This does not
revise the accepted ledger or complete the initial/later QROM composition.

The [three new integration tests](../../../crates/iroha_zkp_vole/tests/material_slot_interface.rs)
pass in both portable and `accel` builds. They check real affine-leaf
correspondence, a controlled affine inverse and streaming selected-row
correspondence/effects, including an equal known seed. Row lengths come from
the source `ProofParams::ell_hat()`. Synthetic role namespaces, dimension
descriptors and controlled replies are labeled; these are not whole ballot
proofs or random-permutation samples. Test adapters are private test code.

The [portable](portable-tests.txt) and [accelerated-feature](accel-tests.txt)
logs retain both streams. The [receipt](receipt.json) records successful
exits, source bookends and switching arithmetic. All [76 scoped inputs](inputs.json)
were unchanged across both runs. This is live-checkout evidence, not a
hermetic compiler-input/binary certificate. Scoped formatting and local
Markdown paths were checked. Two local reviews found and resolved two
wording issues before their final mathematical readback; a test review found
no blocker. These reviews are not independent cryptographic acceptance.

Reproduce from the repository root:

```sh
scripts/cargo_fast.sh --target-slot parliament-development --jobs 4 --no-sccache --stable-local-metadata -- test --locked --offline --profile local-release -p iroha_zkp_vole --test material_slot_interface -- --nocapture --test-threads=1
scripts/cargo_fast.sh --target-slot parliament-development --jobs 4 --no-sccache --stable-local-metadata -- test --locked --offline --profile local-release -p iroha_zkp_vole --test material_slot_interface --features accel -- --nocapture --test-threads=1
shasum -a 256 -c docs/validation/parliament_ballot_material_entry/SHA256SUMS
```

This manifest freezes only the new argument, test and validation record.
Earlier receipts remain unchanged. Quantitative primitive premises, complete
driver resources, composition, external review and hardware qualification
remain open. Development testing stays enabled; binding production use stays
gated.
