# Conditional root-entry validation

The [root-entry lemma](../../../specs/parliament_ballot_b6_root_entry.md)
establishes a root-only, five-query slot reduction under the proposed
chosen-input AES game. It retains the actual H4 IV, equal numeric keys and
the full continuation. Switching its five permutation replies to independent
blocks costs at most `10/2^128`. This is not a numerical AES bound or acceptance
of that primitive game.

The new [integration tests](../../../crates/iroha_zkp_vole/tests/root_slot_interface.rs)
pass **3/3 in each of the portable and `accel` builds**. They compare an opaque
block-callback adapter with the real PRG, check the actual row widths and
wrapped addresses, and exercise a controlled equal-key continuation. The
synthetic H4 namespaces and controlled alias replies are explicitly identified
in the tests; they are not a full prover run or random-permutation experiment.

[Portable](portable-tests.txt) and [accelerated-feature](accel-tests.txt) logs
retain both output streams. The [receipt](receipt.json) records the commands,
successful exits and source bookends: all [73 scoped inputs](inputs.json)
were unchanged across both executions. This is a live-checkout check, not a
complete, hermetic compiler-input or binary-provenance certificate. Scoped
Rust formatting and local Markdown file links were also checked. Two local
agent reviews found no blocker within the lemma's stated scope; neither is
independent cryptographic review.

Reproduce from the repository root:

```sh
scripts/cargo_fast.sh --target-slot parliament-development --jobs 4 --no-sccache --stable-local-metadata -- test --locked --offline --profile local-release -p iroha_zkp_vole --test root_slot_interface -- --nocapture --test-threads=1
scripts/cargo_fast.sh --target-slot parliament-development --jobs 4 --no-sccache --stable-local-metadata -- test --locked --offline --profile local-release -p iroha_zkp_vole --test root_slot_interface --features accel -- --nocapture --test-threads=1
shasum -a 256 -c docs/validation/parliament_ballot_root_entry/SHA256SUMS
```

The manifest freezes only this new lemma, test and validation record. Earlier
receipts and the accepted numerical ledger are unchanged. Full primitive
entry, resources, quantitative premises, external review and hardware
qualification remain open. Development testing stays enabled; binding
production use stays gated.
