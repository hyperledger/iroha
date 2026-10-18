# Current allocation component validation

This retained attempt **failed** its focused release unit-test command: 27 tests
passed, one failed, and 91 were filtered out. All ten doctests passed. Neither
command timed out. No child was signalled, and no Rust source, manifest or lock
file was edited by this capture. All qualification flags remain false.

[receipt.json](receipt.json) records the exact commands, tool versions, logs,
elapsed times and 32 before/after file identities. Those identities and the 10
guarded absent paths were unchanged during both commands. The guarded files
include the entire 27-file allocation crate, repository Cargo manifest/lock,
toolchain declaration, applicable Cargo config and capture recipe. The root
lock observed here is `2e12f608e4819adab3e5ab49ba66bdb5005a1c3c1c4830a8298b02e12056200e`;
it is the input to this attempt, not an assertion that an earlier build used
these bytes. Present/absent build-environment values are hashed in the receipt.

Both commands used the dedicated target directory
`/private/tmp/parliament-current-candidate-20261013-v1/allocation-target` and a
1,200-second wait limit:

```sh
cargo test --release --locked -p iroha_allocation --lib shared --target-dir /private/tmp/parliament-current-candidate-20261013-v1/allocation-target
cargo test --release --locked -p iroha_allocation --doc --target-dir /private/tmp/parliament-current-candidate-20261013-v1/allocation-target
```

The reusable [capture recipe](capture.py.template) refuses an existing receipt;
repeat attempts must use fresh output directories. A timeout records the live
PID and leaves the child running instead of terminating it.

## Observed results and failure scope

[shared.txt](shared.txt) records exit 101. All five new projection controls pass:

- charged projection clones retain the original pool credit;
- public projection retains the concrete charge across thread transfer;
- erased trait projection retains prepaid control/vtable without allocation;
- erased slice projection preserves its owner and releases hidden payload;
- projection callback unwind retires the original charge.

The passing tests also exercise original allocation/alignment identity,
prepaid refusal and retry custody, allocation-free cloning, final-reference
retirement order, unwind, cross-thread custody and the other two wake controls.
These are finite component tests, not exhaustive proofs.

The failed test is
`shared::wake_tests::charged_waker_conversion_clones_callbacks_and_final_drop_allocate_nothing`.
It stops at `shared_wake_tests.rs:70`, `assert!(waker.will_wake(&clone))`.
Consequently its subsequent successful callback, wake-count, final-drop and
pool-credit assertions were **not reached in this run**.

Read-only source triage identifies an over-strong assertion as the first issue:
Rust 1.93.1 permits false negatives from `will_wake` and implements the check
using data and vtable address equality. See the
[version-pinned Rust implementation and contract](https://github.com/rust-lang/rust/blob/1.93.1/library/core/src/task/wake.rs#L434-L455).
The crate's clone callback retains the original allocation pointer and builds a
raw waker using a generic associated `const TABLE`. Separate promoted table
addresses are a plausible explanation; this capture did not instrument the
addresses or establish that machine-level cause. The same unconditional
assertion also exists in the unrun `charged_shared_custody` integration test.
A proposed follow-up is to check data-pointer identity and retain all actual
callback/custody/no-allocation assertions, then run both affected targets. This
attempt neither applies that change nor treats the failed command as passing.

[doctests.txt](doctests.txt) records exit 0: one ordinary doctest and nine
compile-fail doctests, including both projection thread-safety/lifetime
rejection examples.

## Exclusions

This selection does not run the 91 filtered unit tests, crate integration
targets, full workspace suite, mobile/device qualification or standalone worker
campaign. It is not a resource bound, full dependency/toolchain attestation or
independent cryptographic review. Other workspace packages are not compiled by
these selected allocation-crate commands. The capture guards do not claim a
hermetic compiler/native/runtime environment. Production remains gated.
