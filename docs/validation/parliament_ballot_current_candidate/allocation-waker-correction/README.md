# Allocation waker assertion correction

The corrected focused release suite passes **28 shared unit tests and all nine
`charged_shared_custody` integration tests**. Both commands completed with exit
0, without timeout or process signals. The 37 guarded files and ten absent
paths remained unchanged through both runs. These results do not qualify the
release, verifier resource bound or unsafe ownership implementation.

The earlier [failed attempt](../allocation-tests/README.md) remains immutable:
its `will_wake` assertion failed before that unit test's callback/final-drop
assertions. The earlier ten passing doctests are also retained there.

## Exact correction

[correction.patch](correction.patch) changes only two test assertions and three
comment lines across three files. [sources-before.json](sources-before.json)
binds the original byte copies under [sources-before](sources-before/).
There is no runtime logic change.

Rust 1.93.1 explicitly permits false negatives from `Waker::will_wake` and
implements it by comparing data and vtable addresses. Its public `data` accessor
returns the original raw-waker data pointer. See the
[version-pinned contract and implementation](https://github.com/rust-lang/rust/blob/1.93.1/library/core/src/task/wake.rs#L437-L455)
and [data accessor](https://github.com/rust-lang/rust/blob/1.93.1/library/core/src/task/wake.rs#L539-L544).
Requiring `will_wake` to return true was stronger than that contract.

The tests now compare the original and cloned data pointers. This alone checks
only pointer identity: all existing actual callback, payload identity, physical
allocation, charge, wake count, drop count and allocation-refusal checks remain
in place. The private conversion comment now describes retention of the original
control allocation, without suggesting a unique vtable address. Generic
associated-constant table promotion is a plausible explanation for the old
false negative; no instrumented machine-level diagnosis is claimed.

The passing unit test exercises allocation-free conversion/cloning, borrowed
wake, consumed clone wake and final explicit drop. It verifies two callback
invocations, one final payload drop and final pool refund. The integration test
also checks the same physical control allocation, a borrowed and consumed first
waker, and a final consumed wake on another thread. Its payload destructor
checks that the physical control was freed while the original charge was still
retained. Other selected tests cover callback unwind and failed allocation.
The five projection controls from the first attempt still pass.

Independent read-only review verified all three original snapshot hashes and
the exact diff, and confirmed that both tests retain their callback, original
payload, wake/drop/refund and allocation-free checks. The reviewer made no
source changes or duplicate test runs.

## Retained validation

[receipt.json](receipt.json) records the exact commands, source/metadata/archive
hashes, Cargo configuration presence, hashed build-environment values, Rust
tool versions, complete logs and elapsed times. The recipe is
[capture.py.template](capture.py.template); use a fresh output directory for a
new attempt. Its per-command wait is 1,200 seconds and it retains a timed-out
child's PID without killing it.

```sh
cargo test --release --locked -p iroha_allocation --lib shared --target-dir /private/tmp/parliament-current-candidate-20261013-v1/allocation-target
cargo test --release --locked -p iroha_allocation --test charged_shared_custody --target-dir /private/tmp/parliament-current-candidate-20261013-v1/allocation-target
```

The logs are [shared.txt](shared.txt) and
[charged-shared-custody.txt](charged-shared-custody.txt). All 91 other unit tests
remain filtered out; other crate integration targets and the full workspace
suite were not run. The private comment correction contains no doctest change,
so the prior doctest command was not repeated. The capture is not a hermetic
compiler, native runtime or full dependency attestation. Worker rebuild and
campaign evidence are separate. Production remains gated.
