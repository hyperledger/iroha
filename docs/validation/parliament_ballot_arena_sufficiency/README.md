# Conditional arena replay evidence

The [source argument](../../../specs/parliament_ballot_arena_sufficiency.md)
separates an order-independent frontend spatial bound from exact backend
replay over retained-state classes. It advances B6.4 without changing the
frozen worker, charge contract or production gate.

`source-model.json` records all 135,064 row/mode/layout traces: 32,768
registration retained classes and 998 vote sizes per row/mode. Every trace
fits the 32 MiB buddy arena and ends empty. Conditional all-length rounded-live
bounds are 5,017,216 bytes (candidate) and 7,211,136 bytes (comparator); requested
bounds are 4,069,654 and 6,565,341 bytes. Frontend arbitrary-length safety uses
a separate conservative 3,670,016-byte spatial envelope. Representative
allocation counts are not all-length maxima: Vec growth is nonmonotone.

`native-oracle.json` retains 88 exact trace inputs, raw stdout/stderr, binary
hash and comparisons with the actual Rust arena implementation. Eighty-two
traces succeed; six deliberately fail for fragmentation, quota, alignment,
nonrestoring repetition, leaked allocation and double-free. Success requires
identical offsets, layouts, peaks, counters and cleanup; rejection requires
exit 1, empty stdout and the exact intended diagnostic. Crashes, unrelated
operational errors, non-object JSON and qualification claims fail the checker.
These are supplied allocator traces, not measured verifier allocation streams.

The new [Rust oracle](../../../crates/iroha_parliament_ballot_proof/examples/arena_trace_replay.rs)
imports the unchanged arena source. Its interpreter, JSON, backing allocation
and bookkeeping run outside that arena. `oracle-test-receipt.json` and
`oracle-build-receipt.json` retain six Rust tests, strict release Clippy, build
results and the copied executable's identity. Their complete source inventory
is `oracle-build-source.sha256`; exact concurrent-sensitive Norito and lock
contents are retained as templates. There is one allocator oracle build:
portable/accelerated modes change trace provider alignment, not oracle code.
After the clean test/lint/build intervals, the shared checkout added an
unrelated `iroha` dependency in `Cargo.lock`. `post-build-lock.json`, its diff
and both exact lock templates preserve that distinction; the oracle is still
bound to the original lock and has not been repinned to the later checkout.

`run_validation.py` retains exact final commands, per-command outputs, exits,
source checks and hashes in `validation-receipt.json`. Run it from this checkout
with the documented local paths available. `--require-qualified` returns 2
after successful source-model replay because full qualification is unavailable.
All 99 focused Python tests, six Rust oracle tests, strict release Clippy,
scoped formatting and the retired-codec guard pass.
The separate current Core source-contract result is reported without changing
or waiving the integration guard: it still fails on the existing SCCP
block-start ordering mismatch. No full workspace suite was run.

Earlier successful development replays are kept as `source-model.initial.json`,
`source-model.source-guard.json` and `native-oracle.initial.json`, with their
exact earlier checker templates. They precede final publication hardening and
representative-statistic wording. The final records have their own source
identities; earlier results were not repinned. Both checkers now atomically
replace an explicit output with a failure receipt after a failed rerun, so an
old passing report cannot survive a recognized failure.

Complementary retained records:

- [Selected compiled layouts](../parliament_ballot_arena_layout/README.md): exact frozen binary layout/drop observations.
- [Compiled stack frontiers](../parliament_ballot_compiled_stack/README.md): 26 focused tests and raw instruction evidence; complete stack bounds remain null.
- [Original resource campaign](../parliament_ballot_resource_contract/README.md): unchanged worker and original measurements.

The correspondence premises, complete native/TLS/System coverage, complete
stack bound, independent review, calibration and named hardware requirements
remain open. `complete_workspace_certificate` and `profile_qualified` remain
false. No production integration or activation is authorized by this record.
