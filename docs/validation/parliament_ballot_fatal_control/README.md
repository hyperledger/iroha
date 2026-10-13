# Fatal resource reporting outside charged verification

Status, 2026-10-13: standalone diagnostic fix; production remains gated.

The earlier memory-entry worker wrote its resource-exhaustion JSON directly to
stdout while its arena was active. A full, undrained pipe blocked both frozen
binaries until the pipe was drained. The [retained reproduction](backpressure-reproduction/README.md)
preserves those binaries' identities and observations. Their successful finite
campaign never established termination under output backpressure.

The current worker uses a separately counted, native shared control page.
Before enabling its arena it publishes the exact admitted debit. Exhaustion
publishes a terminal marker and immediately calls `_exit(73)` without output,
formatting, allocation or unwinding. The external
[supervisor](../../../scripts/parliament_ballot_memory_supervisor.py) reads only
after child death and emits the fatal JSON itself. It requires agreement among
the exit, marker and actual input length; ordinary results must also match the
shared debit. Missing/corrupt evidence and diagnostic timeouts remain operational
failures with no inferred refund. Failed campaign rows retain raw child output
and shared bytes. A timeout racing a terminal exit discards the synthetic result.

The [native control contract](../../../crates/iroha_parliament_ballot_proof/examples/memory_entry/README.md)
defines the fresh zeroed, mode-0600, unlinked regular file, exclusive writer,
mapping lifetime and same-host atomic layout. This is process control, not a
proof codec, persisted ballot format or production service.

## Evidence

The [new build receipt](build/build-receipt.json) records all six successful
locked release commands: tests, strict all-target Clippy and build, in both
modes. Each mode passes 17 Rust tests. All 2,021 source guards stayed unchanged.
The isolated 121-package lock has no unexpected package identities against the
1,149-package root lock; this is not feature/dependency-graph parity. The exact
derivation is retained in [workspace.diff](build/generated-source/workspace.diff.template).

The [campaign](campaign/report.json) passes **122 observations / 61 mode pairs**,
with all 2,034 input guards unchanged. Outcomes are 16 acceptances, 50 codec or
proof rejections, 38 admission refusals, 16 explicit resource exhaustions and
two staging errors. Coverage retains both rows, both roles, three vote sizes,
late invalidity, malformed framing, shortage, exhaustion and retrieval controls.
The direct 425,985-byte borrowed input still refuses before copying with zero
charge and zero arena allocations. All raw [cases](campaign/cases.jsonl) retain
their post-exit supervisor evidence.

The worker reservation is **43,106,304 bytes (41.109375 MiB)** on this Mac:
32 MiB heap, 1 MiB metadata, 8 MiB supplied stack, 64 KiB control, two 16 KiB
guards and the new 16 KiB fatal page. Requested/block allocation peaks remain
6,565,341/7,211,136 bytes in both modes. Returning workers have zero live arena
bytes; terminal exits do not promise destructor cleanup.

The [real-binary output controls](backpressure-fixed-v2/README.md) exercise a full
undrained pipe and a pipe with no reader in both modes. These controls require
the child to exit with exact shared debit and no child output; a timeout cannot
pass. They are finite regressions, not a universal wall-clock bound.
The earlier [four observations](backpressure-fixed/README.md) remain frozen.
The revised helper additionally requires the shared checker's complete source
inventory and genuine per-mode Cargo commands; five tests cover that validation
and strict control/JSON types. The stronger run uses the same compiled workers.

The [focused check receipt](fatal-control-checks.json) records 61 passing Python
tests: 16 preparer, 22 campaign, 10 supervisor and 13 independent zero-challenge
checks. Scoped Rust formatting and the retired-codec guard pass. The unrelated
Core source-contract check still fails at the missing modeled
`Executable::IvmProved(proved)` queue binding; it is preserved as a failure.
The same check confirms production availability remains false, qualified attempt
latency is absent, and Core/Torii have no experimental ballot dependencies.

Local peer review found and resolved exact-fd-permission validation, ordinary
debit/state contradictions, timeout-publication races and loss of failed-case
supervisor evidence. This is not independent unsafe-code or cryptographic review.

## Scope and reproduction

File staging remains before worker admission. Normal stdout and parent fatal
publication can block after charged execution; this fix makes no whole-CLI
completion promise. Native `_exit`, atomic execution, supplied-stack behavior,
allocator correctness and the other platform premises still require their
specified treatment. Old disassembly, stack graphs and frontiers describe their
old images and do not transfer to these binaries.

Use fresh source, build-output and binary directories. Prepare with
`scripts/prepare_parliament_ballot_memory_entry.py`, resolve metadata, compare
the isolated lock, then run the retained [builder](build/build_worker.py.template).
Run `scripts/check_parliament_ballot_memory_entry.py` with explicit `--portable`,
`--accel`, `--build-receipt` and new `--output` paths. The output-control driver
also requires its explicit source-bound receipt and new destination. Preserve
old attempts; never repin them to changed source or rebuilt binaries.

TODO: establish all-admitted-input stack/work and runtime-allocation bounds,
refresh compiled analysis for the actual candidate, obtain independent review
and complete named hardware qualification. Complete workspace certification,
physical cost calibration and profile qualification remain false.
