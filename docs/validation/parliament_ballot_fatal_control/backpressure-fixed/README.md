# Fatal output independence on the shared-control binaries

The [report](report.json) and [four observations](cases.jsonl) exercise both
binaries from the separate [fatal-control build](../build/build-receipt.json).
Each child receives a one-byte record and `--heap-limit 1`, which forces its first
arena allocation to exhaust. The current external supervisor owns the shared
control page and reads it only after the child exits.

Both portable and accelerated binaries pass with a full pipe and with a broken
pipe connected to stdout. Every observation has raw exit 73, an exhausted marker,
exact debit of one unit and one byte, no stderr and no timeout. Only the parent
constructs the resource report from the shared page. The extra counted page is
16,384 bytes on this host. All 2,033 guarded source, build, executable, log,
metadata, receipt, supervisor and regression-helper inputs remained unchanged.

The full pipes are prefilled with 65,536 bytes and remain undrained until the
child has exited. Draining afterward returns exactly those bytes: the child adds
none. For the broken-pipe cases, the read endpoint is closed before spawn. The
supervisor's `raw_stdout` is empty but explicitly marked uncaptured when using
these external sinks; the full-pipe byte comparison supplies the direct output
check. A broken sink by itself cannot prove the absence of attempted writes.
The retained Rust fatal path's source argument separately excludes output calls.

The reusable [regression helper](check_parliament_ballot_fatal_output.py.template)
records partial failure and refuses a successful report after input drift. Its
four focused tests cover strict debit/control/result checks, build-identity
changes, missing evidence, output reuse refusal and CLI failure. The supervisor
revision was independently reviewed before these runs. The old blocking behavior
is separately retained in [the preceding witness](../backpressure-reproduction/README.md).

This closes the selected full/broken stdout regression. The recorded elapsed
times are diagnostic observations, not a universal completion-time certificate.
Native termination, complete stack/workspace bounds, target calibration and
independent qualification remain separate; all qualification flags stay false.
