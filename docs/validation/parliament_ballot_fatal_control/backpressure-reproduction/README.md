# Old fatal-output backpressure witness

The source-pinned original in-memory worker calls blocking `write(1, ...)` inside
`exhausted()` before `_exit(73)`. The retained [report](report.json) reproduces the
dependency on both binaries from the earlier memory-entry build receipt.

A one-byte record with a one-byte heap limit exhausts the arena. With normal
captured stdout, both children exit 73 and report the exact 1-unit/1-byte debit.
With stdout redirected to a pipe prefilled with 65,536 bytes, each child remains
running after 0.5 seconds. Draining that same pipe lets each exit 73 immediately
and yields the same resource report. No signal is sent and every child exits.
These durations demonstrate output dependence; they are not calibrated timing.

The [reproducer](reproduce.py.template) checks both binary hashes against the old
build receipt before execution and checks all three input hashes afterward. No
source, binary or old artifact is changed. The receipt and binaries are named by
absolute paths and hashes in the report. This witness supports removing output
from the fatal charged path; it supplies no complete resource certificate.
