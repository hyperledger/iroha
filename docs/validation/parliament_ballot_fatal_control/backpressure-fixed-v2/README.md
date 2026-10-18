# Fatal output independence with complete build-receipt validation

The [report](report.json) and [four observations](cases.jsonl) exercise both
binaries from the separate [fatal-control build](../build/build-receipt.json).
Each child receives one byte and `--heap-limit 1`, forcing its first arena
allocation to exhaust. The external supervisor reads its shared control page
only after child death and constructs the resource report outside that child.

Both binaries pass with a full stdout pipe and a broken stdout pipe. Every raw
and returned exit is 73, with state EXHAUSTED, exact debit of one unit and one
byte, no stderr and no timeout. The counted shared page is 16,384 bytes here.
The full pipes remain undrained until child exit, then yield exactly their
65,536 prefilled bytes: zero child bytes were added. The broken-pipe read ends
are closed before spawn. External-sink stdout is explicitly uncaptured by the
supervisor; the full-pipe drain provides the direct byte check. Broken output
alone cannot establish that no write was attempted; the Rust fatal source path
separately contains only publication and immediate native termination.

The [revised helper](check_parliament_ballot_fatal_output.py.template) reuses the
reviewed memory-entry validator. It reconstructs required adapter, generated,
fixture and dependency source coverage, validates actual Cargo command modes,
and binds logs, metadata and both binaries. It also guards the actual loaded
validator, resource helper and supervisor. All 2,035 guarded inputs remained
unchanged. Strict integer fields, boolean flags and unique finite JSON fields
are checked independently. Five focused tests pass, including duplicate and
non-Cargo command records and omitted required sources. Independent review
found no remaining issue before this new four-observation run.

The [first attempt](../backpressure-fixed/README.md) remains immutable. Its real
observations were valid and its actual receipt separately passed the stronger
validator, but its standalone receipt check only guarded declared inputs and
did not reject incomplete source inventories or duplicated non-Cargo records.
This fresh run supersedes that weaker validation method without rebuilding or
changing either binary. The earlier blocking behavior remains in the
[old-binary witness](../backpressure-reproduction/README.md).

These are selected output regressions, not a universal timing, stack or complete
workspace certificate. Native termination and complete resource qualification
remain separate; all qualification flags stay false.
