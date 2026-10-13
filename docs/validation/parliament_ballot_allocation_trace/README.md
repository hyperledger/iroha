# Compiled verifier allocation-stream diagnostic

2026-10-13: **132 corpus observations and 14 controls pass on both instrumented
modes. No profile selection or workspace qualification follows.**
This experiment compares allocations made by a separately compiled cold verifier
with the existing [source grammar](../parliament_ballot_arena_sufficiency/README.md).
The earlier arena oracle replayed supplied traces; it did not observe the
verifier's allocation stream.

## Build and derivation

The [preparer](../../../scripts/prepare_parliament_ballot_allocation_trace.py)
checks the four frozen resource-worker modules before deriving a separate
workspace. The derived allocator records each successful arena allocation and
each arena-provenance deallocation. Setup installs the heap base; markers bracket
arena activation and ordinary cleanup. A separate read adapter preserves the
ordinary exact-length/EOF check and supports explicit post-reservation EOF/EIO
injection. These diagnostic read failures are not production configuration.
The frozen worker, arena, native mapping and budget sources remain unchanged.

The [build receipt](build-receipt.json) binds both executable hashes, Rust 1.93.1,
six release commands and 1,994 guarded source files. Each mode passed **17 tests,
strict all-target Clippy and its release build**, without source drift. The
[before](build-source.json) and [after](build-source-after.json) inventories agree.
The scope includes resolved package Rust sources/manifests/build scripts,
available registry checksum files, original and generated diagnostic sources,
the four resource modules, preparer/builder and root metadata. It is a
conservative source inventory, not a hermetic compiler, native-header or runtime
attestation. Commands and complete outputs are retained in `portable-*.txt` and
`accel-*.txt`.

The final generated tree is `/tmp/parliament-allocation-trace/worker-src-3`.
Original diagnostic/resource templates are under `sources/`; generated files and
the exact workspace patch are under `generated-source/`. Root Cargo manifest,
lock and Norito snapshots are retained as `*.build.template`. The isolated
[lock comparison](lock-comparison.json) checks package-identity membership only;
it does not claim identical dependency edges, feature resolution or builds.
The repository root lock was not modified.

Two earlier attempts remain distinct. `initial-preparation/` retains metadata
and lock comparison for `worker-src-1`, before the final sealing correction.
`failed-build-1/` retains `worker-src-2`: its 17 portable tests passed, but strict
Clippy rejected three manual alignment predicates. Replacing those predicates
with `is_multiple_of` and preparing a fresh tree preceded the successful full
matrix. Those earlier artifacts were not repinned as final evidence.

## Recorder boundary and controls

The recorder reserves **16,777,216 bytes (16 MiB)** in a separate mapping for
524,288 fixed, 32-byte records. Each record holds an operation, arena-relative
offset, requested size and alignment. Raw process addresses are not persisted.
Atomic phase ownership excludes overlapping hook writes and sealing; collision,
overflow, invalid layout/base or phase misuse invalidates the observation. Hooks
perform no allocation, TLS access, formatting, symbol lookup or waiting.

The recorder mapping is instrumentation overhead **in addition to** the original
43,089,920-byte (41.09375 MiB on this Mac) worker reservation. It is not hidden
inside that reservation. After worker join and arena deactivation, the driver
copies retained records into ordinary storage and serializes them with Norito
JSON. That additional Vec/String memory and file I/O are also outside the
charged interval. This run supplies no prover/verifier timing or whole-process
memory certificate.

The file contains a typed `header` and `records` array. Header validity and flags
are captured **before** the file write and sync. A complete-looking file with
`observation_valid: true` is therefore insufficient: the supervisor must also
validate the child's expected exit, final stdout receipt, exact header agreement
and completed capture. A write/sync failure exits 76 even if a full JSON document
was already written. Existing output files are refused. Terminal arena OOM
retains the original resource-failure exit 73 and produces no completed stream;
an absent stream is never interpreted as zero allocations.

The completed controls exercise empty/routed allocation, allocate-copy-free
reallocation, recorder overflow, recorder collision, existing-output refusal and
terminal OOM in each mode. Overflow/collision are expected **invalid recorder**
observations, not successful grammar matches. The terminal control is an
expected missing stream. Source and executable identities must remain stable
through the campaign.

## Campaign status and interpretation

The [campaign](campaign-1/report.json) and [summary](campaign-summary.json)
retain **132 verification/input observations plus 14 controls**, with all
2,041 guarded inputs unchanged. The corpus outcomes are 16 accepted, 104
rejected, four admission refusals and eight charged input errors. All 66
portable/accelerated pairs agree on input, outcome, stage and debit.

The **132 corpus streams** contain **8,943,472 allocation/free events**, representing
4,471,736 allocations. Six ordinary controls match their expected streams;
four overflow/collision controls are invalid as expected, two existing-output
controls refuse setup, and two terminal OOM controls retain no completed
stream. Every attempted child's stdout/stderr, exit and compressed raw dump
identity is retained. All 146 gzip roundtrips and raw hashes were checked.

| Row | Largest observed requested live bytes | Largest observed rounded live bytes | Largest observed allocation count per call |
| --- | ---: | ---: | ---: |
| Candidate | 4,069,654 | 5,017,216 | 19,041 |
| Comparator | 6,565,341 | 7,211,136 | 184,164 |

These finite observed peaks agree with the conditional source-model ceilings;
they do not establish a universal compiler/runtime bound. The internal BAVC
provider count is checked against its source-derived range, not independently
recovered from proof indices. Exact order, layout and offsets are checked for
each event that actually occurred.

The corpus uses existing independent proofs for both rows, registration and votes
at 3, 500 and 1,000 seats. It includes late-invalid proofs, byte-reachable decoder
prefixes, registration empty/maximal fields and interior growth cases, admission
refusals, and charged read failures. It does not generate new proofs.

The [matcher](../../../scripts/parliament_ballot_allocation_match.py)
compares ordered allocation/free identities and layouts, including bounded
restoring provider repetitions, then replays the observed offsets and checks live
state and worker statistics. An accepted finite trace demonstrates membership in
the reviewed grammar for that input and **instrumented binary**. It does not
prove that every admitted input follows the grammar, that the original frozen
worker has identical compiler transformations, or that every allocation goes
through these hooks. Native/System/TLS calls, compiled stack bounds, exceptional
termination and complete runtime coverage remain separate obligations.

[Focused checks](focused-checks.json) pass 81 Python tests and 182 subtests
across the allocation, stack-frontier and prover-accounting helpers, plus the
codec guard and formatting of the three diagnostic source templates. A first
format check tried to follow the generated module beside its template and
failed because that file belongs to the isolated build tree; that diagnostic
is retained separately from the passing explicit-source check. The real Core
source-contract check still fails on concurrent block-start ordering. No full
workspace pass is claimed.

## Reproduction

Use Python 3.11+, the pinned Rust toolchain and a matching source inventory.
New builds need a fresh directory and receipt; do not overwrite or repin this
record. From the repository root, an independent attempt can be prepared with:

```sh
python3.11 scripts/prepare_parliament_ballot_allocation_trace.py \
  --output /tmp/parliament-trace-repro/source
mkdir /tmp/parliament-trace-repro/evidence
cargo metadata --format-version 1 \
  --manifest-path /tmp/parliament-trace-repro/source/Cargo.toml \
  > /tmp/parliament-trace-repro/evidence/dependency-metadata.json
python3.11 scripts/prepare_parliament_ballot_allocation_trace.py --check-lock \
  /tmp/parliament-trace-repro/source/root-Cargo.lock.template \
  /tmp/parliament-trace-repro/source/Cargo.lock \
  > /tmp/parliament-trace-repro/evidence/lock-comparison.json
python3.11 docs/validation/parliament_ballot_allocation_trace/build_worker.py.template \
  --root "$PWD" --out /tmp/parliament-trace-repro/evidence \
  --work /tmp/parliament-trace-repro/source \
  --target /tmp/parliament-trace-repro/target --binaries /tmp/parliament-trace-repro
python3.11 scripts/check_parliament_ballot_allocation_trace.py \
  --portable /tmp/parliament-trace-repro/worker-portable \
  --accel /tmp/parliament-trace-repro/worker-accel \
  --build-receipt /tmp/parliament-trace-repro/evidence/build-receipt.json \
  --output-dir /tmp/parliament-trace-repro/campaign
```

The build helper uses ordinary Cargo for the isolated manifest and never kills
a child on timeout. Preserve any incomplete receipt and resolve the running
child before retrying. The supervisor retains attempted/completed cases and
refuses successful campaign publication after missing evidence, mismatch,
interruption or source drift.

No security premise, independent reviewer acceptance, hardware baseline,
production envelope, calibrated budget or activation gate is discharged by this
diagnostic. `complete_allocation_correspondence`,
`complete_workspace_certificate` and `profile_qualified` remain false.
Production remains gated.
