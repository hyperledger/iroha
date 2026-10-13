# Standalone finish-and-discard validation

The [job adapter](../../../crates/iroha_parliament_ballot_proof/examples/prover_lifecycle/job.rs)
owns the statement, credential-secret object and single-use proving tape. Every
spawned job runs one existing synchronous proving call. Cancellation suppresses
publication; it does not interrupt or retry that call. `wait` joins and releases
input owners while retaining the unpublished proof. `finish`, or dropping the
job, releases that retained proof too when cancellation wins. Cancellation and
publication share one mutex decision; later cancellation returns `TooLate`.

This is an experimental example and component evidence, **not a production
wallet API, phone qualification, constant-time review, or comprehensive erasure
certificate**. No library, protocol, SDK, Core or activation gate changed.
See the [lifecycle contract](../../../specs/parliament_ballot_prover_lifecycle.md).

## Results and scope

The [summary receipt](receipt.json) records **8/8 tests in both portable and
accelerated release builds**, strict Clippy for both modes, both example builds,
all four example modes on each build, scoped rustfmt and the no-legacy-codec
guard. Builds used `parliament-lifecycle`, normal metadata, `--release --locked`
and a 20-minute wait budget; no build was killed. Exact commands, logs, source
inventories, compiler/host facts and four retained binary hashes are linked from
the receipts. Binary files remain under the recorded task-owned `/tmp` paths.

The eight tests cover:

- Honest registration and S=3 vote publication, both rows, byte-for-byte equal
  to the four independently generated proof fixtures and verified normally.
- Cancellation inside each real prover, followed by successful internal
  completion, discarded output, and selected-buffer cleanup.
- Cancellation after `wait`, while the completed proof is still retained.
- Dropping an in-flight job: the test releases the worker only after observing
  the destructor's cancellation request, then requires joined cleanup.
- Ordinary wrong-witness failures with and without cancellation.
- Partial entropy-fill failures for the actual secret and tape owners.
- A publication/cancellation race with outcomes required to agree with the
  locked decision; deterministic tests separately exercise both sides.
- Observer calibration: all-zero release versus a nonzero last byte, including
  the witness-sized and proof-sized ranges.

The test-only allocator pauses at the first worker-local, zeroed, align-1
allocation of 4,480 bytes (registration) or 6,688 bytes (vote). On these pinned
S=3 fixture paths, earlier profile/statement allocations have different sizes
or alignments; this identifies `build_witness`'s final-size buffer. The vote
prover may already have copied its pad to the stack before this milestone.

The probe registers exact initialized slices and reads them through the
original, still-live deallocation pointer immediately before `System.dealloc`.
It observes the 48-byte secret, 112-byte tape, witness and discarded proof
ranges. It never reads freed memory. Observation callbacks make no explicit
Rust allocation, but this does not bound native TLS setup or allocator work.
The observed zero bytes establish only those named ranges in these builds.
Backend/provider scratch, compiler-created copies, registers, stack spills,
caller copies and prior snapshots are outside this evidence. No panic/unwind,
process-abort, kill or power-loss cleanup claim is made. The 8 MiB requested
thread stack is not a measured cap.

Cancellation-to-finish times in the raw tests are **one diagnostic observation
per row/role/mode**, with the probe present, on the recorded Mac. They are not
p95, deadlines, phone results, cold-process results, or a throughput claim.
S=500 and S=1,000 cancellation conditions and named-phone qualification remain
open.

## Source identities and concurrent edits

There was **no single source-stable campaign covering every command**. An
unrelated task edited Norito while validation was running. The source guards
detected it; the receipts retain those failures instead of relabeling them.
The lifecycle, test, fixture, ballot and backend source stayed unchanged.

| Evidence | Source inventory | Norito `src/lib.rs` SHA-256 | Guard result |
| --- | --- | --- | --- |
| Both 8-test runs; portable lint/build and four example modes | [242 inputs](test-campaign/source.sha256), manifest `1c1b08bd757712a4f146188569c0d6fd5897dd1662c6b0edbddcf1bf3de59c06` | `b7d640fdc4463bdcc4ce14acfcc4dc72b1239c48d06a7a6fa24f5d99bbee765e` | Each listed command passed before/after guards. The enclosing [raw campaign](test-campaign/receipt.json) later stopped during accelerated Clippy and deliberately retains `passed: false`. |
| Accelerated lint/build and four example modes; format/codec guards | [243 inputs](supplemental/source.sha256), manifest `d69e9435e7958df4e1d3ec0a397c2167f77da5e03f19c70ed66f6370757c969c` | `43d86d2a44695a01f837835000636ee7d0e983d2a10922105140f5c29ecca8d4` | [Supplemental receipt](supplemental/receipt.json): all before/after guards passed. |

The [exact intervening delta](test-to-supplement-norito.patch) changes the
unrelated `canonical_frame_payload` helper signature and its tests. It is not
silently excluded as test-only code. Inventories refresh current Rust modules
and build scripts for the local dependency/vendor packages; there were no
newly discovered module files in this run. These controlled local build receipts
are not hermetic or attested build provenance.

Original resource evidence was never repinned. The initial old-resource hash
mismatch is retained in [the prebuild record](attempts/prebuild-guard.json).
An earlier interrupted run is preserved under
[attempts/source-drift-during-accel](attempts/source-drift-during-accel/receipt.json).
Other `attempts/*.txt` files are development diagnostics, not final source-linked
qualification results.

Exact old Norito, lock, runner and contract bytes are retained as `.template`
files. [Source reconstruction](source-reconstruction.json) checks all 242 test,
243 supplemental and 242 earlier-attempt entries, using archived bytes only
when their original hash matches. No checkout file is rewritten:

```sh
python3.11 docs/validation/parliament_ballot_prover_lifecycle/verify_sources.py
```

## Reproduction

The [full runner](run_validation.py) executes the focused suite with source
checks before and after each command. Give it a new output/binary directory to
preserve these historical receipts:

```sh
python3.11 docs/validation/parliament_ballot_prover_lifecycle/run_validation.py \
  --output /tmp/parliament-lifecycle-new-evidence \
  --binary-dir /tmp/parliament-lifecycle-new-binaries
```

Its source identity is the checkout at that new run; it does not silently
restore or claim to remeasure an older source set. The separately preserved
[supplement runner](finish_validation.py) documents the remaining checks run
after the interrupted campaign. Existing deterministic fixtures are public
test material and must never serve as production credentials or randomness.
