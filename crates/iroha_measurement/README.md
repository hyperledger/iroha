# Phase and resource measurement

`iroha_measurement` owns the shared phase tree and resource observation record
for proof, verification, native and SDK flows. It sits below the proof, Core
and data-model crates: its only dependencies are `iroha_allocation`, the Norito
codec and the C library, and `tests/layering.rs` fails if that changes.

## Measurements never affect validity

Nothing in this crate may be consulted by validation code. Validity, gas,
effects and certified roots never depend on a measurement, a target or a local
limit. Every recording method returns `()` or an opaque guard, so instrumented
code has nothing to branch on; a finished record leaves only through the
`RecordSink` given to `Session::begin`. Two source-checked guards fail on
drift:

- `tests/public_api.rs` compares every `pub fn` and `pub` field of
  `src/recorder.rs` with a reviewed list, so a new method that returns a
  readable value or accepts borrowed text or bytes is refused.
- `fixtures/consumers.json` lists every workspace member that depends on the
  recorder, the dependency table it uses and every source file that names it.
  `tests/layering.rs` takes the members from the workspace manifest and scans
  their sources. Every consumer today uses a dev-dependency, so code compiled
  into a node cannot reach the recorder; a renamed dependency is refused.

## What one record contains

One `Session` measures one root flow and emits one `MeasurementRecord`:

| Section | Content | Classification |
|---|---|---|
| `identity` | workload, flow, emitter, source commit and dirty digest, artifact, profile, configuration, named hardware, cache policy | — |
| `phase_tree` | per phase: calls, completed, interrupted, unwound, truncated; inclusive and exclusive wall time, opening-thread CPU and process-window CPU; peak concurrent children; active threads; system load at boundaries; allocations and live-buffer high-water | `measured` |
| `byte_counters` | named ciphertext, key, proof, transaction and public-input sizes | `measured` |
| `work_counters` | named public counts of completed work: calls, columns, rows | `measured` |
| `allocations` | scoped counters and observed `iroha_allocation` budgets | `measured` |
| `process` | process CPU, kernel peak RSS, load, thermal state | `measured` |
| `scheduling` | declared worker counts and their provenance | `local_scheduling` |
| `address_space` | the `RLIMIT_AS` pair actually in force | `local_scheduling` |
| `declared` | caller-declared projections, engineering targets, consensus bounds and local limits, each with provenance | per entry, never `measured` |
| `failures` | raw failures as static stage and code labels | `measured` |
| `recorder` | overflow, stale-guard and clock-anomaly counts | `measured` |

Exclusive wall time is inclusive time minus the exact union of the direct
children's intervals, computed per call, so parallel children are never
subtracted twice. Process-window CPU uses the process CPU clock over the same
windows; it is not CPU uniquely attributable to a phase. A deterministic
consensus bound can be declared only with protocol-constant or committed-State
provenance.

The unattributed time of a record is its root's exclusive wall time.
`MeasurementRecord::findings` rejects a record whose unattributed share exceeds
1%, whose identity is unbound, whose run did not succeed, or whose accounting
does not hold exactly. A rejected or failed run is still a record: failures are
retained, never dropped.

The 1% rule bounds only the time outside every phase, so a root with a single
wrapper phase passes it. `MeasurementRecord::largest_undivided_phase` reports
the phase with the most exclusive time and its share of the root, and the
harness prints it for every record. A consumer that needs finer attribution
states a bound with `--max-undivided-phase-ppm`.

## Public-only recording interface

After `Session::begin` the recorder accepts only `&'static str` labels from a
closed grammar, enumerated kinds and unsigned integers, and identity text
outside its grammar is replaced before it is recorded. Witness bytes, keys,
hidden programs and formatted error text are therefore not attached by
accident. This is not a sandbox against deliberate leaking: `String::leak`
yields a static string, a 96-byte label can spell a short secret in
hexadecimal, and a hand-built `MeasurementRecord` can be given to any sink.
Instrumented code must record only static names and public geometry. The
session's own buffers are overwritten and released on success, on an error
return and on unwind.

Thermal state is read from the thermal-pressure notification on macOS and
iOS, and from the thermal sysfs class on Linux and Android. The iOS and
Android probes are compile-checked only; Android usually denies an
application the read, so a device run takes its thermal state from the SDK
emitter. The harness rejects a record without thermal state when it is run
with `--require-thermal-state`.

## One schema for every emitter

The record is Norito-encoded and has a Norito JSON view with the same fields.
`fixtures/record_schema_v1.json` is generated from the Rust schema and lists
every key, type and enumerated word; `fixtures/measurement_record_v1.json` and
`.norito.hex` are the golden record; `fixtures/record_mutations_v1.json` lists
mutations with the finding codes every validator must report. SDK emitters in
other languages emit the JSON view and are checked against these files, as
`scripts/zk_resource_harness.py` already is. Regenerate the fixtures after an
intentional schema change with
`cargo test -p iroha_measurement --lib -- --ignored regenerate_tracked_fixtures`.

## Harness

`scripts/zk_resource_harness.py run` starts one executable, pins it by SHA-256,
samples it with the existing native process observer, collects the records it
writes to `IROHA_MEASUREMENT_OUTPUT_DIR`, and writes one report under the
ignored `dist/zk-resource-harness/`. The run is accepted only when the command
succeeded, the process observation did not fail, and every record has no
finding. Runs are never overwritten or deleted.

What the report retains is public:

- The command's standard output and standard error are counted and hashed,
  not stored, because a prover that panics prints witness-dependent values.
  `--retain-output-tail-bytes` stores a bounded tail and is unsafe for a
  workload that handles private data.
- The argument vector is recorded as a digest. `--record-arguments` stores it
  verbatim; the arguments must then be public.
- `--hardware`, `--profile`, `--config` and `--cache-policy` are asserted by
  the operator. The report carries the observed host facts (system, release,
  machine, model, CPU, logical CPUs, physical memory) beside the asserted
  hardware name. The harness neither clears nor checks caches.

Checks beyond the record schema:

- A record's identity must equal the harness context, its process identifier
  must be the observed child, and its CPU and peak RSS must not exceed the
  kernel's totals for that child.
- With `--address-space-limit-bytes` the run is rejected unless the platform
  applied the limit and every record observed exactly that soft and hard
  limit. The report's `process.address_space` states the limit in force; on
  Linux it also carries the kernel's own record of the child. Darwin refuses
  `RLIMIT_AS`, so there the request produces a retained, rejected run.
- A Norito file without its JSON view, and a native emitter's JSON view
  without its Norito file, are reported as a half-written record.
- `--require-thermal-state` rejects a record without thermal state (device
  runs); `--max-undivided-phase-ppm` rejects a tree whose largest undivided
  phase holds more than the stated share of the root.
- A command that exits before two samples could be taken is judged on the
  kernel's exact totals. A running image other than the pinned executable is
  an identity failure.

`salvage` reports whether an earlier run is unchanged evidence for the current
source, artifact, profile, configuration and hardware. It does not trust the
manifest for the verdict or the scope: the report must agree with the
manifest, every record is decoded and judged again, the derived verdict must
be the one the report states, and each record's own identity must equal the
scope. `salvage --manifest-sha256` requires the digest retained from the original
`run`; a missing external pin always refuses. The reader reproduces the original
requirements before checking separately requested consumer constraints. It
returns the same held-descriptor bytes it verified, so consumers must not reopen
those paths. The manifest is not signed and the harness creates no signing or
qualification authority.

The admitted child inventory contains only public records. Unknown files remain
rejected workload state and are excluded from the evidence manifest. The harness
provides no filesystem sandbox or private-data clearing guarantee; reviewed
emitters own their public-only output contract.

```sh
cargo test -p iroha_core_privacy --features fastpq-replay-measurement \
    --test fastpq_phase_tree_measurement --no-run
python3 scripts/zk_resource_harness.py run \
    --hardware <reference-hardware-record> --profile <profile> --config <config> \
    --cache-policy warm --record-arguments -- <test-binary> --exact \
    eight_row_transfer_prove_and_verify_have_complete_phase_trees --nocapture
```

That workload is the transparent FASTPQ replay prover (a `fastpq_prover`
developer tool) at public-call granularity: one phase holds almost all of the
proving root, and the report says so. Backend-internal phases and the complete
X509 prover run, whose current top-level phases leave more than 1%
unattributed, belong to their consumer tasks.

Validate with `cargo test -p iroha_measurement` and
`python3 -m pytest scripts/tests/zk_resource_harness_test.py`.

## Rust SDK diagnostic flow

`crates/iroha/tests/sdk_phase_tree_measurement.rs` exercises the actual immutable
`AccountClient` through transaction preparation, signing, canonical frame
encoding, complete canonical decoding and signature verification. It emits the
same `FlowKind::Sdk` record through the existing recorder and original harness.
The recorder is a dev-dependency of this explicit integration target; shipping
SDK code gains no recorder dependency. The client uses an existing public test
key and makes no HTTP request or ledger admission.

The main workload performs 128 actual transactions at public-call granularity.
Its scoped allocation counter covers only the canonical frame vectors it owns,
using their actual capacities, and does not claim all SDK allocations. The
record reports process observations and its largest undivided phase normally;
no timing or resource threshold can change an SDK result. The controls compare
identical chosen-payload signatures with and without recording, retain an
actual wrong-authority signing failure, and retain a test unwind before another
independent successful call. Both Norito records and their JSON views are
round-tripped through the shared schema.

```sh
cargo test --offline --locked -p iroha_measurement --test layering --test public_api
cargo test --offline --locked -p iroha --test sdk_phase_tree_measurement
cargo test --offline --locked -p iroha --test sdk_phase_tree_measurement \
    --no-run --message-format=json-render-diagnostics
python3 scripts/zk_resource_harness.py run \
    --hardware <reference-hardware-record> --profile <actual-profile> \
    --config sdk.prepare-sign-frame.128 --cache-policy warm -- \
    <exact-cargo-test-artifact> --exact \
    actual_sdk_prepare_sign_and_canonical_frame_emit_shared_records --nocapture
```

Run `actual_sdk_error_is_returned_and_failed_record_is_retained` and
`sdk_unwind_is_retained_and_next_actual_call_remains_usable` separately through
the same harness to retain intentional rejected records; a passing Rust test
for these controls does not make the measured failed flow acceptable. Do not
combine them with the success workload when qualifying a successful run. Keep
the manifest digest printed by each original harness invocation and replay it
with the same pinned artifact and source.

TODO: This is one Rust SDK flow. It does not complete the six SDK delivery
surfaces (Rust, Kotlin/Java/Android, Swift, JavaScript, Python and C#), other-language emitters, SDK device thermal adapters, physical-device
runs or HTTP/ledger integration. Those ordinary implementation and execution
gaps remain separate from this diagnostic target's component qualification.
