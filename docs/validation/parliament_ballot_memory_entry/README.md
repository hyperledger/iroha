# Bounded in-memory verification entry

This separately built diagnostic implements the borrowed-input boundary in the
[resource proposal](../../../specs/parliament_ballot_resource_contract.md).
It moves regular-file retrieval and its error owners before charged verification.
The frozen original worker and all its evidence remain unchanged. No production
schema, Core/Torii dependency, profile selection or activation is introduced.

## Boundary and evidence

The supervisor stages at most 425,984 bytes and closes the file before calling
the synchronous entry. The caller retains that immutable owner through the
worker join. The request's private pointer and length come from the same borrow.
The worker reserves the actual length before enabling the arena and copying the
bytes; all worker-owned values are dropped before disabling it. Setup and file
staging failures spend no verification charge. The [code-adjacent contract](../../../crates/iroha_parliament_ballot_proof/examples/memory_entry/README.md)
states the one-shot process, concurrency, fatal-exit and native-runtime limits.

The [build receipt](build-receipt.json) records six successful locked release
commands: tests, strict all-target Clippy and build in each feature mode.
Each mode passes 16 Rust tests. All 2,019 guarded source files remained unchanged.
The isolated lock uses 121 packages whose non-diagnostic identities occur in the
1,149-package root lock. This is package-identity membership, not feature or
dependency-edge parity. Root manifests and locks were not changed by preparation.
The exact source transformation is retained in
[workspace.diff](generated-source/workspace.diff.template).

The [campaign report](campaign/report.json) and [raw cases](campaign/cases.jsonl)
retain **122 successful observations, 61 input pairs**, with 2,031 guarded inputs
unchanged. Both modes agree on input identity, outcome, stage and charge.

| Outcome | Observations |
| --- | ---: |
| Accepted | 16 |
| Codec or proof rejected | 50 |
| Admission refused | 38 |
| Explicit resource exhaustion | 16 |
| Staging input error | 2 |

Coverage includes both rows, registration and votes at 3/500/1,000 seats, late
invalid coefficients, truncation, impossible lengths, work/byte shortage, arena
exhaustion, a long path, FIFO, empty input and oversized regular file. A separate
425,985-byte caller slice bypasses file staging and supplies an equally large
byte budget. Both workers reject it at reservation with zero charge and zero
arena allocations, demonstrating the entry's independent cap check.

Returning worker reports show zero live arena bytes after cleanup. The largest
observed requested/block peaks are 6,565,341/7,211,136 bytes in both modes. The
fixed mapping is 43,089,920 bytes (41.09375 MiB): 32 MiB heap, 1 MiB metadata,
8 MiB supplied stack, 64 KiB control and two 16 KiB guard pages. Terminal
exhaustion reports do not establish destructor cleanup.

Twelve preparer tests and 20 campaign-checker tests pass; the latter includes
the final finite-JSON exponent-overflow regression. The combined
[51-test check](../parliament_ballot_b6/memory-driver-checks.json) includes the
19 normal-return tests; its earlier checker revision is identified separately
from the final [20-test check](campaign-helper-check.json). Diagnostic formatting
and the codec guard pass. Local peer review verified the lifetime, source
derivation and evidence bindings; see the [review receipt](review-receipt.json).

## Limits

These are finite diagnostic observations. The caller buffer and file retrieval
are excluded explicitly; the arena-owned copy is included. This does not prove
an all-input work/stack bound or account for every native, TLS, loader, panic or
exceptional allocation. The old worker's disassembly, stack graph and conditional
frontier classifications do not transfer to this changed executable. Neither
physical cost nor the named validator/phone baselines is qualified. The unrelated
current Core source-contract failure is retained in the combined check.

TODO: complete runtime and exceptional-path coverage, all-valid-input completion,
physical calibration and independent implementation review before claiming the
64 MiB requirement. `complete_workspace_certificate`, `physical_cost_calibrated`
and `profile_qualified` remain false. Production remains gated.

## Reproduction

Use a fresh work directory, output directory and binary directory; retain old
attempts. From the repository root, prepare with
`scripts/prepare_parliament_ballot_memory_entry.py --output <new-source-dir>`.
Resolve Cargo metadata for that manifest into `<new-output>/dependency-metadata.json`,
then run the preparer's `--check-lock` against the retained root lock template
and resolved isolated lock. The retained `build_worker.py.template` accepts
explicit `--root`, `--out`, `--work`, `--target` and `--binaries` paths and runs
both modes' tests, Clippy and builds. It does not kill timed-out build children.

Run `scripts/check_parliament_ballot_memory_entry.py` with explicit `--portable`,
`--accel`, `--build-receipt` and a fresh `--output`. The checker refuses changed
build sources, injected loader environments, incomplete evidence or mismatched
mode results. Failed runs retain completed observations. Binaries are identified
by hash in the receipt and remain outside this repository. No old receipt may
be repinned to a rebuilt binary.
