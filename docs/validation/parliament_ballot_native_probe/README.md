# Native endpoint observation for the standalone ballot worker

This macOS experiment addresses one open part of the [resource
contract](../../../specs/parliament_ballot_resource_contract.md): verification
can cause allocations through Rust `System` or native runtime paths that bypass
the routed arena. It observes specified native calls and preserves failures. It
does **not** establish complete native allocation coverage, a live-byte bound,
stack sufficiency, the 64 MiB certificate, or profile qualification.

## Construction and source identity

The [preparation tool](../../../scripts/prepare_parliament_ballot_native_probe.py)
checks the four frozen resource-worker modules and derives an isolated diagnostic
crate. The generated workspace adds phase markers immediately before arena
activation and after ordinary verifier cleanup/deactivation, plus a bounded
terminal snapshot before the existing resource-failure exit. The original worker
sources and measured executables remain unchanged. `generated/` retains the
derived source, exact diff, manifest, lock and preparation receipt as templates.

The derived crate copies all root registry patches and resolves its own lock.
[Lock comparison](lock-comparison.json) finds no new dependency package identity
apart from the diagnostic crate. This membership check is not a claim of equal
dependency edges, enabled features or build output. Normal build metadata is
retained. The [build receipt](build-receipt.json) records 15 release tests per
mode, strict release Clippy over all diagnostic targets, both release builds,
their logs and hashes, and unchanged before/after source inventories. Its 1,993
source paths cover resolved Rust sources, manifests, build scripts and selected
build inputs; they are not a complete compiler, header or native-runtime
dependency proof. Failed preliminary attempts are kept under `attempts/`.

The [C implementation and method](../../../crates/iroha_parliament_ballot_proof/examples/native_probe/README.md)
interpose 21 named allocation, deallocation and mapping endpoints. The
[C control receipt](c-controls/receipt.json) records a positive control for every
endpoint, five other interval/failure controls, and seven internal counter and
concurrency scenarios. Six Python receipt tests pass in the separate
[focused checks](final-checks.json). The compiled hook imports are limited to
the forwarded endpoints. This is evidence about those entry points on the
recorded machine, not every path through its allocators.

## Interval and report semantics

One process-wide state contains the phase and number of in-flight calls. Entry
captures a phase atomically; a marker or seal encountering an in-flight call
invalidates the observation. Hooks use fixed counters and lock-free atomics,
without allocating, formatting, using TLS, resolving symbols or taking a mutex.
The host resolves the observer API once and verifies that all marker/snapshot
calls use the same state. No state address is persisted.

The three counted phases are setup, charged verification, and teardown. Setup
starts when injection becomes effective and excludes earlier loader history.
Ordinary observations seal after worker join and TLS destruction. Unadmitted
inputs seal directly from setup. Arena exhaustion seals from the charged phase
and emits a fixed-stack-buffer terminal report; it remains an incomplete call,
without a runtime image inventory in that report. A panic or signal with no
snapshot remains missing evidence, never a zero count. Post-seal activity is
outside the observation.

Counters contain endpoint call counts, requested-byte arguments and failure
sentinels. Nested wrappers can count one underlying operation more than once;
realloc records its requested new size and free has no size. These are neither
unique allocation counts nor live or peak native bytes. Zero-size null results
need not indicate allocation failure. The injected library itself changes the
runtime and therefore cannot supply uninstrumented timing qualification.

The [supervisor](../../../scripts/check_parliament_ballot_native_probe.py)
requires fresh-process empty, routed-arena, direct-System, first-thread-handle,
first-TLS and panic controls in both feature modes before running existing proof
fixtures. Missing required native-positive observations stop the campaign before
proof measurements. Each started and completed child is journaled with original
exit status and raw output; a failed or interrupted campaign keeps its evidence.
Inherited `DYLD_*` settings are refused, and injection is confined to its children.

## Recorded campaign

The [campaign report](campaign/report.json), [aggregate receipt](supervisor-receipt.json)
and [append-only child journal](campaign/cases.jsonl)
retain **134 passing observations: 14 controls and 120 proof cases**, with no
guarded input changes. Both feature modes observe three charged endpoint calls
for direct `System`, four for the first thread handle, and three for first TLS
use. Empty and routed-arena controls observe none; the routed allocation still
uses the arena. Each deliberate panic terminates with SIGABRT and no snapshot,
as expected. Missing-interposer controls refuse observation.

The proof cases include 66 ordinary completed intervals, 38 unadmitted cases and
16 arena-exhaustion terminal intervals. Every charged interval has zero observed
calls to the 21 named endpoints. The unadmitted cases have no charged interval;
the terminal cases establish only their observed incomplete prefix. The original
outcomes and reservation semantics pass validation in both modes. These finite
observations do not rule out hidden/native allocations or justify a zero-byte
allowance for all executions.

The [final focused checks](final-checks.json) pass 60 Python tests and three
subtests, diagnostic Rust formatting, and the codec guard. The same receipt
separately retains the repository-wide formatting differences in unrelated
SCCP/Mochi files and the existing Core start-phase source-contract failure. No
full-workspace test or formatting pass is claimed.

## Installed runtime and remaining work

The [runtime identity helper](../../../crates/iroha_parliament_ballot_proof/examples/native_probe/runtime_identity.rs)
captures the actual process's dyld shared-cache UUID and loaded image paths and
Mach-O UUIDs before the worker starts. Its three tests pass as part of each
15-test diagnostic suite. The separate [installed-runtime record](runtime-identity.json)
retains the command output and SDK/private-header identity used during research.
UUIDs identify the installed binaries; they do not connect an Apple source tag
to those binaries or establish allocation behavior. Ordinary worker reports must
identify the supplied executable and interposer and the installed malloc,
pthread and kernel libraries.

TODO: resolve hidden/internal entry points, zone function pointers, direct
syscalls and Mach traps, allocator metadata/caches, loader storage, native TLS,
unseen compiler/unwind paths, and executions outside the finite corpus. Complete
allocation correspondence and justified native/recursive stack bounds remain
separate obligations. No finite zero-call result can discharge them. Named
hardware, physical calibration and independent review remain required, and
production stays gated.
