# Shared qualification command dispatch

The disposable iOS bridge privately includes the shared qualification module and
calls its existing `run` function. Previously only the standalone CLI dispatched
the `malformed` command, so the bridge compiled an unreachable malformed runner
and strict Clippy rejected ten dead-code diagnostics.

The existing leading-`malformed` dispatch now lives in the shared runner. The
CLI calls that entry point once, and the malformed submodule is private. The
malformed implementation, its tests, and the bridge source/manifest/lock remain
byte-identical. No public API, feature switch or lint suppression was added.
Two new shared tests cover exact help bytes and flushing, option errors before
work, one-prefix dispatch, ordinary option values, and writer-error propagation.

The [initial owner receipt](initial/owner-receipt.json) retains the two bridge
Clippy exits 101 and their ten dead-code diagnostics. Its earlier fuzz passes
remain historical context. The [final owner receipt](final/owner-receipt.json)
retains successful portable and accelerated strict Clippy checks (0.63 and 0.48
seconds) and **all 17 host/shared tests passing in each mode**, including both new
dispatch regressions (29.46 and 18.13 seconds elapsed for the commands). Each mode
uses `--locked --offline`; Clippy includes all targets with `-D warnings`, and
tests run serially with zero ignored or filtered tests. All 69 watched inputs
were identical before/after every command and at capture. Exact command logs
remain under `initial/` and `final/`.

This captures completed owner validation without rerunning it. The watched
inputs are not an exhaustive dependency/toolchain trace; compiler/runtime and
concurrent-writer-free observation remain host premises.

The [source receipt](source-freeze.json) and [patch](shared-dispatch.patch) record
the four changed files and the formatting command. The
[source map](captured-sources.json) authenticates their exact before/after bytes,
five unchanged malformed/bridge inputs, and all retained validation outputs.
The original custody and [overlap record](pre-edit.json) distinguish three
changed paths in the prior 3,392-input aggregate (shared module, CLI and
qualification documentation) from zero overlap with the recorded 402-input source
CLI and the 411-input complete Python source-contract regression capture.
The new shared tests were not among those three prior aggregate pins.

Earlier observations and frozen evidence remain identified by their original
sources. This harness dispatch change does not transfer measured resource or
physical-device qualification to a new binary. The new host checks concern
ordinary host compilation/tests of the copied bridge, not iPhone execution,
cryptographic review, the full B6 resource vector or production readiness.
Production remains gated.

The [capture recipe](capture.py.template) verifies source and validation identities
before retaining them. The [freeze review](freeze-review.json) and
[manifest](SHA256SUMS) bind this bundle without repinning earlier evidence.
