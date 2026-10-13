# Native endpoint probe

This is an experimental macOS diagnostic, separate from the frozen arena worker.
It observes 21 **named dynamic entry points** using fixed process-wide counters.
It neither measures live native bytes nor establishes complete native coverage,
a 64 MiB process ceiling, cryptographic qualification, or another platform's behavior.

The [C ABI](np_api.h) has one static state in [the dylib](np_interpose.c).
The host resolves and checks this API during setup. It must serialize marker API
calls, place `np_transition(0,1)` immediately before arena activation, and place
`np_transition(1,2)` after arena deactivation and ordinary cleanup. After join,
`np_snapshot` seals the observation and copies counters into caller-owned memory.
The state combines phase and in-flight hook count in one lock-free atomic word;
a boundary collision invalidates the evidence rather than waiting indefinitely
or dropping the other thread's events. No thread identity or TLS filter is used.

Snapshot permits three explicit endings: setup-only (unadmitted), charged-but-
incomplete (terminal failure), and completed-call teardown. Consumers must check
`phase_before_seal` and their required outcome. A valid snapshot of an incomplete
call is not evidence of successful verification. Post-seal native activity is
outside the observation. Setup starts when the interposer is effective; it does
not cover the process's entire loader/startup history. Snapshot calls and phase
markers are single-owner lifecycle operations, not concurrent control APIs.

Each counter records calls, requested-byte arguments and failure-sentinel results.
Realloc counts its new requested size; deallocation calls with a size argument
record that argument. `free` has no size argument. Nested public endpoints are
counted separately, so summing them double-counts possible underlying operations.
NULL from a zero-size allocator/realloc call is implementation-defined and need
not mean a semantic allocation failure. The probe does not access `errno`.
Counter overflow or a failed marker/snapshot makes the receipt invalid.

Hooks contain only fixed-state lock-free atomics and the original endpoint call:
no symbol lookup, allocation, TLS, formatting, backtrace or mutex. This is not a
wait-free timing claim. Clang is passed `-fno-builtin` to prevent source-level
allocation calls from being optimized into other endpoints or eliminated.
The loader record follows Apple's primary
[dyld interpose header](https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/include/mach-o/dyld-interposing.h).
The public Xcode SDK need not contain that header; this implementation declares
the two-pointer section record directly. Arm64e pointer authentication is rejected.
The current control campaign must identify its actual architecture and OS runtime;
successful compilation alone does not qualify x86_64 or a different macOS build.

Run focused controls in a new output directory, with Python 3.11+ and Xcode CLI:

```sh
python3.11 crates/iroha_parliament_ballot_proof/examples/native_probe/run_controls.py --output-dir /tmp/parliament-native-controls-fresh
```

The runner builds the dylib, a C consumer and internal counter tests. Each of the
21 endpoints has a fresh-process positive control; empty/outside intervals,
unadmitted/terminal phases and a failing mmap are separate controls. Seven
internal scenarios check overflow, products, ordering, boundary collision,
post-seal exclusion, nesting and four-thread process-wide counting. These test
counter mechanics and interception of the named calls. They do not test direct
Rust `System`, raw-pthread first-use TLS/destructor/thread-handle paths, routed
arena allocation, a panic subprocess or the actual verifier; the separate worker
adapter and supervisor own those controls. No proof/provider is warmed here.

The runner retains commands, raw stdout/stderr and original exits, selected SDK
declaration hashes, source/binary identities, and failures. SDK declarations are
not native implementation identities. A missing positive control fails the run.
Existing `DYLD_*` environment settings are rejected; the only added child setting
injects this freshly built dylib. Interposition changes loader/runtime behavior.

Known exclusions remain: hidden/internal entry points, zone function pointers,
direct syscalls/Mach traps, allocator metadata and caches, loader storage,
native TLS, unseen compiler/unwind paths, and any path absent from the corpus.
The imported endpoint list and zero observed calls cannot close these exclusions.
Production remains gated.
