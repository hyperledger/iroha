# Native runtime allocation audit

This read-only audit found no direct `System` or native heap allocation in the
traced ordinary cold verifier success/rejection path. It does **not** establish
complete native allocation coverage or a whole-process memory ceiling.
`complete_workspace_certificate` and `profile_qualified` remain false. No new
build, verification campaign, phase marker or interposer was run for this audit.

[The machine-readable receipt](native-runtime-audit.json) records source hashes,
call chains, existing executable imports and the remaining obligations. Its 85
reviewed repository files match the [frozen build](build-receipt.json); both
inspected executable hashes also match. This is a source review, not a complete
machine-code reachability analysis.

## Source identity

- Rust 1.93.1, commit `01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`:
  all 16 reviewed upstream source files match the code extracted from the
  installed rustdoc HTML byte-for-byte. The receipt pins both raw code and HTML.
- The relevant registry packages are `cpufeatures 0.2.17`, `cipher 0.4.4`,
  `keccak 0.1.6`, `zeroize 1.8.2` and `libc 0.2.186`; package checksums,
  local source-file hashes and available VCS identities are recorded. Patched
  `vendor/aes` sources and manifests are part of the repository source pin.
- The local SDK `pthread/pthread.h` hash matches the build receipt. It supplies
  ABI declarations, not the implementation of the loaded native runtime.
- Apple's `libpthread-539` resolves to
  `42d026df5b07825070f60134b980a1ec2552dfee`; `dyld-1378` resolves to
  `fd8d0c4d52320ebf64db34f3cb280310d905c5ae`. The receipt hashes the inspected
  immutable source files. **Neither tag is proved to be the source of the
  installed macOS 27.0.1, build 26A434, runtime.** The Rust `libc` package pins
  bindings, not Apple's allocator, loader or pthread binaries.

## Ordinary call chain and boundary

The example's `workspace::execute` opens the path with `O_NONBLOCK`, checks its
regular-file metadata and reserves the budget before setting `ACTIVE`. The
charged interval then includes the bounded input `Vec`, exact read and
trailing-byte check, `Reservation::verify`, fixed-size outcome classification,
and destruction of the input, typed statement, verifier buffers and file. The
worker clears `ACTIVE` after `execute` returns. Native thread setup/teardown and
JSON reporting sit outside this interval.

| Stage | Source-backed finding | Remaining obligation |
| --- | --- | --- |
| Cold entry | `budget.rs:188–222`: `verify_cold` builds a profile, decodes the record and statement, then calls the ordinary registration/vote verifier once. | The test-record boundary is not a production wire decoder. |
| Backend | `proof.rs:670–776`: decode, reconstruct VOLE, hash the transcript and run QuickSilver; verification does not grind. Runtime CRT tables are embedded/borrowed. Owned buffers use default `Vec`/`Box` allocations routed to the arena. | No exhaustive machine-code proof that every reachable operation uses that route. |
| AES | `prg.rs:153–199` owns a routed provider `Box`. `vendor/aes/src/autodetect.rs` requests only `aes`. Pinned `cpufeatures` stores its cache in a static atomic; Apple's ARM64 `aes` branch returns `true`, without `sysctlbyname`. x86 uses CPUID. | Linux/Android ARM64 detection calls `getauxval`; those native runtimes need their own source/runtime pin and review. |
| Input/errors | Pinned `std::io::default_read_exact` loops over `read`. OS errors use the scalar `Repr::new_os`; EOF uses a static error. These paths do not construct a custom boxed error. | Native `read`, error-location access and loader first-use behavior remain external. |
| Cleanup | Pinned `OwnedFd::drop` calls native `close`; ordinary verifier error classification does not format error messages. | Native `close` and exceptional destruction/runtime behavior remain external. |

The [pinned Rust allocator documentation](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/alloc.rs#L56)
explicitly allows internal direct `System` calls. On Unix,
[`System`](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/sys/alloc/unix.rs)
ultimately uses native allocation functions; the global arena cannot intercept
these calls merely by implementing `GlobalAlloc`.

## Conditional bypasses and excluded infrastructure

These are concrete mechanisms, **not observations that an ordinary proof
invoked them**:

- [`Thread::new`](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/thread/thread.rs#L85)
  creates `Arc<Inner, System>`. The raw pthread worker avoids Rust thread
  construction; no ordinary verifier call to `thread::current` was found.
- [TLS destructor bookkeeping](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/sys/thread_local/destructors/list.rs)
  uses `Vec<..., System>`. Apple's Rust guard calls `_tlv_atexit`. Native TLS
  storage and registration are separate from the routed Rust heap.
- [`panic_with_hook`](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/std/src/panicking.rs#L787)
  updates TLS panic state before invoking a hook. The default hook can enter
  backtrace/output machinery. Installing a custom hook alone therefore would
  not prove allocation-free panic handling. No input-triggered panic defect
  was demonstrated by this audit.

Apple's pinned
[`_pthread_allocate`](https://github.com/apple-oss-distributions/libpthread/blob/42d026df5b07825070f60134b980a1ec2552dfee/src/pthread.c#L548)
allocates a separate `PTHREAD_SIZE` mapping even with a supplied stack, using
`mach_vm_map` with an allocation fallback. This is native thread infrastructure
created before `ACTIVE`, **outside the example's 64KiB control partition**.
That partition contains application/arena control objects; it does not account
for pthread-owned metadata, native TLS or loader state. No installed-runtime
byte bound for that infrastructure is established here.

The receipt retains `nm -u` output for both frozen executables. Native allocator,
TLS bootstrap/registration, unwind/backtrace and dispatch semaphore imports are
present. An import proves neither ordinary-path reachability nor an allocation
during the charged interval. Conversely, a missing import would not exclude
allocation hidden inside a library or performed through another entry point.

## Proposed diagnostic, pending implementation review

The useful next experiment is a **named-endpoint observation**, not a certificate:

1. Build a separately identified diagnostic revision with explicit begin/end
   markers matching `ACTIVE`, including input read and ordinary cleanup. Preserve
   the current evidence unchanged. Record setup and teardown separately.
2. Review a small C interposer using Apple's
   [`DYLD_INTERPOSE` definition](https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/include/mach-o/dyld-interposing.h).
   Hooks use fixed static atomic state only: no allocation, formatting, TLS,
   mutexes, backtraces or symbol lookup inside hooks. Validate that atomics are
   lock-free; counter overflow or incomplete interception invalidates evidence.
3. Initially observe explicit allocator endpoints (`malloc`, `calloc`, `realloc`,
   `posix_memalign`, `aligned_alloc` and selected documented `malloc_zone_*`
   allocation entry points). Observe `mmap` and selected Mach VM allocation/map
   endpoints separately. Name every installed hook in the receipt. Keep endpoint
   events separate; nested wrappers must not be summed as distinct live bytes.
4. Use process-wide phase observations conservatively. Do not discard concurrent
   native activity solely because it is outside the worker thread. Resolve any
   required symbols before activation, record the resulting setup cost, and do
   not pre-run proof verification or its provider under the label “cold”.
5. Require fresh-process positive controls for direct Rust `System` allocation,
   libc allocation, aligned allocation, each claimed zone/VM endpoint, and first
   Rust TLS/destructor/thread-handle access on a raw pthread. Add negative
   controls: an empty interval, routed `Box` allocation, and calls immediately
   outside the interval. Missing a required positive observation fails the
   diagnostic. A subprocess panic control must remain a runtime failure.
6. Only after those controls pass, run valid, early-invalid, late-invalid and
   exhausted cold cases for both modes with source/binary/input/runtime hashes.
   Retain event data and original child exits. Any future fail-on-observed-native-
   allocation mode needs separate review and a dedicated resource/runtime result;
   it must not turn native failure into invalid-proof rejection.

Known blind spots include hidden/internal allocator entry points, zone function
pointers, direct syscalls/Mach traps, native allocator metadata, loader-managed
storage, compiler/unwind runtime calls, allocations outside the marked interval,
and paths absent from the finite corpus. Interposition itself changes loader and
runtime behavior. Zero observed events cannot close these gaps, establish a
whole-process RSS ceiling, or qualify another OS/build. No native hook experiment
has been implemented or executed by this audit.
