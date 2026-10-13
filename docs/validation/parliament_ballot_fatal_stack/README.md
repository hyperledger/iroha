# Fatal-control image stack diagnostic

Status, 2026-10-13: source-bound compiled diagnostic; complete stack and workspace
certificates remain false. Production remains gated.

These fresh [portable](portable.json) and [accelerated](accel.json) captures refer
to the fatal-control binaries in the [successful build receipt](../parliament_ballot_fatal_control/build/build-receipt.json).
They do not transfer results from the earlier file-reading worker. No executable
was rebuilt or run. The [capture receipt](receipt.json) binds 2,039 unchanged
inputs, including all 2,021 build sources, the binaries, build logs/metadata,
loaded validation helpers, analyzer/tests and LLVM tool. The prior phase
[manifest](../parliament_ballot_b6/pre-fatal-stack-mask-artifact-manifest.sha256)
pins the successful build receipt before this analyzer change. Its historical
source hashes are preserved, not repinned.

## Narrow decoder change

The previous analyzer stopped on the new shared-slot `stlur x9, [x8, #0x8]`:
portable worker `0x100000fd8` / fatal routine `0x100005c68`, accelerated worker
`0x100000fdc` / fatal routine `0x100005c6c`. The current
[analyzer snapshot](parliament_ballot_stack_audit.py.template) accepts `STLUR`
as a store with no control transfer or base writeback. It checks the W/X source,
X/SP base and signed nine-bit immediate, and retains ordinary stack/red-zone
checks. No unknown instruction is assigned a zero cost.

This interpretation follows Arm's official [A64 instruction reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85),
printed pages 891–892 (PDF pages 894–895): FEAT_LRCPC2, unscaled 32/64-bit
store with an offset from -256 to 255. LLVM's corresponding
[compiler implementation and fixtures](https://lists.llvm.org/pipermail/llvm-commits/Week-of-Mon-20230925/1216812.html)
provide an additional primary-source spelling check. The instruction does not
bound memory-system latency or prove ownership of the addressed page.

All **40 focused tests** pass; [test output](tests.txt) and
[test snapshot](parliament_ballot_stack_audit_test.py.template) are retained.
The 14 additional cases cover store width/base/offset, preservation of SP and
FP, malformed/writeback forms, red-zone checks and both branches of the actual
relocated fatal routine. Its native `_exit` and possible function fallthrough
remain explicit frontiers.

## Current compiled results

| Mode | Text instructions | Functions | Entry-CFG instructions visited | Worker local frame | Resolved worker region, including red zone | Complete worker stack bound |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Portable | 93,768 | 896 | 86,453 | 176 B | 15,984 B | Unknown |
| Accelerated | 91,554 | 894 | 84,285 | 176 B | 13,440 B | Unknown |

These finite region figures stop descent at opaque functions/components and
exclude their unseen stack use. They assume ordinary ARM64 SP/FP preservation,
ABI-conforming memory accesses and a 128-byte Apple red zone, added once along
a nested path. They are not measurements or complete all-input stack bounds.
Both worker functions have 198 instructions visited from their ordinary entry
out of 204 decoded instructions. Six trailing instructions without a discovered
ordinary-entry path are not counted as analyzed exception/unwind coverage.

The separately resolved local frames are 176 bytes for `workspace::worker`,
16 for `workspace::exhausted`, 16 for `fatal::exhausted` and zero for
`Arena::allocate`, in both images. The fatal body has all 15 instructions
visited and no frame error; its region is 144 bytes including the red zone.
Its call to native `_exit` remains an unknown callee, and the analyzer does not
silently discard the continuation if that native call were to return. These
local figures do not establish a bound for the allocator, verifier or runtime
invoked by the worker.

## Remaining gaps, without inferred pruning

The reachable worker graphs retain these exact frontier-site counts:

| Kind | Portable | Accelerated |
| --- | ---: | ---: |
| Native edge | 142 | 138 |
| Indirect call | 38 | 38 |
| Indirect branch | 4 | 4 |
| Function fallthrough | 82 | 82 |
| Exceptional terminal | 39 | 39 |
| Unsupported instruction | 2 | 0 |

Both graphs also contain one opaque positive-weight recursive component of
63 functions, including allocation-error/panic/runtime paths. All addresses,
caller depths, targets and component members are retained in the JSON. No
native, indirect, exceptional or recursive continuation has been arbitrarily
pruned. The old image's separate predicate/no-return evidence is not reused as
an assertion about this image.

The only reported frame-analysis errors in the whole portable image are:

- `aes::soft::fixslice::aes128_key_schedule`, `0x1000249e0`:
  unsupported `eon x10, x12, x10`, at an 816-byte caller depth.
- `aes::soft::fixslice::aes256_key_schedule`, `0x100025c74`:
  unsupported `eon x11, x12, x11`, at a 1,040-byte caller depth.

The whole accelerated image has no reported frame-analysis errors. This alone
does not close its opaque call frontiers. Both workers themselves retain seven
native sites (`pthread_self`, the two stack queries, `_exit`, `malloc`, `bzero`,
`memcpy`) and a `brk` site; their source feasibility and pre/post-admission scope
are not guessed from the compiled graph. The full reachable graphs additionally
include panic/unwind/TLS and synchronization runtime possibilities.

The smallest substantive next bound is an adapter argument with
`Reservation::verify` explicitly opaque: fixed admission/control publication,
one bounded input copy and its ownership, buddy-tree traversal under the
private uncontended-arena premise, and the fatal terminal path. It can use
ordinary compiler/ABI/Rust ownership assumptions plus named `memcpy`, `bzero`
and `_exit` contracts; it must state the remaining native costs. That argument
would close a named adapter boundary, not all-input verifier work/stack or the
complete 64 MiB certificate. The two `EON` decoder gaps can likewise be handled
in a later tested change without pretending that this resolves the runtime
frontiers.

## Reproduction

With the retained sources/binaries and Xcode tools available, from the repository
root, choose a new output directory:

```sh
.venv/bin/python docs/validation/parliament_ballot_fatal_stack/capture.py.template \
  --root "$PWD" --output /private/tmp/parliament-fatal-stack-recapture
```

The retained driver refuses output reuse, checks the frozen receipt against its
prior manifest, validates the complete required source scope and all six Cargo
build modes, captures disassembly/function starts/native stubs/unwind metadata,
and reruns the focused analyzer tests. Drift or a command failure produces a
failed receipt. The manifest covers the local evidence snapshots; older frozen
artifacts are unchanged.

Independent read-only engineering review reran all 40 tests, verified all 2,039
current input hashes and both result/test-log hashes, and reviewed the decoder,
receipt pin, loaded-helper identities and stated limitations. It found no
remaining concrete defect within this diagnostic's scope. This is local peer
review, not the required independent cryptographic or unsafe-code review.
