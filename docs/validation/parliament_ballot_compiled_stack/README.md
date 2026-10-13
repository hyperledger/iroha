# Compiled ARM64 stack diagnostic

This diagnostic analyzes the retained portable and accelerated macOS resource
workers without rebuilding or executing them. **It does not establish that the
complete verifier fits its supplied 8 MiB stack.** The complete stack bound,
workspace certificate and profile qualification remain unset/false.
The full [portable](portable.json) and [accelerated](accel.json) reports retain
function-level results and all unresolved frontiers.

The [receipt](receipt.json) links the exact binaries to the original
[normal-metadata build](../parliament_ballot_resource_contract/build-receipt.json)
and its frozen source manifest. This is the prior controlled build linkage, not
an attested or newly reproduced build. Later shared-checkout changes do not
replace those source identities. The retained
[source reconstruction](../parliament_ballot_resource_contract/post-campaign-source-change/receipt.json)
documents recovery of the old resource source where it subsequently changed.

| Retained mode | Text instructions | Functions | Worker local SP decrement | Resolved direct region, including red zone | Complete stack bound |
| --- | ---: | ---: | ---: | ---: | --- |
| Portable | 92,628 | 925 | 336 B | 15,984 B | Unknown |
| Accelerated | 90,551 | 923 | 336 B | 13,232 B | Unknown |

The finite figures bound only the analyzed direct-call region, stopping descent
at opaque boundaries. They exclude unseen callees/targets of indirect/native calls,
unsupported functions and positive-weight recursive components. They are neither
measured high-water marks nor complete ordinary-call bounds. After opaque calls,
the analysis may resume the caller using ABI preservation of SP/FP. It keeps
both outcomes of conditional branches, including error/panic branches; its
maximum path need not be feasible for a particular proof or security parameter.
The accelerated maximum path, for example, reaches an AES bounds-check panic
boundary. No normal-path feasibility claim is attached to that path.

## Method and failures kept visible

The [analyzer](../../../scripts/parliament_ballot_stack_audit.py) reads
[`llvm-objdump`](https://llvm.org/docs/CommandGuide/llvm-objdump.html) disassembly,
Mach-O `LC_FUNCTION_STARTS` and the imported-stub table. Its CFG tracks constant
SP changes and known frame-pointer offsets. Calls contribute the caller's live
SP decrement plus the callee region; explicit tail branches reuse the current
stack. Zero-depth tail cycles can be collapsed. Positive-weight recursion is
opaque, with no invented depth. A fallthrough across a function boundary is also
opaque: the tool does not assume that a no-return call returns into the next
function's bytes, or infer no-return behavior from a function name.

Unknown instructions, register-sized SP changes, missing targets/instructions,
misaligned SP, inconsistent stack joins and unproved stack-probe loops fail
closed, as do direct SP/known-FP accesses below the assumed frame/red zone. The
two retained images have no such reported frame-analysis errors;
that does not close their many call frontiers. Each image's reachable worker
region has one 69-function recursive component containing allocation failure
and panic/runtime paths. Seven indirect sites in backend PRG/provider/drop paths
also remain unresolved. The JSON reports preserve every address, caller depth,
name, frontier and component; these are static possibilities, not observed calls.
The function-entry CFGs visit 85,655 portable and 83,567 accelerated instructions;
decoded text after unresolved branches or without an ordinary entry path is
not silently counted as analyzed coverage.

The analysis assumes ordinary ARM64 ABI preservation of SP/FP and ABI-conforming
stack memory accesses. It reserves the full
[Apple ARM64 128-byte red zone](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)
at each local maximum, adding it once along a nested path. It does not prove
stack-pointer aliases stay within their frames, resolve native or vtable code,
or bound signal, exception, unwinding, loader, pthread or TLS stack behavior.
It is specific to these macOS ARM64 binaries; it says nothing about x86, iOS or
Android compiled frames. Unwind metadata is archived for inspection but is not
used as a substitute for local SP depth. LLVM's
[stack-size metadata](https://llvm.org/docs/CodeGenerator.html#emitting-function-stack-size-information)
likewise describes prologue allocation and omits functions with dynamic
allocation, so a metadata-only rebuild would not close the unresolved calls.

## Reproduction and validation

From the repository root, with the retained binaries and Xcode LLVM tools:

```sh
python3.11 scripts/parliament_ballot_stack_audit.py /tmp/parliament-resource-contract/resource-portable --raw-dir /tmp/stack-portable --output /tmp/stack-portable.json
python3.11 scripts/parliament_ballot_stack_audit.py /tmp/parliament-resource-contract/resource-accel --raw-dir /tmp/stack-accel --output /tmp/stack-accel.json
python3.11 -m pytest -q scripts/tests/parliament_ballot_stack_audit_test.py
```

All 26 focused tests passed. They cover the actual 2,032-byte reservation prologue, multiple
balanced epilogues, pre/post-indexed SP writes, FP restoration, shifted
immediates, alternative frame depths, tail reuse, zero-depth and growing cycles,
missing instructions/targets, unknown operations, native/indirect boundaries,
red-zone accounting and rejection of another architecture. There is no Cargo,
nightly compiler or proof-computation run in this diagnostic. Raw tool output,
source/tool/binary hashes and exact test output are retained alongside this note.
An independent read-only engineering review found no remaining concrete defect
within these stated assumptions after the FP-clobber and direct-memory checks
were added; this is not a formal ISA proof.

A complete stack argument still needs proven targets for the indirect calls,
source/compiled invariants that bound or exclude exceptional recursion, and
pinned native/runtime stack bounds. These finite regions cannot replace those
obligations or justify a complete 64 MiB workspace certificate.
