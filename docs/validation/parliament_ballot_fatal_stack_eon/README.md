# Fatal-control stack capture with EON decoding

Status, 2026-10-13: compiled diagnostic only; complete stack/workspace
certification and production qualification remain false.

This follow-up removes the two unsupported scalar `EON` sites recorded in the
frozen [STLUR-only capture](../parliament_ballot_fatal_stack/README.md). It uses
the same existing [fatal-control binaries](../parliament_ballot_fatal_control/build/build-receipt.json),
without rebuilding or executing them. The prior capture and its manifest are
unchanged. The [receipt](receipt.json) guards 2,059 unchanged inputs, including
the preceding 19-file artifact and manifest, all 2,021 build sources, binary/tool
identities, and actual loaded analyzer/validation helpers. It checks the build
receipt against the frozen preceding B6 phase manifest and reuses the complete
source-inventory and six-command Cargo validation.

The [analyzer snapshot](parliament_ballot_stack_audit.py.template) now handles
scalar EON's same-width W/X operands and optional LSL/LSR/ASR/ROR shift, bounded
to the operand width. EON has a register destination and no SP operand. Writing
X29 or W29 invalidates the analyzer's known FP, so a later SP restore cannot
use a stale value. Dotted forms of the two newly supported scalar mnemonics
are rejected explicitly instead of passing through generic opcode normalization.
This is narrow support for the observed instructions, not a complete ISA decoder.

The semantics follow Arm's official [A64 instruction reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85),
printed pages 401–402 (PDF pages 404–405), EON (shifted register). This instruction
changes a general-purpose destination and does not change SP or branch. No
constant latency, ownership or memory-safety claim follows from decoding it.

All **62 focused tests** pass ([log](tests.txt), [snapshot](parliament_ballot_stack_audit_test.py.template)).
The 22 new cases exercise both actual scalar spellings, 32/64-bit widths,
all allowed shift kinds and limits, FP clobber, invalid/mixed-width/SP operands,
and unknown scalar suffixes. Independent local engineering review reran all
62 tests and found no concrete issue in this delta or its unchanged treatment
of opaque call costs.

## Results and remaining frontiers

| Mode | Text instructions | Functions | Entry-CFG instructions visited | Whole-image frame-analysis errors | Resolved worker region | Complete worker stack bound |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Portable | 93,768 | 896 | 86,508 | 0 | 15,984 B | Unknown |
| Accelerated | 91,554 | 894 | 84,285 | 0 | 13,440 B | Unknown |

The portable analysis visits 55 additional instructions after the two EON
sites. AES128/AES256 key-schedule local frames remain 816/1,040 bytes, with
411/442 visited instructions. The deeper traversal reveals two additional
native `_memcpy` frontiers at `0x100024a30` / `0x100025cc4`; their costs remain
unknown. The accelerated instruction coverage is unchanged.

The worker's 176-byte local frame, the two 16-byte exhaustion frames, the
zero-frame arena-allocation function and the 144-byte fatal local region
(including red zone) are unchanged in both modes. The complete reports are
[portable](portable.json) and [accelerated](accel.json). The ordinary-entry worker
CFG still visits 198/204 decoded instructions; no exception/unwind coverage is
inferred for the trailing six instructions.

| Reachable worker frontier kind | Portable | Accelerated |
| --- | ---: | ---: |
| Native edge | 144 | 138 |
| Indirect call | 38 | 38 |
| Indirect branch | 4 | 4 |
| Function fallthrough | 82 | 82 |
| Exceptional terminal | 39 | 39 |
| Unsupported instruction | 0 | 0 |

Each graph retains one 63-function positive-weight recursive component.
All addresses, caller depths, native names and component members remain in the
JSON. Native `_exit`, its possible continuation, System allocation/free paths,
indirect dispatch and panic/unwind/runtime possibilities are not pruned.
Removing decoder gaps does not assign any of these paths a zero cost.

The finite figures bound only resolved direct-call regions under ordinary
ARM64 SP/FP preservation, ABI-conforming stack memory accesses and the 128-byte
Apple red zone, added once along a nested path. Opaque callees/components are
excluded. No all-admitted-input termination/work, complete 8 MiB stack,
complete 64 MiB workspace or hardware/cryptographic qualification follows.

## Reproduction and next boundary

With the retained sources, binaries, old frozen capture and Xcode LLVM tools:

```sh
.venv/bin/python docs/validation/parliament_ballot_fatal_stack_eon/capture.py.template \
  --root "$PWD" --output /private/tmp/parliament-fatal-stack-eon-recapture
```

Output must be new. No old report or manifest is rewritten. Raw disassembly,
function starts, native stubs, unwind metadata and loaded helper snapshots
are retained. The driver validates source identity before capture and rechecks
guards afterward, preserving a failed receipt on capture/test failure or drift.

TODO: close the named memory-entry adapter boundary with bounded source
ownership/control-flow arguments while treating `Reservation::verify` as opaque
and stating finite native-routine premises. Then discharge the verifier's
remaining indirect/recursive/native stack and work obligations. These are
substantive source/runtime bounds; this decoder work does not demand or supply
a universal compiler correctness proof. Independent cryptographic/unsafe-code
review and the named hardware qualification remain separate requirements.

Final read-only provenance review independently verified all 2,059 guard hashes,
both analysis hashes, every raw LLVM-output hash and the test-log hash, including
the unchanged 19-file preceding artifact. No changes were requested. This local
engineering review does not replace the required independent cryptographic or
unsafe-code review.
