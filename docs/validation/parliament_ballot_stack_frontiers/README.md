# Failure-entry boundaries in the frozen ARM64 stack graph

This [separate report](report.json) narrows the remaining stack obligations in
the exact frozen resource-worker images. In the resolved direct/provider graph,
31 of the 32 remaining indirect sites can only be reached after entering one
of three named failure functions. The remaining site belongs to worker I/O
error destruction and is outside `Reservation::verify`. Removing those failure
entries from the traversed graph breaks its positive-weight recursive component.
Every removed edge remains an explicit **unknown-cost failure frontier**.

This establishes a useful proof boundary, not an 8 MiB stack certificate.
There is no claim that all valid or malformed inputs avoid panic, or that a
failure handler completes within the supplied stack. The original
[stack audit](../parliament_ballot_compiled_stack/README.md) and
[provider catalog](../parliament_ballot_indirect_targets/README.md) are unchanged.
No executable was rebuilt or run.

## Boundary and provenance

The helper checks exactly these emitted symbols against literal signatures in
the installed Rust 1.93.1 rustdoc sources:

| Excluded function entry | Source evidence | Meaning |
|---|---|---|
| `core::panicking::panic_fmt` | [Retained source](core-panicking.rs.template), line 60 | Panic handler/formatting path |
| `core::panicking::panic_nounwind_fmt` | Same source, line 95 | Non-unwinding panic formatting path |
| `alloc::alloc::handle_alloc_error` | [Retained source](alloc-alloc.rs.template), line 399 | Allocation-failure handler path |

Each signature returns `!`: it does not return normally. That alone does not
prove absence of unwinding, allocation, native work, recursion, or additional
stack use. Literal excerpts, complete extracted source hashes, installed HTML
hashes and corresponding Rust commit URLs are in the report. The compiler
identity matches the original build receipt (Rust 1.93.1, commit
`01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`). This is installed source provenance,
not an independently attested standard-library build or extracted LLVM
`noreturn` metadata. Source URLs identify the corresponding
[panic implementation](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/core/src/panicking.rs)
and [allocation failure implementation](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/alloc/src/alloc.rs).

No instruction-level continuation is removed using these signatures. Original
local frame maxima, both branch outcomes, call continuations, traps, unwinding
edges and function-boundary fallthroughs remain. Ordinary `Result` rejection
and cleanup paths are included. The conditional provider edges retain their
separate source/memory-safety premises; hidden calls through unresolved native
or indirect endpoints remain unknown.

## Result of the separate calculation

Each root starts with a relative SP of zero. A longest-path calculation sums
the caller SP decrements at nested modeled call edges. It rejects positive
recursive components and frame errors, and collapses only zero-depth tail
cycles. Local contributions include the original analyzer's 128-byte Apple red
zone. These are compiled **caller-frame contributions**, not full call peaks.

| Root / mode | Reachable functions | Caller-frame envelope | Indirect sites | Native sites | Failure entries | Trap sites | Fallthroughs |
|---|---:|---:|---:|---:|---:|---:|---:|
| Reservation / portable | 244 | 15,648 B | 0 | 108 | 37 | 23 | 57 |
| Reservation / accel | 239 | 13,056 B | 0 | 102 | 37 | 23 | 57 |
| Worker / portable | 261 | 15,984 B | 1 | 129 | 39 | 26 | 59 |
| Worker / accel | 256 | 13,392 B | 1 | 123 | 39 | 26 | 59 |

There are no positive-weight recursive components or indirect branches in these
failure-entry-separated graphs. This does not prove the original runtime cannot
recurse. The earlier opaque-component calculation omitted the internals of a
69-function component. Cutting its failure entries exposes additional finite
caller paths; therefore the accelerated caller-frame envelope can exceed the
earlier resolved-region number. Neither number is a complete stack bound.

The report records every original indirect site with a concrete syntactic
worker call path and its first failure entry, if any. Reachability here is
graph reachability, not proof that a particular input realizes that path.
The remaining worker-only `std::io::Error` destructor is at `0x100001684`
portable / `0x1000039d8` accelerated. Source-pinned
[`workspace.rs`](../../../crates/iroha_parliament_ballot_proof/examples/resource_contract/workspace.rs)
acquires, inspects and reads the input file; those I/O error paths retain this
obligation. The reservation API receives an already copied slice and returns
fixed-size errors. Neither successful file-copy observations nor this boundary
analysis proves the dynamic destructor branch unreachable for every worker path.

The reservation-root native sites divide into memory operations (80 portable /
74 accelerated), System allocator branches (14 each), exit/report calls (4
each), and unwind continuation (10 each). The helper does not assume the arena
activation flag or pointer provenance removes System branches. Each native
symbol has a grouped obligation containing its maximum modeled caller SP;
every individual site remains in the report.

## What completes the next proof step

For a proposed complete bound, let `F` be the caller-frame envelope, `D_j` the
reported SP contribution before an unresolved endpoint, and `K_j` a justified
bound on that endpoint's additional peak relative to that SP, including its
hidden calls. A bound of the form `max(F, max_j(D_j + K_j))` requires every
continuation contract and the graph/ABI premises to hold. The report supplies
`F` and `D_j`; **all `K_j` remain unknown**. Root-caller/runtime stack outside
the selected entry also needs its own bound.

The concrete remaining obligations are:

- Prove relevant checks cannot enter panic/allocation-failure handling for the
  admitted domain, or bound those handlers and their unwind/abort behavior.
  A `Result` decoder and finite passing samples do not prove panic absence.
- Prove compiled activation/provenance invariants before excluding System
  allocation branches; bound the remaining native memory routines and all
  callbacks or hidden runtime use on the installed platform.
- Resolve traps, unwind continuations and function fallthroughs with checked
  path conditions or contracts. No arbitrary recursion limit is introduced.
- For the whole worker, establish source/compiled `io::Error` variant-flow
  facts or bound its dynamic destructor, and bound file/thread setup endpoints.

The narrowed reservation graph removes the need to guess 31 panic-runtime
indirect target sets before addressing ordinary verifier caller frames. It
does not discharge complete workspace, all-input completion, unsafe review,
physical calibration, or production qualification requirements. All complete
bound and qualification flags remain false/null.

## Reproduce and verify

```sh
python3.11 scripts/parliament_ballot_stack_frontiers.py --output /tmp/parliament-stack-frontiers-new
python3.11 -m pytest -q scripts/tests/parliament_ballot_stack_frontiers_test.py
```

The output directory must be new. `--rustdoc-src` selects another copy of the
installed Rust 1.93.1 source HTML if needed. The helper verifies both older
artifact manifests and catalog inputs, exact retained binaries and source
premises, and reproduces the previous provider-expanded graph before applying
cuts. It then rechecks every input hash. Source copies and [validation
receipt](validation-receipt.json) retain **14 passing tests**, including
independent weighted/fan-in and zero/positive-cycle examples, explicit failure
frontier retention, unknown native/indirect/trap preservation, source-signature
mutations and refusal to overwrite prior evidence. Independent engineering
review found no concrete arithmetic or boundary defect within this stated
scope; it is not machine-code or unsafe-code qualification.

[SHA256SUMS](SHA256SUMS) covers the new artifact set. Old source pins and reports
have not been changed.
