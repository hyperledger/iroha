# Bound for the in-memory verification adapter

Status, 2026-10-13: **conditional adapter bound**, with the full verifier and
native costs explicitly opaque. This is not complete workspace sufficiency or
production qualification.

For the two retained fatal-control binaries, the adapter's own compiled region
uses at most **336 bytes of stack including the 128-byte red zone**, issues at
most **5,298 ARM64 instructions outside opaque callees**, and holds at most one
**524,288-byte input block** for at most **425,984 input bytes**. Both modes have
these same bounds. The zeroing and copying primitives each receive at most
425,984 bytes. These are separate dimensions, not a conversion into verification
units, CPU time or a claim that the whole invocation completes within them.

The [report](report.json) and [checker snapshot](parliament_ballot_adapter_bound.py.template)
bind the [current EON captures](../parliament_ballot_fatal_stack_eon/README.md),
their exact six function bodies and their unchanged build sources. All 2,081
input guards stayed unchanged. There was no build or executable run. Earlier
unconditional frontier reports remain intact; the conditional cuts here do not
retroactively close them.

After this successful interval, local review found concurrent changes to five
guarded build inputs: `Cargo.lock`, `iroha_allocation`'s
`allocation/allocator_refusal.rs`, `allocation/shared.rs`, `shared.rs` and
`shared_reservation_tests.rs`. The [post-analysis check](post-analysis-source-check.json)
preserves every old/current hash: 2,076 of 2,081 guards still match. A fresh
[actual checker invocation](current-source-refusal-command.json) refuses with
[UNKNOWN and its raw reason](current-source-refusal/report.json). The original
report remains unchanged and valid only for its pinned source/image interval;
current-source equivalence is not established. No pins were refreshed and no
source was rebuilt or restored to hide the drift.

## Boundary and premises

The measured region in this argument starts immediately after the worker's
successful supplied-stack check and before its admission comparisons: portable
`0x100000f60`, accelerated `0x100000f64`. The already-created 176-byte worker
frame stays live and is counted. Mapping, file staging, thread creation and the
three native stack-query calls precede this entry. The region ends at worker
return, direct input-allocation fatal exit, or suspension inside an opaque
callee. The full body of `Reservation::verify`, including anything it invokes,
is opaque. Its normal return resumes the adapter; its failure to return does
not become an adapter completion certificate.

The argument requires these explicit premises:

1. **Ordinary implementation semantics.** The compiled program implements its
   build-pinned Rust source, the ARM64 ABI and valid Rust/allocator memory
   contracts. Calls preserve the required callee-saved registers and SP/FP;
   actual accesses respect the ABI stack frame/red zone. No asynchronous signal,
   exception or unwinding edge is inserted into this ordinary execution. These
   are ordinary compiler/ABI/memory-safety premises, not a request for a new
   universal compiler proof.
2. **Private invocation.** `run` retains the mapping and same immutable borrowed
   input until its joined worker finishes. ARENA is the published nonnull arena,
   the fatal page remains mapped, and its initial SETUP state is fresh. There is
   one invocation and no concurrent, asynchronous or reentrant allocation,
   arena operation or mutation of ACTIVE, ARENA, request/control storage or the
   borrowed bytes. The external supervisor neither mutates nor truncates the
   shared page. The arena begins empty, with its initialized availability tree
   and unlocked lock. These requirements are already part of this standalone
   entry's [ownership contract](../../../crates/iroha_parliament_ballot_proof/examples/memory_entry/README.md);
   they are not properties of a concurrent embedded service.
3. **Opaque return contract.** If the verifier returns, it returns a valid
   fixed-size `Receipt` and preserves the adapter's live Vec allocation,
   pointer/layout, borrowed input, request, fatal state and private globals.
   Its internal allocations obey `GlobalAlloc`; it returns with a valid
   unlocked arena and the adapter's input block still allocated. It does not
   mutate the input through the shared slice or free/reallocate caller-owned
   storage. Its internal objects have ended their ownership as promised by the
   pinned `Reservation::verify` interface. These obligations are not proved by
   treating the function as opaque. Its nested fatal, native, panic, TLS and
   allocator work remains inside its opaque cost, including on nonreturn.
4. **Native and atomic behavior.** The native zero/copy functions implement
   their valid-range operation, preserve ABI/private state, do not unwind or
   reenter Rust/adapter callbacks, and return normally. Zero-length copy is
   allowed without a memory access, including the empty Vec's aligned dangling
   destination pointer. `_exit` does not return normally or unwind
   into Rust. Native work, stack and hidden allocation/TLS/loader costs are
   left as unknown parameters below; they are not assumed zero. Ordinary
   atomic/memory accesses complete according to the architecture, with valid
   mapped memory and without external fault injection. The compiled lock uses
   actual `CASAB`, so uncontended comparison against the initial zero byte
   succeeds; this is not inferred from source `compare_exchange_weak` alone.

If a premise fails, this artifact supplies no all-path bound for the resulting
execution. The supervisor still treats unclassified termination as a worker
error; this note does not change outcome handling or refund policy.

## Source argument

The build-pinned `budget.rs::reserve` checks the actual input length before
allocation: `N <= 425984`, at least one unit, and enough byte budget. A refusal
reaches a fixed result without allocation or verification. The success path
publishes exactly units=1 and bytes=N to the fatal slot before enabling ACTIVE.
`run` derived the raw pointer and length from the same live immutable slice;
`execute` uses that same N for the owned `Vec<u8>` and borrowed slice.

For admitted N, the adapter creates at most one owned Vec, then calls zeroing
and copying on at most N bytes each. N is below `isize::MAX`, its alignment is
one, and both copy lengths are equal, so these adapter operations do not take
size-overflow or unequal-length panic paths under the stated contracts. N=0
needs no allocation or deallocation. For N>0, a failed routed allocation enters
the dedicated fatal path, not the standard allocator error handler or a System
fallback. ACTIVE's own true store dominates its allocation load; private-state
noninterference preserves that value. ARENA remains nonnull.

The input block size is `B = next_power_of_two(max(N, 64))`, hence
`64 <= B <= 524288` when allocated. The arena has 32 MiB / 64 = 2^19 leaves.
Allocation halves a width initially 32 MiB until it reaches B, at most 19
iterations, then updates at most 19 ancestors. Release starts at the allocated
node and updates at most 19 ancestors. The arithmetic remains inside the
1,048,575-byte availability tree and the 32 MiB heap under the initialized-tree
and live-allocation contracts. A low heap limit may produce explicit exhaustion;
this note does not assume that allocation always succeeds.

The owned input remains live across the opaque verifier call. On ordinary
return, the fixed `Receipt` and error classification own no heap values. The
input is released once, with the same original pointer, N and alignment one,
before ACTIVE is cleared. The live-pointer/range and nonzero rounded-layout
premises exclude System free and divide-by-zero failure for this particular
adapter release. They do not establish universal provenance for arbitrary
verifier frees. With no other live allocations after the verifier's promised
cleanup, releasing the input also establishes the adapter's zero live-byte
contribution for the later supervisor stats check. The stats/join/reporting
code itself is outside this worker adapter interval.

The three lock acquisitions belong to allocation, contains and release. The
retained instructions use a compare-and-swap that returns the old byte. With no
interference and the lock initially false, the first CASAB returns zero and
takes the success branch; no spin retry is needed. Allocation releases before
verification, and the return premise supplies an unlocked valid arena before
contains/release. Arm's official [A64 reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85),
printed pages 95–96, describes this compare-and-swap behavior. The source weak
CAS loop, by itself, would not justify a no-retry claim on another image.

## Current machine argument

The checker hashes all instructions and operands of each of the six exact
function bodies, recomputes the frozen stack analysis, then constructs the
conditional ordinary CFG. Every conditional cut has an address, original
instruction, retained edge and named premise in [report.json](report.json).
Unknown bodies/callees, an unmodeled cycle, unmatched cut or changed source
identity produce UNKNOWN, never qualification.

| Body | Local frame | Reachable instructions after premises | Loop-backedge allowance | Conservative local issued-instruction bound |
| --- | ---: | ---: | --- | ---: |
| Worker from adapter entry | 176 B | 154 | None | 154 |
| Allocation shim | 0 B | 1 | None | 1 |
| Arena allocate | 0 B | 95 | Two edges, at most 19 each | 3,705 |
| Input deallocation | 16 B | 71 | One edge, at most 19 | 1,420 |
| Exhaustion wrapper | 16 B | 3 | None | 3 |
| Fatal publication | 16 B | 15 | None | 15 |

Removing the three declared backedges leaves acyclic graphs. A walk with at
most B such edges has at most B+1 acyclic segments, each visiting at most the
number of vertices. Thus `|V| * (1+B)` is a conservative instruction count.
Using 19 backedges is deliberately loose even where 19 iterations permit only
18 taken backedges. The loop functions call no helpers; the remaining graph is
acyclic and each helper has one call site, so summing these six local bounds
is safe. It even sums mutually exclusive normal/fatal paths: **5,298**.

The largest adapter-owned nested frame chain is worker → exhaustion wrapper →
fatal: 176 + 16 + 16 = 208 bytes. Adding one 128-byte red zone gives **336**.
The returning deallocation chain is smaller. The checker retains opaque
callee entry depths rather than assigning their bodies zero complete cost.
For parameterized native/verifier bounds, where each `S` includes the callee's
own stack and red-zone use, the conditional composition is:

```text
S <= max(336,
         176 + S_bzero(N), 176 + S_memcpy(N),
         208 + S_exit, 176 + S_verifier(N))
I <= 5298 + I_bzero(N) + I_memcpy(N) + I_exit + I_verifier(N)
```

The I quantities count issued machine instructions, not CPU cycles or the
contract's abstract debit unit. No numeric value is assigned to an opaque
parameter. If any is unbounded or the callee does not complete, this is not a
finite completion bound. Native call stubs and lazy binding belong in their
native parameters. Opaque verifier calls to the fatal routine include their
own deeper frames in `S_verifier`; the direct adapter's 208-byte fatal entry
depth must not be substituted for those paths.

The input's B-byte block is a contribution **inside** the already reserved
32 MiB heap, not another reservation to add to 41.109375 MiB. It remains occupied
while the verifier runs. No conclusion here assigns all 32 MiB to verifier
scratch in addition to that input. Native hidden allocations remain unresolved;
this adapter-only result cannot establish complete 64 MiB sufficiency.

## Validation and remaining work

All 20 focused tests pass. They cover both actual images, retained opaque costs,
bounded/unmodeled CFG cycles, conditional cuts, unexpected callees/control
escapes, lock/private-state/pointer/layout instruction mutations, changed frame
reports, frozen-source failure preserving UNKNOWN and output-reuse refusal.
Root independently reran the same 20 tests and reviewed the checker. No old
artifact or production source was changed.

Independent ownership review also passed all 20 tests and checked the actual
predicates, all three tree loops, same pointer/N/alignment forwarding, call
depths, terminal composition and the 5,298/336 bounds. It found no substantive
blocker under the stated premises and separately discovered the later source
drift above. This local review does not replace independent unsafe-code or
cryptographic review.

```sh
.venv/bin/python scripts/parliament_ballot_adapter_bound.py \
  --root "$PWD" --output /private/tmp/parliament-adapter-recheck
.venv/bin/python -m pytest -q scripts/tests/parliament_ballot_adapter_bound_test.py
```

TODO: discharge the verifier's all-admitted-input work/stack and return-invariant
obligations, and replace the named native cost parameters with appropriately
reviewed platform bounds. Runtime/System/TLS coverage, independent unsafe-code
and cryptographic review, the deferred Intel baseline and exact named phone
qualification remain separate. This finite adapter argument closes a concrete
local contribution; it does not qualify the complete service.
