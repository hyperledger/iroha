# Standalone ballot verification resource contract

Status, 2026-10-13: **proposal implemented for standalone qualification;
not a selected profile, production policy or activation qualification**.
The owner requested research, a concrete proposal and implementation after
the [B6 audit](parliament_ballot_b6_requirement_audit.md) identified undefined
charge and workspace scopes. That instruction authorizes this engineering
contract; it is not acceptance of cryptographic assumptions or launch evidence.

## Decision and research basis

Use one indivisible **verification reservation unit** for one complete cold
verification call. Use bytes as a separate resource dimension. Do not convert
AES calls, field operations and copied bytes into invented equivalent CPU
operations. The existing source inventories help review the bounded service;
they are not summed to produce this unit.

This follows the structure of native cryptographic precompile pricing:
[EIP-2537](https://eips.ethereum.org/EIPS/eip-2537) defines deterministic charges,
including malformed-length handling, separately from its worst-case pricing
requirement. [EIP-2565](https://eips.ethereum.org/EIPS/eip-2565) uses a deterministic
formula and benchmarks to justify its calibration. These are accounting
precedents, not adopted primitives, execution engines or security assumptions.
The proposed unit still needs a qualified worst-case cost before deriving
production throughput, block budgets or stamp difficulty.

For memory, a requested-allocation counter is insufficient. Rust's
[`GlobalAlloc`](https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html)
contract permits allocations to be eliminated or moved to the stack and
forbids allocator unwinding. The standard library can also use
[`System` directly](https://doc.rust-lang.org/std/alloc/index.html).
[`Builder::stack_size`](https://doc.rust-lang.org/std/thread/struct.Builder.html#method.stack_size)
is a requested size that a platform may increase. Therefore the implementation
uses a fixed reclaiming arena and an explicitly supplied native stack mapping,
and reports runtime allocations outside that allocator as an open coverage
obligation. It never adds a requested stack size to requested heap and calls
the sum a complete memory certificate.

## Verification and debit boundary

The current entry is one bounded `TEST_RECORD`, with trusted row and role
selected by the qualification caller. It is the existing test codec, not a new
production format. The service includes profile construction, fresh statement
and list decoding/validation, transcript preparation, full proof verification,
and destruction of verifier-owned values before returning a fixed result.
No warm-cache discount applies.

The maximum copied record is 425,984 bytes: the design's 262,144-byte envelope
allowance plus its 163,840-byte shared-context allowance. This combined cap
accommodates the existing standalone records. It does **not** prove that a
future authenticated envelope and shared context individually fit their caps.
Their exact layouts and framing remain subject to the selection order.

Admission reads only trusted metadata and the actual outer byte length:

1. Reject an outer length above the copy-in cap before verifier allocation or
   decoding. The standalone supervisor opens a regular file nonblocking and
   reads its metadata first; filesystem/path setup is outside the worker arena.
2. Require at least one work unit and exactly the actual outer length in the
   byte budget. Check both counters before mutating either one.
3. Debit both dimensions atomically and return a linear, single-use reservation.
4. Copy at most the reserved bytes into the worker, then execute once. A changed
   length cannot reuse the reservation. Declared inner lengths and roster size
   never lower the debit.
5. Retain the full debit after success, any early or late malformed-input
   rejection, an unused reservation, or worker/resource failure. There is no
   refund path.

One unit covers either row and role and any supported roster size, conservatively
including the comparator's larger reconstruction tree and the candidate's
larger proof. It is an abstract whole-call reservation, not one instruction,
millisecond, gas price or assumed 250 ms certificate. Portable and accelerated
builds use the same debit logic. Work shortage and byte shortage execute no
verification and leave both remaining budgets unchanged.

## Workspace and failure boundary

The proposed 64 MiB scope is **one serialized cold verifier invocation**.
Its owned input, decoding/list/transcript buffers, backend/relation scratch,
AES provider boxes, allocator bookkeeping/alignment/fragmentation and cleanup
belong inside the scope. Native stack, guard pages and control/result storage
are separately reserved and counted. Caller spare capacity does not cross the
boundary: only bounded input bytes are copied.

The diagnostic worker reserves a 32 MiB reclaiming heap, 1 MiB of allocator
metadata, an 8 MiB native stack, two OS-page guards and 64 KiB of control
storage. Their exact mapping sizes and sum are emitted by the worker. No arena
allocation falls back to the system allocator. Unsupported native targets or
mapping/stack setup failures refuse the invocation. The supplied stack must be
the actual worker stack; a thread-builder request alone is insufficient.
Verifier-owned heap values are freed before reporting. The one-shot child
retains the published mapping through reporting until process exit, avoiding
an allocator pointer/unmapping race; repeated invocation is refused.

Code and immutable tables, the supervisor's stack, loader/kernel/thread
infrastructure, network/disk retrieval, and unrelated node queues are not
verifier workspace. This definition is neither all-process RSS nor requested
Rust heap alone. Runtime/TLS or direct-system allocations caused by verification
still require an explicit audit or bounded allowance; they cannot be silently
put in the excluded node overhead. Allocation optimization can move work to
the bounded native stack, but does not establish that all valid executions
finish within the available space.

An arena allocation failure uses an explicit worker resource-failure exit.
It is not caught by unwinding through `GlobalAlloc`. A signal, panic or otherwise
unclassified worker termination is a worker error, not an inferred allocation
failure and not an invalid-proof result. The standalone supervisor preserves
these distinctions. Any later production consumer must treat local resource
unavailability as inability to validate, never a consensus-invalid ballot.

Multiple invocations require separate worker reservations. Node admission must
bound concurrency and add its own queue/cache/shared runtime overhead; multiplying
64 MiB by worker count alone is not a whole-node memory certificate.

## What this implementation can establish

Tests must establish atomic debit boundaries, no early-failure refund,
same-length reservation enforcement, bounded copy-in, arena alignment and
non-overlap, reallocation/copy behavior, reclamation/coalescing, exhaustion,
native stack placement, and outcome/charge parity across feature modes. The
campaign uses the eight existing independent ballot fixtures, malformed and
late-invalid variants, insufficient budgets and explicit arena exhaustion.
Every case records its input identity, executable/source identity, result,
debit and enforced mapping sizes. Interrupted or source-drifted campaigns must
retain completed cases while refusing a successful final publication.

Successful finite cases demonstrate implementation and feasibility, not
all-valid-input sufficiency. Separate flags distinguish reservation semantics,
arena/stack containment, complete workspace coverage, physical-cost calibration
and profile qualification. The latter three remain false until supported by
their own evidence.

The separate [native endpoint experiment](../docs/validation/parliament_ballot_native_probe/README.md)
derives a diagnostic worker without modifying the frozen resource worker. It
counts 21 named process-wide allocation/mapping endpoints across setup, charged
verification and teardown, with fresh-process routed/System/thread/TLS/panic
controls before proof observations. A marker collision, missing positive control,
overflow or missing snapshot cannot become a successful zero-call observation.
Terminal resource failure remains an incomplete interval. Requested endpoint
bytes are not unique live bytes, and installed runtime UUIDs do not authenticate
source correspondence. Hidden calls and other coverage gaps remain explicit;
this instrument does not discharge the complete workspace requirement.

The separately derived [allocation-stream worker](../docs/validation/parliament_ballot_allocation_trace/README.md)
also compares real verifier allocation/free order, layouts and offsets against
the source grammar. Its 132 corpus observations and 14 controls pass, including
charged read errors and invalid recorder/terminal controls. The recorder adds
16 MiB outside the original reservation and serializes after cleanup. Finite
stream membership does not establish complete compiler correspondence, native
coverage, all-input completion or a whole-process 64 MiB bound.

## Remaining selection and policy obligations

TODO: complete the runtime/System/TLS coverage audit and establish that every
valid maximum-size input, and every admitted malformed path, either finishes
within the reservation or has a specified non-consensus resource outcome.
Independent unsafe-code review and target execution evidence are required.

TODO: qualify the full service on the named Xeon baseline, including all relevant
malformed paths and cold conditions. Only then derive `B_work`, stamp difficulty
and admitted concurrency from a defensible worst case. The owner's Intel run
remains deferred; this contract does not substitute the development Mac.

With this proposed tariff, at most `B_work` calls can be reserved per block.
Byte packing imposes a separate bound. Actual casting capacity additionally
depends on eligible blocks, opening/closing positions, minimum cadence and
post-synchrony inclusion assumptions. No casting-window formula or committed
policy value is silently chosen here.

The cryptographic proof, primitive/resource premises, independent assessments,
owner acknowledgements, exact production envelope accounting and named phone
qualification remain required. Production schemas, Core integration and
activation stay gated by the original design.
