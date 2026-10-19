# Ballot verification resource contract

Status, 2026-10-20: **standalone and canonical-input diagnostic workers implemented;
not a selected profile, production policy or activation qualification**.
The owner requested research, a concrete proposal and implementation after
the [B6 audit](parliament_ballot_b6_requirement_audit.md) identified undefined
charge and workspace scopes. That instruction authorizes this engineering
contract. Design §12.2 authorizes development, testing and production integration
engineering alongside B6; cryptographic assumptions and launch evidence still
need their own qualification.

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

The current [canonical-input worker](../crates/iroha_parliament_ballot/examples/canonical_resource_probe/README.md)
borrows two inputs: `Enc(AnonymousBallotEnvelopeV1)` and
`Enc(AuthenticatedBallotContextV1)`, with trusted network and body identifiers
supplied separately. It copies both inputs, decodes the canonical context,
checks its structure and derived fields, verifies the actual stamp and vote
proof, and destroys its owned values before returning fixed metadata. This is
vote validity only: it does not authenticate chain history or execute a casting
window/nullifier decision. No warm-cache discount applies.

The separate copy-in caps are 262,144 envelope bytes and 163,840 context bytes,
425,984 combined. The current envelope has a fixed canonical size of **233,455
bytes**. For every structurally valid context, let `S` be the sealed seats
(`3..=1000`), `N` the distinct ordered required bodies (`2..=10`), and `K` the
minimal signed byte length of the positive integral citizenship bond
(`1..=17`, since the bond is at most `u128::MAX`). With `u(x)` the unsigned
LEB128 prefix length, its complete frame size is
`803 + 130*S + 17*N + K + u(8 + 130*S) + u(8 + 17*N)`.
The maximum is **130,995 bytes**, so the maximal valid pair is **364,450
bytes**. This includes the pinned Norito header and every field prefix. The
measured 1,000-seat context was 130,963 bytes: it used nine bodies and a
two-byte bond, rather than the maximum configuration.

The [typed context decoder](../crates/iroha_data_model/src/governance/anonymous_ballot/context.rs)
checks the outer cap before decoding, then limits each sequence to 1,000
elements, both sequences together to 1,010, and cumulative nominal Norito
allocation charges to **327,680 bytes**. The ten-body restriction is checked
structurally after decoding; generic Norito decode APIs do not inherit this
entry-specific policy. The charge includes sequence counts, span storage,
element payload charges, retained vectors and bounded numeric backing.
It is not physical heap or workspace: codec controls, allocator overhead,
validation/error scratch and the rest of verification require separate bounds.
Structural validation does not authenticate supplied digests. The
`EncodedBallotContextV1` constructor checks the same byte cap before allocating
its encoded output; its caller still owns structural validation and authentication.

The [typed envelope decoder](../crates/iroha_data_model/src/governance/anonymous_ballot/ballot.rs)
permits zero sequence elements and exactly **233,012 bytes** of cumulative
nominal allocation: its one fixed proof copy. Positional fields borrow input;
other scalar and fixed-byte values stay inline. Wrong field or proof lengths
fail before that copy. A failure after proof construction retains the nominal
charge even though the failed value's owner is dropped. These charges exclude
codec controls, allocator overhead and error storage, so this is not a physical
workspace certificate.

Both typed decoders retain Norito's original local refusal owner. Schema and
canonical-default ceilings are created inside the classification boundary and
remain invalid-input errors; an original enclosing budget or reported allocator
failure is local unavailability. Equal numeric ceilings do not determine origin.
Binary and JSON byte carriers preserve that distinction through nested decoding.
Admission and block checks must not turn a local decode shortage into malformed
ballot evidence or consume a nullifier. Independent replay applies the same rule
to sealed-list decoding. No wire representation or proof rule changes.

The six [wire-size tests](../crates/iroha_data_model/src/governance/anonymous_ballot/context_wire_size_tests.rs)
cover the formula, prefix transitions, body subsets, bond widths, maximal
context roundtrip and fixed envelope size. Nine [context decoder controls](../crates/iroha_data_model/src/governance/anonymous_ballot/context_decode_tests.rs)
cover valid-header malicious counts, combined limits, early refusal and nested
carrier budgets. Nine [envelope controls](../crates/iroha_data_model/src/governance/anonymous_ballot/envelope_decode_tests.rs)
cover exact proof charges, malformed fields, late failure and nested binary/JSON
refusal provenance. The [current receipt](../docs/validation/parliament_ballot_canonical_resources/envelope-refusal-receipt.json)
records 107 model tests, 79 protocol tests (two fixture helpers ignored) and
25 example tests. Fresh portable and accelerated workers each pass 55 campaign
cases with identical inputs, full reports and debits. All 114 scoped inputs were
unchanged around each successful build/test. This is ordinary live-checkout
validation, not a complete frozen compiler-input inventory. The initial failed
test assertions and earlier campaigns retain their own scope.

The earlier [in-memory worker](../crates/iroha_parliament_ballot_proof/examples/memory_entry/README.md)
accepts one bounded standalone `TEST_RECORD`, with trusted row and role.
Its evidence remains specific to that source and format. Both workers retrieve
bounded regular files before invocation and retain immutable caller storage
until the worker joins. Actual slice lengths, not metadata or spare capacity,
supply admission. Retrieval and caller buffers are outside verification; owned
copies and their destruction are inside. The frozen original file-reading
worker has its own earlier scope.
The earlier [122-observation campaign](../docs/validation/parliament_ballot_memory_entry/README.md)
passed but its fatal stdout write could block inside charged work. The
[shared-control revision](../docs/validation/parliament_ballot_fatal_control/README.md)
removes that write and passes its own 122 observations, including direct borrowed
oversize refusal and separate full/broken-output controls. This is finite
boundary evidence; complete workspace and physical-cost claims remain open.

Admission reads only trusted metadata and actual borrowed byte lengths:

1. Reject an input length above its copy-in cap before arena allocation or
   decoding. The supervisor caps staging independently, and the borrowed entry
   checks the actual slice length even if file staging was bypassed.
2. Require at least one work unit and an available byte budget no smaller than
   the sum of actual input lengths. Check both counters before mutating either one.
3. Debit both dimensions atomically and return a linear, single-use reservation.
4. Copy at most the reserved bytes into the worker, then execute once. A changed
   length cannot reuse the reservation. Declared inner lengths and roster size
   never lower the debit.
5. Retain the full debit after success, any early or late malformed-input
   rejection, an unused reservation, or worker/resource failure. There is no
   refund path.

The diagnostic's fixed mapping and native thread setup precede worker-local
admission; refusal reports still include that reservation. Zero charged units
or arena allocations do not imply zero supervisor/setup cost.

The standalone unit covers either row and role and any supported roster size;
the typed diagnostic uses the same unit for one complete V1 vote-validity call.
It is an abstract whole-call reservation, not one instruction,
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
storage, plus one native shared fatal-control page. On the observed Mac these
reservations total 43,106,304 bytes (41.109375 MiB). Their exact mapping sizes
and sum are emitted by the worker. No arena
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
The child stores its exact debit before charged work; exhaustion publishes a
shared atomic marker and exits without formatting or writing. A separate
supervisor reads the native control page after child death, checks the marker,
debit and exit together, then publishes the result. Normal results must agree
with the shared debit too. Missing/corrupt control or a diagnostic timeout is an
operational error, preserving raw evidence and never inferring a refund.
The parent may block while publishing afterward; whole-command completion is
outside the charged verification-time claim.
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
standalone campaign uses eight independent ballot fixtures and their controls.
The separate [canonical campaign](../docs/validation/parliament_ballot_canonical_resources/README.md)
retains 55 cases per mode over genuine 3-, 500- and 1,000-seat votes, a separately
stamped late-invalid vote, malformed inputs, insufficient budgets and exhaustion.
Its earlier frozen captures precede the typed decoder limits described above;
the separately retained context-boundary and envelope-refusal runs each repeat
all 55 cases per mode on their changed workers, with full report and input parity
checked from raw evidence.
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

The [ownership audit](../docs/validation/parliament_ballot_ownership/README.md)
and [compiled free predicates](../docs/validation/parliament_ballot_free_predicates/README.md)
support conditional arena-origin reasoning without proving universal pointer
provenance or excluding any of the ten unconditional free sites. The separate
[I/O error guard](../docs/validation/parliament_ballot_io_error_guard/README.md)
checks a non-Custom destructor return path; its charged-read source argument
does not cover all worker errors or bound native read/retry behavior. These
refinements leave the full service's workspace and time requirements open.

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
owner acknowledgements, validation of the final integrated schemas and ingress
costs, and named phone qualification remain required. The exact encoding formula
and nominal decoder limits do not close the physical-workspace requirement.
Design section 12.2 authorizes production-schema
and Core integration engineering alongside qualification; binding production
activation remains disabled until all qualification requirements hold.
