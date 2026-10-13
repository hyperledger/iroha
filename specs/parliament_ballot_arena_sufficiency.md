# Conditional standalone arena sufficiency

This record refines the [resource-contract proposal](parliament_ballot_resource_contract.md)
without changing its worker, entry point, charge semantics or production gate.
The [checker](../scripts/check_parliament_ballot_arena_sufficiency.py) establishes
space sufficiency for a pinned **source allocation model**, conditional on its
allocation, layout and control-flow correspondence assumptions. It does not
certify compiled execution or the complete 64 MiB workspace requirement.
[Retained evidence](../docs/validation/parliament_ballot_arena_sufficiency/README.md)
identifies every script, source, tool and diagnostic binary used.

## Allocator semantics

The model uses the worker's 32 MiB buddy arena, minimum 64-byte blocks,
leftmost suitable placement, exact allocation layouts and eager coalescing.
An allocation must pass alignment, rounded-live-block quota and spatial
availability separately. A small live-byte sum alone is insufficient: eight
64-byte allocations in a 512-byte heap, followed by freeing alternating blocks,
leave 256 bytes free but cannot satisfy a 128-byte request.

A compressed repetition is accepted only when one complete body preserves
all free-block topology, live identities, offsets, layouts and current byte
counters. Induction then covers every finite repetition count in its declared
range. This checks allocator restoration; source review separately supplies
that range and the absence of other allocations between repetitions.

## All-length frontend bound

The reviewed frontend grammar has at most 12 simultaneous allocations,
including old/new realloc buffers and the copied input. The first allocation
is the input, rounded to at most 524,288 bytes. Every other block is at most
262,144 bytes, with alignment at most eight. Profile construction has at most
four simultaneous temporary buffers and retains none.

For a request of buddy size `B`, each live block smaller than `B` intersects
one aligned `B`-sized bin; a larger block occupies exactly `block_size / B`
bins. If the sum of these occupied-bin upper bounds is less than `heap_size / B`,
some entire bin is free. Eager coalescing makes its buddy node available.

The checker deliberately permits the input plus eleven maximum non-input
blocks **before** the next request, overcounting the 12-object source bound.
For all 13 request orders from 64 to 262,144 bytes, spatial availability,
quota and alignment pass. Its conservative post-request envelope is
3,670,016 bytes (3.5 MiB). This establishes modeled frontend admission for
all bounded lengths and partial-construction prefixes, independently of
transient placement or exact Vec growth. Ordinary rejection cleanup allocates
nothing. The named rejection traces are source boundaries, not a proof that
particular malformed bytes reach them.

## Retained-state classes and backend replay

Registration has eight buddy classes for the body (including empty) and four
for each of six opaque fields: `8 * 4^6 = 32,768` tuples. The copied canonical
record stays within one rounded class for each row. Profile temporaries restore
their initial state; the fixed field-slice buffer and typed fields are allocated
in fixed order. Later profile/frame temporaries are safe by the frontend lemma
and are freed before backend entry. Therefore each tuple determines the
backend's retained geometry, regardless of exact field lengths within it.

The checker uses the upper endpoint of each field interval. These endpoints
maximize retained input/field requested bytes. **They do not maximize frontend
Vec growth or allocation counts:** a smaller intermediate field can produce
an extra growth step with a larger final capacity. A regression preserves a
concrete example of this nonmonotonicity. Frontend sufficiency comes from the
separate spatial bound, not representative enumeration.

Votes enumerate every list size `S=3..1000`. Both rows and provider alignments
(portable eight, accelerated sixteen) give
`2 * 2 * (32,768 + 998) = 135,064` complete representative traces. Every replay
checks fragmentation, quota, provider-loop restoration and final cleanup.
Backend schedules depend on row, role and vote size; proof-dependent provider
counts use the restoring-loop induction. Ordinary early returns are allocation
prefixes followed by nonallocating drops.

For each row, the all-length live-heap bound is the greater of the universal
frontend envelope and the representative backend maximum. The latter includes
maximum retained requested bytes for its class. Both modes give:

| Row | Conditional rounded live-block bound | Conditional requested-live bound |
| --- | ---: | ---: |
| Candidate | 5,017,216 B | 4,069,654 B |
| Comparator | 7,211,136 B | 6,565,341 B |

The checker also reports allocation-count maxima **over checked representative
traces only**. These are not all-length work bounds. Neither total supplies
metadata, native stack, runtime/TLS memory, allocator-internal cost or CPU units.

## Correspondence obligations and remaining work

The source grammar pins Rust 1.93.1 Vec/RawVec/TrustedLen allocation policy,
64-bit layouts and default allocate-copy-free reallocation. Compiler allocation
elimination/reordering/replacement, exceptional paths, direct System/TLS calls
and native runtime behavior are outside the source-model theorem.
[Disassembly evidence](../docs/validation/parliament_ballot_arena_layout/README.md)
supports three private type layouts and return-object drop order in both
frozen ARM64 workers; it is a manual, selected-site audit, not a complete
machine-code allocation correspondence proof. The separate native oracle runs
the actual arena implementation against supplied traces, not the verifier.

A subsequent [allocation-stream campaign](../docs/validation/parliament_ballot_allocation_trace/README.md)
observes separately compiled, instrumented verifiers. All 132 corpus streams
match the grammar and actual arena offsets, with 14 controls and unchanged
source guards. It checks 8,943,472 allocation/free events, cleanup and worker
statistics. Observed peaks equal the conditional source-model ceilings. This
closes the selected finite observation gap; it does not prove correspondence
for all inputs or for the earlier uninstrumented binary. Recorder memory and
post-interval serialization are additional diagnostic overhead.

The [compiled-stack audit](../docs/validation/parliament_ballot_compiled_stack/README.md)
retains exact instruction data and unresolved native, indirect and recursive
frontiers. A separate
[provider-target catalog](../docs/validation/parliament_ballot_indirect_targets/README.md)
extracts three emitted AES tables per frozen ARM64 worker and checks the seven
backend indirect sites: one encrypt dispatch and six destructor calls. Its
scoped graph rerun adds 21 source-conditional edges per image. The pointer
addresses and slot loads come from the exact binary bytes; completeness of
the target sets additionally assumes the pinned private Rust construction and
ownership paths and ordinary memory safety. This is not whole-binary points-to
analysis or a stable Rust vtable ABI claim.

The worker-root graphs retain 32 indirect-call frontiers each, 169 portable / 163
accelerated native-edge frontiers, four indirect branches, and one positive-weight
recursive component containing 69 functions each. Exceptional terminals and
function-boundary fallthroughs also remain unresolved. The finite resolved-region
maxima stay 15,984 bytes portable / 13,232 bytes accelerated; these are not full
stack bounds. Neither the supplied 8 MiB stack's sufficiency nor complete 64 MiB
workspace sufficiency follows from resolving these seven sites conditionally.

The later [failure-entry calculation](../docs/validation/parliament_ballot_stack_frontiers/README.md)
locates 31 of the remaining 32 indirect sites behind three explicitly excluded
failure entries. Those cuts remove positive recursion, with each excluded edge
retained as an unknown-cost obligation. The reservation root then has no
indirect sites and the worker has one I/O error destructor. Caller-frame
contributions become 15,648/13,056 bytes for reservation and 15,984/13,392 for
worker entry. Exposing previously opaque component internals can increase a
partial number; none is a complete stack bound. Native/failure costs, unwind,
traps, fallthroughs and source-target premises remain unresolved. Panic absence
and allocation success for all admitted inputs have not been established.

A separate [activation check](../docs/validation/parliament_ballot_allocator_activation/README.md)
binds the worker's activation store and four false-only System allocation arms
in each original image. Conditional on private-state noninterference and the
stated source/compiler/ABI premises, these four sites can be excluded from the
worker-established ordinary reservation path. Ten System free sites remain.
Unconditional activation is unknown; unresolved aliases, callbacks, native and
exceptional behavior retain their prior obligations and unknown costs.

The separate [source ownership audit](../docs/validation/parliament_ballot_ownership/README.md)
finds no setup-owned container at reservation entry. The
[compiled free-predicate analysis](../docs/validation/parliament_ballot_free_predicates/README.md)
checks all ten sites per image for the observed arena's null/range predicate,
capacity guards and same-pointer forwarding. Combining these facts still
requires universal source-to-machine provenance and intact arena/provider
state; no unconditional free frontier is removed. The separate
[I/O tag guard](../docs/validation/parliament_ballot_io_error_guard/README.md)
checks a non-Custom return path and the ordinary charged-read source lemma,
without proving whole-worker variant flow or closing its indirect frontier.

TODO: establish complete target-specific allocation correspondence and
ordinary/exceptional path conditions; discharge the provider-target premises
and resolve remaining indirect stack sites and the runtime recursive component
without assuming a recursion limit; account for installed native/System/TLS
memory and stack; obtain independent
unsafe review and physical calibration. Keep `complete_arena_certificate`,
`complete_workspace_certificate` and `profile_qualified` false until their
respective requirements are met. Production availability remains false.
