# Historical profile-constructor contribution

This conditional argument replaces the opaque outer `Profile::new` coordinator
in the [frontend formula](../parliament_ballot_frontend_bound/README.md) with a
bounded local contribution and named unresolved callees. It concerns the exact
fatal-control binaries and their recovered historical source identities. It
does not establish a complete profile-construction or verification bound.

The [checker](analysis/parliament_ballot_profile_bound.py.template) and
[report](analysis/report.json) retain their complete source/capture dependency
chain. The frozen frontend helper and report have independently fixed hashes;
the helper resolves the original adapter identities through the separately
retained historical recovery. All resolved bytes are checked before and after
analysis. Four live-source differences are recorded separately; no evidence is
repinned and `applies_to_current_checkout` remains false. No worker was rebuilt
or executed for this argument.

## Ordinary control and the two-role loop

Both images have the same local geometry: 672 ordinary reachable instructions,
a 1,632-byte fixed frame, and 1,760 own stack bytes including the audit's
128-byte red-zone allowance. Exact whole-function bodies are pinned, including
their separately unresolved exceptional landing pads. The analyzer recomputes
frame information from the retained disassembly before deriving the local CFG.

There is exactly one ordinary cycle. It is the source `Role::ALL` loop,
implementing the two namespaces and prefixes. At portable address `0x10000f790`,
`w8=0`. The header at `0x10000f80c` copies `x8` into the callee-saved `x20`.
No ordinary instruction inside the loop changes `x20`; an ordinary call must
preserve it under the ABI premise. At the bottom, `w8=1` and `w9=1` precede
`tbz w20,#0` at `0x10000fc14`. The first successful iteration returns to the
header, which now sets `x20=1`; the second cannot take the back edge. An error
from the namespace-frame callee leaves the loop earlier. Accelerated addresses
are four bytes higher. There is no data-dependent retry or later re-entry.

Removing this back edge leaves a DAG. The checker computes longest paths with
an edge budget of one, preserving both sides of every conditional branch and
every ordinary call continuation. Under the loop and ABI premises, this gives
**834 local issued instructions**, including call instructions but excluding
callee bodies. It is neither a cycle count nor a time or gas calibration.

| Opaque callee | Maximum calls per ordinary path |
| --- | ---: |
| `crt_table_digest` | 1 |
| Parameter-array concatenation | 1 |
| Relation-dimension concatenation | 1 |
| Descriptor `frame_bytes` | 1 |
| Descriptor `sha3_512` | 1 |
| Namespace `frame_digest` | 2 |
| Rust deallocator | 3 |

There are five possible ordinary deallocation sites but at most three on any
path. All call targets and multiplicities are checked; no callee is assumed to
be free or to return. A callee that aborts or does not return may stop the local
prefix, but its own resources and exceptional continuation remain unresolved.

## Source correspondence and ownership

The source `Profile::new` and inlined `descriptor_bytes` are retained in
[source](analysis/source/). A valid typed `Row` selects one of two fixed embedded
tables and fixed parameter values. Caller record bytes do not control these
dimensions. The coordinator makes one CRT-table digest call, concatenates six
two-byte parameters and four four-byte dimensions, and constructs the descriptor
frame from six bounded fields. Those two concatenations have logical outputs
of 12 and 16 bytes. The descriptor is checked to have exactly 286 bytes before
its fixed-size array conversion. Neither fact is an allocator-capacity bound.

Descriptor hashing consumes that 286-byte array. Each namespace digest frames
the fixed 64-byte descriptor digest and the three-/four-byte role label; its
framed input is 89/90 bytes. These are the source requests passed to the opaque
hash/frame callees, not their compiled cost or temporary-memory bounds. CRT
serialization, hashing, frame construction and allocation beneath those calls
remain in their corresponding terms.

The two temporary parameter/dimension vectors are released after descriptor
construction, including its ordinary error return. The descriptor vector is
released on length failure, namespace failure or successful construction.
The successful `Profile` contains fixed arrays and a typed row and is `Copy`;
it retains none of those vectors. This is source ownership reasoning under
the callees' Rust contracts, not a universal proof of allocator pointer origin,
runtime erasure, absence of hidden allocation or correct machine cleanup.

The machine path requires valid return storage and typed row, an available
stack, no data race/asynchronous mutation/re-entry, and ordinary ABI-preserving
callees. Returned vectors/results must satisfy their Rust layout, length and
ownership contracts and preserve every other live object. These premises are
explicit: finite traces do not establish them. Unwinding and exceptional entry
at the retained landing pads are outside the ordinary path and remain unknown.

## Symbolic composition

Let `I_CRT`, `I_PC`, `I_DC`, `I_F`, `I_H`, `I_NS`, and `I_free` be nonnegative
work bounds for the named callee categories. Let `S_k` be each callee's complete
additional stack, including any native/runtime needs. Then:

```text
I_Profile <= 834 + I_CRT + I_PC + I_DC + I_F + I_H
                   + 2*I_NS + 3*I_free
S_Profile <= max(1760, 1632 + max_k S_k)
```

The generic namespace bound must cover either role; the generic deallocation
bound must cover each actual layout. The older reservation formula can replace
its opaque `I_P,S_P` with these expressions, retaining the reservation's
2,032-byte caller frame. This yields 980 local reservation/record/profile
instructions and a 3,792-byte owned stack contribution along the profile path,
with the other verification and all lower callee costs still unresolved. These
are not whole-call numerical totals. Do not add the profile contribution again
after substituting it into that formula.

## Reproduction and remaining work

```sh
.venv/bin/python -m pytest -q scripts/tests/parliament_ballot_profile_bound_test.py
.venv/bin/python scripts/parliament_ballot_profile_bound.py \
  --root "$PWD" --output /private/tmp/parliament-profile-bound-new
```

The focused controls cover both historical images, source/helper identity
changes, role-loop/frame/call mutations, unknown callee refusal, stale frame
results, before/after input drift, UNKNOWN persistence and existing-output
refusal. The [test and review receipt](test-and-review-receipt.json) records the
executed checks and their source interval. Complete CRT/hash/frame/allocator
costs, machine/source correspondence, native and exceptional resources, physical
calibration and independent implementation review remain open. Production
qualification and the complete workspace certificate remain false.
