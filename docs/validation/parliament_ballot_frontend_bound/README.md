# Historical verification frontend contribution

This is a conditional resource argument for the exact fatal-control binaries in
[the EON capture](../parliament_ballot_fatal_stack_eon/README.md). It advances
B6.4 through the outer record parser, reservation dispatcher and a separate
framed-field loop. It supplies no full verification work, stack or workspace
certificate. Production qualification remains false.

The [checker](analysis/parliament_ballot_frontend_bound.py.template) mechanically checks
exact bodies, ordinary control flow, fixed parser call arguments, local frame
analysis and call multiplicities. The [report](analysis/report.json) records the result.
The source arguments below are reviewed lemmas over eight hash-bound files in
[source](analysis/source/), not an automated Rust semantics proof.

## Historical scope and premises

The report preserves all 2,081 identities from the prior adapter report. Four
changed files are resolved to separate files in the
[historical recovery bundle](../parliament_ballot_adapter_source_recovery/README.md).
Their bytes must match the **original** hashes. The other identities must still
match their original paths. The original adapter report, build receipt, EON
manifest and validated recovery receipt are independently pinned. The checker
rehashes the resolved inputs before and after analysis, verifies build-source
membership and binary identity across build/capture, and snapshots the reviewed
frontend sources. It records four live source differences separately and always
sets `applies_to_current_checkout=false`. No old checker, evidence pin, source or
binary was replaced; this analysis does not qualify a build of the live checkout.

The conditional boundary uses ordinary Rust/compiler/ARM64 ABI and memory-safety
premises: valid typed `Row`/`Role`, a live immutable record slice, valid return
storage, no data races or asynchronous/reentrant mutation of private invocation
state, and ABI-preserving calls. For a granted reservation, the length is at most
425,984 and the byte debit is the original length. Allocation/decoder/crypto/drop
callees are opaque: on an ordinary return they must preserve the caller's live
record, stack, private allocator state and all other still-live owned objects;
their returned values must satisfy their Rust type/ownership contracts. Native
`memcpy`/`memcmp` calls have valid ranges and their usual copying/comparison
semantics, preserve unrelated memory and do not callback or unwind. These
premises do **not** set any callee cost to zero or establish allocator sufficiency.

All ordinary direct-call continuations and conditional branches remain in the
CFG. There is no speculative native no-return inference. Exceptional entry,
unwinding, process abort, allocator exhaustion and nonreturning work inside an
opaque callee retain their separate obligations. The local instruction limits
also bound the ordinary caller prefix before such a call, but do not bound the
callee's exceptional continuation, runtime resources or elapsed time.

## Outer record and reservation

For both images, `decode_record` has 55 reachable instructions, no call, no cycle
and no stack decrement. Its longest CFG path has **34 issued instructions**.
With the audit's conservative 128-byte red-zone allowance, its own stack bound
is 128 bytes. Its source performs exactly four bounded slice-taking attempts:
two four-byte length prefixes and two payload slices. It allocates no payload
and returns only borrows. Success implies the exact partition
`N = 8 + statement_len + proof_len`, no trailing bytes, and `proof_len` equal to
the selected row/role's fixed proof size. A malformed length never controls a
loop. The compiled SUBS/bounds branches precede payload pointer formation;
proof-length equality and final zero remainder precede the success return.

`Reservation::verify` contains the inlined `verify_cold` coordinator. Its 186
reachable instructions form an acyclic ordinary graph; the longest path is
**112 issued instructions**. It reserves a 2,032-byte local frame. Thus its own
work plus the record leaf is at most **146 issued instructions**, and their
combined owned stack is **2,160 bytes**, including one 128-byte red-zone allowance.
Neither figure includes the other callees' work or additional stack.

The checker derives these ordinary-path call limits, treating branch outcomes
conservatively and leaving their costs opaque:

| Contribution | Maximum calls on a path |
| --- | ---: |
| `Profile::new` | 1 |
| `decode_record` | 1 |
| Either typed statement decoder, combined | 1 |
| Either role verifier, combined | 1 |
| Vote vector cleanup | 1 on the vote branch |
| Body vector + registration-context cleanup | 1 each on the registration branch |
| Native `memcpy` | 2 |

The three possible native-copy sites have fixed lengths 642, 424 and 368 bytes.
The latter two are exclusive role branches, so at most 1,066 bytes are copied
by these coordinator sites. The record payload is borrowed here; this count is
not an estimate of later hash/crypto copies.

Let `I_P`, `I_Dr`, `I_Dv`, `I_Rr`, `I_Rv`, `I_B`, `I_C`, `I_L` denote opaque
nonnegative work limits for profile construction, the two typed decoders, the
two role verifiers and body/context/list cleanup; let `M(n)` denote native copy
work. The ordinary-return composition is:

```text
I_Reservation <= 146 + I_P + M(642)
                 + max(I_Dr + M(368) + I_Rr + I_B + I_C,
                       I_Dv + M(424) + I_Rv + I_L)
S_Reservation <= max(2160, 2032 + max(S_P, S_Dr, S_Dv, S_Rr, S_Rv,
                                    S_B, S_C, S_L, S_memcpy))
```

These are formulas with unresolved terms, not numerical total bounds. Native
routines may carry hidden stack/TLS/runtime costs; the formula requires those
costs in their corresponding terms. In the earlier adapter formula, these
expressions can replace the opaque `Reservation::verify` term without changing
the caller's retained 176-byte frame.

On an ordinary source return, the token is consumed once and the `Receipt`
contains the original charge plus a fixed-size `Copy` result. No reservation
refund, retry, counter search or cache lookup occurs in this coordinator. Each
successfully decoded local statement goes out of scope before the receipt,
including on a role-verifier error. Partial construction and decoder-local
cleanup belong to the typed decoder's opaque cost. This proves source-visible
ownership/return shape; it does not prove universal allocator pointer provenance
or absence of hidden backend/native allocations. The caller still owns the
record allocation and must release it under the earlier adapter premises.

## Separate framed-field loop

The private `parse_frame` source accepts only the two reviewed call sites. Both
compiled callers pass literal parameters immediately before the call:
registration tag length 16 / field count 11; vote tag length 17 / field count 10.
The function rejects the encoded field count before `Vec::with_capacity`.
Every field attempt reads a four-byte prefix, bounds the borrowed payload and
pushes one slice descriptor. Zero-length fields do not evade progress.

The machine loop initializes `x23=0`, retains the trusted count in `x20`, adds
one to `x23` after each push, then compares it to `x20`. Its only cycle-closing
edge is the not-equal fallthrough at portable `0x10000e608 -> 0x10000e60c`
(accelerated addresses are four bytes higher). Under the fixed positive count
and ordinary call-preservation premise it is taken at most `count-1` times.
The checker removes that single edge to verify a DAG, then unrolls its bounded
budget while retaining both growth/no-growth branches and every call continuation.
It does not assume successful allocation, zero-cost growth or nonreturning panic.

| Local parser contribution | Registration | Vote |
| --- | ---: | ---: |
| Field attempts | 11 | 10 |
| Loop-continue edge budget | 10 | 9 |
| Issued instructions, excluding callees | 299 | 277 |
| Native tag `memcmp` calls | 1 | 1 |
| `with_capacity` calls | 1 | 1 |
| `grow_one` calls (conservative) | 11 | 10 |
| Ordinary error-path deallocation calls | 1 | 1 |
| Own frame including red zone | 240 bytes | 240 bytes |

`parse_frame` has 114 reachable instructions and a 112-byte fixed frame. Native
tag comparison covers at most 16/17 bytes. Slice descriptors have a logical
initialized payload of at most 176/160 bytes on this 64-bit target. This is not
a capacity or allocator-rounded-block bound. A successful parser returns the
owned descriptor vector; its later release belongs to the typed decoder. The
separate parser contribution must **not** be added again while the complete
typed-decoder work remains opaque in the reservation formula above.

## Source length and ownership constraints

The source checks each registration body-context length against 4,096 and each
of six opaque context lengths against 256 **before copying that field**. A
successfully decoded registration owns seven byte vectors with total logical
length at most 5,632 bytes. The other encoded fields have fixed sizes. This gives
`TEST_STATEMENT_REG <= 64 + 5632 + 320 = 6016` bytes (64 bytes of framing).

The vote decoder checks list-byte divisibility by 128 and entry count 3 through
1,000 before splitting/copying entries. It owns one list vector of at most
128,000 logical bytes. All other fields are fixed-size; thus
`TEST_STATEMENT_VOTE <= 61 + 515 + 128000 = 128576` bytes. Its source list split
copies at most 1,000 entries, and ordered-list validation performs at most 999
adjacent comparisons. List digest construction and the compiler/native cost of
copying, comparison and hashing remain separate. Temporary buffers inside those
operations are not included in the successful statement's owned-vector counts.

Adding the exact row/role proof length and eight-byte outer framing gives:

| Row / role | Maximum canonical record bytes |
| --- | ---: |
| Candidate registration | 166,172 |
| Comparator registration | 115,522 |
| Candidate vote | 361,596 |
| Comparator vote | 286,658 |

These are bounds on records whose typed statement decoder succeeds, whether or
not the proof later verifies. They establish that all supported canonical test
records fit the 425,984-byte admission cap. They do not describe a production
schema or assert that malformed admitted statements are this short; malformed
inputs remain bounded by the admission cap and the same field-iteration limit.

## Validation and next boundary

Run the focused checker tests and write a fresh observation:

```sh
.venv/bin/python -m pytest -q scripts/tests/parliament_ballot_frontend_bound_test.py
.venv/bin/python scripts/parliament_ballot_frontend_bound.py \
  --root "$PWD" --output /private/tmp/parliament-frontend-new
```

The retained [test transcript](tests.txt) records **27 passing focused tests**.
The [review receipt](test-and-review-receipt.json) binds the tested/reviewed bytes
and records independent source, compiled-body and provenance reviews.

The suite checks historical identity resolution, source/recovery drift,
unambiguous JSON, unknown control/call refusal, acyclic and bounded-cycle path
metrics, both actual images, branch/count mutations, frame-report mismatch,
UNKNOWN persistence and existing-output refusal. The next useful local boundary
is a typed decoder's complete normal path: fixed-size field validation, bounded
copy/hash requests and error cleanup. The current artifact intentionally leaves
those callees, lower-level cryptography and native/runtime costs unresolved.
