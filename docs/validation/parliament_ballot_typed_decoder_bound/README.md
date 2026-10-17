# Historical typed-decoder contribution

The two complete outer typed-decoder bodies have finite, acyclic ordinary
control flow in both retained fatal-control images. Their own work is bounded
by **322 registration / 315 vote issued instructions**. Substituting the
previously bounded framed parser gives **621 / 592 local instructions** and
**1,824 / 1,184 bytes of owned stack**, including the conservative red zone.
All lower callees remain explicit terms. These results do not certify total
verification work, workspace sufficiency or production readiness.

The [checker](analysis/parliament_ballot_typed_decoder_bound.py.template) and
[report](analysis/report.json) extend the frozen
[frontend evidence](../parliament_ballot_frontend_bound/README.md). All 2,103
resolved historical guards matched before and after analysis. Four live source
differences remain separately reported, and current-checkout applicability is
false. The prior 15-file manifest, exact typed bodies, original build/capture
chain, recovered input identities and loaded helper bytes are verified. Nothing
was rebuilt, repinned or changed in prior evidence.

## Boundary and ordinary-return premises

Inputs may be **arbitrary malformed statement bytes up to 425,984 bytes**.
Neither a successful canonical statement nor its smaller size maximum is a
precondition. In the memory-entry flow, successful outer-record parsing supplies
a borrow no larger than that admitted record. `Profile` is a valid previously
constructed value, returned storage is valid, and the immutable input remains
live throughout decoding.

The source/compiled correspondence uses ordinary Rust ownership, compiler and
ARM64 ABI/memory-safety premises. A returning callee must preserve live caller
stack, input, private allocator state, owned objects and callee-saved registers,
and meet its Rust return-value contract. There is no concurrent, asynchronous
or reentrant mutation of this private state. Valid native `memcpy` calls preserve
unrelated memory, do not overlap, callback or unwind, and permit zero-length
copies with the retained aligned dangling pointer without accessing memory.
These premises neither bound native/runtime resources nor prove allocator
ownership for every backend pointer.

Every ordinary conditional branch, direct-call normal continuation and partial
cleanup path is retained. Longest-path metrics conservatively consider all CFG
branch choices; no success-only trace is substituted for the universal argument.
The `RegistrationStatement::new`, `OpaqueField::new`, `sealed_list::split`,
`VoteStatement::validate`, drop, allocation, shim and native bodies remain
opaque. Their own exceptions, nonreturning work, stack/TLS and other hidden
resources are not covered by a decoder-local number.

## Machine contribution and call limits

| Contribution | Registration | Vote |
| --- | ---: | ---: |
| Ordinary reachable instructions | 512 | 422 |
| Longest local instruction path | 322 | 315 |
| Local stack frame | 1,584 bytes | 944 bytes |
| Local frame + red zone | 1,712 bytes | 1,072 bytes |
| Local instructions including framed parser | 621 | 592 |
| Owned stack including framed parser and red zone | 1,824 bytes | 1,184 bytes |
| Live caller stack at parser's opaque callees | 1,696 bytes | 1,056 bytes |

Each decoder calls `parse_frame` at most once. The helper substitutes its
previously proved 299/277-instruction contribution and 112-byte frame, without
adding a second copy of the whole parser term. The following maxima exclude
calls *inside* these opaque bodies:

| Direct opaque contribution | Registration maximum | Vote maximum |
| --- | ---: | ---: |
| `__rust_alloc` | 2 | 0 |
| allocation shim | 2 | 0 |
| `__rust_dealloc` | 7 | 2 |
| `OpaqueField::new` | 5 | 0 |
| `RegistrationStatement::new` | 1 | 0 |
| registration-context drop | 1 | 0 |
| complete registration-statement drop | 1 | 0 |
| `sealed_list::split` | 0 | 1 |
| `VoteStatement::validate` | 0 | 1 |
| native `memcpy` | 4 | 1 |
| `alloc::raw_vec::handle_error` | 1 | 0 |

Independent maxima need not occur on the same path. In particular, registration
has at most seven direct outer cleanup calls in total, counting deallocation
and both composite drop kinds together; voting has at most two. These are call
counts, not proofs that free is bounded or that a pointer cannot reach System.
Inside the parser there are separately at most one tag `memcmp`, one capacity
allocation, 11/10 growth calls and one error-path deallocation. Its later
successful-vector cleanup is already represented in the outer decoder table.

For the registration decoder, portable allocation-error call sites
`0x10000ef98` and `0x10000efa8` are retained. Their hypothetical ordinary returns
reach `BRK #1` at `0x10000efac`; the accelerated sites are four bytes higher.
The report includes that exceptional frontier with unknown continuation work
and stack. It does not infer that `handle_error` returns, does not assume it
never returns, and does not reinterpret the trap as a successful return. The
local count includes the trap instruction if reached; exception handling or
resumption beyond it is unresolved. Unwind landing pads have no ordinary CFG
entry and remain outside this ordinary-entry claim. Neither table closes any
backend/native exceptional frontier.

## Bounded copy requests and length checks

All request bounds below apply even when a later check rejects the statement.
The checker verifies that removing a required guard edge makes the corresponding
allocation/copy/split call unreachable. The edge predicates and operand flow
are reviewed against the exact body hash; this is not an arbitrary-ARM symbolic
execution engine.

For registration, portable `0x10000e908` keeps the unsigned `body_len<=4096`
branch. That edge dominates the inlined body allocation and copy. The bounded
length remains in callee-saved `x20` and supplies the allocation size and copy's
`x2`. Portable `0x10000e9b8` similarly requires the first opaque field's length
to be at most 256 before its allocation/copy. Its length is kept in the private
stack slot, preserved around allocation, and reloaded into the copy's `x2`.
Zero-length paths retain their legal no-access copy. The other two direct
registration copies are fixed 368- and 424-byte structure transfers. Thus at
most **5,144 bytes** are requested by the four direct `memcpy` sites, excluding
all lower callees' copying. The vote success transfer is fixed **480 bytes**.

The five out-of-line `OpaqueField::new` calls can receive arbitrary borrowed
field slices up to the admitted cap, **not necessarily at most 256 bytes**.
Their hash-pinned source checks the 256-byte cap before `to_vec`. Together with
the first inlined field and body check, source-visible owned payload copies
are at most 4,096 + 6*256 = 5,632 bytes on any construction path. This does not
bound the allocation capacity or account for composite objects' implementation
copies, and the helper leaves each opaque constructor's cost unresolved.

For voting, portable `0x10000df74` requires the list length's low seven bits to
be zero. The shift then computes `entries=len>>7`; `SUB entries,3`, unsigned
comparison against 998 and the non-`HS` edge at `0x10000dfcc` admit exactly
3 through 1,000 entries. Unsigned underflow rejects 0, 1 and 2. The cap also
excludes any larger or wrapping count for a valid admitted length. Both edges
dominate `sealed_list::split`. The same list pointer/length is passed, so split
receives at most **128,000 bytes / 1,000 entries**, despite arbitrary bytes in
other fields. Its body and allocation work stay opaque. Fixed-size fields are
checked before their fixed loads/copies, and no input field length controls an
outer decoder loop.

## Hash requests and partial ownership

The reviewed sources are the eight files retained by the
[frontend source snapshot](../parliament_ballot_frontend_bound/analysis/source/).
`RegistrationStatement::new` is called at most once with already bounded owned
body/context values. Its source requests one body digest at most:

```text
SHA3-512(Frame("PARL/BODY/v1"; P16, body_context))
framed length <= 2 + 12 + 2 + 2*4 + 16 + 4096 = 4136 bytes
```

The frame writer makes three fixed header absorptions and two absorptions per
field: at most seven SHA3 update requests and one finalization for this body
digest. Those are source-level API request counts; the complete constructor,
framing and hash implementations remain opaque cost terms.

The vote decoder invokes public validation at most once. Its source checks the
vote value, then list length/order with at most 999 adjacent comparisons, then
the declared size, and only then requests one list digest at most:

```text
SHA3-512(Frame("PARL/LIST/v1"; P16, B, u16_le(S), concat(L)))
framed length <= 2 + 12 + 2 + 4*4 + 16 + 64 + 2 + 128000 = 128114 bytes
```

That source request has at most eleven SHA3 update requests and one
finalization. `concat(L)` constructs a separate temporary of at most 128,000
logical bytes; this buffer must be counted in a later heap-liveness argument.
No bound on hash/native instructions or stack is invented from the byte count.
These hash requests are nested in already opaque constructor/validation costs;
adding them on top of those complete costs would double-count them.

The source parser's descriptor vector contains borrowed slices; its payload
owners stay with the original immutable record. Registration construction owns
the body and each opaque field in evaluation order. If a later field or fixed
value check fails, Rust drops the already constructed values before returning
an error. Construction transfers body/context ownership into the constructor;
its internal cleanup on an error belongs to its opaque cost. After successful
construction, a bad supplied body digest drops the complete local statement.
On success, seven vectors move into the returned registration statement.

Voting may allocate its list before some later fixed-size or public-validation
checks. Each such ordinary error releases that list and the descriptor vector.
On success, its one list vector moves into the returned vote statement. Errors
are fixed-size `Copy` values and return no source-visible owned vectors.
Allocator abort, unwinding or a trap does not produce an ordinary error return
and carries no cleanup-completion claim here. These source ownership facts do
not establish a universal compiled free-pointer origin or free cost.

## Composition and remaining boundary

Let `C_r`, `C_v` be the *opaque callee* part of the framed parser, excluding its
299/277 local instructions. Let `A[k]`, `M[k]`, `O[k]` be nonnegative upper costs
over every permitted argument of length at most `k` to allocation, native copy
and opaque-field construction. This notation does not assume cost is monotone
in length. Let `H`, `F`, `E`, `N`, `D_C`, `D_R`, `L`, `V` denote opaque work for
shim, deallocation, handle-error, statement construction, context drop,
statement drop, list split and public validation. A conservative ordinary
composition, or caller-prefix bound up to the retained exceptional frontier, is:

```text
I_decode_registration <= 621 + C_r + 2H + A[4096] + A[256]
                         + M[4096] + M[256] + M[368] + M[424]
                         + 5O[425984] + N + 7F + D_C + D_R + E
I_decode_vote         <= 592 + C_v + L + V + M[480] + 2F
```

The standalone `E` term is conservative on ordinary returns and leaves its
possible exceptional behavior unresolved. Parser callee multiplicities remain
11/10 growth calls even though the source's capacity contract could make growth
infeasible; the checker does not rely on that additional elimination.
For stack, if `S_r` / `S_v` are maxima of the **direct** opaque callee stack
terms, and `S_Cr` / `S_Cv` maxima for the parser's opaque callees:

```text
S_decode_registration <= max(1824, 1584 + S_r, 1696 + S_Cr)
S_decode_vote         <= max(1184,  944 + S_v, 1056 + S_Cv)
```

Substitute these expressions for the corresponding opaque typed-decoder terms
in the frontend coordinator. Its 2,032-byte caller frame and the adapter's
176-byte frame remain live. No complete total follows until the symbolic terms
and exceptional scope are bounded. The smallest next local unit is a bounded
copy/constructor or public-validation callee with its hash/allocator boundary
still explicit; a full cryptographic/runtime certificate remains separate.

The retained [test transcript](tests.txt) records **24 passing focused tests**.
The [test and review receipt](test-and-review-receipt.json) binds the tested
bytes, independent root/ownership reviews and the final guard verification.

Run only the focused suite and a fresh checker output:

```sh
.venv/bin/python -m pytest -q scripts/tests/parliament_ballot_typed_decoder_bound_test.py
.venv/bin/python scripts/parliament_ballot_typed_decoder_bound.py \
  --root "$PWD" --output /private/tmp/parliament-typed-decoder-new
```
