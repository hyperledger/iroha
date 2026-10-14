# Typed request-family dispatch boundary

This audit reads the current staged public/generator/transition/controller
modules and the exact Rust public ballot APIs. The added components are
`request_dispatch.py` and `request_family.py` in the ignored ideal-machine
stage. No Rust, tracked source, production gate or frozen component was edited.
The implementation remains a conditional mathematical circuit construction.

## Actual public boundary and remaining shapes

The source interfaces are `registration::prove(Row, &RegistrationStatement,
&CredentialSecret, ProvingTape)` and `vote::prove(Row, &VoteStatement,
&CredentialSecret, u16, ProvingTape)`. `Row` has exactly Candidate/Comparator;
role is selected by the two distinct functions. There is no native error for
an arbitrary row or role string. Such Python factory errors are contract
validation of circuit metadata, not additional ballot outcomes.

`RegistrationStatement` has private fields. `BodyContext::new` enforces4096
bytes, `OpaqueField::new` enforces256 bytes, and fixed digests/commitments are
typed arrays. The registration instance relies on those bounds and the
constructor-derived body digest. Oversize body/context values, wrong fixed
lengths and malformed raw encodings therefore are upstream construction or
decoding outcomes, not unreachable branches that should be invented inside
the typed registration prover. All legal registration length families are
represented by PublicShape: body0..4096 and six lengths0..256, for either row.

`VoteStatement` exposes a `Vec<Commitment>` and a declared u16 size. Its native
validation order is:

1. VoteValue for vote bytes other than0/1/2.
2. List::Size when the actual vector length is outside3..1000.
3. List::Order at the first non-increasing adjacent pair.
4. ListLength when declared size differs from actual length.
5. ListDigest when the recomputed list digest differs.

These checks precede descriptor compilation in `vote::prove`. Each element is
already a128-byte Commitment; raw list byte counts not divisible by128 fail in
`sealed_list::split`, outside this typed method. Declaration size is not the
actual vector length and cannot replace it in the dispatcher.

Before this addition, PublicShape/P0 described only lengths0..1024. The
generator and content controller accept only3..1000. Thus size rejection for
0..2 and1001..1024 had a standalone P0 model but no request-family integration,
and every actual length at least1025 had no such family at all. A large-length
P0 extension would also truncate Size.actual to16 bits and perform needless
list/hash work. The new header circuit and rejected-size family close that
typed rejection class for every64-bit length word without inspecting any list
entry. On invalid vote bytes, VoteValue wins for every length.

For counts3..1000, the root-owned ContentRequest runs exact P0, totalized P1,
the generator, valid-controlled writes and the typed return, then clears its
derived state. It handles content rejection, primary exhaustion and success.
This is a finite overcomputation on invalid content, charged explicitly and
cancelled under the unchanged-F/no-interleaving premise. The new ContentFamily
only relocates its return into the common union; it does not replace P0.

## Header circuit and same-length binding

VoteHeaderDispatch takes vote8 and actual_length64. Its76-bit output is
continuation1, code3, actual_length64, vote8. Codes0/1/2 mean continue content
validation, VoteValue and List::Size. Only the selected payload is nonzero.
Continuation is not proof acceptance; the content validator must still run.

All three unsigned comparisons are explicit Boolean circuits. The emitted
clean map has284 X,398 CNOT and444 Toffoli gates:2902 elementary gates under
the existing five-gate Toffoli convention. It uses379 clean history bits,
72 input bits and76 caller output bits. It makes no F call and has no list,
log, counter, witness or random-tape input. Its supplied actual-length word is
the authenticated metadata of the same typed Vec. It does not authenticate
that word against an untrusted serialized payload.

RejectedVoteFamily has a fixed public n outside3..1000. It explicitly prepares
the64 bits of that same n, computes the header, copies the result into the
common union, invokes the clean header again and clears the constant word.
Preparing/clearing n costs2*popcount(n) X gates. Source-bound construction uses
the real vote proof capacity for the selected row. The family retains the
entire typed statement layout, `(451+128*n)*8` bits, including the untouched
`n*1024` list bits. Its interval layout is lazy; it allocates and reads no list.
Only the original vote8 wires are touched among its borrowed input registers.

Its cost is5881+2*popcount(n) elementary gates, with519 clean work bits and a
253+proof-bit target. There are zero sampled private coins and no F/log/counter
accesses. The log and counter are external retained registers left unchanged,
not absent storage whose lifetime cost can be erased. The family parameter
must come from the authenticated descriptor of the same request. A forged
length header, invalid pointer or unmatched body is not certified here.

The64-bit model matches the retained target's usize width. Tests at u64::MAX
exercise the total word circuit and exact payload without allocation; they do
not assert that Rust can allocate a Vec of that many128-byte values. Valid
slice/Vec memory bounds and architecture assumptions remain upstream. Another
word width requires an explicit adapted certificate rather than truncation.

## Common result union

The common mathematical result register has:

```text
tag2 || error_code3 || order_index64 || actual_length64 || declared_count16
|| vote_value8 || exhaustion_last32 || proof_length64 || proof_bytes
```

Tags are0 proof,1 exhaustion and2 public error. This is253 fixed bits plus
proof capacity, not native Rust enum memory or a new protocol wire format.
Both native usize payloads are represented at64 bits. Content P0 has16-bit
order/actual values, but its list bound makes their high48 bits provably zero.
ContentFamily statically relocates existing output wires and leaves those96
additional target bits untouched, meaning zero XOR contribution even for a
nonzero old target. Gates, original inputs, log/counter and work are unchanged.

The rejected-header projection copies code3, actual64 and vote8 and XORs
`1 XOR continuation` into the high tag bit. This costs75 payload CNOTs, one
continuation CNOT and one X:77 gates. Order, declared size, exhaustion last,
proof length and proof all contribute zero. Arbitrary old result targets are
preserved where the contribution is zero; no erasure of caller data is claimed.

A registration-only RequestTransition still has its97+proof-bit envelope.
If a single result register across both roles is required, its exhaustion flag
maps to common tag bit0 and its remaining fields shift by156 bits; all public
error fields contribute zero. That static adapter is straightforward but is not
implemented by this vote-family component. Separate typed role entrypoints
can instead retain their explicit return types.

## Classical family selection and accounting limits

Honest requests in the frozen experiment are classical and atomic. A public
length/row/role may therefore select the corresponding fixed circuit family;
this is not superposition access to proof generation. For VOTE, a valid
authenticated n selects ContentFamily exactly when3<=n<=1000, otherwise
RejectedVoteFamily. Vote content and declared size never select a different
size family. The fixed rejected family still runs the source-priority header
for every vote byte. The header predicate is priced, but a trusted host family
selector/descriptor reader is not thereby a certified raw input parser.

The accepted registration family set has `2*4097*257^6` size/row members and
the bounded vote content set has1996. These are finitely indexed circuit
families, not a claim that a giant coherent multiplexer or runtime code
generator is free. Wire-index/gate-stream specification is classical circuit
description; its physical execution/compiler overhead is not priced by this
logical gate census. An accepted uniform dispatcher/lifetime resource theorem
must state its finite input encoding and controller model explicitly.

Transport, parsing, allocation, authentication of length descriptors and raw
parameter decoding are not implied by a borrowed typed-argument map. A network
endpoint may need to receive/reject oversized payloads; neither T nor an oracle
query cap bounds their total byte lengths. Source constructors have distinct
BoundExceeded/FixedLength/EntryLength outcomes and caller-selected invocation
order; there is no universal raw-request error priority to infer here.

Source `verify` additionally rejects proof length before public vote validation;
that is a different API and is not modeled by this prover-request dispatcher.
Profile/table/environment failures, allocation/panic behavior, entropy-source
failure before a tape exists, and native runtime cleanup remain separate.
The native prover also checks application witnesses; the witness-free ideal
simulator's valid-request comparison premise does not prove an actual-input
primitive bridge or admit arbitrary bad-witness requests for free.

## Validation and freeze scope

The header module has35 passing tests, including all256 vote bytes at15 length
boundaries, every high bit beyond16, exhaustive8-bit comparator controls,
arbitrary-target clean maps, source drift and missing-uncompute. An initial
helper test found that allocating internal flags before validating a supplied
wire could legitimize an out-of-range index; it is fixed by validating against
the pre-call inventory. Exact prior helper and failed JUnit are retained here.

The family module has38 passing tests. Sparse states cover n=0/1/2/1001/1024,
65536 and u64::MAX with source error precedence, unchanged borrowed inputs,
exact gate census, actual header length, clean inverse and dirty-work mutation.
Content tests use the root's explicitly synthetic orchestration fixture to
test every result field, complete log/state identity, arbitrary old targets
and static zero-extension. Their source cryptographic semantics come from the
separate component reviews, not the synthetic fixture.

Independent family review is complete: 37 separate controls passed and the
reviewed helper/test identities stayed fixed. The controls independently check
the common field map, high padding targets, retained log identity, true inverse,
full-width rejected lengths, untouched input storage and exact resource census.
Its receipt and notes live in `target/parliament-family-review/`.

Selected source identities bind the reviewed Rust paths; they do not establish
a compiler/dependency closure or native execution. The root owns final composed
capture. No full actual cryptographic gate stream, Cargo build or native worker
execution occurred here.

TODO: finish the reviewed common-family integration and final capture, then
retain explicit typed-descriptor, classical-selection, whole-joint-projection,
primitive-entry and physical-workspace obligations. Full simulator coverage,
complete resources and every production/qualification flag remain false.
