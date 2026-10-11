# Norito Format (v1)

This document is the source of truth for Norito's on-wire encoding in the
Iroha workspace. It defines the header, flags, and the canonical length and
string layouts used across components.

Norito's first-release Rust implementation targets `std` only. There is no
WASM/no-`std` codec branch, panic containment is always active at fallible
decode boundaries, and build features do not weaken those safety rules.

Rust bare payload writers use the object-safe `SerializePayload` contract.
`NoritoSerialize` adds typed frame ownership. Borrowed field adapters can
implement or derive `SerializePayload` without acquiring a root-frame identity;
generic frame writers require `NoritoSerialize` explicitly. This separation
does not change the V1 header, payload layout, checksum or signed bytes.
`core::PayloadRef` forwards an existing field's binary and JSON serialization,
length hints, and errors without inserting a wrapper field. It has no decoder
or frame identity; its containing record retains the canonical schema.

`DeserializePayload<'a>` owns `deserialize` and `try_deserialize` within the
active bounded payload context. Both typed frame directions are blanket
implementations over the corresponding payload trait and `NoritoSchema`.
`NoritoSchema::static_nominal_name()` may expose a complete literal nominal
identity without copying it. `schema::identity::nominal_name::<T>()` borrows that
literal or retains the existing owned generic composition. Derives expose a
literal only when there are no type, const, or erased lifetime arguments. This
changes no identity bytes, frame projection, payload layout, or schema hash.
Derives also expose `static_frame_name()` for a complete literal root identity:
the explicit `frame` declaration, or the complete nominal literal when there
is no projection. Dynamic generic and erased lifetime names remain composed
unless a fixed root projection is explicitly declared. Frame hashes and bytes
are unchanged; generic-name and serializer resource admission remain separate
obligations.

`NoritoSchema` declares one nominal identity and one root-frame projection;
`schema::identity::frame_hash` computes the fixed digest used by every typed
reader and writer. Neither direction has an independent hash method.
Codec derives emit payload implementations; use `#[derive(NoritoSchema)]` with
`#[norito_schema(name = "...")]` for a framed owner. A field-only payload
needs no frame identity. The retired `#[norito(schema_name = "...")]`
attribute is rejected.

Bare `Decode` requires `for<'de> DeserializePayload<'de> + SerializePayload`.
Canonical field/container decoders use those payload contracts for
reconstruction and byte comparison; exact slice helpers use `DeserializePayload`
with `DecodeFromSlice`. They do not require a frame identity. Typed frame callers
explicitly require the appropriate `NoritoSerialize`/`NoritoDeserialize`
contracts. Option fields use the same
canonical child decoder as other owned fields, preserving advertised layout
flags and field, allocation and nesting limits. Option, tuple and result slice
decoders reject unread bytes inside a declared child field with a typed length
error in every build profile; bytes after the complete outer value remain
available to a prefix-decoding caller.

`Decode`/`NoritoDeserialize` and `DeserializePayload` derives accept
`#[norito(validate = "path")]` for fallible owner validation. The function
consumes the reconstructed value and returns `Result<Self, norito::Error>`;
typed errors propagate unchanged. Each successful reconstruction invokes the
hook once, including generated slice decoders and unit records. Serializers
and JSON decoders do not invoke this binary hook. Validation must preserve
canonical fields rather than normalize external input.

`MultisigPolicy` and `MultisigMember` use this hook to call their existing
checked constructors directly. Their private field carriers serve strict JSON
decoding only; binary decoding retains the public owners' declared identities
and does not cast archived values to a second wire type.

## KAGEMUSHA ledger verifier installation

The first-release `KagemushaWalletLedgerActionV1` includes the closed
`InstallVerifierPack { asset: [u8; 32], manifest_digest: [u8; 32], pack: Vec<u8> }`
action. The enclosing instruction retains its original exact scheme identity.
These fields carry an installation request, not a native proof verdict. Core
requires the real registered reserve account and asset permission, independently
pins the signed manifest identity, authenticates every native original, and
stores one immutable canonical World row. The row's fixed key tag is 14; its
value schema and bounds are specified in
[`kagemusha_wallet_wire_v1.md`](specs/kagemusha_wallet_wire_v1.md#310-ledger-native-verifier-installation).
Existing proof-consuming actions use that same-overlay installed owner and
retain native proof quotas and complete accumulator decisions. No alternative
or compatibility action accepts retired artifact layouts.

## Contract error presentation metadata

The V1 `EmbeddedContractInterfaceV1` payload appends `error_messages` after
`error_types`. Each entry is the ordered record `(error_type: String, code:
u32, message: String)`. The catalog is sorted uniquely by UTF-8 identity and
numeric code, references declared variants, and limits each nonblank message
to 4096 UTF-8 bytes. `ContractManifest` and its signature payload carry the
optional catalog between `error_types` and `kotoba`; empty compiler catalogs
are represented as `None` there. `ContractRejection` appends `message:
Option<String>`, resolved from the originating authenticated interface.
Presentation text does not enter nominal error descriptors or their schema
hashes. It remains covered by the complete artifact hash and manifest signature.

## Header

The Norito header is always present on wire and on disk. It frames the payload
and supplies the schema hash and checksum needed for deterministic decoding.

| Field | Size (bytes) | Notes |
| --- | --- | --- |
| Magic | 4 | ASCII `NRT0` |
| Major | 1 | `VERSION_MAJOR = 0` |
| Minor | 1 | `VERSION_MINOR = 0x00` |
| Schema hash | 16 | First 16 bytes of a domain-separated SHA-256 schema digest |
| Compression | 1 | `0 = None`, `1 = Zstd` |
| Payload length | 8 | Uncompressed payload length (u64, little-endian) |
| CRC64 | 8 | CRC64-XZ (ECMA polynomial, reflected, init/xor all ones) over the payload |
| Flags | 1 | Layout flags (see below) |

Total header size: 40 bytes.

Alignment padding:
- For uncompressed payloads, encoders must insert zero padding between the
  header and payload when the archived type's alignment would otherwise be
  violated.
- Padding length must be the exact alignment padding required for the type and
  padding bytes must be zero. Decoders without a concrete type alignment must
  accept any zero padding up to 64 bytes and treat the remaining bytes as the
  payload. Extra non-zero bytes are rejected.

In-memory archived handles:
- `Archived<T>` is a zero-sized, byte-aligned address marker. It never contains
  a Rust `T`, so unvalidated wire bytes are not exposed as a typed Rust value.
- Payload footprint and alignment are separate properties exposed by
  `archived_payload_size::<T>()` and `archived_payload_align::<T>()`. Framing
  uses those properties, so making the marker opaque does not alter padding or
  the v1 wire layout.
- Retagging an archived marker changes only the decoder type at the same byte
  address. Every decoder must obtain bytes through an active payload context
  and validate the requested range; a marker alone never authorizes a pointer
  read. An outer/root decode span never widens a nested field's active context,
  so a field pointer cannot consume sibling bytes. Missing context, truncated
  scalar ranges, invalid Boolean tags, and invalid Unicode scalar values are
  decode errors.

Schema and resource enforcement:
- Typed decoders must reject payloads whose header schema hash does not match
  the expected type. `ArchiveView::decode` performs this check; use
  `ArchiveView::decode_unchecked` only for raw inspection tools. Both methods,
  plus `decode_exact`, always install payload-derived resource limits and
  require the value decoder to consume the complete checksummed payload.
  Zero-filled bytes are valid only as the exact alignment padding between the
  header and payload; a zero-filled logical tail is not a second encoding.

### Fixed framed payloads

`core::FixedFrameLayout<T: NoritoSerialize>` retains one type-derived schema
identity, explicit flag set, fixed payload length and the existing type-derived
alignment padding. Construction checks flags, archive-length policy and length
arithmetic before resolving the schema name once. The original caller must fund
that construction and retain the layout with its backing buffer and I/O owner.

After construction, `write` and borrowed `payload` validation allocate no codec
storage on success or malformed-frame errors. They share the existing bare-frame
header/CRC writer; the V1 bytes do not change. Validation rejects the wrong schema,
flags, compression, length, padding, checksum, truncation or suffix. Input buffer
alignment is irrelevant because returned bytes are borrowed without archived
casts, typed deserialization or a decoder-budget allocation. The exact fixed
length admitted at construction is retained; these operations do not renegotiate
ambient flags or a later global archive limit.

The schema owner still defines and validates the fixed fields, discriminants and
reserved bytes. This API does not infer that schema from a payload or accept a
caller-provided schema digest. Writer allocations/errors and partial output remain
with the original I/O owner. Codec success grants no allocation credit, storage
lease, durability or root-publication authority; those require the enclosing
funded storage protocol. Generic decoder limits are not a substitute for funding.

## Header Flags

The final header byte carries the layout flags. V1 defines one flag:

| Flag | Hex | Meaning |
| --- | --- | --- |
| `COMPACT_LEN` | `0x02` | Per-value length prefixes are compact varints. |

All other bits (`0x01`, `0x04`, `0x08`, `0x10`, `0x20`, `0x40`, `0x80`) are
reserved; decoders reject them in headers, encoders never emit them, and
ambient layout guards mask them.

`COMPACT_LEN` affects per-value length prefixes only. Sequence and map entry
counts remain fixed 8-byte little-endian `u64` headers in both layouts.

Default v1 payloads use `COMPACT_LEN` (`flags = 0x02`) while keeping the minor
version byte fixed at `0x00`. The header flag byte is therefore the source of
truth for compact per-value lengths; decoders must not infer compactness from
the version or from payload heuristics. Fixed-width per-value prefixes are a
distinct advertised V1 mode when a caller explicitly encodes with
`flags = 0x00`.
Nested tuple and metadata-entry serializers inherit that exact selection.
They do not merge defaults into an active layout: changing length formats
after an enclosing field has been written would make the frame internally
inconsistent. Defaults apply only when no layout context is active.

### rANS table V1 checksum

`RansTablesV1.checksum_sha256` is SHA-256 of the complete uncompressed Norito
frame for `RansTablesBodyV1`, including its canonical schema identity and
header, with fixed-width per-value lengths (`flags = 0x00`).
`RansTablesBodyV1::checksum_sha256` owns this domain for both the native table
producer and the runtime loader. Ambient layout guards and the default compact
layout do not change this checksum; the loader accepts only this V1 domain.
This checksum checks the table body, not its optional manifest signature.

## Length Prefixes

Norito uses length prefixes in multiple places, with explicit flags deciding the
encoding:

- Per-value prefixes (fields, elements, strings, blobs) use `COMPACT_LEN`.
  - If set: unsigned varint (7-bit continuation).
  - If not set: fixed 8-byte little-endian u64.
- Sequence length headers are fixed 8-byte little-endian u64 in v1.
- The first-release standalone election finalization instruction, retained
  `ElectionState`, Torii tally response, and IVM `VoteGetTallyResponse` encode
  each option weight as canonical `u128`. Proof public-input limbs are 32-byte
  little-endian values whose upper 16 bytes must be zero; no `u64` tally layout
  or fallback decoder is admitted.
- `Vec<u8>` is encoded as a fixed-size sequence: `[len_u64][raw-bytes]` (no per-element
  length prefixes). Borrowed `&[u8]` payloads use the same layout and stream without
  copying their backing bytes; their slice decoder also requires the fixed count.
  Decoders reject per-element length-prefixed byte vectors.
- Every other sequence element is `[len][payload]`, with `len` encoded per
  `COMPACT_LEN`.

Encoders compute length-delimited fields with a real counting pass, then stream
payloads directly into the destination. They do not retain a second copy of the
encoded payload. The write pass verifies every counted length and fails with a
length mismatch if a stateful serializer changes between passes.
Allocation failures in temporary codec buffers are returned as errors rather
than using infallible `Vec` growth. These rules do not change the v1 bytes.
The field writer takes only its destination and value. Generated serializers
and manual callers do not construct per-field scratch buffers.

The length-only encoder has its own counting destination. Core field and
container helpers measure each child once during that pass, then add its measured
length without replaying its body. This prevents nested count/write pairs from
doubling work at every level. Only a helper that owns the measurement may do this;
caller-supplied lengths and optional length hints remain untrusted. Byte writers,
checksum writers, canonical comparisons, and separately constructed nested
buffers always receive actual bytes. Count overflow remains an error even if a
custom serializer ignores an individual failed write.

`core::SequencePayloadLength` retains exact generic element-sequence lengths
incrementally. Each append counts its supplied element once under a validated,
frozen layout; snapshots and reads use constant-size counters. It includes the
sequence count and element prefixes, and rejects overflow.
This is an observation of the supplied elements, not a serializer or a promise
about later bytes: callers must preserve their values and serialization behavior.
The raw `Vec<u8>` specialization is a different layout and is excluded. Existing
writers retain their checked count/write behavior and all v1 bytes are unchanged.

Embedded instruction frames retain the counting destination through a
codec-owned prefix writer. A size-only pass measures the concrete payload and
adds the fixed header/alignment overhead; it does not construct a checksum writer.
Actual frame output still computes and checks length, checksum, and finalized
flags across its two passes. The tuple prefix runs in the enclosing layout
context. `ConstVec` retains individually framed byte elements; `SmallVec`
retains fixed-width element length prefixes.

`Metadata` projects borrowed entry views into the same element-sequence writer
as `ConstVec`, preserving its sequence-of-tuples layout without collecting entries.
The writer derives cardinality from an exact-size iterator, measures and writes
each element in a single pass, and rejects an iterator whose yielded element
count differs from its reported length.

Varint encodings must fit in `u64` and use the shortest (canonical) encoding;
overflow or overlong encodings are rejected.

## Binary Sequence Span Planning

Norito implementations may plan binary sequence payload spans before semantic
decode. The planner is an internal optimization and does not change the wire
layout:

- Sequences are planned from `[count_u64][len][payload]...`, honoring the
  header's `COMPACT_LEN` flag for each element length.
- The plan returns element byte ranges in original sequence order and the total
  bytes consumed from the sequence payload. Semantic decode and validation still
  happen on CPU and must report failures in original index order.
- Each declared element span is authoritative. A zero-length span is valid only
  when that element type's canonical encoding is empty; it is never treated as
  a missing length whose payload can be recovered from following bytes.
- An optional Metal/CUDA helper, `norito_length_prefixed_sequence_plan`, may
  compute the spans of large length-prefixed sequences. The helper must pass a
  startup self-test, and the scalar planner re-verifies every helper plan; a
  plan is used only when it matches the scalar result exactly. An unavailable
  backend falls back to the scalar planner for that call. Helper errors,
  malformed span output, or scalar mismatches fall back and disable that helper
  for the process. GPU-named helper exports report unavailable or backend
  failure instead of silently substituting CPU work; the Norito caller owns
  deterministic scalar fallback.
- Helper use is performance-only: decoded values, rejection class, ordering,
  hashes, and emitted bytes must remain identical. Native helper waits are
  bounded before CPU fallback.

### Counted length framing and encode depth

Every length-delimited field is sized by running its serializer against a
counting sink. Norito then emits that measured length and constrains the output
pass to the same byte count. Nested counted children share the original encoder
and an active exact-length scope: successful writes advance one offset, and
scopes enforce the smaller child/enclosing end before forwarding bytes. This
avoids routing each emitted byte through a separate writer for every ancestor.
Overruns remain sticky even when a serializer suppresses an I/O error; short
successful writes fail the final exact-length check. The arbitrary-writer
`serialize_to_writer_exact` seam still verifies actual output separately.
`codec::verify_exact_payload` streams the fixed V1 bare encoding over retained
source bytes and rejects byte drift, overrun and trailing suffixes. It creates no
second output buffer and restores the ambient encode context. Custom serializers
still own their scratch allocations. Native lane batch decoding borrows its
original payload directly; this removes redundant input/output copies but does
not establish complete decoded-graph resource funding.

`encoded_len_hint` and `encoded_len_exact` are optional diagnostics; canonical encoding never trusts them for framing,
admission, or buffer reservation. This prevents a recursive or incorrect
length oracle from exhausting the stack, forcing a payload-sized speculative
allocation, or understating the bytes accepted by the output pass.

Unit-record size hints use the same zero-field layout calculation as other
structures. A unit record's payload is empty in every layout; both length
diagnostics report zero. Canonical framing continues to measure actual
serialization rather than trust either hint.

Use `canonical_frame_len` to count the exact uncompressed V1 frame emitted by
`encode_canonical`, including for resource admission and length-prefixed hashes.
Both ignore ambient layout guards and restore the caller's guard on return.
The lower-level `core::encoded_frame_len` follows the active layout, matching
the corresponding layout-aware encoder.

Derive-generated serializers and length diagnostics also enforce
`MAX_VALUE_NESTING_DEPTH`. Recursive in-memory values therefore return a
typed `NestingDepthExceeded` error through fallible encoding APIs before native
stack exhaustion. The guard changes no accepted wire bytes or field ordering.

### Decode-scoped resource limits

Archive byte limits do not bound collection reservations: an eight-byte
sequence header can advertise an element count far larger than the containing
payload, while nested length-delimited fields can amplify otherwise modest
archives. The root and `core` byte-slice `decode_from_bytes` entry points,
exact-slice decoders, and all `ArchiveView` decode methods therefore install
`canonical_decode_limits(frame_or_payload_len)` automatically. This also
charges a compressed frame's declared uncompressed length before reserving or
decompressing it, so a tiny frame cannot request an allocation up to the global
archive ceiling.

`ArchiveView::decode_exact_with<T, R, F>` keeps `T` as the original wire
schema and padding owner while permitting a callback to return a different
result `R`, such as a borrowed payload view with prepaid field allocations.
The same scoped flags, payload-derived limits, stricter outer limits and exact
consumption checks apply. The callback must still validate its field structure;
framing alone grants no canonical-value or finality authority. This API changes
no wire bytes or layout.

`core::borrow_canonical_text<T: NominalText>` borrows the single UTF-8 payload
of an explicitly declared nominal text type. The original type supplies its
literal frame identity, alignment and model byte ceiling. Existing header,
checksum, length and exact-consumption checks are followed by the same canonical
streaming frame writer, with no owned string, aligned copy or decode-scope
allocation. Outer field limits remain active. This establishes only canonical
framing: model syntax and exact NFC validation remain separate, with scratch
admitted before normalization. Name and StatePath share the payload reader and
canonical NFC predicate with their owned decoders. This changes no wire layout.

Hosts decoding untrusted data with narrower semantic bounds must additionally
use `decode_from_bytes_with_limits` (or `decode_from_reader_with_limits`) and an
explicit `DecodeLimits` value. The explicit byte-slice APIs enter a private
decoder directly instead of recursing through the default, so trusted
high-compression callers can select a larger but still finite expansion budget.
Nested scopes compose by selecting the stricter member in every dimension. The
budget specifies a per-sequence element count, a per-field/blob byte length,
cumulative element and allocation-byte totals, and a maximum nesting depth.
Norito validates declared bodies against the bytes remaining before allocating
temporary storage and returns typed resource-limit errors on violation.
Resource-limit and allocation errors are terminal. The V1 decoder never retries
the same bytes through an alternate layout after a budget has rejected them;
the header flags select the only layout used for that frame.

An execution boundary that preserves local retry outcomes must inspect the
original error after inner decoder scopes unwind. The hidden
`core::decode_error_matches_active_limits` helper requires the recorded field,
sequence, cumulative element or allocation ceiling to match a surviving scope.
A decode-budget nesting refusal also requires an exact surviving caller depth
that is narrower than `MAX_VALUE_NESTING_DEPTH`. An unrelated wider scope cannot
turn an inner format limit into local pressure; the global archive cap and
canonical nesting ceiling remain format rejections. This query
adds no wire data, allocation owner or release notification, and does not retry
the decoder.

Canonical artifact admission uses `decode_canonical_for_admission` for the complete
single decode and exact canonical-byte comparison. Its opaque result distinguishes
actual allocator failure, an original enclosing admission-budget refusal, and invalid
input. Canonical/default/schema budgets are checked before enclosing operational budgets
at each resource check. The original emitting layer, counter family and process-unique
observer root/boundary are carried privately in the Rust error, so equal numeric ceilings,
cumulative consumption and nested attempts do not guess provenance. Direct JSON parsers
and checked writers retain the actual refusing caller layer even without an inner framed
scope. Immediate descendant errors can return to their active parent; an earlier direct
attempt, an earlier sibling or another thread cannot acquire a later boundary, including
under the same shared counters after a fresh refusal was swallowed. Reconstructing a
resource error from copied fields also cannot establish current local origin. Observer
identities never wrap; after finite identity exhaustion, later budget-layer errors fail
local classification closed. The counter context and prepared attempt sequence are unchanged.
The numeric active-limit helper never relabels a carried protocol error. Canonical
re-encoding failures without decoder provenance remain invalid input. This adds no wire
fields, second decode, allocation-pool owner or release notification. IVM `CNTR` and
`DBG1` parsing preserve these local refusals as unmetered execution deferrals; whole-image
and schema limits remain deterministic artifact rejections. The JSON parser and bounded
canonical writer preserve the same opaque refusal across binary `Json` fields, including
trigger metadata; copying diagnostic fields or formatting JSON errors cannot replace its
scope identity. Unscoped binary/JSON conversions retain the complete `DecodeResourceError`
fields in `json::Error::DecodeResource`; only `ScopedDecodeResource` carries private observer
provenance. The fieldless `DecodeResourceLimit` remains an anonymous checked-bound or fieldless-owner
category, never a substitute for an actual recorded decoder refusal. Non-resource core
errors remain terminal JSON diagnostics and cannot become allocator refusals. JSON body,
intrinsic nesting, and arithmetic-overflow bounds remain protocol failures.


Closed named and tuple records can opt into `#[norito(decode_fields)]`. Their ordinary
`DeserializePayload` and caller-prepared destination then use one generated
positional field walk. Tuple slice decoding keeps its original whole-input
archived contract; named slice decoding keeps its existing prefix contract.
Fixed byte-array fields retain their raw-field framing;
other fields use the canonical child decoder relationship. Generic, skipped,
flattened and whole-value validation-hook records are rejected by this initial
opt-in rather than silently changing their contracts. No schema or V1 bytes change.
The shared positional and Option prefix kernels bound and borrow each declared
payload without charging its byte length as an allocation. Element-framed
`[u8; N]` decoding likewise checks borrowed element prefixes while filling fixed
stack storage without a heap charge. Generic fixed arrays always use their
encoder's element-framed layout; explicit raw fields and nominal raw-byte types
retain their fixed-width decoders. Input length never selects an array layout.
Manual record walks use `framed_byte_array_field` for direct byte-array fields,
and prepared destinations honor the decoder selected by that field constructor.
Optional and sequence-element arrays keep the generic element-framed value
format; raw record-field bytes cannot be passed to that value decoder.
Archived generic arrays charge each actual element copy once. Their owning
element decoder also requires `SerializePayload`: partial or unreported child
access uses the same allocation-free canonical byte comparison as other fields,
without imposing an additional deserialization lifetime bound. Actual archived
realignment buffers and owned child storage retain their own allocation charges;
field, flags, bounds, depth and complete-consumption checks remain active.

`ChargedElementSequence` constructs exact span backing from the original finite
pool during that same sequence walk. It borrows the original input and exposes
the existing prepared element visitor without a second framing pass. Crypto's
`PreparedPublicKeyDecode::try_decode_payload` and the numeric
`PreparedQuantityDecode::try_decode_payload` similarly admit their final compact
key or native-digit backing at the canonical field's allocation point. Later
field failures destroy that backing before returning physical credit; consumed
logical decode work is never reset or refunded. These owners cover their stated
allocations only. Enclosing source, diagnostics and retained execution through
worker refusal remain separate obligations. V1 bytes and validation order are
unchanged.

`PreparedDecodeWorkspace` preadmits its two reusable physical counter controls
from an explicit original `iroha_allocation` reservation. Active scopes borrow
synchronous stack nodes; every reused attempt has a new checked identity, so a
retained old refusal cannot acquire the new attempt's provenance. The workspace
owns no input, graph or alignment copy. `decode_canonical_into` resets destination
validity, runs the shared header/field kernels, then compares the complete filled
payload against the original frame through the existing streaming canonical
writer. It preserves original codec/resource causes separately from local
prepared-destination failures; neither is retried through an owning decoder.

The prepared entry preserves the caller's original owning boundary. The canonical
field entry keeps its whole-payload field-length check and record depth before the
first child. `decode_canonical_archive_into`, used by the prepared SignedBlock
reader, instead follows `ArchiveView::decode`: it authenticates the frame and type,
installs the original schema/layout flags, derives limits from the payload length,
and enters the generated record without an extra whole-record field or depth.
The first field and every child still use the sole bounded framing kernels. Both
entries share the positional walk, destination/refusal custody and exact complete
canonical frame comparison; neither introduces another V1 representation, a
scratch archived decoder or a limit override.

Prepared sequence destinations supply initialized `SequenceSpan` scratch and
initialized output storage. The existing scalar sequence walker validates the
complete span plan before any element callback, preserving late-framing error
precedence. Raw `Vec<u8>` and element-framed `ConstVec<u8>` retain distinct layouts.
Logical sequence/storage limits still apply; they do not fund physical backing.
Callers must admit every buffer and crypto leaf before the operation, validate
intrinsic type/length bounds separately from local bank geometry, retain input
and destination custody on refusal, and transfer initialized children only after
the complete canonical frame succeeds. This API alone does not fund a caller's
whole decoded graph or secret-consuming workflow.

Rust error adapters retain these refusals through
`core::Error::decode_resource_error` and the copyable `core::DecodeResourceError`.
Conversion back to `Error` preserves every resource field without allocating a
diagnostic, but deliberately does not recreate private admission-scope provenance. Sumeragi's native codec and the model evidence decoder
preserve this category, so a scoped refusal is not reported as malformed evidence.
This error representation changes no V1 frame, schema or signed bytes.

Standard-library B-tree ownership uses the pinned toolchain's node geometry.
A known tree of at most eleven entries charges one complete leaf, including a
conservative bound for every possible field order and alignment. Larger trees
and aggregate distributions retain the largest internal-node bound. The
allocator census checks actual insertion requests through the split boundary,
multiple insertion orders and over-aligned keys/values; outer allocation scopes
still refuse before insertion when the full charge does not fit. This changes
neither the query ceiling nor canonical wire bytes.

Both `Ok` and `Err` branches of the result slice decoder enter the shared
nesting guard before decoding their bounded child. The guard restores the
previous depth on success, child error or consumed-length rejection, including
when another decode follows inside the same active limit scope.

Canonical field/frame decoding of derived records validates the complete
boundary: every length-prefixed field must consume exactly its declared span,
and the record must end exactly at the end of its enclosing field or frame
payload. A valid checksum does not make trailing bytes part of a structure. A
unit record's canonical payload is empty, so any byte inside its span is
rejected. Explicit prefix-field decoding reports only the bytes belonging to
that field so the enclosing decoder can read its following fields.

Nested decode scopes may tighten but never relax an outer budget. Binary value
decoding is sequential in V1, so its budget counters stay in the calling decode
scope. Application-defined deserializers that create threads must pass a
bounded decode operation explicitly. Lazy callers must use
`stream_seq_iter_with_limits`, `StreamSeqIter::new_with_limits`, or the bounded
`StreamMapIter` constructors so the iterator owns a cloneable budget context
and reapplies it for every `next`/`finish` call. No thread-local guard is moved
with an iterator.

Explicitly unbounded low-level decode scopes remain an internal trusted-data
concern; public byte-slice framed and exact-slice boundaries retain their
payload-derived defaults. Reader-based decoding cannot derive a budget from a
complete frame slice, so untrusted readers must use the explicit-limit reader
API. A host must choose cumulative budgets with enough headroom for temporary
alignment copies and container metadata; accounting is intentionally
conservative and may charge both a declared field body and a temporary copy.

All public framed, reader, compressed, and bare-value decoders converge on the
same exact payload boundary. A decoded value must consume the complete
checksummed payload; a Rust type's in-memory size is never used as evidence of
wire consumption. Instrumented decoders report consumption directly, while a
custom decoder that does not report complete access uses an allocation-free
canonical byte comparison. Equal-length but byte-different payloads are rejected.

## Bounded data-model text leaves

The first-release `ChainId`, `Name`, and `Json` wrappers enforce their semantic
and resource invariants on every safe construction and decode path. A
`ChainId` is exact, case-sensitive ASCII, is 1–128 bytes, begins and ends with
an ASCII alphanumeric, and otherwise permits only alphanumerics plus `.`, `_`,
`:`, and `-`. Its decoder rejects an oversized declared string length before
reading or allocating the body. A `Name` is
NFC-normalized, is at most 255 UTF-8 bytes, and rejects whitespace, Unicode
control characters (including NUL), Unicode bidirectional controls, and the
reserved `@`, `#`, and `$` delimiters.

`Name` normalization is consensus-critical and uses the exact ICU4X NFC
algorithm and compiled-data profile pinned by `iroha_data_model`. Construction
and decoding fail closed unless the compiled normalization tables match the
reviewed semantic fingerprint. Updating either the pinned normalizer or that
fingerprint is therefore a protocol change and requires a reviewed regression
corpus update.

A `Json` value is exactly one well-formed Norito JSON document with no
duplicate object keys or trailing tokens. Its UTF-8 representation is at most
1,048,576 bytes and its structural depth is at most
`norito::json::MAX_JSON_VALUE_NESTING_DEPTH`. The fixed type-level limits apply
before any lower ledger or application-specific metadata limit. Norito
decoders inspect the nested string length before allocating its backing
storage; malformed, oversized, or over-depth wire values never become a
`Json`. Raw JSON producers use the fallible `Json::from_raw_json`, while plain
text that should become a JSON string uses `Json::new` or `Json::from`.
Each generic or tape-first typed document entry point preflights the complete
document's maximum value depth once with an allocation-free, quote-aware scalar
scan before generated `JsonDeserialize` or custom `FastFromJson` recursion
begins. Generic-to-tape adapters may validate the exact next subtree again to
find its boundary, but construct their tape over only that non-overlapping
slice and never rescan unrelated enclosing bytes. The security bound is
independent of the selected hardware Stage-1 tape, so every node reaches the
same decision. Unknown fields then use the same strict iterative subtree
grammar, so an individually valid subtree cannot exceed the global limit by
hiding beneath a typed outer object or array.

Checked JSON writers stream into the original `JsonWriteSink`. Every container
they successfully enter is released when the write returns, including byte,
depth and unsupported-leaf refusals. A refused entry never releases an inherited
level. Partial bytes and the exact original error remain with the sink owner;
cleanup does not retry through an unbounded string or grant allocation credit.
Generated empty tuple enum variants retain their tuple pattern and canonical
tag/content bytes.

The primitive signed BigInt slice decoder validates the borrowed canonical
two's-complement payload before constructing native digits. It charges the
inherited decode allocation scope once for the exact native backing, then uses
one fallible allocation. Zero needs no backing; negative values use fixed
bounded scratch instead of an additional byte vector. Signed-byte minimality,
domain limits, advertised field layout and canonical wire bytes are unchanged.
The archived BigInt adapter forwards the original typed decoder error so local
allocation refusals retain their captured origin through enclosing records.

An already classified canonical decode error retains the original attempt's
admission outcome after its caller scope retires. Introducing its underlying
error into a new canonical observer does not establish a new local origin;
copied resource-limit numbers cannot establish one either. Portable checkpoint
adapters consume the original captured classification without inventing a pool
release owner or treating valid source bytes as a completed proof rejection.

JSON field dispatch uses one key hash implementation for compile-time constants,
the scalar parser, and the tape parser. With `crc-key-hash`, the portable
Castagnoli byte update and runtime-detected ARM CRC or x86 SSE4.2 update use
the same raw register seeded with `0xffffffff`, without a final complement,
before the fixed 64-bit avalanche. Without that feature they
all use FNV-1a. These hashes select JSON fields internally; they do not alter
the serialized JSON or binary schema hashes. Key comparisons still guard
against hash collisions.

Typed JSON floating-point values must be finite. Norito rejects literals whose
decimal exponent overflows `f64`; finite values are rendered with Ryu's
locale-independent shortest-roundtrip representation, preserving their exact
IEEE-754 bits when decoded again.

## Transaction Payload Layout

`TransactionPayload` is the nine-field canonical first-release struct. Its fields are encoded
in this exact order, with the active per-field length-prefix rules:

```text
domain
authority
creation_time_ms
instructions
time_to_live_ms
nonce
fee_payment
metadata
attachments
```

`domain` is either the exact deployment `NetworkId` or the genesis-only marker.
`fee_payment` is required and immediately precedes `metadata` on wire. It contains either an authority payer or one exact sponsor
program and immutable revision, followed by canonically ordered charge limits
and the optional positive executable gas bound. The retired transaction
metadata keys `fee_sponsor`, `gas_asset_id`, and `gas_limit` are not alternate
encodings of this field and are rejected by transaction construction and
admission. Native queue admission is the sole transaction path; the retired
`admission_intent` field has no wire slot or decoder.
`attachments` is the ordered optional proof-attachment list and remains part of
the signed transaction identity. SDK encoders and fixture exporters must emit
this nine-field V1 layout. Missing fields, retired extra slots, and unknown JSON
fields fail closed; there is no metadata-marker or legacy payload fallback.
`time_to_live_ms` retains its canonical option discriminant so a malformed
signed payload can be decoded into a typed admission rejection, but
first-release transactions must encode `Some(positive milliseconds)`. Safe
builders assign `100_000` ms when no explicit lifetime is selected, and
stateless admission also enforces the governed
`transaction.max_time_to_live_ms` ceiling.

The `instructions` field contains the sole first-release `Executable` enum.
Its canonical variant tags are:

```text
0  Instructions(ConstVec<InstructionBox>)
1  ContractCall(ContractInvocation)
2  Ivm(IvmBytecode)
3  IvmProved(IvmProved)
4  Batch(ConstVec<ExecutableBatchItem>)
```

`Batch` is the flat ordered form for atomically interleaving native ISIs and
deployed-contract calls. Each `ExecutableBatchItem` uses tag `0` for
`Instruction(InstructionBox)` and tag `1` for
`ContractCall(ContractInvocation)`. Raw IVM bytecode and nested batches are not
batch-item variants. Nodes reject an empty `Batch`; SDKs should reject one
before signing. Instruction-only transactions use `Executable` tag `0`.

Dynamic `InstructionBox` and erased `QueryBox` payloads carry a registry wire
identifier plus the concrete Norito payload. First-release built-ins use
explicit, frozen identifiers: instruction IDs are inventoried in
`crates/iroha_data_model/src/isi/registry/wire_ids.rs`, and query IDs are pinned
by `crates/iroha_data_model/tests/fixtures/query_wire_ids_v1.txt`. Iterable
query IDs use the path-independent `iroha.query.v1::iterable::<domain>::<item>`
namespace. Encoders emit those identifiers rather than deriving new values
from the current Rust module layout. The golden checks bind each built-in type
label to its identifier, so swapping two otherwise valid identifiers is also a
wire-contract failure.
Registries are direction-separated: concrete Rust type names are internal
encoding keys, while decoders accept only the registered frozen wire IDs. There
is no type-name decode alias and no unregistered type-name encoding fallback.
Instruction framing helpers also accept only canonical wire IDs. Instruction
registrations reject a wire ID equal to any concrete type name, a concrete type
name equal to any registered wire ID, duplicate types, and duplicate wire IDs.
For queries, the built-in inventory is complete; an application registry may
add only new concrete types with unique explicit IDs and may not re-register a
built-in type under an alternate ID. New built-ins must add a unique identifier
and update the corresponding golden inventory; an existing V1 identifier must
not be renamed or reused for a different layout.

Public-lane candidate admission uses the explicit instruction wire ID
`iroha.staking.register_public_lane_candidate`. Its canonical fields are the
registration, exact activation height, BLS proof of possession, and typed peer
signature. The peer authorization includes a fixed protocol domain and the
genesis-derived network identity. The current rebind layout carries an explicit
optional peer-consent signature, whose message binds network, lane, account,
activation height, previous peer, and replacement peer. Both optional-signature
tags use the ordinary advertised Norito layout; there is no retired-layout
decoder. Generated-record frame fixtures cover candidate admission and both
rebind consent forms.

The only supported SDK/node compatibility handshake is
`DATA_MODEL_VERSION = 4`. Validation-fee policy and payout-lifecycle proposal
preimages bind the canonical `proposal_operator`; policy proposals also bind
the exact payout-lifecycle proposal when a payout binding is present. Enacted
authorization retains the operator, native proposal fingerprint, canonical
certificate id, complete `GovernanceCertificateV1`, and exact enacted height.
Admission validates and derives those bindings rather than accepting a
validation-fee-specific electorate, snapshot, window, or finalization-evidence
layout. Proposal-owned `u64` values encoded as JSON numbers are bounded by
`9,007,199,254,740,991`; canonical decimal-string fields retain the full `u64`
range. Peers and SDKs reject every other data-model version instead of
attempting a compatibility decode.

Admission schedules a mixed batch as one global live-state barrier. Items run
in canonical input order against the same transaction view, and failure of any
item rolls back every staged state change. A signed transaction containing a
contract-call item binds one gas limit in `fee_payment`; explicit native-ISI gas
and contract-call gas consume that shared limit, and fee settlement happens
once for the transaction rather than once per item. Trigger actions may store
the same `Batch` form. One trigger invocation executes the items atomically and
shares its deterministic trigger gas budget across the complete sequence.

## Block execution context

The first-release `BlockExecutionContextBundle` (version 1) encodes, in order,
`version`, `external` (routing contexts aligned with the block's external
entrypoints) and the required nullable
`lane_merge: Option<SumeragiLaneMergeSection>`, which names the lane blocks the
global block merges (`specs/sumeragi_lanes.md` §4.2). Omitted slots and unknown
fields are rejected; there is no compatibility decoder.

No economic result, settlement, replay alias, FASTPQ output claim, applying
header copy, or execution-prefix write root belongs in this proposal field.
Execution uses the actual carrier header; proposal construction cannot depend
on outputs that themselves persist that header's hash. `BlockHeader` no longer
carries the generic result Merkle root. Attaching outputs preserves its bytes,
hash and signatures; the CommitQC-certified execution result `R`
(`specs/sumeragi.md` §4.1) authenticates the complete executed wire and state
transition. State's private execution seals
are not additional proposal claims or a second finality authority.

The complete network-input projection comes from physical external inputs,
with no synthetic Time inputs. Physical `external_*` APIs keep their named
payload-field semantics. The header input Merkle root remains physical external
only; merged lane blocks are bound by `execution_context_hash` through
`lane_merge`. Network input and execution-output counts
are independent. A SealedReveal's outer entrypoint owns its network input proof,
while the actual transcript key and each `TransferTranscript.batch_hash` retain
the inner execution-call hash.

`BlockResult` contains, in order, `outputs`, `output_merkle`,
`committed_fragment_count`, `fastpq_transcripts`, `axt_envelopes`,
`axt_policy_snapshot`, and `axt_transitioned_dataspaces`. All seven fields are
required. The retired lane-finality-statement field is absent from both the
canonical binary layout and JSON; trailing old fields are rejected, with no
fallback decoder. Native finality authenticates the actual execution through
its canonical result and complete executed wire. `outputs` is the sole
`Vec<ExecutionOutputV1>`: Network rows precede Pipeline rows, followed by Time
rows. Each owns its complete `TransactionResult` (including independent-batch
receipts) and its actual callback completions. Network rows explicitly join an input
index; Pipeline and Time rows carry invocation descriptors and no input leaf.
An internal trigger-use descriptor contains only the bounded trigger ID, its
registration height and the canonical action hash. That hash commits to the
actual use-time authority together with the persistent action; authority is not
copied into the descriptor. Execution must authenticate and use the same action
under its exclusive State owner. The retired parallel authority field is rejected
in both JSON and binary decoding. Authority size therefore does not enlarge a
terminal descriptor; hashing/allocation of the action still requires its own bound.
Rejected Network inputs retain no callback completions. Rejected internal
invocations retain exactly one callback-zero Failure naming the root, representing
the whole invocation; rolled-back nested successes cannot survive as completions.
The output Merkle cache covers each complete typed row, including its source.
The actual committed-fragment count remains execution-owned; leaf counts do not
infer how many State fragments applied. Old parallel input/result/completion
vectors and `TransactionEntrypoint::Time` have no compatibility decoder.

`set_execution_outputs` receives the complete outputs and all execution metadata
in one operation. It checks immutable proposal commitments, source/phase order,
exact Network coverage, transcript structure, policy, row and aggregate costs,
and complete canonical SignedBlockWire length before mutation. No result-metadata
setter can enlarge a checked candidate afterward. Signatures remain mutable;
`validate_execution_outputs` must check final complete bytes before publication.
These structural checks cannot infer which outputs execution should produce or
authenticate transcript source custody. Core must verify its actual capture
inventory, including legitimate nested/protocol owners.

`BlockParameters` now encodes, in order, `max_transactions`, the independent
`max_time_trigger_invocations`, and the atomic `execution_output` policy. Both
new JSON fields are required whenever the block object is present; the retired
one-field payload has no compatibility decoder. `BlockParameter` adds the
`MaxTimeTriggerInvocations` and `ExecutionOutput` variants. The latter carries
seven ordered fields: `max_outputs`, `max_output_bytes`,
`max_total_output_bytes`, `max_executed_wire_bytes`, `max_pipeline_triggers`,
`max_time_triggers`, and `max_time_invocations`. Core permits replacing this
capacity envelope only during genesis; later active Time-count changes must fit
that envelope. Total Pipeline/Time registrations include disabled and depleted
actions. Zero Pipeline capacity disables registration, while Time capacities
remain positive. These are consensus parameters, with no node-local override.

The ordinary candidate selector caps Network count using terminal capacity under
the maximum permitted future Pipeline/Time growth before queue selection/signing.
State captures actual policy, active Time count and total Pipeline registrations
after its constructor's start effects, then retains one terminal plan bound to
the applying source before ordinary/native Network execution. One complete native
group occupies one Network row regardless of route count. State retains a
Reserved, Running, Retained or Poisoned owner throughout its private producer
continuation; none of these states yet authorizes publication. Its private
Network owner freezes routes, validation instants and reveal order before work,
then runs actual admission, execution and callback capture. Successful business
changes apply only after the complete receipt/trace/completion row fits. Healthy
output overflow rolls back State, events, witness and ZK deduplication while
retaining accountable completed work. Actual rejection drops the business
attempt, applies any prevalidated rejection penalty, then settles eligible fees;
a later fee failure does not roll back the penalty. Economic eligibility uses
the original typed error before bounded diagnostic projection. Output slots are
allocated before work and retain original source order independently of execution
order. The actual callback journal owns nested by-call and data-trigger traces.
Actual Pipeline and Time invocations share the same pre-apply row-fit and rollback
owner. Pipeline derives signed-input events from retained Network dispositions and
frozen routes, then BlockApproved; original source/candidate positions survive
skips. Event route data does not authorize callback write routing. A real Pipeline
failure rolls back its business effects and disables the same authenticated action
in a separate transaction; Time failure preserves the existing retry/removal policy.
Healthy output overflow does neither. Root-repeat ordering remains Pipeline-before-DFS
and Time-after-DFS, guarded against self-replacement. The sole canonical driver,
genesis, source/host admission and complete common sealing tail still need integration. This
isolated migration does not enable a production native path. Registration
and parameter instruction guards do not yet qualify privileged mutation,
restoration predecode or complete source/host admission.

`ExecutionOutputLimits` is the explicit non-wire projection of the agreed policy,
with no default or unlimited values. Internally derived terminal ceilings use
canonical encoding of bounded maximum descriptors, never caller byte estimates. The linear `ExecutionOutputBudget` reserves bounded terminal
rows for every prospective invocation before phase execution. Unused slots can
be released only by the execution owner after eligibility checks. An oversized
actual output selects its already-reserved typed OutputLimit terminal; the
execution owner must first roll back the invocation and every side channel.
Actual rejected Network execution uses `finish_network_rejection` after its
independent economic disposition. If its full error does not fit, the reserved
string storage retains `execution rejected; diagnostic omitted` in a `LimitCheck`
rejection. This fixed diagnostic is distinct from healthy OutputLimit and carries
no callback completions or business receipts. It cannot determine fee eligibility,
misconduct, or work charges; deterministic replay must execute the original source.
Actual rejected Pipeline/Time rows use `finish_internal_rejection`; an oversized
failure diagnostic reuses both reserved reason strings for `callback failed;
diagnostic omitted` and `TriggerFailureRootV1::OmittedAfterRejection`. The exact
row has no business receipts and one callback-zero root Failure completion.
`DeclaredInstructionProjection` means the root failed; `ReturnedBeforeRollback`
means the root returned before a chained failure. Both describe rolled-back work.
Core bounds diagnostic formatting and checks program payload sizes before copying
oversized failure projections. The original execution outcome determines quarantine
or retry; this bounded wire diagnostic cannot change that policy.
Allocator/encoding failures remain local refusals, not canonical execution
errors. Model arithmetic does not reserve host memory, authenticate the plan,
or bound source, signature and execution-metadata growth. Complete Core admission,
mutation coverage and producer integration remain open in this isolated migration;
late attachment refusal alone does not establish liveness.

`CommittedTransaction` and execution receipt proofs carry the full typed Network
output, its hash and its output-tree proof, separately from the input proof.
Finality anchors require an independently trusted target HeightContextId, checked
before BLS verification. A context copied from an unverified artifact cannot
establish trust; an authenticated successor uses its own target context rather
than the initial predecessor pin. Anchors verify exact executed-wire hash and length, recompute the
complete input/output commitments and validate the Network index join. Internal
Pipeline/Time outputs use an output-only finality anchor. No synthetic input
grants authority. A structurally valid replacement row
still fails the original finalized executed-wire commitment. The existing
32-MiB full-proof carrier cap and 256-MiB consensus wire ceiling are unchanged;
admission/proof delivery policy must reconcile them before activation.

## Sumeragi consensus messages

Votes, certificates, timeout votes and evidence are specified with their signing
preimages in [`specs/sumeragi.md`](specs/sumeragi.md) §3; `crates/iroha_sumeragi`
owns their Norito encoding.

The executable release wire identity includes the compiled layouts of
`WireMessage` and native `Evidence`, including every `Defect` discriminant,
and a separate root for the canonical compact `ExecutionResultCommitment` payload.
`IntoSchema` describes composite enum variants through schema-only payload
identities: ordered tuple fields or ordered named fields under the owning enum.
These descriptions add no wire wrapper and do not change Norito frame identities.
The release identity therefore changes when an evidence field or defect tag
changes, even though block effects carry the canonical evidence frame as bytes.

## Hidden RAM-FHE program encoding

The private program tape uses the declared frame identity
`iroha_crypto::ram_lfe::HiddenRamFheProgramV1` and the canonical default Norito
flags. Its payload contains length-delimited version (`u8`, exactly 1), register
count (`u16`, exactly 4), memory-lane count (`u16`, exactly 32), and tape fields.
The tape is a byte sequence with a fixed `u64` byte count. Each instruction is six
little-endian `u64` words: one opcode, its operands, and zero-filled unused words.
The decoder rejects unknown opcodes, oversized indices, nonzero unused words,
incorrect profile metadata, trailing bytes, and invalid program semantics before
returning a program. The tape is limited to 256 instructions; the complete frame
is bounded by `RAM_LFE_HIDDEN_PROGRAM_MAX_BYTES`.

Decoded instructions share one clearing allocation across program clones; the
last owner clears its complete backing storage. Explicit encoded bytes use a
clearing owner too. The previous instruction-vector layout is not decoded.

## Hardware Acceleration Validation

Norito hardware acceleration is performance-only. Accelerated paths must either
produce the same semantic result as the scalar path or fall back:

- GPU CRC64 helpers must pass startup self-tests that include large payloads and
  chunk-boundary sizes. Sampled production calls compare the GPU checksum to the
  portable CRC64-XZ fallback; any mismatch marks the helper unavailable and the
  call is recomputed on CPU.
- CPU SIMD CRC64 candidates are selected only after startup parity checks against
  the portable fallback. Targets with a broken local SIMD routine use
  `crc64fast`'s runtime-selected implementation instead.
- GPU zstd compression is validated by requiring sampled GPU output to be a
  single zstd frame, decoding it on CPU, and comparing the uncompressed bytes to
  the original payload. GPU helpers may emit different valid single-frame zstd
  byte streams from CPU zstd; the canonical Norito payload remains the decoded
  bytes plus the header `Payload length` and CRC64. A sampled frame-shape or
  decode mismatch disables the GPU backend and falls back to CPU compression.
  Consensus-critical code must not hash or sign public Norito compressed bytes
  unless that callsite fixes its own compression implementation.
- JSON Stage-1 output and length-prefixed binary sequence spans are validated
  against scalar results before use so quote/string state, element ranges, and
  error ordering remain hardware-independent.

## String Encoding

`String` and `&str` values are encoded as:

```
[len][utf8-bytes]
```

`len` uses the per-value prefix rules above (`COMPACT_LEN`). Decoders must not
apply nested-length heuristics or reinterpret string payloads based on their
contents.

Owning `String` slice and archived decoders share their length/body/UTF-8 kernel
with `core::borrow_canonical_string` and `core::decode_string_into`. Prepared
decoding borrows the original payload or fills initialized caller storage without
allocating another string. It preserves the original logical byte charge before
body/UTF-8 validation and the `InvalidUtf8` cause. A short destination is a local
storage error. These payload operations do not admit physical storage or verify a
complete frame: the enclosing field retains its flags/depth checks, and its owner
still requires exact consumption and canonical full-frame comparison.

## Numeric and BigInt

`BigInt` encodes as:

```
[len_u32][twos_complement_le_bytes]
```

`len_u32` is a 4-byte little-endian length of the following payload. The bytes
are the unique minimal little-endian two's-complement representation; zero has
an empty payload. The value is bounded to the signed 4,096-bit domain
`-2^4095..=2^4095-1`, so the canonical payload is at most 512 bytes. Values
outside that signed domain and redundant sign-extension bytes are rejected.

`Numeric` encodes as a struct `(mantissa, scale)`:
- `mantissa` is a `BigInt` containing the raw integer value (no decimal scale
  is embedded in the integer).
- `scale` is a `u32` count of fractional digits (e.g., `1.88` is mantissa `188`,
  scale `2`).

The V1 Kotodama `decimal` profile uses `Numeric` with scale `0..=28`; its
canonical pointer representation removes fractional trailing zeroes and stores
zero at scale zero. `quantity` applies the same canonical representation and
additionally requires a non-negative mantissa. Arithmetic never rounds unless
an explicitly rounded operation supplies a scale and rounding mode.

Kotodama V1 numeric pointers carry one complete, uncompressed, schema-bound
Norito frame. Numeric frames always use header flags `0`, compression `None`,
and no alignment padding. Their payloads are:

```text
IntValueV1      := byte_len_u32_le || mantissa_twos_complement_le
DecimalValueV1  := byte_len_u32_le || mantissa_twos_complement_le || scale_u8
QuantityValueV1 := byte_len_u32_le || mantissa_twos_complement_le || scale_u8
```

`byte_len_u32_le` is fixed-width (never a compact varint), is at most 64, and
must consume the payload exactly (apart from the required scale byte in the two
scaled forms). The signed-byte and decimal canonicality rules above are checked
after the frame checksum, schema, declared length, compression, and flags have
been validated. In particular, an empty mantissa is the only zero encoding;
`[00]`, redundant `00`/`ff` sign extension, zero at nonzero scale, a nonzero
scaled mantissa divisible by ten, scale 29 or greater, and a negative quantity
are invalid.

The normative nominal schema names and type-name hashes are:

| Type | Schema name | 16-byte schema hash (hex) | Maximum frame bytes |
|---|---|---:|---:|
| `int` | `iroha.numeric.IntValueV1` | `07c039457363b9e1d36bbd31d93dec4a` | 108 |
| `decimal` | `iroha.numeric.DecimalValueV1` | `ba2ffed52e4d8ee16f17efefe1828524` | 109 |
| `quantity` | `iroha.numeric.QuantityValueV1` | `e4769984c81ce0e8b678f2eb06274ee3` | 109 |

Including the 39-byte pointer-TLV envelope, the corresponding hard maxima are
147, 148, and 148 bytes. Lengths beyond those caps must be rejected before any
allocation based on the declared length.

Exact decimal arithmetic is defined over conceptual unbounded integer
intermediates. The exact mathematical result is normalized first; only its
canonical mantissa and scale are checked against the value domain. Exact
division first reduces the mathematical fraction and classifies its denominator.
A remaining prime factor other than 2 or 5 is a repeating decimal. Otherwise,
the larger multiplicity of 2 or 5 is the proven minimum output scale; a value
above 28 is an exact-division scale overflow. A representable quotient performs
exactly one quotient/remainder attempt at that proven scale. Implementations
must expose deterministic charge points before each denominator-classification
division, scale construction, quotient/remainder, and normalization division;
an out-of-gas decision occurs at that charge point before the arithmetic work
begins.

## Native STARK field carriers

Native STARK digest payloads contain exactly six canonical little-endian
Goldilocks words (48 bytes). The ZK-ACE identity-commitment and replay-nullifier
wrappers delegate to that payload codec without adding a struct-field prefix.
Native STARK and FASTPQ Fp4 payloads contain exactly four canonical little-endian
Goldilocks coefficients (32 bytes), in coefficient order. A coefficient greater
than or equal to `2^64 - 2^32 + 1` is rejected rather than reduced at the wire
boundary. Struct-framed field coefficients are not an alternate encoding.

These are value payloads: the containing Norito archive still has its mandatory
schema-bound header and normal enclosing field framing. Bounded slice decoders
consume exactly 48 or 32 bytes; complete archive decoders additionally reject
trailing bytes. These fixed carriers do not depend on ambient layout flags.
FASTPQ ordering commitments and Fiat--Shamir initialization explicitly select
the canonical V1 layout when encoding their structured metadata.

## Kotodama V1 Schema-Bound Aggregates

Kotodama values crossing an entrypoint or durable-state boundary use canonical
Norito records bound to an exact recursive schema. The schema and record are
wire data; compiler-owned VM handles and their heap layouts are not.

For entrypoints, `EntrypointValueTypeV1` contains one flat preorder node tape.
A `List<T, N>` is represented by `EntrypointValueTypeNodeV1::List`; that node
stores the compile-time capacity `N`, and the complete element subtree follows
it immediately in the same tape. Struct field counts, tuple arities, and the
fixed Option/Result/List child counts make every subtree boundary
deterministic. This representation preserves recursive type structure without
building a recursively owned Rust value, so binary/JSON decoding, validation,
cloning, comparison, and destruction do not consume native stack per aggregate
level. State values use the analogous recursive `StateValueNodeV1::List` node.
Both profiles require `1 <= N <= 64`, permit nested lists and structured
elements, and reject records whose logical length exceeds the schema capacity.
An entrypoint value schema is limited to 256 nodes and aggregate depth 256.
`EntrypointValueTypeV1` validates the complete tape during binary and JSON
deserialization, so truncated trees, trailing trees, over-limit depths, and
otherwise invalid schemas are never returned as decoded values.
The logical 256-level schema remains flat on wire and therefore does not consume
one JSON parser frame per logical type level. The dynamic JSON `Value` parser
admits 33 structural levels, including one boundary-envelope level, while
recursively owned typed JSON decoders enforce the codec's 32-level limit.
The built-in `QueryPage<View>` product uses the canonical nominal schema name
`QueryPage`; its `items` list child is followed by the exact `View`
specialization, so
generic source punctuation never becomes part of an ABI identifier and the
five projection schemas remain structurally distinct. `QueryPage` and those
five projection names are reserved ABI nominals: a decoder rejects schemas
whose ordered fields, leaf kinds, list capacity, or continuation type differ
from their declared V1 shapes. Canonical public type strings retain those
nominals (`AccountView`, `Option<AccountView>`, and
`QueryPage<AccountView>`), while ordinary user structs retain the explicit
`struct Name` rendering.
The exact encoded schema is domain-separated and hashed into its argument,
return, or state record; a decoder must reject a record whose schema hash or
flat schema-delimited atom tape does not match.

An empty nominal struct has a zero-field schema and contributes no atoms to
the canonical record. Its VM representation is one initialized public zero
word, including inside lists, sums, and other products; this does not turn its
nominal schema into Unit. KSV1 permits zero arity for Struct nodes, while tuple
arity remains at least two. KRV1 permits an empty atom stream at the root or
inside a list element when the bound schema describes an empty product.

On wire, a list starts with one flat `List(u8)` atom containing its active
element count. The count is followed immediately in the record's single atom
tape by one schema-delimited atom stream for each active element, in order.
The count must not exceed the schema capacity. Unused capacity, recursive
per-list containers, end markers, and placeholder elements are not serialized.
`Option` and `Result` likewise encode one boolean tag followed by atoms for
only the selected branch (`some`/`ok` when true, `none`/`err` when false); the
inactive branch is supplied by the schema and contributes no record atoms.
This rule applies recursively inside products, lists, options, and results.

After schema validation and Norito decoding, the VM materializes different,
VM-local layouts:

- A list handle names one contiguous owned-heap allocation
  `[len: u64][capacity: u64][capacity * element_words]`. The allocation reserves
  the schema capacity up front, while only the `len` active slots have semantic
  values. The element width comes from the schema and is never inferred from
  heap bytes.
- An option/result handle names one owned-heap allocation
  `[tag: u64][max(branch_words) payload capacity]`. Only the selected branch
  payload is materialized; inactive payload bytes have no semantic value.

These raw handles are neither pointer-ABI TLVs nor Norito wire values. They
must never be persisted or transmitted directly. Crossing another boundary
requires re-encoding the active logical value into its schema-bound canonical
Norito record.

## Map Encoding

Maps encode deterministically with the same active layout flags:

- Entry count uses a fixed 8-byte little-endian u64 header.
- Each entry is `[key_len][key_payload][value_len][value_payload]`, with
  key/value lengths encoded via `COMPACT_LEN`.
- `HashMap` encodes entries in sorted key order for deterministic output;
  `BTreeMap` uses its natural ordering.

JSON objects have a separate key contract. `JsonObjectKey` supplies canonical,
unquoted text; the map writer adds quotes and applies the same escaping as JSON
strings. `JsonObjectKeyOwned` parses that text directly when decoding. Numeric
and boolean keys therefore use quoted decimal and `true`/`false` spellings.
Byte-array keys use uppercase hexadecimal. Arbitrary JSON values, optional
values, tuples, and collections are not object keys; their ordinary value
serializers cannot establish an unambiguous key identity.

Bounded writers visit key text through the checked contract, including through
borrowed keys, and stop on the first conversion or output-limit error. Streaming
formatters must preserve that error even if a formatter ignores a failed write.
Key decoders retain duplicate-key rejection and the active decode resource
limits. This JSON contract does not change the binary map layout above.

Persisted MV maps use the distinct `norito::json::JsonKeyCodec` contract: its
writer emits a complete quoted JSON key and its decoder receives unquoted text.
Norito owns the single trait and primitive/tuple implementations; domain types
own their implementations and MV owns only map serialization. Moving this
contract does not change key spellings, decoding, or the map wire layout.


## Heap Encoding

`BinaryHeap<T>` uses the ordinary element-sequence layout: a fixed-width
little-endian u64 count followed by each element's active-layout length prefix
and payload. Elements appear in ascending `Ord` order. Within an equal-`Ord`
group, their active-layout payload bytes appear in lexicographic order.
Equality under `Ord` does not imply identical payloads; the encoded order must
therefore be independent of heap backing, insertion history and reconstruction.
Equal payloads retain every element and its multiplicity.

The encoder admits the sorted-reference array through the original cumulative
codec context before allocation. Uniquely ordered heaps use only that array.
Tied groups additionally admit an exact three-usize metadata entry for every
tied element and one packed arena containing their measured payloads. Checked
writes cannot exceed the measured key lengths. The comparator only borrows
those admitted bytes; it neither serializes elements nor allocates sorting
scratch. The sequence emits the same key bytes that established tie order.

Every real reference, metadata, key-arena and nested element allocation joins
the original context, including each separate framing pass. Releasing local
scratch does not reset cumulative charges. Length-only heap measurement must
also construct real tie keys to establish canonical order; nested measurements
needed for those writes consume the same finite count-work allowance. The
codec incorporates its already measured keys without counting their payloads
again. No additional layout flag, frame identity or alternate decoder is used.

## MV JSON Snapshot Undo

The first-release MV JSON schema retains exact current and predecessor presence.
For Cell, `revert:null` means there is no retained predecessor; a present
predecessor is `revert:{"value":PREVIOUS}` even when `PREVIOUS` itself is null.
For Storage, the undo object omits untouched keys; a key's null undo means its
preimage was absent, while `{"value":PREVIOUS}` means its preimage was present.
The current `blocks` values keep their ordinary JSON representation. The
streaming decoder requires exactly one `value` member and rejects retired
unwrapped undo values rather than guessing from a payload token. Object keys
still use `JsonKeyCodec`; binary Norito and signed block wire formats do not
change. Explicit native execution-tip records and compound encoded-blob
snapshot records keep their existing separate schemas.


## MerkleTree Derived-Cache Encoding

`iroha_crypto::MerkleTree<T>` never serializes its breadth-first internal-node
cache or cached root. Its V1 payload is the tuple
`(hash_scheme: u8, leaves: Vec<HashOf<T>>)`, using the ordinary tuple and
sequence layouts selected by the header flags. `leaves` contains canonical
leaf-node hashes in left-to-right order and is limited to 65,536 entries.

The V1 hash-scheme discriminants are:

- `1`: application Merkle V1, with the versioned application internal-node
  domain;
- `2`: SHA-256 V1, where parents are `SHA-256(left || right)` and a missing
  right child promotes the left child.

Decoders reject unknown schemes or oversized leaf sets, retain the declared
scheme as part of the private tree invariant, and deterministically rebuild
every internal node and the root from the leaves. Encoders reconstruct using
that retained scheme and reject an in-memory tree whose cached nodes do not
match it. This also preserves the explicit scheme for empty and singleton
trees, whose node caches alone are ambiguous. There is no decoder fallback for
the retired full-node-vector layout. JSON uses the equivalent object
`{"hash_scheme": <u8>, "leaves": [<HashOf<T>>, ...]}` and follows the same
reconstruction and bounds.

## NCB Columnar (internal)

NCB payloads are exact and canonical:
- Alignment padding between NCB columns must be zero-filled.
- Bitset padding bits (flags and presence) must be zero.
- Trailing bytes after the NCB payload are rejected.

## AoS Ad-hoc (Adaptive Columnar)

The `norito::aos` helpers used by adaptive columnar encoders follow the same
length prefix rules and honor the active `COMPACT_LEN` flag, so embedded AoS
payloads stay consistent with their parent Norito headers.

## Derived Record Layout

Derive-generated structs and tuple structs encode their fields in declaration
order. The record adds no header, field count, offset table or presence bitset:

- Each non-flattened field is `[len][payload]`, where `len` is the field
  payload length encoded per `COMPACT_LEN` (a compact varint when set, a fixed
  8-byte little-endian `u64` otherwise).
- A `[u8; N]` field is `[len = N][N raw bytes]`, with no per-byte prefixes.
- A `#[norito(flatten)]` field is inlined with no prefix of its own, and its
  nested fields follow the frame's layout flags. Flattening never switches a
  frame to compact lengths: a `0x00` frame containing a flattened field carries
  header flags `0x00`.
- `#[norito(skip)]` fields are omitted from the payload.
- Unit and field-less records have an empty payload.
- An enum variant is its `u32` tag followed by the variant's fields, each
  length-prefixed as above; a unit variant is the tag alone.

Field payloads use the frame's layout flags when encoding nested collections or
string/blob values. Every derive-generated field is decoded canonically and
must consume exactly its declared span; fixed byte arrays use an equivalent
exact-length copy. Trailing bytes inside a declared field are rejected; there is
no archived-value retry that can accept another field encoding or consume
following fields.

Fields annotated with `#[norito(default)]` or a custom default remain mandatory
ordinary binary fields and consume their declaration-order field frame. Those
attributes supply values only for absent JSON fields. A missing or malformed
binary field is rejected; binary decoding never synthesizes an omitted
positional value.

Every derive-generated enum tag is a canonical little-endian `u32`. An explicit
Rust discriminant selects the wire tag, and subsequent implicit variants follow
Rust's incrementing discriminant sequence. `#[codec(index = N)]` may pin an
otherwise implicit variant; when used alongside an explicit Rust discriminant,
the two values must agree. Effective tags must be unique. The encode, decode,
and schema derives reject disagreements and duplicates at compile time and use
the same effective tag set.

### Derive attribute contract

The `#[norito(...)]` namespace is closed: derive entry points validate every
container, enum variant, and field before code generation. Unknown keys,
malformed helper paths, valued flag attributes, and duplicate options are
compile-time errors. Representation keywords that Norito does not implement,
including `transparent` and `untagged`, are rejected rather than ignored.
Tuple newtypes therefore keep the ordinary tuple layout; changing that layout
requires a deliberately specified and tested wire-format change.

Named enum fields honor `#[norito(json = "module")]` and
`#[norito(with = "module")]` in both `JsonDeserialize` and explicit `FastJson`
derives, matching their serializers. A helper-owned field does not require its
type to implement the default JSON trait. Missing, duplicate and trailing-field
checks still apply to the enclosing enum, as does unknown-field rejection when
`deny_unknown_fields` is selected. Helper selection does not change binary
layouts or schema identities.

## Compression Selection and Validation

The header `Compression` byte identifies the payload encoding:

- `0 = None`: payload bytes follow the header (with optional alignment padding).
- `1 = Zstd`: payload bytes are compressed with Zstandard.

`Payload length` and `CRC64` always describe the uncompressed payload. For
compressed payloads, the encoded byte stream begins immediately after the
header with no alignment padding. Decoders must reject unknown compression
values or unsupported algorithms; builds without the `compression` feature
accept only `None`.

Encoders choose compression explicitly (`to_compressed_bytes`) or via the
adaptive helper (`to_bytes_auto`) that applies deterministic heuristics. The
chosen algorithm is recorded in the header; there is no on-wire negotiation.

## Schema Hash Details

The 16-byte frame hash is the first 16 bytes of
`SHA-256("norito:v1:type-name\0" || NoritoSchema::frame_name())`.
The historical domain separator remains part of V1; the name bytes now come
only from an explicit protocol declaration. Rust source paths and compiler
`type_name` output do not select the active frame identity.

`#[derive(NoritoSchema)]` requires `#[norito_schema(name = "protocol.name")]`.
An optional `frame = "protocol.root"` declares a root projection, such as a
borrowed signing view sharing its owned record's frame. Generic constructors
compose their arguments' nominal identities in declared order; they never
substitute a child's root projection. Payload field types do not need identities
unless they participate in a nominal generic argument or are independently framed.
A name must not be reused for different layouts. Moving a Rust owner between
modules leaves its declared identity and encoded bytes unchanged.

The `schema-structural` feature exposes schema-inspection hashes using
`SHA-256("norito:v1:structural-schema\0" || canonical JSON schema)`.
It does not change frame headers or typed decoder selection. The type-name
hash helper likewise serves inspection and source-capture tooling only.

Typed decoders must reject payloads whose header schema hash does not match the
expected type. `ArchiveView::decode` enforces this check; `decode_unchecked`
is reserved for tooling that explicitly opts out of schema validation. Schema
opt-out never disables the payload-derived resource budget.

### Enum slice boundaries

A derived enum with `#[norito(decode_from_slice)]` decodes one payload prefix and
returns the exact consumed byte count, including its discriminant. Named, tuple
and unit variants share the bounded payload decoder; bytes belonging to the
caller remain unread. Nested fields and complete-frame/exact-slice APIs still
reject trailing bytes. The advertised layout, validation hook, field/count
bounds and enclosing allocation budget apply to the prefix operation. This
changes no wire bytes, frame identities or protocol version.

### Fixed JSON object schema metadata

`FastJsonWrite::json_object_field_order()` reports the exact field order for
derived named structs with a value-independent object shape, applying the same
renaming and skipped-field rules as serialization. Conditional omissions and
flattened objects return `None`. Snapshot readers use this metadata without
constructing a default World or serializing its stores; this changes no bytes.

### Retail phone identifier attestation

`IdentifierResolutionReceipt` now encodes three derived-struct fields in
order: `payload`, `attestation`, and
`Option<PhoneRetailCanonicalityAttestationV1>`. The option is part of the
Norito payload even when absent for a non-phone receipt. The phone attestation
encodes its signed `PhoneRetailCanonicalityPayloadV1` followed by the
signature. The payload fixes the field order as exact `NetworkId`, policy ID,
program ID, input ciphertext hash, output ciphertext hash, opened output
hash, canonical phone nullifier, UAID, account ID, issue time, and expiry
time. The signed payload's schema identity is
`iroha_data_model::identifier::PhoneRetailCanonicalityPayloadV1`; the
attestation's is
`iroha_data_model::identifier::PhoneRetailCanonicalityAttestationV1`.

### Sumeragi execution-result schedule projection

The sole `iroha_data_model::sumeragi_finality::ExecutionResultCommitment` frame
contains `height`, `execution`, `schedule`, `beacon`, and `native_lanes` in that
order. Its schedule contains `height`, the complete `current` epoch context,
the optional complete `boundary` (including its next context and frozen
preparation), then `next` and `after_next`. Each successor is either
`Ready { height, params }` (tag 0), or
`PendingBoundary { height, boundary_height, predecessor_context_id, params }`
(tag 1). A ready successor derives its epoch from `boundary.next` when a
boundary exists, otherwise from `current`; no duplicate epoch bytes occur in
the successor slots. The encoder rejects an owned successor whose epoch differs
from that exact source before writing the frame. The decoder reconstructs the
complete owned graph, charging every additional roster, public-key and proof
allocation to the inherited decode budget, and the result reader validates the
complete graph. The result's `IntoSchema` projection describes these exact wire
fields. The 64 KiB result-preimage/shared-witness limit is unchanged, including
31-member boundaries with frozen preparations. The standalone `ScheduleOutcome`
codec still represents its full owned graph; it is not the result frame's
schedule codec. There is no decoder for the repeated-successor result layout.

## Finite count-first source traversal

`core::encoded_payload_len_bounded` and `encoded_frame_len_bounded` share a finite
byte allowance across nested count writers. Real leaf and framing writes consume
that allowance once; incorporating an already measured child neither repeats its
traversal nor charges it twice. An exceeded allowance stays rejected even if the
serializer ignores the write error. The framed helper includes the canonical
header and alignment padding. Arbitrary work before a serializer emits bytes
remains subject to the caller's source-specific work checks. Wire layouts and
canonical comparisons are unchanged.

### Complete callable schema body

`ivm_abi::call::CallSchemaV1` has one CS1 body: magic `43533100`, a fixed
little-endian `u64` count, then complete preorder nodes. The Norito header
advertises the layout flags used by child strings, string vectors and the
length-prefixed complete error descriptor; the decoder does not guess flags.
Node tags are Struct=0, Tuple=1, Option=2, Result=3, List=4, Leaf=5, Unit=6,
Error=7, StateCursor=8, StateRoot=9, Pointer=10 and SecretNumeric=11. Struct
payloads are canonical String followed by Vec<String> in declaration order;
Tuple uses `u32`, List uses `u8`, Leaf/StateCursor use one-byte public kind
ordinals 0..13, and Pointer/SecretNumeric use `u16`. Zero-field nodes have no
payload. Inline children retain all nominal identities, roles and constraints.

The borrowed writer does not construct a second encoded graph. The decoder
charges the original sequence/cumulative-element budget and the actual node
Vec layout before reserving it, charges capacity excess, and uses the original
canonical String, Vec<String> and error decoders with their active allocation,
UTF-8, field and nesting limits. It validates the complete bounded forest before
publication. Native allocator refusal remains distinct from malformed wire.
Generic per-node enum wrappers and the previous vector body are retired; no
alternate decoder remains. This changes the authenticated V1 semantic ABI hash,
so all native artifact captures and generated ABI hash material must be produced
from the changed compiler before their mandatory consumers pass.


The JSON parser's `parse_string_with_buffer` and typed map/sequence callbacks share
ordinary parsing, framing and logical-quota kernels. A caller can admit an exact
original-pool string/key destination before copying without replacing a resource
refusal with syntax. These callbacks do not fund enclosing maps, crypto validation
scratch or retained retry state, and do not change canonical JSON or binary layouts.
