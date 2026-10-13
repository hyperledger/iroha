# Arena and stack sufficiency feasibility review

This source review does **not** certify that every admitted input completes in
the 32 MiB arena or 8 MiB stack. No valid-input exhaustion defect was found in
the reviewed paths. No new build, campaign, stack measurement or exhaustive
allocation trace was executed. The existing containment and finite-campaign
claims remain distinct from sufficiency.

## Concrete heap bound and its limit

The [existing requested-allocation inventory](../../../specs/parliament_ballot_b6_standalone_resources.md)
separates BAVC reconstruction, VOLE conversion/lifting and relation evaluation.
Using its comparator vote `S=1000` maximum, the measured-layout 960-byte provider
and the **full admitted** 425,984-byte copied record gives
`6,277,951 + 960 + 425,984 = 6,704,895` requested bytes. This is a substitution
into that source model, not a new complete certificate or a rerun of its frozen
source guard. Its optional canonical-record size alone does not cover all
admitted malformed records.

[`arena.rs:108`](../../../crates/iroha_parliament_ballot_proof/examples/resource_contract/arena.rs#L108)
rounds each allocation separately to
`next_power_of_two(max(size, alignment, 64))`. For audited layouts with
`alignment <= 64`, rounded live bytes are at most `2*M + 64*N`, where `M` is
live requested bytes and `N` is the live allocation count, including old and new
buffers during reallocation. A small explicit live-object inventory can make
this a conservative inequality well below 32 MiB. The current aggregate phase
buckets do not themselves supply that inventory: retained statements, VOLE
state, relation scratch and conversion scratch contain multiple allocations.
No unproved value for `N` is adopted here.

Even a proved rounded-live inequality is insufficient for this buddy allocator.
It also requires a free block of the requested order (`arena.rs:124–127`). For
example, freeing alternating minimum blocks after filling a buddy heap leaves
half the heap free but no double-sized free block. That is an allocator example,
**not a demonstrated verifier trace**. Sufficiency therefore additionally needs
an allocation/free-order argument or exhaustive abstract replay, not merely
extra headroom in a sum.

## Finite source work that can close the arena gap

The relevant input-dependent dimensions are bounded and identifiable:

- The copied record length is `0..=425984`. Registration has one `0..=4096`
  field and six `0..=256` fields; vote has `S=3..=1000`. Empty allocations and
  each resulting buddy order must be represented. Frame append/reallocation
  schedules must cover intermediate lengths, not infer their capacity from
  only the largest fixture.
- The fixed row and role determine all large backend buffer lengths.
  [`bavc.rs:1050`](../../../crates/iroha_zkp_vole/src/bavc.rs#L1050)
  allocates marks, keys and seeds from the trusted shape. Comparator keys and
  seeds round to 4 MiB and 2 MiB. Hidden indices affect traversal and provider
  invocation counts, not these lengths.
- [`vole/convert.rs:80`](../../../crates/iroha_zkp_vole/src/vole/convert.rs#L80)
  implements the fold iteratively with two heap vectors, of `depth*width` and
  `width` bytes. Its “stack” is not recursive native-stack storage. Provider
  constructions have one live box. A trace model may collapse repeated balanced
  allocation/free subtraces only after establishing that they restore allocator
  state and cover each applicable size/alignment class.
- [`vole.rs:564`](../../../crates/iroha_zkp_vole/src/vole.rs#L564) drops original
  columns before allocating rows, while lifted columns remain live.
  [`keccak_relation.rs:247`](../../../crates/iroha_parliament_ballot_proof/src/keccak_relation.rs#L247)
  uses five heap vectors, and `vote.rs:339` allocates `S` selector products.
  These lifetimes, both profile constructions and realloc overlap must appear
  explicitly in the trace grammar.

An actionable completion artifact is a source-bound allocation grammar plus
exact replay of the existing allocator over all admitted shape classes and
early-return prefixes. It must verify alignment admission, available block order,
live quota, reclamation and zero live allocations on ordinary return. The
existing allocation/provider/Rust-library inventories provide its starting
point; no new cryptographic assumption or production charging policy is needed.
This artifact has **not** been implemented by this review.

## Malformed paths and stack boundary

`budget.rs:205` constructs the profile before test-record decoding. Therefore an
empty, truncated or trailing-data record still has that preparation cost.
`test_codec.rs:177` fixes the field-slice count before allocating it;
`test_codec.rs:222` bounds registration copies; and `test_codec.rs:272` checks
vote entry length/count before copying the list. Each rejection prefix must
retain the full admitted input-buffer allowance. After successful proof-codec
validation, fixed admitted relation/profile dimensions govern reconstruction;
canonical late-invalid proofs execute the complete allocation path. Existing
malformed classes and late-invalid observations exercise this structure but
are not exhaustive across all lengths and allocator states. File changes/read
errors, resource failure and exceptional termination remain separate outcomes.

The native mapping establishes an actual 8 MiB supplied stack and guard pages,
not a proof that every ordinary call fits. Source bounds on loops and heap
buffers do not bound compiler spills, inlining, helper call frames or native
runtime paths. A target/compiler/feature-specific compiled call-path and frame
bound is still needed; ordinary and exceptional paths must be distinguished.
The [native runtime audit](native-runtime-audit.md) separately records the
unclosed System/TLS/native-runtime coverage. Neither a heap trace certificate
nor a larger stack reservation would discharge that coverage automatically.
