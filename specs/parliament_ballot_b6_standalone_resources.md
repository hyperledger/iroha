# Standalone ballot resource model

The [checker](../scripts/check_parliament_ballot_resource_accounting.py) binds
these formulas to 75 Rust source files and six manifests/toolchain/lock files.
It fails if that reviewed source set changes. This is a conditional requested
allocation ceiling and a separated arithmetic/hash/loop inventory for the
standalone implementation. It is **not complete verifier work, a production
allocation certificate, a cycle/deadline bound, or profile qualification**.
The production `complete_certificate` and `profile_qualified` flags stay false.

```sh
python3.11 scripts/check_parliament_ballot_resource_accounting.py
python3.11 -m pytest scripts/tests/check_parliament_ballot_resource_accounting_test.py -q
```

`--require-complete` intentionally exits 1. The generated JSON contains each
phase's buffers, primitive counters, table weights, source hashes and
assumptions. Routine Rust benchmarks are not repeated for this model.

## Boundary and allocation assumptions

The cold path is a bounded `TEST_RECORD` slice, profile compilation, statement
decoding, and ordinary registration/vote verification. The record decoder
borrows its two fields. Decoding bounds copied fields before allocation.
Ordinary verification is also reported separately: it compiles one profile;
the cold path compiles two. Cold registration additionally recomputes the body
digest; cold vote additionally validates/hashes its list once. No prover or
credential-secret operations are included.

The allocation model counts requested `GlobalAlloc` layouts, with 64-bit
`usize`, `Key<Gf256>` of 40 bytes, and `Tree` metadata at most 24 bytes. Those
are explicit target/layout assumptions, not language-level representation
promises. Slices, vector headers, fixed objects and stack frames are excluded.
An existing caller's `Vec` can have arbitrarily large spare capacity even when
its length is valid. Therefore caller-owned inputs are excluded; the optional
record column below adds **exactly** a canonical record's length, assuming that
is its complete backing allocation. It does not bound arbitrary callers.

The checked allocation policy is Rust 1.93.1 commit
`01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`. Its
[RawVec growth](https://github.com/rust-lang/rust/blob/01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf/library/alloc/src/raw_vec/mod.rs)
uses the larger of twice the old capacity, the required length and its small
minimum; its stored capacity follows the request. Six relevant alloc sources
were checked byte-for-byte against this toolchain's installed rustdoc HTML;
their SHA-256 hashes are in the JSON. The model bounds grow-only buffers by
twice final length, with another half-capacity during reallocation. Known
frame appends are modeled individually. This does not bound internal malloc
metadata, size classes or temporary allocator storage.

Profile compilation's CRT word and byte buffers have a conservative envelope
of 421,520 candidate / 418,520 comparator bytes, including growth overlap.
After those buffers drop, descriptor construction holds 12 parameter bytes,
16 dimension bytes and its growing frame; its 796-byte envelope is separately
listed and is dominated by the CRT phase. The profile returned is fixed-size.

The [provider layout receipt](../docs/validation/parliament_ballot_b6/provider-layout.md)
compiles the pinned AES provider for four 64-bit targets in both feature modes.
Each provider requests 960 bytes; alignment differs. The checker validates
the source hashes and retained LLVM IR before specializing its symbolic
provider term. Only one provider Box can be live: node expansion, leaf
commitment and small-VOLE expansion construct/drop theirs sequentially. This
receipt executes no target code and establishes no provider stack bound.

| Row / role | Seats | Verifier-owned requested bytes, upper bound | With exact-capacity canonical record |
|---|---:|---:|---:|
| Candidate registration | — | 2,327,194 | 2,493,366 |
| Candidate vote | 3 | 3,452,826 | 3,686,806 |
| Candidate vote | 500 | 3,580,058 | 3,877,654 |
| Candidate vote | 1,000 | 3,708,058 | 4,069,654 |
| Comparator registration | — | 6,028,543 | 6,144,065 |
| Comparator vote | 3 | 6,023,679 | 6,182,721 |
| Comparator vote | 500 | 6,150,911 | 6,373,569 |
| Comparator vote | 1,000 | 6,278,911 | 6,565,569 |

These are conditional source-model bounds, not measured RSS. Candidate peaks
at transposition; comparator peaks during BAVC reconstruction. The JSON
explicitly includes BAVC's return offset/hidden-index copies; seed storage and
conversion scratch; retained gate/delta/mask buffers; QuickSilver scratch and
vote selector products. Original columns drop before row allocation. Gate-head
buffers and mask-product temporaries drop before the lift. Some small disjoint
temporaries are summed conservatively. Large phases are never summed together.

## Arithmetic, hashing and bounded loops

Let `l` denote witness bits, `C` total constraints, `R` revealed leaves, and
`S` list entries. Full GF(2^256) multiplication, `mul_u64`, `mul_bit`, and
GF(2^256)-by-GF(2^768) leaf multiplication are separate units. Each leaf also
performs one affine GF(2^256) multiplication. Full products invoke 16
`clmul64` calls, scalar products four, and extended leaf products 48; these
are call counts, not equal-cost CPU operations.

The relation's addition-degree alignment is included. Registration emits
75,136 products, 192,044 alignment products and 36,736 constraints. Vote emits
`113024+S` products and at most 289,864 alignment products, plus 55,427
constraints. Every constraint has a full multiplication to lift its degree,
even when the corresponding power is one. Booleanity, both universal hashes,
Delta powers, masking and coefficient evaluation are additionally counted.
Coordinate masking and **public-bit construction** both use `mul_bit`.

For vote multiplexer work, `P` is the number of set bits in the list and `Z`
the number of bit columns containing a one. The model uses `P<=1024*S` and
`Z<=1024`. This is a safe ceiling; no claim is made that a sorted distinct list
attains both maxima. The fixed CRT matrices instead use actual table weights:

| Matrix | Candidate set bits | Comparator set bits |
|---|---:|---:|
| G | 88,281 | 87,345 |
| W_CRT | 30,584 | 31,102 |
| W_TREE | 30,807 | 32,163 |
| W_GATE | 88,020 | 89,170 |

Column application XORs `width*weight` bytes while testing every matrix entry.
The independent all-bits ceiling is also reported. Matrix/vector multiplication
visits every packed word regardless of weight; it uses distinct word-and-XOR,
parity and output-bit operations. Shape and padding checks reject malformed
table parses.

PRG bounds include separate provider constructions/Box allocations, logical
AES input blocks, calls to the provider's slice-encryption interface and output
bytes. The bounds permit all `L-1` internal GGM nodes, although hidden paths
are skipped. Every revealed leaf has a leaf expansion and a small-VOLE
expansion. Provider batching may compute unused lanes, and accelerated provider
construction can prepare decryption state too: neither is priced as one AES
block. Verification hashes the supplied counter once and never grinds.

Sponge counts include every domain byte, the 77-byte prefix, absorb padding,
and additional squeezes. H5 takes **two** Keccak-f permutations per gate;
challenge 1 needs an additional output permutation. Profile, body/list,
authorization and message hashes are separated from backend hashes. Registration
uses maximal bounded body/context fields; vote reports S=3, 500 and 1,000.

The JSON separately bounds tree traversals, padding checks, mask folding,
corrections, matrix application, transposition and list comparisons. Finite
byte-copy, initialization, drop-zeroization, encoding/decoding and ordinary
scalar control/check work are **not a complete charged schedule** here. In
particular, a list of cryptographic counts must not be presented as total
`B_work` or used to set an admission stamp difficulty without those terms and
an explicit charge model.

## Remaining certificate terms

Complete production framing, authenticated shared-context mapping, admission
work stamps and their checks remain gated. A process/64 MiB workspace bound
also needs target-specific stack/provider scratch, compiler spill/copy effects,
allocator overhead, failure behavior and concurrency scope. Constant-time and
secret erasure need independent implementation review; verifier inputs are
public, and resource ceilings do not establish prover leakage properties.
This model changes no Rust protocol implementation or activation gate.
