# Frozen worker allocation layouts

[receipt.json](receipt.json) records read-only disassembly of the two existing
macOS ARM64 `resource_contract` binaries identified by the original
[build receipt](../parliament_ballot_resource_contract/build-receipt.json).
No library, worker, build receipt, source pin or binary was changed or rebuilt.
The six relevant source files still match that build's source manifest; both
binary hashes were checked before and after extraction.

The release binaries have no usable DWARF records for these types. Their
emitted allocator arguments and element strides nevertheless establish the
following allocation layouts for these exact binaries, in both modes:

| Type | Element bytes | Alignment | Emitted evidence |
| --- | ---: | ---: | --- |
| Private `vole::Tree` | 24 | 8 | `Layout::new` computes `(tau + 2*tau) << 3` and calls `__rust_alloc(size, 8)`; construction advances by 24 bytes. |
| `Key<Gf256>` | 40 | 8 | Relation scratch allocates 64,000 bytes twice and 12,800 bytes twice at alignment 8; element copies advance by 40. Its vector destructor frees `capacity * 40` at alignment 8. |
| `Gf256` | 32 | 8 | Its vector destructor iterates in 32-byte strides and frees `capacity << 5` at alignment 8. |

The compiler merged the `Key<Gf256>` and `PlainValue<Gf256>` vector-destructor
implementations. `nm` retains both names at the same address; the receipt keeps
these aliases so the disassembler's choice of displayed name is not mistaken
for a different function.

The retained BAVC destructor also releases `offsets, com, seeds, hidden` in source
field order, with alignments `8,1,1,2`. The VOLE destructor releases
`commitment, hidden, delta, q, q_masks`, with alignments `1,2,1,1,1`. These checks
support the return-object cleanup in the
[backend trace](../../../scripts/parliament_ballot_arena_backend.py).

The receipt gives exact command arrays, function address ranges, mangled names,
tool version, output hashes and source hashes. Re-run those `xcrun nm` and
`xcrun llvm-objdump` commands against the hash-matching binaries to reproduce
the extracts. The `.txt` files are unmodified command stdout.

This is source-assisted manual disassembly review, not a proved machine-code
data-flow analysis. It narrows three target-specific layout premises; it does
not establish correspondence for every allocation in the trace, arbitrary
compiler transformations, native/TLS allocation, stack use, concurrency, other
targets or another build. Workspace and profile qualification remain false.
