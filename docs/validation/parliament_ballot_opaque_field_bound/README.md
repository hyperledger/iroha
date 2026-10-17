# Conditional opaque-field constructor bound

The [checker](../../../scripts/parliament_ballot_opaque_field_bound.py) derives
the four local paths of `OpaqueField::new` in both retained ARM64 standalone
worker images. Its symbolic interpreter tracks length intervals, input/result
and allocation ownership tokens, call arguments, saved registers, stack and
result writes. It verifies the unsigned length guard before allocation/copy,
the zero-byte path, ordinary cleanup, and the final allocation-error frontier.
All constructor, native, physical-workspace and production qualification flags
remain false; current-checkout applicability is false.

| Path | Length | Local issued instructions | Calls |
| --- | --- | ---: | --- |
| Oversize error | 257 through `2^64-1` | 20 | None |
| Empty success | 0 | 23 | One zero-byte `memcpy` |
| Allocated success | 1 through 256 | 29 | Shim, allocation, copy |
| Allocation-null prefix | 1 through 256 | 18 | Shim, allocation, error handler |

The own frame is 48 bytes, or 176 bytes including the retained conservative
128-byte red-zone allowance. Zero-length construction skips allocation but
still calls `memcpy(1, input, 0)` under its explicit no-access pointer contract.
The final error call's hypothetical return reaches the next function. Its work,
fallthrough and exceptional continuation remain unknown; it is not silently
treated as a normal return or excluded using its symbol name.

The [retained reviewed draft](capture/sources/02-README.md.template) contains the
full source/callee/ABI premises and composition. Only ordinary returning calls
permit substitution of `29 + H + A[256] + M[256]` for the constructor's opaque
term. Five such calls change the decoder's local contribution from 621 to 766
while preserving the added lower terms. Their frames are sequential, not summed;
callee depth becomes `1584+48=1632`. No complete work, stack or memory bound is
inferred. Later caller cleanup remains separately charged.

The [focused suite](../../../scripts/tests/parliament_ballot_opaque_field_bound_test.py)
passed **137 tests in 9.04 seconds** in the captured run.
[JUnit](capture/tests.xml), [stdout](capture/tests.stdout.txt), stderr and exact
command records remain in `capture/`. The [capture receipt](capture/receipt.json)
records pytest exit 0, normal analysis exit 0 and qualification refusal exit 2.
The [analysis](capture/analysis.json) and [refusal](capture/refusal.json) reports
are byte-identical. Peer review independently ran the same final 137 tests; this
is local engineering review, not independent cryptographic or native review.

The analysis authenticates 2,153 retained input identities and resolves all
2,021 recorded build inputs. The original Cargo.lock is read from its
manifest-bound archive; its changed live identity remains a separate observation.
Neither historical analyzers nor workers were rerun. Body bytes, captured
disassembly, source, function ownership and native stub targets are bound to
the successful recorded build/capture. Compiler/disassembler correctness,
callee contracts, runtime costs and exceptional behavior remain premises or
unknown obligations.

The execution used ignored staged paths. Its five selected source/config/recipe
inputs, applicable conftest absences and launcher/interpreter identities remained
unchanged. The [tested source snapshots](capture/sources/) retain those bytes;
the installed helper and test are identical. Publication is not another test
run. Interpreter/pytest dependencies, cache coherence, unobserved child reads
and non-atomic before/after observation remain explicit capture limits.

The original [staged manifest](capture/STAGED_SHA256SUMS) is preserved unchanged
and still names its historical stage paths. [CAPTURE_SHA256SUMS](CAPTURE_SHA256SUMS)
binds the copied files using paths relative to this final bundle. The
[document custody record](document-custody.json) authenticates the three prior
central documents against the frozen admissibility manifest and retains exact
before/after bytes. Earlier manifests and aggregate indices are unchanged.

The guarded [publication recipe](publish.py.template) and
[publication receipt](publication-receipt.json) identify the byte-for-byte source
installation and the three reviewed document replacements. The final
[manifest](SHA256SUMS) covers every bundle file except itself. Production stays
gated; native, allocator, exceptional, full-workspace and hardware obligations
remain open.
