# Conditional allocator activation in the frozen workers

This separate analysis checks four explicit System allocation sites in each
original ARM64 resource-worker binary. The local checks pass in both modes:
the worker's true store to `ACTIVE` dominates its call to
`Reservation::verify`, and the four `malloc`/`posix_memalign` sites can be reached
only through the allocator's zero-test arm. **Unconditional activation remains
UNKNOWN.** The analysis does not prove opaque-call noninterference, arbitrary
pointer provenance, callback behavior or absence of panic.

The [report](analysis/report.json) and [source/test receipt](validation-receipt.json)
are new evidence. The earlier [stack frontiers](../parliament_ballot_stack_frontiers/README.md),
worker binaries, source pins and allocation observations are unchanged. No worker
was executed or rebuilt for this analysis.

## Exact checked boundary

The [helper](../../../scripts/parliament_ballot_allocator_activation.py) verifies
the old stack, provider and frontier artifact manifests and the two original
executable hashes. It reads the Mach-O symbol table directly and requires one
local section-defined private `ACTIVE` symbol. The exact worker source is checked
against the original build receipt and retained in
[the analysis](analysis/workspace.rs.template).

The source contains five literal accesses: a private false initializer, an
acquire load, two release clears, and one release activation. The clear in
`worker` follows `execute`; the clear in `run` follows thread join. The source
does not export the flag's address. These are facts about the pinned source,
not an independent proof of compiler correctness or whole-binary alias behavior.

The compiled reference catalog is explicitly **resolved-only**: it recognizes
adjacent `ADRP`/`ADD` materializations of the flag address. It checks ordinary
control flow and propagates GPR constants and possible flag-pointer taint in
their owning functions. Merges retain taint when the exact address is lost.
Unresolved flag-derived memory accesses, escapes, unsupported manipulations,
unknown instructions and indirect jumps make those local checks unknown.
The catalog does not establish that every arbitrary computed or aliased store
in the binary has been found. That unresolved scope is retained in the report.

| Check | Portable | Accelerated |
|---|---|---|
| Private flag address | `0x1000d4d50` | `0x1000d4d50` |
| True release store | `0x100002944` | `0x100001a8c` |
| Worker verification call | `0x100002a58` | `0x100001ba0` |
| Resolved flag stores | One true, two false | One true, two false |
| Explicit guarded System allocation sites | 4 | 4 |

Both outcomes of conditional branches are included. Deleting the activation
instruction makes the verification call unreachable from the worker entry;
no resolved clear lies on a path from that activation to the call. None of the
resolved store-owning functions belongs to the earlier reservation-root
direct/provider graph. This means **no resolved writer**, not no possible writer.

At each targeted allocation site, the helper requires an acquire byte load and
an immediately following `cbz` of its result. The load and branch must dominate
the native site. The false successor must reach that site, and the true
successor must not. The check covers `__rust_alloc` and the separately emitted
`Routed::alloc`; it does not remove deallocation branches based on an assumed
pointer origin.

## Conditional consequence and unresolved premises

The four sites can be excluded from this worker-established, ordinary
reservation path **only under** the explicit source/compiler linkage,
memory-safety, private-state noninterference and ordinary ARM64 call-ABI
premises. Opaque native calls, callbacks and other threads must neither write
the flag nor reenter a flag-writing setup/worker path. The helper identifies
three calls between activation and verification whose ordinary returns require
that premise; it does not prove their hidden effects. Directly calling
`Reservation::verify` without this worker activation has no such guarantee.

Under those premises, the System-frontier count is **14 to 10 per mode**:
four allocation sites are excluded conditionally, while ten `free` sites remain.
The unconditional frontier count is unchanged. The existing conditional provider
and failure-entry premises also remain in force. Failure handlers, native hidden
work, callbacks, traps, function fallthroughs and unwind behavior retain their
unknown costs; no exceptional edge is assigned zero stack or declared harmless.

This yields no new numeric complete stack bound, proof of all-input completion,
8 MiB stack certificate or 64 MiB workspace certificate. All production and
qualification flags remain false. The next distinct obligation would be a
justified ownership/noninterference argument for the remaining frees or a
bound for native endpoints; finite successful observations cannot supply it.

## Validation and reproduction

The focused tests cover synthetic Mach-O bounds/privacy, independent diamond
and bypass graphs, unknown instructions and controls, taint at merges and
escapes, unsupported shifted pointer operations, source-access mutations,
both frozen images, activation/branch-polarity mutations, reachable-writer
rejection, atomic read-modify-write escapes, returned and tail-call pointer
escapes, fresh-directory refusal and UNKNOWN CLI outcomes. Source changes
during analysis invalidate its result. A failed local check leaves an explicit
UNKNOWN receipt rather than a conditional pass.

Independent read-only review found and corrected three fail-closed helper gaps:
unsupported shifted operands, LDADD data operands, and return/tail-call pointer
escapes. An earlier unreviewed development receipt is kept outside this final
artifact set under `/tmp/parliament-allocator-activation-before-return-check`;
it is not the receipt linked above. The final analysis uses the corrected helper.

```sh
python3.11 -m pytest -q scripts/tests/parliament_ballot_allocator_activation_test.py
python3.11 scripts/parliament_ballot_allocator_activation.py \
  --output /tmp/parliament-allocator-activation-new
```

The output must be new. [SHA256SUMS](SHA256SUMS) covers the final report,
source snapshots, checks and this validation note. This engineering check is
not an ISA proof or independent cryptographic/unsafe-code qualification.
