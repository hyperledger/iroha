# Current candidate: conditional compiled correspondence

This artifact re-evaluates four ordinary compiled contributions for the guarded
current standalone worker. It preserves the historical artifacts and their
`BODY_HASHES`. It does **not** establish a complete verification, native-runtime,
cryptographic, exceptional-path or 64 MiB workspace bound. Production remains
gated; every complete-certificate and qualification flag stays false.

The new checker is
[`parliament_ballot_current_correspondence.py`](../../../scripts/parliament_ballot_current_correspondence.py),
with focused
[negative controls](../../../scripts/tests/parliament_ballot_current_correspondence_test.py).
It requires the exact current
[build-v2 receipt](../parliament_ballot_current_candidate/build-v2/build-receipt.json)
and [fresh stack capture](../parliament_ballot_current_candidate/stack/receipt.json).
All current build inputs are checked before and after analysis. A discrepancy
retains `UNKNOWN`, rather than refreshing a pin or reusing a historical result.

## What corresponds

The two new binaries differ from their historical counterparts, so their
whole-file identities are not interchangeable. The checker compares every byte
other than the following explicitly delimited metadata:

- The 16-byte build UUID and the trailing code-signature container. Signature
  validity and signing identity are not claimed by this argument.
- Symbol string-table layout and the `n_strx` words pointing into it. Every
  symbol row is resolved in order; type, section, description and value must
  match exactly. All undefined native and externally visible names must match.
  Only eleven private, section-defined local names per image may differ by
  reviewed compiler hash spelling: ten anonymous data names and one allocation
  `Shared::drop` symbol. Their addresses and the bytes at those addresses match.

Symbol/signature metadata must reside within `__LINKEDIT` and cannot overlap
loaded sections or each other. Section owners/extents, file/header geometry and
all load commands except the UUID payload match. Unsupported symbol forms,
including `N_INDR`, refuse. Thus the check retains exact instruction/data bytes,
zero-fill geometry, constants, initial data, native-library load paths and
ordinals, bind/rebase/export records, function starts, unwind tables and indirect
symbol indices. Apple defines the checked fields in
[`nlist.h`](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/nlist.h)
and [`loader.h`](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).
This is a comparison of these pinned files, not a general Mach-O verifier.
Native libraries loaded at runtime retain their explicit external contracts.

Twelve selected code ranges per mode also receive exact byte equality checks
and individual SHA-256 identities. Their addresses and lengths are unchanged:

| Function | Instructions | Machine bytes |
| --- | ---: | ---: |
| worker | 203 | 812 |
| arena allocate | 100 | 400 |
| routed deallocate | 86 | 344 |
| exhaustion wrapper | 3 | 12 |
| fatal exhaustion | 15 | 60 |
| allocation shim | 1 | 4 |
| Reservation::verify | 196 | 784 |
| decode_record | 55 | 220 |
| parse_frame | 123 | 492 |
| decode_registration | 616 | 2,464 |
| decode_vote | 438 | 1,752 |
| Profile::new | 694 | 2,776 |

The portable disassembly tuples match directly. The accelerated tuples differ
at exactly thirteen `ADRP` annotations: registration offsets `0x30/0x164`, vote
`0x28`, and Profile offsets `0xf8/0x11c/0x12c/0x150/0x160/0x3f0/0x414/0x41c/0x444/0x570`.
Only the anonymous symbol hash in the annotation changes; opcode, register,
numeric `0x10005b000` address and `+0x49` addend remain exact. The checker first
verifies the corresponding symbol rename and the image bytes, then substitutes
these thirteen complete, address-specific annotation spans in memory. It never
strips operands or arbitrary labels. Every other textual difference refuses.

## Source and analysis ownership

Both pinned build receipts enumerate 2,021 source/build identities. After mapping
the two isolated worker directories and the unchanged build-recipe location,
2,014 identities agree. Seven differences remain explicit: root Cargo.lock;
allocation `src/allocation/shared.rs`, `src/shared.rs`,
`src/shared_reservation_tests.rs`, `src/shared_wake_tests.rs`; and the generated
preparation receipt/root-lock copy. The exact current values come from the
pinned build receipt and are checked against live bytes. Any new source change
refuses, including changes to a previously allowed path.

The worker, arena, native setup, fatal slot, budget, framing, Profile and typed
decoder sources used by these lemmas are unchanged. Changed allocation-library
routines remain opaque where reached; this does not transfer a historical
universal ownership proof for them. The separate
[allocation tests and correction](../parliament_ballot_current_candidate/allocation-waker-correction/README.md)
are component evidence. The correspondence checker does not invoke historical
`inputs()` routines or repin their stale live paths; historical reports,
source notes, helper snapshots and complete child manifests retain their exact
identities.

After correspondence, the four unchanged frozen analysis helpers execute again
over the current capture (with only the verified annotation substitution).
They reconstruct the control-flow graphs, check branch/loop predicates and call
targets, and retain their original source, ABI and ordinary-memory-safety
premises. The ordinary contributions per mode are:

| Scoped contribution | Local issued instructions | Owned stack including red zone |
| --- | ---: | ---: |
| Adapter, excluding verifier/native callees | 5,298 | 336 B |
| Reservation coordinator plus record dispatch | 146 | 2,160 B |
| Profile coordinator | 834 | 1,760 B |
| Registration decoder including its framing parser | 621 | 1,824 B |
| Vote decoder including its framing parser | 592 | 1,184 B |

These are substitutions for corresponding symbolic terms, **not a sum forming
a whole-verifier bound**. The typed rows already include parser work; it must
not be added a second time. Call-site stack depths and each unresolved callee
are retained in the report. Source field counts and bounded request sizes are
also recomputed. Malformed inputs can occupy the entire admitted 425,984-byte
slice; successful typed canonical maxima do not bound every parser input.

The original [adapter premises](../parliament_ballot_adapter_bound/README.md),
[frontend scope](../parliament_ballot_frontend_bound/README.md),
[Profile exclusions](../parliament_ballot_profile_bound/README.md) and
[typed-decoder boundaries](../parliament_ballot_typed_decoder_bound/README.md)
remain mandatory. In particular, one request owns the arena/control state,
without asynchronous or reentrant allocation/mutation during ACTIVE. Compiled
uncontended `CASAB` progress and the depth-19 arena-tree bounds remain specific
to these machine bodies. Native calls obey ABI, memory/noninterference and
ordinary-return contracts, with work/stack costs still symbolic. The opaque
verifier must return ordinarily preserving live input/arena state for the
adapter continuation claim; verifier unwind/abort is not covered. Zero-length
`memcpy` retains its original pointer/length contract. Worker TLS/stack-query
setup precedes the admitted interval. No compiler correctness proof is newly
demanded or purportedly supplied.

## Validation and remaining work

The retained [analysis report](analysis/report.json) contains all per-image
results, 24 body identities, annotation substitutions and before/after input
guards. The [capture receipt](capture-receipt.json) binds its actual CLI command
and output. The 49 focused controls are retained as an actual
[tool transcript](tests-tool-transcript.txt); the capture recipe does not rerun
the unchanged test suite.

The negative controls cover instruction/branch/data changes, native imports and
loader binding, symbol addresses and malformed metadata, unreviewed annotations,
function ranges, source inventory/premises, and source drift before/after
analysis. Drift tests alter read results in the test process and never modify
the shared checkout. Successful controls also confirm all four analyses retain
their unresolved terms and the old `BODY_HASHES` remain unchanged.

```sh
.venv/bin/python -m pytest scripts/tests/parliament_ballot_current_correspondence_test.py -q
.venv/bin/python scripts/parliament_ballot_current_correspondence.py --root "$PWD" --output /new/empty/output
```

Lower cryptographic/typed-field validation, hash/copy/allocation/drop/native
costs, exceptional terminals and workspace sufficiency remain open. No physical
timing calibration or independent cryptographic qualification transfers from
this correspondence. The useful next boundary remains the explicitly named
opaque lower callees in the recomputed reports.
