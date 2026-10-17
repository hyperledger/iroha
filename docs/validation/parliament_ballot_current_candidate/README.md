# Current standalone Parliament worker evidence

The current-source standalone worker passes **122 observations (61 matched
portable/accelerated pairs)** and **four full/broken-output controls**. Both
release modes pass 17 worker tests, strict Clippy and builds. This is local
diagnostic evidence on this ARM64 Mac. **No profile is qualified; production
remains gated.** Intel qualification remains an explicit owner TODO.

The [reconciliation summary](summary.json) checks the fresh receipts and records
the earlier build's two changed inputs and the historical adapter's five
changed live paths. Exact older bytes are retained separately. Its
[recipe](capture_summary.py.template) never repins or transfers those results.

## Candidate and retained attempts

The final [build receipt](build-v2/build-receipt.json) binds 2,021 inputs, the
isolated resolved dependency metadata, six successful Cargo commands and the
two binaries. No bound input changed during the build. Package identity
membership against the root lock was checked; that check is not a claim of
whole-workspace feature or dependency-graph equivalence. Root manifests and
locks were read only throughout this work.

| Mode | Binary SHA-256 |
| --- | --- |
| Portable | `3f658228a903c50c9a549baedd0b822e14fca03f654659720cb434b83d9bb9dc` |
| Accelerated | `40219e559636f092c3b4197f6e65eb1ab083f25444fcafd2b635221b4f7e18e7` |

The unchanged preparer creates a separate worker crate. Its source, lock and
metadata are retained in [build-v2](build-v2/). The build recipe is
[build_worker.py.template](build-v2/build_worker.py.template). It waits up to
1,200 seconds per Cargo command and retains a timed-out child's PID without
killing it. Its input inventory covers package Rust sources, manifests, build
scripts and available checksum manifests, plus original/derived worker and
fixture inputs. It is not a hermetic compiler, system-header or native-runtime
attestation.

[preparation-v1](preparation-v1/) retains the first preparation. A concurrent
root-lock change added an `iroha_service_model` edge to `irohad_lib`, outside
the standalone closure; a fresh preparation was used instead of changing that
capture. The earlier successful [build](build/build-receipt.json) is also
retained. The subsequent waker test/comment correction changed two of its
guarded source files. The final build used a new source directory, receipt and
binary paths. Its binary hashes equal the earlier current-candidate build;
neither receipt is overwritten or silently repinned.

## Allocation assertion correction

The first [allocation run](allocation-tests/README.md) retained a release-test
failure at `Waker::will_wake`, which permits false negatives. The
[scoped correction](allocation-waker-correction/README.md) replaces two overly
strong test assertions with original data-pointer identity and clarifies one
private comment. Runtime logic is unchanged. Every existing actual callback,
allocation, custody, wake/drop and refund assertion remains. All **28 shared
unit tests and nine custody integration tests pass** afterward. Ten earlier
doctests passed; the comment change contains no doctest. The original bytes,
patch, failed run and passing runs remain separate evidence.

## Fresh worker observations

The [campaign](campaign/report.json) binds 2,034 inputs and records 16 accepts,
50 codec/proof rejections, 38 admission refusals, 16 resource exhaustions and
two staging errors. Every portable/accelerated pair agrees on input identity,
outcome, stage and exact debit. The fixture and malformed-input corpus includes
a genuinely borrowed 425,985-byte over-cap input. All 102 returning worker cases
release the arena; the separate file-size refusal occurs during input staging.
These finite observations are not an all-input proof.

The [output controls](fatal-output/report.json) bind 2,035 inputs. Each mode
exits through the counted fatal-control page with stdout already full or its
receiver closed. A full pipe receives no additional child bytes. Fatal debit
publication remains outside the worker's output formatting path.

The worker reserves **43,106,304 bytes (41.109375 MiB)** of explicit mappings
on this Mac, including arena, allocator metadata, stack, control, fatal page
and guards. That counted mapping is not whole-process RSS or a complete
64 MiB workspace certificate. Native/TLS/runtime and all-input stack/work
obligations remain open.

Reproduction after a fresh successful build, with new output directories:

```sh
.venv/bin/python scripts/check_parliament_ballot_memory_entry.py --portable <portable> --accel <accel> --build-receipt <receipt> --output <new-campaign>
.venv/bin/python scripts/check_parliament_ballot_fatal_output.py --root "$PWD" --build-receipt <receipt> --output <new-output-controls>
.venv/bin/python docs/validation/parliament_ballot_current_candidate/capture_stack.py.template --root "$PWD" --build-receipt <receipt> --output <new-stack-capture>
```

## Fresh compiled diagnostics and source guard

The [stack receipt](stack/receipt.json) binds 2,038 inputs and fresh disassembly
of both final binaries. The unchanged reviewed analyzer passes **62 regression
tests** and reports zero whole-image frame errors. Portable/accelerated images
contain 896/894 functions and 93,768/91,554 text instructions. The worker's
resolved stack regions remain 15,984/13,440 bytes. Native edges (144/138),
38 indirect calls, four indirect branches, 82 function fallthroughs,
39 exceptional terminals and recursion still prevent a complete bound.
The historical adapter/profile/decoder lemmas are not automatically transferred
to these new binaries. New compiled correspondence and remaining opaque
callee costs need explicit analysis.

The [source-guard controls](source-guard-controls/README.md) bind the current
same-block order: settlement expiry, SCCP begin, draw, reconciliation,
Parliament enactment, the same returned pause batch's enactment, then lapse.
The checker keeps its independent construction and implementation checks.
At this capture the full source check refuses at
`state/state_block_construction.rs: start construction must consume the original acquisition`.
No Core runtime code or production availability gate was changed.

Complete verifier work/workspace bounds, actual-input cryptographic bridges,
full reduction resources, independent crypto/unsafe review and named physical
baseline measurements remain required. Supplementary phone results do not
replace the Pixel 6a or iPhone SE (third generation) baseline. The current
[B6 requirement audit](../../../specs/parliament_ballot_b6_requirement_audit.md)
owns those open conditions.
