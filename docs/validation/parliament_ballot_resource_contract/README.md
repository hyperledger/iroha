# Standalone verification reservation and workspace experiment

2026-10-13: **local implementation and campaign pass; no profile selection,
complete workspace certificate, calibrated cost or production qualification**.
The owner requested research, a proposal and implementation. The
[resource contract](../../../specs/parliament_ballot_resource_contract.md)
records the research and decisions; the
[worker](../../../crates/iroha_parliament_ballot_proof/examples/resource_contract.rs)
implements them without a Core dependency or production record format.

## Results

The [campaign report](campaign/report.json) and [all 120 raw records](campaign/cases.jsonl)
contain 60 complete portable/accelerated pairs with matching input, outcome,
verification stage and debit. The eight existing independent ballot vectors
cover both rows, registration and votes at 3, 500 and 1,000 seats. Each has
valid, late-invalid coefficient, truncation, impossible length, work shortage,
byte shortage and arena-exhaustion cases. Additional cases cover a long path
with no work budget, a FIFO without a writer, an empty record and oversized
input. Late-invalid cases reach proof verification. The campaign observed:

| Outcome | Calls | Debit |
| --- | ---: | --- |
| Accepted | 16 | One unit plus actual record bytes |
| Rejected malformed/invalid proof | 50 | Same full debit |
| Insufficient budget or oversized input | 36 | Zero; zero arena allocations |
| Explicit arena exhaustion | 16 | Full debit retained; dedicated exit 73 |
| FIFO input refused | 2 | Zero; input error, no blocking open |

Each normal worker report accounts for 43,089,920 reserved bytes (41.09375 MiB):
32 MiB heap, 1 MiB buddy metadata, 8 MiB supplied native stack, 64 KiB control
and two 16 KiB guard pages on this Mac. The entire mapping remains reserved
until child exit. Verifier-owned live heap is zero before reporting. Maximum
observed requested heap was 6,565,341 bytes, with 7,211,136 bytes in rounded
arena blocks, on the comparator 1,000-seat vote. These finite observations
are below the arena limit; they are not a worst-case sufficiency proof.

The fixed unit reserves one whole cold-input invocation, including profile,
fresh decoding/list validation, transcript, proof checking and cleanup. It is
not a calibrated CPU/gas unit. Each case starts a dedicated process, but no
cache-flushing, host-isolation or timing-baseline claim is made.

## Tests, review and identity

- Ten Rust tests pass in each feature mode: atomic/nonrefundable reservations,
  exact input length, both roles/rows, buddy alignment/coalescing and 20,000
  fragmented operations, zeroing/reallocation, actual native stack placement,
  error classification and fixed OOM reporting. Strict Clippy passes in both
  modes. Commands and outputs are retained in `test-*.txt`, `clippy-*.txt` and
  [validation-commands.json](validation-commands.json).
- [33 supervisor tests](python-tests.txt) cover independent fixture digests,
  outcome/debit/partition enforcement, feature and late-stage refusal, signals,
  non-object JSON, source/executable mismatches, setup/generation errors,
  timeouts with partial output, interruption, failure durability and incomplete
  pair counting. The codec dependency guard passes.
- Separate-agent engineering review found and resolved pre-admission long-path
  allocation, blocking FIFO acquisition, published-arena lifetime, operational
  error classification, failure publication and false pair-count issues.
  This is not an independent human cryptographic or unsafe-code audit.

The [build receipt](build-receipt.json) binds both executable hashes to a clean
before/after 231-file compiled-source scope, Rust 1.93.1, the native SDK header,
resolved libc 0.2.186 and normal revision metadata. The campaign checks every
one of those hashes against its 260-file inventory, adding fixture bytes,
supervisor/tests and proposal, and rechecks sources, binaries and receipt on
completion. No changes occurred during that campaign. The complete compiled
scope was manually reviewed. A later [supervisor-only correction](supervisor-scope-change/receipt.json)
now also requires exact coverage of the reviewed inventory, rejecting omitted
or extra entries. All 120 retained observations revalidate; 35 supervisor tests
pass. The original driver/tests are archived at their recorded hashes, so all
260 original campaign source entries still reconstruct. No worker measurement
was repeated or repinned. This inventory does not independently discover the
compiler's dependency graph; these are controlled build records, not a hermetic
or cryptographic attestation.

The first build inventory omitted the newly added Norito module; its limited
scope is preserved under `initial-build/`. A fresh guarded build included that
module and produced the binaries used by the campaign. The exact final lock
is [archived](build-Cargo.lock.template). The dev-only libc dependency edge is
recorded under [dependency-change](dependency-change/receipt.json); subsequent
unrelated lock edits remain separate. The [historical reconstruction](dependency-change/reconstruction-receipt.json)
still reproduces all 223 device, 225 malformed and 92 counter source entries
using explicit archived substitutions. No old evidence was repinned.

A subsequent concurrent Norito helper edit changed the live `lib.rs` after
this campaign. Its [separate receipt](post-campaign-source-change/receipt.json)
recovers the exact frozen file from the retained earlier template and patch,
archives both versions and checks an exact reverse roundtrip. With that file
and the two archived supervisor files, all 260 original campaign entries still
reconstruct. The live checkout is a later source candidate.

## Reproduction

Use the exact source/toolchain scope in `build-source.sha256`; later sources
need a fresh build receipt, not edits to these retained reports. Build commands
are in `build-receipt.json`. Preserve each mode's executable before building
the other mode. The campaign requires an explicit successful build receipt:

```sh
python3.11 scripts/check_parliament_ballot_resource_contract.py \
  --portable /tmp/parliament-resource-contract/resource-portable \
  --accel /tmp/parliament-resource-contract/resource-accel \
  --build-receipt docs/validation/parliament_ballot_resource_contract/build-receipt.json \
  --output-dir /tmp/parliament-resource-contract-new-campaign
python3.11 -m pytest scripts/tests/parliament_ballot_resource_contract_test.py -q
python3.11 docs/validation/parliament_ballot_resource_contract/dependency-change/reconstruct_old_evidence.py --help
```

Output must be a new directory. Completed cases are flushed before continuing;
failed setup, worker error, interruption or source drift produces no successful
qualification. Inputs are public test fixtures. Binary files remain local
temporary build artifacts; hashes and full raw observations are retained here.

## Remaining gates

The [native runtime source audit](native-runtime-audit.md) traces the ordinary
verifier, input and cleanup paths against 85 frozen repository sources and 16
installed Rust sources. It finds no ordinary-path direct native allocation,
but identifies concrete System/TLS/panic bypasses and separately allocated
pthread infrastructure outside the application control partition. The inspected
Apple source tags are not authenticated as the installed runtime's sources.
No interposer or native allocation experiment was executed; the audit defines
positive controls and limitations for such a diagnostic.

The [arena/stack feasibility review](sufficiency-feasibility.md) identifies the
next source-level work: explicit live-object counts, allocation/free trace
classes and exact buddy replay, including malformed prefixes and reallocations.
A live-byte sum alone cannot exclude fragmentation; the supplied stack still
needs a compiled frame/call-path bound. Neither issue is reported as a
demonstrated valid-input failure.

TODO: complete coverage and bound verification-caused System/native/TLS allocation;
establish all-valid-input completion and malformed-path bounds; obtain
independent unsafe-code review and Linux/physical-x86 execution evidence. The
mapping is an enforced subset of workspace, not whole-process RSS or a complete
64 MiB certificate. Resource inability must never be interpreted as a
consensus-invalid ballot.

TODO: use qualified worst-case full-service costs to derive block work/byte
budgets, stamps and concurrency/casting capacity. The named Intel run remains
owner-deferred. Named phones, cryptographic premises/reductions and independent
assessment, envelope sequencing/accounting and owner acceptance remain open.

The [actual Core source check](source-contract.json) still fails on block-start
ordering after concurrent SCCP changes. That is separate from this passing
standalone campaign. Source inspection confirms ballot availability remains
`false` and qualified attempt latency remains `None`. No full-workspace pass
or production integration is claimed.
