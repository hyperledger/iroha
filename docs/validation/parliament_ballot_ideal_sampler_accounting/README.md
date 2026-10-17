# IdealFrontierSim logical accounting

The [source-bound model](../../../specs/parliament_ballot_b6_ideal_sampler_accounting.md)
and [checker](../../../scripts/parliament_ballot_ideal_sampler_accounting.py)
account for the explicit post-deletion public simulator. The report separates
ordinary backend reads, programmed challenge writes, primitive and field work,
bounded search, random bytes, partial logical payloads and lifetime costs.

The new persistent-history model stores every challenge address/value record
chronologically, including exhausted requests. It preserves overwritten records
and earlier larger counters when a later same-prefix request writes fewer
counters. Classical lookup inspections and key-byte comparisons are bounded
separately; their quantum implementation costs remain open.

[report.json](report.json) includes 20 conditional run-count contracts across
both rows and roles, plus an envelope for all admissible openings and bounded
schedules. The envelope uses independent componentwise extrema; it does not
describe a single observed execution. Each count contract assumes its earlier
draws failed and its selected draw, if any, succeeded. This checker does not
run a prover, sample a transcript or implement a programmable quantum API.

The [receipt](receipt.json) binds all 61 reviewed source/endpoint inputs and
the executing checker, test and note identities before and after capture.
The [test log](tests.txt) records 30 passing tests, including independent
frontier/stack traversals, all grinding-bit refusals, invalid schedules/types,
source/helper drift, zero-request lifetime and chronological overwrites.
[qualification-refusal.txt](qualification-refusal.txt) records the actual
`--require-qualified` exit code 2. No qualification field is enabled.

Reproduce from the repository root:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_ideal_sampler_accounting/SHA256SUMS
python3.11 -m unittest scripts.tests.parliament_ballot_ideal_sampler_accounting_test -v
python3.11 scripts/parliament_ballot_ideal_sampler_accounting.py --root "$PWD"
```

For a separate logical lifetime vector, pass explicit nonnegative integer
`--requests T --external-queries Q`, each at most `2^64`. The checker never
derives the request cap from the query cap. `--output` requires a new directory
and refuses to overwrite existing evidence. Changed inputs require new review
and new evidence; do not repin or overwrite this bundle automatically.

The named payload sum is partial. Relation values/indices are kept in their
own units; fixed field scratch, metadata, provider/runtime layout, allocator,
base-oracle and adversary memory are excluded. It is neither a complete memory
total nor a process or physical 64 MiB verification-workspace bound. The
simulator's `32*a` primary tape is separate from verifier admission memory.

This is local executable accounting, not independent cryptographic review.
Computational entry, actual-input collision handling, full reduction resources,
primitive advantages, coherent quantum access and elementary-gate costs remain
open. The previous sampler, arguments and ledger are unchanged. Production
stays gated.
