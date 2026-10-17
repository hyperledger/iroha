# Current post-merge source check

This separate capture records the source checker against the current merged
inputs. It preserves the frozen Result and full-regression bundles. The
historical 1,755-test result remains tied to its original input snapshots;
this capture does not rerun or transfer that result to the current candidate.

The [exact two-file delta](source-delta.json) and [retained diff](source-delta.diff)
cover one restore-test constructor, two Torii test-fixture constructors and one
production `proposal_value_from_state` constructor. Each becomes a named-field
literal with the same visible source expressions. The
[independent local agent review](peer-review.json) found no other changes in
these two files. This is source correspondence, with constructor/type resolution
and native semantics remaining premises. It does not cover the complete
43-call constructor migration across 14 files.

The [actual source check](source-check.json) passed over 402 unchanged observed
inputs. After excluding the two distinct capture-recipe paths, 401 input paths
are common to both runs: 399 have identical bytes and the two reviewed files
carry the expected changes. The current freeze also archives the unchanged
test file without executing it.

The capture runs an instrumented in-process source-check probe and a separate
actual CLI, comparing exit code, stdout and stderr. The source read set is
observed through the probe and Python audit hooks; the separate CLI read set
is not independently traced. Before/after and freeze-time input checks detect
source drift. Installed Python and surrounding resolver/compiler/runtime and
serializer behavior remain trusted premises.

`prior-source-check.json` and `prior-result-manifest.sha256` preserve exact
provenance of the Result capture. The two old source snapshots are retained
again under `prior-sources/`; current captured inputs are mapped in
`captured-sources.json`. The parser, checker and test file retain their reviewed
identities. The test file is archived without executing it. `SHA256SUMS` covers
this new bundle and `freeze-receipt.json` records its scope and stability checks.

Production remains gated: binding availability is false, qualified attempt
latency is unset, and Core/Torii have no experimental ballot dependencies.
No Rust tests, native builds, mutation rebuilds, formal-model run, performance
qualification or independent external review is performed by this capture.

Replay the source checker with:

```sh
.venv/bin/python scripts/formal/check_sora_parliament_source_contract.py
```

Capture recipes refuse to overwrite existing outputs.
TODO: Complete remaining current-candidate B6 requirements before production
integration or activation; retain the historical regression scope explicitly.
