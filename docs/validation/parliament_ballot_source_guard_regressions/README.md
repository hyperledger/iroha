# Complete Parliament source-contract regressions

This bundle retains collection and execution of the complete
`scripts/tests/check_sora_parliament_source_contract_test.py` module. It is Python
structural-checker regression evidence. It does not establish Rust compilation,
runtime behavior, independent cryptographic review, device or validator
qualification, the full B6 resource vector, or production readiness. The
production gate remains unchanged.

The [final full receipt](full.json) and [actual pytest log](full.txt) retain
**1,755 passed, zero failed, zero skipped**, with pytest and capture exit zero.
Pytest reported 973.34 seconds; the capture measured 973.427 seconds. All 411
observed input hashes and both guarded path-existence checks stayed unchanged.
There were no setup/teardown or collection errors. The
[final inventory](final-collection.json) collected the same 1,755
[node IDs](full-nodeids.json) before execution, with six stable input pins.

The [preliminary collection receipt](collection.json) and
[log](collection.txt) retain 1,687 collected items in 0.216 seconds, exit zero,
with six observed input pins stable during collection. This historical inventory
precedes the final Result-aware guard correction and is not a test execution.
Its original checker, tests, and recipe bytes remain retained; the final phases
use the later candidate. The [freeze review](freeze-review.json) distinguishes
this historical drift from the stable final collection and full execution.

The final checker SHA-256 is
`4b160bff09631da0fef6ae61fe94b8e037e281fd2fa358a6b544588df7a5a2ec`,
and the test module SHA-256 is
`e35855cc059afa7be471dc5678338a06b78d0c6560a282085370d391bdb3a3af`.
The final read set excludes `docs/validation/parliament_ballot_b6.md`,
`specs/parliament_ballot_b6_requirement_audit.md`,
`specs/parliament_ballot_implementation_goals.md`, and `status.md`.
Publishing updated status in those files does not alter this capture's observed
input identities.

## Capture boundaries

The [capture recipe](capture.py.template) runs each phase in a fresh Python
process. It requires the editing owner's exact checker and test hashes before
importing them, retains complete node IDs and setup/call/teardown outcomes, and
records the real pytest exit and output. Final collection and execution have no
keyword or marker selection, no fail-fast limit, and no expected-failure
overrides added by the capture. The recipe clears `PYTEST_ADDOPTS` and
`PYTEST_PLUGINS`, disables automatic plugin loading, and rejects an effective
pytest configuration that contradicts those scope claims. Repository pytest
configuration and explicit plugins remain observed inputs.

Before/after hashes cover explicitly pinned checker/configuration files,
repository imports, and observed repository source/data/configuration reads.
Exact first-observed bytes are retained under `sources/<phase>/`. A Python
`open` audit hook and an instrumented `guard.read` observe reads while preserving
the original checker behavior. This is non-atomic evidence: it does not prove
that a file could not change and return to its original bytes between
observations. Python bytecode caches and `.git`, `.venv`, `.pytest_cache`, and
generated bundle outputs are excluded. The installed interpreter, pytest,
standard library, and import/cache coherence are trusted. Child subprocess read
sets are not independently traced; the module's CLI-help subprocess is therefore
outside the in-process read trace.

The earlier collection retains the original capture recipe with SHA-256
`664b44c77d2c7f66cd3ef09014cbc6a5d0ed30cf8bdb8e615b390c03dc2dced7`.
The final recipe is
`36d4bc1b67626a73c42b664903aca84378d74541876ed5719f9190c4af114ec4`.
The intentional delta adds a separate final-collection phase, clears hidden
pytest environment selection/plugins, records and rejects effective
selection/fail-fast/configuration mismatches, passes `--maxfail=0` explicitly,
and makes the trusted bytecode cache premise explicit. The explicit flag avoids
depending on the installed pytest's null representation of its unlimited
default; the strict check still requires numeric zero. The original recipe bytes remain in the preliminary
collection's exact snapshot; its receipt has not been repinned.

## Reproduction and review

The receipts retain the exact commands, interpreter identity, Python and pytest
versions, effective arguments/configuration, elapsed time, output hashes, and
input snapshots. Both capture and [freeze recipe](freeze.py.template) refuse to
overwrite prior outputs. Reproduction requires a separate output directory or
checkout and the corresponding retained checker, tests, and observed inputs;
changing only the command's expected hashes would not reproduce a historical
candidate.

The freeze recipe verifies each phase's captured snapshots and output hashes,
the final inventory/execution node-ID agreement, and actual outcome counters.
It records current-versus-captured drift separately from during-run drift and
rechecks guarded path existence. It preserves failures without repair,
suppression, or conversion into a pass. The [manifest](SHA256SUMS) binds the
receipts, outputs, recipes, README, freeze review, and all exact snapshots.
Root and a peer agent reviewed the capture recipe's read scope and configuration
checks. This local evidence review is not independent cryptographic review or
release acceptance.
