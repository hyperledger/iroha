# Current State phase source guard

This is a structural source-checker repair and retained execution evidence.
It does not qualify the Parliament ballot, its resource bounds, Core runtime,
or production integration. The full source-contract check still fails.

The current State constructor added SCCP reconciliation in commit
`5f89bf021f9`, then the G0 draw and returned fast-pause enactment batch in
`1a6270412cbb`. The former guard's exact four-call region therefore rejected
current source. The replacement checks the current required order on the
original `sb` and height: private expiry, SCCP S0, G0 draw, G2a reconciliation,
Parliament enactment, consumption of that same returned pause batch, then G4
lapse cleanup. This matches the relative order in
[`specs/sccp.md` §4.7.2](../../../../specs/sccp.md).

`require_block_start_phase_call_order` uses the existing unconditional-owner
locator after removing only the exact current non-semantic lint attributes.
It pins the complete reviewed wrapper and constructor with literal-preserving
token digests, preventing intact call text inside a disabled owner, outer
conditional, closure or early-success path from satisfying the check.
`require_block_start_enactment_phases` invokes this boundary and then the
unchanged mandatory construction-owner and phase-body checks.

The primary focused receipt is
[`phase-controls-validated.json`](phase-controls-validated.json), with its
[actual pytest output](phase-controls-validated.txt) and
[capture recipe](phase-controls-validated.py.template). Its 74 controls cover
missing/duplicate/conditional/foreign/late calls, typed error propagation,
phase swaps, batch substitution or loss, wrong height, disconnected declaration
owners, whole-body bypasses, literal changes, and comments/spacing. An explicit
sentinel test shows that the separate construction guard is still mandatory
after the call boundary succeeds and cannot be reached through a failed call
boundary. This sentinel does not qualify or suppress the actual construction
check. Prior queue/Kura helpers were unchanged and their separate 192 controls
were not repeated in this phase.

The first [`phase-controls.json`](phase-controls.json) and associated recipe/log
are retained as an earlier observation. Its import inventory added
`scripts/tests/conftest.py` after execution, so the validated recipe explicitly
pins that file and `pytest.ini` before pytest starts. Both observations retain
the actual effective arguments (pytest also inserts its configured import mode).
The validated run has seven unchanged source/config/recipe pins and disables
third-party pytest plugin autoload. The installed interpreter and pytest runtime
remain trusted; their versions and interpreter hash are recorded.

[`phase-source-check.json`](phase-source-check.json) retains the observed
executed read set, before/after hashes, a separate ordinary CLI invocation,
and its [actual failure log](phase-source-check.txt). All 55 observed inputs
remain unchanged. The probe and CLI agree on exit 1 and the exact first error:

```text
crates/iroha_core/src/state/state_block_construction.rs: start construction must consume the original acquisition
```

The probe records repository source/data/config opens and `guard.read` paths,
plus repository imports and the dynamically loaded Rust masker. Bytecode
caches and generated evidence outputs are excluded. The ordinary child CLI's
read set is not independently instrumented; the receipt claims matching
outcome under the observed unchanged inputs, not an independent trace of that
child. These are before/after observations, not an atomic filesystem snapshot.
Later source-contract assertions were not executed after the first failure.

The immediate next mismatch is the constructor's new Clippy `expect` attribute.
Read-only diagnosis also found later conditional acquisition/retirement fields
from `37ffc88687c`; neither construction check was repaired or waived here.
The shared positioned Parliament pass remains unavailable, and the SCCP
binding-ballot gate is false with no qualified latency. The captured Core and
Torii manifests have no experimental ballot/VOLE dependency. Production stays
gated.

`free_predicates` completed an independent local code review. The peer independently
reported 74 passing selected tests and 20 additional in-memory adversarial
refusals. The latter are attributed review observations, not replayable evidence
in this bundle or independent cryptographic review.

[`source-snapshots.json`](source-snapshots.json) maps the exact final checker,
tests, shared masker, pytest config and conftest to retained copies. Earlier
checker/test snapshots remain in [`../source-guard-history/`](../source-guard-history/).
`SHA256SUMS` binds this bundle with repository-relative paths and excludes itself.
The capture recipes refuse existing outputs; use a separate destination for a
future observation instead of replacing these records.

From the repository root, the selected boundary can be checked again with:

```sh
.venv/bin/python -m pytest -q scripts/tests/check_sora_parliament_source_contract_test.py -k 'block_start_phase_call_order or block_start_phase_calls_reject_disconnected_or_late_owners or block_start_admission_and_stage_refusals_remain_typed'
.venv/bin/python scripts/formal/check_sora_parliament_source_contract.py
shasum -a 256 -c docs/validation/parliament_ballot_current_candidate/source-guard-controls/SHA256SUMS
```

TODO: review the remaining construction-owner mismatch separately, then rerun
the full current-candidate source contract. Do not infer qualification from
these passing boundary controls.
