# Retained ARM64 exception metadata and control coverage

This component checks compact-unwind, CIE/FDE and Rust LSDA structures in two
historical standalone worker images, then conservatively follows control from
function entries and every listed landing pad of reached owners. It executes
no worker. Complete exception semantics, native/stack/workspace costs, current
checkout applicability and production qualification remain **false**.

The [captured full component note](capture/sources/03-README.md.template)
describes the exact parsing subset, Rust 1.93.1 first-action rule, byte `PC+3`
lookup, field-relative CIE/FDE addresses, folded compact ranges and unknown
frontiers. Its staged proposal/future-capture wording is preserved as the
reviewed input; the completed results are recorded here and in the
[capture receipt](capture/receipt.json). Initial reference notes are likewise
historical observations; the final helper additionally resolves FDE headers,
without interpreting CFI or authenticating the loaded personality routine.

## Recorded results and remaining gap

The [summary](capture/summary.json) and [182-case JUnit](capture/tests.xml)
record all four staged modules: 46 helper cases, 119 independent cases, 15 graph
controls and two whole-function reference controls. All passed. Collection,
tests, analysis, LLVM comparison and qualification refusal exited
`0, 0, 0, 0, 2`. Seventy-one selected paths, runtime executable identities and
absent pytest configuration paths remained stable across the observations.

Both images have 71 CIEs and 228 LSDA tables. Portable/accelerated modes have
606/598 FDEs. The [independent LLVM comparison](capture/decoder-comparison.json)
binds the exact final report and matches every retained CIE/FDE header record,
including code regions, LSDA and personality slots. Its original command
[receipt](capture/sources/29-receipt.json.template) and exact text outputs are
retained; the capture invokes no fresh LLVM decoder and no worker.

The separate [final-report all-body comparison](all-body-capture/comparison.json)
and its [command receipt](all-body-capture/receipt.json) recompute the independent
whole-function universe from the exact six captured text inputs and bind the
final decompressed report. They check set inclusion, identical native direct-site
sets and the explicit instruction/function difference. This is a new static
comparison, with no worker or historical test rerun.

The augmented graph has 284/288 functions and 32,952/31,253 instructions. The
independent whole-function direct-call universe has 287/291 functions and
32,998/31,299 instructions. The **46 additional instructions per image remain
unresolved**, behind the indirect byte-table branch in
`std::panicking::default_hook`, including three outlined helpers; they are not
proven dead. Indirect/native calls, function fallthrough, trap continuation,
CFI execution and exceptional entry stack/register state remain open. This
coverage result supplies no complete numeric resource bound.

The [normal report gzip](capture/analysis.json.gz) and
[refusal report gzip](capture/refusal.json.gz) retain the same exact 21,715,273
raw bytes, SHA-256
`9460da92323a358a6bdf13cb27ad286bb6ee5799ab88189b1db05bcd3c1dce70`.
Each deterministic gzip is 1,568,707 bytes, SHA-256
`3e4891e20cc4c731677a1ddbd8b4342ab22a524ad40976d2821df8ac2f8938d9`.
Both are retained exactly as captured. The recipe records decompressed hashes;
compression changes no report detail or qualification flag.

## Installed test scope and reproduction

The [installed helper](../../../scripts/parliament_ballot_exception_coverage.py)
is byte-identical to the captured helper. The
[installed synthetic tests](../../../scripts/tests/parliament_ballot_exception_coverage_independent_test.py)
retain 113 cases. Exactly three parametrized functions (six cases requiring
retained images or host Rust reference files) were removed from the original
119-case independent module; no remaining assertion or function changed.
The [extraction record](install-capture/sources/05-install-extraction.json.template),
[exact diff](install-capture/sources/06-install-extraction.diff.template) and
[recipe](install-capture/sources/04-prepare-install-test.py.template) preserve
that custody. The complete original 119-case module remains in the frozen
capture. The 46 helper cases and 17 parent controls also remain there as exact
source templates; they are not installed with unresolved stage dependencies.

The exact derived candidate passed all 113 cases in a separate ignored,
repository-shaped directory, with exact collection/JUnit membership and stable
source/runtime/configuration observations. See its
[receipt](install-capture/receipt.json) and [JUnit](install-capture/tests.xml).
This checks the intended repository-root import layout. Publication itself is
not a test rerun against tracked source. To run the installed synthetic suite
from the repository root with the repository's pytest environment:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_ADDOPTS='' PYTEST_PLUGINS='' PYTHONPATH='' PYTHONOPTIMIZE=0 pytest -c pytest.ini -o addopts= --import-mode=importlib -p no:cacheprovider --maxfail=0 scripts/tests/parliament_ballot_exception_coverage_independent_test.py
```

The full image analysis is **host-bound retained evidence**, not clean-clone
revalidation. It requires the exact original inventory, snapshots, historical
binaries, original source paths and host references. On the capture host, using
a fresh output path:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/parliament_ballot_exception_coverage.py --stage /Users/mtakemiya/dev/iroha/target/parliament-exception-coverage-stage --out /tmp/parliament-exception-recheck.json
```

Add `--require-qualified` to a separate fresh output invocation to require the
unchanged refusal exit 2. Missing or changed selected input bytes refuse with
`UNKNOWN`; do not repin them to the current checkout. The
[original inventory](capture/sources/08-input-inventory.json.template) and
[supplement](capture/sources/09-input-inventory-fde.json.template) bind 21 inputs.
Their existing large binary/disassembly snapshots are not duplicated here.
A new host/image candidate requires a separately reviewed capture.

## Evidence custody

[CAPTURE_SHA256SUMS](CAPTURE_SHA256SUMS) maps every copied capture file using
paths relative to this bundle; the unchanged original 53-entry manifest is
retained as [STAGED_SHA256SUMS](capture/STAGED_SHA256SUMS), including its original
scratch paths. The [installation capture map](INSTALL_CAPTURE_SHA256SUMS)
likewise preserves its original [17-entry manifest](install-capture/STAGED_SHA256SUMS).
The [all-body comparison map](ALL_BODY_CAPTURE_SHA256SUMS) preserves its separate
[seven-entry manifest](all-body-capture/STAGED_SHA256SUMS), comparison/recipe sources
and actual output.
The final [bundle manifest](SHA256SUMS), [publication inventory](publication-inventory.json)
and [publication receipt](publication-receipt.json) authenticate the complete
published membership, exact installed source identities and three documentation
replacements. [Document custody](document-custody.json) binds their preimages to
the unchanged prior GF component manifest and retains both before/after bytes.
No older bundle, aggregate index or historical result is rewritten.

These are selected, non-atomic byte observations. Python/pytest dependencies,
import/cache coherence, unobserved child reads, LLVM instruction decoding and
loaded-runtime/compiler correspondence remain explicit trust boundaries.
Exploratory scratch attempts are kept separately on the capture host; they are
not promoted to passes by this publication. TODO: discharge indirect targets,
CFI/loaded-personality semantics, exceptional provenance/cleanup, native costs
and full resource obligations before claiming qualification.
