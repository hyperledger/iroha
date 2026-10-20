# Conditional post-entry composition evidence

The [composition note](../../../specs/parliament_ballot_b6_conditional_composition.md)
joins `B_0` to the distinct `IdealFrontierSim` endpoint under the stated
fresh-tape, atomic-request, QROM and proposed primitive-game premises. This
record authenticates source-informed local review and arithmetic, not a
compiled prover, independent review or qualification.

Run from the repository root with Python 3.11+ and no external dependencies:

```sh
python3.11 -m unittest discover -s scripts/tests -p parliament_ballot_conditional_composition_test.py -v
python3.11 scripts/parliament_ballot_conditional_composition.py --json
python3.11 scripts/parliament_ballot_conditional_composition.py --json --require-qualified
```

The last command must exit **2**. Default inputs are `T=2^44` valid invocations
(including exhaustion, jointly across roles/rows) and `Q_all=2^64` non-prover
combined backend evaluations over the whole lifetime. Verification and
permitted public diagnostics count toward `Q_all`. Other private interfaces
are not introduced by this accounting.

At those illustrative inputs, the known contribution formula is approximately
`2.580369758331738851711784e-19` (`log2 ≈ -61.7490559890373203`). The
report supplies exact rational enclosing endpoints; the decimal is only a
display approximation. Its lower endpoint is not an adversary-advantage lower
bound or evidence of an attack. Neither the clipped nor unclipped known sum
includes initial programming or AES advantages. Both remain `null`, as do
complete driver resources. Every report has `qualified=false`.

The calculation uses one material-switching contribution, one fixed-gate H5
refresh contribution, one own-label contribution and one deletion comparison
with one salt-collision term. Exact coordinate/projection identities add no
loss. It neither doubles deletion nor imports the frozen ledger's different
PRP/exhaustion terms. No older ledger or receipt is revised.

All **15 tests pass**. A separate captured CLI run returns the expected exit
2 for `--require-qualified`, with the same JSON report as the ordinary run.
All 31 scoped inputs remained unchanged around this arithmetic capture.

The [receipt](receipt.json) records test commands/outcomes, source scope and
local review limits. [inputs.json](inputs.json) pins the sources and argument
notes used here; [report.json](report.json) retains the arithmetic output.
The manifest covers these artifacts and the helper/tests. Matching selected
source excerpts does not reauthenticate older whole-file receipts: in
particular their `profile.rs` pins differ from the current source, and the
old H5 receipt also pins an earlier generator-interface note. The retained
[source-literal check](profile-source-check.json) reproduces both descriptor
identifiers and four role/row prefixes using the recorded CRT digest inputs;
it does not regenerate those table digests or execute Rust. Existing
derivations and prior test records retain their original scope.

**TODO:** finish the real-prover initial-programming adapters and query
accounting, full primitive-driver resource vectors and numerical assumptions,
dependent security-reduction reconciliation, independent review and named
hardware qualification. No Rust build or full-workspace suite is claimed by
this arithmetic checkpoint. Development testing remains enabled; binding
production activation remains gated.
