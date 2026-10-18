# Ordinary return boundaries in the frozen workers

The earlier failure-frontier analysis deliberately retained every ordinary call
continuation. This separate check explains its 57/59 function fallthroughs and
23/26 trap entries without assigning zero cost to failure or exceptional code.
Both frozen ARM64 modes give the same classification:

| Original root | Callee normal-return continuations excluded conditionally | Native unwind continuations still unresolved | Traps outside the cut ordinary-entry CFG |
|---|---:|---:|---:|
| `Reservation::verify` | 50 | 7 | 23 |
| Worker | 52 | 7 | 26 |

**All original unconditional frontier and resource obligations remain open.**
“No normal return” does not prove no unwind, no native work, no hook, no callback,
termination, or a resource bound. The new
[report](analysis/report.json) is separate from the unchanged
[original failure-frontier report](../parliament_ballot_stack_frontiers/report.json).

## Derivation boundary

The [helper](../../../scripts/parliament_ballot_noreturn_frontiers.py) uses exactly
three initial facts: the already pinned `!` declarations for
`core::panicking::panic_fmt`, `core::panicking::panic_nounwind_fmt` and
`alloc::alloc::handle_alloc_error`. Their extracted source signatures and installed
rustdoc hashes are checked again. The source-to-image correspondence remains the
explicit premise of the original evidence; this is not an independently attested
standard-library or compiler proof.

The helper walks the local callee closure of the targeted frontier calls. Of
16 candidate functions per mode, 15 derive no normal return in three rounds:
11 functions in the first round, three in the second, and one in the third.
`workspace::decimal` remains unproved because it can return. A function can use
only seeds and facts established in earlier rounds. Mutually recursive functions
cannot establish each other's result. A closed loop alone is deliberately
insufficient for this checker.

For each candidate, both conditional branch outcomes and all unknown-call normal
continuations are retained. A call to a previously established nonreturn function
ends only its ordinary continuation. A reachable return, unresolved tail,
fallthrough or trap blocks the derivation. The report records every reachable
instruction, each justified call cut, known tail, blocking exit, and ordinary
call whose exceptional or native cost remains unknown. Unknown native symbols
are never seeds.

`workspace::exhausted` is derived in round three without assuming that `_exit`
cannot return. In the portable image, native `_exit` is a `BL` at `0x100003364`.
Its normal continuation remains and leads to the already derived
`slice_index_fail` call at `0x100003374`; the only function-end fallthrough is
another such call at `0x100003388`. The native write loop and `_exit` call retain
unknown duration and resource cost. A mutation that turns `_exit` into an unknown
native tail blocks this derivation.

## What the earlier gaps mean

All 57/59 recorded function fallthroughs occur at literal `BL` instructions at
the captured function end. None is ordinary padding. In each reservation graph,
15 target an original seed, 33 target derived panic/allocation wrappers, two
target the derived `exhausted`, and seven target native `__Unwind_Resume`.
The worker adds two wrapper-target fallthroughs. The first 50/52 cannot continue
by a normal return under the stated premises.

The seven `__Unwind_Resume` sites lie outside the cut ordinary-entry CFG, but
the helper makes **no native no-return assertion** about them. Their continuation
and exceptional-entry obligations remain unresolved. This analysis does not
construct landing-pad or unwind edges from platform exception tables and cannot
exclude execution through such edges.

Every original exceptional terminal is `BRK #1` immediately following a `BL`,
but lexical adjacency is not a sufficient proof. Several traps also have
incoming branches after other failure calls. The helper recomputes whole-owner
reachability after *all* justified cuts. That establishes that all 23/26 traps
are outside the resulting ordinary-entry CFG; it does not establish that arbitrary
exceptional reentry, corrupted control state or resumed traps are impossible.
Each trap and its original cost obligation remain in the report.

These findings explain conservative ordinary-continuation overapproximation in
the earlier analyzer. They do not invalidate the earlier evidence, remove a
failure-entry cost, or establish all-input panic freedom. Each newly cut failure
call is retained as an unknown-cost boundary. No complete stack, native or
64 MiB workspace bound is produced, and production/profile qualification stays
false.

TODO: bound the retained failure/native/exceptional paths and discharge the
source/compiler, memory-safety and control-flow premises before using this
classification in a complete resource certificate.

## Validation and reproduction

All 19 focused tests pass. Independent review read the full helper and reran the
tests and a fresh analysis, with no actionable finding in the stated conditional
ordinary-control scope. Native continuations and all-input unknowns were checked
separately from normal-flow exclusions; the reviewed hashes are in the receipt.

The tests cover unknown native calls followed by return, trap or
fallthrough; unknown native tails; conditional returns; closed loops; mutual
recursion; strict derivation rounds; shared traps with multiple incoming failure
paths; missing CFG nodes; changed seeds and frontier shapes; both frozen images;
and the `exhausted` native-tail mutation. Artifact identity checks bind the
original successful build receipt to its frozen frontier digest, actual binary
bytes to the captured binary identity, and disassembly/stub text to the original
capture hashes. Outputs must be new and prior evidence is never rewritten.

```sh
python3.11 -m pytest -q scripts/tests/parliament_ballot_noreturn_frontiers_test.py
python3.11 scripts/parliament_ballot_noreturn_frontiers.py \
  --output /tmp/parliament-noreturn-frontiers-new
shasum -a 256 -c docs/validation/parliament_ballot_noreturn_frontiers/SHA256SUMS
```

The [validation receipt](validation-receipt.json) and [manifest](SHA256SUMS)
identify the reviewed helper, tests, report and checks. No worker was rebuilt or
executed, and no production code was changed.
