# Conditional initial-programming evidence

The [entry derivation](../../../specs/parliament_ballot_b6_initial_programming.md)
supplies explicit joint samplers for challenge 1, challenge 2 and each globally
fixed challenge-3 counter domain. It joins the real fresh-tape mathematical
game to `B_0` under the common atomic-request and independent backend-domain
QROM premises. A subsequent join uses the unchanged
[post-entry composition](../parliament_ballot_conditional_composition/README.md).
This does not establish concrete primitive assumptions, full reduction
resources, independent review or qualification.

The critical scheduling points are explicit: sample the fresh coordinate
inside the target instruction; defer unread current assignments in disjoint
domains; obtain the programmed value with one honest target read; preserve
the first-success/exhaustion result and every primary write. The counter
hybrid is fixed across the complete adaptive lifetime. The direct query
ceiling is `2*Q_all+T`, with no extra role multiplier. Proof padding is after
the final observation and is not a protocol operation.

From the repository root, using Python 3.11+ and its standard library:

```sh
python3.11 -m unittest discover -s scripts/tests -p parliament_ballot_initial_programming_test.py -v
python3.11 scripts/parliament_ballot_initial_programming.py --json
python3.11 scripts/parliament_ballot_initial_programming.py --json --require-qualified
```

All **16 new tests pass**. The final command returns **2** and emits the same
JSON report as the ordinary run. A separate existing framing test passes its
12 row/role/challenge combinations, checking byte lengths, domain suffixes
and little-endian counters in the Python framing model. This is not new Rust
execution evidence. All 45 scoped source/specification/helper inputs remained
unchanged around the capture; the scope is not a complete dependency closure.

At illustrative `T=2^44`, `Q_all=2^64`, the conditional formula components
are approximately:

| Contribution | Display approximation |
| --- | ---: |
| Challenge 1 | `3.140185666045886984313515e-16` |
| Challenge 2 | `1.383946656132175076736745e-295` |
| All challenge-3 counter domains | `6.620891773990184086886097e-97` |
| Clipped entry plus post-entry `K` | `3.142766035804218723165227e-16` |

These are **formula values, not a complete advantage bound**. The report's
exact rational endpoints enclose the contributions; the decimal displays
are approximate. The 400-bit relative dyadic square-root enclosure retains
the tiny challenge-2 component. The lower endpoint is not an advantage lower
bound or an attack. AES advantages and complete driver resources remain
`null`; every report has `qualified=false`.

The [receipt](receipt.json) records commands, source scope and local review
limits. [inputs.json](inputs.json) pins the current inputs,
[report.json](report.json) retains the numerical output, and the manifest
covers the helper, tests, derivation and evidence. The frozen post-entry
helper is imported unchanged; its earlier report correctly retains unknown
entry at that earlier checkpoint. No earlier receipt or ledger is rewritten.

Source review covers actual challenge framing, the supplied-seed algebra
between challenges, and geometric retry failures returning before leaf
recomputation. Existing source tests already address those framing/counter
behaviors; this checkpoint does not rerun their Rust suites or provide an
instrumented failed-retry query trace. The separate
[zero-challenge certificate](../parliament_ballot_zero_challenge/README.md)
supplies the both-row fallback check omitted by the older driver proposal.
Local reviewers checked the three sampler cuts, query convention, collision
handling, post-observation padding, composition and rational arithmetic.
They are not independent cryptographic reviewers.

**TODO:** complete source-to-game/coherent-oracle resource realization,
quantified primitive/model premises, dependent application-security joins,
the complete ledger and independent attack-cost review, plus native resource
and named hardware qualification. Development testing remains enabled;
binding production activation remains gated.
