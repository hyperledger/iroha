# Zero-challenge fallback admissibility

The fixed challenge `0^256` belongs to the admissible challenge set for both
actual Parliament rows and both roles. This closes the comparator fallback
check left open in section 2 of the
[frozen bounded-driver proposal](../../../specs/parliament_ballot_b6_hybrid_driver.md).
The proposal and earlier ledger are unchanged.

| Actual row | `tau` | Grinding bits | Vector sizes | Leaves `L` | Marked nodes | Revealed seeds | Actual `T_open` |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| Candidate | 33 | 8 | 17 × 256, 16 × 128 | 6,400 | 76 | 11 | 229 |
| Comparator | 22 | 6 | 8 × 4,096, 14 × 2,048 | 61,440 | 55 | 12 | 225 |

All 32 challenge bytes are zero. Thus every grinding bit is clear, and the
low-bit-first decoder produces one zero index for each vector. With zero
indices, the source position rule selects heap leaves `L-1` through
`L+tau-2`. Mark those leaves and every ancestor. A seed is revealed exactly
where a marked parent has one marked child: the other child's seed is public.
Equivalently, if the marked subtree has `m` nodes and `tau` selected leaves,
the number of boundary children is `2(m-tau)-(m-1) = m-2tau+1`.

The candidate boundary, in decommitment order, is
`[6432, 3216, 1608, 804, 402, 100, 50, 23, 12, 6, 1]`.
The comparator boundary is
`[30730, 7682, 1920, 960, 480, 240, 120, 60, 30, 13, 5, 1]`.
Both counts satisfy their own inclusive opening threshold. The source's tree
tweak and node-buffer arithmetic checks also pass at these actual sizes.

Registration and vote use `Profile::context(role)` with the same
`self.row.vole()` and the extended construction. Their namespaces and relation
dimensions differ; these do not enter the challenge decoder, tree geometry or
opening-size predicate. The all-zero fallback need not occur at any real
counter. No claim is made that it is a hash preimage or an accepted proof.

The [checker](../../../scripts/check_parliament_ballot_zero_challenge.py) pins
eight source/proposal/ledger files and retains exact source references in
[report.json](report.json). It compares the source-style full-heap marking with
an independent ancestor-path frontier calculation. The latter reuses the
ledger's interleaved vector listing; both the reviewed copy and the actually
loaded module are hash checked. Source correspondence is a reviewed
mathematical model, not a machine-checked proof of compiled Rust semantics.

The [13 regression tests](../../../scripts/tests/parliament_ballot_zero_challenge_test.py)
cover both actual thresholds and one-below refusals, every grinding bit,
malformed lengths/indices, source and imported-helper drift, and all 112 valid
patterns across three small tree geometries. The toy geometries test the
combinatorics; they are not backend parameter profiles.

For zero, the source decoder reads 256 bits. `mark_hidden` initializes
`2L-1` Boolean entries, checks and marks `tau` indices, then performs `L-1`
parent iterations with two child reads each. These finite counts are 12,799
initializations and 6,399 parent iterations for candidate, versus 122,879 and
61,439 for comparator. They exclude allocation, cryptographic opening
material, the checker's independent calculation and complete simulator costs.

Reproduce without modifying existing evidence:

```sh
.venv/bin/python -m pytest -q scripts/tests/parliament_ballot_zero_challenge_test.py
python3 scripts/check_parliament_ballot_zero_challenge.py --output /tmp/parliament-zero-challenge-reproduction
```

TODO: the uniform fixed-opening H5 lemma, primitive-game embedding, full
simulator resource bound and independent cryptographic review remain open.
This certificate closes only fixed fallback admissibility. Production
qualification remains false.
