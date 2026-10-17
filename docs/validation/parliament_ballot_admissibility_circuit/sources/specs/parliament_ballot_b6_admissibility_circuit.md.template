# B6 clean challenge-admissibility circuit

Status: **conditional component construction; not qualified**. The
[ideal public sampler](parliament_ballot_b6_ideal_public_sampler.md) uses up to
`2M` challenge trials per request, where `M=2^20`. Earlier accounting bounded
classical loop visits but left the challenge predicate's reversible gates and
workspace unpriced. This component implements that predicate on supplied
challenge wires. The [helper](../scripts/parliament_ballot_admissibility_circuit.py)
emits actual `X`, `CNOT` and `Toffoli` gates, and its
[tests](../scripts/tests/parliament_ballot_admissibility_circuit_test.py) interpret
those gates. This is an analytical circuit, not a replacement Rust verifier or
a quantum API in the runtime.

The [component evidence](../docs/validation/parliament_ballot_admissibility_circuit/README.md)
retains its source scope and validation. Prior frozen arguments, ledgers,
measurements and aggregate receipts remain unchanged. TODO: complete the
surrounding simulator, actual-input entry reductions, primitive bounds and
independent assessment before qualification.

## Interface and correspondence

For a fixed row and a 256-bit supplied challenge `y`, define

```text
P(y) = [all high grinding bits are zero]
       AND [the selected pattern reveals at most T_open node keys].
```

The circuit implements

```text
|y,z,0_work> -> |y,z XOR P(y),0_work>.
```

The output bit may start as either value. Every challenge wire is restored,
and all work is uncomputed. Both roles use the same predicate for a given row.
Fixed-width input and fixed public row selection are interface premises;
malformed byte lengths and external request/public-statement validation are
outside this operation.

Correspondence is to the exact reviewed `decode_challenge`, `Shape::position`,
and `mark_hidden`/`opening_nodes` algorithms in
[`bavc.rs`](../crates/iroha_zkp_vole/src/bavc.rs), the row definitions and derived
geometry in [`params.rs`](../crates/iroha_zkp_vole/src/params.rs), the extended
counter bound in [`variant.rs`](../crates/iroha_zkp_vole/src/variant.rs), and the
candidate/comparator selection in
[`profile.rs`](../crates/iroha_parliament_ballot_proof/src/profile.rs). Those four
complete files and the sampler note are pinned. This selected source inventory
supports the reviewed correspondence argument; it is not a compiler or
dependency-closure certificate.

| Row | Consecutive hidden-index widths | Grinding bits | Leaves `L` | `C=T_open` |
| --- | --- | ---: | ---: | ---: |
| Candidate | 17 of 8 bits, then 16 of 7 bits | 8 | 6,400 | 229 |
| Comparator | 8 of 12 bits, then 14 of 11 bits | 6 | 61,440 | 225 |

Index slices consume the low `256-g` challenge bits, low bit first, exactly as
the source decoder. Each slice already lies in its power-of-two vector range.
No extra range check is needed within this fixed-width interface. The top `g`
bits are the grinding bits.

## Fixed-address construction

Let `d=ceil(log2 L)`. Allocate `2L-1` zero mark bits, a `d`-bit zero frontier
counter, one zero flag, and `d+g-2` reusable zero ladder bits. The challenge and
output wires are separate. All wire addresses and loop bounds depend only on
the public geometry, never on challenge values. There is no QRAM, measurement,
early rejection, or unit-cost many-controlled gate.

For each vector and every possible index in it, XOR an equality test between
its challenge slice and that constant index into the corresponding leaf mark.
Equality uses X gates on zero positions around a clean AND ladder. For `s>=2`
controls the ladder uses `2s-3` Toffolis and restores `s-2` scratch bits.

The leaf addresses use the source interleaving. If `h=2^(k-1)`, its first
`tau*h` leaves are `L-1+tau*j+i` for `0<=j<h`, `0<=i<tau`. Its remaining
`tau1*h` leaves are `L-1+tau*h+tau1*(j-h)+i` for `h<=j<2h`, `0<=i<tau1`.
These disjoint ranges cover every leaf exactly once. Thus each vector marks
exactly its one selected leaf without an indirect write or overlapping target.

Visit parents from `L-2` down to zero. For child marks `a,b`, compute the parent
mark `a OR b` into its fresh zero bit with two CNOTs and one Toffoli:
`a XOR b XOR ab`. Compute `a XOR b` into the reusable flag, increment the
frontier counter controlled by that flag, then clear the flag. Descendant marks
are already available in this order, so this is exactly the source recurrence.

A controlled increment visits counter bits high to low, toggling bit `j` on
`flag AND all lower counter bits`, then toggles bit zero on `flag`. With the
same clean ladder, it costs `(d-1)^2` Toffolis and one CNOT. It is a modular
permutation on arbitrary inputs; here every partial sum counts a subset of the
`L-1` parent XORs and is at most `L-1`, so no valid computation overflows.
The transcript's 32-bit trial counter and the programming log's append counter
are different registers, neither generated nor charged by this operation.

For each constant `j=0,...,C`, XOR into the output the conjunction that the
frontier counter equals `j` and all grinding bits are zero. Negate the relevant
zero-control positions before each AND ladder and restore them afterward.
These count equalities are mutually exclusive, so their XOR is the required
`count<=C` predicate. The helper requires `0<=C<=L-1`; it cannot silently truncate
out-of-range constants into repeated encodings.

Finally reverse the entire mark/count computation, including both gate order
within each block and block order. Its inputs have not changed and the output
was never used as a work control. All marks, count, flag and ladder wires
therefore return to zero. This gives exact basis-state equality without phase
changes. Linearity extends it to arbitrary superpositions and entanglement of
the challenge and output with retained state. The sampler still has classical
atomic requests; this circuit does not introduce coherent proof-request access.

## Exact component resources

Write `n_i=2^depth_i`, `B=sum_i n_i*depth_i`, and `s=d+g`. For this emitter,
including full uncomputation, the exact gate counts are

```text
Toffoli = 2*sum_i n_i*(2*depth_i-3)
         +2*(L-1)*(1+(d-1)^2) +(C+1)*(2*s-3),
CNOT    = 14*(L-1),
X       = 2*B + 2*sum_{j=0}^C(s-popcount(j)).
```

The first term computes and uncomputes leaf marks. Each forward parent block
uses seven CNOTs: two for OR, four for flag preparation/cleanup, and one for
the controlled increment. Its Toffolis are one for OR and `(d-1)^2` for that
increment. The middle threshold test runs once. The smaller test geometries
require every index depth at least two, so these formulas never misprice a
single-control gate as a negative Toffoli count.

Use the same exact `X+CNOT+5*Toffoli` elementary one/two-qubit convention as the
[existing log circuit](parliament_ballot_b6_oracle_log_circuit.md#3-lookup-counts-with-no-free-data-access).
This excludes physical connectivity, fault tolerance and primitive-oracle
implementations. The predicate makes **zero oracle calls**.

| Row | X | CNOT | Toffoli | Elementary gates | Clean work bits |
| --- | ---: | ---: | ---: | ---: | ---: |
| Candidate | 106,218 | 89,586 | 2,022,888 | 10,310,244 | 12,832 |
| Comparator | 1,425,450 | 860,146 | 30,245,486 | 153,513,026 | 122,916 |

Clean work is exactly `(2L-1)+d+1+(d+g-2) = 2L+2d+g-2` bits. The 256 challenge
wires and one output wire are additional inputs/outputs. Scratch is reused
between trials, not multiplied by their count. Its zero initialization is an
explicit preparation premise, not included in gates on already initialized
wires. This inventory is unrelated to the physical 64 MiB verifier limit.

For a schedule with `a` primary and `b` auxiliary trials, this predicate component
costs `(a+b)*G_row`. Both use the same predicate; auxiliary trials still append
no programming record. Since `a+b<=2M`, its conservative per-request upper bound
is `2M*G_row`. At `T` sequential requests its upper bound is `2M*T*G_row`.
For the comparator this is 321,940,149,501,952 elementary gates per request, or
5,663,631,005,205,440,627,350,700,032 at `T=2^44`. The zero-challenge fallback
requires no additional search trial in the specified sampler.

These are upper bounds for this explicit construction, not lower bounds for
all possible implementations, feasibility claims, or cryptographic advantages.
They may be included once in a future complete simulator accounting. They do
not replace the reconstruction's own separate pattern passes, or alter any
frozen ledger or oracle-log subtotal.

## Validation and remaining work

Tests use an independent ancestor-union/frontier reference, an explicit gate
interpreter, exhaustive small geometries, actual-row cases, count comparison,
and cleanup/inversion controls. The all-width reasoning is the construction
above; finite tests supplement it. The executable checks source identities
before and after accounting, refuses existing output files, and always rejects
`--require-qualified`.

TODO: price challenge-randomness preparation and its retained tape, first-success
selection, trial controller and counter, access to the selected challenge,
remaining public reconstruction/relation operations, primitive circuits,
complete reductions and final comparisons. Establish the actual-input bridges
and justified primitive advantages, then obtain independent review and the
required hardware/resource qualification. All full-resource, physical-workspace
and profile-qualification flags remain false; production stays gated.
