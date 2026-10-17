# Clean field-product circuit kernels

This component supplies explicit reversible circuits for three polynomial
arithmetic APIs already named in the B6 simulator's logical accounting. It
implements a product XOR into a supplied output register, with exact gate and
clean-work counts. It does not compile the simulator, mutate the Rust runtime,
adopt a primitive advantage, or qualify a profile.

The [helper](../../../scripts/parliament_ballot_gf_circuit.py) and
[tests](../../../scripts/tests/parliament_ballot_gf_circuit_test.py) are installed
byte for byte from the reviewed and tested staged sources. The retained capture
records **99 tests passed in 0.71 seconds**, normal CLI exit 0 and qualification
refusal exit 2 with identical reports. Root and a separate local reviewer
checked the construction and source correspondence; these automated local
consistency reviews are not independent external cryptographic review. Tests
were not rerun during installation. TODO: complete the whole-program
scheduling, input-routing and cleanup argument before composing these kernels
into a simulator resource vector.

## Source interface

The complete `crates/iroha_zkp_vole/src/field.rs` is pinned at
`df65fd59ae7970752ec71c18212e3aee09fc8f498068dff29e3ac23da9d5e3a8`.
It is also the field source identity in the frozen ideal-sampler accounting
report. Three additional pins bind that report, its accounting note, and the
existing oracle-log circuit's elementary-gate convention. The helper checks
all four before and after reporting. This is a selected source inventory, not
a complete compiler, dependency or historical-accounting closure.

The source encodes polynomial coefficient `x^i` at bit `i mod 8` of byte
`i/8`; limbs are little endian. `mul_limbs` produces carry-less convolution,
and `reduce_limbs` reduces it modulo the declared monic binary polynomial.
The ordinary `Mul` operation on `Gf256` uses its 256-bit polynomial. Its
`mul_u64` uses the low 64 polynomial coordinates of the scalar, rather than
integer multiplication or a multiplicative field embedding. `mul_tripled`
widening keeps the 256 coefficients in the low positions of `Gf768`, whose
reduction polynomial is different. These distinctions determine the circuits:

| Source operation | First bits `p` | Second bits `q` | Output bits `n` | Modulus |
| --- | ---: | ---: | ---: | --- |
| `Gf256` multiplication | 256 | 256 | 256 | `x^256+x^10+x^5+x^2+1` |
| `Gf256::mul_u64` | 256 | 64 | 256 | `x^256+x^10+x^5+x^2+1` |
| `Gf256::mul_tripled` | 256 | 768 | 768 | `x^768+x^19+x^17+x^4+1` |

The helper checks the pinned macro arguments and `Gf256`/`Gf768`
`LambdaField` association. The correspondence is to this reviewed polynomial
semantics, not an instruction-by-instruction reversible version of the native
Rust implementation or its acceleration/compiler paths. No statement about
the native implementation's allocation, physical stack or timing follows.

## Exact joint map

For fixed public widths and monic polynomial `f` of degree `n`, the interface is

```text
|a[p], b[q], z[n], 0_work[p+q-1]>
  -> |a[p], b[q], z XOR rem_f(a*b), 0_work[p+q-1]>.
```

The two input registers, output and work regions must be pairwise disjoint.
Every wire within each region is distinct. The output may initially have any
value. The input values may be equal or zero: equality of values does not mean
that a wire can be supplied twice. `validate_wires` rejects all such aliasing,
including output/source aliasing, a repeated Toffoli control, incorrectly sized work
regions and malformed wire labels. Zero work remains a semantic preparation
premise; it cannot be certified by inspecting a Python wire index.

All gate locations and iteration limits depend only on the public geometry.
There is no secret lookup, QRAM, measurement, branching on field values or
variable-width many-controlled gate.

The map preserves source computational-basis labels jointly with the output;
it need not preserve the inputs' standalone reduced quantum state. For example,
an output initially zero can become entangled with coherent input labels.
The clean circuit identity holds on every basis state and contains no phases,
so linearity gives the identity on arbitrary superpositions and external
entanglement. It does not introduce coherent proof-request access into the
sampler's existing classical atomic request interface.

## Construction and proof

Let `m=p+q-1`. For every `i=0,...,p-1` and `j=0,...,q-1`, execute

```text
Toffoli(a_i, b_j; work_(i+j)).
```

Each work bit starts zero. After these `pq` gates its value is

```text
work_d = XOR_{i+j=d} (a_i AND b_j),  0 <= d < m.
```

That is exactly the coefficient vector of the polynomial product over GF(2).
All sources remain unchanged. Collisions of different pairs at the same work
target are required XOR additions, not an overlap error; these gates commute
because no work bit is ever a control in the convolution.

The highest possible product degree is `p+q-2`. Thus only `p+q-1`
convolution bits are needed even though the Rust temporary allocates whole
limbs including a leading coefficient known to be zero. This is a different
mathematical circuit representation, not a reduction of the native allocator
or stack charge.

For each public degree `d`, compute the *classical circuit-description
constant* `R_d = x^d mod f`. The helper generates these constants by `R_0=1`
and shifting one coefficient position, XORing `f` if the resulting leading
coefficient is one. The invariant `degree(R_d)<n` means one such reduction
suffices for each description-generation step. This host-side description
generation is not a hidden online operation on the quantum inputs.

For every set bit `k` of `R_d`, execute `CNOT(work_d; z_k)`. The resulting XOR
is `sum_d work_d*R_d = rem_f(a*b)` because polynomial reduction is linear over
GF(2). This leaves the convolution bits unchanged. Multiple CNOTs into one
output bit implement the required XOR and do not interfere with one another.

Finally reverse every convolution gate in reverse order. Their controls are
unchanged and the middle step never targeted them or the convolution work.
Each original contribution cancels, returning all `m` work bits to zero.
This proves the exact map and cleanup without relying on the input values or
an irreducibility assumption. The production moduli are the source field
polynomials; the test helper also permits small monic quotient-ring examples
to test the construction independently of field classification.

The whole gate list is a reversible permutation on arbitrary wire states.
The stated clean-work product semantics applies to the zero-work subspace.
For dirty initial work the same circuit generally XORs additional reduced
work into the output; it must not be advertised as a dirty-ancilla kernel.

## Exact resources

Let `wt` count nonzero coefficients of the public reduced monomial. This exact
emitter has

```text
Toffoli = 2*p*q,
CNOT    = sum_{d=0}^{p+q-2} wt(x^d mod f),
X       = 0,
clean work bits = p+q-1,
supplied input/output bits = p+q+n,
base-oracle calls = 0.
```

The compute and inverse convolution give the two `pq` terms. The middle
linear map runs once. No modulus coefficients are secret controls, and no
oracle is needed to obtain them. Initialized source, output and zero-work
registers are supplied. Their preparation, allocation or physical storage is
not priced by the gate count.

Use the prior exact Toffoli decomposition into five one/two-qubit gates over
`CNOT`, `controlled-V` and `controlled-V-dagger`, with `V^2=X`. For controls
`a,b` and target `t`, the sequence `CV(b,t)`, `CX(a,b)`, `CV†(b,t)`,
`CX(a,b)`, `CV(a,t)` restores `b` and has exponent
`b-(a XOR b)+a=2ab` on `V`. This is an exact Toffoli, not a relative-phase
replacement. Thus this construction's elementary count is `CNOT+5*Toffoli`.
Sequential elementary depth is at most that count; no parallel scheduling,
physical connectivity or fault-tolerance reduction is claimed.

| Kernel | Toffoli | CNOT | Elementary gates | Clean work bits | All interface bits |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gf256_mul` | 131,072 | 1,298 | 656,658 | 511 | 1,279 |
| `gf256_mul_u64` | 32,768 | 508 | 164,348 | 319 | 895 |
| `gf256_mul_tripled` | 393,216 | 1,788 | 1,967,868 | 1,023 | 2,815 |

These are upper bounds for a supplied-register implementation and exact
counts of this emitter, not lower bounds for every multiplier or claims of
practical feasibility. Workspace can be reused by successive calls only when
their disjoint interfaces and zero-work invariant have been established.

## What this closes and what it does not

The frozen resource inventory names full GF(2^256) products, `mul_u64`
products and source limb products for wider leaf arithmetic. This artifact
provides concrete reversible implementations for three mathematical field
APIs. The wide kernel reduces modulo the 768-bit polynomial; it must not be
substituted by three independent 256-bit products or charged a second time
on top of an already expanded carry-less multiplication count.

No lifetime or request total is adopted here. Multiplying scalar operation
counts by these gate counts alone does not establish a full reversible
simulator. A later composition must identify every counted API operation,
place and route its operands/output, account for equal-register source uses,
preserve values that are overwritten by the classical algorithm, and uncompute
or retain the entire computation's intermediate history. In-place operations,
squares, a discarded operand, table addressing and a source expression using
the same register twice are not silently supplied by this disjoint kernel.
Copying a basis label to a separate register and later uncomputing it would
need its own explicit wire/lifetime and gate charge.

Other obligations include AES and concrete public hash circuits, the bounded
trial controller, selected-challenge access, reconstruction/CRT and relation
scheduling, source field generation and serialization, primitive interfaces,
actual-input entry reductions, adversary costs, hybrid multiplicities and final
security comparison. The physical 64 MiB verifier workspace and named-device
measurements are separate. Complete resource, physical, primitive-advantage,
independent-review and profile-qualification flags remain false.

## Validation

Independent tests compare emitted gates against carry-less product
followed by polynomial long division, with asymmetric small widths, all basis
states in small geometries, arbitrary output values, actual production word
boundaries, zero/equal operands and both reduction polynomials. They check exact
counts, preservation, zero cleanup and inverse execution, and detect omitted
uncomputation, wrong modulus/control and dirty-work misuse. The source-style
u64 reduction loop agrees with independent long division on all 1,853 reachable
monomial columns across the three kernels. Malformed geometries, aliasing,
source drift, output replacement and requested qualification refuse. A caller
mutation after the emitter's first gate cannot alter the copied public layout.
Finite tests supplement the all-width proof above.

The CLI refuses existing output files. A failed source check emits `UNKNOWN`
with false qualification flags and exit 1; a conditional successful accounting
returns exit 0, or exit 2 with identical report content for
`--require-qualified`. It performs no Rust build, hardware benchmark or base
oracle query.

## Retained evidence and publication custody

The [capture receipt](capture/receipt.json) binds the actual
[pytest output](capture/tests.stdout.txt), [JUnit results](capture/tests.xml),
[component report](capture/analysis.json), and identical
[qualification refusal](capture/refusal.json). It also retains nine exact
source/configuration/recipe snapshots, including the
[reviewed component note](capture/sources/02-README.md.template) and
[executing capture recipe](capture/sources/08-capture.py.template).
The four selected component pins do not establish a complete compiler,
dependency, historical-accounting or Python runtime closure. Runtime executable
identities and absent conftests were observed before and after; these are
non-atomic observations. Python/pytest dependency behavior, bytecode-cache
coherence and unobserved child reads remain trusted. Pytest temporary files
remain separate ignored scratch, outside this frozen evidence.

The [original staged manifest](capture/STAGED_SHA256SUMS) retains its original
repository-relative paths; use the [copied capture map](CAPTURE_SHA256SUMS) for
paths relative to this bundle. The copied map covers all 22 original capture
entries plus that original manifest, with no symlink duplicates.
[Document custody](document-custody.json) binds the three prior central
document identities through the previously frozen opaque-field manifest and
retains exact before/after bytes. That prior manifest and every earlier
execution artifact remain unchanged; the central prose now links this
component without promoting qualification.

The [publication inventory](publication-inventory.json),
[guarded publication recipe](publish.py.template), and
[publication receipt](publication-receipt.json) bind the exact install and
document transition. The final [manifest](SHA256SUMS) covers this complete
bundle. The captured sources and reports remain evidence of the recorded
staged commands; installation is byte identity, not another test run or a
whole-program composition claim. All complete-resource, physical-workspace,
primitive-advantage, external-review and profile-qualification flags remain
false, and production remains gated.
