# B6 explicit reversible chronological oracle log

Status, 2026-10-13: **conditional construction proposal; local consistency
reviews complete**. These automated local reviews are not owner acceptance
or independent cryptographic review.
This gives a circuit for one previously unpriced part of the frozen
[IdealFrontierSim accounting](parliament_ballot_b6_ideal_sampler_accounting.md):
the persistent programming log's coherent lookup and append operations.
It does not change the frozen simulator, arguments, ledger, or qualification.
The implemented helper is
[`parliament_ballot_oracle_log_circuit.py`](../scripts/parliament_ballot_oracle_log_circuit.py),
with [finite circuit tests](../scripts/tests/parliament_ballot_oracle_log_circuit_test.py).
Its production-size output is a symbolic resource vector, not an executed
quantum simulator. A separate
[evidence receipt](../docs/validation/parliament_ballot_oracle_log_circuit/receipt.json)
retains the exact construction, inputs and validation. TODO: complete the
entry bridges and full reduction resources before qualification; this
component does not satisfy those obligations.

## 1. Precisely bounded interface

Let `T` bound valid classical atomic simulator requests and let `Q_ext`
bound all other calls to this combined backend interface. Additional
verification, diagnostic, or final-comparison calls must be included if
they are actually executed; they are not silently covered by this note.
The frozen sampler makes at most 741 ordinary reads per request, and
appends at most `M+2` challenge records, where `M=2^20`. Both rows and roles,
successful and exhausted requests, and all auxiliary/fallback paths are
covered by those source-bound maxima. Auxiliary draws append no record.

Fix the maximum record capacity and query encoding before interaction:

```text
N = T*(M+2),                  R <= Q_ext+741*T,
W = max(K1,K2,K3) = 215150 bytes,
v = 8*264 = 2112 bits,
k = b+8*W.                                                   (C-1)
```

Here `b` is an **explicit finite byte-length register width**, chosen large
enough for every message addressed by the particular finite experiment.
This note does not derive an adversarial message-length restriction from a
query count. The source helper refuses a `b` too small for the frozen honest
read envelope (6,882,996 bytes, a conservative sum of a batch of reads).
Arbitrarily longer adversarial inputs require a larger supplied width.

A query has a length register and a sufficiently large full message
register, with canonical zero padding after its stated length. Its length
and first `W` bytes form the compared `k` bits. The base oracle receives the
**entire** original message, not this truncated comparison head. Each log
key is an actual framed address of length at most `W`, padded to `W` bytes,
with its full `b`-bit length. Therefore matching the head and length is
equivalent to matching the complete original address on the legal query
encoding: a match forces the length to be at most `W`. A longer message
never matches a log record and receives its full-message base answer.
The circuit still extends to a permutation on all bit strings; interpreting
noncanonical register encodings as source messages is outside the interface.

Addresses retain all source namespace, role, row, domain and length bytes.
Values occupy `v` bits, zero-padded after their domain's output length.
The designated backend domains have no larger individual response. On a
match the circuit uses the padded programmed response, including its zero
tail; on a miss it uses the padded base response. It does not XOR together
multiple values or change unprogrammed domains.

The persistent storage is a fixed array of `N` slots. Each contains one
active bit, `k` key bits, and `v` value bits. Initially every slot is zero.
A counter `c` of width `d=max(2,ceil(log2(N+1)))` records the next free slot.
Valid append states have exactly slots `0..c-1` active, all later slots
zero, and `c<N`. These invariants follow by induction from the bounded
sampler's write count. Lookup itself works even with holes in active flags.
Old matching records remain present. This preserves old larger-counter
entries when a later identical prefix writes only fewer counters.

This is deliberately padded storage, larger than the earlier variable-size
logical payload. No quantum RAM or indirect quantum address is assumed.
Every gate's wire indices follow a fixed sequential scan of all `N` slots,
including empty ones. Circuit wiring is independent of every sampled key,
value, selected opening, query, and adversary state.

## 2. Clean equality and newest-match routing

Use exact `X`, `CNOT`, and `Toffoli` gates. A clean AND ladder XORs the AND
of `s>=2` control bits into a target, restores `s-2` scratch bits, and costs
`2s-3` Toffolis. Compute the first `s-2` prefix products, toggle the target,
then reverse those prefix products. This proves the claimed count without
assuming a unit-cost many-controlled gate.

Let `enable` allow a harmless identity query. For each slot `i`, compute

```text
e_i = enable AND active_i AND (query_head == key_i).            (C-2)
```

In place, XOR the query head into the slot key and negate each resulting
key bit. Apply the clean AND ladder to those `k` agreement bits, `enable`,
and `active_i`; its target is a fresh `e_i`. Then undo the negations and
XORs. The query and log key are restored before moving to any base call.
The ladder has `k+2` controls, uses `k` scratch bits, and costs `2k+1`
Toffolis. Computing and later uncomputing every `e_i` costs `4k+2`
Toffolis, `4k` CNOTs, and `4k` X gates per slot. This uses stored key wires,
not free classical hard-coding or recompilation after each request.

Prepare `r_N=1` and fresh zero targets for

```text
r_i = r_(i+1) AND NOT e_i,                 i=N-1,...,0.         (C-3)
```

Each step is two X gates around one Toffoli. Thus `r_i` states that no
slot `j>=i` matches. Reuse one temporary bit to compute
`hit_i=e_i AND r_(i+1)`, XOR every `value_i` bit into the response using a
Toffoli controlled by `hit_i`, and uncompute `hit_i`. At most one hit is
true; it is exactly the largest matching active slot.

Let the supplied base oracle have the standard response-XOR interface

```text
O_F: |X,Z> -> |X,Z XOR F(X)>.
```

Use it once to compute `F(X)` in a fresh `v`-bit register. Compute
`miss=enable AND r_0` in the same hit bit, copy its controlled base response,
uncompute `miss`, and call `O_F` again to clear the base register. These are
**two unconditional base queries**, even when an active record matches or
`enable=0`. No controlled-oracle access assumption is used. The full base
address, retained log, base function and enable bit remain unchanged during
the operation.

Finally reverse (C-3), clear the prepared `r_N`, and reverse every (C-2)
computation. All scratch, flags and temporary key modifications disappear.
Only the response is XORed with the newest value, or the ordinary base
value on a miss. This is exact basis-state equality with no phases. By
linearity it holds on arbitrary superpositions and entanglement with the
adversary, base-function register, log and other retained state.

It is not necessary to assume independent or distinct log keys. It is also
not necessary to measure the query or log. For the actual sampler the log
updates and requests are classical and atomic; previous quantum queries
may be correlated with every stored record. Conditioning on a classical
history and applying the exact identity branch by branch handles this
adaptive state. The circuit itself is a fixed unitary even if log registers
are viewed as a purification. This does not turn honest proof requests
into a new superposition-access API.

## 3. Lookup counts, with no free data access

For `N>=1` one lookup has exactly these gate counts and clean workspace:

```text
Toffoli = N*(4k+6+v) + v+2,
CNOT    = 4kN,
X       = 4kN+4N+2,
base XOR calls = 2,
clean work bits = 2N+k+v+2.                                (C-4)
```

The Toffoli terms are: `N*(4k+2)` for equality and its inverse, `2N` for
the suffix flags and their inverse, `N*(v+2)` for hit/copy/unhit, and `v+2`
for miss/copy/unmiss. The workspace is `e[N]`, `r[N+1]`, one hit, `k`
ladder bits, and `v` base-response bits. Input query/response registers,
persistent log and base-oracle state are additional. Serial depth is at
most the gate count when every listed gate is executed sequentially.

When `N=0`, no records exist: compute the base answer, copy it controlled
by enable, then uncompute. This costs two base calls, `v` Toffolis and `v`
clean work bits. A separate uncontrolled-query optimization is not assumed.

These are gates over wires with unrestricted logical connectivity. To make
the elementary convention concrete, one Toffoli is exactly five two-qubit
gates in the set `{CNOT, controlled-V, controlled-V-dagger}` with

```text
V = (1/2) * [[1+i,1-i],[1-i,1+i]],        V^2 = X.
```

For controls `a,b` and target `t`, execute `CV(b,t)`, `CNOT(a,b)`,
`CV-dagger(b,t)`, `CNOT(a,b)`, `CV(a,t)`. The exponent on `V` is
`b-(a XOR b)+a=2ab`, and `b` is restored. The identity is exact, not a
relative-phase Toffoli. Consequently an explicit one/two-qubit gate bound
is `X+CNOT+5*Toffoli`. The general reversible-gate context and two-qubit
construction are in [Barenco et al., 1995](https://arxiv.org/pdf/quant-ph/9503016v1);
the identity above supplies the complete special case used here. This
convention does not price error correction, physical connectivity, a
Clifford+T compiler, or the base oracle.

## 4. Explicit bounded append circuit

A write supplies a canonical padded `k+v`-bit input record. Its framing and
sampling work belong to the surrounding simulator; they are not free and
are outside this interface construction. The staging record is retained.
For each fixed slot index `i=0,...,N-1`, compute `h=[c=i]` using a clean
AND ladder over `d` counter bits, with X gates for zero bits of constant `i`.
Using `h`, XOR the supplied key/value bits into the corresponding slot
with `k+v` Toffolis, toggle its active flag with a CNOT, then uncompute `h`.
The valid next slot is blank, so its XOR copy gives exactly the requested
new record. All earlier slots remain unchanged, even on address collisions.

Increment `c` with a reversible binary increment: for `j=d-1` down to `1`,
flip bit `j` controlled by all lower bits, then flip bit zero. Decompose
every multi-controlled flip with the same clean ladder. For `d>=2` this
costs `(d-2)^2` Toffolis, one CNOT and one X. No overflow occurs on valid
appends: the counter can represent `N`. No secret allocation, unit-cost
RAM write or arbitrary-address quantum routing is hidden in this scan.

One append has

```text
Toffoli = N*(4d-6+k+v) + (d-2)^2,
CNOT    = N+1,
X       <= 4dN+1,
base calls = 0,
clean work bits = d-1.                                     (C-5)
```

The workspace is one selector plus `d-2` ladder bits, reusable during the
increment. The operation is a permutation on arbitrary registers and has
the stated append semantics on the blank-slot/capacity invariant. Reversing
the emitted gates recovers the entire prior state. The caller supplies no
append beyond capacity; this is justified by `T*(M+2)`, including all
exhaustion writes, rather than by silently dropping an overflow record.

## 5. Persistent wires and lifetime bounds

For positive `N` the explicitly allocated log uses `N*(1+k+v)` wires plus
`d` counter wires. It needs `k+v` incoming-record staging wires and at most
the greater of the lookup/append clean-work counts. The full query and
response, base-oracle representation, adversary, other simulation data,
and code/controller resources are additional. Initialization of all these
zero wires is an explicit preparation inventory, not included among gates
on already initialized wires. This padded circuit-memory count is distinct
from the earlier logical payload and from the physical **64 MiB verifier
workspace** requirement. It establishes no runtime/RSS or hardware bound.

Multiply (C-4) by `R<=Q_ext+741T`, and (C-5) by at most `N` writes.
Two base calls per lookup must replace any single-call convention when this
construction is inserted into a reduction; the frozen ledger is not
automatically updated. These calls are charged separately from elementary
non-oracle gates. Every request uses the same fixed-capacity array. A
smaller scan or different data structure might improve the cost but needs
its own coherent construction and accounting.

For scale only, take the previously discussed `T=2^44`, `Q_ext=2^64`, and
explicitly choose `b=64`. The helper derives

```text
N = 18,446,779,258,081,640,448,
R <= 18,459,779,883,568,463,872,
base calls <= 36,919,559,767,136,927,744,
overlay elementary gates <=
  19,347,974,815,955,654,674,147,436,438,602,340,115,048,038,400,
log2(overlay bound) ~= 153.761,
log2(persistent log wires) ~= 84.717.                         (C-6)
```

This is a conservative **upper bound for this particular construction**,
not a lower bound on all simulators, a feasibility estimate, or a new
deployment cap. It cannot be substituted for a primitive-call subtotal:
the units differ. It does not show that any named primitive remains secure
at this new resource vector. In particular, presenting an explicit bound
does not certify the prior incomplete reduction budget or prove it
unachievable by another construction.

## 6. Executable verification and remaining scope

The helper verifies 65 input identities: the preceding frozen receipt,
report, helper and notes, plus its 61 retained source/endpoint inputs with
overlaps removed. Frozen identity checks happen before parsing metadata;
no prior helper is imported or executed. Rust source membership is checked,
and identities are rechecked after accounting. Key dimensions, write
counts and ordinary-read envelope come from the frozen report. The
264-byte maximum response is the source-bound challenge-1 interface.
Requested bounds reject booleans, floats and out-of-range integers.
`--require-qualified` always exits unsuccessfully. Output creation refuses
to replace an existing path.

The tests emit and interpret actual small gate lists. They check all
three-slot one-bit key/value/active histories and every query, response and
enable bit; input/log preservation; zero scratch; arbitrary old response
XOR; inactive contents; multiple overwrites; older larger counters; length
tag separation; append into every valid next slot; reversed append gates;
and emitted gate counts against (C-4)/(C-5). A missing oracle uncompute is
detected, and the exact five-gate Toffoli identity is checked on all eight
basis states. The toy layout optionally supplies extra full-query tail
wires, counted as external inputs rather than clean work. A long-message
test checks that identical length/head values with different actual tails
both miss a shorter stored address, receive distinct full-message base
answers, and preserve the entire query/log/work state. The all-width proof
is the explicit ladder/scan derivation
above; finite tests alone are not a proof for arbitrary widths or quantum
implementations.

This advances a concrete missing coherent-access and log-update cost for
the **post-deletion ideal public simulator**. It supplies no actual-input
primitive bridge, primitive advantage, full reduction multiplicity or
complete adversary/simulator gate vector. Base random-oracle implementation,
concrete AES/Keccak/relation/sampling/framing circuits, controller work and
physical memory are still outside its bound. It does not adopt a globally
consistent fresh-slot primitive model or repair that entry obligation.
All full-resource, independent-review, physical-workspace and production
qualification flags remain false.
