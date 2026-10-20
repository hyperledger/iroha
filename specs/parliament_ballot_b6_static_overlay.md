# B6 static programming slots and the root oracle environment

Status: **implemented reversible component, conditional whole-driver use**.
The [root-entry reduction](parliament_ballot_b6_root_entry.md) needs a
persistent oracle environment throughout the entire adversary interaction.
This note removes an avoidable lifetime-sized scan from each programming
write and identifies that reduction's ordinary-read surface. It does not
construct independent random oracles, price the complete root driver or
establish a numerical AES advantage. Development testing remains enabled;
binding production activation remains gated.

The new [helper](../scripts/parliament_ballot_static_overlay.py) and
[tests](../scripts/tests/parliament_ballot_static_overlay_test.py) implement
the component. The [validation record](../docs/validation/parliament_ballot_static_overlay/README.md)
retains its scope and results. Earlier circuits, observations and manifests
remain unchanged; this is a different private storage layout, not a revised
claim about the cost of those frozen circuits.

## 1. Root-driver oracle surface

Work at `B_0` and the adjacent material hybrids, after the conditional
[initial programming](parliament_ballot_b6_initial_programming.md) step.
The driver has prescribed challenge 1/2 values and a bounded primary
challenge-3 schedule. All its ordinary backend evaluations remain real,
with actual IVs, namespaces and complete messages. The private root challenge
oracle still receives at most five classical block requests. Its ordinary
public AES calls, other material and quantum continuation are separate work.

The source [hash layer](../crates/iroha_zkp_vole/src/hash.rs) and
[transcript](../crates/iroha_zkp_vole/src/transcript.rs) give this surface for
the extended 256-bit rows:

| Domain suffix | Root/material driver use | Native response bits |
| --- | --- | ---: |
| `00` | Actual-IV leaf-hash key | 1,024 |
| `01` | Inner and outer commitment digests | 512 |
| `04` | `H4(iv_pre || mu)` | 128 |
| `05` | Both salted gate labels | 10 |
| `08` | Complete public statement digest | 512 |
| `09` | Prescribed challenge 1, persistent overwrite | 2,112 |
| `0a` | Prescribed challenge 2, persistent overwrite | 832 |
| `0b` | Each attempted primary challenge 3, persistent overwrite | 256 |

`H3` signing randomness is not used by these fresh-tape ballot provers.
Whether an enclosing environment permits it or other addresses, and the
total completion on unused/invalid encodings, must still be explicit in that
environment. Concrete credential SHAKE, public-frame SHA3 and public AES are
not replaced by backend-oracle programming.

For one valid request in these mathematical hybrids, ordinary reads are

```text
H_mu: 1; H4: 1; H0: 1; H1: tau+1; H5: 2*g
total = 2*g + tau + 4 = 1445 candidate, 1418 comparator.          (S-1)
```

[BAVC commitment](../crates/iroha_zkp_vole/src/bavc.rs) derives and stores
the H0 key once and performs the two H1 levels. `Commitment::open` reuses
that committer and adds no backend-oracle query; oversized patterns reject
before leaf recomputation. [VOLE commitment](../crates/iroha_zkp_vole/src/vole.rs)
hashes both gate labels. The prescribed challenge values replace the three
families' ordinary reads in `B_0`; retries and auxiliary selection add no
ordinary backend read. Repeated selected material is cached as required by
the material-entry argument. This count is not the ordinary Rust prover's
query count with unprogrammed challenges, nor the endpoint sampler's smaller
one-label-per-gate count.

Thus `R <= Q_all + 1445*T` bounds **semantic** ordinary backend evaluations
in one such lifetime driver, if `Q_all` includes every additional validation,
public verification, diagnostic, preprocessing and final-continuation call.
This does not derive `Q_all` from an adversary-only budget. Source setup or
extra passes outside this boundary must be included separately. Nor is `R`
a count of base-oracle calls in a reversible realization: dispatch and
compute/uncompute can add calls. Each realization must account for those
explicitly. The existing endpoint reconstruction counts do not price this
earlier real/mixed driver.

## 2. Reserve slots by request and primary counter

Fix the valid-request cap `T` and primary cap `M=2^20` before interaction.
Let `j` be the zero-based ordinal of a valid invocation, never reused.
Reserve `N=T*(M+2)` slots, in this fixed order:

```text
slot(j, challenge1) = j*(M+2)
slot(j, challenge2) = j*(M+2)+1
slot(j, counter c)  = j*(M+2)+2+c,  0 <= c < M.                (S-2)
```

Each slot contains `active || key[k] || value[v]`. As in the prior overlay,
`k=b+8*W`, `W=215150` bytes, and `v=2112` bits. The key includes its complete
byte length and all namespace/message/domain bytes, with zero padding.
Values are zero after their native response width. Public metadata supplies
the fixed wire offsets; no quantum pointer or QRAM is assumed.

On an admitted valid request, challenge 1/2 slots are enabled. Primary slots
use the schedule's attempted prefix flags, including the successful attempt.
Exhaustion enables all `M`
primary slots; the auxiliary schedule enables none. Unattempted primary
slots remain zero, so the log may have holes. Invalid outer requests write
nothing and do not consume a valid-invocation ordinal. Implementing that
outer controller and proving its source correspondence remain obligations;
the component receives the correct ordinal and schedule as inputs.
Specifically, it receives a `valid` control: `e=valid` for challenge 1/2 and
`e=valid AND primary_flag[c]` for a primary slot. With `valid=0`, it still
executes and charges all framing/write circuits but changes no log slot.
It does not authenticate validity or select/advance `j`.
Here `j` is classical controller metadata, not a coherent address supplied
to the write circuit. A coherent content arena that reserves a segment for
every outer call instead needs `(T+I)*(M+2)` slots when `I` invalid calls are
allowed, unless it separately implements and prices valid-ordinal selection.
Its earlier `T+I` resource envelope cannot be replaced by `T` for free.

The older compact log routes a record to a variable next-free position by
scanning `N` slots. Static reservation needs no such routing and no append
counter. It retains the same maximum number of slots; this is not a memory
reduction. Current arenas/callers that expect the older counter/layout need
an explicit integration change before they can use this component.

## 3. Exact conditional write and history equivalence

For a fixed fresh slot, retain the supplied record `r` and enable bit `e`.
Emit one CNOT to its active bit and one Toffoli per key/value bit:

```text
active ^= e
slot_bit[t] ^= e AND r[t],       0 <= t < k+v.                   (S-3)
```

These gates commute, preserve every control, need no clean scratch, and
are their own inverse. On an initially zero slot they produce the requested
active record when enabled and leave zero when disabled. The same circuit
is a well-defined reversible XOR map on arbitrary initial targets, but it
is an append only under the fresh-zero-slot premise. Reusing a slot does
not implement an overwrite and is outside the schedule invariant.

Framing prepares a shared zero staging register with the existing exact
namespace/field/domain order, applies (S-3), and unprepares staging. Supplied
transcript fields, primary values and enable flags remain available. Every
disabled slot still incurs its gates. No field generation, validity test,
randomness preparation, oracle evaluation or hidden memory access is treated
as part of this inexpensive write.

For any request prefix, delete inactive static slots and read active slots
in increasing index order. Induction on (S-2) shows that this is precisely
the old chronological sequence: challenge 1, challenge 2, ascending attempted
counters, then the next request. The sequences are equal even when complete
keys repeat. Therefore their last active matching value agrees for every
query. A later short primary prefix does not remove an older larger-counter
entry. Exhaustion retains all its programmed values despite returning no
proof.

The [existing lookup](parliament_ballot_b6_oracle_log_circuit.md) already
supports holes and selects the largest active matching slot. Its clean XOR
map therefore supplies the same functional oracle using either history
representation. Basis-state equality of its response and restored work,
with no phases, extends by linearity to superpositions and arbitrary
entanglement. For adaptive classical requests, apply this equality at each
atomic boundary with the same incoming state and coins. It preserves the
public response and subsequent oracle/adversary interaction without
measuring private adversary registers or assuming independent stored keys.
The implementation retains the original history, coin and control registers.
The component is coherent within either layout; the lifetime comparison here
uses the specified classical request history. No arbitrary compact-to-sparse
conversion is asserted to be a free unitary.

This is equality after projecting private storage representations. The
compact array/counter and sparse array are not identical registers, and an
unrestricted API exposing their layout, timing or memory contents would
invalidate that observation boundary. The source challenge counter remains
in the proof; only the private append-position counter is removed. This
note does not reorder writes across domains to match another hybrid's
physical append history.

## 4. Resource improvement and remaining lookup cost

Each fixed-slot write has exact costs

```text
CNOT = 1; Toffoli = k+v; X = 0; oracle calls = 0;
extra clean work = 0;
elementary one/two-qubit gates = 1+5*(k+v).                      (S-4)
```

The convention is the same exact five-gate Toffoli decomposition used by
the older circuit. Framing, source controls, retained registers and the
shared staging register are additional and charged by the supplied-field
composition. Over all `N` reserved slots, the raw-write subtotal is
`N*(1+5*(k+v))`, including disabled attempts, instead of scanning `N` slots
for every write. Metadata can describe this circuit without allocating
the enormous lifetime register or executing the full gate stream.

Coherent lookup is unchanged. For `N>=1`, the older fixed-scan lookup costs

```text
Toffoli = N*(4*k+6+v)+v+2;
CNOT = 4*k*N;
X = 4*k*N+4*N+2;
base response-XOR calls = 2;
clean work bits = 2*N+k+v+2.                                    (S-5)
```

It uses the full original message for the base oracle, not merely the
compared `W`-byte prefix. Canonical query padding and explicit finite
message capacity remain premises. Neither a query count nor the 64-bit
length tag supplies a maximum physical message register automatically.
The new write circuit does not improve (S-5), shrink persistent storage,
construct a base oracle, or establish useful AES security at the resulting
resources. No earlier `>2^151` cost observation is rewritten: it describes
the older explicit circuit.

## 5. What is still missing for the root reduction

The root lemma's environment `Gamma` is not implemented merely by declaring
an immutable `F` instruction. A complete construction must specify the
adversary's finite input lengths/time/resources; a common total address
interpretation and domain response widths; how independent base functions
are realized; every dispatch and compute/uncompute call; the private
programming state; and the actual lifetime controller and real/mixed prover
work. Correct source domain padding is not a free extra random tail.
External messages with other lengths, prefixes/domains or counter bytes
`>=M` must follow that common total interpretation. Honest frame lengths and
the primary trial cap do not automatically reject such oracle queries.

One may instead state an explicitly oracle-relative primitive premise that
supplies the required independent functions. That is a changed assumption,
not an ordinary finite-cost AES reduction, and requires explicit assessment.
A finite base-function simulation must be proved at the complete driver's
query budget, including future continuation, not just the five selected AES
requests. The immutable-base/overlay separation makes this obligation
precise; the overlay itself is not a random-function implementation.

There is a finite option that avoids assuming these functions are free.
[Zhandry, Fact 2](https://eprint.iacr.org/2012/182), states that
private `2q`-wise independence preserves a `q`-query quantum algorithm's
observable distribution exactly. Applied here, keep that base fixed and
place the adaptive overwrite log above it; include the entire wrapper in
`q`, including every base dispatch, compute/uncompute and later access.
Seeds remain private and independent of the challenge and initial advice;
oracle-dependent preprocessing must be charged. This is bounded observable
equality, not equality of private function tables. It does not make the
original reprogramming hybrids free. A concrete implementation and its full
cost would yield a finite quantum-time AES distinguisher with at most five
classical challenge calls; a bound for classical computation alone would
not suffice. The theorem supplies no inexpensive realization at this
deployment's parameters.
It simulates the assumed random functions; it does not establish that the
concrete SHAKE backend satisfies that model.

TODO: integrate the static slot layout with a whole-lifetime root driver
and its actual read/validation/return interfaces; price or explicitly assess
the independent oracle environment; establish the adversary-to-aggregate
query conversion; and quantify the primitive terms at the resulting full
resources. The source count (S-1), exact storage relation and tested write
component close specific local gaps, not these remaining obligations.
