# B6 initial H5 transition for a fixed opening

Status, 2026-10-13: **conditional derivation; local consistency reviews complete,
independent cryptographic review pending**. This note addresses
the initial H5/correction transition in §6 of the
[bounded driver proposal](parliament_ballot_b6_hybrid_driver.md). It supplies
an explicit gate-domain reduction under the premises below. It does not
establish entry into the ideal-row experiment, the complete G5–G6 transition,
the later mask-coordinate/deletion composition, an actual-IV primitive
embedding, a computational resource certificate, or independent review.
Production remains gated. The frozen [arguments](parliament_ballot_proof_arguments.md),
their equation (57), and the security ledger are unchanged.

The new bound concerns the salted construction and uses a conservative sum
over gates. It does not import a square-root-of-gates batching claim. Source
and primary-theorem identities are in the separate
[receipt](../docs/validation/parliament_ballot_h5_fixed_opening/receipt.json).

## 1. Premises and the two experiments

Let `T` bound all valid proving invocations, including exhaustion, across the
roles and rows under analysis. Invalid invocations take an identical path.
Let `g_* = max_R n_mult,R` (`704` for the current pair of rows). Let `Q` bound
external quantum backend-oracle queries that the dispatcher must process;
using the full backend-query budget is safe. The application adversary,
auxiliary registers, request history and oracle state persist throughout.

The conditional entry premises are:

1. The designated backend hash domains are independent quantum-accessible
   random functions with the exact frozen input encodings. Here H5 returns
   the specified ten bits. Its finite domain may be partitioned by the
   fixed-position gate index. This is the existing backend QROM premise,
   not a statement about concrete SHAKE or public Keccak computations.
2. Requests are classical and atomic, with no current-request fields or
   timing trace released between internal computations. Subsequent quantum
   access is unrestricted except for the stated query budget. Initial
   advice is independent of the sampled oracle functions; earlier access is
   retained and charged, rather than conditioned away.
3. The computational material hybrids have already made every selected
   expanded row fresh uniform and mutually independent, independent of the
   entering history, revealed expanded rows, commitment/opening material,
   actual IV and other oracles. This is a premise about the ideal experiment;
   conformance of the actual PRG does not prove it. Selected row values are
   cached wherever that experiment reuses them.
4. The selective opening `I`, primary counter schedule and exhaustion flag
   are sampled independently of current commitment/material coins and salt,
   as in the proposed bounded schedule. They may have any supported
   distribution on admissible openings, including a fixed one. The claim
   does not cover choosing `I` after observing the current rows or H5 values.
5. Each valid invocation has a fresh independent uniform 256-bit salt `S`.
   The retained IV is the actual `H4_role(iv_pre || mu)`, with all its prior
   correlations. No IV entropy or uniform-IV premise is used here.
6. Before its H5 calls, the current request has made no H5-dependent use of
   the fresh hidden-row prefix coordinates or salt. Other row coordinates,
   the fresh pad, witnesses and private bookkeeping can be retained, but
   do not constrain these fresh coordinates. The source dependencies and
   permitted reordering that support this premise are checked in §3.

The two experiments retain the same real values of all independent
challenges, the same counter schedule, and the same final error/success rule.
Every challenge write is made at the location computed from that
experiment's resulting material. No unused auxiliary opening is returned on
exhaustion. Both experiments continue through the adversary's final bit.

**`RealH5`.** Starting at this ideal-material entry, use the unrefreshed H5
function for both labels of every gate. Compute the original gate
corrections and all subsequent fields from those values.

**`PatchH5`.** Starting from the same entry, for each request sample the ten
correction bits of every gate uniformly and independently. Evaluate the
visible labels in the current oracle, and install the hidden assignments
specified in arguments (51). Reconstruct the private H5-derived material
using those values and continue the original computation. Assignments use
chronological functional overwrite. On an own-label equality, evaluation
precedes overwrite and the experiment is still defined; it need not be
consistent there. It neither aborts on collisions nor conditions its inputs
on their absence. Later collision flags/aborting games require their own
comparison.

Under these premises, the derivation below gives

```text
F(q,p) = sqrt(q*p) + (q*p)/2

|Pr[RealH5 outputs 1] - Pr[PatchH5 outputs 1]|
  <= g_* * T * F(2*Q + 2*T, 2^-512) + T * 2^-256.                 (H5-F)
```

This is an isolated alternative conditional bound. It is not a replacement
of a term in the accepted ledger or a numerical primitive-security claim.

## 2. The late uniform-coordinate sampler

Work on the first 256 coordinates of each expanded row. Fix an admissible
opening with hidden index `delta_i` in vector `i`, fix the revealed rows, and
write `r_i,j` for their 256-bit prefixes. Define the known quantities

```text
a_i   = XOR_(j != delta_i) r_i,j
b_i,k = XOR_(j != delta_i, bit_k(j)=1) r_i,j
beta_i,k = bit_k(delta_i).
```

The hidden prefix `h_i = r_i,delta_i` is uniform by premise 3. Directly from
the bitwise VOLE fold,

```text
u_i   = h_i XOR a_i
v_i,k = b_i,k XOR beta_i,k*h_i.
```

Instead of sampling the `h_i`, sample independent uniform strings
`U,C_1,...,C_(tau-1)` of length 256; put `C_0=0` and set

```text
u_i = U XOR C_i
h_i = U XOR C_i XOR a_i.                                      (H5-1)
```

This is a bijection between `tau` independent uniform strings and the
original hidden prefixes. It leaves the revealed rows unchanged. `U` is
the current witness-prefix mask `U_P`, and `C_i` is the corresponding prefix
of the source correction `c_i`. Disjoint coordinates of the expanded rows
can be sampled separately. This reparameterization neither conditions on
the source tree keys being distinct nor gives the real PRG independent
outputs; independence is the stated ideal-entry premise.

The globally aligned reconstructed column is

```text
q_i,k = v_i,k XOR beta_i,k*U
      = b_i,k XOR beta_i,k*(C_i XOR a_i).                       (H5-2)
```

Thus all its prefix coordinates are fixed before sampling `U`. This agrees
with the source reconstruction: its hidden-row fold removes `u_i`, and the
later `c_i` addition on selected index bits changes `u_i` into the common
mask `U`. Let `G_e` be the fixed gate-label linear map, and put

```text
A_e = G_e(q)                         // observable label
gamma_e = G_e(beta)                  // one bit
L0_e = A_e XOR gamma_e*U
L1_e = L0_e XOR U
Lhid_e = A_e XOR U.                                           (H5-3)
```

`A_e` depends on the fixed opening, revealed rows and `C_i`, but not on `U`
or `S`. The relation is valid for every hidden index, including zero. It
uses no division by a challenge and no distributional property of `I`.

The sampler can therefore construct every `A_e`, retain arbitrary actual
IV and other material, and defer just `U` and `S`. After drawing them it
uses (H5-1) to finish the hidden prefixes and the original computation. This
is the same joint distribution, not a claim that `U` remains conditionally
uniform after later oracle observations.

## 3. Exact source dependencies and reordering

The pinned source supports the following narrower statements:

| Source | Relevant dependency |
| --- | --- |
| [proving.rs](../crates/iroha_parliament_ballot_proof/src/proving.rs) | Root, `iv_pre`, pad and salt occupy disjoint parts of the 112-byte tape; salt is bytes 80–111 |
| [convert.rs](../crates/iroha_zkp_vole/src/vole/convert.rs) | The fold computes the sums used in (H5-1)–(H5-2); hidden reconstruction never reads the omitted seed slot |
| [vole.rs](../crates/iroha_zkp_vole/src/vole.rs) | `commit_as` constructs rows, corrections and field masks before gate H5 calls; `gate_labels` reads only the first 256 row coordinates |
| [vole.rs](../crates/iroha_zkp_vole/src/vole.rs) | `reconstruct_as` adds the correction on the selected index bits before applying the same gate-label map |
| [hash.rs](../crates/iroha_zkp_vole/src/hash.rs) | Extended H5 absorbs namespace, IV, salt, `LE32(e)`, label, `05`; it returns the low ten bits for these rows |
| [proof.rs](../crates/iroha_zkp_vole/src/proof.rs) | The commitment, including all H5 calls and `c_mult`, precedes challenge 1; challenge 2, relation coefficients and counter work follow |
| [profile.rs](../crates/iroha_parliament_ballot_proof/src/profile.rs) | Role changes the namespace while the selected row supplies VOLE geometry |

Within `commit_as`, salt enters only H5. It is not consumed by H0, H1, tree
expansion, row expansion, correction generation, the actual IV derivation
or the gate-label calculation. Challenge 1 includes it only after
`c_mult` exists. The source normally samples the entire tape first; moving
private sampling later is justified by these dependencies, not by assuming
that a salt already exposed to the adversary is fresh again.

`Layout::mask_row(m) = ell + m*d_0`, with `ell >= 256` for both relations,
places the low field-mask coordinates outside the deferred prefix. The high
mask expansion uses the root and actual IV. It is independent of the
deferred ideal-row prefixes under premise 3. Neither mask path reads salt.
Fresh uniform tape coins remain a game premise: the caller-supplied tape
API, including its reproducible `from_bytes` constructor, does not enforce
entropy on arbitrary callers.

For a selected gate `e`, move its private refresh and both H5 evaluations
before every current-request H5 evaluation at other gates. Labels and field
mask values do not depend on the H5 evaluations, and calls at different
gate indices are in disjoint domains. Their reads and writes commute even
when salts or IVs repeat across requests. The collected gate values are
identical for each fixed set of coins and oracle functions. The subsequent
field-mask tag computation and challenge writes remain after all gates,
with their actual resulting inputs. Previous requests remain in order.

There is no current-request H5 query, hidden assignment, challenge write or
publication before the selected refresh in the reduction. In particular,
earlier converted gates are not evaluated first. Their current-request
operations are deferred to after the selected gate, then executed with the
same sampled material and cached values. This avoids losing the fresh
location distribution through an earlier correlated gate query.

These are mathematical game scheduling identities. They do not establish a
constant-time implementation, permit ignoring faults, or change production
execution order.

## 4. One whole-lifetime reduction for each gate

The primary result used is Grilo–Hövelmanns–Hülsing–Majenz,
[Tight adaptive reprogramming in the QROM, arXiv:2010.15103v2](https://arxiv.org/pdf/2010.15103v2),
Figure 2 and Theorem 1. Its reprogramming interface samples a location and
auxiliary output from a supplied joint distribution, replaces the value by
a fresh uniform output in one game, and returns the location and auxiliary
output. The distinguishing bound sums `F(qhat_r,pmax_r)` over instructions;
`qhat_r` counts prior target-oracle queries and `pmax_r` is the expected
maximum of the marginal location distribution. The result is information
theoretic for query-bounded distinguishers. It does not require hiding the
returned location or auxiliary output after the instruction.

Define `H_k`, for `0 <= k <= g_*`, as follows. At every valid request, gates
with `e < min(k,n_mult,R)` refresh their hidden H5 values independently to
uniform ten-bit values; the remaining gates use the current oracle.
Afterward compute the **original** correction formula and all dependent
material. Chronological writes persist. `H_0 = RealH5`.

Compare `H_e` and `H_(e+1)` with one distinguisher `D_e` covering the entire
adaptive execution. Its target oracle is the H5 subdomain with fixed gate
index `e`, across all relevant namespaces. It retains/emulates all other
domains and prior writes exactly. There is at most one target reprogramming
instruction per valid invocation that has this gate, and at most `T` in
total. No instruction is needed on rows lacking this gate.

This target domain is finite. A correctly encoded H5 input has 162 bytes:
prefix `[0,77)`, IV `[77,93)`, salt `[93,125)`, gate `[125,129)`, label
`[129,161)`, and suffix byte 161. These fixed widths make parsing injective.
For fixed `e` and the four current role/row prefixes, there are at most
`4 * 2^(128+256+256)` target addresses. Malformed encodings and other
prefixes/gates belong to the retained other domains. No variable-length
concatenation is parsed heuristically. The receipt independently computes
the four namespaces from the frozen descriptor digests and checks their
distinct prefixes against the source test pins. It also checks the actual
row constants: candidate `n_mult=704`, comparator `n_mult=696`, so
`g_*=704`. These are deterministic encoding/parameter checks, not hash
collision assumptions or a full source execution proof.

At the current request, run the sampler and scheduling of §§2–3. Before the
instruction, `D_e` knows `R`, the actual IV and `A_e`; it has not sampled
`U,S`. It supplies the following joint distribution:

```text
sample U <- uniform {0,1}^256
sample S <- uniform {0,1}^256, independently
X  = PREFIX_R || actual_IV || S || LE32(e) || (A_e XOR U) || 05
X' = (U,S)
return (X,X')
```

Every possible full location determines exactly one pair `(U,S)`. Therefore,
for every entering history and every fixed choice of the retained material,

```text
max_x Pr[X=x] <= 2^-512.                                     (H5-4)
```

The bound survives averaging over that history. It does not condition away
prior quantum queries or require that the actual IV be independent of
them. The reprogramming interface is allowed to return `X'`: the reduction
uses it privately to construct the hidden prefixes and continue the
prover. These variables are not an additional application-adversary API.

In the no-refresh game, the instruction only samples and returns this
material, and the resulting execution is `H_e`. In the refresh game it
first writes a fresh uniform ten-bit value at the hidden point, giving
`H_(e+1)`. Query the selected gate's two labels in that resulting oracle,
finish the other gates, and continue. Nothing prescribes a
witness-dependent reprogramming value in this theorem application.

This is not a sequential reprogramming proof that reveals one hidden label
and then incorrectly asserts that all other labels retain fresh entropy.
The reductions for different `e` are separate experiments. Each resamples
the current `(U,S)` inside its own location instruction and defers that
request's other-gate operations. The final sum pays for every gate.

## 5. Oracle queries, other domains and future access

A quantum query to the combined backend domain can be simulated by a
reversible dispatcher. Parse the address and mark whether it belongs to
the selected H5 gate. Query the target oracle into an ancilla, copy its
answer into the response only under that mark, and query again to erase
the ancilla. Nonselected inputs use a fixed dummy target address; the other
domain's answer is supplied from its own retained oracle. This costs at
most **two** target queries per external combined-domain query, including
queries spanning several gates or roles. It does not rely on free
controlled-oracle access. The domain parsing and every other operation also
have computational costs; this proof is not a certificate for those costs.

For each completed proving request, the source's selected gate makes two
classical H5 evaluations. They can be made directly to the target oracle
and cached. The source prover does not reconstruct the proof afterward;
any later adversarial verification queries are included in `Q`. Neither
the private location sampler nor the gate-specific driver needs extra H5
queries. Thus, before any target refresh,

```text
qhat_e,r <= 2*Q + 2*T.                                      (H5-5)
```

Only two honest queries per request go to this fixed-gate target oracle;
it is not `2*g_*` there. The honest calls to other H5 gates and all H0/H1/H4,
transcript, relation, generator and non-oracle operations remain in the
distinguisher and must be charged in any full computation/resource claim.
They are not queries to this particular oracle. Independent other-domain
oracles may be included as private independent randomness and reversible
operations for this information-theoretic theorem; their implementation
does not become free in a later computational primitive reduction.

All prior target queries, including those in earlier requests, contribute
to (H5-5). All subsequent quantum queries and final computation remain part
of `D_e`; no post-query secrecy assertion is needed. Combining Theorem 1,
(H5-4), (H5-5), and a triangle inequality over gates gives

```text
|Pr[H_0 outputs 1] - Pr[H_g* outputs 1]|
  <= g_* * T * F(2*Q + 2*T, 2^-512).                         (H5-6)
```

If a different surrounding experiment adds honest target H5 calls, their
actual number must be added before using this formula. The bound is stated
for the cached source-matching proving driver above, not an arbitrary
uncounted reconstruction or logging implementation.

## 6. Exact fresh-value-to-correction identity

Consider a request in `H_g*`. Fix its pre-refresh oracle table, all other
material and the adversary's conditional quantum state. For `U != 0`, the
visible and hidden points of one gate differ. Different gate indices make
all the current request's gate pairs disjoint. Hence no current hidden
refresh changes a current visible value.

Write `V_e` for the current visible H5 value, `Y_e` for the refreshed hidden
value, and `F_e` for the ten mask-coordinate bits entering the correction.
The refreshed `Y_e` are independent uniform ten-bit strings, independent of
the pre-refresh table and other current material. The original correction
formula is

```text
Cmult_e = Y_e XOR V_e XOR F_e.
```

For the fixed table and material this is a bijection from all `Y_e` to all
`Cmult_e`. Re-express the same random coins as independent uniform
`Cmult_e`, then put

```text
H5(hidden_e) := Cmult_e XOR V_e XOR F_e.                       (H5-7)
```

Every table entry and every internal value after the assignments is the
same under this change of variables. Consequently the joint distribution
of the table, transcript, private material and adversary quantum registers
is the same, including all future oracle operations. Conditioning on a
table here is a mathematical equality of mixtures; it is not an operation
that measures or extracts the adversary's state.

Previous-request collisions are permitted in this identity: `V_e` is read
from the current table, and (H5-7) overwrites that table in the specified
chronological order. A later write may conflict with an earlier proof.
The reprogramming bound already includes distinguishing through such
previous and future accesses. If a later proof requires globally
nonconflicting assignments or aborts on them, that additional step still
needs its own bound; this note does not remove any frozen collision charge.

At `U=0` the two labels coincide and the original correction is `F_e`;
claiming an exact uniform correction there would be wrong. Couple the
experiments using the identity above until an invocation samples `U=0`,
then allow arbitrary divergence. The freshly uniform `U` in each invoked
slot gives

```text
Pr[any own-label equality in at most T invocations] <= T*2^-256.
```

This is one charge for the endpoint coupling, not one per gate. It adds the
last term of (H5-F). No salt-uniqueness conditioning, IV-separation event or
uniform-IV assumption is needed for this totalized-overwrite lemma.

## 7. Fixed openings, exhaustion, roles and remaining obligations

The proof conditions only on independently selected admissible `I` and
other schedule information, with a bound uniform in those choices. It
therefore applies to their mixtures without changing the bound. In
particular, the bounded driver's exhaustion sampler may return a sampled
admissible opening or its verified fixed fallback. The unused opening is
still not published on exhaustion; H5 and challenge-oracle effects remain
in the experiment and the invocation still counts toward `T`.

No uniform-opening averaging, opening acceptance probability, or entropy
of the grinding suffix occurs in (H5-1)–(H5-F). The actual zero-fallback
membership check is a separate combinatorial obligation. This note does
not assert that a real counter sequence ever reaches that challenge.

Both roles use independent namespaces and fresh per-request coins. A
single fixed-gate reduction can include their disjoint namespace domains,
so `T` is the joint lifetime count, not multiplied by the number of roles.
The same construction includes both rows; absent gates make no refresh
instruction, and `g_*` is the maximum gate count. No candidate opening-size
or success-probability certificate is transferred to the comparator.

The next review must check the ideal-entry premises against the complete
computational reductions and the outer challenge-programming game, then
compose the joint mask-coordinate change and hidden-label deletion with
this exact totalized endpoint. In particular, the source's actual derived
IV still needs the separate primitive-interface embedding. A complete
computation must also account for all other-domain oracle state,
reversible operations, gates and memory; (H5-5) only counts accesses to the
selected H5 gate. The existing positive exhaustion slack may be retained
conservatively; no ledger term is removed here.

This note supplies a conditional local derivation for that review. It
does not attest owner acceptance, independent cryptographic review,
profile qualification or production readiness.
