# B6 bounded hybrid-driver proposal

Status, 2026-10-13: **proposal for cryptographic review; no qualification or
accepted new assumption**. This specifies the driver missing from the
[generator-interface analysis](parliament_ballot_b6_generator_interface.md).
It keeps the existing [arguments and ledger](parliament_ballot_proof_arguments.md)
unchanged. It neither proves their complete zero-knowledge bound nor supplies
a numerical AES advantage, a quantum resource certificate, owner acceptance,
or independent review. Production remains gated.

The proposal separates three things: exact local distribution identities;
candidate computational reductions with explicit interfaces; and open
composition/resource obligations. A driver below is a mathematical experiment,
not executable simulator code or a new production API. In particular, a
symbolic hidden-key handle cannot be substituted into the current Rust API.
The separate [receipt](../docs/validation/parliament_ballot_hybrid_driver/receipt.json)
records the reviewed source/specification hashes and checks their stability.

## 1. Entry contract and shared state

Start **conditionally** at arguments §6.5.2 game `G_4`, after its three
challenge-programming transitions. This entry already requires their
protocol-specific QROM embeddings; this proposal does not establish them.
Every valid request has independent uniform challenge values, including the
sequence tried by the bounded counter loop. Its commitment, witness, H5 and
other public-oracle computations are otherwise real. Invalid requests use the
same validation and return path in every game.

The driver runs one adversary to its final output bit. It retains one state
across registration and vote requests, repetitions, exhaustion, interleaved
quantum queries and subsequent computation. Its state is:

- The adversary's quantum registers and its public application environment.
  The driver does not inspect, clone, measure or receive those private
  registers except through the specified experiment interfaces.
- One persistent oracle environment for every role/domain. The role namespace
  and concrete byte encodings are unchanged. Credential functions and public
  statements are never programmed or replaced.
- The proof-invocation ordinal, accepted/failed response history, and the
  validation/logging state required by the enclosing game.
- Private current-request material: real application witness while needed,
  fresh root, `iv_pre`, pad and salt, real `mu`, actual
  `IV = H4_role(iv_pre || mu)`, the retry schedule, selected opening, symbolic
  key handles where a component reduction needs them, and cached component
  outputs. None of these private handles becomes an adversarial interface.

Oracle updates mean the same persistent functional overwrite semantics as the
arguments. This is not an implementation by measuring an adversary's quantum
query or by treating a classical table as a coherent oracle. A realization of
that environment and its costs remain obligations in §7.

Requests are classical and atomic. The proof game does not expose an internal
execution-time trace; resource costs are nevertheless charged. This proposal
is not a timing, cancellation, OOM or runtime-fault equivalence theorem.
Atomicity permits moving **private random
sampling** earlier. It does not erase prior queries, justify changing an
already observable oracle entry, or exempt later quantum queries from a
hybrid bound. All post-request continuations are part of each distinguisher.

## 2. Bounded selective schedule at the first hybrid

Let `M = 2^20` and let `Omega_R` be the row's exact admissible challenge set:
the grinding suffix is zero and the decoded opening has at most that row's
`T_open` revealed nodes. Admissibility depends on the fixed tree and challenge,
not the root, pad, witness, salt or oracle transcript. Use the row's own decoder;
the comparator does not inherit the candidate's `1/7360` certificate.

Define the following private schedule before constructing the commitment:

```text
Schedule(row):
    primary = []
    for c = 0, ..., M-1:
        Y = fresh uniform 256-bit string
        append Y to primary
        if Y is in Omega_row:
            return (Success(c), primary, Y)

    for j = 0, ..., M-1:
        Z = fresh uniform 256-bit string
        if Z is in Omega_row:
            return (Exhausted, primary, Z)
    return (Exhausted, primary, y_zero)
```

`y_zero` is admissible for the candidate: its all-zero decoded indices expose
11 nodes, as retained in the existing arguments. Applying this proposal to
the comparator requires checking its zero-pattern opening against its own
limit; no candidate fallback certificate is transferred. Alternatively a
separately verified fixed admissible comparator challenge can be named.
The proposed candidate driver has at most `2M` draws and admissibility checks
per valid invocation, including every exhaustion branch.

Call the resulting real-material game `B_0`. It computes the same real
commitment/transcript as `G_4`, installs each primary `Y_c` at that game's
exact `X_3,c`, returns the original first-success counter and proof on success,
and returns the prescribed exhaustion error otherwise. On exhaustion it does
**not** call `open` for the auxiliary challenge, hash its opening, or write an
extra oracle entry. The auxiliary value is private unused bookkeeping in
`B_0`; only later hybrids use it to define a hidden path.

Two local identities justify this scheduling:

1. The primary values are independent of the commitment coins, and membership
   in `Omega_R` depends only on those values. Presampling them gives the same
   joint distribution as drawing them at the counter loop, including every
   programmed value and the first-success/exhaustion result. Writes stay at
   the locations computed from that game's actual material.
2. On exhaustion, an independent auxiliary value that is never read by the
   observable `B_0` computation can have any distribution without changing
   the adversary's joint state. Replacing an exact uniform-from-`Omega_R`
   sampler by the bounded auxiliary sampler above therefore costs zero
   **at this point**, before the material is replaced.

The second identity does not justify changing the auxiliary sampler after
the CRT transformation: there it can affect transcript material and retained
oracle writes even when no proof is returned. Use this same bounded sampler
throughout all subsequent games. This removes the otherwise unspecified
worst-case cost of an exact rejection sampler from each primitive reduction.

Success uses a uniform admissible opening. Exhaustion uses a bounded mixture
of uniform admissible samples and a fixed fallback. Consequently, the needed
multi-hiding lemma must hold uniformly for **every fixed admissible opening**,
or for its resulting coin-independent mixture. The published uniform-opening
statement cannot simply be renamed to obtain that lemma.

## 3. Ordered material hybrids and what they expose

For each request let `I = Decode(y_star)` be its private selected opening and
let `Hidden(I)` mark those leaves and all their ancestors. Select request
ordinals in increasing order; within a request use this order:

| Stage | Proposed change | Material that must remain consistent |
| --- | --- | --- |
| Root | Replace the root's tree expansion and high-mask expansion jointly | Both outputs, all derived children and high bits |
| Paths | Replace each distinct non-root internal node in `Hidden(I)`, parent before child | Child keys for every subsequent expansion; shared ancestors are changed once |
| Leaves | Replace the raw 144-byte expansion of each selected leaf | Leaf seed, affine commitment, commitment hash and eventual opening |
| Rows | Replace each selected leaf seed's expanded row | Small-VOLE columns, corrections, witness mask and CRT masks |

Finish these computational changes for all invocations while H5 is still
evaluated by the real rule for each game's material. Then perform the
statistical H5/correction transition, mask-coordinate change and hidden-label
deletion, in request order. Each experiment answers a request immediately;
this is an ordering of adjacent experiments, not permission to delay the
adversary's requests until all future requests are known.

Unknown future requests use the appropriate side of that experiment's ordinal
boundary when they arrive. Unused component slots can be identity steps, so
the number of possible transitions has a deterministic upper bound. Selecting
one adjacent step gives a distinguisher that runs the **whole** adversary and
all prior/future requests. It does not run only the selected request.

No marked node slot is selected by an opening: the opening reveals only the
unmarked child of a marked ancestor with exactly one marked child. This is
a statement about slots; it does not rule out equal key bytes in different
slots or permit discarding such collisions.
[`mark_hidden`, `revealed_nodes` and `Commitment::open`](../crates/iroha_zkp_vole/src/bavc.rs)
implement this ownership of opening keys. A selected leaf's seed is used as
an expansion key; its commitment, not that seed or node key, is revealed.

The simulator must replace repeated internal uses consistently. In particular,
the source recomputes a hidden leaf commitment during `open`; the mathematical
driver instead reuses its cached commitment. With real material these are
identical deterministic values. With replaced material fresh resampling would
be a different, incorrect experiment. Failed oversized openings reveal and
cache no additional leaf result; success uses the selected pattern once.

## 4. Explicit component reduction candidates

The following describes the needed forward-only, classical challenge access
inside a quantum distinguisher. It is **not yet an embedding into the current
uniform-IV benchmark**. Section 5 states the exact interface gap.

A fresh unknown challenge key may be represented by a private symbolic handle
only after the preceding game makes the corresponding key a fresh uniform
value independent of the already generated state. Other keys and coins are
generated as in that adjacent game. The driver never conditions on the
challenge key differing from other keys. Key-collision cases are part of the
experiment and may not be discarded without a proved loss.

### 4.1 Root and path keys

At the selected invocation, let the challenge key occupy the fresh root slot.
Compute the actual `mu` and H4-derived IV, and forward the root's two uses:
tree tweak zero producing 64 bytes, and
[`MASK_TWEAK = 2^31-1`](../crates/iroha_zkp_vole/src/vole.rs)
producing the row's `n_mask * w_grind` high bits. Both outputs must be supplied
by the same challenge key/game; replacing them independently is not justified.
At these two rows they consume four plus one AES blocks. Preserve exact
truncation and unused-bit masking.

For a subsequent path step, the target internal key is a uniform child of a
previously replaced parent. Place the challenge-key handle in that child
coordinate and retain the independently sampled sibling. The parent's unused
private raw output need not be materialized as bytes containing the unknown
key. Forward the target node's one four-block expansion at its real node
tweak; continue using the returned children. The target node is marked, so
its key is never copied into the opening. All descendant keys needed for
unmarked subtrees become known from the reply and can be computed normally.

This gives the correct adjacent real/ideal distribution **conditional on**
the chosen-input component oracle and preceding hybrid invariant. It is not
a way to put an unknown key into an unmodified real GGM tree, whose parent
would still constrain that key.

### 4.2 One selected leaf

After the path steps, place the challenge key at the selected leaf of vector
`i`. For the actual IV and tweak `L-1+i`, request the nine blocks

```text
X(IV,t,c) = LE32(a+c mod 2^32) || middle64 || LE32(z+t mod 2^32)
for c = 0, ..., 8, where IV = LE32(a) || middle64 || LE32(z).
```

Split the reply as `sd[32] || b0[96] || b1[16]`, evaluate the real H0-derived
affine leaf transformation, and cache `(sd, com)`. Use `sd` for the ordinary
expanded row and `com` for H1 and every subsequent opening. Preserve all other
leaf computations. The selected node key has no further required use in this
driver; the source's repeated leaf computation is answered from this cache.
Only the prescribed public proof projection reaches the adversary.

If the raw reply is independent uniform bytes, then for every fixed hash key

```text
(sd,b0,b1) -> (sd, L_h0(sd) XOR b0, low128(sd*h1) XOR b1)
```

is a bijection. Its inverse applies the same masks. Thus `sd` and `com` are
independent uniform strings conditional on that hash key and on state
independent of the raw reply. This local identity does not prove the raw
reply's independence in an AES experiment.

### 4.3 One expanded row

After the ideal leaf step, place the challenge-key handle at that leaf's
uniform `sd`. Sample its uniform 112-byte commitment independently. The
unused private affine masks can be defined mathematically by the inverse
bijection; the driver neither knows nor computes them, and must establish
that no subsequent observable computation reads them.

Forward the actual row expansion under that key, the unchanged IV and tweak
`2^31+i`, with the role's actual `ell_hat` and exact truncation. Use the reply
in [`convert_to_vole`](../crates/iroha_zkp_vole/src/vole/convert.rs), and then
run the remaining CRT/transcript computation. Return the cached commitment
if the opening is returned. No honest computation otherwise requires the
unknown seed bytes. Public AES computation by the adversary remains available
and charged; it is not redirected to this private challenge handle.

This is a separate hop. Uniformity of the leaf's `sd` does not by itself make
the output of AES keyed by it uniform.

## 5. Primitive interface that must be justified

One possible precisely stated target is a fresh-secret-key AES distinguishing
experiment with the following candidate interface:

1. Sample uniform `K` independently of initial advice and the initially
   independent backend oracle environment.
2. Provide a forward classical request `EvalBlock(x)`. In one branch it returns
   `AES256_K(x)`; in the other it returns a uniformly sampled permutation at
   `x`, consistently on repeats. The driver chooses the actual block inputs.
3. Permit the same surrounding quantum environment and public AES computation
   as the ballot experiment. Specify how the independent QROM is supplied or
   simulated; neither its coherent access nor its programming is free by
   default. Permit no disclosure of `K`.
4. Charge the complete driver's resource vector and its challenge requests,
   and take the final output-probability gap.

This is a **proposed game definition**, not an accepted security premise or a
known numerical bound. Calling it AES security does not prove it for fixed
AES, nor transfer a theorem proved in a different oracle model.

Under this interface, each component forwards its real block inputs. The IV
keeps its actual H4-derived distribution and correlation with prior oracle
state. Fixed-IV counter blocks within each stated component are distinct;
the root's two tweak ranges are also distinct. A subsequent classical
permutation-to-independent-block coupling can therefore be charged for that
component's actual number of distinct blocks. Repeated internal uses replay
the same values. This local coupling does not apply to coherent requests to
the challenge permutation or to independent outputs for aliased `(IV,t)`
pairs. A future reduction requiring either must state a different game.

The existing [reference PRG games](parliament_ballot_b6_generator_interface.md)
instead supply a uniform public IV. Those games do not directly let this
driver choose the H4-derived IV while retaining its prior quantum state.
Giving the driver a challenge IV and simply overwriting H4 introduces an
additional transition; searching for its preimage introduces computation.
Neither operation is present or costed in the current proof. A review must
prove an embedding into the unchanged premise, or explicitly specify and
assess the proposed alternate premise. It must also resolve the published
`N_i` leaf-query charge versus this proposed one-selected-leaf driver; the
source's cached call count is not a substitute for that proof.

For comparison only, [FAEST v3 Definition 10.7 and Lemmas 10.24/10.51](https://faest.info/faest-spec-v3.0.pdf#page=79)
supply the published generator and multi-hiding framework. Their random-IV
interface and stated leaf query counts are retained in the earlier analysis.
They do not certify this adapted driver, the added affine leaf, salted H5 or
the bounded auxiliary schedule.

## 6. Fixed-opening algebra and the open H5 lemma

There is a local algebraic reason to seek a uniform-over-opening lemma. For
one vector fix the selected index `delta`, fix all revealed expanded rows
`r_j`, and let `r_delta` be independent uniform. Bitwise small-VOLE obeys

```text
u = XOR_j r_j
v_k = XOR_{j: bit_k(j)=1} r_j
q_k = v_k XOR bit_k(delta)*u.
```

The coefficient of `r_delta` in every `q_k` is zero. Hence `q` is determined
by revealed rows, while `u` is uniform. This holds for every fixed index,
including zero. Across vectors, the map from independent `u_i` to the common
mask and corrections `(u_0, u_1 XOR u_0, ..., u_(tau-1) XOR u_0)` is a
bijection. Disjoint row coordinates and the CRT maps give the corresponding
ideal-mask argument, conditional on the required CRT bijectivity and source
layout correspondence.

Likewise the six QuickSilver response equations have unit-diagonal triangular
form, and the four remaining consistency masks enter additively. Their joint
inverse in arguments (53)–(54) uses no division by `Delta`. Reparameterizing
them remains algebraically valid at `Delta=0`. These facts establish neither
oracle indistinguishability nor independence from a previously queried H5.

**Required uniform H5 statement.** For each fixed admissible opening, and
uniformly over the entering adaptive transcript and permitted quantum
auxiliary state, the material transition must establish:

- The observable H5 label is determined by reconstructed public material,
  while the opposite label has the required conditional distribution from
  the ideal witness-prefix mask. State exactly what is conditioned on.
- Programming the opposite label consistently with the sampled gate
  correction satisfies the chosen QROM programming theorem, including
  same-label, previous-proof, same-request and repeated-IV/salt events.
- The same bound holds for both namespaces and for the bounded exhaustion
  mixture without conditioning away its fallback mass.
- The pad/mask coordinate change preserves the **joint oracle state**, and
  the later deletion argument covers all subsequent quantum accesses.

The intended order is: enter ideal row/mask material; generate the sampled
gate corrections with consistent hidden H5 assignments; perform the joint
witness/response coordinate change; derive the public `a_0`; retain hidden
assignments during their deletion argument; then discard unused private
witness/pad bookkeeping. No already returned field changes. Each challenge
is programmed from the final material of that adjacent game; the primary
counter values and counter numbers stay unchanged, including on exhaustion.

**TODO:** supply and independently review this uniform H5 lemma and its
composition with the preceding component experiments. The cancellation and
bijection identities above are not its proof. Until then, the proposed final
game's equality with the full oracle-visible `Sim+` execution is unproved.
If that equality and all hops are proved, the sampler already matches `Sim+`;
the existing positive `sigma` may remain as conservative slack. This proposal
neither removes it from the frozen ledger nor adopts a revised total bound.

## 7. Lifetime resources and remaining acceptance obligations

Both roles share the invocation ceiling `T`; they do not each receive a
separate allowance. Invalid requests, application context work and direct
verification still need their own permitted counts. They are not free merely
because they do not enter the component hybrids.

For each component distinguisher, record at least

```text
R_B = (adversary gates/time, public AES and Keccak work,
       backend queries by domain, challenge block requests,
       programming locations and overwrite operations,
       validation/relation/transcript work, sampling/admissibility work,
       classical memory, quantum memory, coherent access implementation,
       preprocessing/advice, final comparison).
```

Every distinguisher continues through the whole lifetime and final comparison.
Its resource vector includes all other honest requests and public verification.
The number of hybrid steps multiplying an advantage is distinct from the
work of one reduction; neither may silently replace the other.

Structural finite bounds available to a proposed driver are:

| Quantity | Bound or disposition |
| --- | --- |
| Primary trial values and challenge-3 writes | At most `M*T` |
| Extra auxiliary trial values | At most `M*T`; no extra challenge-3 writes |
| Total trial randomness | At most `512*M*T` bits, excluding other coins and oracle generation |
| Root transitions | At most one joint transition per valid invocation |
| Non-root path transitions | At most `tau*(ceil(log2 L)-1)` per invocation; shared ancestors can reduce this |
| Leaf / row transitions | At most `tau` each per invocation |
| Challenge requests per candidate root/path/leaf/row step | Respectively 5 / 4 / 9 / `ceil(ell_hat/128)` classical block requests under the proposed interface |
| Invocation source work | Real-prover and verifier component reports supply their own entry-specific costs; neither bounds the new complete driver |
| H5, relation, transcript, persistent QROM and final comparison | Full source/algorithm and computational accounting still required |

Counts are not a complete elementary-gate bound. A mathematical programmable
oracle cannot be assigned zero memory/gate cost when evaluating a concrete
AES reduction unless that oracle is explicitly part of the primitive game
being assessed. An oracle-relative assumption and an efficient simulation of
that oracle in a standard primitive experiment are different claims.

Before this proposal can support B6.1, a reviewer must resolve all of:

1. The `G_4` entry, exact retry/write scheduling and uniform fixed-opening H5
   theorem, including exhaustion, arbitrary witnesses and both roles.
2. The root/path key-handle invariant and every source use of hidden keys;
   cached openings, seed visibility, key collisions and unused bookkeeping
   must give the exact adjacent distributions.
3. The actual primitive game and IV/QROM embedding, its challenge-query mode,
   and the published multiquery versus proposed one-leaf reduction issue.
4. Full resource vectors and concrete primitive bounds; direct switching or
   PRP-native accounting must be chosen coherently without double charging.
5. Equality of the last game to the shared `Sim+` on complete public and
   oracle state, not only accepted proof bytes.

These are mathematical and resource obligations. Owner acceptance of changed
security/selection requirements and independent attack-cost review remain
separate obligations in the existing B6 record. A proposal, a hash receipt or
local algebra cannot stand in for any of them.
