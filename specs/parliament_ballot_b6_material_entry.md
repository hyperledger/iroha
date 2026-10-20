# B6 conditional entry into independent material

Status: **conditional computational reduction, not an accepted primitive
bound or qualification**. This extends the
[root-entry lemma](parliament_ballot_b6_root_entry.md) to the marked paths,
selected affine leaves and selected expanded rows of the
[bounded hybrid driver](parliament_ballot_b6_hybrid_driver.md). Under its
proposed chosen-input AES/`Γ` game, the adjacent reductions below reach the
specified independent-material endpoint. Full resources, quantitative
primitive premises, initial programming, later statistical composition and
independent review remain separate obligations. Existing frozen arguments,
numerical ledgers and receipts are unchanged.

## 1. Entry, ordering and projection

Retain the root lemma's fresh-tape, atomic classical-request and full-lifetime
quantum/environment contract. The private primitive oracle accepts classical
block inputs; public AES computations remain available and charged. `Γ`
must supply or correctly simulate the required persistent quantum oracle
environment. No direct private key/seed getter is part of the proof oracle.

Start conditionally at the bounded driver `B_0`, whose prescribed challenges
and opening schedule already require the initial programming arguments.
Before material generation, `Schedule(row)` determines the selected admissible
opening `I`, success/exhaustion, primary trial values and auxiliary/fallback
values, independently of tape and generator coins. Preserve those values and
the order/count of primary programming writes; compute each write's location
from that adjacent game's actual transcript material. Locations can differ
between games, and agree under the coupling when the supplied material agrees.
No auxiliary opening or extra challenge write is exposed on exhaustion.

For a fixed valid-proof invocation ordinal `j`, order its material slots as
follows:

1. The joint root slot.
2. Distinct marked non-root internal nodes in increasing heap index.
3. The selected leaf in each vector, in vector order.
4. The selected expanded row in each vector, in vector order.

A parent has a smaller heap index than its children. The selected path rank
or vector is fixed by the reduction; its actual node is computed from `I`
before material generation. Unused ranks are identity steps. Across invocations
use chronological order, including invocations that exhaust. A distinguisher
simulates the whole preceding and subsequent lifetime, not just a retained
commitment or successful proof.

The reductions construct the selected invocation with a symbolic challenge
coordinate from the outset. They do not splice an unknown key into an already
executed tree or public transcript. The projection keeps all public outputs,
adversary registers and oracle history, while omitting only unread private
root/key/raw-mask bookkeeping. The statement does not cover timing, OOM,
cancellation, secret getters or arbitrary repeated `Commitment::open` calls.

## 2. Independent parents are essential

Every step below enters after earlier replacement slots have become
**independent block outputs**, including their permutation-to-independent
switching step. Stopping at a random-permutation endpoint is insufficient:
two distinct 128-bit inputs cannot have equal permutation outputs, whereas
the halves of a uniform 256-bit child key agree with probability `2^-128`.
Consequently that permutation-derived child is not a fresh uniform AES key.

After the parent's 64-byte output is independent uniform, either 32-byte
child coordinate is uniform and independent of its sibling, parent key,
other generated coordinates and entering state. For a target child, sample
the sibling normally and represent the target by the primitive game's fresh
uniform key `K`. The unmaterialized parent output is mathematically the
concatenation of these two coordinates in their actual left/right order.

This is an exact reparameterization: the
[BAVC source](../crates/iroha_zkp_vole/src/bavc.rs) stores the two child keys;
it never hashes, compares or publishes the concatenated parent output as a
separate value. The parent's already-replaced slot no longer depends on its
AES key. All operations before the target's first use can run on the other
known coordinates. Numeric coincidences with `K` are not tested or excluded.

## 3. Marked internal-node hop

Let `v` be the target non-root marked internal node. Its parent is marked
and already replaced. Use the construction in §2 to place the challenge
handle in node `v`. With the actual IV, make four requests

```text
X(IV, v, c), c = 0,1,2,3,
X(IV,t,c) = LE32(a+c mod 2^32) || middle64 || LE32(z+t mod 2^32).
```

Concatenate the replies into the two child keys. `expand_node` is the only
direct computational use of this internal key. Later descendants use their
returned numeric keys. A marked slot is never serialized by the selected
opening: `revealed_nodes` emits only unmarked frontier children. The root's
separate high-mask use has already been handled jointly in the root hop.

The real challenge branch exactly matches the adjacent real-node game.
The permutation branch replaces only node `v`'s expansion. Switch its four
distinct replies to independent blocks before proceeding to any child hop.
With the root lemma's advantage convention,

```text
gap_path(j,p) <= ε_path(j,p; 4, Γ, R_B) + δ4,
δ4 = 1 - product(c=0..3, 1-c/2^128) <= 6/2^128.
```

This proof includes duplicate key bytes in different nodes, invocations or
roles. Other slots retain their prescribed adjacent-hybrid status; ordinary
unreplaced known-key operations still compute public AES. The real branch
agrees automatically on aliases among those operations and the designated
slot; in the permutation branch only the designated node slot changes.
No global key-indexed ideal cipher or equality test is introduced.

## 4. Selected affine-leaf hop and cache

After the path stage, the parent of selected leaf
`v = Shape::position(i,I_i)` has independent child outputs. Embed the unknown
key in that child coordinate as in §2. The selected leaf uses nine requests

```text
X(IV, L-1+i, c), c = 0,...,8.
raw = sd[32] || b0[96] || b1[16].
```

Apply the actual affine transformation with the actual stored H0 key:

```text
com = c0[96] || c1[16],
c0 = L_h0(sd) XOR b0,
c1 = low128(sd*h1) XOR b1.
```

[`LeafCommitter::commit`](../crates/iroha_zkp_vole/src/bavc.rs) implements
these operations. Cache `(sd,com)` on this first use. H1 consumes `com` in its
original vector position; the row expansion consumes `sd`. Neither is
resampled. Every other leaf retains its prescribed adjacent-hybrid status,
including earlier selected leaves already replaced. Unselected leaves and
both H1 levels remain actual computations, including existing oracle values
and equal-input correlations.

The successful opening recomputes this same source leaf with the same key,
IV, vector tweak and stored H0 key. Replaying the cache is therefore exact in
the real branch and required in the replaced branch. `LeafCommitter` stores
H0 at construction, so this cache does not omit a later H0 query. Oversized
openings return before leaf work; the proof loop stops at its first admissible
opening. The auxiliary opening on exhaustion is never exposed. The lemma
does not provide consistency for a new arbitrary opening pattern requested
through the low-level BAVC API.

Thus the primitive driver needs nine distinct classical challenge queries,
not a new nine-query draw at opening. Its bounds are

```text
gap_leaf(j,i) <= ε_leaf(j,i; 9, Γ, R_B) + δ9,
δ9 = 1 - product(c=0..8, 1-c/2^128) <= 36/2^128.
```

After this switching, the raw 144 bytes are independent uniform. For every
fixed actual H0 key, including zero components,

```text
(sd,b0,b1) <-> (sd,c0,c1)
```

is a bijection, with inverse given by the same XOR products. Therefore `sd`
and `com` are jointly independent uniform, conditional on the entering
state/H0 key. This conclusion requires the full independent-output leaf
endpoint; a uniform seed marginal alone is insufficient.

## 5. Selected expanded-row hop

At the independent leaf endpoint, use its bijection to sample `com` as an
independent 112-byte string and let the primitive challenge key occupy `sd`.
The inverse masks `b0,b1` are defined mathematically but need not be computed.
Their only uses were the affine calculation and the opening recomputation,
now represented by the same cached `com`. The unknown seed bytes are not
copied into the public opening or hashed by H1.

The seed's sole remaining use in this projection is
[`Instance::fold`](../crates/iroha_zkp_vole/src/vole/convert.rs): expand at
tweak `2^31+i`, using the actual IV and the **complete** `ell_hat` row.
Forward the `q = ceil(ell_hat/128)` block addresses and retain exactly the
specified output bits. Then run the ordinary fold and all subsequent VOLE,
CRT, H5, relation, transcript, retry and public-output computations.

| Row / role | `ell_hat` bits | Bytes | `q` | Last block bytes |
| --- | ---: | ---: | ---: | ---: |
| Candidate registration | 35,920 | 4,490 | 281 | 10 |
| Candidate vote | 53,584 | 6,698 | 419 | 10 |
| Comparator registration | 35,960 | 4,495 | 281 | 15 |
| Comparator vote | 53,624 | 6,703 | 419 | 15 |

[`ProofParams::ell_hat`](../crates/iroha_zkp_vole/src/params.rs) uses
`ell + 10*d0`. Even a shorter vector expands the full `d0`-based row;
shortening it to `ell + 10*d_i` would change the experiment. The tail supplies
the low-mask values and shares used by
[`VOLE::commit_as`](../crates/iroha_zkp_vole/src/vole.rs); replacing only the
witness prefix would not reach the independent-material endpoint.

All four lengths are byte-aligned. Distinct counters give distinct block
addresses even across low-word wrapping. The real branch is exactly the
adjacent real-row game; the permutation branch changes just this selected
row slot. Other slots retain their prescribed status, and unreplaced
numeric-key AES operations stay concrete. Hence

```text
gap_row(j,i) <= ε_row(j,i; q, Γ, R_B) + δq,
δq = 1 - product(c=0..q-1, 1-c/2^128)
   <= binom(q,2)/2^128.
```

The coefficients are 39,340 for registration and 87,571 for vote. As in the
root lemma, couple the distinct-input reply tuple and apply the same complete
continuation channel. Truncation, public AES under coincident keys and later
quantum oracle interaction cannot increase its distance. This does not permit
coherent requests to the private primitive challenge oracle.

## 6. Composition and endpoint

Induct on the ordered slots of §1. The root lemma establishes independent
child and high-mask coordinates. Each marked-node step maintains that
invariant and makes the next selected child eligible for the fresh-key game.
Each selected-leaf step supplies the independent raw tuple and then the
independent `(sd,com)` coordinates needed by its row step. Unmarked subtrees,
unselected leaves and revealed rows stay actual deterministic functions of
their numeric seeds and the unchanged primitives.

This reaches `FullMaterial/RealH5`: every marked internal expansion, selected
raw leaf expansion, selected expanded row and root high-mask coordinate has
the independent **per-slot** law stated in
[ideal-public-sampler §1](parliament_ballot_b6_ideal_public_sampler.md).
Repeated uses of the same slot are cached, and distinct slots may have equal
bytes. H5 is still evaluated by its real two-label rule for this material.
Its ordinary reads and corrections, all primary challenge writes and the
complete prior/future oracle history are retained, including on exhaustion.

This is the material entry for the later
[fixed-opening H5](parliament_ballot_b6_h5_fixed_opening.md),
[coordinate-change](parliament_ballot_b6_mask_coordinate.md) and
[deletion](parliament_ballot_b6_hidden_assignment_deletion.md) arguments.
It is **not yet** the direct public sampler's post-deletion response law.
Those conditional joins and their quantitative resources still require a
complete composition audit; no equality to the frozen real-root `Sim+` is
claimed.

For `r` frontier keys and `tau` selected leaves, the marked-tree identity is
`m = r+tau-1`, so the non-root path count is `r+tau-2`. Admissibility gives
`r <= T_open`, yielding the following safe slot ceilings; attainability of
the cap is unnecessary and not claimed.

| Row | Root | Non-root paths | Leaves | Rows | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Candidate | 1 | 260 | 33 | 33 | 327 |
| Comparator | 1 | 245 | 22 | 22 | 290 |

The total gap is the sum of the actual whole-lifetime primitive advantages
and switching losses for these adjacent drivers. One can pad every invocation
to 260 path ranks and 33 leaf/row ranks, with identity steps where absent,
for a deterministic ceiling across mixed rows and roles. `T` counts valid
proof invocations including exhaustion; invalid requests retain their
unchanged handling and still contribute to the driver's resource cost.
Do not choose an index from already observed challenge outputs or charge only
a successful request. A uniform switching bound for at most `T` invocations is

```text
δ_material <= T * [10 + 260*6 + 33*(36 + binom(419,2))] / 2^128
           = T * 2,892,601 / 2^128.
```

This is a separately derived additive switching term under the proposed
game. It neither replaces the published multiquery leaf term nor gets added
to the frozen PRP-native exponential factor as another charge for the same
transition. The differing interfaces in
[FAEST v3 Lemmas 10.24/10.51](https://faest.info/faest-spec-v3.0.pdf#page=90)
still require their own hypotheses; this note does not revise those theorems.

## 7. Executable correspondence

The [material-slot tests](../crates/iroha_zkp_vole/tests/material_slot_interface.rs)
compare the opaque nine-block leaf adapter with `leaf_commit_as`, exercise
the affine inverse with zero/nonzero H0 components and check cached commitment
projection. A separate selected-row adapter omits the selected seed, streams
the other known rows and uses an independent XOR fold. It agrees with
`convert_to_vole` in the real branch. A controlled reply change affects only
the selected row's index columns even when another known seed equals it.
`ProofParams::ell_hat()` supplies the full lengths for both rows and roles.

These finite tests do not execute the whole transformed prover, implement a
programmable quantum oracle or prove fresh entropy, the source-use census or
security. The [validation record](../docs/validation/parliament_ballot_material_entry/README.md)
retains the runs, scoped source hashes and the limits of local review.

**TODO:** quantify each complete driver resource vector and its AES advantage
under a justified or explicitly accepted primitive/QROM model; finish the
initial and later composition audit; reconcile the complete security ledger
and obtain independent attack-cost review. Component query counts, exact
local identities and source conformance tests cannot supply those premises.
Development testing remains enabled and binding production use remains gated.
