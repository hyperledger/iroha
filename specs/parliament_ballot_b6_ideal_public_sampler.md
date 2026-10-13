# B6 direct sampler for ideal public material

Status, 2026-10-13: **conditional exact sampler proposal, local consistency
reviews complete**. Two automated local reviews found no blocking issue
under the stated premises. These are not owner acceptance or independent
cryptographic review.
This note gives a bounded public sampler for the fully replaced material
endpoint retained by the frozen [mask-coordinate](parliament_ballot_b6_mask_coordinate.md)
and [hidden-assignment deletion](parliament_ballot_b6_hidden_assignment_deletion.md)
notes. It samples a canonical opening and runs the source reconstruction
algorithm. The resulting public material has the exact distribution of
that endpoint after unused private coordinates are discarded.

This defines a distinct simulator proposal, `IdealFrontierSim`. It is not
an equality to the real-root frozen `Sim+`, an adopted primitive premise,
or production qualification. The [driver proposal](parliament_ballot_b6_hybrid_driver.md),
[arguments](parliament_ballot_proof_arguments.md), ledger and earlier
receipts remain unchanged. A separate
[receipt](../docs/validation/parliament_ballot_ideal_public_sampler/receipt.json)
binds this note to the actual source and the selected endpoint definition.

## 1. The endpoint being sampled

Fix a valid request, its role/row, actual IV and an admissible selected
opening `I=(delta_0,...,delta_(tau-1))`. The opening is sampled independently
of the request's material coins by the existing bounded schedule. Retain
the entering adversary state and every oracle table, including all earlier
programmed challenge values. No IV or public hash key is made uniform here.

The full-replacement material endpoint has these precise rules:

- Mark each selected leaf and all its ancestors. For each marked internal
  node, including the root, its two child keys are one fresh independent
  uniform 64-byte output, cached by this invocation/node slot.
- At each unmarked internal node, compute the actual 64-byte AES generator
  expansion with its actual key, IV and heap-node tweak.
- At each selected leaf, its raw 144-byte expansion is fresh uniform and
  independent, cached by this invocation/vector/selected-leaf slot.
  Apply the actual H0-keyed affine leaf transformation. Other leaves use
  the actual generator and that same transformation.
- Selected expanded rows and the separate root high-mask output are the
  independent ideal coordinates of the preceding notes. They are no
  longer used by the public algorithm after its response-coordinate change
  and private-log deletion. Revealed expanded rows remain actual generator
  outputs from their revealed seeds.

Fresh outputs here are indexed by replacement **slots**, not by a global
map from key/IV/tweak bytes. Repeated internal use of one slot reuses its
cached output. Distinct slots can have equal key bytes; that event is not
conditioned away. The forward primitive reduction must justify this exact
endpoint, including byte-level aliases across invocations and roles. A
globally memoized ideal PRG, a without-replacement ideal permutation, or a
partial replacement state need not have this law. This note supplies no
embedding from those interfaces merely by naming slots.

For the equality below, condition on arbitrary fixed entering oracle
functions and their correlated adversary state. Each new slot output is
still independent of that state under the endpoint definition. The proof
therefore covers prior queries and degenerate public H0 values directly.

## 2. Frontier geometry and distribution

The source heap has internal nodes `0,...,L-2` and leaves
`L-1,...,2L-2`. Node `v` has children `2v+1,2v+2`. Its selected leaves are
the actual interleaved `Shape::position(i,delta_i)`, not a concatenation of
power-of-two trees.

Let `M` be the marked set, and `F` its frontier: the unmarked child of each
marked parent having exactly one marked child. Let `r=|F|`. The source
serializes `F` by decreasing parent index, selecting the other child as
`2*parent+1+left_is_marked`. The selected commitments precede these keys
in vector order.

The following graph facts hold for every admissible pattern:

1. A descendant of an unmarked node cannot be marked, because marking is
   closed under ancestors. The root is marked.
2. Every unmarked leaf has a unique first unmarked ancestor. That ancestor
   belongs to `F`. Thus the frontier subtrees are disjoint and partition
   exactly the `L-tau` unselected leaves.
3. Each frontier key is one child coordinate of a fresh marked-parent
   expansion. Different frontier nodes have different parents, since a
   marked parent cannot have two unmarked children. Their keys are
   therefore jointly independent uniform 32-byte strings.
4. All keys and leaf outputs inside a frontier subtree are deterministic
   functions of its frontier key, the actual IV and the actual primitive
   functions. Equal bytes or aliased primitive inputs preserve their actual
   correlations. They are not replaced by independent strings.

Joint frontier uniformity does not require distinct sampled keys. Zero
keys and duplicate keys are allowed and are evaluated normally. No
secret marked-node or root key is needed to expand these subtrees.

If `m` is the number of marked internal nodes, the marked induced tree has
`m+tau-1` edges. Its internal nodes contribute `2*m-r` marked child edges.
Hence

```text
m = r+tau-1,
unmarked internal nodes = L-tau-r.                            (S-1)
```

This identity also counts the real tree expansions needed by the sampler.

## 3. Selected commitments are uniform, with the actual H0 key

For the extended construction,

```text
H0_role(IV) = h0[96] || h1[32]
raw_i = sd_i[32] || b0_i[96] || b1_i[16]
c0_i = sd_i.mul_tripled(h0) XOR b0_i
c1_i = low128(sd_i*h1) XOR b1_i
com_i = c0_i || c1_i.                                        (S-2)
```

These are `LeafCommitter::commit`, `affine_check`, and
`universal_hash::leaf_hash` in the current source. For every fixed `h0,h1`,
the map `(sd_i,b0_i,b1_i) -> (sd_i,c0_i,c1_i)` is a bijection. Its inverse
keeps `sd_i` and XORs the same two products into `c0_i,c1_i`. It works when
either hash-key component is zero as well as for all other values.

Because `raw_i` is uniform under the specified replacement, `sd_i` and
the 112-byte `com_i` are independent uniform strings, conditional on the
actual H0 key and entering state. Different selected slots have independent
outputs. Their commitments are also independent of the frontier keys.

After the selected-row replacement, the selected seeds do not determine
any retained public row. After the mask-coordinate change and deletion,
neither those seeds nor selected-row/high-mask coins are read by a public
routine. Their remaining seed/affine-mask coordinates may therefore be
discarded. Sample `com_i` directly as 112 fresh bytes instead. This is
marginalization after a bijection, not a claim that a real leaf commitment
is uniformly random or that the hidden key can be reconstructed.

The global commitment is **not** sampled uniformly. It remains the two
levels of actual H1 evaluation over all selected and revealed leaf
commitments. Repeated H1 inputs, earlier queried points and actual hash
collisions retain their existing oracle values.

## 4. Direct material sampler

For fixed `I`, define `FrontierMaterial(role,row,IV,I)` as follows:

```text
Use the actual row shape and mark_hidden/revealed_nodes ordering.
Require the selected admissible pattern; r <= T_open.
For i=0,...,tau-1:
    sample com_i uniformly from 112 bytes.
For v in F in source opening order:
    sample K_v uniformly from 32 bytes, independently.
decom = com_0 || ... || com_(tau-1)
        || frontier keys in that order
        || 32*(T_open-r) zero bytes.

Reconstruct the public BAVC material with the exact algorithm of
bavc::reconstruct_as using this decom, I, namespace and actual IV.
Return decom and its reconstructed commitment/revealed seed cache.
```

The source first checks lengths, the pattern and zero padding, evaluates
H0 at the actual IV, fills the frontier-key slots, and expands only unmarked
internal nodes in increasing heap order. Each such node already has its
key from the opening or its earlier unmarked parent. It then visits
vectors and leaf indices in source order. Selected leaves use their
supplied commitment; other leaves execute the full actual affine leaf
calculation and produce their seed. H1 hashes each vector and then the
vector digests in vector order.

Selected seed slots are zero placeholders in `Reconstruction`; their
bytes are never expanded or treated as known seeds. A genuine revealed
seed whose bytes happen to be zero is still expanded normally. Hidden
reconstruction skips by selected index, not by testing seed bytes.

The canonical decommitment lengths are:

| Row | `tau` | `L` | `T_open` | Opening bytes |
| --- | ---: | ---: | ---: | ---: |
| candidate | 33 | 6,400 | 229 | `33*112+229*32 = 11,024` |
| comparator | 22 | 61,440 | 225 | `22*112+225*32 = 9,664` |

Only `32*r+112*tau` bytes are fresh material randomness; the unused key
slots are zero padding. This is not a uniform sampler of all byte strings
of the opening length.

For the full public protocol use **one** nested reconstruction: after
sampling the opening and canonical corrections, call the algorithm of
`vole::reconstruct_as`. It invokes the BAVC reconstruction above once and
then computes the revealed row folds, `Q,qbar,Delta` and the ordinary
visible H5 cache. Retain its commitment and outputs. Do not first run a
separate BAVC reconstruction and then silently omit the cost of the
duplicated pass. This is a mathematical algorithm under the entered oracle
interfaces; it is not an implemented programmable-QROM Rust API.

## 5. Exact kernel equality

Fix `I`, the entering oracle functions and state, the actual IV and all
other public coins of the request. Compare the full-replacement endpoint
of §1 to the sampler of §4.

By §2, replace the endpoint's complete marked-parent coin list by its
frontier-key projection: that projection has exactly the sampler's
independent uniform law. Other marked child coordinates and the root key
are unused by the public computation and can be marginalized. Couple
the two algorithms with the same frontier keys. Every unmarked descendant
key and revealed leaf output is then identical, including all correlations
from equal keys and actual generator input aliases.

Apply the bijection in §3 independently to selected leaf slots and couple
their `com_i` to the sampler's direct draws. Discard the unused selected
seeds and remaining private row/high-mask coordinates. Every leaf
commitment in the H1 vector input is now identical in the two algorithms.
The same H0/H1 functions and input ordering yield the same commitment and
revealed seed cache. The canonical opening bytes are identical.

Thus the two material kernels are exactly equal after projecting away
unused private coordinates. They do not have the same complete secret
root/tree state; the direct sampler does not retain one. This is not the
impossible bijection from one real 256-bit root to many independent keys
identified in the mask note.

The remaining source hidden-VOLE reconstruction is a deterministic
function of this common seed cache, the selected pattern, canonical
corrections, actual IV and ordinary H5 function. The hidden seed index is
skipped. Consequently `Q,qbar,Delta`, all cached visible H5 values and all
public response equations are identical under the coupling. Other-domain
query inputs and every programmed challenge location/value are identical
too. No overwritten value is restored and no earlier oracle history is
discarded.

Classical internal sampling may be reordered to realize this coupling:
for example direct commitments can be sampled before the H0 read, whereas
their affine-coordinate representation is defined using its result.
Uniformity holds for every fixed H0 value, and no adversary acts inside the
atomic request. This changes neither the public outputs nor the joint
oracle/adversary state. It does not permit a different order of published
requests or of programmed writes.

This proof works for arbitrary fixed entering functions and correlated
quantum adversary registers because the new slot coins are independent
and the coupled continuation is identical. Induction over classical
requests gives exact equality for the entire adaptive interaction and all
subsequent adversarial oracle/primitive queries. No post-query key entropy
or independence among deterministic revealed leaf outputs is asserted.

## 6. The bounded simulator proposal

Define `IdealFrontierSim` using the same public validation and relation
context as `IdealPublic` from the deletion note:

```text
On a valid public request (role,row,x):
    derive the actual namespace, mu and fixed relation dimensions;
    sample fresh iv_pre and salt and compute the actual H4-derived IV;
    run the existing bounded Schedule(row), obtaining primary Y_c,
        success/exhaustion, and admissible y_star;
    decode I from y_star;
    sample the canonical direct opening of section 4;
    sample canonical c_1,...,c_(tau-1), gate corrections and d;
    run one source-shaped VOLE reconstruction and cache its results;
    sample prescribed chall_1, chall_2, four consistency fields and
        six transmitted coefficients;
    derive Vtilde and A_0 from the public equations;
    program challenge 1 and 2 and EVERY attempted primary counter,
        in the unchanged order and at their exact resulting locations;
    on success, serialize the source proof with y_star and its counter;
    on exhaustion, return the same typed error without an opening;
    retain the persistent oracle state and erase unused local material.
```

There is no root, pad, application witness, selected seed, high-mask stream
or hidden H5 assignment in this simulator. Its H5 reads are ordinary. All
existing primary writes remain even when no proof is returned.

`Schedule(row)` draws at most `M=2^20` independent primary 256-bit values,
stopping at the first actual admissible challenge. After primary exhaustion
it draws at most `M` extra values and otherwise uses `0^256`. The separately
frozen zero-challenge evidence verifies the fallback for both rows and
roles (11 and 12 revealed keys respectively). Extra trials generate no
challenge writes; they select the private material for the exhausted
request. The same auxiliary value must be used through that request.

The equality in §5 holds for **every fixed admissible I**, so integrating
over this bounded schedule, including its fallback atom, gives exact
equality to the corresponding same-material `IdealPublic` baseline.
There is no success-probability factor or additional statistical slack in
this identity. It does not delete the conservative `sigma` retained in
the frozen ledger or change an earlier game's auxiliary schedule.

Scope of the interface is one selected opening per invocation. The
simulator does not offer later arbitrary `Commitment::open` requests on a
retained secret tree. Cached selected commitments are reused in H1 and in
the one returned opening. Re-running the real hidden-leaf calculation from
a fabricated root would be incorrect. Later public verification and
adversarial primitive/oracle queries are covered by the identical public
material and persistent interfaces.

## 7. Error and resource boundaries

For the fixed supported rows, every internally sampled byte string has the
required length. The schedule supplies an admissible pattern, padding is
zero, and gate corrections are canonical. Every 32-byte generator key and
GF(2^256) encoding is valid, including zero. The row's tree-tweak and buffer
shape bounds are already satisfied. Thus the reconstruction's structural
rejections are unreachable in this sampler. Invalid external requests
remain on the identical prescribed validation path before material
sampling. Private root consistency is not a new validation requirement.

The public equations use fixed, well-formed relation streams and canonical
field samples. They do not inspect application witness validity. The
sampler itself needs only public inputs; the comparison to the preceding
prover-derived endpoint retains that endpoint's valid-request premises.
Operating-system allocation failure, faults and timing leakage are not
modeled by this mathematical equality or its operation inventory.

For `n=L-tau`, `u=L-tau-r`, and `b=ceil(ell_hat/128)`, one material and
VOLE reconstruction has the following explicit operations:

| Operation | Count or input size |
| --- | --- |
| Fresh material bytes | `32*r+112*tau` |
| Actual internal tree expansions | `u`, 64 bytes and four AES blocks each |
| Actual revealed leaf expansions | `n`, 144 bytes and nine AES blocks each |
| Actual revealed row expansions | `n`, `ell_hat` bits and `b` AES blocks each |
| AES block evaluations for these expansions | `4*u+(9+b)*n` |
| Generator key constructions for these expansions | `u+2*n` |
| Affine/LeafHash transforms | `n`, with actual public H0 key |
| H0 evaluations | One, at actual IV, returning 128 bytes |
| H1 vector evaluations | `tau`, hashing `112*N_i` commitment bytes each, plus namespace/domain |
| H1 outer evaluation | One, hashing `64*tau` digest bytes, plus namespace/domain |
| Hidden-index small-VOLE folds | One per vector, on all `N_i` positions with selected position zero |
| Visible H5 evaluations | Exactly `n_mult`, cached once for this request |
| Further reconstruction | Source correction alignment, CRT matrix products, field lifting and public relation/hash equations |

The actual `ell_hat` values are 35,920/53,584 bits for candidate
registration/vote and 35,960/53,624 for comparator registration/vote.
Thus `b=281` for registration and `b=419` for vote in both rows. These are
source operation counts, not AES security estimates or quantum gate
counts. The source retains deterministic correlations between all actual
primitive calls; no ideal block sampling is used for these revealed calls.

The source-shaped implementation uses bounded logical buffers: the
canonical opening, `(2L-1)*32` key bytes and node flags during BAVC
reconstruction, `L*32` revealed-seed slots, then the VOLE columns and public
field vectors. The bounded schedule may store at most `32*M` primary bytes
for their later writes; auxiliary search needs only its current value and
selected result. These facts do not certify a whole-process memory peak.

There are at most `2*M` schedule trials per invocation. Each uses 32 fresh
bytes and the actual grinding/decode/opening-admissibility predicate, which
depends only on the fixed row and trial value. Public coins and relation
work, source key setup/field arithmetic, all transcript queries and
programming, oracle simulation/coherent access, retained lifetime state,
the adversary and final comparison must also be charged in a full resource
vector. No complete elementary-gate/time/memory vector is claimed here.

This exact sampler makes the post-deletion endpoint concrete and bounded.
It still needs owner/reviewer consideration as a **distinct public
simulator**. It does not resolve the computational entry or its actual-IV,
equal-input and quantum-resource obligations, and supplies no primitive
advantage or production qualification.
