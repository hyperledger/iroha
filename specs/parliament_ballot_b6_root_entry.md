# B6 conditional root entry

Status: **root-only reduction under a proposed primitive interface**. This
discharges the root-slot source-use and simulation obligation in
[hybrid-driver §4.1](parliament_ballot_b6_hybrid_driver.md), conditional on the
game stated below. It does not accept that game as a security premise, give a
numerical AES advantage, establish the other component hops, or qualify the
ballot. Development testing is enabled; binding production use remains gated.
The earlier hybrid-driver receipt remains a historical, unchanged artifact.

## 1. Experiment and scope

Fix a valid-proof invocation ordinal `j` in the shared, adaptive lifetime of
registration and vote requests. It is an ordinal fixed by the reduction, not
an invocation selected after observing secret material. Earlier requests run
on their prescribed side of the adjacent hybrid; all later requests and the
adversary's final computation are retained. If invocation `j` is never reached,
the two games coincide and the reduction makes no challenge requests.

At this invocation the root `K` is uniform in `{0,1}^256`, independently of
the entering classical/quantum state, oracle environment, request, witness
and other tape coordinates. This is an honest fresh-tape experiment premise.
The [caller-owned tape API](../crates/iroha_parliament_ballot_proof/src/proving.rs)
does not prove it: `fill_with` accepts a caller's RNG and `from_bytes` permits
reproducible tapes. Secret-derived reference FAEST tapes, repeated tapes,
caller-controlled roots and private-state inspection are outside this lemma.

The common environment `Γ` includes exactly the quantum oracle access and
programming operations required by the enclosing hybrid. The reduction must
be permitted to run those operations, either as a declared primitive-game
environment or through a separately justified simulation. This lemma does
not implement a coherent oracle with a classical table. It never observes,
copies or measures the adversary's private quantum registers.

The selected challenge interface is one private, classical forward oracle:

```text
EvalBlock(x[16]) -> y[16]
real:        y = AES256_K(x), for fresh uniform secret K
permutation: y = P(x), for an independent uniform 128-bit permutation P
```

Repeated inputs get the same answer. Public AES under any numerically known
key remains available, including quantum computation by the adversary where
the enclosing experiment permits it. There is no explicit `Reveal(K)` or
direct root-byte projection. This restriction does **not** forbid accidental
equal key bytes, an opened value equaling `K`, or adversarial key recovery.
Their benefit belongs in the primitive distinguishing advantage.

This clarifies “no disclosure of K” in hybrid-driver §5: it specifies the
interface, not a condition that all other key values differ from `K`.
The proposed chosen-input interface is stronger in its IV freedom than the
uniform-public-IV generator experiment in
[FAEST v3 Definition 10.7](https://faest.info/faest-spec-v3.0.pdf#page=79).
That published experiment does not supply the missing actual-IV embedding.

## 2. Source-use census and five inputs

For both supported 256-bit rows, the protocol-visible computation needs the
root through exactly two expansions:

| Source | Root use and retained result |
| --- | --- |
| [Ballot `ProvingTape::backend`](../crates/iroha_parliament_ballot_proof/src/proving.rs) | Copies tape bytes `0..32` into the private backend tape; pad, IV preimage and salt occupy disjoint coordinates. |
| [Backend `prove_bounded`](../crates/iroha_zkp_vole/src/proof.rs) | Computes the actual `H4_role(iv_pre || mu)` IV before passing the root to VOLE commitment. Later proof fields use commitment results, IV preimage and salt. |
| [VOLE `commit_as`](../crates/iroha_zkp_vole/src/vole.rs) | Passes the root to BAVC commitment and later to `Layout::mask_values`. |
| [BAVC `commit_as` / `expand_node`](../crates/iroha_zkp_vole/src/bavc.rs) | Copies the root into node zero and expands it at tweak zero into two 32-byte child keys. Every other tree expansion reads another node slot. |
| [VOLE `Layout::mask_values`](../crates/iroha_zkp_vole/src/vole.rs) | Expands the same root at `MASK_TWEAK = 0x7fffffff`, retaining `n_mask * w_grind` bits. |
| [BAVC `Commitment::open`](../crates/iroha_zkp_vole/src/bavc.rs) | Reads selected leaf keys and unmarked frontier keys, never the root slot. The secret `node_keys()` getter is outside the proof-oracle projection. |

An admissible opening selects one leaf in every vector. There is at least one
selected leaf, so its ancestors include marked node zero. Frontier revelation
emits an unmarked child of a marked node, not node zero. Selected leaves are
also distinct from the root (`L = 6,400` or `61,440`). Thus opening and leaf
recomputation need no direct root bytes. An opening failure reveals no keys.
Allocation, copying, erasure and secret debug/getter interfaces are not public
observations of this atomic proof game; no timing, cancellation, OOM or
runtime-fault equivalence is asserted.

Write the actual IV as `LE32(a) || middle64 || LE32(z)`. From
[`Prg::fill`](../crates/iroha_zkp_vole/src/prg.rs), the block address is

```text
X(IV,t,c) = LE32(a+c mod 2^32) || middle64 || LE32(z+t mod 2^32).
```

The selected root uses precisely

```text
x0..x3 = X(IV, 0, c), c = 0..3
x4     = X(IV, 0x7fffffff, 0).
tree   = EvalBlock(x0) || ... || EvalBlock(x3)   // 64 bytes
high   = low_bits(EvalBlock(x4), h)
h      = 80 for FAEST_256F; 60 for FAEST_256S.
```

Here `n_mask = 10`, and `w_grind` is 8 or 6 in
[`params.rs`](../crates/iroha_zkp_vole/src/params.rs). “Low bits” follows the
source byte order: take `ceil(h/8)` leading bytes and clear unused high bits
of the final byte. The 60-bit output therefore has its last high nibble zero.

These five inputs are distinct for **every** IV. The first four have distinct
low words modulo `2^32`; the fifth differs in its high word because
`0x7fffffff` is nonzero modulo `2^32`. This includes both kinds of word wrap.
There is no random-IV or collision-avoidance premise in this argument.

## 3. Exact root-slot simulation

The reduction runs the entire surrounding driver, representing only the
selected root slot by its oracle handle. It computes the actual H4-derived
IV, without overwriting H4 or sampling a substitute IV. At node zero it makes
the first four requests and stores the returned child bytes. Descendants,
leaf commitments and expanded rows then use the normal algorithms on known
bytes. At the later high-mask operation it makes the fifth request and
applies the exact projection above. It preserves all intervening operations,
opening retries, exhaustion and all subsequent requests and oracle accesses.

The private root copy in the tree/tape can be omitted because the source-use
census gives every observable dependency on it. No other code in this
projection compares, hashes, serializes or branches on those root bytes.
Repeated designated uses, if represented by the driver, reuse the same oracle
answers. This is a transformed mathematical driver, not a way to pass an
opaque key handle into the unmodified Rust prover.

With `EvalBlock = AES256_K`, its projected joint interaction is **exactly**
the adjacent real-root game. With `EvalBlock = P`, it is exactly the game
that replaces **only these designated root operations** by one random
permutation. “Projected” omits private root storage and includes all public
responses, the adversary's retained state and the common oracle environment.

To see why key aliases do not alter this equality, let a known descendant,
opened key, future root or adversarial candidate key have numeric value `k`.
The reduction evaluates public `AES256_k` normally, even when `k = K`; it
neither tests that equality nor conditions it away. In the real branch those
evaluations automatically agree with the challenge on equal block inputs.
In the permutation branch the designated root slot uses `P` while these
other operations still use public AES. That is exactly the specified adjacent
game. Replacing every equal numeric key globally would be a different game
and is not claimed. The later
[ideal public sampler](parliament_ballot_b6_ideal_public_sampler.md) likewise
uses replacement slots, rather than a global cache keyed by numeric key bytes.

If `B_j` is this complete driver and advantage means the absolute final
output-probability gap, then

```text
|Pr[H_real,j = 1] - Pr[H_perm,j = 1]|
  = Adv_AES256^(chosen-input,Γ)(B_j).
```

This equality defines the exact reduction, not a numerical upper bound on
AES. It is valid for the prescribed quantum continuation because both
branches use identical interfaces and algorithms outside the challenge.

## 4. Switching to independent root material

Let `N = 2^128`. Conditional on any entering state and actual IV satisfying
§1, the five distinct permutation replies are a uniformly ordered tuple
without replacement. Five independent uniform blocks form such a tuple
conditioned on having no repeats. Their full-tuple total-variation distance
is therefore

```text
δ5 = 1 - product(i=0..4, 1 - i/N) <= 10/N.
```

Couple those tuples to agree whenever the independent tuple has no repeated
block. All five addresses are fixed before the first reply, and only these
designated calls access the private challenge oracle, so this tuple coupling
also applies when the fifth call occurs later in the source schedule.
All intervening and later computation is the same continuation driven
by the supplied replies and common independent coins/oracles. It may use
those replies to select numeric AES keys, produce openings, update the QROM
or continue the quantum adversary. Applying that same channel cannot increase
the distinguishing distance. Projection to 64 tree bytes and 80/60 mask bits
also cannot increase it; the exact full-tuple distance is not asserted to be
the distance of the shorter public proof.

The independent-block branch yields two independent uniform 256-bit child
keys and independent uniform `h` high-mask bits. Unreplaced descendants are
still computed normally from those children. Consequently the root-only hop
satisfies

```text
|Pr[H_real,j = 1] - Pr[H_uniform-root,j = 1]|
  <= Adv_AES256^(chosen-input,Γ)(B_j) + δ5
  <= Adv_AES256^(chosen-input,Γ)(B_j) + 10/2^128.
```

There are at most `T` such root hops across the two roles together. A sum of
their bounds is conditional on this premise for every adjacent driver; it is
not an extra factor in the execution cost of one driver. The query count is
at most five, but its charged resources cover the **whole lifetime**, including
public AES/Keccak, validation, other proofs, quantum memory/access, QROM
implementation or declared oracle environment, advice and final comparison.
Post-deletion sampler costs do not price this earlier driver automatically.

## 5. Executable scope and remaining work

The [root-slot interface tests](../crates/iroha_zkp_vole/tests/root_slot_interface.rs)
check the adapter against source PRG outputs and retain controlled projection
and alias cases. They establish finite interface correspondence, not fresh
entropy, a quantum security theorem, source-wide noninterference or an AES
advantage estimate. The source-use argument and same-continuation argument
above are separate mathematical obligations, available for review.
The [validation record](../docs/validation/parliament_ballot_root_entry/README.md)
retains three passing tests per portable/accelerated-feature build and the
source bookends; it does not strengthen the lemma's assumptions.

**TODO:** assess or embed the proposed chosen-input/QROM primitive game;
complete its full resource vector and quantitative AES premise; establish
the path, selected-leaf and expanded-row key-handle reductions and their
composition with entry/programming/coordinate/deletion steps; obtain
independent cryptographic and attack-cost review. No accepted ledger number,
requirement weakening, profile selection or production activation follows
from this root-only result.
