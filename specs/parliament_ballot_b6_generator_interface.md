# B6 leaf-generator interface and outstanding reduction

Status, 2026-10-13: source-derived interface analysis and a limited algebraic
check; **no new primitive premise is accepted and no profile is qualified**.
This note makes the unresolved `epsilon_leaf` entry in
[arguments §8.4](parliament_ballot_proof_arguments.md) reviewable. It does not
replace the missing extended multi-hiding proof or the
[security review's](parliament_ballot_b6_security_review.md) unknown bounds.
The candidate and comparator are both covered as implementations; a theorem
for one row is not silently transferred to the other.

## 1. Exact implemented primitive and call matrix

[Prg::fill](../crates/iroha_zkp_vole/src/prg.rs) reads the IV as a low
little-endian 32-bit word `a`, unchanged middle eight bytes `m`, and high
little-endian 32-bit word `z`. For a 32-byte key `K`, define

```text
X(IV,t,c) = LE32(a+c mod 2^32) || m || LE32(z+t mod 2^32)
G9(K,IV,t) = AES256_K(X(IV,t,0)) || ... || AES256_K(X(IV,t,8)).
```

`G9` is exactly 144 bytes, without truncation. The generator receives no
role prefix, proof salt, `mu` or `H0` output. Those values influence other
parts of the protocol; they must not be inserted into this PRG when stating
an assumption. The [extended leaf implementation](../crates/iroha_zkp_vole/src/bavc.rs)
uses `G9` as follows:

```text
H0_role(IV) = h0[96] || h1[32]
G9(K,IV,t) = sd[32] || b0[96] || b1[16]
c0 = LeafHash(h0, sd || b0)
c1 = low128(sd * h1 in GF(2^256)) XOR b1
com = c0 || c1.
```

The field encoding and low-coordinate projection are those in `bavc.rs`;
`LeafHash` is the additive-mask operation in
[universal_hash.rs](../crates/iroha_zkp_vole/src/universal_hash.rs).

| Implemented quantity | Candidate | Comparator |
| --- | ---: | ---: |
| Vectors `tau` | 33 | 22 |
| Vector sizes `N_i` | 17 of 256, then 16 of 128 | 8 of 4096, then 14 of 2048 |
| Total leaves `L` | 6400 | 61440 |
| Largest vector `N_0` | 256 | 4096 |
| Leaf tweak for vector `i` | `6399+i` | `61439+i` |
| Leaf output / public commitment | 144 / 112 bytes | 144 / 112 bytes |

For every leaf `(i,j)`, the key is the GGM node key at
`BAVC.PosInTree(i,j)`. All leaves in vector `i` use the **same tweak**
`L-1+i`, with their respective tree-derived keys. The real call matrix is
therefore many correlated keys with one fixed vector tweak, not one secret
key with `N_i` distinct tweaks. The prover's `BAVC::open` recomputes a hidden
leaf's same deterministic output; it does not draw fresh leaf randomness.
The verifier instead uses the hidden commitment supplied in the opening.
A simulator that substitutes that output must reuse the same replacement.

After the leaf step, the hidden seed `sd` is the key for its expanded VOLE
row, under tweak `2^31+i` and the same IV. The output lengths are 35,920 /
53,584 bits for candidate registration / vote, and 35,960 / 53,624 bits for
the comparator. This use is correlated with the leaf output. It must be
simulated before a separate row-expansion hybrid is charged; the two
generator advantages cannot simply be merged or one omitted.

## 2. Checked primary-source interface

[FAEST v3.0, Definition 10.7](https://faest.info/faest-spec-v3.0.pdf#page=79)
samples one secret key and one uniform public IV, then permits repeated
tweak queries. Its real oracle evaluates the PRG. Its PRP ideal caches
blocks sampled without replacement globally; its PRF ideal caches
independent strings. Repeated tweaks return the cached answer. The
distinguishing convention is `abs(2 Pr[correct guess]-1)`.

[Lemma 10.24, G2](https://faest.info/faest-spec-v3.0.pdf#page=93)
charges `AdvPRP(PRG_4lambda)[N_i]`, upper-bounded using `N_0`; its FAEST
leaf term also includes a separate expanded-row advantage. The commitment
experiment presamples admissible hidden positions. The proof's one-query
root/path terms do not change the stated leaf-query count.

[Lemma 10.51](https://faest.info/faest-spec-v3.0.pdf#page=134)
addresses quantum oracle access in that multi-hiding experiment. It does
not state the ballot's salted `H5`, affine leaf or bounded-counter
adaptation. These sections were inspected on 2026-10-13; this is not a
full independent cryptographic review.

## 3. Fully specified benchmark games, not adopted assumptions

The following reference games instantiate a nine-block leaf oracle. They
provide precise interfaces against which a proposed reduction can be
checked. Neither game supplies a concrete AES bound, and neither is declared
to be the unresolved ballot experiment merely by naming it.

`Leaf9-F(q_leaf)` has the following classical request interface. The
distinguisher may perform quantum computation between requests; requests
and replies in this version are classical.

1. Sample `K` uniformly from 32 bytes and `IV` uniformly from 16 bytes,
   independently of initial advice; disclose only `IV`. Fix hidden bit `b`.
2. Permit at most `q_leaf` requests `Eval(t)`, with `t` a 32-bit integer.
3. If `b=0`, return `G9(K,IV,t)`. If `b=1`, sample a uniform 144-byte
   `R[t]` on its first request and return that same value on every repeat.
4. Output the distinguisher's bit. Advantage is the absolute difference
   between its probabilities of outputting one in the two branches.

`Leaf9-P(q_leaf)` changes only the ideal branch: on a new tweak, sample nine
128-bit blocks successively without replacement from the set unused by
**all previous new-tweak requests in this game**, concatenate and cache
them. Different games do not implicitly share that exclusion set.

For a fixed IV, distinct tweaks give distinct high words; counters `0..8`
give distinct low words even across wraparound. Thus a classical invocation
with `d` distinct tweaks evaluates exactly `9d` distinct AES inputs under
this key. A repeated `Eval(t)` is a replay, not nine fresh ideal draws.
An ideal-table coupling between these two classical interfaces can fail
only when sampling with replacement repeats a block, giving the union
bound `min(1, binom(9d,2)/2^128)`. This statement is about the two specified
ideal tables, not concrete AES or the complete quantum ballot experiment.

A coherent variant must be named separately: define fixed functions first
and provide a specified reversible oracle, for example
`|t,y> -> |t,y XOR O(t)>`. A classical lazy-sampling description alone
does not specify how to implement quantum requests, count inverse queries,
or compose accesses with the rest of the reduction. No coherent-query
switching bound is inferred from the preceding classical coupling. The
required reduction must say whether it makes only classical leaf requests
inside a quantum environment, or needs this stronger oracle interface.

The benchmark's initial advice is independent of its sampled key and IV.
AES is a public algorithm: evaluating it, including coherently, is permitted
with its computation charged. Any additional ideal-AES or random-oracle
interface, preprocessing or auxiliary state needs an explicit joint
distribution and resource accounting.
In particular, an arbitrary correlated setup cannot be added for free.

## 4. Two source-level facts that can be established locally

**The leaf transformation is reversible.** Let `L_h0(sd)` be the first
term of `LeafHash(h0,sd||b0)`, before adding `b0`. For every fixed public
`h=(h0,h1)`, define

```text
Phi_h(sd,b0,b1) = (sd, L_h0(sd) XOR b0, low128(sd*h1) XOR b1).
```

The inverse retains `sd` and XORs the same two masks into `c0,c1`.
Consequently, if the entire 144-byte input is uniform independently of
`h`, `(sd,c0,c1)` is uniform, with independent components, conditional on
`h`. Both directions are efficient. This establishes the local
postprocessing fact used by the proposed leaf hop. It does not establish
pseudorandomness of `G9`, the independence of its input from the prior
transcript, or uniformity after sampling blocks without replacement.

**Arbitrary-IV independent-output strengthening is false.** For a fixed
key, let `IV'` preserve `a,m` and replace `z` by `z+1 mod 2^32`. Set
`t'=t-1 mod 2^32`. Then, for all nine counters,

```text
X(IV',t',c) = X(IV,t,c), so G9(K,IV',t') = G9(K,IV,t).
```

A putative ideal function that returned independent 144-byte strings for
these two distinct `(IV,t)` pairs would be distinguishable by equality,
with gap `1-2^-1152` using two classical requests. This is an interface
counterexample, not an attack on the ballot: its IVs are derived through
`H4` and proof roots are freshly sampled. It rules out treating arbitrary
IV/tweak pairs as independent labels under one key. A multi-IV game must
restrict its admissible inputs or preserve the actual AES-input aliases.

## 5. Required ballot embedding and acceptance checklist

Write `Gamma` for the complete surrounding quantum experiment, including
both proof interfaces, past state, all oracle domains, chosen `mu`, sampled
`iv_pre` and salt, opening positions, failure handling and future queries.
The source computes an IV through `H4(iv_pre || mu)` in the role namespace.
It does not specify a proof that embeds that IV and `Gamma` into the
benchmark's fresh uniform-IV experiment.

The needed adjacent games select an invocation and hidden vector position,
enter the *already justified* root/path hybrid, and differ only by replacing
that hidden leaf's 144-byte generator result by a consistent ideal result.
They continue the same `Gamma`, including later openings, expanded rows,
the public commitment hash, salted `H5` and all subsequent adversarial
accesses. This describes the required transition; the existing documents
do not give the complete driver that realizes it. In particular, the
entry hybrid is a premise to prove, not an operation available in production.

An author of that driver and an independent cryptographic reviewer must
resolve every row below before assigning `epsilon_leaf` a game and value.

| Obligation | Required evidence; current disposition |
| --- | --- |
| Key placement and auxiliary state | Specify how the challenge key is embedded at a hidden GGM leaf, every use of it, and the joint law of all other keys and state. Establish fresh independence where claimed; do not condition away key collisions or disclosures without a loss. Open. |
| IV placement | Match fixed uniform IV to the `H4`-derived value and its prior/future quantum oracle state, or state and justify a different IV game explicitly. Open. |
| Query mode and count | Exhibit `B_(invocation,vector)` and its complete request trace. Distinguish one key / many tweaks, many keys / one tweak, repeated calls, and coherent requests. `N_i` is the cited upper bound; code having one leaf call is not a proof that the reduction has one oracle request. Open. |
| Output visibility and consistency | Supply the exact public/private projection. The driver may receive `sd` internally but must not reveal it as an extra adversarial interface. Recomputed hidden commitments must use the same replacement; unknown-key uses outside this projection must be simulated. Open. |
| Selective opening and retry composition | Prove entry into the prescribed opening-position distribution in the salted, bounded-counter simulation, with failed/exhausted calls and future transcript/oracle state. Do not assume it for real Fiat–Shamir challenges. Open. |
| Row expansion and other keys | Preserve the use of leaf-derived `sd` in the row generator, shared-IV correlations, joint root/high-mask use, and repeated keys/IVs across invocations and roles. Identify which later hop charges each change. Open. |
| Leaf algebra | The conditional bijection in §4 is available. Applying it requires uniform raw bytes conditional on the actual hash key and surrounding state. That premise remains open. |
| Resources | Charge all emulation, public primitive work, future queries, oracle-state maintenance, quantum/classical memory, advice and preprocessing. A transcript count or nine-block label is not this resource vector. Open. |
| Ledger form | Choose and justify direct-to-uniform loss accounting or a PRP-native multiplicative transition, then propagate it through every game. Do not combine the additive switching charge with a multiplicative factor for the same change. Open. |

There is a limited reduction principle: if a simulator can generate the
whole surrounding state independently of a fresh hidden key, use that key
only through one `G9` reply, and continue using only that reply, it can
forward one benchmark query and perform the same continuation. Its final
distinguishing gap is then a one-query benchmark gap, with the simulator's
full resources charged. This follows by identical execution in each
branch. The actual ballot IV, state and hidden-key-use conditions have not
been established by that principle. It therefore does not authorize the
smaller `binom(9,2)` charge in arguments (96).

For a multiquery driver, the minimum declaration is
`(q_leaf, query mode, IV law, key/auxiliary-state law, all other oracles,
full resource vector, ideal table, public/private projection)`. The current
label “correlated nine-block leaf experiment” omits these fields. Naming
the reference games above does not fill them. No numeric primitive bound,
newly accepted assumption, complete multi-hiding theorem or independent
review is claimed by this document.

## 6. Envelope accounting and current engineering order

The earlier sequencing treated complete envelope sizes as a preselection
requirement while deferring production schemas until after selection. The
owner's 2026-10-18 authorization in the
[ballot design](parliament_private_ballot_design.md) §12.2 resolves that
engineering order: implement and test the actual canonical schemas alongside
B6, then include their full framing, decoding, copying and verification costs
in the qualification evidence.

This authorization does not waive item 5, resolve the missing cryptographic
premises or establish selection. The standalone inventory alone does not
certify complete envelopes. Independent review, complete accounting and the
owner's qualification record remain required before binding production
activation; they do not prevent schema or integration engineering.
