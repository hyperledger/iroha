# B6 conditional initial challenge programming

Status: **conditional QROM derivation, not qualification**. This supplies
explicit real-prover entry adapters for the three challenge-programming steps
used by the [bounded driver](parliament_ballot_b6_hybrid_driver.md). It joins
the [post-entry composition](parliament_ballot_b6_conditional_composition.md)
without replacing its endpoint or its frozen arithmetic record. Fresh honest
tapes, the backend-domain model, full reduction resources and independent
review remain requirements. Development testing is enabled; binding production
activation remains gated.

The [entry calculator](../scripts/parliament_ballot_initial_programming.py)
and [validation record](../docs/validation/parliament_ballot_initial_programming/README.md)
are separate from the earlier ledger. They evaluate the conditional terms
below, not AES advantages or a complete application-security bound.

## 1. Common experiment and exact domains

Use the same valid-witness experiment, atomic classical requests, whole-lifetime
quantum continuation and observation boundary as the post-entry note. Let `T`
bound valid invocations, including exhaustion, across both roles and rows.
`Q_all` counts every non-prover combined backend evaluation: preprocessing,
interleaving, verification, permitted public diagnostics, relevant invalid-input
checks and access after the final proof. Additional honest calls outside the
prover are included there, not silently omitted. Invalid requests follow the
common outer path and do not consume a programming instruction.

The application witness may be adaptive, repeated or known. Each valid request
has an undisclosed uniform independent 112-byte tape `(root, iv_pre, pad, salt)`.
The source [`ProvingTape`](../crates/iroha_parliament_ballot_proof/src/proving.rs)
delegates randomness to its caller; neither `from_bytes` nor `fill_with` proves
this distribution. Wrappers may read the pad while forming a witness before
checking it. No argument here depends on a claim that invalid inputs never
touch tape bytes: the mathematical outer validity check and atomic interface
determine the experiment.

Retain actual public digests and `IV = H4(iv_pre || mu)`. No IV replacement,
`H3` hybrid, key-distinctness condition or salt-collision exclusion is made.
The designated backend domains are independent QROM base functions with
persistent adaptive overwrite semantics. This is a model premise, not a
claim about concrete SHAKE. Fixing non-target base functions below leaves
their adaptive overlays and the environment running normally; it does not
condition on a future programmed table or transcript.

The actual encodings are those of
[`transcript.rs`](../crates/iroha_zkp_vole/src/transcript.rs) and
[`hash.rs`](../crates/iroha_zkp_vole/src/hash.rs):

```text
X1   = PREFIX || mu || com || corrections || mult_corrections
             || iv_pre || salt || 09
X2   = PREFIX || C1 || u_tilde || v_tilde || d || 0a
X3,c = PREFIX || C2 || a0 || ... || a6 || LE32(c) || 0b
```

All four role/row prefixes have 77 bytes and are distinct. Both rows use
264-byte `C1`, 104-byte `C2` and 32-byte `C3`. The lengths are:

| Row / role | `X1` | `X2` | `X3,c` |
| --- | ---: | ---: | ---: |
| Candidate registration | 144,494 | 5,078 | 410 |
| Candidate vote | 215,150 | 7,286 | 410 |
| Comparator registration | 95,204 | 5,078 | 410 |
| Comparator vote | 141,572 | 7,286 | 410 |

Thus each target is a finite syntactic domain, with no heuristic parsing.
For `X3,c`, `C2` occupies `[77,181)`, coefficients `[181,405)`, the counter
`[405,409)` and suffix byte 409. Wrong lengths/prefixes, other domains and
other counters are retained outside the target. The four namespaces can be
one disjoint-union target because the output length is common within each
challenge family; there is no additional role multiplier.

## 2. The reprogramming interface and query convention

Use [GHHM, arXiv:2010.15103v2, Figure 2 and Theorem 1](https://arxiv.org/pdf/2010.15103v2#page=6).
An instruction samples `(X,X')` from a supplied joint distribution and, in
one experiment, overwrites the target value at `X` with fresh uniform `Y`.
It returns `(X,X')`, **not `Y`**. The distinguisher subsequently queries `X`
once to obtain the ordinary or refreshed challenge. Its whole continuation
belongs to the distinguishing experiment.

For `F(q,p) = sqrt(q*p) + q*p/2`, the theorem sums `F(qhat_r,pmax_r)` over
instructions. `pmax_r` is the expected maximum of the marginal location law
chosen at that instruction; it is not conditional entropy after disclosure
of the auxiliary output. The samplers below operate on retained classical
control state and fresh coins without examining the adversary's quantum
registers. Prior target-oracle correlations are retained.

Use the same conservative dispatcher as the H5 note: reversibly parse a
combined address, query the selected target into an ancilla (use a fixed
dummy target address on other branches), copy its answer under the selection
mark, query again to erase the ancilla, and undo parsing. The other domains
are served from their own retained functions/overlays. This costs at most
two target calls per combined external evaluation, without free controlled
oracle access. A direct classical honest target read costs one.

Each reduction below has at most one such honest target read per valid
invocation. Consequently every prior-query count is safely bounded by

```text
qhat <= 2*Q_all + T.                                             (I-1)
```

No prover-side verification/reconstruction pass is inserted. Any surrounding
verifier is counted in `Q_all`. Other-domain calls, parsing, auxiliary state,
oracle realization and every computation still cost resources; (I-1) is not
a resource-vector certificate. In particular, hardwiring independent base
functions for an information-theoretic proof is not a finite-cost simulator.

For a formulation requiring exactly `T` instructions, first run the complete
permitted continuation and save its final measured bit. Pad missing instructions
with uniform fresh salt-, `C1`- or `C2`-containing dummy locations in the target
domain, without subsequent oracle reads, then return the saved bit. The same
marginal ceilings apply. This changes neither bit distribution nor the query
count. It is proof padding after observation, not a protocol write, terminal
oracle-table equality or implemented resource claim.

## 3. Challenge 1: real challenges to fresh programmed `C1`

Let `G1` be the actual fresh-tape prover with its tape coordinates exposed
only to the mathematical driver. This is an exact reparameterization of the
real game. `G2` instead draws uniform `C1`, writes it at `X1`, and uses it
locally; all other operations and oracle history remain real.

For one whole-lifetime comparison, target the `09` domain across all four
namespaces. At each valid request, before drawing its tape, supply this
joint sampler:

```text
draw fresh uniform (root, iv_pre, pad, salt)
form the actual padded witness and the actual IV
compute the actual BAVC/VOLE commitment, including salted H5 values
form X1; return (X1, private tape/commitment/continuation state)
```

Commitment generation uses other domains, public AES and arithmetic; it
does not query `09`. Independent non-target base functions can be fixed
while their existing overlays remain part of the retained state. For every
fixed entering control state and such functions, a complete `X1` specifies
its 256-bit salt. Hence `max_x Pr[X1=x] <= 2^-256`, even though the gate
corrections depend on salted H5. No conditioning on sampled salt, commitment
fields, success or subsequent observations is used. The actual sampler is
forward-defined; its private auxiliary state is not a new adversary API.

After the instruction, query `09` at the returned location once, obtaining
the existing challenge in the unrefreshed game and a fresh uniform challenge
in the refreshed game. Continue the source through final observation.
These are `G1` and `G2` respectively, including exhaustion and future access.
Repeated locations are ordinary chronological overwrites handled by the
theorem. Therefore

```text
Adv(G1,G2) <= T * F(2*Q_all+T, 2^-256).                         (I-2)
```

## 4. Challenge 2: fresh `C1` inside the location sampler

`G3` additionally draws uniform `C2` and writes it at `X2`. Target the `0a`
domain. For a valid request, retain its real tape, witness and commitment,
but do not yet draw its fresh programmed `C1` or install its `09` write.
Inside the location instruction, draw `C1` uniformly, compute the ordinary
VOLEHash responses and `d = witness XOR u`, and return `X2` plus the private
continuation state and pending `X1 -> C1` assignment.

Every `X2` specifies all 2,112 bits of this fresh `C1`. Thus the maximum
marginal mass is at most `2^-2112` for every retained pre-sampler state.
The intervening source operations are field algebra and byte encoding:
[`VoleHasher`](../crates/iroha_zkp_vole/src/universal_hash.rs) parses the
supplied challenge instead of reading `09` or `0a` again.

After the instruction, obtain `C2` with one target read and install the
pending `09` write, then continue normally. The assignment and target
operation commute because their complete domains are disjoint, and no
adversarial access occurs between them. Collisions with earlier `09`
entries still overwrite in the same order within that domain. The public
output and persistent functional oracle at the atomic boundary agree with
`G2` or `G3`; no physical log-order or timing equivalence is asserted.
Consequently

```text
Adv(G2,G3) <= T * F(2*Q_all+T, 2^-2112).                        (I-3)
```

## 5. Challenge 3: global counterwise hybrids

Put `M = 2^20`. Define `H_c`, `0 <= c <= M`, over the **whole lifetime**:
challenges 1/2 are fresh programmed; every reached counter `r<c` receives a
fresh uniform programmed value; every reached `r>=c` reads the ordinary
challenge-3 oracle. Preserve real material, the first successful opening,
all attempted writes and the bounded exhaustion error. Then `H_0=G3`, and
`H_M=G4` where every attempted counter is programmed. The hybrid index is
fixed globally, not selected after observing a request's successful counter.

For adjacent `H_c,H_(c+1)`, target only the counter-`c` subdomain. At each
valid request:

1. Run real commitment construction, challenge 1, consistency responses and
   `d`, stopping before drawing or programming `C2`.
2. Privately draw the already-programmed values for counters `<c`, testing
   their row-specific admissibility. If an earlier one succeeds, finish the
   request with the ordinary fresh `C2`, coefficients and required writes;
   this request needs no target instruction.
3. Otherwise, inside the target location sampler draw fresh uniform
   832-bit `C2`, compute the seven QuickSilver coefficients from the retained
   witness/material and `C2`, and return `X3,c`. All coefficient computation
   is algebraic. The complete returned location contains `C2` and all
   coefficients, so no conditional auxiliary inversion is needed.
4. Recover those fields from `X3,c`, apply the pending challenge-2 and
   earlier-counter assignments, and query the target at `X3,c` once.
   The returned value is ordinary in `H_c` and fresh programmed in
   `H_(c+1)`. Test its admissibility and resume the actual later counter loop.

Reaching `c` depends only on earlier independent samples and fixed row
geometry. It is independent of the current `C2`, which is not sampled until
step 3. Every full target location specifies that `C2`, so its maximum
marginal probability is at most `2^-832`, also conditional on reaching `c`.
Retained material can be correlated with previous target-oracle queries;
that does not change the fresh coordinate's law. Do not condition on the
deferred `0a` or earlier-counter writes: they would reveal this coordinate.

The source's retry paths support this scheduling.
[`decode_challenge`](../crates/iroha_zkp_vole/src/bavc.rs) rejects nonzero
grinding bits directly. Otherwise `mark_hidden` computes opening size from
the decoded indices and fixed tree. `Commitment::open` returns
`OpeningTooLarge` before leaf recomputation when the cap is exceeded.
Neither failure reads a pending challenge entry. Successful opening work
is performed only after the source's first admissible value. The
[`prove_bounded` loop](../crates/iroha_zkp_vole/src/proof.rs) retains all
attempts and returns exhaustion after counter `M-1`, without wrapping.

Deferred writes can collide with past entries, but their complete domains
(`0a` and counters `<c`) are disjoint from target `c`. Their functional
overwrites commute with the target operation. Writes within any one domain
remain chronological; later counters stay ordinary in both adjacent games.
This is not an equality of physical append-log order. Any concrete coherent
log realization must separately implement the required logical state and
charge its preparation, update and cleanup costs.

There are at most `T` target instructions and direct target reads per fixed
counter. A query spanning counters is charged in every separate reduction,
so the triangle inequality gives

```text
Adv(G3,G4) <= min(1, T*M*F(2*Q_all+T, 2^-832)).                (I-4)
```

This does not reassert fresh `C2` entropy at consecutive attempts of one
execution: each fixed-counter comparison uses its own pre-`C2` sampler cut.

## 6. Entry into `B_0` and composition

In `G4`, primary counter values are independent uniform draws, and
admissibility depends only on their values and the fixed row. Presampling
them before material generation preserves the entire primary sequence,
first-success/exhaustion result and their later exact write locations.
The driver's bounded auxiliary search and the separately
[verified zero fallback for both rows](../docs/validation/parliament_ballot_zero_challenge/README.md)
can be added on exhaustion at zero observable cost: that opening remains
private unused bookkeeping in real-material `B_0`. It adds no primary
attempt, opened commitment, hash or challenge write. No acceptance-probability
factor or exhaustion approximation is required.

Combining (I-2)--(I-4), define

```text
q = 2*Q_all + T
E_entry_raw = T*F(q,2^-256) + T*F(q,2^-2112) + T*2^20*F(q,2^-832)
E_entry = min(1, E_entry_raw)
Adv(RealProver,B_0) <= E_entry.                                (I-5)
```

There is no extra role, key/IV/salt-collision, `mu`, `H3` or exhaustion term
in this derivation. The final allowed observation and all prior history are
the same at every join. Substituting this **conditional** entry component
into the separately derived post-entry chain gives

```text
Adv(RealProver,IdealFrontierSim) <= min(1, E_entry + E_AES + K),  (I-6)
```

where `K` has exactly the definition of the post-entry note. `E_AES` and its
whole-lifetime resource vectors remain unquantified. The target is the distinct
public frontier simulator, not frozen real-root `Sim+`. Dependent anonymity,
authorization and other application-property reductions still need explicit
reconciliation with this endpoint and bound.

## 7. Arithmetic and limits

The separate entry helper uses rational dyadic square-root enclosures with
400 bits of relative resolution, so the tiny challenge-2 term is not rounded
up to the previous helper's absolute decimal grid. For `x=n/d>0`, compute
`e=floor(log2(x))` by bit lengths and exact comparison, set
`b=max(0,400-floor(e/2))`, and take `k=isqrt(floor(n*2^(2b)/d))`.
The interval is `[k/2^b,(k+1)/2^b]`, collapsed only when
`k*k*d = n*2^(2b)`. Its width is at most `2^-400*sqrt(x)`; zero is exact.
No floating-point operation determines an endpoint or clipping decision.

The report encloses these formula contributions and their sum with the
frozen helper's post-entry `K`. Its lower endpoint is not an adversary-advantage
lower bound. It keeps AES advantages and full resources unknown, and always
refuses qualification. A later derivation of an entry term does not rewrite
the earlier receipt that correctly left it unknown at that checkpoint.

**TODO:** certify full source-to-game and coherent-oracle resource realization;
supply justified or explicitly accepted quantitative primitive/model premises;
reconcile dependent application reductions and the complete concrete ledger;
obtain independent cryptographic/implementation and attack-cost review. These
mathematical adapters exclude timing, OOM, cancellation, malformed generated
internal material and arbitrary caller-selected tapes. Source/test evidence
has its stated finite scope; no full Rust refinement or native qualification
is supplied by this note.
