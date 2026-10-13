# Local zero-knowledge argument for KAGEMUSHA public proofs

This implementation-coupled argument establishes a bounded local lemma for the
public sigma and Omega PIPA-R proofs in an ideal scalar-mask, normalized
transcript random-oracle model. It does not close the joint recursive privacy
gate C12. Current-key admission, concrete randomness fidelity, recursive source
composition and public outcome projection remain separate obligations in the
[recursive construction argument](kagemusha_recursion_soundness_v1.md#composition-keys-and-disclosure).
No production sampler, proof format or accepted security assumption changes.

The relevant implementation is the [prover](../crates/iroha_plonk/src/prover/mod.rs),
[opening proof](../crates/iroha_plonk/src/pcs/ipa/prover.rs), and
[actual-key mask checker](../crates/iroha_core_zk/src/kagemusha_wallet_artifacts_v1/producer_inventory/compiler/full_catalog/mask_boundary.rs).
The local derivation and the explicit 255-bit bounded-sampling clarification
passed an independent source and algebra review; this is an engineering
argument, not an external cryptographic audit or current-artifact qualification.

## 1. Exact local experiment and theorem

Fix an admitted current indexed key K with prime-order curve group G of order r,
nonidentity W, public preprocessing, Direct instances, a>=1 advice columns and
the reviewed predicate M(K). This is a checkable condition on this actual key,
not acceptance of historical descriptors. Let B be its base-field order and
mu:F_B->F_r the actual challenge map. Set lambda=max_t Pr[mu(U_B)=t]: Omega
(Pallas) has r=q,B=p,lambda=1/p; sigma (Vesta) has r=p,B=q,lambda=2/q.

For n=2^k, blinding factor b and usable extent u=n-b-1, M(K) means
the actual admitted descriptor, fixed tables and permutation tables satisfy:

- Boundary gate expressions are independent of masked advice cells, and vanish
  on masked rows. Usable lookup expressions are also independent of those cells.
  Fixed tails are zero and permutation tails fix their own row/column identities.
- The actual S7 opening plan has positive residual masking rank after every
  distinct disclosed rotation and x3. Fresh dimensions are b+1 for advice and
  sorted lookup polynomials, b for products, and n for R. Product[u] stays fixed.
  Repeated queries reuse their value; distinct rotations cannot alias modulo n.
- The unique quotient h and unique R share exactly rotation zero. R is globally
  last in the actual forward Horner order and has coefficient one in that group.
  Every other group has a residual private pad or consists wholly of public
  fixed/permutation preprocessing, which the simulator computes exactly.

Strict key import and matching public preprocessing are separate prerequisites;
symbolic boundary checks alone do not authenticate an artifact or a witness.

One persistent lazy random oracle has addresses (base-field/IV/parameter identity,
cumulative padded rate-two blocks). Logical aliases are identified; domains are
ordinary encoded inputs. Cross-field distinction is at this modeled interface,
not a claim about literal sponge states. The observer only queries. The simulator
may program its one final, previously unqueried IPA address; it never overwrites.

An efficient preparer E queries this oracle at most Q times before the atomic
proof request and produces (K,x,w,Z), with a valid witness for K's indexed
arithmetic relation. Z may contain w itself, a correlated payment-key owner,
private source/custody state, all prior private and public proof queries, earlier
abort results and arbitrary functions of those. It contains no fresh proof
coins or complete unqueried oracle function. The simulator receives only K,x,
public preprocessing and the query/program handle. E's retained Z is available
to a reduction/continuation, not the simulator. Atomic means no observer gets
partial proof messages or interleaves queries while this call is generated.

Let Real_id use independent uniform F_r masks in the exact source order. Let Sim
be the complete simulator in Appendix A, with
exact ideal field draws. Both retain all oracle entries they create and return
canonical proof bytes or their explicit exceptional outcome. Algebraic failure
symbols, not only accepted proofs, are compared. Shape/encoding failures are
public prechecks; the theorem concerns the subsequent valid cryptographic call.

**Derived local theorem.** Under M(K), the views (Z, output, residual oracle
service) have statistical distance at most

    delta_id(K,Q) = min(1, 2Q/(r-1) + B_real(K) + B_sim(K)),                 (1)
    B_side(K) = M/r + [u(c+2L)+2n+Rots+3+2k]lambda + lambda^k.            (2)

Here n=2^k, u=n-b-1, b is the descriptor blinding factor, c the number of copied
columns, L the lookup count, Rots the number of distinct opening rotations and
M the number of serialized fresh W-blinded points. This is uniform in the valid
witness and efficiently generated prior auxiliary state, including its finite
private oracle history. It couples the **service**, not just a marginal proof
string, so a bounded continuation retaining Z can query the same table. No
key/witness independence, receipt-signing grant, DLog trapdoor, head-hash ROM or
additional joint-privacy assumption occurs in this local theorem.

Equations (1)-(2) use two conservative stopped comparisons; a tighter constant
is unnecessary. Sections 2-4 prove the claim rather than infer it from pointwise
uniform marginals. Equality there means equality of the coupled stopped or
subprobability laws before their first charged bad event. It does not mean
independently conditioning the two complete experiments on successful
publication or absence of all bad events. Both bad masses are charged
unconditionally in (1). This theorem concerns the specified proof model and
ideal masks, not literal fixed-Poseidon execution.

## 2. Freshness against the complete finite prior history

Fix a reached pre-coin realization of Z and the finite table T queried by E;
unqueried oracle answers remain lazy. The first advice commitment is
C0=A(w,tails)+rho W. For each fixed coefficient choice its new independent rho
makes C0 uniform over G. This statement remains true when the witness, key and
private prior table are correlated. If C0=identity, charge its 1/r mass in (2).
Conditional only for the freshness calculation on finite C0, it is uniform on
r-1 points and independent of that finite prior state.

Every local challenge address contains C0's injective finite-point (x,y) encoding
at an offset fixed by this K,x prelude. For any one previous address, at most one
C0 can match these two words. Thus the event that any local address was already
queried has probability <=Q/(r-1). The bound uses all private queries, not just
the observer's visible queries. Different earlier profiles/lengths cannot increase
that count: they either fail the prefix match or fix the same two-word position.
Within this proof, each squeeze adds a padded block, even for an empty update, so
addresses have strictly increasing normalized lengths. The final programming
address is not an earlier address of this call. No future selected-success event
is conditioned on, and no failed occupied-address attempt is retried away.

Replace each new local query by a fresh raw uniform base answer, maintaining its
entry. This virtual fresh-answer view and the real lazy-oracle view agree unless
the hit event occurs. The same stopped replacement applies to Sim. Coupling the
two virtual laws below then couples prior and newly written entries; after the
call all other addresses can be answered by the same lazy randomness. This is
why ordinary arbitrary auxiliary-state postprocessing is justified. It does not
grant the observer program access, a primitive-Poseidon inverse oracle or the
prover's future RNG state.

## 3. Full PLONK/multiopen law, conditional on auxiliary state

Work in the virtual fresh-answer game. The following induction holds for every
fixed valid w and prior Z; the only fresh variables used are the ideal masks.

**Commitment messages.** For every newly committed polynomial p, its independent
blind rho makes Commit(p,rho) uniform, jointly independent of its coefficients.
For any translation p->p+Delta there exists a unique rho translation preserving
the same commitment because W spans G. This is a distributional bijection;
the simulator neither knows nor computes any discrete logarithm. Fresh h-piece
and q' blinds apply even though those polynomials depend on earlier masks. Thus
every such commitment is sampleable at its actual place in the schedule, and
subsequent fresh oracle challenges reveal no information about the hidden
coefficients through the commitment.

**Domain validity and denominators.** M(K)'s boundary identities ensure that new
advice tails do not change usable gate/lookup inputs; blind-row constraints vanish.
The product[u] link stays unmasked. Sorted A'/S' usable rows and grand-product
usable rows are therefore determined by w and earlier challenges, independently
of their newly sampled tails. Joint beta/gamma denominators are bounded after
exposing pre-beta/gamma commitments: each copied-column denominator is affine in
fresh gamma for fixed beta; each lookup's A'+beta and S'+gamma factors contribute
one root each. A union bound gives u(c+2L)lambda without asserting independent
denominators. Zero-preserving inversion is included as a bad case, not called a
native abort. Away from it, all masked polynomials satisfy the domain relation
and the prover's quotient is the exact polynomial quotient.

**Disclosed evaluations.** For fresh tail positions J,

    L_j(z) = ((z^n-1)/n) * omega^j/(z-omega^j).

For distinct off-domain points, the matrix of these values is diagonally
scaled Cauchy, hence full row rank until |J| rows. Each witness slot's disclosed
rotations and x3 obey that limit by M(K). Conditional on previous evaluations
and commitments, remaining evaluations are uniform affine coordinates. The
commitment constraint does not remove a coordinate: its blind adjusts uniquely.
Identical repeated (slot, rotation modulo n) queries reuse one sampled value;
they are not separately randomized. Different primitive slot polynomials have
disjoint fresh tails. Product usable
parts depend only on usable witness rows and challenges, not those tails. Thus
this is a joint triangular masking argument, not a claim of independent
marginals from dependent hidden polynomials.

Public fixed, copy and Direct instance evaluations are computed from K,x. At the
chosen x_eval, h_eval is exactly Protocol::constraint_terms divided by x_eval^n-1,
a deterministic function of the disclosed evaluations/challenges. It imposes no
additional secret restriction. The individual h-piece commitments are hidden
by their own blinds. In each ordinary point-set group, forward Horner at nonzero
x1 has a nonzero coefficient on a remaining private evaluation coordinate, so
that group's q_t(x3) is uniform. Groups use disjoint slot masks.

**The exceptional h group.** h is dependent on witness polynomials and must not
be treated as an independent pad. Its group contains independent R globally
last, with coefficient one under the actual forward Horner implementation.
Conditional on R(x_eval), the coefficient vector of R has n-1 free dimensions.
For x3!=x_eval, R(x3) is uniform even after conditioning on h and all other group
outputs. It masks this group's q_t(x3). The q' commitment reveals no additional
polynomial condition because its separate blind is fresh. Wholly public groups
are computed, never sampled. These observations prove exactly the joint scalar
message law used by Sim up to the IPA, with all preceding commitments and oracle
answers retained.

## 4. IPA response law and programming the one last challenge

Let zeta=x3. Given the preceding full public transcript, the actual source draws
n coefficients s and subtracts s(zeta) from the constant term, giving a uniform
s in ker(ev_zeta). Its commitment S has its own blind and is independent of s.
At nonzero xi, p'=p+xi*s-p(zeta) is uniform on ker(ev_zeta), **even conditional on
any earlier hidden p and auxiliary Z**. The public current commitment T fixes
its accompanying blind as a function of p'; that blind is not separately assumed
independent or uniform after T is fixed.

Each earlier L/R pair has new independent W blinds. Therefore their points are
jointly uniform, hiding p', and their fresh raw oracle answers are independent of
p'. After k rounds the emitted c is the functional

    ell_U(p') = sum_i p'_i * product_j u_j^(-bit_(k-1-j)(i)).

Its coefficient at i=0 is one, as is ev_zeta's. It vanishes on ker(ev_zeta) only
when the coefficient vectors are equal, equivalently
u_j^-1=zeta^(2^(k-1-j)) for every j. Away from that rank collapse, c is uniform.
For fixed zeta, the collapsing vector is unique (or impossible), with mass at
most lambda^k under the actual mapped challenges. This uses the fresh-answer law,
not a uniform-scalar-challenge fiction.

For the last round, let T denote the public current point before the last L/R;
G and b_fold are public functions of the entire challenge vector and zeta.
The honest verifier equation is

    T + u^-1 L + u R = c G + c b_fold z U_base + f W.

Honest L,R are uniform independent points before their fresh raw challenge a;
conditional on nondegenerate u=mu(a), c is uniform as just shown. For fixed
T,L,u,c,R the equation fixes f uniquely because W!=0. Sim instead samples
raw a, c, f and L, then computes

    R = u^-1 (c G + c b_fold z U_base + f W - T - u^-1 L).

For fixed T,L,u,c the map f->R is a bijection. Hence it produces the *same joint*
(a,L,R,c,f,G) law as the honest last round, away from the charged bad cases.
This proves the response distribution, not just algebraic acceptance. Sampling
the raw a preserves Vesta's two possible raw preimages rather than selecting a
canonical inverse of mu. The simulator installs this exact a only at the fresh
last address. All addresses/answers and the unabsorbed G suffix now have the
same joint law. No input to a fixed circuit gate has been programmed by this
argument.

Identity points cost M/r. Zero IPA challenges cost k*lambda; G=identity costs at
most k*lambda by the degree-k multilinear generator polynomial with nonzero
constant generator. Evaluation degeneracies cost (2n+Rots+3)lambda: x_eval=0/
domain, x3=domain/rotation collision, x1=0 and xi=0. Combine these with section 3's
denominator and rank-collapse terms to obtain (2). Stop at the first bad event;
real and simulated exceptional outputs may differ there and their masses are
charged separately. Successful-release conditioning, favorable resampling and
unobserved physical-resource failures are not smuggled into this bound.

## 5. Concrete randomness: exact reductions, not asserted small epsilons

The source makes the ideal/implementation distinction unavoidable but explicit.
`prover::Witness::digest` hashes usable advice rows (not fresh tail masks) with
personalization `PIPA-v1-WitnessD`; statement binding includes descriptor digest,
transcript representation and framed instances. They are computed before opening
the fresh stream. `ProverRandomness::into_stream` then uses:

    OS mode:      seed = E32
    hedged mode:  seed = BLAKE2b-32_person("PIPA-v1-ProveRng",
                                      E32 || statement_digest || witness_digest)
    stream = ChaCha20(seed).

E32 is one fresh 32-byte OS request, with Entropy on error. Sigma dispatch and
Bootstrap's public sigma use hedged mode; Omega finish uses OS mode. Recovery
mode has a different secret-seed/context contract and is not covered by calling
it fresh OS randomness. Exact selected checkpoint/proof reuse takes no fresh
local ZK hybrid. A genuinely recomputed proof is a new bounded attempt.

Each `Field::random` consumes eight next_u64 values and reduces 512 bits. Under
uniform bytes, its exact TV distance from uniform F_r is

    d_red(r) = a_r(r-a_r)/(r*2^512),  a_r = 2^512 mod r.

For N field draws, sequential replacement costs <=N*d_red(r), even if later use
of the draws is adaptive. The fixed upper count from the source schedule is

    N = 2n + a(b+2) + 2L(b+2) + (Zp+L)(b+1) + H + 2k + 3,
    M = a + 3L + Zp + H + 2k + 3,

where Zp counts permutation product sets and H quotient pieces. Native random
stream consumption is at most 64N bytes; earlier aborts use a prefix. Counts must
come from the actual current key. Prior shape examples are DATA only.

Define the following *advantage terms*, not new assumed security promises:

- e_OS: distinguishing the actual fresh seed/error process from its ideal
  independent uniform-success-seed reference, jointly with the actual pre-coin
  state. The reference retains the source's error process, without conditioning
  on success or suppressing an error. If that process is itself hidden-state
  dependent, its public simulation belongs to the source projection, not (1).
- e_hedge: distinguishing `BLAKE2b_person(U256||b)` from an independent uniform
  256-bit seed, for the adaptively preselected binding b=(statement,witness)
  correlated with Z. This seed-level term is sufficient, not claimed necessary.
- e_CC(Lbytes): distinguishing the first Lbytes of ChaCha20 under an independent
  uniform seed from uniform bytes, with the same auxiliary/ordinary-oracle
  interface. A stream-level combined hedge/ChaCha term can replace their sum.

The concrete cryptographic proof-return bound obtained by composition is

    Omega: delta_id + e_OS + e_CC(64N) + N*d_red(r),
    sigma: delta_id + e_OS + e_hedge + e_CC(64N) + N*d_red(r),              (3)

capped at one, plus the simulator's bounded-sampling exhaustion if implemented.
These terms are reduction advantages of explicit primitives/distributions.
Collision resistance alone does not prove e_hedge small; a fixed deterministic
256-to-256 map on entropy need not have uniform image. For example, prefixing a
collision-resistant one-bit-shorter digest with zero preserves collision
resistance while making the first output bit constant. This is a generic
non-implication, not a model of the actual BLAKE2b implementation. This is not a statistical
attack on BLAKE2b, ChaCha or the proof. Likewise a 256-bit seed cannot give
statistical uniformity of a much longer tape; the relevant concrete bridge is
computational PRG security. The accepted recursive-FS soundness assumption
supplies none of these bounds. The implementation already describes these
sources as CSPRNG/hedged production randomness; (3) states precisely the normal
randomness-instantiation obligation rather than adding RP57 privacy by fiat.

For each canonical simulator draw, sample 32 independent uniform bytes and
clear only bit 255, the high bit of the last little-endian byte. Accept the
resulting uniform integer in [0,2^255) exactly when it is smaller than the field
modulus, including zero. After 128 unsuccessful candidates, return an explicit
exhaustion outcome. Both Pasta moduli satisfy 2^254 < r < 2^255, so accepted
values are uniform and each draw exhausts with probability
(1-r/2^255)^128 < 2^-128. Apply the same construction to the raw base-field
challenge. Full 256-bit rejection would not have this bound.
Its scalar-draw count is
J_r=M+1+E_private+G_mask: M-1 sampled points, final c/f, the independent private evaluation
coordinates before x1 (repeated queries reuse their value), and one scalar for each masked group. It also samples one
raw base-field final answer. Thus an explicit extra bound is (J_r+1)*2^-128;
public-only groups and h_eval are computed, not drawn. This is the bounded
sampler's total refusal, never a loop until accepted. Source field reduction and
simulator canonical rejection are different samplers and separately accounted.

## 6. Established local result and remaining obligations

The ideal-mask local L(K) with auxiliary private prefix and residual normalized
oracle is established by sections 1-4 for each actually admitted M(K) key.
The same-stateful-suffix reduction in the recursive construction argument needs
no separate *ideal local* privacy premise. It can retain the actual original
payment key/witness privately, and run the existing first receipt pipeline.
The observer still receives only the allowed public outputs. Formula (3) states
the concrete coin conversion instead of labeling it automatically negligible.

This does not prove that production allocator contention, scheduling/cancellation,
wall-clock leakage or platform entropy failures are reproduced by a public-only
simulator. Nor does algebra authorize conditioning a caller on eventual success.
The cryptographic local interface handles its complete protocol-error law;
physical source outcomes need their actual transition/projection, or an explicit
scope excluding such physical observations. They are not B_side terms.

The remaining recursive boundary is exact: E must prepare a valid indexed
arithmetic witness using the same modeled oracle at every changed cut. An A/W
circuit that literally evaluates fixed Pow5 on earlier proof bytes is not made
oracle-relative merely by substituting H in its native verifier. The ordinary
single-proof theorem above can start at any genuine valid cut, but does not show
that all counterfactual intermediate cuts of the recursive graph are valid under
one experiment. The accepted recursive knowledge/accumulation heuristic is not
used to assert this missing privacy/source statement. No executable fixed-hash
simulator is required, and no impossibility or design attack is asserted.

The next obligations are a coherent recursive-consumer erasure, actual
current-key M(K) reports, and explicit conventional cryptographic justification
of the production seed and stream distributions. Hedged production randomness
is retained. Neither a BLAKE2b random oracle nor a joint RP57 privacy assumption
is silently added by this local lemma.

## Appendix A: complete bounded public-input simulator

Inputs: exact admitted public descriptor/VK/parameter set K; the public fixed and
sigma preprocessing polynomials for that same K; canonical outer instance x;
one persistent normalized-RO query/program handle. No witness, discrete logs,
private transcript table enumeration, native prover or source authority is input.
The reconstructed public polynomial tables must match the actual indexed key;
`omega::Program::source_circuit` provides public circuit metadata, not authority
to select or generate a different key. Bounds below are for a fixed descriptor.

`word()` samples a raw uniform base-field element and applies the native map only
when required. A program stores the **raw** word, including which of two Vesta
preimages was selected. `point()` draws t uniform in Fr and returns tW, preserving
identity as a failure rather than repeatedly choosing a favorable transcript.
All samplers are capped; failure is explicit. The algorithm below has one final
attempt. Existing bounded-retry prototypes require their separate first-retry
coupling bound; they are not silently the same algorithm.

```
S(K,x,H):
  reject invalid public encoding/unsupported shape with the canonical error
  start transcript using exact key_repr, pipa-rb1, pipainst and Direct frame
  sample/write each advice commitment; query theta
  sample/write each lookup A',S' commitment; query beta; query gamma
  sample/write permutation and lookup product commitments
  sample/write R commitment; query y
  sample/write every h-piece commitment; query x_eval
  stop_bad if x_eval=0 or x_eval^n=1

  compute Direct instance, fixed and sigma polynomial evaluations from K,x
  sample disclosed witness/product/lookup/R evaluations in exact schedule
  compute h_eval by Protocol::constraint_terms at x_eval divided by x_eval^n-1
  query x1; query x2; stop_bad if x1=0
  sample/write q_prime commitment; query x3
  stop_bad if x3^n=1 or x3 equals any query rotation of x_eval

  for each exact static point-set group in protocol order:
    if the group has a fresh residual witness pad: sample q_t(x3) uniformly
    else if it contains h and R-last: sample q_t(x3) uniformly using R pad law
    else: compute q_t(x3) from the public polynomials and actual x1 weights
    write q_t(x3)
  query x4
  run exact public multiopen equations to derive P_open, v, x3

  sample/write S; query xi; query z; stop_bad if xi=0
  T := P_open - v*g0 + xi*S
  for j=0..k-2:
    sample/write L_j,R_j; query raw a_j, set u_j=mu(a_j)
    stop_native if u_j=0
    T := T + u_j^-1 L_j + u_j R_j

  draw raw a uniform in Fb; u := mu(a); stop_bad if u=0
  Uvec := (u_0,...,u_(k-2),u)
  G := sum_i fold_scalars(Uvec)[i] * g_i
  b_fold := product_(j=0..k-1) (1 + Uvec[j]*x3^(2^(k-1-j)))
  stop_bad if G=identity
  stop_bad if every Uvec[j]^-1 = x3^(2^(k-1-j))
  draw c,f uniform in Fr; sample L
  R := u^-1 * (c*G + c*b_fold*z*U + f*W - T - u^-1*L)
  stop_bad if R=identity
  form exact normalized address after writing L,R and final padding
  if address occupied: fail; do not overwrite or retry around the conflict
  program H[address] := a
  write L,R; squeeze and require raw a/mapped u
  write c,f; append canonical unabsorbed G suffix
  return exact canonical proof bytes (no salt or private witness attached)
```

Serialization follows PIPA §7: product/lookup evaluation ordering, scalar
one-field versus two-limb absorption, all consecutive empty-squeeze pads and
point compression are inherited from the actual schedule. This is not a new
proof format. Omega's output additionally carries the unchanged P/V inputs;
its outer generator suffix is a distinct proof field, not a substitute for P/V.

Why the last line of algebra gives the full distribution: in an honest execution
p' is uniform on the dimension-(n-1) hyperplane `p'(x3)=0`, conditional on the
preceding visible transcript in the ideal-coin fresh-answer game. Earlier L/R
points are independently blinded. The final coefficient is

    c = sum_i p'_i product_j u_j^(-bit_(k-1-j)(i)).

This functional is zero on the hyperplane only when its coefficient vector is
exactly the evaluation vector; coefficient zero of both is one. That gives the
listed rank-collapse condition, impossible at x3=0 for nonzero u, and at most
lambda^k otherwise. Away from it, c is uniform. For each fixed c,u,L,T, the map
f -> R above is a bijection on the whole prime-order group because u,W are
nonzero. Hence sampling c,f and solving R has the honest joint (R,c,f) law.
The identity-R event has probability 1/r and remains a first-bad event. The
output meets the original opening equation and G relation under the programmed
oracle; this equation does not establish the entire PLONK distribution without
M(K) and the earlier masking steps.

One final-round program request suffices. In particular the simulator does not
program x, x3, the PLONK quotient, any head hash, fold challenge or signature.
For an adversary querying after publication, proof-verification addresses read
the same retained answers; they are not reprogrammed on verification/replay.
Fresh prior-table collisions are covered before publication by C0. Exposing
partial proof messages while the proof is being generated is a different
interface and needs a separate scheduling/freshness argument.

### Canonical and exceptional branches

The oracle returns only canonical base elements. The native map always returns
a canonical scalar; a noncanonical challenge is therefore not a random bad
event in this experiment. Noncanonical input instances, proof scalars, compressed
points, or accumulator vectors are canonical decoder rejections and are never
reduced to gain acceptance. A malformed oracle request likewise does not create
an alternate encoding/address. On Vesta, both raw 0 and raw p map to zero; on
Pallas only raw 0 does. Their probabilities are retained through the actual map.

The first C0 is sampled over the whole group and its identity error is preserved.
Only the freshness calculation conditions this point to be finite, charging its
1/r identity mass separately. An occupied final address yields explicit simulator
failure, even if the proposed answer happens to equal its existing answer; this
conservative difference is included in the prior-query bad event. No code retries
until it finds an unoccupied prefix. Simulated stops at native-permitted xi=0,
x1=0 or other proof-analysis degeneracies are distinguishable failure outcomes,
charged in the stated real/simulated first-bad bounds, never claimed native rules.
The result compares total outputs including failure, not successful proofs only.

## Appendix B: equal-opening translation under a fixed transcript function

A narrower algebraic fact holds even when the IPA transcript uses fixed RP57.
Fix the complete reached IPA-entry prefix, its commitment C, evaluation point x
and **actual** evaluation v. Let two openings satisfy

    Commit(p0,r0) = Commit(p1,r1) = C,
    p0(x) = p1(x) = v.

Use independent ideal uniform scalar masks. The opening prover samples s
uniformly from `ker(ev_x)` and a blind sigma, writes `S = Commit(s,sigma)`,
and derives xi from that prefix and S. On the path where xi is nonzero, translate
the first opening's masks by

    s1     = s0     + (p0-p1)/xi,
    sigma1 = sigma0 + (r0-r1)/xi.

The polynomial difference belongs to the same evaluation kernel. Its commitment
with the blind difference is zero, so S, the transcript prefix and deterministic
xi are unchanged. This translation is an invertible, measure-preserving map on
each fixed-S fiber. Both executions then have exactly the same masked polynomial
`p + xi*s - v*e0` and initial synthetic blind `r + xi*sigma`. Coupling their
subsequent L/R masks identically makes all later points, challenges, final c/f
responses and returned generator equal. Rank collapse needs no additional
exclusion; zero round challenges and identity-point refusals occur together.

This establishes stopped algebraic opening indistinguishability for equal
C, v and complete entry prefix. The prover does not stop at xi=0: that continuing
branch is excluded from this result, and its probability under fixed RP57 is
not bounded here. Identity-S refusal occurs before xi and has the same law for
both openings. Concrete randomness, allocation, cancellation and entropy
outcomes require their separate arguments.

The translation uses the openings; it is not a public-input sampling algorithm.
Nor does it compare different private Direct-frame prefixes, unequal actual
evaluations, or an F-generated proof with an H-programmed one. Thus it sharpens
the local IPA statement, including the complete c/f response, without supplying
the joint public sigma/P/V simulator or closing C12.

### Same Direct frame and the actual opening value

The equal-v premise can be derived for two valid usable witnesses sharing the
same admitted K and Direct frame i. It must not be inferred for different i.
The IPA prover does not serialize v separately: it computes the actual polynomial
evaluation. The multiopen verifier reconstructs its claimed value from i and
the reached message prefix pi. Write a=x1, b=x2, c=x4, z=x3, and let S be the
number of point-set groups in source order. For group t, Q_t is its transmitted
evaluation at z, r_t interpolates its earlier claimed evaluations, and
d_t(z) is the product of z minus its opening points. The two source Horner folds give

    Phi(K,i,pi) = c^S sum_t b^(S-1-t) (Q_t-r_t(z))/d_t(z)
                  + sum_t c^(S-1-t) Q_t.

For a valid usable assignment with nonzero usable copy/lookup denominator
factors, the domain quotient is exact, so v_actual=Phi. These factors are
`v_j(omega^r)+beta*sigma_j(omega^r)+gamma`, `A'_ell(omega^r)+beta`, and
`S'_ell(omega^r)+gamma` at usable rows r, with the source's sorted,
theta-compressed lookup columns. Call their joint nonzero condition GoodDen.
It is sufficient for the algebraic identity; it is not a native abort rule.

For fixed i, the masked prefix itself can be coupled under fixed F. Each fresh
commitment blind makes its point uniform without consuming a polynomial-mask
coordinate. After equal points determine the adaptive evaluation challenges,
the Cauchy-rank argument translates fresh tails to preserve disclosed values;
the corresponding blinds translate to preserve their already exposed points.
At regular x3, the remaining group coordinates preserve each Q_t. Adjust R last
to compensate changes in the dependent h group, keeping R(x) and its commitment
fixed; its coefficient is one. The separately blinded q-prime point likewise
stays fixed. This is a triangular affine-fiber coupling. At x1=0 each group
selects its last slot: that slot is either still privately padded or public and
identical; the h group still ends in R.

Thus, on the common branch where both witnesses satisfy GoodDen, x3 is outside
the FFT domain and earlier rotated opening points, and reached xi is nonzero,
the prefix, C, z and actual v agree. Appendix B then couples the full c/f
response. Construct the prefix coupling before imposing GoodDen: the total
coupling loss is bounded by the union of exceptional x3, either witness's
GoodDen failure, and reached xi=0. No small bound for that union under fixed
RP57 is supplied here, and neither world's law is conditioned on successful
publication. Native identity and zero-round stops already coupled stay coupled.

Different private Direct frames change Phi through their instance evaluations
and their absorbed prelude. Residual masks alone do not remove that dependence.
This result eliminates an additional opening-polynomial argument within a
same-frame fiber; it supplies neither an efficient public sampler nor the
across-frame joint law needed by C12. Independent source/algebra review and
108 finite polynomial checks support this bounded derivation; they do not
qualify native proofs, current keys or the concrete randomness conversion.
