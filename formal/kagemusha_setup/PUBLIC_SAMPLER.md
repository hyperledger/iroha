# Fixed-transcript public sampler and the remaining fold barrier

This extends the [same-Direct-frame translation](../../specs/kagemusha_local_zk_v1.md)
into a concrete public-input sampler comparison. It does not derive salted-fold
hiding from recursive Fiat–Shamir soundness. The comparison below is an ideal
scalar-coin algebraic statement, not a claim about OS entropy, faults, current
installed parameters or all C12.

## 1. Exact model and claim

Fix the actual deterministic RP57 functions F in both fields and a coherent
source/parameter/key family K. Every producer, verifier, circuit, simulator and
continuation uses those same functions, encodings, challenge conversions and
pinned generators. No hash answer is programmed. A simulation owner knows the
discrete logarithms of the setup points to one nonzero base B, including W;
these logarithms are auxiliary state in both sides of each local comparison.
They are not published or assumed available for current installed parameters.
The setup-before-pins/installed-setup transfer is a separate claim.

At a genuine atomic proof cut, fix a valid usable witness w, its canonical
Direct frame i, all pre-coin auxiliary state L, and a source satisfying the
support/rank/R-last predicate below. Fresh scalar coins are independent uniform
field elements. Group/field/FFT operations are exact. The observer obtains the
complete returned proof or projected cryptographic error, not a partial byte
stream or the new internal coin tape. It may subsequently compute F freely.
Allocation, cancellation, durable writes and bounded sampler exhaustion are not
silently identified between different implementations; their joint outcome
comparison remains separate.

Let S_F(K,i) be the mathematical public-input algorithm implemented in structure
by [`simulate`](simulator.py): independently sample each
blinded point uniformly in G, apply native identity errors, sample the fresh
private scalar evaluations, compute all public evaluations and expected_h from
i, sample masked point-set evaluations, and run the known-log IPA sampler. It
runs F unmodified. It explicitly stops at irregular x3 and xi=0. On canonical
frames lacking a witness it remains a finite total sampler; a successful output
is made algebraically verifying using the setup logs. Its private file/output
wrapper and exception strings are not, by themselves, a native custody/error
implementation.

For compact Send m0, the current inventory and Appendix C imply that the honest
proof law and this sampler's law can be coupled, with identical complete proof
bytes and shared ordinary cryptographic stops, except on

    B = {a usable copy/lookup denominator vanishes}
        union {x3 lies in H or an earlier rotated opening point}
        union {reached xi = 0}.

The statistical distance of the projected local responses is at most Pr[B] in
the source-coupled ideal-coin experiment, capped at one. This is an explicit
bound, not a claim that Pr[B] is small under fixed F. It is uniform pointwise in
all fixed pre-coin (K,i,w,L) for which the premise holds. Add concrete randomness
and operation-outcome differences separately when lifting to native execution.

## 2. Blinded commitments preserve the hidden scalar fiber

For any already fixed polynomial a, its commitment C(a)+rW is uniform over G
when r is uniform and W is nonidentity. More strongly, if a is itself random,
this point is independent of its entire polynomial. Conditional on any exposed
point, the polynomial keeps its previous law; the blind is the unique scalar
that realizes that point. This statement remains true after revealing setup
logs, since no new blind is revealed.

It applies in source order to advice, A'/S', products, R, all quotient pieces,
and q'. Their nonlinear polynomial dependencies therefore do not consume mask
coordinates through point messages. Identity stops depend only on these same
uniform points and are coupled. Hash-derived challenges are exactly equal
because the emitted prefixes and F are equal, without any uniform-hash claim.

For example, R is drawn before y and h after y. Conditional on the exposed R
point, R's coefficients remain uniform. y is then fixed; h depends on the usable
witness, row masks and y, but not on the remaining R coefficients. This precise
conditional independence is what permits the later nonlinear compensation.

## 3. Initial evaluations are the sampler's uniform messages

A row polynomial with fresh evaluation coordinates J has the form
`a(T)=a_fixed(T)+sum_(j in J) r_j L_j(T)`. At distinct points outside H,
`L_j(t)=(t^n-1)*omega^j/(n*(t-omega^j))`. After removing nonzero row and column
scales the evaluation matrix is Cauchy. Thus any at most |J| distinct disclosures
have full row rank, independent of a_fixed. Conditioning on previous disclosed
values leaves a uniform affine fiber of the remaining dimension.

Compact Send advice and A'/S' have six coordinates; products have five, excluding
both their start and retained endpoint z[u]. Active support makes all usable
lookup values and retained product prefixes independent of advice-padding
coordinates. Different row-polynomial masks are sampled independently. Each
slot's original disclosures are therefore jointly uniform in exactly the
sampler's source order. Repeated queries reuse their earlier coordinate.
Fixed/sigma/Direct-instance evaluations are computed from the same public i,K.
R(x) is independently uniform. The native x=0 or x^n=1 refusal is common to both
sides before these disclosures. GoodDen is not needed for this prefix-law claim.

## 4. Point-set messages: triangular nonlinear compensation

The source groups have private last slots respectively lookup product, A4,
first copy product, A', R. Hence each group has a private coefficient one even
when x1=0; no x1 inverse or exception is necessary for this compact profile.
At regular x3 each chosen private slot has a fresh residual evaluation coordinate
after its earlier disclosures. Slots belong to exactly one group.

First expose the four groups without H_x. Conditional on the entire prior prefix,
each is surjective in its own independent residual coordinate. Exposing one
may also change the dependent quotient polynomial, but cannot consume another
non-H group's residual coordinate. Thus these four transmitted values are
independent uniform field words in order.

Last expose the H_x/R group. Fix every other polynomial and the already
transmitted values. Its value is a fixed (possibly nonlinear) offset plus
R(x3), with coefficient one. The R coefficient vector retains full rank for
(R(x),R(x3)) when x3!=x. Translating its residual coordinate compensates any
change to the other polynomials, including H_x, while retaining R(x). Adjusting
the already conditioned commitment blind retains the R point and hence y.
The q' point also remains fixed through its independent blind. Therefore the
last group value is uniform, independently of the earlier group messages.

This is a measure-preserving triangular change of variables: arbitrary offsets
need not be linear, provided each stage has a disjoint uniform pivot and the
last R pivot is absent from the earlier offset. It does not assume h itself is
uniform, independent of the witness, or linear in earlier masks.

On GoodDen, Appendix C proves H_x(x)=N(x)/(x^n-1). Consequently the actual
multiopen polynomial's value is exactly the public Phi computed by the sampler
from these disclosures and i. On the bad denominator branch the preceding
message argument still holds, but this equality is not available; that branch
is charged without conditioning the prefix distribution on its absence.

## 5. Complete IPA law, including c and f

At the matched IPA entry, C, evaluation point z=x3, actual value v=Phi and the
complete transcript prefix agree. Native s is uniform in the evaluation kernel
K_z (the discarded original constant coefficient has equal-size fibers).
Its independent blind makes S uniform and independent of s. Conditional on S,
xi is fixed. For xi!=0, `p+xi*s-v*e0` is uniform in K_z, for every p with p(z)=v.
The blind adjusts uniquely to the matched commitment.

Every L/R point pair has two new independent W blinds. Hence the native round
points are conditionally independent uniform group points, independent of the
remaining folded coefficient vector; the sampler draws exactly that law.
F produces the same round challenges. Point identities, zero round challenges
and folded-generator identity yield the same cryptographic stopped branches.

Conditioned on the complete round path, c is a linear functional of uniform
K_z. It is deterministically zero when that functional is proportional to evaluation at z,
i.e. `u_j^-1=z^(2^(k-1-j))` for every round j; otherwise it is uniform. This is
the maintained `rank_collapsed` branch, not an event silently discarded here.
The generator is the actual source fold of K's generators. Given that path and
c, nonzero W determines one f satisfying the final group identity. Knowing the
logs computes it; native algebra yields that same unique f. Thus full c/f and
the generator suffix agree, not only the message prefix or individual challenges.
At xi=0 native continues but the maintained simulator stops, so it is charged.

## 6. Stopping argument and comparison costs

Generate the matching uniform points/disclosures without conditioning on future
GoodDen, x3 or xi events. They have identical prefix marginals by the preceding
fiber argument. Charge the source's hidden GoodDen failure at its beta/gamma cut;
charge the shared public x3 and reached xi exceptions at their actual cuts. Before
these events the algebraic transition to every next public message agrees, so
the usual first-divergence coupling yields the stated Pr[B] bound. There is no
need to replace it by twice the same event probability for this particular
honest-to-sampler construction; comparing two different witnesses through the
sampler conservatively sums their respective bounds.

Use the beta/gamma/line cut quantities defined in
[Appendix C](../../specs/kagemusha_local_zk_v1.md#appendix-c-compact-send-support-and-zero-preserving-products).
For kappa_3, fix the prefix and q-prime polynomial immediately before its fresh
commitment blind, and take the largest defined x3 atom over that blind, retaining
native identity errors as bottom. For kappa_xi0, fix the prefix and IPA s
polynomial immediately before its fresh S commitment blind, and take the
probability of reached xi=0 over that blind, again retaining identity errors as
bottom. The ideal independent scalar blind makes each respective commitment
point uniform, independently of the fixed polynomial. No uniformity of its
fixed-RP57 challenge is inferred. With these exact cuts, compact Send's
per-attempt local cost is bounded by

    min(1, min(1,4090*(kappa_beta+kappa_gamma+7*kappa_line))
             + min(1,4100*kappa_3) + kappa_xi0).

Take conditional suprema over every reached permitted prefix for an adaptive
budgeted continuation, or retain explicit expectations over those cuts. For
fresh bounded attempts compose by first divergence; exact replay is a retained
response, not a new coin draw. No numerical fixed-RP57 bound is asserted.

## 7. What this adds to the recursive bridge

The proof supplies the missing masked-prefix premise for the compact Send
instance of the same-F known-log sampler. Its construction generalizes to a
source whose verified M(K) gives the same support/rank/last-mask structure,
with public-only point groups evaluated exactly. It does not certify that every
current Omega/A/W original satisfies that predicate or that the experiment's
coherent known-log setup is the installed one.

Crucially, after replacing a valid cut, this public sampler can be used by the
later erased continuation on arbitrary canonical frames; no invented recursive
witness is needed there. Different frames still induce different sampler laws.
They become the same endpoint law only if the surviving public arguments of
those samplers have first been coupled. The [endpoint factorization](ERASED_ENDPOINT.md) makes that step explicit. Actual fixed-F salted folds must still be compared
with the independent erased tapes under the same private-log auxiliary state.
The selected recursive Fiat–Shamir assumption states only knowledge soundness
and accumulation security; this local proof uses none of it as a privacy axiom.

## Maintained source map

The concrete support, product and quotient premises are derived in
[Appendix C](../../specs/kagemusha_local_zk_v1.md#appendix-c-compact-send-support-and-zero-preserving-products).
The native [prover](../../crates/iroha_plonk/src/prover/mod.rs),
[lookup](../../crates/iroha_plonk/src/prover/lookup.rs),
[permutation](../../crates/iroha_plonk/src/prover/permutation.rs),
[vanishing](../../crates/iroha_plonk/src/prover/vanishing.rs),
[multiopen](../../crates/iroha_plonk/src/prover/multiopen.rs) and
[IPA prover](../../crates/iroha_plonk/src/pcs/ipa/prover.rs) own the sampled messages.
The setup experiment and its separate current-authority limitation are described
in the [setup README](README.md). The narrower surviving-fold target is derived
in [SALTED_FOLD_PRIVACY.md](SALTED_FOLD_PRIVACY.md).
