# KAGEMUSHA proof privacy under a fixed transcript function

This specifies the sole first-release candidate: norm-product PLONK, total named
challenge maps, scoped full-group generator claims and committed-mask folds.
The ideal-coin local statements below are conditional mathematical statements.
The [C12 logical composition](kagemusha_c12_composition_v1.md) combines them
with honest setup, source-derived private originals and causal custody under
its explicit premises. This document does not qualify an installed catalog,
current native execution or physical wallet behavior. Historical programmable
transcript derivations retain their own source/model scope in the
[recursion memo](kagemusha_recursion_soundness_v1.md#retained-arguments-and-selected-source-transfer);
their raw-role and linear-product exceptional bounds are not used here.

## 1. Experiment and observable result

Fix the same deterministic RP57 functions in both Pasta fields, the same
parameter/key catalog K, canonical encodings and actual native/circuit schedule.
A local proof cut fixes its valid usable witness, Direct public frame and all
prior auxiliary state before fresh coins are drawn. The mathematical simulation
owner knows coherent discrete logs of K's generators, including nonzero W.
These logs are not claimed available for the installed production parameters.
The [common-template composition](kagemusha_c12_composition_v1.md) gives the
setup-before-pins transfer in one ideal raw-oracle experiment. Applying that
model to the actual deterministic BLAKE2b implementation uses the stated
instantiation assumption. The experiment does not condition on a particular
installed pin; this local law does not supply installed generator logs or
require a simulator for an arbitrary chosen key.

The local observer receives the complete proof or its declared cryptographic
refusal. It does not receive new private masks, partial proof bytes, addresses
of private checkpoints or their contents. If such observations are part of the
wallet interface, their joint law needs its own source/state comparison. Timing,
allocation, cancellation, entropy failures, storage failures and publication
outcomes are not silently identified with a cryptographic refusal.

Under independent uniform field coins, the public sampler uses the actual fixed
F without programming an answer. It samples blinded commitments, evaluations and
the IPA endpoint in source order. Its comparison with an honest proof requires
the source-specific masking/support predicate M(K), including R-last, described
below. The comparison is statistical in this ideal experiment. Actual seeded
prover coins have the computational conversion in §6.

## 2. Total first-release algebra

The scalar field conversion happens first: raw base Fp embeds into scalar Fq;
raw base Fq reduces canonically modulo scalar Fp. Define nz(0)=1 and nz(a)=a
otherwise. The only role transformations are

- PLONK evaluation x = 5 nz(a)^2;
- multiopening x3 = 25 nz(a)^4;
- IPA Xi and every actual IPA or accumulation round u = nz(a).

Each role has its own existing raw squeeze. The first raw squeeze retained by
the source-bound terminal prefix owner is unchanged. Theta, beta, gamma, y,
x1, x2, z, zeta and alpha are unchanged; normalization padding zeros are not
challenges and remain zero. No additional squeeze, absorption, retry or sampler
is introduced.

Both Pasta orders have 2-adicity 32 and five is a nonsquare. Every supported
k≤28 domain element and rotation is a fourth power. Thus x is nonzero
nonsquare, x3 is square but nonquartic, neither is in H, and x3 differs from every
rotated x. Xi and actual u are nonzero. These identities hold for every fixed F,
including adversarially selected answers. Norm factors a²−5 in the copy and
lookup products never vanish. There is no GoodDen or rank-collapse refusal
premise in the current honest source construction.

Ordinary absorbed commitments and D/L/R remain finite-only. The final unabsorbed
G and normalized generator-claim carriers allow canonical identity, encoded as
zero32 or coordinates (0,0). No finite Pasta point has x=0. Every alternate
encoding rejects. Syntax still grants no authority: decide checks the complete
MSM G=⟨s(u),g⟩. A Corrected claim has exactly the same source k/challenges and a
distinct full-group G, and both selection and generator decisions remain bound.

## 3. Mask fibers and the PLONK/multiopen response

For any fixed polynomial p, C(p)+rW is uniform on the full prime-order group
when r is uniform and W≠O. For random p, the point is independent of p as well.
Conditioning on an exposed point fixes a unique blind for each possible p and
therefore preserves the original law of p's remaining mask coordinates. This
argument remains valid when the simulator knows all setup logs.

At points outside H, row-Lagrange evaluation matrices differ from Cauchy
matrices by invertible row/column scalings. Distinct queried points therefore
have full row rank until all independent mask coordinates are consumed.
M(K) must inventory every source polynomial, its fresh mask rows, all prior
queries, and its reserved product endpoint. Products have b fresh coordinates;
advice and permuted lookup columns have b+1. A retained endpoint is not an
extra independent mask. Usable constraints must not depend on fresh tail rows.

The initial disclosed private evaluations are sampled from these full-rank
fibers. Public fixed/permutation/Direct-instance evaluations come from K and the
public frame. After those disclosures, every earlier multiopen point group
needs a remaining private coordinate with coefficient one, including x1=0.
R-last provides an independent R(x3) coordinate while holding R(x) fixed, and
compensates the dependent quotient evaluation without changing prior messages.
The q-prime blind preserves its already exposed commitment. Honest polynomial
identities then give exactly the public opening value, with no denominator
exception because of the total maps and norm products.

This is a source predicate, not a generic claim that every PLONK descriptor is
hiding. The complete current sigma/Q/A/W/Omega inventory and actual generated
keys must satisfy it; a passing compact-source check cannot substitute for that
catalog proof. M also does not prove validity of an arbitrary public frame:
the local cut requires its matching valid source witness.

Strict KAGEMUSHA original import uses
`SourceBoundVerifyingKeyV2::from_masked_artifact_v2` and the corresponding
proving-key constructor. Their shared `iroha_plonk::keys::masking` owner checks
actual reconstructed fixed/sigma rows, fresh-tail dependencies in rotated
gate/lookup expressions, zero fixed tails, uncopied tail labels, S7 residual
rank, and the private coefficient-one pivots and quotient/R order above.
Canonical source, selectors, copy tables, parameters and every original VK
commitment must still match. Predicate, bounded-work or cancellation failures
return before source authority escapes. Generic unmasked import does not
imply M; the wallet's complete strict source-admission path is the premise.
The same admission and refusal run in real and simulated setup, with no
simulator-only catalog abort and no altered native verification equation.

## 4. Exact IPA endpoint, including rank collapse

Native IPA samples n independent coefficients and subtracts their evaluation at
x3 from coefficient zero. The result S is uniform on K_x3={p:p(x3)=0}; every
fiber of this map has r elements. Its independent W blind makes the S commitment
independent of S. Since Xi is nonzero, p+Xi S−v e0 is uniform on K_x3 for every
honest input p with p(x3)=v.

Each L/R pair has two new independent W blinds. Conditional on every prior
point and arbitrary fixed-F challenge, every pair of finite points has the
same number of underlying blind pairs. The initial coefficient vector thus
retains its uniform K_x3 law through the full path. Let L_u have coefficient
`prod_j u_j^(-bit_(k-1-j)(i))` at index i. The final c is L_u(p').

If every u_j^-1=x3^(2^(k-1-j)), L_u equals evaluation at x3 and c is exactly zero.
Otherwise c is uniform. The sampler takes the same branch; it neither rejects
rank collapse nor assumes its probability is small. For a fixed point path and
c, nonzero W gives exactly one final blind f satisfying the full-group equation.
The sampler computes that f from its coherent setup logs. G is the actual
folded generator for the same u, including identity, and its complete decision
is retained. No final oracle answer is programmed.

## 5. Cryptographic stops and adaptive accounting

For a fresh point B(hidden,prefix)+bW, ideal uniform b makes identity probability
exactly1/r at every reached cut, even with known setup logs and fixed F. Native
finite-point refusal can be coupled at that same cut. Alternatively the total
no-stop comparison charges the reached point inventory. For one complete honest
Direct PIPA proof that inventory is

`B = a + 3L + t + d + 2 + 2k`,

where a is the advice count, L the lookup count, t the permutation-set count,
and d the degree. It counts advice; sorted lookup pairs and products;
permutation products; R; d−1 quotient pieces; q-prime; S; and 2k IPA messages.
The unabsorbed G is not charged as a fresh-blind point. A committed-mask fold
has 33 finite messages, D and 32 L/R. Its exact identity-stop mass is
1−(1−1/r)^33, bounded by 33/r, in the ideal-tape subexperiment without external
faults. The stopped materializer preserves that branch and the complete
pre-sampled tape, so the selected logical composition adds no separate B/r or
33/r erasure term. A comparison that erases these stops must charge their
reached-attempt masses instead; it must not both retain and charge them.

For finite adaptive attempts, stop the coupling at its first divergence and sum
conditional reached costs. Retained replay reuses the same selected bytes and
creates no new proof-coin comparison. Do not condition on eventual success or
bound unlimited retries by a fixed finite sum. Operational/source failures and
publication are separate kernels in the whole-wallet argument.

## 6. Concrete production coins

The production owner requests 32 fresh OS bytes per new proof. Its optional
hedge binds those bytes to the exact statement and usable-witness digests, then
ChaCha20 expands the resulting seed. Seed selection fails explicitly; there is
no deterministic fallback. Fixed streams exist only in crate tests. Restoration
verifies retained original proofs instead of creating a replacement stream.

For a finite complete proof the exact number of field draws is

`N = a(b+2) + L(3b+5) + t(b+1) + 2n + d + 2 + 2k`.

Each Pasta field draw reduces 512 bits. With s=2^512 mod r, its exact distance
from uniform is s(r−s)/(r 2^512), at most r/(4 2^512). The concrete comparison
therefore includes the joint conditional OS-source deviation, the chosen
hedge/ChaCha distinguishing terms for 64N bytes, and the reached field-reduction
sum. A combined stream-level hedge/ChaCha term is acceptable only under its
explicit auxiliary-state and finite-query interface. A 256-bit seed cannot be
statistically close to a longer independent tape; no such claim is made.
The separate 33-scalar fold owner samples directly from the OS into its private
cleared tape. Each scalar allows 134 fresh 32-byte candidates, clears only bit
255, and accepts the first canonical encoding including zero. With
q = 1 − r/2^255, independent ideal fills give exact tape exhaustion
1 − (1 − q^134)^33 ≤ 33q^134 < 2^-128. Entropy failure and cancellation
return immediately; there is no whole-tape retry. Candidate and accepted scratch
values are cleared by their owned wrappers. This does not establish erasure of
compiler copies, registers, abort/OOM paths or persistent storage. Neither the
proof seed owner nor this fold sampler establishes actual OS entropy quality.

## 7. Composition and remaining implementation obligations

The local sampler alone does not simulate the wallet's complete history. The
[common-template composition](kagemusha_c12_composition_v1.md) combines it with
committed-mask folds, all three Q stages, source-derived Omega frames, capsule
originals and causal logical storage. That theorem retains failures and exact
replay and states its setup, source-validity and finite-coin premises explicitly.
Its honest-setup quantifier supplies coherent logs privately; it neither
conditions on a literal installed pin nor infers those logs for an arbitrary
chosen key. The concrete raw-oracle instantiation and joint coin assumptions
remain explicit. Current source/key catalog admission, genuine all-route
native/circuit execution, fresh fixture/SDK validation and physical-to-logical
storage/refusal and payment-release refinement remain separate requirements.
Cryptographic component tests cannot establish those physical or whole-wallet
properties.
