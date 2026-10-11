# Native Pasta SWU regularity from checked arithmetic and cited theorems

The maintained checker establishes the exact prime, rational-group, polynomial
and Euler hypotheses below for the native Pallas and Vesta constants. This note
applies standard geometric and character-sum theorems to those hypotheses. The
checker does not execute those theorems or a Lean/Sage proof. This distinction is
preserved by its `character_sum_theorem_executed=false` and
`regularity_proved=false` fields; neither field denies the conditional mathematical
implication stated here.

This argument concerns the actual two-map sum for **independent uniform field
inputs**. It does not prove the raw-XMD query simulation, concrete hash security,
current fixed-setup indistinguishability, recursive privacy or C12 completion.

## Binding to the native construction

`source_manifest.json` binds hash_to_curve.rs, both curve and field declarations,
and field/mod.rs plus field/cios.rs. The latter define canonical parity and
`from_raw` as conversion of ordinary little-endian limbs into Montgomery form.
The checker reads canonical p, A, B=1265, Z=−13 and the thirteen isogeny
coefficients from these source constants; it does not prove the complete Rust
field implementation or its hardware paths.

On the auxiliary curve E′: y²=x³+Ax+B, let t=Zu² and ta=t²+t. Away from ta=0,
native SWU uses x1=B(ta+1)/(−A ta) and x2=t x1, choosing the square ordinate
candidate and matching its canonical parity to u. Its exceptional branch uses
divisor AZ. Since p≡1 mod4 and Z is nonsquare, t=−1 has no rational solution;
therefore ta=0 only at u=0. The native F(0) is finite, whereas the auxiliary
proof function F0 sets F0(0)=O. No production map is changed.

The exact auxiliary/target group certificates prove odd prime order r. Thus no
finite rational y=0 exists. For nonzero u, x1/x2 and square status are unchanged
by u→−u, while canonical parity flips. Hence F0 is odd. The degree-three isogeny
is a rational-group isomorphism by the separately checked group/map certificates,
so applying it after the auxiliary sum preserves the distribution and character
bounds without a cofactor loss.

## Covers and their arithmetic hypotheses

Write w=Ax+B, v=t+1 and Φ=B²(ta+1)³+A³ta². The two branch covers over E′ are

    P1=Z²wu⁴+Zwu²+B,        P2=BZ²u⁴+Zwu²+w.

Clearing squares gives models W²=Hj(u), where
H1=−A³BZ³vΦ and H2=−A³BvΦ. The checker verifies deg Φ=12, deg Hj=14,
gcd(Hj,Hj′)=1, gcd(Φ,v)=1, Φ(0)=B², and the exact cleared identities using
s1=A³Z³u³v² and s2=A³v² as the ordinate scales.

A squarefree degree-14 hyperelliptic model in odd characteristic is geometrically
connected and has genus six. At either geometric point over w=0, its checked
ordinate satisfies y²=−(B/A)³≠0, so w is a uniformizer. P2 and reciprocal P1
are Eisenstein there: unit leading coefficient, lower coefficients divisible
by w, constant with valuation one. Each degree-four cover is totally ramified,
which rules out every nontrivial unramified intermediate cover. These are
geometric consequences, not assertions inferred from sample points.

The checker also establishes that −AB is nonsquare and that the square classes
at (H1(0), leading H1, H2(0), leading H2) are (+,−,−,+). Rational W=0 would
map to forbidden rational two-torsion, so there are no such fibers. The only
extra rational cover points are two on C1 at u=0 and two on C2 at infinity;
all four map to O because their x coordinates have poles.

## Character bound and exact boundary accounting

[FFSTV, Theorem 3 equation (6), preprint page 9](https://eprint.iacr.org/2010/539)
bounds the character sum along a nonconstant smooth projective cover without a
nontrivial unramified factor by (2g−2)√p for each nontrivial character of the
base Jacobian. The genus-six covers above satisfy these hypotheses, giving
|Sj|≤10√p. This uses the general theorem, not the paper's different q≡3 mod4
SWU example. The retained primary PDF hash is
`1da6be57ba921ee747ed5fc3c37f8ef4596fa5275063889d44ddad2d02a9f842`.

For each nonzero u, exactly one cover contributes the two opposite ordinate
points. Oddness and the four O boundary points give

    S1(χ)+S2(χ)=2 S_F0(χ)+2.

Consequently |S_F0(χ)|≤10√p+1≤(21/2)√p at the native field sizes. The complete
source-specific genus/ramification/boundary derivation is
[CompElliptic at commit 2c044403](https://github.com/daira/CompElliptic/blob/2c0444035a84db957f27f06433715058d1e890ad/design/weil-constant-derivation.md)
(SHA256 `bdf5d2bc0e7d9977384e9e0adc5c380fe0adf0f7f8bd025face90d605919cbdb`).
Its [WeilInstance theorem](https://github.com/daira/CompElliptic/blob/2c0444035a84db957f27f06433715058d1e890ad/CompElliptic/Hashing/WeilInstance.lean)
explicitly receives two character-bound premises h1/h2. Reading or executing that
formal file alone does not discharge the cited geometric theorem application.

## Transfer to the actual two-map distribution

For each nontrivial character, F0(U) has Fourier coefficient at most C/√p,
C=21/2. The coefficient of F0(U)+F0(V) is its square. Parseval and
Cauchy–Schwarz on the group of order r give total variation
C²√(r−1)/(2p). Coupling the same U,V for F and F0 changes a sum only when at
least one input is zero, with probability 2/p−1/p². Therefore the actual sum
followed by the rational-group isogeny obeys

    TV(actual sum, uniform target group)
        ≤ (441/8)√(r−1)/p + 2/p−1/p² < 2^−120.

Here p>2^254 and r<2^255; bounding √(r−1)<2^128 makes the first term less than
(441/512)·2^−120, with the second below 2^−253. The factor one-half is essential:
this is a TV bound, not an unchanged L1 bound. It is an average distribution
statement, not a pointwise guarantee that every target has preimages.

The 512-bit reduction bias, finite inverse-sampler failures, raw-XMD adaptive
query consistency, and fixed release-parameter authority remain separate. No
setup artifact is regenerated or accepted by these certificates.
