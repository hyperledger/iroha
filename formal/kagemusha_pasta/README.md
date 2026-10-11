# Pasta field, auxiliary-curve and SWU cover certificates

These standard-library Python checks establish primality of the two exact Pasta
moduli and verify finite algebraic certificates for the native auxiliary curves
and degree-three isogenies, then the exact polynomial and Euler hypotheses for
the SWU branch covers. They require Python 3.10 or newer and run from any
directory; paths resolve relative to this repository. No Cargo build, external
library, random search, large-number factorization, parameter artifact or proof
generation is involved.

```sh
python3.12 -B formal/kagemusha_pasta/check.py
python3.12 -B -m unittest discover -s formal/kagemusha_pasta -p 'test_*.py' -v
```

Optimized Python execution is deliberately refused. `source_manifest.json` pins
the seven native source files and all nine certificate and documentation files. Review and update
these pins when their contents change. A mismatch fails closed; this manifest is
a source-consistency check, not a signature or an independent trust authority.
Nothing under `target/` is needed to run these checks.

## Prime certificates

`supplied_primes.json` retains twelve explicit Lucas witness/factor nodes from
[CompElliptic's Pasta field certificates at commit 2c044403](https://github.com/daira/CompElliptic/blob/2c0444035a84db957f27f06433715058d1e890ad/CompElliptic/Fields/Pasta.lean).
The upstream source hash and URL are recorded in the data. The verifier does not
execute Lean or trust an external arithmetic implementation.

For each supplied integer n, it checks a complete factorization of n−1 into
recursively proved prime powers, a witness satisfying a^(n−1)=1 modulo n, and
gcd(a^((n−1)/q)−1,n)=1 for every distinct prime factor q. For any prime divisor ℓ
of n, these conditions force a to have order n−1 modulo ℓ. Thus n−1 divides
ℓ−1; since ℓ≤n, ℓ=n and n is prime. Both roots must equal the native field
`MODULUS_STR` values in their exact order.

Unsupplied leaves use deterministic trial division with an explicit
400,000,000 cap, at most 9,999 odd candidate divisors per leaf. The actual largest
leaf, 399082391, needs 9,988 such divisions. Upstream leaves this integer to its
`pratt` tactic rather than listing an expanded certificate. No large Pasta
integer is factored. A prior development attempt with a 100,000,000 cap correctly
refused this leaf; the current cap is explicit, not a probable-prime fallback.

## Auxiliary group orders and isogenies

After primality succeeds, the checker reads the exact native auxiliary A,
B=1265, Z=−13 and thirteen isogeny coefficients. It derives a finite point from
the u=1 SWU branch, checks its curve equation, and verifies [r]P=O with bounded
affine arithmetic. Prime r gives exact point order r. The integer Hasse interval
contains only the multiple r, proving that the auxiliary group has order r.
The finite isogeny image independently gives the same certificate for the
target curve. This uses [Hasse's theorem, MIT lecture 7, Theorem 7.3 and §7.4](https://math.mit.edu/classes/18.783/2025/LectureNotes7.pdf).

Writing the native affine map as (Nx/Dx, y·Ny/Dy), `auxiliary.py` verifies the
complete coefficient identity

```text
(X³+AX+1265) Ny² Dx³ = (Nx³+5 Dx³) Dy²
```

It also verifies both curves are nonsingular, both fractions are reduced, the
x-map has degree three, its derivative is nonzero, and its leading coefficients
are nonzero. At infinity the leading terms are c0·x and c6·y, so the map sends
O to O. A nonconstant rational map of smooth projective curves extends everywhere;
an elliptic-curve map preserving O is a homomorphism. See
[MIT lecture 4, Theorem 4.15, Remark 4.19 and Definition 4.20](https://math.mit.edu/classes/18.783/2025/LectureNotes4.pdf).

The function-field tower gives degree three: the domain-to-image-x degree is
2·3 and the target-to-x degree is two. Since p>3 the map is separable, hence its
geometric kernel has size three. Because gcd(3,r)=1, its kernel on the order-r
rational group is trivial, so it bijects the two rational groups. This is an
isomorphism of finite groups of rational points, not of algebraic curves. See
[MIT lecture 5, Definition 5.6 and Theorem 5.8](https://math.mit.edu/classes/18.783/2025/LectureNotes5.pdf).
No sampled homomorphism assertion is used. Reduced denominators cannot vanish
at a finite rational point: such a point would lie in the rational kernel;
the possible y=0 exception is excluded by odd group order. This also matches
the native infinity branch.

## SWU cover arithmetic

After primes and auxiliary groups succeed, `cover.py` checks the exact degree-12
core and both squarefree degree-14 hyperelliptic model polynomials, their cleared
identities with the native branch formulas, and the Euler conditions for Z and
−AB. It checks all rational boundary square classes and the nonzero geometric
ordinate over Ax+B=0. No geometric theorem is executed by these polynomial
operations. [REGULARITY.md](REGULARITY.md) states how the checked hypotheses and
standard cited curve/character-sum theorems yield a bound for two independent
uniform field inputs. The driver keeps the executed arithmetic and this cited
mathematical interpretation distinct.

## Scope and controls

The sixteen test methods include both roots and curves, missing or composite
factors, changed witnesses, extra nodes, wrong roots/order, small Carmichael
negatives, exact polynomial mutations, and off-curve rejection. Two controls
separately exercise the prime theorem's arithmetic conditions: base two on 341 passes
Fermat but fails the Lucas gcd condition; base two on 15 fails Fermat.

The four cover controls check both exact families and reject a changed model,
a square Z and a repeated polynomial. The checker proves the stated arithmetic
certificates. The cited geometric/Weil interpretation in REGULARITY.md is a
separate mathematical argument, not a Lean formalization or executed theorem.
Accordingly the result reports `cover_arithmetic_verified=true` and
`character_sum_theorem_executed=false`, and retains `regularity_proved=false`
for this executable check. Neither the arithmetic nor the cited bound proves
raw-XMD simulation, setup indistinguishability, C12 privacy composition, current
proof validity or release readiness; `C12_closed` remains false.
