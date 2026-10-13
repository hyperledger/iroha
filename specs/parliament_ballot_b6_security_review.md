# Parliament ballot B6: arithmetic and source-hypothesis review

Status, 2026-10-13: **B6 remains unqualified; production approval is absent.**
This is an automated source-hypothesis, transcription and arithmetic review of
the candidate-row ledger in
[`parliament_ballot_proof_arguments.md`](parliament_ballot_proof_arguments.md)
§§3, 6.1, 6.5 and 8. It is not an independent human cryptographic review, an
attack-cost certification, a proof of the protocol-specific reductions, or an
owner's acceptance of a changed security contract. The comparator inherits
only explicitly recomputed component arithmetic, not the candidate theorem.
Implementation conformance and measurements belong to the separate
[standalone validation record](../docs/validation/parliament_ballot_standalone.md).
The later [B6 evidence](../docs/validation/parliament_ballot_b6.md) records the
additional parser, resource and attached-device campaigns.

## Reproducible check and scope

Run from the repository root, with Python 3.11+ and no third-party packages:

```sh
python3 scripts/check_parliament_ballot_security_ledger.py
python3 scripts/check_parliament_ballot_security_ledger.py --json
python3 -m unittest discover -s scripts/tests -p parliament_ballot_security_ledger_test.py -v
python3 scripts/check_parliament_ballot_security_ledger.py --require-qualified
```

The last command deliberately returns **2**, even when arithmetic passes.
The JSON preserves missing primitive bounds, complete resource bounds and
complete query thresholds as `null`; the hypothetical table never fills them.
Normal exit zero means only that the listed arithmetic checks agree.
Rational expressions, heap expectation and integer soundness crossings are
exact. Square roots, exponentials and diagnostic logarithms use 160-digit
`Decimal` arithmetic; tests check stability at 220 digits. Decimal outputs are
approximations, not interval-certified security proofs. Exact comparisons
determine the reported adjacent integer soundness crossings.

The checker freezes the dimensions and formulas named above. It does not
parse the Rust implementation or prove that a formula applies to it. Existing
source/vector guards own that separate transcription link. It recomputes all
components of the current consolidated ledger, both rows' interactive hash
errors, the alternative PRP-native exponents, retry terms, statistical union,
ideal-table diagnostics, residuals, nominal substitution, and the known
resource inventory. Historical, unadopted comparison/extraction proposals in
arguments §§8.3 and 10 are outside its scope.

## Exact results and thresholds

At `q = 2^64`, `T = 2^44`, `U = 2^34`, `M_ctr = 2^20`:

| Expression from the written conditional argument | Recomputed result |
| --- | ---: |
| `Q = q + 1447 T + M_ctr T + 1024` | `36,918,944,040,625,374,208` |
| Single-output relation soundness | approximately `2^-119.8687268` |
| Batch relation soundness | approximately `2^-109.9015005` |
| `epsilon_P1` | `3.33067066206186707003e-16` |
| `K_sim` | `2.16986018284917889921e-19` |
| Recorded `D_sw` (applicability unresolved below) | `1.49586152901958979746e-19` |
| `C = epsilon_P1 + K_sim + sigma` | `3.33284052224471624893e-16` |
| `C + D_sw` | `3.33433638377373583873e-16` |
| Programmed-game lifetime exhaustion upper bound | approximately `2^-161.5401352` |
| Bounded-simulator correction `sigma` | approximately `2^-367.0802704` |

The exact heap computation reproduces the numerator printed in arguments
(77), over denominator `2^248`. It averages boundary edges using each node's
probability of containing no selected leaf. Independent exhaustive enumeration
of small heaps tests that method. Its value is approximately `221.9574684231`,
strictly below 222; Markov's inequality and the eight grinding bits give
`p > (1 - 222/230)/256 = 1/7360`. This is the programmed-game certificate;
the real-game transfer still carries the programming losses.

**The `2^-64` obstruction holds even at zero external queries.** Holding the
specified lifetime `T` fixed, the recorded upper-bound expression gives

```text
epsilon_P1(0) = (3/2) * 2^44 * sqrt(2^44 / 2^256)
              = 3 * 2^-63 = 6 * 2^-64.
```

It increases with `q`. Consequently no nonnegative `q` makes the written
bound containing `Z` certify `2^-64`, even before adding any unknown or other
known term. A query cutoff of zero would be incorrect: there is no such
cutoff. This is a limitation of this upper bound, not a demonstrated attack or
a lower bound on the true advantage. A sharper argument or different
parameters could change the conclusion.

For the written soundness polynomial alone, exact bisection gives these
largest nonnegative integer **external** query counts with a bound strictly
below the target, holding all other parameters fixed:

| Conditional polynomial | Target `2^-64` | Target `1/2` |
| --- | ---: | ---: |
| Single output | `9469576631732150086226556343` | `28759109021232136921968687268973145796` |
| Batch | `299304673498139815634236508` | `908988499159099446878788736424656837` |

Tests verify the exact inequality at each integer and its failure at the next
integer. These are algebraic crossings outside the fixed deployment ceiling,
not approved query budgets or complete-construction security thresholds.
They retain the unreviewed adaptive embedding and backend oracle premises.

At the stated ceiling the JSON supplies the remaining allowance for the
unknown terms in every game, with and without the recorded direct switching
charge. For example, using `C + D_sw`, joint zero knowledge requires
`T e_gen < 1/2 - C - D_sw`; privacy requires
`T e_gen + alpha_P < 1/4 - C - D_sw - rho_rep`.
Their right sides are about `0.499999999999999666566` and
`0.249999999999999666566`. They are shared residuals, not simultaneous
allocations to each missing term. The corresponding `2^-64` residuals are
negative. Complete-construction `1/2` crossings remain unknown because the
missing bounds must be functions of the complete resources.

The listed structural/model-statistical exceptions, conservatively summed as
`delta_leaf,all + delta_MH + delta_sep + 2 delta_salt + 2 rho_rep + sigma`,
are approximately `3.76592547652e-48 < 2^-128`. This calculation depends on
the stated random-oracle/ideal-distribution premises. Including recorded
`D_sw` raises the sum above `2^-128`. The intended statistical budget must
therefore say whether it covers all information-theoretic switching distances.
The checker does not silently reclassify switching as computational, nor add
`D_sw` to a PRP-native argument already using its multiplicative factor.

## Primary-source checks and their limits

The linked versions were inspected for the statements and hypotheses below.
This is not a full proof audit. Historical reading-status statements in the
older documents describe their earlier pass; this record gives the scope of
the new check.

| Primary source inspected | Supported use and unresolved obligation |
| --- | --- |
| [Grilo–Hövelmanns–Hülsing–Majenz, Theorem 1 and Proposition 2](https://arxiv.org/pdf/2010.15103v2) | Supplies the adaptive fresh-value reprogramming shape and its `3R/2 * sqrt(q p_max)` simplification when `q p_max < 1`. The new value is fresh and independent. The protocol must establish each location distribution, side information, shared oracle and counter embedding; the theorem does not supply those facts. |
| [Jaeger, Theorem 2.1 and §4](https://arxiv.org/html/2511.16009v1) | Fixed-permutation one-way-to-hiding gives a `2q sqrt(Adv_ow)` comparison and supports a route to adaptive embeddings. It does not prove the protocol's hidden-label query-mass bound. The admissible distinguisher and its access to private state remain part of the embedding. |
| [FAEST v3, Definition 10.7, Lemma 10.24, Corollary 10.54](https://faest.info/faest-spec-v3.0.pdf) | Defines generator games and retains explicit primitive advantages; its signature theorem models designated hashes as quantum random oracles. It supplies neither a numerical AES advantage for these games nor a complete theorem for this ballot extension. The multiquery leaf issue is detailed below. |
| [Bertoni–Daemen–Peeters–Van Assche, Theorem 2](https://keccak.team/files/SpongeIndifferentiability.pdf) | A classical random-permutation sponge result. It cannot justify quantum queries by replacing a birthday exponent with a quantum-search exponent. |
| [Carolan–Poremba–Zhandry, Theorem 8.1](https://arxiv.org/html/2410.16595v1) | The special one-round, shared-randomness/reset theorem explicitly requires `r <= c`. SHAKE256 has `r = 1088 > c = 512`. One padded invocation does not repair that failed hypothesis. |
| [Alagic–Carolan–Majenz–Tokat, Theorem 7.22](https://arxiv.org/html/2504.16887v1) | Quantum sponge indifferentiability exists in the random-permutation model. Its displayed scale is `O(l^2 sqrt(q^9 2^-min(r,c)) + l^3 (q^5 2^-min(r,c))^(1/4))`. At `l=1`, `q=2^64`, `c=512`, these monomials are `2^32` and `2^-48`; at `q=2^77` they are `2^90.5` and `2^-31.75`. No useful concrete certificate at these resources follows from that asymptotic statement. |
| [Gaži–Pietrzak–Tessaro, Theorems 2–3 and Appendix G](https://research-explorer.ista.ac.at/download/1671/4827/IST-2016-673-v1%2B1_053.pdf) | Classical keyed-sponge PRF analysis, with separate key-absorption steps in the checked construction. No checked extension establishes the concrete mixed tag/secret/context encoding, selective-entry leakage/corruption game or existential uniqueness premise here. |
| [Hosoyamada, ePrint 2025/1059](https://eprint.iacr.org/2025/1059) | Abstract inspected only; the PDF could not be retrieved in this pass. Its advertised keyed-sponge/KMAC regimes and encodings are insufficient to import a theorem for `P`. No full-theorem claim is made. |
| [Carolan–Majenz, §5 and Theorem 5.5](https://arxiv.org/html/2609.28469v1) | Gives an explicit ideal-permutation collision-search diagnostic, with swap-query and output-block charges. This is useful for frames; it is neither selective-entry pseudorandomness nor existential uniqueness. Its fixed-target preimage bound also requires a target independent of the permutation. |
| [FIPS 202, §6](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | Fixes SHAKE256 and SHA3-512 algorithms, padding, rate and capacity. Standardization and conformance do not prove the application-specific assumptions. |

### Generator games and switching need a sharper statement

FAEST's leaf term is `Adv_PRG[ N0 ]`; Game G2 uses `Ni` queries. The extension's
correlated-game interface is implicit. Its direct switching subtotal uses
`binom(9,2)`, while its PRP-native exponent uses `9 N0`. The smaller charge
needs a justified single-query reduction. This applicability gap is not an
attack.

For comparison, the classical switching union charge for `9 N0 = 2304`
distinct blocks under one key is `binom(2304,2)/2^128`. Substituting it gives
`4.67579748963e-18`. This separate diagnostic does not prove the quantum
correlated experiment. Qualification needs explicit game interfaces, query
counts and a coherent direct-uniform or PRP-native reduction.

The nominal `Q_star^2 / 2^256` substitutions are not established AES security
bounds. They require concrete assessment for the joint root output, shared-IV
hidden paths, nine-block correlated leaves and actual expanded rows, including
the reduction's runtime and preprocessing. A generic key-search scale is not
an upper bound against all algorithms for fixed AES.

### A properly charged ideal frame diagnostic

The standalone vote authorization frame has `128 S + 536 <= 128536` bytes;
registration is smaller. Two maximum frames occupy
`L = 2 * (floor(128536/72) + 1) = 3572` SHA3-512 blocks.
For ordinary XOR query budget `Q_star`, the source's swap-query count requires
`t = 2 Q_star + 2 L`.

The theorem's simplifying size condition `t <= 2^798` holds, yielding

```text
p_collision <= 32 t^3 / 2^512 + 128 t^3 / 2^1024 + 32768 t^2 / 2^1600.
```

At `Q_star = 2^77` this gives approximately `6.58887371452e-83`, slightly
above `2^-273`. The nominal `64 Q_star^3 / 2^512 = 2^-275` does not follow
with these query units. It remains hypothetical. The random-permutation
calculation does not fill the concrete SHA3 ledger entries.

### Why P, U and the backend model remain open

`P` concerns one concrete four-tag SHAKE family with public commitments,
both authorization families, adaptive leakage/corruption exclusions and a
joint simulator. The inspected sources do not yield its required numerical
bound. An ideal random-table hybrid is a useful diagnostic but changes the
credential relation unless a consistent oracle-relative construction and
concrete bridge are supplied. Tags alone establish disjoint input strings,
not independent concrete functions.

`U` asks whether colliding secrets **exist** at a selected context, without
requiring the adversary to output them. Collision-search bounds do not bound
that event. For an independently sampled ideal map at a fixed context the
union calculation is exactly `binom(2^384,2)/2^1024`, below `2^-257`; a union
over `2^24` fixed contexts is below `2^-233`. Adaptive, primitive-dependent
contexts are a different experiment. For fixed SHAKE, a bad deterministic
context, if one exists and can be supplied as uncharged advice, makes its
existential event certain. That observation does not exhibit such a context;
it explains why the probability space and preprocessing model are essential.

The backend proof assumes independent programmable quantum oracle domains.
The current code evaluates a fixed hash construction. Neither the known
quantum sponge theorem at these parameters nor conformance supplies a concrete
bridge; this remains an explicit model assumption. The protocol-specific
adaptive soundness and extended CRT/simulation arguments also still require
independent review even if every primitive bound were later supplied.

## Complete inventory of known and missing resource categories

The reported nominal primitive subtotal is exactly
`27000944741207686661537792 / 185`, with `log2 = 76.9498307985590493`.
Below `2^77` it leaves only
`955464837380613003542528 / 185`, approximately `2^72.1291675`, for omitted
primitive work. This proves the subtotal's arithmetic, not equation (97)'s
strict inequality for the complete cost.

The later [request-stage reconciliation](parliament_ballot_b6_request_accounting.md)
checks the candidate's normal-return request contribution against the actual
cold entry. Its 4,096 term is an intercept in
`w_request <= 4,096 + ((2,750,672 + 65,536)/740) q_request`, not a pointwise
preparation ceiling: candidate vote preparation alone reaches 7,548 Keccak
permutations at `S=1,000`. Counting `H_mu` among induced backend queries makes
the coupled inequality hold at every reviewed rejection/completion stage.
This preserves the recorded nominal request subtotal while resolving that
component's allocation; it does not establish the honest-simulator allowances,
complete reduction resources or physical AES/provider and gate costs.

| Resource category | What is currently available |
| --- | --- |
| Backend oracle inventory | `q_pub + 1447 T + M_ctr T + 1024`; separate role/domain and verification charges remain essential |
| Known AES work | 2,764,797 blocks per full vote commitment; 2,750,672 per heavy verification; commitment plus reconstruction charged |
| Nominal request/direct-primitive caps | Each `2^64`; declared assumptions, not consequences of the backend query ceiling or enforced deployment caps |
| Nominal extra validation/non-counter Keccak | The candidate completed-request contribution uses the checked coupled `2^12` intercept plus per-backend-query coefficient, not a standalone `2^12` ceiling. The honest-invocation `2^16` allowance and remaining reduction work still need justification |
| Counter hashing | At most `M_ctr T` programmed attempts, four Keccak permutations each |
| Bounded simulator sampling | At most another `M_ctr T` admissibility trials on exhaustion; total at most `2^65` 256-bit draws and checks, `2^73` random bits for those draws |
| Final comparison | Unquantified; cannot be silently set to zero or assumed to fit the remaining headroom |
| Relation, transcript and context processing | Invocation count known; elementary gate cost, framing and credential-generation accounting incomplete |
| Admissibility and sampling computation | Trial count bounded; per-trial gates and randomness generation cost incomplete; extra trials do not program additional challenge-oracle entries |
| Memory, tables, coherent access and QRAM | Quantities and access cost missing |
| Preprocessing and primitive-dependent advice | Accounting and allowed model missing |
| Primitive-to-elementary-gate conversion | Missing for AES, Keccak and the surrounding computation; pooled primitive calls are not elementary gates |

The JSON has a nonnumeric entry for every missing category. The named
primitive bounds must use the resulting full resource vectors, including all
reductions, rather than the adversary's external oracle count alone.

## Corrections required before the ledger can be accepted

The factual and status corrections below are integrated into the arguments
and profile records. The named proof, resource and qualification obligations
remain open; integrating their descriptions does not discharge them.

1. Record the absence of any `2^-64` query cutoff for the written `Z` bound
   at fixed `T`, including its failure at `q=0`. Keep complete `1/2`
   thresholds unknown pending resource-dependent primitive bounds.
2. Resolve the leaf-game query interface and switching charge. Until then
   label the reproduced `D_sw` and PRP-native adaptation as conditional;
   do not claim that arithmetic validates their hypotheses.
3. Preserve the XOR/swap conversion and output-frame length in any use of
   the new collision theorem. Keep fixed Keccak separate from its random
   permutation model, and keep the `64 Q_star^3` entry hypothetical.
4. Complete equation (97)'s final-comparison allowance, all non-oracle work
   and preprocessing. Replace an unconditional `W < 2^77` reading with the
   checked subtotal and explicit missing allowance until then.
5. Maintain `P`, all three `U` restrictions, four generator terms and concrete
   frame/model bounds as missing. Supply reviewed protocol embeddings and an
   independent attack-cost assessment before asserting qualification.
6. Arguments §8.6 now links the final strengthened-relation conformance and
   timing evidence. Keep its distinction between implementation evidence and
   cryptographic qualification, and preserve historical review provenance.

None of these obligations is discharged by the nominal table's values below
`1/2`. No owner acceptance or human cryptographic review has been inferred
from the instruction to continue engineering work.
