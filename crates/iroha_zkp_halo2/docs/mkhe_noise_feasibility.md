# MKHE construction and feasibility diagnostics

`zk_ams_mkhe_noise_feasibility_v1` reports a specified algebraic construction,
explicit query assumptions, conditional statistical allocation, and exact
resource comparisons. It does not certify parameters, admit keys, or change
readiness. `authorizes_release` and `protocol_privacy_established` remain false.

The retained profile uses degree 131,072, eight parties, 38 RNS limbs, CBD
parameter 2, T256 plaintexts and batches of at most eight. Its exact modulus is
the product of those 38 ordered primes. The separate native-40 profile is not
substituted. The diagnostic reuses the same downstream norm recurrence as the
retained `noise.rs` certificate; the original certificate outputs and all
operational gates remain unchanged.

## Construction contracts

For weighted pair RKG, one pair has
`K + H1*S = g*s_left*s_right + p*(E0*s_right + E1*U + E2)`.
Eight diagonal weights of one and 28 off-diagonal weights of two sum to 64.
With `N=131072`, `|E_j|<=16`, `|U|<=8` and `|s_right|<=1`, the
inclusive honest-source quotient bound is
`64 * (N*16 + N*16*8 + 16) = 1,207,960,576`, strictly below `2^31`.
The all-party Galois source bound is `8*(2*N*2+2)=4,194,320`, below `2^23`.
These differ from the retained ingress proof bound, below `2^22`.

`WeightedPairWithCks` includes all eight evaluated-key CKS smudges in addition
to those sources. `RawWeightedPairAlternative` diagnoses the algebra before
compaction and explicitly has no admitted equivalent key format.
`DirectThreeRoundAlternative` includes the third-round seeded-final-a
normalization term:
`E0*S + E1*U + E2 + E3`.
Its inclusive bound is `2*N*16*8 + 2*16 = 33,554,464`; its Galois bound is 16.
It remains conditional on the unavailable complete 32-key by 38-digit proof
admission. Selecting the enum is not an admission token. No caller-supplied
boolean or digest can turn this diagnostic into one.

These are sufficient upper bounds for the stated honest sampled sources.
They do not establish the bounds extracted from adversarial proofs, a
minimum necessary smudge width, or impossibility of another construction.

## Explicit vector and query allocation

The caller supplies maximum counts of public full-polynomial smudge vectors.
Every party, digit, key, invocation and epoch must be counted. The current
construction requires at least eight ingress vectors, 304 RKG vectors, 9,424
Galois vectors and eight terminal vectors. This is a minimum complete key-set
census, not a release session limit. Raw/direct alternatives require zero
evaluated-key CKS vectors because their algebra has no such step.

For independent integer uniform smudges on `[-B,B]`, translation of a finite
box has total variation
`1 - product_j max(0, 1 - |delta_j|/(2B+1))`, bounded above by
`sum_j |delta_j|/(2B+1)`. Two sources below `2^b` can differ by less than
`2^(b+1)`. For `C` counted coordinates and `B=2^w-1`,
`w=b+128+ceil(log2(C))+1` is a conservative sufficient allocation.
The implementation uses integer arithmetic throughout.

`RecordedCoefficientWidths` records the actual 151-bit CKS widths and
coefficient-only terminal rule. It reports their conditional session shortfall.
`ConditionalVectorQueryAllocation` computes hypothetical widths separately for
ingress, RKG, Galois and terminal sources. With the minimum current census,
`ceil(log2(C))=31`, yielding ingress/RKG/Galois widths 182/191/183.
It does not change the actual samplers.

TODO: Establish the complete coalition/simulation model and malicious-source
extraction bounds, enumerate all public views, and enforce an agreed session
census. The finite-box calculation alone is not a whole-protocol privacy proof.

## Exact feasibility

The current 151-bit evaluated-key CKS contribution yields switch bound 494,
final residual bound 2,287 and terminal smudge width 2,027. The exact comparison
`2*(2^2287-1) < Q` fails. This means this sufficient correctness certificate
does not close; it does not show every evaluated ciphertext is incorrect.

The existing response sampler would need a 2,056-bit mask and a 258-byte
signed response coefficient. Its actual capacity remains 2,048 bits.
The exact terminal payload is 35,913,783 bytes, above the unchanged 32 MiB
ceiling. The hypothetical minimum-census allocation instead gives terminal
width 2,122, final bound 2,382 and 37,355,575 payload bytes. It also fails.

For the raw/direct alternatives, the recorded-coefficient recurrence gives
final bound 2,115 and a 33,030,199-byte terminal payload. Those arithmetic
checks pass but do not supply the missing admission or privacy theorem.
All three constructions retain the current native combine residency lower
bound: nine 38-limb polynomial payloads total 342 MiB, above the 160 MiB
workspace ceiling. This is a necessary residency check, not a peak-memory
certificate.

The diagnostic has separate exact non-secret integer arithmetic so it can
report masks that the existing runtime refuses. It neither enlarges runtime
integers nor changes any sampler, proof layout, cap or readiness conjunction.

## Validation contract

The candidate preserves every original noise test verbatim. New tests cover
the actual corrected schedule, raw/direct admission separation, exact
same-bit-length modulus boundaries, purpose-specific and monotone query
allocation, missing party/digit/key census refusals, and distinct rotation
versus relinearization inputs. Ninety-six small exact negacyclic cases test
weighted-pair, CKS and direct-normalization identities; all 96 detect omission
of the CKS residual. Finite-box controls independently enumerate overlap.

Source review and formatting do not establish compiled execution. Run the
new tests, retained noise/direct/resource/readiness tests, and strict
all-target lint on the composed source before claiming component validation.
The original genuine-proof `EngineUnavailable` failures remain unresolved.
