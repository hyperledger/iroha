# Independent review of conditional request-family envelopes

No resource-count or scope discrepancy was found in the reviewed frozen
implementation. The local typed-body envelope follows from the component
census and the source's complete request composition. This is an independent
agent arithmetic review, not an external cryptographic review, production
qualification, a native memory measurement, or an executed adaptive experiment.

The reviewed [implementation](../parliament-request-family-envelope-stage/envelope.py)
has SHA-256 `b48501cde4e69c5f563c1cd890788b57fa143e2a10f83297dfa8fffc83dd2eb4`.
The owner's unchanged 44-test capture receipt is
`45aa1b03470958707588f5e09af9ec4047e385813144297b29840add64191293`.
This review restored its exact 165 selected inputs, added two review scripts,
and verified all 167 selected copies before and after its own execution.

## Source-dependence assessment

The frozen `request_generator.py` constructs REG's variable P1 and original
public-input width from the seven opaque lengths. Its S0, opening, R0 and R1
constructions receive only fixed row/role/trial parameters or fixed-width
registers. R1's REG list count is zero. The supplied public bytes may change
values read by these circuits, but not their gate schedules or work widths.
All P1 outputs and original coin widths remain fixed for REG.

VOTE additionally varies P0 and R1 with actual list count. The totalized P1 in
`content_request.py` is explicitly checked to have the original P1 cost and
output shape before replacement. P0 always contributes 60 retained bits;
R1 always contributes 322; P1's retained width grows by 1024 per list item.
S0/opening/R0 are independent of n. The component census covers the full
admitted 3..1000 size interval, rather than inferring this from endpoint equality.

`stage_plan.py` borrows existing input intervals and relocates static wire
labels, sums clean component costs, retains every stage output, and reuses
the maximum clean workspace. `request_transition.py` executes G, W, E and G
inverse. `content_request.py` uses the same layout discipline with validated
W/E. Therefore the clean P0/P1/R1 component counts appear twice in the full
request. The implementation preserves that second factor of two.

W's source frames and E's proof layout are functions of row/role and the fixed
trial cap, not body/context lengths or list count. Validated W's exact delta is
(-4 X, 4-2M CX, 2M CCX); validated E is two ordinary E calls plus the source masks
and flags. `ContentFamily` then extends the mathematical result by 96 bits
through static relocation without additional gates or work. The review found
those deltas, the retained P0 output, and all return bits included.

The maximum variable VOTE clean workspace is R1's 924930303 bits. It is below
the fixed candidate S0 peak 1872769931 and comparator opening peak 7442924779.
REG P1 is similarly dominated by a fixed generator stage. At the largest
permitted T/b, W work also remains below the fixed generator peaks. Consequently
the source scratch maximum remains fixed across each row/role's shape family.
This is logical circuit storage; no physical allocator interpretation follows.

## Independent checks

All **42 tests passed in 59.95 seconds**, with exact collection/execution
membership and no skipped cases. [test_review.py](test_review.py),
[JUnit](capture/junit.xml) and the [receipt](capture/receipt.json) record:

- Two new full-cap source-factory metadata cases, not present in the endpoint
  observations: candidate REG body 37 with context lengths (0,1,7,63,255,256),
  T=3,b=23; comparator VOTE n=257,T=7,b=4096. Complete gate vectors, all logical
  allocation widths, and G/W/E component vectors match the envelope.
- Eight direct W comparisons against the frozen emitter's resource metadata,
  crossing both rows and roles at (T=1,b=23) and (T=2^64,b=4096). VOTE uses the
  validated wrapper. Every fixed append scan is included.
- All 1996 VOTE row/length gate vectors independently recomputed from the frozen
  n=3 observations plus scalar P0/P1 and the source-derived R1 increment. This
  recomputation does not consume the envelope's component CSV. Public and retained
  growth account for exactly 2048 additional logical bits per list item.
- Separate REG X and elementary maxima. The X witness adds 468 X but removes
  1024 CX and 56 public bits relative to the size endpoint. The exact elementary
  maximum therefore exceeds that witness by 556, while the independently combined
  coordinate upper vector exceeds the exact elementary maximum by 468. The
  implementation does not label that synthetic upper vector an exact attained cost.
- Eight rejected-size comparisons against the frozen header family, including
  u64 maximum descriptors. All borrowed list storage is retained and no native
  Vec reachability or invalid-invocation budget is inferred.
- Sixteen invalid geometry/shape refusals, source drift at both accounting
  boundaries, scratch dominance, and explicit preservation of unpriced terms.

The normal CLI exits 0; `--require-qualified` exits 2 with identical conditional
JSON. Both outputs match the owner's frozen report byte-for-byte, SHA-256
`6aded572ba259f9beae5cc6ca1c78acc95714aab21849662f3d7aa6c64bdffc9`.
These checks build and count source models; they do not expand full gate streams,
run Rust/native code, allocate the described logical storage, sample real proofs,
or provide a new semantic equivalence theorem for the component circuits.

## Custody and remaining limits

[capture.py](capture.py) authenticates the owner's exact receipt and restored
source copies. It executes this review from its own frozen tree with plugin
autoload and conftest loading disabled, then authenticates the selected sources
again. Its [manifest](capture/SHA256SUMS) preserves that tree and outputs.
Installed Python/pytest and their runtime remain trusted; full runtime closure
is unclaimed. The original code, component package and both earlier captures
are unchanged.

The accepted boundary is a conditional local body map at M=2^20, log-sizing
T in 1..2^64 and length width b in 23..4096. The descriptor and typed-entry premises,
canonical log/capacity and supplied clean registers remain caller obligations.
The historical Cargo identity is restored for the review; this does not qualify
the changed current native candidate.

TODO: price and validate raw entry/constructors, application witnesses, authority,
family selection and descriptor authentication, all input/coin preparation,
initialization, external F queries and adversary work, adaptive composition,
primitive bridges, native workspace, baseline hardware and independent review.
The local body envelope can close the stated family-arithmetic gap while all
full-resource and production qualification flags remain false.
