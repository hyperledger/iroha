# Conditional complete typed-request body envelopes

This stage combines the frozen component family census with the frozen complete
request observations. It derives exact local body resource counts for every
bounded typed REG shape and every bounded VOTE content shape, then reports
coordinate maxima at explicit M=2^20, log-sizing T in 1..2^64, and b in 23..4096.
It does not execute or price a complete adaptive experiment. The original
circuits, ledgers, observations and published evidence remain unchanged.

## Source-dependence proof

In `request_generator.build_generator`, the only uses of REG opaque lengths are
`prepare_public(shape,...)` and the original `public_preparation` input width.
The accepted REG list count is fixed at zero. `ell=35840`, the relation and
R1 public width, row geometry, schedule cap, opening dimensions, CRT matrices,
VOLE columns and R0 dimensions depend only on role, row and M. The schedule
receives only the row geometry and M. Opening receives fixed-width namespace,
iv, salt, challenge and original coin registers; their **values** can change
without changing the gate schedule. R1(REG,0) never receives opaque lengths.
The original coin sum excludes the public preparation width and adds precisely
the supplied 128-bit iv_pre plus 256-bit salt, so changing body/context lengths
does not silently remove or add coins.

Thus only P1's gates and original public storage vary over the REG domain.
P1 always returns 6376 bits. The component proof shows its history and maximum
scratch are constant across all seven lengths. More conservatively, its largest
work region is strictly below the full generator's observed maximum. Since the
other stages are fixed, that larger maximum is attained by a fixed stage and
remains unchanged for every REG shape. Retained stage outputs are fixed.

For VOTE, `ell=53504` and the row geometry are independent of actual list count.
The only varying construction calls are P0/P1 and
`QuickSilverResponse('vote',n,...)`. P0 returns 60 bits; P1 returns
7976+1024*n bits; R1 returns 322 bits. The full source component census covers
each integer n=3..1000, including its nonmonotone prefix-popcount terms before
confirming coordinatewise monotonicity. The captured n=3 and n=1000 observations
have identical S0/opening/R0 gates, work and input/output widths per row. The
source call graph proves independence at the intervening sizes; endpoint
equality alone would not do so. P1 namespace/iv/salt positions relocate with n,
but `RetainedPlan` and `RequestTransition` apply static integer wire maps,
without gates or extra copied input registers.

Candidate's fixed S0 peak is 1872769931 work bits; comparator's fixed opening
peak is 7442924779. All variable P0/P1/R1 work is smaller throughout the bounded
family: the largest R1 work is 924930303 bits at n=1000. The complete generator
scratch maximum is therefore fixed per row. The component census and its source
derivation establish this across the full domain, not only the four observations.

`actual_transition` builds W and E from row/role/M/T/b, without opaque lengths
or n. Their field widths are fixed and the source mapping borrows existing
registers. `ContentRequest` adds validity-controlled W and typed E; their exact
cost delta depends only on M and the fixed proof length. `ContentFamily` adds
96 caller-output bits by wire relocation, with no added gates or clean work.
Both valid and invalid bounded content execute the same fixed schedule; invalid
content's returned contribution and log identity do not refund computation.

The local request executes G, W, E and G inverse. Component census costs already
include each component's clean compute/copy/inverse. The generator's additional
forward/inverse traversal therefore multiplies those component costs by **two**
again. W uses its actual single forward mutation cost; E its single clean map.

## Exact maxima and storage

REG P1's elementary cost increases with every opaque byte, even where prefix
popcount decreases. The bounded size endpoint B=4096, c_i=256 maximizes full
request elementary gates, CX, CCX, public input and total logical storage.
The X maximum instead occurs at B=4095, c_i=255: both hash-block maxima and all
prefix-popcount maxima coincide there. The full request has 468 more X, 1024
fewer CX, 556 fewer elementary gates and 56 fewer public bits at that witness.

`exact_coordinate_maxima` reports separately attained maxima. It is not a single
cost vector and does not assert simultaneous attainment. The separate
`coordinatewise_gate_upper_vector` obeys X+CX+5*CCX; its REG elementary value is
468 larger than the exact elementary maximum. The two complete attaining cases
are retained separately. For bounded VOTE every coordinate is nondecreasing in
n, so n=1000 simultaneously attains the displayed maxima. Constant coordinates
can have additional maximizers.

Each exact body count retains all original public inputs and original coins,
the full caller output, all retained G outputs, one persistent log and counter,
and max(G scratch,W work,E work), with no duplicated borrowed fields. The log
has N=T*(M+2) slots of 1+b+8*215150+2112 bits. Its counter has
max(2,bit_length(N)) bits. Changing T/b rebases W and all persistent/work widths
through the frozen independently checked W formula; fixed G/E costs are not
scaled by T. T is a log-sizing parameter here, not an inferred valid-request or
invalid-invocation budget. A caller must establish the canonical log/capacity
premise separately. Logical wires are not physical qubits or native allocation.

Rejected actual VOTE sizes are reported separately. For a fixed u64 descriptor
n outside 3..1000, cost is 5881+2*popcount(n) elementary gates, zero F calls and
519 clean work bits, plus 3608+1024*n borrowed public input bits and the complete
253+8*proof_bytes caller output. The descriptor n=2^64-1 attains the conservative
u64 gate/storage maxima. This does not establish native Vec reachability,
descriptor authentication, raw decoder semantics or any invalid-call budget.

## Custody, validation and remaining work

The checker authenticates 161 selected inputs: the frozen 154-input base/content
catalog, four component-review scripts and three component-capture records.
It reads and parses exact authenticated observation/census buffers, verifies
source identities before and after accounting, and refuses source drift.
`capture.py` restores frozen source snapshots into an isolated tree because the
live Cargo manifest has changed. Its receipt records collection, JUnit results,
CLI refusal and input stability. This historical-source body model is not a
qualification of the changed current native candidate. Installed Python,
pytest and their runtime are trusted; no full runtime closure is claimed.

Unknown work remains explicit: raw input construction, application witnesses
and authority checks, family selection and descriptor authentication, all
input/coin preparation and purification, initialization, external queries and
adversary resources, the adaptive controller, base-oracle implementation,
primitive entry/advantages, physical verifier workspace, required hardware and
external review. `--require-qualified` always returns the same conditional
JSON with exit 2. All full-experiment and production qualification flags remain
false. No new request admission limit is introduced.

TODO: discharge those obligations before any complete resource or qualification
certificate. The full local typed-body envelope closes only the explicitly
specified body-computation family gap.
