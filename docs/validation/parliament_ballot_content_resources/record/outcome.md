# Retained outcome

Both commands in [the receipt](capture/receipt.json) exited zero. Four exact
metadata constructions completed in 139.58 seconds, followed by independent
scalar checks in 0.05 seconds. The 152 selected machine sources, 158 unique
watched files in total, and executing Python identity were unchanged before and
after. The observation additionally identifies 34 loaded repository modules.
The [arithmetic checks](capture/checks.json) rejected all seven deliberately
changed report examples. Neither command streamed the complete gate sequence.

All four cases use M=1,048,576, T=17,592,186,044,416, b=64 and
N=T(M+2). Each has 31,790,755,097,454,963,270,352,896 persistent log bits and a
65-bit position counter. Counts below describe one request using that log.

| Row | Public list count | Elementary gates (X+CX+5 CCX) | Base F calls | Total logical bits |
| --- | ---: | ---: | ---: | ---: |
| Candidate | 3 | 166702860207775482442082173872041 | 6200 | 31790755097454965698582019 |
| Candidate | 1000 | 166702860207775482442120717732401 | 6200 | 31790755097454965700623875 |
| Comparator | 3 | 166702860207775484569776903826639 | 5960 | 31790755097454971267526803 |
| Comparator | 1000 | 166702860207775484569815447686999 | 5960 | 31790755097454971269568659 |

P0's clean stage has 28,242,528 elementary gates at list count3 and
7,225,099,904 at count1000; it appears twice through G and its inverse. The common
return has 1,864,349 bits for candidate and 1,264,845 for comparator, each exactly
253+8*proof_bytes. Its extra 96 wires have no added gates. Shared work is the
maximum of the clean stage/W/E regions: 1,872,769,931 bits for candidate and
7,442,924,779 for comparator. The full X/CX/CCX vectors, original coins, retained
registers, validated W/E and P0 stage records are in the
[observation](capture/observation.json).

The older accepted-only observation is unchanged. At n=1000, its generator
forward census plus exactly one P0 stage equals the new forward census; the
new retained outputs add60 bits and the common return adds156 bits to its
original proof/exhaustion return. This comparison does not alter the old
observation's scope.

These four cases do not prove a maximum across public shapes, a complete
adaptive-lifetime resource vector, an implementation of the raw request
dispatcher, a native cost bound, or an accepted cryptographic reduction. The
explicit fixed-scan log dominates these mathematical counts. All qualification
flags remain false, and no production or published source was changed.
