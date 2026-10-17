# Accepted-request resource observation review

Local consistency review is clear for the stated boundary: one accepted, fixed-shape atomic request, with a chronological log sized for at most `T=2^44` requests and the full `M=2^20` primary and auxiliary tapes. This is not independent external cryptographic review, complete qualification, or a claim of a family-wide maximum.

The reviewed observation is `target/parliament-ideal-machine-stage/request-accepted-observation.json` (SHA-256 `81ffb1db693c94f73f41239da3cd8164893d9c84ddd805d873ec3ede974f4f4c`). The independent arithmetic checker imports none of the circuit factories. It verifies all 38 semantic-source pins and 30 implementation/dependency pins before and after, all four row/role cases, all transcript field offsets, the source proof length, input/randomness partitions, retained stage-output widths, full enabled-append/framing census, return census, component sums and false qualification fields. The full generator's individual kernel gate totals are not reexecuted by this review; their existing component reviews remain premises.

The scalar checks use the actual source dimensions: candidate `tau=33, g=704, T_open=229`; comparator `tau=22, g=696, T_open=225`; REG `ell=35840`, VOTE `ell=53504`. REG's observed public shape has a 4096-byte body and six 256-byte context fields. VOTE's observed shape has exactly 1000 entries. The four cases are endpoint observations; selecting those endpoints does not itself prove a maximum over all shapes or contents.

For one request the private-input count is exactly

```
512*M + 256*T_open + 896*tau + tau*ell + 10*g + 736*8 bits.
```

This includes both complete challenge tapes, all padded frontier coin slots (including unused slots), all hidden commitments, correction and masked-witness coins, and fixed IV/salt/challenge/response coins. No private tape is silently reset by the clean inverse. The single request's public and private inputs are counted only once even though W/E borrow many of the same fields.

The allocation is the sum of the original inputs, one caller return, all retained generator stage outputs, one shared scratch allocation, the lifetime-capacity log and its counter. Shared scratch is `max(generator scratch, write staging/append scratch, E scratch)`; W input fields are borrowed, not separately allocated. The log has `N=T*(M+2)` records, each containing one active flag, a 64-bit key length, 215150 message bytes and 264 response bytes. The counter has 65 bits, so the completely full value N is representable. All M+2 fixed append scans and their disabled iterations are charged.

F calls derive independently as

```
2 * [P1:8 + opening:(8*tau + 12 + 4*g)]
= 6200 candidate, 5960 comparator.
```

The outer factor includes the complete generator inverse. Programming and return use no F calls. Generator reads have final domains 0/1/4/5/8, so bypassing the persistent overlay is valid only under the established log domain invariant 9/10/11, one immutable source-padded F, and no request interleaving. Concrete public SHA3/SHAKE/AES arithmetic is counted separately from ideal F calls. This read also checked the `RequestTransition` field remapping, retained-versus-scratch boundaries, W forward/true-inverse order and E target mapping; no alias or omitted overlap was found.

These counts remain **per request**, despite the lifetime-sized log. They exclude the costs of other requests, external adversary queries/L0, adversary and base-oracle state, random-input preparation or any purifying registers across requests, and content-invalid or malformed-shape dispatch. A complete lifetime vector must name and charge those separately; tracing private tapes in a classical mixture does not establish a free coherent reset. The observation flags those limits and does not claim physical 64 MiB workspace or production qualification.

Validation command:

```
PYTHONDONTWRITEBYTECODE=1 python3 -B target/parliament-request-resource-review/check.py
```

It passed all four cases with stable 68 selected pins. While authoring the independent checker, its first two exploratory runs caught my own arithmetic transcription errors (a 32-byte salt omitted from the fixed proof-byte subtotal, and one extra 64-byte field in the VOTE public-input subtotal); both were corrected from the explicit source field inventories before the successful result. No observed implementation or report defect was found. Only this ignored review directory was written; no circuit, source, tracked evidence or frozen artifact changed.
