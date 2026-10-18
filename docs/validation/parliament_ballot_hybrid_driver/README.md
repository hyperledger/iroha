# B6 bounded hybrid-driver proposal record

This record freezes the
[proposal](../../../specs/parliament_ballot_b6_hybrid_driver.md) and its
[source receipt](receipt.json). It adds no executable simulator, primitive
advantage, complete reduction, quantum resource certificate or production
change. The existing arguments and numerical ledger remain unchanged.

The proposal makes the auxiliary exhaustion schedule bounded from the first
material hybrid, specifies root/path/leaf/row challenge uses and cached
openings, and identifies the unresolved uniform-over-opening H5 lemma and
actual primitive-game embedding. Its local distribution and algebraic
identities do not discharge those obligations.

The root agent completed a local consistency review of the schedule,
fixed-opening identities, hidden-key and cache rules, and the actual-IV
interface. That review requested no corrections. It is not independent
cryptographic review or proof of the H5 lemma, primitive embedding or complete
computational resources. Every corresponding qualification flag in the
receipt remains false.

The receipt pins 18 existing source/specification files, checked unchanged
during authoring and again at freeze. These hashes identify the examined
inputs; they do not establish proof correctness. Seven proposal-local links
were checked. No code or runtime tests apply to this documentation-only
proposal, and none are claimed.

From the repository root, verify the three frozen artifacts with:

```sh
shasum -a 256 -c docs/validation/parliament_ballot_hybrid_driver/SHA256SUMS
```

The manifest covers this README, the receipt and the proposal. It does not
repin previous B6 reports, measurements or manifests. Production remains
gated, and owner acceptance and independent review remain outstanding.
