# B6 application-reduction reconciliation

This records the conditional [application joins](../../../specs/parliament_ballot_b6_application_reconciliation.md)
for `IdealFrontierSim`. Development testing remains enabled. No profile is
selected or qualified, and binding production activation remains gated.

## Result and scope

The note defines the changed credential experiment `P_F`, supports its
false-input totality at the mathematical source-model boundary, and derives
the privacy and properties 2/3/8 bounds using that experiment. The original
`Sim+` premise cannot automatically be reused. Valid-witness ZK is invoked
only where real witnesses exist; soundness and existential uniqueness remain
real-game premises. No numerical value for the new premise is established.

The query audit separates the required adversary budget from an aggregate
non-prover budget. It retains the original meaning of `q_pub` and avoids
double charging induced verification or target-oracle dispatch. A complete
adversary-to-aggregate conversion is still missing.

The captured candidate VOTE request circuit costs
`166702860207775482442106240502206` elementary gates per specified body at
the stated lifetime-sized log. Repeating that circuit `2^44` times gives
`2932667730911459172349823042824132140461981696 > 2^151` gates. This is an
exact multiplication of captured structural metadata, not circuit execution,
a family maximum, a lower bound on all reductions, protocol runtime or an
attack. It supplies no AES advantage estimate.

## Validation

- Three local agents reviewed the privacy/totality, authorization/counting,
  and resource boundaries. No blocking finding remained. Three resource
  wording clarifications were applied: backend-call units, the extra work
  in real/mixed drivers, and no impossibility inference from gate counts.
- Python 3.11 checked the integer product and strict `2^151` inequality
  directly against the retained request observation. It also checked the
  illustrative `(1+744)*2^64` conversion and `1001*1000` guess count.
- All 22 scoped input hashes remained unchanged. They are selected source
  and antecedent evidence identities, not a dependency closure or a new
  authentication of an older build against the current checkout.
- Both preceding composition/entry manifests were verified unchanged
  (20 entries). Local Markdown targets and whitespace were checked.

No executable source changed and no Rust suite was rerun. The local reviews
are not independent cryptographic review, and the checks do not prove a
cryptographic theorem or qualify the current native implementation.

Retained files: [receipt](receipt.json), [inputs](inputs.json),
[integer checks](arithmetic.json), [check results](checks.json), and
[manifest](SHA256SUMS). The manifest uses repository-relative paths and
also binds the new specification. Earlier arguments, calculators and reports
retain their frozen scope and bytes.

TODO: implement and price the whole-lifetime root reduction's complete
oracle environment, with an explicit total dispatcher, persistent overlay
and supplied-oracle versus finite-cost realization boundary. Quantitative
premises, full resources, named hardware and independent qualification remain
open.
