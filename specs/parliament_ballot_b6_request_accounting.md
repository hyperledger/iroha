# B6 candidate request primitive accounting

Status, 2026-10-13: **a source-bound component calculation, not qualification**.
This resolves one ambiguity in the nominal request subtotal in
[arguments §8.5, equation (97)](parliament_ballot_proof_arguments.md).
The current candidate verifier exceeds 4,096 Keccak permutations during public
preparation. That number remains usable as the **intercept of a coupled
inequality**, not a pointwise bound on all preparation. No primitive premise,
policy budget, total gate cost or profile acceptance follows from this check.
The historical ledger and its reports are unchanged.

## Entry, units and stages

The entry is the bounded cold `TEST_RECORD` call in
[`resource_contract/budget.rs`](../crates/iroha_parliament_ballot_proof/examples/resource_contract/budget.rs),
including fresh profile construction and statement decoding followed by the
ordinary public verifier. Its work upper bounds also cover the ordinary public
verifier called on an already decoded bounded statement. Registration uses
maximum opaque fields; votes cover every `S` from 3 through 1,000.

`w` adds **logical AES input blocks** to **Keccak-f permutations** solely in the
same nominal units as (97). The counts come from the reviewed standalone
[source schedules](parliament_ballot_b6_standalone_resources.md). AES provider
key schedules, unused batch lanes, field arithmetic, parsing/copy/check work,
allocator/runtime work and elementary-gate conversion are not included.
`q` counts completed designated backend hash calls induced by this request,
including `H_mu`; it is part of the argument's `q_pub`, not the new abstract
verification reservation unit.

The reviewed normal-return branches are:

1. **Input or statement rejection, `q=0`.** The cold entry constructs one
   profile. A vote can then hash one bounded list before rejecting its digest;
   malformed size, order, vote or framing fails no later. Registration can hash
   one bounded body context before rejecting. The maximum is 2,408 permutations
   for a candidate vote, or 686 for registration.
2. **Strict proof-codec rejection, `q=1`.** A valid bounded statement completes
   preparation, including `H_mu`, before the backend codec. A counter above its
   limit is a concrete reachable example. At `S=1,000`, cold preparation costs
   7,548 permutations; ordinary preparation costs 5,140. Excluding `H_mu`, these
   are 6,602 and 4,194 respectively, both above 4,096.
3. **Codec-valid completed verification, `q=744`.**
   [`codec::decode_as`](../crates/iroha_zkp_vole/src/codec.rs) already checks the
   counter, grinding bits, opening-node bound and padding before
   [`proof::grinder_of`](../crates/iroha_zkp_vole/src/proof.rs) reconstructs.
   Reconstruction repeats those checks on the same bytes. Remaining typed
   errors concern fixed row, length, table and relation invariants; arbitrary
   256-bit field bytes have no additional canonicality restriction. For these
   fixed valid invariants, there is no further input-dependent refusal before
   the final challenge comparison. The call count is
   `1 H_mu + 1 H4 + 1 H0 + 34 H1 + 704 H5 + 3 challenges = 744`.

The transition claims are a source review, not a control-flow proof extracted
by the arithmetic checker. They assume execution of the pinned correct
profile/relations through an ordinary return. Process abort, panic,
cancellation and resource failure are outside this partition and cannot be
called invalid proofs by using this note. The separate worker contract owns
those outcomes. The caller does not mutate the owned decoded statement between
its first and repeated validation. Bounded successful preparation has no
remaining input-driven frame/namespace error; fixed implementation failures
are not charged as an attacker-controlled alternate branch here.

## Exact coupled bound

Keep the candidate coefficient already appearing in (97):

```text
C = (2,750,672 + 65,536) / 740 = 704,052 / 185.
w_request <= 4,096 + C q_request.
```

For candidate vote `S=1,000`, which maximizes these preparation bounds:

| Normal-return stage | `w` upper bound | `q` | Exact unused allowance |
| --- | ---: | ---: | ---: |
| Input/statement rejection | 2,408 | 0 | 1,688 |
| Strict proof-codec rejection | 7,548 | 1 | `65,432 / 185` |
| Codec-valid completion | `2,750,672 + 15,917 = 2,766,589` | 744 | `12,753,483 / 185` |

All margins are positive. The checker verifies both roles and all 998 admitted
vote sizes using exact rational arithmetic. Consequently, for any finite
sequence of these completed candidate requests,

```text
sum w_request <= 4,096 N_requests + C sum q_request
              <= 4,096 N_requests + C q_pub.
```

The last inequality uses the argument's definition that `q_pub` includes
**every** backend call induced by public verification. Excluding `H_mu` or
forgetting an early request's calls invalidates this derivation. With the
already declared nominal caps `N_requests <= 2^64` and `q_pub <= 2^64`, this
recovers the existing request contribution in (97), without increasing its
numeric subtotal or pretending that 4,096 alone bounds preparation. Summation
is valid for adaptive request choices because each completed request obeys
the same pointwise coupled inequality.

The candidate coefficient is **not transferred to the comparator**: the
checker includes a comparator `S=1,000` case for which it fails. The independent
resource contract may reserve one abstract unit for either row; that does not
extend the candidate cryptographic ledger to another row.

## Reproduction and remaining scope

```sh
python3.11 scripts/check_parliament_ballot_request_accounting.py --json
python3.11 -m unittest discover -s scripts/tests -p parliament_ballot_request_accounting_test.py -v
python3.11 scripts/check_parliament_ballot_request_accounting.py --require-qualified
```

The last command returns 2. The
[retained JSON](../docs/validation/parliament_ballot_b6/request_primitive_accounting.json)
pins 77 reviewed source/formula files and identifies the checker and tests.
Source drift refuses the component calculation rather than silently repinning
it. This is a symbolic source check, not a compiled-binary execution receipt or
hermetic build manifest. No timing measurements or new cryptographic vectors
are claimed.

This closes only the **request-stage allocation of nominal primitive counts**.
It leaves the [security review's](parliament_ballot_b6_security_review.md)
simulator/final-comparison costs, actual generator reduction interfaces,
primitive/model bounds, gate/memory/advice/preprocessing accounting and
independent assessments unresolved. In particular it does not prove complete
`W < 2^77`, supply a total resource vector, or turn the hypothetical substitution
into a security certificate. Production framing, ingress work and committed
capacity remain separate obligations.
