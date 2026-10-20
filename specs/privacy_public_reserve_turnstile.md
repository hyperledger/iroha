# Funded public reserve turnstile

P.2's existing Orchard and private-IVM public bridge uses one mandatory
`funded_allowance: Quantity` on the exact `PublicReserveCustody` record. The
record binds the full asset ID (definition, account and balance scope), pool
namespace and bootstrap digest. Bootstrap starts the allowance at zero,
including when the reserve already has a balance. There is no old-layout
fallback or default for a missing encoded allowance.

The original `PreparedNumericAssetMovement` apply owner performs the public
movement and updates this record in the same disposable State transaction:

- A typed, verified pool deposit increases the allowance by the exact existing
  transparent units debited from the submitter and credited to the reserve.
- A typed, verified withdrawal decreases it by the exact reserve debit and
  recipient credit. Both the reserve balance and allowance must cover the debit.
- Ordinary incoming transfers, mint credits and bootstrap commitments do not
  increase allowance. They cannot authorize a public withdrawal.
- Apply rechecks the exact current custody, owner, live balance delta, asset,
  scope and existing backing. A stale or duplicate prepared delta refuses.
  An inconsistent retained counter is not clamped or repaired by a top-up.

Only the governed bootstrap owner can claim custody. Retail wallet enrollment
cannot grant this status. Maintenance still assesses an enrolled reserve's
period, but cannot spend its backing. An ordinary wallet continues to pay its
existing maintenance fee. Payment-fee finalization rechecks custody installed
after principal execution and rejects the complete transaction rather than
waiving the fee. A malformed row targeted at that exact balance refuses;
unrelated rows do not change the decision.

Restore preserves the counter and requires its value to be at most the exact
retained balance; a missing balance is valid only for zero allowance. Existing
bootstrap, pool-root, nullifier, custody uniqueness and dependency checks remain
in force. The counter lives in the existing canonical `privacy_commitments`
map; it adds no side ledger or separately authoritative cache.

The focused candidate built from the current optimizations source plus these
reserve and tiered-accounting changes passed 127 Core and 9 CorePrivacy tests.
Those checks exercised both reserve owners, ordinary top-ups, exhaustion,
stale and duplicate deltas, owner/asset/scope substitutions, restore, fee
periods and disposable transaction rollback on that captured source.

TODO: qualify the native proof/effect path, current generated schemas and State
inventory, and original transaction rollback with the remaining composed
transaction changes. The focused component result does not qualify those
paths or the release. P.2 remains in progress while the economic work below
is locally implementable.

TODO: specify and implement relation-bound hidden issuance and supply allowances,
including private-IVM bootstrap notes, plus the remaining cross-pool economic
contract. A public net-deposit counter bounds aggregate withdrawals; it does
not prove hidden conservation or entitlement and cannot prevent an erroneous
proof from stealing another depositor's funded allowance. It creates no new
FCMP++ or PQ-MASP public bridge. See `specs/zk_economic_invariants.json` for the
remaining findings and `specs/zk_delivery_plan.md` P.2/P.16/P.18 for acceptance.
