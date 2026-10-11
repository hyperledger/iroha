# Conditional accounting argument

This argument describes [`accounting.py`](accounting.py), the committed-operation
projection of canonical design §§3.2, 5 and 6. It is conditional on authentic
Load issuance, exact operation ownership and ordinals, the provider's single
successor rule, correct native/circuit checks, and complete lineage obligations.
Those premises are not established by this Python model. This is not a proof of
the concrete PLONK system, C12, native finality or the implementation refinement.

## Core and lineage

For wallet i, let Bᵢ be its committed core balance, Dᵢ its last completed lineage's
burned total, and Eᵢ the amounts that its committed, not-yet-folded Receive steps
will deterministically burn. Eᵢ is a specification ghost value. A wallet does not
learn or spend against a guessed future verdict. Define the accounting balance

`Nᵢ = Bᵢ − Dᵢ − Eᵢ`.

All Send, Unload and Retiring transitions require a durable fold of the current
head. At that point Eᵢ = 0, and their checked available balance is Bᵢ − Dᵢ. A
completed fold moves Eᵢ into Dᵢ without changing Bᵢ or Nᵢ. A core balance from an
unfolded Receive therefore cannot authorize another debit.

The model separately tracks the core and lineage-adjusted pending sets. Archive
may remove a core descriptor before its lineage verdict is known. A failed
Archive keeps the adjusted descriptor. Send, Unload and Retiring take that
adjusted set from their folded predecessor and write it back into the core.
Collection requires a successful Archive covered by a durable fold, and keeps
the independent unpaid fee original. Neither Archive branch affects value.

## Disjoint reserve categories

Let L be funded but unabsorbed Load amounts, T undelivered Send amounts, F earned
but unpaid Send fees, U unpaid Unload face amounts, and K the backing of genuine
Send credits whose first Receive takes the burn branch. Let R be the reserve.
The invariant is

`R = Σ Nᵢ + L + T + F + U + K`.

Every term is nonnegative. A malformed, unbacked incoming object does not create
a deposit or reserve liability: its amount is added to Bᵢ and Eᵢ together, so
Nᵢ is unchanged. In particular, summing every wallet's burned counter as K would
be wrong; it would count unbacked rejected input as real money. K includes only
amounts removed from an existing backed in-flight credit.

The per-wallet equality is also checked independently:

`Bᵢ = absorbed Loadsᵢ + first Receive amountsᵢ − gross Sendsᵢ − Unload facesᵢ`.

This prevents a transfer between unrelated wallet states from passing merely
because the aggregate sum stays constant. First credit identities remain
permanent; changing a consumed credit's original is rejected, and exact retry
does not append another effect. Load, Send and Unload ordinals are checked per
wallet. Ledger payouts and fees have permanent paid identities.

## Transition induction

Initially all money is online and every reserve term is zero. For each permitted
atomic model transition, the following deltas preserve the invariant:

| Transition | Reserve and category changes |
| --- | --- |
| IssueLoad of net a | R += a; L += a. Its separate online charge goes directly from payer to beneficiary. |
| Absorb exact next Load | L -= a; Nᵢ += a. Replaying the absorbed receipt changes nothing. |
| Send amount a and fee f | Nᵢ -= a+f; T += a; F += f. Delivery loss never reverses this step. |
| First accepted Receive | T -= a; Nⱼ += a. |
| First backed Receive with failing lineage input | T -= a; K += a. Bⱼ and Eⱼ both increase by a, leaving Nⱼ unchanged. |
| Rejected unbacked Receive input | Bⱼ and Eⱼ both increase by a; no reserve category changes. |
| Completed fold | Dᵢ += Eᵢ; Eᵢ becomes zero; Nᵢ is unchanged. |
| Unload face a | Nᵢ -= a; U += a. |
| First Unload payout | R -= a; U -= a. The bound account receives a−c and the quoted beneficiary receives c, with 0 ≤ c ≤ a. |
| First fee payout | R -= f; F -= f. The fixed beneficiary receives f; Receive need not have happened. |
| Archive, collection, delivery copies, Retiring, CloseLoads and exact retries | No monetary category changes. |

The checked debit guard prevents negative Nᵢ. Funded issuance and first-identity
guards prevent removing a liability twice. Finite unsigned bounds reject core
overflow before commit, including an invalid Receive whose optimistic Bᵢ would
overflow. The same algebra applies for any finite number of these transitions,
wallets or hops; it does not depend on an acyclic transfer graph. This is the
inductive invariant of the abstract transition system under the premises above.

Online balances, the fee account and R also sum to their initial supply. The
model recomputes each bound account's debit/payout from voucher and claim
records, and the fixed beneficiary's balance from charged/paid fee records.
Paying twice or redirecting fees cannot be hidden by conserving the aggregate.

## Scope and remaining proof obligations

The local suite exercises three-wallet onward spending, splits, cycles, delayed
delivery, both Receive outcomes, mismatched duplicate originals, Archive no-op
resynchronization, independent fee custody, pre-closure Load races, late Receive
after Retiring, checked integer boundaries and eight deliberately invalid state
mutations. `schedules.py` adds exhaustive finite accounting graphs and reachable
transition-mutation counterexamples; the exact completed bounds and counts are
recorded in the [model README](README.md). Its larger three-wallet graph exhausts
the declared one-Load/two-Payment/one-Unload vocabulary. Neither those finite graphs nor the
example schedules exhaust the full monetary state graph. The provider model's
exhaustive counts apply only to that separate provider abstraction.

`publication_accounting.py` checks one bounded product with that provider: two
Send capsules compete for the same funded, folded old head. Selection projects
the unique irreversible debit and in-flight liability before signing completes;
it does not make a Payment available. Only released original custody can populate
delivery bytes. Every provider crash, uncertainty, loss and repair transition
preserves that monetary projection. Receiver replay cannot add a second credit,
and a carrier original remains usable after loss of the payer's copies. The
3,076-state graph and four composition mutations are scoped in the README.
Authentic prior funding, the receiver's own durable operation and successful
fold verification are still premises, rather than newly proved subprotocols.

Requests and their historical policy, signatures, ownership, schemes, assets,
reserve authority and proof verdicts are abstract premises. `send` consumes an
already authenticated Request; permitting a retired receiver models a Request
quoted before retirement, not permission to issue a new quote. Variant 1 models
post-commit fault containment, not ordinary native admission of malformed data.
`fold` represents successful durable completion of the current lineage; it does
not model intermediate A/W checkpoints, partial folding or power-loss behavior.
Permanent credit/ordinal records are never pruned in this model.

TODO: Extend the one-Send product to every operation and multiple concurrent
wallet/provider heads. Model enrollment markers, actual quote and
historical-control transitions, fold scheduling/preemption and source custody.
Establish native/circuit refinement for every guarded operation and independently
review the argument. Until then this conditional induction does not establish
conservation for the implementation or complete unbounded-hop protocol safety.
