# Nexus Fees and Sponsor Programs

Nexus fees use a quote-to-sign protocol. A transaction always carries a typed,
signature-bound `FeePaymentIntent`; fee sponsorship is never inferred from
metadata and never falls back to charging the sender after a sponsor rejection.

Authenticated genesis bootstrap execution is additionally fee-exempt.
When Core applies the genesis block against an empty committed block history,
it bypasses fee-intent admission and fee settlement so bootstrap state does not
depend on balances, sponsor revisions, or receipt leases that genesis has not
created yet. Public fee quotes and every non-genesis transaction retain the
strict quote-to-sign, admission, and settlement rules described below.

## Committed root monetary policy

Genesis authors exactly one `root_fees_v1` custom parameter containing
`RootFeePolicy`: typed currency, sink, sponsor custody and claim-exempt account
identities plus the four decimal rates. `StateParameters` retains its validated
projection beside the original canonical parameter. Each block and quote view
captures that exact version; same-block `SetParameter` instructions cannot change
that block's admission, charge, output receipt or execution-policy commitment.
Restore rebuilds the projection from the original parameter bytes. Missing policy
is permitted only before H1; ordinary execution and quoting reject absence.

Global execution burns the exact signed network XOR currency. A data space root
burns its own registered, currency restricted to that data space and requires positive base
and gas rates. Public claim exemptions and public sponsor vaults cannot authorize
private-root fees. The typed sink remains the receiver for SCCP and SoraCloud fee
transfers; alias changes cannot redirect it. Currency and sponsor custody are
immutable after H1. Authorized changes of rates, sink and Global claim exemptions
apply from the next block. Signed fee limits, sponsor authorization, rejection
charging and conservation rules remain mandatory.

Node configuration has no monetary fee table or settlement-mode switch. Genesis
recipes explicitly author the intended defaults. Mainnet source-template
materialization binds the operator's accepted canonical XOR into both NPoS and fee
policy before signing. Startup retains both the signed execution-policy and Nexus
context digest checks; deployment readiness reads the fee policy through the
canonical authenticated-original-genesis helper.

The causal regression changes only a mutable process-local copy after identical
H1: the previous executor rejected a signed maximum of one or charged two instead
of one. This does not demonstrate two differently configured fresh nodes passing
startup: their signed-genesis digest checks already refused mismatches. The new
regressions additionally cover complete State results, receipt identity, committed
updates and final-tip certified replay. Full candidate compilation, generated
fixtures and network qualification remain pending.

A signed `FeePaymentIntent` selects the authority or one exact sponsor program and
immutable revision, plus a positive gas limit where required and canonically ordered
maximum charges. Retired fee metadata remains rejected. Successful public SORA v2
claims compare the authority directly with the committed typed exemption set.

## Quote, sign, submit

Clients should use the following flow:

1. Build one exact unsigned `TransactionPayload`. Fix the chain, authority,
   executable, timestamps, nonce, metadata, payer, exact sponsor-program
   revision, and gas bound. Charge maxima may initially be empty.
2. Account-sign `POST /v1/fees/quote` with JSON `{"payload": <payload>}`. The
   request signer must be the payload authority.
3. Inspect the returned ledger observation, canonical route dataspace, charge
   components, sponsor capacities, debit source, and recommended intent.
4. Verify that the quote retained the selected payer, exact program revision,
   and gas bound. Replace only `payload.fee_payment` with the returned intent.
5. Sign and submit that exact payload.

The quote endpoint normally authenticates against the authority's committed
account record. One narrow bootstrap exception permits a canonical single-key
authority that is not yet committed when the payload's first instruction
registers that exact authority. Torii verifies the request with the controller
embedded in the canonical `AccountId`; aliases, multisig witnesses, other
endpoints, and payloads registering another account do not receive this
exception. If the account already exists, its committed controller remains
authoritative.

Torii derives routing through the same queue router used by admission. The
client cannot provide an authoritative route override. Because fees depend on
ledger state, a quote is an observation rather than a reservation; queue
admission repeats the checks and creates deterministic maximum-bound
reservations to prevent concurrent oversubscription.

Rejections include a stable fee code, whether retrying can help, the observed
height, the exact program/revision when applicable, and remediation guidance.
Important codes include `invalid_fee_intent`, `program_not_found`,
`revision_not_active`, `program_not_active`, `beneficiary_not_eligible`,
`operation_not_allowed`, `operation_denied`, `invalid_gas_limit`,
`signed_limit_exceeded`, the three deterministic budget-exhaustion codes,
`vault_insufficient`, `authority_payer_insufficient`,
`relay_capacity_unavailable`, and `invalid_program_configuration`.

## Sponsor programs

A `FeeSponsorProgramId` is the canonical `sponsor-account/program-name`
literal. Program state and funding are consensus-visible:

- `staged`: being provisioned; it cannot sponsor transactions.
- `active`: the active immutable revision may sponsor eligible operations.
- `paused`: deliberately stopped; new sponsorship is rejected.
- `closing`: new sponsorship is rejected while obligations drain.
- `closed`: permanent tombstone; the identifier cannot be reused.

Revisions are immutable and monotonically numbered. The requested activation
height is an earliest bound: consensus postpones the switch until every
unexpired allocation from an older revision has ended. Once activation is
scheduled, old-revision leases must expire before the effective activation
height, so the worker can continue serving the old revision without stranding
locked vault capacity. A revision contains:

- an eligibility mode (`enrolled_only` or `enrolled_or_route_default`);
- ordered allow/deny rules over exact signed operations;
- per-asset transaction, block, program-epoch, and beneficiary-epoch limits;
- a reserve floor and deterministic epoch length.

Rules do not contain wildcards disguised as empty selectors. Native
instructions select an exact registered wire ID and, for asset transfers, may
select an exact asset definition. Contract calls select an exact contract
address, deployed code hash, and entrypoint set. Raw and proved IVM operations
select an exact code hash. A matching deny rule overrides an allow rule.

Eligibility is represented by explicit on-chain enrollment records. A
dataspace may name one exact default program with
`fee_sponsor_program_id`; this grants route-default eligibility only when the
active revision permits it. It does not change the program/revision named in a
signed transaction.

Each program has isolated per-asset vault allocations backed by the configured
`nexus.fees.sponsor_vault_custody_account_id`. Funding moves assets into
custody and credits only the exact program vault. The program record contains
one mandatory, immutable `payout_account`; creation rejects an account that is
not registered, and that account cannot be unregistered while the program is
not closed. `WithdrawFeeSponsorProgram` carries only the program, asset, and
amount: it has no caller-selected destination. Only the exact sponsor account
may authorize a withdrawal, never a program manager, role, or delegated
withdrawal token, and Core releases value only to the recorded payout account
in a paused or closing lifecycle state. One program cannot consume another
program's balance.

Sponsor-program vault assets must use the `Global` balance policy in the first
release. Revision staging, vault funding, receipt-lease registration, and a
later `Global` to `DataspaceRestricted` policy migration all fail closed when
they would create an unscoped sponsor balance. Supporting
`DataspaceRestricted` sponsor assets requires a future scope-keyed vault,
reservation, and spend-lease ledger. This restriction does not prevent an
authority from paying a dataspace-restricted PipelineGas asset in direct mode;
that debit is reserved and settled against the transaction's exact route
bucket.

The committed `ivm_gas_tech_account_id`, `ivm_gas_accepted_assets` and
`ivm_gas_units_per_gas` parameters are the only pipeline fee authority. Missing
fields use protocol defaults. The receiver is a canonical encoded account, with
its carried prefix validated independently of node address settings; aliases
cannot change its identity. Views and block execution use one validated
projection, frozen from the predecessor for the entire block, so a committed
change applies to the next block. Node `[pipeline.gas]` settings are rejected.
Malformed committed fields fail validation or restoration rather than selecting
a local/default fallback. Core keeps the original parameters and their validated
fee and execution-limit projections in one MV value: commit, retained predecessor
and rollback move them together. Binary/JSON serialization commits only the original Parameters
layout; restore rebuilds the projection. Failed validation or a local decode
refusal changes neither value, and ordinary projection reads do not decode.

Governed `ivm_gas_units_per_gas` updates are validated atomically before they
enter consensus state. Asset identifiers must be canonical and unique, TWAPs
must be positive decimals, and liquidity/volatility labels must be known. A
zero `units_per_gas` remains valid when Nexus already settles gas through its
own component. Restoration validates all three fields before runtime use; a
malformed persisted snapshot is refused. Execution consumes the validated
predecessor projection and never refreshes it from transaction-local writes.

Receipt-lane spend leases are source locks. Only the program sponsor or a
delegate holding `CanManageFeeSponsorProgram` may register one. Registration
rejects future source heights, recomputes the proof's source-state commitment
from the authoritative exact program vault, permits at most one unexpired
lease per `(program, revision, asset, dataspace)` route, and rejects any live
aggregate whose unspent remainder would exceed that vault. Allocation submission
requires the program's existing permission and canonical native proof; no retired
node-local fee relay worker supplies monetary authority.
Withdrawals must leave every unexpired lease remainder intact, and final close
waits until executed receipt usage has been merge-settled.

Verified allocation, executed-usage, and merge-settled-usage records are
native-authored consensus state. Contracts may read and enumerate their
canonical keys, but generic IVM state syscalls cannot create, overwrite, or
delete them; updates must pass through the validating native allocation and fee
settlement paths.

## Reservations and settlement

Queue admission reserves the deterministic quoted maxima authorized by the signed
intent against ordinary authority balances or exact sponsor-program vault and budget
capacity. Existing receipt-lane sponsor allocations retain their native source-lock
and usage checks.
Reservations are released on every queue exit: routing or push failure,
rejection, expiry/culling, proposal removal, queue clearing, and commit.
Rechecks subtract existing reservations before admitting another transaction.

Execution is ordered as reserve, execute the business payload, then settle:

- Admission, routing, configuration, and internal execution failures do not
  charge a fee.
- A business-level rejection after valid admission settles the deterministic
  actual work performed, bounded by the signed maxima.
- Successful execution settles the deterministic actual charge, never the
  reserved maximum, and releases the remainder.

There is no sender fallback. If a selected sponsor program is missing,
inactive, ineligible, disallows an operation, lacks budget, or lacks vault
capacity, the transaction is rejected with that sponsor error.

## Execution receipts

Native execution debits the authority or exact sponsor vault in its canonical fee
context. There is one execution path; the retired lane-relay-burn configuration and
unused worker configuration are removed.

An actual nonzero Nexus charge is retained in the exact Network
`TransactionResult` as its mandatory nullable `nexus_fee_receipt` field. The
binary result tuple always has three fields, and JSON always includes the key,
including explicit `null` when no charge was applied. The receipt participates
in the result hash and therefore in the executed output commitment. It binds
the original outer entrypoint, physical dataspace and lane, applying height,
actual authority or sponsor program and revision, signed asset/amount cap,
canonical payload length, metering inputs and actual amount. Settlement
records `Burn`, because the native charge reduces the payer or sponsor custody
balance and the global XOR supply; a committed sink or a fee quote is not
proof of a paid charge.

The execution owner retains the fee overlay until its receipt-bearing terminal
output is funded. A business rejection whose diagnostic is too large retains
the same actual receipt with a bounded reason. If even that terminal cannot
fit, the carrier refuses before the charge is applied. Healthy successful-output
overflow drops the attempted business effects and fee together. Public receipt
shape checks bind the signed intent and arithmetic, but do not authenticate
execution, the applicable policy, FASTPQ coverage or finality; consumers must
verify the genuine executed carrier and its consensus commitment.

The first-release `NexusFeeReceipt` layout is closed and exact. Its
`program_revision` and `lease_id` slots are always encoded, using explicit
`null` when the corresponding binding is absent; omission and unknown fields
are rejected rather than interpreted as a pre-release receipt shape.

Block status exposes fee receipts and lane settlement commitments for audit and
reconciliation. Receipt amounts are canonical decimal strings, and fixed byte
arrays are exact-width uppercase hexadecimal in Norito JSON.

## Operator checklist

- Author the canonical root currency and custody in genesis and accepted PipelineGas
  assets in their existing committed parameters.
- Keep every sponsor-program budget and vault asset globally scoped.
- Create a program, stage an immutable revision, fund every budgeted asset,
  enroll beneficiaries, and schedule activation.
- Configure route defaults by exact program ID only where desired.
- Grant allocation submitters `CanManageFeeSponsorProgram` only for their exact sponsor.
- Use `/v1/fees/quote` in clients and automation; do not manufacture maxima or
  encode fee controls in transaction metadata.
- Monitor stable rejection codes, queue reservations, vault capacity, budget
  windows, and settlement receipts.
- For receipt-backed lanes, verify the first post-activation protocol settlement
  before retiring any temporary external reconciler.


### Enrolled multisig contract calls

`EnrolledMultisigContractCall` permits only Native multisig `Propose` and
`Approve` operations. The submitting beneficiary and canonical registered
controller must both have explicit current enrollment in the same sponsor
program. Enrollment is controlled by that program's sponsor or its exact
registrar permission; an application can enroll newly commissioned controllers
without revising an account whitelist. Route-default eligibility alone does not
satisfy this selector.

The selected body must be the complete canonical `RegisterTrigger` then
`ExecuteTrigger` contract-call pair. Its authority, filter, one-shot action,
attempt identity, arguments, alias, current address/code binding and exact
allowed entrypoint are verified from Native types and World state. Extra,
nested, arbitrary native and raw IVM payloads do not match. Existing explicit
multisig selectors retain their account/operation semantics.

New proposal admission requires both pending and terminal keys to be absent.
An approval may use an exact earlier proposal in the same signed envelope, or
an exact live non-relayed pending proposal. Terminal, canceled, expired and
future pending records never authorize a new admission. At post-execution fee
settlement only, a standalone approval may use a `Finalized` terminal record
joined to the current signed entrypoint hash and block through both the Native
terminal-execution record and its successful `Executed` approval outcome.
Terminal state alone is insufficient. All typed decode/encoding resource
refusals remain deferred, and explicit deny rules, program/beneficiary budgets,
fee limits and isolated vault accounting still apply.
