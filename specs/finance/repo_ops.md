---
title: Repo Operations & Evidence Guide
summary: Bilateral consent, maturity and opt-in early settlement, and audit evidence for repo agreements.
---

# Repo Operations & Evidence Guide

Iroha repo agreements are immutable, one-shot bilateral contracts. Opening an
agreement requires explicit on-chain consent from every account whose balance
will be debited without being the transaction authority. Settlement accepts
only an agreement identifier and derives every economic term and exact balance
scope from the stored agreement.

Early repayment is an explicit, immutable governance term
(`allow_early_repayment`) that both consents bind. This design deliberately
does not support caller-selected collateral substitution or caller-selected
close terms. A different collateral asset, quantity, rate, maturity,
custodian, or governance policy is a new agreement with new consent.

## Security model

`RepoIsi` contains the complete economic proposal:

- agreement identifier;
- initiator, counterparty, and optional custodian;
- cash and collateral asset definitions and quantities;
- fixed rate and maturity timestamp; and
- haircut, margin cadence, and whether the initiator may repay early
  (`RepoGovernance::allow_early_repayment`).

Before the initiator can open it, two exact `CanExecuteSettlement` permissions
must be held by the initiator:

1. The counterparty grants a cash-debit permission. Its `debited_asset` is the
   exact counterparty cash `AssetId`, including its dataspace scope. Its
   `settlement_id` is the repo agreement identifier and its `intent_hash` is
   `RepoIsi::initiation_intent_hash()`.
2. The account that will hold collateral at maturity grants a
   collateral-release permission. In a bilateral repo this is the
   counterparty; in a tri-party repo it is the custodian. Its `debited_asset`
   is the exact collateral custody `AssetId`, its settlement identifier is the
   same, and its hash is `RepoIsi::maturity_intent_hash()`.

Only `debited_asset.account()` may issue or revoke either permission. The two
domain-separated hashes both commit the entire encoded proposal, so a cash
permission cannot be reused as a maturity permission and changing any term
invalidates both permissions.

The permissions select exact balance scopes. Admission rejects zero or
ambiguous matches; it never searches for a convenient balance in another
dataspace. Opening then moves cash and collateral atomically through the
ordinary transparent-transfer policy, transfer-control, transcript, and event
pipeline.

## Agreement lifecycle

### Open

The transaction authority must be the stated initiator. The runtime requires:

- distinct initiator and counterparty accounts;
- a custodian, when present, distinct from both parties;
- distinct cash and collateral asset definitions;
- positive quantities valid for each definition's `NumericSpec`;
- a haircut no greater than 10,000 basis points;
- a maturity later than the authoritative initiation block timestamp;
- both exact owner-issued permissions described above; and
- both asset movements to pass ordinary asset policy and transfer controls.

No term is silently replaced by node configuration. The accepted proposal and
the exact consent-selected cash and collateral custody `AssetId`s are stored in
`RepoAgreement`.

### Margin

`RepoMarginCallIsi` contains only the agreement identifier. The initiator,
counterparty, or custodian may record a check when the agreement's explicit
cadence is due. Margin calls are rejected after settlement and at or after
maturity. Margining records evidence; it does not mutate the agreed cash,
collateral, custody scope, or maturity.

### Settle

`ReverseRepoIsi` contains only `agreement_id`. It is accepted only when:

- the agreement exists and is still active;
- the submitting authority is the recorded initiator, counterparty, or custodian; and
- either the authoritative block time is at or after the recorded maturity, or
  the agreement opted into early repayment
  (`governance.allow_early_repayment = true`) and the submitting authority is
  the initiator (the cash borrower).

Before maturity, an agreement that did not opt in rejects settlement with
"cannot settle before its recorded maturity", and an opted-in agreement
rejects the counterparty and custodian: only the borrower may shorten its own
loan.

The effective settlement timestamp is `min(block timestamp, maturity)`. The
runtime computes ACT/360 interest from the recorded principal, fixed rate,
initiation timestamp, and that effective timestamp, rounding toward zero at the
cash definition's scale. A delayed submission after maturity therefore does
not change the agreed repayment, and an early repayment pays interest accrued
only to the committed block time. Cash returns to the exact counterparty
balance selected at open, and collateral returns from the exact custody balance
selected at open. Both movements again pass ordinary transfer policies and
controls and are applied atomically.

After success, the agreement remains on-chain with `settlement_timestamp_ms`
set to the effective settlement timestamp, and `RepoAccountSettled` events
carry the exact repayment amount and that timestamp. This settled tombstone
makes the agreement identifier permanently one-shot. Reopening or settling it
again is rejected.

Any recorded agreement, active or settled, retains its cash and collateral
asset definitions: `Unregister<AssetDefinition>` and domain unregistration are
rejected while an agreement references them, so an issuer cannot destroy
pledged collateral or repayment balances by retiring the definition.

A registered bond pledged in a repo stays with its title holder (the
counterparty or custodian), who is the holder of record for its coupons and
redemption; manufactured payments between the parties are outside the bond
kernel. Repo legs of a registered bond cannot move while its books are closed
(from a record date until that cash flow is recorded) or after its redemption
is recorded (see `specs/finance/bond_ops.md`).

Revoking a proposal permission after a successful open does not strand the
agreement: consent has already been materialized as immutable agreement state.
Maturity settlement still respects current asset transfer controls.

## Unsupported operations

- **Unilateral early unwind:** not representable. Early repayment exists only
  when both consents bound `allow_early_repayment = true`, and only the
  initiator may use it. Parties that want any other term must create a new
  bilaterally consented agreement.
- **Collateral substitution:** not representable. Repo configuration cannot
  inject a replacement asset into ID-only maturity settlement.
- **Caller-provided close terms:** not accepted. Parties, assets, quantities,
  rates, balance scopes, and timestamps are all derived from stored state.
- **Agreement ID reuse:** not accepted, including after settlement.

These are fail-closed protocol constraints, not operational conventions.

## CLI

Stage the fully specified proposal for review:

```bash
iroha --config client.toml --output \
  app repo initiate \
  --agreement-id daily_repo \
  --initiator <initiator-i105> \
  --counterparty <counterparty-i105> \
  --custodian <custodian-i105> \
  --cash-asset <cash-definition-id> \
  --cash-quantity 1000 \
  --collateral-asset <collateral-definition-id> \
  --collateral-quantity 1050 \
  --rate-bps 250 \
  --maturity-timestamp-ms 1704000000000 \
  --haircut-bps 1500 \
  --margin-frequency-secs 86400 \
  --allow-early-repayment
```

Omit `--allow-early-repayment` for a fixed-maturity agreement.

Before submitting that proposal, create the two exact permission Grants from
the byte-identical `RepoIsi`. The cash owner signs the cash Grant; the
collateral holder signs the maturity Grant. Submit the repo only after both
Grants are final.

Settlement contains no caller-selected economic data:

```bash
iroha --config client.toml app repo unwind --agreement-id daily_repo
```

The initiator, counterparty, or recorded custodian may submit this settlement
at or after maturity. Non-participants are rejected; allowing every participant
to trigger prevents the borrower from vetoing an already committed repayment.
Before maturity, only the initiator of an agreement opened with
`--allow-early-repayment` may submit it.

Other lifecycle commands are:

```bash
iroha --config client.toml app repo get --id daily_repo
iroha --config client.toml app repo list
iroha --config client.toml app repo margin --agreement-id daily_repo
iroha --config client.toml app repo margin-call --agreement-id daily_repo
```

`repo list` returns both active agreements and settled tombstones; it takes the
[collection query](../torii/collection_queries.md) flags, so `--filter` on
`status` narrows it.

## SDK and Torii records

The Rust data model exposes `RepoIsi::settlement_id()`,
`RepoIsi::initiation_intent_hash()`, and
`RepoIsi::maturity_intent_hash()` so clients can construct the exact
`CanExecuteSettlement` permissions. SDKs must hash the canonical Norito
encoding, including every proposal field, with the same public domain
separators. Hashing an independently reconstructed partial object is unsafe.

Torii repo records include:

- `cash_source` and `collateral_custody_asset`, including exact balance scope;
- `governance.allow_early_repayment`;
- `settlement_timestamp_ms`, which is null while active and otherwise the
  effective (maturity or early repayment) settlement timestamp; and
- `status`, derived as `active` or `settled`.

Python `RepoAgreementRecord` and JavaScript `ToriiRepoAgreement` expose those
fields and reject a status that disagrees with the settlement timestamp.

## Evidence checklist

For every agreement, retain:

1. the canonical `RepoIsi` bytes and a human-readable term sheet;
2. both signed Grant transactions and their finality receipts;
3. pre-open snapshots of the exact cash and collateral source balances;
4. the accepted `RepoAgreement`, including exact source IDs;
5. initiation and margin `RepoAccountEvent` records for every role;
6. pre-settlement balance and transfer-control snapshots;
7. the ID-only `ReverseRepoIsi`, settlement receipt, and settlement events; and
8. the settled tombstone plus post-settlement balance snapshots.

For tri-party repos, also retain the custodian's signed maturity Grant and
custody balance snapshots.

The deterministic lifecycle fixture is maintained by:

```bash
scripts/regen_repo_proof_fixture.sh
```

Its test is:

```bash
cargo test -p iroha_core \
  -- --exact smartcontracts::isi::repo::tests::repo_deterministic_lifecycle_proof_matches_fixture
```

The proof must show initiation, margining, and maturity settlement while
retaining the settled agreement tombstone.

## Incident handling

If a proposal has not opened, revoke either exact permission to prevent
admission. If it has opened, do not attempt to rewrite terms or manufacture an
early unwind: the agreement is immutable, and only an opted-in initiator can
repay before maturity. Investigate and, where necessary,
apply the ordinary asset transfer controls using the documented governance
process. Resume maturity settlement only after both legs are permitted.

Because both legs are fully prechecked before either balance changes, a
rejected open or close leaves balances, transfer-control usage, agreement
status, transcripts, and repo events unchanged.
