---
title: Native Bond-Servicing Kernel
summary: Normative contract for registered bond records, record-date entitlements under closed books, vault-funded coupon and redemption servicing, calls, defaults, the transfer freeze and the attribution of holdings of record.
---

# Native Bond-Servicing Kernel

A bond is an ordinary fungible asset definition with scale 0 whose unit is the
legal denomination. Issuance, primary subscription (`SettleAtomic` with
conditional-escrow legs, `OpenConditionalEscrow` tranches) and repo stay the
existing native flows. The kernel adds one typed, authoritative
`BondRecord` per bond, one `BondEntitlement` per holder and recorded cash
flow, and nine native instructions that perform every legally material
cash-flow and supply operation. There is no mutable metadata escape hatch for terms and
no legacy or compatibility path.

Design goals that shape every rule below:

- **The record date is authoritative.** Entitlements are the holdings of
  record at the record date, whoever records them and whenever.
- **Nobody can veto servicing.** No holder, counterparty or third party can
  block recording, funding, claiming or closing of a cash flow.
- **Bounded work, unbounded holders.** Every instruction does bounded work;
  the number of holders is not limited.
- **Funded money is never trapped.** Every amount in a vault belongs to one
  identified unclaimed entitlement and stays claimable.

Source owners:

| Concern | Location |
| --- | --- |
| Terms, record, entitlement, validation, schedule builder, vault derivation | `crates/iroha_data_model/src/bond.rs` |
| Instructions and `BondInstructionBox` (`iroha.bond`) | `crates/iroha_data_model/src/isi/bond.rs` |
| Events and `DataEventFilter::Bond` | `crates/iroha_data_model/src/events/data/bond.rs` |
| Queries `FindBondById`, `FindBonds` | `crates/iroha_data_model/src/query/domain_queries.rs` |
| Execution, book closing, freeze, attribution, retention, rekey, queries | `crates/iroha_core/src/smartcontracts/isi/bond.rs` |
| Verified vault movements, redemption burn, custody gate | `crates/iroha_core/src/smartcontracts/isi/asset.rs` |
| Entitlement range iteration | `crates/iroha_core/src/state/range_bounds.rs` |
| Torii routes `GET /v1/bonds`, `GET /v1/bonds/{bond_id}`, `GET /v1/bonds/{bond_id}/entitlements` | `crates/iroha_torii/src/lib.rs`, `crates/iroha_torii/src/routing/collection_sources.rs` |
| JS codec envelope and vault rendering | `crates/iroha_js_codec/src/bond_instructions.rs` |
| JS SDK builders, schedule, validation, Torii reads, review | `javascript/iroha_js/src/bond.js`, `bondRecords.js`, `transactionReview.js` |

## 1. Data model

`BondId` is the bond's `AssetDefinitionId`.

`BondTerms`:

| Field | Meaning |
| --- | --- |
| `issuer` | Owns the bond definition; signs registration, calls and paying-agent replacement. |
| `paying_agent` | Funds, closes, declares defaults and may push claims. |
| `payment_asset` | Asset definition of every payment (for example a EUR e-money token). |
| `denomination` | Payment-asset amount per bond unit (positive). |
| `coupon_rate_bps` | Annual rate; `0` exactly when `coupon_frequency == 0`. |
| `coupon_frequency` | `0`, `1`, `2`, `4` or `12` payments per year. |
| `day_count` | `ActActIcma`, `Thirty360`, `Act360`, `Act365Fixed`: a legal label, see §1.2. |
| `issue_date_ms`, `maturity_date_ms` | Unix milliseconds, `issue < maturity`. |
| `redemption_price_bps` | Positive; `10_000` is par. |
| `payment_grace_ms` | Grace after a payment date before a default may be declared; at most 366 days. |
| `call` | Optional `BondCallTerms { first_call_date_ms, price_bps, notice_ms }`. |
| `cashflows` | Fully materialised schedule of 1..=400 `BondCashflowTerms`. |
| `identifiers` | `BondIdentifiers { isin <= 12, cfi <= 6, issuer_lei <= 20, bdt_version 1..=32, bdt_document_sha256 }`; every label is non-empty printable ASCII. |
| `terms_sha256` | SHA-256 of the legal terms document. |

Terms never change after registration except the two account references
`issuer` and `paying_agent`, which follow an account rekey (§5) and
`ReplaceBondPayingAgent` (§3, item 8).

`BondCashflowTerms { index, kind: Coupon | Redemption, record_date_ms,
payment_date_ms, amount_per_unit }`. `amount_per_unit` is an exact decimal and
may carry more decimals than the payment asset.

`BondRecord { id, vault, terms, state }` with
`BondState { lifecycle: Active | Called | Matured | Defaulted,
outstanding_units, redeemed_units, retired_units, transfers_frozen, cashflows }`.
`outstanding_units` always equals the bond definition's total supply:
registration fixes it and only redemption claims (`redeemed_units`) and
treasury retirements (`retired_units`) reduce it, so `outstanding_units +
redeemed_units + retired_units` is the registered supply. Every
effective cash flow is a `BondCashflowState { terms, status, recording,
holders, claimed_holders, entitled_units, amount_due, funded, paid,
recorded_at_ms, funded_at_ms, closed_at_ms, evidence_sha256 }` with status
`Scheduled | Recording | Recorded | Funded | Closed | Defaulted | Cancelled`.
`recording` is a `BondRecordingCursor { phase: Holders | Escrows,
after_asset, after_escrow }`, present exactly while the status is
`Recording`. A record holds totals only; its size is bounded by its schedule.

`BondEntitlement { id: BondEntitlementId { bond, index, holder }, units,
amount, claimed_at_ms }` is one holder's entitlement to one cash flow:
`units` held of record and `amount = holder_payment(units)`. Keys order by
bond, then cash flow, then holder.

### 1.1 Registration validation

`BondTerms::validate` (shared by SDKs and Core, integer/decimal arithmetic
only) rejects with `bond.invalid_terms`, in this order:

- identifier bounds; zero denomination or redemption price;
- a frequency outside `{0, 1, 2, 4, 12}`, or a zero rate with a positive
  frequency (and vice versa);
- `issue >= maturity`; a payment grace above 366 days;
- a zero call price, a first call date outside `(issue, maturity)`, or an
  inexact call price;
- an empty schedule or one with more than 400 entries;
- terms without a regular schedule: coupon payment dates step back from
  maturity by `12 / frequency` calendar months (end-of-month clamping) and
  must land exactly on the issue date ("the first coupon period is
  irregular");
- indices that are not `0..n` in order; a record date after its payment date;
  a record date before issue or a payment date after maturity;
- anything other than exactly one `Redemption`, last, paid on maturity with
  `amount_per_unit == denomination × redemption_price_bps / 10_000` exactly;
- coupons on a zero-coupon bond; a coupon whose `amount_per_unit` is not
  exactly `denomination × coupon_rate_bps / (10_000 × coupon_frequency)` (a
  non-terminating quotient, for example 6.50 % monthly on 50, is rejected);
  a coupon not paid on its regular date; a coupon count other than the
  regular count;
- record dates that decrease.

Record dates are free inside each period. Coupon payment dates are therefore
exactly the regular dates, which strictly increase; the final coupon and the
redemption share the maturity payment date.

### 1.2 Schedule builder

`fixed_rate_bullet_schedule(BondScheduleRequest)` materialises the regular
schedule with `regular_coupon_payment_dates` (the same function validation
uses). Record dates are `payment - record_offset_ms`, clamped to the issue
date. Because registration admits only regular periods, the day-count label
does not change any amount in the first release.

### 1.3 Arithmetic

- Holder payment: `floor(units × amount_per_unit)` at the payment asset's
  scale (`RoundingMode::TowardZero`); an unconstrained payment asset receives
  the exact product.
- `amount_due` is the sum of the holders' rounded payments, so funding covers
  every claim exactly and a fully claimed cash flow leaves nothing in the
  vault.

### 1.4 Vault

`bond_vault_account_id(bond) = AccountId(derive_non_signing_ed25519_public_key(
"iroha:bond:vault:v1", [bond.aid_bytes]))`. No private key exists for the
point, the derivation is network independent, and the vault account is
created on first funding. It is stored in `BondRecord::vault`.

## 2. Storage

| Table | Role | Content |
| --- | --- | --- |
| `world.bonds: AssetDefinitionId -> BondRecord` | canonical | One record per registered bond. |
| `world.bond_entitlements: BondEntitlementId -> BondEntitlement` | canonical | Record-date entitlements; claimed rows stay as history. |
| `world.bond_vaults: AccountId -> AssetDefinitionId` | derived from `world.bonds` | Vault index, rebuilt by `World::rebuild_bond_vault_index`. |

Canonical tables are persisted in World snapshots, restored by
`deserialize_world` (which rebuilds the vault index), staged and applied with
every `WorldTransaction`, and readable through `WorldReadOnly`.
`WorldReadOnly::bond_entitlements_of_bond_iter(bond, after, before)` walks
one bond's entitlements as a key range. Entitlement keys use one canonical
JSON spelling in snapshots.

## 3. Instructions

All nine instructions travel only inside `BondInstructionBox`
(wire id `iroha.bond`, tags 0..=8 in the order below); leaf types have no wire
identifiers. Core performs every authority check; the Initial executor admits
the box (§7). Block time is the committed block timestamp. Rejections are
`InvariantViolation` messages prefixed with the stable code from
`BondError::code()` (`bond.unauthorized`, `bond.invalid_state`,
`bond.too_early`, `bond.books_closed`, `bond.not_entitled`, ...).

1. **`RegisterBond { bond, terms }`** (`Register`). The signer is
   `terms.issuer`; the terms validate; the bond is not registered; the payment
   asset differs from the bond and is not itself a registered bond, and the
   bond is not the payment asset of a registered bond; both definitions exist
   and use `AssetBalancePolicy::Global`; the issuer owns the bond definition,
   whose numeric spec has scale 0; issuer and paying-agent accounts exist; the
   minted total is positive and **held entirely by the issuer**; block time is
   before the redemption's record date (a later registration would be born
   frozen, "the bond would register frozen"). The record starts `Active`,
   `outstanding_units = total_quantity`; the vault is indexed.
   **Backdated schedules.** Every cash flow whose record date is at or before
   block time (a prefix, since record dates never decrease) is recorded at
   registration: status `Recorded`, no holders, zero `entitled_units` and
   `amount_due`, `recorded_at_ms` = block time, one `CashflowRecorded` event
   each after `Registered`. The issuer holds every unit and treasury units are
   excluded, so this is exactly what a `RecordBondCashflow` in the same block
   would record; it keeps the books open (§4.1) so allotments and the tranche
   escrow can follow in the registration transaction. The paying agent funds
   these cash flows (nothing moves) and closes them at or after their payment
   dates. Every later cash flow starts `Scheduled`. The intended use is one
   issuer transaction: `Register<AssetDefinition>`, `Mint` to the issuer,
   `RegisterBond`, then the tranche escrow or allotments.
2. **`RecordBondCashflow { bond, index }`** (`RecordCashflow`). Any signer.
   Lifecycle `Active` or `Called`. Starting requires status `Scheduled`, block
   time `>= record_date_ms` and no lower index `Scheduled` or `Recording`; it
   sets status `Recording` with a fresh cursor. A `Recording` cash flow
   continues from its cursor. Each step examines at most
   `BOND_RECORDING_PAGE_ENTRIES` (512) entries:
   - *Holders phase*: the bond's balances in asset-identifier order. Every
     non-zero balance credits its account's entitlement, except the issuer,
     any bond vault, game custody and AMX custody (§4.3).
   - *Escrows phase*: escrow records in identifier order. For each native
     escrow of this bond whose custody account received an entitlement in the
     holders phase, that entitlement is removed and its units credited to the
     escrow's seller (dropped when the seller is the issuer).

   Totals (`holders`, `entitled_units`, `amount_due`) are kept exact on every
   credit. When both phases finish the status becomes `Recorded`,
   `recorded_at_ms` is set, the cursor cleared and `CashflowRecorded` emitted;
   recording the `Redemption` sets `transfers_frozen`. Repeat the instruction
   until the cash flow is `Recorded`.
3. **`FundBondCashflow { bond, index, source }`** (`FundCashflow`). Signer:
   paying agent or issuer; lifecycle `Active` or `Called`; `source` is the
   signer's global balance of the payment asset; status `Recorded`. Moves
   exactly `amount_due` into the vault (no movement when zero). Status
   `Funded`. Funding before the payment date is allowed.
4. **`ClaimBondCashflow { bond, index, holder }`** (`ClaimCashflow`). Signer:
   the holder or the paying agent; the destination is always the holder.
   Status `Funded` or `Closed`, any lifecycle; block time `>= payment_date_ms`;
   the holder has an unclaimed entitlement. A coupon pays the entitlement's
   `amount` from the vault. A redemption first burns exactly the
   entitlement's `units` from the holder's own balance (the only supply change
   a registered bond admits) and then pays; `outstanding_units` decreases and
   `redeemed_units` increases by those units. The entitlement gets
   `claimed_at_ms`, `claimed_holders` and `paid` grow. Any failure rejects the
   whole instruction; the entitlement stays claimable.
5. **`CloseBondCashflow { bond, index }`** (`CloseCashflow`). Signer: paying
   agent; status `Funded`; block time `>= payment_date_ms`. Sets `Closed`
   whether or not every holder claimed; unclaimed entitlements stay claimable
   from the vault (`CashflowClosed` reports `unclaimed_holders` and
   `unclaimed_amount`). The lifecycle becomes `Matured` when every effective
   cash flow is `Closed` or `Cancelled`.
6. **`CallBond { bond, call_date_ms }`** (`Call`). Signer: issuer; lifecycle
   `Active`; call terms exist; `call_date >= first_call_date_ms`;
   `call_date >= block time + notice_ms`; `call_date < maturity`; the date is
   the payment date of a `Scheduled` coupon and every later cash flow is
   `Scheduled`. Every later effective cash flow becomes `Cancelled` and one
   `Redemption` is appended with the next index, that coupon's record date,
   payment date `call_date` and `amount_per_unit = denomination ×
   call.price_bps / 10_000`. The coupon on the call date stays. Lifecycle
   `Called`. The registered schedule is unchanged.
7. **`DeclareBondDefault { bond, index, evidence_sha256 }`**
   (`DeclareDefault`). Signer: paying agent; lifecycle `Active` or `Called`;
   the cash flow is `Scheduled` or `Recorded` (a `Recording` cash flow must be
   completed first) and a `Recorded` cash flow owes a positive `amount_due`
   (one that owes nothing, such as a cash flow recorded at a backdated
   registration, cannot default: "owes nothing and cannot default"); block
   time `> payment_date_ms + payment_grace_ms`. The
   cash flow becomes `Defaulted` with the evidence digest and the lifecycle
   `Defaulted`. Afterwards recording, funding, calls and further defaults are
   rejected; claims and closing of cash flows funded before the default
   continue. Entitlements recorded before the default remain as the record of
   who was owed.
8. **`ReplaceBondPayingAgent { bond, paying_agent }`**
   (`ReplacePayingAgent`). Signer: issuer; any lifecycle; the new agent is an
   existing account, not a bond vault and not the current agent. Emits
   `PayingAgentReplaced`.
9. **`RetireBondTreasuryUnits { bond, quantity }`** (`RetireTreasuryUnits`).
   Burns units the issuer holds directly. Rules, in order:
   - the signer is the issuer (`bond.unauthorized`); `quantity` is a positive
     whole number of units, scale 0 (`bond.invalid_state`);
   - no cash flow is `Recording` (`bond.books_closed`): the cursor walks the
     balances;
   - `quantity <= issuer balance − reserved`, where *reserved* is the
     collateral quantity of every active repo agreement whose counterparty or
     custodian is the issuer and whose `collateral_custody_asset` is the
     issuer's global balance of this bond (`bond.invalid_state`): those units
     go back to the initiator at reverse and the supply lock means retired
     units could never be returned. Units in escrow custody (allotments, the
     tranche) are not the issuer's balance and cannot be retired until the
     escrow returns them.

   Any lifecycle is allowed, as are closed books and the redemption freeze:
   treasury units are never entitled, so retiring them changes no entitlement
   (§4.2). The burn is the verified `BondTreasuryRetirement` burn (§4.4);
   `outstanding_units` decreases and `retired_units` increases by `quantity`.
   When no unit remains outstanding on an `Active` or `Called` bond, every
   `Scheduled` cash flow becomes `Cancelled` (it would record no holders and
   no unit can ever exist again) and the lifecycle becomes `Matured` once
   every effective cash flow is `Closed` or `Cancelled`; recorded, funded and
   claimable cash flows stay owed. Emits `TreasuryUnitsRetired`. Uses: cancel
   the unsold inventory and returned tranche of a failed offering, and
   treasury units after maturity, so `outstanding_units` reflects only units
   owed to holders.

## 4. Movement and supply controls

### 4.1 Book closing and the redemption freeze

`PreparedNumericTransferPlan::prepare` is the single preparation step of every
numeric movement (user transfers and batches, `SettleAtomic` movements and
escrow legs, native escrow funding and release, repo legs, protocol
movements). It calls `ensure_bond_units_movable` for registered bonds:

- While any cash flow of the bond is `Recording`, every movement is refused
  (`bond.books_closed`): the cursor walks the balances.
- **Books closed.** While the bond is `Active` or `Called` and the record date
  of its first `Scheduled` cash flow has passed, movements are refused
  (`bond.books_closed`) until that cash flow is recorded. Cash flows are
  recorded in order and record dates never decrease, so the final coupon and
  the redemption that share a record date keep the books closed until both
  are recorded.
- **Frozen.** Once the redemption is recorded (`transfers_frozen`), movements
  are refused permanently (`bond.transfers_frozen`).
- Neither restricted state stops `RetireBondTreasuryUnits` (§3, item 9): it
  burns treasury units, which no entitlement counts; only a running recording
  refuses it.
- In both restricted states a native escrow may still return custody to its
  seller (source policy `NativeEscrowCustody`, destination the seller of an
  escrow of this bond whose custody is the source): the seller is already the
  holder of record of those units, so the return changes no entitlement and
  lets the seller redeem.

Books are open on a `Matured` or `Defaulted` bond unless it is frozen. Mint
and burn are locked (§4.4), unregistering a holder is refused (§5) and a
rekey cannot move units during a recording (§5), so between the record date
and the completed recording nothing changes the balances being recorded.

### 4.2 Holders of record

| Units held by | Holder of record |
| --- | --- |
| An ordinary account (including a repo counterparty or custodian holding collateral) | That account |
| Native asset-escrow custody (marketplace, lock, conditional; `SettleAtomic` escrow legs) | The escrow's seller until the escrow releases |
| The issuer, directly or as escrow seller | Nobody: treasury units receive nothing |
| A bond vault, game custody, AMX custody | Nobody (they cannot receive registered bond units, §4.3) |

Repo collateral is held by its title holder, which receives coupons and the
redemption; manufactured payments are a matter between the repo parties. An
unreleased allotment escrow opened by the issuer leaves the investor without
an entitlement for that record date, as for any unsettled trade.

### 4.3 Attributed custody only

Registered bond units may rest only in accounts and native asset-escrow
custody. `NumericAssetMovementAuthorization::ensure_admits_bond_units`, applied
by both authorization choke points (`PreparedNumericAssetMovement` and
`PreparedNumericAssetMovementBatch::aggregate`), admits a registered bond's
units only for plain transaction movements and the purposes
`native-escrow-funding`, `native-escrow-retained`, `repo-bilateral` and
`settlement-bilateral`; every other purpose (game seats, VPN leases, AMX,
SCCP and FX escrows, privacy pools, staking and governance bonds, ...) is
refused with `bond.custody_unsupported`. Registration requires the issuer to
hold the whole supply, so no unit can sit in such custody beforehand. Units
sent to a protocol account by a plain transfer are a donation: the holders
phase excludes game, AMX and vault custody, and any other recipient simply
holds an entitlement nobody claims.

### 4.4 Supply lock and vault custody

- **Supply lock.** `Mint` and `Burn` (including retail reserve mint/burn and
  the central checked burn) of a registered bond are rejected with
  `bond.supply_locked`; only the redemption-claim burn
  (`NumericAssetBurnSourcePolicy::BondRedemption`) and the treasury retirement
  (`NumericAssetBurnSourcePolicy::BondTreasuryRetirement`) change the supply.
- **Treasury burn.** `execute_verified_bond_treasury_retirement` re-checks the
  capability (issuer signer, no `Recording` cash flow, positive units) and
  burns from the issuer's own global balance: it requires source ownership,
  refuses privacy reserve, native escrow, FX corridor, SoraFS, KAGEMUSHA and
  SCCP sources, applies the bond definition's transparency and usage policies
  (the issuer controls them) and the issuer's outbound transfer controls, and
  is captured as a supply change tagged `bond-treasury-retirement`.
- **Redemption burn.** The burn checks the exact unclaimed entitlement, refuses
  privacy reserve, escrow, SoraFS, KAGEMUSHA and SCCP sources, and ignores the
  bond definition's confidential (transparent) and issuer usage policies: the
  definition owner cannot trap a funded redemption by tightening them.
- **Vault custody.** Direct debits of a vault (transfers, burns, other
  protocol sources) and credits to a vault (transfers, mints) outside
  `FundBondCashflow` are rejected with `bond.vault_custody`; the checks use
  the `bond_vaults` index. Funding uses the embedded `BondFunding` purpose with
  the `BondVaultFunding` source policy; payments use the retained `BondVault`
  purpose with the `BondVaultCustody` source policy and the
  `BondVaultRelease` control policy. The payment asset's transparency and
  usage policies bind the funding party and the paid holder but never the
  key-less vault, and the vault has no outbound transfer controls, so the
  payment-asset issuer cannot block every payment by binding the vault. A
  holder the payment asset refuses keeps an unclaimed entitlement.
- `execute_verified_bond_movement` and `execute_verified_bond_redemption_burn`
  re-check each capability against the stored record and entitlement
  (signer, exact source and destination, status, unclaimed entitlement,
  exact amount or units) before any balance changes.

## 5. Retention and rekey

- `Unregister<AssetDefinition>` and `Unregister<Domain>` refuse to retire a
  bond definition or the payment-asset definition of any bond
  (`bond.retained`); records are permanent.
- `Unregister<Account>` refuses every bond vault, the issuer and paying agent
  of a bond that is `Active` or `Called` or has a `Recording`, `Recorded` or
  `Funded` cash flow, and every account holding units of a registered bond
  (removing the balance would destroy units outside the supply lock and break
  `outstanding_units`). Unclaimed entitlements of an account without units
  survive its unregistration and pay out once the same account exists again.
- A rekey (`ReplaceAccountController`, multisig rekey) is refused for a vault
  and for an account that holds units of, or has an entitlement in, a cash
  flow that is `Recording`. Otherwise the issuer and paying-agent references
  of every record and every unclaimed entitlement move to the new account;
  claimed entitlements stay as history under the old identifier.

## 6. Events, queries and Torii

`DataEvent::Bond(BondEvent)` (data-event tag 25) carries
`Registered { bond, issuer, paying_agent, outstanding_units, cashflows }`,
`CashflowRecorded { bond, index, kind, holders, entitled_units, amount_due }`
(on completion),
`CashflowFunded { bond, index, amount }`,
`CashflowClaimed { bond, index, holder, units, amount }`,
`CashflowClosed { bond, index, unclaimed_holders, unclaimed_amount }`,
`Called { bond, call_date_ms, redemption_index }`,
`Defaulted { bond, index, evidence_sha256 }`,
`PayingAgentReplaced { bond, previous, paying_agent }` and
`TreasuryUnitsRetired { bond, issuer, quantity, outstanding_units,
retired_units, cancelled_cashflows }` (outstanding and retired totals after the
retirement; the number of cash flows it cancelled). A backdated registration
emits `Registered` followed by one `CashflowRecorded` per cash flow recorded
at registration.
`DataEventFilter::Bond(Option<BondId>)` (filter tag 27) selects all bond
events or one bond's; data triggers index the bond family and subject, and a
bond-scoped trigger filter belongs to the owner of the bond definition.

Queries: singular `FindBondById { bond } -> BondRecord`
(`SingularQueryOutputBox::BondRecord`, `FindError::Bond` when absent) and
iterable `FindBonds -> BondRecord` (`QueryItemKind::BondRecord`, wire tag 31,
wire id `iroha.query.v1::iterable::bond::BondRecord`). The JSON query envelope
accepts `{"type": "FindBondById", "payload": {"bond": "<asset definition
address>"}}` and the iterable `FindBonds`.

Torii serves bond data on public application routes as Norito JSON:

| Route | Content |
| --- | --- |
| `GET /v1/bonds` | Collection query (`filter`, `sort`, `select`, `limit`, `cursor`, `include_total`) over complete `BondRecord` rows, in bond identifier order. |
| `GET /v1/bonds/{bond_id}` | One record; 404 when not registered. |
| `GET /v1/bonds/{bond_id}/entitlements` | Collection query over the bond's entitlement rows `{id: "<index>:<holder>", bond, index, holder, units, amount, claimed, claimed_at_ms}` in cash-flow then holder order; 404 when not registered. |

The collection fields are listed in `specs/torii/collection_queries.md`; the
OpenAPI contract types the pages (`BondRecordPage`, `BondEntitlementPage`).

Read access: record-date holdings are market data of the same kind as current
holders, which `GET /v1/assets/{definition_id}/holders` already serves
publicly, so the Torii routes are public. The signed typed queries keep the
native ledger-wide read root (`NativeQueryAccess::AllLedger`) for consistency
with the repo-agreement and escrow typed queries, whose records are likewise
published by public Torii routes; the root governs the signed query surface,
not confidentiality.

## 7. Initial executor, time and FASTPQ

The fail-safe Initial executor admits `BondInstructionBox`; Core keeps every
authority check above. Bond instructions are time-sensitive (record, payment,
grace, call-notice and default gates use block time), so they follow the NTS
health admission rule for time-sensitive transactions.

Under the bootstrap FASTPQ source profile a transaction (one logical entry)
may produce at most sixteen original transfer deltas. Each coupon claim and
each redemption claim is one payment delta (the redemption burn is a supply
quantity change, not a transfer delta); funding is one delta; a treasury
retirement is a supply quantity change only. A paying agent
therefore packs at most sixteen claims per transaction; a seventeen-claim
transaction is refused atomically with "FASTPQ source intrinsic limit
exceeded". A paid Nexus fee is charged outside that entry budget: with a
base fee enabled, sixteen claims and the fee still fit. Certified
Initial-executor tests pin both bounds, with and without a fee.

## 8. Deviations from the design contract

Relative to `BOND_KERNEL_SPEC.md`:

1. `BondRecord` carries `id` and the derived `vault`; each
   `BondCashflowState` embeds its effective `terms` instead of only `index`,
   so a call-appended redemption is self-describing.
2. Snapshots are not stored in the record: per-holder `BondEntitlement` rows
   live in `world.bond_entitlements` and the record keeps `holders`,
   `claimed_holders` and totals instead of `snapshot` and `claimed`. A
   `Recording` status and cursor make recording paged.
3. **No 4096-holder limit.** The contract's fixed snapshot bound let a holder
   (or a wide distribution) make every cash flow unrecordable. Recording is
   paged instead (§3.2).
4. **Record date enforced by closed books.** The contract snapshot reflected
   the block in which the paying agent recorded. Movements are refused from
   the record date until recording completes (§4.1), so recording at any later
   time yields the holdings of record.
5. **Recording is permissionless.** Under closed books the result does not
   depend on the signer or timing, and an open recording keeps movements
   blocked, so any account may record instead of only the paying agent.
6. **No encumbrance veto.** The contract refused recording while repo
   collateral or an allotment escrow encumbered units; anyone could block
   servicing that way. Escrowed units count for the escrow seller, repo
   collateral for its title holder and issuer allotments for nobody (§4.2).
7. **Attributed custody only.** Registered bond units can enter only accounts
   and native asset-escrow custody (§4.3), and registration requires the
   issuer to hold the whole supply.
8. **Regular schedules enforced.** The contract checked coupon amounts only;
   registration also requires the coupon dates and count to be the regular
   schedule of the stated frequency (§1.1). The contract's strict increase of
   all payment dates is replaced by this rule plus the shared maturity date of
   the final coupon and the redemption, which a strict increase would forbid
   for every bullet bond.
9. **Closing does not wait for every holder.** `CloseBondCashflow` closes a
   funded cash flow at or after its payment date; unclaimed entitlements stay
   claimable from the vault (claims accept `Funded` and `Closed`). There is no
   residual: `amount_due` is the sum of rounded payments, so nothing remains
   once every holder claimed, and `CashflowClosed` reports the unclaimed
   amount instead of a residual.
10. `Matured` is reached when every effective cash flow is closed or
    cancelled, not on closing the redemption alone, so an unpaid coupon can
    still be declared in default. Claims continue after maturity.
11. **Default needs the grace period.** `BondTerms::payment_grace_ms` (new,
    at most 366 days) delays `DeclareBondDefault` until
    `payment_date + grace`; `DeclareBondDefault` accepts only `Scheduled` and
    `Recorded` cash flows of an `Active` or `Called` bond (the contract said
    "not Funded/Closed").
12. After `Defaulted`, claims and closing of cash flows that were already
    funded stay allowed; blocking them would trap holders' money.
13. `CallBond` additionally requires lifecycle `Active`, a call date before
    maturity and every later cash flow `Scheduled`. A call does not rewrite
    cash flows in place: later ones get the added status `Cancelled` and the
    call redemption is appended with the next index.
14. A registered bond's supply is locked (no `Mint`/`Burn`) and vault balances
    are protocol custody exempt from the payment asset's policies on the
    vault; the redemption burn ignores the bond's confidential and usage
    policies (§4.4).
15. Registration additionally requires global balance policies, a payment
    asset distinct from the bond and from every registered bond, a bond that
    is no bond's payment asset, existing issuer and paying-agent accounts, a
    positive minted supply and the whole supply with the issuer.
16. A new eighth instruction `ReplaceBondPayingAgent`; issuer and paying-agent
    references follow account rekeys instead of blocking them.
17. Identifiers must be non-empty printable ASCII in addition to the length
    bounds.
18. Quantities use `Quantity` (non-negative `Numeric`) where the contract says
    `Numeric`.
19. Events carry more than the contract lists: `kind` and `holders` on
    `CashflowRecorded`, `redemption_index` on `Called`, the `Registered`
    payload, the unclaimed figures on `CashflowClosed`, and the new
    `PayingAgentReplaced`.
20. Account retention: vaults, the issuer and paying agent of a bond still
    servicing or with an open cash flow, and every unit holder are retained
    against unregistration; rekeys migrate references (§5).
21. The vault derivation is network independent (the bond identifier alone).
22. Queries are ledger-wide reads in the native executor, while Torii serves
    records and entitlements publicly through collection routes (§6).
23. **Treasury retirement.** A new ninth instruction
    `RetireBondTreasuryUnits` lets the issuer burn units it holds directly
    (not units it owes back as repo collateral), with `retired_units` in the
    state and the `TreasuryUnitsRetired` event; retiring the last outstanding
    unit cancels every unrecorded cash flow (§3, item 9). The contract kept
    treasury units outstanding forever.
24. **Backdated registration.** Registration records every cash flow whose
    record date has passed, with no holders, and refuses a bond whose
    redemption record date has passed (§3, item 1); a recorded cash flow that
    owes nothing cannot default (§3, item 7).

## 9. Known limits

- Issuer-retained (treasury) units are excluded from entitlements and are
  never paid; they stay outstanding until the issuer retires them with
  `RetireBondTreasuryUnits`.
- A repo whose counterparty or custodian is the issuer holds the collateral as
  treasury units: nobody is entitled to them at a record date (manufactured
  payments are a matter between the repo parties), and retirement keeps them
  reserved for the reverse.
- The escrows phase of a recording walks every escrow record of the ledger
  (bounded per step). TODO: index escrows by asset definition.
- A rekey probes every recorded cash flow of every bond for the old account's
  entitlements. TODO: index entitlements by holder.
- Units a seller still has in escrow custody when the redemption is recorded
  must return to the seller (cancel, refund or expiry) before the seller can
  redeem them; an escrow whose payment was marked sent can only be refunded
  through its dispute path. A repo whose collateral matures with the bond
  cannot return the collateral after the redemption is recorded.
- Funds of entitlements nobody can claim (a donated balance held by a
  protocol account, a holder that never claims) stay in the vault; there is no
  prescription sweep yet.
- The definition owner can still change the bond definition's confidential
  policy or transfer its ownership; neither changes the record or the
  redemption burn, but a shielded-only policy blocks ordinary transfers.

## 10. JavaScript SDK

Owners: `crates/iroha_js_codec/src/bond_instructions.rs` (strict JSON
envelope, vault rendering), `crates/iroha_js_host/src/settlement_lifecycle.rs`
(N-API `bondVaultAccountId`), `javascript/iroha_js/src/bond.js` (builders,
schedule, validation, payments), `src/bondRecords.js` (Torii record,
entitlement and page checks), `src/transactionReview.js` (review rows).

### 10.1 Envelope

Bond instructions use one closed JSON envelope that mirrors
`BondInstructionBox`: `{"Bond": {<Variant>: <payload>}}` with exactly one of
`Register`, `RecordCashflow`, `FundCashflow`, `ClaimCashflow`,
`CloseCashflow`, `Call`, `DeclareDefault`, `ReplacePayingAgent`,
`RetireTreasuryUnits`. Each payload
must equal the canonical model JSON of its leaf type: snake_case fields,
canonical quantity strings (`"50"`, `"3.25"`, never `"50.0"`), JSON numbers
for `u16`/`u32`/`u64` fields, lowercase 64-digit hex for `[u8; 32]` digests
and explicit `null` for absent optional terms. Unknown, missing, renamed or
extra fields, two variants, leaf envelopes (`{"RegisterBond": ...}`) and
generic base64 instruction literals are refused. Instruction archives and
public frames decode back to the same envelope, so
`noritoDecodeInstructionBoxArchive`, `noritoDecodeInstruction` and the
transaction review render every bond field. The codec admits shape only;
terms validation and every state check remain in Core.

### 10.2 Builders and helpers

Builders take camelCase options and return the envelope:
`buildRegisterBondInstruction({ bondId, terms })`,
`buildRecordBondCashflowInstruction({ bondId, index })` (any signer; repeat
until `Recorded`),
`buildFundBondCashflowInstruction({ bondId, index, sourceAssetHoldingId })`
(global, unscoped bucket only),
`buildClaimBondCashflowInstruction({ bondId, index, holder })`,
`buildCloseBondCashflowInstruction({ bondId, index })`,
`buildCallBondInstruction({ bondId, callDateMs })`,
`buildDeclareBondDefaultInstruction({ bondId, index, evidenceSha256 })`,
`buildReplaceBondPayingAgentInstruction({ bondId, payingAgent })` and
`buildRetireBondTreasuryUnitsInstruction({ bondId, quantity })` (a positive
whole number of units; zero, fractional and JavaScript-number quantities are
refused before submission).
Quantities are `KotodamaQuantity`, canonical decimal strings or bigint
(JavaScript numbers are refused); integers are safe JavaScript integers,
bigint or decimal strings; digests are 32 bytes or 64 hex digits. Terms take
the required `paymentGraceMs`.

- `buildBondSchedule({ denomination, couponRateBps, couponFrequency,
  issueDateMs, maturityDateMs, redemptionPriceBps, recordOffsetMs })` ports
  `fixed_rate_bullet_schedule` (§1.2) with integer calendar arithmetic and
  exact decimal arithmetic on bigint mantissas. It returns
  `[{ index, kind, recordDateMs, paymentDateMs, amountPerUnit }]` and refuses
  exactly what Core refuses, in the same order and with the same
  `bond.invalid_terms: ...` messages.
- `validateBondTerms(terms)` normalizes builder terms to canonical native
  JSON and applies every `BondTerms::validate` rule (§1.1), including the
  regular-schedule rule, in Core's order with Core's messages.
  `buildRegisterBondInstruction` calls it and also refuses a payment asset
  equal to the bond.
- `bondHolderPayment({ units, amountPerUnit, paymentScale })` is
  `holder_payment` (§1.3).
- `bondVaultAccountId(bondId, networkPrefix)` calls the native
  `bond_vault_account_id` derivation (§1.4) and renders the I105 literal for
  the given prefix; the derivation itself is network independent.
- Constants: `BOND_MAX_CASHFLOWS`, `BOND_RECORDING_PAGE_ENTRIES`,
  `BOND_MAX_PAYMENT_GRACE_MS`, `BOND_RECORD_PAGE_MAX_ITEMS`,
  `BOND_ENTITLEMENT_PAGE_MAX_ITEMS`.

`javascript/iroha_js/test/fixtures/bond-v1-codec.json` is generated from the
data model by `bond_instruction_tests.rs` (rerun the ignored
`regenerate_bond_js_fixture` test to accept a change; a checked test requires
equality with a fresh generation). It pins every envelope with its archive and
frame bytes, vault accounts, schedule outputs and refusals, a verdict for each
validation rule, rounded holder payments, and a serviced `BondRecord` with its
entitlements. The JS tests replay all of them.

### 10.3 Torii reads and review

`ToriiClient` and `ToriiBrowserClient` expose:

- `listBonds({ limit?, cursor?, filter?, signal? })` (`GET /v1/bonds`):
  `{ items, nextCursor, total? }`, at most 20 records per page, the response
  capped at 16 MiB;
- `getBond(bondId)` (`GET /v1/bonds/{bond_id}`, `null` on 404, capped at
  2 MiB);
- `getBondEntitlements(bondId, { index?, holder?, limit?, cursor?, signal? })`
  (`GET /v1/bonds/{bond_id}/entitlements`, `null` on 404): one page of
  entitlement rows, at most 1000 per page, capped at 4 MiB; `index` and
  `holder` become an exact collection filter.

Responses are parsed with lossless integers, checked (lifecycle and status
enums, cash-flow totals, the recording cursor exactly while `Recording`,
contiguous indices, entitlement identity `<index>:<holder>` and claim flags,
the requested bond, the `outstanding_units`, `redeemed_units` and
`retired_units` strings) and returned as native snake_case JSON
(prototype-free objects, as the lossless parser builds them).

`reviewTransactionPayload` renders a `kind: "bond"` row for every variant.
The cash-flow kind, dates, amount per unit, entitled units and payment are not
carried by `RecordCashflow`, `FundCashflow`, `ClaimCashflow`,
`CloseCashflow` or `DeclareDefault`, so the review accepts
`expected.bonds: [{ record, entitlements? }]` (a record from `getBond` and rows
from `getBondEntitlements`). With them the rows add the cash-flow kind, record
and payment dates, amount per unit, status, the funding amount due and the
vault, the holder's entitled units and exact payment (and a warning for an
already claimed entitlement), the unclaimed holders a close leaves claimable,
the payment grace of a default, the call price, the replaced paying agent,
the outstanding units before and after a treasury retirement (and the
cancellation of unrecorded cash flows when none remains),
the book closing and recording progress of a record step, and the freeze
(recording) or burn (claiming) effect of the redemption. Without them the rows
show only the instruction's own fields.

### 10.4 Choices relative to the design contract

- Builder options and `buildBondSchedule` entries are camelCase, as across
  the SDK, so a schedule feeds `terms.cashflows` directly; the envelopes keep
  the native snake_case fields.
- `bondVaultAccountId` takes an explicit network prefix because an I105
  literal is network specific; the derivation is not.
- `listBonds` and `getBondEntitlements` are page reads of the Torii
  collection routes rather than whole-table reads.
- `validateBondTerms` and `bondHolderPayment` are additional pure helpers so
  applications can refuse invalid terms and show exact payments before
  submission; `ToriiBrowserClient` gains the same reads as `ToriiClient`.

## 11. Primary offering, repo and servicing on a registered bond

The Silicon Alps demo flows run unchanged on a registered bond; certified
Initial-executor tests in `crates/iroha_core/src/executor_bond_admission_tests.rs`
(`bond_admission::demo`) commit each step as its own transaction and pin every
balance. No custody, book-closing or supply rule refuses them, provided the
timing rules of §11.2 hold.

### 11.1 Flows

1. **Issuance** (one issuer transaction): `Register<AssetDefinition>` (scale
   0, `AssetBalancePolicy::Global`, owned by the issuer), `Mint` of the whole
   supply to the issuer, `RegisterBond`, and `OpenConditionalEscrow` of the
   10 % tranche from the issuer to the issuer. Past record dates of a
   backdated schedule are recorded at registration (§3, item 1), so the books
   are open for the escrow in the same transaction. The tranche units are in
   escrow custody with the issuer as seller: nobody is entitled to them.
2. **Subscription before the minimum raise**: the buyer submits `SettleAtomic`
   with one movement (the trade fee, buyer EUR to the platform) and four escrow
   legs (bond units issuer to buyer — the allotment —, EUR buyer to issuer,
   EUR buyer to platform, EUR buyer to the issuer's reserve account). Its
   owner-qualified `settlement_id` is `{ owner: buyer, reference }`: the
   namespace owner must debit one of the legs, and the buyer debits its own
   EUR. The issuer first grants the buyer `CanExecuteSettlement {
   debited_asset: <issuer's bond balance>, settlement_id, intent_hash }` for
   that exact settlement; the buyer's own balances need no consent. Until
   release the allotment counts for the issuer (nobody, §4.2).
3. **Minimum raise**: the attestor submits `AttestEscrowCondition` for every
   leg and for the tranche (any number per transaction, before each escrow's
   expiry). Allotments go to the buyers, the tranche back to the issuer.
4. **Purchase after the minimum raise**: `SettleAtomic` with the bond movement
   issuer to buyer, the EUR movements (issuer, platform) and one escrow leg for
   the reserve, again buyer-owned (`{ owner: buyer, reference }`) and under the
   issuer's consent.
5. **Repo**: `RepoIsi` with the buyer as initiator delivering bond units as
   collateral and a counterparty (the bank) delivering EUR. The counterparty
   grants the initiator two consents, both for the settlement id
   `{ owner: initiator, reference: agreement id }`: its EUR balance under the
   initiation intent hash and its bond balance under the maturity intent hash. With
   `allow_early_repayment`, `ReverseRepoIsi` returns the units early. The
   counterparty is holder of record while it holds the collateral (§4.2).
6. **Failed offering**: at or after the escrow expiry anyone submits
   `ExpireConditionalEscrow` for every allotment leg and the tranche; units
   return to the issuer and EUR to the buyers. The issuer then retires the
   unsold supply with `RetireBondTreasuryUnits`; retiring every unit cancels
   each unrecorded cash flow and matures the bond once the cash flows recorded
   at registration are closed (§3, item 9).
7. **Servicing**: at the record date anyone repeats `RecordBondCashflow`
   until `Recorded` (the final coupon, then the redemption, which freezes the
   bond); the paying agent funds both; from the payment date holders claim
   their own entitlements and the paying agent pushes the others (at most
   sixteen claims per transaction, §7), closes both cash flows and the bond
   becomes `Matured`. Redemption claims burn the units. The issuer retires its
   remaining treasury units afterwards.

### 11.2 Schedule and timing constraints

- **Regular monthly schedule.** `coupon_frequency = 12`; the issue date is
  exactly the maturity stepped back by a whole number of calendar months, with
  the same time of day and the day of month clamped to the month length; every
  coupon is paid on maturity minus a whole number of months. Any time of day
  works, so a maturity a few minutes ahead with an issue date one or more
  months in the past is valid. `buildBondSchedule` (§10.2) produces the exact
  schedule.
- **Exact monthly coupon.** `denomination × coupon_rate_bps / 120_000` must be
  a terminating decimal, that is `denomination × coupon_rate_bps` divisible by
  three (for example 100 at 600 bps pays 0.5 per unit per month; 50 at 650 bps
  is refused).
- **Record dates.** Each record date lies in `[issue, payment]` and record
  dates never decrease; `buildBondSchedule` uses `payment − recordOffsetMs`
  clamped to the issue date, so the final coupon and the redemption share the
  record date `maturity − recordOffsetMs`.
- **Registration** needs block time before the redemption record date. Every
  cash flow whose record date has passed is recorded with no holders; with a
  monthly backdated bond these are all coupons before the final one, and only
  the final coupon and the redemption can pay the demo's buyers. The paying
  agent funds (zero, nothing moves) and closes each of them, in one
  transaction, before the bond can mature; they cannot be defaulted.
- **Before the final record date**: allotment releases, purchases, repo
  initiation and reverse, and every other movement of the bond must settle.
  From the record date until the cash flow is recorded the books are closed;
  after the redemption is recorded the bond is frozen for good. Only escrows
  returning units to their seller (expiry, refund) still move units then.
  An allotment that has not been released at the record date pays its buyer
  nothing.
- **At or after the payment date** (maturity for the final coupon and the
  redemption): claims and closing. Funding may precede the payment date.
- **Grace.** `payment_grace_ms` is at most 366 days and only gates
  `DeclareBondDefault` (`> payment_date + grace`); any value, including 0, is
  valid for a demo that never defaults.
