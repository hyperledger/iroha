---
title: Native Bond-Servicing Kernel
summary: Normative contract for registered bond records, record-date snapshots, vault-funded coupon and redemption servicing, calls, defaults and the transfer freeze.
---

# Native Bond-Servicing Kernel

A bond is an ordinary fungible asset definition with scale 0 whose unit is the
legal denomination. Issuance, primary subscription (`SettleAtomic` with
conditional-escrow legs, `OpenConditionalEscrow` tranches) and repo stay the
existing native flows. The kernel adds one typed, authoritative
`BondRecord` per bond and seven native instructions that perform every
legally material cash-flow operation. There is no mutable metadata escape
hatch for terms and no legacy or compatibility path.

Source owners:

| Concern | Location |
| --- | --- |
| Terms, record, validation, schedule builder, vault derivation | `crates/iroha_data_model/src/bond.rs` |
| Instructions and `BondInstructionBox` (`iroha.bond`) | `crates/iroha_data_model/src/isi/bond.rs` |
| Events and `DataEventFilter::Bond` | `crates/iroha_data_model/src/events/data/bond.rs` |
| Queries `FindBondById`, `FindBonds` | `crates/iroha_data_model/src/query/domain_queries.rs` |
| Execution, freeze, retention, query execution | `crates/iroha_core/src/smartcontracts/isi/bond.rs` |
| Verified vault movements and redemption burn | `crates/iroha_core/src/smartcontracts/isi/asset.rs` |
| Torii routes `GET /v1/bonds`, `GET /v1/bonds/{bond_id}` | `crates/iroha_torii/src/lib.rs` |
| JS codec envelope and vault rendering | `crates/iroha_js_codec/src/bond_instructions.rs` |
| JS SDK builders, schedule, validation, Torii reads, review | `javascript/iroha_js/src/bond.js`, `bondRecords.js`, `transactionReview.js` |

## 1. Data model

`BondId` is the bond's `AssetDefinitionId`.

`BondTerms` (immutable once registered):

| Field | Meaning |
| --- | --- |
| `issuer` | Must own the bond definition and sign registration and calls. |
| `paying_agent` | Records, funds, closes, declares defaults and may push claims. |
| `payment_asset` | Asset definition of every payment (for example a EUR e-money token). |
| `denomination` | Payment-asset amount per bond unit (positive). |
| `coupon_rate_bps` | Annual rate; `0` exactly when `coupon_frequency == 0`. |
| `coupon_frequency` | `0`, `1`, `2`, `4` or `12` payments per year. |
| `day_count` | `ActActIcma`, `Thirty360`, `Act360`, `Act365Fixed`: a legal label only, see §1.2. |
| `issue_date_ms`, `maturity_date_ms` | Unix milliseconds, `issue < maturity`. |
| `redemption_price_bps` | Positive; `10_000` is par. |
| `call` | Optional `BondCallTerms { first_call_date_ms, price_bps, notice_ms }`. |
| `cashflows` | Fully materialised schedule of 1..=400 `BondCashflowTerms`. |
| `identifiers` | `BondIdentifiers { isin <= 12, cfi <= 6, issuer_lei <= 20, bdt_version 1..=32, bdt_document_sha256 }`; every label is printable ASCII. |
| `terms_sha256` | SHA-256 of the legal terms document. |

`BondCashflowTerms { index, kind: Coupon | Redemption, record_date_ms,
payment_date_ms, amount_per_unit }`. `amount_per_unit` is an exact decimal and
may carry more decimals than the payment asset.

`BondRecord { id, vault, terms, state }` where `state` is
`BondState { lifecycle: Active | Called | Matured | Defaulted,
outstanding_units, redeemed_units, transfers_frozen, cashflows }` and every
effective cash flow is a `BondCashflowState { terms, status, snapshot,
entitled_units, amount_due, funded, paid, claimed, recorded_at_ms,
funded_at_ms, closed_at_ms, evidence_sha256 }` with status
`Scheduled | Recorded | Funded | Closed | Defaulted | Cancelled`.

### 1.1 Registration validation

`BondTerms::validate` (shared by SDKs and Core, integer/decimal arithmetic
only) rejects with `bond.invalid_terms`:

- identifier bounds above; zero denomination, redemption price or call price;
- a frequency outside `{0, 1, 2, 4, 12}`, or a zero rate with a positive
  frequency (and vice versa);
- `issue >= maturity`; a first call date outside `(issue, maturity)`;
- an empty schedule or one with more than 400 entries;
- indices that are not `0..n` in order;
- a record date after its payment date; a record date before issue or a
  payment date after maturity;
- payment dates that do not strictly increase, except that the redemption may
  share the maturity payment date with the final coupon (bullet bonds);
  record dates that decrease;
- anything other than exactly one `Redemption`, last, paid on maturity with
  `amount_per_unit == denomination × redemption_price_bps / 10_000` exactly;
- coupons on a zero-coupon bond, or a coupon whose `amount_per_unit` is not
  exactly `denomination × coupon_rate_bps / (10_000 × coupon_frequency)`; a
  non-terminating quotient (for example 6.50 % monthly on 50) is rejected, so
  such schedules must use another denomination.

### 1.2 Schedule builder

`fixed_rate_bullet_schedule(BondScheduleRequest)` materialises a regular
fixed-rate bullet schedule: coupon payment dates step back from maturity by
`12 / frequency` calendar months (end-of-month clamping) and must land exactly
on the issue date, otherwise it refuses with "the first coupon period is
irregular". Record dates are `payment - record_offset_ms`, clamped to the
issue date. Because periods are regular, the day-count label does not change
any amount in the first release.

### 1.3 Arithmetic

- Holder payment: `floor(units × amount_per_unit)` at the payment asset's
  scale (`RoundingMode::TowardZero`); an unconstrained payment asset receives
  the exact product.
- `amount_due` is the sum of the rounded holder payments, so funded money
  always covers every claim exactly and the per-cash-flow residual
  `funded - paid` is zero once all holders claimed (see §8).

### 1.4 Vault

`bond_vault_account_id(bond) = AccountId(derive_non_signing_ed25519_public_key(
"iroha:bond:vault:v1", [bond.aid_bytes]))`. No private key exists for the
point, the derivation is network independent, and the vault account is
created on first funding. It is stored in `BondRecord::vault`.

## 2. Storage

World table `bonds: AssetDefinitionId -> BondRecord`
(`world.bonds`, a canonical authority-registry table) is persisted in World
snapshots (`WorldData::bonds`), restored by `deserialize_world`, staged and
applied with every `WorldTransaction`, and readable through
`WorldReadOnly::bonds()`.

## 3. Instructions

All seven instructions travel only inside `BondInstructionBox`
(wire id `iroha.bond`, tags 0..=6 in the order below); leaf types have no wire
identifiers. Core performs every authority check; the Initial executor admits
the box (§7). Block time is the committed block timestamp. Rejections are
`InvariantViolation` messages prefixed with the stable code from
`BondError::code()` (`bond.unauthorized`, `bond.invalid_state`,
`bond.too_early`, `bond.encumbered`, ...).

1. **`RegisterBond { bond, terms }`** (`Register`). The signer is
   `terms.issuer`; the terms validate; the bond is not registered; the payment
   asset differs from the bond; both definitions exist and use
   `AssetBalancePolicy::Global`; the issuer owns the bond definition, whose
   numeric spec has scale 0; issuer and paying-agent accounts exist; the
   definition's minted total is positive. The record starts `Active`, every
   cash flow `Scheduled`, `outstanding_units = total_quantity`. The intended
   use is one issuer transaction: `Register<AssetDefinition>`, `Mint`,
   `RegisterBond` (and any allotment escrows).
2. **`RecordBondCashflow { bond, index }`** (`RecordCashflow`). Signer: paying
   agent. Lifecycle `Active` or `Called`; the cash flow is `Scheduled`; block
   time `>= record_date_ms`; every lower index is not `Scheduled`. Rejected
   with `bond.encumbered` while an active repo agreement uses the bond in either
   leg, or an active native escrow (marketplace, lock or conditional) holds
   bond units with a counterparty other than the issuer. The snapshot
   aggregates every non-zero global balance of the bond excluding the issuer,
   the vault and native escrow custody accounts; more than 4096 holders is
   `bond.snapshot_too_large`. Sets `entitled_units`, `amount_due`,
   `recorded_at_ms`, status `Recorded`; recording the `Redemption` sets
   `transfers_frozen`.
3. **`FundBondCashflow { bond, index, source }`** (`FundCashflow`). Signer:
   paying agent or issuer; lifecycle `Active` or `Called`; `source` is the
   signer's global balance of the payment asset; status `Recorded`. Moves
   exactly `amount_due` into the vault (no movement when zero). Status
   `Funded`. Funding before the payment date is allowed.
4. **`ClaimBondCashflow { bond, index, holder }`** (`ClaimCashflow`). Signer:
   the holder or the paying agent; the destination is always the holder.
   Status `Funded`; block time `>= payment_date_ms`; the holder is in the
   snapshot and has not claimed. A coupon pays the holder payment from the
   vault. A redemption first burns exactly the holder's snapshot units (the
   only supply change a registered bond admits; the holder still holds them
   because transfers froze at recording) and then pays; `outstanding_units`
   decreases and `redeemed_units` increases by those units. Marks the holder
   claimed and adds the payment to `paid`. Any failure (for example missing
   units) rejects the whole instruction.
5. **`CloseBondCashflow { bond, index }`** (`CloseCashflow`). Signer: paying
   agent; status `Funded`; every snapshot holder claimed. Returns
   `funded - paid` from the vault to the issuer, sets `Closed`. The lifecycle
   becomes `Matured` when every effective cash flow is `Closed` or
   `Cancelled` (an unpaid coupon keeps the bond servicing).
6. **`CallBond { bond, call_date_ms }`** (`Call`). Signer: issuer; lifecycle
   `Active`; call terms exist; `call_date >= first_call_date_ms`;
   `call_date >= block time + notice_ms`; `call_date < maturity`; the date is
   the payment date of a `Scheduled` coupon. Every later effective cash flow
   becomes `Cancelled` and one `Redemption` is appended with the next index,
   that coupon's record date, payment date `call_date` and
   `amount_per_unit = denomination × call.price_bps / 10_000`. The coupon on
   the call date stays. Lifecycle `Called`. Registered terms are unchanged.
7. **`DeclareBondDefault { bond, index, evidence_sha256 }`**
   (`DeclareDefault`). Signer: paying agent; lifecycle `Active` or `Called`;
   the cash flow is `Scheduled` or `Recorded`; block time
   `> payment_date_ms`. The cash flow becomes `Defaulted` with the evidence
   digest and the lifecycle `Defaulted`. Afterwards recording, funding, calls
   and further defaults are rejected; claims and closing of cash flows funded
   before the default continue, so vault money is never trapped.

## 4. Movement and supply controls

- **Transfer freeze.** `PreparedNumericTransferPlan::prepare` is the single
  preparation step of every numeric movement (user transfers and batches,
  `SettleAtomic` movements and escrow legs, conditional-escrow and other
  native escrow funding/release, repo initiation and settlement, protocol
  movements). It calls `ensure_bond_units_movable`, which rejects any
  movement of a bond whose `transfers_frozen` is set with
  `bond.transfers_frozen`. The redemption burn is a supply change, not a
  movement.
- **Supply lock.** `Mint` and `Burn` (including retail reserve mint/burn and
  the central checked burn) of a registered bond's units are rejected with
  `bond.supply_locked`; only the redemption-claim burn
  (`NumericAssetBurnSourcePolicy::BondRedemption`) changes the supply.
- **Vault custody.** Direct debits of a vault balance (transfers, burns,
  other protocol sources) and credits to a vault (transfers, mints) outside
  `FundBondCashflow` are rejected with `bond.vault_custody`. Funding uses the
  embedded `BondFunding` purpose with the `BondVaultFunding` source policy
  (destination must be a registered vault); payments and residuals use the
  retained `BondVault` purpose with the `BondVaultCustody` source policy.
  `execute_verified_bond_movement` and `execute_verified_bond_redemption_burn`
  re-check each capability against the stored record (signer, exact source
  and destination, status, snapshot membership, unclaimed holder, amount
  bounds) before any balance changes.

## 5. Retention

Bond records are permanent. `Unregister<AssetDefinition>` and
`Unregister<Domain>` refuse to retire a bond definition or a payment-asset
definition of any bond (`bond.retained`). `Unregister<Account>` and the
multisig account rekey refuse the vault, issuer and paying agent of any bond
and every holder with an unclaimed entitlement in a `Recorded` or `Funded`
cash flow.

## 6. Events, queries and Torii

`DataEvent::Bond(BondEvent)` (data-event tag 25) carries
`Registered { bond, issuer, paying_agent, outstanding_units, cashflows }`,
`CashflowRecorded { bond, index, kind, holders, entitled_units, amount_due }`,
`CashflowFunded { bond, index, amount }`,
`CashflowClaimed { bond, index, holder, units, amount }`,
`CashflowClosed { bond, index, residual }`,
`Called { bond, call_date_ms, redemption_index }` and
`Defaulted { bond, index, evidence_sha256 }`.
`DataEventFilter::Bond(Option<BondId>)` (filter tag 27) selects all bond
events or one bond's; data triggers index the bond family and subject, and a
bond-scoped trigger filter belongs to the owner of the bond definition.

Queries: singular `FindBondById { bond } -> BondRecord`
(`SingularQueryOutputBox::BondRecord`, `FindError::Bond` when absent) and
iterable `FindBonds -> BondRecord` (`QueryItemKind::BondRecord`, wire tag 31,
wire id `iroha.query.v1::iterable::bond::BondRecord`). Both require the
ledger-wide read root in the native executor because records carry every
investor's record-date holdings. The JSON query envelope accepts
`{"type": "FindBondById", "payload": {"bond": "<asset definition address>"}}`
and the iterable `FindBonds`.

Torii serves the records without a signed query on public application routes
`GET /v1/bonds` (array of records) and `GET /v1/bonds/{bond_id}` (one record,
404 when absent) as Norito JSON, documented in the OpenAPI contract.

## 7. Initial executor, time and FASTPQ

The fail-safe Initial executor admits `BondInstructionBox`; Core keeps every
authority check above. Bond instructions are time-sensitive (record, payment,
call-notice and default gates use block time), so they follow the NTS health
admission rule for time-sensitive transactions.

Under the bootstrap FASTPQ source profile a transaction (one logical entry)
may produce at most sixteen original transfer deltas. Each coupon claim and
each redemption claim is one payment delta (the redemption burn is a supply
quantity change, not a transfer delta); funding and a non-zero residual are
one delta each. A paying agent therefore packs at most sixteen claims per
transaction, fewer when the transaction also pays a fee movement; a
seventeen-claim transaction is refused atomically with
"FASTPQ source intrinsic limit exceeded". Certified Initial-executor tests
pin both bounds.

## 8. Deviations from the design contract

1. `BondRecord` carries `id` and the derived `vault`; each
   `BondCashflowState` embeds its effective `terms` instead of only `index`,
   so a call-appended redemption is self-describing while registered terms
   stay immutable.
2. A call does not rewrite cash flows in place: later effective cash flows
   get the added status `Cancelled` and the call redemption is appended with
   the next index. Indices therefore never change meaning.
3. The final coupon and the redemption may share the maturity payment date;
   all other payment dates strictly increase and record dates must not
   decrease. The contract's strict increase would forbid every bullet bond.
4. `Matured` is reached when every effective cash flow is closed or
   cancelled, not on closing the redemption alone, so an unpaid coupon can
   still be declared in default.
5. After `Defaulted`, claims and closing of cash flows that were already
   funded stay allowed; blocking them would trap holders' money in the vault.
6. The encumbrance check covers every active native escrow kind holding bond
   units for a counterparty other than the issuer and both repo legs, not
   only conditional escrows and repo collateral.
7. A registered bond's supply is locked (no `Mint`/`Burn`), and vault
   balances are protocol custody. The contract defines
   `outstanding_units` as the minted total minus redemptions; without the
   lock the definition owner could dilute holders or burn their units.
8. Registration additionally requires global balance policies, a distinct
   payment asset, existing issuer and paying-agent accounts and a positive
   minted supply.
9. Because `amount_due` is the sum of rounded-down holder payments, the
   close residual is zero by construction; `CloseBondCashflow` still returns
   any `funded - paid` remainder to the issuer.
10. Queries are ledger-wide reads in the native executor (as repo
    agreements and escrows); the JS-facing read is the public Torii route.

## 9. Known limits

- Issuer-retained (treasury) units are excluded from snapshots and are never
  paid or burned; there is no treasury-cancellation instruction yet, so
  `outstanding_units` keeps them after maturity.
- A record keeps every recorded snapshot; each claim loads and stores the
  whole record, so servicing cost grows with holders × recorded cash flows.
  TODO: move entitlements into a per-holder table if bonds approach the
  4096-holder bound.
- Vault predicates scan the bond table on each movement.
- An escrow of bond units whose beneficiary is the issuer stays frozen with
  the bond after the redemption is recorded; a defaulted bond whose
  redemption was recorded stays frozen.
- The definition owner can still change the bond definition's confidential
  policy or transfer its ownership; neither changes the record, but a
  shielded-only policy would block redemption burns.

## 10. JavaScript SDK

Owners: `crates/iroha_js_codec/src/bond_instructions.rs` (strict JSON
envelope, vault rendering), `crates/iroha_js_host/src/settlement_lifecycle.rs`
(N-API `bondVaultAccountId`), `javascript/iroha_js/src/bond.js` (builders,
schedule, validation, payments), `src/bondRecords.js` (Torii record checks),
`src/transactionReview.js` (review rows).

### 10.1 Envelope

Bond instructions use one closed JSON envelope that mirrors
`BondInstructionBox`: `{"Bond": {<Variant>: <payload>}}` with exactly one of
`Register`, `RecordCashflow`, `FundCashflow`, `ClaimCashflow`,
`CloseCashflow`, `Call`, `DeclareDefault`. Each payload must equal the
canonical model JSON of its leaf type: snake_case fields, canonical quantity
strings (`"50"`, `"3.25"`, never `"50.0"`), JSON numbers for `u16`/`u32`/`u64`
fields, lowercase 64-digit hex for `[u8; 32]` digests and explicit `null` for
absent optional terms. Unknown, missing, renamed or extra fields, two
variants, leaf envelopes (`{"RegisterBond": ...}`) and generic base64
instruction literals are refused. Instruction archives and public frames
decode back to the same envelope, so `noritoDecodeInstructionBoxArchive`,
`noritoDecodeInstruction` and the transaction review render every bond field.
The codec admits shape only; terms validation and every state check remain in
Core.

### 10.2 Builders and helpers

Builders take camelCase options and return the envelope:
`buildRegisterBondInstruction({ bondId, terms })`,
`buildRecordBondCashflowInstruction({ bondId, index })`,
`buildFundBondCashflowInstruction({ bondId, index, sourceAssetHoldingId })`
(global, unscoped bucket only),
`buildClaimBondCashflowInstruction({ bondId, index, holder })`,
`buildCloseBondCashflowInstruction({ bondId, index })`,
`buildCallBondInstruction({ bondId, callDateMs })` and
`buildDeclareBondDefaultInstruction({ bondId, index, evidenceSha256 })`.
Quantities are `KotodamaQuantity`, canonical decimal strings or bigint
(JavaScript numbers are refused); integers are safe JavaScript integers,
bigint or decimal strings; digests are 32 bytes or 64 hex digits.

- `buildBondSchedule({ denomination, couponRateBps, couponFrequency,
  issueDateMs, maturityDateMs, redemptionPriceBps, recordOffsetMs })` ports
  `fixed_rate_bullet_schedule` (§1.2) with integer calendar arithmetic and
  exact decimal arithmetic on bigint mantissas. It returns
  `[{ index, kind, recordDateMs, paymentDateMs, amountPerUnit }]` and refuses
  exactly what Core refuses, in the same order and with the same
  `bond.invalid_terms: ...` messages (frequency, issue/maturity order,
  irregular first period, the 400 cash-flow bound, non-terminating or
  over-scale amounts).
- `validateBondTerms(terms)` normalizes builder terms to canonical native
  JSON and applies every `BondTerms::validate` rule (§1.1) in Core's order
  with Core's messages. `buildRegisterBondInstruction` calls it and also
  refuses a payment asset equal to the bond.
- `bondHolderPayment({ units, amountPerUnit, paymentScale })` is
  `holder_payment` (§1.3): `floor(units × amountPerUnit)` at `paymentScale`,
  the exact product when `paymentScale` is `null`.
- `bondVaultAccountId(bondId, networkPrefix)` calls the native
  `bond_vault_account_id` derivation (§1.4) and renders the I105 literal for
  the given prefix; the derivation itself is network independent.

`javascript/iroha_js/test/fixtures/bond-v1-codec.json` is generated from the
data model by `bond_instruction_tests.rs` (rerun the ignored
`regenerate_bond_js_fixture` test to accept a change; a checked test requires
equality with a fresh generation). It pins every envelope with its archive and
frame bytes, vault accounts, schedule outputs and refusals, a verdict for each
validation rule, rounded holder payments and a serviced `BondRecord`. The JS
tests replay all of them.

### 10.3 Torii reads and review

`ToriiClient` and `ToriiBrowserClient` expose `listBonds()`
(`GET /v1/bonds`) and `getBond(bondId)` (`GET /v1/bonds/{bond_id}`, `null` on
404). Responses are parsed with lossless integers, checked to be bond records
(lifecycle and status enums, snapshot and claimed shapes, contiguous cash-flow
indices; `getBond` also requires the requested id) and returned as native
snake_case JSON (prototype-free objects, as the lossless parser builds them).

`reviewTransactionPayload` renders a `kind: "bond"` row for every variant.
The cash-flow kind, dates, amount per unit and holder units are not carried
by `RecordCashflow`, `FundCashflow`, `ClaimCashflow`, `CloseCashflow` or
`DeclareDefault`, so the review accepts
`expected.bonds: [{ record, paymentAssetScale? }]` (records from
`getBond`). With a record the rows add the cash-flow kind, record and payment
dates, amount per unit, status, the funding amount due and the vault, the
holder's snapshot units and payment (rounded when the scale is supplied), the
issuer as residual recipient, the call price, and the freeze (recording) or
burn (claiming) effect of the redemption. Without it the rows show only the
instruction's own fields.

### 10.4 Choices relative to the design contract

- Builder options and `buildBondSchedule` entries are camelCase, as across
  the SDK, so a schedule feeds `terms.cashflows` directly; the envelopes keep
  the native snake_case fields.
- `bondVaultAccountId` takes an explicit network prefix because an I105
  literal is network specific; the derivation is not.
- The transaction review needs bond records to show cash-flow kinds, dates
  and amounts (`expected.bonds`); the payload alone does not contain them.
- `validateBondTerms` and `bondHolderPayment` are additional pure helpers so
  applications can refuse invalid terms and show exact payments before
  submission; `ToriiBrowserClient` gains the same two reads as `ToriiClient`.
