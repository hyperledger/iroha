# Native atomic settlement: first-release contract

This specification accompanies the proposed `SettleAtomic` implementation.
Native compilation and real-network qualification remain required before the
candidate is accepted. The transparent instruction and the confidential
protocol in `private_settlement.md` have different authorization and state
representations; the benchmark compares an identical economic payment vector.

## Signed intent and canonical representation

`SettleAtomic` contains exactly `network_id`, `settlement_id`, `movements`,
`expires_at_height` and `metadata`. The network is identified by genesis.
Expiry is inclusive: execution at the signed height is allowed; execution at
a greater height fails. A successful receipt permanently occupies the business
identifier, so the same identifier cannot execute a second time.

`SettlementId` is the structured pair `{ owner: AccountId, reference: Name }`.
The owner is an explicitly signed participating debit owner; a single movement
therefore uses its payer. All native Atomic, DvP, PvP and FX receipt writers
enforce this namespace. FX uses the signing source payer, never the protocol
reserve owner. Equal references belonging to different owners are independent.
The network scopes the ledger, so durable client/customer-credit keys include
both `NetworkId` and this complete `SettlementId`.

The reference identifies the original business instruction independently of
amount, asset, recipient, expiry, gateway identity or transaction nonce. Reusing
it with changed terms remains a conflict; hashing the complete terms to produce
a fresh identifier would defeat business uniqueness. Native JSON uses the
closed owner/reference object. CLI text and JSON map keys require exactly
`reference$canonical_account`. Bare-name IDs and string-valued native JSON have
no decoder fallback in this first release.

`AtomicSettlementMovements` contains 1 through 255 movements. A single payment
uses the same consent, business-identifier uniqueness and immutable receipt
rules as a multi-payment batch. Each movement is
an exact source `AssetId`, a canonical domainless recipient `AccountId`, and a
positive `Quantity`. The destination has the source's asset definition and
explicit balance scope. Account aliases, ambient lane context and an asset's
display name cannot substitute another bucket. Self-transfers, duplicate
movement keys and unsorted vectors are rejected. Ordering is strictly by
`(source, recipient)`; implementations must not sort an incoming signed value.

Norito binary decoding bounds the vector before allocation and validates its
contents. The canonical layout carries its decode flags; missing scope fields
or alternative layouts are not inferred. JSON uses the same exact closed
fields and validated model. The JavaScript JSON boundary belongs to
`iroha_js_codec`; the host does not maintain a second settlement codec.

The consent digest is `Hash::new_from_chunks` over
`iroha:settlement:atomic-intent:v1\0` and the complete canonical Norito
instruction frame. Consequently network, business identifier, all movements,
expiry and metadata are covered together. It is not a digest of just the
consenting owner's movement.

## Authorization, preparation and application

The transaction authority authorizes debits from its own buckets. Each other
debited bucket requires a live owner-issued `CanExecuteSettlement` permission
binding that exact bucket, business identifier and complete intent hash.
Admission and execution check current consent in their own immutable logical
state view. An earlier admission does not preserve a revoked permission.

Core prepares the complete numeric movement batch in one `StateTransaction`.
Every destination account must already exist. Existing balance policy, transfer
controls, numeric limits and protected reserves still apply. Aggregate outgoing
obligations for each source must be funded by its pre-settlement balance;
incoming movements cannot finance another outgoing obligation in the batch.

Preparation validates every movement, combined transfer-control update and its
bounded serialization before application. It retains the exact signed source
and destination buckets, pre-state balances and one authenticated transfer
transcript. A late invalid movement therefore rejects the complete batch before
an earlier movement can become visible. The receipt is constructed before the
first balance mutation and inserted after successful batch application.

Routing collects every explicit movement scope. A single scoped dataspace can
execute locally; multiple scopes or any Global balance require the universal
coordinator. Direct instructions and `SettlementInstructionBox::Atomic` resolve
to the same routes, fee operation and execution checks.

A direct one-instruction, one-movement `SettleAtomic` carrier with namespace
owner equal to source owner and signed authority, on the same network, checks
for an existing receipt before fee admission and metering. Its new carrier is
rejected with typed `ValidationFail::SettlementReplay`: `AlreadySettled` for
the same intent, or `ConflictingIntent` for changed terms, plus the original
block height/hash locator. Both classifications leave the original receipt
unchanged and produce no second monetary effect or fee. Expiry does not prevent
recovering an already committed original. Composite and delegated carriers
retain ordinary execution and rejection fee policy. A duplicate rejection is
not a newly successful settlement.

## Receipt and query boundary

`SettlementDetails::Atomic` stores the complete validated
`ResolvedSettlementMovements` and the intent hash. Each resolved movement
records the exact source, destination and positive quantity; atomic movements
have no separate per-leg metadata. Shared receipt consumers iterate the full
movement vector, including the 255-movement limit, rather than assuming a pair.

Each `SettlementDetails` variant carries one typed record with closed fields.
The FX outcome has two resolved movements and a mandatory
`FxCorridorPricingContext`; pricing context does not duplicate movement data.
These records use the ordinary schema generator and canonical Norito codecs.

`FindSettlementReceiptById` is a singular, read-only query scoped to the exact
payer in its settlement ID. The registered payer can read its own receipt;
another reader needs the existing exact `CanReadAccountData` grant for that payer
or `CanReadAllLedgerData`. Missing receipts return the typed
`FindError::SettlementReceipt` with the exact owner/reference identity without
inserting state. Torii preserves it as HTTP 404 with code
`query_settlement_receipt_not_found` and the same typed selector in
`details.query_settlement_receipt_not_found`. The SDK requires matching code,
status and selector; generic errors and messages are never absence. This remains
a query observation, not proof that a pending payment cannot execute later.
The singular-query output owner checks source, frame and allocation limits
before cloning the value. A returned receipt cannot mutate retained history.
The query's ID is the same structured owner/reference JSON object.

The Rust SDK's opaque `VerifiedPaymentReceipt` joins exact signed native terms
to the existing genesis-rooted `VerifiedSumeragiBlock` successful-output verifier.
`verify` additionally requires the independently retained exact signed carrier
hash; `verify_recovered` selects an original carrier by independently retained
complete intent and authenticates its signed hash through the same verifier.
An untrusted replay locator merely locates candidate evidence. It grants no
receipt authority. Both operations bind source buckets, recipients, quantities,
reference metadata and the actual authenticated Nexus fee receipt or explicit
absence, and need no block after the payment's own certified carrier. PipelineGas
carriers are unsupported until their fee outcomes have an authenticated receipt.
Decoded evidence must be verified again on resume; the opaque verified type
cannot be deserialized. Customer credit still needs the application's durable
uniqueness transaction keyed by the network and owner-qualified settlement ID.

`PaymentInbox` provides that boundary through the existing durable
`WorkflowStorage` compare-and-store owner. One record contains the immutable
customer-credit entry and its pending notification; recording it is the credit,
not permission to perform a second non-idempotent balance increment. The bank
independently selects the customer and exact destination bucket. A changed
mapping, fee-bound receipt digest or original transaction conflicts with the
existing entry. Concurrent or uncertain writes are recovered under the same key.
Notification acknowledgement changes only the pending flag, and delivery may
repeat using the same network/business key. Restart requires fresh verification
of the original evidence: decoding an inbox record grants no payment authority.
The SDK refuses process-local storage for this operation.

## Matched benchmark workload

For each supported real topology `N = 2, 3, 4, 8, 16`, both profiles use N
primary payments plus one sponsor reimbursement from the first participant's
source. This is N+1 economic movements; it is not N-1 bilateral star transfers.
The same deterministic workload identity fixes payer/recipient keys, asset
definitions, explicit scopes, amounts, warmup flag and session attempt index.
Each confidential leg keeps its existing fixed two-input/three-output relation.

The transparent profile submits one consented atomic instruction for that full
vector. The confidential profile applies the corresponding private payments
and reimbursement through its existing governance, proof and carrier owners.
Both profiles use the same public genesis. Confidential prefunding uses a
separate synthetic pool initialization; it is not evidence of a deposit from
the public balances. Initialization is outside the measured settlement window
and must be retained in the experiment record.

One native worker owns one warmed network for a registered profile/N/seed
session. Its warmups precede measured attempts on that same network. Separate
session and attempt records bind actual process generations, dispatches,
measurements, terminal outcomes and accepted samples. An accepted sample is
retained even if delivery of its acknowledgement fails later. A live network
is not declared quiescent after an individual attempt.

Network bytes require an admitted packet-capture owner and exact listener and
process boundaries. CPU/RSS require the native process observer, including the
proof/coordinator work. Resource snapshots, packet records and matched economic
receipts are independently replayed before an accepted sample is emitted.
Source admission, ten fresh N=3 smoke completions, complete registered-scope
accounting and the release evidence verifier remain mandatory. Unit tests or
synthetic accounting fixtures do not establish any performance result.

## Implementation and validation owners

- Model and bounded codecs:
  `crates/iroha_data_model/src/isi/settlement/atomic.rs` and `atomic_tests.rs`.
- Exact authorization and whole-batch execution:
  `crates/iroha_core/src/smartcontracts/isi/settlement/atomic.rs`,
  `crates/iroha_core/src/smartcontracts/isi/asset.rs`, and
  `crates/iroha_core/src/smartcontracts/isi/settlement/tests/atomic_tests.rs`.
- Admission, routing and fee equivalence:
  `crates/iroha_core/src/pipeline/overlay_atomic_settlement_tests.rs`,
  `crates/iroha_core/src/queue/router/settlement_atomic.rs`, and
  `crates/iroha_core/src/validation_fee_atomic_tests.rs`.
- Receipt output and JSON:
  `crates/iroha_core/src/smartcontracts/isi/query/settlement_receipts.rs` and
  `crates/iroha_js_codec/src/atomic_settlement_json_tests.rs`.
- Native workload and retained process owner:
  `integration_tests/tests/nexus/atomic_private_settlement_matched_workload.rs`
  and `atomic_private_settlement_session.rs`.

TODO: Complete compilation, focused native tests and the admitted network
campaign on one settled source candidate. Until then this specification records
the proposed contract, not a passed release gate or a measured performance claim.

## Linked full returns

The Rust `NativePaymentFullReturnRequest` consumes an opaque verified original
single Global payment and reverses its exact destination/source buckets and full
principal. A domain-separated hash of the original network, scoped settlement ID
and successful signed transaction derives one receiver-owned return ID. Independent
gateways therefore address the same return obligation; existing consensus
settlement uniqueness prevents a second full return through this operation.
The return signs typed metadata binding the original network, ID, successful hash
and complete intent hash. Its own expiry and exact fee authorization remain
independently supplied. `NativePaymentReturnOperation` reuses `NativePaymentOperation`
and its durable journal. Its `submit` explicitly authorizes the return attempt and
fees; `resume` can only continue an original signed carrier or independently
recover successful return settlement. It cannot sign a replacement rejected
carrier; fresh or unsigned journals without success require explicit submission.
`VerifiedPaymentReturn` retains both independently verified successful receipts. The original settlement is never reversed or marked rejected.
An ISO lifecycle report alone cannot construct the linked verified return.

This API is full-return only. Ordinary reverse payments with other IDs are not
verified linked returns. Partial-return APIs remain absent until consensus owns
an allowance that enforces cumulative returned principal at most the original.
