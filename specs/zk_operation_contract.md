# One-call and prepared operation contract (v1)

Task S.1 of the [ZK delivery plan](zk_delivery_plan.md). This document is the
normative contract shared by the six SDK families (Rust, Kotlin/Java/Android,
Swift, JavaScript, Python, C#) for one ledger operation: the mandatory
high-level call, its advanced prepared form for external signing, batches and
contracts, the typed errors, durable recovery, custody, local verification,
finality and dispatch classification. Its machine-readable form and the shared
scenario fixtures are in [`fixtures/zk/operation_v1/`](../fixtures/zk/operation_v1/README.md).

> **Provisional, pending plan-author review.** The plan author designed this
> contract in the S.1/S.2 design memo, section 8. Where the memo is silent this
> version follows the coordinator's provisional decisions of 2026-10-19,
> [`dist/zk-delivery-handoff/claude/s1/provisional-decisions-2026-10-19.md`](../dist/zk-delivery-handoff/claude/s1/provisional-decisions-2026-10-19.md)
> (a local handoff record outside the tracked tree), until the plan author
> reviews them. Every decision here is reversible in the first release, and the
> review supersedes it. `contract.json` records the same state under `review`.

What exists today: this contract; `contract.json`, rendered from
`crates/iroha/src/client/operation_contract.rs`; the scenario fixtures; and
`scripts/check_operation_contract.py`. What does not exist: the transport-free
operation core with the canonical artifact types and their byte vectors (packet
S1-A2), the Rust `execute_operation` and advanced calls that run the scenarios
(S1-A3), the native exposure (S1-B1, S1-B2) and the ports to the other five
families (S1-C1 to S1-C5). No SDK executes the scenarios yet.

## 1. Calls and stages

Every family exposes the mandatory high-level call `execute_operation(request)`.
It runs the advanced calls in this order, durably:

`prepare` → `prove` → `local_verify` → `build` → `sign` → `submit` → `await_finality`

`execute_operation` requires a durable store and returns a durable handle with
`run` (resume from the stored state), `recover` (read-only), `cancel` and
`progress`. The same request, account and store give the same handle after a
restart. A volatile store is an explicit test or advanced option; on a timeout
it still returns `SubmissionOutcomeUnknown` with the transaction identity, never
a guessed outcome.

Each advanced call is also an API of its own, so a caller can sign externally,
compose a batch or embed the canonical instructions in a contract. Errors name
the stage that produced them, from the stage vocabulary shared with durable
workflows ([`zk_durable_workflow.md`](zk_durable_workflow.md) section 8): `plan`,
`load`, `store`, `prove`, `local_verify`, `build`, `sign`, `submit`,
`reconcile`, `finality`, `round`, `cancel`.

| Call | Stages its errors report | Reducer events it applies | What becomes durable |
|---|---|---|---|
| `prepare` | `plan` | `open_attempt` | The operation and an open identity slot (`prepared`). |
| `prove` | `prove` | `build_started`, `build_failed` | The state `proving`; the proofs are held in memory only. |
| `local_verify` | `local_verify` | `build_failed` | Nothing new; a failure returns the state to `prepared`. |
| `build` | `build` | `payload_built`, `build_failed` | The exact unsigned payload (`ready_to_sign`). |
| `sign` | `sign` | `signed` | The signed bytes and their identity (`signed`). |
| `submit` | `submit` | `dispatch_intent` and one dispatch event | The dispatch ordinal, before any byte is sent. |
| `await_finality` | `reconcile`, `finality` | `dispatch_interrupted`, `observed_in_pipeline`, `reconciled_applied`, `reconciled_rejected`, `reconciled_expired` | The outcome evidence. |

Every call of a durable operation may also report the journal stages `load` and
`store`; `cancel` reports `cancel`; `recover` reports `reconcile` and `finality`.
`round` belongs to workflows only. `reconcile` is a read of the committed
outcome of the persisted identity; `finality` authenticates the outcome that
reconciliation selected (section 8).

A process that stops between `prove` and `build` loses the proofs: the
operation is still `proving` and the next call proves again. The proofs are
public, but only the exact unsigned payload persisted by `build` is reused.

## 2. Durable states

An operation runs the shared transaction reducer of durable workflows
(`TransactionOperationV1`; `transaction_transitions` in
`fixtures/zk/workflow_v1/state_machine.json`). Any pair that table does not
list is invalid. After `prepare` the operation is in one of these durable
states:

| State | Durable content |
|---|---|
| `prepared` | An open identity slot. Nothing computed. |
| `proving` | The same; proofs and local verification are under way. |
| `ready_to_sign` | The exact unsigned payload. |
| `signed` | The signed bytes and their identity. No dispatch can have been admitted. |
| `submitting` | The dispatch ordinal, stored before the bytes are sent. |
| `outcome_unknown` | A dispatch may have been admitted; nothing authoritative is known. |
| `pending` | The network acknowledged or showed the transaction; the outcome is not established. |
| `finalized` | Terminal: the outcome evidence of the applied transaction. |
| `rejected` | Terminal: the evidence that closed the identity. |
| `cancelled_before_submission` | Terminal: cancelled while no dispatch could have been admitted; no bytes are kept. |

The reducer's initial state `planned` exists only before `prepare` opens the
identity slot. The operation's journal is the durable workflow journal with a
one-step plan; its status is `in_progress`, `completed`, `cancelling`,
`cancelled` or `failed` as in [`zk_durable_workflow.md`](zk_durable_workflow.md)
section 2. TODO(S1-A2/S1-A3): add the generic workflow kind `operation` that
binds such a journal, with the transport-free core.

## 3. Errors

Every family returns one typed error. Its shared codes are the memo's fourteen
plus `EvidenceUnavailable`, with the same identifiers as `state_machine.json`:

| Code | Meaning for an operation |
|---|---|
| `InvalidInput` | The request, a driver result or an external artifact is malformed. |
| `NonCanonicalEncoding` | Bytes are not the canonical encoding of their value. |
| `UnsupportedOperation` | The capability, the node or the requested mode is not supported, including a driver that would upload private material. |
| `BindingMismatch` | A value is bound to another network, authority, intent, payload or identity, including an external signature that does not verify. |
| `ResourceLimitExceeded` | A declared bound was exceeded. |
| `ProofInvalid` | A generated proof failed local verification; nothing was built, signed or dispatched. |
| `AuthorizationDenied` | The authority lacks a permission, or the signer refused or lacks the capability. |
| `Expired` | The transaction expired by authoritative ledger state. |
| `ReplayRejected` | The ledger rejected the transaction as a replay. |
| `LocalResourceUnavailable` | A local resource or node backpressure prevented progress; nothing was admitted. |
| `EvidenceUnavailable` | A required evidence read did not complete with a classified result; the identity is kept. |
| `SubmissionOutcomeUnknown` | A dispatch may have been admitted and nothing authoritative is known. |
| `FinalityPending` | The transaction is known to the network and its outcome is not yet established. |
| `Rejected` | The identity was refused on its only possible admission or rejected by the ledger. |
| `CancelledBeforeSubmission` | The operation was cancelled before any dispatch could have been admitted. |

A durable operation also reports the journal extensions `StorageCorrupted` and
`JournalConflict`; it never runs rounds, so `RoundPending` does not apply.

| Field | Present | Content |
|---|---|---|
| `code` | always | The code. |
| `stage` | always | The stage that produced the error. |
| `action_index` | when one action is identifiable | Zero-based index of the composed action. |
| `bound` | always for `ResourceLimitExceeded` | The exceeded bound: an id of section 5, or the documented id of another declared bound. |
| `actual` | always for `ResourceLimitExceeded` | The value that exceeded it. |
| `maximum` | always for `ResourceLimitExceeded` | The largest permitted value. |
| `transaction` | always for `SubmissionOutcomeUnknown` and `FinalityPending`; otherwise when an identity exists | Signed-transaction hash and entrypoint hash. |
| `detail` | always | Diagnostic without secret material. |
| `progress` | unless no trustworthy journal could be read | Status and state of the last journal record the call validated. |

The typed size refusal of `transaction.structured_size_refusal` in
`specs/zk_resource_contract.json` maps to `ResourceLimitExceeded` with `bound`
`transaction.max_tx_bytes`, `actual` = `encoded_bytes` and `maximum` =
`max_bytes`. An error that reports a terminal outcome names the stage whose
evidence closed the identity: `finality` for an authenticated outcome,
`reconcile` for a Torii state-resolved status and `submit` for a validated
refusal of the only dispatch.

## 4. Artifacts

The provisional artifact names avoid the Torii onboarding and faucet
"prepared-operation V1" contract (`fixtures/prepared_transactions/README.md`).
Both artifacts are public: they hold no private material. Their canonical
Norito types and byte vectors belong to the transport-free core (S1-A2); this
version fixes their fields and meaning only.

`PreparedZkOperationV1`, returned by `prepare`, is the proof-free, unsigned form
of one operation or of one batch composed into one transaction:

| Field | Type | Content |
|---|---|---|
| `payload` | `TransactionPayload` | Every proof-free field fixed: domain, authority, creation time, lifetime, a nonce from the secure random source, fee payment, metadata, the canonical instructions of every composed action in order and the ordered intent descriptor with its declared attachment slots. Generated proof bytes, their lengths and hashes and the statement digests are absent. |
| `intent_digest` | `OrderedIntentDigestV1` | `TransactionPayload::ordered_intent_digest_v1` of `payload`. |
| `statements` | `Vec<ActionStatementDigestV1>` | The public statement digest of each declared action; the proof of action i binds entry i. |
| `attachment_slots` | `Vec<AttachmentSlotV1>` | Every declared occurrence in index order. |
| `resource_quote` | `Vec<ResourceQuoteEntryV1>` | One entry per bound of section 5, in that order. |
| `parameters` | `ParameterSnapshotV1` | The committed parameters the quote used. |

`BuiltZkOperationV1`, returned by `build`, is the complete unsigned transaction
a signer signs:

| Field | Type | Content |
|---|---|---|
| `intent_digest` | `OrderedIntentDigestV1` | Unchanged from the prepared artifact. |
| `signing_bytes` | `Vec<u8>` | `TransactionBuilder::encode_payload`: the canonical complete payload, every occurrence and statement digest bound. |
| `signing_prehash` | `Hash` | `TransactionBuilder::payload_hash`: the prehash every transaction signature signs. |
| `entrypoint_hash` | `HashOf<TransactionEntrypoint>` | `TransactionBuilder::hash_as_entrypoint`: the identity before any signature. |
| `resource_usage` | `Vec<ResourceQuoteEntryV1>` | The exact value of every bound except the signed size, which `sign` measures. |

Nested records:

| Record | Field | Type | Content |
|---|---|---|---|
| `AttachmentSlotV1` | `index` | `u32` | Position of the occurrence in the transaction. |
| | `action_index` | `u32` | The declared action that references it. |
| | `kind` | `AttachmentKindV1` | A generated proof or admitted key material. |
| | `role` | `AttachmentRoleV1` | Its role for that action. |
| | `expected_length` | `u64` | Exact for key material; for a generated proof its canonical padded length when the format fixes one, else the largest length the capability can generate. |
| `ResourceQuoteEntryV1` | `bound` | string | An id of section 5. |
| | `value` | `u64` | In a quote exact for counts and an upper bound for bytes; in a measurement exact. |
| | `maximum` | `u64` | The constant, or the committed parameter of the snapshot. |
| `ParameterSnapshotV1` | `block_height` | `u64` | Height of the committed block the parameters were read at. |
| | `max_tx_bytes` | `u64` | Committed `Parameters.transaction.max_tx_bytes`. |
| | `max_decompressed_bytes` | `u64` | Committed `Parameters.transaction.max_decompressed_bytes`. |
| | `max_includable_transaction_bytes` | `u64` | `Parameters::max_includable_transaction_bytes` for the transaction's route. |

The prepared form of an action inside a contract is the canonical instruction
plus its `ActionIntentV1` declaration with `ActionInvocationBindingV1::Contract`.
Kotodama builtins belong to I.3/I.5; until the I.2/I.3 types exist this part of
the contract stays partial.

## 5. Batches and bounds

An ordinary batch of operations is **one signed atomic transaction**: all of its
actions apply or none do. `prepare` checks every bound below, in this order,
before any proof, journal or external effect exists, and refuses a request over
any of them with `ResourceLimitExceeded` at stage `plan`. No call splits a
batch, and there is no split helper. The values are read from the source, not
copied:

| Bound (`specs/zk_resource_contract.json` id) | Maximum | Owner | Checked at |
|---|---|---|---|
| `attachment.max_actions` | 16 | `SIGNED_ATTACHMENTS_MAX_ACTIONS_V1` | `plan` |
| `attachment.max_occurrences` | 16 | `SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1` | `plan` |
| `attachment.occurrence_max_bytes` | 9,437,184 | `SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1` | `plan`, `build` |
| `attachment.signed_frame_max_bytes` | 9,502,720 | `SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1` | `plan`, `build` |
| `transaction.max_decompressed_bytes` | committed; default 10,485,760 | `max_decompressed_bytes` | `plan`, `build` |
| `transaction.max_tx_bytes` | committed; default 10,485,760 | `max_tx_bytes` | `plan`, `sign` |

The four constants are in
`crates/iroha_data_model/src/transaction/signed_attachments.rs`; the two
committed defaults in `crates/iroha_data_model/src/parameter/system.rs`. The
committed bounds are checked against the parameter snapshot, not the defaults;
the signed size is checked with `Parameters::check_signed_transaction_bytes`
against the includable maximum of the transaction's route. At `prepare` the
counts are exact, the per-occurrence length is the declared expected length and
the byte bounds are quoted upper bounds; `build` and `sign` measure the exact
values. `action_index` names the first action that crosses a bound: for the
action count the first action beyond the maximum, for occurrences the action
that declares the first occurrence beyond it, for a length the action of the
first oversized slot. An aggregate byte bound that no single action crosses has
no `action_index`.

## 6. Custody and randomness

| Rule | Statement |
|---|---|
| `opaque_signer_handles` | The default signer is an opaque handle or a platform signer, so a private key never crosses the native boundary or enters managed memory. Raw-key entry points are explicit test or advanced APIs, named as such. |
| `secure_randomness` | Transaction nonces and proof randomness come from the platform's cryptographically secure random source. Caller-supplied randomness is an explicit test or advanced option, named as such. |
| `no_private_material_upload` | No call sends private material to Torii, a prover service or any other remote party, and no artifact, journal record, error or diagnostic contains it. A capability driver that needs to upload private material is refused with `UnsupportedOperation` before any network effect. |
| `public_artifacts_only` | The prepared and built artifacts, the journal and the signed transaction hold only public data and opaque custody references. |
| `zeroize_private_material` | Private material the SDK holds in memory is erased after use where the platform allows; a family whose managed types cannot be erased documents that limitation. |

Private material is `signing_key`, `witness`, `share`, `decryption_key` and
`randomness`.

## 7. Local verification

The one-call verifies every generated proof locally, after `prove` and before
`build` and `sign`. A local failure is `ProofInvalid` at stage `local_verify`:
the proof is discarded, nothing is built, signed or dispatched, and the
operation returns to `prepared`, so a later run proves again. Local acceptance
is diagnostic and never ledger authorization: the ledger verifies again. This
version defines no opt-out.

## 8. Finality

| Mode | Default | What closes an identity |
|---|---|---|
| `authenticated` | yes | A finality proof that `iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier`, rooted in the caller's independently selected genesis, verifies to bind the exact signed transaction and its applied or rejected execution output to a finalized block. A status read only selects the candidate outcome. |
| `torii_status` | no | The queried Torii's state-resolved global `Applied`, `Rejected` or `Expired` status. The caller trusts that Torii; the mode is explicit and named as weaker. |

In the `authenticated` mode a state-resolved `Applied` or `Rejected` status
moves `outcome_unknown` to `pending` and is followed by one finality read of the
candidate. Verified evidence applies `reconciled_applied` or
`reconciled_rejected`; unavailable evidence is `EvidenceUnavailable` and
evidence bound to another transaction or outcome is `BindingMismatch`, both at
stage `finality`, and neither changes the identity. No authenticated evidence of
expiry exists, so a Torii-reported `Expired` changes nothing in this mode.

Open: `specs/zk_resource_contract.json` records the relations
`authenticated_block_proofs_carry_an_executed_block` and
`finality_proofs_carry_an_executed_block` as violated, so an executed block
larger than the 32 MiB authenticated reader carriers cannot be authenticated
today. The remedy is not chosen before the plan author's review; until then such
an identity stays unresolved in the `authenticated` mode.

## 9. Submission and dispatch classification

The signed bytes and their identity are durable before the dispatch ordinal, and
the ordinal before any byte is sent. The client's single submission owner
(`AccountClient::dispatch_prepared_transaction_payload`) classifies each
dispatch from the HTTP status, the canonical error envelope and the
`x-iroha-reject-code` header, never from text:

| Class | Established by | Reducer event |
|---|---|---|
| `accepted` | HTTP 200 or 202. | `dispatch_accepted` |
| `already_known` | A validated row with this class. | `dispatch_already_known` |
| `refused` | A validated row with this class. | `dispatch_refused` |
| `deferred` | A validated row with this class (backpressure); `LocalResourceUnavailable`. | `dispatch_not_admitted` |
| `not_dispatched` | A local failure before any byte left the client, reported by its cause. | `dispatch_not_admitted` |
| `ambiguous` | Everything else, including every outcome-unknown claim. | `dispatch_ambiguous` |

The validated rows are `DEFINITE_DISPATCH_ROWS`
(`crates/iroha/src/client/transaction_dispatch_error.rs`), published as data in
`dispatch_classification.definite_rows` of `contract.json` together with the
outcome-unknown evidence, the acknowledged statuses and the response bound.
Every family adopts that table unchanged. The guards of the reducer decide the
effect: a refusal closes an identity only when no earlier dispatch of the same
bytes may have been admitted, and a non-admission keeps the identity
dispatchable.

**No clock closes an identity.** Only the closing evidence of the finality mode
does. Exact absence, a failed read, a response not bound to the identity, the
local observation bound, a local clock and Torii-reported time never close it,
and expiry is never inferred from any clock. A submission timeout is
`SubmissionOutcomeUnknown` with the identity until a read resolves it. No fresh
nonce is created automatically, and the exact persisted bytes are sent again
only under the explicit retransmission policy, after a fresh exact-absence read,
within the dispatch bound of the identity.

## 10. Rules

Each rule is exercised by at least one scenario fixture.

| Rule | Statement |
|---|---|
| `prepare_refuses_over_bound_batches` | Over-bound batches are refused at `prepare` with the bound, action index, actual value and maximum; no split. |
| `local_verification_before_signing` | Proofs are verified locally before `build` and `sign`; a failure is `ProofInvalid` with no dispatch. |
| `persist_before_dispatch` | Signed bytes and identity, then the dispatch ordinal, are durable before any byte is sent; a signed identity is never proved, built or signed again. |
| `reconcile_read_only_first` | An unresolved identity is first reconciled read-only; `recover` only reads. |
| `no_clock_closes_an_identity` | A timeout is `SubmissionOutcomeUnknown` with the identity; no clock, absence or failed read closes it. |
| `identical_bytes_only` | The only re-dispatch is the exact persisted bytes under the explicit policy after a fresh exact-absence read. |
| `cancellation_never_recalls` | Cancellation before possible admission drops the bytes; after it only stops observation. |
| `external_signature_verified_before_persisting` | An external signature is verified against the exact built bytes before it is persisted; a mismatch is `BindingMismatch` at `sign`. |
| `custody_stays_local` | Private material stays in custody; an upload is refused with `UnsupportedOperation` before any network effect. |
| `authenticated_finality_by_default` | Only authenticated evidence closes an identity by default; `torii_status` is explicit and weaker. |
| `dispatch_classified_by_closed_table` | Dispatches are classified by the closed table; non-admission keeps the identity dispatchable. |

`contract.json` holds the complete statements.

## 11. Fixtures and checks

- `contract.json` is rendered from `crates/iroha/src/client/operation_contract.rs`.
  The test `tracked_contract_equals_the_rust_tables` fails on any difference;
  `cargo test -p iroha --lib client::operation_contract -- --ignored` rewrites it.
- `scenarios/*.json` are single-operation scenarios written from this contract.
  Their format and the deterministic fake world are in the fixture README.
- `python3 scripts/check_operation_contract.py` checks the set without Rust:
  `contract.json` against `fixtures/zk/workflow_v1/state_machine.json`, the
  source owners of every bound and of `DEFINITE_DISPATCH_ROWS`, and
  `specs/zk_resource_contract.json`; every scenario's vocabulary, trace safety,
  script consumption and outcomes of its refusal tokens; coverage of every rule,
  call stage and durable state; and that this document names every identifier
  of the contract. `make guards` runs it.

## 12. Open

- TODO(S1-A2): the transport-free core crate with these types, the
  single-operation reducer moved from `crates/iroha/src/workflow`, the canonical
  artifact encodings and `vectors.json`.
- TODO(S1-A3): the Rust `execute_operation`, the advanced calls, external and
  multisignature signing, and a runner that executes these scenarios.
- The `torii_status` mode and the batch bounds of other families are defined
  here; their ports are S1-B and S1-C packets.
- The remedy for the two violated authenticated-carrier relations (section 8)
  and the structured size refusal (`queue.rs`) wait for the plan author's review.
- TODO(CI): the pull-request workflow does not run the checker and its tests
  yet; the step is added once the current claim on
  `.github/workflows/pr.yml` is released.
