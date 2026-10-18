# Durable multi-round workflows (contract v1)

Task S.2 of the [ZK delivery plan](zk_delivery_plan.md). This document is the
normative contract for durable transaction and off-chain processes: issuer and
pool bootstrap, distributed key generation, threshold opening, native payment and
prepared private settlement.
Its machine-readable form and the shared scenario fixtures are in [`fixtures/zk/workflow_v1/`](../fixtures/zk/workflow_v1/README.md).

What exists today: this contract, the fixtures, and the Rust implementation in
`crates/iroha/src/workflow/` with its ledger adapter in
`crates/iroha/src/client/workflow_ledger.rs`, plus the proof-gated native payment
operation in `crates/iroha/src/client/native_payment.rs` and prepared private
settlement in `crates/iroha/src/client/private_settlement/operation.rs`. What does not exist: ports to the
other five SDK families (S.3 to S.5), any bootstrap, key-generation or threshold
cryptography (C.4, C.7, R.10 supply drivers), and runs against real validators
(the product deliveries and V.2). The generic engine tests use a fake ledger and clock; native payment tests add
real certificates over synthetic execution outputs and independent receipt verification.

## 1. No atomicity across transactions

Each transaction step is one signed ledger transaction and is atomic by itself.
**A workflow is never atomic across steps.** A finalized transaction or an
irreversible round is not rolled back when a later step fails, when the caller
cancels, or when the process stops. No call claims otherwise: every result,
success or error, carries a progress report with `atomicity:
"per_transaction_only"` and these lists of step indexes:

| List | Meaning |
|---|---|
| `confirmed_steps` | Transaction finalized or round completed. |
| `irreversible_steps` | Confirmed steps that cannot be undone. Every transaction; a round when its plan says so. |
| `unresolved_steps` | A transaction that may still commit, or a round that may have had external effect. |
| `failed_steps` | Transaction identity closed by a refusal, or round failed. |
| `not_started_steps` | No possible external effect. |
| `rolled_back_steps` | Always empty. |

## 2. Parts

| Part | Owner | Rust |
|---|---|---|
| Engine | Ordering, durability, recovery. No capability logic. | `WorkflowEngine`, `WorkflowHandle` |
| Driver | The capability: builds payloads, runs and recovers rounds. | `WorkflowDriver` |
| Account context | Network, authority, signing. | `WorkflowAccount`; `AccountWorkflowContext` over `AccountClient::sign_transaction` |
| Ledger | One dispatch; read-only committed outcome. | `WorkflowLedger`; `AccountWorkflowContext` over submission/global status; native payment requires certified exact input/output authentication |
| Storage | One record per workflow, compare-and-swap, runner lease. Supplied by the caller. | `WorkflowStorage`; `FileWorkflowStorage` (durable), `MemoryWorkflowStorage` (not durable, tests only) |
| Clock | Polling and the caller's local observation bound only. | `WorkflowClock` |

The separately named calls are `AccountClient::bootstrap_workflow`,
`AccountClient::dkg_workflow` and `AccountClient::threshold_opening_workflow`.
Each returns a durable handle with `run`, `recover` (read-only), `cancel` and
`progress`. The same request, account and storage give the same handle after a
restart. A driver that does not implement a step kind returns
`UnsupportedOperation`.

The workflow kinds are `issuer_bootstrap`, `dkg`, `threshold_opening`,
`native_payment`, `amx_relay` and `private_settlement`. The
kind is bound into the workflow identifier, so one request under two kinds is
two workflows. Other multi-round processes (cross-lane, elections) add a kind
when their delivery lands.

A workflow is `in_progress`, `completed`, `cancelling`, `cancelled` or
`failed`. `completed`, `cancelled` and `failed` are terminal: no later call
changes them. An `in_progress` workflow whose call returned an error is
resumable by running it again.

## 3. Plan and identity

A plan is `kind`, an `instance` label, the driver identity (`id`,
`schema_version`), the digest of the driver's immutable request context, and
the ordered steps. A step has a label, a kind (`transaction` or
`offchain_round`), an intent digest (the proof-free intent of a transaction, the
input context of a round), and per kind: the number of transaction identities
it may open (1 to 8, default 1), or for a round whether it is irreversible, how
many participants a completion needs and how many custody references it
returns.

All digests are the Iroha hash (Blake2b-256 with the marker bit set) of a
domain separator followed by the body.

| Digest | Domain (ASCII, NUL-terminated) | Body |
|---|---|---|
| Plan | `iroha:durable-workflow:plan:v1` | Canonical Norito `WorkflowPlanV1` |
| Workflow identifier | `iroha:durable-workflow:id:v1` | Canonical Norito `WorkflowIdentityV1`: kind, network, authority, instance, driver, request context digest, plan digest |
| Round identity | `iroha:durable-workflow:round:v1` | Workflow identifier, step index as `u32` little-endian |
| Transcript | `iroha:durable-workflow:transcript:v1` | Round identity, transcript bytes |
| Journal | `iroha:durable-workflow:journal:v1` | Canonical Norito `WorkflowJournalV1`, which includes version and sequence |
| Stored record | `iroha:durable-workflow:record:v1` | The stored record bytes; the compare-and-swap token |

A journal stored under an identifier it does not hash to, or for another
network or authority, is `BindingMismatch`. A driver other than the one the
plan names is `BindingMismatch`.

## 4. Transaction steps

States: `planned`, `prepared`, `proving`, `ready_to_sign`, `signed`,
`submitting`, `outcome_unknown`, `pending`, `finalized`, `rejected`,
`cancelled_before_submission`. The reducer over these states does not depend
on workflows; the one-call operation of S.1 uses the same table
(`TransactionOperationV1::apply`). The complete transition table is
`transaction_transitions` in `state_machine.json`. Any pair it does not list is
invalid.

What each state holds:

| State | Durable content |
|---|---|
| `prepared`, `proving` | An open identity slot. Nothing computed. |
| `ready_to_sign` | The exact unsigned payload. |
| `signed` | Signed bytes and their identity. No dispatch may have been admitted. |
| `submitting` | The dispatch ordinal, stored **before** the bytes are sent. |
| `outcome_unknown` | A dispatch may have been admitted; nothing authoritative is known. |
| `pending` | The network acknowledged or showed the transaction; not final. |
| `finalized`, `rejected` | Terminal evidence. The signed bytes are dropped. |

### 4.1 Dispatch classification

The submission owner classifies one dispatch. It never reads error text.

| Class | Established by | Effect |
|---|---|---|
| Accepted | HTTP 200 or 202. | `pending` |
| Already known | Validated `already_committed` or `already_enqueued`. | `pending` |
| Refused | A validated definite refusal from the closed table. | `rejected` if no earlier dispatch of these bytes may have been admitted; otherwise `outcome_unknown` |
| Not admitted | Validated backpressure, or a failure before any byte left the client (reported by its cause). | `signed` under the same condition; otherwise `outcome_unknown` |
| Ambiguous | Everything else: transport failure, timeout, 5xx, an oversized or undecodable body, an unlisted code, an outcome-unknown claim. | `outcome_unknown` |

"Validated" means: exactly one canonical error envelope, exactly one
`x-iroha-reject-code` header, and status, envelope code and reject code equal
to one row of `DEFINITE_DISPATCH_ROWS`
(`crates/iroha/src/client/transaction_dispatch_error.rs`). The table mirrors
Torii's queue rejections; a test fails when Torii adds one that is not
classified. Node-side failures (`queue_governance_invalid`,
`queue_nexus_fee_config_invalid`, `queue_admission_invariant`) stay ambiguous.

### 4.2 The resume rule

A step found in `submitting`, `outcome_unknown` or `pending` is first
reconciled by a read-only query on its persisted signed-transaction hash.
`submitting` without a recorded result becomes `outcome_unknown` first: the
bytes may have left.

| Read result | Effect |
|---|---|
| State-resolved global `Applied` | `finalized`; continue with the next step |
| State-resolved global `Rejected` or `Expired` | `rejected`; the identity is closed |
| Queued, approved, committed, or a terminal kind not resolved from state | `outcome_unknown` becomes `pending`; `pending` stays |
| Exact absence for this hash and the global scope | No change |
| Failed read, or a response not bound to this hash and scope | No change |

Only the first two rows close an identity. Exact absence, read failures and
the local observation bound never do, and **expiry is never inferred from a
local clock**. A submission timeout is therefore an unknown outcome until a
read resolves it, and a transaction the network never saw stays
`outcome_unknown`. The call returns `SubmissionOutcomeUnknown` or
`FinalityPending` with the transaction identity, and the workflow stays
resumable. Terminal evidence is stored before the next step starts.

### 4.3 Sending again

- **The same bytes.** Off by default. A call may authorize it
  (`retransmit_identical_bytes`). Then, after a fresh exact-absence read, the
  exact persisted bytes are dispatched once in that call, within the bound of 8
  counted dispatches per identity. A proven non-admission releases its count
  only when no earlier dispatch may have admitted the bytes. Such an identity
  stays dispatchable after any number of backpressure or preflight failures;
  uncertain submissions and their retransmissions keep consuming the bound.
  The identity does not change, so the ledger's
  duplicate protection applies.
- **A new transaction.** Only after the previous identity is closed
  (state-resolved rejection or expiry, or a validated refusal of its only
  possible admission), only when the call says so (`retry_rejected_step`), and
  only while the step has identities left. The driver refreshes context and
  keeps the bound intent. A replacement that repeats an earlier identity is
  `BindingMismatch`. Every identity stays in the journal. When no identity is
  left the workflow is `failed`.

A step is never submitted under a new identity while the previous one may
still commit.

## 5. Off-chain rounds

States: `planned`, `round_started`, `round_waiting`, `round_completed`,
`round_failed`. The round identity is stored (`round_started`) before the
driver starts the round. A round found started or waiting is **recovered**
under that identity (`WorkflowDriver::recover_round`): the driver returns the
original transcript and custody references if the round completed outside the
process, reports the participants it has, reports a terminal failure, or
proves that nothing started. A restart never creates a fresh round.
Before restarting a never-started round, the engine persists a new
`round_restart_intent`, saturating-incrementing `start_ordinal` under compare-and-swap.
If cancellation won during recovery, the stale runner reloads and performs
only read-only recovery; it does not restart the round. Neither first-start
nor restart intent is valid while cancelling.

The engine checks every report:

| Check | Failure |
|---|---|
| Report names the persisted round identity and the bound context digest | `BindingMismatch` |
| Participants strictly ascending | `NonCanonicalEncoding` |
| No participant recorded earlier is missing (a withdrawal is a round failure) | `BindingMismatch` |
| A completion has the required participants and a transcript | `InvalidInput` |
| A completion returns the declared number of custody references | fewer: `LocalResourceUnavailable`; more: `InvalidInput` |
| Bounds on participants, transcript and references | `ResourceLimitExceeded` |

A waiting round stores its participants and the call returns `RoundPending`.
A driver may explicitly opt in with `supports_round_continuation`. During `Run`,
a freshly recovered, correctly bound waiting round is checkpointed under the
same identity and lease before `continue_round` performs authorized effects.
A concurrent cancellation/CAS reload prevents continuation. `Recover` and
`Cancelling` never call it. Drivers default to no continuation, so their waiting
behavior is unchanged. Every continuation report passes the same binding,
participant and transcript checks as the original report.
A terminal failure makes the workflow `failed` with the driver's code.
Duplicate, reordered or missing participants, a changed epoch or consent set,
revocation and transcript substitution are covered at this level by the
fixtures. The cryptographic content of shares and transcripts belongs to the
drivers.

## 6. Cancellation

Cancellation is one compare-and-swap of the journal. It is serialized with
dispatch and round intents: whichever stores first wins. A runner that loses
starts no effect from its stale state; it reloads the winner and reconciles.

| Current step | Result |
|---|---|
| No dispatch can have been admitted, no round started | `cancelled`. A transaction step becomes `cancelled_before_submission` and its payload or signed bytes are dropped; a step whose identity is already closed stays `rejected`. |
| `submitting`, `outcome_unknown`, `pending`, `round_started`, `round_waiting` | `cancelling`. The step is not changed. |

A cancellation stored before a dispatch or round intent prevents that effect.
An intent stored first may take effect after cancellation and must be reconciled.
A build or signature already in flight is discarded if cancellation wins
before its result is stored. After observing `cancelling` or `cancelled`, the
runner starts no build, signature, dispatch or round. While `cancelling`,
only read-only reconciliation runs; it may
stay unresolved indefinitely. When the step resolves the workflow becomes
`cancelled`, with that step's actual outcome reported. If the step was the last
and it committed, the workflow is `completed`. `CancelledBeforeSubmission`
names the step that was not submitted; earlier steps are reported as confirmed.

## 7. The journal

One canonical Norito record per workflow: `WorkflowJournalRecordV1`, the
journal and its digest. The journal holds the identity, status, every step
descriptor and state, every transaction identity a step opened with its
dispatch counters and evidence, the unsigned payload (only in
`ready_to_sign`), the signed bytes (only while they may be dispatched), round
participants, public transcripts and custody references. Timestamps are local
and informational.

**No secret is persisted.** No interface of the module accepts one. A custody
reference identifies a key or share in the caller's keystore; it is not the
key. Signed transaction bytes are public by design but usable by whoever holds
them, so the file store keeps them in an owner-private directory.

Storage rules:

- `compare_and_store` replaces a record only if the stored one has the expected
  record digest, atomically against other processes. The file store takes an
  interprocess lock around read, compare and atomic publish.
- A runner holds an exclusive lease for the whole call. A second runner gets
  `JournalConflict` before it reads or sends anything.
- A storage failure ends the call before any further effect. A write that
  failed after it may have been published is resolved by the next call from
  whatever record is stored.
- On load: bounded length, canonical decoding, recomputed journal digest, plan
  digest, workflow identifier and round identities, all invariants, and the
  identity of retained signed bytes recomputed from the bytes. Any failure is
  `StorageCorrupted` with no progress snapshot. Nothing is repaired.
- The digest detects damage. It does not detect a rollback to an older valid
  record.

### Canonical field layout

The following fields are encoded in the listed order using the canonical
Norito framing in [`norito.md`](../norito.md). `Digest32` is `[u8; 32]`,
`Bytes` is `Vec<u8>`, and `String` is UTF-8. Enums use their zero-based order
in the corresponding vocabulary of `state_machine.json`. An optional field
uses Norito's `Option<T>`; an empty vector and an absent option differ.

| Type | Ordered fields and types |
|---|---|
| `DriverIdentityV1` | `id: String`, `schema_version: u32` |
| `StepDescriptorV1` | `label: String`, `kind: StepKindV1`, `intent_digest: Digest32`, `irreversible: bool`, `max_transaction_identities: u8`, `participants_required: u32`, `custody_handles_required: u32`, `max_transcript_bytes: u32` |
| `WorkflowPlanV1` | `kind: WorkflowKindV1`, `instance: String`, `driver: DriverIdentityV1`, `request_context_digest: Digest32`, `steps: Vec<StepDescriptorV1>` |
| `WorkflowIdentityV1` | `kind: WorkflowKindV1`, `network: String`, `authority: String`, `instance: String`, `driver: DriverIdentityV1`, `request_context_digest: Digest32`, `plan_digest: Digest32` |
| `TransactionIdentityV1` | `signed_transaction_hash: Digest32`, `entrypoint_hash: Digest32` |
| `AttemptEvidenceV1` | `kind: AttemptEvidenceKindV1`, `block_height: Option<u64>`, `detail: String` |
| `TransactionAttemptV1` | `ordinal: u8`, `identity: Option<TransactionIdentityV1>`, `dispatch_ordinal: u8`, `possible_admissions: u8`, `evidence: Option<AttemptEvidenceV1>` |
| `TransactionOperationV1` | `state: TransactionStateV1`, `attempts: Vec<TransactionAttemptV1>`, `unsigned_payload: Option<Bytes>`, `signed_transaction: Option<Bytes>` |
| `CustodyHandleV1` | `label: String`, `reference: Bytes` |
| `RoundRecordV1` | `state: RoundStateV1`, `round_id: Option<Digest32>`, `start_ordinal: u32`, `participants: Vec<Digest32>`, `transcript: Option<Bytes>`, `transcript_digest: Option<Digest32>`, `custody_handles: Vec<CustodyHandleV1>`, `failure: Option<WorkflowErrorCode>` |
| `StepRecordV1` | `descriptor: StepDescriptorV1`, `transaction: Option<TransactionOperationV1>`, `round: Option<RoundRecordV1>` |
| `NativePaymentCompletionV1` | `network: Digest32`, `request_digest: Digest32`, `transaction_hash: Digest32`, `block_height: u64`, `block_hash: Digest32`, `context_id: Digest32`, `receipt_digest: Digest32` |
| `WorkflowJournalV1` | `version: u16`, `sequence: u64`, `workflow_id: Digest32`, `identity: WorkflowIdentityV1`, `status: WorkflowStatusV1`, `cancel_requested: bool`, `failure_code: Option<WorkflowErrorCode>`, `failure_step: Option<u32>`, `created_at_ms: u64`, `updated_at_ms: u64`, `steps: Vec<StepRecordV1>`, `native_payment_completion: Option<NativePaymentCompletionV1>` |
| `WorkflowJournalRecordV1` | `journal: WorkflowJournalV1`, `digest: Digest32` |

`vectors.json` supplies the complete semantic plan, identity and journals,
with byte arrays represented as lowercase hexadecimal strings. Its
`plan_hex`, `identity_hex` and per-record `journal_hex` contain the canonical
Norito frames, including headers, used in the respective digest inputs.
Prepend `iroha:durable-workflow:plan:v1\0`,
`iroha:durable-workflow:id:v1\0` or
`iroha:durable-workflow:journal:v1\0`, respectively, then apply the Iroha hash
(Blake2b-256 with the least significant bit of the last byte set). Here `\0`
denotes one zero byte. The stored record embeds the journal digest; its
compare-and-swap digest instead hashes `iroha:durable-workflow:record:v1\0`
followed by the full `record_hex` frame. The Python guard recomputes these
digests independently of the Rust generator.

## 8. Errors

The shared operation codes: `InvalidInput`, `NonCanonicalEncoding`,
`UnsupportedOperation`, `BindingMismatch`, `ResourceLimitExceeded`,
`ProofInvalid`, `AuthorizationDenied`, `Expired`, `ReplayRejected`,
`LocalResourceUnavailable`, `EvidenceUnavailable`, `SubmissionOutcomeUnknown`, `FinalityPending`,
`Rejected`, `CancelledBeforeSubmission`. Workflow extensions:
`StorageCorrupted`, `JournalConflict`, `RoundPending`.

`EvidenceUnavailable` means a required evidence read did not complete with a
classified proof or resource result. It does not establish proof absence, ledger
rejection or successful settlement. At the AMX signing and dispatch gates, typed
permission or signing failures use `AuthorizationDenied`; locally rejected proofs
use `ProofInvalid`; generic listener/read failures retain `EvidenceUnavailable`
unless an exact existing code describes the cause. An unsigned changed-cut
observation also provides no proof and retains `EvidenceUnavailable`.

These operational failures stop that attempt while preserving the current unsigned
reservation or exact signed bytes. They cannot create a replacement identity or
close an unresolved obligation. The supervisor may revisit the original obligation,
but must expose the cause for operator diagnosis; it cannot relabel an unclassified
remote failure as finite local capacity. Authorization denial here is operational
evidence failure, never authoritative ledger rejection.

An error carries code, stage, step index, the transaction identity when one
exists, actual and maximum for a bound, a diagnostic, and the progress of the
last journal the call validated with its sequence. Progress is absent only
when no trustworthy journal could be read.

## 9. Limits

| Limit | Value |
|---|---|
| Steps per plan | 64 |
| Label bytes | 64 |
| Binding string bytes | 256 |
| Transaction identities per step | 8 |
| Counted dispatches per identity (section 4.3) | 8 |
| Transaction bytes (payload or signed) | 10,485,760 |
| Round transcript bytes | 1,048,576 |
| Round participants | 1,024 |
| Custody references per round | 64 |
| Custody reference bytes | 128 |
| Diagnostic bytes | 512 |
| Journal record bytes | 16,777,216 |

These are client-side bounds of the journal. They do not change what the
ledger accepts.
Before creating a journal, the client computes the worst-case record over
every reachable step prefix. A plan exceeding the record bound is refused
before any effect. Each round declares `max_transcript_bytes` (at most
1,048,576); smaller bounds allow longer round sequences without assuming
completed transcripts can be discarded.

## 10. Fixtures and checks

- `state_machine.json`: rendered from `workflow/contract.rs`. The test
  `tracked_state_machine_equals_the_tables_the_engine_executes` fails on any
  difference.
- `vectors.json`: canonical records, digests and progress reports. The test
  `canonical_byte_vectors_match_the_tracked_fixture` fails on any difference.
- `scenarios/*.json`: interruption before submission, after an ambiguous
  submission and after irreversible progress; dispatch classification;
  reconciliation; retransmission; replacement identities; cancellation in each
  state and concurrently; duplicate resume; storage corruption; uncertain
  writes; rounds; bounds and bindings. The test
  `every_shared_scenario_passes_against_the_fake_world` runs all of them and
  requires every rule of the state machine to be exercised.
- `python3 scripts/check_durable_workflow_contract.py` checks the fixture set
  without Rust: structure, vocabulary, cross-references, rule and state
  coverage, and the record digests of `vectors.json`.
  `make guards` and the pull-request workflow run this checker; the workflow
  also runs its mutation tests. Effect-triggered concurrency fixtures exercise
  cancellation during a recovery call, before its result reaches the engine.

## 11. Open

- A transaction the network never observed stays `outcome_unknown` after its
  signed lifetime. Closing it needs an authoritative "lifetime elapsed and
  absent" answer from the ledger, which does not exist. Until then the caller's
  only action is the authorized retransmission of the same bytes.
- Workflow steps of a multisignature authority need the external-signing form
  of the prepared operation (S.1).
- The journal types live in the Rust client crate. A port that needs them
  behind the native bridge may move the transport-free part
  (`contract`, `journal`) to a lower crate.

## Native payment binding

The Rust `AccountClient::native_payment` operation uses the same journal, runner
lease, signed-byte identity, account signer and classified dispatch owners. Its
single direct `SettleAtomic` carrier requires one Global balance movement with
the account as the payment namespace and debit owner. The independent request
binds complete terms and exact `FeePaymentIntent`; `PipelineGas` is unsupported
until an authenticated exact gas outcome exists.

`submit` explicitly authorizes a paid attempt with that exact fee intent. A fresh
journal may create a carrier, and replacing a known rejected local carrier also
requires explicit `retry_rejected_step`. A previous included rejection may
already have paid a fee; business uniqueness indexes successful settlement.
`resume` first independently recovers prior business success, including from a
fresh gateway. Otherwise it requires the original retained carrier identity and
returns `NewAttemptAuthorizationRequired` for an absent or unsigned journal. Its
same-journal account adapter contains no signer, its driver cannot build a new
payload, and rejected replacement is disabled regardless of the options supplied.
A retained never-dispatched signed carrier may be submitted unchanged; an unknown
carrier must be reconciled before the existing exact-byte retransmission rules
apply. A known rejected identity remains rejected. `recover` remains read-only.
The full-return wrapper uses the same explicit submission/resume boundary.

Journal integrity does not grant signing or dispatch authority. Before either
effect, the native-payment adapter decodes the exact canonical carrier and checks
its network, debit authority, sole complete instruction and fee intent against
the independently retained request. Carrier metadata must be empty and signed
attachments absent, matching the builder. The signer result and dispatch identity
must also match those exact signed bytes. A canonical journal replacement with
recomputed local digests cannot authorize another payment or fee.

Pipeline status selects a candidate block only. `VerifiedSumeragiBlock` must
authenticate the exact signed input and execution output before the carrier can
be marked applied or rejected. Status-only expiry cannot close it. An
authenticated replay rejection may select the original block, but only
`VerifiedPaymentReceipt::verify_recovered` plus exact fee-authorization equality
completes the business intent. The rejected retry carrier remains rejected.

The optional completion record contains six fixed 32-byte fields and one u64
(200 payload bytes), within the existing 2,048-byte fixed journal reserve and
16 MiB record limit. It stores neither full proof nor block. The journal owner
publishes this immutable locator by its existing lease/CAS after verification,
and its presence disables any later dispatch. On every resume the operation
re-fetches the original proof and independently verifies it again against the
caller's selected genesis-rooted verifier, then compares every completion field.
Decoded completion never constructs a verified receipt.

One call defaults to at most 64 full proof reads, one existing bounded transport
response at a time. The caller can choose another nonzero u16 local read budget.
A budget refusal, transport failure or original typed decoder resource refusal
keeps the carrier identity recoverable. Authenticated prefix progress remains in
the caller's operation; after process restart callers supply independently
retained genesis/checkpoint trust and online re-fetching rebuilds the prefix.
TODO: integrate durable authenticated prefix custody with an existing bounded
content-addressed owner before offering offline proof resume. No raw evidence
is embedded in the journal and no current transport or storage ceiling grows.

`NativePaymentOperation::recover` never builds, signs or dispatches. The final
successful block carries its own native certificate, so neither verification nor
recovery requires subsequent unrelated traffic. The `payment_` SDK tests exercise
real QCs with synthetic execution outputs; Core-to-SDK execution coverage remains
owned by `integration_tests/tests/native_payment_receipt.rs`.

## Prepared private settlement

`AccountClient::private_settlement` binds the sponsor, network, complete prepared
artifact digests, governed carrier limit and original authority rosters. Its five
steps are availability certification, promotion/Prepare, Register, Commit and
Finalize. Exact availability certificate bytes become durable before promotion:
reselecting a signer subset would change the final manifest. Prepare and Commit
reuse the existing certificate validators and quorum-equivalence rules. Each
public transaction retains its own exact signing/submission identity and fee.
Before Commit or Finalize, Register success is independently authenticated.

The three public certificate transcripts each have a 1 MiB ceiling within the
existing 16 MiB journal cap; restricted proofs, encrypted capsules and plaintext
witnesses are never serialized into that journal. The caller supplies the same
prepared artifacts on resume. This API performs structural request validation,
not proof generation or local proof verification. Committee helpers keep their
existing bounded fanout and deadlines; a bounded worker retains its permit and
original artifact owner if an awaiting call is dropped.

Only successful exact Finalize execution in a Global block verified from
independently selected genesis constructs `VerifiedPrivateSettlementReceipt`.
Status and public receipt queries supply locators only. Resume refetches and
reverifies the original final-tip block without requiring unrelated traffic.
`recover` cannot certify, promote, sign or submit. Promotion preserves the exact
certificate while requiring `q = n - f` bound upload acknowledgements from the
authorized endpoints; only the independently verified Prepare QC grants protocol
authority. A replica missing its original provisional upload still requires exact
material rehydration, whose recovery control remains open.
New SDK fixtures exercise genuine signatures/certificates over synthetic outputs;
full genuine-prover validator-network qualification remains open.
