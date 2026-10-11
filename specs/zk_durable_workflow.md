# Durable multi-round workflows (contract v1)

Task S.2 of the [ZK delivery plan](zk_delivery_plan.md). This document is the
normative contract for workflows that need more than one transaction or an
off-chain round: issuer and pool bootstrap, distributed key generation and
threshold opening. Its machine-readable form and the scenario fixtures every
SDK family runs are in [`fixtures/zk/workflow_v1/`](../fixtures/zk/workflow_v1/README.md).

What exists today: this contract, the fixtures, and the Rust implementation in
`crates/iroha/src/workflow/` with its ledger adapter in
`crates/iroha/src/client/workflow_ledger.rs`. What does not exist: ports to the
other five SDK families (S.3 to S.5), any bootstrap, key-generation or threshold
cryptography (C.4, C.7, R.10 supply drivers), and runs against real validators
(the product deliveries and V.2). The Rust tests use a fake ledger and a fake
clock.

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
| Ledger | One dispatch; read-only committed outcome. | `WorkflowLedger`; `AccountWorkflowContext` over the submission owner and the global status read |
| Storage | One record per workflow, compare-and-swap, runner lease. Supplied by the caller. | `WorkflowStorage`; `FileWorkflowStorage` (durable), `MemoryWorkflowStorage` (not durable, tests only) |
| Clock | Polling and the caller's local observation bound only. | `WorkflowClock` |

The separately named calls are `AccountClient::bootstrap_workflow`,
`AccountClient::dkg_workflow` and `AccountClient::threshold_opening_workflow`.
Each returns a durable handle with `run`, `recover` (read-only), `cancel` and
`progress`. The same request, account and storage give the same handle after a
restart. A driver that does not implement a step kind returns
`UnsupportedOperation`.

The workflow kinds are `issuer_bootstrap`, `dkg` and `threshold_opening`. The
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
  dispatches per identity. The identity does not change, so the ledger's
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
A terminal failure makes the workflow `failed` with the driver's code.
Duplicate, reordered or missing participants, a changed epoch or consent set,
revocation and transcript substitution are covered at this level by the
fixtures. The cryptographic content of shares and transcripts belongs to the
drivers.

## 6. Cancellation

Cancellation is one compare-and-swap of the journal. It is serialized with
dispatch and round intents: whichever stores first wins, and a runner that
loses stores nothing further and starts no effect.

| Current step | Result |
|---|---|
| No dispatch can have been admitted, no round started | `cancelled`. A transaction step becomes `cancelled_before_submission` and its payload or signed bytes are dropped; a step whose identity is already closed stays `rejected`. |
| `submitting`, `outcome_unknown`, `pending`, `round_started`, `round_waiting` | `cancelling`. The step is not changed. |

A `cancelling` or `cancelled` workflow never builds, signs, dispatches or
starts a round. While `cancelling`, only read-only reconciliation runs; it may
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

## 8. Errors

The shared operation codes: `InvalidInput`, `NonCanonicalEncoding`,
`UnsupportedOperation`, `BindingMismatch`, `ResourceLimitExceeded`,
`ProofInvalid`, `AuthorizationDenied`, `Expired`, `ReplayRejected`,
`LocalResourceUnavailable`, `SubmissionOutcomeUnknown`, `FinalityPending`,
`Rejected`, `CancelledBeforeSubmission`. Workflow extensions:
`StorageCorrupted`, `JournalConflict`, `RoundPending`.

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
| Dispatches per identity | 8 |
| Transaction bytes (payload or signed) | 10,485,760 |
| Round transcript bytes | 1,048,576 |
| Round participants | 1,024 |
| Custody references per round | 64 |
| Custody reference bytes | 128 |
| Diagnostic bytes | 512 |
| Journal record bytes | 16,777,216 |

These are client-side bounds of the journal. They do not change what the
ledger accepts.

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
