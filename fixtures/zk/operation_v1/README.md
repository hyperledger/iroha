# Operation contract fixtures (v1)

Shared fixtures of the one-call and prepared operation contract,
[`specs/zk_operation_contract.md`](../../../specs/zk_operation_contract.md).
**Provisional, pending plan-author review**, like the contract. No SDK family
runs the scenarios yet: the Rust runner arrives with the Rust one-call (packet
S1-A3) and the other families' runners with their ports. Nothing here needs a
network.

| File | Content | Source |
|---|---|---|
| `manifest.json` | The file list and the files that are not defined yet. | Written with the scenarios. |
| `contract.json` | Calls, stages, durable states, error codes and fields, artifact fields, batch limits, custody, local verification, finality modes, dispatch classification and rules. | Rendered from `crates/iroha/src/client/operation_contract.rs`. |
| `scenarios/*.json` | One single-operation scenario per file. | Written by hand from the contract. |

There is no `vectors.json` yet: the canonical Norito types of
`PreparedZkOperationV1` and `BuiltZkOperationV1` belong to the transport-free
operation core (S1-A2), which adds their byte vectors. `manifest.json` lists it
under `pending`, and the checker fails if the file appears before the manifest
names it.

The operation runs the shared transaction reducer, so its states and events are
those of [`../workflow_v1/state_machine.json`](../workflow_v1/state_machine.json).

Check the set without Rust with `python3 scripts/check_operation_contract.py`.
Regenerate `contract.json` after changing the Rust tables:

```sh
cargo test -p iroha --lib client::operation_contract -- --ignored
```

## The fake world

- **Request.** `actions` lists the declared actions of one transaction; each
  action lists its attachment slots, `{"kind": "proof" | "key_material",
  "length": <expected bytes>}`. A batch of several operations is one request
  with several actions. `signer` is `handle` (the account's opaque signer
  handle, the default) or `external` (signatures come from outside the SDK).
  `finality` is `authenticated` (the default) or `torii_status`.
- **Driver.** Proves, verifies locally and builds for the operation's current
  transaction identity. Scripted results are consumed in order.
- **Signer.** Signs the persisted payload, or returns the scripted external
  signature, which the operation verifies against the built bytes.
- **Ledger.** Dispatches and status reads return the scripted results in order.
  In the `authenticated` mode a status read that shows a state-resolved
  `applied` or `rejected` candidate is followed by one finality read.
- **Clock.** Starts at 1,000,000 ms. A sleep advances it by its duration.
- **Storage.** Durable and in memory.

A scripted entry that no call consumes, or a call with no scripted entry, fails
the scenario.

## Scenario

```json
{
  "schema": "iroha.zk_operation.scenario.v1",
  "id": "file name without .json",
  "category": "one of the categories below",
  "rules": ["rule ids of contract.json this scenario exercises"],
  "description": "what happens and why",
  "request": {"actions": [{"attachments": [{"kind": "proof", "length": 1024}]}], "signer": "handle", "finality": "authenticated"},
  "calls": [ ... ]
}
```

Categories: `happy_path`, `finality_modes`, `interruption_before_submission`,
`interruption_after_ambiguous_submission`, `cancellation`,
`local_verification`, `batch_bounds`, `external_signing`, `custody`,
`dispatch_classification`.

## Call

| Field | Meaning |
|---|---|
| `op` | `execute` (`execute_operation`, or `run` of its durable handle once the operation exists), an advanced call (`prepare`, `prove`, `local_verify`, `build`, `sign`, `submit`, `await_finality`), or a handle call (`recover`, read-only; `cancel`; `progress`). |
| `options` | `observation_timeout_ms` (default 0: one read), `poll_interval_ms` (default 1000), `retransmit_identical_bytes`, `retry_rejected_step` (default false). |
| `script` | Lists consumed in order: `proofs`, `local_verifications`, `builds`, `signs`, `dispatches`, `statuses`, `finality_proofs`. |
| `interrupt_after` | A durable state: the process stops immediately after the journal first stores that state in this call, with no further journal write or external effect. |
| `expect` | See below. |

The advanced calls hand the proofs to each other in memory: `local_verify`
follows a successful `prove`, and `build` a successful `local_verify`, with no
interruption between them.

Script tokens:

| List | Tokens |
|---|---|
| `proofs` | `ok`, `fail:<Code>`, `upload_required:<material>` (the driver can only prove by sending that private material to a remote party), `interrupt` |
| `local_verifications` | `ok`, `invalid` (the proof does not verify), `fail:<Code>`, `interrupt` |
| `builds` | `ok`, `fail:<Code>`, `interrupt` |
| `signs` | `ok`, `wrong_key` (signed by a key that does not control the authority), `wrong_bytes` (signed over other bytes), `fail:<Code>`, `interrupt` |
| `dispatches` | the classes of `dispatch_classification`: `accepted`, `already_known`, `refused`, `deferred`, `not_dispatched:<Code>`, `ambiguous`; and `interrupt` |
| `statuses` | `applied`, `rejected`, `expired` (state-resolved), `observed` (in the pipeline), `absent` (exact absence), `read_failed`, `unbound_response`, `interrupt` |
| `finality_proofs` | `verified`, `unavailable`, `mismatch` (bound to another transaction or outcome), `interrupt` |

`interrupt` means the process stops inside that call: the runner is dropped at
that point and performs no further journal write or external call.

## Expectation

| Field | Meaning |
|---|---|
| `result` | `completed` (the operation is finalized), `ok`, `interrupted`, or `{"error": <Code>, "stage", "action_index"?, "bound"?, "actual"?, "maximum"?, "resumable"?, "has_transaction_identity"?}`. |
| `effects` | The exact ordered external effects: `prove:n`, `local_verify:n`, `build:n`, `sign:n`, `dispatch:n`, `status:n`, `finality:n` for transaction identity `n`, and `sleep:<ms>`. No effect carries private material. |
| `journal` | `absent`: no durable operation exists. Otherwise `status` and `state` follow. |
| `status`, `state` | The operation status and the durable state of its transaction identity. |
| `identity` | Optional: `dispatches`, `possible_admissions` and `evidence` of the current identity, as in the workflow fixtures. |
| `artifact` | For a successful `prepare` or `build`: `{"kind": "PreparedZkOperationV1", "actions": n, "attachment_slots": n}` or `{"kind": "BuiltZkOperationV1"}`. |

A `ResourceLimitExceeded` refusal at `prepare` carries `bound`, `actual` and
`maximum`, and `action_index` when one action crosses the bound; the checker
recomputes the count and slot-length refusals from the request.
