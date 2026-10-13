# Durable workflow fixtures (v1)

Shared fixtures of the durable workflow contract,
[`specs/zk_durable_workflow.md`](../../../specs/zk_durable_workflow.md). The Rust
engine runs them with a fake ledger and clock; other SDK-family workflow ports
are not implemented yet. Nothing here needs a network.

| File | Content | Source |
|---|---|---|
| `manifest.json` | The file list. | Written with the scenarios. |
| `state_machine.json` | Vocabularies, transition tables, limits and rules. | Rendered from `crates/iroha/src/workflow/contract.rs`. |
| `vectors.json` | Complete semantic plans, identities and journals; canonical digest inputs, records and progress reports. | Rendered from `crates/iroha/src/workflow/journal_tests.rs`. |
| `scenarios/*.json` | One scenario per file. | Written by hand from the contract. |

The Rust runner is `crates/iroha/src/workflow/scenario_tests.rs`. Check the set
without Rust with `python3 scripts/check_durable_workflow_contract.py`.

Regenerate the two rendered files after changing the Rust tables:

```sh
cargo test -p iroha --lib workflow:: -- --ignored
```

The vector objects are complete serialization inputs: byte arrays use lowercase
hexadecimal, absent options use `null`, and enum names follow
`state_machine.json`. `plan_hex`, `identity_hex` and `journal_hex` include
the canonical Norito headers. The field order and digest domains are listed in
section 7 of the contract; the Python guard independently checks the digests.

## Digests in fixtures

`digest(text)` is the Iroha hash (Blake2b-256, least significant bit of the
last byte set) of the UTF-8 text.

| Value | Input |
|---|---|
| Intent or context digest of a step | `digest("intent:" + label)` |
| Request context digest of a plan | `digest("context:" + instance)` |
| Participant `p1` | `digest("participant:p1")` |
| Account binding | network `fixture-network`, authority `fixture-authority` |

## The fake world

- **Driver.** Building the payload of step `s`, identity ordinal `n` yields the
  bytes `payload:s#n`. A completed round returns the transcript
  `transcript:<label>` and the declared number of custody references, labelled
  `share-0`, `share-1`, with reference bytes `custody-ref:<label>:<index>`.
- **Signer.** Signing `payload:<x>` yields the bytes `signed:<x>`. The identity
  is `signed_transaction_hash = digest` of those bytes and
  `entrypoint_hash = Iroha hash of "entrypoint:" + bytes`.
- **Ledger.** Dispatches and status reads return the scripted results in order.
- **Clock.** Starts at 1,000,000 ms. A sleep advances it by its duration.
- **Storage.** In memory. It can be told to fail one store of a call.

A scripted entry that no call consumes, or a call with no scripted entry, fails
the scenario.

## Scenario

```json
{
  "schema": "iroha.durable_workflow.scenario.v1",
  "id": "file name without .json",
  "category": "one of the categories below",
  "rules": ["rule ids of state_machine.json this scenario exercises"],
  "description": "what happens and why",
  "plan": { "kind": "...", "instance": "...", "driver": {"id": "...", "schema_version": 1}, "steps": [...] },
  "calls": [ ... ]
}
```

A step is `{"label", "kind": "transaction", "max_transaction_identities"?}` or
`{"label", "kind": "offchain_round", "irreversible", "participants_required", "custody_handles_required", "max_transcript_bytes"?}`.
The transcript bound defaults to 1,048,576 bytes and is checked before retaining a round result.

Categories: `happy_path`, `interruption_before_submission`,
`interruption_after_ambiguous_submission`,
`interruption_after_irreversible_progress`, `dispatch_classification`,
`reconciliation`, `retransmission`, `replacement_identity`, `cancellation`,
`duplicate_resume`, `storage_corruption`, `uncertain_write`, `offchain_round`,
`bounds_and_bindings`.

## Call

| Field | Meaning |
|---|---|
| `op` | `run`, `recover` (read-only), `cancel`, `progress`, or `corrupt` (the harness damages the stored record). |
| `options` | `observation_timeout_ms` (default 0: one read), `poll_interval_ms` (default 1000), `retransmit_identical_bytes`, `retry_rejected_step` (default false). |
| `driver` | `present` (default), `absent` (recover only), `wrong_identity`. |
| `script` | Lists consumed in order: `builds`, `signs`, `dispatches`, `statuses`, `round_starts`, `round_recoveries`. |
| `concurrent` | `{"when": <step state>, "action": "cancel" or "run"}` acts after the journal first stores that state. `when: "effect:<effect>"` instead acts inside that external call, immediately after its effect joins the trace; for example `effect:round_recover:0` cancels while round recovery is in flight. |
| `storage_fault` | `{"store": n, "mode"}`: the n-th store of this call fails. `unavailable` and `lost` do not store; `published` stores and then reports failure. |
| `mode` | For `corrupt`: `flip_bit` (lowest bit of the middle byte), `truncate` (drop the last 9 bytes), `append_byte` (one zero byte), `foreign_journal` (a valid first record of the same plan with `-other` appended to the instance), `status_completed` (status set to `completed`, sequence plus one, digest recomputed). |
| `expect` | See below. |

Script tokens:

| List | Tokens |
|---|---|
| `builds` | `ok`, `fail:<Code>`, `wrong_intent`, `oversized` (one byte above the transaction bound), `empty`, `repeat_payload` (the bytes of identity 1), `interrupt` |
| `signs` | `ok`, `fail:<Code>`, `wrong_identity`, `interrupt` |
| `dispatches` | `accepted`, `already_known`, `refused`, `not_admitted:<Code>`, `ambiguous`, `interrupt` |
| `statuses` | `applied`, `rejected`, `expired`, `observed`, `hint_applied`, `hint_rejected` (not resolved from state), `absent` (exact absence), `read_failed`, `unbound_response`, `interrupt` |
| `round_starts`, `round_recoveries` | `completed:<names>`, `waiting:<names>`, `failed:<Code>`, `error:<Code>`, `interrupt`, and the malformed reports `completed_reordered`, `completed_duplicate`, `completed_missing_custody`, `completed_wrong_round`, `completed_context_changed`; recoveries also `not_started` |

`interrupt` means the process stops inside that call: the runner is dropped at
that point and performs no further journal write or external call.

## Expectation

| Field | Meaning |
|---|---|
| `result` | `completed`, `ok`, `absent`, `interrupted`, or `{"error": <Code>, "stage"?, "step"?, "bounds"?, "resumable"?, "has_transaction_identity"?, "progress"?}`. |
| `effects` | The exact ordered external effects: `build:s#n`, `sign:<payload label>`, `dispatch:s#n`, `status:s#n`, `sleep:<ms>`, `round_start:s`, `round_recover:s`, `concurrent:cancel:<status>`, `concurrent:run:<result>`. |
| `status`, `steps` | Workflow status and the state of every step in the stored journal. |
| `partial_completion` | All six lists of the progress report. Mandatory. |
| `identities` | Per step: dispatch count, possible admissions and evidence of each transaction identity. |
| `participants_received`, `sequence`, `cancel_requested` | Further exact values of the stored journal. |
| `journal` | `unreadable` with `journal_error`, or `absent`, instead of the fields above. |

An error carries the progress of the stored journal unless `progress` says
`unavailable` (no trustworthy journal) or `last_validated` (an uncertain write
was published, so the stored record is newer than the one the call validated).
