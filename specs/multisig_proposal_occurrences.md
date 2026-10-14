# Native multisig proposal occurrences

This first-release contract separates an intentional proposal from its instruction
commitment. It applies to SORA Nexus native multisig execution, Torii, SDKs and
applications. There is no instruction-hash selector or compatibility decoder.

## Identity and signed instructions

`MultisigProposalNonce` is a required, nonzero 32-byte caller nonce. Its JSON and CLI
representation is exactly 64 lowercase hexadecimal digits. The caller persists the
nonce before preparing or submitting a proposal. Retry and restart reuse it.

`MultisigProposalId::derive` is the canonical native owner. It hashes the Norito
`ProposalIdentity` struct containing, in order:

1. Domain string `iroha.multisig.proposal-occurrence.v1`.
2. Native `NetworkId`.
3. Original concrete multisig `AccountId`.
4. `MultisigProposalNonce`.

The helper uses `HashOf::new` over this typed struct. Its result is a distinct native
32-byte type with the same strict lowercase hex representation. SDKs call the native
helper; browser applications retain and bind the inspected native result.

The instruction vector does not enter occurrence derivation. Reusing a nonce with
changed instructions addresses the same reserved slot and rejects. `instructions_hash`
continues to mean `HashOf<Vec<InstructionBox>>` and never identifies an occurrence.

| Native instruction | Required fields |
| --- | --- |
| `MultisigPropose` | `account`, `proposal_nonce`, `instructions`, `transaction_ttl_ms` |
| `MultisigApprove` | `account`, `proposal_id`, `instructions_hash` |
| `MultisigCancel` | `account`, `proposal_id`, `instructions_hash` |

Propose execution derives the occurrence from the installed native network and original
concrete account. Approve and Cancel match the occurrence and instruction commitment.
The enclosing transaction independently binds network, signer, fees and exact executable.

## Lifecycle and controller policy

An occurrence retains its original network, account, nonce, ID, full instructions,
instruction hash, signed TTL choice, first committed proposal time and fixed expiry.
Approvals may change only the approvals set. Duplicate proposals never renew expiry or
execute again. Terminal finalized, canceled and expired occurrences remain reserved.
A new intentional payment can use the same contents with a fresh nonce.

Cancellation is a separate occurrence whose instructions contain
`MultisigCancel(target_account, target_proposal_id, target_instructions_hash)`.
The wrapper and target retain separate terminal records and authenticated outcomes.
Later signers approve the explicit wrapper occurrence and content commitment. There is
no automatic lookup by equal cancellation contents or participation-mode switching.
A cancellation wrapper cannot itself be the target of cancellation.

All controller-changing paths require outstanding-proposal invalidation before changing
signatories, quorum or controller. Old terminal history remains under the original
account; approvals do not migrate into a different authority policy. Nested multisig
signatories remain unsupported, and unreachable automatic relay state is removed.

## Transport and durable application custody

`/v1/multisig/propose` requires `proposal_nonce`. `/approve` requires both `proposal_id`
and `instructions_hash`. Resolve requires only `proposal_id` as its proposal selector;
responses contain separate ID and content-hash fields. Lists and pagination key by
occurrence, retaining equal-content proposals independently.

`/cancel` requires a new wrapper `proposal_nonce`, `target_proposal_id` and
`target_instructions_hash`. It always prepares or submits creation of that wrapper.
Its response names `cancel_proposal_id`, `cancel_instructions_hash` and both target
fields. Further signers use ordinary `/approve` with the wrapper ID and hash.

Application `action_id` identifies one staff participation and is separate from the
shared occurrence. Durable custody binds network, original account, nonce, reviewed
intent, exact request/prepare/signed bytes and the original action deadline. An atomic
occurrence reservation rejects conflicting intent while permitting distinct signers'
participations. Ambiguous submission or expiry never silently generates a new nonce.

## Authenticated completion

Approval outcomes, terminal execution state and native evidence bind both occurrence ID
and content hash. The execution-evidence route selects:

```text
/v1/multisig/execution-evidence/{account}/{entrypoint_hash}/{proposal_id}/{instructions_hash}
```

A lookup result is an untrusted candidate. Completion requires checkpoint-rooted native
verification of the successful entrypoint, the exact retained terminal execution and
World membership, with matching network, account, occurrence and content. Proof for
occurrence A cannot complete identical-content occurrence B. Cancellation wrapper
execution and target cancellation are independently authenticated facts.

Controller changes can cancel an outstanding subject without executing a cancellation
wrapper. This terminal state requires the exact retained cancellation original in a
checkpoint-rooted World snapshot. It does not prove that a staff participation committed
or that a monetary effect executed. Applications stop retrying the canceled occurrence
and display its terminal state; they never infer a successful payment from cancellation.

## Acceptance

- Identical instructions with different nonces remain independently pending and execute once each.
- Conflicting nonce reuse, changed TTL and replay after every terminal status fail without mutation.
- Approval, cancellation, fee routing and rooted evidence cannot substitute equal-content occurrences.
- Canceling A leaves equal-content B untouched; wrapper and target histories remain readable.
- Every controller-change route refuses active approval migration and preserves immutable history.
- Restart preserves nonce, exact originals, terminal reservations and non-sliding deadlines.
- SDK, CLI and portal history preserve distinct occurrences and reject missing, duplicate, unknown or hash-only selector fields.

This is a source-level first-release protocol change. Matching validator, service and SDK
artifacts must be validated and installed together. Existing encoded proposal state is
not decoded through a legacy alias; deployment must explicitly account for the actual
retained state before selecting its rollout procedure.
