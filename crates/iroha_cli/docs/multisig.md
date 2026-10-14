# Multi-Signature Usage Guide

This guide explains how to create and operate a multi-signature account shared by multiple users.

## Registering a Multi-Signature Account

__Prerequisites:__

- Any account may submit the multisig registration transaction. The CLI creates a universal,
  domainless controller and does not invent a home domain. A typed instruction may supply an
  explicit `DomainId` when domain-owned routing and role ownership are intentionally required.
- Signatory accounts do not need to exist in advance. Missing signatories are materialized during
  registration and tagged with metadata `iroha:created_via = "multisig"`.
- The CLI expects canonical I105 account literals for `--account` and `--signatories`. These
  literals identify universal accounts and are never resolved through a node-local default.

__Example usage:__

```bash
iroha --fee-payer authority ledger multisig register \
--account <canonical-i105-controller> \
--signatories \
<canonical-i105-signatory-1> \
<canonical-i105-signatory-2> \
<canonical-i105-signatory-3> \
--weights 1 2 3 \
--quorum 3 \
--transaction-ttl "1y 6M 2w 3d 12h 30m 30s"
```

__Explanation:__

To simplify explanations, the multisig controller is labeled `MSA` and the signatories are labeled
`S1`, `S2`, and `S3`.

- `MSA` represents the multi-signature __account__ you provide with `--account` (or let the CLI
  generate in the signatory domain). The generated controller key is random and its private half is
  discarded because direct multisig signing is forbidden (`torii_multisig_direct_sign_reject_total`).
  Omit `--account` to generate a fresh controller or supply your own random id.

- The multi-signature account consists of three __signatories__: `S1`, `S2`, and `S3`.
- Each signatory has an assigned __weight__:
  - `S1`: __1__
  - `S2`: __2__
  - `S3`: __3__
- A transaction is executed once the total weight of approving signatories meets the __quorum__:
  - For example, `S1` (weight __1__) and `S2` (weight __2__) together meet the quorum (__3__).
  - Alternatively, `S3` (weight __3__) alone meets the quorum.
- If the __transaction TTL__ expires before reaching the quorum, the occurrence is retained as expired and cannot execute.
  The policy caps the original proposal TTL; retries never renew it. Nested multisig signatories are rejected.

After submitting the registration, query for accounts whose metadata contains the key
`multisig/spec` to discover the multisig account ID:

```bash
iroha account list --all --filter 'exists(metadata.`multisig/spec`)'
```

The resulting account ID, along with the stored specification, uniquely identifies the multisig
authority and can be reused for future proposals and approvals.

## Proposing a Multi-Signature Transaction

__Prerequisites:__

- The multi-signature account must already be registered.
- The proposer must be one of the signatories.
- The proposal TTL is capped by the multisig policy (`transaction_ttl_ms` set at registration). The CLI will preview the effective expiry and will refuse overrides above the policy cap before sending the transaction.

__Example usage:__

```bash
echo '"congratulations"' | iroha --emit-instructions account meta set \
--id <canonical-i105-multisig> \
--key success_marker \
| iroha --fee-payer authority ledger multisig propose \
--account <canonical-i105-multisig> \
--proposal-nonce <64-lowercase-hex-nonzero-nonce>
```

__Explanation:__

- Proposes setting the string value "congratulations" for the key "success_marker" in the metadata of the multi-signature __account__.
- The proposer automatically becomes the first __approver__.
- Generate and persist a nonzero 32-byte nonce before the first attempt. Pass it with `--proposal-nonce` and retain it for retries. Use a fresh nonce only for a new intentional operation.
- The native owner derives `proposal_id` from the network, original multisig account and nonce. The independent `instructions_hash` commits to the reviewed contents. Identical contents with distinct nonces are separate proposals.
- Torii's `/v1/multisig/propose` endpoint accepts typed JSON instruction objects or base64 native Norito `InstructionBox` frames inside the JSON `instructions` array. Fully native clients may also send the whole `MultisigProposeDto` request body as `application/x-norito`.

## Listing Multi-Signature Transactions

__Assumptions:__

- `S1` (weight __1__) proposed the transaction.
- `S2` (weight __2__) is your account, listing the transactions involved.

__Usage:__

```bash
iroha ledger multisig list all --multisig-selector <canonical-i105-multisig>
```

__Example text output (`--output-format text`):__

```text
multisig_account_id: <canonical-i105-multisig>
proposal_id: <64-lowercase-hex-occurrence-id>
instructions_hash: <reviewed-instruction-commitment>
status: COLLECTING_SIGNATURES
operation_type: SET_KEY_VALUE
intent: null
proposed_at_ms: 1738871998000
```

__Explanation:__

- Each block represents one proposal visible to the authenticated signatory authority.
- `proposal_id` identifies one intentional occurrence. `instructions_hash` is its content commitment. `status`, `operation_type`, and `intent` come directly from the approvals API ordering and classification.
- `proposed_at_ms` is the proposal creation timestamp in milliseconds since the Unix epoch.
- JSON mode remains machine-readable and emits one approval entry per array item using the same server ordering.

## Approving a Multi-Signature Transaction

__Prerequisites:__

- The proposal must have been submitted.
- The approver must be a signatory of the multi-signature account.

__Example usage:__

```bash
iroha --fee-payer authority ledger multisig approve \
--account <canonical-i105-multisig> \
--proposal-id <64-lowercase-hex-occurrence-id> \
--instructions-hash <reviewed-instruction-commitment>
```

__Explanation:__

- Approves the exact __proposal ID__ and __instruction commitment__ for the multi-signature __account__. An equal instruction hash never selects another proposal.
- Approval may lead to either execution or expiration of the proposal.
- If the approval meets the quorum but the multi-signature account lacks the necessary permissions to execute it, the final approval is discarded. Signatories who have not yet approved it can retry after the multi-signature account has acquired the required permissions.

## Canceling a proposal

```bash
iroha --fee-payer authority ledger multisig cancel \
--account <canonical-i105-multisig> \
--proposal-id <target-occurrence-id> \
--instructions-hash <target-instruction-commitment> \
--proposal-nonce <new-cancellation-nonce>
```

Cancellation is a separate proposal containing a native `MultisigCancel` instruction
bound to the target occurrence and content. The CLI prints `cancel_proposal_id` and
`cancel_instructions_hash`. Later signers use `ledger multisig approve` with those two
values. Re-running cancellation retains the original nonce and exact payload; it never
switches automatically to approval. The wrapper and canceled target have separate
permanent histories. See the [native occurrence contract](../../../specs/multisig_proposal_occurrences.md).
