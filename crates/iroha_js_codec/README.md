# JavaScript canonical codec owner

This library owns the strict account and instruction conversions shared by
JavaScript platform bindings. It uses the actual Iroha account/controller and
Norito implementations and preserves the explicit instruction JSON admission
rules previously owned by `iroha_js_host`.

The public boundary parses and renders account addresses, and encodes/decodes
both public instruction frames and the compact `InstructionBox` archives used
inside transaction payloads. These encodings are distinct. Archive admission
requires exact consumption and canonical native re-encoding.
Public frame admission accepts only the canonical `InstructionBox` frame. A
concrete instruction frame, including a validation-fee policy proposal, cannot
substitute for that envelope and is not retried through another decoder.

All four instruction encode/decode operations require an explicit `network_prefix:
u16`. The caller's transaction or network profile owns this value; it is never
inferred from a domainless account archive or defaulted to another network.
The entire synchronous operation runs under the existing thread-local
`ChainDiscriminantGuard`, including typed JSON admission, rendering and canonical
re-encoding. The guard restores the previous context on success, error and unwind;
these operations never mutate the process-wide network selector. Native typed
helper consumers must similarly enter their explicitly selected network scope.

The instruction JSON catalog supports every browser transaction allowlist family:
smart-contract deployment, game and NFT market. Typed native owners validate
payloads; unsupported envelopes do not fall back to generic JSON.

Contract artifact instructions require an explicit `artifact_id` containing an
exact decimal-string `dataspace_id` and canonical `code_hash`. All six artifact
operations preserve the full u64 scope in native frames and archives; equal code
hashes in different dataspaces produce different instruction bytes. Hash-only,
numeric-scope and generic instruction envelopes are rejected, as are unknown
artifact, payload and envelope fields.

`CastPlainBallot` and `UpdatePlainConviction` use one closed native adapter. It
retains the registered model and exact u64 duration in both frame and archive
operations; missing, extra, renamed and choice fields on conviction updates are
rejected before generic instruction admission. Decoding rechecks that contract.

The repo lifecycle uses one closed `Repo` envelope mirroring the registered
`RepoInstructionBox` (`iroha.repo`): exactly one of `Initiate` (complete
`RepoIsi`, including `governance.allow_early_repayment`), `Reverse` or
`MarginCall` (`{"agreement_id": ...}`). Payloads must equal their canonical
model JSON, so the parsed proposal keeps the consented initiation and maturity
intent hashes; generic base64 instruction literals cannot bypass the envelope.

The native bond-servicing kernel uses one closed `Bond` envelope mirroring the
registered `BondInstructionBox` (`iroha.bond`): exactly one of `Register`,
`RecordCashflow`, `FundCashflow`, `ClaimCashflow`, `CloseCashflow`, `Call`,
`DeclareDefault`, `ReplacePayingAgent` or `RetireTreasuryUnits`, each equal to
its canonical model JSON (canonical quantities,
lowercase 32-byte hex digests, explicit `null` for absent optional terms).
Terms validation and every state check stay with Core
(`specs/finance/bond_ops.md`). `bond_vault_account_literal` renders the
key-less bond vault account for a caller-selected network prefix. The shared
vectors in `javascript/iroha_js/test/fixtures/bond-v1-codec.json` are generated
from the data model by `bond_instruction_tests.rs`; rerun its ignored
`regenerate_bond_js_fixture` test to accept an intended change.

Native conditional escrow instructions use closed `OpenConditionalEscrow`,
`AttestEscrowCondition` and `ExpireConditionalEscrow` envelopes whose payloads
must equal the canonical model JSON (including `evidence_hashes`). Atomic
settlement JSON requires the `escrows` array (possibly empty); every escrow leg
field is mandatory because the leg is part of the consented intent hash.

Declarative alias setup (`EnsureAlias`) and `SetKeyValue.AssetDefinition` also
admit exactly their native model JSON. `canonical_atomic_settlement_json` sorts
`Settlement.Atomic` movements by native `(AssetId, AccountId)` order,
`atomic_settlement_intent_hash` and `repo_intent_hashes` return the exact
`CanExecuteSettlement` consent hashes computed by the model methods Core checks,
and `instruction_json_from_wire_pair` admits a planner-issued
`(wire_id, frame)` pair only after an exact decode and re-frame check.

Native bindings convert buffers and error categories only. They also reuse the
typed helper operations for their existing transaction builders and inspection
APIs. There is no Node, daemon, network, filesystem, or key-custody dependency in
this library's interface. All existing model and account-curve features remain
enabled; this extraction does not qualify a browser artifact or alter platform
support policy.

Focused validation: `cargo test -p iroha_js_codec --lib`. The native host's
`shared_codec_adapter` tests verify platform error and result conversion.
