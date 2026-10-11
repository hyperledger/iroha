# KAGEMUSHA ledger implementation

`KagemushaWalletLedgerV1` is the closed instruction boundary. Registration requires an
exact `CanManageKagemushaWallet { asset_definition }` grant and the reserve account's
own transaction authority. Registration permanently binds the network, scheme, asset
incarnation, scale, reserve account and balance scope. Exact retry does not increment
permanent reference counts. Ordinary transfer, burn and account/asset teardown cannot
spend or remove the reserve. Current and rollback snapshot validation checks the reserve
indexes and each retained issuance's registration, wallet and ordinal bindings.
Universal Dataspace assets use this same registration path without a token allowlist
or Parliament approval; the asset-management and reserve-owner permissions still apply.

`IssueLoad` is an ordinary signed transaction instruction. The payer commits the exact
asset, wallet, request identity, expected next ordinal, amount and optional charge. The
ledger checks the ordinal before atomically debiting the payer, crediting the reserve and
retaining the immutable load receipt. A stale ordinal or changed retry cannot debit funds.
Only a deterministic retry of the original transaction at its original height can return
the same receipt. A later transaction reusing the request fails; clients recover the original
receipt through a committed query, including after loads close. Load requires the original
global root scope and rejects independent private roots before debit; a dataspace lane of
the global chain remains eligible. Genesis cannot issue loads. Dedicated issuer keys, voucher
publication and a second publication transaction do not exist.

Committed recovery reads borrow one generation-consistent `StateView` under finite
record and cumulative decode limits. `CommittedLoadReceipts` checks the payer, registered
network/scheme/asset, wallet ordinal and original transaction hash/height membership.
Historical certificate availability does not limit receipt recovery after chain growth.
The returned receipt is transport data; it grants no finality or offline balance authority.
Clients independently authenticate native global consensus and the exact successful direct
transaction with `verify_finalized_kagemusha_wallet_load_v1`, and must verify the complete
Load proof before crediting value. A caller-supplied receipt or height cannot replace that
verification. The receipt retains request, scheme, asset, wallet, ordinal, value, charge,
payer and original transaction/height; later chain growth never replaces it.

Creating that receipt also emits the typed `KagemushaLoadCommittedV1` event with its
canonical transcript digest. The ordinary execution result commits to the exact event
bytes, order and count. An exact execution retry emits no second event, and a failed
enclosing transaction rolls the event back with its debit and receipt. The independent
event-inclusion verifier requires native global finality and the complete expected
receipt. Event naming or an unsigned receipt alone cannot authorize offline value.

The output seal retains each Load's counted event path in the same World overlay before
capturing the World root and execution witness. Each row has a fixed 32-sibling bound and
contains only its receipt digest, height, root, count and index; it contains no certificate or
carrier hash. Snapshot validation requires every issuance to retain its matching path.
`NativeFinalityCursorV1::advance_to_height` advances a charged in-memory prefix from the
original signed genesis in bounded steps and returns an opaque historical native result.
`CommittedLoadReceipts::event_evidence_for` joins that result to the indexed original receipt
and path, checks the certified event root and count, and invokes the model's event verifier.
The cursor cannot import checkpoint trust or rewind progress. Receipt-only recovery remains
available without historical certificate custody; authenticated event evidence requires it.

Load deposits and Unload/fee payouts use the existing atomic numeric movement owner,
including transfer controls, source custody, exact balances, admission and execution
transcripts. Both balance buckets must equal the registered scope. Online asset controls
can delay payouts but cannot rewrite a retained claim or impose a haircut. An undelivered
load remains a reserve liability; no timeout refunds it.

The native package verifier is mandatory. `InstallVerifierPack` requires the registered
reserve account's authority and live exact asset-management permission. It authenticates
the signed sigma/Omega inventory against the registered scheme and selected manifest,
then retains the exact original bytes in one immutable World row. Proof-consuming
instructions mount the same-overlay installation and fully verify sigma, required Omega
and both transported accumulator claims. Missing originals retain `ArtifactsUnavailable`.
Model validation and finalized load receipts never replace native proof verification.

One package reserves one confidential operation and one sigma verification plus an Omega
verification when lineage is carried. Aggregate transport bytes include both accumulator
originals. All transaction/block proof limits are checked together before reservation
counters change or native verification starts. Fixture verifiers remain test-only
orchestration.

The node enrollment journal retains the original E1, approved selection and deadline in
an explicitly initialized private namespace. Before exposing E1 in a signed pre-key permit,
it freezes the authenticated worker's configuration and journal incarnation, retains the exact
preparation and checks the worker's durable acknowledgement. It validates account-signed E5
and stores the private verifier request before returning its sole Complete dispatch decision.
A reread `Verifying` attempt permits Recover only. The worker may atomically claim the
original prepared row once; a claimed row with an unknown result never repeats verification.
After E5 selection the node cannot issue another Prepare, including after restart or worker
storage loss. Unknown or unavailable outcomes do not restore a fresh attempt.
Actual signed pre-key permits are authenticated and retained per native dispatch nonce, and
Resume requires the previous exact original in the same journal. Worker replies bind the
entire exchange packet, selected configuration, incarnation and E5. Evidence retains the
actual first verification time, which may be later than the E5 selection time after recovery;
retries cannot refresh it. Its exact original precedes a durable `Signing` selection that
freezes the credential body and an issue time no earlier than that verification. The returned
E6 must contain that exact body,
evidence and selected Enrollment certificate; its actual signature is checked before exact
E6 bytes are retained for delivery. Retries do not refresh issue time or replace the original.
Publication errors poison the live owner until reopening and reconciliation. Native reads
distinguish initial absence from later custody failure. This local ordering component does
not establish KYC, worker provenance, signer custody or protection from a privileged rollback
of the entire filesystem.

The [enrollment issuer](enrollment_issuer/README.md) connects this journal to current
signed bank or scheme-operator eligibility, the private verifier process and an
Enrollment-role signer. The concrete Torii service owns the journal and these runtimes
on a supervised thread. Its optional configured route authenticates the original account
request and the registered asset before dispatch. Bank middleware supplies bank
eligibility; a scheme operator supplies its selected policy without a mandatory
Parliament gate. These implemented boundaries still require complete Linux launch,
real platform evidence, shutdown and network qualification.

The offline Load relation binds the receipt and credential-bound Advance signature. Native BLS certificate and authenticated epoch verification must succeed before the Advance is signed; the recursive finality prover and its artifact catalogs are retired. The selected released-app/uncompromised-OS assumption supplies this pre-signing trust boundary. See [native finality goals](../../../../specs/kagemusha_native_finality_goals.md).
TODO(G3/G6): qualify their complete installed producer artifacts and the real
end-to-end device/network flow. The online receipt alone grants no foreign wallet-open
or proof-acceptance capability.
