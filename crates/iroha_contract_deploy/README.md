# Native contract deployment service

`iroha_contract_deploy` owns deployment orchestration shared by Musubi and native
Rust consumers. The `iroha` SDK owns transport, fee quoting, signing, and canonical
transaction waits; this crate owns immutable artifact verification, the native
upload/manifest/atomic-commit sequence, and filesystem journals.

`DeploymentService` receives one runtime `Config`. `prepare` takes complete
artifact bytes, a typed alias, and an explicit fee intent; it verifies account
existence, exact effective alias grants, deployment CAS state, and
every quoted native transaction. `persist` records the exact signed plan without
submission. `execute` persists before dispatch; `resume` authenticates that plan
and polls every attempted hash without signing a replacement or replaying it.
Journal inspection, cancellation and receipt reads require the caller's original preflight and
compare the complete authenticated plan before network reads or journal writes.
Managed and package recovery also bind the service's Prepared event to that review
before forwarding progress or dispatching a transaction.
Bare governance identities are rejected because they are not approval evidence.
Registered developers need no global management grant for immutable artifact
creation. All stages pay the configured native fees. Other valid publisher
signatures over the same verified manifest content reuse the first stored
provenance; neither the receipt nor readback claims that provenance was replaced.
An owned domain acquired through the canonical paid `EnsureAlias` flow supplies
only the exact alias scope needed within that domain.

Artifact-derived `LifecycleHook` and `DeploymentLifecycleGuidance` let native
frontends explain a required initialization call separately from the Applied
deployment receipt. Guidance never claims the hook's current state or submits
arguments. Resumed guidance authenticates the retained plan and requires its
artifact hash to match the completed receipt; an unavailable advisory does not
discard successful deployment evidence.

Deployment does not automatically grant mutable entrypoint access. The current
account owner in the canonical contract lifecycle may grant or revoke an exact
`CanInvokeContractEntrypoint` token for that contract address and selector without
`CanManageSmartContractCode`. An original deployer, alias holder, pending owner,
or Parliament identity does not gain this account-owner authority. Existing
exact-token holders and code managers retain their separate delegation rights;
transferring ownership does not implicitly revoke previously issued tokens.

An owner calling a guarded entrypoint quotes and signs the exact self-grant and
call, then persists both before submitting either. The call waits for the grant's
exact `Applied` evidence before dispatch. Required aggregate fee caps and the
original finite deadline bind both stages; transaction expiry never exceeds that
deadline. Recovery reconciles the original signed hashes without renewing either
authorization. Invocation always requires the exact token. It does not grant additional permissions to the contract body:
address-scoped contract state is distinct from the caller's account metadata,
which remains protected by its normal authorization rules.

`current_completed_contract` verifies the retained deployment, current alias and
artifact readback and returns an opaque artifact/receipt pair. Native consumers
encode view or mutable-call arguments against that verified local interface with
`trusted_contract_intent`; no endpoint-provided draft selects executable trust.

`execute` and `resume` receive one explicit typed progress observer. It sees the
authenticated plan before dispatch, durable submitting/recovering stages by exact
hash, Applied evidence only after it is persisted, and the start of final
readback. Progress is observational and never changes signing or recovery policy.
Musubi shows the complete network, signer, alias, and fee review plus stage progress
on human stderr; machine mode retains one final JSON document and no progress output.

Journal custody uses `iroha_fs`: owner-only directories and bounded regular
single-link records, opened relative to the retained locked directory without
following symlinks or reparse points. Unix uses 0700/0600; Windows uses protected
owner DACLs and handle-bound access. Both file and directory are synced before dispatch. A crash
between recording an attempt and sending it deliberately remains unresolved;
resume must not guess whether a request reached Torii. Partial records fail
closed and are never silently overwritten. Native macOS component tests pass;
Linux and Windows runtime and crash qualification remain part of the release matrix.

`inspect_journal` returns a typed `Pending`, `Failed`, `Completed`, or `Cancelled` disposition.
A fixed failure contains the SDK's exact state-resolved rejection or expiry
response from the configured root ledger. Inspection rechecks the exact hash and persists that proof.
An explicit new deployment requires confirmed failure, completion, or cancellation
of a fully unattempted local plan.
Transport uncertainty never becomes a fixed failure. Resuming a completed
historical journal verifies its commit without requiring the alias to remain
at its historical address.

Read-only historical validation binds every envelope and manifest provenance to
the retained deployment authority. A current reader with a different signing
account may inspect the same network, chain, and address profile. Persisting,
executing, or resuming still requires the original deployment authority and key.

`cancel` durably abandons only a fully unattempted local plan. It holds the
exclusive journal lock, rejects any execution or unknown evidence, and retains
the exact ordered hashes in an immutable cancellation record. Repeated cancel
is idempotent; a cancelled plan cannot execute or resume. Cancellation does not
claim transaction expiry and cannot release an attempted ambiguous deployment.

`receipt.json` is produced only after the exact commit reaches state-resolved
`Applied` on the configured root ledger and authenticated alias/nonce plus stored
artifact bytes agree. On a private root, this proves local execution; parent
anchoring is separate evidence. The SDK status selector `global` denotes the
configured ledger's root and does not imply confirmation by its parent network. `completed_receipt` authenticates all retained evidence and rechecks the
exact commit against the configured network without submission. Signed plans
are runtime artifacts; only the finalized receipt is intended for sharing.

Funding preflight queries each registered fee asset's balance policy and binds every
quote to the deployment's exact dataspace. Global assets share one authority balance
across routes; restricted assets use the quoted dataspace's exact `AssetId` bucket.
Cumulative principal and fees never merge different dataspace balances or substitute
parent currency. Missing accounts, definitions, inaccessible routes, and malformed
reads fail; only typed absence of the exact requested holding means zero.
