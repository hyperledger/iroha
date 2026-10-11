# Iroha wallet service

This crate owns private developer custody and durable native account operations.
Musubi and the ordinary Taira account CLI use these services; transaction construction,
fee quotes, plan verification and finality observation remain native SDK responsibilities.

- `WalletStore` creates or imports immutable named wallets outside project directories.
  Public inspection retains exact network/profile identity without reading signing keys.
  Signing uses native `Config` and its bounded, no-follow `private_key_file` reader.
  Typed key-pair import binds an existing owner to a separately authenticated network
  without copying endpoint credentials from another client configuration.
- Musubi namespace binding uses the same purpose-closed wallet preparation journal. One exact
  owner-signed `RegisterMusubiNamespaceBinding` retains complete namespace/dataspace/scope/generation,
  original policy revision, finite UTC and fee authorization. Native execution checks current
  ownership and admission; the wallet selection grants neither and creates no domain or SNS lease.
  Recovery reads all original preparation stages without renewing time or signing another payload;
  only a fresh monotonic observation deadline may change. Missing original custody is an error.
- `AccountService` delegates authoritative balance reads and cumulative principal/fee
  solvency checks to native SDK `blocking::Client::{balance,check_funding}` with exact
  `AssetId` principal buckets. XOR transfers and paid parent alias totals explicitly
  select global balances; fee quotes select each registered asset's policy and exact
  route dataspace. Balance reports retain the full scoped asset identity. The service
  then prepares, submits or reconciles an
  exact fee-paying transfer or alias operation. Native journals retain the original request
  before preflight, the quoted payload before signing, and the signed envelope before dispatch.
  Explicit preparation can finish an interrupted request or payload without replacing its
  nonce, fees, quote or TTL. Read-only partial recovery reports Absent or Expired without HTTP
  or signing. Request-only retirement requires the exact request and clean inventory under
  the original lock; it grants no replacement authorization. Signed and submission-marked
  history preserves exact wire and prevents repeated submission after an attempted write.
  `AccountService::with_deadline` retains the original SDK runtime, HTTP pools and
  cancellation signal; repeated views can only shorten the HTTP deadline.
  `BoundedTransactionOptions` caps aggregate execution fees and shares one deadline across
  paid alias preparation, parent registration and anchoring. Bounded alias recovery requires
  the original alias request, rent guards and fee authorization; it never signs another wire.
  Typed private-root registration and anchor requests bind the exact child, retained parent
  cursor, caller fee maxima and one shared deadline. Their submit/resume methods compare that
  selected request while holding the journal lock. An `Applied` transport result does not
  replace the attachment service's independently verified parent inclusion proof.
  Stream-token custody Configure/Enroll requests use the same journal owner, with one
  canonical native instruction, exact predecessor CAS and separate manager, signer and
  attester identities. Recovery compares the original request and fee authorization before
  dispatch; fresh read budgets never renew the signed transaction or enrollment interval.
  Supplied predecessor records and anchors are claims: the managed coordinator must obtain
  independently authenticated evidence, and native execution enforces current authorization.
  Initial reserve-policy requests accept only revision one without a predecessor and bind
  the exact asset, custody, treasury and service authorities. Their journal retains the
  original signed policy, deadline and fee authorization through ambiguous submission and
  read-only recovery. Selection fields express caller intent; independent native policy
  evidence and managed reserve provisioning remain separate requirements.
  Reserve-account registration retains the exact selected policy, provider owner and immutable
  underwriting terms under the operations account's original fee and UTC authorization. It uses
  one native `RegisterSorafsReserveAccount` instruction and the same once-only submission journal;
  read-only recovery preserves the original wire. These inputs do not prove an active policy,
  provider ownership or partition absence. Native registration creates a zero-balance partition
  in `Warning`; collateral funding, credit, independent current evidence and service readiness
  require their separate native transitions and verification.
  Reserve top-up requests retain the exact selected policy and provider partition, independently
  requested revision, fixed movement id, amount, fees and original UTC authorization. The provider
  owner signs one native `RequestSorafsReserveMovement::TopUp`; it need not be the operations
  authority. A legitimately lagging partition policy digest is retained without projection.
  The same once-only journal verifies every original claim and preserves the signed wire through
  ambiguous submission and read-only recovery. Selection proves no current state or unused movement
  id. Native application pays execution fees and creates a pending movement; manager approval and
  the provider-to-custody asset transfer remain separate. It grants no funded reserve or readiness.
  Generic reserve movement decisions retain the selected policy and claimed partition, independent
  current revision, exact movement id, approve/reject flag, UTF-8 rationale and original UTC/fees.
  One manager-signed `DecideSorafsReserveMovement` uses the same journal and immutable recovery.
  Its wire carries no provider, kind or amount: these caller selections do not prove that the
  movement id belongs to a provider or represents a TopUp. Purpose-specific managed approval must
  join authenticated original request history and fresh state before invoking this planner.
  Manager funding checks cover only its fees; native execution resolves Pending status and owns
  the actual provider/custody transfer. The generic report establishes no collateral or readiness.
  Governed provider-credit upserts retain explicit current absence/hash and the full original
  current/replacement records, desired-record hash, policy/partition claims, signer and UTC/fees.
  One `UpsertProviderCredit` carries the native credit-row CAS; policy and reserve partition claims
  are not native CAS conditions. Its credit authority is independent of reserve policy roles and
  still requires native `CanUpsertSorafsProviderCredit`. The wallet pays signer fees only; native
  execution checks ownership, aggregate custody, exact backing and slash-history retention.
  Original journal recovery cannot replace the CAS, records, claims or signed envelope and
  establishes no reserve borrowing, collateral, capacity or service readiness.
  Provider-owner capacity declarations retain the complete canonical manifest and selected full
  policy/partition/credit claims, independent hashes, original UTC and fee terms. They submit one
  `RegisterCapacityDeclaration`, whose native semantics permit replacement without a capacity CAS.
  The exact owner metadata and shared manifest validator are enforced; native execution owns
  registered ownership, actual pooled backing and active allocation checks. The wallet charges
  owner fees only; stake pointers transfer no principal. Optional pricing remains a hint and zero
  nominal credit is not silently prohibited. Exact original recovery proves no provider admission,
  current capacity, collateral eligibility or service readiness.
  Initial gateway setup retains one ordered manager-signed Configure, exact operator grant and
  exact observer grant. Native Configure owns its initial absence/CAS; native permission delegation
  requires the newly configured policy. Initial recorder setup retains a separate sole Set with
  the full policy, exact recorder roles and active network-derived gateway delivery template.
  Both preserve original UTC, fees and signed wire through the same once-only wallet journal.
  These caller selections confer no current policy or serving authority; native daemon
  Qualification, pending callback reconciliation and final Serving checks remain required.
- `namespace` derives paid one-year domain requests and canonical private dataspace
  leases. Private dataspace names use SNS-derived ids and reject physical parent
  catalog collisions; preparing a lease never adds a parent lane or bootstrap grant.
- `OnboardingService` owns ordinary account admission and faucet recovery.
  Submission uses the native bounded Applied waiter and exact committed-wire readback;
  resume performs an immediate read-only observation.
  `faucet_pow` is the one bounded solver shared with the independent public-reset child.

No service prints or persists credentials in public reports. Filesystem custody uses
the shared `iroha_fs` native handles, immutable publication and file locks on Windows,
macOS and Linux. Unix directories are owner-only 0700 and new single-link files are
0600; private reads also accept 0400. Windows uses protected owner ACLs and retained
native file identities. Tests use temporary directories and mock transports;
cross-compilation alone does not qualify native Windows execution or public rollout.

See the source-coupled [Musubi specification](../../specs/musubi.md) and
[workflow qualification ledger](../../specs/musubi_taira_workflow_goals.md).

The closed `InitialProviderIngestAuthorityRequest` retains the complete owner, dedicated completion
signer and revision-one policy, exact provider/network, finite UTC and fee authorization. The sole
owner-signed native Set uses absence CAS; its wallet journal owns signing, exact-wire verification
and at-most-once dispatch. Inputs remain structural claims. Neither identical-policy execution
nor read-only recovery establishes current signer eligibility, ingest or serving readiness.

Generated publication provisions a clock-independent namespace parent once before generation
publication. Ordinary first use opens it, retains one finite original UTC authorization and a
RequestOnly child marker before quotation, then uses the same wallet signed journal. Missing
parent/marked-child custody refuses. A new invocation may authorize a bounded successor only after
complete-census retirement of an expired absent/RequestOnly attempt; every predecessor and original
UTC remains. At most64 attempts exist, and quoted/signed originals are always reused unchanged.
Native execution still decides current namespace ownership.

The parent atomically provisions a required custody anchor with its original selection. The anchor
commits the selected authorization and exact child hash before effects, so loss of the latest
original or its wallet/marker cannot reset the attempt chain. Local custody is not external rollback
protection.
