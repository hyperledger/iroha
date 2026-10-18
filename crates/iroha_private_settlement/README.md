# `iroha_private_settlement`

Internal native preparation for confidential atomic private settlement. This
crate owns the genuine wallet/prover/sealer orchestration, authenticated context
acquisition, encrypted prepared artifacts and preparation recovery. It depends
on the base `iroha` SDK and the native privacy engine; the SDK's prepared
settlement transport and durable submission workflow remain in `iroha::client`.

Construct `OneCallPrivateSettlementOperation::new(account, request, storage,
artifacts, wallet, verifier)` with an owned `iroha::client::AccountClient`, a
`OneCallPrivateSettlementRequest`, durable workflow storage,
`FilePrivateSettlementArtifacts`, a `PrivateSettlementWallet` and an independently
pinned `SumeragiFinalityVerifier`. Use
`OneCallPrivateSettlementOperation::with_source(account, request, storage,
artifacts, source, wallet, verifier)` when the caller supplies the authenticated
context transport. Both constructors preserve the same native preparation and
verification requirements.

The caller retains exact private business terms, original wallet reservations,
genesis/schema pins and the encrypted artifact key. Selected context is durable
before wallet work. `recover` reopens and independently verifies the retained
context and proofs without invoking the wallet or sending transactions; `run`
explicitly continues the original preparation. Prepared materials feed
`AccountClient::private_settlement` with the SDK's existing
`PrivateSettlementRunOptions` and typed settlement results.

Prepared-artifact reads enforce the caller's wire-size cap before decoding. Their
cumulative decode allocation budget follows Norito's canonical policy for the
authenticated frame length, capped at 128 MiB; narrower enclosing budgets still
apply. A local read refusal does not replace the retained original.

The current full-World context transport requires `CanReadAllLedgerData`.
Selected data space grants do not authorize its unrelated row identities and
low-entropy values; scoped authenticated context proofs remain unfinished.
Whole-network one-call qualification remains open. The fresh-process recovery
and real-network harness is
[`atomic_private_settlement_onecall`](../../integration_tests/tests/nexus/atomic_private_settlement_onecall.rs).
