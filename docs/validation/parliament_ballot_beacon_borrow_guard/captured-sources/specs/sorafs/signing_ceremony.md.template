# SoraFS Parliament Governance (V1)

This note records the first-release boundary between SoraFS release artifacts
and SORA Parliament governance. Governance authority exists only through a
typed proposal, the canonical attempt reducer, and automatic certificate
execution. A `manifest_signatures.json` file is a release-tooling signature
envelope, not a Parliament governance certificate.

## Canonical governance path

The only SoraFS-specific V1 proposal kind is `SorafsProviderGovernance`. Its
payload is closed over the provider-owner `Establish`, `Rebind`, and `Remove`
actions. Other SoraFS artifacts do not acquire governance authority merely by
being placed in a fixture directory or signed by release tooling.

1. Submit `ProposeSorafsProviderGovernance` with the exact closed provider-owner
   action through the ordinary signed transaction path. `ProposalSubmitted`
   records the immutable proposal content id.
2. Draft the zero-based governance attempt with
   `POST /v1/gov/parliament/attempts/draft`, then sign and submit the returned
   `iroha.governance.parliament.attempt.create.v1` instruction.
   `ParliamentAttemptCreated` records the Core-derived attempt id, risk tier,
   policy version, effect hash, and compare-and-set head.
3. Draft each closed reducer transition with
   `POST /v1/gov/parliament/transitions/draft`, then sign and submit its returned
   `iroha.governance.parliament.transition.submit.v1` instruction. Core derives
   sortition, body order, deadlines, results, and certificate bindings; callers
   cannot supply a detached roster, manual approval, or finalization result.
4. Audit progress with
   `GET /v1/gov/parliament/attempts/{governance_attempt_id}` and proposal state
   with `GET /v1/gov/proposals/{id}`. The attempt projection includes the exact
   required bodies, public body state, retained certificate when constructed,
   terminal outcome fields, and bounded reducer payload.
5. Observe accepted commands and consensus-owned terminal outcomes through
   `ParliamentLifecycleTransitionApplied`. Certificate construction is automatic
   and is identified by that event's optional `certificate_id`; it is not a
   client transition. At the certificate's exact enactment height, Core applies
   the typed effect or records `Superseded`/`ExecutionFailed`. A successful
   effect also emits `ProposalEnacted`.

There are no public `/v1/gov/finalize` or `/v1/gov/enact` routes. Standalone
plain or ZK referendum ballots are a separate subsystem and cannot authorize a
Parliament proposal or substitute for its timed-OVN jury result.

## Fixture-signing boundary

Chunker fixtures remain ordinary checked-in release artifacts. Regenerate them
through `sorafs_chunker`'s private external staging workflow and verify
`manifest_signatures.json` with the SoraFS release tools. Do not describe those
detached signatures, local signer lists, or a Governance DAG fixture as a
Parliament certificate or reducer result.

The complete reducer contract and current Torii surface are specified in
[`governance_pipeline.md`](../governance_pipeline.md) and
[`governance_api.md`](../governance_api.md).
