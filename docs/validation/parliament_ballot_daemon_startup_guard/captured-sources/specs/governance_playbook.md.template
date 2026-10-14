# SORA Parliament Operations (V1)

This code-adjacent checklist records the first-release operating boundary for
SORA Parliament. Governance authority comes only from a closed typed proposal
and its canonical Parliament attempt reducer. There is no standing council,
detached roster, client-selected result, manual certificate, or manual
finalize/enact path. Standalone plain and ZK referenda are a separate subsystem
and cannot authorize a Parliament proposal.

## Attempt checklist

1. Submit the proposal's kind-specific instruction in an ordinary signed
   transaction. Record the immutable proposal content and the
   `ProposalSubmitted` event.
2. Send that exact typed proposal and its zero-based retry sequence to
   `POST /v1/gov/parliament/attempts/draft`. Sign and submit the returned
   `iroha.governance.parliament.attempt.create.v1` instruction. Treat
   `ParliamentAttemptCreated` as the authoritative record of the attempt id,
   policy, risk tier, effect hash, and compare-and-set head.
3. For each currently legal reducer command, use
   `POST /v1/gov/parliament/transitions/draft`, then sign and submit the returned
   `iroha.governance.parliament.transition.submit.v1` instruction. Core derives
   sortition, the required-body order, deadlines, results, retries, and
   certificate bindings from committed state. A retry must use the exact next
   attempt sequence.
4. Recover or audit state with
   `GET /v1/gov/parliament/attempts/{governance_attempt_id}` and
   `GET /v1/gov/proposals/{id}`. The attempt projection is the source of truth
   for the required bodies, public progress, retained certificate, reducer
   payload, and terminal outcome.
5. Follow accepted commands and consensus-owned outcomes through
   `ParliamentLifecycleTransitionApplied`. Its optional `certificate_id`
   identifies the automatically constructed certificate. At the exact
   enactment height Core either applies the typed effect, records `Superseded`,
   or records `ExecutionFailed`; a successful effect also emits
   `ProposalEnacted`. `ProposalRejected` records a rejected proposal. Clients do
   not submit a certificate, finalization result, or enactment command.

For each attempt, retain the typed proposal, draft response, signed transaction
hashes, `ParliamentAttemptCreated`, every
`ParliamentLifecycleTransitionApplied` event, and the final attempt projection.
Those committed records are the audit trail; local minutes, JSON envelopes, or
signer lists do not extend governance authority.

## SoraFS fixture-signing boundary

The only SoraFS-specific Parliament proposal in V1 is
`SorafsProviderGovernance`, closed over provider-owner `Establish`, `Rebind`,
and `Remove` actions. Chunker fixtures and their `manifest_signatures.json`
files are release-tooling artifacts. Their detached signatures verify the
fixture bytes; they are not Parliament votes, reducer results, certificates, or
approval envelopes, and they cannot authorize unrelated DA, moderation,
subsidy, freeze, or rollback operations.

See [`sorafs/signing_ceremony.md`](sorafs/signing_ceremony.md) for that narrow
boundary and [`../fixtures/sorafs_chunker/README.md`](../fixtures/sorafs_chunker/README.md)
for fixture verification. The reducer and Torii contracts are specified in
[`governance_pipeline.md`](governance_pipeline.md) and
[`governance_api.md`](governance_api.md).
