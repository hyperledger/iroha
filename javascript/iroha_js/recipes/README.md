# Recipes

This source-checkout directory hosts JavaScript snippets that illustrate common
`@iroha/iroha-js` workflows. Each example favours deterministic Norito payloads
and mirrors the validation logic exported by the SDK. The portable registry
tarball includes only `iso_bridge_builder.mjs` and `nexus_app_transfer.mjs`;
examples that require a source checkout, credentials, or a live Torii endpoint
are identified below. The Nexus recipe requires the verified native host even
when installed from that tarball.

## batching.mjs

- Shows how to assemble multi-instruction transactions with explicit mint,
  transfer, and burn steps while keeping instruction ordering deterministic.
- Highlights the helper builders that normalise quantities and asset IDs before
  handing instructions to the generic `buildTransaction` helper.
- Prints the resulting transaction hashes so you can compare deterministic
  output across environments before submitting to Torii.

Run with:

```bash
npm install
npm run build:native
node ./recipes/batching.mjs
```

The script uses deterministic sample key material; replace the sample
authority/account values with real identities before attempting to submit
transactions on a live network.

## nexus_app_transfer.mjs

- Runs the Nexus App facade from approval through canonical native-codec
  finalization, Torii submission, and exact state-resolved Applied finality.
- Requires Node and the SDK's verified native binding for account validation
  and canonical transaction encoding. Missing bindings reject the operation
  before wallet signing or submission.
- Uses deterministic fake Connect and Torii dependencies to check the exact
  payload and signed-transaction hashes without network requests.

From a source checkout, run:

```bash
npm install
npm run build:native
node ./recipes/nexus_app_transfer.mjs
```

For an installed package, install its matching verified platform binding before
running this recipe. The portable tarball alone does not supply native codecs.

## nft_account_iteration.mjs

- Reads the NFTs an account owns (`torii.nfts.list` with an `owned_by` filter)
  and iterates its asset balances (`torii.accountAssets(id).iterate`) with a
  text filter (`quantity >= 1`) and a `select` projection.

Run with:

```bash
npm install
TORII_URL=http://127.0.0.1:8080 \
ACCOUNT_ID=sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB \
TORII_AUTH_TOKEN=token \
TORII_ALLOW_INSECURE=1 \
node ./recipes/nft_account_iteration.mjs
```

Environment variables:

- `TORII_URL` — Torii endpoint (defaults to `http://127.0.0.1:8080`).
- `ACCOUNT_ID` — account literal for the asset iterator.
- `TORII_AUTH_TOKEN` / `TORII_API_TOKEN` — credentials for permissioned Torii.
- `TORII_ALLOW_INSECURE=1` — allow HTTP even when credentials are attached.

## iso_bridge.mjs

- Demonstrates ISO 20022 pacs.008 / pacs.009 submission via
  `ToriiClient.submitIsoPacs008AndWait` / `submitIsoPacs009AndWait`, and shows
  how to reuse `waitForIsoMessageStatus` when you already have a `message_id`.
- Highlights how to provide XML payloads, override polling cadence through env
  variables, opt into resolving when the bridge reports `Accepted`, and inspect
  pacs.002 codes, ledger hashes, and account hints surfaced by the bridge.

Run with:

```bash
npm install
ISO_NETWORK_ID="$NETWORK_ID" ISO_OPERATOR_SIGNER_MODULE=/path/to/runtime-signer.mjs \
ISO_MESSAGE_ID=existing-message node ./recipes/iso_bridge.mjs
```

Environment variables:

- `TORII_URL` — Torii endpoint with the ISO bridge enabled.
- `ISO_MESSAGE_KIND` — switch between `pacs.008` (default) and `pacs.009`.
- `ISO_POLL_ATTEMPTS` / `ISO_POLL_INTERVAL_MS` — control wait cadence.
- `ISO_MESSAGE_ID` — skip submission and wait on an existing message.
- `ISO_RESOLVE_ON_ACCEPTED=1` — stop polling on reported `Accepted` without a carrier hash; this does not verify settlement.
- `ISO_NETWORK_ID` — exact canonical selected-network hash literal.
- `ISO_OPERATOR_SIGNER_MODULE` — runtime module whose default export has `publicKey` and `sign(message)`; the existing `OperatorSigningContext` binds each fresh request to `ISO_NETWORK_ID`. Keep signer keys outside the repository and config documents. API tokens do not replace operator signatures.
- For a new payment, supply `ISO_UETR`, `ISO_EXPIRES_AT_HEIGHT`, `ISO_SOURCE_ACCOUNT_ID`, `ISO_TARGET_ACCOUNT_ID`, and `ISO_ASSET_DEFINITION_ID`. These are payer-approved, retained business terms; the recipe never invents them. Use the same UETR and exact terms across retries.

The sample payment helpers fill demo envelope, amount, and IBAN fields. Configure
matching ledger identities and bridge bindings before using those samples. Use
`iso_bridge_builder.mjs` for explicit production payment fields. Both recipes
report node status; they do not return independently verified monetary receipts
or authorize customer credit.

## iso_alias.mjs

- Demonstrates both literal (IBAN-style) and indexed lookups via
  `resolveAlias` / `resolveAliasByIndex`.
- Surfaces 404 vs runtime-disabled responses and highlights the account bindings returned by the alias
  APIs so ISO bridge drills can run without bespoke tooling.

Run with:

```bash
npm install
TORII_URL=https://torii.testnet.sora \
ISO_ALIAS_LABEL="GB82 WEST 1234 5698 7654 32" \
ISO_ALIAS_INDEX=0 \
node ./recipes/iso_alias.mjs
```

Environment variables:

- `ISO_ALIAS_LABEL` — resolve a literal alias; omit to skip the lookup.
- `ISO_ALIAS_INDEX` — decimal or `0x`-prefixed index for deterministic lookups.
- `TORII_AUTH_TOKEN` / `TORII_API_TOKEN` — optional headers for secured Torii deployments.

## iso_bridge_builder.mjs

- Uses `buildPacs008Message` / `buildPacs009Message` to translate structured
  settlement parameters (BIC/LEI identifiers, IBANs, purpose codes, and
  supplementary data) into deterministic ISO 20022 XML.
- Accepts overrides via environment variables or a JSON config
  (`ISO_BUILDER_CONFIG=/path/to/options.json`) so you can feed the script with
  production reference data.
- Prints the generated payload by default and submits it to Torii when
  `ISO_SUBMIT=1`, reusing the same wait options as `iso_bridge.mjs`.

Run with:

```bash
npm install
ISO_BUILDER_CONFIG=/path/to/retained-payment.json \
  node ./recipes/iso_bridge_builder.mjs
```

The JSON config uses `BuildPacs008Options` / `BuildPacs009Options`, with
`nexusSettlement.networkId` as its exact canonical string. It must retain `uetr`,
`expiresAtHeight`, `sourceAccountId`, `targetAccountId`, and `assetDefinitionId`;
the latter four are nested inside `nexusSettlement`. Generic supplementary JSON
remains metadata and cannot replace these terms. `ISO_DRY_RUN=1` only prints XML,
including when `ISO_SUBMIT=1`; actual submission requires the runtime signer.

Environment variables (in addition to the common `ISO_*` knobs above):

- `ISO_DEBTOR_AGENT_BIC` / `ISO_DEBTOR_AGENT_LEI` — optional debtor agent BIC + LEI injected as
  `DbtrAgt`. Omit to rely on the instigating agent.
- `ISO_CREDITOR_AGENT_BIC` / `ISO_CREDITOR_AGENT_LEI` — optional creditor agent records (`CdtrAgt`).
- `ISO_DEBTOR_NAME`, `ISO_DEBTOR_LEI`, `ISO_DEBTOR_ID`, `ISO_DEBTOR_ID_SCHEME` — emit a debtor
  party (`Dbtr`) with a legal name, optional LEI, and proprietary identifier. Leave unset to skip.
- `ISO_CREDITOR_*` — mirrors the debtor fields for the creditor party (`Cdtr`).
- `ISO_SUPPLEMENTARY_JSON` — canonical JSON merged into `SplmtryData` (useful for Norito metadata).

Structured overrides supplied via `ISO_BUILDER_CONFIG` can include the same
`BuildPacs008Options` / `BuildPacs009Options` fields (agents, parties, accounts,
purpose codes, supplementary data). The script deep-merges nested objects so
JSON files can override just a subset of identifiers without rewriting every
field.

## streaming.mjs

- Streams `/v1/events/sse` with a collection-query filter over event fields
  (`tx_status = "Approved"` by default) and prints the typed payloads
  (`category`, `event`, `status`, rejection code and reason).
- Treats the endpoint as live-only: reconnects start a new subscription and may have a gap.
- Stops at the terminal `stream_error` frame, which reports that the live stream lost events.

Run with:

```bash
npm install
node ./recipes/streaming.mjs \
  TORII_URL=https://torii.nexus.example \
  PIPELINE_STATUS=Approved \
  STREAM_MAX_EVENTS=25
```

Environment variables:

- `STREAM_FILTER` — override the filter with text such as
  `tx_status in ["Approved", "Rejected"] and tx_dataspace_id = 0`; it is
  parsed locally first, so syntax errors report their column before connecting.
  Torii accepts `=`/`in` on event fields, `and`/`or`, `not tx_status = ...` and
  `tx_block_height is null`.
- `PIPELINE_STATUS` — change the transaction status the default filter matches
  (`Queued`, `Expired`, `Approved` or `Rejected`). This does not configure
  transaction finality; waits still require exact global, state-resolved `Applied`.
- `STREAM_MAX_EVENTS` — stop after N events (`0` keeps the iterator running until interrupted).
- `TORII_API_TOKEN` / `TORII_AUTH_TOKEN` — optional headers for locked-down Torii deployments.

## assets_iterators.mjs

- Iterates NFTs (`torii.nfts.iterate`, optionally filtered to one id) and an
  account's asset holdings (`torii.accountAssets(id).iterate`, sorted by
  asset). The iterators follow `next_cursor`; `PAGE_SIZE` sets the page size
  and `MAX_ITEMS` stops early.

Run with:

```bash
npm install
TORII_URL=http://localhost:8080 \
ACCOUNT_ID=sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB \
NFT_ID=61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D \
PAGE_SIZE=25 \
MAX_ITEMS=100 \
TORII_ALLOW_INSECURE=1 \
node ./recipes/assets_iterators.mjs
```

Environment variables:

- `TORII_URL` — Torii endpoint (defaults to `http://localhost:8080`).
- `ACCOUNT_ID` — account literal for asset iteration.
- `NFT_ID` — optional canonical NFT/asset-holding id (`<base58-asset-definition-id>#<i105-account-id>`) to filter on (exact match).
- `PAGE_SIZE` / `MAX_ITEMS` — pagination controls.
- `TORII_API_TOKEN` / `TORII_AUTH_TOKEN` — credentials for permissioned nodes.
- `TORII_ALLOW_INSECURE=1` — allow HTTP while sending credentials (dev/test only).

## governance.mjs

- Builds sample transactions for governance flows (propose deploy and cast a
  standalone plain ballot) using the SDK builders.
- Prints deterministic hashes for each transaction; optionally submits them to
  Torii when `GOV_SUBMIT=1`.
- When `GOV_FETCH=1`, reuses the new `ToriiClient` governance helpers to fetch proposals, tallies,
  locks, and unlock stats so you can inspect live state after submitting transactions.
- Parliament finalization, certificate derivation, and exact-height enactment are
  automatic protocol work; the recipe does not expose public finalize/enact calls.

Run with:

```bash
npm install
npm run build:native
node ./recipes/governance.mjs
```

Set `TORII_URL`, `NETWORK_ID`, `AUTHORITY`, and `PRIVATE_KEY_HEX` (32- or 64-byte Ed25519 key)
when submitting to a live node. Ensure the authority holds the necessary
governance permissions before enabling `GOV_SUBMIT=1`.

When fetching governance state, provide the identifiers you want to inspect via
`GOV_PROPOSAL_ID`, `GOV_REFERENDUM_ID`, and optionally `GOV_LOCKS_ID`
(defaults to `GOV_REFERENDUM_ID`). Example:

```bash
GOV_FETCH=1 GOV_REFERENDUM_ID=demo-referendum node ./recipes/governance.mjs
```

## soradns.mjs

- Uses the deterministic host helper to derive canonical/pretty hosts for a
  SoraDNS FQDN without contacting a gateway.
- Validates the host patterns advertised by a Gateway Authorisation Record
  (GAR) so operators can confirm the canonical host, wildcard, and pretty host
  are all authorised before dialing.
- Prints the normalized name, canonical label, host patterns, and GAR coverage
  result for troubleshooting.

Run with:

```bash
npm install
npm run build:native
node ./recipes/soradns.mjs docs.sora --gar-patterns hash.gw.sora.id,*.gw.sora.id,docs.sora.gw.sora.name
```

The script also respects `SORADNS_NAME` and `SORADNS_GAR` environment variables
when you want to avoid passing command-line arguments.

## confidential_redemption.mjs

This source-only recipe uses OS randomness, `ConfidentialProver` and the native
`computeConfidentialRoot` helper for a locally verified full-redemption proof.
It closes the wallet while the accepted native job runs and reports event-loop
progress. It creates no ledger note and submits no transaction; a computed local
root does not establish ledger authorization. Rebuild the verified native addon
from this source, then run `node recipes/confidential_redemption.mjs`.
