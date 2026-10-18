# Iroha Torii client

## Collection queries

`iroha_torii_client.list_query` is the single Python implementation of the
Torii collection-query language (`specs/torii/collection_queries.md`); the
full `iroha_python` SDK re-exports it. Filters are built with `F` and Python
operators (parenthesize each comparison), render to the canonical text form
with `.to_text()` and to the JSON form with `.to_json()`, and are checked
against the shared golden vectors in `fixtures/torii/list_query/vectors.json`.
Raw text filters are sent unchanged; `parse_filter(text)` validates them
locally with Torii's messages and columns. Collection queries send a `Filter`
in the JSON form, which alone can carry object and array literals
(`F.metadata.tags == ["a", "b"]`, valid only against `metadata.<key>`);
`.to_text()`, `ListQuery.to_query_pairs()` and event-stream filters reject
them with `FilterError`/`invalid_filter`.

```python
from decimal import Decimal

from iroha_torii_client import F, ListQueryError, ToriiClient, ToriiError

with ToriiClient("https://taira.sora.org", timeout=10.0) as client:
    page = client.accounts.assets(account_id).list(
        filter=F.quantity >= Decimal("10.5"), sort="-quantity", limit=50
    )
    for bucket in client.asset_definitions.holders(definition_id).iter():
        print(bucket.account_id, bucket.scope, bucket.quantity)   # exact Decimal
    try:
        client.domains.list(filter="owned_by = alice")             # unquoted text value
    except ListQueryError as error:                               # HTTP 400 invalid_* too
        print(error.code, error.parameter, error)
    except ToriiError as error:                                   # status, code, details
        print(error.status, error.code, error.details)
```

Collections: `domains`, `accounts`, `asset_definitions`, `nfts`, `rwas`,
`transactions`, `repo_agreements`, `subscription_plans`, `subscriptions`,
`contract_activity`, `contract_events`, `accounts.assets(id)`,
`accounts.permissions(id)`, `accounts.history(id)`, `accounts.transactions(id)`,
`uaid_manifests(uaid)` and `asset_definitions.holders(id)`; each has
`list`, `iter`, `pages`, `rows`, `iter_rows` and `count`. Every request uses
`POST <collection>/query`, is signed when `canonical_request_auth` is
configured and is anonymous otherwise. The client applies `timeout` (default
30 seconds) to every request, never follows redirects, and closes the HTTP
session it created when used as a context manager or on `close()`. Rows
decode the fields that identify them strictly (`id`; `account_id`, `asset`,
`scope` and `quantity` for balances; `entrypoint_hash`, `block_height` and
`block_index` for transactions); every other field may be null or absent and
decodes as `None`.

Torii executes each collection query once over the caller-visible global state.
For collections that support totals and aggregates
(`rows(aggregate=AggregateSpec(...))`, `POST` only), visible rows contribute
exactly once even when they span several dataspace routes.

`subscription_plans` and `subscriptions` return flat rows keyed by `id`.
Manifest pages contain the manifest records in `items`; projections use `rows`.
Every page requires `next_cursor` (a nonempty token or null) and may include
`total` only when requested. Unknown page envelope fields are rejected.

Explorer feeds are exposed as `explorer_accounts`, `explorer_domains`,
`explorer_asset_definitions`, `explorer_assets`, `explorer_nfts`, `explorer_rwas`,
`explorer_blocks`, `explorer_transactions`, `explorer_latest_transactions`,
`explorer_instructions` and `explorer_latest_instructions`. These use the same
bounded query controls, with fixed server ordering and no totals or aggregates.
Rows retain their wire fields; snapshots and continuations live in the opaque cursor.

### History collections

`client.transactions` (every committed transaction; `POST
/v1/transactions/query` only) and `client.accounts.transactions(account_id)`
(transactions the account signed or that reference it) are history
collections of `CommittedTransaction` rows: `entrypoint_hash`, `block_height`,
`block_index`, `block_hash`, `authority`, `timestamp_ms`, `entrypoint_kind`,
`result_ok`, `asset_ids`, `asset_definition_ids` and `metadata`.

`contract_activity`, `contract_events` and `accounts.history(id)` use the same
history controls with their respective row fields. Account movement rows also
carry `movement_index`; filter by `asset_id` or `asset_definition_id` within
`filter`.

- Rows come newest first by (`block_height`, `block_index`), and each cursor
  holds block coordinates, so transactions committed while paging never shift
  later pages.
- `sort`, `include_total` and `aggregate` would scan the whole history; the
  client rejects them before any request with Torii's codes
  (`invalid_sort`, `invalid_include_total`, `invalid_aggregate`).
- Each page has a bounded history-scan budget, so a selective filter can
  return a page with fewer than `limit` rows, even none, together with a
  `next_cursor`. `iter`, `pages`, `iter_rows` and `count` keep following
  `next_cursor` until it is null; never treat a short or empty page as the
  end. `count()` pages through the matches because there is no total.
- `asset_ids` and `asset_definition_ids` match element-wise:
  `F.asset_definition_ids == definition_id` selects transactions touching that
  definition, and `!=`/`not_in` select transactions touching none.
- Bounds on `block_height` in the filter's top-level `and` also bound the
  server's scan: `(F.block_height >= 1200) & (F.result_ok == True)` reads only
  heights from 1200 up, and `F.block_height <= 1500` starts the walk at 1500.

```python
from iroha_torii_client import F

recent = client.accounts.transactions(account_id).iter(
    filter=(F.block_height >= 1200) & (F.asset_definition_ids == definition_id),
)
for tx in recent:                       # newest first; empty pages are skipped
    print(tx.block_height, tx.block_index, tx.entrypoint_hash, tx.result_ok)
```

Anonymous HTTP operations do not require a native extension. Account construction,
parsing, and governance identity checks require the matching `iroha-native` wheel
on Python 3.10 or newer. Install `iroha-torii-client[native]` for those
operations. The Rust owner validates all eleven key algorithms, complete weighted
multisig policies, and exact I105 literals. Missing native support is an explicit
error; there is no structural identity fallback or dependency on the full Python
SDK.

`get_governance_tally(referendum_id, canonical_auth=...)` returns the shared
`GovernanceTally` model, or `None` for a missing referendum. The six-field
response preserves exact `u128` approve/reject/abstain totals and the evaluated
block's `u64` height and lowercase hash. The client rejects missing fields,
numeric coercion, aggregate overflow and inconsistent block coordinates, and
consumes each response under a 4 KiB actual-byte limit.

Use the public Taira profile instead of copying its origin, address
discriminant, Digital Shekel, and XOR metadata. The deployment's exact
genesis-derived `NetworkId` remains caller-supplied because public resets can
change it:

```python
from iroha_torii_client import (
    TAIRA_TESTNET_PROFILE,
    ToriiClient,
    taira_local_signing_context,
)

client = ToriiClient(
    TAIRA_TESTNET_PROFILE.torii_base_url,
    local_signing_context=taira_local_signing_context(configured_network_id),
    orderbook_chain_discriminant=TAIRA_TESTNET_PROFILE.i105_discriminant,
)
```

The lightweight client validates native protocol-1 observations from
`GET /v1/sumeragi/status`. Configure an exact-network operator signing context
before using the authenticated reader:

```python
status = client.get_sumeragi_status()
print(status.height, status.view, status.stage)
print(status.committed_height, status.applied_height, status.halted)
```

The closed schema requires all 21 fields, including explicit nullable keys.
The parser preserves full unsigned values and validates canonical keys,
fingerprints, the beacon horizon and native halt details under a 1 MiB response
bound. The result is immutable operational observation, not a finality proof.
Retired global QC and grouped diagnostics APIs are removed. Native execution
capture parity and actual cross-dataspace settlement qualification remain open.

`get_sumeragi_lanes()` decodes the operator lane list into `SumeragiLaneStatus`.
Every record requires its committed `da_layout` RS16 encoding and resource bounds;
these observations do not confer finality.

Committed Sumeragi evidence is exposed through the authenticated
`list_sumeragi_evidence()` and `get_sumeragi_evidence_count()` reads. The
first-release JSON contract uses the closed `{kind, value}` envelope for
`NativeSumeragiEvidence` and `SccpForgeryEvidence`. Read each typed payload through
`item.value`. Native records retain their root or lane scope; SCCP records retain
the exact submitted certificate bytes, optional anchor, generation liability and
attribution. Both require a non-null consensus admission height and the closed
`pending` or `applied` penalty state. Parsing this DATA grants no signature or
historical-state authority. Missing, extra, retired flat fields and response kinds
that differ from the requested filter fail closed. Both evidence responses require
JSON media types; count is streamed under a 1 KiB client-side ceiling and list
under 1 MiB.

Use `get_status_snapshot()` for `/status`. That route remains a distinct
operational-health surface; its queue and historical lane telemetry must not be
treated as consensus-authoritative state.

Typed public pipeline metadata keeps every lifecycle kind and both exact read
scopes visible. `PipelineTransactionStatusResponse.is_authoritatively_applied`
is the sole finality-success helper: it is true only for `Applied` with
`scope == "global"` and `resolved_from == "state"`. `Committed`, local results,
and queue/cache observations are not successful finality.
Signed transaction hashes in this status surface use exact
`[0-9a-f]{63}[13579bdf]` text; the final odd nibble is the Iroha `HashOf`
marker, not a normalization option. Contract `tx_hash_hex` receipt fields use
the same exact spelling, as do contract entrypoint hashes.

The shared Torii mock returns missing pipeline status as an HTTP 404 JSON
`ErrorEnvelope` bound to the requested hash and scope. Omitted scope means
`global`; explicit `local` and `global` lookups retain their exact scope.

## Caller-trusted unsigned drafts

Contract-call bytes returned for local signing fail closed unless the client
has the exact genesis-derived `local_signing_context` and the caller supplies
an off-wire `ContractCallDraftIntent`. The generic multisig instruction proposal
API is retired from both the HTTP base client and the inheriting SDK. Each
contract-call intent contains the exact Norito executable and final merged
metadata archives plus the trusted resolved address, code hash, and request
payload digest:

```python
from iroha_torii_client import (
    ContractCallDraftIntent, ToriiCanonicalRequestAuth, contract_payload_digest_hex,
)

call_payload = {"amount": 1}
contract_auth = ToriiCanonicalRequestAuth(
    network_id=local_signing_context.network_id,
    account_id=authority,
    signer=sign_request_locally,  # Runtime-owned signer: bytes -> signature bytes.
)

draft = client.prepare_contract_call(
    canonical_auth=contract_auth,  # ToriiCanonicalRequestAuth bound to authority and local network
    authority=authority,
    contract_alias="router::universal",
    entrypoint="increment",
    payload=call_payload,
    metadata={"caller_note": "trusted"},
    creation_time_ms=created_at_ms,
    transaction_ttl_ms=100_000,
    fee_payment=quoted_fee_payment,
    draft_intent=ContractCallDraftIntent(
        executable_b64=trusted_executable_norito_b64,
        metadata_b64=trusted_final_metadata_norito_b64,
        contract_address=trusted_resolved_contract_address,
        code_hash_hex=trusted_contract_code_hash_hex,
        payload_digest_hex=contract_payload_digest_hex(call_payload),
    ),
)
```

These values must come from a trusted local builder and verified artifact/schema
path, never from the Torii response being checked. Payload hashing uses compact,
key-sorted UTF-8 JSON and rejects floats and integers outside the cross-SDK safe
range; encode decimal and wider numeric schema values as canonical strings.
Validation runs before network dispatch where possible, then binds the network,
authority, executable, metadata, response-enriched fee, creation time, TTL,
ordinary admission mode, absent nonce and attachments, and the closed operation
receipt (selector resolution, code/ABI, entrypoint, gas state, and payload
digest) before any bytes are exposed for signing.

## Node-local core and pipeline reads

Peer addresses, detailed clock state, and pipeline preflight load/policy are
operator-only. Configure a separate lightweight client with an immutable signer
bound to the deployment's exact genesis `NetworkId`:

```python
from iroha_torii_client import ToriiClient, ToriiOperatorSigningContext

operator_context = ToriiOperatorSigningContext(
    network_id=exact_genesis_network_id,
    public_key=operator_public_key_multihash,
    signer=operator_signer.sign,
)
operator_client = ToriiClient(
    "https://torii.example",
    operator_signing_context=operator_context,
)

peers = operator_client.list_peers()
clock = operator_client.get_time_status()
preflight = operator_client.get_pipeline_preflight()

relays = operator_client.list_kaigi_relays()
relay = operator_client.get_kaigi_relay(relays.items[0].relay_id) if relays.items else None
health = operator_client.get_kaigi_relays_health()
```

The preflight DTO parses exactly the fields Torii serves, rejects any other
field, exposes both current IVM cycle limits and validates every fee account
field as an exact canonical I105 account id. Alias-shaped `name@domain` values
are rejected instead of interpreted as account identity.

`preflight.sumeragi` carries only `block_cadence_ms`, the signed-genesis target
block time. Torii serves no stall threshold, so `preflight.stall_threshold_ms`
is derived as `PIPELINE_STALL_BLOCK_CADENCES` (20) × `block_cadence_ms`, and
`preflight.is_status_stalled(status)` reports a stall only when
`status.queue_size > 0` and the time since the last non-empty block (or since
the last block, before the first non-empty one) exceeds it. Twenty cadences
cover one crashed leader's view change at the Sumeragi default timings; call
`status.is_queue_stalled(threshold_ms)` directly when the deployment's local
consensus timers are known.

Each helper generates a fresh signature over the exact `GET`, path, query, and
empty body and dispatches once with redirects and retries disabled. Bearer/API
tokens, canonical-account or witness headers, and precomputed operator headers
are rejected rather than used as fallbacks; session authentication and cookies
are rejected as ambient authority too. The lightweight client has no pipeline
recovery, policy, or proof-retention method; no replacement API is invented for
those absent surfaces. Typed Kaigi responses require Torii's exact fields and
integer spellings, and relay details bind the decoded HPKE key to its advertised
marked fingerprint. Each relay snapshot is streamed through a 64 MiB
post-transfer byte bound, decoded as strict UTF-8 JSON with unique object keys,
and closed on every outcome. Kaigi list and health also require Torii's
canonical ordering and fail closed at the hard relay diagnostic cap rather than
materializing an unbounded registry; the relay SSE handshake remains a separate
streaming protocol.

## Tenant-scoped ZK attachments

Every attachment upload, list, fetch, and delete is account-authenticated. The
client signs the exact genesis-derived NetworkId, method, percent-encoded path,
query, and body and disables redirects and retries for the one-shot request:

```python
import os

from iroha_torii_client import ToriiCanonicalRequestAuth, ToriiClient

client = ToriiClient("https://torii.example")
auth = ToriiCanonicalRequestAuth(
    network_id=os.environ["IROHA_NETWORK_ID"],
    account_id=authority,
    signer=wallet.sign,
)
meta = client.upload_attachment(
    b"{}", content_type="application/json", canonical_auth=auth
)
items = client.list_attachments(canonical_auth=auth)
payload, content_type = client.get_attachment(meta["id"], canonical_auth=auth)
client.delete_attachment(meta["id"], canonical_auth=auth)
```

Use a fresh nonce per call (the default). A human chain label, foreign genesis
hash, unsigned call, redirect replay, or missing canonical auth is rejected.
Methods must be ASCII HTTP tokens and signed paths must be the exact
root-relative ASCII wire spelling. `build_canonical_request_headers` first
prepares that target with Requests and signs its `PreparedRequest.path_url`;
the client sends that same prepared request. The pure canonical-message helpers
continue to consume an already exact wire spelling. Operator header builders
and authenticated operator reads use the same prepared-target ownership.
Signer callbacks return 1--3,309 non-zero
signature bytes. The complete `0x` account-header prefix is reserved for
canonical address hex and is never emitted for an alias. Alias headers receive
only a bounded lowercase-ASCII structural preflight; Torii remains authoritative
for UTS-46, active-catalog resolution, and controller verification. The public Python client is signer-only: it neither forwards an
externally constructed `X-Iroha-Witness` nor constructs a typed multisignature
witness end to end.

Space Directory publish/revoke drafts follow the same contract and additionally
require the exact canonical I105 payload authority to equal `auth.account_id`:

```python
from iroha_torii_client import ToriiClient, ToriiLocalSigningContext

client = ToriiClient(
    torii_url,
    local_signing_context=ToriiLocalSigningContext(exact_network_id),
)
draft = client.publish_space_directory_manifest(
    authority=authority,
    manifest=manifest,
    canonical_auth=auth,
)
client.revoke_space_directory_manifest(
    authority=authority,
    uaid=uaid,
    dataspace=11,
    revoked_epoch=42,
    canonical_auth=auth,
)
```

## Fee quotes and sponsor programs

Transaction signing is quote-first. Build one complete unsigned payload with a
required typed `fee_payment`, then account-sign the quote request with the same
authority:

```python
import os

from iroha_torii_client import ToriiCanonicalRequestAuth

auth = ToriiCanonicalRequestAuth(
    network_id=os.environ["IROHA_NETWORK_ID"],
    account_id=authority,
    signer=wallet.sign,
)
program = client.get_fee_sponsor_program(
    f"{sponsor_account}/wallet_payments",
    canonical_auth=auth,
)
quote = client.quote_fees(unsigned_payload, canonical_auth=auth)
```

For sponsorship, `unsigned_payload["fee_payment"]` must name the exact program
and non-zero immutable revision. Verify that `quote["intent"]` preserves the
payer, program/revision, and gas bound, replace only that field, then sign and
submit the unchanged payload. The client does not infer a sponsor, reserve a
quote, or fall back to the authority. Legacy transaction metadata keys
`fee_sponsor`, `gas_asset_id`, and `gas_limit` are rejected.
`IROHA_NETWORK_ID` must be the canonical checksummed hash literal generated
from the deployment genesis; a display chain label is never accepted as a
signing domain.

## Atomic private settlement transport

The Python SDK exposes the complete V1 Torii route set without accepting proof
witnesses or audit plaintext. A native wallet or coordinator first produces a
bounded JSON object for one closed operation. Python validates its exact
top-level shape, signs the final route, sends it once with redirects and retries
disabled, and returns an opaque response that can be handed back to native code:

```python
from iroha_torii_client import (
    AtomicPrivateSettlementOperationV1,
    AtomicPrivateSettlementPreparedRequestV1,
)

prepared = AtomicPrivateSettlementPreparedRequestV1.from_native_prepared_json(
    AtomicPrivateSettlementOperationV1.LEG_UPLOAD,
    native_coordinator.prepared_leg_upload_json(),
)
try:
    response = client.upload_private_settlement_leg_v1(
        prepared,
        canonical_auth=sponsor_auth,
    )
    try:
        native_coordinator.accept_torii_response(response.bytes())
    finally:
        response.close()
finally:
    prepared.close()
```

Availability, Prepare, Commit, certificate persistence, leg upload, and global
carrier submission use the sponsor's canonical account signature. Committee
proof reads require the exact validator operator identity; capsule reads and
approval submission require the exact governed auditor identity. Bundle status
and receipt reads are public and expose only the protocol allowlist.

Prepared requests are operation-bound and retained in erasable buffers. Their
representations and all transport errors redact bodies. Restricted responses
remain opaque, bounded, strict UTF-8 JSON; unexpected fields, identifier
substitution, redirects, compressed responses, and noncanonical hash literals
fail closed. The network must still have the governed feature activated and
the audited proof profile available. This SDK surface is not evidence that a
deployment has passed the independent audit or production qualification gates.

## SORA Parliament V1

The account-authenticated Parliament surface is available through strict V1
methods for readiness, attempt drafting and reading, and lifecycle transition
drafting. Draft callers supply the independently derived IDs or transition
digest that the response must match before an instruction is exposed for
signing:

```python
capabilities = client.get_governance_capabilities_v1(canonical_auth=auth)
draft = client.draft_parliament_attempt_v1(
    proposal,
    attempt_sequence=0,
    expected_proposal_content_id=proposal_content_id,
    expected_governance_attempt_id=governance_attempt_id,
    canonical_auth=auth,
)
attempt = client.get_parliament_attempt_v1(
    governance_attempt_id, canonical_auth=auth
)
```

Parliament requests reject ambient session auth headers, cookies, and
`Session.auth`, and suppress Requests' environment/netrc credential fallback
during preparation.

Attempt reads whose certificate contains a private-jury body (`policy-jury` or
`confirmation-jury`) are rejected: the anonymous-ballot result binding is not
supported yet, so this client admits no certificate that covers a private-jury
body.

## Signed SoraFS orderbook submission

The lightweight client exposes the three signed orderbook submit routes only
with an explicitly injected native verifier:

```python
from iroha_torii_client import SorafsOrderbookSubmissionAmbiguousError, ToriiClient

client = ToriiClient(
    "https://torii.example",
    orderbook_native_verifier=trusted_native_provider,
    orderbook_chain_discriminant=369,
)
receipt = client.submit_sorafs_orderbook_order(
    signed_transaction_bytes,
    expected_network_id=network_id,
    expected_receipt_signer=torii_receipt_public_key,
)
```

The provider must implement
`inspect_sorafs_orderbook_submission_for_discriminant_v1(...)` and
`verify_sorafs_orderbook_submission_receipt_v1(...)`. Without both, or without
the exact expected network, deployment I105 chain discriminant, and receipt
signer, submission fails before HTTP.
The strict route requires a canonical HTTPS base URL, snapshots an exact stock
`requests.Session`, and constructs its own zero-retry adapter. It sends only
qualified explicit headers/proxies/`verify`/`cert`, ignores `trust_env`, netrc,
environment proxy/CA discovery, hooks, cookie persistence, and Requests elapsed
timing, and rejects custom sessions, ambient cookies, or mutable transport
configuration. Its positive timeout (30 seconds by default) is a Requests
connect/read inactivity timeout, not an absolute deadline: a slow drip may
exceed that wall time.
After dispatch, catch `SorafsOrderbookSubmissionAmbiguousError`, reconcile its
payload-free `expected_identity` against finalized state, and never resubmit
automatically. The full `iroha_python.ToriiClient` supplies this native provider
and derives the expected network from its local signing context.

Account identity construction, canonical parsing, and controller checks require the
separate `iroha-native` wheel (`pip install iroha-torii-client[native]`). These
operations use its ABI-30 Rust owner for all eleven curves and full weighted
multisig policies. Missing native validation is an explicit error; anonymous HTTP
transport can operate without loading the native package.
