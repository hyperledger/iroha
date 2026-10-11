# Torii first-release API contract

Torii publishes one application API under `/v1`. Because this is the first
release, clients do not negotiate minor protocol versions and the server does
not carry compatibility routes or DTOs for earlier pre-release designs.

The former `x-iroha-api-version` request header and the API-version response
headers are not part of the contract. Torii ignores unknown request headers in
the usual HTTP manner. `/v1/api/versions` is unmounted, and proof endpoints are
available according to their authentication and rate-limit policies without a
separate minimum-version gate.

`GET /v1/api/version` remains a node-information endpoint. It reports the
active block-header/genesis version; it does not select an HTTP API variant.

## Request-target normalization

Route matching is strict and case-sensitive. Torii does not redirect or alias
trailing slashes. A non-root path ending in `/` is a typed `404
route_not_found`, including a wildcard route with an empty tail. Duplicate
slashes, raw backslashes, percent-encoded `/` or `\` (`%2f` or `%5c`, in any
hexadecimal case), and literal or percent-encoded dot segments are rejected as
`400 request_path_invalid` before a selected handler runs. These rules prevent
reverse proxies and application routers from assigning different meanings to
the same request target.

## Representation negotiation

Representation negotiation is independent of API evolution. Typed endpoints
emit exactly `application/json` and `application/x-norito`. A concrete
structured-suffix type such as `application/problem+json` or
`application/vnd.api+json` is a different representation and does not select
Torii's `application/json` mapping. `application/*` and `*/*` still match by
the ordinary wildcard rules. Supported media-type parameters do not change the
selected representation, so `application/json; charset=utf-8` is JSON.

Torii evaluates each supported representation against the most-specific
matching `Accept` range: an exact type takes precedence over `application/*`,
which takes precedence over `*/*`. That range's `q` value is the effective
quality, including `q=0`; a wildcard cannot re-enable a representation that an
exact range forbids. Torii then compares effective quality, followed by
specificity. An equal explicit preference selects Norito. A wildcard-only tie
and a missing `Accept` select JSON, the default representation, so ordinary
HTTP clients (curl, browsers, `fetch`, Go, Java and Rust HTTP stacks) read JSON
without negotiating; Norito clients request `application/x-norito`
explicitly. Error responses use the representation the success response would
have used. Invalid or out-of-range quality values,
duplicate `q` parameters, quality values with more than three fractional
digits, or a request that permits neither representation return
`406 Not Acceptable`. Repeated `Accept` field lines are combined in wire order
as one comma-separated field before negotiation; the first equally specific
range determines a representation's effective quality. Unsupported media
ranges are ignored unless no supported representation remains.
Because no representation was successfully negotiated, the `406` itself uses
the shared typed error envelope in deterministic `application/json` form.
Negotiated responses include `Vary: Accept`.

This typed negotiation layer does not pre-empt protocol-native safe requests.
For `GET`, `HEAD`, and other safe methods, Torii lets the selected handler
advertise its actual response media type. If that type is JSON or Norito, Torii
still enforces the representation rules above before returning the response.
For SSE, Prometheus, raw content, and other native HTTP media, Torii validates
the actual response `Content-Type` against exact, type-wildcard, and global
wildcard ranges with the same specificity and `q=0` rules. WebSocket handlers
retain their upgrade and subprotocol rules because a successful upgrade has no
ordinary response `Content-Type`.
Unsafe commands are rejected with `406` before their handler runs, so an
unacceptable response preference can never produce a hidden state change.

The following examples are normative for typed endpoints:

| `Accept` | Result |
| --- | --- |
| omitted | `application/json` |
| `application/json, application/x-norito` | `application/x-norito` (equal explicit preference) |
| `application/json;q=0.8, */*;q=0.9` | `application/x-norito` (JSON's exact range fixes its quality at 0.8) |
| `application/x-norito;q=0, */*;q=1` | `application/json` (the exact zero forbids Norito) |
| `application/*;q=0.7` | `application/json` (a wildcard-only tie uses the JSON default) |
| `application/vnd.api+json` | `406`; Torii emits `application/json`, not the requested vendor representation |
| `image/png` | `406` with a JSON `ErrorEnvelope` whose code is `response_not_acceptable` |

Typed request bodies require `Content-Type`. A request body uses exactly
`application/json`, optionally with one `charset=utf-8` parameter, or the
parameter-free `application/x-norito`; suffix JSON and wildcard media ranges
apply to response negotiation only. Unsupported or missing types return `415
Unsupported Media Type`, while an empty, malformed, or schema-invalid body
under a supported type returns `400 Bad Request`. Because `Content-Type` is a
singleton field, repeated, non-ASCII, or syntactically invalid values return
`400 request_content_type_invalid` before a command handler runs. Request
decoding never sniffs bytes and never falls back to a whole-payload base64
wrapper. Negotiation failures, typed extractor
rejections, and handler errors use the shared typed error envelope whenever a
response representation can be selected. Router path and method misses are
typed application errors; protocol streams remain documented transport
exceptions after stream establishment.

`POST /v1/mcp` is a JSON-only boundary and applies the same canonical JSON
`Content-Type` rule before collecting its JSON-RPC body. There is no bodyless
capability document: `GET /v1/mcp` returns `405 Method Not Allowed`. CORS
preflight remains bodyless and does not require `Content-Type`.

Structured query DTOs accept an absent query as an empty object. A present
query is limited to 64 KiB and 64 unique, non-empty `key=value` pairs; empty
segments and duplicate decoded keys return `400 request_query_invalid`, and a
type mismatch names the offending parameter. Components use ordinary RFC 3986
/ HTML-form encoding: `+` and `%20` are both spaces, escapes may use either
hexadecimal case and may escape any byte, and a value may contain `=` after the
first separator. Spaces, control characters and non-ASCII bytes must be
percent-encoded. Decoded keys and values must be UTF-8 without control
characters. Duplicate detection, caching and request signatures all operate on
the decoded pairs, so alternate spellings of one component are the same
request. Collection endpoints decode their controls as described in
[collection queries](collection_queries.md). Scalar coercion recognizes only
lowercase `null`, `true`, `false`, and canonical base-10 integers; aliases,
whitespace, floats, and exponents remain strings. Only explicitly documented
protocol parsers may define different or repeated-key semantics.

SoraFS readback queries are schema-closed. Their numeric fields use canonical
unsigned decimal text, page limits must be within the documented range, and
unknown keys, empty segments, duplicates, and percent-encoded aliases return
`400` instead of being ignored or clamped.

## Errors and correlation

Application errors use the closed `ErrorEnvelope { code, message, details? }`
DTO in the selected JSON or Norito representation. `code` is the stable value
for SDK logic. It is 1–64 lowercase ASCII letters, digits, or underscores,
starts with a letter or digit, and is never a namespaced free-form string.
`message` is exact, non-empty human-readable text of at most 1024 Unicode
characters with no surrounding whitespace or control characters; it may be
reworded between builds. `details` is the
documented `ErrorDetails` record, not an arbitrary JSON object; it contains only
the reusable typed fields declared by the shared Torii model. Clients must
ignore detail fields they do not understand and must handle an unknown `code`
as a non-success without matching `message` text.

`details` is absent when an error has no structured context. When present, it
is a closed record whose optional members have these meanings:

| Member | Meaning |
| --- | --- |
| `layer` | bounded public layer that produced the error |
| `reject_code` | protocol or domain rejection identifier |
| `queue` | typed queue-depth/capacity snapshot |
| `retry_after_seconds` | whole-second retry delay, matching `Retry-After` when that header is present |
| `endpoint` | endpoint path or bounded endpoint group associated with the rejection; never a query string or credential |
| `field`, `expected`, `actual` | field-validation context; values must not contain secrets |
| `profile`, `chain_discriminant` | selected network-profile context |
| `entrypoint_hash` | canonical transaction-entrypoint identity for admission and durability outcomes |
| `tx_hash`, `last_status` | signed-transaction/finality context |
| `hint` | human-readable remediation hint, not a stable SDK discriminator |
| `axt` | typed AXT rejection record |

No error code may place an undocumented object, array, or scalar behind
`details`. Adding a new detail member after `/v1` publication follows the DTO
evolution rules below; it is not an escape hatch for dynamic payloads.
Every textual detail is exact, non-empty, free of control characters, and
bounded to 1024 Unicode characters. `reject_code` and `axt.code` instead use a
1–128 byte ASCII identifier grammar consisting of letters, digits, `_`, `-`,
`.`, and `:`. Values that do not satisfy these public grammars are omitted at
the response boundary; they are never truncated into a second identifier.

One finite response-boundary rule enforces this contract for every ordinary
public, operator, diagnostic, router, authentication, rate-limit, timeout, and
handler `4xx` or `5xx` response. A response that already declares JSON or
Norito is preserved only when its body decodes as `ErrorEnvelope`; a bare
status, empty body, ad-hoc JSON object, malformed typed body, or error body
larger than 256 KiB is replaced with the generic envelope for its HTTP status.
The rejected body is not copied into the replacement message or details. An
invalid public `code` is likewise replaced with the generic status code; the
rejected identifier may be retained only when it independently satisfies the
bounded typed `reject_code` grammar.
An otherwise decodable envelope with an invalid `message` retains its valid
stable code but receives the generic human-readable message for that HTTP
status.
Canonical error responses remove incompatible content encodings, advertise
their exact `Content-Length`, and carry `Vary: Accept`. A `HEAD` error advertises
the length of the corresponding typed representation but emits no body.

Merely belonging to the protocol surface or declaring a non-JSON media type
does not bypass body normalization. A finite protocol-native error must match
an explicit reviewed allowlist entry, including route, status, media type, and
protocol discriminator. The current allowlist contains only a `400` SSE resume
rejection on the catalogued global or contract SSE route with
`Content-Type: text/event-stream` and
`X-Iroha-Stream-Error: stream_resume_unsupported`; telemetry records the same
stable `stream_resume_unsupported` code. An unmarked response or a response
whose marker appears on another route is replaced by the ordinary typed
envelope. Errors after a stream has started follow that stream's terminal
framing instead of the finite HTTP envelope.

The current KAGEMUSHA wallet route is the canonically authenticated private
`GET /v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}` issuance read. It
returns only the payer's finalized canonical Norito load body and voucher,
requires `Accept: application/x-norito`, and keeps responses private with
`Cache-Control: private, no-store`. The route is enabled by `app_api` and projected to
the SDK; it has no OpenAPI or MCP projection. The retired readiness, top-up,
redeem, operation-status and ordinary-wallet routes remain absent. Clients
must not use `/health` or `/readyz` as a wallet-feature admission gate; Torii
has no per-asset readiness response or selector query.

Every HTTP response carries `X-Request-Id`. A client may supply an identifier
containing 1–128 ASCII letters, digits, `-`, `_`, `.`, or `:`; Torii echoes it.
Invalid or absent identifiers are replaced with a unique 64-character
lowercase hexadecimal identifier. Operators use this header to correlate
router, authentication, rate-limit, timeout, panic-boundary, and handler logs.
It is correlation metadata, not an authorization or idempotency token.

Framework failures use the same contract: `404` uses `route_not_found`, `405`
uses `method_not_allowed` and includes `Allow`, oversized typed bodies use
`413 request_payload_too_large`, timeouts use `408 request_timeout`, and an
unexpected panic is contained as `500 internal_server_error` without exposing
panic text. Authentication failures use `401 api_token_required` with
`WWW-Authenticate`. When token authentication is enabled, the request must
carry exactly one `X-API-Token`; repeated fields fail closed even when every
value is individually valid. A node configured to require API tokens but
containing no tokens reports `503 api_token_unavailable`. Every canonical
finite `429` or `503` response includes both `Retry-After` and a matching typed
retry hint.

Connection-level pre-authentication capacity and rate gates run before
credential validation.

Every typed `POST /v1/soracloud/*` operation has its own sealed route-local
canonical-account boundary. Torii bounds the exact body and authenticates its
method, path, exact runtime `NetworkId`, freshness nonce, and account signer
before a typed extractor or SoraCloud handler runs; the same verified principal
then feeds the account-and-route rate gate before the global in-flight gate.
`Origin` remains CORS metadata, not an authenticated rate-limit identity:
changing or spoofing it cannot manufacture another mutation bucket. The route
catalog marks ciphertext queries as bounded reads and all retained or
ledger-changing commands as mutations. Uploaded-model V1 is registry-only; no
private execution or receipt route is cataloged.
This rule does not apply to the separately cataloged public-runtime gateway
exceptions below.

Those admission and authentication failures also take precedence over strict
`Accept` coalescing and negotiation. A syntactically valid supported `Accept`
preference is honored for the primary rejection; malformed, non-ASCII, or
unacceptable preferences receive that rejection as deterministic JSON rather
than replacing it with `406`. Once authentication succeeds, the ordinary
negotiation algorithm applies and malformed or unacceptable `Accept` input
fails with `406 response_not_acceptable` before a command handler runs.

## Reviewed protocol exceptions

These endpoints do not imply SDK or MCP generation. They are explicit media or
transport exceptions to the ordinary typed HTTP operation model. “Restricted
on the public listener” describes the current deployment topology: Torii has a
single listener today, and operator/diagnostic boundaries are enforced by
authentication and network policy rather than by claiming a separate socket.

| Method/path or family | Surface and exposure | Media/protocol | Authentication | Reason |
| --- | --- | --- | --- | --- |
| `GET /health` | protocol, public | framework health response | deployment policy | load-balancer probe |
| `GET /status`, `GET /status/blocks`, `GET /status/peers` | diagnostic, restricted on the public listener | root status negotiates JSON or canonical Norito; exact probes are JSON integers | CIDR/API-token and network policy | root status plus exact infrastructure probes; never an SDK or MCP tool |
| `GET /metrics` | diagnostic, restricted on the public listener | Prometheus text | CIDR/API-token policy | scraper protocol; never an SDK or MCP tool |
| `GET /debug/pprof/profile` | diagnostic, restricted on the public listener | profiler bytes | CIDR/API-token policy | diagnostic artifact |
| `GET /openapi.json`, `GET /v1/schema` | protocol documentation | JSON document | deployment policy | schema/document endpoints are JSON-only; the extensionless OpenAPI alias is not part of V1 |
| `POST /v1/mcp` | protocol | MCP Streamable HTTP JSON-RPC | bounded nested-route boundary which preserves the selected catalog route's exact authentication and admission | tool transport, not an ordinary generated REST operation; GET returns 405 because no SSE stream is provided |
| `GET /v1/ledger/block/{height}` and `GET /v1/ledger/block/{height}/proof/{entry_hash}` | public, OpenAPI and SDK | exact `application/x-norito` cryptographic carrier | listener policy | the executed `SignedBlockWire` and `BlockProofs` bytes must not be projected through a separately evolving JSON shape; the block carrier is finalized-state-bound and limited to 32 MiB |
| `POST /v1/operator/auth/{registration,login}/{options,verify}` | operator, OpenAPI only | WebAuthn JSON | mTLS plus handler-enforced first-credential operator-token bootstrap or authenticated session, rate-limit, lockout, and WebAuthn challenge policy; listener API tokens are not accepted | credential exchange cannot require an already-established operator request signature; after initial enrollment only a session may add rollover credentials; it never enters SDK or MCP projections |
| `GET /v1/operator/auth/credentials`, `DELETE /v1/operator/auth/credentials/{credential_id}` | operator, OpenAPI only | closed credential-metadata JSON | exact-network operator request signature plus mTLS and a valid WebAuthn session; listener API tokens are not accepted | inventory and revocation only; verification keys are never returned and these operations never enter SDK or MCP projections |
| `GET /v1/content/{bundle}/{*path}` and hosted-site reads | protocol | manifest-selected content type, ranges | content policy | raw/static content delivery; an empty wildcard is not a bundle-root alias |
| any method on `/api` or `/api/{*tail}` with the registered alias or Taira Mon alias in `Host` | protocol | proxied SoraCloud HTTP runtime | no route-specific credential; listener-wide API-token and gateway rate/inflight policy apply | reviewed host-routed public-runtime gateways; path-encoded aliases are rejected and these are not OpenAPI, SDK, or MCP operations |
| query-projection, attachment, and SoraFS export reads documented as binary | operator/protocol | `application/octet-stream` or declared artifact media | route policy | exact binary artifacts |
| `/v1/events/sse`, `/v1/contracts/events/sse`, the documented `*/events/stream` and explorer/governance SSE routes | protocol stream | `text/event-stream` | route policy | long-lived SSE cannot switch to an HTTP error envelope after establishment |
| `/v1/events/ws`, `/v1/blocks/stream`, `/v1/connect/ws`, and documented `*/events/ws` routes | protocol stream | WebSocket upgrade/subprotocol | route policy | bidirectional framed protocol; peer transport is not exposed through Torii |
| Norito-RPC ingress | protocol | Norito-RPC framing | staged ingress policy | RPC transport has its own gate errors and retry contract |

The canonical event/block handshake, ordering, heartbeat, lag, reconnect, and
close-code rules are specified in [the Torii streaming contract](streaming.md).

### Operator WebAuthn exchange

The four operator-authentication operations accept at most 64 KiB of JSON and
use one normalized credential envelope rather than accepting a browser's
open-ended `PublicKeyCredential` object. The two options operations require an
exactly empty body; the 64 KiB limit applies to the two verify envelopes. The top-level object contains exactly
`id`, `rawId`, `response`, and `type`; `type` is exactly `public-key`, and `id`
and `rawId` are equal canonical unpadded base64url encodings of a non-empty
credential identifier no longer than 1,024 decoded bytes. Registration
`response` contains exactly `clientDataJSON` and `attestationObject`.
Authentication `response` contains exactly `clientDataJSON`,
`authenticatorData`, and `signature`. Each byte string is non-empty canonical
unpadded base64url. Unknown members, browser-extension members such as
`userHandle`, padded encodings, and alternate credential types are rejected;
this closed envelope is a route-specific exception to the general typed-JSON
unknown-member rule below. Registration accepts only the requested WebAuthn
`none` attestation profile with an empty attestation statement. V1 rejects
reserved authenticator flag bits, inconsistent backup flags, embedded attested
data on assertions, extension data it does not interpret, and trailing CBOR or
authenticator bytes.

Challenges, sessions, and lockout identities share a configured per-kind live
entry bound (at most 65,536 per kind) and expire without full-map scans. New
challenge or session state fails closed with
`503 operator_auth_state_capacity_exhausted` when its bound is occupied. A full
lockout table preserves every tracked identity and its lock, but stops tracking
new identities instead of rejecting otherwise valid unseen callers. Missing-mTLS
denials never consume per-identity lockout state.
First enrollment requires one of the configured unique 32..=256-byte
visible-ASCII bootstrap tokens. Torii retains only domain-separated token
digests after initialization; an enabled empty credential store without a
token is a startup error, bootstrap tokens may be removed after enrollment,
and no more than 16 may be configured. Credential enrollment is separately
bounded to at most 1,024 entries; an authenticated attempt to add
a new credential at the configured limit returns
`409 operator_webauthn_credential_capacity_exhausted`, while replacing the
same credential identifier is rejected with
`409 operator_webauthn_credential_duplicate`; credential rotation is a new
enrollment with a distinct identifier. Persisted credential state is
validated exactly at startup, including its version, fields, canonical
encodings, identifier and counter bounds, allowed algorithm, public key, and
duplicate identifiers. Corrupt or policy-incompatible state prevents Torii
from starting operator authentication instead of being repaired or ignored.

Credential management is a separate, fully authenticated operator boundary.
`GET /v1/operator/auth/credentials` returns exactly `credentials` and
`credentials_total`; entries contain only `credential_id`, `algorithm`,
`sign_count`, and `created_at_ms`, sorted by canonical credential identifier.
`DELETE /v1/operator/auth/credentials/{credential_id}` accepts only the same
non-empty canonical unpadded base64url identifier grammar as credential
exchange. An unknown identifier returns
`404 operator_webauthn_credential_not_found`. Deletion atomically persists the
new credential set and then revokes all outstanding operator sessions and
challenges. The final credential cannot be deleted unless a bootstrap recovery
token remains configured; otherwise Torii returns
`409 operator_webauthn_last_credential`. Every success and error response from
these routes is `private, no-store`.

## Typed JSON mapping

The JSON representation is the Norito JSON mapping of the same public DTO, not
an independently evolving compatibility schema. Struct members use their
declared snake-case names. Adjacently tagged enums contain the declared tag and
content members; a unit variant has a `null` content value. Byte representation
is field-level schema, not a runtime guess. The unannotated Norito mapping of a
fixed `[u8; N]` is a JSON string containing exactly `2 * N` uppercase
hexadecimal digits; its decoder accepts uppercase or lowercase hexadecimal of
exactly that length. A field that explicitly selects the `fixed_bytes` helper
instead emits exactly `N` integer bytes, and an ordinary `Vec<u8>` is likewise
an integer-byte array unless its field selects a documented textual helper.
This field-level encoding is distinct from the forbidden whole-payload base64
wrapper. Hashes, keys, signatures, identifiers, and numeric values use the
mapping declared by their data-model type.

A map is a JSON object. Its public key type must declare an injective canonical
JSON-string mapping and the inverse map-key decoder. Decoding rejects two
different lexical keys that normalize to the same typed key. A key type without
such a mapping is not permitted in a public DTO; the DTO must instead use a
documented array of typed key/value entries or an explicit field helper. JSON
object ordering has no semantic meaning, although canonical Torii output is
deterministic for ordered maps.

Unsigned 64-bit and 128-bit values are emitted as unquoted, lossless decimal
JSON integers. Clients must use an integer representation that preserves their
full range and must not round them through an IEEE-754 `double`. Every declared
integer field must use the JSON integer production: fraction and exponent
spellings such as `1.0` and `1e3` are rejected even when they denote a whole
mathematical value, and unsigned fields also reject lexical `-0`. Optional
fields encode as either their typed value or `null` unless the DTO explicitly
declares that `None` is omitted. Decoders reject duplicate declared members,
unknown enum discriminator values, out-of-range integers, and non-finite
numbers. They ignore unknown object members so an independently produced JSON
object can carry unrelated metadata without changing the typed value. For a
unit enum variant, decoders accept either an explicit `null` content member or
an omitted content member; canonical Torii output always includes the explicit
`null`. Signatures and payload digests cover canonical typed Norito bytes; the
lexical spelling, member order, or ignored members of input JSON are never
signed.

## Route catalog projections

The catalog is the canonical route superset, but consumers receive explicit
projections rather than identical sets. Each descriptor identifies its public,
operator, diagnostic, or protocol surface; listener; feature gate; OpenAPI and
SDK exposure; explicit MCP allowlisting; closed `RouteEffect` classification;
and closed `AdmissionPolicy` principal requirement. Effect and admission have
no unspecified/default form. Catalog validation rejects public mutation,
public expensive compute, public long-lived streams, operator surfaces without
operator admission, and principal admission without the corresponding sealed
authentication boundary. Metrics, diagnostics, streams, and privileged
commands therefore do not become SDK operations or MCP tools merely because
they are mounted. The mounted projection is evaluated for the active
build, while the SDK projection is the canonical supported-build superset.
OpenAPI-derived MCP generation is fail-closed: an operation is emitted only
when its exact HTTP method/path pair is enabled in the catalog's MCP projection
for the compiled feature set. An uncatalogued OpenAPI operation, a catalogued
operation without the MCP bit, or a feature-disabled operation is not generated
as a tool. Purpose-built `connect.*` and `iroha.*` tools are a separately
reviewed, explicit allowlist. When such an alias targets a catalogued route, the
route's compiled feature gate still applies; designated diagnostic and
ledger/proof mirrors additionally require the exact MCP projection. The tools
remain subject to read-only/writer/operator policy. `tools/call` accepts only
exact names from `tools/list`; OpenAPI `operationId` values and retired
convenience spellings are not hidden aliases. Listener metadata records the
intended exposure boundary, while the current single-listener implementation
continues to enforce operator and diagnostic restrictions through
authentication and ingress policy.

## Transaction status privacy

`GET /v1/pipeline/transactions/status` is intentionally a public, status-only
projection. Its closed response contains the transaction hash, status kind,
optional block height, requested scope, and resolution source. It never returns
rejection reasons or diagnostics, trigger completions, batch-transfer receipts,
account identities, amounts, or instruction payloads, and the handler does not
perform a second Kura lookup to hydrate those details.

Pipeline absence is scoped and typed. HTTP `404` is pending only when the
`ErrorEnvelope` has code `pipeline_transaction_status_not_found` and
`details.pipeline_transaction_status_not_found` contains the exact requested
canonical `hash` and `scope` (`local` or `global`; omission requests `global`).
JSON and Norito carry the same envelope. A global `404` requires exact typed
absence from every authoritative shard. An unavailable shard returns `503`
with code `route_unavailable`; generic, malformed, or selector-mismatched
`404` responses remain failures and never establish global absence. A successful
status must also bind the exact hash and requested scope. Cache and queue
observations are progress hints, not proof of Applied execution.

`GET /v1/bridge/finality/attestation/latest` returns the same challenge-bound
statement for whichever height is the durable tip of the immutable state view
that builds the proof; it shares the `{height}` form's rate-limit bucket and
failure contract, and its failures bind the height that view selected (at
least 1; before consensus starts, the status tip or genesis). The
signed `status` carries `beacon_horizon` (`epoch_length_blocks`,
`next_required_pulse_height`, `active_session_id`, `session_covers_next_pulse`,
`local_provider_ready`), or `null` before serialized height activation has
published it, so operators can bound restarts against the next mandatory
beacon pulse over public routes.

`GET /v1/bridge/finality/attestation/{height}` uses one negotiated JSON or
canonical Norito `ErrorEnvelope` with code `bridge_finality_attestation_failure`
and the sole detail `finality_attestation_failure`. Its closed
`FinalityAttestationFailure` record binds
the exact nonzero `challenge` and requested `height`, with a closed `reason` and
`tip_mismatch` payload. In JSON, `reason` is exactly one case-sensitive scalar
string naming a variant below, for example `"GenesisUncommitted"`; tagged objects,
numeric values and alternate spellings are invalid. Norito uses the closed enum.
The CLI report's lower-snake-case `reason` is a separate presentation field.
`TipChanged` requires the `tip_mismatch` payload; every other reason
requires null. The payload carries positive `requested_height`, `applied_height`,
and `status_height` values which are not all equal, plus the exact challenge,
configured `node_id`, and genesis-derived `network_id`.

HTTP `409` reports `TipChanged` or `ConflictingState`. General finality callers
may retry only `TipChanged` after validating every selector against their
independently retained request, node and network, within the existing deadline.
Genesis scaling treats `TipChanged` as non-retryable conflict. HTTP `503` reports
`ConsensusUninitialized`, `GenesisUncommitted`, `RestartRequired`, or
`FinalityUnavailable`; only the first two permit bounded startup retries. HTTP
`500` reports `InternalFailure`. Missing/corrupt proofs and identity, signature,
subject or CommitQC failures never grant retryable progress. Generic HTTP errors,
malformed payloads, and mismatched reason/status/payload combinations are errors.
These unsigned observations never authenticate readiness or finality. Every
response is `no-store`, carries `X-Content-Type-Options: nosniff`, and varies by
`X-Iroha-Finality-Challenge, Accept`.

For current-tip attestations past H2, the ordinary State-backed producer joins the
current certificate and H2's genesis execution anchor through every original native
ancestry frame in one captured State history. It verifies the exact current and H2
quorums and signed availability; the response does not assert the health of every
intermediate local quorum witness. The separately returned genesis proof must match
that exact H2 parent execution. Standalone proof and checkpoint exports retain their
full-prefix certificate checks. A typed unavailable body or height outside the
captured native snapshot maps to `FinalityUnavailable`; other original-execution
rejections map to `ConflictingState`. Neither failure permits startup retries, and
diagnostic text never determines classification.

Exact committed details use `POST /v1/pipeline/transactions/details`. The body
is a canonical `SignedQuery` containing `FindTransactions` with exactly one
`entrypoint_hash` equality predicate and default query parameters and selector.
Torii validates the exact genesis-derived `NetworkId`, lifetime, signature, and
one-shot nonce before any state or Kura access. It then admits only the
transaction authority, a source or destination account named by a committed
batch receipt, or an account holding the exact `CanReadAllLedgerData` operator
capability. Unsigned, wrong-network, replayed, broadened, and projected requests
fail closed; there is no legacy detail field on the public status DTO.

## Canonical history availability

Block, block-header, and transaction history share one WSV-anchored Kura
cursor. Every selected slot must contain a body whose header hash and one-based
height match the immutable query snapshot. A missing body and an authenticated
hash-only snapshot slot return a typed canonical-history availability failure;
a hash or height mismatch returns a typed corruption failure. `FindBlocks`,
`FindBlockHeaders`, indexed and unindexed `FindTransactions`, transaction
snapshots and cursor continuations never skip either condition or report a
successfully exhausted or truncated history. `/v1/ledger/headers` uses the same
source: availability failures map to `503`, while contradictory durable bodies
map to `500`.

## HTTP observability

Every matched request carries the catalog's stable route ID, Axum route
template, API surface, listener, route effect, admission policy, and tooling
projections in request extensions.
The same metadata is copied to the response for outer middleware. Neither logs
nor metric labels fall back to the raw request URI; concrete identifiers,
cursor values, and query strings therefore cannot create label cardinality or
leak through route labels. Unmatched requests use `http.route_not_found` and
the fixed template `unmatched`.

HTTP metrics include stable route ID/template, surface, bounded representation,
stable error code, method, status, latency, and exact request/response body
sizes when known. JSON and Norito retain their established content-type labels;
all other response content types are reduced to a bounded media category.
Typed `ErrorEnvelope` responses copy their validated code into an internal
response extension. Reviewed non-typed protocol errors use their exact finite
allowlist code, currently `error_code="stream_resume_unsupported"`. An ordinary failed response can be
reported as `error_code="unclassified"` only if code outside the assembled
Torii router bypasses the normalization boundary; that is an actionable
contract violation, not a supported response form.

## `/v1` evolution

Until the first release is published, incompatible API changes replace the
pre-release contract directly; there are no aliases or migration DTOs. After
publication, the typed Norito layouts and their JSON mappings are frozen for
the lifetime of `/v1`. Reordering, adding, removing, or retyping a field, adding
a variant to a closed enum, changing requiredness, or changing a field's JSON
mapping requires a new major path unless the type already declares an explicit
extensibility mechanism. Adding an independent route or a new stable error-code
string is additive. Clients must handle unknown error codes without assuming
that human-readable messages are stable. Adding a required request field is
never compatible within `/v1`.

Release tests pin both the public schema-name header hash and the canonical
structural-schema hash for proof-bearing request DTOs. A refactor that changes
field order, type identity, nesting, or representation therefore fails before
an incompatible binary layout can be published under an unchanged `/v1`
schema name.

Internal wire and consensus types may keep implementation version suffixes.
Those names do not create nested route versions and do not provide a second
public response schema.

## Sharp cutover and release gates

External atomicity means the release exposes only the canonical route tree.
Implementation may be staged internally, but no compatibility router, alias,
redirect, fallback decoder, migration DTO, or dual-write path is mounted in the
release. Because no earlier public release exists, there is no old-to-new
migration manifest or supported migration period. A reviewed negative-path
inventory exists only to prove that known pre-release spellings cannot resolve
through redirects, normalization, wildcard capture, or another method.

The following are mandatory release gates; a failure blocks publication:

1. The catalog validates, and the mounted method/path set equals the enabled
   mounted projection including reviewed implicit `HEAD` and CORS `OPTIONS`
   behavior. Each mounted authentication policy is exercised against the
   middleware/handler that enforces it.
2. OpenAPI equals the enabled OpenAPI projection, MCP contains only its enabled
   explicit allowlist, and generated SDK operations equal the canonical SDK
   projection. Generated artifacts must be reproducible and clean.
3. Adversarial route tests cover known retired spellings, trailing and duplicate
   slashes, case changes, percent-encoded separators and dot segments, wildcard
   capture, wrong methods, and framework redirects.
   The proof-record route permits canonical `%2F` only within its single typed
   `ProofId` parameter for slash-delimited backend labels; decoded empty or dot
   components, backslashes, nested escapes, and noncanonical encodings remain
   rejected. The decoded identifier uses the `ProofId` display spelling; data
   colons may remain literal or use the existing component encoder's `%3A`.
4. JSON/Norito golden vectors and structural-schema guards, negotiation and
   typed-error tests, offline idempotency/lifecycle tests, cursor
   snapshot/authorization/lifetime tests, and streaming establishment/lag/
   backpressure tests all pass.
5. Every supported first-party SDK passes its contract, fixture, and generated
   surface suites against the same release artifacts.
6. The full Cargo workspace build, test, format, strict lint, serialization
   guard, and generated-artifact suites pass. Focused suites may run earlier,
   but they never replace the full release matrix.

Rollback selects an earlier unpublished build or deployment artifact; it does
not reactivate retired routes in the release binary.
