# ZK App API: Attachments and Proof Tooling

This document describes the app-facing ZK endpoints exposed by Torii for
handling proof attachments and proof tooling. These facilities are
non-consensus: they do not affect validation, execution, or block formation.
They are intended for operator tooling and UI/UX flows.

Key properties:
- Deterministic, non‑forking behavior. Disabling the worker does not change consensus results.
- Feature‑gated under `app_api` (enabled by default for Torii).
- Rate‑limited; attachment storage is partitioned by an exact-network,
  canonically authenticated account. API tokens are only an optional
  additional gate.
- On‑disk storage under `./storage/torii` by default.

For a repo-wide view of which surfaces perform real proof verification versus
decode-only/demo work, see [ZK Audit Matrix](zk_audit_matrix.md).

## Direct verifier convenience endpoints

Torii exposes one diagnostic verifier in addition to the runtime-critical
ledger paths:

- `POST /v1/zk/verify-batch` (feature `zk-verify-batch`) performs
  cryptographic verification, but only for the standalone native IPA
  `iroha_zkp_halo2::OpenVerifyEnvelope` format. It does not consult the
  verifying-key registry, does not enforce ledger circuit/schema policy, and is
  not a substitute for `iroha_core_zk::verify_backend_with_timing_guardrails`.
  The wire carries only a `(version, curve, n)` selector; the verifier derives
  the deterministic V1 generators and callers cannot submit another parameter
  set. The complete derived parameter fingerprint is absorbed into the opening
  transcript. The route fails closed unless `halo2.enabled` of the committed ZK validity policy is true and
  admits work through Torii's general and heavy-query limits before moving
  decoding and verification to a blocking worker; owned permits remain with
  that physical worker if the HTTP request is cancelled. Requests must declare
  exactly one `Content-Type`: `application/json` (optionally with the single
  parameter `charset=utf-8`) or parameter-free `application/x-norito`. Torii
  applies the configured total body ceiling before decoding, bounds the native
  Norito batch length before allocating the outer vector, and rejects JSON
  base64 strings that cannot fit `max_envelope_bytes` before allocating their
  decoded buffers. It then applies finite batch, per-envelope, curve-`k`, and
  transcript-label ceilings. Before content-type inspection or decode, Torii
  requires canonical account authentication over the exact runtime
  `NetworkId`, method, URI, nonce, expiry, and bounded raw body. The embedding
  API requires those limits
  explicitly; the no-limit Torii handler has been removed.

The pre-release decode-only `/v1/zk/verify` and `/v1/zk/submit-proof` routes
were removed. To request ledger-authoritative proof verification, submit a
signed transaction containing `VerifyProof` (or the applicable proof-bearing
instruction) through the ordinary transaction pipeline.

Runtime-critical surfaces such as governance ballots/tallies, confidential
assets, and registry-backed STARK/Halo2 flows use the guarded core verifier
path instead. `IvmProved` admission fails closed until the complete execution
relation is available.

## Confidential-tree read endpoints

- `POST /v1/zk/roots` returns a bounded suffix of mutation-time persisted roots.
  It validates fixed frontier/current-root metadata plus bounded history and
  checkpoint shape, but never rebuilds commitments or recomputes prefix roots.
  Snapshot decode/recovery is the boundary that fully projects the ordered
  commitment prefix and authenticates those persisted values.
- `POST /v1/zk/merkle-path` accepts at most 128 distinct commitments. It scans
  the frontier once to record requested positions and multiplicity, builds one
  compact authenticated tree projection, compares the projection root and
  frontier with persisted metadata, and derives every requested path plus the
  next-zero path from that projection. Work is `O(N + k * tree_depth)` and each
  stored commitment is leaf-hashed once per request, rather than once per path.

Both routes retain Torii's general and heavy-query admission permits inside a
blocking worker through physical completion. Their responses identify the exact
committed block height and hash evaluated by the retained immutable state view.

## Attachments

Attachments store sanitized artifacts such as proof envelopes or JSON DTOs. Each attachment is addressed by a deterministic id derived from the sanitized bytes.

All attachment list/count/read/create/delete requests carry canonical account
authentication bound to the exact runtime `NetworkId`, HTTP method, URI, nonce,
expiry, and bounded raw body. Torii verifies it before any query/path/body
extractor runs and derives the tenant exclusively from the verified `AccountId`.
API-token possession alone never selects or authorizes a tenant.

Endpoints:
- `POST /v1/zk/attachments` — store attachment, returns metadata `{ id, size, content_type, created_ms, provenance? }`.
- `GET  /v1/zk/attachments` — list metadata for stored attachments (JSON array).
- Supports filters via query params: `id`, `content_type` (substring), `since_ms`, `before_ms`, `has_tag=<TAG>` (ZK1 TLV tag present, e.g., `PROF`, `IPAK`), `limit`, `offset`, `order=asc|desc`, `ids_only=true`.
- `GET  /v1/zk/attachments/:id` — fetch stored attachment bytes by id; content type is preserved.
- `DELETE /v1/zk/attachments/:id` — delete stored attachment and metadata.
 - `GET  /v1/zk/attachments/count` — return `{ count }` for the same filter set as the list endpoint.
- `GET  /v1/zk/proof/{backend}/{hash}` — fetch a proof record by backend and proof hash (64‑hex). Returns JSON `{ backend, proof_hash, status, verified_at_height?, vk_ref?, vk_commitment? }`.
 - `GET  /v1/zk/proofs` — list proof records with optional filters and pagination.
   - Filters: `backend`, `status=Submitted|Verified|Rejected`, `has_tag=<TAG>` (exactly four ASCII graphic/non-space printable characters; requires `zk-proof-tags` feature), `verified_from_height`, `verified_until_height`, `bridge_only`, `bridge_start_from_height`, and `bridge_end_until_height`.
   - Pagination and projection: `limit`, `offset`, `order=asc|desc`, and `ids_only=true`.
   - Unknown status/order values, malformed tags, zero or over-limit pages, and inverted height ranges fail with `400 Bad Request`; they never broaden the query by silently dropping a filter.
 - `GET  /v1/zk/proofs/count` — return `{ count }` for the same filters. List-only `limit`, `offset`, `order`, and `ids_only` parameters fail with `400 Bad Request`.
- Proof endpoints enforce Torii’s dedicated guardrails:
  - Body limits: proof submission payloads exceeding `torii.proof_max_body_bytes` are rejected.
  - Rate limit: `torii.proof_rate_per_minute` + `torii.proof_burst` (returns `429` + `Retry-After` using `torii.proof_retry_after_secs` unless `api_rate_limit_bypass_cidrs` bypasses rate limiting only).
  - Pagination: `torii.proof_max_list_limit` caps `limit`; zero or larger requests fail with `400 Bad Request`.
  - Timeout: list/count handlers abort after `torii.proof_request_timeout_ms` wall-clock.
  - Egress throttling: proof fetches are shaped by `torii.proof_egress_bytes_per_sec` + `torii.proof_egress_burst_bytes`; throttled responses return `Retry-After` with the proof retry hint.
  - Caching: `GET /v1/zk/proof/...` emits `Cache-Control: public,max-age=torii.proof_cache_max_age_secs` and `ETag="<proof_hash>"`. `If-None-Match` applies HTTP weak comparison across comma-separated or repeated validators and supports a sole wildcard; opaque tag values remain case-sensitive, and a malformed validator set is non-matching. A match returns `304 Not Modified` without a body. Routed `GET /v1/proofs/{id}` uses the same validator contract.
  - Metrics: `torii_proof_requests_total`, `torii_proof_request_duration_seconds`, `torii_proof_response_bytes_total`, `torii_proof_cache_hits_total`, and `torii_proof_throttled_total` expose outcomes and cache hits per endpoint.

Details:
- Deterministic id: Blake2b‑32 of the sanitized request body bytes (lower‑case hex).
- Content‑Type: normalized to the sniffed type (magic‑byte inspection). The declared header is recorded in `provenance.declared_type`.
- Provenance: responses include `provenance` with `{ declared_type, sniffed_type, hashes { blake2b_256, sha256 }, sanitizer { verdict, expanded_bytes, archive_depth, sandboxed } }`.
- Rejections: unsupported types return `415 Unsupported Media Type`; expansion/sandbox failures return `413`/`400` with the rejection reason in the body.
- Sanitizer admission: upload POST and compressed-origin export GET share the configured proof-work semaphore. The lease is acquired before handler work and remains owned by detached blocking work, the sandbox child, and its stdout reader after HTTP cancellation, so authenticated retries cannot create unbounded sanitizer tasks.
- Size cap: enforced per item via `torii.attachments_max_bytes` (default 4 MiB) against both the submitted bytes and the canonical sanitized bytes. A compressed request whose sanitized body exceeds the cap receives `413 Payload Too Large` and is not retained.
- Per-tenant quota: Torii enforces per-tenant attachment limits using `torii.attachments_per_tenant_max_count` (count) and `torii.attachments_per_tenant_max_bytes` (aggregate bytes). The tenant is the canonically authenticated `AccountId`; there is no anonymous or token-derived fallback. If an upload can fit after eviction, Torii first fsyncs a bounded, validated transaction intent, then durably commits the new body, metadata, and prover reference before removing the oldest attachments for that account. Recovery rolls back a partial incoming commit or completes victim deletion after a complete commit; deletion failure returns `500` and preserves the intent for a later retry. When the incoming body alone exceeds `torii.attachments_per_tenant_max_bytes`, Torii returns `413 Payload Too Large`.
- Node-global quota: `torii.attachments_global_max_count` (range `1..=20000`) and `torii.attachments_global_max_bytes` bound retained attachment copies and sanitized body bytes across every tenant. Admission and tenant-local eviction run under the same mutation lock as explicit deletion and TTL collection. Torii may evict only the submitting tenant's oldest entries; if that cannot make the complete upload fit, it returns `413 Payload Too Large` before deleting anything and never evicts another tenant's data. Deleting the last attachment for a tenant removes its empty storage directory. Accounting examines at most 20000 root entries and 40000 aggregate tenant-child entries, charges malformed/raw entries against those bounds, and fails closed. The background prover starts only after quota recovery succeeds.
- Retention (TTL): attachments older than `torii.attachments_ttl_secs` (default 7 days) are removed by a background GC that runs approximately every 60 seconds.
- Storage layout:
  - Data: `storage/torii/zk_attachments/<tenant-key>/<id>.bin`
  - Metadata: `storage/torii/zk_attachments/<tenant-key>/<id>.json`

## IVM execution preparation

The former Torii binding-only IVM preparation and proof-job routes are retired.
`POST /v1/zk/ivm/derive`, `POST /v1/zk/ivm/prove`, and its job GET/DELETE paths
are absent. The old derive response represented an `IvmProved` executable
bound to a verifier-key policy that cannot establish execution soundness.
Torii will serve authenticated public preparation data only after a distinct
response shape and a complete State-owned finalized anchor are available. Raw
private witnesses belong solely in local native proving and never in Torii
requests.

Production Core rejects `IvmProved` until one complete native STARK execution
relation proves every admitted transition and verified effects can be checked
against the authoritative finalized state. The retired Halo2 and STARK binding
circuits cannot be registered as IVM execution verifier keys. Generic proof
verification and unrelated circuits continue under their own rules.

## Background Prover Reports

The background prover worker is enabled by default and remains idle until attachments are present. It scans attachments and produces a JSON report per attachment. It verifies `ProofAttachment` payloads (single or list) using the core ZK backend verifiers:

- Norito (`application/x-norito`): the body must decode as `ProofAttachment` or `ProofAttachmentList`.
- JSON (`application/json`): the body must decode as a `ProofAttachment` object, a `ProofAttachmentList` (base64 string), or a JSON array of `ProofAttachment`.
- ZK1/TLV envelopes are not accepted as top‑level attachment payloads; they are tagged (`zk1_tags`) but reported as `ok=false`. The first-release structural profile rejects envelopes with more than 64 TLVs, and report metadata stores each repeated tag only once.

Verification rules:
- `vk_ref` is resolved via the WSV verifying‑key registry. When a registry entry omits inline key bytes, Torii loads the key bytes from `torii.zk_prover_keys_dir` (see storage layout below).
- `vk_commitment` is validated against the computed VK hash when present.
- Backends and circuits are allowlisted via `torii.zk_prover_allowed_backends` and `torii.zk_prover_allowed_circuits` (prefix match).
- Supported backends currently include `halo2/ipa` and other `halo2/…` variants built into the node. The `stark/fri` family is supported when built with feature `zk-stark` and `stark.enabled` of the committed `zk_validity_policy_v1` parameter is true (the protocol default). `groth16/…` remains unsupported.

Background reports are bounded node-local worker diagnostics. Torii does not
mount a report HTTP API, and first-release clients do not expose report
list/count/get/delete adapters.

Report schema (JSON):
```json
{
  "id": "<64-hex>",
  "ok": true,
  "error": null,
  "content_type": "application/json",
  "size": 123,
  "created_ms": 1710000000000,
  "processed_ms": 1710000300000,
  "backend": "halo2/ipa",
  "vk_ref": { "backend": "halo2/ipa", "name": "vk_main" },
  "proof_hash": "…",
  "circuit_id": "halo2/pasta/ipa/kaigi-usage-v1"
}
```

When an attachment carries multiple proofs, the report includes a `proofs` array with per‑proof `{ backend, ok, error, vk_ref, proof_hash, circuit_id }` entries.

Storage layout:
- Reports: `storage/torii/zk_prover/reports/<id>.json`
- Bounded report retention summaries:
  `storage/torii/zk_prover/report_index/<id>.json`. Each report owns one
  atomically replaced summary shard, so report creation has constant index
  write amplification and never rewrites a global index. Summary shards are
  capped at 64 KiB; projected errors are capped at 4 KiB, content types at 256
  bytes, and tag metadata at 64 unique bounded strings. Full report bodies
  remain local to the node.
- Prover key store: `storage/torii/zk_prover/keys/zkid-v1-<id-hash>.vk`
  (fixed-length exact-ID hash; override via `torii.zk_prover_keys_dir`).

Retention:
- Attachments are subject to TTL GC (see above).
- Prover reports are also subject to TTL GC controlled by `torii.zk_prover_reports_ttl_secs` (default: 7 days). The prover worker deletes reports older than the TTL on each scan cycle.

## Configuration

Configure via `iroha_config` (`[torii]` section). Defaults are shown in comments.

TOML (recommended for production):
```toml
[torii]
# Attachments
attachments_ttl_secs = 604800         # 7 days
attachments_max_bytes = 4_194_304     # 4 MiB
attachments_per_tenant_max_count = 128
attachments_per_tenant_max_bytes = 67_108_864  # 64 MiB aggregate per tenant
attachments_global_max_count = 4096
attachments_global_max_bytes = 1_073_741_824   # 1 GiB aggregate per node
attachments_allowed_mime_types = ["application/x-norito", "application/json", "application/x-zk1"]
attachments_max_expanded_bytes = 16_777_216    # 16 MiB expanded payload cap
attachments_max_archive_depth = 2              # max nested gzip/zstd layers
attachments_sanitize_timeout_ms = 1000         # sanitizer timeout (ms)
attachments_sanitizer_mode = "subprocess"      # production default; in_process has no OS isolation

# Background prover (non-consensus)
zk_prover_enabled = true              # enabled; idle until attachments exist
zk_prover_scan_period_secs = 30       # scan every 30 seconds when enabled
zk_prover_reports_ttl_secs = 604800   # delete reports older than 7 days
zk_prover_max_inflight = 2            # process up to 2 attachments concurrently
zk_prover_max_scan_bytes = 16_777_216 # cap each scan to 16 MiB of attachment data
zk_prover_max_scan_millis = 2000      # bail out after 2 seconds of wall-clock time per scan
zk_prover_keys_dir = "./storage/torii/zk_prover/keys"
zk_prover_allowed_backends = ["halo2/"] # prefix match (empty = allow all)
zk_prover_allowed_circuits = []       # prefix match (empty = allow all)

# IVM simulation and view tooling
ivm_tooling_max_inflight = 1         # concurrent blocking workers
ivm_tooling_timeout_ms = 60000       # synchronous worker deadline

# (optional) app API tokens and rate limits
require_api_token = true
api_tokens = ["example-token-value-at-least-32-bytes"]
# Proof endpoint guardrails
proof_rate_per_minute = 120           # steady-state tokens/min (None to disable rate limiting)
proof_burst = 60                      # burst tokens per endpoint key
proof_max_body_bytes = 8_388_608      # maximum submission payload size (bytes)
proof_body_max_inflight = 8           # aggregate pre-parse proof/KAGEMUSHA body admission
proof_body_read_timeout_ms = 15000    # absolute deadline for each admitted proof/KAGEMUSHA body
proof_max_list_limit = 200            # maximum allowed `limit` for proofs list
proof_request_timeout_ms = 1000       # wall-clock timeout for list/count
proof_cache_max_age_secs = 30         # Cache-Control max-age for proof fetches
proof_retry_after_secs = 1            # Retry-After value returned on throttling
proof_egress_bytes_per_sec = 8_388_608 # optional steady-state egress budget (bytes/sec)
proof_egress_burst_bytes = 67_108_864 # optional egress burst budget (64 MiB)
```

In subprocess mode, install the dedicated `attachment_sanitizer` executable in the same directory
as the node binary. The node never re-executes itself as a sanitizer. It clears inherited
environment variables, bounds both sides of the helper protocol, and refuses the request if the
helper is missing, has the wrong name, aliases the node executable, or cannot be placed in an OS
sandbox. Linux requires `bwrap`; macOS uses `sandbox-exec`. Official release bundles and container
images include the helper, and Linux images include Bubblewrap.

Configuration must be set via `iroha_config` files. Environment variable overrides exist for developer tooling but are not intended for operator-facing deployments.

The body-admission count and read deadline are shared with KAGEMUSHA V1 top-up/redemption command bodies; the shared gate prevents slow or concurrent uploads from reserving heavy verification capacity before their bounded bodies are complete.

When the worker exhausts the byte, time, or bounded directory-work budget, it stops scheduling new attachments, increments `torii_zk_prover_budget_exhausted_total{reason="bytes|time|work"}`, and leaves the remainder queued for the next scan. Discovery retains only a scan-budget-derived window, resumes its directory cursor across cycles, canonically orders that window instead of collecting the complete multi-tenant attachment population, and reserves the latter half of the scan deadline for scheduled work. Live gauges expose the current workload via `torii_zk_prover_inflight` (attachments in progress), `torii_zk_prover_pending` (discovered pending entries plus one sentinel while the sweep is incomplete), and the most recent cycle statistics: `torii_zk_prover_last_scan_bytes` and `torii_zk_prover_last_scan_ms`.

### Operations & Dashboards

- A full operator runbook covering alerting, log pivots, and incident
  procedures lives in [`zk/prover_runbook.md`](zk/prover_runbook.md).
- Import [`grafana_zk_prover.json`](grafana_zk_prover.json) into Grafana to seed
  dashboards for queue depth, attachment throughput, worker latency, and ledger
  correlation panels.
- Recommended alerts:
  - Page when `avg_over_time(torii_zk_prover_pending[10m]) > 0` or when
    `histogram_quantile(0.95, sum(rate(torii_zk_prover_latency_ms_bucket[5m])) by (le))`
    stays above your configured `zk_prover_max_scan_millis` for longer than
    15 minutes.
  - Ticket when `increase(torii_zk_prover_budget_exhausted_total{reason="bytes"}[30m]) > 0`
    so operators can adjust the byte budget or prune problematic attachments.

## Security and Operations

- The app API is subject to rate limits; limits are enforced per endpoint key. You can require an API token for app-facing endpoints via `require_api_token=true` and set `api_tokens`.
- CIDR allowlist (`api_rate_limit_bypass_cidrs`) can bypass rate limits for selected origins; it grants no authentication, internal-read, or routed-visibility privilege.
- These endpoints do not change consensus outcomes. You can disable the prover worker (`zk_prover_enabled=false`) without impacting validation or execution.

## CLI Helpers

Use the CLI to interact with the app API (requires Torii URL and any API token if configured):

- Attachments:
  - `iroha app zk attachments upload --file <PATH> [--content-type <MIME>]`
  - `iroha app zk attachments list`
  - `iroha app zk attachments get --id <ID> --out <PATH>`
  - `iroha app zk attachments delete --id <ID>`
- Verification helpers:
  - `iroha app zk verify-batch --json <PATH>` or `--norito <PATH>`
## Verifying Key Registry (App API)

Torii exposes convenience endpoints that validate registry inputs, quote fees, and prepare canonical
unsigned transactions. Torii never accepts a signing key and never submits these drafts. The client
must validate the returned draft, sign it locally, construct the signed transaction, and submit that
transaction through the ordinary transaction pipeline.

Endpoints:
- `POST /v1/zk/vk/register` — Prepare `RegisterVerifyingKey` for local signing
- `POST /v1/zk/vk/update` — Prepare `UpdateVerifyingKey` for local signing (version must increase)
- `GET  /v1/zk/vk` — List records using optional `backend`, case-sensitive
  `status=Active|Proposed|Withdrawn`, `name_contains`, `limit`, `offset`,
  `order=asc|desc`, and `ids_only` parameters. Unknown status/order values,
  zero or over-cap pages, and pagination windows beyond the configured fetch
  budget return `400 Bad Request` instead of broadening the query.
- `GET  /v1/zk/vk/{backend}/{name}` — Get a verifying key record as JSON

Both POST schemas are strict. They accept the public `authority` that will sign the transaction but
reject `private_key` and every other unknown field. A successful request returns HTTP 200 with
exactly this draft:

```json
{
  "submitted": false,
  "transaction_payload_b64": "<canonical padded-base64 TransactionPayload>",
  "signing_message_b64": "<padded-base64 HashOf<TransactionPayload>>"
}
```

SDK draft decoders reject non-canonical base64, oversized payloads, a signing-message hash that does
not match the payload, the wrong chain or authority, extra instructions, and any registry record
that does not exactly match the request. Only after these checks should a client sign and submit.

`GET` responses include the normalized record and its Norito encoding. For the
generated canonical replay-binding key (encoded blobs abbreviated):

```json5
{
  "id": { "backend": "halo2/ipa", "name": "ivm_replay_binding" },
  "record": {
    "version": 1,
    "circuit_id": "halo2/pasta/ipa/ivm-replay-binding-v1",
    "owner_manifest_id": null,
    "namespace": "core",
    "backend": "halo2-ipa-pasta",
    "curve": "pallas",
    "public_inputs_schema_hash": "03f741ebb9859047e5be057c54e1e468e7dc5ed1cebeb4e3a554f5a04277413b",
    "commitment": "9ce86e89d81b1fa022ad01130e2e6f78f0038eca11e714e5b0f14100895c05ed",
    "vk_len": 111,
    "max_proof_bytes": 8388608,
    "gas_schedule_id": "halo2_default",
    "metadata_uri_cid": null,
    "vk_bytes_cid": null,
    "activation_height": null,
    "withdraw_height": null,
    "status": "Active",
    "key": { "backend": "halo2/ipa", "bytes_b64": "..." }
  },
  "record_norito_base64": "..."
}
```

When `ids_only=true`, the list endpoint returns objects containing just `{ "backend": "...", "name": "..." }`.

DTOs (POST bodies, JSON):
  - `vk_bytes` (base64) — full verifying key bytes; Torii computes the commitment and validates it against `commitment_hex` when present. `vk_len` is optional here but, when provided, must match the byte length.
  - `commitment_hex` (hex, 64) — commitment only; when bytes are omitted you must supply `vk_len` so the record captures verifier size metadata.

CLI commands build and sign the equivalent registry transaction locally with the active client
configuration; their JSON files contain public registry data only:

- Register: `iroha app zk vk register --json ./vk_register.json`
- Update: `iroha app zk vk update --json ./vk_update.json`
- Get: `iroha app zk vk get --backend <backend> --name <name>`

Generate a complete CLI registration file for the supported Halo2 IVM
replay-binding relation. The helper selects the compiled circuit, key, schema,
curve and proof limit; the output contains no signing authority or private key.

```bash
cargo run --locked -p iroha_cli --features dev-tools --bin ivm_replay_binding_keygen -- \
  --name ivm_replay_binding \
  --vk-out ./replay-binding.vk \
  --template-out ./vk_register.json
iroha app zk vk register --json ./vk_register.json
```

The CLI uses the account and signing key in its client configuration. The HTTP
draft endpoint instead requires the public `authority` field in its own request
DTO. Do not insert HTTP-only fields into a CLI registration file. Proving-key
archive export is optional; server proving derives that key automatically.

Notes:
- Commitments are domain-separated SHA-256 hashes over the `iroha:zk:v1:vk`
  domain plus length-prefixed backend and VK bytes, and are checked while preparing the draft and
  again during ledger execution.

### Subscribing to Verifying Key Registry Events


Examples (JSON5):

1) Listen to all verifying key events for a specific id (backend + name):


2) Listen only for updates (version bumps) regardless of id:


CLI usage example:



### Subscribing to Proof Events

You can also subscribe to proof verification events via `DataEventFilter.Proof`. The CLI offers presets for convenience.

Examples:

1) Listen to all events for a proof id:

```
iroha trigger register \
  --id proof_watch \
  --filter data \
  --data-proof halo2/ipa:0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd \
  --path ./on_proof.ko
```

2) Only successes (Verified) for that proof:

```
iroha trigger register \
  --id proof_successes \
  --filter data \
  --data-proof halo2/ipa:0123abcd... \
  --data-proof-only verified \
  --path ./on_verified.ko
```

## Operational Boundaries

- The prover worker verifies proofs using configured backend verifiers. Proof
  generation remains a client/operator responsibility and is intentionally not
  part of the Torii API surface.
- Report retention is controlled by `torii.zk_prover_reports_ttl_secs` and can
  be managed via the report delete endpoints.

## Governance Endpoints (ZK Ballots)

For submitting ZK ballots and building transaction skeletons, refer to the
Governance App API document. These strict request schemas and their nested
window, provenance, proof, and public-input objects reject unknown fields and
all private-key aliases before dispatch; Torii returns a skeleton for clients
to sign locally and submit:
- POST `/v1/gov/ballots/zk-v1` — v1-style DTO with explicit envelope fields.
- POST `/v1/gov/ballots/zk-v1/ballot-proof` — accepts canonical V1 `BallotProof` JSON directly.

Both routes return `{ "drafted": true, "tx_instructions": [...] }` only after
constructing one unsigned instruction. Invalid fields return Torii's standard
`ErrorEnvelope` with HTTP `400`; these drafting routes never report a
transaction as accepted.

Both routes require one typed genesis-derived `network_id` and canonical
exact-network account authentication over the bounded raw request before DTO
decoding. The authenticated account must equal the body `authority`; retired
`chain_id`/`genesis_hash` keys, redirects, and transparent retries are rejected.

See specs/governance_api.md for details and examples.
