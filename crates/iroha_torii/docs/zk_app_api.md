# Torii App API: ZK Attachments and Proof Tooling

This document describes the app-facing ZK endpoints exposed by Torii for
storing proof attachments and running proof tooling. These features are
strictly non-consensus and do not affect block production or validation.

Contents
- Endpoints and storage layout
- Configuration (TTL, size caps, tokens, rate limits)
- Operational notes and safety
- Examples (curl and CLI)

## Endpoints

Attachments (store sanitized bytes with metadata):
- `POST /v1/zk/attachments` — store a new attachment (body = bytes, sanitized on ingest)
- `GET  /v1/zk/attachments` — list stored attachments (JSON array)
- `GET  /v1/zk/attachments/count` — count stored attachments
- `GET  /v1/zk/attachments/{id}` — fetch stored attachment bytes by id
- `DELETE /v1/zk/attachments/{id}` — delete an attachment

Every attachment route requires canonical account authentication over the exact
runtime `NetworkId`, HTTP method, URI, nonce, expiry, and bounded raw body. Torii
verifies these headers before query/path/body extraction and derives the storage
tenant only from the verified account. An API token, when configured, is an
additional gate and never establishes attachment ownership.

Confidential-tree witnesses (committed ledger reads):
- `POST   /v1/zk/roots` — return the bounded recent-root window for one asset
- `POST   /v1/zk/merkle-path` — return current inclusion paths and the next zero-leaf path

The binding-only IVM preparation and proof-job routes are removed. Core rejects
`IvmProved` until the complete native STARK execution relation and State-owned
finalized anchor are available.

`POST /v1/zk/verify-batch` requires canonical
account authentication over the exact runtime `NetworkId`, method, URI, nonce,
expiry, and bounded raw body before content-type inspection or decode.

Notes
- Attachment id is a deterministic Blake2b‑32 (hex, lowercase) of the sanitized body bytes.
- Content type is normalized from magic‑byte sniffing; the declared header is recorded in `provenance`.
- Attachments persist on disk under `./storage/torii/zk_attachments/`:
  - `./storage/torii/zk_attachments/{tenant-key}/{id}.bin` (body)
  - `./storage/torii/zk_attachments/{tenant-key}/{id}.json` (metadata)
- Background-prover diagnostics persist under
  `./storage/torii/zk_prover/reports/{id}.json`. They are node-local worker
  state and have no public HTTP or SDK surface. Metadata is stored as one
  bounded, atomically replaced summary shard
  per report under `./storage/torii/zk_prover/report_index/{id}.json`; saving a
  report never rewrites a global summary file. A shard is capped at 64 KiB;
  its projected error and content-type fields are capped at 4 KiB and 256
  bytes respectively. Retention and garbage collection scan one shard at a
  time.
- Base directory is configured with `torii.data_dir`; tests/dev harnesses can override with `data_dir::OverrideGuard`. The directory must be owned by the Torii operator and exclusively writable by the Torii process owner; a shared or less-privileged writable data directory is unsupported.
- IVM proof generation and preparation are unavailable until the complete
  native execution relation exists. Generic STARK and Halo2 verification
  remain separate from IVM execution admission.
- STARK verification (`stark/fri` family) is supported when built with feature `zk-stark` and `stark.enabled` of the committed `zk_validity_policy_v1` parameter is true (the protocol default). It is not a node-configuration key.
- For `halo2/*` and `stark/fri` backends, proof bytes are expected to be a Norito-encoded `OpenVerifyEnvelope`.
- For STARK wrappers, `OpenVerifyEnvelope.public_inputs` carries schema-descriptor bytes; concrete public input values are carried in `StarkFriOpenProofV1.public_inputs`.
- Confidential-tree reads dispatch exclusively through the tree profile persisted in `ZkAssetState`. The first release admits only `PoseidonPastaV1`; verifier-role bindings and node-local configuration do not select a tree hash or depth. Torii validates every retained root and frontier checkpoint before serving witnesses. A registered tree with no commitments returns the profile-defined depth-16 empty root as both `latest` and the sole root entry.

## Configuration

All runtime behavior is configured via `iroha_config` (Torii section). The following keys are relevant:

- `torii.attachments_ttl_secs` (u64)
  - Time‑to‑live for attachments. A background GC removes entries older than this TTL.
  - Default: 7 days.
- `torii.attachments_max_bytes` (u64)
  - Maximum size (bytes) for both the submitted body and the canonical sanitized body retained for a single attachment. A compressed body that expands beyond this cap is rejected with `413 Payload Too Large` rather than being stored unreadably.
  - Default: 4 MiB.
- `torii.attachments_per_tenant_max_count` (u64)
  - Maximum number of attachments retained per tenant (0 disables the cap). The tenant is the exact canonically authenticated `AccountId`; anonymous and token-derived tenants do not exist.
  - Default: 128.
- `torii.attachments_per_tenant_max_bytes` (u64)
  - Aggregate bytes retained per tenant. When an upload can fit after tenant-local eviction, Torii fsyncs one bounded transaction intent, commits the new body, metadata, and prover reference durably, then removes the oldest attachments for that tenant. Startup and every later mutation roll back an incomplete incoming commit or finish victim deletion after a complete commit. A deletion failure returns `500` and retains the intent for recovery; bodies larger than the cap are rejected with `413`.
  - Default: 64 MiB.
- `torii.attachments_global_max_count` (u64)
  - Maximum number of attachment copies retained by one node across all tenants. The supported range is `1..=20000`, matching the bounded filesystem quota scan.
  - Default: 4096.
- `torii.attachments_global_max_bytes` (u64)
  - Aggregate sanitized attachment bytes retained by one node across all tenants. An upload may evict only the submitting tenant's oldest entries to make room; Torii returns `413` rather than evicting another tenant's data.
  - Default: 1 GiB.
- `torii.attachments_allowed_mime_types` (list of strings)
  - Allowlisted MIME types for attachment payloads after magic‑byte sniffing.
  - Default: `["application/x-norito", "application/json", "application/x-zk1"]`.
- `torii.attachments_max_expanded_bytes` (u64)
  - Maximum bytes the sanitizer may expand while inspecting gzip/zstd payloads. The resulting canonical body must still fit `torii.attachments_max_bytes` before it can be retained.
  - Default: 16 MiB.
- `torii.attachments_max_archive_depth` (u32)
  - Maximum nested gzip/zstd layers.
  - Default: 2.
- `torii.attachments_sanitizer_mode` (string)
  - Sanitizer execution mode (`subprocess` or `in_process`).
  - `subprocess` requires the dedicated `attachment_sanitizer` executable beside the node and an OS sandbox (`bwrap` on Linux or `sandbox-exec` on macOS). It fails closed when either is unavailable. `in_process` does not provide a parser isolation boundary and is not recommended for a shipping deployment.
  - Default: `subprocess`.
- `torii.attachments_sanitize_timeout_ms` (u64)
  - Sanitization timeout in milliseconds.
  - Default: 1000.
- `torii.zk_prover_enabled` (bool)
  - Enables the background prover scan worker. When disabled, no new local diagnostic reports are created.
  - Default: true (idle until attachments exist).
- `torii.zk_prover_scan_period_secs` (u64)
  - Scan period for the background prover.
  - Default: 30 seconds.
- `torii.zk_prover_reports_ttl_secs` (u64)
  - Retention window for prover reports.
- `torii.zk_prover_reports_max_count` / `torii.zk_prover_reports_max_bytes`
  - Global on-disk retention geometry for report bodies plus their bounded summary shards.
  - Defaults: 4096 reports and 256 MiB. Before committing a report, the worker deterministically evicts the oldest reports until both limits are satisfied; zero count and byte budgets too small for one maximum-size report are rejected during configuration parsing.
- `torii.zk_prover_max_inflight` / `torii.zk_prover_max_scan_bytes` / `torii.zk_prover_max_scan_millis`
  - Concurrency and per-scan budgets for the prover worker.
  - Attachment discovery is inside the same wall-clock deadline, uses at most the first half of that deadline so scheduled work can make progress, and never materializes the complete multi-tenant namespace. One in-memory location slot is admitted per started 512 bytes of the byte budget (hard maximum 4096); directory work is limited to eight iterator steps per slot (hard maximum 32768). The cursor resumes on the next cycle and each bounded window is ordered canonically by tenant key and attachment id before scheduling. Discovery work exhaustion is reported as `reason="work"` alongside `bytes` and `time`.
- `torii.zk_prover_keys_dir` (path)
  - Directory holding verifying key bytes for registry entries without stored key bytes.
- `torii.zk_prover_allowed_backends` / `torii.zk_prover_allowed_circuits` (string list)
  - Allowlists for prover scope (prefix match, empty = allow all).
- `torii.ivm_tooling_max_inflight` / `torii.ivm_tooling_timeout_ms`
  - Bound concurrent blocking IVM contract simulation/view workers and their
    synchronous deadline. Timed-out workers retain the capacity lease until
    physical completion.
- `torii.max_content_len` (bytes)
  - Global HTTP request body limit; applies to attachments uploads as an upper bound.
- `confidential.tree_roots_history_len` (non-zero usize)
  - Bounds recent roots returned by `/v1/zk/roots`; the effective minimum is one. Empty-root construction and tree depth are fixed by the persisted confidential-tree profile and have no runtime configuration knobs.

Access control and rate limiting:
- `torii.require_api_token` (bool) and `torii.api_tokens` (list of strings)
  - When enabled and tokens are provided, app API routes require `x-api-token: <token>` header. Unknown/missing tokens are rejected.
- `torii.query_rate_per_authority_per_sec` (Option<u32>) and `torii.query_burst_per_authority` (Option<u32>)
  - Per-authority rate limiter for app API query endpoints, including attachment reads.
- `torii.tx_rate_per_authority_per_sec` (Option<u32>) and `torii.tx_burst_per_authority` (Option<u32>)
  - Per-authority transaction submission rate limiter for `/v1/pipeline/transactions` and other tx-producing endpoints.
- `torii.api_rate_limit_bypass_cidrs` (list of CIDRs)
  - Requests from these networks bypass the rate limiter only (still subject to body size, admission, token, internal-read, and routing authorization checks).

Tip: These keys map to the `iroha_config::parameters::user::Torii` section and are threaded into Torii at startup. Environment variables exist for developer convenience (e.g., `TORII_ATTACHMENTS_TTL_SECS`), but prefer static config files in production.

## Operational Notes

- Non-consensus: attaching proofs and running the background verifier does not modify WSV or affect consensus.
- Determinism & safety: id derivation and report generation are deterministic (based on body and content type). The prover verifies proofs using configured backends; it does not generate proofs or affect consensus.
- Sanitization: gzip/zstd payloads are expanded within configured limits and only allowlisted types are stored; sanitizer metadata is captured in `provenance` and compressed-origin exports are re‑sanitized. POST and export GET acquire the same bounded physical-work lease before handler work, and cancellation keeps that lease in every blocking worker, child process, and stdout reader until it actually exits.
- Subprocess isolation: Torii rejects the node binary and differently named helpers, clears the child environment to the three sanitizer protocol variables, exposes only the helper and runtime libraries inside the filesystem sandbox, and caps both request and response streams. Official release bundles and container images ship the helper; Linux images also ship Bubblewrap.
- GC cadence: attachment GC runs every minute and removes entries older than `attachments_ttl_secs`.
- Storage hygiene: deleting an attachment durably journals the mutation before removing its `.bin`, `.json`, live processing reference, and last-reference receipt; incomplete deletes are hidden and replayed before Torii serves the store. Report retention removes the corresponding node-local files under `zk_prover/reports`.
- Mutation recovery: every attachment write or delete uses one closed, versioned mutation journal. Startup replays that single authoritative operation before reconciling attachment pairs and prover receipts, so quota eviction and explicit/TTL deletion converge after any crash boundary. Node-global accounting scans at most 20,000 tenant-root entries and 40,000 aggregate child entries, counts malformed/raw entries against those bounds, and fails closed.
- Payloads: the prover expects `ProofAttachment`/`ProofAttachmentList` payloads (Norito or JSON). ZK1/TLV envelopes are tagged but rejected as top‑level payloads. The first-release ZK1 structural profile permits at most 64 TLVs per envelope, and repeated tags are stored once in report metadata.
- Key bytes: when a registry entry omits stored VK bytes, the prover loads bytes from `torii.zk_prover_keys_dir` using `zkid-v1-<id-hash>.vk` naming. `id-hash` is lowercase hexadecimal SHA-256 over `"iroha:torii:zk-key-id:v1" || u32_be(len(backend_utf8)) || backend_utf8 || u32_be(len(name_utf8)) || name_utf8`, using the exact unnormalised registry ID bytes.
- VK commitments are domain-separated SHA-256 hashes over the `iroha:zk:v1:vk`
  domain plus length-prefixed backend and VK bytes. Generic ledger
  `VerifyProof` and specialized proof instructions require a registry `vk_ref`;
  proof attachments do not carry verifying-key bytes.
- The retired Halo2 IVM binding circuit and its local proving-key archive
  do not establish execution soundness. Generic proof verification and
  unrelated circuits retain their own verifier-key policy.
- Halo2/Pasta uses transparent IPA parameters. Each admitted circuit checks its fixed compiled domain exponent against the canonical verifier-key envelope before constructing deterministic parameters.
- KAGEMUSHA V1 release archives authenticate each paired Pasta parameter payload by signed length and SHA-256 commitment; locally derived transparent parameters must match that commitment.
- Generic STARK/FRI parameters are authenticated by the registered verifier key and validated against consensus floors and ceilings.

## Examples

Raw attachment `curl` calls are intentionally omitted: all five routes require
the complete canonical exact-network account-signature header set. Prefer the
CLI or an SDK signer. If `require_api_token=true`, include the configured token
in addition to those signed headers; a token alone is rejected.

CLI shortcuts (`iroha_cli`):

```bash
# Upload attachment
iroha app zk attachments upload --file ./proof.json --content-type application/json

# List/get/delete
iroha app zk attachments list
iroha app zk attachments get --id <id> --out ./downloaded.bin
iroha app zk attachments delete --id <id>

```

See also: the ZK vote tally convenience endpoint (`POST /v1/zk/vote/tally`) and CLI helper `iroha app zk vote tally` for inspecting election tallies. Successful tally responses include `evaluated_block_height` and `evaluated_block_hash` from the same immutable state view used for lookup; unknown election identifiers return `404`.
