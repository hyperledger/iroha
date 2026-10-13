# Verifying-Key & Proof Lifecycle

This document captures how verifying keys (VKs) and zero-knowledge proof
envelopes flow through the first Iroha 3 release. It ties together on-chain
state, Torii app endpoints, and the CLI helpers for operators and SDK authors.

## High-level flow

1. **Authoritative VK creation** – An operator or compiler artefact produces a verifying key and its 32-byte commitment. VKs are versioned and namespaced by backend (`backend::name`).
2. **Admission through Torii** – An SDK either builds the registry transaction locally or asks
   `/v1/zk/vk/{register,update}` for a canonical unsigned draft. Signing remains local; the signed
   transaction is submitted through the ordinary transaction pipeline. Accepted transactions
   update the VK registry stored on-chain and replicated across peers.
3. **Contract/runtime usage** – Generic proof verification references VKs by `(backend, name)` through `vk_ref`. Specialized proof ISIs may carry proof-specific VK material only where their instruction binds it to a registered verifier commitment. Execution resolves VK commitments during proof verification.
4. **Proof verification** – Clients submit a signed transaction containing
   `VerifyProof` (or the applicable proof-bearing instruction) through the
   ordinary transaction pipeline. Verification runs inside `iroha_core_zk`
   during transaction execution. Successful verifications materialise
   `ProofRecord`s that can be queried via Torii (`/v1/zk/proofs*`).
5. **Background reporting** – The optional Torii prover worker (`torii.zk_prover_enabled=true`) scans attachments, verifies `ProofAttachment` payloads, and exports telemetry describing proof sizes and processing latency. Reports are deleted automatically after the configured TTL.

## Verifying keys

- Registry entries live in the world state under `verifying_keys[(backend, name)]`.
- When a new VK is registered, the commitment must match the hashed payload or inline bytes bundled with the transaction. Updates bump the version and must preserve monotonicity.
- A VK update is a key rotation for the same circuit identity: `circuit_id` is immutable for a registered `(backend, name)`. Register a distinct key id when introducing a different circuit.
- `CanManageVerifyingKeys` is a global, zero-field capability. The ledger requires its exact canonical unit payload; same-name permissions carrying arbitrary JSON do not authorize registry changes.

### Relevant endpoints

- `POST /v1/zk/vk/register` – validate and prepare an unsigned
  `RegisterVerifyingKey` transaction.
- `POST /v1/zk/vk/update` – validate and prepare an unsigned
  `UpdateVerifyingKey` transaction with a higher version and the existing `circuit_id`.
- `GET  /v1/zk/vk` – list VKs with optional filters (`backend`, `status`, `name_contains`) and bounded `limit`/`offset` pagination. Unknown status/order values, zero or over-limit pages, and pagination windows beyond the configured fetch budget fail with `400 Bad Request`.
- `GET  /v1/zk/vk/{backend}/{name}` – fetch a single VK record.

### CLI helpers

`iroha_cli app zk` builds, quotes, signs, and submits registry transactions with the active client
configuration:

- `iroha_cli app zk vk register --json path/to/register.json`
- `iroha_cli app zk vk update --json path/to/update.json`
- `iroha_cli app zk vk get --backend halo2/ipa --name kaigi-usage-v1`

The CLI JSON files contain public VK record data only and reject embedded authorities, private keys,
and unknown fields. Embedded VK record bytes remain base64-encoded, while commitments are lowercase
hex strings. SDKs that call the POST draft endpoints must additionally verify the returned canonical
payload, payload hash, chain, authority, single instruction, key id, and record before local signing.

## Proof lifecycle

### Submission & verification

- The pre-release decode-only `/v1/zk/verify` and `/v1/zk/submit-proof`
  convenience routes were removed because their success responses could be
  mistaken for cryptographic or ledger acceptance. Proofs enter the
  authoritative lifecycle only through a signed transaction containing
  `VerifyProof` or another proof-bearing instruction.
- During transaction execution, `iroha_core::smartcontracts::isi::zk::VerifyProof` computes a domain-separated, length-prefixed proof hash from the backend name and proof bytes, derives a `ProofId`, and ensures the proof is unique across the ledger.
- Generic `VerifyProof` resolves VK commitments from the referenced `(backend, name)` pair only. The referenced record must be active, gas-scheduled, active for its circuit/version, and bound to the proof envelope's circuit, schema, and `vk_hash`.
- The resulting `ProofRecord` stores:
  - `backend` and `proof_hash`
  - `status` (`Submitted`, `Verified`, `Rejected`)
  - `verified_at_height` (block height when verification finished)
  - Optional `vk_ref` and `vk_commitment`
- ZK1/TLV envelopes are inspected at verification time. Recognised 4-byte tags are recorded lazily to power tag-based queries.

### IVM execution proofs

`IvmProved` admission is closed until the complete native STARK execution
relation and State-owned finalized anchor are implemented. The former
four-commitment Halo2/STARK binding circuits and Torii proof job endpoint are
retired; deterministic replay of a supplied payload does not prove private
execution. The canonical `IvmExecutionStatementV1` value and normalized
signed-intent digest define public claims only and grant no authorization by
themselves. The binding-only Torii derive and proof-job routes are removed;
public preparation will require a distinct admissible response shape. Raw
private inputs stay local to future native proving.

### Query surface

`/v1/zk/proofs` and `/v1/zk/proofs/count` expose the ledger-facing records:

- Shared filters: `backend`, `status`, `has_tag`, and the verification and
  bridge height ranges. The list route additionally accepts `offset`, `limit`,
  `order=asc|desc`, and `ids_only`; the count route rejects those list-only
  parameters.
- Status values are exact (`Submitted`, `Verified`, or `Rejected`), tags are
  exactly four ASCII graphic/non-space printable characters, and inverted
  verification-height ranges are invalid. Malformed filters fail with
  `400 Bad Request` rather than being ignored.
- Tag filtering is efficient: tags are indexed at verification time and served from a dedicated `(tag → proof ids)` index.
- `ids_only=true` returns `{ backend, hash }` objects for lightweight pagination.
- `/v1/zk/proof/{backend}/{hash}` remains available for direct lookups.

### CLI coverage

New subcommands are available under `iroha_cli app zk proofs`:

- `iroha_cli app zk proofs list [--backend halo2/ipa] [--status Verified] [--has-tag PROF] [--limit 20]`
- `iroha_cli app zk proofs count [--backend halo2/ipa] [--has-tag IPAK]`
- `iroha_cli app zk proofs get --backend halo2/ipa --hash 0123...`

All commands emit Norito JSON responses. Filters match the HTTP query parameters one-to-one, making it easy to script pagination or supply the output into monitoring tooling.

## Background prover & telemetry

- Controlled via `torii.zk_prover_enabled`, `torii.zk_prover_scan_period_secs`, `torii.zk_prover_reports_ttl_secs`, `torii.zk_prover_max_inflight`, `torii.zk_prover_max_scan_bytes`, `torii.zk_prover_max_scan_millis`, `torii.zk_prover_keys_dir`, `torii.zk_prover_allowed_backends`, and `torii.zk_prover_allowed_circuits` in `iroha_config`.
- Attachments must decode as `ProofAttachment`/`ProofAttachmentList` (Norito or JSON). ZK1/TLV envelopes are tagged but rejected as top‑level payloads.
- Backends are allowlisted by prefix; default `["halo2/"]`. The `stark/fri` family is supported when built with feature `zk-stark` and enabled by the chain's ZK validity policy (`stark.enabled`). STARK guardrails split the outer `OpenVerifyEnvelope` cap (`stark.max_envelope_bytes`) from the backend-native proof cap (`stark.max_proof_bytes`). These switches and limits, like every other validity-affecting `[zk]` and `[confidential]` value, are committed chain policy: the custom parameter `zk_validity_policy_v1`, set in genesis or by an authorized `SetParameter` and effective from the next block, or the protocol default. A node's own configuration supplies only local resources (workers, queues, wall-clock budgets); it has no key for these values. `groth16/…` remains unsupported.
- Each report now records `latency_ms = processed_ms - created_ms` so operators can track queue delays.
- The prover emits telemetry:
  - `torii_zk_prover_attachment_bytes` (histogram, labelled by `content_type`)
  - `torii_zk_prover_latency_ms` (histogram)
  - `torii_zk_prover_inflight` (gauge) and `torii_zk_prover_pending` (gauge)
  - `torii_zk_prover_last_scan_bytes` and `torii_zk_prover_last_scan_ms` (gauges)
  - `torii_zk_prover_budget_exhausted_total{reason}` (counter)
  - `zk_verify_latency_ms` and `zk_verify_proof_bytes` (histograms, labelled by `backend`)
- Metrics surface under `/metrics` when telemetry is enabled with a profile that allows metrics exposure.
- Reports older than the TTL are garbage-collected on every scan tick. Reports
  are node-local worker state and have no HTTP deletion surface.

Nightly Milestone 0 runs scrape the new histograms and publish rollups alongside the existing Torii operator dashboard, ensuring proof verification latency regressions surface quickly.
