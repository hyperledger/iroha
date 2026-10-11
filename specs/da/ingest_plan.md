# Sora Nexus Data Availability Ingest Plan

_Drafted: 2026-02-20 - Owner: Core Protocol WG / Storage Team / DA WG_

The DA-2 workstream extends Torii with a blob ingest API that emits Norito
metadata and seeds SoraFS replication. This document captures the proposed
schema, API surface, and validation flow so implementation can proceed without
blocking on outstanding simulations (DA-1 follow-ups). All payload formats MUST
use Norito codecs; no serde/JSON fallbacks are permitted.

## Goals

- Accept large blobs (Taikai segments, lane sidecars, governance artefacts)
  deterministically over Torii.
- Produce canonical Norito manifests describing the blob, codec parameters,
  erasure profile, and retention policy.
- Persist chunk metadata in SoraFS hot storage and enqueue replication jobs.
- Publish pin intents + policy tags to the SoraFS registry and governance
  observers.
- Expose admission receipts so clients regain deterministic proof of publication.

## API Surface (Torii)

```
POST /v1/da/ingest
Content-Type: application/norito+v1
```

Payload is a Norito-encoded `DaIngestRequest`. Responses use
`application/norito+v1` and return `DaIngestReceipt`.

| Response | Meaning |
| --- | --- |
| 202 Accepted | Blob queued for chunking/replication; receipt returned. |
| 400 Bad Request | Schema/size violation (see validation checks). |
| 401 Unauthorized | Missing/invalid API token. |
| 409 Conflict | Duplicate `client_blob_id` with mismatched metadata. |
| 413 Payload Too Large | Exceeds configured blob length limit. |
| 429 Too Many Requests | Rate limit hit. |
| 503 Service Unavailable | Bounded ingest compute capacity is saturated; retry later. |
| 500 Internal Error | Unexpected failure (logged + alert). |

```
GET /v1/da/proof-policies
Accept: application/json | application/x-norito
```

Returns a versioned `DaProofPolicyBundle` derived from the current lane catalog.
The bundle advertises `version` (currently `1`), a `policy_hash` (hash of the
ordered policy list), and `policies` entries carrying `lane_id`, `dataspace_id`,
`alias`, and the enforced `proof_scheme` (`merkle_sha256` is the only V1
variant; KZG requires a separately reviewed future protocol version and wire
layout). Each block header
commits to the policy sidecar used for that block via
`da_proof_policies_hash`. This endpoint and the commitment list endpoint expose
the node's active snapshot for discovery. The commitment prove endpoint instead
returns the historical policy sidecar committed by the referenced block, so
verification is bound to the signed block state and never to a mutable current
Nexus configuration.

The policy hash is computed over the Norito-encoded ordered policy list and
changes when that list changes. Clients can compare it to detect current policy
changes; the hash alone does not authenticate a historical block's policy.

## Canonical Norito Schema

```rust
/// Top-level ingest request.
pub struct DaIngestRequest {
    pub network_id: NetworkId,            // exact genesis-derived security domain
    pub owner: AccountId,                 // authenticated quota charge identity
    pub client_blob_id: BlobDigest,      // submitter-chosen identifier
    pub lane_id: LaneId,                 // target Nexus lane
    pub epoch: u64,                      // epoch blob belongs to
    pub sequence: u64,                   // monotonic sequence per (lane, epoch)
    pub blob_class: BlobClass,           // TaikaiSegment, GovernanceArtifact, etc.
    pub codec: BlobCodec,                // e.g. "cmaf", "pdf", "norito-batch"
    pub erasure_profile: ErasureProfile, // parity configuration
    pub retention_policy: RetentionPolicy,
    pub chunk_size: u32,                 // bytes (must align with profile)
    pub total_size: u64,
    pub payload_hash: BlobDigest,         // BLAKE3 of canonical decompressed bytes
    pub compression: Compression,        // Identity, gzip, deflate, or zstd
    pub norito_manifest: Option<Vec<u8>>, // required slot: pre-built manifest or explicit null
    pub payload: Vec<u8>,                 // raw blob data (<= configured limit)
    pub metadata: ExtraMetadata,          // optional key/value metadata map
    pub signatures: Vec<DaIngestSignatureV1>, // canonical account-controller witnesses
}

pub struct DaIngestSignatureV1 {
    pub signer: PublicKey,
    pub signature: Signature,
}

// Compact immutable authorization carried into the block pin-intent sidecar.
pub struct DaIngestAuthorizationV1 {
    pub network_id: NetworkId,
    pub owner: AccountId,
    pub lane_id: LaneId,
    pub epoch: u64,
    pub sequence: u64,
    pub payload_hash: BlobDigest,
    pub payload_bytes: u64,
    pub request_content_hash: Hash,
    pub signatures: Vec<DaIngestSignatureV1>,
}

pub enum BlobClass {
    TaikaiSegment,
    NexusLaneSidecar,
    GovernanceArtifact,
    Custom(u16),
}

pub struct ErasureProfile {
    pub data_shards: u16,
    pub parity_shards: u16,
    pub row_parity_stripes: u16, // explicit even when zero
    pub chunk_alignment: u16, // chunks per availability slice
    pub fec_scheme: FecScheme,
}

pub struct RetentionPolicy {
    pub hot_retention_secs: u64,
    pub cold_retention_secs: u64,
    pub required_replicas: u16,
    pub storage_class: StorageClass,
    pub governance_tag: GovernanceTag,
}

pub struct ExtraMetadata {
    pub items: Vec<MetadataEntry>,
}

pub struct MetadataEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub visibility: MetadataVisibility, // public vs governance-only
    pub encryption: MetadataEncryption,
}

pub enum MetadataVisibility {
    Public,
    GovernanceOnly,
}

pub enum MetadataEncryption {
    None,
    ChaCha20Poly1305(MetadataCipherEnvelope),
}

pub struct MetadataCipherEnvelope {
    pub key_label: Option<String>, // required slot: label or explicit null
}

pub struct DaRentQuote {
    pub base_rent: XorQuantity,
    pub protocol_reserve: XorQuantity,
    pub provider_reward: XorQuantity,
    pub pdp_bonus: XorQuantity,
    pub potr_bonus: XorQuantity,
    pub egress_credit_per_gib: XorQuantity,
}

pub enum ChunkRole {
    Data,
    LocalParity,
    GlobalParity,
    StripeParity,
}

pub struct ChunkCommitment {
    pub index: u32,
    pub offset: u64,
    pub length: u32,
    pub commitment: ChunkDigest,
    pub parity: bool,
    pub role: ChunkRole,
    pub group_id: u32,
}

pub struct DaManifestV1 {
    pub version: u16,
    pub client_blob_id: BlobDigest,
    pub lane_id: LaneId,
    pub epoch: u64,
    pub blob_class: BlobClass,
    pub codec: BlobCodec,
    pub blob_hash: BlobDigest,
    pub chunk_root: BlobDigest,
    pub storage_ticket: StorageTicketId,
    pub total_size: u64,
    pub chunk_size: u32,
    pub total_stripes: u32,
    pub shards_per_stripe: u32,
    pub erasure_profile: ErasureProfile,
    pub retention_policy: RetentionPolicy,
    pub rent_quote: DaRentQuote,
    pub chunks: Vec<ChunkCommitment>,
    pub ipa_commitment: BlobDigest,
    pub metadata: ExtraMetadata,
    pub issued_at_unix: u64,
}

pub struct DaIngestReceipt {
    pub client_blob_id: BlobDigest,
    pub lane_id: LaneId,
    pub epoch: u64,
    pub blob_hash: BlobDigest,          // BLAKE3 of raw payload
    pub chunk_root: BlobDigest,         // Merkle root after chunking
    pub manifest_hash: BlobDigest,      // Norito manifest hash
    pub storage_ticket: StorageTicketId,
    pub pdp_commitment: Option<Vec<u8>>, // required slot: Norito-encoded PDP bytes or explicit null
    pub stripe_layout: DaStripeLayout,   // total_stripes, shards_per_stripe, row_parity_stripes
    pub queued_at_unix: u64,
    pub rent_quote: DaRentQuote,        // XOR rent + incentives derived from policy
    pub operator_signature: Signature,
}
```

The first-release request, receipt, authorization, signature, stripe-layout,
manifest, and manifest-owned carrier objects are closed schemas. Every V1 field
is present on the wire. Nullable manifest, PDP, and metadata key-label slots use
explicit `null`; zero row-parity counts and zero IPA commitments are still
serialized; tagged enum envelopes reject unknown fields; the metadata-
encryption envelope requires both its `cipher` and `params` keys; and unknown
fields are rejected at each closed boundary. Pre-release layouts that omitted
compression, row parity, PDP, stripe, rent, IPA, metadata encryption, or
cipher-envelope fields do not decode and are not upgraded by defaults.
Removing the pre-release fallbacks does not reorder or retype the canonical
binary fields, so already-valid current V1 bytes retain their encoding.

> Implementation note: the canonical Rust representations for these payloads now live under
> `iroha_data_model::da::types`, with request/receipt wrappers in `iroha_data_model::da::ingest`
> and the manifest structure in `iroha_data_model::da::manifest`.

The `compression` field advertises how callers prepared the payload. Torii accepts
`identity`, `gzip`, `deflate`, and `zstd`, transparently decompressing the bytes before
hashing, chunking, and verifying optional manifests.

### Validation Checklist

1. Verify request Norito header matches `DaIngestRequest`.
2. Before decompression, reject zero or greater-than-64-MiB `total_size` claims
   and reject `sequence = u64::MAX`, which cannot have a monotonic successor.
3. Enforce power-of-two `chunk_size` in the inclusive 1 KiB–2 MiB range and
   at most 1,024 source chunks.
4. Require 1–64 data shards, 2–64 parity shards, and at most 64 row-parity
   stripes. Cross-stripe parity is additionally limited to 64 source stripes,
   bounding the cubic RS16 matrix step. `rs16::validate_erasure_work_budget`
   also caps generated parity bytes and transient RS16 workspace at 128 MiB
   each, closing multiplicative layouts that pass the dimension caps.
   Signature verification, normalization, chunking, RS16 generation, manifest
   construction, and PDP construction run on blocking workers behind
   `torii.da_ingest.max_concurrent_compute_jobs` (default `1`). The owned
   semaphore permit remains inside the physical worker, so cancelling an HTTP
   request cannot admit replacement work while its detached computation is
   still running. Admission is fail-fast: a request that reaches a saturated
   compute boundary receives `503` instead of retaining its decoded payload in
   an unbounded semaphore wait queue.
5. `retention_policy.required_replica_count` must respect governance baseline.
6. Require the exact genesis-derived `NetworkId`, bind `owner` to the
   authenticated account, and verify the canonical witness set against the
   committed account controller. Single-key accounts require exactly their
   controller key; multisig accounts require committed-member weights meeting
   the committed threshold.
7. Reject duplicate `client_blob_id` unless payload hash + metadata identical.
8. When `norito_manifest` is provided, verify every chunk field—including
   `role` and `group_id`—exactly matches the canonical chunk vector before
   accepting its IPA commitment; otherwise the node generates and stores the
   manifest.
9. Enforce the configured replication policy: Torii rewrites the submitted
   `RetentionPolicy` with `torii.da_ingest.replication_policy` (see
   `replication_policy.md`) and rejects pre-built manifests whose retention
   metadata does not match the enforced profile.

### Request authorization

DA ingest uses one required, two-layer V1 signing preimage. The inner BLAKE3
content commitment starts with `iroha:da-ingest-request:content:v1\0` and
absorbs the client blob id, class, codec, erasure and retention policies, chunk
size, compression, optional manifest, transported payload, and ordered metadata
entries. Variable-width values use unsigned little-endian `u64` lengths.

The outer authorization digest starts with `iroha:da-ingest-request:v1\0` and
absorbs the exact 32 genesis-hash bytes of `NetworkId`, the length-prefixed
canonical controller bytes of `owner`, lane, epoch, sequence, the BLAKE3
commitment and exact byte length of the canonical decompressed payload, and the
inner content commitment. Witnesses are non-empty and strictly ordered by
`PublicKey`; duplicate, invalid, or non-canonical witness sets are rejected.
There is no label-domain signature, unsigned pin intent, omitted authorization,
or alternate decoder. The current pin-intent JSON shape is closed: its alias
slot is always present as a string or explicit `null`, and unknown fields are
rejected on both an intent and its header-committed bundle.

Torii checks the exact network and authenticated principal before
decompression, erasure computation, or storage work. Consensus repeats the
security decision from the compact
`DaIngestAuthorizationV1` carried by every `DaPinIntent`: it verifies the
enclosing lane/epoch/sequence tuple, exact network, signatures, payload charge,
account existence, and the committed single-key or weighted-multisig controller
before any quota accounting. Rust, JavaScript, and Swift builders share a
golden digest vector.

### Exact post-ingest pin authorization

`DaPinScopeV1` binds the original network, owner, authorization digest, lane,
epoch and sequence to the durable storage ticket, manifest digest and optional
alias. `request_authorization_digest` is a `BlobDigest` containing all 32 raw
BLAKE3 bytes from `DaIngestAuthorizationV1::signing_digest()`. No marker bit is
inserted or normalized. Its binary field uses the ordinary DA digest encoding;
JSON uses the canonical DA fixed-byte representation. This is the sole field
representation, and matching compares every digest byte.

The producer's scope witnesses sign the domain-separated pin-scope transcript.
Changing any digest bit, storage ticket, manifest or alias invalidates those
witnesses. The SDK preserves the original ingest request and adds its scope
witness for one explicit follow-up submission. It checks the returned scope and
durable receipt against those exact inputs; a second pending result is returned
to the caller rather than replayed in a loop.

### Governed producer and epoch admission

The consensus-visible custom parameter
`iroha:da_ingest_admission_policy_v1` is the only authority for DA producers
and replay epochs. Each canonical lane entry binds an exact active lane
incarnation, a sorted producer-account set, one current epoch, and at most the
immediately preceding grace epoch. The V1 payload is bounded to 1,024 lane
records, 4,096 producer identities, and 1,024 admitted `(lane, epoch)` windows.
An absent or malformed policy disables non-empty DA ingest; it is never
interpreted as an open policy.

Policy revision one has no predecessor. Every later revision increments by
exactly one and commits the exact predecessor policy hash. Existing lane
records may not be dropped. Changing a producer set, disabling a lane, or
changing its incarnation must advance the current epoch; grace may carry only
the predecessor's current epoch and may not cross an incarnation change. An
empty producer set is a durable lane tombstone: it admits and retains no
window, while preserving the epoch floor. A later reactivation remains in the
same permanent lane record and must advance that floor, so a retired lane
identifier cannot make an old signed request valid after reuse.

Torii captures the committed policy and active incarnation from one state view
at the next proposal height before compute, then repeats that check under the
replay-lifecycle fence before reservation and durable receipt commit. A policy
transition during queued spool work cancels or retires the stale receipt.
Validators independently apply the same owner/lane/incarnation/epoch decision
to every header-committed `DaPinIntent`, so node-local configuration cannot
create a second admission path.

When a policy revision retires a window, Torii first hard-links every excluded
receipt into the durable retired-receipt archive and syncs that directory. It
then removes the active receipt names, syncs the spool root, checkpoints and
truncates the replay cursor journal, removes receipt-index heads, and finally
clears matching replay-cache state. The ordering is retryable after any crash:
old receipt evidence cannot repopulate a cursor on restart, and a cursor is not
forgotten while its active receipt name can still be rediscovered.

### Chunking & Replication Flow

1. Chunk payload into `chunk_size`, compute BLAKE3 per chunk + Merkle root.
2. Build Norito `DaManifestV1` (new struct) capturing chunk commitments (role/group_id),
   erasure layout (row and column parity counts plus `ipa_commitment`), retention policy,
   and metadata.
3. Queue the canonical manifest and PDP bytes under the sharded ticket index
   `config.da_ingest.manifest_store_dir/artifacts/<first-ticket-byte-hex>/<ticket-hex>/`
   as `manifest.norito` and `pdp-commitment.norito`. The one-record-per-ticket
   layout gives SoraFS orchestration a direct, unambiguous lookup without
   scanning the shared spool.
4. Publish pin intents via `sorafs_car::PinIntent` with governance tag + policy.
5. Emit Norito event `DaIngestPublished` to notify observers (light clients,
   governance, analytics).
6. Return `DaIngestReceipt` (signed by Torii DA service key) and add the
   `Sora-PDP-Commitment` response header containing the base64 Norito encoding
   of the derived commitment so SDKs can stash the sampling seed immediately.
   The receipt now embeds `rent_quote` (a `DaRentQuote`) and `stripe_layout`
   so submitters can surface the XOR obligations, reserve share, PDP/PoTR bonus expectations,
   and the 2D erasure matrix dimensions alongside the storage-ticket metadata before committing funds.
7. Optional registry metadata is limited to `da.registry.alias`, a public,
   unencrypted UTF-8 alias used to seed the pin registry entry. Registry
   ownership and quota identity come only from the exact-network signed
   `owner`; metadata cannot select or rebind an owner. Controller witnesses are
   checked before expensive ingest work and checked again from committed state
   during block admission.

### Consensus quota admission

Every accepted block charges all DA pin intents to their signed `owner` under
two deterministic ceilings: intent count and canonical payload bytes. Windows
are derived solely from block height as `(height - 1) /
nexus.da.ingest_quota_window_blocks`; wall-clock time and Torii-local process
state are not inputs. The first-release defaults are 100 blocks, 1,024 intents,
and 64 GiB per account per window, configured by:

- `nexus.da.ingest_quota_window_blocks`
- `nexus.da.ingest_quota_max_count_per_account`
- `nexus.da.ingest_quota_max_bytes_per_account`

All values are mandatory non-zero consensus-policy inputs. Validators aggregate
the complete block with checked arithmetic, reject the entire block on an
overflow, corrupt prior record, or either exceeded ceiling, and then commit the
canonical usage records and pin indexes through the same `WorldBlock`. The
native `da_ingest_quota_v1/` state namespace is opaque to generic IVM durable
state syscalls, so neither a normal transaction nor a directly invoked contract
can forge, reset, disclose, or delete quota counters. Replay and restart use the
same checkpointed WSV records; the signed `(lane, epoch, sequence)` remains the
one-shot nonce and existing pin indexes reject reuse.

## Storage / Registry Updates

- Extend `sorafs_manifest` with `DaManifestV1`, enabling deterministic parsing.
- Add new registry stream `da.pin_intent` with versioned payload referencing
  manifest hash + ticket id.
- Update observability pipelines to track ingest latency, chunking throughput,
  replication backlog, and failure counts.
- Torii `/status` responses now include a `taikai_ingest` array that surfaces the latest
  encoder-to-ingest latency, live-edge drift, and error counters per (cluster, stream), enabling DA-9
  dashboards to ingest health snapshots directly from nodes without scraping Prometheus.

## Testing Strategy

- Unit tests for schema validation, signature checks, duplicate detection.
- Golden tests verifying Norito encoding of `DaIngestRequest`, manifest, and receipt.
- Negative wire tests proving omission-based pre-release request, stripe, receipt, manifest,
  erasure-profile, and metadata layouts do not decode, plus JSON tests for required nullable slots
  and unknown-field rejection throughout the manifest-owned object graph.
- Integration harness spinning up mock SoraFS + registry, asserting chunk + pin flows.
- Property tests covering random erasure profiles and retention combinations.
- Fuzzing of Norito payloads to guard against malformed metadata.
- Golden fixtures for every blob class live under
  `fixtures/da/ingest/manifests/<blob_class>/manifest.{norito.hex,json}` with a companion chunk
  listing in `fixtures/da/ingest/sample_chunk_records.txt`. The ignored test
  `regenerate_da_ingest_fixtures` refreshes the fixtures, while
  `manifest_fixtures_cover_all_blob_classes` fails as soon as a new `BlobClass` variant is added
  without updating the Norito/JSON bundle. This keeps Torii, SDKs, and docs honest whenever DA-2
  accepts a new blob surface.【fixtures/da/ingest/README.md:1】【crates/iroha_torii/src/da/tests.rs:2902】

## CLI & SDK Tooling (DA-8)

- `iroha app da submit` (new CLI entrypoint) now wraps the shared ingest builder/publisher so operators
  can ingest arbitrary blobs outside of the Taikai bundle flow. The command lives in
  `crates/iroha_cli/src/commands/da.rs:1` and consumes a payload, erasure/retention profile, and
  optional metadata/manifest files before signing the canonical `DaIngestRequest` with the CLI
  config key. Successful runs persist `da_request.{norito,json}` and `da_receipt.{norito,json}` under
  `artifacts/da/submission_<timestamp>/` (override via `--artifact-dir`) so release artefacts can
  record the exact Norito bytes used during ingestion.
- The command defaults to `client_blob_id = blake3(payload)` but accepts overrides via
  `--client-blob-id`, honours metadata JSON maps (`--metadata-json`) and pre-generated manifests
  (`--manifest`), and supports `--no-submit` for offline preparation plus `--endpoint` for custom
  Torii hosts. Receipt JSON is printed to stdout in addition to being written to disk, closing the
  DA-8 “submit_blob” tooling requirement and unblocking SDK parity work.
- `iroha app da get` adds a DA-focused alias for the multi-source orchestrator that already powers
  `iroha app sorafs fetch`. Operators can point it at manifest + chunk-plan artefacts (`--manifest`,
  `--plan`, `--manifest-id`) **or** simply pass a Torii storage ticket via `--storage-ticket`. When the
  ticket path is used the CLI pulls the manifest from `/v1/da/manifests/<ticket>`, persists the bundle
  under `artifacts/da/fetch_<timestamp>/` (override with `--manifest-cache-dir`), derives the **manifest
  hash** for `--manifest-id`, and then runs the orchestrator with the supplied `--gateway-provider`
  list. Payload verification still relies on the embedded CAR/`blob_hash` digest while the gateway id is
  now the manifest hash so clients and validators share a single blob identifier. All advanced knobs from
  the SoraFS fetcher surface intact (manifest envelopes, client labels, guard caches, anonymity transport
  overrides, scoreboard export, and `--output` paths), and the manifest endpoint can be overridden via
  `--torii-url` for a custom Torii base URL, so end-to-end availability checks live entirely under the
  `da` namespace without duplicating orchestrator logic.
- `iroha app da get-blob` pulls canonical manifests straight from Torii via `GET /v1/da/manifests/{storage_ticket}`.
  The command now labels artefacts with the manifest hash (blob id), writing
  `manifest_{manifest_hash}.norito`, `manifest_{manifest_hash}.json`, and `chunk_plan_{manifest_hash}.json`
  under `artifacts/da/fetch_<timestamp>/` (or a user-supplied `--output-dir`) while echoing the exact
  `iroha app da get` invocation (including `--manifest-id`) required for the follow-up orchestrator fetch.
  This keeps operators out of the manifest spool directories and guarantees the fetcher always uses the
  signed artefacts emitted by Torii. The JavaScript Torii client mirrors this flow via
  `ToriiClient.getDaManifest(storageTicketHex)` while the Swift SDK now exposes
  `ToriiClient.getDaManifestBundle(...)`. Both return the decoded Norito bytes, manifest JSON, manifest hash,
  and strict payload-bound `sorafs.chunk_fetch_plan.v1` object so SDK callers
  can hydrate orchestrator sessions without shelling out to the CLI. Bare
  arrays and plans with missing or substituted whole-payload bindings are
  rejected. Swift
  clients can additionally call `fetchDaPayloadViaGateway(...)` to pipe those bundles through the native
  SoraFS orchestrator wrapper.【IrohaSwift/Sources/IrohaSwift/ToriiClient.swift:240】
- `/v1/da/manifests` responses now surface `manifest_hash`, and both CLI + SDK helpers (`iroha app da get`,
  `ToriiClient.fetchDaPayloadViaGateway`, and the Swift/JS gateway wrappers) treat this digest as the
  canonical manifest identifier while continuing to verify payloads against the embedded CAR/blob hash.
- `iroha app da rent-quote` computes deterministic rent and incentive breakdowns for a supplied storage size
  and retention window. The helper consumes either the active `DaRentPolicyV1` (JSON or Norito bytes) or
  the built-in default, validates the policy, and prints a JSON summary (`gib`, `months`, policy metadata,
  and the `DaRentQuote` fields) so auditors can cite exact XOR charges inside governance minutes without
  writing ad hoc scripts. The command now also emits a one-line `rent_quote ...` summary before the JSON
  payload to make console logs and runbooks easier to scan when quotes are generated during incidents.
  Pass `--quote-out artifacts/da/rent_quotes/<stamp>.json` (or any other path)
  to persist the pretty-printed summary and use `--policy-label "governance ticket #..."` when the
  artefact needs to cite a specific vote/config bundle; the CLI trims custom labels and rejects blank
  strings to keep `policy_source` values meaningful in evidence bundles. See
  `crates/iroha_cli/src/commands/da.rs` for the subcommand and `specs/da/rent_policy.md`
  for the policy schema.【crates/iroha_cli/src/commands/da.rs:1】【specs/da/rent_policy.md:1】
- Pin registry parity now extends to SDKs:
  `buildRegisterPinManifestTransaction(...)` builds and signs one exact-network
  native transaction whose sole `RegisterPinManifest` carries the canonical
  `ManifestV1` bytes, optional alias, and optional non-zero predecessor.
  `ToriiClient.registerSorafsPinManifest(...)` accepts only those signed bytes,
  disables retries and redirects, and posts versioned Norito. Torii verifies
  the network/signature/instruction shape and derives the digest, chunker,
  content length, pin policy, and fee inputs solely from the manifest. No
  client-supplied lifecycle epoch or JSON registration DTO is accepted. This
  keeps CI bots and automation from shelling out to the CLI when recording
  registrations through `/v1/sorafs/pin/register`, and the helper ships with
  TypeScript/README coverage so DA-8’s “submit/get/prove” tooling parity is
  fully satisfied on JS alongside Rust/Swift.【javascript/iroha_js/src/toriiClient.js:1045】【javascript/iroha_js/test/toriiClient.test.js:788】
- `iroha app da prove-availability` chains all of the above: it takes a storage ticket, downloads the
  canonical manifest bundle, runs the multi-source orchestrator (`iroha app sorafs fetch`) against the
  supplied `--gateway-provider` list, persists the downloaded payload + scoreboard under
  `artifacts/da/prove_availability_<timestamp>/`, and immediately invokes the existing PoR helper
  (`iroha app da prove`) using the fetched bytes. Operators can tweak the orchestrator knobs
  (`--max-peers`, `--scoreboard-out`, manifest endpoint overrides) and the proof sampler
  (`--sample-count`, `--leaf-index`, `--sample-seed`) while a single command produces the artefacts
  expected by DA-5/DA-9 audits: payload copy, scoreboard evidence, and JSON proof summaries.
- `da_reconstruct` (new in DA-6) reads a canonical manifest plus the chunk directory emitted by the chunk
  store (`chunk_{index:05}.bin` layout) and deterministically reassembles the payload while verifying
  every Blake3 commitment. The CLI lives under `crates/sorafs_car/src/bin/da_reconstruct.rs` and ships as
  part of the SoraFS tooling bundle. Typical flow:
  1. `iroha app da get-blob --storage-ticket <ticket>` to download `manifest_<manifest_hash>.norito` and the chunk plan.
  2. `iroha app sorafs fetch --manifest manifest_<manifest_hash>.json --plan chunk_plan_<manifest_hash>.json --output payload.car`
     (or `iroha app da prove-availability`, which writes the fetch artefacts under
     `artifacts/da/prove_availability_<ts>/` and persists per-chunk files inside the `chunks/` directory).
  3. `cargo run -p sorafs_car --features da_harness,dev-tools --bin da_reconstruct --manifest manifest_<manifest_hash>.norito --chunks-dir ./artifacts/da/prove_availability_<ts>/chunks --output reconstructed.bin --json-out summary.json`.

  A regression fixture lives under `fixtures/da/reconstruct/rs_parity_v1/` and captures the full manifest
  and chunk matrix (data + parity) used by `tests::reconstructs_fixture_with_parity_chunks`. Regenerate it with

  ```sh
  cargo test -p sorafs_car --features 'dev-tools,da_harness' --bin da_reconstruct regenerate_da_reconstruct_fixture_assets -- --ignored --nocapture
  ```

  The fixture emits:

  - `manifest.{norito.hex,json}` — canonical `DaManifestV1` encodings.
  - `chunk_matrix.json` — producer-ordered index/offset/length/digest/parity rows: each source
    stripe's data commitments precede its global parity commitments, with stripe parity last.
  - `chunks/` — `chunk_{index:05}.bin` payload slices for both data and parity shards.
  - `payload.bin` — deterministic payload used by the parity-aware harness test.
  - `commitment_bundle.{json,norito.hex}` — sample Merkle-only
    `DaCommitmentBundle` using the V1 wire layout.

  The harness refuses missing or truncated chunks, checks the final payload Blake3 hash against `blob_hash`,
  and emits a summary JSON blob (payload bytes, chunk count, storage ticket) so CI can assert reconstruction
  evidence. This closes the DA-6 requirement for a deterministic reconstruction tool that operators and QA
  jobs can invoke without wiring bespoke scripts.

## TODO Resolution Summary

All previously blocked ingest TODOs have been implemented and verified:

- **Compression hints** — Torii accepts caller-provided labels (`identity`, `gzip`, `deflate`,
  `zstd`) and normalises payloads before validation so the canonical manifest hash matches the
  decompressed bytes.【crates/iroha_torii/src/da/ingest.rs:220】【crates/iroha_data_model/src/da/types.rs:161】
- **Governance-only metadata encryption** — Torii now encrypts governance metadata with the
  configured ChaCha20-Poly1305 key, rejects mismatched labels, and surfaces two explicit
  configuration knobs (`torii.da_ingest.governance_metadata_key_hex`,
  `torii.da_ingest.governance_metadata_key_label`) to keep rotation deterministic.【crates/iroha_torii/src/da/ingest.rs:707】【crates/iroha_config/src/parameters/actual.rs:1662】
- **Large payload streaming** — multi-part ingestion is live. Clients stream deterministic
  `DaIngestChunk` envelopes keyed by `client_blob_id`, Torii validates each slice, stages them
  under `manifest_store_dir`, and atomically rebuilds the manifest once the `is_last` flag lands,
  eliminating the RAM spikes seen with single-call uploads.【crates/iroha_torii/src/da/ingest.rs:392】
- **Manifest versioning** — `DaManifestV1` carries an explicit `version` field and Torii refuses
  unknown versions, guaranteeing deterministic upgrades when new manifest layouts ship.【crates/iroha_data_model/src/da/types.rs:308】
- **PDP/PoTR hooks** — PDP commitments derive directly from the chunk store and are persisted
  beside manifests so DA-5 schedulers can launch sampling challenges from canonical data; the
  `Sora-PDP-Commitment` header now ships with both `/v1/da/ingest` and `/v1/da/manifests/{ticket}`
  responses so SDKs immediately learn the signed commitment that future probes will reference.【crates/sorafs_car/src/lib.rs:360】【crates/sorafs_manifest/src/pdp.rs:1】【crates/iroha_torii/src/da/ingest.rs:476】
- **Shard cursor journal** — a lane's typed `shard_id` override selects its DA/storage shard
  (defaulting to `lane_id` when absent), and Sumeragi now persists the highest
  `(epoch, sequence)` per `(shard_id, lane_id)` into
  `da-shard-cursors.norito` alongside the DA spool so restarts drop resharded/unknown lanes and keep
  replay deterministic. The in-memory index uses the same `(shard_id, lane_id)` key, so lanes
  sharing a storage shard retain independent lane-scoped sequence cursors. It fails fast on
  commitments for unmapped lanes instead of defaulting to the lane id, making cursor advancement
  and replay errors explicit, and block validation rejects per-lane shard-cursor regressions with
  a dedicated `DaShardCursorViolation` reason + telemetry labels for operators. The first-release
  journal layout requires both each cursor's `last_block_height` and the complete
  `canonical_reset_heights` map; truncated pre-release layouts are rejected rather than defaulted.
  Startup and rewind are serialized by one hydration fence, capture one fixed committed WSV hash
  prefix, and build commitments, confidential receipts, receipt cursors, shard cursors, and pin
  intents in a private aggregate. A missing non-hash-only Kura body, WSV/body hash mismatch,
  cursor regression, or receipt gap aborts the rebuild without changing any published index; all
  five indexes publish only after the complete replay succeeds. Historical commitments for lanes
  no longer in the catalog remain identity-only and do not become active query/cursor rows. Block
  proof and block/transaction query consumers likewise accept a Kura body only when its hash and
  declared height match the immutable WSV slot being queried.
  【crates/iroha_config/src/parameters/actual.rs】【crates/iroha_core/src/da/shard_cursor.rs】【crates/iroha_core/src/sumeragi/main_loop.rs】【crates/iroha_core/src/state.rs】【crates/iroha_core/src/block.rs】【specs/nexus_lanes.md:47】
- **Shard cursor lag telemetry** — the `da_shard_cursor_lag_blocks{lane,shard}` gauge reports how
  far a shard trails the height being validated. Missing/stale/unknown lanes set the lag to the
  required height (or delta), and successful advances reset it to zero so steady-state stays flat.
  Operators should alarm on non-zero lags, inspect the DA spool/journal for the offending lane,
  and verify the lane catalog for accidental resharding before replaying the block to clear the
  gap.
- **Confidential compute lanes** — lanes use the typed `confidential_compute` descriptor with an
  exact `mechanism` (`encryption` or `secret_sharing`), a positive `key_version`, and canonically
  ordered `allowed_audiences`, together with a non-full-replica storage profile. Catalog
  construction rejects partial or malformed policies; the retired string metadata keys are never
  interpreted. Sumeragi enforces non-zero payload/manifest digests and storage tickets and indexes
  the SoraFS ticket + policy version without exposing payload bytes. Receipts hydrate from Kura
  during replay so validators recover the same confidentiality metadata after restarts.【crates/iroha_config/src/parameters/actual.rs】【crates/iroha_core/src/da/confidential.rs】【crates/iroha_core/src/da/confidential_store.rs】【crates/iroha_core/src/state.rs】

## Implementation Notes

- Torii’s `/v1/da/ingest` endpoint now normalises payload compression, enforces the replay cache,
  deterministically chunks the canonical bytes, rebuilds `DaManifestV1`, and drops the encoded payload
  into `config.da_ingest.manifest_store_dir` for SoraFS orchestration before issuing the receipt; the
  handler also attaches a `Sora-PDP-Commitment` header so clients can capture the encoded commitment
  immediately.【crates/iroha_torii/src/da/ingest.rs:220】
- Client-supplied manifest bytes are admitted only through checked Norito decoding; malformed or
  truncated payloads return `400 Bad Request`. Manifest retrieval resolves the exact sharded ticket
  path above, so request cost is independent of the total number of spool artifacts. On Unix,
  Torii creates the ticket-index directories with owner-only `0700` permissions and all new DA and
  Taikai artifact files with `0600` permissions.
- Replay admission has two independent bounds: per-window fingerprints and the configured global
  number of `(lane, epoch)` windows. Durable cursor advances use a checksummed append journal and a
  capacity-sized checkpoint interval, making persistence amortized O(1) per advance instead of
  rewriting the full cursor map for every receipt. Recovery truncates only an incomplete final
  frame; over-capacity or corrupt complete state fails startup closed.
- After persisting the canonical `DaCommitmentRecord`, Torii now emits a
  `da-commitment-schedule-<lane>-<epoch>-<sequence>-<ticket>.norito` file beside the manifest spool.
  Each entry bundles the record with the raw Norito `PdpCommitment` bytes so DA-3 bundle builders and
  DA-5 schedulers ingest identical inputs without re-reading manifests or chunk stores.【crates/iroha_torii/src/da/ingest.rs:1814】
- SDK helpers expose the PDP header bytes without forcing every client to reimplement Norito parsing:
  `iroha::da::{decode_pdp_commitment_header, receipt_pdp_commitment}` cover Rust, the Python `ToriiClient`
  now exports `decode_pdp_commitment_header`, and `IrohaSwift` ships matching helpers so mobile
  clients can stash the encoded sampling schedule immediately.【crates/iroha/src/da.rs:1】【python/iroha_torii_client/client.py:1】【IrohaSwift/Sources/IrohaSwift/ToriiClient.swift:1】
- Torii also exposes `GET /v1/da/manifests/{storage_ticket}` so SDKs and operators can fetch manifests
  and chunk plans without touching the node’s spool directory. The response returns the Norito bytes
  (base64), rendered manifest JSON, a strict
  `sorafs.chunk_fetch_plan.v1` `chunk_plan` object ready for `sorafs fetch`. Manifest-to-plan
  conversion validates the full producer-ordered RS16 inventory, then includes only data
  commitments in this application-payload fetch plan; parity commitments remain in the manifest
  and reconstruction inventory,
  plus the relevant
  hex digests (`storage_ticket`, `client_blob_id`, `blob_hash`, `chunk_root`) so downstream tooling can
  feed the orchestrator without recomputing digests, and emits the same `Sora-PDP-Commitment` header to
  mirror ingest responses. Manifest retrieval intentionally has no sampling or challenge query:
  Torii cannot turn a requester-selected value into an availability guarantee. The CLI's explicit
  `--sample-count`, `--sample-seed`, and `--leaf-index` inputs produce local retrievability
  diagnostics only; those proofs are not valid inputs for rewards, slashing, provider availability
  claims, or consensus. Any future enforcement must use a committed challenge (for example, a
  governed VRF output) whose exact block and manifest binding cannot be chosen by the provider.
  【crates/iroha_torii/src/da/ingest.rs:1】【crates/iroha_cli/src/commands/da.rs:1】

### Large Payload Streaming Flow

Clients that need to ingest assets larger than the configured single-request limit initiate a
streaming session by calling `POST /v1/da/ingest/chunk/start`. Torii responds with a
`ChunkSessionId` (BLAKE3-derived from the requested blob metadata) and the negotiated chunk size.
Each subsequent `DaIngestChunk` request carries:

- `client_blob_id` — identical to the final `DaIngestRequest`.
- `chunk_session_id` — ties slices to the running session.
- `chunk_index` and `offset` — enforce deterministic ordering.
- `payload` — up to the negotiated chunk size.
- `payload_hash` — BLAKE3 hash of the slice so Torii can validate without buffering the entire blob.
- `is_last` — indicates the terminal slice.

Torii persists validated slices under `config.da_ingest.manifest_store_dir/chunks/<session>/` and
records progress inside the replay cache to honour idempotency. When the final slice lands, Torii
reassembles the payload on disk (streaming through the chunk directory to avoid memory spikes),
computes the canonical manifest/receipt exactly as with single-shot uploads, and finally responds to
`POST /v1/da/ingest` by consuming the staged artifact. Failed sessions can be aborted explicitly or
are garbage-collected after `config.da_ingest.replay_cache_ttl`. This design keeps the network format
Norito-friendly, avoids client-specific resumable protocols, and reuses the existing manifest pipeline
unchanged.

**Implementation status.** The canonical Norito types now live in
`crates/iroha_data_model/src/da/`:

- `ingest.rs` defines `DaIngestRequest`/`DaIngestReceipt`, together with the
  `ExtraMetadata` container used by Torii.【crates/iroha_data_model/src/da/ingest.rs:1】
- `manifest.rs` hosts `DaManifestV1` and `ChunkCommitment`, which Torii emits after
  chunking completes.【crates/iroha_data_model/src/da/manifest.rs:1】
- `types.rs` provides shared aliases (`BlobDigest`, `RetentionPolicy`,
  `ErasureProfile`, etc.) and encodes the default policy values documented below.【crates/iroha_data_model/src/da/types.rs:240】
- Manifest and PDP spool files land in the sharded, storage-ticket-indexed
  `config.da_ingest.manifest_store_dir/artifacts/` hierarchy, ready for direct
  SoraFS orchestration lookup without a global directory scan.【crates/iroha_torii/src/da/ingest.rs:220】
- Sumeragi enforces manifest availability when sealing or validating DA bundles:
  blocks fail validation if the spool is missing the manifest or the hash differs
  from the commitment.【crates/iroha_core/src/sumeragi/main_loop.rs:5335】【crates/iroha_core/src/sumeragi/main_loop.rs:14506】

Roundtrip coverage for the request, manifest, and receipt payloads is tracked in
`crates/iroha_data_model/tests/da_ingest_roundtrip.rs`. Manifest coverage also
asserts the exact current JSON object graph and rejects missing, unknown, and
pre-release binary carrier layouts without compatibility decoding.
【crates/iroha_data_model/tests/da_ingest_roundtrip.rs:1】

**Retention defaults.** Governance ratified the initial retention policy during
SF-6; the defaults enforced by `RetentionPolicy::default()` are:

- hot tier: 7 days (`604_800` seconds)
- cold tier: 90 days (`7_776_000` seconds)
- required replicas: `3`
- storage class: `StorageClass::Hot`
- governance tag: `"da.default"`

Downstream operators must override these values explicitly when a lane adopts
stricter requirements.

## Rust client proof artefacts

`iroha::Client::da().manifest(&StorageTicketId).await` reads the canonical typed
Torii response through the client-owned asynchronous transport. Archive validation,
filesystem operations and PoR generation live in `iroha_storage_client`.
`StorageClient::da_manifest` verifies the response projections against the complete
Norito artifact before returning a bundle. The explicit `iroha::blocking` facade
uses the same manifest operation for synchronous callers.

### Example

```rust
use iroha::client::Client;
use iroha_storage_client::{
    client::{StorageClient, build_da_proof_artifact, write_da_proof_artifact},
    da::{DaProofArtifactMetadata, DaProofConfig},
};

let client = Client::builder(config).build()?;
let storage = StorageClient::new(&client);
let manifest = storage.da_manifest(&storage_ticket).await?;
let payload = std::fs::read("artifacts/da/payload.car")?;
let metadata = DaProofArtifactMetadata::new(
    "artifacts/da/manifest.norito",
    "artifacts/da/payload.car",
);

// Build the JSON artefact in-memory.
let artifact = build_da_proof_artifact(
    &manifest,
    &payload,
    &DaProofConfig::default(),
    &metadata,
)?;

// Persist it next to other DA artefacts.
write_da_proof_artifact(
    &manifest,
    &payload,
    &DaProofConfig::default(),
    &metadata,
    "artifacts/da/proof_summary.json",
    true,
)?;
```

The JSON payload that leaves the helper matches the CLI down to the field names
(`manifest_path`, `payload_path`, `proofs[*].chunk_digest`, etc.), so existing
automation can diff/parquet/upload the file without format-specific branches.

## Proof verification benchmark

Use the DA proof benchmark harness to validate verifier budgets on representative payloads before
tightening block-level caps:

- `cargo xtask da-proof-bench` rebuilds the chunk store from the manifest/payload pair, samples PoR
  leaves, and times verification against the configured budget. Taikai metadata is auto-filled, and the
  harness falls back to a synthetic manifest if the fixture pair is inconsistent. When `--payload-bytes`
  is set without an explicit `--payload`, the generated blob is written to
  `artifacts/da/proof_bench/payload.bin` so fixtures stay untouched.【xtask/src/da.rs:1332】【xtask/src/main.rs:2515】
- Reports default to `artifacts/da/proof_bench/benchmark.{json,md}` and include proofs/run, total and
  per-proof timings, budget pass rate, and a recommended benchmark budget (110% of the slowest
  iteration). The harness accepts its measurement budget through `--budget-ms`.
- Latest run (synthetic 1 MiB payload, 64 KiB chunks, 32 proofs/run, 10 iterations, 250 ms budget)
  recommended a 3 ms verifier budget with 100% of iterations inside the cap.【artifacts/da/proof_bench/benchmark.md:1】
- Example (generates a deterministic payload and writes both reports):

```shell
cargo xtask da-proof-bench \
  --payload-bytes 1048576 \
  --sample-count 32 \
  --iterations 10 \
  --budget-ms 250 \
  --json-out artifacts/da/proof_bench/benchmark.json \
  --markdown-out artifacts/da/proof_bench/benchmark.md
```

Revision-4 consensus authenticates the mandatory Reed-Solomon-16 layout in
signed genesis/current-height context. Candidate bodies remain bounded by
`sumeragi.block.max_payload_bytes`; there are no node-local global DA
commitment/opening knobs. Torii ingestion policy in this plan is separate from
the consensus body/chunk layout and cannot weaken its validation.

## PoR failure handling and slashing

Storage workers now surface PoR failure streaks and bonded slash recommendations alongside each
verdict. Consecutive failures above the configured strike threshold emit a recommendation that
includes the provider/manifest pair, the streak length that triggered the slash, and the proposed
penalty computed from the provider bond and `penalty_bond_bps`; cooldown windows (seconds) keep
duplicate slashes from firing on the same incident.【crates/sorafs_node/src/lib.rs:486】【crates/sorafs_node/src/config.rs:89】【crates/sorafs_node/src/bin/sorafs-node.rs:343】

- Configure thresholds/cooldown via the storage worker builder (defaults mirror the governance
  penalty policy).
- Slash recommendations are recorded in the verdict summary JSON so governance/auditors can attach
  them to evidence bundles.
- Stripe layout + per-chunk roles are now threaded through Torii’s storage pin endpoint
  (`stripe_layout` + `chunk_roles` fields) and persisted into the storage worker so
  auditors/repair tooling can plan row/column repairs without re-deriving layout from upstream

### Placement + repair harness

`cargo run -p sorafs_car --features da_harness,dev-tools --bin da_reconstruct -- --manifest <path> --chunks-dir <dir>` now
computes a placement hash over `(index, role, stripe/column, offsets)` and performs row-first then
column RS(16) repair before reconstructing the payload:

- Placement defaults to `total_stripes`/`shards_per_stripe` when present and falls back to chunk
- Missing/corrupted chunks are rebuilt with row parity first; remaining gaps are repaired with
  stripe (column) parity. Repaired chunks are written back to the chunk directory, and the JSON
  summary captures the placement hash plus row/column repair counters.
- If row+column parity cannot satisfy the missing set, the harness fails fast with the unrecoverable
  indices so auditors can flag irreparable manifests.
