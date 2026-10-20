# World State Tiering Plan

This note captures the initial steps towards splitting the World State View (WSV)
into *hot* and *cold* tiers so validators can bound memory usage without giving up
fast transaction validation.

## Motivation

- The in-memory WSV keeps every key resident, so long-lived networks accumulate
  tens of gigabytes of state and stress validator hardware.
- Operators need predictable resource bounds while retaining the ability to keep
  frequently accessed data hot for low-latency queries and validation.

## Current Implementation

- `TieredStateBackend` (see `crates/iroha_core/src/state/tiered.rs`) now processes
  per-block WSV diffs after each committed block, ranks keys by their last
  mutation, and spills entries beyond the configured hot capacity to the
  on-disk cold tier. Cold payloads are written using Norito encoding alongside a
  snapshot manifest (`manifest.json`) that records key hashes, value
  fingerprints, and relative spill paths. The manifest is written atomically
  (temp file + fsync) before the snapshot directory is promoted.
- Runtime configuration lives under `iroha_config.parameters.tiered_state`
  (`enabled`, `hot_retained_keys`, `hot_retained_bytes`, `hot_retained_grace_snapshots`,
  `cold_store_root`, `da_store_root`, `max_snapshots`, `max_cold_bytes`). The node
  applies these knobs at startup via `State::set_tiered_backend`, and the default
  build keeps the feature disabled until operators opt in.
  When `cold_store_root` is unset, the cold tier stores snapshots under
  `da_store_root`. When both roots are set, snapshots land under
  `cold_store_root` and older directories are offloaded to `da_store_root` once
  `max_cold_bytes` is exceeded; reads hit the cold root first and rehydrate
  payloads back into `cold_store_root` when DA-backed shards are accessed.
- `hot_retained_bytes` enforces a deterministic hot-tier budget weight: each
  entry charges its canonical Norito-encoded key bytes plus the measured value
  footprint. This is not an allocator-exact resident-memory measurement. Grace
  retention or entries unavailable to an incremental snapshot may temporarily
  exceed the budget; telemetry reports the total overflow.
- `hot_retained_grace_snapshots` keeps newly hot entries pinned for a short
  window to reduce hot/cold churn when rankings fluctuate.
- Cold payloads reuse the last persisted shard when the value hash is unchanged,
  avoiding redundant re-encoding work across snapshots.
- `max_cold_bytes` prunes the oldest snapshot directories once total cold storage
  exceeds the configured budget, offloading to `da_store_root` when configured
  (always retaining the newest snapshot).
- Changing `cold_store_root` or `da_store_root` resets the in-memory tiering
  metadata and snapshot counter so new roots start with a clean hot/cold ordering.
- `StateBlock::commit` records a fresh snapshot under the configured primary
  cold root (pruning older directories according to `max_snapshots`) after
  releasing the world-state write lock. Snapshot processing may be offloaded to
  a background worker to keep block commit latency low while preserving
  deterministic manifests across peers. Capture retains exact overlay values
  before publication: a complete cold baseline or incremental changes including
  deletions. Each store is captured in a separate function frame so iterator and
  value temporaries do not accumulate on the stack across the World inventory.
- Snapshot directories use a zero-padded 20-digit index (e.g., `00000000000000000001`);
  pruning only targets those canonical snapshot directories so auxiliary folders
  such as `lanes/` and `retired/` remain intact.

## Derived membership indexes

The first-release World uses `(key, member) -> ()` rows for proof status and
tag membership, account scope membership, asset definition domain/owner and
holder indexes, asset definition/domain membership, NFT owner/domain,
RWA owner/status/frozen state, and escrow seller/buyer/status. The redundant
`assets_by_account` table is removed; the canonical `assets` account range
owns that lookup. `asset_definition_asset_counts` and
`account_scope_account_counts` retain only the small counts used by query
planning and telemetry.

Membership insertion/removal changes a B+tree path and bounded leaves instead
of cloning a group-sized collection on each transaction's first write.
Iteration seeks the prefix and streams members in canonical order. Restore
reconstructs both current and predecessor membership images and counts from
their authoritative source histories. The authority registry checks these
derivations; the World accumulator excludes them from canonical state roots.
Proof-tag cold-tier entries use the tuple key and unit value. The derived
proof-tag index is omitted from World JSON snapshots and rebuilt from
`proof_tags`; the old grouped snapshot field is rejected.

## Snapshot authenticity & recovery

- Every state snapshot now ships with two sidecar files in the snapshot directory:
  - `snapshot.sha256` — hex-encoded SHA-256 of `snapshot.data`
  - `snapshot.sig` — signature over the raw SHA-256 digest using the node’s identity key
- Snapshots also include `snapshot.merkle.json` (chunk size, total length, root hash, and per-chunk digests) computed with the configured `snapshot.merkle_chunk_size_bytes`. Restores validate the Merkle root against the snapshot bytes before replaying blocks.
- Restore refuses snapshots when either sidecar is missing, the digest mismatches, or the signature fails under the configured node public key. Operators should keep the signing key secure and rotate snapshots if keys rotate.
- `snapshot.verification_public_key` can override the verification key if operators want a dedicated verifier (defaults to the node identity key).
- `snapshot.signing_private_key` can override the key used to sign snapshots if you want to separate signing from the node identity key.
- Operational flow:
  1. Ensure the node identity key is available when `snapshot.mode = "read_write"`.
  2. On creation, the node writes `snapshot.data`, `snapshot.sha256`, `snapshot.sig`, and `snapshot.merkle.json` atomically (temp files renamed in place) and fsyncs the snapshot directory.
  3. On startup, restore loads `snapshot.data`, verifies the Merkle metadata (`snapshot.merkle.json`), recomputes the digest, verifies the signature, confirms the snapshot `chain_id` matches the configured chain, then checks block hashes against Kura.
  4. If any check fails, the node falls back to building state from genesis.

### Operator checklist
- Keep `snapshot.store_dir` writable by the node and include it in backups alongside both sidecars.
- Tune `snapshot.merkle_chunk_size_bytes` for your I/O profile (default 1 MiB). Changing the chunk size requires taking a new snapshot.
- If rotating node keys, generate a fresh snapshot so future restores validate under the new public key.
- For incident bundles/audits, include `snapshot.data`, `snapshot.sha256`, and `snapshot.sig` plus the node public key used for verification.

## Next Steps

1. **Populate metrics:** expose hot/cold hit ratios, spill counts, and snapshot
   latencies so we can size the hot tier before switching it on by default.
2. **Pluggable stores:** support swapping the cold tier between sled, LMDB, or a
   streaming offload so operators can choose durability characteristics.
3. **API surface:** add admin and telemetry endpoints for runtime inspection and
   surface the new `tiered_state` knobs via CLI/REST for dynamic control.
4. **Verification:** extend integration tests to run with a limited hot tier and
   ensure transaction validation pulls cold data on demand without diverging.

These steps keep the implementation small and testable while moving us towards a
bounded-memory WSV that still delivers the current validation guarantees.
