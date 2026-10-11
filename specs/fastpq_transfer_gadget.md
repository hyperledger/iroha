% FastPQ Transfer Gadget Design

# Overview

The current FASTPQ planner records every primitive operation involved in a `TransferAsset` instruction, which means each transfer pays for balance arithmetic, hash rounds, and SMT updates separately. To reduce trace rows per transfer we introduce a dedicated gadget that verifies only the minimal arithmetic/commitment checks while the host continues to execute the canonical state transition.

- **Scope**: single transfers and small batches emitted via the existing Kotodama/IVM `TransferAsset` syscall surface.
- **Goal**: cut FFT/LDE column footprint for high-volume transfers by collapsing per-transfer arithmetic and reusing the canonical sparse-Merkle context.

# Architecture

```
Kotodama builder → IVM syscall (transfer_v1 / transfer_v1_batch)
          │
          ├─ Host (unchanged business logic)
          └─ Transfer transcript (Norito-encoded)
                   │
                   └─ FASTPQ TransferGadget
                        ├─ Balance arithmetic block
                        ├─ Poseidon commitment check
                        ├─ Dual SMT path verifier
                        └─ Authority digest equality
```

## Transcript Format

The host emits a `TransferTranscript` per syscall invocation:

```rust
struct TransferTranscript {
    batch_hash: Hash,
    deltas: Vec<TransferDeltaTranscript>,
    authority_digest: Hash,
    poseidon_preimage_digest: Option<Hash>,
}

struct TransferDeltaTranscript {
    from_account: AccountId,
    to_account: AccountId,
    asset_definition: AssetDefinitionId,
    amount: Quantity,
    from_balance_before: Quantity,
    from_balance_after: Quantity,
    to_balance_before: Quantity,
    to_balance_after: Quantity,
    from_smt_witness: TransferSmtWitness,
    to_smt_witness: TransferSmtWitness,
}

struct TransferSmtWitness {
    root_before: [u8; 32],
    root_after: [u8; 32],
    path_bits: Vec<u8>,
    siblings: Vec<[u8; 32]>,
}
```

- `batch_hash` ties the transcript to the transaction entrypoint hash for replay protection.
- `authority_digest` is the host’s hash over sorted signers/quorum data; the gadget checks equality but does not redo signature verification. Concretely the host Norito-encodes the `AccountId` (which already embeds the canonical multisig controller) and hashes `b"iroha:fastpq:v1:authority|" || encoded_account` with Blake2b-256, storing the resulting `Hash`.
- `poseidon_preimage_digest` = Poseidon(account_from || account_to || asset || amount || batch_hash); ensures the prover recomputes the same digest as the host. The preimage bytes are `norito(from_account) || norito(to_account) || norito(asset_definition) || norito(amount) || batch_hash` using bare Norito encoding. The host packs that stream into little-endian `u64` words, while the prover feeds the same stream to `PoseidonByteHasher`; both use the canonical width-3, rate-2 BN254 Poseidon permutation with an `x^5` S-box. A byte-level `0x01` delimiter terminates the final word before the field-sponge padding, including a new word for an eight-byte-aligned preimage, so trailing-zero byte extensions remain distinct. The 32-byte output is the canonical BN254 field representation. This digest is present for single-delta transcripts and omitted for multi-delta batches.【crates/iroha_core/src/fastpq/mod.rs:171】【crates/fastpq_prover/src/gadgets/transfer.rs:946】【crates/iroha_zkp_poseidon/src/poseidon.rs:458】

All fields are serialized via Norito so existing determinism guarantees hold.
Sender and receiver witnesses are required structured SMT paths, not optional
proof blobs. Each delta chains `from_smt_witness.root_before` to
`from_smt_witness.root_after`, then `to_smt_witness.root_before` to
`to_smt_witness.root_after`; the transcript sequence must start at
`public_inputs.old_root` and finish at `public_inputs.new_root`.
`TransitionBatch` metadata embeds the Norito-encoded transcript vector under the
`transfer_transcripts` key so the prover can decode the witness without
performing out-of-band queries. Public inputs (`dsid`, `slot`, roots,
`perm_root`, `tx_set_hash`) are carried in
`FastpqTransitionBatch.public_inputs`, leaving metadata for entry hash/transcript
count bookkeeping. Missing, malformed, unpaired, or root-mismatched SMT
witnesses are rejected before proof construction.

The `fastpq_json` and `fastpq_fixture_rebind` tools accept only the canonical
`FastpqTransitionBatch` frame at their batch boundary. Internal prover structs,
bare payloads, alternate layouts, and trailing bytes are rejected. JSON-tool
proofs, touch-manifest commitments, and emitted Norito objects
use the canonical V1 frame independently of ambient layout guards.
The JSON helper produces captured AXT transfer proofs only. It rejects retired
lane-relay request fields and does not synthesize metadata-only relay proofs.
AXT proof bytes are the exact `FastpqAxtCompactArtifactV1` frame, with complete
quantity-encoded public rows and no embedded replay proof. The JSON prover and
verifier report the artifact byte length and SHA-256; the former preprocessing
`trace_commitment` field is removed. Metadata-only opaque effects have no
transfer AIR and are rejected before proving.
Torii recovery emits the same public batch frame, counting the borrowed source
before model conversion and enforcing the per-batch and aggregate byte budgets.
The Core prover lane canonically encodes persisted proofs within the smaller of
the configured sidecar budget and the production verifier's proof-byte cap;
`proof_digest` hashes the exact admitted frame.

V1 uses a 32-bit path for each canonical `FastpqBalanceKeyV1` Norito frame. The
`iroha_data_model::fastpq::transfer_balance_key` owner frames the typed asset definition
followed by the complete domainless `AccountId`, with schema identity
`iroha_data_model::fastpq::FastpqBalanceKeyV1` and the canonical declared V1 layout.
The host and prover share this owner. Display prefixes, aliases, and ambient
codec flags do not affect its bytes; alternate frames and raw display strings
are rejected at trace admission. Asset columns project the canonical UUID bytes. For
one `transfer_transcripts` vector, materialization and verification first sort
the distinct full balance-key bytes lexicographically. Each key keeps the first
four little-endian bytes of its domain-separated key hash when that path is
free; a collision advances with wrapping `u32` linear probing to the first free
path. The probe window is bounded by the number of distinct keys. The verifier
reconstructs this allocation from the complete transcript vector and rejects a
witness whose `path_bits` selects any other path. Consequently colliding full keys receive distinct deterministic leaves on every peer.

`fixtures/fastpq/balance_key_v1.json` pins the exact canonical frames for all
eleven supported single-key algorithms, weighted/threshold-sensitive multisig
policies, a policy combining all algorithms, and a 256-member policy. The Rust
`kotlin-fixture-gen fastpq-balance-keys-v1` command regenerates these frames from
the independently validated complete-controller fixture.

## Gadget Layout

1. **Balance Arithmetic Block**
   - Inputs: `from_balance_before`, `amount`, `to_balance_before`.
   - Checks:
     - `from_balance_before >= amount` (range gadget with shared RNS decomposition).
     - `from_balance_after = from_balance_before - amount`.
     - `to_balance_after = to_balance_before + amount`.
   - Packed into a custom gate so all three equations consume one row group.

2. **Poseidon Commitment Block**
   - Preflight validation recomputes `poseidon_preimage_digest` with the canonical BN254 Poseidon byte hasher before trace construction. V1 has no lookup-table column or lookup grand product; the canonical metadata commitment binds the validated transcript bytes.

3. **Merkle Path Block**
   - Extends the existing Kaigi SMT gadget with a "paired update" mode. Two leaves (sender, receiver) share the same column for sibling hashes, reducing duplicated rows.

4. **Authority Digest Check**
   - Simple equality constraint between the host-provided digest and the witness value. Signatures remain in their dedicated gadget.

5. **Batch Loop**
   - Kotodama calls `ledger::asset::transfer_batch(transfers: entries)` with a bounded typed list. The compiler evaluates the list once and brackets its active transfers with the internal batch begin/end kernel. The host buffers these transfers and replays them as one `TransferAssetBatch`, reusing the Poseidon/SMT context. Source code cannot open, apply, or close a raw batch. The IVM kernel also accepts canonical pre-encoded `TransferAssetBatch` records for native producers; this wire boundary is not a Kotodama source API.

# Host & Prover Changes

| Layer | Changes |
|-------|---------|
| `ivm::syscalls` | Add `transfer_v1_batch_begin` (`0x29`) / `transfer_v1_batch_end` (`0x2A`) so programs can bracket multiple `transfer_v1` syscalls without emitting intermediate ISIs, plus `transfer_v1_batch_apply` (`0x2B`) for pre-encoded batches. |
| `ivm::host` & tests | Core/Default hosts treat `transfer_v1` as a batch append while the scope is active, surface `SYSCALL_TRANSFER_V1_BATCH_{BEGIN,END,APPLY}`, and the mock WSV host buffers entries before committing so regression tests can assert deterministic balance updates.【crates/ivm/src/core_host.rs:1001】【crates/ivm/src/host.rs:451】【crates/ivm/src/mock_wsv.rs:3713】【crates/ivm/tests/wsv_host_pointer_tlv.rs:219】【crates/ivm/tests/wsv_host_pointer_tlv.rs:287】
| `iroha_core` | Emit `TransferTranscript` after the state transition, build `FastpqTransitionBatch` records with explicit `public_inputs` during `StateBlock::capture_exec_witness`, and run the FASTPQ prover lane so both Torii/CLI tooling and the V1 backend receive canonical `TransitionBatch` inputs. `TransferAssetBatch` groups sequential transfers into a single transcript, omitting the poseidon digest for multi-delta batches so the gadget can iterate across entries deterministically. |
| `fastpq_prover` | `gadgets::transfer` now validates multi-delta transcripts (balance arithmetic + Poseidon digest), requires real paired SMT witness material, checks chained roots from `public_inputs.old_root` to `public_inputs.new_root`, and surfaces validated witnesses for the planner (`crates/fastpq_prover/src/gadgets/transfer.rs`). `trace::build_trace` decodes those transcripts out of batch metadata, rejects transfer batches missing `transfer_transcripts`, rejects malformed witness paths, attaches the validated witnesses to `Trace::transfer_witnesses`, and `TracePolynomialData::transfer_plan()` keeps the aggregated plan alive until the planner consumes the gadget (`crates/fastpq_prover/src/trace.rs`). Row-count regression evidence now comes from execution-captured V1 batches; standalone synthetic row generation has been removed. |
| Kotodama | Lowers `ledger::asset::transfer_batch(transfers: entries)` for `List<(AccountId, AccountId, AssetDefinitionId, quantity), N>` with `N` in 1..64. The complete list is evaluated left-to-right before one batch begin, its active elements are transferred in order, and one batch end publishes the atomic batch. Saved lists use the same bounded traversal; empty lists return Unit without opening a batch, and capacity does not determine active length. |

Example Kotodama usage:

```text
fn pay(AccountId a, AccountId b, AssetDefinitionId asset, quantity x) {
    ledger::asset::transfer_batch(transfers: [(a, b, asset, x), (b, a, asset, 1)]);
}
```

`TransferAssetBatch` executes the same permission and arithmetic checks as individual `Transfer::asset_quantity` calls, but records all deltas inside a single `TransferTranscript`. Multi-delta transcripts elide the poseidon digest until per-delta commitments land in a follow-up. The Kotodama builder now emits the begin/end syscalls automatically, so contracts can deploy batched transfers without hand-encoding Norito payloads.

## Row-count Regression Evidence

Row-count regression inputs are V1 batches captured from execution with real
transfer SMT witness material. The old standalone synthetic row generator has
been removed because it could not prove the transfer witness chain. The emitted
JSON from `iroha_cli audit witness` contains the same `row_usage` summary
(`total_rows`, per-selector counts, ratio) and can be checked with
`scripts/fastpq/check_row_usage.py` and CI snapshot tooling.

# Rollout Plan

1. **TF-1 (Transcript plumbing)**: ✅ `StateTransaction::record_transfer_transcripts` now emits Norito transcripts for every `TransferAsset`/batch, `sumeragi::witness::record_fastpq_transcript` stores them inside the global witness, and `StateBlock::capture_exec_witness` builds `fastpq_batches` with explicit `public_inputs` for operators and the prover lane (use `--no-fastpq-batches` if you need a slimmer output).【crates/iroha_core/src/state.rs:8801】【crates/iroha_core/src/sumeragi/witness.rs:280】【crates/iroha_core/src/fastpq/mod.rs:157】【crates/iroha_cli/src/audit.rs:185】
2. **TF-2 (Gadget implementation)**: ✅ `gadgets::transfer` validates multi-delta transcripts (balance arithmetic + Poseidon digest), requires paired SMT witnesses from execution capture, exposes structured witnesses via `TransferGadgetPlan`, and `trace::build_trace` threads those witnesses into `Trace::transfer_witnesses` while populating SMT columns from verified paths. Row-usage checks now consume captured V1 batch artifacts instead of synthetic row samples.【crates/fastpq_prover/src/gadgets/transfer.rs:1】【crates/fastpq_prover/src/trace.rs:1】
3. **TF-3 (Batch helper)**: Enable the batch syscall + Kotodama builder, including host-level sequential application and gadget loop.
4. **TF-4 (Telemetry & docs)**: Update `fastpq_plan.md`, `fastpq_migration_guide.md`, and dashboard schemas to surface allocation of transfer rows vs other gadgets.

# Open Questions

- **Domain limits**: current FFT planner panics for traces beyond 2¹⁴ rows. TF-2 should either raise the domain size or document a reduced benchmark target.
- **Multi-asset batches**: initial gadget assumes the same asset ID per delta. If we need heterogeneous batches, we must ensure the Poseidon witness includes the asset each time to prevent cross-asset replay.
- **Authority digest reuse**: long term we can reuse the same digest for other permissioned operations to avoid recomputing signer lists per syscall.


This document tracks design decisions; keep it in sync with roadmap entries when milestones land.
