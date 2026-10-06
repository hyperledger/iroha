<!--
SPDX-License-Identifier: Apache-2.0
-->
# Confidential Assets & Protocol-Bound ZK Design

## Motivation
- Define local confidential note proofs and their protocol-owned admission boundaries.
- Provide auditors and operators with lifecycle controls (activation, rotation, revocation) for circuits and cryptographic parameters.

## Threat Model
- Validators are honest-but-curious: they execute consensus faithfully but attempt to inspect ledger/state.
- Network observers see block data and gossiped transactions; no assumption of private gossip channels.
- Out of scope: off-ledger traffic analysis, quantum adversaries (tracked separately under PQ roadmap), ledger availability attacks.

## Design Overview
The Rust wallet entrypoint is `iroha_core_zk::confidential::ConfidentialProver`.
It binds a typed `NetworkId`, canonical `AssetDefinitionId`, and an owned
`Zeroizing<[u8; 32]>` spend key. `prove_transfer` and `prove_unshield` select the
canonical relation/key internally, consume zeroizing note openings, and
self-verify the resulting proof. The circuit-specific builders are internal to
Core; wallet callers cannot supply a circuit identifier or verifier key.
`ConfidentialTree` accepts a complete commitment
prefix or one membership path per actual input; no dummy path is exposed.
The executable source example is
[`confidential_redemption.rs`](../crates/iroha_core_zk/examples/confidential_redemption.rs),
run with `cargo run -p iroha_core_zk --example confidential_redemption`.
It is local proof construction; active-key, authenticated-root, nullifier and
transaction authority checks remain owned by ledger admission. Secret opening
and prover `Debug` output is redacted; returned public proof material is inspectable.
Persist a private change opening securely before proving consumes it. Once its
new leaf index is authenticated, restore the opening and call
`ConfidentialUnshieldOutputV3::into_input(index)`. This consumes it into an input
using the wallet's default diversifier, even if the previous input used a
different diversifier. The helper checks shape; proving still checks membership.

Consumed note commitments are public and link spends to their inputs. These
relations hide note amounts, nonces, spend keys and paths; the public redemption
amount remains visible. They provide neither transaction unlinkability nor
account/network anonymity. The current data model has no generic `Shield`,
`ZkTransfer` or `Unshield` instruction. A proof artifact cannot authorize a
ledger change without an implemented protocol's independent state checks.

- Local notes bind `(asset_tag, amount, owner_tag, rho)` through the fixed Pasta
  Poseidon construction in `crates/iroha_core_zk/src/confidential_v2.rs`:
  - Commitment: `Poseidon(NOTE_DOMAIN, [amount, rho_scalar, owner_tag, asset_tag])`.
  - Owner tag: `Poseidon(OWNER_DOMAIN, [spend_scalar, diversifier])`.
  - Nullifier: `Poseidon(NULLIFIER_DOMAIN, [spend_scalar, rho_scalar, asset_tag, network_tag])`.
    The spend key and nonce use distinct domain-separated hash-to-scalar labels.
    Asset and network tags use separate domains, with the latter binding the
    exact genesis-derived `NetworkId`. Note position is absent from this input.
  - Encrypted payload: `enc_payload = AEAD_XChaCha20Poly1305(ephemeral_shared_key, note_plaintext)`.
- Specialized confidential protocols transport Norito-encoded proof payloads containing:
  - Public inputs: Merkle anchor, nullifiers, new commitments, asset id, circuit version.
  - Encrypted payloads for recipients and optional auditors.
  - Zero-knowledge proof attesting value conservation, ownership, and authorization.
- Verifying keys and parameter sets are controlled through on-ledger registries with activation windows; nodes refuse to validate proofs that reference unknown or revoked entries.
- Consensus headers commit to the active confidential feature digest so blocks are only accepted when registry and parameter state matches.
- Proof construction uses a Halo2 (Plonkish) stack without trusted setup; Groth16 or other SNARK variants are intentionally unsupported in v1.

### Deterministic Fixtures

The Swift wallet's encrypted-payload codec uses the deterministic fixture at
`fixtures/confidential/encrypted_payload_v1.json`. Its positive envelope and
malformed samples are checked by
`IrohaSwift/Tests/IrohaSwiftTests/ConfidentialEncryptedPayloadTests.swift` for
exact serialization, round trips, and decode errors. The Rust data model tests
the current exact-eight-slot `ConfidentialMemoEnvelopeV1` separately in
`crates/iroha_data_model/tests/confidential_memo_envelope_v1.rs`.

The generic proofless `zk::Shield` instruction is not part of the first-release
wire surface. KAGEMUSHA V1 is a separate aggregate-balance protocol: its
top-up operation atomically debits the payer, credits the per-asset reserve, and
emits a hardware-bound mint credit after circuit-verifiable block finality. It
does not append a caller-supplied confidential note. The encrypted memo-envelope
fixture remains a local wallet codec fixture and grants no monetary authority.

## Consensus Commitments & Capability Gating
- Block headers expose `conf_features = { vk_set_hash, poseidon_params_id, pedersen_params_id, conf_rules_version }`; the digest participates in the consensus hash and must equal the local registry view for block acceptance.
- Governance can stage upgrades by programming `next_conf_features` with a future `activation_height`; until that height, block producers must continue to emit the previous digest.
- Validator nodes MUST operate with `confidential.enabled = true` and `assume_valid = false`. Startup checks refuse to join the validator set if either condition fails or if local `conf_features` diverge.
- P2P handshake metadata now includes `{ enabled, assume_valid, conf_features }`. Peers advertising unsupported features are rejected with `HandshakeConfidentialMismatch` and never enter consensus rotation.
- Non-validator observers may set `assume_valid = true`; they blindly apply confidential deltas but do not influence consensus safety.

## Asset Policies
- Each registered asset definition carries runtime `AssetConfidentialPolicy` state. Public asset registration always creates `TransparentOnly`; only verifier-backed `RegisterZkAsset` execution and validated policy-transition instructions may change it:
  - `TransparentOnly`: default mode; only transparent instructions (`MintAsset`, `TransferAsset`, etc.) are permitted and shielded operations are rejected.
  - `ShieldedOnly`: confidential movement remains available, but public
    redemption is forbidden so balances do not surface publicly.
  - `Convertible`: holders may move value between transparent and shielded representations using the on/off-ramp instructions below.
- Policies follow a constrained FSM to prevent stranding funds:
  - `TransparentOnly → Convertible` occurs only when `RegisterZkAsset`
    installs an active canonical unshield verifier binding.
  - `Convertible → ShieldedOnly` (enforced minimum delay).
  - `ShieldedOnly → Convertible` re-enables proof-bound public redemption.
  - `Convertible` or `ShieldedOnly` can never return to `TransparentOnly` in
    ABI V1, even when the commitment log is empty. Registration, scheduled
    activation, read-only effective-mode projection, and due-transition
    application all preserve this invariant.
- The asset-definition owner, or an account with the exact scoped
  `CanManageAssetDefinitionConfidentialPolicy` grant, may register verifier
  bindings or schedule/cancel policy transitions. The generic
  `CanModifyAssetDefinitionMetadata` grant does not authorize these operations.
  Core enforces this before any policy state is applied, independently of the
  executor admission layer.
- Governance instructions set `pending_transition { new_mode, effective_height, previous_mode, transition_id, conversion_window }` via the `ScheduleConfidentialPolicyTransition` ISI and may abort scheduled changes with `CancelConfidentialPolicyTransition`. Scheduling is valid only between `Convertible` and `ShieldedOnly`; a `TransparentOnly` asset must activate through verifier registration. Mempool validation ensures no transaction straddles the transition height and inclusion fails deterministically if a policy check would change mid-block.
- Pending transitions are applied automatically when a new block opens. A derived, snapshot-rebuilt index stores one exact `(effective_height, asset_definition_id)` key per transition plus an exact count per height, so scheduling and cancellation remain logarithmic and block opening is proportional to transitions that are due rather than to the total number of asset definitions. Scheduling, cancellation, application, asset replacement, and unregistration update both derived stores atomically with authoritative policy state. Snapshot and startup reconstruction reject a malformed pending transition immediately, even when its advertised height is far in the future. At the programmed `effective_height`, the runtime updates `AssetConfidentialPolicy`, refreshes `zk.policy` metadata, and clears the pending entry. If transparent supply remains when a `ShieldedOnly` transition matures, the runtime clears the transition, logs a warning, and retains the currently active mode. It never restores an earlier transparent mode after a conversion window has opened.
- Config knobs `policy_transition_delay_blocks` and `policy_transition_window_blocks` enforce minimum notice and grace periods to let wallets convert notes around the switch. `policy_transition_max_per_height` limits deterministic start-of-block work and rejects a schedule before any policy mutation when the target height is full.
- `pending_transition.transition_id` doubles as an audit handle; governance must quote it when finalising or cancelling transitions so operators can correlate on/off-ramp reports.
- `policy_transition_window_blocks` defaults to 200 blocks, and `policy_transition_max_per_height` defaults to 256. Nodes reject governance requests that attempt shorter notice or exceed the exact-height capacity.
- Genesis manifests and CLI flows surface current and pending policies. Admission logic reads the policy at execution time to confirm each confidential instruction is authorised.
- No `vk_shield` field exists in the canonical first-release confidential-asset
  instruction or state schema. An optional `vk_unshield` binding may activate the confidential
  policy and, after the first commitment exists, cannot be cleared or changed
  to a different verifier commitment. KAGEMUSHA V1 does not use either
  asset-bound role; its paired artifact set is authenticated by its release
  manifest. No generic commitment-ingress or confidential-transfer instruction
  exists.
- Migration checklist — see “Migration sequencing” below for the staged upgrade plan that Milestone M0 tracks.

#### Monitoring transitions via Torii

Wallets and auditors poll `GET /v1/confidential/assets/{definition_id}/transitions` to inspect
the active `AssetConfidentialPolicy`. The JSON payload always includes the canonical
asset id, the latest observed block height, the policy’s `current_mode`, the mode that is
effective at that height (conversion windows temporarily report `Convertible`), and the
expected `vk_set_hash`/Poseidon/Pedersen parameter identifiers. Swift SDK consumers can call
`ToriiClient.getConfidentialAssetPolicy` to receive the same data as typed DTOs without
hand-written decoding. When a governance transition is pending the response also embeds:

- `transition_id` — audit handle returned by `ScheduleConfidentialPolicyTransition`.
- `previous_mode`/`new_mode`.
- `effective_height`.
- `conversion_window` and the derived `window_open_height` (the block where wallets must
  begin conversion for ShieldedOnly cut-overs).

Example response:

```json
{
  "asset_id": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
  "block_height": 4217,
  "current_mode": "Convertible",
  "effective_mode": "Convertible",
  "vk_set_hash": "8D7A4B0A95AB1C33F04944F5D332F9A829CEB10FB0D0797E2D25AEFBAAF1155D",
  "poseidon_params_id": 7,
  "pedersen_params_id": 11,
  "pending_transition": {
    "transition_id": "BF2C6F9A4E9DF389B6F7E5E6B5487B39AE00D2A4B7C0FBF2C9FEF6D0A961C8ED",
    "previous_mode": "Convertible",
    "new_mode": "ShieldedOnly",
    "effective_height": 5000,
    "conversion_window": 720,
    "window_open_height": 4280
  }
}
```

A `404` response indicates no matching asset definition exists. When no transition is
scheduled the `pending_transition` field is `null`.

### Policy state machine

| Current mode | Next mode | Prerequisites | Effective-height handling | Notes |
|---|---|---|---|---|
| `TransparentOnly` | `Convertible` | Call `RegisterZkAsset` with an active canonical `vk_unshield` binding. | Activation is immediate; this is not a scheduled transition. | Confidential activation is irreversible in ABI V1. |
| `Convertible` | `ShieldedOnly` | Schedule with the required lead time and conversion window. Transparent supply must be zero at cut-over. | On success the policy becomes `ShieldedOnly`. If transparent supply remains, the pending transition is cleared and the current `Convertible` mode is retained. | Disables public redemption without invalidating confidential notes. |
| `ShieldedOnly` | `Convertible` | Schedule with the required lead time. | State flips at `effective_height`; proof-bound public redemption becomes available again. | Existing notes and verifier bindings remain valid. |
| Either confidential mode | Same as current | Cancel the exact pending `transition_id`. | The pending entry is removed immediately. | Cancellation never restores `TransparentOnly`. |

All other mode changes are rejected. In particular, scheduling cannot activate a
`TransparentOnly` asset, and neither registration nor a scheduled transition can
disable confidentiality after activation.

### Migration sequencing

1. **Activate verifier roles:** Register an active canonical unshield verifier. The first valid binding moves a `TransparentOnly` asset to `Convertible` immediately.
2. **Stage a confidential-mode transition:** Submit `ScheduleConfidentialPolicyTransition` with an `effective_height` that respects `policy_transition_delay_blocks`. When moving toward `ShieldedOnly`, specify a conversion window (`window ≥ policy_transition_window_blocks`).
3. **Publish operator guidance:** Record the returned `transition_id` and circulate an on/off-ramp runbook. Wallets and auditors subscribe to `/v1/confidential/assets/{id}/transitions` to learn the window open height.
4. **Window enforcement:** The asset remains `Convertible` throughout the notice window so holders can complete public redemption before cut-over.
5. **Finalize or abort:** At `effective_height`, the runtime verifies zero transparent supply. Success flips the policy to `ShieldedOnly`; failure logs the prerequisite error, clears the pending transition, and leaves the current confidential mode unchanged.
6. **Persist the canonical state:** After a successful transition, operators archive the
   verifier registrations, `RegisterZkAsset` instruction, transition receipt, and resulting
   policy fingerprint. Asset-registration manifests never carry `confidential_policy` state.

New networks that start with confidentiality enabled register each asset transparently, then
include active canonical verifying-key records followed by `RegisterZkAsset` in genesis. The
runtime derives the initial confidential policy only after validating those bindings. Networks
still follow the checklist above when changing modes post-launch so conversion windows remain
deterministic and wallets have time to adjust.

### Norito manifest versioning & activation

- Genesis manifests MUST include a `SetParameter` for the custom `confidential_registry_root` key. The payload is Norito JSON matching `ConfidentialRegistryMeta { vk_set_hash: Option<String> }`: omit the field (`null`) when no verifier entries are active, otherwise supply a 32-byte hex string (`0x…`) equal to the hash produced by `compute_vk_set_hash` over the verifier instructions shipped in the manifest. Nodes refuse to start if the parameter is missing or the hash disagrees with the encoded registry writes.
- The on-wire `ConfidentialFeatureDigest::conf_rules_version` embeds the manifest layout version. For v1 networks it MUST remain `Some(1)` and equals `iroha_config::parameters::defaults::confidential::RULES_VERSION`. When the ruleset evolves, bump the constant, regenerate manifests, and roll out binaries in lock-step; mixing versions causes validators to reject blocks with `ConfidentialFeatureDigestMismatch`.
- Activation manifests SHOULD bundle registry updates, parameter lifecycle changes, and policy transitions so the digest stays consistent:
  1. Apply the planned registry mutations (`Publish*`, `Set*Lifecycle`) in an offline state view and compute the post-activation digest with `compute_confidential_feature_digest`.
  2. Emit `SetParameter::custom(confidential_registry_root, {"vk_set_hash": "0x…"})` using the computed hash so lagging peers can recover the correct digest even if they miss intermediate registry instructions.
  3. Append the `ScheduleConfidentialPolicyTransition` instructions. Each instruction must quote the governance-issued `transition_id`; manifests that forget it will be rejected by the runtime.
  4. Persist the manifest bytes, a SHA-256 fingerprint, and the digest used in the activation plan. Operators verify all three artefacts before voting the manifest into effect to avoid partitions.
- When rollouts require a deferred cut-over, record the target height in a companion custom parameter (for example `custom.confidential_upgrade_activation_height`). This gives auditors a Norito-encoded proof that validators honoured the notice window before the digest change took effect.

## Verifier & Parameter Lifecycle
### ZK Registry
- Ledger stores `ZkVerifierEntry { vk_id, circuit_id, version, proving_system, curve, public_inputs_schema_hash, vk_hash, vk_len, max_proof_bytes, gas_schedule_id, activation_height, deprecation_height, withdraw_height, status, metadata_uri_cid, vk_bytes_cid }` where `proving_system` is currently fixed to `Halo2`.
- `(circuit_id, version)` pairs are globally unique; the registry maintains a secondary index for lookups by circuit metadata. Attempts to register a duplicate pair are rejected during admission.
- `circuit_id` must be non-empty and `public_inputs_schema_hash` must be provided (typically a Blake2b-32 hash of the verifier’s canonical public-input encoding). Admission rejects records that omit these fields.
- Governance instructions include:
  - `PUBLISH` to add a `Proposed` entry with metadata only.
  - `ACTIVATE { vk_id, activation_height }` to schedule entry activation at an epoch boundary.
  - `DEPRECATE { vk_id, deprecation_height }` to mark the final height where proofs may reference the entry.
  - `WITHDRAW { vk_id, withdraw_height }` for emergency shutdown; affected assets freeze confidential spending after the withdraw height until new entries activate.
- Genesis manifests auto-emit a `confidential_registry_root` custom parameter whose `vk_set_hash` matches the active entries; validation cross-checks this digest against local registry state before a node can join consensus.
- Registering or updating a verifier requires a `gas_schedule_id`; verification enforces that the registry entry is `Active`, present in the `(circuit_id, version)` index, and that Halo2 proofs provide an `OpenVerifyEnvelope` whose `circuit_id`, `vk_hash`, and `public_inputs_schema_hash` match the registry record. Registry, proof-attachment admission, checked verifier guardrails, and IVM host verifier snapshots reject explicit trusted-setup labels such as Groth16, Halo2/BN254, Halo2/BLS12, and Halo2/KZG; the admitted production verifier families are transparent Halo2 IPA over Pasta and STARK/FRI.
- KAGEMUSHA V1 proof admission is not selected through a caller-controlled
  registry role. It authenticates the complete paired-Pasta release manifest,
  verifies the exact state, history, mint-finality, platform-credential, and
  GuardBundle roles, and terminally decides both recursive accumulators. The
  generic proof preverification path grants no KAGEMUSHA authority.
- Production Halo2/IPA metadata has one strict `ZK1\0` TLV layout: verifier keys encode `IPAK` → `CID1` → `H2VK`, while proofs encode `PROF` followed by optional `I10P`. The retired binary inner envelope and its standalone parser were removed; production dispatch never guesses or accepts that legacy shape.

### Proving Keys
- Proving keys remain off-ledger but are referenced by content-addressed identifiers (`pk_cid`, `pk_hash`, `pk_len`) published alongside verifier metadata.
- Wallet SDKs fetch PK data, verify hashes, and cache locally.

### Pedersen & Poseidon Parameters
- Separate registries (`PedersenParams`, `PoseidonParams`) mirror verifier lifecycle controls, each with `params_id`, hashes of generators/constants, activation, deprecation, and withdraw heights.

## Deterministic Ordering & Nullifiers
- Each registered asset persists `ConfidentialTreeProfile::PoseidonPastaV1` in
  `ZkAssetState`. This fixed-depth Pasta Poseidon profile is the only
  first-release tree construction. `RegisterZkAsset` validates every configured
  unshield verifier against it; key rotation may retain
  the profile, but no populated asset can switch profiles.
- All confidential append paths use the same profile-aware batch operation.
  `ZkAssetState` persists a fixed 16-slot
  incremental frontier and the current root. A hot append validates that
  constant-size metadata and the retained-history tail, validates every new
  scalar, simulates the complete batch on a copied frontier, reserves storage,
  and only then extends the ordered commitment and root vectors. It neither
  clones nor rehashes the prior commitment prefix; work is
  `O(batch * tree_depth)`. Blocks therefore append commitments deterministically
  in transaction order and in each proof's canonical authenticated output
  order, without leaving a partial prefix after capacity, allocation, or
  commitment validation fails.
- Snapshot decode/recovery and explicitly admitted audits perform the separate
  full integrity tier. They build one compact projection from the ordered
  commitment prefix, compare its root and exact frontier with the persisted
  metadata, and validate retained roots and checkpoints. Hot consensus writes
  never substitute that linear rebuild for incremental validation.
- `note_position` is derived from the tree offsets but **not** part of the nullifier; it only feeds membership paths within the proof witness.
- Standalone confidential proof builders take one membership path per actual
  input. Builders pad an absent slot with the canonical empty-tree path; the
  fixed two-input circuit gates its common-root equality by the constrained
  presence bit. A present second input must authenticate against
  the first input's root. One-note full redemption therefore remains possible
  when all 65,536 commitment leaves are occupied; no ledger empty leaf or
  caller-supplied dummy path is required. These retained proof helpers do not
  restore the retired generic monetary instructions. Tree-list builders reject
  impossible cardinalities, capacities and indices before Merkle hashing. Every
  generated envelope passes purpose-bound local verification for its fixed
  transfer, full-unshield or change-unshield relation within the 192 KiB cap.
- The same spend key, nonce, asset tag and network tag produce the same nullifier
  independently of note position or anchor changes. This does not replace
  protocol-owned replay checks or authenticated historical-root admission.

### V1 public-amount proof scalars

The generic `Shield`, `ZkTransfer`, and `Unshield` wires are retired. KAGEMUSHA
V1 public-to-offline and offline-to-public amounts are carried inside its
scale-bound top-up request and proof-authenticated redemption voucher.
The direct `SubmitZkAceAuthorizedTransfer` instruction is retired. ZK-ACE callers instead
select an active governed `PrivacyZkAcePolicyRecordV1`; the canonical native
builder binds an atomic `u128` amount into
`ZkAcePqAuthorizationStatementV1`, wraps the statement and proof in exactly one
`SubmitPrivacyProofV1`, and signs that complete transaction.

The signed path rejects zero, fractional, noncanonical, and over-`u128` input
before proof construction. Runtime admission then revalidates the signed
transaction intent, compiled protocol profile, governed policy and
authorization epoch, statement amount, proof, and replay nullifier before any
balance mutation. Supporting fractional or wider public amounts in a future
ZK-ACE circuit requires an explicitly versioned statement schema and migration
plan.

### Protocol-private transfer and redemption proofs

KAGEMUSHA V1 uses one hidden aggregate balance per device lane and asset.
Its fixed-shape paired-Pasta recursion proves `Bootstrap`, `MintFold`,
`SendSplit`, `ReceiveFold`, `RedeemSplit`, and `Rotate`; proof envelopes are
not standalone executable instructions. The sole peer-payment paired proof is
carried directly by `KagemushaPaymentV1` together with its compact output,
encrypted receiver credit, and recursively verified hardware commit certificate.
Redemption vouchers instead carry `KagemushaRedemptionProofV1`, never public
predecessor/successor state heads. Redemption couples the hardware-bound
terminal voucher to a unique nullifier and an equal debit from the pooled
reserve before public credit.

This separation is a consensus invariant. A proof that is sound for the note
tree does not by itself authorize settlement against a particular backing
pool, so no generic dispatch, InstructionBox discriminant, IVM bridge, relay,
CLI command, or SDK transaction builder may expose either circuit directly.

For a governed privacy public reserve, Core accepts the transparent payout leg
only through its exact verified pool-bridge source. At application it rejoins
the prepared transfer's authorized amount and both live balances, then checks
that the source debit and destination credit equal that exact amount before
either balance is written. The bounded decimal relation uses fixed stack limbs
instead of new BigInt arithmetic scratch. This transparent conservation guard
does not establish the private
proof's ownership, note conservation, or production qualification; those gates
still require their complete verifier and adversarial evidence.

## Ledger Flow
1. **`TopUpKagemushaV1 { request }`**
   - Runtime validates the payer, recipient hardware lane, active release,
     exact scale and amount, idempotency identifiers, and reserve binding.
   - It atomically debits online funds and credits the sole reserve for the
     asset. Finality later attaches the exact circuit-verifiable mint credit;
     recovery cannot mint a different output.
2. **`RedeemKagemushaV1 { request }`**
   - Runtime verifies the recursive balance proof, hardware-bound voucher, and
     unique terminal nullifier.
   - It atomically debits the reserve and credits the requested account. Proof
     failure, replay, or reserve underflow leaves all monetary state unchanged.
- Retiring an asset definition directly or by unregistering its owning domain
  rejects outstanding KAGEMUSHA reserve liability before custody or the
  definition is removed. Fully redeemed pools remain archived for replay audit.
- Domain retirement also rejects definitions retained by active SoraFS reserve
  custody, governed SCCP settlement routes, or native FX corridor policies.

## Data Model Additions
- `ConfidentialConfig` (new config section) with enablement flag, `assume_valid`, gas/limit knobs, anchor window, verifier backend.
- `ConfidentialNote`, `ConfidentialTransfer`, and `ConfidentialMint` Norito schemas with explicit version byte (`CONFIDENTIAL_ASSET_V1 = 0x01`).
- `ConfidentialEncryptedPayload` wraps AEAD memo bytes with `{ version, ephemeral_pubkey, nonce, ciphertext }`, defaulting to `version = CONFIDENTIAL_ENCRYPTED_PAYLOAD_V1` for the XChaCha20-Poly1305 layout.
- Canonical positive key-derivation vectors for nonzero spend keys live in `specs/confidential_key_vectors.json`; both the CLI and Torii endpoint regress against these fixtures. Wallet-facing derivatives and negative all-zero spend-key admission coverage for the spend/nullifier/viewing ladder are published in `fixtures/confidential/keyset_derivation_v1.json` and exercised by the Rust + Swift SDK tests to guarantee cross-language parity.
- Registered `asset::AssetDefinition` state contains
  `confidential_policy: AssetConfidentialPolicy { mode, vk_set_hash,
  poseidon_params_id, pedersen_params_id, pending_transition }`. The public
  `NewAssetDefinition` registration payload deliberately omits this field and
  always builds `TransparentOnly` state with no pending transition;
  `RegisterZkAsset` is the only confidential activation path.
- `ZkAssetState` persists the sole first-release tree profile, an exact
  fixed-size incremental frontier, its current root, and any generic
  confidential verifier bindings. KAGEMUSHA V1 release artifacts and pooled
  reserves are stored in their dedicated state and are not asset-bound verifier
  roles.
  The frontier and root are required first-release snapshot fields; there is no
  legacy reconstruction fallback. Execution rejects proofs whose referenced
  verifying key fails to match the registered commitment, whose proof envelope
  does not bind the expected schema and active verifier metadata, or whose
  auxiliary bytes are non-empty. Recovery rejects populated state when a full
  commitment projection disagrees with the persisted frontier/current root or
  when retained roots and checkpoints do not authenticate under the profile.
- The ordered commitment prefix and bounded exact root suffix (per asset with
  frontier checkpoints), `NullifierSet` keyed by
  `(network_id, asset_id, nullifier)`, `ZkVerifierEntry`, `PedersenParams`, and
  `PoseidonParams` are stored in world state.
- Mempool maintains transient `NullifierIndex` and `AnchorIndex` structures for early duplicate detection and anchor age checks.
- Norito schema updates include canonical ordering for public inputs; round-trip tests ensure encoding determinism.
- Encrypted payload roundtrips are locked in via unit tests (`crates/iroha_data_model/src/confidential.rs`), and the wallet key-derivation vectors above anchor the AEAD envelope derivations for auditors. `norito.md` documents the on-wire header for the envelope.

## IVM Integration & Syscall
- Introduce `VERIFY_CONFIDENTIAL_PROOF` syscall accepting:
  - `circuit_id`, `version`, `scheme`, `public_inputs`, `proof`, and resulting `ConfidentialStateDelta { asset_id, nullifiers, commitments, enc_payloads }`.
  - Syscall loads verifier metadata from registry, enforces size/time limits, charges deterministic gas, and only applies delta if proof succeeds.
- Host exposes read-only `ConfidentialLedger` trait for retrieving Merkle root snapshots and nullifier status; Kotodama library provides witness assembly helpers and schema validation.
- Pointer-ABI docs updated to clarify proof buffer layout and registry handles.

## Node Capability Negotiation
- Handshake advertises `feature_bits.confidential` together with a `ConfidentialFeatureDigest { vk_set_hash, poseidon_params_id, pedersen_params_id, conf_rules_version }`. Validator participation requires `confidential.enabled=true`, `assume_valid=false`, identical verifier backend identifiers, and matching digests; mismatches fail the handshake with `HandshakeConfidentialMismatch`.
- Config supports `assume_valid` for observer nodes only: when disabled, encountering confidential instructions yields deterministic `UnsupportedInstruction` without panic; when enabled, observers apply declared state deltas without verifying proofs.
- Mempool rejects confidential transactions if local capability is disabled. Gossip filters avoid sending shielded transactions to peers without matching capability while blind-forwarding unknown verifier IDs within size limits.

### Reveal Pruning & Nullifier Retention Policy

Confidential ledgers must retain enough history to prove note freshness and to
replay governance-driven audits. The default policy, enforced by
`ConfidentialLedger`, is:

- **Nullifier retention:** keep spent nullifiers for *minimum* `730` days (24
  months) after spend height, or the regulator-mandated window if longer.
  Operators may extend the window via `confidential.retention.nullifier_days`.
  Nullifiers younger than the retention window MUST remain queryable via Torii so
  auditors can prove double-spend absence.
- **Public redemption:** KAGEMUSHA V1 redemption consumes an authenticated
  terminal nullifier and transfers the exact amount from the per-asset reserve.
  Generic confidential redemption follows its own verifier policy. The
  commitment log remains append-only; there is no generic reveal instruction
  or generic confidential lifecycle event compatibility wire.
- **Frontier checkpoints:** commitment frontiers maintain rolling checkpoints
  covering the larger of `max_anchor_age_blocks` and the retention window. Nodes
  compact older checkpoints only after all nullifiers within the interval expire.
- **Stale digest remediation:** if `HandshakeConfidentialMismatch` is raised due
  to digest drift, operators should (1) verify that nullifier retention windows
  align across the cluster, (2) run `iroha_cli app confidential verify-ledger` to
  regenerate the digest against the retained nullifier set, and (3) redeploy the
  refreshed manifest. Any nullifiers pruned prematurely must be restored from
  cold storage before rejoining the network.

Document local overrides in the operations runbook; governance policies extending
the retention window must update node configuration and archival storage plans in
lockstep.

### Eviction & Recovery Flow

1. During dial, `IrohaNetwork` compares the advertised capabilities. Any mismatch raises `HandshakeConfidentialMismatch`; the connection is closed and the peer remains in the discovery queue without ever being promoted to `Ready`.
2. The failure is surfaced via the network service log (including the remote digest and backend), and Sumeragi never schedules the peer for proposal or voting.
3. The handshake digest carries the confidential rules version and the protocol-default ZK and SCCP policy hash of the release only. It carries neither the registry fields (`vk_set_hash`, `pedersen_params_id`, `poseidon_params_id`) nor the chain's committed `zk_validity_policy_v1`: those are State, decided by blocks, and peers at different heights must still connect. A mismatch therefore means the peers run releases with different protocol defaults; operators remediate by installing the same release.
4. If a stale peer manages to broadcast a block (e.g., via archival replay), validators reject it deterministically with `BlockRejectionReason::ConfidentialFeatureDigestMismatch`, keeping ledger state consistent across the network.

### Replay-safe handshake flow

1. Each attempt negotiates a fresh mandatory SoraNet NK2/NK3 session key inside TLS 1.3 or QUIC. The signed payload (`handshake_signature_payload`) uses an explicit V1 domain and binds the complete 256-bit domain-separated session hash, BLS-normal node public key, Norito-encoded advertised address, relay/consensus/confidential/crypto/trust capabilities, mandatory exact genesis-derived `NetworkId`, and mandatory listener-observed TLS/QUIC certificate fingerprint. The message is AEAD-encrypted before it leaves the node.
2. The responder derives the same full session hash and verifies the long-term peer signature over those exact `HandshakeHello` claims before enforcing or using them. Replaying a captured message in another session, altering a capability, connecting to a network with another genesis hash (even under the same display name), or changing the authenticated transport binding therefore fails signature verification deterministically; the compact 64-bit connection disambiguator is used only for simultaneous-connection tie-breaking.
3. Confidential capability flags and the `ConfidentialFeatureDigest` travel inside the signed `HandshakeConfidentialMeta`. After authentication, the receiver compares the tuple `{ enabled, assume_valid, verifier_backend, digest }` against its locally configured `ConfidentialHandshakeCaps`; any mismatch exits early with `HandshakeConfidentialMismatch` before the transport transitions to `Ready`.
4. The handshake digest does not change when registries or the committed ZK validity policy change, so no restart is needed after such a change. Stale state cannot re-enter through the handshake in any case: every block header carries the full `ConfidentialFeatureDigest` computed from committed State at its height (`compute_confidential_feature_digest`), and a block with another digest is rejected deterministically.
5. Handshake successes and failures update the standard `iroha_p2p::peer` counters (`handshake_failure_count`, error taxonomy helpers) and emit structured log entries tagged with the remote peer ID and digest fingerprint. Monitor these indicators to catch replay attempts or misconfigurations during rollout.

## Key Management & Payloads
- Per-account key derivation hierarchy:
  - `sk_spend` → `nk` (nullifier key), `ivk` (incoming viewing key), `ovk` (outgoing viewing key), `fvk`.
- Encrypted note payloads use AEAD with ECDH-derived shared keys; optional auditor view keys may be attached to outputs per asset policy.
- CLI additions: `confidential create-keys`, `confidential send`, `confidential export-view-key`, auditor tooling for decrypting memos, and the `iroha app zk envelope` helper for producing/inspecting Norito memo envelopes offline.

## Gas, Limits & DoS Controls
- Deterministic gas schedule:
  - Halo2 (Plonkish): base `250_000` gas + `2_000` gas per public input.
  - `5` gas per proof byte, plus per-nullifier (`300`) and per-commitment (`500`) charges.
  - These constants are the `gas` section of the committed `zk_validity_policy_v1` chain parameter (`gas.{proof_base, per_public_input, per_proof_byte, per_nullifier, per_commitment}`), or the protocol default when a chain commits none. A node configuration cannot set them. An authorized `SetParameter` changes the schedule from the next block; `/v1/configuration` reports the schedule State charges and is read-only.
- Hard limits: fields of the `confidential` section of the committed `zk_validity_policy_v1` chain parameter, or the protocol default when a chain commits none. A node configuration cannot set them; an authorized `SetParameter` changes them from the next block. Protocol defaults:
- `max_proof_size_bytes = 1_048_576`.
- `max_nullifiers_per_tx = 8`, `max_commitments_per_tx = 8`, `max_confidential_ops_per_block = 256`.
- `max_anchor_age_blocks = 10_000`. `verify_timeout_ms` (default `750`) is the one node-local value here: an operator latency budget for telemetry and backpressure. Consensus validity is determined by deterministic bounds such as proof size, gas, public input counts, registry policy, and anchor age.
- Additional quotas ensure liveness: `max_proof_bytes_block`, `max_verify_calls_per_tx`, `max_verify_calls_per_block`, and `max_public_inputs` bound block builders; `reorg_depth_bound` (≥ `max_anchor_age_blocks`) governs frontier checkpoint retention.
- Runtime execution now rejects transactions that exceed these per-transaction or per-block limits, emitting deterministic `InvalidParameter` errors and leaving ledger state unchanged.
- Mempool prefilters confidential transactions by `vk_id`, proof length, and anchor age before invoking the verifier to keep resource usage bounded.
- Verification rejects deterministic bound violations with explicit errors. SIMD backends are optional but do not alter gas accounting or validity, and local timeout observations do not change ledger outcomes.

### Calibration Baselines & Acceptance Gates
- **Reference platforms.** Calibration runs MUST cover the three hardware profiles below. Runs failing to capture all profiles are rejected during review.

  | Profile | Architecture | CPU / Instance | Compiler flags | Purpose |
  | --- | --- | --- | --- | --- |
  | `baseline-simd-neutral` | `x86_64` | AMD EPYC 7B12 (32c) or Intel Xeon Gold 6430 (24c) | `RUSTFLAGS="-C target-feature=-avx,-avx2,-fma"` | Establish floor values without vector intrinsics; used to tune fallback cost tables. |
  | `baseline-avx2` | `x86_64` | Intel Xeon Gold 6430 (24c) | default release | Validates AVX2 path; checks that SIMD speedups stay within tolerance of neutral gas. |
  | `baseline-neon` | `aarch64` | AWS Graviton3 (c7g.4xlarge) | default release | Ensures NEON backend remains deterministic and aligned with x86 schedules. |

- **Benchmark harness.** All gas calibration reports MUST be produced with:
  - `CRITERION_HOME=target/criterion cargo bench -p iroha_core --features bench --bench isi_gas_calibration -- --sample-size 200 --warm-up-time 5 --save-baseline <profile-label>`
  - `cargo test -p iroha_core bench_repro -- --ignored` to confirm the deterministic fixture.
  - `CRITERION_HOME=target/criterion cargo bench -p ivm --bench gas_calibration -- --sample-size 200 --warm-up-time 5 --save-baseline <profile-label>` whenever VM opcode costs change.

- **Fixed randomness.** Export `IROHA_CONF_GAS_SEED=conf-gas-seed-2026Q1` before running benches so `iroha_test_samples::gen_account_in` switches to the deterministic `KeyPair::from_seed` path. The harness prints `IROHA_CONF_GAS_SEED_ACTIVE=…` once; if the variable is missing, review MUST fail. Any new calibration utilities must continue honouring this env var when introducing auxiliary randomness.

- **Result capture.**
  - Upload Criterion summaries (`target/criterion/**/raw.csv`) for each profile into the release artefact.
  - Store derived metrics (`ns/op`, `gas/op`, `ns/gas`) in `specs/confidential_assets_calibration.md` along with the git commit and compiler version used.
  - Maintain the last two baselines per profile; delete older snapshots once the newest report is validated.

- **Acceptance tolerances.**
  - Gas deltas between `baseline-simd-neutral` and `baseline-avx2` MUST remain ≤ ±1.5%.
  - Gas deltas between `baseline-simd-neutral` and `baseline-neon` MUST remain ≤ ±2.0%.
  - Calibration proposals exceeding these thresholds require either schedule adjustments or an RFC explaining the discrepancy and mitigation.

- **Review checklist.** Submitters are responsible for:
  - Including `uname -a`, `/proc/cpuinfo` excerpts (model, stepping), and `rustc -Vv` in the calibration log.
  - Verifying `IROHA_CONF_GAS_SEED` echoed in the bench output (the benches print the active seed).
  - Ensuring pacemaker and confidential verifier feature flags mirror production (`--features confidential,telemetry` when running benches with Telemetry).

## Config & Operations
- `iroha_config` `[confidential]` holds node-local settings only:
  ```toml
  [confidential]
  enabled = true
  assume_valid = false
  verifier_backend = "halo2-ipa-pallas"
  verify_timeout_ms = 750   # local budget of one verification attempt
  ```
- Confidential limits, windows and registry caps are chain policy: the `confidential` section of the committed `zk_validity_policy_v1` parameter (protocol defaults shown), set in the genesis manifest or by an authorized `SetParameter` and effective from the next block. A node configuration that names one of them fails to load.
  ```json
  { "max_proof_size_bytes": 1048576, "max_nullifiers_per_tx": 8, "max_commitments_per_tx": 8,
    "max_confidential_ops_per_block": 256, "max_anchor_age_blocks": 10000,
    "max_proof_bytes_block": 1048576, "max_verify_calls_per_tx": 128,
    "max_verify_calls_per_block": 128, "max_public_inputs": 32, "reorg_depth_bound": 10000,
    "policy_transition_delay_blocks": 100, "policy_transition_window_blocks": 200,
    "policy_transition_max_per_height": 256, "tree_roots_history_len": 10000,
    "tree_frontier_checkpoint_interval": 100, "registry_max_vk_entries": 64,
    "registry_max_params_entries": 32, "registry_max_delta_per_block": 4 }
  ```
  A policy is coherent when a per-proof limit does not exceed the per-transaction limit, a per-transaction limit does not exceed the per-block limit, and `tree_roots_history_len` covers `max_anchor_age_blocks`. The default per-transaction verifier-call cap admits one complete production-shaped Soracloud BFV full-bootstrap execution proof batch, which can verify one proof per registered identifier slot. Keep the per-block cap aligned with the desired number of heavy confidential jobs per block.
- Telemetry emits aggregate metrics: `confidential_proof_verified`, `confidential_verifier_latency_ms`, `confidential_proof_bytes_total`, `confidential_nullifier_spent`, `confidential_commitments_appended`, `confidential_mempool_rejected_total{reason}`, and `confidential_policy_transitions_total`, never exposing plaintext data.
- RPC surfaces:
  - `GET /confidential/capabilities`
  - `GET /confidential/zk_registry`
  - `GET /confidential/params`

## Testing Strategy
- Determinism: randomized transaction shuffling within blocks yields identical Merkle roots and nullifier sets.
- Reorg resilience: simulate multi-block reorgs with anchors; nullifiers remain stable and stale anchors rejected.
- Gas invariants: verify identical gas usage across nodes with and without SIMD acceleration.
- Boundary testing: proofs at size/gas ceilings, max in/out counts, and telemetry latency-budget reporting.
- Lifecycle: governance operations for verifier and parameter activation/deprecation, rotation spend tests.
- Policy FSM: allowed/disallowed transitions, pending transition delays, and mempool rejection around effective heights.
- Registry emergencies: emergency withdrawal freezes affected assets at `withdraw_height` and rejects proofs afterwards.
- Capability gating: validators with mismatched `conf_features` reject blocks; observers with `assume_valid=true` keep up without affecting consensus.
- State equivalence: validator/full/observer nodes produce identical state roots on the canonical chain.
- Authenticated outputs: full-unshield V2 admits no private output;
  change-unshield V3 inserts only its proof-bound zero-or-one change commitment;
  retired, substituted, missing, extra, and reordered output layouts fail before
  effects.
- Tree integrity and atomicity: mixed/profile-changing verifier registrations,
  retained-root or checkpoint drift, and over-capacity multi-output batches fail
  without changing commitments, roots, checkpoints, nullifiers, balances,
  metadata, or events. Operation-count regressions require exactly one leaf hash
  and `tree_depth` parent hashes per appended commitment, independently of the
  prior tree size. Restart and reorg tests preserve the exact persisted profile,
  fixed frontier, current root, and checkpoint tuple.
- Negative fuzzing: malformed proofs, oversized payloads, and nullifier collisions reject deterministically.

## Outstanding Work
- Benchmark Halo2 parameter sets (circuit size, lookup strategy) and record the results in the calibration playbook so gas/timeout defaults can be updated alongside the next `confidential_assets_calibration.md` refresh.
- Finalize auditor disclosure policies and associated selective-viewing APIs, wiring the approved workflow into Torii once the governance draft is signed off.
- Extend the witness encryption scheme to cover multi-recipient outputs and batched memos, documenting the envelope format for SDK implementers.
- Commission an external security review of circuits, registries, and parameter-rotation procedures and archive the findings next to the internal audit reports.
- Specify auditor spentness reconciliation APIs and publish view-key scope guidance so wallet vendors can implement the same attestation semantics.

## Implementation Phasing
1. **Phase M0 — Stop-Ship Hardening**
   - ✅ Nullifier derivation now follows the Poseidon PRF design (`nk`, `rho`, `asset_id`, exact genesis-derived `network_id`) with deterministic commitment ordering enforced in ledger updates.
   - ✅ Execution enforces proof size caps and per-transaction/per-block confidential quotas, rejecting over-budget transactions with deterministic errors.
   - ✅ P2P handshake advertises `ConfidentialFeatureDigest` (backend digest + registry fingerprints) and fails mismatches deterministically via `HandshakeConfidentialMismatch`.
   - ✅ Remove panics in confidential execution paths and add role gating for nodes without matching capability.
  - ⚪ Expose verifier timeout budgets and enforce reorg depth bounds for frontier checkpoints.
     - Verification timeout budgets are telemetry/operator budgets only; proofs fail deterministically on size, gas, public input, policy, or anchor-age bounds.
     - ✅ Frontier checkpoints now respect `reorg_depth_bound`, pruning checkpoints older than the configured window while keeping deterministic snapshots.
   - Introduce `AssetConfidentialPolicy`, policy FSM, and enforcement gates for mint/transfer/reveal instructions.
   - Commit `conf_features` in block headers and refuse validator participation when registry/parameter digests diverge.
2. **Phase M1 — Registries & Parameters**
   - Land `ZkVerifierEntry`, `PedersenParams`, and `PoseidonParams` registries with governance ops, genesis anchoring, and cache management.
   - Wire syscall to require registry lookups, gas schedule IDs, schema hashing, and size checks.
   - Ship encrypted payload format v1, wallet key derivation vectors, and CLI support for confidential key management.
3. **Phase M2 — Gas & Performance**
   - Implement deterministic gas schedule, per-block counters, and benchmark harnesses with telemetry (verify latency, proof sizes, mempool rejections).
   - Harden CommitmentTree checkpoints, LRU loading, and nullifier indices for multi-asset workloads.
4. **Phase M3 — Rotation & Wallet Tooling**
   - Enable multi-parameter and multi-version proof acceptance; support governance-driven activation/deprecation with transition runbooks.
   - Deliver wallet SDK/CLI migration flows, auditor scanning workflows, and spentness reconciliation tooling.
5. **Phase M4 — Audit & Ops**
   - Provide auditor key workflows, selective disclosure APIs, and operational runbooks.
   - Schedule external cryptography/security review and publish findings in `status.md`.

Each phase updates roadmap milestones and associated tests to maintain deterministic execution guarantees for the blockchain network.

### SDK & Fixture Coverage (Phase M1)

The local Swift encrypted-payload codec has an exact-byte fixture. Rust tests
the exact-eight-slot confidential memo envelope. KAGEMUSHA transaction parity
is exercised by its dedicated V1 suite; the first-release surface has no
generic confidential wallet-flow fixture or encoder:

```bash
# Rust exact-eight-slot memo envelope
cargo test -p iroha_data_model --test confidential_memo_envelope_v1

# Swift encrypted-payload fixture
cd IrohaSwift && swift test --filter ConfidentialEncryptedPayloadTests
```

The release-surface guards reject the retired generic and anonymous-escrow type
names and wire fingerprints while retaining only the KAGEMUSHA V1
instructions. The Swift fixture test checks exact bytes and malformed-input
behavior; the Rust memo-envelope test checks its current wire shape.

#### Wallet and SDK builders

SDKs expose authenticated KAGEMUSHA V1 top-up/redemption. They do not expose
generic `Shield`, `ZkTransfer`, `Unshield`, or native anonymous-escrow requests
or encoders. SDK manifests and generated
instruction catalogs must omit all three retired data-model types and their
wire fingerprints.

`vk_unshield` is the only first-release generic confidential-asset verifier
binding; it grants no KAGEMUSHA authority.
Wallet implementations must build and sign the complete KAGEMUSHA V1 object;
a proof envelope, amount, nullifier list, or opaque commitment is never
sufficient authority on its own.

### Telemetry & Monitoring (Phase M2)

Phase M2 now exports CommitmentTree health directly via Prometheus and Grafana:

- `iroha_confidential_tree_commitments`, `iroha_confidential_tree_depth`, `iroha_confidential_root_history_entries`, and `iroha_confidential_frontier_checkpoints` expose the live Merkle frontier per asset while `iroha_confidential_root_evictions_total` / `iroha_confidential_frontier_evictions_total` count the LRU trims enforced by `confidential.tree_roots_history_len` and the checkpoint depth window.
- `iroha_confidential_frontier_last_checkpoint_height` and `iroha_confidential_frontier_last_checkpoint_commitments` publish the height + commitment count of the most recent frontier checkpoint so reorg drills and rollbacks can prove that checkpoints advance and retain the expected payload volume.
- The Grafana board (`dashboards/grafana/confidential_assets.json`) includes a depth series, eviction-rate panels, and the existing verifier cache widgets so operators can prove that CommitmentTree depth never collapses even as checkpoints churn.
- Alert `ConfidentialTreeDepthZero` (in `dashboards/alerts/confidential_assets_rules.yml`) trips once commitments are observed but the reported depth sticks at zero for five minutes.

You can verify the metrics locally before wiring Grafana:

```bash
curl -s http://127.0.0.1:8180/metrics \
  | rg 'iroha_confidential_(tree_(commitments|depth)|root_history_entries|frontier_(checkpoints|last_checkpoint_height|last_checkpoint_commitments)|root_evictions_total|frontier_evictions_total){asset_id="4cuvDVPuLBKJyN6dPbRQhmLh68sU"}'
```

Pair this with `rg 'iroha_confidential_tree_depth'` on the same scrape to confirm that depth grows with new commitments while eviction counters only increase when the history caps trim entries. These values must line up with the Grafana dashboard export you attach to governance evidence bundles.

#### Gas schedule telemetry & alerts

Phase M2 also threads the configurable gas multipliers into the telemetry pipeline so operators can prove that every validator shares the same verification costs before approving a release:

- `iroha_confidential_gas_base_verify` mirrors `gas.proof_base` of the committed `zk_validity_policy_v1` parameter (protocol default `250_000`).
- `iroha_confidential_gas_per_public_input`, `iroha_confidential_gas_per_proof_byte`, `iroha_confidential_gas_per_nullifier`, and `iroha_confidential_gas_per_commitment` mirror the other four charges of that section. Core sets the gauges whenever it installs the schedule a State charges (at restore and at block construction), so they follow an authorized change of the committed policy. No node configuration holds a schedule.

Scrape the gauges alongside the CommitmentTree metrics to confirm the knobs are identical across peers:

```bash
# compare active multipliers across validators
for host in validator-a validator-b validator-c; do
  curl -s "http://$host:8180/metrics" \
    | rg 'iroha_confidential_gas_(base_verify|per_public_input|per_proof_byte|per_nullifier|per_commitment)'
done
```

Grafana dashboard `confidential_assets.json` now includes a “Gas Schedule” panel that renders the five gauges and highlights divergence. Alert rules in `dashboards/alerts/confidential_assets_rules.yml` cover:
- `ConfidentialGasMismatch`: checks the max/min of each multiplier across all scrape targets and pages when any diverge for more than 3 minutes, which means the nodes are at different heights or on different histories: the schedule is committed chain policy (`zk_validity_policy_v1`), and node configuration can neither cause nor cure a divergence.
- `ConfidentialGasTelemetryMissing`: warns when Prometheus cannot scrape any of the five multipliers for 5 minutes, indicating a missing scrape target or disabled telemetry.

Keep the following PromQL handy for on-call investigations:

```promql
# ensure every multiplier matches across validators (uses the same projection as the alert)
(max without(instance, job) (iroha_confidential_gas_per_public_input)
  - min without(instance, job) (iroha_confidential_gas_per_public_input)) == 0
```

Deviation should remain zero outside of controlled config rollouts. When changing the gas table, use a coordinated validator restart, capture before/after scrapes, attach them to the change request, and update `specs/confidential_assets_calibration.md` with the new multipliers so governance reviewers can link the telemetry evidence to the calibration report.
