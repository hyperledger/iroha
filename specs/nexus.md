#! Iroha 3 – SORA Nexus Ledger: Technical Design Specification

This document specifies the SORA Nexus Ledger architecture for Iroha 3: a single global, logically unified ledger organized around Data Spaces (DS). Data Spaces provide strong privacy domains (“private data spaces”) and open participation (“public data spaces”). The design preserves composability across the global ledger while ensuring strict isolation and confidentiality for private‑DS data, and introduces data‑availability scaling via erasure coding across Kura (block storage) and WSV (World State View).

Iroha 3 supports self-hosted deployments and the connected data spaces of SORA
Nexus. Each data space can have multiple lanes for transaction routing,
dissemination, and certification. Execution is powered by the shared Iroha
Virtual Machine (IVM) and Kotodama toolchain, so contracts and bytecode artifacts
remain portable across both deployment profiles.

Goals
- One global logical ledger composed from many cooperating validators and Data Spaces.
- Private Data Spaces for permissioned operation (e.g., CBDCs), with data never leaving the private DS.
- Public Data Spaces with open participation, Ethereum-like permissionless access.
- Composable smart contracts across Data Spaces, subject to explicit permissions for access to private‑DS assets.
- Performance isolation so public activity cannot degrade private‑DS internal transactions.
- Data availability at scale: erasure‑coded Kura and WSV to support effectively unbounded data while keeping private‑DS data private.

Non‑Goals (Initial Phase)
- Defining token economics or validator incentives; scheduling and staking policies are pluggable.
- Changing `abi_version` away from `1` is out of scope. The first-release ABI v1 surface includes typed anchored-spend staging at syscall `0xB5` and pointer ID `0x0013`; runtime upgrades do not add a second ABI.

Terminology
- SORA Nexus Ledger: The connected ledger architecture with a global execution
  domain and independently executing data spaces. Public lanes feed certified
  transaction batches into global execution; independent data space roots retain
  their own State and local finality and coordinate through authenticated evidence.
- Data Space (DS): A bounded execution and storage domain with its own validators, governance, privacy class, DA policy, quotas, and fee policy. Two classes exist: public DS and private DS.
- Private Data Space: Permissioned validators and access control; transaction data and state never leave the DS. Only commitments/metadata are anchored globally.
- Public Data Space: Permissionless participation; full data and state are publicly available.
- Data Space Manifest (DS Manifest): A Norito-encoded manifest that declares DS parameters (validators/QC keys, privacy class, ISI policy, DA parameters, retention, quotas, ZK policy, fees). The manifest hash is anchored on the nexus chain. Unless overridden, DS quorum certificates use ML‑DSA‑87 (Dilithium5‑class) as the default post‑quantum signature scheme.
- Space Directory: A global on‑chain directory contract that tracks DS manifests, versions, and governance/rotation events for resolvability and audits.
- DSID: A globally unique identifier for a physical Data Space. It qualifies an
  object's execution/storage location but is not the object's namespace.
- Namespace: An independently governed logical naming scope with an explicit
  home-DS binding. Namespace identity remains distinct from both `DataSpaceId`
  and `LaneId`, even when a rendered identifier includes a data space suffix.
- Data space catalog: `DataSpaceCatalog`, configured by
  `[[nexus.dataspace_catalog]]`, defines data spaces and their `DataSpaceId`s.
- Lane catalog: `LaneCatalog`, configured by `[[nexus.lane_catalog]]`, defines
  lanes and their `LaneId`s. Each lane explicitly references one data space;
  multiple lanes can reference the same data space catalog entry.
- Lane: A transaction routing, dissemination, and certification stream assigned
  to exactly one Data Space. Public lanes certify ordered batches that the
  global chain executes against global State (`sumeragi_lanes.md`). Lane
  configuration does not create an independent data space root; those roots have
  their own State and local finality (`sumeragi.md` §11).
- Anchor: A cryptographic commitment from a DS block/header included into the nexus chain to bind DS history into the global ledger.
- Kura: Iroha block storage. Extended here with erasure‑coded blob storage and commitments.
- WSV: Iroha World State View. Extended here with versioned, snapshot‑capable, erasure‑coded state segments.
- IVM: Iroha Virtual Machine for smart contract execution (Kotodama bytecode `.to`).
 - AIR: Algebraic Intermediate Representation. An algebraic view of computation for STARK‑style proofs, describing execution as field‑based traces with transition and boundary constraints.

In articles and diagrams, call an institution's environment a **data space**.
Explain lanes when their routing or scaling role matters. A single-lane example
does not make the two identities interchangeable or impose a one-to-one model.

Data Spaces Model
- Identity: `DataSpaceId (DSID)` identifies a physical execution, storage, and
  validator boundary. Domains, account aliases, and asset definitions retain
  their own logical identifiers and bind explicitly to a home DSID. Creating a
  domain, namespace, asset, governance module, or lane never implicitly creates
  a Data Space. Multiple such objects and multiple lanes may share one DSID;
  transactions can touch multiple DSIDs atomically.
  The data space catalog records that identity; independent execution and local
  finality require the independently signed root and authority of `sumeragi.md`
  §11, not merely the catalog entry or its associated lanes.
- Manifest lifecycle: DS creation, updates (key rotation, policy changes), and retirement are recorded in the Space Directory. Each per‑slot DS artifact references the latest manifest hash.
- Classes: Public DS (open participation, public DA) and Private DS (permissioned, confidential DA). Hybrid policies are possible via manifest flags.
- Policies per DS: ISI permissions, DA parameters `(k,m)`, encryption, retention, quotas (min/max tx share per block), ZK/optimistic proof policy, fees.
- Governance: DS membership and validator rotation defined by the manifest’s governance section (on-chain proposals, multisig, or external governance anchored by nexus transactions and attestations).

Gossip routing by data space
- Transaction gossip batches carry a plane tag (public or restricted) derived from the lane catalog. Each restricted batch contains one exact lane/data space route. Recipients come from that route’s current committed native incarnation and live participant-role keys with matching pinned proofs of possession. Restricted gossip receivers enforce the same membership before materializing transactions; Torii ingress remains a separate admission boundary. Restricted batches target only connected authorized members, respecting `transaction_gossip_restricted_target_cap`; missing authority or unavailable recipients defer delivery without using the public overlay. Public batches use `transaction_gossip_public_target_cap` (set `null` for broadcast). Target selection reshuffles on the per-plane cadence set by `transaction_gossip_public_target_reshuffle_ms` and `transaction_gossip_restricted_target_reshuffle_ms` (default: `transaction_gossip_period_ms`). Telemetry reports recipient selections, outcomes, and drop reasons for each data space.
- Unknown data spaces are re-queued when `transaction_gossip_drop_unknown_dataspace` is enabled; otherwise they fall back to restricted targeting to avoid leaks.
- Receive-side validation drops entries whose lanes/data spaces disagree with the local catalog, whose plane tag does not match the derived data space visibility, or whose advertised route does not match the locally re-derived routing decision.

Capability manifests & UAID
- Universal accounts: Every participant receives a deterministic canonical UAID (`UniversalAccountId` in `crates/iroha_data_model/src/nexus/manifest.rs`) that spans all data spaces. UAIDs are Blake2b-256 digests with the final-byte LSB set to `1`; onboarding clients must submit the explicit `uaid` literal, and Torii rejects mutable alias/account-derived fallback generation. Capability manifests (`AssetPermissionManifest`) bind a UAID to a specific data space, activation/expiry epochs, and an ordered list of allow/deny `ManifestEntry` rules that scope `dataspace`, `program_id`, `method`, `asset`, and optional AMX roles. Deny rules always win; the evaluator emits either `ManifestVerdict::Denied` with an audit reason or an `Allowed` grant with the matching allowance metadata.
- UAID portfolio snapshots are now exposed via `GET /v1/accounts/{uaid}/portfolio` (see `specs/torii/portfolio_api.md`), backed by the deterministic aggregator in `iroha_core::nexus::portfolio`.
- Allowances: Each allow entry carries deterministic `AllowanceWindow` buckets (`PerSlot`, `PerMinute`, `PerDay`) plus an optional `max_amount`. Hosts and SDKs consume the same Norito payload, so enforcement remains identical across hardware and SDK implementations.
- Audit telemetry: The Space Directory broadcasts `SpaceDirectoryEvent::{ManifestActivated, ManifestExpired, ManifestRevoked}` (`crates/iroha_data_model/src/events/data/space_directory.rs`) whenever a manifest changes state. The new `SpaceDirectoryEventFilter` surface allows Torii/data-event subscribers to monitor UAID manifest updates, revocations, and deny-wins decisions without custom plumbing.

### UAID manifest operations

Space Directory operations ship in two forms so operators can choose either the
in-binary CLI (for scripted rollouts) or direct Torii submissions (for automated
CI/CD). Both paths enforce the `CanPublishSpaceDirectoryManifest{dataspace}`
permission inside the executor (`crates/iroha_core/src/smartcontracts/isi/space_directory.rs`)
and record lifecycle events in world state (`iroha_core::state::space_directory_manifests`).

#### CLI workflow (`iroha app space-directory manifest …`)

1. **Encode manifest JSON** — convert policy drafts into Norito bytes and emit a
   reproducible hash before review:

   ```bash
   iroha app space-directory manifest encode \
     --json dataspace/capability.json \
     --out artifacts/capability.manifest.to \
     --hash-out artifacts/capability.manifest.hash
   ```

   The helper accepts either `--json` (raw JSON manifest) or `--manifest` (existing
   `.to` payload) and mirrors the logic in
   `crates/iroha_cli/src/space_directory.rs::ManifestEncodeArgs`.

2. **Publish/replace manifests** — enqueue `PublishSpaceDirectoryManifest`
   instructions from either Norito or JSON sources:

   ```bash
   iroha app space-directory manifest publish \
     --manifest artifacts/capability.manifest.to \
     --reason "Retail wave 4 on-boarding"
   ```

   `--reason` backfills `entries[*].notes` for records that omitted operator notes.

3. **Expire** manifests that reached their scheduled end of life or **revoke**
   UAIDs on demand. Both commands require exact lower-case
   `--uaid uaid:<64-hex>` literals (LSB=1) and the numeric data space id:

   ```bash
   iroha app space-directory manifest expire \
     --uaid uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11 \
     --dataspace 11 \
     --expired-epoch 4600

   iroha app space-directory manifest revoke \
     --uaid uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11 \
     --dataspace 11 \
     --revoked-epoch 9216 \
     --reason "Fraud investigation NX-16-R05"
   ```

4. **Produce audit bundles** — `manifest audit-bundle` writes the manifest JSON,
   `.to` payload, hash, data space profile, and machine-readable metadata to an
   output directory so governance reviewers can download a single archive:

   ```bash
   iroha app space-directory manifest audit-bundle \
     --manifest-json dataspace/capability.json \
     --profile dataspace/profiles/cbdc_profile.json \
     --out-dir artifacts/capability_bundle
   ```

   The bundle embeds `SpaceDirectoryEvent` hooks from the profile to prove the
   data space exposes the mandatory audit webhooks; see `specs/space_directory.md`
   for the field layout and evidence requirements.

#### Torii APIs

Operators and SDKs can prepare the same actions over HTTPS. Torii validates and
quotes each mutation, but private keys remain with the client:

- `GET /v1/space-directory/uaids/{uaid}` — resolve the current data space bindings
  for a UAID (normalized addresses, data space ids, program bindings). Add
  `canonical I105 output` for Sora Name Service output (canonical I105 output only).
- `GET /v1/accounts/{uaid}/portfolio` —
  Norito-backed aggregator that mirrors `ToriiClient.getUaidPortfolio` so wallets
  can render universal holdings without scraping each data space's state. Pass
  `asset_id=<canonical_base58_asset_definition_id>` to filter the snapshot down to one asset.
- `GET /v1/space-directory/uaids/{uaid}/manifests?dataspace={id}` — fetch the
  canonical manifest JSON, lifecycle metadata, and manifest hash for audits.
- `POST /v1/space-directory/manifests` — prepare new or replacement manifests
  from JSON (`authority`, `manifest`, optional `reason`).
- `POST /v1/space-directory/manifests/revoke` — prepare emergency revocations
  with the authority, UAID, data space id, effective epoch, and optional reason.

Both mutation routes reject unknown fields, including `private_key`, and return
`submitted: false` with canonical `transaction_payload_b64` and
`signing_message_b64`. The caller validates the payload, signs locally, and
submits through the ordinary transaction pipeline. Preparing either draft also
requires exact-NetworkId canonical account authentication over the exact HTTP
method, path, query, and raw JSON body. The authenticated account must equal the
body `authority`; CIDR allowlists or a deployment-wide API token are additional
admission controls and never substitute for that signature.

The JS SDK (`javascript/iroha_js/src/toriiClient.js`) wraps these read surfaces
via `ToriiClient.getUaidPortfolio`, `.getUaidBindings`, and
`.getUaidManifests`; all SDK implementations use the same REST payloads.
Reference `specs/torii/portfolio_api.md` for complete request/response
schemas and `specs/space_directory.md` for the source-adjacent operator
playbook.

AMX budget guardrails (NX-17)
- `ivm::analysis::enforce_amx_budget` estimates execution costs for each data space
  and group from the static analysis report. At AXT commit the host enforces
  `pipeline.amx_per_dataspace_budget_ms` (default 30 ms) and
  `pipeline.amx_group_budget_ms` (default 140 ms); a violation rejects the
  transaction with `AMX_TIMEOUT`.【crates/ivm/src/analysis.rs:795】

High‑Level Architecture
1) Global Composition Layer (Nexus Chain)
- Maintains a single, canonical ordering of 1‑second Nexus Blocks that finalize atomic transactions spanning one or more Data Spaces (DS). Every committed transaction updates the unified global world state (vector of per‑DS roots).
- Contains minimal metadata plus aggregated proofs/QCs to ensure composability, finality, and fraud detection (DSIDs touched, per‑DS state roots before/after, DA commitments, per‑DS validity proofs, and the DS quorum certificate using ML‑DSA‑87). No private data is included.
- Consensus: the global Sumeragi instance (`sumeragi.md`). Each committee is exactly `3f + 1` (4 to 31 validators) from governed NPoS elections, with epoch randomness from the finalized global threshold-BLS beacon.

2) Data Space Layer (Public/Private)
- Executes per‑DS fragments of global transactions, updates DS‑local WSV, and produces per‑block validity artifacts (aggregated per‑DS proofs and DA commitments) that roll up into the 1‑second Nexus Block.
- Private DS encrypt data‑at‑rest and data‑in‑flight among authorized validators; only commitments and PQ validity proofs leave the DS.
- Public DS export full data bodies (via DA) and PQ validity proofs.

3) Atomic Cross‑Data‑Space Transactions (AMX)
- Transactions on different lanes of one data space need no cross-lane protocol: the global block that merges the lanes fixes their order and atomicity (`sumeragi_lanes.md`).
- Data spaces with separate state keep DS-local finality; AMX across them is a two-phase commit through the global chain (Begin, Prepare/escrow, relay, Decision by deadline, Settle; `sumeragi.md` §11, goal S6).
- Privacy: private DS export only proofs/commitments; no raw private data leaves the DS.

Confidential CBDC-style settlement uses the separate governed, default-off
`AtomicPrivateSettlementV1` path specified in `private_settlement.md`.

4) Data Availability (DA) with Erasure Coding
- Kura stores block bodies and WSV snapshots as erasure-coded blobs. Public blobs are widely sharded; private blobs are stored only within private‑DS validators, with encrypted chunks.
- DA Commitments are recorded in both DS artifacts and Nexus Blocks, enabling sampling and recovery guarantees without revealing private contents.

Block and Commit Structure
- Data Space Proof Artifact (per 1s slot, per DS)
  - Fields: dsid, slot, pre_state_root, post_state_root, ds_tx_set_hash, kura_da_commitment, wsv_da_commitment, manifest_hash, ds_qc (ML‑DSA‑87), ds_validity_proof (FASTPQ‑ISI).
  - Private‑DS export artifacts without data bodies; public DS allow body retrieval via DA.

- Nexus Block (1s cadence)
  - Fields: block_number, parent_hash, slot_time, tx_list (atomic cross‑DS transactions with DSIDs touched), ds_artifacts[], nexus_qc.
  - Function: finalizes all atomic transactions whose required DS artifacts verify; updates the global world state vector of DS roots in one step.

Consensus and Scheduling
- Consensus: one Sumeragi instance orders the global chain (`sumeragi.md`). Each lane is a further Sumeragi instance whose committee is pinned at creation; the global chain merges its certified blocks (`sumeragi_lanes.md`). Data spaces with separate state use the two-phase commit of `sumeragi.md` §11.
- Transaction Scheduling: Users submit atomic transactions declaring touched DSIDs and read‑write sets. DS execute in parallel within the slot; the nexus committee includes the transaction in the 1s block if all DS artifacts verify and DA certificates are timely (≤300 ms).
- Performance Isolation: Each DS has independent mempools and execution. Per‑DS quotas bound how many transactions touching a given DS can be committed per block to avoid head‑of‑line blocking and protect private DS latency.

Data Model and Namespacing
- Namespace bindings: logical namespaces bind explicitly to a home `dsid`;
  the namespace identifier and the `DataSpaceId` remain separate typed values.
  Canonical `AccountId` remains domainless, while account labels, domains, and
  assets carry their own identity and routing context outside that account ID.
- Global References: A global reference is a tuple
  `(dsid, namespace_or_object_id, version_hint)` and can be placed on-chain in
  the nexus layer or in AMX descriptors for cross-DS use. The DSID selects the
  physical boundary; it does not replace the logical namespace or object ID.
- Norito Serialization: All cross‑DS messages (AMX descriptors, proofs) use Norito codecs. No serde usage in production paths.

Smart Contracts and IVM Extensions
- Execution Context: Add `dsid` to IVM execution context. Kotodama contracts always execute within a specific Data Space.
- Atomic Cross‑DS Primitives:
  - `amx_begin()` / `amx_commit()` demarcate an atomic multi‑DS transaction in the IVM host.
  - `amx_touch(dsid, key)` declares read/write intent for conflict detection against slot snapshot roots.
  - `verify_space_proof(dsid, proof, statement)` → bool
  - Remote spends use the signed `AxtAnchoredSpendV1` envelope wire. Production admission remains closed until the finalized source anchor, successful execution receipt, exact transfer occurrence, and atomic nonce/budget/effect owner are connected; no reusable-handle VM syscall is admitted.
  - State permanently retains both the issuer-context nonce and the physical source transfer coordinate `(network, dataspace, lane, finalized block header, transaction index, transcript index, delta index)`. One transactional reservation pairs them, and snapshot restore rejects missing or inconsistent pairs. Neither a new nonce nor a different handle or proof can make a consumed physical transfer fresh. This replay substrate does not authorize a remote spend while source finality and issuer authority remain unverified.
- Asset Handles and Fees:
  - Asset operations are authorized by the DS’s ISI/role policies; fees are paid in the DS’s gas token. Optional capability tokens and richer policy (multi‑approver, rate‑limits, geofencing) can be added later without changing the atomic model.
- Determinism: All syscalls are pure and deterministic given inputs and declared AMX read/write sets. No hidden time or environment effects.

Post‑Quantum Validity Proofs (FASTPQ V1)

The [FASTPQ implementation plan](fastpq_plan.md#implemented-release-boundary)
defines the current accepted operations and authenticated public inputs. The
production verifier still reconstructs the replay; its replacement by qualified
bounded-opening admission remains a [release requirement](fastpq_production_readiness.md).
Generalized ISI coverage and performance targets are not current qualification.

- Native STARK Merkle commitments and Fiat–Shamir framing use the single shared
  six-lane Goldilocks Poseidon-x7 construction. The [compact protocol
  contract](fastpq_compact_protocol_contract.md) and [exact V1 framing
  contract](fastpq_compact_v1_framing.md) own its field arithmetic, fixed binary
  FRI geometry, transcript, complete context and query schedule.
- Hash construction and proof geometry are compiled protocol identities. A
  data space manifest cannot select another hash, FRI arity, transcript or proof
  system. There is no general-STARK or recursive fallback for an unsupported
  operation.
- The [public artifact boundary](fastpq_public_artifacts.md) distinguishes
  ordinary and AXT statements, canonical transport, offline verification and
  authenticated node admission. Decoding or mathematically verifying an
  artifact does not establish source finality, asset authority or permission.
- [Resource and soundness qualification](fastpq_production_readiness.md) must
  bind the final source, proof representation and supported hardware before
  release. Offline proof checks do not qualify production admission or establish
  proof-size, throughput, memory or security guarantees.

AIR Primer (for Nexus)
- Execution trace: A matrix with width (register columns) and length (steps). Each row is a logical step of ISI processing; columns hold pre/post values, selectors, and flags.
- Constraints:
  - Transition constraints: enforce row‑to‑row relations (e.g., post_balance = pre_balance − amount for a debit row when `sel_transfer = 1`).
  - Boundary constraints: bind public I/O (old_root/new_root, counters) to the first/last rows.
  - Lookups/permutations: ensure membership and multiset equalities against committed tables (permissions, asset params) without bit‑heavy circuits.
- Commitment and verification:
  - Prover commits to traces via hash‑based encodings and constructs low‑degree polynomials that are valid iff constraints hold.
  - Verifier checks low‑degree via FRI (hash‑based, post‑quantum) with a few Merkle openings; cost is logarithmic in steps.
- Example (Transfer): registers include pre_balance, amount, post_balance, nonce, and selectors. Constraints enforce non‑negativity/range, conservation, and nonce monotonicity, while an aggregated SMT multi‑proof links pre/post leaves to old/new roots.

ABI Stability (ABI v1)
- ABI v1 is the sole first-release surface. Its finalized candidate includes signed anchored-spend staging at `0xB5` with pointer ID `0x0013`; retired `0xB4` is unassigned.
- Runtime upgrades must keep `abi_version = 1` with empty `added_syscalls`/`added_pointer_types`.
- ABI goldens (syscall list, ABI hash, pointer type IDs) pin that one candidate and must be regenerated together for any pre-release edit.

Privacy Model
- Private Data Containment: Transaction bodies, state diffs, and WSV snapshots for private DS never leave the private validator subset.
- Public Exposure: Only headers, DA commitments, and PQ validity proofs are exported.
- Optional ZK Proofs: Private DS may produce ZK proofs (e.g., balance sufficient, policy satisfied) enabling cross‑DS actions without revealing internal state.
- Access Control: Authorization is enforced by ISI/role policies inside the DS. Capability tokens are optional and can be introduced later if needed.

Performance Isolation and QoS
- Separate consensus, mempools, and storage per DS.
- Nexus scheduling quotas per DS to bound anchor inclusion time and avoid head-of-line blocking.
- Contract resource budgets per DS (compute/memory/IO), enforced by IVM host. Public‑DS contention cannot consume private‑DS budgets.
- Asynchronous cross‑DS calls avoid long synchronous waits inside private‑DS execution.

Data Availability and Storage Design
1) Erasure Coding
- Use systematic Reed‑Solomon (e.g., GF(2^16)) for blob‑level erasure coding of Kura blocks and WSV snapshots: parameters `(k, m)` with `n = k + m` shards.
- Default parameters (proposed, public DS): `k=32, m=16` (n=48), enabling recovery from up to 16 shard losses with ~1.5× expansion. For private DS: `k=16, m=8` (n=24) within the permissioned set. Both are configurable per DS Manifest.
- Public Blobs: Shards distributed across many DA nodes/validators with sampling‑based availability checks. DA commitments in headers allow light clients to verify.
- Private Blobs: Shards encrypted and distributed only within private‑DS validators (or designated custodians). Global chain carries only DA commitments (no shard locations or keys).

2) Commitments and Sampling
- For each blob: compute a Merkle root over shards and include it in `*_da_commitment`. Remain PQ by avoiding elliptic‑curve commitments.
- DA Attesters: VRF‑sampled regional attesters (e.g., 64 per region) issue an ML‑DSA‑87 certificate attesting successful shard sampling. Target DA attestation latency ≤300 ms. Nexus committee validates certificates instead of pulling shards.

3) Kura Integration
- Blocks store transaction bodies as erasure-coded blobs with Merkle commitments.
- Headers carry blob commitments; bodies are retrievable via DA network for public DS and via private channels for private DS.

4) WSV Integration
- WSV Snapshotting: Periodically checkpoint DS state into chunked, erasure-coded snapshots with commitments recorded in headers. Between snapshots, maintain change logs. Public snapshots are widely sharded; private snapshots remain within private validators.
- Proof‑Carrying Access: Contracts can provide (or request) state proofs (Merkle/Verkle) anchored by snapshot commitments. Private DS may supply zero‑knowledge attestations instead of raw proofs.

5) Retention and Pruning
- No pruning for public DS: retain all Kura bodies and WSV snapshots via DA (horizontal scaling). Private DS may define internal retention, but exported commitments remain immutable. Nexus layer retains all Nexus Blocks and DS artifact commitments.

Networking and Node Roles
- Global Validators: Participate in nexus consensus, validate Nexus Blocks and DS artifacts, perform DA checks for public DS.
- Data Space Validators: Run DS consensus, execute contracts, manage local Kura/WSV, handle DA for their DS.
- DA Nodes (optional): Store/publicize public blobs, facilitate sampling. For private DS, DA nodes are co-located with validators or trusted custodians.

System‑Level Improvements and Considerations
- Sequencing/mempool decoupling: Adopt a DAG mempool (e.g., Narwhal‑style) feeding a pipelined BFT at the nexus layer to lower latency and improve throughput without changing the logical model.
- DS quotas and fairness: Per‑DS per‑block quotas and weight caps to avoid head‑of‑line blocking and ensure predictable latency for private DS.
- DS attestation (PQ): Default DS quorum certificates use ML‑DSA‑87 (Dilithium5‑class). This is post‑quantum and larger than EC signatures but acceptable at one QC per slot. DS may explicitly opt for ML‑DSA‑65/44 (smaller) or EC signatures if declared in the DS Manifest; public DS are strongly encouraged to keep ML‑DSA‑87.
- DA attesters: For public DS, use VRF‑sampled regional attesters that issue DA certificates. The nexus committee validates certificates instead of raw shard sampling; private DS keep DA attestations internal.
- Recursion and epoch proofs: Optionally aggregate multiple micro‑batches within a DS into one recursive proof per slot/epoch to keep proof sizes and verify time steady under high load.
- Lane scaling: lanes are Sumeragi instances opened and closed by deterministic autoscale in the global chain (`sumeragi_lanes.md` §6).
- Deterministic acceleration: Provide SIMD/CUDA feature‑gated kernels for hashing/FFT with a bit‑exact CPU fallback to preserve cross‑hardware determinism.

Fees and Economics (Initial Defaults)
- Gas unit: per‑DS gas token with metered compute/IO; fees are paid in the DS’s native gas asset. Conversion across DS is an application concern.
- Inclusion priority: round‑robin across DS with per‑DS quotas to preserve fairness and 1s SLOs; within a DS, fee bidding can break ties.
- Future: optional global fee market or MEV‑minimizing policies can be explored without changing atomicity or PQ proof design.

- Security Considerations
- Deterministic Execution: IVM syscalls remain deterministic; cross‑DS outcomes are driven by AMX commit and finality, not wall‑clock or network timing.
- Access Control: ISI permissions in private DS restrict who may submit transactions and what operations are allowed. Capability tokens encode fine‑grained rights for cross‑DS use.
- Confidentiality: End‑to‑end encryption for private‑DS data, erasure‑coded shards stored only among authorized members, optional ZK proofs for external attestations.
- DoS Resistance: Isolation at mempool/consensus/storage layers prevents public congestion from impacting private‑DS progress.

Changes to Iroha Components
- iroha_data_model: Introduce `DataSpaceId`, DS‑qualified identifiers, AMX descriptors (read/write sets), proof/DA commitment types. Norito‑only serialization.
- ivm: Ship the one ABI v1 surface, including typed anchored-spend staging; keep ABI goldens pinned to the final candidate.
- iroha_core: Implement nexus scheduler, Space Directory, AMX routing/validation, DS artifact verification, and policy enforcement for DA sampling and quotas.
- Space Directory & manifest loaders: Thread FMS endpoint metadata (and other common-good service descriptors) through DS manifest parsing so nodes auto-discover local service endpoints when joining a Data Space.
- kura: Blob store with erasure coding, commitments, retrieval APIs respecting private/public policies.
- WSV: Snapshotting, chunking, commitments; proof APIs; integration with AMX conflict detection and verification.
- irohad: Node roles, networking for DA, private‑DS membership/authentication, configuration via `iroha_config` (no env toggles in production paths).

Configuration and Determinism
- All runtime behavior configured via `iroha_config` and threaded through constructors/hosts. No production env toggles.
- Hardware acceleration (SIMD/NEON/METAL/CUDA) is optional and feature-gated; deterministic fallbacks must produce identical results across hardware.
- - Post‑Quantum default: All DS must use PQ validity proofs (STARK/FRI) and ML‑DSA‑87 for DS QCs by default. Alternatives require explicit DS Manifest declaration and policy approval.

### Runtime Lane Lifecycle Control

- **Consensus lifecycle transaction:** add lanes to the physical lane catalog by
  submitting a signed transaction containing `SetParameter` with the custom
  parameter id `nexus_lane_lifecycle_v1`. Construct the versioned payload with
  `LaneLifecycleParameterV1::new(&current_catalog, &active_incarnations, plan)`;
  it commits to the exact catalog and active lane incarnations reviewed by the
  signer and is rejected if topology changed before execution. The transaction
  authority must hold `CanSetParameters`. The physical catalog only grows:
  plans that retire a lane and configuration swaps that drop one are rejected,
  because a lane's storage and history outlive its closure. Opening and closing
  consensus lanes is native lane state (`sumeragi_lanes.md` §2).
  Lifecycle effects publish only with the committed block, replay identically
  on every peer, reconcile lane storage before state publication, and refresh
  queue routing after publication. A block accepts at most one lifecycle
  transition. There is no node-local HTTP mutation route: `POST /v1/nexus/lifecycle`
  is unregistered and resolves as a wrong method on the read-only resource.
  Submit the signed transaction through the normal transaction endpoint instead.
- **Status discovery:** `GET /v1/nexus/lifecycle` is a read-only, access-policy
  checked endpoint that negotiates JSON or native Norito. Its versioned response
  contains the exact canonical `lane_count`/`lanes` and the domain-separated
  `catalog_hash`, plus the exact active lane-incarnation entries
  and their `incarnation_root`. Clients validate both commitments before signing,
  so a delayed request cannot replay after a lane is retired and recreated with
  identical metadata. The Rust client exposes `get_lane_lifecycle_status`;
  Python and Mochi follow the same fetch-once, sign, submit, and wait sequence. They intentionally surface stale concurrent
  updates instead of silently refetching and signing a topology the operator did
  not review.
- **Behaviour:** Normal transaction validation rejects malformed or unsupported
  payload versions, stale catalog commitments, empty or structurally invalid
  plans, reserved autoscale-lane mutations, unknown data spaces, and authorities
  without `CanSetParameters`. A rejected transaction leaves both the block
  overlay and committed topology unchanged.
- **Safety:** Commit revalidates the signed plan against committed state under
  the lifecycle lock before publishing storage or topology.
- **Propagation:** Queue routing, per-lane limits, and manifests are rebuilt
  from the committed catalog. Consensus and DA workers consume the same
  refreshed state snapshot, while snapshots and startup replay restore the
  effective catalog and lane storage geometry after restart.
- **Storage:** Kura and tiered WSV geometry are provisioned for added lanes, and DA shard cursor mappings are synced and persisted.

Implementation Path
1) Introduce data‑space‑qualified IDs and Nexus block/global state composition in the data model.
2) Implement Kura/WSV erasure‑coding backends as mandatory deterministic protocol components.
3) Finalize the sole ABI v1, including `0xB5` and pointer `0x0013`; regenerate syscall, pointer, gas, and ABI-hash fixtures together.
4) Deliver minimal nexus chain with a single public DS and 1s blocks; then add first private‑DS pilot exporting proofs/commitments only.
5) Expand to full atomic cross‑DS transactions (AMX) with DS‑local FASTPQ‑ISI proofs and DA attesters; enable ML‑DSA‑87 QCs across DS.

Testing Strategy
- Unit tests for data model types, Norito roundtrips, AMX syscall behaviors, and proof encoding/decoding.
- IVM tests to pin ABI v1 syscall list/ABI hash/pointer‑type goldens.
- Integration tests for atomic cross‑DS transactions (positive/negative), DA attester latency targets (≤300 ms), and performance isolation under load.
- Security tests for DS QC verification (ML‑DSA‑87), conflict detection/abort semantics, and confidential shard leakage prevention.

### NX-18 Telemetry & Runbook Assets

- **Grafana board:** `dashboards/grafana/nexus_lanes.json` now exports the “Nexus Lane Finality & Oracles” dashboard requested by NX‑18. Panels cover `histogram_quantile()` on `iroha_slot_duration_ms`, `iroha_da_quorum_ratio`, oracle price/staleness/TWAP/haircut gauges, and the live `iroha_settlement_buffer_xor` buffer panel so operators can prove the 1 s slot, DA, and treasury SLOs without bespoke queries.
- **CI gate:** `scripts/telemetry/check_slot_duration.py` parses Prometheus snapshots, prints the p50/p95/p99 slot latency, and enforces the NX‑18 thresholds (p95 ≤ 1000 ms, p99 ≤ 1100 ms). The companion harness `scripts/telemetry/nx18_acceptance.py` gates DA quorum, oracle staleness/TWAP/haircuts, settlement buffers, and slot quantiles in one pass (`--json-out` persists evidence), and both run inside `ci/check_nexus_lane_smoke.sh` for RCs.
- **Evidence bundler:** `scripts/telemetry/bundle_slot_artifacts.py` copies the metrics snapshot + JSON summary into `artifacts/nx18/` and emits `slot_bundle_manifest.json` with SHA-256 digests, ensuring every RC uploads the exact artefacts that triggered the NX‑18 gate.
- **Release automation:** `scripts/run_release_pipeline.py` invokes `ci/check_nexus_lane_smoke.sh` (skip with `--skip-nexus-lane-smoke`) and copies `artifacts/nx18/` into the release output so NX‑18 evidence rides alongside the bundle/image artefacts without a manual step.
- **Runbook:** `specs/runbooks/nexus_lane_finality.md` documents the on-call workflow (thresholds, incident steps, evidence capture, chaos drills) that accompanies the dashboard, fulfilling the “publish operator dashboards/runbooks” bullet from NX‑18.
- **Telemetry helpers:** reuse the existing `scripts/telemetry/compare_dashboards.py` to diff exported dashboards (preventing staging/prod drift) and `scripts/telemetry/check_nexus_audit_outcome.py` during routed-trace or chaos rehearsals so every NX‑18 drill archives the matching `nexus.audit.outcome` payload.

Open Questions (Clarification Needed)
1) Transaction signatures: Decision — end users are free to pick any signing algorithm that their target DS advertises (Ed25519, secp256k1, ML‑DSA, etc.). Hosts must enforce multisig/curve capability flags in manifests, provide deterministic fallbacks, and document latency implications when mixing algorithms. Outstanding: finalise capability negotiation flow across Torii/SDKs and update admission tests.
2) Gas economics: Each DS may denominate gas in a local token, while global settlement fees are paid in SORA XOR. Outstanding: define the standard conversion path (public-lane DEX vs. other liquidity sources), ledger accounting hooks, and safeguards for DS that subsidise or zero-price transactions.
3) DA attesters: Target number per region and threshold (e.g., 64 sampled, 43‑of‑64 ML‑DSA‑87 signatures) to meet ≤300 ms while maintaining durability. Any regions we must include from day one?
4) Default DA parameters: We proposed public DS `k=32, m=16` and private DS `k=16, m=8`. Do you want a higher redundancy profile (e.g., `k=30, m=20`) for certain DS classes?
5) DS granularity: Domains and assets can both be DS. Should we support hierarchical DS (domain DS as parent of asset DS) with optional inheritance of policies, or keep them flat for v1?
6) Heavy ISIs: For complex ISIs that cannot produce sub‑second proofs, should we (a) reject them, (b) split into smaller atomic steps across blocks, or (c) allow delayed inclusion with explicit flags?
7) Cross‑DS conflicts: Is client‑declared read/write set sufficient, or should the host infer and expand it automatically for safety (at cost of more conflicts)?

Appendix: Compliance with Repository Policies
- Norito is used for all wire formats and JSON serialization via Norito helpers.
- ABI v1 only; no runtime toggles for ABI policies. Syscall and pointer‑type surfaces are fixed and pinned by golden tests.
- Determinism preserved across hardware; acceleration is optional and gated.
- No serde in production paths; no environment-based configuration in production.
