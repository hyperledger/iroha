# Iroha v2.0

Hyperledger Iroha v2 is a deterministic, Byzantine fault tolerant distributed ledger that emphasises a
modular architecture, strong defaults, and approachable APIs. The platform ships as a set of Rust crates
that can be embedded into bespoke deployments or used together to operate a production blockchain network.

---

## 1. Overview

Iroha 2 continues the design philosophy introduced with Iroha 1: provide a curated collection of
capabilities out of the box so operators can stand up a network without writing large amounts of custom
code. The v2 release consolidates the execution environment, consensus pipeline, and data model into a
single cohesive workspace.

The v2 line is designed for organisations that want to operate their own permissioned or consortium
blockchains. Each deployment runs its own consensus network, maintains independent governance, and can tailor
configuration, genesis data, and upgrade cadence without depending on third parties. The shared workspace
allows multiple independent networks to build against the exact same codebase while choosing the features and
policies that match their use cases.

Both Iroha 2 and SORA Nexus (Iroha 3) run the same Iroha Virtual Machine (IVM). Developers can author Kotodama
contracts once and deploy them across self-hosted networks or the global Nexus ledger without recompiling or
forking the execution environment.
### 1.1 Relationship to the Hyperledger ecosystem

Iroha components are designed to interoperate with other Hyperledger projects. Consensus, data-model, and
serialization crates can be reused in composite stacks or alongside Fabric, Sawtooth, and Besu deployments.
Common tooling—such as Norito codecs and governance manifests—helps keep interfaces consistent across the
ecosystem while allowing Iroha to provide an opinionated default implementation.

### 1.2 Client libraries and SDKs

To ensure first-class mobile and web experiences, the project publishes maintained SDKs:

- `IrohaSwift` for iOS and macOS clients, integrating Metal/NEON acceleration behind deterministic fallbacks.
- `iroha_js` for JavaScript and TypeScript applications, including Kaigi builders and Norito helpers.
- `iroha_python` for Python integrations, with HTTP, WebSocket, and telemetry support.
- `iroha_cli` for terminal-driven administration and scripting.

languages and platforms.

### 1.3 Design principles

- **Determinism first:** Every node executes the same code paths and produces the same results given the same
  inputs. SIMD/CUDA/NEON paths are feature-gated and fall back to deterministic scalar implementations.
- **Composable modules:** Networking, consensus, execution, telemetry, and storage each live in dedicated
  crates so embedders can adopt subsets without carrying the entire stack.
- **Explicit configuration:** Behavioural knobs are surfaced through `iroha_config`; environment toggles are
  limited to developer conveniences.
- **Secure defaults:** Canonical codecs, strict pointer ABI enforcement, and versioned manifests make
  cross-network upgrades predictable.

## 2. Platform architecture

### 2.1 Node composition

An Iroha node runs several cooperating services:

- **Torii (`iroha_torii`)** exposes HTTP/WebSocket APIs for transactions, queries, streaming events, and
  telemetry (`/v1/...` endpoints).
- **Core (`iroha_core`)** coordinates validation, consensus, execution, governance, and state management.
- **Sumeragi (`iroha_core::sumeragi`)** implements the NPoS-ready consensus pipeline with view changes,
  reliable broadcast data availability, and commit certificates. See the
  [Sumeragi consensus guide](./sumeragi.md) for details.
- **Kura (`iroha_core::kura`)** persists canonical blocks, recovery sidecars, and witness metadata on disk.
- **World State View (`iroha_core::state`)** stores the authoritative in-memory snapshot used for validation
  and queries.
- **Iroha Virtual Machine (`ivm`)** executes Kotodama bytecode (`.to`) and enforces the pointer ABI policy.
- **Norito (`crates/norito`)** provides deterministic binary and JSON serialization for every on-wire type.
- **Telemetry (`iroha_telemetry`)** exports Prometheus metrics, structured logging, and streaming events.
- **P2P (`iroha_p2p`)** manages gossip, topology, and secure connections between peers.

### 2.2 Networking and topology

Iroha peers maintain an ordered topology derived from committed state. Each consensus round selects a leader,
validating set, proxy tail, and Set B validators. Transactions are gossiped using Norito-encoded messages
before the leader bundles them into a proposal. Reliable broadcast guarantees that blocks and supporting
evidence reach all honest peers, ensuring data availability even under network churn. View changes rotate
leadership when deadlines are missed, and commit certificates ensure that every committed block carries the
canonical signature set used by all peers.

### 2.3 Cryptography

The `iroha_crypto` crate powers key management, hashing, and signature verification:

- Ed25519 is the default validator key scheme.
- Optional backends include Secp256k1, TC26 GOST, BLS (for aggregate attestations), and ML-DSA helpers.
- Streaming channels pair Ed25519 identities with Kyber-based HPKE to secure Norito streaming sessions.
- All hashing routines use deterministic implementations (SHA-2, SHA-3, Blake2, Poseidon2) with workspace
  audits documented in `specs/crypto/dependency_audits.md`.

### 2.4 Streaming and application bridges

- **Norito streaming (`iroha_core::streaming`, `norito::streaming`)** provides deterministic, encrypted media
  and data channels with session snapshots, HPKE key rotation, and telemetry hooks. Kaigi conferencing and
  confidential evidence transfers use this lane.
- **Connect bridge (`connect_norito_bridge`)** exposes a C ABI surface that powers platform SDKs
  (Swift, Kotlin/Android) while reusing the Rust clients under the hood.
- **ISO 20022 bridge (`iroha_torii::iso20022_bridge`)** converts regulated payment messages into Norito
  transactions, enabling interoperability with financial workflows without bypassing consensus or validation.
- All bridges preserve deterministic Norito payloads so downstream systems can verify state transitions.

## 3. Data model

The `iroha_data_model` crate defines all ledger objects, instructions, queries, and events. Highlights:

- **Domains, accounts, and assets** use canonical I105 account ids and canonical Base58 asset ids. Account aliases are separate on-chain
  bindings in `name@dataspace` / `name@domain.dataspace` form that resolve to I105 account ids, and asset aliases are separate on-chain bindings in `name#dataspace` / `name#domain.dataspace` form that resolve to canonical Base58 asset ids. Metadata is deterministic (`Metadata` map). Asset quantities support fixed-point
  operations; NFTs carry arbitrary structured metadata.

- **Roles and permissions** use Norito-enumerated tokens that map directly to executor checks.
- **Triggers** (time-based, block-based, or predicate-driven) emit deterministic transactions via the on-chain
  executor.
- **Events** stream via Torii and mirror committed state transitions, including confidential flows and
  governance actions.
- **Transactions, blocks, and manifests** are Norito-encoded (`SignedTransaction`, `SignedBlockWire`) with
  explicit version headers, ensuring forward-extendable decoding.
- **Customisation** happens through the executor data model: operators may register custom instructions,
  permissions, and parameters while preserving determinism.
- **Repositories (`RepoInstruction`)** allow bundling deterministic upgrade plans (executors, manifests, and
  assets) so multi-step rollouts can be managed on-chain with governance approval.
- **Consensus artifacts**—such as commit certificates and witness lists—reside in the data model and
  round-trip through golden tests to guarantee compatibility between `iroha_core`, Torii, and SDKs.
- **Confidential registries and events** capture asset policies, verifier keys,
  commitments, nullifiers, and authenticated transfer events. V1 exposes no
  generic shield/transfer/unshield event family; KAGEMUSHA offline payments
  never touch consensus state.

## 4. Transaction lifecycle

1. **Admission:** Torii decodes the Norito payload, checks signatures, TTL, and size limits, then enqueues the
   transaction locally.
2. **Gossip:** The transaction propagates across the topology; peers deduplicate by hash and repeat admission
   checks.
3. **Selection:** The current leader pulls transactions from the pending set and performs stateless validation.
4. **Stateful simulation:** Candidate transactions execute inside a transient `StateBlock`, invoking IVM or
   built-in instructions. Conflicts or rule violations are dropped deterministically.
5. **Trigger materialisation:** Scheduled triggers due in the round are converted into internal transactions
   and validated using the same pipeline.
6. **Proposal sealing:** When block limits are reached or timeouts expire, the leader emits a Norito-encoded
   `BlockCreated` message.
7. **Validation:** Peers in the validating set re-run stateless/stateful checks. Successful peers sign
   `BlockSigned` messages and forward them to the deterministic collector set.
8. **Commit:** A collector assembles a commit certificate once it collects the canonical signature set,
   broadcasts `BlockCommitted`, and finalises the block locally.
9. **Application:** All peers record the block in Kura, apply state updates, emit telemetry/events, purge
   committed transactions from the mempool, and rotate topology roles.

Recovery paths use deterministic broadcast to retransmit missing blocks, and view changes rotate leadership
when deadlines lapse. Sidecars and telemetry provide diagnostic insights without mutating consensus results.

## 5. Smart contracts and execution

Smart contracts run on the Iroha Virtual Machine (IVM):

- **Kotodama** compiles high-level `.ko` sources into deterministic `.to` bytecode.
- **Pointer ABI enforcement** ensures contracts interact with host memory through validated pointer types.
  Syscall surfaces are described in `ivm/docs/syscalls.md`; the ABI list is hashed and versioned.
- **Syscalls and hosts** cover ledger state access, trigger scheduling, confidential primitives, Kaigi media
  flows, and deterministic randomness.
- **Built-in executor** continues to support Iroha Special Instructions (ISI) for asset, account, permission,
  and governance operations. Custom executors can extend the instruction set while honouring Norito schemas.
- **Confidential features**—including shielded transfers and verifier registries—are exposed via executor
  instructions and validated by hosts with Poseidon commitments.

## 6. Storage and persistence

- **Kura block store** writes each finalised block as a `SignedBlockWire` payload with a Norito header, keeping
  canonical headers, transactions, commit certificates, and witness data together.
- **World State View** keeps the authoritative state in memory for fast queries. Deterministic snapshots and
  pipeline sidecars (`pipeline/sidecars.norito` + `pipeline/sidecars.index`) support recovery and audits.
- **State tiering** allows hot/cold partitioning for large deployments while preserving deterministic
  validation.
- **Sync and replay** load committed blocks back into state using the same validation rules. Deterministic
  broadcast ensures peers can recover missing data from neighbours without relying on trusted storage.

## 7. Governance and economics

- On-chain parameters (`SetParameter`) control consensus timers, mempool limits, telemetry knobs, and feature
  flags. Hijiri fee parameters use the same instruction under the dedicated `CanSetHijiriParameters`
  permission. Genesis manifests generated by `kagami` install the bootstrap Hijiri parameter operator;
  networks explicitly enact their initial Hijiri parameter state.
- **Kaigi** instructions manage collaborative sessions (create/join/leave/end) and feed Norito streaming
  telemetry for conferencing use cases.
- **Hijiri** deterministically adjusts validation-fee admission. One bounded global on-chain parameter owns
  fee bands and default risk, while bounded per-account parameters attach governed risk to universal account
  identities. Admission resolves only the execution accounts involved in the transaction, aggregates each
  context's base fee, and applies its Q16 multiplier once with upward rounding. The signed transaction and
  nested multisig marker bind the exact policy-and-account-risk snapshot used for admission. An authenticated
  native-Norito Torii route evaluates a bounded same-snapshot quote for the committed tip's checked successor;
  it is explicitly evaluated-only rather than an independent state witness.
- **NPoS mode** (when enabled) uses VRF-backed election windows and stake-weighted committees while preserving
  deterministic configuration defaults.
- **Confidential registries** govern zero-knowledge verifier keys, proof lifecycles, and commitments for
  shielded flows.

## 8. Client experience and tooling

- **Torii API** offers REST and WebSocket interfaces for transactions, queries, event streams, telemetry, and
  governance endpoints. JSON projections are derived from Norito schemas.
- **CLI tooling** (`iroha_cli`, `iroha_monitor`) covers administration, live peer dashboards, and pipeline
  inspection.
- **Genesis tooling** (`kagami`) generates Norito-encoded manifests, validator key material, and configuration
  templates.
- **SDKs** (Swift, JS/TS, Python) provide idiomatic access to instructions, queries, triggers, and telemetry.
- **Scripts and CI hooks** inside `scripts/` automate dashboard validation, codec regeneration, and smoke
  tests.

## 9. Performance, resilience, and roadmap

- The current pipeline targets **20,000 tps** with **2–3 second** block times under favourable network
  conditions, backed by batch signature verification and deterministic scheduling.
- **Telemetry** exposes Prometheus metrics for consensus timers, mempool occupancy, block propagation health,
  and Kaigi usage.
- **Resilience features** include deterministic data availability, recovery sidecars, topology rotation, and
  configurable view/change thresholds.
- Future roadmap milestones (see `roadmap.md`) continue work on Nexus data spaces, enhanced confidential
  tooling, and broader hardware acceleration while preserving deterministic outputs.

## 10. Operations and deployment

- **Artifacts:** Dockerfiles, Nix flake, and `cargo` workflows support reproducible builds. `kagami` emits
  genesis manifests, validator keys, and example configs for both permissioned and NPoS deployments.
- **Self-hosted networks:** Operators manage their own peer sets, admission rules, and upgrade cadence. The
  workspace supports many independent Iroha 2 networks co-existing without coordination, sharing only the
  upstream code.
- **Configuration lifecycle:** `iroha_config` resolves user → actual → defaults layers, ensuring every knob is
  explicit and version-controlled. Runtime changes flow through `SetParameter` instructions.
- **Observability:** `iroha_telemetry` exports Prometheus metrics, structured logs, and dashboard data checked
  by CI scripts (`ci/check_swift_dashboards.sh`, `scripts/render_swift_dashboards.sh`,
  `scripts/check_swift_dashboard_data.py`). Streaming and consensus events are available over WebSocket;
  authenticated status plus transaction, ingress, and P2P queue metrics provide consensus diagnostics.
  Hijiri parameters use the existing parameter query and event surfaces; there is no
  dedicated Hijiri event stream.
- **Testing:** `cargo test --workspace`, integration tests (`integration_tests/`), language SDK suites, and
  Norito golden fixtures protect determinism. Pointer ABI, syscall lists, and governance manifests have
  dedicated golden tests.
- **Recovery:** Kura sidecars, deterministic replay, and broadcast sync allow nodes to recover state from disk
  or peers. Hijiri policy and account-risk records recover as ordinary on-chain parameters; Hijiri-specific
  checkpoints are not implemented.

# Glossary

For terminology referenced in this document, consult the project-wide glossary at
<https://docs.iroha.tech/reference/glossary.html>.
