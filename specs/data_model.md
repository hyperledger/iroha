# Iroha 3 Data Model – Deep Dive

This document explains the structures, identifiers, traits, and protocols that
form the first-release Iroha 3 data model, as implemented in the
`iroha_data_model` crate and used across the workspace.

## Scope and Foundations

- Purpose: Provide canonical types for domain objects (domains, accounts, assets, NFTs, roles, permissions, peers), state-changing instructions (ISI), queries, triggers, transactions, blocks, and parameters.
- Serialization: Wire records use Norito codecs and schema contracts, with manual implementations for validated or bounded representations. Canonical protocol JSON is mandatory, including without default features.
- IVM note: Certain deserialization-time validations are disabled when targeting the Iroha Virtual Machine (IVM), since the host performs validation before invoking contracts (see crate docs in `src/lib.rs`).

## Core Traits and Helpers

- `Identifiable`: Entities have a stable `Id` and `fn id(&self) -> &Self::Id`. Should be derived with `IdEqOrdHash` for map/set friendliness.
- `Registrable`/`Registered`: Many entities (e.g., `Domain`, `AssetDefinition`, `Role`) use a builder pattern. `Registered` ties the runtime type to a lightweight builder type (`With`) suitable for registration transactions.
- `HasMetadata`: Unified access to a key/value `Metadata` map.
- `IntoKeyValue`: Storage split helper to store `Key` (ID) and `Value` (data) separately to reduce duplication.
- `Owned<T>`/`Ref<'world, K, V>`: Lightweight wrappers used in storages and query filters to avoid unnecessary copies.

## Names and Identifiers

- `Name`: Valid textual identifier. Disallows whitespace and reserved characters `@`, `#`, `$` (used in composite IDs). Constructible via `FromStr` with validation. Names must arrive in their exact Unicode NFC spelling; alternate canonically equivalent spellings are rejected rather than rewritten. The special name `genesis` is reserved (checked case-insensitively).
- `IdBox`: A sum-type envelope for any supported ID (`DomainId`, `AccountId`, `AssetDefinitionId`, `AssetId`, `NftId`, `PeerId`, `TriggerId`, `RoleId`, `Permission`, `CustomParameterId`). Useful for generic flows and Norito encoding as a single type.
- `iroha_model_base::topology::{DataSpaceId, LaneId, ShardId}`: Numeric dataspace, lane and shard identities. Validation, codecs and applicable storage keys belong to the base owner; catalogs, lifecycle rules and ledger composition remain in the aggregate.
- `iroha_model_base::chain::ChainId`: Exact, case-sensitive ASCII deployment label, bounded to 128 bytes and validated by constructors and codecs. Import it from its base owner. Genesis-derived `iroha_data_model::NetworkId` remains the exact lineage identity at ledger composition.

String forms of IDs (round-trippable with `Display`/`FromStr`):
- `iroha_model_base::domain::DomainId`: exactly `name.dataspace` (e.g., `wonderland.paynet`), with one validated DNS label per component.
- `AccountId`: canonical domainless account identifier encoded via `AccountAddress` as I105 only. Strict parser inputs must be canonical I105; domain suffixes (`@domain`), account-alias literals, canonical hex parser input, legacy `norito:` payloads, and `uaid:`/`opaque:` account parser forms are rejected. On-chain account aliases use `name@domain.dataspace` or `name@dataspace` and resolve to canonical `AccountId` values.
- `AssetDefinitionId`: canonical unprefixed Base58 address over the canonical asset-definition bytes. This is the public asset ID. On-chain asset aliases use `name#domain.dataspace` or `name#dataspace` and resolve only to this canonical Base58 asset ID.
- `AssetId`: public asset identifier in canonical bare Base58 form. Asset aliases like `name#dataspace` or `name#domain.dataspace` resolve to `AssetId`. Internal ledger holdings may additionally expose split `asset + account + optional dataspace` fields where needed, but that composite shape is not the public `AssetId`.
- `NftId`: `nft$domain.dataspace` (e.g., `rose$garden.paynet`).
- `iroha_model_base::peer::PeerId`: canonical public-key identity; equality is by public key. Its wrapper, validation and codecs live in the base crate; the ledger `Peer` entity stays in the aggregate.

## Entities

### Domain
- `iroha_model_base::domain::DomainId` owns private `name: Name` and `dataspace: Name` components. Construct it through `try_new` or `parse_fully_qualified`; read them through getters. Domain registration and `IdBox` conversion stay in the aggregate.
- `Domain { id, logo: Option<SorafsUri>, metadata: Metadata, owned_by: AccountId }`.
- Builder: `NewDomain` with `with_logo`, `with_metadata`, then `Registrable::build(authority)` sets `owned_by`.

### Account
- `AccountId` is the canonical domainless account identity keyed by the controller and encoded as canonical I105.
- `Account { id, metadata, label?, uaid?, opaque_ids[] }` — `label` is an optional primary `AccountAlias` used by rekey records, `uaid` carries the optional Nexus-wide [Universal Account ID](./universal_accounts_guide.md), and `opaque_ids` tracks hidden identifiers bound to that UAID. A canonical UAID is always a Blake2b-256 digest with the final-byte LSB set to `1`; account onboarding must provide it explicitly. Stored account state no longer carries any linked-domain field.
- Builders:
  - `NewAccount` via `Account::new(id)` registers the canonical domainless account subject.
- Alias model:
  - Canonical account identity never includes a domain or dataspace segment.
  - `AccountAlias` values are separate SNS bindings layered on top of `AccountId`.
  - Domain-qualified aliases such as `merchant@banka.paynet` carry both a domain and dataspace in the alias binding.
  - Dataspace-root aliases such as `merchant@paynet` carry only the dataspace and therefore pair naturally with `Account::new(...)`.
  - Tests and fixtures should seed the universal `AccountId` first, then add alias leases, alias permissions, and any domain-owned state separately instead of encoding domain assumptions into the account identity itself.
  - Public singular account lookup now focuses on aliases (`FindAliasesByAccountId`); account identity itself stays domainless.

### Asset Definitions and Assets
- `AssetDefinitionId { aid_bytes: [u8; 16] }` exposed textually as an unprefixed Base58 address with versioning and checksum.
- `AssetDefinition { id, name, description?, alias?, spec: NumericSpec, mintable: Mintable, logo: Option<SorafsUri>, metadata, owned_by: AccountId, total_quantity: Quantity }`.
  - `name` is required human-facing display text and must not contain `#`/`@`.
  - `alias` is optional and must be one of:
    - `<name>#<domain>.<dataspace>`
    - `<name>#<dataspace>`
    with the left segment exactly matching `AssetDefinition.name`.
  - Alias lease state is stored authoritatively in the persisted alias-binding record; the inline `alias` field is derived when definitions are read back through core/Torii APIs.
  - Torii asset-definition responses may include `alias_binding { alias, status, lease_expiry_ms, grace_until_ms, bound_at_ms }`, where `status` is one of `permanent`, `leased_active`, `leased_grace`, or `expired_pending_cleanup`.
  - Alias resolution uses the latest committed block timestamp rather than node wall clock. Once `grace_until_ms` has passed, alias selectors stop resolving immediately even if sweep cleanup has not removed the stale binding yet; direct definition reads may still report the lingering binding as `expired_pending_cleanup`.
  - `Mintable`: `Infinitely` | `Once` | `Limited(u32)` | `Not`.
  - Builders: `AssetDefinition::new(id, spec)` or convenience `numeric(id)`; `name` is required and must be set via `.with_name(...)`.
- `AssetId { account: AccountId, definition: AssetDefinitionId, scope: AssetBalanceScope }`.
- `Asset { id, value: Quantity }` with storage-friendly `AssetEntry`/`AssetValue`.
- `AssetBalanceScope`: `Global` for unrestricted balances and `Dataspace(DataSpaceId)` for dataspace-restricted balances.
- `AssetTotalQuantityMap = BTreeMap<AssetDefinitionId, Quantity>` exposed for summary APIs.

### NFTs
- `NftId { domain: DomainId, name: Name }`.
- `Nft { id, content: Metadata, owned_by: AccountId }` (content is arbitrary key/value metadata).
- Builder: `NewNft` via `Nft::new(id, content)`.

### Roles and Permissions
- `RoleId { name: Name }`.
- `Role { id, permissions: BTreeSet<Permission> }` with builder `NewRole { inner: Role, grant_to: AccountId }`.
- `Permission { name: Ident, payload: Json }` – the `name` and payload schema must align with the active `ExecutorDataModel` (see below).

### Peers
- `iroha_model_base::peer::PeerId` wraps `PublicKey`; construct with `PeerId::new` and read with `public_key()`.
- `Peer { address: SocketAddr, id: PeerId }` and parsable `public_key@address` string form.

### Cryptographic primitives (feature `sm`)
- `Sm2PublicKey` and `Sm2Signature`: SEC1-compliant points and fixed-width `r∥s` signatures for SM2. Constructors validate curve membership and distinguishing IDs; Norito encoding mirrors the canonical representation used by `iroha_crypto`.
- `Sm3Hash`: `[u8; 32]` newtype representing the GM/T 0004 digest, used in manifests, telemetry, and syscall responses.
- `Sm4Key`: 128-bit symmetric key wrapper shared between host syscalls and data-model fixtures.
These types sit alongside the existing Ed25519/BLS/ML-DSA primitives and become part of the public schema once the workspace is built with `--features sm`.

### Triggers and Events
- `TriggerId { name: Name }` and `Trigger { id, action: action::Action }`.
- `action::Action { executable: Executable, repeats: Repeats, authority: AccountId, filter: EventFilterBox, retry_policy, metadata }`.
  - Construction: `Action::new(...)` is the single fallible constructor and returns `ActionValidationError` when the filter is forbidden, a filter-bound authority conflicts with the action authority, or retry-policy constraints are violated. `with_retry_policy(...)` is fallible for the same reason; there is no generally available infallible constructor.
  - `Repeats`: `Indefinitely` or `Exactly(u32)`; ordering and depletion utilities included.
  - `retry_policy`: optional scheduled-time-trigger retry settings; non-scheduled triggers reject retry policies.
  - Safety: `TriggerCompleted` cannot be used as an action’s filter (validated during (de)serialization).
  - Enabled state: triggers are enabled by default. The reserved `__enabled` metadata flag disables execution when set to `false` or `0`; malformed values fail closed and are treated as disabled. Active-trigger queries return only enabled triggers with remaining repeats.
  - Pipeline triggers: state-mutating pipeline triggers are deterministic-only. They may target transaction `Approved`/`Rejected` events or block `Approved` events derived from committed block validation. Local queue, warning, witness, merge-ledger, created, committed, and rejected-block notifications remain subscription events only.
  - Data-trigger scope: an ordinary data trigger binds one exact subject owned by its action authority. `Any`, unbound or foreign subjects, and system/governance event families require the registering account to hold the exact direct `CanRegisterGlobalDataTrigger { authority }` capability. The same rule applies in genesis. Persisted scope provenance is either `Owned` or capability-backed `GlobalPermission`; the retired uncredentialed genesis-global mode is an incompatible first-release snapshot and fails fast.
- `EventBox`: sum type for pipeline, pipeline-batch, data, time, execute-trigger, and trigger-completed events; `EventFilterBox` mirrors that for subscriptions and trigger filters.
- `TriggerCompletedEvent`: reports the trigger id, `trigger_execution_hash`, `step_index`, and success/failure outcome for each trigger invocation. `trigger_execution_hash` identifies the actual trigger invocation rather than an external transaction, and `step_index` is the zero-based position inside the trigger sequence including chained data triggers.

### SoraFS Moderation Challenges

- Each activated moderation case retains the complete consensus policy that admitted it. Challenge funding and settlement derive the voting asset, exact 150-unit bond, escrow and slash accounts, 2,500-bps rejection slash, and 24-hour resolution grace from that immutable case snapshot; a later live governance-configuration or active-policy revision cannot reinterpret an open case.
- The challenge submission deadline and resolution deadline are distinct. Submission is inclusive through `challenge_submission_deadline_unix_ms`; the resolution deadline is exactly 24 hours later. Pending challenges block reveals only through the resolution deadline. Accepted challenges terminate the case, rejected challenges permit reveals to continue, and unresolved challenges expire permissionlessly and fail open.
- Every unsettled challenge is an aggregate liability of its exact `(asset definition, escrow account)` balance. Ordinary transfers, burns, batches, SCCP releases, and other protocol-custody paths must preserve the combined reserve; only the typed refund/slash settlement capability may consume a retained bond. Settlement preflights the complete reserve and remains atomic under transaction rollback.
- Account, asset-definition, and domain removal fail closed while active policy, an open case, or a retained challenge can still name the affected custody subject or asset. Historical challenge records retain their asset definition even after settlement and policy rotation because canonical validation must still recompute the exact precision-aware refund/slash split.

## Parameters and Configuration

- System parameter families (all `Default`ed, carry getters, and convert to individual enums):
- `SumeragiParameters { block_cadence_ms, max_clock_drift_ms, key_activation_lead_blocks, key_overlap_grace_blocks, key_expiry_grace_blocks, key_allowed_algorithms, payload_retry_interval_ms, exec_budget_ms, apply_budget_ms, max_block_bytes, epoch_length_blocks, demotion_window }`. The cadence (default 1000 ms, the core's `block_time`) and key policy are signed chain context. The Sumeragi chain parameters `payload_retry_interval_ms` (5000), `exec_budget_ms` (4000), `apply_budget_ms` (1000), `max_block_bytes` (4 MiB) and `epoch_length_blocks` (3600) map 1:1 onto the core's `ChainParams` and have `SumeragiParameter` variants; `demotion_window` (128) is a genesis constant whose variant is accepted only in the genesis block. An empty build waits for queued work and retries after `payload_retry_interval_ms`; it never creates an empty block.
  - `BlockParameters { max_transactions: NonZeroU64 }`.
  - `TransactionParameters { max_signatures, max_instructions, ivm_bytecode_size, max_tx_bytes, max_decompressed_bytes, max_time_to_live_ms }`. `max_time_to_live_ms` defaults to one day and bounds every signature-bound transaction lifetime.
  - `SmartContractParameters { fuel, memory, execution_depth, max_output_items, max_output_bytes }`. The output limits bound the aggregate queued instructions, durable writes, FastPQ entries, completed AXT states, and access artifacts retained by one IVM execution.
- `Parameters` groups all families and a `custom: BTreeMap<CustomParameterId, CustomParameter>`.
- Single-parameter enums: `SumeragiParameter`, `BlockParameter`, `TransactionParameter`, `SmartContractParameter` for diff-like updates and iteration.
- Custom parameters: executor-defined, carried as `Json`, identified by `CustomParameterId` (a `Name`).

## ISI (Iroha Special Instructions)

- Core trait: `Instruction` with `dyn_encode`, `as_any`, and a stable per-type identifier `id()` (defaults to the concrete type name). All instructions are `Send + Sync + 'static`.
- `InstructionBox`: owned `Box<dyn Instruction>` wrapper with clone/eq/ord implemented via type ID + encoded bytes.
- Built-in instruction families are organized under:
  - `mint_burn`, `transfer`, `register`, and a `transparent` bundle of helpers.
  - Type enums for meta flows: `InstructionType`, boxed sums like `SetKeyValueBox` (domain/account/asset_def/nft/trigger).
- Errors: rich error model under `isi::error` (evaluation type errors, find errors, mintability, math, invalid parameters, repetition, invariants).
- Instruction registry: `instruction_registry_with_ids!{ ... }` builds a direction-separated registry. Concrete Rust type names select entries only inside the encoder; every producer must obtain the registered stable wire ID plus canonical framed bytes through `framed_instruction_payload`. Decoding accepts only registered stable wire IDs and never treats a Rust type name as an alias. `InstructionBox` clone and Norito codecs use the same registry, whose complete built-in first-release inventory is installed lazily when no explicit test or embedding registry was set.

## Transactions

- `Executable`: `Instructions(ConstVec<InstructionBox>)`, `ContractCall(ContractInvocation)`, `Ivm(IvmBytecode)`, `IvmProved(IvmProved)`, or a flat ordered `Batch(ConstVec<ExecutableBatchItem>)`. In the sole first-release layout, `Executable::Batch` uses tag `4`, while its item tags are `0` for `Instruction(InstructionBox)` and `1` for `ContractCall(ContractInvocation)`. Raw IVM bytecode and nested batches are excluded from batch items. `IvmBytecode` serializes as base64 (transparent newtype over `Vec<u8>`).
- `TransactionBuilder`: constructs the nine-field first-release transaction
  payload with `domain`, `authority`, `creation_time_ms`, `instructions`,
  `time_to_live_ms`, `nonce`, `fee_payment`, `metadata`, and `attachments`.
  - Helpers: `with_instructions`, `with_executable_batch`, `with_bytecode`,
    `with_executable`, `with_fee_payment_intent`,
    `with_metadata`, `with_attachments`, `set_nonce`, `set_ttl`,
    `set_creation_time`, `sign`.
  - Retired admission fields and extra binary slots are invalid. Native consensus
    owns routing and admission of the complete signed transaction.
  - Admission rejects an empty mixed batch. Its items execute in input order against one transaction view and commit or roll back as one atomic unit. A transaction batch containing a contract call requires one signature-bound gas limit shared by all of its explicit ISIs and calls; fees settle once for the transaction.
- Trigger actions may also carry a mixed batch. One trigger invocation preserves the same ordered atomic semantics and shares one deterministic trigger gas budget across all items.
- `SignedTransaction` (versioned with `iroha_version`): carries `TransactionSignature` and payload; provides hashing and signature verification.
- Entrypoints and results:
  - `TransactionEntrypoint`: `External(SignedTransaction)` |
    `SealedCommitment(SignedSealedTransactionCommitment)` | `SealedReveal(SealedTransactionReveal)` |
    `AnonymousBallot(CanonicalAnonymousBallotEnvelopeV1)`. Their explicit tags are
    0, 1, 2 and 4; retired tag 3 is invalid. The anonymous carrier retains the
    complete canonical ballot envelope and has no account authority, creation
    timestamp or metadata. Use `authority_opt()` when inspecting arbitrary inputs.
  - `TransactionResult` carries `Result<DataTriggerSequence, TransactionRejectionReason>`
    plus batch-transfer receipts, a required nullable Nexus fee receipt and contract
    emissions. An anonymous Network output is an empty success or
    `AnonymousBallot(OutsideCastingWindow | DuplicateNullifier)` (rejection tag 5),
    with no triggers, completions, receipts, fees or emissions. Ballot rejections
    are invalid on ordinary or internal outputs. Repeated identical anonymous
    envelopes retain their envelope hash but each output owns a distinct ordered
    input index, permitting success followed by a duplicate rejection. Ordinary
    and internal execution-call hashes remain unique. Structural validity does not
    authenticate the proof or execution. Core admission remains locally unavailable
    pending the authoritative ballot State/context adapter; development proof tests
    are available through `scripts/test_parliament_ballot_local.sh`.
  - `ExecutionStep(ConstVec<InstructionBox>)`: a single ordered batch of instructions in a transaction.

The only supported SDK/node compatibility handshake is
`DATA_MODEL_VERSION = 4`. SDKs must reject any other value before submission;
the first release does not decode superseded data-model layouts.

### Validation-fee Parliament governance

- `ValidationFeePolicyProposal` and `ValidationFeePayoutLifecycleProposal`
  bind the canonical transaction authority as `proposal_operator`; Core derives
  it from execution and different operators produce different fingerprints.
  Policy proposals additionally bind the exact previously enacted payout
  lifecycle when they carry a treasury payout binding.
- `ValidationFeeParliamentAuthorizationV1` retains the proposal operator,
  proposal fingerprint, canonical certificate id, complete
  `GovernanceCertificateV1`, and enacted height. Registry validation derives
  the certificate id, verifies the complete certificate, requires its proposal
  content id to equal the native proposal fingerprint, and requires its due
  height to equal the enacted height. Enabled policies additionally require
  `effective_from_height = enacted_at_height + 120,960` exactly.
- There is no validation-fee-specific electorate, snapshot, referendum window,
  or finalization-evidence path. The complete Parliament attempt and its
  certificate are the single authorization source.
- The V1 policy registry, its payout-lifecycle references, and lifecycle-scoped
  credit leaves are append-only. Draining a lifecycle retains its canonical zero
  balance and immutable asset binding. Physical retirement would require a new
  consensus transition that derives both lifecycle inactivity and an exact zero
  reference count from the same frozen state; no caller-supplied approximation is
  accepted.
- Account, asset-definition, and containing-domain unregistration scans the
  typed validation-fee index for retained `Enacted` proposal kinds, not only the
  active-policy projection. Every policy treasury/DS reference and every payout
  treasury, pool-vault, recipient, DS, and XOR reference therefore remains pinned
  during pre-activation and after lifecycle drain. Containing-domain teardown
  matches its complete definition set in one proposal-index pass.

## Blocks

- `SignedBlock` (versioned) encapsulates:
  - `signatures: BTreeSet<BlockSignature>` (from validators),
  - `payload: BlockPayload` with the header, the sole canonical
    `external_entrypoints: Vec<TransactionEntrypoint>` sequence, and the required
    V1 DA, NPoS, and execution-context option fields,
  - `result: BlockResult` (secondary execution state) containing the sole typed `outputs`, `output_merkle`, `committed_fragment_count`, `fastpq_transcripts: BTreeMap<Hash, Vec<TransferTranscript>>`, `axt_envelopes`, `axt_policy_snapshot`, and `axt_transitioned_dataspaces`; all seven fields are required and retired lane-finality statements are rejected,
  - `commit_certificate: Option<CommitCertificate>`: the Sumeragi finality proof of a
    committed block, as opaque canonical Norito bytes of the core block header, its
    `CommitQC` and the preimage of the certified result `R` (`specs/sumeragi.md` §3.2, §3.4,
    §4.1; decoded and verified by `iroha_core`). It is `None` on proposals, on executed
    blocks before commit and on genesis; `canonical_resultless_proposal` clears it, and it
    is not covered by the block hash (a header hash), the proposal wire hash or the
    executed block wire hash.
- Utilities: `presigned`, fallible `set_transaction_results(...)` and `set_transaction_results_with_transcripts(...)`, `header()`, `signatures()`, `hash()`, `add_signature`, `replace_signatures`.
- Every `BlockPayload` and `BlockResult` V1 field is present on wire, including
  empty vectors and `None` options. Pre-release layouts that omitted empty
  entrypoints or trailing fields are rejected instead of being hydrated or
  defaulted. Block-local roster evidence is not part of V1: reconfiguration
  authority comes solely from the authenticated Sumeragi v2 height context and
  its parent CommitQC, and the longer pre-release roster-bearing block layouts
  are rejected.
- `BlockHeader` JSON likewise carries every nullable commitment as an explicit
  value or `null`. Consensus signatures use one versioned V1 header projection
  that always includes the nullable NPoS- and execution-context commitments;
  field presence never selects an alternate historical hash layout. The result
  Merkle root remains outside that pre-execution signature projection and is
  validated after deterministic execution.
- Nested execution contexts use the same exact rule: Native-AMX receipts,
  merge references, and every nullable certified-execution binding must appear
  explicitly, while unknown JSON fields and shortened pre-release Norito
  layouts fail closed.
- Merkle commitments bind each application-tree root to its exact non-zero leaf count. Raw typed leaf hashes and internal nodes are separated by the stable `iroha:merkle:leaf:v1\0` and `iroha:merkle:internal:v1\0` domains; the result root is placed into the block header.
- Serialized Merkle trees carry only a V1 hash-scheme discriminant and at most 65,536 canonical leaf-node hashes. Internal nodes and roots are derived caches: decoders rebuild them deterministically and do not accept the retired full-node-vector layout.
- Block inclusion proofs (`BlockProofs`) expose block identity, the authenticated executed-block wire hash, exact entry/result root-and-count commitments, both proofs, and the `fastpq_transcripts` map. The entry commitment covers the full executed-entrypoint order (including scheduled entrypoints), so entry and result proof indices and leaf counts must match. `TrustedBlockProofAnchor::from_untrusted_finality_artifact` verifies the complete Sumeragi-v2 finality artifact and its exact header association before deriving an anchor from the `CommitQC` execution commitment. Verifiers must compare the requested entry hash and index, every commitment value, and the exact FASTPQ transcript projection with that target-specific anchor; values copied from the proof response are not a trust anchor.
- `ExecWitness` messages (streamed via Torii and piggy-backed on consensus gossip) now include both `fastpq_transcripts` and prover-ready `fastpq_batches: Vec<FastpqTransitionBatch>` with embedded `public_inputs` (dsid, slot, roots, perm_root, tx_set_hash), so external provers can ingest canonical FASTPQ rows without re-encoding transcripts.

## Queries

- Two flavors:
  - Singular: implement `SingularQuery<Output>` (e.g., `FindParameters`, `FindExecutorDataModel`).
  - Iterable: implement `Query<Item>` (e.g., `FindAccounts`, `FindAssets`, `FindDomains`, etc.).
- Type-erased forms:
  - `QueryBox<T>` is a boxed, erased `Query<Item = T>` with Norito serde backed by a global registry.
  - `QueryWithFilter<T> { query, predicate, selector }` pairs a query with a DSL predicate/selector; converts into an erased iterable query via `From`.
- Registry and codecs:
  - The built-in query registry maps concrete query types to frozen `iroha.query.v1::iterable::<domain>::<item>` wire IDs for encoding and maps only those wire IDs to constructors for dynamic decode. Custom registries may add new types with unique explicit IDs; type-name decode aliases, retired Rust-path IDs, and unregistered encoding fallbacks are rejected.
  - `QueryRequest = Singular(SingularQueryBox) | Start(QueryWithParams) | Continue(ForwardCursor)` and `QueryResponse = Singular(..) | Iterable(QueryOutput)`.
  - `QueryOutputBatchBox` is a sum-type over homogeneous vectors (e.g., `Vec<Account>`, `Vec<Name>`, `Vec<AssetDefinition>`, `Vec<BlockHeader>`), plus tuple and extension helpers for efficient pagination.
- DSL: Implemented unconditionally in `query::dsl` with projection traits (`HasProjection<PredicateMarker>` / `SelectorMarker`) for compile-time-checked predicates and selectors. Iterable requests carry a canonical item discriminator plus encoded query, predicate, and selector components.

## Executor and Extensibility

- `Executor { bytecode: IvmBytecode }`: the validator-executed code bundle.
- `ExecutorDataModel { parameters: CustomParameters, instructions: BTreeSet<Ident>, permissions: BTreeSet<Ident>, schema: Json }` declares the executor-defined domain:
  - Custom configuration parameters,
  - Custom instruction identifiers,
  - Permission token identifiers,
  - A JSON schema describing custom types for client tooling.
- Customization samples exist under `data_model/samples/executor_custom_data_model` demonstrating:
  - Custom permission token via `iroha_executor_data_model::permission::Permission` derive,
  - Custom parameter defined as a type convertible into `CustomParameter`,
  - Custom instructions serialized into `CustomInstruction` for execution.

### CustomInstruction (executor-defined ISI)

- Type: `isi::CustomInstruction { payload: Json }` with stable wire id `"iroha.custom"`.
- Purpose: envelope for executor-specific instructions in private/consortium networks or for prototyping, without forking the public data model.
- Default executor behavior: the built-in executor in `iroha_core` does not execute `CustomInstruction` and will panic if encountered. A custom executor must downcast `InstructionBox` to `CustomInstruction` and deterministically interpret the payload on all validators.
- Norito: encodes/decodes via `norito::codec::{Encode, Decode}` with schema included; the `Json` payload is serialized deterministically. Round-trips are stable so long as the instruction registry includes `CustomInstruction` (it is part of the default registry).
- IVM: Kotodama compiles to IVM bytecode (`.to`) and is the recommended path for application logic. Only use `CustomInstruction` for executor-level extensions that cannot yet be expressed in Kotodama. Ensure determinism and identical executor binaries across peers.
- Not for public networks: do not use for public chains where heterogeneous executors risk consensus forks. Prefer proposing new built-in ISI upstream when you need platform features.

## Metadata

- `iroha_model_base::metadata::Metadata` owns the `BTreeMap<Name, Json>` representation attached to domains, accounts, asset definitions, NFTs, triggers and transactions. Import it directly from the base crate; `HasMetadata` stays with aggregate ledger entities. The base owner also provides `metadata::Path`.
- The binary representation retains its declared nominal identity and sequence-of-tuples layout. Decoding rejects duplicate keys and charges destination-tree allocations; encoding streams borrowed entries without a second collection.
- API: `contains`, `iter`, `get`, `insert`, and (with `transparent_api`) `remove`.

## Features and Determinism

- The workspace requires `std`; protocol JSON is unconditional. The [crate manifest](../crates/iroha_data_model/Cargo.toml) owns the shipping application, cryptographic, HTTP and internal mutable-API feature selections. The crate exports no C ABI; native SDK bridges consume Norito payloads.
- Determinism: All serialization uses Norito encoding to be portable across hardware. IVM bytecode is an opaque byte blob; execution must not introduce non-deterministic reductions. The host validates transactions and supplies inputs to IVM deterministically.

### Transparent API (`transparent_api`)

- Purpose: exposes full, mutable access to the `#[model]` structs/enums for internal components such as Torii, executors, and integration tests. Without it, those items are intentionally opaque so external SDKs only see safe constructors and encoded payloads.
- Mechanics: the `iroha_data_model_derive::model` macro rewrites each public field with `#[cfg(feature = "transparent_api")] pub` and keeps a private copy for the default build. Enabling the feature flips those cfgs, so destructuring `Account`, `Domain`, `Asset`, etc. becomes legal outside their defining modules.
- Surface detection: the crate entry point owns one `TRANSPARENT_API: bool = cfg!(feature = "transparent_api")` declaration and one public export inventory.
- Enabling: internal consumers that require mutable model access select `features = ["transparent_api"]` explicitly. The aggregate forwards this selection to the foundational owner. JSON codecs do not depend on it.

## Quick Examples

Construct and round-trip metadata through its canonical owner:

```rust
use iroha_model_base::{metadata::Metadata, name::Name};
use iroha_primitives::json::Json;

let mut metadata = Metadata::default();
let key: Name = "tier".parse().unwrap();
metadata.insert(key.clone(), Json::from(1_u32));
let frame = norito::to_bytes(&metadata).unwrap();
let decoded: Metadata = norito::decode_from_bytes(&frame).unwrap();
assert_eq!(decoded, metadata);
assert_eq!(decoded.get(&key), Some(&Json::from(1_u32)));
```

Ledger builders and typed query expressions are exercised in the maintained
[transaction tests](../crates/iroha_data_model/src/transaction.rs) and
[query DSL tests](../crates/iroha_data_model/src/query/dsl_fast.rs).
The [Rust SDK](../crates/iroha/README.md) owns network operations and signing
contexts.

Asset-definition id / alias quick reference (CLI + Torii):

```bash
# Register an asset definition with a canonical Base58 id + explicit name + alias
iroha ledger asset definition register \
  --id 66owaQmAQMuHxPzxUN3bqZ6FJfDa \
  --name pkr \
  --alias pkr#bankb.paynet

# Short alias form (no owner segment): <name>#<dataspace>
iroha ledger asset definition register \
  --id 66owaQmAQMuHxPzxUN3bqZ6FJfDa \
  --name pkr \
  --alias pkr#paynet

# Mint using alias + account components
iroha ledger asset mint \
  --definition-alias pkr#bankb.paynet \
  --account sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV \
  --quantity 500

# Resolve alias to the canonical Base58 id via Torii
curl -sS http://127.0.0.1:8080/v1/assets/aliases/resolve \
  -H 'content-type: application/json' \
  -d '{"alias":"pkr#bankb.paynet"}'
```

Migration note:
- Old `name#domain` asset-definition IDs are not accepted in v1.
- Public asset selectors use one asset-definition format only: canonical Base58 ids. Aliases remain optional selectors, but resolve to the same canonical id.
- Public asset lookups address owned balances with `asset + account + optional scope`; raw encoded `AssetId` literals are an internal representation and are not part of the Torii/CLI selector surface.
- `POST /v1/assets/definitions/query` and `GET /v1/assets/definitions` accept asset-definition filters/sorts over `alias_binding.status`, `alias_binding.lease_expiry_ms`, `alias_binding.grace_until_ms`, and `alias_binding.bound_at_ms` in addition to `id`, `name`, `alias`, and `metadata.*`.

## Versioning

- `SignedTransaction`, `SignedBlock`, and `SignedQuery` are canonical Norito-encoded structs. Each implements `iroha_version::Version` to prefix their payload with the current ABI version (currently `1`) when encoded via `EncodeVersioned`.

## Documentation Ownership

Keep this source-adjacent data-model specification aligned with the
implementation. The public query and instruction catalogs, examples, and
translations are maintained in the sibling `iroha-docs` repository and
published at <https://docs.iroha.tech/>.
