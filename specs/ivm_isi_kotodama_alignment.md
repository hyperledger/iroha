# IVM ⇄ ISI ⇄ Data Model ⇄ Kotodama — Alignment Review

This document audits how the Iroha Virtual Machine (IVM) instruction set and syscall surface map to the Iroha Special Instructions (ISI) and `iroha_data_model`, and how Kotodama compiles into that stack. It identifies current gaps and proposes concrete improvements so the four layers fit together deterministically and ergonomically.

Note on bytecode target: Kotodama smart contracts compile to Iroha Virtual Machine (IVM) bytecode (`.to`). They do not target “risc5”/RISC‑V as a standalone architecture. Any RISC‑V‑like encodings referenced here are part of IVM’s mixed instruction format and remain an implementation detail.

## Scope and Sources
- IVM: `crates/ivm/src/{instruction.rs,ivm.rs,syscalls.rs,host.rs,mock_wsv.rs}` and `crates/ivm/docs/*`.
- ISI/Data Model: `crates/iroha_data_model/src/isi/*`, `crates/iroha_core/src/smartcontracts/isi/*`, and docs `specs/data_model_and_isi_spec.md`.
- Kotodama: `crates/kotodama_lang/src/*`, docs in `crates/ivm/docs/*`.
- Core integration: `crates/iroha_core/src/{state.rs,executor.rs,smartcontracts/ivm/cache.rs}`.

Terminology
- “ISI” refers to built‑in instruction types that mutate world state via the executor (e.g., RegisterAccount, Mint, Transfer).
- “Syscall” refers to IVM `SCALL` with an 8‑bit number that delegates to the host for ledger operations.

---

## Current Mapping (As Implemented)

### IVM Instructions
- Arithmetic, memory, control flow, crypto, vector, and ZK helpers are defined in `instruction.rs` and implemented in `ivm.rs`. These are self‑contained and deterministic; acceleration paths (SIMD/Metal/CUDA) have CPU fallbacks.
- System/host boundary is via `SCALL` (opcode 0x60). Numbers are listed in `syscalls.rs` and include world operations (register/unregister domain/account/asset, mint/burn/transfer, role/permission ops, triggers) plus helpers (`GET_PRIVATE_INPUT`, `COMMIT_OUTPUT`, `GET_MERKLE_PATH`, etc.).

### Host Layer
- Trait `IVMHost::syscall(number, &mut IVM)` lives in `host.rs`.
- DefaultHost implements only non‑ledger helpers (alloc, heap growth,
  inputs/outputs, ZK proof helpers, feature discovery) — it does NOT perform
  world state mutations.
- The `ivm` crate also has codec/test hosts: `CoreHost` validates pointer-ABI
  TLVs for representative syscalls, while `mock_wsv.rs` provides an in-memory
  WSV harness for VM and Kotodama tests.
- The production runtime adapter is
  `iroha_core::smartcontracts::ivm::host::CoreHostImpl`. It decodes pointer-ABI
  arguments, queues built-in ISI, delegates helper syscalls to the VM host
  layer, and executes nested contract calls through the same permission and
  manifest checks as direct contract transactions.

### ISI and Data Model
- Built‑in ISI types and semantics are implemented in `iroha_core::smartcontracts::isi::*` and documented in `specs/data_model_and_isi_spec.md`.
- `InstructionBox` uses a registry with stable “wire IDs” and Norito encoding; native execution dispatch is the current code path in core.

### Core Integration of IVM
- Contract admission builds an immutable `PreparedContract` with validated
  metadata, interface, control flow, and predecode. Warm calls reuse prepared
  state and pooled VMs, resetting dirty memory instead of cloning the full
  stack and Merkle tree.
- `CoreHostImpl` implements `IVMHost`: stateful syscalls are decoded via the
  pointer-ABI TLV layout, mapped to built-in ISI (`InstructionBox`), and
  queued. Once the VM returns, the host hands those ISI to the regular executor
  so permissions, invariants, events, and telemetry remain identical to native
  execution. Helper syscalls that do not touch WSV still delegate to the VM host
  layer.
- Contract dispatch consumes the signed authorization policy and permission
  declaration table for both direct `ContractCall` and nested `CALL_CONTRACT`.
  `Anyone` permits invocation; declared roles require the exact instance or
  imported chain token, held directly or through an assigned role. Lifecycle
  hooks require their exact runtime address-and-hook token.
- `executor.rs` continues to run built-in ISI natively; the VM host adapter is
  the bridge for IVM contracts, not a replacement for the native executor.
- Executor validation and migration inputs and results use an eight-byte
  little-endian `u64` length prefix that includes the prefix itself. Core reads
  results directly from a permission-checked VM memory slice and caps the full
  framed result at the deterministic one-MiB heap-window size; shorter,
  oversized, partially readable, trailing, or non-canonical results fail
  closed before decoding.

### Kotodama → IVM
- Kotodama has lexer, parser, semantic analysis, IR, register allocation, and
  codegen in `crates/kotodama_lang`.
- One branded V1 `seiyaku`/`誓約` or `module`, private functions, authorized
  `kotoage fn`/`言挙げ fn`, read-only `view fn`, `hajimari`/`始まり` and
  `kaizen`/`改善` lifecycle declarations, typed state,
  structs, tuples, triggers, stable error enums, and internal helper calls are
  wired through resolution, semantic analysis, and codegen.
- Source host capabilities use canonical namespaces such as `context`,
  `ledger`, `state`, and `crypto`. Flat legacy operation aliases, source
  metadata, raw pointers, direct syscall variants, and opaque instruction
  submission are rejected.
- Codegen emits pointer-ABI TLVs for ledger syscalls and host helpers:
  - `MintAsset` sets x10=account, x11=asset, x12=&QuantityValueV1, then
    calls `SYSCALL_MINT_ASSET`.
  - `BurnAsset`, `TransferAsset`, batch transfers, roles, permissions, triggers,
    contract lifecycle helpers, and selected query/sysvar helpers follow the
    same pointer-ABI convention.
- Test helpers such as `test::invoke_kotoage_as(...)` use the test-host
  intrinsic surface, accept a JSON argument payload for a literal target, and
  return that declaration's statically resolved type. Runtime arguments and
  returns are validated against the complete signed callable schemas.

---

## Alignment Boundaries

1. Core host coverage and parity

`CoreHostImpl` maps the first-release contract syscalls used by Kotodama and the
runtime contract surface into queued ISI, including domains/accounts/assets,
NFTs, roles, permissions, triggers, parameters, smart-contract lifecycle
operations, queries, AXT helpers, ZK verifier calls, and nested contract calls.
Allowed syscall numbers outside that production mapping fail closed with a
metered host rejection until an explicit mapping and test coverage are added.
Soracloud host syscalls are ABI-listed and access-described; dedicated
Soracloud handler execution uses `irohad`'s `SoracloudIvmHost`, while ordinary
`CoreHostImpl` contract execution validates their request TLV, schema,
operation, and payload variant, then fails closed with metered `NotImplemented`.
`SoracloudIvmHost` has no ledger world-state snapshot and therefore excludes
the complete state-backed AXT syscall family from its advertised host surface;
AXT execution remains confined to production `CoreHostImpl` instances backed
by replicated ledger state and a Space Directory policy snapshot.

2. Syscall surface vs. ISI/Data Model naming and coverage

NFT syscalls use canonical `SYSCALL_NFT_*` names aligned with
`iroha_data_model::nft`. Role, permission, trigger, parameter, and
smart-contract lifecycle syscalls are tied to concrete core ISI in
`CoreHostImpl`.
The syscall tables in `crates/ivm/docs/syscalls.md` remain the source to update
when a new number, pointer type, or gas rule is introduced.

3. ABI for passing typed data across the VM/host boundary

Pointer-ABI TLVs are decoded in the runtime host (`decode_tlv_typed` and
specialized helpers), giving a deterministic path for IDs, metadata, JSON,
Norito payloads, and contract-call arguments. Kotodama emits the matching TLVs
for its builtins and fails closed when static access descriptors cannot be
derived for production manifests.

4. Gas and error mapping consistency

IVM opcodes charge per-op gas. Runtime host syscalls prepare and quote a
deterministic size-aware cost for queued ISI, query payloads, ZK verification,
seiyaku calls, and helper payloads; the VM debits that quote before execution.
No query, allocation, or state effect occurs before affordability is known.
Host errors are normalized into VM-visible errors or explicit status registers
before state changes are committed.

5. Determinism across acceleration paths

Hardware-assisted paths keep deterministic CPU fallbacks, and blockchain-visible
results must remain byte-for-byte identical across peers. `SETVL`,
`PARBEGIN`, and `PAREND` are public deterministic hints/no-op markers in the
current VM behavior; acceleration work must preserve the same observable trace
semantics.

6. Kotodama language surface vs. ledger semantics

Kotodama wires contract bodies, `StateMap` handles, structs, tuples, triggers,
typed parameters/returns, and namespaced capabilities into the IVM host model.
The current source call helper has an exact two-quantity argument and quantity
result shape; the generic `CALL_CONTRACT` record ABI is a runtime surface and
does not provide arbitrary typed external calls in source. Every `kotoage fn`
and `view fn` declares
`authorize(anyone)` or `authorize(DeclaredPermission)` before its return type;
the signed declaration table binds each name to an instance role or an explicit
chain import. Runtime caller authorization remains separate
from operation-specific host authorization. `view fn` declarations reject
stateful effects across the complete call graph.

Nested calls use the calling contract's subject as their immediate caller;
they do not inherit the originating transaction signer's permissions. Calls
share staged durable storage, while ledger queries use the invocation snapshot
and queued ledger instructions apply only after root success. Re-entry into
any active contract address, including a view, is rejected. A canonical outer
`Result::err` preserves its return value, consumed gas and read dependencies
while discarding the frame's writes and queued effects, including successful
descendants. Root execution, local runs and noncommitting simulations follow
the same rule; an inner Result inside another returned value is ordinary data.

Lifecycle authorization cannot be weakened in source. ABI V1 maps both
`hajimari`/`始まり` and `kaizen`/`改善` to the runtime-defined
exact address-and-hook `CanInvokeContractEntrypoint` permission. This hook permission is separate from
revisioned address lifecycle admission: only the current account owner or the
certified Parliament corridor may activate or deactivate an existing address,
and raw activation cannot create one. Suspension retains the last artifact
identity and unfinished hook; resumption never replays a completed initializer.
Every prepared call binds the lifecycle revision. Both active and suspended
replacements preserve all existing complete durable schemas, and added scalar
values must pass canonical runtime validation before `kaizen` completes.

An instance permission name identifies the same role across replacements.
Only the current account owner or a holder of the exact scoped token may grant
or revoke a currently declared instance role. Executing the contract's grant
helper does not confer that token on its subject, and a general code-management
permission does not authorize scoped delegation. An explicit chain import
matches only the named token with canonical JSON `null` payload, never a typed
built-in permission payload.
Removing its declaration makes outstanding tokens unusable while absent; it
does not delete those tokens. Redeclaring the same name restores that same role
identity. Revocation remains an explicit permission operation.
While suspended, the current owner and exact holders may grant or revoke roles
declared by the retained artifact. Those grants cannot authorize invocation
until the instance resumes; undeclared names remain invalid in either state.

---

## Maintenance Steps

### A. Extend the production host by explicit ABI slices

For each new syscall in `ivm::syscalls`, add the ordered ABI-list entry,
document the register and pointer types, implement or intentionally reject the
number in `CoreHostImpl`, and add focused runtime tests that prove the queued
ISI matches native execution semantics.

### B. Keep typed-value ABI rules canonical

Use Norito-framed pointer-ABI TLVs for structured arguments. VM registers carry
pointers to values such as `AccountId`, `AssetDefinitionId`, `Name`, `Json`,
`NftId`, and `QuantityValueV1`, while the host decodes them with the same
Norito-backed data-model types used by native ISI.

### C. Keep syscall naming and coverage aligned with ISI/Data Model

Maintain the mapping table in `crates/ivm/docs/syscalls.md` and the host tests
in `crates/iroha_core/src/smartcontracts/ivm/host.rs` whenever a syscall or ISI
shape changes. Privileged ISI must continue to be enforced through the same
permission path as native execution.

### D. Preserve gas and error consistency

Gas costs must be input-size predictable and platform-independent. Exact
numeric operations use the staged 64-bit logical-limb formulas in
[`kotodama_numeric_v1.md`](./kotodama_numeric_v1.md), so compact small values
cost less than wide values without making gas depend on a host bigint backend.
Host-side ISI errors should continue to normalize into deterministic VM errors
or status register conventions without committing partial state.

### E. Preserve deterministic acceleration behavior

SIMD, Metal, CUDA, and other accelerated paths must keep deterministic scalar
fallbacks and equivalence tests. Any optimization that changes reduction order,
trace shape, or public output must stay outside consensus-visible behavior.

### F. Keep Kotodama compiler wiring and manifests synchronized

When adding or changing builtins, update semantic effects, access descriptor
derivation, IR lowering, register allocation, codegen, test-host execution, and
manifest documentation together. Production manifests should remain specific:
dynamic or malformed helper payloads fail closed instead of widening access
descriptors.

---

## Representative Mapping Table

This is a readable subset. The canonical list is
`crates/ivm/docs/syscalls.md` plus the ordered ABI list in
`ivm::syscalls::abi_syscall_list()`.

- `SYSCALL_REGISTER_DOMAIN(id: ptr DomainId)` → ISI `Register<Domain>`
- `SYSCALL_REGISTER_ACCOUNT(id: ptr AccountId)` → ISI `Register<Account>`
- `SYSCALL_REGISTER_ASSET(id: ptr AssetDefinitionId)` → ISI
  `Register<AssetDefinition>`
- `SYSCALL_MINT_ASSET(account: ptr AccountId, asset: ptr AssetDefinitionId,
  amount: ptr QuantityValueV1)` → ISI `Mint<Quantity, Asset>`
- `SYSCALL_BURN_ASSET(account: ptr AccountId, asset: ptr AssetDefinitionId,
  amount: ptr QuantityValueV1)` → ISI `Burn<Quantity, Asset>`
- `SYSCALL_TRANSFER_V1(from: ptr AccountId, to: ptr AccountId,
  asset: ptr AssetDefinitionId, amount: ptr QuantityValueV1)` → batch-internal ISI
  `Transfer<Asset>`
- `SYSCALL_TRANSFER_ASSET_SCOPED(from: ptr AccountId, to: ptr AccountId,
  asset: ptr AssetDefinitionId, amount: ptr QuantityValueV1,
  dataspace: ptr DataSpaceId)` → standalone ISI `Transfer<Asset>`
- `SYSCALL_TRANSFER_V1_BATCH_APPLY(&NoritoBytes<TransferAssetBatch>)` → ISI
  `TransferAssetBatch`
- `SYSCALL_NFT_MINT_ASSET(id: ptr NftId, owner: ptr AccountId)` → ISI
  `Register<Nft>`
- `SYSCALL_NFT_TRANSFER_ASSET(from: ptr AccountId, to: ptr AccountId,
  id: ptr NftId)` → ISI `Transfer<Nft>`
- `SYSCALL_NFT_SET_METADATA(id: ptr NftId, key: ptr Name, value: ptr Json)` →
  ISI `SetKeyValue<Nft>`
- `SYSCALL_NFT_BURN_ASSET(id: ptr NftId)` → ISI `Unregister<Nft>`
- `SYSCALL_CREATE_ROLE(name: ptr Name, permissions: ptr Json)` → ISI
  `Register<Role>`
- `SYSCALL_DELETE_ROLE(name: ptr Name)` → ISI `Unregister<Role>`
- `SYSCALL_GRANT_ROLE(account: ptr AccountId, role: ptr Name)` → ISI
  `Grant<Role>`
- `SYSCALL_REVOKE_ROLE(account: ptr AccountId, role: ptr Name)` → ISI
  `Revoke<Role>`
- `SYSCALL_GRANT_PERMISSION(account: ptr AccountId, permission: ptr Name|Json)`
  → ISI `Grant<Permission>`
- `SYSCALL_REVOKE_PERMISSION(account: ptr AccountId, permission: ptr Name|Json)`
  → ISI `Revoke<Permission>`
- `SYSCALL_CREATE_TRIGGER(spec: ptr Json|Trigger)` → ISI `Register<Trigger>`
- `SYSCALL_REMOVE_TRIGGER(name: ptr Name)` → ISI `Unregister<Trigger>`
- `SYSCALL_SET_TRIGGER_ENABLED(name: ptr Name, enabled: int)` → ISI
  `SetKeyValue<Trigger>`
- `SYSCALL_SET_PARAMETER(param: ptr Parameter)` → ISI `SetParameter`
- `SYSCALL_CALL_CONTRACT(request pointers)` → nested contract execution with
  manifest entrypoint permission enforcement

Notes
- “ptr T” means a pointer in a register to Norito-encoded bytes for T, stored
  in VM memory; the host decodes it into the corresponding `iroha_data_model`
  type.
- Return conventions are syscall-specific. Mutating ISI syscalls queue
  instructions or return a VM error; query/helper syscalls return scalars,
  pointer TLVs, status vectors, or schema-bound nested contract return records as
  documented in `crates/ivm/docs/syscalls.md`.

---

## Risk Controls

- Keep native ISI execution as the authoritative mutation path: IVM contracts
  queue the same ISI and rely on the regular executor for permission checks,
  invariants, events, and telemetry.
- Require focused parity tests when a host mapping is added or changed.
- Keep ABI hash and syscall-list golden tests in sync with any syscall-surface
  change.
- Preserve pointer-ABI round-trip fixtures in
  `crates/ivm_abi/tests/norito_pointer_abi_roundtrip.rs`.
