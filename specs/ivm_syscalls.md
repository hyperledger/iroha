# IVM Syscall ABI

This document defines the IVM syscall numbers, pointer-ABI calling conventions, reserved number ranges, and the canonical table of contract-facing syscalls used by Kotodama lowering. It complements `ivm.md` (architecture) and `kotodama_grammar.md` (language).

Versioning
- The set of recognized syscalls depends on the bytecode header `abi_version` field. The first release accepts only `abi_version = 1`; other values are rejected at admission. Unknown numbers for the active `abi_version` deterministically trap with `E_SCALL_UNKNOWN`.
- Runtime upgrades keep `abi_version = 1` and do not expand syscall or pointer‑ABI surfaces.
- Syscall gas costs are part of the versioned gas schedule bound to the bytecode header version. See `ivm.md` (Gas policy).

Numbering ranges
- `0x00..=0x1F`: VM core/utility (debug/exit helpers are available under `CoreHost`; remaining dev helpers are mock-host only).
- `0x20..=0x5F`: Iroha core ISI bridge (stable in ABI v1).
- `0x60..=0x7F`: extension ISIs gated by protocol features (still part of ABI v1 when enabled).
- `0x80..=0xFF`: host/crypto helpers and reserved slots; only numbers present in the ABI v1 allowlist are accepted.

Durable helpers (ABI v1)
- The allowed durable-state helpers in `0x50..=0x5A` are part of ABI V1 and included in `abi_hash`. Number `0x54` is unassigned and rejected as unknown; ABI V1 carries no compatibility reservation or tombstone for the pre-release scalar map-path helper.
- The hash also binds the literal `CNTR` marker and framing, nominal contract-interface and state-type schemas, all embedded state-type tags/layouts/canonical samples, the nesting bound and admission rules, and the typed state-value schema/record identities and validation rules.
- CoreHost wires STATE_{GET,SET,DEL} to WSV-backed durable smart-contract state; dev/test hosts may persist locally but must preserve identical syscall semantics.
- Generic programs are identified by the absence of `CNTR`. They retain pure,
  numeric, codec, crypto, output, query, and ordinary permission-checked ISI
  calls, but cannot use contract-entrypoint grants, contract code/lifecycle
  administration, durable state, the opaque contract instruction bridge,
  nested contract calls, or contract-identity sysvars. The exact sorted denylist,
  rejection semantics, and reserved contract transaction metadata are encoded
  into `abi_hash` and enforced at admission and host dispatch before effects.

Pointer‑ABI calling convention (smart‑contract syscalls)
- Arguments are placed in registers `r10+` as raw `u64` values or as pointers to immutable Norito TLV envelopes in INPUT, an allocated HEAP range, or an exact loader-authenticated code literal (e.g., `AccountId`, `AssetDefinitionId`, `Name`, `Json`, `NftId`).
- Scalar return values are the `u64` returned from the host. Pointer results are written into `r10`; host-produced TLVs use INPUT first and deterministically spill to allocated HEAP when INPUT is full.

Canonical syscall table (subset)

| Hex  | Name                       | Arguments (in `r10+`)                                                   | Returns     | Gas (base + variable)        | Notes |
|------|----------------------------|-------------------------------------------------------------------------|-------------|------------------------------|-------|
| 0x1A | SET_ACCOUNT_DETAIL         | `&AccountId`, `&Name`, `&Json`                                          | `u64=0`     | `G_set_detail + bytes(val)`  | Writes a detail for the account |
| 0x22 | MINT_ASSET                 | `&AccountId`, `&AssetDefinitionId`, `&QuantityValueV1`                  | `u64=0`     | `G_mint`                     | Mints `amount` of asset to account |
| 0x23 | BURN_ASSET                 | `&AccountId`, `&AssetDefinitionId`, `&QuantityValueV1`                  | `u64=0`     | `G_burn`                     | Burns `amount` from account |
| 0x24 | TRANSFER_V1 | `&AccountId(from)`, `&AccountId(to)`, `&AssetDefinitionId`, `&QuantityValueV1` | `u64=0` | `G_transfer` | Batch-internal FASTPQ transfer; `transfer_batch` coalesces entries on this path |
| 0x29 | TRANSFER_V1_BATCH_BEGIN    | –                                                                       | `u64=0`     | `G_transfer`                 | Begin FASTPQ transfer batch scope |
| 0x2A | TRANSFER_V1_BATCH_END      | –                                                                       | `u64=0`     | `G_transfer`                 | Flush accumulated FASTPQ transfer batch |
| 0x2B | TRANSFER_V1_BATCH_APPLY    | `r10=&NoritoBytes(TransferAssetBatch)`                                  | `u64=0`     | `G_transfer`                 | Apply a Norito-encoded batch in a single syscall |
| 0x2C | TRANSFER_ASSET_SCOPED      | `&AccountId(from)`, `&AccountId(to)`, `&AssetDefinitionId`, `&QuantityValueV1`, `&DataSpaceId` | `u64=0` | `G_transfer` | Standalone `transfer_asset` path; global assets use global source balances and dataspace-restricted assets use `r14` |
| 0x25 | NFT_MINT_ASSET             | `&NftId`, `&AccountId(owner)`                                           | `u64=0`     | `G_nft_mint_asset`           | Registers a new NFT |
| 0x26 | NFT_TRANSFER_ASSET         | `&AccountId(from)`, `&NftId`, `&AccountId(to)`                          | `u64=0`     | `G_nft_transfer_asset`       | Transfers ownership of NFT |
| 0x27 | NFT_SET_METADATA           | `&NftId`, `&Name`, `&Json`                                              | `u64=0`     | `G_nft_set_metadata`         | Updates NFT metadata |
| 0x28 | NFT_BURN_ASSET             | `&NftId`                                                                | `u64=0`     | `G_nft_burn_asset`           | Burns (destroys) an NFT |
| 0xA1 | SMARTCONTRACT_EXECUTE_QUERY| `r10=&NoritoBytes(QueryRequest)`                                        | `r10=ptr (&NoritoBytes(QueryResponse))` | `G_scq + per_item*items + per_byte*bytes(resp)` | Iterable queries run ephemerally; `QueryRequest::Continue` rejected |
| 0xA2 | CREATE_NFTS_FOR_ALL_USERS  | –                                                                       | `u64=count` | `G_create_nfts_for_all`      | Helper; feature‑gated |
| 0xA3 | SET_SMARTCONTRACT_EXECUTION_DEPTH | `depth:u64`                                                         | `u64=prev`  | `G_set_depth`                | Admin; feature‑gated |
| 0xA4 | GET_AUTHORITY              | – (host writes result)                                                  | `&AccountId`| `G_get_auth`                 | Host writes pointer to current authority into `r10` |
| 0xA8 | CURRENT_TIME_MS            | –                                                                       | `u64=deterministic_execution_time_ms` | `G_sysvar` | Kotodama `context::transaction_time_ms()`; signer-chosen transaction creation time (within admission tolerance) for transaction calls, block-header time for triggers |
| 0xF7 | GET_MERKLE_PATH            | `addr:u64`, `out_ptr:u64`, optional `root_out:u64`                      | `u64=len`   | `G_mpath + len`             | Writes path (leaf→root) and optional root bytes |
| 0xFA | GET_MERKLE_COMPACT         | `addr:u64`, `out_ptr:u64`, optional `depth_cap:u64`, optional `root_out:u64` | `u64=depth` | `G_mpath + depth`           | `[u8 depth][u32 dirs_le][u32 count][count*32 siblings]` |
| 0xFF | GET_REGISTER_MERKLE_COMPACT| `reg_index:u64`, `out_ptr:u64`, optional `depth_cap:u64`, optional `root_out:u64` | `u64=depth` | `G_mpath + depth`           | Same compact layout for register commitment |

Gas enforcement
- CoreHost charges extra gas for ISI syscalls using the native ISI schedule; FASTPQ batch transfers are charged per entry.
- ZK_VERIFY syscalls reuse the confidential verification gas schedule (base + proof size).
- SMARTCONTRACT_EXECUTE_QUERY charges base + per-item + per-byte; sorting multiplies per-item cost and unsorted offsets add a per-item penalty.
- Numeric syscalls use quote-free staged metering: each bounded validation,
  logical-limb arithmetic, normalization, and output phase is debited before it
  begins. Small compact values therefore cost less than wide values without
  making consensus depend on host bigint performance.

Notes
- Pointer arguments are validated on first dereference. V1 accepts INPUT,
  allocated HEAP, and exact loader-authenticated literal envelopes; stack,
  OUTPUT, unallocated or partially owned HEAP, and arbitrary code offsets fail
  with `E_NORITO_INVALID`.
- All mutations are applied via Iroha’s standard executor (through `CoreHost`), not directly by the VM.
- Kotodama `block_height()` lowers to the existing extended `SYSVAR_BLOCK_HEIGHT` syscall (`0x010021`) and returns the host-provided block height as an integer.
- `QuantityValueV1`, `IntValueV1`, and `DecimalValueV1` use pointer types
  `0x0010`, `0x0011`, and `0x0012`. Pointer ID `0x0013` is the assigned
  `AxtAnchoredSpendV1` type and is wrong for numeric operands; `0x000C` and
  `0x0014` are unassigned and rejected as unknown.
  Their unconditional syscall blocks are `0x010100..=0x010113`,
  `0x010120..=0x01012F`, and `0x010140..=0x01014F`. Exact division distinguishes
  repeating results from terminating results needing scale above 28; rounded
  operations require an explicit scale and one of `toward_zero` (tag 0),
  `away_from_zero` (tag 1), `floor` (tag 2), `ceil` (tag 3), `nearest_even`
  (tag 4), `nearest_away` (tag 5), or `nearest_toward_zero` (tag 6).
  Arithmetic and gas depend only on canonical bytes and deterministic 64-bit
  logical-limb work.
- `JSON_BUILD` (`0x01004E`) consumes one compiler-emitted construction schema
  and flattened word table, recursively reads bounded `Option`/`List` handles,
  sorts object keys canonically, and encodes one `Json` payload. Int, decimal,
  and quantity values remain exact canonical strings, including the complete
  signed 512-bit int domain; bytes use lowercase `0x` hex, and no
  floating-point or host integer-width conversion is used.
- Every `JSON_GET_*` syscall returns a compiler-owned `Option<T>` sum handle;
  missing/wrongly typed fields are `none`. Numeric getters distinguish
  `JSON_GET_INT`, `JSON_GET_DECIMAL`, and `JSON_GET_QUANTITY` at
  `0x010160..=0x010162`; all three accept canonical strings only. JSON number
  tokens are rejected, `0x010163..=0x010165` remain unassigned, and retired
  numeric getter names are not part of V1.
- `CORE_QUERY_GET` (`0x010001`) accepts stable entity tag `1..=5` for account,
  asset, asset definition, domain, or NFT plus that family's exact typed ID,
  and returns a compiler-owned `Option<View>` handle. `CORE_QUERY_PAGE`
  (`0x010002`) accepts the same tag with `offset` in `0..=i64::MAX`, `limit` in
  `1..=64`, and `offset + limit` fitting `i64`; it returns `List<View, 64>` plus
  `Option<int>` continuation handles. The host orders canonical IDs, performs
  one ledger query, decodes the canonical host-created projection exactly once, and
  materializes only the requested projection into guest handles. The precise
  view and `QueryPage<T>` field layouts are normative in
  `specs/kotodama_grammar.md`; those layouts and stable entity tags are bound
  into the ABI hash. Query families outside these five remain explicit
  `NoritoBytes` specialist APIs.
- Exact gas constants (`G_*`) are defined by the active gas schedule; see `ivm.md`.

Errors
- `E_SCALL_UNKNOWN`: syscall number not recognized for the active `abi_version`.
- Input validation errors propagate as VM traps (e.g., `E_NORITO_INVALID` for malformed TLVs).

Cross‑references
- Architecture and VM semantics: `ivm.md`
- Language and builtin mapping: `specs/kotodama_grammar.md`

Generation note
- A complete list of syscall constants can be generated from source with:
  - `make docs-syscalls` → writes `specs/ivm_syscalls_generated.md`
  - `make check-docs` → verifies the generated table is up to date (useful in CI)
- The subset above remains a curated, stable table for contract-facing syscalls.

## Admin/Role TLV Examples (Mock Host)

This section documents the TLV shapes and minimal JSON payloads accepted by the mock WSV host for admin‑style syscalls used in tests. All pointer arguments follow the V1 pointer ABI and its provenance rules. Production hosts may use richer schemas; these examples aim to clarify types and basic shapes.

- REGISTER_PEER / UNREGISTER_PEER
  - Args: `r10=&Json`
  - Example JSON: `{ "peer": "peer-id-or-info" }`
  - CoreHost note: `REGISTER_PEER` expects a `RegisterPeerWithPop` JSON object with `peer` + `pop` bytes (optional `activation_at`, `expiry_at`); `UNREGISTER_PEER` accepts a peer-id string or `{ "peer": "..." }`.

- CREATE_TRIGGER / REMOVE_TRIGGER / SET_TRIGGER_ENABLED
  - CREATE_TRIGGER:
    - Args: `r10=&Json`
    - Minimal JSON: `{ "name": "t1" }` (additional fields ignored by the mock)
  - REMOVE_TRIGGER:
    - Args: `r10=&Name` (trigger name)
  - SET_TRIGGER_ENABLED:
    - Args: `r10=&Name`, `r11=enabled:u64` (0 = disabled, non‑zero = enabled)
  - CoreHost note: `CREATE_TRIGGER` expects a full trigger spec (base64 Norito `Trigger` string or
    `{ "id": "<trigger_id>", "action": ... }` with `action` as a base64 Norito `Action` string or
    a JSON object), and `SET_TRIGGER_ENABLED` toggles the trigger metadata key `__enabled` (missing
    defaults to enabled).

- Roles: CREATE_ROLE / DELETE_ROLE / GRANT_ROLE / REVOKE_ROLE
  - CREATE_ROLE:
    - Args: `r10=&Name` (role name), `r11=&Json` (permissions set)
    - JSON accepts either key `"perms"` or `"permissions"`, each a string array of permission names.
    - Examples:
      - `{ "perms": [ "mint_asset:rose#wonder" ] }`
      - `{ "permissions": [ "read_assets:<i105-account-id>", "transfer_asset:rose#wonder" ] }`
    - Supported permission name prefixes in the mock:
      - `register_domain`, `register_account`, `register_asset_definition`
      - `read_assets:<account_id>`
      - `mint_asset:<asset_definition_id>`
      - `burn_asset:<asset_definition_id>`
      - `transfer_asset:<asset_definition_id>`
  - DELETE_ROLE:
    - Args: `r10=&Name`
    - Fails if any account is still assigned this role.
  - GRANT_ROLE / REVOKE_ROLE:
    - Args: `r10=&AccountId` (subject), `r11=&Name` (role name)
  - CoreHost note: permission JSON may be a full `Permission` object (`{ "name": "...", "payload": ... }`) or a string (payload defaults to `null`); `GRANT_PERMISSION`/`REVOKE_PERMISSION` accept `&Name` or `&Json(Permission)`.

- Unregister ops (domain/account/asset): invariants (mock)
  - UNREGISTER_DOMAIN (`r10=&DomainId`) fails if accounts or asset definitions exist in the domain.
  - UNREGISTER_ACCOUNT (`r10=&AccountId`) fails if the account has non‑zero balances or owns NFTs.
  - UNREGISTER_ASSET (`r10=&AssetDefinitionId`) fails if any balances exist for the asset.

Notes
- These examples reflect the mock WSV host used in tests; real node hosts may expose richer admin schemas or require additional validation. The pointer‑ABI rules still apply: TLVs must have allowed provenance (INPUT, allocated HEAP, or an exact loader-authenticated literal), version 1, matching type IDs, and valid payload hashes.
