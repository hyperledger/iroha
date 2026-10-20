//! Iroha-specific syscall number definitions.
//!
//! The VM uses the `SCALL` instruction to invoke host-provided ledger operations. Section 7 of the
//! IVM specification assigns concrete numeric codes to those operations. The constants below mirror
//! that table so that VM users can refer to the syscalls symbolically. Actual behaviour and gas
//! charges are implemented by the host. These calls are collectively known as **Iroha Special
//! Instructions** (ISI).
//!
//! The table below includes helper syscalls used for cryptographic proof
//! generation and verification, Merkle path queries and hardware feature
//! discovery. Additional concurrency primitives may be added in future core
//! releases without changing the fixed ABI v1 surface in this release.
mod semantic_surface;
use semantic_surface::semantic_abi_surface_v1;

use iroha_data_model::prelude::{
    DECIMAL_SCHEMA_HASH_V1, DECIMAL_SCHEMA_NAME_V1, INT_SCHEMA_HASH_V1, INT_SCHEMA_NAME_V1,
    MAX_DECIMAL_ENVELOPE_BYTES_V1, MAX_DECIMAL_FRAME_BYTES_V1, MAX_INT_ENVELOPE_BYTES_V1,
    MAX_INT_FRAME_BYTES_V1, MAX_QUANTITY_ENVELOPE_BYTES_V1, MAX_QUANTITY_FRAME_BYTES_V1,
    NUMERIC_FRAME_HEADER_BYTES_V1, NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1, QUANTITY_SCHEMA_HASH_V1,
    QUANTITY_SCHEMA_NAME_V1,
};
/// Debug helper for development; part of the ABI v1 surface.
pub const SYSCALL_DEBUG_PRINT: u32 = 0;
/// Lifecycle and utility syscalls. Gracefully terminate the program and return a value.
pub const SYSCALL_EXIT: u32 = 0x01;
/// Abort execution and revert state changes.
pub const SYSCALL_ABORT: u32 = 0x02;
/// Output a debug message (development only).
pub const SYSCALL_DEBUG_LOG: u32 = 0x03;
/// Abort with `r10=&NoritoBytes(ContractErrorTypeDescriptor)`, `r11=code:u32`, and zero `r12..r15`.
pub const SYSCALL_CONTRACT_ABORT: u32 = 0x04;
/// Helper syscalls for inputs/outputs; part of the ABI v1 surface.
/// Retrieve a piece of public input provided by the host.
pub const SYSCALL_GET_PUBLIC_INPUT: u32 = 0xF1;
/// Allocate heap memory.
pub const SYSCALL_ALLOC: u32 = 0xF0;
/// Domain and peer management.
pub const SYSCALL_REGISTER_DOMAIN: u32 = 0x10;
pub const SYSCALL_UNREGISTER_DOMAIN: u32 = 0x11;
pub const SYSCALL_TRANSFER_DOMAIN: u32 = 0x12;
pub const SYSCALL_REGISTER_PEER: u32 = 0x15;
pub const SYSCALL_UNREGISTER_PEER: u32 = 0x16;
/// Account management.
pub const SYSCALL_REGISTER_ACCOUNT: u32 = 0x13;
pub const SYSCALL_UNREGISTER_ACCOUNT: u32 = 0x14;
/// Add a signatory for an account.
pub const SYSCALL_ADD_SIGNATORY: u32 = 0x17;
/// Remove a signatory from an account.
pub const SYSCALL_REMOVE_SIGNATORY: u32 = 0x18;
/// Update account quorum.
pub const SYSCALL_SET_ACCOUNT_QUORUM: u32 = 0x19;
pub const SYSCALL_SET_ACCOUNT_DETAIL: u32 = 0x1A;
/// Asset definitions.
pub const SYSCALL_REGISTER_ASSET: u32 = 0x20;
pub const SYSCALL_UNREGISTER_ASSET: u32 = 0x21;
pub const SYSCALL_MINT_ASSET: u32 = 0x22;
pub const SYSCALL_BURN_ASSET: u32 = 0x23;
/// Batch-internal FASTPQ transfer gadget syscall.
pub const SYSCALL_TRANSFER_V1: u32 = 0x24;
/// Begin a FASTPQ transfer batch; subsequent `transfer_v1` calls are coalesced.
pub const SYSCALL_TRANSFER_V1_BATCH_BEGIN: u32 = 0x29;
/// End the current FASTPQ transfer batch scope.
pub const SYSCALL_TRANSFER_V1_BATCH_END: u32 = 0x2A;
/// Submit a pre-baked FASTPQ batch via a Norito-encoded [`TransferAssetBatch`].
pub const SYSCALL_TRANSFER_V1_BATCH_APPLY: u32 = 0x2B;
/// Transfer a numeric asset balance within an explicit dataspace scope.
pub const SYSCALL_TRANSFER_ASSET_SCOPED: u32 = 0x2C;
/// Non‑fungible asset (NFT) operations (canonical names).
pub const SYSCALL_NFT_MINT_ASSET: u32 = 0x25;
pub const SYSCALL_NFT_TRANSFER_ASSET: u32 = 0x26;
pub const SYSCALL_NFT_SET_METADATA: u32 = 0x27;
pub const SYSCALL_NFT_BURN_ASSET: u32 = 0x28;
/// Smart-contract durable state (key-value by path).
///
/// Pointer-ABI arguments: paths use `&NoritoBytes(canonical Norito StatePath)` TLV; values use
/// `&NoritoBytes` TLV.
///
/// GET:  r10 = &NoritoBytes(StatePath)  -> On success, r10 = &NoritoBytes
/// value in host-owned memory; if missing, r10 = 0.
/// SET:  r10 = &NoritoBytes(StatePath), r11 = &NoritoBytes value  -> stores
/// value, returns 0.
/// DEL:  r10 = &NoritoBytes(StatePath)  -> deletes value if present, returns 0.
pub const SYSCALL_STATE_GET: u32 = 0x50;
pub const SYSCALL_STATE_SET: u32 = 0x51;
pub const SYSCALL_STATE_DEL: u32 = 0x52;
/// Test whether a durable-state key is currently present.
///
/// Args: r10 = &NoritoBytes(StatePath) Ret: r10 = 1 when present, 0 when absent
pub const SYSCALL_STATE_HAS: u32 = 0x01_0031;
/// Return the byte length of a durable-state value without copying the value.
///
/// Args: r10 = &NoritoBytes(StatePath)
/// Ret:  r10 = value payload length, r11 = 1 when present, 0 when absent
pub const SYSCALL_STATE_LEN: u32 = 0x01_0032;
/// Count durable-state keys under a prefix without copying the key list.
///
/// Args: r10 = &NoritoBytes(StatePath) Ret: r10 = total matching keys
pub const SYSCALL_STATE_COUNT: u32 = 0x01_0033;
/// Decode one canonical Kotodama `StateMap` key from a page returned by [`SYSCALL_STATE_SCAN`].
///
/// Args: r10 = &NoritoBytes(Vec<StatePath>), r11 = &Name(base), r12 = index
/// Ret:  r10 = &NoritoBytes(canonical key), or 0 when index is out of range
pub const SYSCALL_STATE_MAP_KEY_AT: u32 = 0x01_0034;
/// Encode one compiler-flattened typed durable value.
///
/// Args: r10 = &NoritoBytes(StateValueSchemaV1), r11 = aligned raw word table, r12 = word count
/// Ret: r10 = &NoritoBytes(StateValueRecordV1)
pub const SYSCALL_STATE_VALUE_ENCODE: u32 = 0x01_0035;
/// Decode one typed durable value into an aligned compiler word table.
///
/// Args: r10 = &NoritoBytes(StateValueSchemaV1), r11 = &NoritoBytes(StateValueRecordV1); zero is
/// rejected because absence is represented by `StateMap.get`'s outer `Option`, never by a typed
/// value Ret: r10 = &Blob(pad:u8 then flattened u64 words)
pub const SYSCALL_STATE_VALUE_DECODE: u32 = 0x01_0036;
/// Convert one canonical nominal `Name` into a durable-state `StatePath`.
///
/// Args: r10 = &Name Ret: r10 = &NoritoBytes(canonical Norito StatePath)
pub const SYSCALL_STATE_PATH_FROM_NAME: u32 = 0x01_0037;
/// Seek through at most 64 current map positions, including overlay tombstones.
///
/// Args: r10 = &NoritoBytes(StatePath map), r11 = &NoritoBytes(StateCursorV1) or 0,
/// r12 = limit (1..=64), r13 = r14 = r15 = 0.
/// Ret: r10 = &NoritoBytes(Vec<StatePath>), r11 = next cursor or 0,
/// r12 = selected keys, r13 = examined positions. No count or lookahead is performed.
pub const SYSCALL_STATE_SCAN: u32 = 0x01_0038;
/// Maximum distinct current positions examined by one live map page, including tombstones.
pub const STATE_SCAN_MAX_CANDIDATES_V1: usize = 64;
/// Maximum number of entries returned by one V1 durable-state key page.
pub const STATE_SCAN_MAX_ITEMS_V1: u64 = 64;
/// Maximum UTF-8 byte length of a canonical V1 durable-state `StatePath`.
///
/// The 16 KiB path accommodates a canonical `Name` base of at most 255 UTF-8 bytes, one separator,
/// and the lowercase-hex expansion of a 4 KiB canonical key. Keep this synchronized with
/// `iroha_model_base::state_path::MAX_STATE_PATH_BYTES`.
pub const STATE_MAX_PATH_BYTES: usize = iroha_model_base::state_path::MAX_STATE_PATH_BYTES;
/// Conservative maximum canonical Norito frame carried inside the `NoritoBytes` path TLV.
///
/// This separately ABI-binds transport framing so header-only gas quoting can
/// reject oversized input without reducing the 16 KiB UTF-8 path ceiling.
/// `StatePath` serializes as one length-prefixed string; the alignment slack
/// keeps this bound conservative for every V1 layout flag set.
pub const STATE_MAX_PATH_FRAME_BYTES: usize = STATE_MAX_PATH_BYTES
    + norito::core::Header::SIZE
    + (core::mem::align_of::<u64>() - 1)
    + core::mem::size_of::<u64>();
/// Maximum raw `NoritoBytes` payload stored under one V1 durable-state path.
///
/// The bound leaves enough room beneath the one-million-cycle default for a
/// prepare-time worst-case read escrow, the path, and VM instruction gas.
pub const STATE_MAX_VALUE_BYTES: usize = 512 * 1024;
/// Maximum raw canonical Norito key-payload bytes accepted by V1 `StateMap` paths.
pub const STATE_MAP_MAX_KEY_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 bytes in the canonical `Name` used as a V1 `StateMap` base.
pub const STATE_MAP_MAX_BASE_BYTES: usize = iroha_model_base::name::MAX_NAME_BYTES;
/// Conservative maximum canonical Norito `Name` frame accepted for a V1 `StateMap` base.
pub const STATE_MAP_MAX_BASE_FRAME_BYTES: usize = STATE_MAP_MAX_BASE_BYTES
    + norito::core::Header::SIZE
    + (core::mem::align_of::<u64>() - 1)
    + core::mem::size_of::<u64>();
/// Maximum encoded `Vec<StatePath>` page accepted by `STATE_MAP_KEY_AT`.
pub const STATE_MAP_MAX_PAGE_BYTES: usize = 1024 * 1024;
/// Return payload length for a pointer-ABI TLV.
///
/// Args: r10 = &TLV Ret: r10 = payload length (u64)
pub const SYSCALL_TLV_LEN: u32 = 0x77;
/// JSON object field getters.
///
/// All JSON_GET_* syscalls return a compiler-owned `Option<T>` sum handle.
/// Only a key absent from the JSON object returns `Option::none`. A non-object
/// root, or a present field whose JSON value is not the getter's exact
/// canonical type (for example a JSON number where `JSON_GET_INT` requires a
/// canonical decimal string), traps with `DecodeError`, so malformed input never
/// reads as absent.
///
/// Args: r10 = &Json, r11 = &Name key
/// Ret:  r10 = `Option<T>` sum handle whose active payload is one ABI word.
/// Active payload: one `&Json` pointer.
pub const SYSCALL_JSON_GET_JSON: u32 = 0x79;
/// Active payload: one `&Name` pointer.
pub const SYSCALL_JSON_GET_NAME: u32 = 0x7A;
/// Active payload: one `&AccountId` pointer.
pub const SYSCALL_JSON_GET_ACCOUNT_ID: u32 = 0x7B;
/// Active payload: one `&NftId` pointer.
pub const SYSCALL_JSON_GET_NFT_ID: u32 = 0x7C;
/// Active payload: one `&Blob` pointer containing decoded lowercase `0x` hex bytes.
pub const SYSCALL_JSON_GET_BLOB_HEX: u32 = 0x7D;
/// Active payload: one `&AssetDefinitionId` pointer.
pub const SYSCALL_JSON_GET_ASSET_DEFINITION_ID: u32 = 0x80;
/// Construct an empty JSON object.
///
/// Args: none Ret: r10 = host-owned &Json
pub const SYSCALL_JSON_OBJECT: u32 = 0x81;
/// Insert or replace an integer field in a JSON object.
///
/// Args: r10 = &Json object, r11 = &Name key, r12 = value (i64 as u64) Ret: r10 = host-owned &Json
pub const SYSCALL_JSON_SET_I64: u32 = 0x82;
/// Insert or replace an account-id field in a JSON object using canonical string encoding.
///
/// Args: r10 = &Json object, r11 = &Name key, r12 = &AccountId Ret: r10 = host-owned &Json
pub const SYSCALL_JSON_SET_ACCOUNT_ID: u32 = 0x83;
/// Build a state path from a base Name and a NoritoBytes key by appending
/// `"/" + lowercase_hex(payload)`.
///
/// The encoding is injective and its lexical order is the unsigned bytewise order of canonical
/// Norito key payloads. Payloads larger than [`STATE_MAP_MAX_KEY_BYTES`] are rejected.
///
/// Args: r10 = &Name base, r11 = &NoritoBytes key
/// Ret:  r10 = host-owned &NoritoBytes(canonical Norito StatePath)
pub const SYSCALL_BUILD_PATH_KEY_NORITO: u32 = 0x56;
/// JSON <-> NoritoBytes helpers (developer convenience):
/// ENCODE_JSON: r10 = &Json -> r10 = &NoritoBytes (minified JSON bytes)
pub const SYSCALL_JSON_ENCODE: u32 = 0x57;
/// DECODE_JSON: r10 = &NoritoBytes (JSON bytes) -> r10 = &Json (minified)
pub const SYSCALL_JSON_DECODE: u32 = 0x58;
/// Schema-based Norito encode: r10 = &Name schema, r11 = &Json value -> r10 = &NoritoBytes
pub const SYSCALL_SCHEMA_ENCODE: u32 = 0x59;
/// Schema-based Norito decode: r10 = &Name schema, r11 = &NoritoBytes -> r10 = &Json
pub const SYSCALL_SCHEMA_DECODE: u32 = 0x5A;
/// Schema info: r10 = &Name schema -> r10 = &Json {"id":"<hex>", "version":N}
pub const SYSCALL_SCHEMA_INFO: u32 = 0x5B;
/// Decode a canonical Norito-framed `Name` from `NoritoBytes` and return a host-owned `&Name` TLV.
///
/// Args: r10 = &NoritoBytes (canonical Norito `Name` frame) Ret: r10 = host-owned &Name
pub const SYSCALL_NAME_DECODE: u32 = 0x5C;
/// Encode a pointer-ABI TLV into NoritoBytes by copying its canonical envelope.
///
/// Numeric Int, Decimal, and Quantity frames are checked before publication.
///
/// Args: r10 = &PointerType::<T>
/// Ret:  r10 = &NoritoBytes(payload = complete TLV bytes)
pub const SYSCALL_POINTER_TO_NORITO: u32 = 0x5D;
/// Decode a NoritoBytes payload produced by [`SYSCALL_POINTER_TO_NORITO`] back into the
/// original pointer-ABI TLV. Expects the payload to begin with the canonical TLV header
/// `(type_id, version, len, payload…)`. Numeric frames must be canonical and
/// within their nominal V1 domains. Expected numeric types require a matching
/// envelope and reject null input.
///
/// Args: r10 = &NoritoBytes, r11 = expected pointer type id (u16)
/// Ret:  r10 = &PointerType::<T>
pub const SYSCALL_POINTER_FROM_NORITO: u32 = 0x5E;
/// Compare two pointer-ABI TLVs for deep equality by content (header + payload).
///
/// Args: r10 = &TLV, r11 = &TLV Ret: r10 = 1 if equal, 0 if not
pub const SYSCALL_TLV_EQ: u32 = 0x5F;
/// Roles and permissions.
pub const SYSCALL_CREATE_ROLE: u32 = 0x30;
pub const SYSCALL_DELETE_ROLE: u32 = 0x31;
pub const SYSCALL_GRANT_ROLE: u32 = 0x32;
pub const SYSCALL_REVOKE_ROLE: u32 = 0x33;
pub const SYSCALL_GRANT_PERMISSION: u32 = 0x34;
pub const SYSCALL_REVOKE_PERMISSION: u32 = 0x35;
/// Grant the current immutable contract address's declared instance permission.
///
/// Args: r10 = &AccountId, r11 = &Name (declared instance permission).
pub const SYSCALL_GRANT_CONTRACT_PERMISSION: u32 = 0x36;
/// Revoke the current immutable contract address's declared instance permission.
///
/// Args: r10 = &AccountId, r11 = &Name (declared instance permission).
pub const SYSCALL_REVOKE_CONTRACT_PERMISSION: u32 = 0x37;
/// Triggers.
pub const SYSCALL_CREATE_TRIGGER: u32 = 0x40;
pub const SYSCALL_REMOVE_TRIGGER: u32 = 0x41;
pub const SYSCALL_SET_TRIGGER_ENABLED: u32 = 0x42;
/// Governance kill-switch for contract instances.
pub const SYSCALL_DEACTIVATE_CONTRACT_INSTANCE: u32 = 0x43;
/// Governance removal of stored smart contract bytecode.
pub const SYSCALL_REMOVE_SMART_CONTRACT_BYTES: u32 = 0x44;
/// Governance registration of smart contract metadata (manifest only).
pub const SYSCALL_REGISTER_SMART_CONTRACT_CODE: u32 = 0x45;
/// Governance registration of compiled contract bytecode.
pub const SYSCALL_REGISTER_SMART_CONTRACT_BYTES: u32 = 0x46;
/// Governance activation of a contract instance binding.
pub const SYSCALL_ACTIVATE_CONTRACT_INSTANCE: u32 = 0x47;
/// Zero-knowledge mode helpers. Commit two opaque typed private numeric inputs without truncating
/// either projection or the compressed Pedersen point.
///
/// Args: r10 = private `&Int|&Decimal|&Quantity` value,
/// r11 = private `&Int|&Decimal|&Quantity` blinding input.
/// Ret: r10 = public `&Int` containing the complete 48-byte compressed point.
pub const SYSCALL_PRIVATE_NUMERIC_VALCOM: u32 = 0xF8;
pub const SYSCALL_GET_ACCOUNT_BALANCE: u32 = 0xF9;
pub const SYSCALL_VERIFY_SIGNATURE: u32 = 0xFC;
/// Retrieve one bounded typed private numeric input in ZK mode.
///
/// Args: r10 = input index, r11 = [`crate::private_input::PrivateInputKindV1`] tag.
/// Ret: r10 = opaque private `&Int|&Decimal|&Quantity` HEAP TLV.
pub const SYSCALL_GET_PRIVATE_INPUT: u32 = 0xFD;
pub const SYSCALL_COMMIT_OUTPUT: u32 = 0xFE;
// ZK verification and state-read syscalls (pointer-ABI NoritoBytes payloads)
/// Verify a ballot proof for an election (no state mutation).
pub const SYSCALL_ZK_VOTE_VERIFY_BALLOT: u32 = 0x60;
/// Verify a tally proof for an election (no state mutation).
pub const SYSCALL_ZK_VOTE_VERIFY_TALLY: u32 = 0x61;
/// Read recent Merkle roots for an asset's shielded ledger.
pub const SYSCALL_ZK_ROOTS_GET: u32 = 0x62;
/// Read finalized tally for an election, if present.
pub const SYSCALL_ZK_VOTE_GET_TALLY: u32 = 0x63;
/// Batch verification of Halo2 OpenVerify envelopes.
pub const SYSCALL_ZK_VERIFY_BATCH: u32 = 0x64;
/// Verify a BLS-based VRF proof and return the 32-byte output in a Blob TLV.
///
/// Args:
/// - r10 = &Blob input
/// - r11 = &Blob public key (BLS compressed bytes; variant-dependent size)
/// - r12 = &Blob proof (BLS signature bytes; variant-dependent size)
/// - r13 = variant code (1 = BLS Normal, 2 = BLS Small)
///
/// Return:
/// - On success, `r10` = pointer to `&Blob` TLV with 32-byte VRF output.
/// - On failure (bad inputs or verify), `r10 = 0`.
pub const SYSCALL_VRF_VERIFY: u32 = 0x66;
/// Batch VRF verification: verify multiple tuples and return a Norito-encoded
/// vector of 32-byte outputs on success.
pub const SYSCALL_VRF_VERIFY_BATCH: u32 = 0x67;
/// Read the exact committed VRF epoch seed from world state.
///
/// Args: `r10 = epoch:u64` (public).
/// Return: `r10 = &Blob(seed[32])`, or zero when that exact epoch is absent.
/// `r11` is unchanged. There is no latest-epoch fallback or guest status channel.
pub const SYSCALL_VRF_EPOCH_SEED: u32 = 0x7E;
/// Hardware and proof generation helpers.
/// Return a deterministic, self-reported Norito-encoded execution summary.
pub const SYSCALL_EXECUTION_SUMMARY: u32 = 0xF4;
/// Increase heap size by the number of bytes in `x10`.
pub const SYSCALL_GROW_HEAP: u32 = 0xF5;
/// Verify a Norito-encoded OpenVerifyEnvelope against the on-chain verifying-key registry.
pub const SYSCALL_VERIFY_PROOF: u32 = 0xF6;
/// Write the Merkle path for address `x10` to memory at `x11`. Optional: if `x12 != 0`, write the
/// current Merkle root to the 32-byte buffer at `x12`.
pub const SYSCALL_GET_MERKLE_PATH: u32 = 0xF7;
/// Write a compact Merkle proof for address `x10` to memory at `x11` using the layout: `[u8
/// depth][u32 dirs_le][u32 count][count*32 siblings]`. If `x12 != 0`, cap the depth to `min(x12,
/// 32)`. If `x13 != 0`, write the current 32-byte Merkle root to `x13`.
pub const SYSCALL_GET_MERKLE_COMPACT: u32 = 0xFA;
/// Write a compact Merkle proof for the register leaf at index `x10` to memory
/// at `x11` using the same layout as `GET_MERKLE_COMPACT`. If `x12 != 0`, cap
/// depth; if `x13 != 0`, write the 32-byte register Merkle root to `x13`.
pub const SYSCALL_GET_REGISTER_MERKLE_COMPACT: u32 = 0xFF;
/// Compute SM3 hash of a blob (`&Blob` -> `&Blob`).
pub const SYSCALL_SM3_HASH: u32 = 0x90;
/// Verify an SM2 signature (`&Blob` message, `&Blob` signature, `&Blob` public key, optional `&Blob` distid).
pub const SYSCALL_SM2_VERIFY: u32 = 0x91;
/// SM4-GCM encrypt: returns ciphertext||tag in Blob TLV.
pub const SYSCALL_SM4_GCM_SEAL: u32 = 0x92;
/// SM4-GCM decrypt: returns plaintext Blob TLV or 0 on failure.
pub const SYSCALL_SM4_GCM_OPEN: u32 = 0x93;
/// SM4-CCM encrypt: returns ciphertext||tag in Blob TLV.
pub const SYSCALL_SM4_CCM_SEAL: u32 = 0x94;
/// SM4-CCM decrypt: returns plaintext Blob TLV or 0 on failure.
pub const SYSCALL_SM4_CCM_OPEN: u32 = 0x95;
/// Compute SHA-256 hash of a blob (`&Blob` -> `&Blob`).
pub const SYSCALL_SHA256_HASH: u32 = 0x96;
/// Compute SHA3-256 hash of a blob (`&Blob` -> `&Blob`).
pub const SYSCALL_SHA3_HASH: u32 = 0x97;
/// Compute raw Blake2b-256 hash of a blob (`&Blob` -> `&Blob`).
pub const SYSCALL_BLAKE2B256_HASH: u32 = 0x98;
/// Compute Keccak-256 hash of a blob (`&Blob` -> `&Blob`).
pub const SYSCALL_KECCAK256_HASH: u32 = 0x99;
/// Compute Iroha's canonical ledger hash (`Hash::new`) of a blob (`&Blob` -> `&Blob`).
pub const SYSCALL_IROHA_HASH: u32 = 0x9A;
/// Developer helper: validate a public TLV and return a host-usable pointer.
///
/// Expects `x10` to hold a pointer to a valid public TLV. INPUT and allocated-HEAP host results are
/// retained in place. Immutable program literals are materialized in the host arena (INPUT when
/// space remains, otherwise allocated HEAP). Stack/output, private, unallocated, malformed, and
/// ABI-disallowed envelopes are rejected.
pub const SYSCALL_INPUT_PUBLISH_TLV: u32 = 0xE0;
// Smart-contract host shims (development API)
/// Execute an operation-tagged instruction from canonical `&NoritoBytes(InstructionBox)`.
pub const SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION: u32 = 0xA0;
/// `r11` operation tag authorizing a decoded `SubmitBallot` instruction for syscall `0xA0`.
pub const SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT: u64 = 1;
/// Execute a query from canonical `&NoritoBytes(QueryRequest)`.
pub const SYSCALL_SMARTCONTRACT_EXECUTE_QUERY: u32 = 0xA1;
/// Convenience syscall used by samples: create one NFT per known account.
pub const SYSCALL_CREATE_NFTS_FOR_ALL_USERS: u32 = 0xA2;
/// Set SmartContract execution depth parameter to the value in `x10`.
/// Development/testing helper for trigger samples.
pub const SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH: u32 = 0xA3;
/// Get the current authority as a host-owned `&AccountId` pointer in `x10`.
pub const SYSCALL_GET_AUTHORITY: u32 = 0xA4;
/// Execute subscription billing based on trigger metadata and subscription state.
pub const SYSCALL_SUBSCRIPTION_BILL: u32 = 0xA5;
/// Record subscription usage from trigger args payload.
pub const SYSCALL_SUBSCRIPTION_RECORD_USAGE: u32 = 0xA6;
/// Resolve a canonical alias literal (for example `merchant@centralbank`) to the current AccountId.
pub const SYSCALL_RESOLVE_ACCOUNT_ALIAS: u32 = 0xA7;
/// Get the deterministic logical execution time in Unix milliseconds.
///
/// Production hosts bind this to signed transaction creation time for
/// transaction contract calls and to block-header time for trigger calls.
pub const SYSCALL_CURRENT_TIME_MS: u32 = 0xA8;
/// Call an admitted deployed contract through an immutable typed interface binding.
/// Args: r10 = &Blob(contract_address), r11 = &NoritoBytes(ContractCallBindingV1),
/// r12 = argument table base, r13 = exact argument words, r14 = result table base,
/// r15 = exact result words. The binding commits the full code hash and CNTR ordinal.
/// The authenticated argument/return schemas own both tables; no raw selector is accepted.
pub const SYSCALL_CALL_CONTRACT: u32 = 0xA9;
/// Emit one declared native event: r10 = event ordinal, r11 = public word-table base,
/// r12 = exact schema word count. The runtime authenticates the declaration and origin.
pub const SYSCALL_EMIT_CONTRACT_EVENT: u32 = 0xAA;
// IDs 0xAB through 0xAF are intentionally unassigned.
/// Begin an atomic cross-transaction (AXT) envelope.
pub const SYSCALL_AXT_BEGIN: u32 = 0xB0;
/// Declare a DS touch within an active AXT.
pub const SYSCALL_AXT_TOUCH: u32 = 0xB1;
/// Commit the active AXT envelope if all invariants hold.
pub const SYSCALL_AXT_COMMIT: u32 = 0xB2;
/// Verify a DS proof bundle inside an AXT.
pub const SYSCALL_VERIFY_DS_PROOF: u32 = 0xB3;
// 0xB4 is unassigned in ABI V1. Signed anchored spends are carried by
// AxtEnvelopeRecord, not by a reusable-handle VM syscall.
/// Stage one canonical issuer-signed anchored spend inside the active AXT envelope.
pub const SYSCALL_AXT_STAGE_ANCHORED_SPEND: u32 = 0xB5;
/// Return whether `number` is one of the state-backed AXT envelope syscalls.
///
/// AXT remains available to both contract and generic ABI V1 programs when execution is bound to a
/// live world-state snapshot. State-free tools use this predicate to reject the whole envelope
/// surface before execution instead of running against an implicit allow-all policy.
#[must_use]
pub const fn is_axt_syscall(number: u32) -> bool {
    matches!(
        number,
        SYSCALL_AXT_BEGIN
            | SYSCALL_AXT_TOUCH
            | SYSCALL_AXT_COMMIT
            | SYSCALL_VERIFY_DS_PROOF
            | SYSCALL_AXT_STAGE_ANCHORED_SPEND
    )
}
/// Open and fund a native asset escrow.
pub const SYSCALL_ESCROW_OPEN_OFFER: u32 = 0xB8;
/// Accept an open native asset escrow.
pub const SYSCALL_ESCROW_ACCEPT: u32 = 0xB9;
/// Mark accepted escrow off-chain payment as sent.
pub const SYSCALL_ESCROW_MARK_PAYMENT_SENT: u32 = 0xBA;
/// Release a paid escrow to the buyer.
pub const SYSCALL_ESCROW_RELEASE: u32 = 0xBB;
/// Cancel and refund an escrow before payment is marked.
pub const SYSCALL_ESCROW_CANCEL: u32 = 0xBC;
/// Open a dispute for court moderation.
pub const SYSCALL_ESCROW_OPEN_DISPUTE: u32 = 0xBD;
/// Resolve a disputed escrow with a buyer/seller split.
pub const SYSCALL_ESCROW_RESOLVE_DISPUTE: u32 = 0xBE;
// ID 0xBF is intentionally unassigned.
/// Soracloud runtime host surface.
/// Read committed service-state metadata for handler-local execution.
pub const SYSCALL_SORACLOUD_READ_COMMITTED_STATE: u32 = 0xC0;
/// Emit a deterministic service-state mutation staged for authoritative write-back.
pub const SYSCALL_SORACLOUD_EMIT_STATE_MUTATION: u32 = 0xC1;
/// Emit an outbound Soracloud mailbox message.
pub const SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE: u32 = 0xC2;
/// Append deterministic runtime journal material.
pub const SYSCALL_SORACLOUD_APPEND_JOURNAL: u32 = 0xC3;
/// Publish a checkpoint artifact.
pub const SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT: u32 = 0xC4;
/// Read authoritative service config material exposed through the Soracloud host.
pub const SYSCALL_SORACLOUD_READ_CONFIG: u32 = 0xC8;
/// Read authoritative service secret envelopes exposed through the Soracloud host.
pub const SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE: u32 = 0xC9;
/// Execute an arbitrary Norito-encoded read-only query request.
pub const SYSCALL_QUERY_EXECUTE_NORITO: u32 = 0x01_0000;
/// Read one projected core-ledger entity by stable [`CoreQueryEntityTagV1`].
///
/// [`CoreQueryEntityTagV1`]: crate::core_query::CoreQueryEntityTagV1
pub const SYSCALL_CORE_QUERY_GET: u32 = 0x01_0001;
/// Read one bounded page of projected core-ledger entities by stable [`CoreQueryEntityTagV1`].
///
/// `r13` is zero for an unfiltered page or an `AccountId` pointer for asset pages.
/// A nonzero owner filter is invalid for every other entity tag.
///
/// [`CoreQueryEntityTagV1`]: crate::core_query::CoreQueryEntityTagV1
pub const SYSCALL_CORE_QUERY_PAGE: u32 = 0x01_0002;
/// Read one runtime/system/custom parameter from `r10=&Name`.
pub const SYSCALL_QUERY_GET_PARAMETER: u32 = 0x01_0006;
/// Read one contract manifest from `r10=&NoritoBytes(ContractArtifactId)`.
pub const SYSCALL_QUERY_GET_CONTRACT_MANIFEST: u32 = 0x01_0007;
/// Read one contract instance from `r10=&NoritoBytes(ContractAddress)` or `r10=&Name(alias)`.
pub const SYSCALL_QUERY_GET_CONTRACT_INSTANCE: u32 = 0x01_0008;
/// Return the current chain id as a pointer-ABI `Blob` TLV.
pub const SYSCALL_SYSVAR_CHAIN_ID: u32 = 0x01_0020;
/// Return the current block height in `r10`.
pub const SYSCALL_SYSVAR_BLOCK_HEIGHT: u32 = 0x01_0021;
/// Return the current block timestamp in milliseconds in `r10`.
pub const SYSCALL_SYSVAR_BLOCK_TIME_MS: u32 = 0x01_0022;
/// Return the current authority as an `AccountId` TLV.
pub const SYSCALL_SYSVAR_AUTHORITY: u32 = 0x01_0023;
/// Return the canonical contract address literal as a Blob TLV, or zero outside contract scope.
pub const SYSCALL_SYSVAR_CONTRACT_ADDRESS: u32 = 0x01_0024;
/// Return the current contract entrypoint name as a `Blob` TLV, or zero when not in a contract scope.
pub const SYSCALL_SYSVAR_ENTRYPOINT: u32 = 0x01_0025;
/// Return the immutable subject account of the currently executing deployed contract.
///
/// The result is an `AccountId` TLV in `r10`. Calls outside a deployed-contract
/// scope fail closed instead of falling back to transaction authority.
pub const SYSCALL_SYSVAR_CONTRACT_SUBJECT: u32 = 0x01_0027;
/// Retag one public bytes carrier as canonical `NoritoBytes`.
///
/// Args: r10 = a validated public `&Blob` or `&NoritoBytes` TLV.
/// Ret: r10 = a fresh host-owned `&NoritoBytes` TLV with the identical payload.
/// Null, malformed, disallowed, and non-bytes pointer types are rejected.
pub const SYSCALL_NORMALIZE_NORITO_BYTES: u32 = 0x01_0028;
/// Decode a complete schema-bound public argument record.
///
/// Args: r10 = `&NoritoBytes(EntrypointArgumentRecordV1)`;
/// r11 = `&NoritoBytes(EntrypointArgumentSchemaV1)`.
/// Ret: r10 = aligned owned-HEAP table base (zero for no arguments), r11 = exact word count.
/// Slots contain declaration-ordered flattened scalar bits, aggregate handles, or validated
/// pointer-ABI addresses. Public root invocation preparation is performed by the interpreter.
pub const SYSCALL_DECODE_ARGUMENT_RECORD: u32 = 0x01_0026;
/// Atomically set native incoming/outgoing availability for one account/asset pair.
///
/// Args: `r10 = &AccountId`, `r11 = &AssetDefinitionId`, `r12 = expected revision`,
/// `r13 = availability flags` (bit 0 incoming, bit 1 outgoing; reserved bits zero),
/// `r14 = &Option<string>`.
pub const SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY: u32 = 0x01_0200;
/// Set the native UTC daily outbound-transfer cap for one account/asset pair.
///
/// Args: `r10 = &AccountId`, `r11 = &AssetDefinitionId`,
/// `r12 = &Option<Quantity>`.
pub const SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT: u32 = 0x01_0201;
/// Set the native post-credit holding limit for one account/asset pair.
///
/// Args: `r10 = &AccountId`, `r11 = &AssetDefinitionId`,
/// `r12 = &Option<Quantity>`.
pub const SYSCALL_SET_ASSET_HOLDING_LIMIT: u32 = 0x01_0202;
/// Propose native alias-based account recovery with a replacement controller.
///
/// Args: `r10 = &Blob(alias literal)`, `r11 = &AccountId(replacement controller)`,
/// `r12 = request_generation` (the exact nonzero next request generation).
pub const SYSCALL_ACCOUNT_RECOVERY_PROPOSE: u32 = 0x01_0210;
/// Approve the pending native recovery request for an alias.
///
/// Args: `r10 = &Blob(alias literal)`, `r11 = request_generation` (nonzero).
pub const SYSCALL_ACCOUNT_RECOVERY_APPROVE: u32 = 0x01_0211;
/// Cancel the pending native recovery request for an alias.
///
/// Args: `r10 = &Blob(alias literal)`, `r11 = request_generation` (nonzero).
pub const SYSCALL_ACCOUNT_RECOVERY_CANCEL: u32 = 0x01_0212;
/// Finalize the pending native recovery request for an alias.
///
/// Args: `r10 = &Blob(alias literal)`, `r11 = request_generation` (nonzero).
pub const SYSCALL_ACCOUNT_RECOVERY_FINALIZE: u32 = 0x01_0213;

/// Open a controller-bound native lock from a fixed eight-word public heap table in r10.
/// Words: &Blob(key), &AccountId(source), &AccountId(destination), &AssetDefinitionId,
/// &Quantity(amount), release_until_ms:u64, cancel_not_before_ms:u64, expires_at_ms:u64.
/// Zero timestamps mean absent; the authenticated active contract supplies the controller.
pub const SYSCALL_ASSET_LOCK_OPEN: u32 = 0x01_0220;
/// Draw a controlled lock: r10=&Blob(key), r11=&Quantity(amount), r12=&Quantity(expected_remaining).
pub const SYSCALL_ASSET_LOCK_DRAWDOWN: u32 = 0x01_0221;
/// Cancel a controlled lock: r10=&Blob(key), r11=&Quantity(expected_remaining).
pub const SYSCALL_ASSET_LOCK_CANCEL: u32 = 0x01_0222;
/// Expire a controlled lock: r10=&Blob(key).
pub const SYSCALL_ASSET_LOCK_EXPIRE: u32 = 0x01_0223;
// Kotodama V1 exact numeric families. These numbers are deliberately grouped
// by value domain so admission, host dispatch, and generated SDK tables can
// classify them without depending on source-language spellings.
/// Construct an `int` from the two's-complement bits of an `i64` in `r10`.
pub const SYSCALL_INT_FROM_I64: u32 = 0x01_0100;
/// Construct an `int` from a `u64` in `r10`.
pub const SYSCALL_INT_FROM_U64: u32 = 0x01_0101;
/// Convert an `int` to `i64`; `r14` selects trap or status on range failure.
/// `r11`, `r12`, and `r13` must be zero.
pub const SYSCALL_INT_TO_I64: u32 = 0x01_0102;
/// Convert an `int` to `u64`; `r14` selects trap or status on sign/range failure.
/// `r11`, `r12`, and `r13` must be zero.
pub const SYSCALL_INT_TO_U64: u32 = 0x01_0103;
/// Checked integer negation.
pub const SYSCALL_INT_NEG: u32 = 0x01_0104;
/// Checked integer addition.
pub const SYSCALL_INT_ADD: u32 = 0x01_0105;
/// Checked integer subtraction.
pub const SYSCALL_INT_SUB: u32 = 0x01_0106;
/// Checked integer multiplication.
pub const SYSCALL_INT_MUL: u32 = 0x01_0107;
/// Integer division truncated toward zero.
pub const SYSCALL_INT_DIV: u32 = 0x01_0108;
/// Integer remainder paired with truncation-toward-zero division.
pub const SYSCALL_INT_REM: u32 = 0x01_0109;
/// Numeric integer equality.
pub const SYSCALL_INT_EQ: u32 = 0x01_010A;
/// Numeric integer inequality.
pub const SYSCALL_INT_NE: u32 = 0x01_010B;
/// Numeric integer less-than comparison.
pub const SYSCALL_INT_LT: u32 = 0x01_010C;
/// Numeric integer less-or-equal comparison.
pub const SYSCALL_INT_LE: u32 = 0x01_010D;
/// Numeric integer greater-than comparison.
pub const SYSCALL_INT_GT: u32 = 0x01_010E;
/// Numeric integer greater-or-equal comparison.
pub const SYSCALL_INT_GE: u32 = 0x01_010F;
/// Integer negation modulo `2^512`, interpreted in the signed domain.
pub const SYSCALL_INT_WRAP_NEG: u32 = 0x01_0110;
/// Integer addition modulo `2^512`, interpreted in the signed domain.
pub const SYSCALL_INT_WRAP_ADD: u32 = 0x01_0111;
/// Integer subtraction modulo `2^512`, interpreted in the signed domain.
pub const SYSCALL_INT_WRAP_SUB: u32 = 0x01_0112;
/// Integer multiplication modulo `2^512`, interpreted in the signed domain.
pub const SYSCALL_INT_WRAP_MUL: u32 = 0x01_0113;
/// Floor square root of a signed 512-bit integer, rejecting negative input.
pub const SYSCALL_INT_ISQRT: u32 = 0x01_0114;
/// Checked full-width integer absolute value.
pub const SYSCALL_INT_ABS: u32 = 0x01_0115;
/// Smaller of two full-width signed integers.
pub const SYSCALL_INT_MIN: u32 = 0x01_0116;
/// Larger of two full-width signed integers.
pub const SYSCALL_INT_MAX: u32 = 0x01_0117;
/// Mathematical ceiling of a full-width integer quotient.
pub const SYSCALL_INT_DIV_CEIL: u32 = 0x01_0118;
/// Nonnegative greatest common divisor of full-width integers.
pub const SYSCALL_INT_GCD: u32 = 0x01_0119;
/// Truncating integer mean with a full-width intermediate sum.
pub const SYSCALL_INT_MEAN: u32 = 0x01_011A;
/// Convert an `int` to an exact scale-zero `decimal`.
pub const SYSCALL_DECIMAL_FROM_INT: u32 = 0x01_0120;
/// Checked decimal negation.
pub const SYSCALL_DECIMAL_NEG: u32 = 0x01_0121;
/// Exact decimal addition.
pub const SYSCALL_DECIMAL_ADD: u32 = 0x01_0122;
/// Exact decimal subtraction.
pub const SYSCALL_DECIMAL_SUB: u32 = 0x01_0123;
/// Exact decimal multiplication; canonical results requiring scale above 28 fail.
pub const SYSCALL_DECIMAL_MUL: u32 = 0x01_0124;
/// Exact finite decimal division at the denominator's proven minimum scale.
pub const SYSCALL_DECIMAL_DIV_EXACT: u32 = 0x01_0125;
/// Decimal division rounded at an explicit output scale.
pub const SYSCALL_DECIMAL_DIV_ROUND: u32 = 0x01_0126;
/// Numeric decimal equality.
pub const SYSCALL_DECIMAL_EQ: u32 = 0x01_0127;
/// Numeric decimal inequality.
pub const SYSCALL_DECIMAL_NE: u32 = 0x01_0128;
/// Numeric decimal less-than comparison.
pub const SYSCALL_DECIMAL_LT: u32 = 0x01_0129;
/// Numeric decimal less-or-equal comparison.
pub const SYSCALL_DECIMAL_LE: u32 = 0x01_012A;
/// Numeric decimal greater-than comparison.
pub const SYSCALL_DECIMAL_GT: u32 = 0x01_012B;
/// Numeric decimal greater-or-equal comparison.
pub const SYSCALL_DECIMAL_GE: u32 = 0x01_012C;
/// Convert a scale-zero decimal to `int`; `r14` selects trap or status on inexact conversion.
/// `r11`, `r12`, and `r13` must be zero.
pub const SYSCALL_DECIMAL_TO_INT_EXACT: u32 = 0x01_012D;
/// Convert a decimal to `int` by truncating toward zero.
pub const SYSCALL_DECIMAL_TO_INT_TRUNC: u32 = 0x01_012E;
/// Convert a decimal to `int` using an explicit rounding mode.
pub const SYSCALL_DECIMAL_TO_INT_ROUND: u32 = 0x01_012F;
/// Fused decimal multiplication/division with one final explicit rounding.
/// Args: r10=value, r11=multiplier, r12=divisor, r13=int scale,
/// r14=rounding tag, r15=0. Arithmetic faults trap; r10 returns decimal.
pub const SYSCALL_DECIMAL_MUL_DIV_ROUND: u32 = 0x01_0130;
/// Convert a non-negative `int` to nominal `quantity`; `r14` selects trap or status.
/// `r11`, `r12`, and `r13` must be zero.
pub const SYSCALL_QUANTITY_FROM_INT: u32 = 0x01_0140;
/// Convert a non-negative canonical `decimal` to nominal `quantity`; `r14` selects trap or status.
/// `r11`, `r12`, and `r13` must be zero.
pub const SYSCALL_QUANTITY_FROM_DECIMAL: u32 = 0x01_0141;
/// Convert a `quantity` to the same-valued `decimal`.
pub const SYSCALL_QUANTITY_TO_DECIMAL: u32 = 0x01_0142;
/// Exact quantity addition.
pub const SYSCALL_QUANTITY_ADD: u32 = 0x01_0143;
/// Exact quantity subtraction; negative results fail with quantity underflow.
pub const SYSCALL_QUANTITY_SUB: u32 = 0x01_0144;
/// Multiply a quantity by a decimal; the result must remain non-negative.
pub const SYSCALL_QUANTITY_MUL_DECIMAL: u32 = 0x01_0145;
/// Divide a quantity by a decimal exactly; the result must remain non-negative.
pub const SYSCALL_QUANTITY_DIV_DECIMAL_EXACT: u32 = 0x01_0146;
/// Divide a quantity by a decimal using explicit scale and rounding.
pub const SYSCALL_QUANTITY_DIV_DECIMAL_ROUND: u32 = 0x01_0147;
/// Compute an exact decimal ratio of two quantities.
pub const SYSCALL_QUANTITY_RATIO_EXACT: u32 = 0x01_0148;
/// Compute a rounded decimal ratio of two quantities.
pub const SYSCALL_QUANTITY_RATIO_ROUND: u32 = 0x01_0149;
/// Numeric quantity equality.
pub const SYSCALL_QUANTITY_EQ: u32 = 0x01_014A;
/// Numeric quantity inequality.
pub const SYSCALL_QUANTITY_NE: u32 = 0x01_014B;
/// Numeric quantity less-than comparison.
pub const SYSCALL_QUANTITY_LT: u32 = 0x01_014C;
/// Numeric quantity less-or-equal comparison.
pub const SYSCALL_QUANTITY_LE: u32 = 0x01_014D;
/// Numeric quantity greater-than comparison.
pub const SYSCALL_QUANTITY_GT: u32 = 0x01_014E;
/// Numeric quantity greater-or-equal comparison.
pub const SYSCALL_QUANTITY_GE: u32 = 0x01_014F;
/// Fused quantity multiplication/division with one final explicit rounding.
/// Args: r10=quantity, r11=decimal multiplier, r12=decimal divisor,
/// r13=int scale, r14=rounding tag, r15=0. Arithmetic faults trap.
pub const SYSCALL_QUANTITY_MUL_DIV_ROUND: u32 = 0x01_0150;
/// Parse a canonical base-10 JSON string into an exact `int` pointer.
pub const SYSCALL_JSON_GET_INT: u32 = 0x01_0160;
/// Parse a canonical base-10 JSON string into an exact `decimal` pointer.
pub const SYSCALL_JSON_GET_DECIMAL: u32 = 0x01_0161;
/// Parse a canonical non-negative base-10 JSON string into a `quantity` pointer.
pub const SYSCALL_JSON_GET_QUANTITY: u32 = 0x01_0162;
/// Read a JSON string field as a Kotodama `string`.
///
/// Active payload: one `&Blob` pointer holding the string's UTF-8 bytes.
pub const SYSCALL_JSON_GET_STRING: u32 = 0x01_0166;
/// Read a JSON boolean field as a Kotodama `bool`.
///
/// Active payload: one scalar word, `1` for `true` and `0` for `false`.
pub const SYSCALL_JSON_GET_BOOL: u32 = 0x01_0167;
/// Return whether `number` belongs to the exact Kotodama V1 numeric surface.
#[must_use]
pub const fn is_numeric_v1_syscall(number: u32) -> bool {
    matches!(number, 0x01_0100..=0x01_011A | 0x01_0120..=0x01_0130 | 0x01_0140..=0x01_0150)
}
/// Construct one native JSON value from a compiler-emitted schema and flattened words.
///
/// Args: r10 = `&NoritoBytes(JsonConstructionSchemaV1)`, r11 = aligned public word-table address,
/// r12 = exact word count. Ret: r10 = `&Json`.
pub const SYSCALL_JSON_BUILD: u32 = 0x01_004E;
/// Encode a public typed value to a schema-bound canonical Norito record.
/// Args: r10=&NoritoBytes(EntrypointValueTypeV1), r11=owned public heap table,
/// r12=exact word count. Ret: r10=&Blob(EntrypointReturnRecordV1).
pub const SYSCALL_VALUE_ENCODE: u32 = 0x01_0050;
/// Concatenate two public Blob payloads; r10/r11 inputs, r10 output.
pub const SYSCALL_BLOB_CONCAT: u32 = 0x01_0051;
/// Validate Blob UTF-8; r10 returns the same pointer or zero for invalid UTF-8.
pub const SYSCALL_UTF8_VALIDATE: u32 = 0x01_0052;
/// Format a public scalar using its canonical textual representation.
/// Uses the same schema/table arguments as VALUE_ENCODE and returns a UTF-8 Blob.
pub const SYSCALL_VALUE_TO_STRING: u32 = 0x01_0053;
/// Return whether `number` is one of the canonical typed JSON getters.
#[must_use]
pub const fn is_json_getter_syscall(number: u32) -> bool {
    matches!(
        number,
        SYSCALL_JSON_GET_JSON
            | SYSCALL_JSON_GET_NAME
            | SYSCALL_JSON_GET_ACCOUNT_ID
            | SYSCALL_JSON_GET_NFT_ID
            | SYSCALL_JSON_GET_BLOB_HEX
            | SYSCALL_JSON_GET_ASSET_DEFINITION_ID
            | SYSCALL_JSON_GET_INT
            | SYSCALL_JSON_GET_DECIMAL
            | SYSCALL_JSON_GET_QUANTITY
            | SYSCALL_JSON_GET_STRING
            | SYSCALL_JSON_GET_BOOL
    )
}
/// Kotodama test-runner helper: resolve a fixture actor alias to an `AccountId` TLV.
///
/// These host-private helpers are intentionally outside [`abi_syscall_list`]. Production hosts
/// reject them, while `koto_test` opts in explicitly when it executes test-mode bytecode.
pub const SYSCALL_KOTO_TEST_ACTOR_ACCOUNT: u32 = 0x00FE_0001;
/// Kotodama test-runner helper: return a fixture actor public key as a `Blob` TLV.
pub const SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY: u32 = 0x00FE_0002;
/// Kotodama test-runner helper: sign a message with a fixture actor seed.
pub const SYSCALL_KOTO_TEST_ACTOR_SIGN: u32 = 0x00FE_0003;
/// Kotodama test-runner helper: invoke a contract entrypoint with canonical argument encoding.
///
/// `x10 = 0` selects the current caller; otherwise `x10` is a fixture actor alias TLV.
/// `x11` is the entrypoint alias, `x12` is JSON arguments, `x13` is the caller-owned
/// result table, and `x14` is its exact capacity (1..=8192 words). Successful
/// schema-bound transfer returns the table base/count in `x10`/`x11`.
/// This helper is test-only and does not change the production ABI syscall surface.
pub const SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS: u32 = 0x00FE_0004;
/// Kotodama test-runner helper: assert that an actor entrypoint invocation rejects.
pub const SYSCALL_KOTO_TEST_EXPECT_REJECT_AS: u32 = 0x00FE_0005;
/// Kotodama test-runner helper: report a failed `test::assert`/`test::assert_eq` and stop.
///
/// `x10` is a `Blob` with the compiler's canonical assertion-site record; `x11`/`x12` are the
/// actual/expected values as canonical state-value records (or zero), `x13` their schema (or
/// zero), and `x14` a dynamic message pointer (or zero). The host never returns success.
pub const SYSCALL_KOTO_TEST_ASSERT_FAILED: u32 = 0x00FE_0006;
/// Kotodama test-runner helper: set the block height reported to later seiyaku calls (`x10`).
pub const SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT: u32 = 0x00FE_0007;
/// Kotodama test-runner helper: advance the block height by `x10` blocks.
pub const SYSCALL_KOTO_TEST_ADVANCE_BLOCKS: u32 = 0x00FE_0008;
/// Kotodama test-runner helper: set the transaction time in milliseconds (`x10`).
pub const SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS: u32 = 0x00FE_0009;
/// Kotodama test-runner helper: record the source location of the next test-helper call.
///
/// `x10` is a `Blob` with the compiler's canonical call-site record; the host reports a failure of
/// the following seiyaku call or actor helper at that location.
pub const SYSCALL_KOTO_TEST_CALL_SITE: u32 = 0x00FE_000A;
/// Return whether `number` belongs to the host-private Kotodama test surface.
pub const fn is_koto_test_syscall(number: u32) -> bool {
    matches!(
        number,
        SYSCALL_KOTO_TEST_ACTOR_ACCOUNT
            | SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY
            | SYSCALL_KOTO_TEST_ACTOR_SIGN
            | SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS
            | SYSCALL_KOTO_TEST_EXPECT_REJECT_AS
            | SYSCALL_KOTO_TEST_ASSERT_FAILED
            | SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT
            | SYSCALL_KOTO_TEST_ADVANCE_BLOCKS
            | SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS
            | SYSCALL_KOTO_TEST_CALL_SITE
    )
}
/// Returns whether a syscall number is allowed for the given ABI policy.
///
/// This function centralizes the mapping between `ProgramMetadata.abi_version` and the set of
/// syscalls available to programs compiled against that ABI. Hosts should call this before
/// attempting to handle a syscall to ensure stable first-release behavior; unknown or disallowed
/// numbers must be rejected with `VMError::UnknownSyscall`.
pub fn is_syscall_allowed(policy: crate::SyscallPolicy, number: u32) -> bool {
    syscalls_for_policy(policy).binary_search(&number).is_ok()
}
/// ABI V1 syscalls that require an authenticated contract identity or its
/// durable-state namespace and are therefore unavailable to generic programs.
///
/// Generic programs are identified by the absence of a canonical `CNTR`
/// section. Keep this list strictly sorted: it is encoded into the canonical
/// ABI descriptor and is therefore consensus-visible.
pub const GENERIC_PROGRAM_DENIED_SYSCALLS_V1: &[u32] = &[
    SYSCALL_GRANT_CONTRACT_PERMISSION,
    SYSCALL_REVOKE_CONTRACT_PERMISSION,
    SYSCALL_DEACTIVATE_CONTRACT_INSTANCE,
    SYSCALL_REMOVE_SMART_CONTRACT_BYTES,
    SYSCALL_REGISTER_SMART_CONTRACT_CODE,
    SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
    SYSCALL_ACTIVATE_CONTRACT_INSTANCE,
    SYSCALL_STATE_GET,
    SYSCALL_STATE_SET,
    SYSCALL_STATE_DEL,
    SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
    SYSCALL_CALL_CONTRACT,
    SYSCALL_EMIT_CONTRACT_EVENT,
    SYSCALL_SYSVAR_CONTRACT_ADDRESS,
    SYSCALL_SYSVAR_ENTRYPOINT,
    SYSCALL_SYSVAR_CONTRACT_SUBJECT,
    SYSCALL_STATE_HAS,
    SYSCALL_STATE_LEN,
    SYSCALL_STATE_COUNT,
    SYSCALL_STATE_SCAN,
    SYSCALL_ASSET_LOCK_OPEN,
    SYSCALL_ASSET_LOCK_DRAWDOWN,
    SYSCALL_ASSET_LOCK_CANCEL,
    SYSCALL_ASSET_LOCK_EXPIRE,
];
/// Return whether an ABI syscall is available to a contract-less program.
///
/// The result is false both for syscalls outside the selected ABI and for the
/// ABI-bound generic-program denylist. Admission and host dispatch must both
/// apply this function so a rejected program cannot produce side effects.
#[must_use]
pub fn is_generic_program_syscall_allowed(policy: crate::SyscallPolicy, number: u32) -> bool {
    is_syscall_allowed(policy, number)
        && match policy {
            crate::SyscallPolicy::AbiV1 => GENERIC_PROGRAM_DENIED_SYSCALLS_V1
                .binary_search(&number)
                .is_err(),
        }
}
/// Host-state access conservatively implied by an ABI syscall.
///
/// This classification is intentionally independent of compiler metadata. It
/// is used by admission and the parallel scheduler to reject or serialize
/// bytecode whose declared access set cannot be proven from its instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallAccess {
    /// The call only touches VM-local data or immutable execution context.
    None,
    /// Contract-owned durable state read.
    StateRead,
    /// Contract-owned durable state write.
    StateWrite,
    /// Ledger/world-state read with arguments not proven by the bytecode scanner.
    LedgerRead,
    /// Ledger/world-state write with arguments not proven by the bytecode scanner.
    LedgerWrite,
    /// Nested, opaque, or externally routed access; serialize conservatively.
    Dynamic,
}
/// Return the explicitly registered host-state access class for a syscall.
///
/// Unlike [`syscall_access`], this function has no conservative fallback. Host metering uses it to
/// distinguish a deliberately classified dynamic syscall from a newly allowed syscall whose
/// security metadata was never registered. Such a syscall must fail closed during preparation.
#[must_use]
pub const fn registered_syscall_access(number: u32) -> Option<SyscallAccess> {
    if is_numeric_v1_syscall(number) || number == SYSCALL_JSON_BUILD {
        return Some(SyscallAccess::None);
    }
    if matches!(
        number,
        SYSCALL_STATE_MAP_KEY_AT
            | SYSCALL_VALUE_ENCODE
            | SYSCALL_BLOB_CONCAT
            | SYSCALL_UTF8_VALIDATE
            | SYSCALL_VALUE_TO_STRING
            | SYSCALL_STATE_VALUE_ENCODE
            | SYSCALL_STATE_VALUE_DECODE
            | SYSCALL_STATE_PATH_FROM_NAME
    ) {
        return Some(SyscallAccess::None);
    }
    if matches!(
        number,
        SYSCALL_STATE_GET
            | SYSCALL_STATE_HAS
            | SYSCALL_STATE_LEN
            | SYSCALL_STATE_COUNT
            | SYSCALL_STATE_SCAN
    ) {
        return Some(SyscallAccess::StateRead);
    }
    if matches!(number, SYSCALL_STATE_SET | SYSCALL_STATE_DEL) {
        return Some(SyscallAccess::StateWrite);
    }
    if matches!(
        number,
        SYSCALL_SMARTCONTRACT_EXECUTE_QUERY
            | SYSCALL_QUERY_EXECUTE_NORITO
            | SYSCALL_CORE_QUERY_GET
            | SYSCALL_CORE_QUERY_PAGE
            | SYSCALL_QUERY_GET_PARAMETER
            | SYSCALL_QUERY_GET_CONTRACT_MANIFEST
            | SYSCALL_QUERY_GET_CONTRACT_INSTANCE
            | SYSCALL_GET_ACCOUNT_BALANCE
            | SYSCALL_RESOLVE_ACCOUNT_ALIAS
            | SYSCALL_VRF_EPOCH_SEED
            | SYSCALL_ZK_ROOTS_GET
            | SYSCALL_ZK_VOTE_GET_TALLY
            | SYSCALL_SORACLOUD_READ_COMMITTED_STATE
            | SYSCALL_SORACLOUD_READ_CONFIG
            | SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE
    ) {
        return Some(SyscallAccess::LedgerRead);
    }
    if matches!(
        number,
        SYSCALL_REGISTER_DOMAIN
            | SYSCALL_UNREGISTER_DOMAIN
            | SYSCALL_TRANSFER_DOMAIN
            | SYSCALL_REGISTER_PEER
            | SYSCALL_UNREGISTER_PEER
            | SYSCALL_REGISTER_ACCOUNT
            | SYSCALL_UNREGISTER_ACCOUNT
            | SYSCALL_ADD_SIGNATORY
            | SYSCALL_REMOVE_SIGNATORY
            | SYSCALL_SET_ACCOUNT_QUORUM
            | SYSCALL_SET_ACCOUNT_DETAIL
            | SYSCALL_REGISTER_ASSET
            | SYSCALL_UNREGISTER_ASSET
            | SYSCALL_MINT_ASSET
            | SYSCALL_BURN_ASSET
            | SYSCALL_TRANSFER_V1
            | SYSCALL_TRANSFER_V1_BATCH_BEGIN
            | SYSCALL_TRANSFER_V1_BATCH_END
            | SYSCALL_TRANSFER_V1_BATCH_APPLY
            | SYSCALL_TRANSFER_ASSET_SCOPED
            | SYSCALL_NFT_MINT_ASSET
            | SYSCALL_NFT_TRANSFER_ASSET
            | SYSCALL_NFT_SET_METADATA
            | SYSCALL_NFT_BURN_ASSET
            | SYSCALL_CREATE_ROLE
            | SYSCALL_DELETE_ROLE
            | SYSCALL_GRANT_ROLE
            | SYSCALL_REVOKE_ROLE
            | SYSCALL_GRANT_PERMISSION
            | SYSCALL_REVOKE_PERMISSION
            | SYSCALL_GRANT_CONTRACT_PERMISSION
            | SYSCALL_REVOKE_CONTRACT_PERMISSION
            | SYSCALL_CREATE_TRIGGER
            | SYSCALL_REMOVE_TRIGGER
            | SYSCALL_SET_TRIGGER_ENABLED
            | SYSCALL_REGISTER_SMART_CONTRACT_CODE
            | SYSCALL_REGISTER_SMART_CONTRACT_BYTES
            | SYSCALL_ACTIVATE_CONTRACT_INSTANCE
            | SYSCALL_DEACTIVATE_CONTRACT_INSTANCE
            | SYSCALL_REMOVE_SMART_CONTRACT_BYTES
            | SYSCALL_ZK_VOTE_VERIFY_BALLOT
            | SYSCALL_ZK_VOTE_VERIFY_TALLY
            | SYSCALL_ZK_VERIFY_BATCH
            | SYSCALL_AXT_BEGIN
            | SYSCALL_AXT_TOUCH
            | SYSCALL_AXT_COMMIT
            | SYSCALL_VERIFY_DS_PROOF
            | SYSCALL_AXT_STAGE_ANCHORED_SPEND
            | SYSCALL_ESCROW_OPEN_OFFER
            | SYSCALL_ESCROW_ACCEPT
            | SYSCALL_ESCROW_MARK_PAYMENT_SENT
            | SYSCALL_ESCROW_RELEASE
            | SYSCALL_ESCROW_CANCEL
            | SYSCALL_ESCROW_OPEN_DISPUTE
            | SYSCALL_ESCROW_RESOLVE_DISPUTE
            | SYSCALL_SUBSCRIPTION_BILL
            | SYSCALL_SUBSCRIPTION_RECORD_USAGE
            | SYSCALL_SORACLOUD_EMIT_STATE_MUTATION
            | SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE
            | SYSCALL_SORACLOUD_APPEND_JOURNAL
            | SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT
            | SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY
            | SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT
            | SYSCALL_SET_ASSET_HOLDING_LIMIT
            | SYSCALL_ACCOUNT_RECOVERY_PROPOSE
            | SYSCALL_ACCOUNT_RECOVERY_APPROVE
            | SYSCALL_ACCOUNT_RECOVERY_CANCEL
            | SYSCALL_ACCOUNT_RECOVERY_FINALIZE
            | SYSCALL_ASSET_LOCK_OPEN
            | SYSCALL_ASSET_LOCK_DRAWDOWN
            | SYSCALL_ASSET_LOCK_CANCEL
            | SYSCALL_ASSET_LOCK_EXPIRE
    ) {
        return Some(SyscallAccess::LedgerWrite);
    }
    if matches!(
        number,
        SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION
            | SYSCALL_CALL_CONTRACT
            | SYSCALL_EMIT_CONTRACT_EVENT
            | SYSCALL_CREATE_NFTS_FOR_ALL_USERS
            | SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH
            | SYSCALL_COMMIT_OUTPUT
    ) {
        return Some(SyscallAccess::Dynamic);
    }
    if matches!(
        number,
        SYSCALL_EXIT
            | SYSCALL_ABORT
            | SYSCALL_CONTRACT_ABORT
            | SYSCALL_DEBUG_PRINT
            | SYSCALL_DEBUG_LOG
            | SYSCALL_ALLOC
            | SYSCALL_GROW_HEAP
            | SYSCALL_GET_PUBLIC_INPUT
            | SYSCALL_GET_PRIVATE_INPUT
            | SYSCALL_PRIVATE_NUMERIC_VALCOM
            | SYSCALL_VERIFY_SIGNATURE
            | SYSCALL_INPUT_PUBLISH_TLV
            | SYSCALL_SM3_HASH
            | SYSCALL_SM2_VERIFY
            | SYSCALL_SM4_GCM_SEAL
            | SYSCALL_SM4_GCM_OPEN
            | SYSCALL_SM4_CCM_SEAL
            | SYSCALL_SM4_CCM_OPEN
            | SYSCALL_SHA256_HASH
            | SYSCALL_SHA3_HASH
            | SYSCALL_BLAKE2B256_HASH
            | SYSCALL_KECCAK256_HASH
            | SYSCALL_IROHA_HASH
            | SYSCALL_EXECUTION_SUMMARY
            | SYSCALL_VERIFY_PROOF
            | SYSCALL_GET_MERKLE_PATH
            | SYSCALL_GET_MERKLE_COMPACT
            | SYSCALL_GET_REGISTER_MERKLE_COMPACT
            | SYSCALL_JSON_ENCODE
            | SYSCALL_JSON_DECODE
            | SYSCALL_TLV_LEN
            | SYSCALL_JSON_GET_JSON
            | SYSCALL_JSON_GET_NAME
            | SYSCALL_JSON_GET_ACCOUNT_ID
            | SYSCALL_JSON_GET_NFT_ID
            | SYSCALL_JSON_GET_BLOB_HEX
            | SYSCALL_JSON_GET_ASSET_DEFINITION_ID
            | SYSCALL_JSON_GET_INT
            | SYSCALL_JSON_GET_DECIMAL
            | SYSCALL_JSON_GET_QUANTITY
            | SYSCALL_JSON_GET_STRING
            | SYSCALL_JSON_GET_BOOL
            | SYSCALL_JSON_OBJECT
            | SYSCALL_JSON_SET_I64
            | SYSCALL_JSON_SET_ACCOUNT_ID
            | SYSCALL_SCHEMA_ENCODE
            | SYSCALL_SCHEMA_DECODE
            | SYSCALL_SCHEMA_INFO
            | SYSCALL_NAME_DECODE
            | SYSCALL_BUILD_PATH_KEY_NORITO
            | SYSCALL_POINTER_TO_NORITO
            | SYSCALL_POINTER_FROM_NORITO
            | SYSCALL_TLV_EQ
            | SYSCALL_VRF_VERIFY
            | SYSCALL_VRF_VERIFY_BATCH
            | SYSCALL_GET_AUTHORITY
            | SYSCALL_CURRENT_TIME_MS
            | SYSCALL_SYSVAR_CHAIN_ID
            | SYSCALL_SYSVAR_BLOCK_HEIGHT
            | SYSCALL_SYSVAR_BLOCK_TIME_MS
            | SYSCALL_SYSVAR_AUTHORITY
            | SYSCALL_SYSVAR_CONTRACT_ADDRESS
            | SYSCALL_SYSVAR_CONTRACT_SUBJECT
            | SYSCALL_SYSVAR_ENTRYPOINT
            | SYSCALL_NORMALIZE_NORITO_BYTES
            | SYSCALL_DECODE_ARGUMENT_RECORD
    ) {
        return Some(SyscallAccess::None);
    }
    None
}
/// Return the conservative host-state access class for an ABI v1 syscall.
///
/// The fallback is [`SyscallAccess::Dynamic`]. New or unknown syscalls therefore still serialize
/// conservatively, while [`registered_syscall_access`] lets admission and host metering reject an
/// allowed-but-unclassified syscall outright.
#[must_use]
pub const fn syscall_access(number: u32) -> SyscallAccess {
    match registered_syscall_access(number) {
        Some(access) => access,
        None => SyscallAccess::Dynamic,
    }
}
/// Return the sorted syscall-number component of the ABI hash descriptor.
///
/// The complete hash also binds pointer types and the typed V1 query,
/// entrypoint, collection, and exact numeric protocol records. It binds contracts to
/// a specific host ABI. When comparing runtime ABI against a manifest-provided
/// `abi_hash`, nodes can reject execution if a mismatch is detected.
pub fn abi_syscall_list() -> &'static [u32] {
    syscalls_for_policy(crate::SyscallPolicy::AbiV1)
}
const ABI_V1_SYSCALL_METADATA: &[(u32, &str)] = &[
    (SYSCALL_DEBUG_PRINT, "DEBUG_PRINT"),
    (SYSCALL_EXIT, "EXIT"),
    (SYSCALL_ABORT, "ABORT"),
    (SYSCALL_DEBUG_LOG, "DEBUG_LOG"),
    (SYSCALL_CONTRACT_ABORT, "CONTRACT_ABORT"),
    (SYSCALL_REGISTER_DOMAIN, "REGISTER_DOMAIN"),
    (SYSCALL_UNREGISTER_DOMAIN, "UNREGISTER_DOMAIN"),
    (SYSCALL_TRANSFER_DOMAIN, "TRANSFER_DOMAIN"),
    (SYSCALL_REGISTER_ACCOUNT, "REGISTER_ACCOUNT"),
    (SYSCALL_UNREGISTER_ACCOUNT, "UNREGISTER_ACCOUNT"),
    (SYSCALL_REGISTER_PEER, "REGISTER_PEER"),
    (SYSCALL_UNREGISTER_PEER, "UNREGISTER_PEER"),
    (SYSCALL_ADD_SIGNATORY, "ADD_SIGNATORY"),
    (SYSCALL_REMOVE_SIGNATORY, "REMOVE_SIGNATORY"),
    (SYSCALL_SET_ACCOUNT_QUORUM, "SET_ACCOUNT_QUORUM"),
    (SYSCALL_SET_ACCOUNT_DETAIL, "SET_ACCOUNT_DETAIL"),
    (SYSCALL_REGISTER_ASSET, "REGISTER_ASSET"),
    (SYSCALL_UNREGISTER_ASSET, "UNREGISTER_ASSET"),
    (SYSCALL_MINT_ASSET, "MINT_ASSET"),
    (SYSCALL_BURN_ASSET, "BURN_ASSET"),
    (SYSCALL_TRANSFER_V1, "TRANSFER_V1"),
    (SYSCALL_NFT_MINT_ASSET, "NFT_MINT_ASSET"),
    (SYSCALL_NFT_TRANSFER_ASSET, "NFT_TRANSFER_ASSET"),
    (SYSCALL_NFT_SET_METADATA, "NFT_SET_METADATA"),
    (SYSCALL_NFT_BURN_ASSET, "NFT_BURN_ASSET"),
    (SYSCALL_TRANSFER_V1_BATCH_BEGIN, "TRANSFER_V1_BATCH_BEGIN"),
    (SYSCALL_TRANSFER_V1_BATCH_END, "TRANSFER_V1_BATCH_END"),
    (SYSCALL_TRANSFER_V1_BATCH_APPLY, "TRANSFER_V1_BATCH_APPLY"),
    (SYSCALL_TRANSFER_ASSET_SCOPED, "TRANSFER_ASSET_SCOPED"),
    (SYSCALL_CREATE_ROLE, "CREATE_ROLE"),
    (SYSCALL_DELETE_ROLE, "DELETE_ROLE"),
    (SYSCALL_GRANT_ROLE, "GRANT_ROLE"),
    (SYSCALL_REVOKE_ROLE, "REVOKE_ROLE"),
    (SYSCALL_GRANT_PERMISSION, "GRANT_PERMISSION"),
    (SYSCALL_REVOKE_PERMISSION, "REVOKE_PERMISSION"),
    (
        SYSCALL_GRANT_CONTRACT_PERMISSION,
        "GRANT_CONTRACT_PERMISSION",
    ),
    (
        SYSCALL_REVOKE_CONTRACT_PERMISSION,
        "REVOKE_CONTRACT_PERMISSION",
    ),
    (SYSCALL_CREATE_TRIGGER, "CREATE_TRIGGER"),
    (SYSCALL_REMOVE_TRIGGER, "REMOVE_TRIGGER"),
    (SYSCALL_SET_TRIGGER_ENABLED, "SET_TRIGGER_ENABLED"),
    (
        SYSCALL_DEACTIVATE_CONTRACT_INSTANCE,
        "DEACTIVATE_CONTRACT_INSTANCE",
    ),
    (
        SYSCALL_REMOVE_SMART_CONTRACT_BYTES,
        "REMOVE_SMART_CONTRACT_BYTES",
    ),
    (
        SYSCALL_REGISTER_SMART_CONTRACT_CODE,
        "REGISTER_SMART_CONTRACT_CODE",
    ),
    (
        SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
        "REGISTER_SMART_CONTRACT_BYTES",
    ),
    (
        SYSCALL_ACTIVATE_CONTRACT_INSTANCE,
        "ACTIVATE_CONTRACT_INSTANCE",
    ),
    (SYSCALL_STATE_GET, "STATE_GET"),
    (SYSCALL_STATE_SET, "STATE_SET"),
    (SYSCALL_STATE_DEL, "STATE_DEL"),
    (SYSCALL_BUILD_PATH_KEY_NORITO, "BUILD_PATH_KEY_NORITO"),
    (SYSCALL_JSON_ENCODE, "JSON_ENCODE"),
    (SYSCALL_JSON_DECODE, "JSON_DECODE"),
    (SYSCALL_SCHEMA_ENCODE, "SCHEMA_ENCODE"),
    (SYSCALL_SCHEMA_DECODE, "SCHEMA_DECODE"),
    (SYSCALL_SCHEMA_INFO, "SCHEMA_INFO"),
    (SYSCALL_NAME_DECODE, "NAME_DECODE"),
    (SYSCALL_POINTER_TO_NORITO, "POINTER_TO_NORITO"),
    (SYSCALL_POINTER_FROM_NORITO, "POINTER_FROM_NORITO"),
    (SYSCALL_TLV_EQ, "TLV_EQ"),
    (SYSCALL_ZK_VOTE_VERIFY_BALLOT, "ZK_VOTE_VERIFY_BALLOT"),
    (SYSCALL_ZK_VOTE_VERIFY_TALLY, "ZK_VOTE_VERIFY_TALLY"),
    (SYSCALL_ZK_ROOTS_GET, "ZK_ROOTS_GET"),
    (SYSCALL_ZK_VOTE_GET_TALLY, "ZK_VOTE_GET_TALLY"),
    (SYSCALL_ZK_VERIFY_BATCH, "ZK_VERIFY_BATCH"),
    (SYSCALL_VRF_VERIFY, "VRF_VERIFY"),
    (SYSCALL_VRF_VERIFY_BATCH, "VRF_VERIFY_BATCH"),
    (SYSCALL_TLV_LEN, "TLV_LEN"),
    (SYSCALL_JSON_GET_JSON, "JSON_GET_JSON"),
    (SYSCALL_JSON_GET_NAME, "JSON_GET_NAME"),
    (SYSCALL_JSON_GET_ACCOUNT_ID, "JSON_GET_ACCOUNT_ID"),
    (SYSCALL_JSON_GET_NFT_ID, "JSON_GET_NFT_ID"),
    (SYSCALL_JSON_GET_BLOB_HEX, "JSON_GET_BLOB_HEX"),
    (SYSCALL_VRF_EPOCH_SEED, "VRF_EPOCH_SEED"),
    (
        SYSCALL_JSON_GET_ASSET_DEFINITION_ID,
        "JSON_GET_ASSET_DEFINITION_ID",
    ),
    (SYSCALL_JSON_OBJECT, "JSON_OBJECT"),
    (SYSCALL_JSON_SET_I64, "JSON_SET_I64"),
    (SYSCALL_JSON_SET_ACCOUNT_ID, "JSON_SET_ACCOUNT_ID"),
    (SYSCALL_SM3_HASH, "SM3_HASH"),
    (SYSCALL_SM2_VERIFY, "SM2_VERIFY"),
    (SYSCALL_SM4_GCM_SEAL, "SM4_GCM_SEAL"),
    (SYSCALL_SM4_GCM_OPEN, "SM4_GCM_OPEN"),
    (SYSCALL_SM4_CCM_SEAL, "SM4_CCM_SEAL"),
    (SYSCALL_SM4_CCM_OPEN, "SM4_CCM_OPEN"),
    (SYSCALL_SHA256_HASH, "SHA256_HASH"),
    (SYSCALL_SHA3_HASH, "SHA3_HASH"),
    (SYSCALL_BLAKE2B256_HASH, "BLAKE2B256_HASH"),
    (SYSCALL_KECCAK256_HASH, "KECCAK256_HASH"),
    (SYSCALL_IROHA_HASH, "IROHA_HASH"),
    (
        SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
        "SMARTCONTRACT_EXECUTE_INSTRUCTION",
    ),
    (
        SYSCALL_SMARTCONTRACT_EXECUTE_QUERY,
        "SMARTCONTRACT_EXECUTE_QUERY",
    ),
    (
        SYSCALL_CREATE_NFTS_FOR_ALL_USERS,
        "CREATE_NFTS_FOR_ALL_USERS",
    ),
    (
        SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH,
        "SET_SMARTCONTRACT_EXECUTION_DEPTH",
    ),
    (SYSCALL_GET_AUTHORITY, "GET_AUTHORITY"),
    (SYSCALL_SUBSCRIPTION_BILL, "SUBSCRIPTION_BILL"),
    (
        SYSCALL_SUBSCRIPTION_RECORD_USAGE,
        "SUBSCRIPTION_RECORD_USAGE",
    ),
    (SYSCALL_RESOLVE_ACCOUNT_ALIAS, "RESOLVE_ACCOUNT_ALIAS"),
    (SYSCALL_CURRENT_TIME_MS, "CURRENT_TIME_MS"),
    (SYSCALL_CALL_CONTRACT, "CALL_CONTRACT"),
    (SYSCALL_EMIT_CONTRACT_EVENT, "EMIT_CONTRACT_EVENT"),
    (SYSCALL_AXT_BEGIN, "AXT_BEGIN"),
    (SYSCALL_AXT_TOUCH, "AXT_TOUCH"),
    (SYSCALL_AXT_COMMIT, "AXT_COMMIT"),
    (SYSCALL_VERIFY_DS_PROOF, "VERIFY_DS_PROOF"),
    (SYSCALL_AXT_STAGE_ANCHORED_SPEND, "AXT_STAGE_ANCHORED_SPEND"),
    (SYSCALL_ESCROW_OPEN_OFFER, "ESCROW_OPEN_OFFER"),
    (SYSCALL_ESCROW_ACCEPT, "ESCROW_ACCEPT"),
    (SYSCALL_ESCROW_MARK_PAYMENT_SENT, "ESCROW_MARK_PAYMENT_SENT"),
    (SYSCALL_ESCROW_RELEASE, "ESCROW_RELEASE"),
    (SYSCALL_ESCROW_CANCEL, "ESCROW_CANCEL"),
    (SYSCALL_ESCROW_OPEN_DISPUTE, "ESCROW_OPEN_DISPUTE"),
    (SYSCALL_ESCROW_RESOLVE_DISPUTE, "ESCROW_RESOLVE_DISPUTE"),
    (
        SYSCALL_SORACLOUD_READ_COMMITTED_STATE,
        "SORACLOUD_READ_COMMITTED_STATE",
    ),
    (
        SYSCALL_SORACLOUD_EMIT_STATE_MUTATION,
        "SORACLOUD_EMIT_STATE_MUTATION",
    ),
    (
        SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE,
        "SORACLOUD_EMIT_MAILBOX_MESSAGE",
    ),
    (SYSCALL_SORACLOUD_APPEND_JOURNAL, "SORACLOUD_APPEND_JOURNAL"),
    (
        SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT,
        "SORACLOUD_PUBLISH_CHECKPOINT",
    ),
    (SYSCALL_SORACLOUD_READ_CONFIG, "SORACLOUD_READ_CONFIG"),
    (
        SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE,
        "SORACLOUD_READ_SECRET_ENVELOPE",
    ),
    (SYSCALL_INPUT_PUBLISH_TLV, "INPUT_PUBLISH_TLV"),
    (SYSCALL_ALLOC, "ALLOC"),
    (SYSCALL_GET_PUBLIC_INPUT, "GET_PUBLIC_INPUT"),
    (SYSCALL_EXECUTION_SUMMARY, "EXECUTION_SUMMARY"),
    (SYSCALL_GROW_HEAP, "GROW_HEAP"),
    (SYSCALL_VERIFY_PROOF, "VERIFY_PROOF"),
    (SYSCALL_GET_MERKLE_PATH, "GET_MERKLE_PATH"),
    (SYSCALL_PRIVATE_NUMERIC_VALCOM, "PRIVATE_NUMERIC_VALCOM"),
    (SYSCALL_GET_ACCOUNT_BALANCE, "GET_ACCOUNT_BALANCE"),
    (SYSCALL_GET_MERKLE_COMPACT, "GET_MERKLE_COMPACT"),
    (SYSCALL_VERIFY_SIGNATURE, "VERIFY_SIGNATURE"),
    (SYSCALL_GET_PRIVATE_INPUT, "GET_PRIVATE_INPUT"),
    (SYSCALL_COMMIT_OUTPUT, "COMMIT_OUTPUT"),
    (
        SYSCALL_GET_REGISTER_MERKLE_COMPACT,
        "GET_REGISTER_MERKLE_COMPACT",
    ),
    (SYSCALL_QUERY_EXECUTE_NORITO, "QUERY_EXECUTE_NORITO"),
    (SYSCALL_CORE_QUERY_GET, "CORE_QUERY_GET"),
    (SYSCALL_CORE_QUERY_PAGE, "CORE_QUERY_PAGE"),
    (SYSCALL_QUERY_GET_PARAMETER, "QUERY_GET_PARAMETER"),
    (
        SYSCALL_QUERY_GET_CONTRACT_MANIFEST,
        "QUERY_GET_CONTRACT_MANIFEST",
    ),
    (
        SYSCALL_QUERY_GET_CONTRACT_INSTANCE,
        "QUERY_GET_CONTRACT_INSTANCE",
    ),
    (SYSCALL_SYSVAR_CHAIN_ID, "SYSVAR_CHAIN_ID"),
    (SYSCALL_SYSVAR_BLOCK_HEIGHT, "SYSVAR_BLOCK_HEIGHT"),
    (SYSCALL_SYSVAR_BLOCK_TIME_MS, "SYSVAR_BLOCK_TIME_MS"),
    (SYSCALL_SYSVAR_AUTHORITY, "SYSVAR_AUTHORITY"),
    (SYSCALL_SYSVAR_CONTRACT_ADDRESS, "SYSVAR_CONTRACT_ADDRESS"),
    (SYSCALL_SYSVAR_ENTRYPOINT, "SYSVAR_ENTRYPOINT"),
    (SYSCALL_DECODE_ARGUMENT_RECORD, "DECODE_ARGUMENT_RECORD"),
    (SYSCALL_SYSVAR_CONTRACT_SUBJECT, "SYSVAR_CONTRACT_SUBJECT"),
    (SYSCALL_NORMALIZE_NORITO_BYTES, "NORMALIZE_NORITO_BYTES"),
    (SYSCALL_STATE_HAS, "STATE_HAS"),
    (SYSCALL_STATE_LEN, "STATE_LEN"),
    (SYSCALL_STATE_COUNT, "STATE_COUNT"),
    (SYSCALL_STATE_MAP_KEY_AT, "STATE_MAP_KEY_AT"),
    (SYSCALL_STATE_VALUE_ENCODE, "STATE_VALUE_ENCODE"),
    (SYSCALL_STATE_VALUE_DECODE, "STATE_VALUE_DECODE"),
    (SYSCALL_STATE_PATH_FROM_NAME, "STATE_PATH_FROM_NAME"),
    (SYSCALL_STATE_SCAN, "STATE_SCAN"),
    (SYSCALL_JSON_BUILD, "JSON_BUILD"),
    (SYSCALL_VALUE_ENCODE, "VALUE_ENCODE"),
    (SYSCALL_BLOB_CONCAT, "BLOB_CONCAT"),
    (SYSCALL_UTF8_VALIDATE, "UTF8_VALIDATE"),
    (SYSCALL_VALUE_TO_STRING, "VALUE_TO_STRING"),
    (SYSCALL_INT_FROM_I64, "INT_FROM_I64"),
    (SYSCALL_INT_FROM_U64, "INT_FROM_U64"),
    (SYSCALL_INT_TO_I64, "INT_TO_I64"),
    (SYSCALL_INT_TO_U64, "INT_TO_U64"),
    (SYSCALL_INT_NEG, "INT_NEG"),
    (SYSCALL_INT_ADD, "INT_ADD"),
    (SYSCALL_INT_SUB, "INT_SUB"),
    (SYSCALL_INT_MUL, "INT_MUL"),
    (SYSCALL_INT_DIV, "INT_DIV"),
    (SYSCALL_INT_REM, "INT_REM"),
    (SYSCALL_INT_EQ, "INT_EQ"),
    (SYSCALL_INT_NE, "INT_NE"),
    (SYSCALL_INT_LT, "INT_LT"),
    (SYSCALL_INT_LE, "INT_LE"),
    (SYSCALL_INT_GT, "INT_GT"),
    (SYSCALL_INT_GE, "INT_GE"),
    (SYSCALL_INT_WRAP_NEG, "INT_WRAP_NEG"),
    (SYSCALL_INT_WRAP_ADD, "INT_WRAP_ADD"),
    (SYSCALL_INT_WRAP_SUB, "INT_WRAP_SUB"),
    (SYSCALL_INT_WRAP_MUL, "INT_WRAP_MUL"),
    (SYSCALL_INT_ISQRT, "INT_ISQRT"),
    (SYSCALL_INT_ABS, "INT_ABS"),
    (SYSCALL_INT_MIN, "INT_MIN"),
    (SYSCALL_INT_MAX, "INT_MAX"),
    (SYSCALL_INT_DIV_CEIL, "INT_DIV_CEIL"),
    (SYSCALL_INT_GCD, "INT_GCD"),
    (SYSCALL_INT_MEAN, "INT_MEAN"),
    (SYSCALL_DECIMAL_FROM_INT, "DECIMAL_FROM_INT"),
    (SYSCALL_DECIMAL_NEG, "DECIMAL_NEG"),
    (SYSCALL_DECIMAL_ADD, "DECIMAL_ADD"),
    (SYSCALL_DECIMAL_SUB, "DECIMAL_SUB"),
    (SYSCALL_DECIMAL_MUL, "DECIMAL_MUL"),
    (SYSCALL_DECIMAL_DIV_EXACT, "DECIMAL_DIV_EXACT"),
    (SYSCALL_DECIMAL_DIV_ROUND, "DECIMAL_DIV_ROUND"),
    (SYSCALL_DECIMAL_EQ, "DECIMAL_EQ"),
    (SYSCALL_DECIMAL_NE, "DECIMAL_NE"),
    (SYSCALL_DECIMAL_LT, "DECIMAL_LT"),
    (SYSCALL_DECIMAL_LE, "DECIMAL_LE"),
    (SYSCALL_DECIMAL_GT, "DECIMAL_GT"),
    (SYSCALL_DECIMAL_GE, "DECIMAL_GE"),
    (SYSCALL_DECIMAL_TO_INT_EXACT, "DECIMAL_TO_INT_EXACT"),
    (SYSCALL_DECIMAL_TO_INT_TRUNC, "DECIMAL_TO_INT_TRUNC"),
    (SYSCALL_DECIMAL_TO_INT_ROUND, "DECIMAL_TO_INT_ROUND"),
    (SYSCALL_DECIMAL_MUL_DIV_ROUND, "DECIMAL_MUL_DIV_ROUND"),
    (SYSCALL_QUANTITY_FROM_INT, "QUANTITY_FROM_INT"),
    (SYSCALL_QUANTITY_FROM_DECIMAL, "QUANTITY_FROM_DECIMAL"),
    (SYSCALL_QUANTITY_TO_DECIMAL, "QUANTITY_TO_DECIMAL"),
    (SYSCALL_QUANTITY_ADD, "QUANTITY_ADD"),
    (SYSCALL_QUANTITY_SUB, "QUANTITY_SUB"),
    (SYSCALL_QUANTITY_MUL_DECIMAL, "QUANTITY_MUL_DECIMAL"),
    (
        SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
        "QUANTITY_DIV_DECIMAL_EXACT",
    ),
    (
        SYSCALL_QUANTITY_DIV_DECIMAL_ROUND,
        "QUANTITY_DIV_DECIMAL_ROUND",
    ),
    (SYSCALL_QUANTITY_RATIO_EXACT, "QUANTITY_RATIO_EXACT"),
    (SYSCALL_QUANTITY_RATIO_ROUND, "QUANTITY_RATIO_ROUND"),
    (SYSCALL_QUANTITY_EQ, "QUANTITY_EQ"),
    (SYSCALL_QUANTITY_NE, "QUANTITY_NE"),
    (SYSCALL_QUANTITY_LT, "QUANTITY_LT"),
    (SYSCALL_QUANTITY_LE, "QUANTITY_LE"),
    (SYSCALL_QUANTITY_GT, "QUANTITY_GT"),
    (SYSCALL_QUANTITY_GE, "QUANTITY_GE"),
    (SYSCALL_QUANTITY_MUL_DIV_ROUND, "QUANTITY_MUL_DIV_ROUND"),
    (SYSCALL_JSON_GET_INT, "JSON_GET_INT"),
    (SYSCALL_JSON_GET_DECIMAL, "JSON_GET_DECIMAL"),
    (SYSCALL_JSON_GET_QUANTITY, "JSON_GET_QUANTITY"),
    (SYSCALL_JSON_GET_STRING, "JSON_GET_STRING"),
    (SYSCALL_JSON_GET_BOOL, "JSON_GET_BOOL"),
    (
        SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
        "SET_ASSET_TRANSFER_AVAILABILITY",
    ),
    (
        SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT,
        "SET_ASSET_TRANSFER_DAILY_LIMIT",
    ),
    (SYSCALL_SET_ASSET_HOLDING_LIMIT, "SET_ASSET_HOLDING_LIMIT"),
    (SYSCALL_ACCOUNT_RECOVERY_PROPOSE, "ACCOUNT_RECOVERY_PROPOSE"),
    (SYSCALL_ACCOUNT_RECOVERY_APPROVE, "ACCOUNT_RECOVERY_APPROVE"),
    (SYSCALL_ACCOUNT_RECOVERY_CANCEL, "ACCOUNT_RECOVERY_CANCEL"),
    (
        SYSCALL_ACCOUNT_RECOVERY_FINALIZE,
        "ACCOUNT_RECOVERY_FINALIZE",
    ),
    (SYSCALL_ASSET_LOCK_OPEN, "ASSET_LOCK_OPEN"),
    (SYSCALL_ASSET_LOCK_DRAWDOWN, "ASSET_LOCK_DRAWDOWN"),
    (SYSCALL_ASSET_LOCK_CANCEL, "ASSET_LOCK_CANCEL"),
    (SYSCALL_ASSET_LOCK_EXPIRE, "ASSET_LOCK_EXPIRE"),
];
const ABI_V1_SYSCALL_COUNT: usize = ABI_V1_SYSCALL_METADATA.len();
const fn abi_v1_syscall_numbers() -> [u32; ABI_V1_SYSCALL_COUNT] {
    let mut numbers = [0; ABI_V1_SYSCALL_COUNT];
    let mut index = 0;
    while index < ABI_V1_SYSCALL_COUNT {
        numbers[index] = ABI_V1_SYSCALL_METADATA[index].0;
        index += 1;
    }
    numbers
}
const ABI_V1_SYSCALL_NUMBERS: [u32; ABI_V1_SYSCALL_COUNT] = abi_v1_syscall_numbers();
/// Return the canonical syscall list for the first-release ABI policy.
pub fn syscalls_for_policy(policy: crate::SyscallPolicy) -> &'static [u32] {
    let crate::SyscallPolicy::AbiV1 = policy;
    &ABI_V1_SYSCALL_NUMBERS
}
/// Return a symbolic name for a syscall number, when known.
/// This is used for documentation/tests; hosts should match on numbers directly.
pub fn syscall_name(number: u32) -> Option<&'static str> {
    let mut left = 0;
    let mut right = ABI_V1_SYSCALL_METADATA.len();
    while left < right {
        let middle = left + (right - left) / 2;
        let (candidate, name) = ABI_V1_SYSCALL_METADATA[middle];
        if candidate < number {
            left = middle + 1;
        } else if candidate > number {
            right = middle;
        } else {
            return Some(name);
        }
    }
    None
}
/// Render a minimal syscall list as markdown lines `- 0xNN NAME`.
pub fn render_syscalls_min_list() -> String {
    let mut nums: Vec<u32> = abi_syscall_list().to_vec();
    nums.sort_unstable();
    let mut out = String::new();
    for n in nums {
        if let Some(name) = syscall_name(n) {
            out.push_str(&format!("- 0x{n:02X} {name}\n"));
        } else {
            out.push_str(&format!("- 0x{n:02X}\n"));
        }
    }
    out
}
/// Structured doc row for a syscall.
pub struct SyscallDoc {
    pub number: u32,
    pub args: &'static str,
    pub ret: &'static str,
    pub gas: &'static str,
}
// Use the generated syscall docs table if present (preferred). This file is
// produced by the `gen_syscalls_doc` helper. It must define
// `pub static DOCS: &[SyscallDoc]`.
#[path = "syscalls_doc_gen.rs"]
mod syscalls_doc_gen;
// Use the generated gas asset table if present (preferred). This file is
// produced by the `gen_syscalls_doc` helper. It must define `GasAsset` and
// `pub static GAS_ASSETS: &[GasAsset]`.
#[path = "gas_spec.rs"]
pub mod gas_spec;
/// Render a markdown table with columns: Number, Name, Args, Return, Gas.
pub fn render_syscalls_markdown_table() -> String {
    let mut nums: Vec<u32> = abi_syscall_list().to_vec();
    nums.sort_unstable();
    let docs = syscalls_doc_gen::DOCS;
    let mut out = String::new();
    out.push_str("| Number | Name | Args | Return | Gas |\n");
    out.push_str("|---|---|---|---|---|\n");
    for n in nums {
        let name = syscall_name(n).unwrap_or("");
        let (mut args, mut ret, mut gas) = ("-", "-", "-");
        if let Some(d) = docs.iter().find(|d| d.number == n) {
            args = d.args;
            ret = d.ret;
            gas = d.gas;
        }
        out.push_str(&format!(
            "| 0x{n:02X} | {name} | {args} | {ret} | {gas} |\n"
        ));
    }
    out
}
/// Re-export generated gas assets for tests/docs.
pub use gas_spec as _gas_spec_placeholder;
/// Render a markdown table with ABI policy names and their hashes.
///
/// The table is used in docs to surface the canonical `abi_hash` values
/// for the currently supported policies. Keep output stable (lowercase hex).
pub fn render_abi_hashes_markdown_table() -> String {
    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use core::fmt::Write as _;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
    let items: &[(&str, crate::SyscallPolicy)] = &[("ABI v1", crate::SyscallPolicy::AbiV1)];
    let mut out = String::new();
    out.push_str("| Policy | abi_hash (hex) |\n");
    out.push_str("|---|---|\n");
    for (name, pol) in items {
        let h = compute_abi_hash(*pol);
        let hex = hex_lower(&h);
        let _ = core::fmt::Write::write_fmt(&mut out, format_args!("| {name} | {hex} |\n"));
    }
    out
}
const ABI_V1_SURFACE_DOMAIN: &[u8] = b"IVM_ABI_V1_FULL_SURFACE\0";
const ABI_SURFACE_DESCRIPTOR_FORMAT_VERSION: u16 = 10;
const ABI_V1_NORITO_ENCODE_FLAGS: u8 = norito::core::header_flags::COMPACT_LEN;
const PROGRAM_HEADER_LAYOUT_V1: &str = "49-bytes:magic[4]=IVM\\0;version_major:u8=1;version_minor:u8=1;mode:u8;vector_length:u8;max_cycles:u64le;abi_version:u8;abi_hash[32]=Iroha-Hash-v1(canonical-ABI-descriptor-for-abi_version;Blake2b-256-with-final-byte-LSB-set-to-1);abi-hash-validated-before-prefix-or-instruction-decode";
const NUMERIC_MANTISSA_BITS_V1: u16 = 512;
const DECIMAL_MAX_SCALE_V1: u8 = 28;
const NUMERIC_WIRE_FORMAT_VERSION_V1: u8 = 1;
const NUMERIC_FRAME_LAYOUT_V1: &str = "canonical-norito-v1-header=40;uncompressed;layout-flags=0;int-body=u32le-length+minimal-le-twos-complement;decimal-and-quantity-body=int-body+u8-scale;zero=empty-mantissa";
const NUMERIC_POINTER_ENVELOPE_LAYOUT_V1: &str =
    "u16be-type+u8-version(1)+u32be-frame-length+frame+iroha-hash32(frame);exact-length";
const NUMERIC_ERROR_PRECEDENCE_V1: &str = "operands-in-register-order:pointer-provenance,type-policy,expected-type,version,capped-length,range,snapshot,hash,frame,schema,canonical;then-scale-pointer;then-required-zero-registers-and-rounding-and-failure-tags-in-syscall-contract-order;then-divisor-zero;then-arithmetic;result-domain=scale-before-mantissa-before-quantity-sign;quantity-sub-negative=underflow";
// This is the base for invalid-surface sentinels. They cannot be emitted by
// `iroha_crypto::Hash::new`: every valid Iroha hash has the low bit of its final
// byte set. Returning an unmistakable sentinel is safer than silently hashing
// an incomplete generated registry, while release tests require the compiled
// surface to validate successfully.
const INVALID_ABI_SURFACE_HASH: [u8; 32] = [0; 32];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AbiSyscallSurface {
    number: u32,
    args: &'static str,
    ret: &'static str,
    access: SyscallAccess,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNamedTypeSurface {
    name: &'static str,
    ty: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiCoreQueryProjectionSurface {
    name: &'static str,
    entity_tag: u64,
    fields: Vec<AbiNamedTypeSurface>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiQueryPageSurface {
    name: &'static str,
    fields: Vec<AbiNamedTypeSurface>,
    items_capacity: u8,
    next_offset_semantics: &'static str,
    item_ordering: &'static str,
    account_filter: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiEntrypointSurface {
    schema_version: u8,
    call_table_layout: &'static str,
    call_frame_checks: &'static str,
    max_call_words: u64,
    value_utilities: &'static str,
    context_address: &'static str,
    unit_layout: &'static str,
    struct_identity: &'static str,
    vrf_epoch_seed: &'static str,
    error_layout: &'static str,
    enum_layout: &'static str,
    sum_json: &'static str,
    invocation_outcome: &'static str,
    fault_schema_hash: [u8; 16],
    fault_layout: &'static str,
    fault_semantics: &'static str,
    event_layout: &'static str,
    event_semantics: &'static str,
    authorization: &'static str,
    lifecycle: &'static str,
    int_kind: &'static str,
    int_pointer_type_id: u16,
    decimal_kind: &'static str,
    decimal_pointer_type_id: u16,
    quantity_kind: &'static str,
    quantity_pointer_type_id: u16,
    list_kind: &'static str,
    list_layout: &'static str,
    list_child_count: u8,
    list_capacity_is_schema_bound: bool,
    list_min_capacity: u8,
    list_max_capacity: u8,
    max_schema_nodes: u64,
    max_schema_depth: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNumericRoundingSurface {
    name: &'static str,
    tag: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNumericFaultSurface {
    name: &'static str,
    tag: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNumericRuleSurface {
    name: &'static str,
    specification: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNumericOperatorSurface {
    operator: &'static str,
    lhs: &'static str,
    rhs: &'static str,
    allowed: bool,
    result: &'static str,
    semantics: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNumericJsonSurface {
    type_name: &'static str,
    token_kind: &'static str,
    decoded_string_grammar: &'static str,
    validation: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiNumericSurface {
    semantics_descriptor_version: u8,
    int_pointer_type_id: u16,
    decimal_pointer_type_id: u16,
    quantity_pointer_type_id: u16,
    mantissa_bits: u16,
    max_scale: u8,
    int_domain: &'static str,
    decimal_domain: &'static str,
    quantity_domain: &'static str,
    canonicalization: &'static str,
    integer_division: &'static str,
    wrapping_modulus: &'static str,
    rules: Vec<AbiNumericRuleSurface>,
    operators: Vec<AbiNumericOperatorSurface>,
    json_grammar: Vec<AbiNumericJsonSurface>,
    fault_ordering: Vec<AbiNumericRuleSurface>,
    wire_format_version: u8,
    int_schema_name: &'static str,
    int_schema_hash: [u8; 16],
    decimal_schema_name: &'static str,
    decimal_schema_hash: [u8; 16],
    quantity_schema_name: &'static str,
    quantity_schema_hash: [u8; 16],
    frame_header_bytes: u64,
    int_max_frame_bytes: u64,
    decimal_max_frame_bytes: u64,
    quantity_max_frame_bytes: u64,
    pointer_envelope_overhead_bytes: u64,
    int_max_envelope_bytes: u64,
    decimal_max_envelope_bytes: u64,
    quantity_max_envelope_bytes: u64,
    frame_layout: &'static str,
    pointer_envelope_layout: &'static str,
    error_precedence: &'static str,
    rounding_modes: Vec<AbiNumericRoundingSurface>,
    failure_modes: Vec<AbiNumericRoundingSurface>,
    faults: Vec<AbiNumericFaultSurface>,
    pointer_faults: Vec<AbiNumericFaultSurface>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiPrivateInputKindSurface {
    name: &'static str,
    tag: u64,
    pointer_type_id: u16,
    payload_schema: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiPrivateInputSurface {
    abi_version: u16,
    record_name: &'static str,
    record_schema_hash: [u8; 16],
    record_layout: &'static str,
    kind_discriminant_layout: &'static str,
    kinds: Vec<AbiPrivateInputKindSurface>,
    max_inputs: u64,
    max_record_bytes: u64,
    max_transport_bytes: u64,
    transport_validation: &'static str,
    runtime_validation: &'static str,
    projection_domain: &'static [u8],
    projection_layout: &'static str,
    valcom_domain: &'static [u8],
    valcom_h_dst: &'static [u8],
    valcom_h_message: &'static [u8],
    valcom_h_compressed: [u8; 48],
    valcom_scalar_derivation: &'static str,
    valcom_result: &'static str,
    privacy_rule: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiIndexedLiteralSurface {
    opcode: u8,
    mnemonic: &'static str,
    table_kind: u8,
    payload_layout: &'static str,
    result: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiStateValueKindSurface {
    name: &'static str,
    tag: u32,
    word_layout: &'static str,
    pointer_type_id_or_zero: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiTaggedLayoutSurface {
    name: &'static str,
    tag: u32,
    layout: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiEmbeddedStateTypeSurface {
    name: &'static str,
    tag: u8,
    layout: &'static str,
    canonical_sample_frame: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiTypedStateValueSurface {
    wire_format_version: u8,
    norito_header_bytes: u16,
    norito_version_major: u8,
    norito_version_minor: u8,
    norito_default_encode_flags: u8,
    enum_discriminant_layout: &'static str,
    schema_payload_magic: [u8; 4],
    schema_node_count_bytes: u8,
    schema_node_tag_bytes: u8,
    schema_kind_tag_bytes: u8,
    record_payload_magic: [u8; 4],
    record_stream_count_bytes: u8,
    record_atom_tag_bytes: u8,
    record_pointer_length_bytes: u8,
    record_list_item_count_bytes: u8,
    schema_hash_domain: &'static [u8],
    schema_hash_algorithm: &'static str,
    schema_name: &'static str,
    schema_hash: [u8; 16],
    record_name: &'static str,
    record_hash: [u8; 16],
    schema_layout: &'static str,
    record_layout: &'static str,
    traversal_semantics: &'static str,
    option_tag_semantics: &'static str,
    result_tag_semantics: &'static str,
    kinds: Vec<AbiStateValueKindSurface>,
    nodes: Vec<AbiTaggedLayoutSurface>,
    atoms: Vec<AbiTaggedLayoutSurface>,
    max_nodes: u64,
    max_depth: u64,
    max_words: u64,
    max_schema_bytes: u64,
    max_record_bytes: u64,
    list_min_capacity: u8,
    list_max_capacity: u8,
    decoded_table_offset: u16,
    decoded_word_bytes: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiDurableStateSurface {
    semantics_version: u8,
    contract_interface_section_magic: [u8; 4],
    contract_interface_section_layout: &'static str,
    contract_interface_schema_name: &'static str,
    contract_interface_schema_hash: [u8; 16],
    embedded_state_type_schema_name: &'static str,
    embedded_state_type_schema_hash: [u8; 16],
    embedded_state_type_tag_layout: &'static str,
    embedded_state_type_max_depth: u64,
    embedded_state_type_validation: &'static str,
    embedded_state_types: Vec<AbiEmbeddedStateTypeSurface>,
    dynamic_access_hint_validation_version: u8,
    dynamic_access_hint_max_keys: u32,
    dynamic_access_hint_key_types: Vec<&'static str>,
    dynamic_access_hint_bound_kinds: Vec<&'static str>,
    dynamic_access_hint_reserved_state_identifiers: Vec<&'static str>,
    dynamic_access_hint_reserved_state_prefixes: Vec<&'static str>,
    dynamic_access_hint_validation: &'static str,
    scan_max_items: u64,
    max_path_bytes: u64,
    max_path_frame_bytes: u64,
    max_value_bytes: u64,
    map_max_key_bytes: u64,
    map_max_base_bytes: u64,
    map_max_base_frame_bytes: u64,
    map_max_page_bytes: u64,
    path_size_unit: &'static str,
    path_transport: &'static str,
    value_storage: &'static str,
    ordering_version: u8,
    key_ordering: &'static str,
    prefix_match: &'static str,
    map_path_derivation_version: u8,
    map_path_derivation: &'static str,
    page_overflow: &'static str,
    operation_path_rules_version: u8,
    operation_path_rules: &'static str,
    state_value_validation_version: u8,
    state_value_validation: &'static str,
    cursor_schema_hash: [u8; 16],
    cursor_schema_hash_domain: &'static [u8],
    cursor_max_bytes: u64,
    scan_max_candidates: u64,
    cursor_layout: &'static str,
    scan_semantics: &'static str,
    typed_value: AbiTypedStateValueSurface,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiGenericProgramSurface {
    semantics_version: u8,
    artifact_discriminator: &'static str,
    allowed_syscall_rule: &'static str,
    denied_syscalls: Vec<u32>,
    rejection: &'static str,
    validation_points: &'static str,
    durable_state: &'static str,
    reserved_transaction_metadata: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AbiSurface {
    descriptor_format_version: u16,
    policy_tag: u8,
    program_header_layout: &'static str,
    syscalls: Vec<AbiSyscallSurface>,
    pointer_type_ids: Vec<u16>,
    core_query_projections: Vec<AbiCoreQueryProjectionSurface>,
    query_page: AbiQueryPageSurface,
    entrypoint: AbiEntrypointSurface,
    numeric: AbiNumericSurface,
    private_input: AbiPrivateInputSurface,
    indexed_literals: Vec<AbiIndexedLiteralSurface>,
    generic_program: AbiGenericProgramSurface,
    durable_state: AbiDurableStateSurface,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbiSurfaceError {
    EmptySyscallSurface,
    EmptyPointerSurface,
    SyscallsNotStrictlySorted { previous: u32, current: u32 },
    PointerTypesNotStrictlySorted { previous: u16, current: u16 },
    MissingSignature(u32),
    DuplicateSignature(u32),
    UnexpectedSignature(u32),
    EmptyArguments(u32),
    EmptyReturn(u32),
    SurfaceTooLarge,
}
fn invalid_abi_surface_hash(error: AbiSurfaceError) -> [u8; 32] {
    let (tag, first, second) = match error {
        AbiSurfaceError::EmptySyscallSurface => (1, 0, 0),
        AbiSurfaceError::EmptyPointerSurface => (2, 0, 0),
        AbiSurfaceError::SyscallsNotStrictlySorted { previous, current } => (3, previous, current),
        AbiSurfaceError::PointerTypesNotStrictlySorted { previous, current } => {
            (4, u32::from(previous), u32::from(current))
        }
        AbiSurfaceError::MissingSignature(number) => (5, number, 0),
        AbiSurfaceError::DuplicateSignature(number) => (6, number, 0),
        AbiSurfaceError::UnexpectedSignature(number) => (7, number, 0),
        AbiSurfaceError::EmptyArguments(number) => (8, number, 0),
        AbiSurfaceError::EmptyReturn(number) => (9, number, 0),
        AbiSurfaceError::SurfaceTooLarge => (10, 0, 0),
    };
    let mut sentinel = INVALID_ABI_SURFACE_HASH;
    sentinel[0] = tag;
    sentinel[1..5].copy_from_slice(&first.to_le_bytes());
    sentinel[5..9].copy_from_slice(&second.to_le_bytes());
    sentinel
}
const fn syscall_access_tag(access: SyscallAccess) -> u8 {
    match access {
        SyscallAccess::None => 0,
        SyscallAccess::StateRead => 1,
        SyscallAccess::StateWrite => 2,
        SyscallAccess::LedgerRead => 3,
        SyscallAccess::LedgerWrite => 4,
        SyscallAccess::Dynamic => 5,
    }
}
fn append_abi_field(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), AbiSurfaceError> {
    let len = u64::try_from(value.len()).map_err(|_| AbiSurfaceError::SurfaceTooLarge)?;
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}
/// Canonical encoder for the ABI hash descriptor.
///
/// Every value is paired with a stable field name and both byte strings are length-prefixed. Nested
/// records and sequence items are themselves framed fields, so no two different partitions of the
/// same byte stream can alias. Inputs are explicit integers, booleans, and UTF-8 protocol names;
/// encoding never depends on debug formatting, a codec configuration, or host hardware.
#[derive(Default)]
struct AbiDescriptorEncoder {
    bytes: Vec<u8>,
}
impl AbiDescriptorEncoder {
    fn field(&mut self, name: &str, value: &[u8]) -> Result<(), AbiSurfaceError> {
        append_abi_field(&mut self.bytes, name.as_bytes())?;
        append_abi_field(&mut self.bytes, value)
    }
    fn text(&mut self, name: &str, value: &str) -> Result<(), AbiSurfaceError> {
        self.field(name, value.as_bytes())
    }
    fn bool(&mut self, name: &str, value: bool) -> Result<(), AbiSurfaceError> {
        self.field(name, &[u8::from(value)])
    }
    fn u8(&mut self, name: &str, value: u8) -> Result<(), AbiSurfaceError> {
        self.field(name, &[value])
    }
    fn u16(&mut self, name: &str, value: u16) -> Result<(), AbiSurfaceError> {
        self.field(name, &value.to_le_bytes())
    }
    fn u32(&mut self, name: &str, value: u32) -> Result<(), AbiSurfaceError> {
        self.field(name, &value.to_le_bytes())
    }
    fn u64(&mut self, name: &str, value: u64) -> Result<(), AbiSurfaceError> {
        self.field(name, &value.to_le_bytes())
    }
    fn record(
        &mut self,
        name: &str,
        encode: impl FnOnce(&mut Self) -> Result<(), AbiSurfaceError>,
    ) -> Result<(), AbiSurfaceError> {
        let mut record = Self::default();
        encode(&mut record)?;
        self.field(name, &record.bytes)
    }
    fn sequence<T>(
        &mut self,
        name: &str,
        items: &[T],
        mut encode_item: impl FnMut(&mut Self, &T) -> Result<(), AbiSurfaceError>,
    ) -> Result<(), AbiSurfaceError> {
        self.record(name, |sequence| {
            let count = u64::try_from(items.len()).map_err(|_| AbiSurfaceError::SurfaceTooLarge)?;
            sequence.u64("count", count)?;
            for item in items {
                sequence.record("item", |record| encode_item(record, item))?;
            }
            Ok(())
        })
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
fn private_input_surface_v1() -> Result<AbiPrivateInputSurface, AbiSurfaceError> {
    use crate::private_input::{
        MAX_PRIVATE_INPUT_RECORD_BYTES_V1, MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1,
        MAX_PRIVATE_INPUTS_V1, PRIVATE_INPUT_ABI_VERSION_V1, PRIVATE_INPUT_RECORD_NAME_V1,
        PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1, PRIVATE_NUMERIC_VALCOM_DOMAIN_V1,
        PRIVATE_NUMERIC_VALCOM_H_COMPRESSED_V1, PRIVATE_NUMERIC_VALCOM_H_DST_V1,
        PRIVATE_NUMERIC_VALCOM_H_MESSAGE_V1, PrivateInputKindV1, PrivateInputRecordV1,
    };
    let kind = |value: PrivateInputKindV1, name: &'static str, payload_schema: &'static str| {
        AbiPrivateInputKindSurface {
            name,
            tag: value.tag(),
            pointer_type_id: value.pointer_type() as u16,
            payload_schema,
        }
    };
    Ok(AbiPrivateInputSurface {
        abi_version: PRIVATE_INPUT_ABI_VERSION_V1,
        record_name: PRIVATE_INPUT_RECORD_NAME_V1,
        record_schema_hash: norito::schema::identity::frame_hash::<PrivateInputRecordV1>(),
        record_layout: "canonical-Norito-v1-frame;PrivateInputRecordV1{kind:explicit-u32-codec-index,payload:Vec<u8>};payload-is-one-complete-canonical-schema-bound-numeric-frame",
        kind_discriminant_layout: "u32-little-endian-codec-index;Int=0;Decimal=1;Quantity=2;register-request-tag-is-the-same-numeric-value",
        kinds: vec![
            kind(PrivateInputKindV1::Int, "int", "IntValueV1"),
            kind(PrivateInputKindV1::Decimal, "decimal", "DecimalValueV1"),
            kind(PrivateInputKindV1::Quantity, "quantity", "QuantityValueV1"),
        ],
        max_inputs: u64::try_from(MAX_PRIVATE_INPUTS_V1)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_record_bytes: u64::try_from(MAX_PRIVATE_INPUT_RECORD_BYTES_V1)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_transport_bytes: u64::try_from(MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        transport_validation: "reject-over-count-then-scan-in-order-for-per-record-and-checked-aggregate-byte-bounds-before-host-retention;bounded-malformed-records-decode-only-after-runtime-debit",
        runtime_validation: "fixed-maximum-quote;debit-before-decode-or-allocation;selected-record-bound;canonical-outer-Norito-reencode-equality;exact-requested-kind;numeric-frame-bound-decode-and-reencode-equality;then-opaque-private-HEAP-TLV-allocation",
        projection_domain: PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1,
        projection_layout: "IrohaHash(domain||u16le(abi-version)||u64le(kind-tag)||u64le(complete-envelope-bytes)||complete-canonical-numeric-TLV-envelope);projection-remains-private",
        valcom_domain: PRIVATE_NUMERIC_VALCOM_DOMAIN_V1,
        valcom_h_dst: PRIVATE_NUMERIC_VALCOM_H_DST_V1,
        valcom_h_message: PRIVATE_NUMERIC_VALCOM_H_MESSAGE_V1,
        valcom_h_compressed: PRIVATE_NUMERIC_VALCOM_H_COMPRESSED_V1,
        valcom_scalar_derivation: "for-role-in-{value=0,blind=1}:IrohaHash(valcom-domain||u16le(abi-version)||u8(role)||private-projection),interpreted-little-endian-and-reduced-modulo-BLS12-381-scalar-order-by-exactly-two-unconditional-constant-time-conditional-subtract-rounds;no-secret-dependent-division-loop-or-branch;no-u64-truncation",
        valcom_result: "full-48-byte-compressed-BLS12-381-G1-Pedersen-point-reinterpreted-as-nonnegative-little-endian-Kotodama-int-TLV;runtime-H-is-the-ABI-bound-fixed-compressed-subgroup-point;test-derivation-is-hash_to_curve(message,dst,empty-augmentation)-and-must-equal-that-fixed-point;only-final-result-is-public",
        privacy_rule: "Secret<int|decimal|quantity>-only-source-operands;same-private-visibility;opaque-input-TLV-bytes-cannot-be-loaded-by-guest;no-public-return-log-state-key-state-value-host-write-or-control-flow-before-full-width-valcom",
    })
}
fn collect_abi_syscall_surface(
    syscalls: &[u32],
    docs: &[SyscallDoc],
) -> Result<Vec<AbiSyscallSurface>, AbiSurfaceError> {
    if syscalls.is_empty() {
        return Err(AbiSurfaceError::EmptySyscallSurface);
    }
    if let Some(pair) = syscalls.windows(2).find(|pair| pair[0] >= pair[1]) {
        return Err(AbiSurfaceError::SyscallsNotStrictlySorted {
            previous: pair[0],
            current: pair[1],
        });
    }
    for doc in docs {
        if syscalls.binary_search(&doc.number).is_err() {
            return Err(AbiSurfaceError::UnexpectedSignature(doc.number));
        }
    }
    let mut surface = Vec::with_capacity(syscalls.len());
    for &number in syscalls {
        let mut rows = docs.iter().filter(|doc| doc.number == number);
        let doc = rows
            .next()
            .ok_or(AbiSurfaceError::MissingSignature(number))?;
        if rows.next().is_some() {
            return Err(AbiSurfaceError::DuplicateSignature(number));
        }
        if doc.args.is_empty() {
            return Err(AbiSurfaceError::EmptyArguments(number));
        }
        if doc.ret.is_empty() {
            return Err(AbiSurfaceError::EmptyReturn(number));
        }
        surface.push(AbiSyscallSurface {
            number,
            args: doc.args,
            ret: doc.ret,
            access: syscall_access(number),
        });
    }
    Ok(surface)
}
fn encode_abi_surface(surface: &AbiSurface) -> Result<Vec<u8>, AbiSurfaceError> {
    if surface.syscalls.is_empty() {
        return Err(AbiSurfaceError::EmptySyscallSurface);
    }
    if surface.pointer_type_ids.is_empty() {
        return Err(AbiSurfaceError::EmptyPointerSurface);
    }
    if let Some(pair) = surface
        .syscalls
        .windows(2)
        .find(|pair| pair[0].number >= pair[1].number)
    {
        return Err(AbiSurfaceError::SyscallsNotStrictlySorted {
            previous: pair[0].number,
            current: pair[1].number,
        });
    }
    if let Some(pair) = surface
        .pointer_type_ids
        .windows(2)
        .find(|pair| pair[0] >= pair[1])
    {
        return Err(AbiSurfaceError::PointerTypesNotStrictlySorted {
            previous: pair[0],
            current: pair[1],
        });
    }
    for syscall in &surface.syscalls {
        if syscall.args.is_empty() {
            return Err(AbiSurfaceError::EmptyArguments(syscall.number));
        }
        if syscall.ret.is_empty() {
            return Err(AbiSurfaceError::EmptyReturn(syscall.number));
        }
    }
    let mut descriptor = AbiDescriptorEncoder::default();
    descriptor.field("domain", ABI_V1_SURFACE_DOMAIN)?;
    descriptor.u16(
        "descriptor_format_version",
        surface.descriptor_format_version,
    )?;
    descriptor.u8("policy_tag", surface.policy_tag)?;
    descriptor.text("program_header_layout", surface.program_header_layout)?;
    descriptor.record("generic_program", |generic| {
        generic.u8(
            "semantics_version",
            surface.generic_program.semantics_version,
        )?;
        generic.text(
            "artifact_discriminator",
            surface.generic_program.artifact_discriminator,
        )?;
        generic.text(
            "allowed_syscall_rule",
            surface.generic_program.allowed_syscall_rule,
        )?;
        generic.sequence(
            "denied_syscalls",
            &surface.generic_program.denied_syscalls,
            |record, syscall| record.u32("number", *syscall),
        )?;
        generic.text("rejection", surface.generic_program.rejection)?;
        generic.text(
            "validation_points",
            surface.generic_program.validation_points,
        )?;
        generic.text("durable_state", surface.generic_program.durable_state)?;
        generic.text(
            "reserved_transaction_metadata",
            surface.generic_program.reserved_transaction_metadata,
        )
    })?;
    descriptor.sequence(
        "indexed_literals",
        &surface.indexed_literals,
        |literal, instruction| {
            literal.u8("opcode", instruction.opcode)?;
            literal.text("mnemonic", instruction.mnemonic)?;
            literal.u8("table_kind", instruction.table_kind)?;
            literal.text("payload_layout", instruction.payload_layout)?;
            literal.text("result", instruction.result)
        },
    )?;
    descriptor.sequence("syscalls", &surface.syscalls, |record, syscall| {
        record.u32("number", syscall.number)?;
        record.text("arguments", syscall.args)?;
        record.text("return", syscall.ret)?;
        record.u8("access", syscall_access_tag(syscall.access))
    })?;
    descriptor.sequence(
        "pointer_type_ids",
        &surface.pointer_type_ids,
        |record, type_id| record.u16("type_id", *type_id),
    )?;
    descriptor.record("core_query", |core_query| {
        core_query.text("singular_result", "Option<View>")?;
        core_query.sequence(
            "projections",
            &surface.core_query_projections,
            |projection_record, projection| {
                projection_record.text("name", projection.name)?;
                projection_record.u64("entity_tag", projection.entity_tag)?;
                projection_record.sequence("fields", &projection.fields, |field_record, field| {
                    field_record.text("name", field.name)?;
                    field_record.text("type", field.ty)
                })
            },
        )?;
        core_query.record("page", |page| {
            page.text("name", surface.query_page.name)?;
            page.sequence(
                "fields",
                &surface.query_page.fields,
                |field_record, field| {
                    field_record.text("name", field.name)?;
                    field_record.text("type", field.ty)
                },
            )?;
            page.u8("items_capacity", surface.query_page.items_capacity)?;
            page.text(
                "next_offset_semantics",
                surface.query_page.next_offset_semantics,
            )?;
            page.text("item_ordering", surface.query_page.item_ordering)?;
            page.text("account_filter", surface.query_page.account_filter)
        })
    })?;
    descriptor.record("durable_state", |state| {
        state.u8("semantics_version", surface.durable_state.semantics_version)?;
        state.field(
            "contract_interface_section_magic",
            &surface.durable_state.contract_interface_section_magic,
        )?;
        state.text(
            "contract_interface_section_layout",
            surface.durable_state.contract_interface_section_layout,
        )?;
        state.text(
            "contract_interface_schema_name",
            surface.durable_state.contract_interface_schema_name,
        )?;
        state.field(
            "contract_interface_schema_hash",
            &surface.durable_state.contract_interface_schema_hash,
        )?;
        state.text(
            "embedded_state_type_schema_name",
            surface.durable_state.embedded_state_type_schema_name,
        )?;
        state.field(
            "embedded_state_type_schema_hash",
            &surface.durable_state.embedded_state_type_schema_hash,
        )?;
        state.text(
            "embedded_state_type_tag_layout",
            surface.durable_state.embedded_state_type_tag_layout,
        )?;
        state.u64(
            "embedded_state_type_max_depth",
            surface.durable_state.embedded_state_type_max_depth,
        )?;
        state.text(
            "embedded_state_type_validation",
            surface.durable_state.embedded_state_type_validation,
        )?;
        state.sequence(
            "embedded_state_types",
            &surface.durable_state.embedded_state_types,
            |record, state_type| {
                record.text("name", state_type.name)?;
                record.u8("tag", state_type.tag)?;
                record.text("layout", state_type.layout)?;
                record.field("canonical_sample_frame", &state_type.canonical_sample_frame)
            },
        )?;
        state.u8(
            "dynamic_access_hint_validation_version",
            surface.durable_state.dynamic_access_hint_validation_version,
        )?;
        state.u32(
            "dynamic_access_hint_max_keys",
            surface.durable_state.dynamic_access_hint_max_keys,
        )?;
        state.sequence(
            "dynamic_access_hint_key_types",
            &surface.durable_state.dynamic_access_hint_key_types,
            |record, key_type| record.text("key_type", key_type),
        )?;
        state.sequence(
            "dynamic_access_hint_bound_kinds",
            &surface.durable_state.dynamic_access_hint_bound_kinds,
            |record, bound_kind| record.text("bound_kind", bound_kind),
        )?;
        state.sequence(
            "dynamic_access_hint_reserved_state_identifiers",
            &surface
                .durable_state
                .dynamic_access_hint_reserved_state_identifiers,
            |record, identifier| record.text("identifier", identifier),
        )?;
        state.sequence(
            "dynamic_access_hint_reserved_state_prefixes",
            &surface
                .durable_state
                .dynamic_access_hint_reserved_state_prefixes,
            |record, prefix| record.text("prefix", prefix),
        )?;
        state.text(
            "dynamic_access_hint_validation",
            surface.durable_state.dynamic_access_hint_validation,
        )?;
        state.u64("scan_max_items", surface.durable_state.scan_max_items)?;
        state.u64("max_path_bytes", surface.durable_state.max_path_bytes)?;
        state.u64(
            "max_path_frame_bytes",
            surface.durable_state.max_path_frame_bytes,
        )?;
        state.u64("max_value_bytes", surface.durable_state.max_value_bytes)?;
        state.u64("map_max_key_bytes", surface.durable_state.map_max_key_bytes)?;
        state.u64(
            "map_max_base_bytes",
            surface.durable_state.map_max_base_bytes,
        )?;
        state.u64(
            "map_max_base_frame_bytes",
            surface.durable_state.map_max_base_frame_bytes,
        )?;
        state.u64(
            "map_max_page_bytes",
            surface.durable_state.map_max_page_bytes,
        )?;
        state.text("path_size_unit", surface.durable_state.path_size_unit)?;
        state.text("path_transport", surface.durable_state.path_transport)?;
        state.text("value_storage", surface.durable_state.value_storage)?;
        state.u8("ordering_version", surface.durable_state.ordering_version)?;
        state.text("key_ordering", surface.durable_state.key_ordering)?;
        state.text("prefix_match", surface.durable_state.prefix_match)?;
        state.u8(
            "map_path_derivation_version",
            surface.durable_state.map_path_derivation_version,
        )?;
        state.text(
            "map_path_derivation",
            surface.durable_state.map_path_derivation,
        )?;
        state.text("page_overflow", surface.durable_state.page_overflow)?;
        state.u8(
            "operation_path_rules_version",
            surface.durable_state.operation_path_rules_version,
        )?;
        state.text(
            "operation_path_rules",
            surface.durable_state.operation_path_rules,
        )?;
        state.u8(
            "state_value_validation_version",
            surface.durable_state.state_value_validation_version,
        )?;
        state.text(
            "state_value_validation",
            surface.durable_state.state_value_validation,
        )?;
        state.field(
            "cursor_schema_hash",
            &surface.durable_state.cursor_schema_hash,
        )?;
        state.field(
            "cursor_schema_hash_domain",
            surface.durable_state.cursor_schema_hash_domain,
        )?;
        state.u64("cursor_max_bytes", surface.durable_state.cursor_max_bytes)?;
        state.u64(
            "scan_max_candidates",
            surface.durable_state.scan_max_candidates,
        )?;
        state.text("cursor_layout", surface.durable_state.cursor_layout)?;
        state.text("scan_semantics", surface.durable_state.scan_semantics)?;
        state.record("typed_value", |typed| {
            let value = &surface.durable_state.typed_value;
            typed.u8("wire_format_version", value.wire_format_version)?;
            typed.u16("norito_header_bytes", value.norito_header_bytes)?;
            typed.u8("norito_version_major", value.norito_version_major)?;
            typed.u8("norito_version_minor", value.norito_version_minor)?;
            typed.u8(
                "norito_default_encode_flags",
                value.norito_default_encode_flags,
            )?;
            typed.text("enum_discriminant_layout", value.enum_discriminant_layout)?;
            typed.field("schema_payload_magic", &value.schema_payload_magic)?;
            typed.u8("schema_node_count_bytes", value.schema_node_count_bytes)?;
            typed.u8("schema_node_tag_bytes", value.schema_node_tag_bytes)?;
            typed.u8("schema_kind_tag_bytes", value.schema_kind_tag_bytes)?;
            typed.field("record_payload_magic", &value.record_payload_magic)?;
            typed.u8("record_stream_count_bytes", value.record_stream_count_bytes)?;
            typed.u8("record_atom_tag_bytes", value.record_atom_tag_bytes)?;
            typed.u8(
                "record_pointer_length_bytes",
                value.record_pointer_length_bytes,
            )?;
            typed.u8(
                "record_list_item_count_bytes",
                value.record_list_item_count_bytes,
            )?;
            typed.field("schema_hash_domain", value.schema_hash_domain)?;
            typed.text("schema_hash_algorithm", value.schema_hash_algorithm)?;
            typed.text("schema_name", value.schema_name)?;
            typed.field("schema_hash", &value.schema_hash)?;
            typed.text("record_name", value.record_name)?;
            typed.field("record_hash", &value.record_hash)?;
            typed.text("schema_layout", value.schema_layout)?;
            typed.text("record_layout", value.record_layout)?;
            typed.text("traversal_semantics", value.traversal_semantics)?;
            typed.text("option_tag_semantics", value.option_tag_semantics)?;
            typed.text("result_tag_semantics", value.result_tag_semantics)?;
            typed.sequence("kinds", &value.kinds, |kind_record, kind| {
                kind_record.text("name", kind.name)?;
                kind_record.u32("tag", kind.tag)?;
                kind_record.text("word_layout", kind.word_layout)?;
                kind_record.u16("pointer_type_id_or_zero", kind.pointer_type_id_or_zero)
            })?;
            typed.sequence("nodes", &value.nodes, |node_record, node| {
                node_record.text("name", node.name)?;
                node_record.u32("tag", node.tag)?;
                node_record.text("layout", node.layout)
            })?;
            typed.sequence("atoms", &value.atoms, |atom_record, atom| {
                atom_record.text("name", atom.name)?;
                atom_record.u32("tag", atom.tag)?;
                atom_record.text("layout", atom.layout)
            })?;
            typed.u64("max_nodes", value.max_nodes)?;
            typed.u64("max_depth", value.max_depth)?;
            typed.u64("max_words", value.max_words)?;
            typed.u64("max_schema_bytes", value.max_schema_bytes)?;
            typed.u64("max_record_bytes", value.max_record_bytes)?;
            typed.u8("list_min_capacity", value.list_min_capacity)?;
            typed.u8("list_max_capacity", value.list_max_capacity)?;
            typed.u16("decoded_table_offset", value.decoded_table_offset)?;
            typed.u16("decoded_word_bytes", value.decoded_word_bytes)
        })
    })?;
    descriptor.record("entrypoint", |entrypoint| {
        entrypoint.u8("schema_version", surface.entrypoint.schema_version)?;
        entrypoint.text("call_table_layout", surface.entrypoint.call_table_layout)?;
        entrypoint.text("call_frame_checks", surface.entrypoint.call_frame_checks)?;
        entrypoint.u64("max_call_words", surface.entrypoint.max_call_words)?;
        entrypoint.text("value_utilities", surface.entrypoint.value_utilities)?;
        entrypoint.text("context_address", surface.entrypoint.context_address)?;
        entrypoint.text("unit_layout", surface.entrypoint.unit_layout)?;
        entrypoint.text("struct_identity", surface.entrypoint.struct_identity)?;
        entrypoint.text("vrf_epoch_seed", surface.entrypoint.vrf_epoch_seed)?;
        entrypoint.text("error_layout", surface.entrypoint.error_layout)?;
        entrypoint.text("enum_layout", surface.entrypoint.enum_layout)?;
        entrypoint.text("sum_json", surface.entrypoint.sum_json)?;
        entrypoint.text("invocation_outcome", surface.entrypoint.invocation_outcome)?;
        entrypoint.field("fault_schema_hash", &surface.entrypoint.fault_schema_hash)?;
        entrypoint.text("fault_layout", surface.entrypoint.fault_layout)?;
        entrypoint.text("fault_semantics", surface.entrypoint.fault_semantics)?;
        entrypoint.text("event_layout", surface.entrypoint.event_layout)?;
        entrypoint.text("event_semantics", surface.entrypoint.event_semantics)?;
        entrypoint.text("authorization", surface.entrypoint.authorization)?;
        entrypoint.text("lifecycle", surface.entrypoint.lifecycle)?;
        entrypoint.text("int_kind", surface.entrypoint.int_kind)?;
        entrypoint.u16(
            "int_pointer_type_id",
            surface.entrypoint.int_pointer_type_id,
        )?;
        entrypoint.text("decimal_kind", surface.entrypoint.decimal_kind)?;
        entrypoint.u16(
            "decimal_pointer_type_id",
            surface.entrypoint.decimal_pointer_type_id,
        )?;
        entrypoint.text("quantity_kind", surface.entrypoint.quantity_kind)?;
        entrypoint.u16(
            "quantity_pointer_type_id",
            surface.entrypoint.quantity_pointer_type_id,
        )?;
        entrypoint.text("list_kind", surface.entrypoint.list_kind)?;
        entrypoint.text("list_layout", surface.entrypoint.list_layout)?;
        entrypoint.u8("list_child_count", surface.entrypoint.list_child_count)?;
        entrypoint.bool(
            "list_capacity_is_schema_bound",
            surface.entrypoint.list_capacity_is_schema_bound,
        )?;
        entrypoint.u8("list_min_capacity", surface.entrypoint.list_min_capacity)?;
        entrypoint.u8("list_max_capacity", surface.entrypoint.list_max_capacity)?;
        entrypoint.u64("max_schema_nodes", surface.entrypoint.max_schema_nodes)?;
        entrypoint.u64("max_schema_depth", surface.entrypoint.max_schema_depth)
    })?;
    descriptor.record("numeric", |numeric| {
        numeric.u16("int_pointer_type_id", surface.numeric.int_pointer_type_id)?;
        numeric.u16(
            "decimal_pointer_type_id",
            surface.numeric.decimal_pointer_type_id,
        )?;
        numeric.u16(
            "quantity_pointer_type_id",
            surface.numeric.quantity_pointer_type_id,
        )?;
        numeric.u16("mantissa_bits", surface.numeric.mantissa_bits)?;
        numeric.u8("max_scale", surface.numeric.max_scale)?;
        numeric.record("semantics", |semantics| {
            semantics.u8(
                "descriptor_version",
                surface.numeric.semantics_descriptor_version,
            )?;
            semantics.text("int_domain", surface.numeric.int_domain)?;
            semantics.text("decimal_domain", surface.numeric.decimal_domain)?;
            semantics.text("quantity_domain", surface.numeric.quantity_domain)?;
            semantics.text("canonicalization", surface.numeric.canonicalization)?;
            semantics.text("integer_division", surface.numeric.integer_division)?;
            semantics.text("wrapping_modulus", surface.numeric.wrapping_modulus)?;
            semantics.sequence("rules", &surface.numeric.rules, |rule_record, rule| {
                rule_record.text("name", rule.name)?;
                rule_record.text("specification", rule.specification)
            })?;
            semantics.sequence(
                "operators",
                &surface.numeric.operators,
                |operator_record, operator| {
                    operator_record.text("operator", operator.operator)?;
                    operator_record.text("lhs", operator.lhs)?;
                    operator_record.text("rhs", operator.rhs)?;
                    operator_record.bool("allowed", operator.allowed)?;
                    operator_record.text("result", operator.result)?;
                    operator_record.text("semantics", operator.semantics)
                },
            )?;
            semantics.sequence(
                "json_grammar",
                &surface.numeric.json_grammar,
                |json_record, grammar| {
                    json_record.text("type_name", grammar.type_name)?;
                    json_record.text("token_kind", grammar.token_kind)?;
                    json_record.text("decoded_string_grammar", grammar.decoded_string_grammar)?;
                    json_record.text("validation", grammar.validation)
                },
            )?;
            semantics.sequence(
                "fault_ordering",
                &surface.numeric.fault_ordering,
                |fault_record, rule| {
                    fault_record.text("name", rule.name)?;
                    fault_record.text("specification", rule.specification)
                },
            )?;
            semantics.text("full_error_precedence", surface.numeric.error_precedence)
        })?;
        numeric.text("int_domain", surface.numeric.int_domain)?;
        numeric.text("decimal_domain", surface.numeric.decimal_domain)?;
        numeric.text("quantity_domain", surface.numeric.quantity_domain)?;
        numeric.text("canonicalization", surface.numeric.canonicalization)?;
        numeric.text("integer_division", surface.numeric.integer_division)?;
        numeric.text("wrapping_modulus", surface.numeric.wrapping_modulus)?;
        numeric.u8("wire_format_version", surface.numeric.wire_format_version)?;
        numeric.text("int_schema_name", surface.numeric.int_schema_name)?;
        numeric.field("int_schema_hash", &surface.numeric.int_schema_hash)?;
        numeric.text("decimal_schema_name", surface.numeric.decimal_schema_name)?;
        numeric.field("decimal_schema_hash", &surface.numeric.decimal_schema_hash)?;
        numeric.text("quantity_schema_name", surface.numeric.quantity_schema_name)?;
        numeric.field(
            "quantity_schema_hash",
            &surface.numeric.quantity_schema_hash,
        )?;
        numeric.u64("frame_header_bytes", surface.numeric.frame_header_bytes)?;
        numeric.u64("int_max_frame_bytes", surface.numeric.int_max_frame_bytes)?;
        numeric.u64(
            "decimal_max_frame_bytes",
            surface.numeric.decimal_max_frame_bytes,
        )?;
        numeric.u64(
            "quantity_max_frame_bytes",
            surface.numeric.quantity_max_frame_bytes,
        )?;
        numeric.u64(
            "pointer_envelope_overhead_bytes",
            surface.numeric.pointer_envelope_overhead_bytes,
        )?;
        numeric.u64(
            "int_max_envelope_bytes",
            surface.numeric.int_max_envelope_bytes,
        )?;
        numeric.u64(
            "decimal_max_envelope_bytes",
            surface.numeric.decimal_max_envelope_bytes,
        )?;
        numeric.u64(
            "quantity_max_envelope_bytes",
            surface.numeric.quantity_max_envelope_bytes,
        )?;
        numeric.text("frame_layout", surface.numeric.frame_layout)?;
        numeric.text(
            "pointer_envelope_layout",
            surface.numeric.pointer_envelope_layout,
        )?;
        numeric.text("error_precedence", surface.numeric.error_precedence)?;
        numeric.sequence(
            "rounding_modes",
            &surface.numeric.rounding_modes,
            |rounding, mode| {
                rounding.text("name", mode.name)?;
                rounding.u64("tag", mode.tag)
            },
        )?;
        numeric.sequence(
            "failure_modes",
            &surface.numeric.failure_modes,
            |failure, mode| {
                failure.text("name", mode.name)?;
                failure.u64("tag", mode.tag)
            },
        )?;
        numeric.sequence("faults", &surface.numeric.faults, |fault, value| {
            fault.text("name", value.name)?;
            fault.u64("tag", value.tag)
        })?;
        numeric.sequence(
            "pointer_faults",
            &surface.numeric.pointer_faults,
            |fault, value| {
                fault.text("name", value.name)?;
                fault.u64("tag", value.tag)
            },
        )
    })?;
    descriptor.record("private_input", |private| {
        let surface = &surface.private_input;
        private.u16("abi_version", surface.abi_version)?;
        private.text("record_name", surface.record_name)?;
        private.field("record_schema_hash", &surface.record_schema_hash)?;
        private.text("record_layout", surface.record_layout)?;
        private.text("kind_discriminant_layout", surface.kind_discriminant_layout)?;
        private.sequence("kinds", &surface.kinds, |kind_record, kind| {
            kind_record.text("name", kind.name)?;
            kind_record.u64("tag", kind.tag)?;
            kind_record.u16("pointer_type_id", kind.pointer_type_id)?;
            kind_record.text("payload_schema", kind.payload_schema)
        })?;
        private.u64("max_inputs", surface.max_inputs)?;
        private.u64("max_record_bytes", surface.max_record_bytes)?;
        private.u64("max_transport_bytes", surface.max_transport_bytes)?;
        private.text("transport_validation", surface.transport_validation)?;
        private.text("runtime_validation", surface.runtime_validation)?;
        private.field("projection_domain", surface.projection_domain)?;
        private.text("projection_layout", surface.projection_layout)?;
        private.field("valcom_domain", surface.valcom_domain)?;
        private.field("valcom_h_dst", surface.valcom_h_dst)?;
        private.field("valcom_h_message", surface.valcom_h_message)?;
        private.field("valcom_h_compressed", &surface.valcom_h_compressed)?;
        private.text("valcom_scalar_derivation", surface.valcom_scalar_derivation)?;
        private.text("valcom_result", surface.valcom_result)?;
        private.text("privacy_rule", surface.privacy_rule)
    })?;
    Ok(descriptor.finish())
}
fn embedded_state_type_surface_v1() -> Result<Vec<AbiEmbeddedStateTypeSurface>, AbiSurfaceError> {
    use crate::metadata::{EmbeddedStateFieldDescriptor as Field, EmbeddedStateType as Type};
    let samples = vec![
        ("Int", Type::Int, "u8-tag"),
        ("Decimal", Type::Decimal, "u8-tag"),
        ("Quantity", Type::Quantity, "u8-tag"),
        ("Bool", Type::Bool, "u8-tag"),
        ("String", Type::String, "u8-tag"),
        ("Bytes", Type::Bytes, "u8-tag"),
        ("DataSpaceId", Type::DataSpaceId, "u8-tag"),
        ("AccountId", Type::AccountId, "u8-tag"),
        ("AssetDefinitionId", Type::AssetDefinitionId, "u8-tag"),
        ("AssetId", Type::AssetId, "u8-tag"),
        ("NftId", Type::NftId, "u8-tag"),
        ("DomainId", Type::DomainId, "u8-tag"),
        ("Name", Type::Name, "u8-tag"),
        ("Json", Type::Json, "u8-tag"),
        (
            "Tuple",
            Type::Tuple(vec![Type::Int, Type::Decimal]),
            "u8-tag+Vec<EmbeddedStateTypeV1>;arity-at-least-2",
        ),
        (
            "Struct",
            Type::Struct {
                name: "Fixture::Sample".to_owned(),
                fields: vec![
                    Field {
                        name: "left".to_owned(),
                        ty: Type::Int,
                    },
                    Field {
                        name: "right".to_owned(),
                        ty: Type::Decimal,
                    },
                ],
            },
            "u8-tag+String(name)+Vec<{String(name),EmbeddedStateTypeV1}>;nonempty-unique-fields",
        ),
        (
            "StateMap",
            Type::StateMap {
                key: Box::new(Type::Int),
                value: Box::new(Type::Quantity),
            },
            "u8-tag+owned(key)+owned(value);top-level-only;key-is-supported-canonical-scalar",
        ),
        (
            "Option",
            Type::Option(Box::new(Type::Int)),
            "u8-tag+owned(value)",
        ),
        (
            "Result",
            Type::Result {
                ok: Box::new(Type::Int),
                err: Box::new(Type::Decimal),
            },
            "u8-tag+owned(ok)+owned(err)",
        ),
        (
            "List",
            Type::List {
                element: Box::new(Type::Quantity),
                capacity: 64,
            },
            "u8-tag+owned(element)+u8(capacity);capacity=1..64;no-StateMap-descendant",
        ),
        ("Unit", Type::Unit, "u8-tag;one-canonical-zero-scalar-word"),
        (
            "Error",
            Type::Error(crate::error_types::list_error_type()),
            "u8-tag+canonical-Norito-ContractErrorTypeDescriptor;one-u32-code-scalar-word",
        ),
        (
            "StateCursor",
            Type::StateCursor(crate::entrypoint::EntrypointValueTypeV1 { nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(crate::entrypoint::EntrypointValueKindV1::Int)] }),
            "u8-tag+complete-EntrypointValueTypeV1-key-schema;one-NoritoBytes-pointer-to-canonical-StateCursorV1-frame",
        ),
        (
            "Enum",
            Type::Enum(iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1 {
                identity: "Example::Status".into(),
                variants: vec![iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Ready".into(), code: 1 }],
            }),
            "u8-tag+canonical-Norito-ContractEnumTypeDescriptorV1;one-nonzero-u32-ordinary-enum-code;no-error-catalog",
        ),
    ];
    samples
        .into_iter()
        .map(|(name, value, layout)| {
            let tag = value.wire_tag();
            let canonical_sample_frame =
                norito::encode_canonical(&value).map_err(|_| AbiSurfaceError::SurfaceTooLarge)?;
            Ok(AbiEmbeddedStateTypeSurface {
                name,
                tag,
                layout,
                canonical_sample_frame,
            })
        })
        .collect()
}
fn typed_state_value_surface_v1() -> Result<AbiTypedStateValueSurface, AbiSurfaceError> {
    use crate::state_value::{
        DECODED_STATE_VALUE_TABLE_OFFSET, DECODED_STATE_VALUE_WORD_BYTES,
        MAX_STATE_VALUE_LIST_CAPACITY_V1, MAX_STATE_VALUE_NODES, MAX_STATE_VALUE_RECORD_BYTES,
        MAX_STATE_VALUE_SCHEMA_BYTES, MAX_STATE_VALUE_WORDS, MIN_STATE_VALUE_LIST_CAPACITY_V1,
        STATE_VALUE_RECORD_ATOM_TAG_BYTES_V1, STATE_VALUE_RECORD_LIST_ITEM_COUNT_BYTES_V1,
        STATE_VALUE_RECORD_NAME_V1, STATE_VALUE_RECORD_PAYLOAD_MAGIC_V1,
        STATE_VALUE_RECORD_POINTER_LENGTH_BYTES_V1, STATE_VALUE_RECORD_STREAM_COUNT_BYTES_V1,
        STATE_VALUE_SCHEMA_HASH_DOMAIN_V1, STATE_VALUE_SCHEMA_KIND_TAG_BYTES_V1,
        STATE_VALUE_SCHEMA_NAME_V1, STATE_VALUE_SCHEMA_NODE_COUNT_BYTES_V1,
        STATE_VALUE_SCHEMA_NODE_TAG_BYTES_V1, STATE_VALUE_SCHEMA_PAYLOAD_MAGIC_V1,
        StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
        StateValueSchemaV1,
    };
    let kind = |value: StateValueKindV1, name: &'static str, word_layout: &'static str| {
        AbiStateValueKindSurface {
            name,
            tag: value.tag(),
            word_layout,
            pointer_type_id_or_zero: value
                .pointer_type()
                .map_or(0, |pointer_type| pointer_type as u16),
        }
    };
    let kinds = vec![
        kind(
            StateValueKindV1::Int,
            "Int",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::Decimal,
            "Decimal",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::Quantity,
            "Quantity",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::Bool,
            "Bool",
            "one-inline-u64-word;only-0-or-1",
        ),
        kind(
            StateValueKindV1::String,
            "String",
            "one-u64-pointer-word;complete-canonical-TLV;payload-is-UTF-8",
        ),
        kind(
            StateValueKindV1::Json,
            "Json",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::Bytes,
            "Bytes",
            "one-u64-pointer-word;source-is-complete-canonical-Blob-or-NoritoBytes-TLV;persisted-pointer-atom-is-canonical-Blob-TLV;payload-is-raw-bytes",
        ),
        kind(
            StateValueKindV1::AccountId,
            "AccountId",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::AssetDefinitionId,
            "AssetDefinitionId",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::AssetId,
            "AssetId",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::DomainId,
            "DomainId",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::NftId,
            "NftId",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::Name,
            "Name",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::DataSpaceId,
            "DataSpaceId",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::AxtDescriptor,
            "AxtDescriptor",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::ProofBlob,
            "ProofBlob",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::SoracloudRequest,
            "SoracloudRequest",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
        kind(
            StateValueKindV1::SoracloudResponse,
            "SoracloudResponse",
            "one-u64-pointer-word;complete-canonical-TLV",
        ),
    ];
    let nodes = vec![
        AbiTaggedLayoutSurface {
            name: "Struct",
            tag: StateValueNodeV1::STRUCT_TAG,
            layout: "u8-tag+canonical-Norito-String(name)+canonical-Norito-Vec<String>(ordered-field-names);one-inline-immediate-child-subtree-per-field;zero-fields=one-zero-runtime-slot-and-no-record-atoms",
        },
        AbiTaggedLayoutSurface {
            name: "Tuple",
            tag: StateValueNodeV1::TUPLE_TAG,
            layout: "u8-tag+u16le(arity);arity-at-least-2;one-inline-immediate-child-subtree-per-position",
        },
        AbiTaggedLayoutSurface {
            name: "Option",
            tag: StateValueNodeV1::OPTION_TAG,
            layout: "u8-tag;exactly-one-inline-immediate-child-subtree",
        },
        AbiTaggedLayoutSurface {
            name: "Result",
            tag: StateValueNodeV1::RESULT_TAG,
            layout: "u8-tag;exactly-two-inline-immediate-child-subtrees-in-ok-then-error-order",
        },
        AbiTaggedLayoutSurface {
            name: "List",
            tag: StateValueNodeV1::LIST_TAG,
            layout: "u8-tag+u8(capacity)+one-inline-element-subtree;capacity-is-schema-bound;element-schema-boundary-is-reconstructed-from-the-flat-preorder-tree",
        },
        AbiTaggedLayoutSurface {
            name: "Leaf",
            tag: StateValueNodeV1::LEAF_TAG,
            layout: "u8-tag+u8(StateValueKindV1-tag)",
        },
        AbiTaggedLayoutSurface {
            name: "Unit",
            tag: StateValueNodeV1::UNIT_TAG,
            layout: "u8-tag;no-payload;one-canonical-zero-scalar-word",
        },
        AbiTaggedLayoutSurface {
            name: "Error",
            tag: StateValueNodeV1::ERROR_TAG,
            layout: "u8-tag+canonical-Norito-ContractErrorTypeDescriptor;code-must-belong-to-exact-nominal-schema",
        },
        AbiTaggedLayoutSurface {
            name: "StateCursor",
            tag: StateValueNodeV1::STATE_CURSOR_TAG,
            layout: "u8-tag+complete-EntrypointValueTypeV1-key-schema;opaque-one-word-canonical-NoritoBytes-pointer;frame-key-schema-hash-must-match",
        },
        AbiTaggedLayoutSurface {
            name: "Enum",
            tag: StateValueNodeV1::ENUM_TAG,
            layout: "u8-tag+canonical-Norito-ContractEnumTypeDescriptorV1;nonzero-code-must-belong-to-exact-ordinary-enum-schema",
        },
    ];
    let atoms = vec![
        AbiTaggedLayoutSurface {
            name: "Tag",
            tag: StateValueAtomV1::TAG_TAG,
            layout: "KRV1-u8-tag+u8-bool(only-0-or-1);compiler-owned-option-or-result-discriminant",
        },
        AbiTaggedLayoutSurface {
            name: "Bool",
            tag: StateValueAtomV1::BOOL_TAG,
            layout: "KRV1-u8-tag+u8-bool(only-0-or-1)",
        },
        AbiTaggedLayoutSurface {
            name: "Pointer",
            tag: StateValueAtomV1::POINTER_TAG,
            layout: "KRV1-u8-tag+u32le(byte-length)+raw-bytes(complete-validated-pointer-ABI-TLV-envelope)",
        },
        AbiTaggedLayoutSurface {
            name: "List",
            tag: StateValueAtomV1::LIST_TAG,
            layout: "KRV1-u8-tag+u8(item-count-0..64)+each-item-as-u16le(atom-count-0..256)+inline-active-only-element-atom-stream;items-in-order",
        },
        AbiTaggedLayoutSurface {
            name: "Unit",
            tag: StateValueAtomV1::UNIT_TAG,
            layout: "KRV1-u8-tag;no-payload;materializes-zero-word",
        },
        AbiTaggedLayoutSurface {
            name: "ErrorCode",
            tag: StateValueAtomV1::ERROR_CODE_TAG,
            layout: "KRV1-u8-tag+u32le(nonzero-variant-code);requires-nominal-schema-membership",
        },
        AbiTaggedLayoutSurface {
            name: "EnumCode",
            tag: StateValueAtomV1::ENUM_CODE_TAG,
            layout: "KRV1-u8-tag+u32le(nonzero-variant-code);requires-exact-ordinary-enum-schema-membership;not-an-error-code",
        },
    ];
    Ok(AbiTypedStateValueSurface {
        wire_format_version: 1,
        norito_header_bytes: u16::try_from(norito::core::Header::SIZE)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        norito_version_major: norito::core::VERSION_MAJOR,
        norito_version_minor: norito::core::VERSION_MINOR,
        norito_default_encode_flags: ABI_V1_NORITO_ENCODE_FLAGS,
        enum_discriminant_layout: "standalone-StateValueKindV1-StateValueNodeV1-and-StateValueAtomV1=explicit-u32le-codec-index-followed-by-variant-fields;KSV1-flat-schema-node-and-kind-tags=explicit-u8;KRV1-flat-record-atom-tags=explicit-u8",
        schema_payload_magic: STATE_VALUE_SCHEMA_PAYLOAD_MAGIC_V1,
        schema_node_count_bytes: STATE_VALUE_SCHEMA_NODE_COUNT_BYTES_V1,
        schema_node_tag_bytes: STATE_VALUE_SCHEMA_NODE_TAG_BYTES_V1,
        schema_kind_tag_bytes: STATE_VALUE_SCHEMA_KIND_TAG_BYTES_V1,
        record_payload_magic: STATE_VALUE_RECORD_PAYLOAD_MAGIC_V1,
        record_stream_count_bytes: STATE_VALUE_RECORD_STREAM_COUNT_BYTES_V1,
        record_atom_tag_bytes: STATE_VALUE_RECORD_ATOM_TAG_BYTES_V1,
        record_pointer_length_bytes: STATE_VALUE_RECORD_POINTER_LENGTH_BYTES_V1,
        record_list_item_count_bytes: STATE_VALUE_RECORD_LIST_ITEM_COUNT_BYTES_V1,
        schema_hash_domain: STATE_VALUE_SCHEMA_HASH_DOMAIN_V1,
        schema_hash_algorithm: "iroha_crypto::Hash::new(schema-hash-domain||exact-canonical-Norito-schema-frame)",
        schema_name: STATE_VALUE_SCHEMA_NAME_V1,
        schema_hash: norito::schema::identity::frame_hash::<StateValueSchemaV1>(),
        record_name: STATE_VALUE_RECORD_NAME_V1,
        record_hash: norito::schema::identity::frame_hash::<StateValueRecordV1>(),
        schema_layout: "canonical-Norito-v1-frame;header=NRT0+version+schema+compression-none+payload-length+crc64+advertised-layout-flags;archived-value=Vec<u8>(KSV1||u16le(total-logical-node-count)||flat-preorder-u8-node-and-kind-tag-stream);List-capacity-precedes-inline-element-subtree;exactly-one-root;iterative-encode-decode",
        record_layout: "canonical-Norito-v1-frame;header=NRT0+version+schema+compression-none+payload-length+crc64+advertised-layout-flags;archived-value=Vec<u8>(KRV1||schema-hash-[u8;32]||root-u16le-atom-count(0..256)||flat-active-only-atom-stream);atom=u8-tag+variant-payload;Tag-and-Bool=u8(only-0-or-1);Pointer=u32le-byte-length+raw-bytes;List=u8-item-count(0..64)+each-item-u16le-atom-count(0..256)+inline-item-stream;iterative-encode-decode-drop",
        traversal_semantics: "schema-is-exactly-one-preorder-tree;products-store-children-in-order;sums-and-lists-consume-one-compiler-owned-word;record-atoms-contain-only-active-sum-payloads;empty-struct=one-zero-runtime-slot-and-empty-schema-bound-atom-stream",
        option_tag_semantics: "false=None-with-no-payload;true=Some-with-one-active-child-payload",
        result_tag_semantics: "false=Err-with-error-child-payload;true=Ok-with-ok-child-payload",
        kinds,
        nodes,
        atoms,
        max_nodes: u64::try_from(MAX_STATE_VALUE_NODES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_depth: u64::try_from(MAX_STATE_VALUE_NODES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_words: u64::try_from(MAX_STATE_VALUE_WORDS)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_schema_bytes: u64::try_from(MAX_STATE_VALUE_SCHEMA_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_record_bytes: u64::try_from(MAX_STATE_VALUE_RECORD_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        list_min_capacity: MIN_STATE_VALUE_LIST_CAPACITY_V1,
        list_max_capacity: MAX_STATE_VALUE_LIST_CAPACITY_V1,
        decoded_table_offset: u16::try_from(DECODED_STATE_VALUE_TABLE_OFFSET)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        decoded_word_bytes: u16::try_from(DECODED_STATE_VALUE_WORD_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
    })
}
fn collect_abi_surface(policy: crate::SyscallPolicy) -> Result<AbiSurface, AbiSurfaceError> {
    let crate::SyscallPolicy::AbiV1 = policy;
    let syscalls =
        collect_abi_syscall_surface(syscalls_for_policy(policy), syscalls_doc_gen::DOCS)?;
    let mut pointer_type_ids = crate::pointer_abi::policy_pointer_types(policy)
        .iter()
        .map(|pointer_type| *pointer_type as u16)
        .collect::<Vec<_>>();
    pointer_type_ids.sort_unstable();
    let (core_query_projections, query_page, entrypoint, numeric) = semantic_abi_surface_v1()?;
    let private_input = private_input_surface_v1()?;
    let indexed_literals = vec![
        AbiIndexedLiteralSurface {
            opcode: crate::instruction::wide::memory::LDLIT,
            mnemonic: "LDLIT",
            table_kind: crate::metadata::LiteralKindV1::PointerTlv as u8,
            payload_layout: "exact ABI-v1 pointer TLV envelope",
            result: "validated code-memory pointer",
        },
        AbiIndexedLiteralSurface {
            opcode: crate::instruction::wide::memory::LDI64,
            mnemonic: "LDI64",
            table_kind: crate::metadata::LiteralKindV1::I64 as u8,
            payload_layout: "exact 8-byte little-endian signed i64",
            result: "sign-preserving 64-bit register value",
        },
    ];
    let generic_program = AbiGenericProgramSurface {
        semantics_version: 1,
        artifact_discriminator: "canonical-CNTR-section-absent-after-fixed-header-and-optional-literal-table",
        allowed_syscall_rule: "exact-ABI-policy-surface-minus-denied-syscalls",
        denied_syscalls: GENERIC_PROGRAM_DENIED_SYSCALLS_V1.to_vec(),
        rejection: "GenericSyscallNotAllowed(syscall-number)-before-side-effects",
        validation_points: "static-instruction-analysis-during-admission-and-defense-in-depth-before-host-quote-or-dispatch",
        durable_state: "unavailable-without-authenticated-contract-identity-and-namespace",
        reserved_transaction_metadata: "reject-presence-before-decode-in-order:contract_manifest,gov_contract_address,gov_manifest_approvers,contract_address,contract_alias,contract_entrypoint,contract_payload",
    };
    let durable_state = AbiDurableStateSurface {
        semantics_version: 6,
        contract_interface_section_magic: crate::metadata::CONTRACT_INTERFACE_SECTION_MAGIC,
        contract_interface_section_layout: "ASCII-CNTR+u32le(payload-bytes)+canonical-Norito-frame(EmbeddedContractInterfaceV1 fields in exact order:seiyaku_name,compiler_fingerprint,abi_hash[32],features_bitmap,access_set_hints,permissions,events,kotoba,entrypoints,callables,states,error_types,enum_types,error_messages);abi_hash=Iroha-Hash-v1(canonical-ABI-descriptor-for-declared-abi_version;Blake2b-256-with-final-byte-LSB-set-to-1)-and-must-equal-runtime-descriptor-before-admission",
        contract_interface_schema_name: crate::metadata::CONTRACT_INTERFACE_SCHEMA_NAME_V1,
        contract_interface_schema_hash: norito::schema::identity::frame_hash::<
            crate::metadata::EmbeddedContractInterfaceV1,
        >(),
        embedded_state_type_schema_name: crate::metadata::EMBEDDED_STATE_TYPE_SCHEMA_NAME_V1,
        embedded_state_type_schema_hash: norito::schema::identity::frame_hash::<
            crate::metadata::EmbeddedStateType,
        >(),
        embedded_state_type_tag_layout: "one-u8-tag-at-start-of-custom-length-delimited-payload",
        embedded_state_type_max_depth: u64::try_from(
            crate::metadata::MAX_EMBEDDED_STATE_TYPE_DEPTH_V1,
        )
        .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        embedded_state_type_validation: "top-level-state-is-scalar-or-exactly-one-StateMap;StateMap-forbidden-below-top-level;map-key-in-{Int,Decimal,Quantity,Bool,String,Bytes,DataSpaceId,AccountId,AssetDefinitionId,AssetId,NftId,DomainId,Name};Tuple-arity-at-least-2;Struct-name-and-nonempty-field-names-are-canonical-and-fields-are-unique-and-nonempty;List-capacity=1..64-and-no-StateMap-descendant",
        embedded_state_types: embedded_state_type_surface_v1()?,
        dynamic_access_hint_validation_version: 1,
        dynamic_access_hint_max_keys: crate::access_hints::DYNAMIC_ACCESS_HINT_MAX_KEYS_V1,
        dynamic_access_hint_key_types: crate::access_hints::DYNAMIC_ACCESS_HINT_KEY_TYPES_V1
            .to_vec(),
        dynamic_access_hint_bound_kinds: crate::access_hints::DYNAMIC_ACCESS_HINT_BOUND_KINDS_V1
            .to_vec(),
        dynamic_access_hint_reserved_state_identifiers:
            crate::access_hints::DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1.to_vec(),
        dynamic_access_hint_reserved_state_prefixes:
            crate::access_hints::DYNAMIC_ACCESS_HINT_RESERVED_STATE_PREFIXES_V1.to_vec(),
        dynamic_access_hint_validation: "base_key=ASCII-state-colon-plus-one-generated-exact-canonical-state-declaration-identifier-with-no-aliasing-or-trimming;target=exact-declared-top-level-StateMap;key_type=exact-declared-map-key-type;bound_kind=exact-{page,take};max_keys=1..64;duplicate=full-{base_key,key_type,bound_kind,max_keys}-record-equality-rejected-independently-within-each-list;cross-read-write-repeat=allowed;metadata=advisory-and-never-scheduler-authoritative",
        scan_max_items: STATE_SCAN_MAX_ITEMS_V1,
        max_path_bytes: u64::try_from(STATE_MAX_PATH_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_path_frame_bytes: u64::try_from(STATE_MAX_PATH_FRAME_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        max_value_bytes: u64::try_from(STATE_MAX_VALUE_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        map_max_key_bytes: u64::try_from(STATE_MAP_MAX_KEY_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        map_max_base_bytes: u64::try_from(STATE_MAP_MAX_BASE_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        map_max_base_frame_bytes: u64::try_from(STATE_MAP_MAX_BASE_FRAME_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        map_max_page_bytes: u64::try_from(STATE_MAP_MAX_PAGE_BYTES)
            .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
        path_size_unit: "canonical StatePath UTF-8 bytes; canonical-Norito transport frame bounded separately",
        path_transport: "STATE_GET,STATE_SET,STATE_DEL,STATE_SCAN,STATE_HAS,STATE_LEN,STATE_COUNT=&NoritoBytes(canonical-Norito-StatePath);STATE_PATH_FROM_NAME-input=&Name-and-output=&NoritoBytes(canonical-Norito-StatePath);BUILD_PATH_KEY_NORITO-input-base=&Name-and-output=&NoritoBytes(canonical-Norito-StatePath);STATE_SCAN-page=&NoritoBytes(canonical-Norito-Vec<StatePath>);STATE_MAP_KEY_AT-base=&Name",
        value_storage: "raw NoritoBytes payload; pointer boundary wraps exactly once",
        ordering_version: 1,
        key_ordering: "canonical StatePath order; StateMap lowercase-hex suffixes preserve canonical Norito key byte order",
        prefix_match: "key equals prefix or remaining suffix begins with slash",
        map_path_derivation_version: 1,
        map_path_derivation: "canonical-Name-base(<=255-UTF8-bytes) + slash + lowercase_hex(canonical_norito_key_payload<=4096-bytes); result is canonical StatePath<=16384-UTF8-bytes",
        page_overflow: "reject before selected-page materialization",
        operation_path_rules_version: 1,
        operation_path_rules: "canonical-StatePath-transport-only;CNTR-present:value-operations(STATE_GET,STATE_SET,STATE_DEL,STATE_HAS,STATE_LEN)=declared-non-map-base-or-canonical-StateMap-child-only;bare-StateMap-base-rejected;count-operation(STATE_COUNT)=same-declared-path-validation-with-bare-StateMap-base-allowed;page-operation(STATE_SCAN)=exact-declared-bare-StateMap-base-only;CNTR-absent=all-durable-state-syscalls-rejected-by-generic-program-profile",
        state_value_validation_version: 1,
        state_value_validation: "CNTR-present:STATE_SET-before-mutation-and-present-STATE_GET-before-publication-reconstruct-exact-StateValueSchemaV1-from-declared-scalar-type-or-StateMap-value-type;schema-frame=canonical-Norito-Vec<u8>(KSV1+u16le-total-logical-node-count+flat-preorder-u8-node-and-kind-tags);record-frame=canonical-Norito-Vec<u8>(KRV1+schema-hash+root-u16le-atom-count+flat-active-only-u8-tagged-atom-stream);require-exact-schema_hash=iroha_crypto::Hash::new(KOTODAMA_STATE_VALUE_SCHEMA_V1\\0||exact-canonical-Norito-schema-frame);validate-exact-active-only-atom-stream,pointer-policy,pointer-type,pointer-envelope-hash,and-canonical-leaf-payload;CNTR-absent=unavailable",
        cursor_schema_hash: norito::schema::identity::frame_hash::<
            iroha_data_model::smart_contract::state_cursor::StateCursorV1,
        >(),
        cursor_schema_hash_domain:
            iroha_data_model::smart_contract::state_cursor::STATE_CURSOR_SCHEMA_HASH_DOMAIN_V1,
        cursor_max_bytes: iroha_data_model::smart_contract::state_cursor::MAX_STATE_CURSOR_BYTES_V1
            as u64,
        scan_max_candidates: STATE_SCAN_MAX_CANDIDATES_V1 as u64,
        cursor_layout: "canonical-Norito-StateCursorV1{instance:String<=1024,map:bare-Name-StatePath<=255,schema_hash:[u8;32],key_schema_hash:[u8;32],last_key:canonical-map-child-StatePath};schema_hash=Iroha-Hash(domain||canonical-Norito-EmbeddedStateType::StateMap);key_schema_hash=Iroha-Hash(KOTODAMA_STATE_KEY_SCHEMA_V1\0||canonical-Norito-EntrypointValueTypeV1);keys=existing-scalars-or-nonempty-nested-tuples;physical-key=canonical-StateValueRecordV1<=4096-bytes;word=NoritoBytes-pointer;JSON=0x-prefixed-frame-hex",
        scan_semantics: "STATE_SCAN=seek-after-last-examined-canonical-key;instance-and-exact-map-schema-bound;position-never-authorization;current-invocation-backing-plus-overlay;sorted-distinct-candidates-including-tombstones;stop-immediately-at-N-live-values-or-64-candidates;no-total-count-or-extra-lookahead;bounded-page-has-continuation-even-if-next-page-empty;deleted-cursor-key-valid;insertions-before-cursor-not-revisited;gas=request-and-schema-bytes+examined-physical-key-bytes-and-items+response-bytes;conservative-map-prefix-scheduler-read",
        typed_value: typed_state_value_surface_v1()?,
    };
    Ok(AbiSurface {
        descriptor_format_version: ABI_SURFACE_DESCRIPTOR_FORMAT_VERSION,
        policy_tag: 1,
        program_header_layout: PROGRAM_HEADER_LAYOUT_V1,
        syscalls,
        pointer_type_ids,
        core_query_projections,
        query_page,
        entrypoint,
        numeric,
        private_input,
        indexed_literals,
        generic_program,
        durable_state,
    })
}
fn build_abi_surface_descriptor(policy: crate::SyscallPolicy) -> Result<Vec<u8>, AbiSurfaceError> {
    encode_abi_surface(&collect_abi_surface(policy)?)
}
fn abi_surface_descriptor(policy: crate::SyscallPolicy) -> Result<&'static [u8], AbiSurfaceError> {
    use std::sync::OnceLock;
    static ABI_V1: OnceLock<Result<Vec<u8>, AbiSurfaceError>> = OnceLock::new();
    let crate::SyscallPolicy::AbiV1 = policy;
    match ABI_V1.get_or_init(|| build_abi_surface_descriptor(policy)) {
        Ok(descriptor) => Ok(descriptor.as_slice()),
        Err(error) => Err(*error),
    }
}
/// Compute the stable first-release ABI hash for the complete allowed surface.
///
/// The domain-separated, versioned, length-prefixed descriptor binds the ABI-v1 policy tag;
/// indexed-literal opcodes, table kinds, and payload layouts; every sorted syscall signature and
/// host-access class; every allowed pointer type; the CNTR marker, section layout, nominal schema
/// identities, complete embedded state-type tag/layout table, admission rules, depth limit, and
/// durable-state caps, ordering, storage, paging, and path derivation; typed durable-state nominal
/// schema identities, exact schema-binding domain, kind/node/atom discriminants and layouts,
/// pointer mappings, traversal rules, decoded-table layout, and aggregate caps; typed core-query
/// entity tags, projections, and page semantics; recursive entrypoint `List`, `Int`, `Decimal`, and
/// `Quantity` kinds; and canonical numeric domains, exact arithmetic/conversion/wrapping rules,
/// JSON grammar, fault ordering, frame schema/layout, error-precedence, and rounding rules; and the
/// bounded typed private-input record, nominal kind tags, projection domains, full-width commitment
/// derivation, independent generator, and declassification rule. Gas prices and staged-metering
/// phase tags remain bound independently by the gas-schedule hash. A malformed compiled registry
/// returns a diagnostic sentinel with an invalid Iroha-hash marker; release tests require that path
/// to be unreachable, and a valid Iroha hash can never equal such a sentinel.
pub fn compute_abi_hash(policy: crate::SyscallPolicy) -> [u8; 32] {
    match abi_surface_descriptor(policy) {
        Ok(descriptor) => *iroha_crypto::Hash::new(descriptor).as_ref(),
        Err(error) => invalid_abi_surface_hash(error),
    }
}
#[cfg(test)]
#[path = "syscalls/access_profile_tests.rs"]
mod access_profile_tests;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_state_frame_bounds_cover_exact_text_maxima() {
        let path: iroha_model_base::state_path::StatePath = "p"
            .repeat(STATE_MAX_PATH_BYTES)
            .parse()
            .expect("maximum StatePath");
        let path_frame = norito::to_bytes(&path).expect("encode maximum StatePath");
        assert!(path_frame.len() <= STATE_MAX_PATH_FRAME_BYTES);
        let base: iroha_model_base::name::Name = "b"
            .repeat(STATE_MAP_MAX_BASE_BYTES)
            .parse()
            .expect("maximum Name");
        let base_frame = norito::to_bytes(&base).expect("encode maximum Name");
        assert!(base_frame.len() <= STATE_MAP_MAX_BASE_FRAME_BYTES);
        assert_eq!(
            STATE_MAX_PATH_BYTES,
            iroha_model_base::state_path::MAX_STATE_PATH_BYTES
        );
        assert_eq!(
            STATE_MAP_MAX_BASE_BYTES,
            iroha_model_base::name::MAX_NAME_BYTES
        );
    }
    fn canonical_surface() -> AbiSurface {
        collect_abi_surface(crate::SyscallPolicy::AbiV1).expect("canonical ABI-v1 surface")
    }
    #[test]
    fn numeric_v1_ranges_are_complete_and_legacy_numbers_fail_closed() {
        let policy = crate::SyscallPolicy::AbiV1;
        let expected = (0x01_0100..=0x01_011A)
            .chain(0x01_0120..=0x01_012F)
            .chain(0x01_0140..=0x01_014F)
            .collect::<Vec<_>>();
        assert_eq!(expected.len(), 59);
        for number in expected {
            assert!(is_numeric_v1_syscall(number));
            assert!(is_syscall_allowed(policy, number));
            assert_eq!(registered_syscall_access(number), Some(SyscallAccess::None));
            assert!(syscall_name(number).is_some());
        }
        for unassigned in core::iter::once(0x54)
            .chain([0x65, 0x68])
            .chain(0x69..=0x76)
            .chain(0xD2..=0xDE)
            .chain(0x01_0040..=0x01_004D)
        {
            assert!(
                !is_syscall_allowed(policy, unassigned),
                "unassigned {unassigned:#x}"
            );
            assert_eq!(registered_syscall_access(unassigned), None);
            assert_eq!(syscall_name(unassigned), None);
        }
    }
    fn descriptor_hash(surface: &AbiSurface) -> [u8; 32] {
        let descriptor = encode_abi_surface(surface).expect("test surface is canonical");
        *iroha_crypto::Hash::new(descriptor).as_ref()
    }
    #[test]
    fn public_value_utility_semantics_are_bound_to_the_abi_hash() {
        let surface = canonical_surface();
        assert!(
            surface
                .entrypoint
                .value_utilities
                .contains("EntrypointReturnRecordV1")
        );
        assert!(surface.entrypoint.value_utilities.contains("UTF8-bytes"));
        assert_surface_mutation_changes_hash(|surface| {
            surface.entrypoint.value_utilities = "untyped-or-locale-dependent-encoding";
        });
    }
    #[test]
    fn context_address_bytes_are_bound_to_the_abi_hash() {
        let surface = canonical_surface();
        assert!(
            surface
                .entrypoint
                .context_address
                .contains("UTF8-literal-exactly60bytes")
        );
        assert_surface_mutation_changes_hash(|surface| {
            surface.entrypoint.context_address = "NoritoBytes-encoded-contract-address";
        });
    }
    fn assert_surface_mutation_changes_hash(mutator: impl FnOnce(&mut AbiSurface)) {
        let canonical_surface = canonical_surface();
        let canonical_hash = descriptor_hash(&canonical_surface);
        let mut changed = canonical_surface;
        mutator(&mut changed);
        assert_ne!(descriptor_hash(&changed), canonical_hash);
    }
    #[test]
    fn removed_syscall_numbers_are_unknown() {
        let removed = [
            0x85, 0x86, 0x87, 0x88, 0x89, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0xAB, 0xAC, 0xAD, 0xAE,
            0xAF, 0xBF, 0xD0, 0xD1, 0x01_0029, 0x01_0163, 0x01_0164, 0x01_0165,
        ];
        for number in removed {
            assert!(!is_syscall_allowed(crate::SyscallPolicy::AbiV1, number));
            assert_eq!(registered_syscall_access(number), None);
            assert_eq!(syscall_name(number), None);
        }
    }
    #[test]
    fn koto_test_syscalls_are_host_private() {
        let private = [
            SYSCALL_KOTO_TEST_ACTOR_ACCOUNT,
            SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY,
            SYSCALL_KOTO_TEST_ACTOR_SIGN,
            SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS,
            SYSCALL_KOTO_TEST_EXPECT_REJECT_AS,
            SYSCALL_KOTO_TEST_ASSERT_FAILED,
            SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT,
            SYSCALL_KOTO_TEST_ADVANCE_BLOCKS,
            SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS,
            SYSCALL_KOTO_TEST_CALL_SITE,
        ];
        for syscall in private {
            assert!(is_koto_test_syscall(syscall));
            assert!(!is_syscall_allowed(crate::SyscallPolicy::AbiV1, syscall));
            assert!(syscall > u8::MAX as u32);
        }
    }
    #[test]
    fn generic_program_syscall_profile_is_sorted_complete_and_fail_closed() {
        assert!(
            GENERIC_PROGRAM_DENIED_SYSCALLS_V1
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "ABI-bound denylist must remain strictly sorted"
        );
        assert_eq!(
            GENERIC_PROGRAM_DENIED_SYSCALLS_V1,
            &[
                SYSCALL_GRANT_CONTRACT_PERMISSION,
                SYSCALL_REVOKE_CONTRACT_PERMISSION,
                SYSCALL_DEACTIVATE_CONTRACT_INSTANCE,
                SYSCALL_REMOVE_SMART_CONTRACT_BYTES,
                SYSCALL_REGISTER_SMART_CONTRACT_CODE,
                SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
                SYSCALL_ACTIVATE_CONTRACT_INSTANCE,
                SYSCALL_STATE_GET,
                SYSCALL_STATE_SET,
                SYSCALL_STATE_DEL,
                SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
                SYSCALL_CALL_CONTRACT,
                SYSCALL_EMIT_CONTRACT_EVENT,
                SYSCALL_SYSVAR_CONTRACT_ADDRESS,
                SYSCALL_SYSVAR_ENTRYPOINT,
                SYSCALL_SYSVAR_CONTRACT_SUBJECT,
                SYSCALL_STATE_HAS,
                SYSCALL_STATE_LEN,
                SYSCALL_STATE_COUNT,
                SYSCALL_STATE_SCAN,
                SYSCALL_ASSET_LOCK_OPEN,
                SYSCALL_ASSET_LOCK_DRAWDOWN,
                SYSCALL_ASSET_LOCK_CANCEL,
                SYSCALL_ASSET_LOCK_EXPIRE,
            ]
        );
        for &syscall in GENERIC_PROGRAM_DENIED_SYSCALLS_V1 {
            assert!(is_syscall_allowed(crate::SyscallPolicy::AbiV1, syscall));
            assert!(!is_generic_program_syscall_allowed(
                crate::SyscallPolicy::AbiV1,
                syscall
            ));
        }
        for syscall in [
            SYSCALL_REGISTER_DOMAIN,
            SYSCALL_INT_ADD,
            SYSCALL_SUBSCRIPTION_BILL,
            SYSCALL_SUBSCRIPTION_RECORD_USAGE,
            SYSCALL_AXT_BEGIN,
            SYSCALL_AXT_TOUCH,
            SYSCALL_AXT_COMMIT,
            SYSCALL_VERIFY_DS_PROOF,
            SYSCALL_AXT_STAGE_ANCHORED_SPEND,
        ] {
            assert!(is_generic_program_syscall_allowed(
                crate::SyscallPolicy::AbiV1,
                syscall
            ));
        }
        assert!(!is_generic_program_syscall_allowed(
            crate::SyscallPolicy::AbiV1,
            u32::MAX
        ));
    }
    #[test]
    fn axt_syscall_classifier_is_exact() {
        for syscall in [
            SYSCALL_AXT_BEGIN,
            SYSCALL_AXT_TOUCH,
            SYSCALL_AXT_COMMIT,
            SYSCALL_VERIFY_DS_PROOF,
            SYSCALL_AXT_STAGE_ANCHORED_SPEND,
        ] {
            assert!(is_axt_syscall(syscall));
        }
        for syscall in [SYSCALL_ESCROW_OPEN_OFFER, SYSCALL_STATE_GET, u32::MAX] {
            assert!(!is_axt_syscall(syscall));
        }
    }
    #[test]
    fn syscall_access_classification_is_conservative() {
        assert_eq!(syscall_access(SYSCALL_STATE_GET), SyscallAccess::StateRead);
        assert_eq!(syscall_access(SYSCALL_STATE_SET), SyscallAccess::StateWrite);
        assert_eq!(
            syscall_access(SYSCALL_STATE_MAP_KEY_AT),
            SyscallAccess::None
        );
        assert_eq!(
            syscall_access(SYSCALL_STATE_VALUE_ENCODE),
            SyscallAccess::None
        );
        assert_eq!(
            syscall_access(SYSCALL_STATE_VALUE_DECODE),
            SyscallAccess::None
        );
        assert_eq!(
            syscall_access(SYSCALL_CORE_QUERY_GET),
            SyscallAccess::LedgerRead
        );
        assert_eq!(
            syscall_access(SYSCALL_CORE_QUERY_PAGE),
            SyscallAccess::LedgerRead
        );
        assert_eq!(
            syscall_access(SYSCALL_VRF_EPOCH_SEED),
            SyscallAccess::LedgerRead
        );
        assert_eq!(
            syscall_access(SYSCALL_TRANSFER_ASSET_SCOPED),
            SyscallAccess::LedgerWrite
        );
        assert_eq!(
            syscall_access(SYSCALL_CALL_CONTRACT),
            SyscallAccess::Dynamic
        );
        assert_eq!(syscall_access(SYSCALL_SHA256_HASH), SyscallAccess::None);
        assert_eq!(syscall_access(0x00ff_fffe), SyscallAccess::Dynamic);
        for number in abi_syscall_list() {
            assert!(
                syscall_name(*number).is_some(),
                "ABI syscall 0x{number:06x} lacks a registry name"
            );
        }
    }
    #[test]
    fn abi_v1_has_one_canonical_signature_per_allowed_syscall() {
        let allowed = abi_syscall_list();
        assert!(is_syscall_allowed(
            crate::SyscallPolicy::AbiV1,
            SYSCALL_STATE_SCAN
        ));
        for retired in [0x53, 0x55, 0x01_0030] {
            assert!(!is_syscall_allowed(crate::SyscallPolicy::AbiV1, retired));
            assert!(syscall_name(retired).is_none());
        }
        assert_eq!(
            syscalls_doc_gen::DOCS.len(),
            allowed.len(),
            "the canonical signature registry must exactly cover ABI v1"
        );
        for (&number, row) in allowed.iter().zip(syscalls_doc_gen::DOCS) {
            assert_eq!(
                row.number, number,
                "canonical signatures must use sorted ABI-v1 syscall order"
            );
            assert!(
                syscall_name(number).is_some_and(|name| !name.is_empty()),
                "ABI syscall 0x{number:06x} must have a canonical name"
            );
            assert!(!row.args.is_empty());
            assert!(!row.ret.is_empty());
        }
        let surface = collect_abi_syscall_surface(allowed, syscalls_doc_gen::DOCS)
            .expect("the compiled ABI-v1 registry must be valid");
        assert_eq!(surface.len(), allowed.len());
        assert!(build_abi_surface_descriptor(crate::SyscallPolicy::AbiV1).is_ok());
        assert!(abi_surface_descriptor(crate::SyscallPolicy::AbiV1).is_ok());
        let hash = compute_abi_hash(crate::SyscallPolicy::AbiV1);
        assert_ne!(hash, INVALID_ABI_SURFACE_HASH);
        assert_eq!(hash[hash.len() - 1] & 1, 1, "valid Iroha hash marker");
    }
    #[test]
    fn abi_hash_binds_atomic_invocation_outcomes_and_reentry_rules() {
        let surface = canonical_surface();
        for rule in [
            "outer-Result::err=rollback-frame-and-successful-descendants",
            "error-return-is-recoverable",
            "reads-and-consumed-gas-retained",
            "nested-error-values-are-data",
            "active-contract-address-reentry-rejected-including-views",
            "max-nesting32",
            "immediate-caller=parent-contract-subject",
        ] {
            assert!(surface.entrypoint.invocation_outcome.contains(rule));
        }
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.invocation_outcome = "commit-error-returns-and-allow-reentry";
        });
    }
    #[test]
    fn abi_hash_binds_runtime_fault_identity_layout_and_origin() {
        let surface = canonical_surface();
        assert_eq!(
            surface.entrypoint.fault_schema_hash,
            norito::schema::identity::frame_hash::<iroha_data_model::executor::fault::IvmFaultV1>()
        );
        for rule in [
            "deepest-origin-survives-nested-unwind",
            "parent-CALL-never-overwrites-child-origin",
            "no-source-text-or-local-path-in-consensus",
            "allocation-and-execution-deferrals-never-consensus-faults",
            "host-unavailability-and-metering-invariants-never-consensus-faults",
            "contract-rejection-and-recoverable-Result-remain-distinct",
        ] {
            assert!(surface.entrypoint.fault_semantics.contains(rule));
        }
        for layout in [
            "IvmFaultV1={kind:IvmFaultKindV1,site:IvmFaultSiteV1}",
            "Entrypoint1(u32-CNTR-ordinal)",
            "Execute1{pc_offset:u64-executable-relative}",
            "Numeric10(NumericFaultV1)",
            "PointerAbi11(PointerAbiFaultV1)",
            "ReentrantCall28",
            "CallDepthExceeded29",
        ] {
            assert!(surface.entrypoint.fault_layout.contains(layout));
        }
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.fault_schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.fault_layout = "presentation-text-only";
        });
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.fault_semantics = "overwrite-origin-at-parent-call";
        });
    }
    #[test]
    fn abi_hash_binds_declared_instance_permissions() {
        let surface = canonical_surface();
        for rule in [
            "required-authenticated-permission-table",
            "Anyone",
            "Permission(Name)",
            "RuntimeLifecycle",
            "instance-grants=immutable-address+declared-name",
            "shared-grants=exact-chain-name+canonical-null",
            "no-implicit-open-or-string-authorization",
            "effect-authority-is-independent",
        ] {
            assert!(surface.entrypoint.authorization.contains(rule));
        }
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.authorization = "chain-global-string-guards";
        });
    }
    #[test]
    fn abi_hash_binds_upgrade_storage_and_suspension_rules() {
        let surface = canonical_surface();
        for rule in [
            "retained-code-binding-survives-suspension",
            "pending-transition-survives-suspension",
            "same-code-resume-never-replays-completed-hook",
            "prepared-calls-bind-lifecycle-revision",
            "existing-state-names-and-complete-types-remain-exact",
            "new-maps-start-empty",
            "new-scalars-require-kaizen-and-canonical-present-values-before-completion",
        ] {
            assert!(surface.entrypoint.lifecycle.contains(rule));
        }
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.lifecycle = "suspension-forgets-storage-and-replays-constructor";
        });
    }
    #[test]
    fn abi_hash_binds_native_event_qualified_nominal_identity() {
        let surface = canonical_surface();
        assert!(
            surface.entrypoint.event_layout.contains(
                "root=Struct-qualified-name-final-double-colon-component-equals-event-name"
            )
        );
        assert!(
            !surface
                .entrypoint
                .event_layout
                .contains("root=Struct-name-equals-event-name")
        );
        assert_surface_mutation_changes_hash(|candidate| {
            candidate.entrypoint.event_layout = "root=Struct-name-equals-event-name";
        });
    }
    #[test]
    fn abi_hash_descriptor_binds_every_semantic_surface_component() {
        let surface = canonical_surface();
        let canonical = descriptor_hash(&surface);
        assert_eq!(canonical, compute_abi_hash(crate::SyscallPolicy::AbiV1));
        assert_surface_mutation_changes_hash(|changed| {
            changed.descriptor_format_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| changed.policy_tag += 1);
        assert_eq!(surface.program_header_layout, PROGRAM_HEADER_LAYOUT_V1);
        assert!(
            surface
                .program_header_layout
                .contains("version_major:u8=1;version_minor:u8=1;")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.program_header_layout = "host-dependent-header";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.indexed_literals[1].opcode ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.indexed_literals[1].table_kind ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.indexed_literals[1].payload_layout = "mutated scalar layout";
        });
        assert_surface_mutation_changes_hash(|changed| {
            let last = changed.syscalls.last_mut().expect("ABI has syscalls");
            last.number = last
                .number
                .checked_add(1)
                .expect("last syscall number has headroom");
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.syscalls[0].args = "mutated arguments";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.syscalls[0].ret = "mutated return";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.syscalls[0].access = if changed.syscalls[0].access == SyscallAccess::Dynamic {
                SyscallAccess::None
            } else {
                SyscallAccess::Dynamic
            };
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.syscalls.pop();
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.pointer_type_ids.pop();
        });
    }
    #[test]
    fn abi_hash_uses_the_documented_iroha_hash_v1_commitment() {
        let descriptor = abi_surface_descriptor(crate::SyscallPolicy::AbiV1)
            .expect("the canonical ABI-v1 descriptor must be available");
        let hash = compute_abi_hash(crate::SyscallPolicy::AbiV1);
        assert_eq!(hash, *iroha_crypto::Hash::new(descriptor).as_ref());
        assert_ne!(
            hash,
            iroha_crypto::sha256(descriptor),
            "ABI v1 uses marked Blake2b-256, not raw SHA-256"
        );
        assert_eq!(
            hash[hash.len() - 1] & 1,
            1,
            "Iroha Hash v1 must set the final-byte marker bit"
        );
    }
    #[test]
    fn abi_descriptor_ignores_ambient_norito_layout_flags() {
        let canonical = build_abi_surface_descriptor(crate::SyscallPolicy::AbiV1)
            .expect("build canonical ABI descriptor");
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        let under_noncanonical_ambient = build_abi_surface_descriptor(crate::SyscallPolicy::AbiV1)
            .expect("build ABI descriptor under alternate ambient flags");
        assert_eq!(under_noncanonical_ambient, canonical);
    }
    #[test]
    fn abi_hash_binds_typed_private_input_and_full_width_commitment_semantics() {
        use crate::private_input::{
            MAX_PRIVATE_INPUT_RECORD_BYTES_V1, MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1,
            MAX_PRIVATE_INPUTS_V1, PRIVATE_INPUT_ABI_VERSION_V1,
            PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1, PRIVATE_NUMERIC_VALCOM_DOMAIN_V1,
            PRIVATE_NUMERIC_VALCOM_H_COMPRESSED_V1, PRIVATE_NUMERIC_VALCOM_H_DST_V1,
            PRIVATE_NUMERIC_VALCOM_H_MESSAGE_V1,
        };
        let private = canonical_surface().private_input;
        assert_eq!(private.abi_version, PRIVATE_INPUT_ABI_VERSION_V1);
        assert_eq!(private.kinds.len(), 3);
        assert_eq!(private.kinds[0].name, "int");
        assert_eq!(private.kinds[1].name, "decimal");
        assert_eq!(private.kinds[2].name, "quantity");
        assert_eq!(private.max_inputs, MAX_PRIVATE_INPUTS_V1 as u64);
        assert_eq!(
            private.max_record_bytes,
            MAX_PRIVATE_INPUT_RECORD_BYTES_V1 as u64
        );
        assert_eq!(
            private.max_transport_bytes,
            MAX_PRIVATE_INPUT_TRANSPORT_BYTES_V1 as u64
        );
        assert_eq!(
            private.projection_domain,
            PRIVATE_NUMERIC_PROJECTION_DOMAIN_V1
        );
        assert_eq!(private.valcom_domain, PRIVATE_NUMERIC_VALCOM_DOMAIN_V1);
        assert_eq!(private.valcom_h_dst, PRIVATE_NUMERIC_VALCOM_H_DST_V1);
        assert_eq!(
            private.valcom_h_message,
            PRIVATE_NUMERIC_VALCOM_H_MESSAGE_V1
        );
        assert_eq!(
            private.valcom_h_compressed,
            PRIVATE_NUMERIC_VALCOM_H_COMPRESSED_V1
        );
        assert_surface_mutation_changes_hash(|changed| changed.private_input.abi_version += 1);
        assert_surface_mutation_changes_hash(|changed| changed.private_input.kinds[0].tag ^= 1);
        assert_surface_mutation_changes_hash(|changed| {
            changed.private_input.projection_domain = b"mutated-private-domain";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.private_input.valcom_h_message = b"known-generator-relation";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.private_input.valcom_h_compressed[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.private_input.valcom_result = "truncated-u64";
        });
    }
    #[test]
    fn abi_hash_descriptor_binds_every_durable_state_semantic() {
        use crate::state_value::{
            DECODED_STATE_VALUE_TABLE_OFFSET, DECODED_STATE_VALUE_WORD_BYTES,
            MAX_STATE_VALUE_LIST_CAPACITY_V1, MAX_STATE_VALUE_NODES, MAX_STATE_VALUE_RECORD_BYTES,
            MAX_STATE_VALUE_SCHEMA_BYTES, MAX_STATE_VALUE_WORDS, MIN_STATE_VALUE_LIST_CAPACITY_V1,
            STATE_VALUE_RECORD_ATOM_TAG_BYTES_V1, STATE_VALUE_RECORD_LIST_ITEM_COUNT_BYTES_V1,
            STATE_VALUE_RECORD_NAME_V1, STATE_VALUE_RECORD_PAYLOAD_MAGIC_V1,
            STATE_VALUE_RECORD_POINTER_LENGTH_BYTES_V1, STATE_VALUE_RECORD_STREAM_COUNT_BYTES_V1,
            STATE_VALUE_SCHEMA_HASH_DOMAIN_V1, STATE_VALUE_SCHEMA_KIND_TAG_BYTES_V1,
            STATE_VALUE_SCHEMA_NAME_V1, STATE_VALUE_SCHEMA_NODE_COUNT_BYTES_V1,
            STATE_VALUE_SCHEMA_NODE_TAG_BYTES_V1, STATE_VALUE_SCHEMA_PAYLOAD_MAGIC_V1,
            StateValueRecordV1, StateValueSchemaV1,
        };
        let state = canonical_surface().durable_state;
        assert_eq!(state.semantics_version, 6);
        assert_eq!(
            state.contract_interface_section_magic,
            crate::metadata::CONTRACT_INTERFACE_SECTION_MAGIC
        );
        assert_eq!(
            state.contract_interface_schema_name,
            crate::metadata::CONTRACT_INTERFACE_SCHEMA_NAME_V1
        );
        assert_eq!(
            state.contract_interface_schema_hash,
            norito::schema::identity::frame_hash::<crate::metadata::EmbeddedContractInterfaceV1>()
        );
        assert_eq!(
            state.embedded_state_type_schema_name,
            crate::metadata::EMBEDDED_STATE_TYPE_SCHEMA_NAME_V1
        );
        assert_eq!(
            state.embedded_state_type_schema_hash,
            norito::schema::identity::frame_hash::<crate::metadata::EmbeddedStateType>()
        );
        assert_eq!(
            state.embedded_state_type_max_depth,
            crate::metadata::MAX_EMBEDDED_STATE_TYPE_DEPTH_V1 as u64
        );
        assert!(
            state
                .embedded_state_type_validation
                .contains("StateMap-forbidden-below-top-level")
        );
        assert_eq!(
            state
                .embedded_state_types
                .iter()
                .map(|state_type| (state_type.name, state_type.tag))
                .collect::<Vec<_>>(),
            vec![
                ("Int", 0),
                ("Decimal", 1),
                ("Quantity", 2),
                ("Bool", 3),
                ("String", 4),
                ("Bytes", 5),
                ("DataSpaceId", 6),
                ("AccountId", 7),
                ("AssetDefinitionId", 8),
                ("AssetId", 9),
                ("NftId", 10),
                ("DomainId", 11),
                ("Name", 12),
                ("Json", 13),
                ("Tuple", 14),
                ("Struct", 15),
                ("StateMap", 16),
                ("Option", 17),
                ("Result", 18),
                ("List", 19),
                ("Unit", 20),
                ("Error", 21),
                ("StateCursor", 22),
                ("Enum", 23),
            ]
        );
        for state_type in &state.embedded_state_types {
            assert!(!state_type.layout.is_empty());
            let decoded: crate::metadata::EmbeddedStateType =
                norito::decode_canonical(&state_type.canonical_sample_frame)
                    .expect("ABI-bound state-type sample frame must decode");
            assert_eq!(decoded.wire_tag(), state_type.tag);
            assert_eq!(
                norito::encode_canonical(&decoded)
                    .expect("re-encode canonical ABI-bound state-type sample"),
                state_type.canonical_sample_frame
            );
        }
        assert_eq!(state.dynamic_access_hint_validation_version, 1);
        assert_eq!(
            state.dynamic_access_hint_max_keys,
            crate::access_hints::DYNAMIC_ACCESS_HINT_MAX_KEYS_V1
        );
        assert_eq!(
            state.dynamic_access_hint_key_types,
            crate::access_hints::DYNAMIC_ACCESS_HINT_KEY_TYPES_V1
        );
        assert_eq!(
            state.dynamic_access_hint_bound_kinds,
            crate::access_hints::DYNAMIC_ACCESS_HINT_BOUND_KINDS_V1
        );
        assert_eq!(
            state.dynamic_access_hint_reserved_state_identifiers,
            crate::access_hints::DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1
        );
        assert_eq!(
            state.dynamic_access_hint_reserved_state_prefixes,
            crate::access_hints::DYNAMIC_ACCESS_HINT_RESERVED_STATE_PREFIXES_V1
        );
        assert!(
            state
                .dynamic_access_hint_reserved_state_identifiers
                .contains(&"state")
        );
        assert!(
            !state
                .dynamic_access_hint_reserved_state_identifiers
                .contains(&"amount")
        );
        assert!(
            state
                .dynamic_access_hint_validation
                .contains("target=exact-declared-top-level-StateMap")
        );
        assert!(state.dynamic_access_hint_validation.contains(
            "duplicate=full-{base_key,key_type,bound_kind,max_keys}-record-equality-rejected-independently-within-each-list"
        ));
        assert!(
            state
                .dynamic_access_hint_validation
                .contains("cross-read-write-repeat=allowed")
        );
        assert!(
            state
                .dynamic_access_hint_validation
                .contains("metadata=advisory-and-never-scheduler-authoritative")
        );
        assert_eq!(state.scan_max_items, STATE_SCAN_MAX_ITEMS_V1);
        assert_eq!(state.max_path_bytes, STATE_MAX_PATH_BYTES as u64);
        assert_eq!(
            state.max_path_frame_bytes,
            STATE_MAX_PATH_FRAME_BYTES as u64
        );
        assert_eq!(state.max_value_bytes, STATE_MAX_VALUE_BYTES as u64);
        assert_eq!(state.map_max_key_bytes, STATE_MAP_MAX_KEY_BYTES as u64);
        assert_eq!(state.map_max_base_bytes, STATE_MAP_MAX_BASE_BYTES as u64);
        assert_eq!(
            state.map_max_base_frame_bytes,
            STATE_MAP_MAX_BASE_FRAME_BYTES as u64
        );
        assert_eq!(state.map_max_page_bytes, STATE_MAP_MAX_PAGE_BYTES as u64);
        assert!(state.path_transport.contains("Vec<StatePath>"));
        assert_eq!(state.operation_path_rules_version, 1);
        assert!(
            state
                .operation_path_rules
                .contains("bare-StateMap-base-rejected")
        );
        assert_eq!(state.state_value_validation_version, 1);
        assert!(
            state.state_value_validation.contains(
                "exact-StateValueSchemaV1-from-declared-scalar-type-or-StateMap-value-type"
            )
        );
        assert!(
            state
                .state_value_validation
                .contains("present-STATE_GET-before-publication")
        );
        assert!(state.state_value_validation.contains("KSV1+u16le"));
        assert!(state.state_value_validation.contains("KRV1+schema-hash"));
        let typed = &state.typed_value;
        assert_eq!(typed.wire_format_version, 1);
        assert_eq!(
            typed.norito_header_bytes,
            u16::try_from(norito::core::Header::SIZE).expect("Norito header width")
        );
        assert_eq!(typed.norito_version_major, norito::core::VERSION_MAJOR);
        assert_eq!(typed.norito_version_minor, norito::core::VERSION_MINOR);
        assert_eq!(
            typed.norito_default_encode_flags,
            ABI_V1_NORITO_ENCODE_FLAGS
        );
        assert_eq!(
            ABI_V1_NORITO_ENCODE_FLAGS,
            norito::core::default_encode_flags(),
            "Norito's workspace default must remain aligned with the pinned ABI-v1 layout"
        );
        assert_eq!(
            typed.schema_payload_magic,
            STATE_VALUE_SCHEMA_PAYLOAD_MAGIC_V1
        );
        assert_eq!(
            typed.schema_node_count_bytes,
            STATE_VALUE_SCHEMA_NODE_COUNT_BYTES_V1
        );
        assert_eq!(
            typed.schema_node_tag_bytes,
            STATE_VALUE_SCHEMA_NODE_TAG_BYTES_V1
        );
        assert_eq!(
            typed.schema_kind_tag_bytes,
            STATE_VALUE_SCHEMA_KIND_TAG_BYTES_V1
        );
        assert_eq!(
            typed.record_payload_magic,
            STATE_VALUE_RECORD_PAYLOAD_MAGIC_V1
        );
        assert_eq!(
            typed.record_stream_count_bytes,
            STATE_VALUE_RECORD_STREAM_COUNT_BYTES_V1
        );
        assert_eq!(
            typed.record_atom_tag_bytes,
            STATE_VALUE_RECORD_ATOM_TAG_BYTES_V1
        );
        assert_eq!(
            typed.record_pointer_length_bytes,
            STATE_VALUE_RECORD_POINTER_LENGTH_BYTES_V1
        );
        assert_eq!(
            typed.record_list_item_count_bytes,
            STATE_VALUE_RECORD_LIST_ITEM_COUNT_BYTES_V1
        );
        assert!(typed.schema_layout.contains("KSV1"));
        assert!(typed.schema_layout.contains("flat-preorder-u8"));
        assert!(typed.record_layout.contains("KRV1"));
        assert!(typed.record_layout.contains("root-u16le-atom-count"));
        assert!(typed.record_layout.contains("u32le-byte-length"));
        assert_eq!(typed.schema_hash_domain, STATE_VALUE_SCHEMA_HASH_DOMAIN_V1);
        assert_eq!(
            typed.schema_hash_algorithm,
            "iroha_crypto::Hash::new(schema-hash-domain||exact-canonical-Norito-schema-frame)"
        );
        assert_eq!(typed.schema_name, STATE_VALUE_SCHEMA_NAME_V1);
        assert_eq!(
            typed.schema_hash,
            norito::schema::identity::frame_hash::<StateValueSchemaV1>()
        );
        assert_eq!(typed.record_name, STATE_VALUE_RECORD_NAME_V1);
        assert_eq!(
            typed.record_hash,
            norito::schema::identity::frame_hash::<StateValueRecordV1>()
        );
        assert_eq!(typed.kinds.len(), 18);
        assert_eq!(typed.nodes.len(), 10);
        assert_eq!(typed.atoms.len(), 7);
        assert_eq!(typed.max_nodes, MAX_STATE_VALUE_NODES as u64);
        assert_eq!(typed.max_depth, MAX_STATE_VALUE_NODES as u64);
        assert_eq!(typed.max_words, MAX_STATE_VALUE_WORDS as u64);
        assert_eq!(typed.max_schema_bytes, MAX_STATE_VALUE_SCHEMA_BYTES as u64);
        assert_eq!(typed.max_record_bytes, MAX_STATE_VALUE_RECORD_BYTES as u64);
        assert_eq!(typed.list_min_capacity, MIN_STATE_VALUE_LIST_CAPACITY_V1);
        assert_eq!(typed.list_max_capacity, MAX_STATE_VALUE_LIST_CAPACITY_V1);
        assert_eq!(
            typed.decoded_table_offset,
            u16::try_from(DECODED_STATE_VALUE_TABLE_OFFSET).expect("positive table offset")
        );
        assert_eq!(
            typed.decoded_word_bytes,
            u16::try_from(DECODED_STATE_VALUE_WORD_BYTES).expect("positive word width")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.semantics_version += 1
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.contract_interface_section_magic[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.contract_interface_section_layout = "mutated-CNTR-layout";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.contract_interface_schema_name = "wrong.ContractInterface";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.contract_interface_schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.embedded_state_type_schema_name = "wrong.EmbeddedStateType";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.embedded_state_type_schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.embedded_state_type_tag_layout = "host-enum-layout";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.embedded_state_type_max_depth += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.embedded_state_type_validation = "accept-all-type-trees";
        });
        for index in 0..state.embedded_state_types.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.embedded_state_types[index].name = "MutatedStateType";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.embedded_state_types[index].tag ^= 0x80;
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.embedded_state_types[index].layout = "mutated-layout";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.embedded_state_types[index].canonical_sample_frame[0] ^= 1;
            });
        }
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.embedded_state_types.swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.dynamic_access_hint_validation_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.dynamic_access_hint_max_keys += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .dynamic_access_hint_key_types
                .swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .dynamic_access_hint_bound_kinds
                .swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .dynamic_access_hint_reserved_state_identifiers
                .swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .dynamic_access_hint_reserved_state_prefixes[0] = "mutated-reserved-prefix";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.dynamic_access_hint_validation = "accept-unvalidated-hints";
        });
        assert_surface_mutation_changes_hash(|changed| changed.durable_state.scan_max_items += 1);
        assert_surface_mutation_changes_hash(|changed| changed.durable_state.max_path_bytes += 1);
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.max_path_frame_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| changed.durable_state.max_value_bytes += 1);
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.map_max_key_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.map_max_base_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.map_max_base_frame_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.map_max_page_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.path_size_unit = "decoded UTF-8 bytes";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.path_transport = "&Name";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.value_storage = "full pointer TLV envelope";
        });
        assert_surface_mutation_changes_hash(|changed| changed.durable_state.ordering_version += 1);
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.key_ordering = "host insertion order";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.prefix_match = "raw text prefix";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.map_path_derivation_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.map_path_derivation = "base + slash + debug(key)";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.page_overflow = "truncate selected page";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.operation_path_rules_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.operation_path_rules = "all operations accept map bases";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.state_value_validation_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.state_value_validation = "accept any bounded payload";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.wire_format_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.norito_header_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.norito_version_major += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.norito_version_minor += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .typed_value
                .norito_default_encode_flags ^= 0x80;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.enum_discriminant_layout = "host-enum-layout";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_payload_magic[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_node_count_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_node_tag_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_kind_tag_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.record_payload_magic[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.record_stream_count_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.record_atom_tag_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .typed_value
                .record_pointer_length_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .durable_state
                .typed_value
                .record_list_item_count_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_hash_domain = b"mutated-domain";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_hash_algorithm = "unkeyed-host-hash";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_name = "wrong.StateValueSchema";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.record_name = "wrong.StateValueRecord";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.record_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.schema_layout = "unframed-schema";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.record_layout = "unframed-record";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.traversal_semantics = "host-dependent";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.option_tag_semantics = "false=Some";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.result_tag_semantics = "false=Ok";
        });
        for index in 0..typed.kinds.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.kinds[index].name = "MutatedKind";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.kinds[index].tag ^= 0x80;
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.kinds[index].word_layout = "mutated-word";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.kinds[index].pointer_type_id_or_zero ^= 0x8000;
            });
        }
        for index in 0..typed.nodes.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.nodes[index].name = "MutatedNode";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.nodes[index].tag ^= 0x80;
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.nodes[index].layout = "mutated-node-layout";
            });
        }
        for index in 0..typed.atoms.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.atoms[index].name = "MutatedAtom";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.atoms[index].tag ^= 0x80;
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.durable_state.typed_value.atoms[index].layout = "mutated-atom-layout";
            });
        }
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.kinds.swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.nodes.swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.atoms.swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.max_nodes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.max_depth += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.max_words += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.max_schema_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.max_record_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.list_min_capacity += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.list_max_capacity -= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.decoded_table_offset += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.durable_state.typed_value.decoded_word_bytes += 1;
        });
    }
    #[test]
    fn abi_hash_descriptor_binds_generic_program_semantics() {
        let generic = canonical_surface().generic_program;
        assert_eq!(generic.semantics_version, 1);
        assert_eq!(generic.denied_syscalls, GENERIC_PROGRAM_DENIED_SYSCALLS_V1);
        assert!(
            generic
                .artifact_discriminator
                .contains("CNTR-section-absent")
        );
        assert!(generic.rejection.contains("before-side-effects"));
        assert!(generic.validation_points.contains("host-quote-or-dispatch"));
        assert!(generic.durable_state.contains("unavailable"));
        assert!(
            generic
                .reserved_transaction_metadata
                .contains("contract_payload")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.semantics_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.artifact_discriminator = "mutated-discriminator";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.allowed_syscall_rule = "allow-all";
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.generic_program.denied_syscalls.pop();
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.rejection = "ignore";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.validation_points = "execution-only";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.durable_state = "raw-global-state";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.generic_program.reserved_transaction_metadata = "accept-all";
        });
    }
    #[test]
    fn abi_hash_descriptor_binds_core_query_tags_projection_shapes_and_page_semantics() {
        use crate::core_query::{CoreQueryEntityTagV1 as Tag, QUERY_PAGE_CAPACITY_V1};
        let surface = canonical_surface();
        assert_eq!(
            surface
                .core_query_projections
                .iter()
                .map(|projection| projection.entity_tag)
                .collect::<Vec<_>>(),
            vec![
                Tag::Account.as_u64(),
                Tag::Asset.as_u64(),
                Tag::AssetDefinition.as_u64(),
                Tag::Domain.as_u64(),
                Tag::Nft.as_u64(),
            ]
        );
        assert_eq!(
            surface
                .core_query_projections
                .iter()
                .map(|projection| {
                    (
                        projection.name,
                        projection
                            .fields
                            .iter()
                            .map(|field| (field.name, field.ty))
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (
                    "kotodama::AccountView",
                    vec![("id", "AccountId"), ("metadata", "Json")]
                ),
                (
                    "kotodama::AssetView",
                    vec![("id", "AssetId"), ("amount", "Quantity")]
                ),
                (
                    "kotodama::AssetDefinitionView",
                    vec![
                        ("id", "AssetDefinitionId"),
                        ("name", "String"),
                        ("description", "Option<String>"),
                        ("owned_by", "AccountId"),
                        ("total_quantity", "Quantity"),
                        ("numeric_scale", "Option<int>"),
                        ("metadata", "Json"),
                    ]
                ),
                (
                    "kotodama::DomainView",
                    vec![
                        ("id", "DomainId"),
                        ("owned_by", "AccountId"),
                        ("metadata", "Json"),
                    ]
                ),
                (
                    "kotodama::NftView",
                    vec![
                        ("id", "NftId"),
                        ("owned_by", "AccountId"),
                        ("content", "Json"),
                    ]
                ),
            ]
        );
        assert_eq!(
            usize::from(surface.query_page.items_capacity),
            QUERY_PAGE_CAPACITY_V1
        );
        assert_eq!(
            surface
                .query_page
                .fields
                .iter()
                .map(|field| (field.name, field.ty))
                .collect::<Vec<_>>(),
            vec![("items", "List<T,64>"), ("next_offset", "Option<int>")]
        );
        assert_eq!(
            surface.query_page.next_offset_semantics,
            "present-iff-another-canonical-page-exists;some-requires-nonempty-items;nonnegative;not-less-than-item-count;from-window=offset+item-count-with-checked-i64"
        );
        for projection_index in 0..surface.core_query_projections.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.core_query_projections[projection_index].entity_tag += 10;
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.core_query_projections[projection_index].name = "MutatedView";
            });
            for field_index in 0..surface.core_query_projections[projection_index]
                .fields
                .len()
            {
                assert_surface_mutation_changes_hash(|changed| {
                    changed.core_query_projections[projection_index].fields[field_index].name =
                        "mutated_field";
                });
                assert_surface_mutation_changes_hash(|changed| {
                    changed.core_query_projections[projection_index].fields[field_index].ty =
                        "Blob";
                });
            }
            assert_surface_mutation_changes_hash(|changed| {
                changed.core_query_projections[projection_index]
                    .fields
                    .swap(0, 1);
            });
        }
        assert_surface_mutation_changes_hash(|changed| {
            changed.query_page.items_capacity -= 1;
        });
        for field_index in 0..surface.query_page.fields.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.query_page.fields[field_index].name = "mutated_field";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.query_page.fields[field_index].ty = "Blob";
            });
        }
        assert_surface_mutation_changes_hash(|changed| {
            changed.query_page.fields.swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.query_page.next_offset_semantics = "present-on-every-page";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.query_page.item_ordering = "host-insertion-order";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.query_page.account_filter = "filter-after-pagination";
        });
    }

    #[test]
    fn abi_hash_binds_distinct_root_argument_and_trigger_event_keys() {
        let surface = canonical_surface();
        for clause in [
            "root-default-input-route=GET_PUBLIC_INPUT-entrypoint_argument_record-NoritoBytes-with-opcode-and-host-gas",
            "trigger_event_json=actual-firing-Json-independent-of-prepared-root-arguments",
            "no-argument-record-fallback-to-trigger-event-key",
        ] {
            assert!(surface.entrypoint.call_frame_checks.contains(clause));
        }
        assert!(!surface.entrypoint.call_frame_checks.contains(
            "root-default-input-route=GET_PUBLIC_INPUT-trigger_event_json-with-opcode-and-host-gas"
        ));
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.call_frame_checks = "root-default-input-route=GET_PUBLIC_INPUT-trigger_event_json-with-opcode-and-host-gas";
        });
    }

    #[test]
    fn abi_hash_binds_table_layout_frame_checks_and_word_limit() {
        let original = collect_abi_surface(crate::SyscallPolicy::AbiV1).expect("ABI surface");
        assert_eq!(original.entrypoint.max_call_words, 8192);
        assert!(
            original
                .entrypoint
                .call_table_layout
                .contains("no-register-value-call-path")
        );
        let encoded = encode_abi_surface(&original).expect("encode canonical surface");
        let mut changed = original.clone();
        changed.entrypoint.max_call_words -= 1;
        assert_ne!(encoded, encode_abi_surface(&changed).unwrap());
        changed = original.clone();
        changed.entrypoint.call_frame_checks = "no-initialization-check";
        assert_ne!(encoded, encode_abi_surface(&changed).unwrap());
        changed = original;
        changed.entrypoint.call_table_layout = "invalid-layout";
        assert_ne!(encoded, encode_abi_surface(&changed).unwrap());
    }
    #[test]
    fn abi_hash_descriptor_binds_exact_epoch_seed_semantics() {
        let surface = canonical_surface();
        for clause in [
            "r10=public-u64-epoch",
            "nullable-Blob-exactly32bytes",
            "no-latest-fallback",
            "r11-unchanged",
            "local-allocation-refusal-deferred",
        ] {
            assert!(surface.entrypoint.vrf_epoch_seed.contains(clause));
        }
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.vrf_epoch_seed = "substitute-latest-seed";
        });
    }
    #[test]
    fn abi_hash_descriptor_binds_entrypoint_numeric_and_recursive_list_semantics() {
        use crate::{
            entrypoint::{
                MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH, MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
                MAX_ENTRYPOINT_LIST_CAPACITY_V1, MIN_ENTRYPOINT_LIST_CAPACITY_V1,
            },
            pointer_abi::PointerType,
        };
        let surface = canonical_surface();
        assert!(
            surface
                .entrypoint
                .unit_layout
                .contains("every-public-CNTR-entrypoint-requires-return_type-and-return_schema")
        );
        assert!(
            surface
                .entrypoint
                .unit_layout
                .contains("absent-return-descriptor-invalid")
        );
        assert!(surface.entrypoint.unit_layout.contains(
            "nested-calls-always-return-schema-hashed-EntrypointReturnRecordV1-including-Unit-null"
        ));
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.unit_layout = "Unit-without-explicit-public-return-descriptor";
        });
        assert!(
            surface
                .entrypoint
                .struct_identity
                .contains("max1024-ASCII-bytes")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.struct_identity = "unqualified-display-names";
        });
        assert!(
            surface
                .entrypoint
                .sum_json
                .contains("Some(Unit)={some:null}-distinct-from-None")
        );
        assert!(
            surface
                .entrypoint
                .sum_json
                .contains("no-flattened-or-nullable-Option-form")
        );
        assert!(
            surface
                .entrypoint
                .sum_json
                .contains("JSON_BUILD-rejects-implicit-Result")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.sum_json = "Option-null-or-flattened-payload";
        });
        assert_eq!(surface.entrypoint.int_kind, "Int");
        assert_eq!(surface.entrypoint.decimal_kind, "Decimal");
        assert_eq!(surface.entrypoint.quantity_kind, "Quantity");
        assert_eq!(
            surface.entrypoint.int_pointer_type_id,
            PointerType::Int as u16
        );
        assert_eq!(
            surface.entrypoint.decimal_pointer_type_id,
            PointerType::Decimal as u16
        );
        assert_eq!(
            surface.entrypoint.quantity_pointer_type_id,
            PointerType::Quantity as u16
        );
        assert_eq!(
            surface.entrypoint.list_min_capacity,
            MIN_ENTRYPOINT_LIST_CAPACITY_V1
        );
        assert_eq!(
            surface.entrypoint.list_max_capacity,
            MAX_ENTRYPOINT_LIST_CAPACITY_V1
        );
        assert_eq!(
            surface.entrypoint.max_schema_nodes,
            u64::try_from(MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES).expect("node limit fits u64")
        );
        assert_eq!(
            surface.entrypoint.max_schema_depth,
            u64::try_from(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH).expect("depth limit fits u64")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.schema_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.int_kind = "MutatedInt";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.int_pointer_type_id += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.decimal_kind = "MutatedDecimal";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.decimal_pointer_type_id += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.quantity_kind = "MutatedQuantity";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.quantity_pointer_type_id += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.list_layout = "nested-recursive-record";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.list_child_count += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.list_capacity_is_schema_bound = false;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.list_min_capacity += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.entrypoint.list_max_capacity -= 1;
        });
    }
    #[test]
    fn checked_numeric_conversions_bind_failure_mode_and_typed_faults() {
        let surface = canonical_surface();
        for (number, name, input) in [
            (SYSCALL_INT_TO_I64, "INT_TO_I64", "Int"),
            (SYSCALL_INT_TO_U64, "INT_TO_U64", "Int"),
            (
                SYSCALL_DECIMAL_TO_INT_EXACT,
                "DECIMAL_TO_INT_EXACT",
                "Decimal",
            ),
            (SYSCALL_QUANTITY_FROM_INT, "QUANTITY_FROM_INT", "Int"),
            (
                SYSCALL_QUANTITY_FROM_DECIMAL,
                "QUANTITY_FROM_DECIMAL",
                "Decimal",
            ),
        ] {
            assert_eq!(syscall_name(number), Some(name));
            let syscall = surface
                .syscalls
                .iter()
                .find(|row| row.number == number)
                .unwrap();
            assert_eq!(
                syscall.args,
                format!(
                    "r10=&{input}, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1"
                )
            );
            assert!(syscall.ret.contains("r11=NumericFaultV1-or-zero"));
        }
        let index = surface
            .numeric
            .rules
            .iter()
            .position(|rule| rule.name == "conversion_failure_mode")
            .unwrap();
        assert!(
            surface.numeric.rules[index]
                .specification
                .contains("Trap-preserves-NumericFaultV1-without-ABORT")
        );
        assert!(
            surface.numeric.rules[index]
                .specification
                .contains("malformed-controls-always-trap")
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.rules[index].specification = "status-only-conversions";
        });
    }
    #[test]
    fn abi_hash_descriptor_binds_numeric_pointer_rules_and_rounding_tags() {
        use crate::pointer_abi::PointerType;
        let surface = canonical_surface();
        for expected in [
            PointerType::Int,
            PointerType::Decimal,
            PointerType::Quantity,
        ] {
            assert_eq!(
                surface
                    .pointer_type_ids
                    .iter()
                    .filter(|&&type_id| type_id == expected as u16)
                    .count(),
                1
            );
        }
        assert_eq!(PointerType::from_u16(0x0010), Some(PointerType::Quantity));
        assert!(surface.pointer_type_ids.contains(&0x0010));
        assert_eq!(PointerType::from_u16(0x000C), None);
        assert!(!surface.pointer_type_ids.contains(&0x000C));
        assert_eq!(
            PointerType::from_u16(0x0013),
            Some(PointerType::AxtAnchoredSpendV1)
        );
        assert!(surface.pointer_type_ids.contains(&0x0013));
        assert_eq!(surface.numeric.int_pointer_type_id, PointerType::Int as u16);
        assert_eq!(
            surface.numeric.decimal_pointer_type_id,
            PointerType::Decimal as u16
        );
        assert_eq!(
            surface.numeric.quantity_pointer_type_id,
            PointerType::Quantity as u16
        );
        assert_eq!(surface.numeric.mantissa_bits, 512);
        assert_eq!(surface.numeric.max_scale, 28);
        assert_eq!(surface.numeric.semantics_descriptor_version, 4);
        assert_eq!(surface.numeric.rules.len(), 15);
        assert_eq!(surface.numeric.operators.len(), 102);
        assert_eq!(
            surface
                .numeric
                .operators
                .iter()
                .filter(|operator| operator.allowed)
                .count(),
            34
        );
        assert_eq!(surface.numeric.json_grammar.len(), 3);
        assert_eq!(surface.numeric.fault_ordering.len(), 7);
        assert_eq!(surface.numeric.wire_format_version, 1);
        assert_eq!(surface.numeric.int_schema_name, INT_SCHEMA_NAME_V1);
        assert_eq!(surface.numeric.int_schema_hash, INT_SCHEMA_HASH_V1);
        assert_eq!(surface.numeric.decimal_schema_name, DECIMAL_SCHEMA_NAME_V1);
        assert_eq!(surface.numeric.decimal_schema_hash, DECIMAL_SCHEMA_HASH_V1);
        assert_eq!(
            surface.numeric.quantity_schema_name,
            QUANTITY_SCHEMA_NAME_V1
        );
        assert_eq!(
            surface.numeric.quantity_schema_hash,
            QUANTITY_SCHEMA_HASH_V1
        );
        assert_eq!(surface.numeric.frame_header_bytes, 40);
        assert_eq!(surface.numeric.int_max_frame_bytes, 108);
        assert_eq!(surface.numeric.decimal_max_frame_bytes, 109);
        assert_eq!(surface.numeric.quantity_max_frame_bytes, 109);
        assert_eq!(surface.numeric.pointer_envelope_overhead_bytes, 39);
        assert_eq!(surface.numeric.int_max_envelope_bytes, 147);
        assert_eq!(surface.numeric.decimal_max_envelope_bytes, 148);
        assert_eq!(surface.numeric.quantity_max_envelope_bytes, 148);
        assert_eq!(surface.numeric.frame_layout, NUMERIC_FRAME_LAYOUT_V1);
        assert_eq!(
            surface.numeric.pointer_envelope_layout,
            NUMERIC_POINTER_ENVELOPE_LAYOUT_V1
        );
        assert_eq!(
            surface.numeric.error_precedence,
            NUMERIC_ERROR_PRECEDENCE_V1
        );
        assert_eq!(
            surface
                .numeric
                .rounding_modes
                .iter()
                .map(|mode| (mode.name, mode.tag))
                .collect::<Vec<_>>(),
            vec![
                ("toward_zero", 0),
                ("away_from_zero", 1),
                ("floor", 2),
                ("ceil", 3),
                ("nearest_even", 4),
                ("nearest_away", 5),
                ("nearest_toward_zero", 6),
            ]
        );
        assert_eq!(
            surface
                .numeric
                .failure_modes
                .iter()
                .map(|mode| (mode.name, mode.tag))
                .collect::<Vec<_>>(),
            vec![("trap", 0), ("status", 1)]
        );
        assert_eq!(
            surface
                .numeric
                .faults
                .iter()
                .map(|fault| (fault.name, fault.tag))
                .collect::<Vec<_>>(),
            vec![
                ("mantissa_overflow", 1),
                ("scale_overflow", 2),
                ("division_by_zero", 3),
                ("repeating_decimal", 4),
                ("exact_division_scale_overflow", 5),
                ("invalid_scale", 6),
                ("inexact_conversion", 7),
                ("negative_quantity", 8),
                ("quantity_underflow", 9),
                ("invalid_rounding_mode", 10),
                ("invalid_failure_mode", 11),
                ("reserved_register_nonzero", 12),
                ("negative_square_root", 13),
            ]
        );
        assert_eq!(
            surface
                .numeric
                .pointer_faults
                .iter()
                .map(|fault| (fault.name, fault.tag))
                .collect::<Vec<_>>(),
            vec![
                ("invalid_address", 1),
                ("unknown_type", 2),
                ("type_not_allowed", 3),
                ("wrong_type", 4),
                ("invalid_envelope_version", 5),
                ("oversized_length", 6),
                ("truncated_envelope", 7),
                ("payload_hash_mismatch", 8),
                ("malformed_frame", 9),
                ("schema_mismatch", 10),
                ("noncanonical", 11),
            ]
        );
        assert_surface_mutation_changes_hash(|changed| {
            changed
                .pointer_type_ids
                .retain(|type_id| *type_id != PointerType::Decimal as u16);
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.int_pointer_type_id += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.decimal_pointer_type_id += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.quantity_pointer_type_id += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.mantissa_bits -= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.max_scale -= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.semantics_descriptor_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.int_domain = "unbounded";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.decimal_domain = "binary-float";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.quantity_domain = "signed";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.canonicalization = "preserve-source-scale";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.integer_division = "floor";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.wrapping_modulus = "2^64";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.wire_format_version += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.int_schema_name = "wrong.Int";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.int_schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.decimal_schema_name = "wrong.Decimal";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.decimal_schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.quantity_schema_name = "wrong.Quantity";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.quantity_schema_hash[0] ^= 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.frame_header_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.int_max_frame_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.decimal_max_frame_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.quantity_max_frame_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.pointer_envelope_overhead_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.int_max_envelope_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.decimal_max_envelope_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.quantity_max_envelope_bytes += 1;
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.frame_layout = "host-dependent";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.pointer_envelope_layout = "unframed";
        });
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.error_precedence = "unspecified";
        });
        for rule_index in 0..surface.numeric.rules.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.rules[rule_index].name = "mutated_rule";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.rules[rule_index].specification = "host-dependent";
            });
        }
        for operator_index in 0..surface.numeric.operators.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.operators[operator_index].operator = "mutated_operator";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.operators[operator_index].lhs = "mutated_lhs";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.operators[operator_index].rhs = "mutated_rhs";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.operators[operator_index].allowed =
                    !changed.numeric.operators[operator_index].allowed;
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.operators[operator_index].result = "mutated_result";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.operators[operator_index].semantics = "host-dependent";
            });
        }
        for grammar_index in 0..surface.numeric.json_grammar.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.json_grammar[grammar_index].type_name = "mutated_type";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.json_grammar[grammar_index].token_kind = "JSON-number";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.json_grammar[grammar_index].decoded_string_grammar = ".*";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.json_grammar[grammar_index].validation = "accept-anything";
            });
        }
        for order_index in 0..surface.numeric.fault_ordering.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.fault_ordering[order_index].name = "mutated_fault_stage";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.fault_ordering[order_index].specification = "unspecified";
            });
        }
        assert_surface_mutation_changes_hash(|changed| changed.numeric.rules.swap(0, 1));
        assert_surface_mutation_changes_hash(|changed| changed.numeric.operators.swap(0, 1));
        assert_surface_mutation_changes_hash(|changed| changed.numeric.json_grammar.swap(0, 1));
        assert_surface_mutation_changes_hash(|changed| {
            changed.numeric.fault_ordering.swap(0, 1);
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.numeric.rules.pop();
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.numeric.operators.pop();
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.numeric.json_grammar.pop();
        });
        assert_surface_mutation_changes_hash(|changed| {
            let _ = changed.numeric.fault_ordering.pop();
        });
        for mode_index in 0..surface.numeric.rounding_modes.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.rounding_modes[mode_index].name = "mutated_mode";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.rounding_modes[mode_index].tag += 10;
            });
        }
        for mode_index in 0..surface.numeric.failure_modes.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.failure_modes[mode_index].name = "mutated_failure_mode";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.failure_modes[mode_index].tag += 10;
            });
        }
        for fault_index in 0..surface.numeric.faults.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.faults[fault_index].name = "mutated_fault";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.faults[fault_index].tag += 20;
            });
        }
        for fault_index in 0..surface.numeric.pointer_faults.len() {
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.pointer_faults[fault_index].name = "mutated_pointer_fault";
            });
            assert_surface_mutation_changes_hash(|changed| {
                changed.numeric.pointer_faults[fault_index].tag += 30;
            });
        }
    }
    #[test]
    fn abi_descriptor_framing_distinguishes_ambiguous_byte_partitions() {
        let mut first = AbiDescriptorEncoder::default();
        first.field("ab", b"c").expect("small descriptor field");
        first.field("d", b"ef").expect("small descriptor field");
        let mut second = AbiDescriptorEncoder::default();
        second.field("a", b"bc").expect("small descriptor field");
        second.field("de", b"f").expect("small descriptor field");
        assert_ne!(first.finish(), second.finish());
    }
    #[test]
    fn abi_registry_validation_rejects_missing_duplicate_and_extra_rows() {
        let number = SYSCALL_EXIT;
        assert_eq!(
            collect_abi_syscall_surface(&[number], &[]),
            Err(AbiSurfaceError::MissingSignature(number))
        );
        let row = SyscallDoc {
            number,
            args: "r10=status:u64",
            ret: "u64=status",
            gas: "G_exit",
        };
        let duplicate = [
            SyscallDoc {
                number: row.number,
                args: row.args,
                ret: row.ret,
                gas: row.gas,
            },
            SyscallDoc {
                number: row.number,
                args: row.args,
                ret: row.ret,
                gas: row.gas,
            },
        ];
        assert_eq!(
            collect_abi_syscall_surface(&[number], &duplicate),
            Err(AbiSurfaceError::DuplicateSignature(number))
        );
        let extra = SyscallDoc {
            number: SYSCALL_ABORT,
            args: "-",
            ret: "u64=0",
            gas: "G_abort",
        };
        assert_eq!(
            collect_abi_syscall_surface(&[number], &[extra]),
            Err(AbiSurfaceError::UnexpectedSignature(SYSCALL_ABORT))
        );
        assert!(matches!(
            collect_abi_syscall_surface(&[SYSCALL_ABORT, SYSCALL_EXIT], &duplicate),
            Err(AbiSurfaceError::SyscallsNotStrictlySorted { .. })
        ));
    }
    #[test]
    fn invalid_surface_sentinels_cannot_be_mistaken_for_iroha_hashes() {
        let errors = [
            AbiSurfaceError::EmptySyscallSurface,
            AbiSurfaceError::EmptyPointerSurface,
            AbiSurfaceError::SyscallsNotStrictlySorted {
                previous: 2,
                current: 1,
            },
            AbiSurfaceError::PointerTypesNotStrictlySorted {
                previous: 2,
                current: 1,
            },
            AbiSurfaceError::MissingSignature(1),
            AbiSurfaceError::DuplicateSignature(1),
            AbiSurfaceError::UnexpectedSignature(1),
            AbiSurfaceError::EmptyArguments(1),
            AbiSurfaceError::EmptyReturn(1),
            AbiSurfaceError::SurfaceTooLarge,
        ];
        let mut sentinels = errors.map(invalid_abi_surface_hash);
        assert!(sentinels.iter().all(|sentinel| sentinel[31] & 1 == 0));
        sentinels.sort_unstable();
        assert!(sentinels.windows(2).all(|pair| pair[0] != pair[1]));
    }
    #[test]
    fn pointer_policy_hash_input_is_sorted_complete_and_unique() {
        let policy = crate::SyscallPolicy::AbiV1;
        let allowed = crate::pointer_abi::policy_pointer_types(policy);
        for &pointer_type in crate::pointer_abi::PointerType::all() {
            assert_eq!(
                allowed.contains(&pointer_type),
                !matches!(pointer_type, crate::pointer_abi::PointerType::TestOnly),
                "pointer policy completeness for {pointer_type:?}"
            );
        }
        let mut ids = allowed
            .iter()
            .map(|pointer_type| *pointer_type as u16)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        let mut surface = canonical_surface();
        surface.pointer_type_ids = ids;
        assert!(encode_abi_surface(&surface).is_ok());
    }
}
