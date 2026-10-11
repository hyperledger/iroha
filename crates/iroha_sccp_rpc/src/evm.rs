//! EVM JSON-RPC client for Ethereum and BSC (spec §7.1, §7.2, §8).
//!
//! [`EvmClient`] issues the `eth_*` calls the builders and wallet flows need:
//! chain id and head, blocks by number (with transaction hashes), receipts one
//! by one or per block, EIP-1186 proofs, code, `eth_call`, nonces, the priority
//! fee and raw transaction submission.
//!
//! Blocks come back with every header field needed to re-encode the RLP
//! header, including the London, Shanghai, Cancun and Prague fields when the
//! block has them, plus the untouched JSON object for anything else (such as
//! BSC's `milliTimestamp`). Receipts carry every field of the receipt trie
//! encoding. Nothing is verified here: hashes, roots and proofs are checked by
//! `iroha_sccp`.
//!
//! Hex follows the Ethereum JSON-RPC encoding strictly: quantities are `0x`
//! followed by at least one digit and no leading zero (`0x0` for zero); data is
//! `0x` followed by an even number of digits; fixed-size data must have exactly
//! its size. Anything else is an [`RpcError::InvalidResponse`].
//!
//! Every answer is decoded inside its attempt
//! ([`HttpTransport::json_rpc_then`]) under its method's byte cap
//! ([`crate::limits::json_rpc_response_cap`]), so an endpoint that answers
//! with malformed data is discredited and the next call starts at the next
//! endpoint.

use std::fmt;

use norito::json::{Map, Value};

use crate::http::{
    HttpTransport, JsonRpcCall, RpcError, expect_object, invalid_response, optional,
    optional_array, optional_str, required_array, required_str,
};

/// Why a hex string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The `0x` prefix is missing.
    MissingPrefix,
    /// A quantity has no digits.
    Empty,
    /// Data has an odd number of digits.
    OddLength,
    /// A character is not a hex digit.
    InvalidDigit,
    /// A quantity has a leading zero.
    LeadingZero,
    /// A quantity does not fit the target integer.
    Overflow,
    /// Fixed-size data has another length.
    WrongLength {
        /// Required byte length.
        expected: usize,
        /// Decoded byte length.
        found: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => formatter.write_str("missing `0x` prefix"),
            Self::Empty => formatter.write_str("a quantity needs at least one digit"),
            Self::OddLength => formatter.write_str("data has an odd number of hex digits"),
            Self::InvalidDigit => formatter.write_str("not a hex digit"),
            Self::LeadingZero => formatter.write_str("a quantity has a leading zero"),
            Self::Overflow => formatter.write_str("the quantity is too large"),
            Self::WrongLength { expected, found } => {
                write!(formatter, "expected {expected} bytes, found {found}")
            }
        }
    }
}

impl std::error::Error for HexError {}

fn hex_digits(text: &str) -> Result<&str, HexError> {
    let digits = text.strip_prefix("0x").ok_or(HexError::MissingPrefix)?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HexError::InvalidDigit);
    }
    Ok(digits)
}

fn quantity_digits(text: &str, max_digits: usize) -> Result<&str, HexError> {
    let digits = hex_digits(text)?;
    if digits.is_empty() {
        return Err(HexError::Empty);
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(HexError::LeadingZero);
    }
    if digits.len() > max_digits {
        return Err(HexError::Overflow);
    }
    Ok(digits)
}

/// Parses a quantity into a `u64`.
///
/// # Errors
/// [`HexError`] unless `text` is a canonical quantity below `2^64`.
pub fn parse_quantity_u64(text: &str) -> Result<u64, HexError> {
    let digits = quantity_digits(text, 16)?;
    u64::from_str_radix(digits, 16).map_err(|_| HexError::InvalidDigit)
}

/// Parses a quantity into a `u128`.
///
/// # Errors
/// [`HexError`] unless `text` is a canonical quantity below `2^128`.
pub fn parse_quantity_u128(text: &str) -> Result<u128, HexError> {
    let digits = quantity_digits(text, 32)?;
    u128::from_str_radix(digits, 16).map_err(|_| HexError::InvalidDigit)
}

/// Parses a quantity into a [`U256`].
///
/// # Errors
/// [`HexError`] unless `text` is a canonical quantity below `2^256`.
pub fn parse_quantity_u256(text: &str) -> Result<U256, HexError> {
    let digits = quantity_digits(text, 64)?;
    left_padded_word(digits).map(U256)
}

fn left_padded_word(digits: &str) -> Result<[u8; 32], HexError> {
    let padded = format!("{digits:0>64}");
    let mut word = [0_u8; 32];
    hex::decode_to_slice(padded, &mut word).map_err(|_| HexError::InvalidDigit)?;
    Ok(word)
}

/// Parses data (`0x` and an even number of hex digits).
///
/// # Errors
/// [`HexError`] unless `text` is canonical data.
pub fn parse_data(text: &str) -> Result<Vec<u8>, HexError> {
    let digits = hex_digits(text)?;
    if !digits.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    hex::decode(digits).map_err(|_| HexError::InvalidDigit)
}

/// Parses fixed-size data of exactly `N` bytes.
///
/// # Errors
/// [`HexError`] unless `text` is canonical data of `N` bytes.
pub fn parse_data_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let bytes = parse_data(text)?;
    let found = bytes.len();
    bytes
        .try_into()
        .map_err(|_| HexError::WrongLength { expected: N, found })
}

/// Parses an `eth_getProof` storage key: `0x` and 1..=64 digits, as data or as
/// a quantity (nodes echo either), left-padded to 32 bytes.
///
/// # Errors
/// [`HexError`] for anything else.
pub fn parse_storage_key(text: &str) -> Result<[u8; 32], HexError> {
    let digits = hex_digits(text)?;
    if digits.is_empty() {
        return Err(HexError::Empty);
    }
    if digits.len() > 64 {
        return Err(HexError::Overflow);
    }
    left_padded_word(digits)
}

/// Formats a quantity.
pub fn format_quantity(value: u64) -> String {
    format!("{value:#x}")
}

/// Formats data.
pub fn format_data(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// A 256-bit unsigned integer as 32 big-endian bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct U256([u8; 32]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);

    /// The integer with big-endian bytes `bytes`.
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Big-endian bytes.
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Big-endian bytes without leading zeros (empty for zero), as RLP encodes
    /// integers.
    pub fn minimal_be_bytes(&self) -> &[u8] {
        let start = self
            .0
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(self.0.len());
        &self.0[start..]
    }

    /// Whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// The value as a `u128`, if it fits.
    pub fn to_u128(self) -> Option<u128> {
        let (high, low) = self.0.split_at(16);
        if high.iter().any(|byte| *byte != 0) {
            return None;
        }
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(low);
        Some(u128::from_be_bytes(bytes))
    }

    /// The value as a `u64`, if it fits.
    pub fn to_u64(self) -> Option<u64> {
        self.to_u128().and_then(|value| u64::try_from(value).ok())
    }

    /// Formats the value as a quantity.
    pub fn to_quantity(self) -> String {
        let digits = hex::encode(self.minimal_be_bytes());
        let trimmed = digits.trim_start_matches('0');
        if trimmed.is_empty() {
            "0x0".to_owned()
        } else {
            format!("0x{trimmed}")
        }
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        let mut bytes = [0_u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from(u128::from(value))
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_quantity())
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_quantity())
    }
}

/// A block number or tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockTag {
    /// A block number.
    Number(u64),
    /// `earliest`.
    Earliest,
    /// `latest`.
    Latest,
    /// `safe`.
    Safe,
    /// `finalized`.
    Finalized,
    /// `pending`.
    Pending,
}

impl BlockTag {
    /// The JSON-RPC spelling: a quantity or the tag name.
    pub fn to_param(self) -> String {
        match self {
            Self::Number(number) => format_quantity(number),
            Self::Earliest => "earliest".to_owned(),
            Self::Latest => "latest".to_owned(),
            Self::Safe => "safe".to_owned(),
            Self::Finalized => "finalized".to_owned(),
            Self::Pending => "pending".to_owned(),
        }
    }
}

impl From<u64> for BlockTag {
    fn from(number: u64) -> Self {
        Self::Number(number)
    }
}

/// A block for state queries: a number or tag, or a block hash (EIP-1898).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockId {
    /// A number or tag.
    Tag(BlockTag),
    /// A block hash.
    Hash([u8; 32]),
}

impl BlockId {
    /// Parameter of state methods (`eth_getProof`, `eth_call`, …): a number or
    /// tag string, or an EIP-1898 `{"blockHash": …}` object.
    pub fn to_state_param(self) -> Value {
        match self {
            Self::Tag(tag) => Value::from(tag.to_param()),
            Self::Hash(hash) => {
                let mut map = Map::new();
                map.insert("blockHash".to_owned(), Value::from(format_data(&hash)));
                Value::Object(map)
            }
        }
    }

    /// Parameter of `eth_getBlockReceipts`: a number or tag, or a plain hash.
    pub fn to_block_param(self) -> Value {
        match self {
            Self::Tag(tag) => Value::from(tag.to_param()),
            Self::Hash(hash) => Value::from(format_data(&hash)),
        }
    }
}

impl From<BlockTag> for BlockId {
    fn from(tag: BlockTag) -> Self {
        Self::Tag(tag)
    }
}

impl From<u64> for BlockId {
    fn from(number: u64) -> Self {
        Self::Tag(BlockTag::Number(number))
    }
}

/// Block header fields, as needed to re-encode the RLP header.
///
/// Optional fields exist from the fork that introduced them: `base_fee_per_gas`
/// (London), `withdrawals_root` (Shanghai), `blob_gas_used`, `excess_blob_gas`
/// and `parent_beacon_block_root` (Cancun), `requests_hash` (Prague).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmHeader {
    /// Block hash reported by the endpoint.
    pub hash: [u8; 32],
    /// `parentHash`.
    pub parent_hash: [u8; 32],
    /// `sha3Uncles` (ommers hash).
    pub ommers_hash: [u8; 32],
    /// `miner` (beneficiary).
    pub beneficiary: [u8; 20],
    /// `stateRoot`.
    pub state_root: [u8; 32],
    /// `transactionsRoot`.
    pub transactions_root: [u8; 32],
    /// `receiptsRoot`.
    pub receipts_root: [u8; 32],
    /// `logsBloom`.
    pub logs_bloom: [u8; 256],
    /// `difficulty`.
    pub difficulty: U256,
    /// `number`.
    pub number: u64,
    /// `gasLimit`.
    pub gas_limit: u64,
    /// `gasUsed`.
    pub gas_used: u64,
    /// `timestamp` in seconds.
    pub timestamp: u64,
    /// `extraData`.
    pub extra_data: Vec<u8>,
    /// `mixHash` (`prevRandao` after the merge).
    pub mix_hash: [u8; 32],
    /// `nonce`.
    pub nonce: [u8; 8],
    /// `baseFeePerGas` (London).
    pub base_fee_per_gas: Option<U256>,
    /// `withdrawalsRoot` (Shanghai).
    pub withdrawals_root: Option<[u8; 32]>,
    /// `blobGasUsed` (Cancun).
    pub blob_gas_used: Option<u64>,
    /// `excessBlobGas` (Cancun).
    pub excess_blob_gas: Option<u64>,
    /// `parentBeaconBlockRoot` (Cancun).
    pub parent_beacon_block_root: Option<[u8; 32]>,
    /// `requestsHash` (Prague).
    pub requests_hash: Option<[u8; 32]>,
}

/// A block returned by `eth_getBlockByNumber`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmBlock {
    /// Header fields.
    pub header: EvmHeader,
    /// Transaction hashes.
    pub transactions: Vec<[u8; 32]>,
    /// Ommer hashes.
    pub uncles: Vec<[u8; 32]>,
    /// `size`, when reported.
    pub size: Option<u64>,
    /// The block object as returned, for fields this type does not name.
    pub raw: Value,
}

/// A log of a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmLog {
    /// Emitting contract.
    pub address: [u8; 20],
    /// Topics.
    pub topics: Vec<[u8; 32]>,
    /// Data.
    pub data: Vec<u8>,
    /// Position of the log in the block.
    pub log_index: Option<u64>,
    /// Position of the transaction in the block.
    pub transaction_index: Option<u64>,
    /// Transaction hash.
    pub transaction_hash: Option<[u8; 32]>,
    /// Block hash.
    pub block_hash: Option<[u8; 32]>,
    /// Block number.
    pub block_number: Option<u64>,
    /// Whether the log was removed by a reorganisation.
    pub removed: bool,
}

/// A transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReceipt {
    /// EIP-2718 type (`0` when absent).
    pub tx_type: u8,
    /// `status` (1 success, 0 failure) after Byzantium.
    pub status: Option<u8>,
    /// Post-state `root` before Byzantium.
    pub state_root: Option<[u8; 32]>,
    /// `cumulativeGasUsed`.
    pub cumulative_gas_used: u64,
    /// `logsBloom`.
    pub logs_bloom: [u8; 256],
    /// Logs, in order.
    pub logs: Vec<EvmLog>,
    /// Transaction hash.
    pub transaction_hash: [u8; 32],
    /// Position in the block.
    pub transaction_index: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// Block number.
    pub block_number: u64,
    /// `gasUsed`.
    pub gas_used: u64,
    /// `effectiveGasPrice`.
    pub effective_gas_price: Option<U256>,
    /// Sender.
    pub from: Option<[u8; 20]>,
    /// Recipient.
    pub to: Option<[u8; 20]>,
    /// Created contract.
    pub contract_address: Option<[u8; 20]>,
    /// `blobGasUsed` (Cancun).
    pub blob_gas_used: Option<u64>,
    /// `blobGasPrice` (Cancun).
    pub blob_gas_price: Option<U256>,
}

/// One storage slot of an EIP-1186 proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmStorageProof {
    /// Slot key (as requested).
    pub key: [u8; 32],
    /// Slot value.
    pub value: U256,
    /// RLP trie nodes from the storage root.
    pub proof: Vec<Vec<u8>>,
}

/// An EIP-1186 account proof (`eth_getProof`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmAccountProof {
    /// Account address.
    pub address: [u8; 20],
    /// Balance.
    pub balance: U256,
    /// Code hash.
    pub code_hash: [u8; 32],
    /// Nonce.
    pub nonce: u64,
    /// Storage root.
    pub storage_hash: [u8; 32],
    /// RLP trie nodes from the state root.
    pub account_proof: Vec<Vec<u8>>,
    /// Requested storage slots, in request order.
    pub storage_proof: Vec<EvmStorageProof>,
}

/// An `eth_call` / `eth_estimateGas` call object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvmCallRequest {
    /// Sender, when it matters.
    pub from: Option<[u8; 20]>,
    /// Called contract.
    pub to: [u8; 20],
    /// Call data.
    pub data: Vec<u8>,
    /// Transferred value.
    pub value: Option<U256>,
    /// Gas limit.
    pub gas: Option<u64>,
}

impl EvmCallRequest {
    /// A call of `to` with `data`.
    pub fn new(to: [u8; 20], data: Vec<u8>) -> Self {
        Self {
            to,
            data,
            ..Self::default()
        }
    }

    fn to_param(&self) -> Value {
        let mut map = Map::new();
        if let Some(from) = self.from {
            map.insert("from".to_owned(), Value::from(format_data(&from)));
        }
        map.insert("to".to_owned(), Value::from(format_data(&self.to)));
        map.insert("data".to_owned(), Value::from(format_data(&self.data)));
        if let Some(value) = self.value {
            map.insert("value".to_owned(), Value::from(value.to_quantity()));
        }
        if let Some(gas) = self.gas {
            map.insert("gas".to_owned(), Value::from(format_quantity(gas)));
        }
        Value::Object(map)
    }
}

/// JSON-RPC client of one EVM chain (Ethereum or BSC).
#[derive(Debug)]
pub struct EvmClient {
    transport: HttpTransport,
}

impl EvmClient {
    /// A client over `transport`.
    pub fn new(transport: HttpTransport) -> Self {
        Self { transport }
    }

    /// The underlying transport.
    pub fn transport(&self) -> &HttpTransport {
        &self.transport
    }

    /// `eth_chainId`.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn chain_id(&self) -> Result<u64, RpcError> {
        self.transport
            .json_rpc_then("eth_chainId", Vec::new(), |value| {
                value_hex(&value, "eth_chainId", parse_quantity_u64)
            })
    }

    /// `eth_blockNumber`.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn block_number(&self) -> Result<u64, RpcError> {
        self.transport
            .json_rpc_then("eth_blockNumber", Vec::new(), |value| {
                value_hex(&value, "eth_blockNumber", parse_quantity_u64)
            })
    }

    /// `eth_getBlockByNumber`; `None` if the endpoint does not know the block.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn block_by_number(&self, block: BlockTag) -> Result<Option<EvmBlock>, RpcError> {
        self.transport.json_rpc_then(
            "eth_getBlockByNumber",
            vec![Value::from(block.to_param()), Value::from(false)],
            parse_block,
        )
    }

    /// `eth_getBlockByNumber` for up to [`crate::http::MAX_JSON_RPC_BATCH`]
    /// numbers in one JSON-RPC batch, in request order.
    ///
    /// # Errors
    /// Any [`RpcError`]; one failed call fails the whole batch.
    pub fn blocks_by_number(&self, numbers: &[u64]) -> Result<Vec<Option<EvmBlock>>, RpcError> {
        let calls = numbers
            .iter()
            .map(|number| {
                JsonRpcCall::new(
                    "eth_getBlockByNumber",
                    vec![Value::from(format_quantity(*number)), Value::from(false)],
                )
            })
            .collect();
        self.transport.json_rpc_batch_then(calls, |results| {
            results
                .into_iter()
                .map(|result| result.and_then(parse_block))
                .collect()
        })
    }

    /// `eth_getTransactionReceipt`; `None` for an unknown or pending
    /// transaction.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn transaction_receipt(&self, hash: &[u8; 32]) -> Result<Option<EvmReceipt>, RpcError> {
        self.transport.json_rpc_then(
            "eth_getTransactionReceipt",
            vec![Value::from(format_data(hash))],
            |value| {
                if value.is_null() {
                    return Ok(None);
                }
                parse_receipt(&value).map(Some)
            },
        )
    }

    /// `eth_getBlockReceipts`; `None` if the endpoint does not know the block.
    ///
    /// # Errors
    /// Any [`RpcError`].
    // TODO(WP9): an adversarially log-filled block answers with more receipt
    // JSON than the transport ceiling admits; proving events in such blocks
    // needs a streaming receipt decoder instead of a `Value` tree.
    pub fn block_receipts(&self, block: BlockId) -> Result<Option<Vec<EvmReceipt>>, RpcError> {
        self.transport.json_rpc_then(
            "eth_getBlockReceipts",
            vec![block.to_block_param()],
            |value| {
                if value.is_null() {
                    return Ok(None);
                }
                let receipts = value.as_array().ok_or_else(|| {
                    invalid_response("eth_getBlockReceipts result is not an array")
                })?;
                receipts
                    .iter()
                    .map(parse_receipt)
                    .collect::<Result<_, _>>()
                    .map(Some)
            },
        )
    }

    /// `eth_getProof` of `address` and `storage_keys` at `block`.
    ///
    /// # Errors
    /// Any [`RpcError`]; [`RpcError::InvalidResponse`] also if the proof is for
    /// another address or other slots.
    pub fn proof(
        &self,
        address: &[u8; 20],
        storage_keys: &[[u8; 32]],
        block: BlockId,
    ) -> Result<EvmAccountProof, RpcError> {
        let keys = storage_keys
            .iter()
            .map(|key| Value::from(format_data(key)))
            .collect();
        self.transport.json_rpc_then(
            "eth_getProof",
            vec![
                Value::from(format_data(address)),
                Value::Array(keys),
                block.to_state_param(),
            ],
            |value| {
                let proof = parse_account_proof(&value)?;
                if proof.address != *address {
                    return Err(invalid_response(
                        "eth_getProof answered for another address",
                    ));
                }
                if proof.storage_proof.len() != storage_keys.len()
                    || proof
                        .storage_proof
                        .iter()
                        .zip(storage_keys)
                        .any(|(slot, key)| slot.key != *key)
                {
                    return Err(invalid_response(
                        "eth_getProof answered for other storage keys",
                    ));
                }
                Ok(proof)
            },
        )
    }

    /// `eth_getCode` of `address` at `block`.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn code(&self, address: &[u8; 20], block: BlockId) -> Result<Vec<u8>, RpcError> {
        self.transport.json_rpc_then(
            "eth_getCode",
            vec![Value::from(format_data(address)), block.to_state_param()],
            |value| value_hex(&value, "eth_getCode", parse_data),
        )
    }

    /// `eth_call` at `block`; returns the return data.
    ///
    /// # Errors
    /// Any [`RpcError`]; a revert is a [`RpcError::JsonRpc`] whose `data`
    /// carries the revert payload.
    pub fn call(&self, request: &EvmCallRequest, block: BlockId) -> Result<Vec<u8>, RpcError> {
        self.transport.json_rpc_then(
            "eth_call",
            vec![request.to_param(), block.to_state_param()],
            |value| value_hex(&value, "eth_call", parse_data),
        )
    }

    /// `eth_estimateGas` against the latest state.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn estimate_gas(&self, request: &EvmCallRequest) -> Result<u64, RpcError> {
        self.transport
            .json_rpc_then("eth_estimateGas", vec![request.to_param()], |value| {
                value_hex(&value, "eth_estimateGas", parse_quantity_u64)
            })
    }

    /// `eth_getTransactionCount` (the account nonce) at `block`.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn transaction_count(&self, address: &[u8; 20], block: BlockId) -> Result<u64, RpcError> {
        self.transport.json_rpc_then(
            "eth_getTransactionCount",
            vec![Value::from(format_data(address)), block.to_state_param()],
            |value| value_hex(&value, "eth_getTransactionCount", parse_quantity_u64),
        )
    }

    /// `eth_maxPriorityFeePerGas`.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn max_priority_fee_per_gas(&self) -> Result<U256, RpcError> {
        self.transport
            .json_rpc_then("eth_maxPriorityFeePerGas", Vec::new(), |value| {
                value_hex(&value, "eth_maxPriorityFeePerGas", parse_quantity_u256)
            })
    }

    /// `eth_sendRawTransaction`; returns the transaction hash the endpoint
    /// reports (callers compare it with `keccak256(raw)`).
    ///
    /// # Errors
    /// Any [`RpcError`]; rejections are [`RpcError::JsonRpc`].
    pub fn send_raw_transaction(&self, raw: &[u8]) -> Result<[u8; 32], RpcError> {
        if raw.is_empty() {
            return Err(RpcError::InvalidRequest(
                "a raw transaction must not be empty".to_owned(),
            ));
        }
        self.transport.json_rpc_then(
            "eth_sendRawTransaction",
            vec![Value::from(format_data(raw))],
            |value| value_hex(&value, "eth_sendRawTransaction", parse_data_array::<32>),
        )
    }
}

fn hex_error(what: &str, key: &str, error: HexError) -> RpcError {
    invalid_response(format!("{what}.{key}: {error}"))
}

/// A top-level result string parsed with `parse`.
fn value_hex<T>(
    value: &Value,
    what: &str,
    parse: impl Fn(&str) -> Result<T, HexError>,
) -> Result<T, RpcError> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid_response(format!("{what} result is not a string")))?;
    parse(text).map_err(|error| invalid_response(format!("{what} result: {error}")))
}

fn hex_field<T>(
    map: &Map,
    key: &str,
    what: &str,
    parse: impl Fn(&str) -> Result<T, HexError>,
) -> Result<T, RpcError> {
    parse(required_str(map, key, what)?).map_err(|error| hex_error(what, key, error))
}

fn optional_hex_field<T>(
    map: &Map,
    key: &str,
    what: &str,
    parse: impl Fn(&str) -> Result<T, HexError>,
) -> Result<Option<T>, RpcError> {
    optional_str(map, key, what)?
        .map(|text| parse(text).map_err(|error| hex_error(what, key, error)))
        .transpose()
}

fn hex_list<T>(
    values: &[Value],
    what: &str,
    parse: impl Fn(&str) -> Result<T, HexError>,
) -> Result<Vec<T>, RpcError> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let text = value
                .as_str()
                .ok_or_else(|| invalid_response(format!("{what}[{index}] is not a string")))?;
            parse(text).map_err(|error| invalid_response(format!("{what}[{index}]: {error}")))
        })
        .collect()
}

fn tx_type(map: &Map, what: &str) -> Result<u8, RpcError> {
    optional_hex_field(map, "type", what, parse_quantity_u64)?.map_or(Ok(0), |value| {
        u8::try_from(value).map_err(|_| invalid_response(format!("{what}.type exceeds one byte")))
    })
}

/// Parses an `eth_getBlockByNumber` result with transaction hashes (`null`
/// for an unknown block).
fn parse_block(value: Value) -> Result<Option<EvmBlock>, RpcError> {
    if value.is_null() {
        return Ok(None);
    }
    let what = "block";
    let map = expect_object(&value, what)?;
    let header = parse_header(map)?;
    let transactions = hex_list(
        required_array(map, "transactions", what)?,
        "block.transactions",
        parse_data_array::<32>,
    )?;
    let uncles = hex_list(
        optional_array(map, "uncles", what)?,
        "block.uncles",
        parse_data_array::<32>,
    )?;
    let size = optional_hex_field(map, "size", what, parse_quantity_u64)?;
    Ok(Some(EvmBlock {
        header,
        transactions,
        uncles,
        size,
        raw: value,
    }))
}

fn parse_header(map: &Map) -> Result<EvmHeader, RpcError> {
    let what = "block";
    Ok(EvmHeader {
        hash: hex_field(map, "hash", what, parse_data_array::<32>)?,
        parent_hash: hex_field(map, "parentHash", what, parse_data_array::<32>)?,
        ommers_hash: hex_field(map, "sha3Uncles", what, parse_data_array::<32>)?,
        beneficiary: hex_field(map, "miner", what, parse_data_array::<20>)?,
        state_root: hex_field(map, "stateRoot", what, parse_data_array::<32>)?,
        transactions_root: hex_field(map, "transactionsRoot", what, parse_data_array::<32>)?,
        receipts_root: hex_field(map, "receiptsRoot", what, parse_data_array::<32>)?,
        logs_bloom: hex_field(map, "logsBloom", what, parse_data_array::<256>)?,
        difficulty: hex_field(map, "difficulty", what, parse_quantity_u256)?,
        number: hex_field(map, "number", what, parse_quantity_u64)?,
        gas_limit: hex_field(map, "gasLimit", what, parse_quantity_u64)?,
        gas_used: hex_field(map, "gasUsed", what, parse_quantity_u64)?,
        timestamp: hex_field(map, "timestamp", what, parse_quantity_u64)?,
        extra_data: hex_field(map, "extraData", what, parse_data)?,
        mix_hash: hex_field(map, "mixHash", what, parse_data_array::<32>)?,
        nonce: hex_field(map, "nonce", what, parse_data_array::<8>)?,
        base_fee_per_gas: optional_hex_field(map, "baseFeePerGas", what, parse_quantity_u256)?,
        withdrawals_root: optional_hex_field(map, "withdrawalsRoot", what, parse_data_array::<32>)?,
        blob_gas_used: optional_hex_field(map, "blobGasUsed", what, parse_quantity_u64)?,
        excess_blob_gas: optional_hex_field(map, "excessBlobGas", what, parse_quantity_u64)?,
        parent_beacon_block_root: optional_hex_field(
            map,
            "parentBeaconBlockRoot",
            what,
            parse_data_array::<32>,
        )?,
        requests_hash: optional_hex_field(map, "requestsHash", what, parse_data_array::<32>)?,
    })
}

fn parse_log(value: &Value) -> Result<EvmLog, RpcError> {
    let what = "log";
    let map = expect_object(value, what)?;
    let removed = match optional(map, "removed") {
        None => false,
        Some(flag) => flag
            .as_bool()
            .ok_or_else(|| invalid_response("log.removed is not a boolean"))?,
    };
    Ok(EvmLog {
        address: hex_field(map, "address", what, parse_data_array::<20>)?,
        topics: hex_list(
            required_array(map, "topics", what)?,
            "log.topics",
            parse_data_array::<32>,
        )?,
        data: hex_field(map, "data", what, parse_data)?,
        log_index: optional_hex_field(map, "logIndex", what, parse_quantity_u64)?,
        transaction_index: optional_hex_field(map, "transactionIndex", what, parse_quantity_u64)?,
        transaction_hash: optional_hex_field(map, "transactionHash", what, parse_data_array::<32>)?,
        block_hash: optional_hex_field(map, "blockHash", what, parse_data_array::<32>)?,
        block_number: optional_hex_field(map, "blockNumber", what, parse_quantity_u64)?,
        removed,
    })
}

fn parse_receipt(value: &Value) -> Result<EvmReceipt, RpcError> {
    let what = "receipt";
    let map = expect_object(value, what)?;
    let status = optional_hex_field(map, "status", what, parse_quantity_u64)?
        .map(|status| match status {
            0 => Ok(0),
            1 => Ok(1),
            _ => Err(invalid_response("receipt.status is neither 0x0 nor 0x1")),
        })
        .transpose()?;
    let state_root = optional_hex_field(map, "root", what, parse_data_array::<32>)?;
    if status.is_none() && state_root.is_none() {
        return Err(invalid_response("receipt lacks both `status` and `root`"));
    }
    Ok(EvmReceipt {
        tx_type: tx_type(map, what)?,
        status,
        state_root,
        cumulative_gas_used: hex_field(map, "cumulativeGasUsed", what, parse_quantity_u64)?,
        logs_bloom: hex_field(map, "logsBloom", what, parse_data_array::<256>)?,
        logs: required_array(map, "logs", what)?
            .iter()
            .map(parse_log)
            .collect::<Result<_, _>>()?,
        transaction_hash: hex_field(map, "transactionHash", what, parse_data_array::<32>)?,
        transaction_index: hex_field(map, "transactionIndex", what, parse_quantity_u64)?,
        block_hash: hex_field(map, "blockHash", what, parse_data_array::<32>)?,
        block_number: hex_field(map, "blockNumber", what, parse_quantity_u64)?,
        gas_used: hex_field(map, "gasUsed", what, parse_quantity_u64)?,
        effective_gas_price: optional_hex_field(
            map,
            "effectiveGasPrice",
            what,
            parse_quantity_u256,
        )?,
        from: optional_hex_field(map, "from", what, parse_data_array::<20>)?,
        to: optional_hex_field(map, "to", what, parse_data_array::<20>)?,
        contract_address: optional_hex_field(map, "contractAddress", what, parse_data_array::<20>)?,
        blob_gas_used: optional_hex_field(map, "blobGasUsed", what, parse_quantity_u64)?,
        blob_gas_price: optional_hex_field(map, "blobGasPrice", what, parse_quantity_u256)?,
    })
}

fn parse_account_proof(value: &Value) -> Result<EvmAccountProof, RpcError> {
    let what = "proof";
    let map = expect_object(value, what)?;
    let storage_proof = required_array(map, "storageProof", what)?
        .iter()
        .map(|slot| {
            let what = "proof.storageProof";
            let slot = expect_object(slot, what)?;
            Ok(EvmStorageProof {
                key: hex_field(slot, "key", what, parse_storage_key)?,
                value: hex_field(slot, "value", what, parse_quantity_u256)?,
                proof: hex_list(
                    required_array(slot, "proof", what)?,
                    "proof.storageProof.proof",
                    parse_data,
                )?,
            })
        })
        .collect::<Result<_, RpcError>>()?;
    Ok(EvmAccountProof {
        address: hex_field(map, "address", what, parse_data_array::<20>)?,
        balance: hex_field(map, "balance", what, parse_quantity_u256)?,
        code_hash: hex_field(map, "codeHash", what, parse_data_array::<32>)?,
        nonce: hex_field(map, "nonce", what, parse_quantity_u64)?,
        storage_hash: hex_field(map, "storageHash", what, parse_data_array::<32>)?,
        account_proof: hex_list(
            required_array(map, "accountProof", what)?,
            "proof.accountProof",
            parse_data,
        )?,
        storage_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Value {
        norito::json::parse_value(text).expect("test JSON")
    }

    #[test]
    fn quantities_are_canonical() {
        assert_eq!(parse_quantity_u64("0x0"), Ok(0));
        assert_eq!(parse_quantity_u64("0x18daf08"), Ok(0x18d_af08));
        assert_eq!(parse_quantity_u64("0xFFFFFFFFFFFFFFFF"), Ok(u64::MAX));
        assert_eq!(
            parse_quantity_u64("0x1ffffffffffffffff"),
            Err(HexError::Overflow)
        );
        assert_eq!(parse_quantity_u64("0x01"), Err(HexError::LeadingZero));
        assert_eq!(parse_quantity_u64("0x"), Err(HexError::Empty));
        assert_eq!(parse_quantity_u64("1"), Err(HexError::MissingPrefix));
        assert_eq!(parse_quantity_u64("0X1"), Err(HexError::MissingPrefix));
        assert_eq!(parse_quantity_u64("0xg"), Err(HexError::InvalidDigit));
        assert_eq!(parse_quantity_u64("0x+1"), Err(HexError::InvalidDigit));
        assert_eq!(parse_quantity_u64(" 0x1"), Err(HexError::MissingPrefix));
        assert_eq!(parse_quantity_u128("0x100000000000000000"), Ok(1 << 68));
        assert_eq!(
            parse_quantity_u128(&format!("0x1{}", "0".repeat(32))),
            Err(HexError::Overflow)
        );
    }

    #[test]
    fn u256_quantities_round_trip() {
        let value = parse_quantity_u256(
            "0x4168ab54c50c21f13c2fc36b285fc7666824d3acb7879f56945b73d07338a942",
        )
        .expect("256-bit");
        assert_eq!(
            value.to_quantity(),
            "0x4168ab54c50c21f13c2fc36b285fc7666824d3acb7879f56945b73d07338a942"
        );
        assert_eq!(value.to_u128(), None);
        assert_eq!(parse_quantity_u256("0x0").expect("zero"), U256::ZERO);
        assert!(U256::ZERO.is_zero());
        assert!(U256::ZERO.minimal_be_bytes().is_empty());
        assert_eq!(U256::ZERO.to_quantity(), "0x0");
        let small = U256::from(0x0102_u64);
        assert_eq!(small.minimal_be_bytes(), &[1, 2]);
        assert_eq!(small.to_u64(), Some(0x0102));
        assert_eq!(small.to_quantity(), "0x102");
        assert_eq!(format!("{small}"), "0x102");
        assert_eq!(format!("{small:?}"), "0x102");
        assert_eq!(U256::from_be_bytes(small.to_be_bytes()), small);
        assert_eq!(
            parse_quantity_u256(&format!("0x1{}", "0".repeat(64))),
            Err(HexError::Overflow)
        );
    }

    #[test]
    fn data_is_even_and_sized() {
        assert_eq!(parse_data("0x"), Ok(Vec::new()));
        assert_eq!(parse_data("0x00ff"), Ok(vec![0, 0xff]));
        assert_eq!(parse_data("0xABcd"), Ok(vec![0xab, 0xcd]));
        assert_eq!(parse_data("0x0"), Err(HexError::OddLength));
        assert_eq!(parse_data("00"), Err(HexError::MissingPrefix));
        assert_eq!(parse_data("0xzz"), Err(HexError::InvalidDigit));
        assert_eq!(parse_data_array::<2>("0x0102"), Ok([1, 2]));
        assert_eq!(
            parse_data_array::<20>("0x0102"),
            Err(HexError::WrongLength {
                expected: 20,
                found: 2
            })
        );
        assert_eq!(format_data(&[0, 0xab]), "0x00ab");
        assert_eq!(format_quantity(0), "0x0");
        assert_eq!(format_quantity(255), "0xff");
    }

    #[test]
    fn storage_keys_accept_data_and_quantity_spellings() {
        let mut expected = [0_u8; 32];
        expected[30] = 0x1b;
        expected[31] = 0x75;
        assert_eq!(parse_storage_key("0x1b75"), Ok(expected));
        assert_eq!(
            parse_storage_key(&format!("0x{}", hex::encode(expected))),
            Ok(expected)
        );
        assert_eq!(parse_storage_key("0x"), Err(HexError::Empty));
        assert_eq!(
            parse_storage_key(&format!("0x{}", "1".repeat(65))),
            Err(HexError::Overflow)
        );
        assert_eq!(parse_storage_key("1b75"), Err(HexError::MissingPrefix));
    }

    #[test]
    fn block_parameters_are_spelled_as_json_rpc_expects() {
        assert_eq!(BlockTag::Number(0x018d_af08).to_param(), "0x18daf08");
        assert_eq!(BlockTag::Finalized.to_param(), "finalized");
        assert_eq!(BlockTag::Safe.to_param(), "safe");
        assert_eq!(BlockTag::Earliest.to_param(), "earliest");
        assert_eq!(BlockTag::Pending.to_param(), "pending");
        assert_eq!(BlockTag::from(5), BlockTag::Number(5));
        assert_eq!(BlockId::from(5).to_state_param(), Value::from("0x5"));
        assert_eq!(
            BlockId::from(BlockTag::Latest).to_block_param(),
            Value::from("latest")
        );
        let hash = [0xab_u8; 32];
        assert_eq!(
            BlockId::Hash(hash).to_state_param(),
            parse(&format!(r#"{{"blockHash":"{}"}}"#, format_data(&hash)))
        );
        assert_eq!(
            BlockId::Hash(hash).to_block_param(),
            Value::from(format_data(&hash))
        );
    }

    #[test]
    fn call_objects_carry_only_given_fields() {
        let mut request = EvmCallRequest::new([1; 20], vec![0x95, 0xd8, 0x9b, 0x41]);
        assert_eq!(
            request.to_param(),
            parse(r#"{"to":"0x0101010101010101010101010101010101010101","data":"0x95d89b41"}"#)
        );
        request.from = Some([2; 20]);
        request.value = Some(U256::from(1_u64));
        request.gas = Some(21_000);
        let param = request.to_param();
        assert_eq!(param.get("value").and_then(Value::as_str), Some("0x1"));
        assert_eq!(param.get("gas").and_then(Value::as_str), Some("0x5208"));
        assert_eq!(
            param.get("from").and_then(Value::as_str),
            Some("0x0202020202020202020202020202020202020202")
        );
    }

    fn receipt_json(status: &str) -> String {
        format!(
            r#"{{"type":"0x2","status":"{status}","cumulativeGasUsed":"0x5208","logsBloom":"0x{bloom}","logs":[{{"address":"0x{addr}","topics":["0x{topic}"],"data":"0x","logIndex":"0x0","removed":false}}],"transactionHash":"0x{topic}","transactionIndex":"0x0","blockHash":"0x{topic}","blockNumber":"0x1","gasUsed":"0x5208","effectiveGasPrice":"0x1","from":"0x{addr}","to":null,"contractAddress":"0x{addr}"}}"#,
            bloom = "00".repeat(256),
            addr = "11".repeat(20),
            topic = "22".repeat(32),
        )
    }

    #[test]
    fn receipts_parse_and_reject_malformed_fields() {
        let receipt = parse_receipt(&parse(&receipt_json("0x1"))).expect("receipt");
        assert_eq!(receipt.tx_type, 2);
        assert_eq!(receipt.status, Some(1));
        assert_eq!(receipt.to, None);
        assert_eq!(receipt.contract_address, Some([0x11; 20]));
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].topics, vec![[0x22; 32]]);
        assert!(!receipt.logs[0].removed);
        assert!(parse_receipt(&parse(&receipt_json("0x2"))).is_err());
        assert!(parse_receipt(&parse(&receipt_json("0x01"))).is_err());
        let without_status = receipt_json("0x1").replace(r#""status":"0x1","#, "");
        assert!(parse_receipt(&parse(&without_status)).is_err());
        let with_root = receipt_json("0x1").replace(
            r#""status":"0x1","#,
            &format!(r#""root":"0x{}","#, "33".repeat(32)),
        );
        let legacy = parse_receipt(&parse(&with_root)).expect("pre-Byzantium receipt");
        assert_eq!(legacy.status, None);
        assert_eq!(legacy.state_root, Some([0x33; 32]));
    }

    #[test]
    fn block_transactions_are_hashes() {
        let header = format!(
            r#""hash":"0x{h}","parentHash":"0x{h}","sha3Uncles":"0x{h}","miner":"0x{a}","stateRoot":"0x{h}","transactionsRoot":"0x{h}","receiptsRoot":"0x{h}","logsBloom":"0x{b}","difficulty":"0x0","number":"0x1","gasLimit":"0x1","gasUsed":"0x0","timestamp":"0x1","extraData":"0x","mixHash":"0x{h}","nonce":"0x0000000000000000","uncles":[]"#,
            h = "44".repeat(32),
            a = "55".repeat(20),
            b = "00".repeat(256),
        );
        let hashes = parse(&format!(
            r#"{{{header},"transactions":["0x{}"]}}"#,
            "66".repeat(32)
        ));
        let block = parse_block(hashes).expect("block").expect("known block");
        assert_eq!(block.transactions, vec![[0x66; 32]]);
        assert_eq!(block.header.base_fee_per_gas, None);
        assert_eq!(block.header.requests_hash, None);
        let objects = parse(&format!(
            r#"{{{header},"transactions":[{{"hash":"0x{}"}}]}}"#,
            "66".repeat(32)
        ));
        assert!(parse_block(objects).is_err());
        assert_eq!(parse_block(Value::Null).expect("null"), None);
        let bad_nonce = parse(
            &format!(r#"{{{header},"transactions":[]}}"#)
                .replace(r#""nonce":"0x0000000000000000""#, r#""nonce":"0x00""#),
        );
        assert!(parse_block(bad_nonce).is_err());
    }
}
