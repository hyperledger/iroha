//! Chain-wide configuration parameters.
//!
//! They are supposed to be moved out of the configuration file:
//! [iroha#4028](https://github.com/hyperledger/iroha/issues/4028)

use std::{
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

use iroha_data_model::{prelude::MetadataLimits, transaction::TransactionLimits, LengthLimits};
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};

use crate::{
    ByteSize, Complete, CompleteError, CompleteResult, FromEnv, FromEnvDefaultFallback,
    FromEnvResult, ReadEnv, UserDuration,
};

const DEFAULT_MAX_TXS: NonZeroU32 = nonzero!(2_u32.pow(9));
const DEFAULT_BLOCK_TIME: Duration = Duration::from_secs(2);
const DEFAULT_COMMIT_TIME_LIMIT: Duration = Duration::from_secs(4);
const DEFAULT_WASM_FUEL_LIMIT: NonZeroU64 = nonzero!(30_000_000u64);
const DEFAULT_WASM_MAX_MEMORY: u64 = 500 * 2_u64.pow(20); // 500 MiB

/// Default limits for metadata
const DEFAULT_METADATA_LIMITS: MetadataLimits = MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));
/// Default limits for ident length
const DEFAULT_IDENT_LENGTH_LIMITS: LengthLimits = LengthLimits::new(1, 2_u32.pow(7));
/// Default maximum number of instructions and expressions per transaction
const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
/// Default maximum number of instructions and expressions per transaction
const DEFAULT_MAX_WASM_SIZE_BYTES: u64 = 4 * 2_u64.pow(20); // 4 MiB

/// Default transaction limits
const DEFAULT_TRANSACTION_LIMITS: TransactionLimits =
    TransactionLimits::new(DEFAULT_MAX_INSTRUCTION_NUMBER, DEFAULT_MAX_WASM_SIZE_BYTES);

#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    pub max_transactions_in_block: Option<NonZeroU32>,
    pub block_time: Option<UserDuration>,
    pub commit_time: Option<UserDuration>,
    pub transactions_limits: Option<TransactionLimits>,
    pub asset_metadata_limits: Option<MetadataLimits>,
    pub asset_definition_metadata_limits: Option<MetadataLimits>,
    pub account_metadata_limits: Option<MetadataLimits>,
    pub domain_metadata_limits: Option<MetadataLimits>,
    pub identifier_length_limits: Option<LengthLimits>,
    pub wasm_fuel_limit: Option<NonZeroU64>,
    pub wasm_max_memory: Option<ByteSize>,
}

#[derive(Debug)]
pub struct Config {
    pub max_transactions_in_block: NonZeroU32,
    pub block_time: Duration,
    pub commit_time: Duration,
    pub transactions_limits: TransactionLimits,
    pub asset_metadata_limits: MetadataLimits,
    pub asset_definition_metadata_limits: MetadataLimits,
    pub account_metadata_limits: MetadataLimits,
    pub domain_metadata_limits: MetadataLimits,
    pub identifier_length_limits: LengthLimits,
    pub wasm_fuel_limit: NonZeroU64,
    pub wasm_max_memory: ByteSize,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            max_transactions_in_block: self.max_transactions_in_block.unwrap_or(DEFAULT_MAX_TXS),
            block_time: self
                .block_time
                .map(UserDuration::get)
                .unwrap_or(DEFAULT_BLOCK_TIME),
            commit_time: self
                .commit_time
                .map(UserDuration::get)
                .unwrap_or(DEFAULT_COMMIT_TIME_LIMIT),
            transactions_limits: self
                .transactions_limits
                .unwrap_or(DEFAULT_TRANSACTION_LIMITS),
            asset_metadata_limits: self
                .asset_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            asset_definition_metadata_limits: self
                .asset_definition_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            account_metadata_limits: self
                .account_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            domain_metadata_limits: self
                .domain_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            identifier_length_limits: self
                .identifier_length_limits
                .unwrap_or(DEFAULT_IDENT_LENGTH_LIMITS),
            wasm_fuel_limit: self.wasm_fuel_limit.unwrap_or(DEFAULT_WASM_FUEL_LIMIT),
            wasm_max_memory: self
                .wasm_max_memory
                .unwrap_or(ByteSize(DEFAULT_WASM_MAX_MEMORY)),
        })
    }
}

impl FromEnvDefaultFallback for UserLayer {}
