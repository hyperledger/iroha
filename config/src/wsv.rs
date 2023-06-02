//! Module for `WorldStateView`-related configuration and structs.
#![allow(clippy::std_instead_of_core)]

use iroha_config_base::{Configuration, Documented};
use iroha_data_model::prelude::*;
use serde::{Deserialize, Serialize};

use crate::wasm;

/// Default maximum number of instructions and expressions per transaction
const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);

/// Default limits for metadata
const DEFAULT_METADATA_LIMITS: MetadataLimits = MetadataLimits::new(2_u32.pow(20), 2_u32.pow(12));

/// Default maximum number of instructions and expressions per transaction
const DEFAULT_MAX_WASM_SIZE_BYTES: u64 = 2_u64.pow(22); // 4 MiB

/// Default transaction limits
const DEFAULT_TRANSACTION_LIMITS: TransactionLimits =
    TransactionLimits::new(DEFAULT_MAX_INSTRUCTION_NUMBER, DEFAULT_MAX_WASM_SIZE_BYTES);

/// `WorldStateView` configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "WSV_")]
pub struct Configuration {
    /// [`MetadataLimits`] for every asset with store.
    #[config(default = "DEFAULT_METADATA_LIMITS")]
    asset_metadata_limits: MetadataLimits,
    /// [`MetadataLimits`] of any asset definition metadata.
    #[config(default = "DEFAULT_METADATA_LIMITS")]
    asset_definition_metadata_limits: MetadataLimits,
    /// [`MetadataLimits`] of any account metadata.
    #[config(default = "DEFAULT_METADATA_LIMITS")]
    account_metadata_limits: MetadataLimits,
    /// [`MetadataLimits`] of any domain metadata.
    #[config(default = "DEFAULT_METADATA_LIMITS")]
    domain_metadata_limits: MetadataLimits,
    /// [`LengthLimits`] for the number of chars in identifiers that can be stored in the WSV.
    #[config(default = "LengthLimits::new(1, 2_u32.pow(7))")]
    ident_length_limits: LengthLimits,
    /// Limits that all transactions need to obey, in terms of size
    /// of WASM blob and number of instructions.
    #[config(default = "DEFAULT_TRANSACTION_LIMITS")]
    transaction_limits: TransactionLimits,
    /// WASM runtime configuration
    #[config(default = "wasm::Configuration::default()")]
    wasm_runtime_config: wasm::Configuration,
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                asset_metadata_limits in prop::option::of(Just(Configuration::DEFAULT_ASSET_METADATA_LIMITS())),
                asset_definition_metadata_limits in prop::option::of(Just(Configuration::DEFAULT_ASSET_DEFINITION_METADATA_LIMITS())),
                account_metadata_limits in prop::option::of(Just(Configuration::DEFAULT_ACCOUNT_METADATA_LIMITS())),
                domain_metadata_limits in prop::option::of(Just(Configuration::DEFAULT_DOMAIN_METADATA_LIMITS())),
                ident_length_limits in prop::option::of(Just(Configuration::DEFAULT_IDENT_LENGTH_LIMITS())),
                transaction_limits in prop::option::of(Just(Configuration::DEFAULT_TRANSACTION_LIMITS())),
                wasm_runtime_config in prop::option::of(Just(Configuration::DEFAULT_WASM_RUNTIME_CONFIG())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { asset_metadata_limits, asset_definition_metadata_limits, account_metadata_limits, domain_metadata_limits, ident_length_limits, transaction_limits, wasm_runtime_config }
        }
    }
}
