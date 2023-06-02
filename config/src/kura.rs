//! Module for kura-related configuration and structs
use core::num::NonZeroU64;

use eyre::Result;
use iroha_config_base::{Configuration, Documented};
use serde::{Deserialize, Serialize};

/// `Kura` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "KURA_")]
pub struct Configuration {
    /// Initialization mode: `strict` or `fast`.
    #[config(default = "Mode::Strict")]
    init_mode: Mode,
    /// Path to the existing block store folder or path to create new folder.
    #[config(default = "\"./storage\".to_owned()")]
    block_store_path: String,
    /// Maximum number of blocks to write into a single storage file.
    // SAFETY: Value is not zero
    #[config(default = "unsafe { NonZeroU64::new_unchecked(1000_u64) }")]
    blocks_per_storage_file: NonZeroU64,
    /// Default buffer capacity of actor's MPSC channel.
    #[deprecated]
    #[config(default = "100")]
    actor_channel_capacity: u32,
    /// Whether or not new blocks be outputted to a file called blocks.json.
    #[config(default = "false")]
    debug_output_new_blocks: bool,
}

/// Kura initialization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Strict validation of all blocks.
    #[default]
    Strict,
    /// Fast initialization with basic checks.
    Fast,
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                init_mode in prop::option::of(Just(Configuration::DEFAULT_INIT_MODE())),
                block_store_path in prop::option::of(Just(Configuration::DEFAULT_BLOCK_STORE_PATH())),
                blocks_per_storage_file in prop::option::of(Just(Configuration::DEFAULT_BLOCKS_PER_STORAGE_FILE())),
                actor_channel_capacity in prop::option::of(Just(Configuration::DEFAULT_ACTOR_CHANNEL_CAPACITY())),
                debug_output_new_blocks in prop::option::of(Just(Configuration::DEFAULT_DEBUG_OUTPUT_NEW_BLOCKS()))
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { init_mode, block_store_path, blocks_per_storage_file, actor_channel_capacity, debug_output_new_blocks }
        }
    }
}
