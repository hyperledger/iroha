//! Module for kura-related configuration and structs
use std::path::PathBuf;

use eyre::Result;
use iroha_config_base::derive::{Documented, Proxy};
use serde::{Deserialize, Serialize};

const DEFAULT_BLOCK_STORE_PATH: &str = "./storage";

/// `Kura` configuration.
#[derive(Clone, Deserialize, Serialize, Debug, Documented, Proxy, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "KURA_")]
pub struct Configuration {
    /// Initialization mode: `strict` or `fast`.
    pub init_mode: Mode,
    /// Path to the existing block store folder or path to create new folder.
    pub block_store_path: PathBuf,
    /// Whether or not new blocks be outputted to a file called blocks.json.
    pub debug_output_new_blocks: bool,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            init_mode: Some(Mode::default()),
            block_store_path: Some(DEFAULT_BLOCK_STORE_PATH.into()),
            debug_output_new_blocks: Some(false),
        }
    }
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
                init_mode in prop::option::of(Just(Mode::default())),
                block_store_path in prop::option::of(Just(DEFAULT_BLOCK_STORE_PATH.into())),
                debug_output_new_blocks in prop::option::of(Just(false))
            )
            -> ConfigurationProxy {
            ConfigurationProxy { init_mode, block_store_path, debug_output_new_blocks }
        }
    }
}
