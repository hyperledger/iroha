//! Module for `SnapshotMaker`-related configuration and structs.

use std::path::PathBuf;

use iroha_config_base::derive::Proxy;
use serde::{Deserialize, Serialize};

const DEFAULT_SNAPSHOT_PATH: &str = "./storage";
// Default frequency of making snapshots is 1 minute, need to be adjusted for larger world state view size
const DEFAULT_SNAPSHOT_CREATE_EVERY_MS: u64 = 1000 * 60;
const DEFAULT_ENABLED: bool = true;

/// Configuration for `SnapshotMaker`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Proxy)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "SNAPSHOT_")]
pub struct Configuration {
    /// The period of time to wait between attempts to create new snapshot.
    pub create_every_ms: u64,
    /// Path to the directory where snapshots should be stored
    pub dir_path: PathBuf,
    /// Flag to enable or disable snapshot creation
    pub creation_enabled: bool,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            create_every_ms: Some(DEFAULT_SNAPSHOT_CREATE_EVERY_MS),
            dir_path: Some(DEFAULT_SNAPSHOT_PATH.into()),
            creation_enabled: Some(DEFAULT_ENABLED),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                create_every_ms in prop::option::of(Just(DEFAULT_SNAPSHOT_CREATE_EVERY_MS)),
                dir_path in prop::option::of(Just(DEFAULT_SNAPSHOT_PATH.into())),
                creation_enabled in prop::option::of(Just(DEFAULT_ENABLED)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { create_every_ms, dir_path, creation_enabled }
        }
    }
}
