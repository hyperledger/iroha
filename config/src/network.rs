//! Module for network-related configuration and structs
use iroha_config_base::{Configuration, Documented};
use serde::{Deserialize, Serialize};

/// Network Configuration parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_NETWORK_")]
pub struct Configuration {
    /// Buffer capacity of actor's MPSC channel
    #[config(default = "100")]
    #[deprecated]
    actor_channel_capacity: u32,
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                actor_channel_capacity in prop::option::of(Just(Configuration::DEFAULT_ACTOR_CHANNEL_CAPACITY())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { actor_channel_capacity }
        }
    }
}
