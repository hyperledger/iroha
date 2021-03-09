//! Module for starting peers and networks. Used only for tests

// Some tests don't use some of the functions
#![allow(dead_code)]

use async_std::task;
use iroha::{
    config::Configuration, permissions::PermissionsValidatorBox, prelude::*,
    sumeragi::config::SumeragiConfiguration, torii::config::ToriiConfiguration,
};
use iroha_data_model::prelude::*;
use iroha_error::{Error, Result};
use iroha_logger::config::{LevelFilter, LoggerConfiguration};
use rand::seq::SliceRandom;
use std::thread;
use tempfile::TempDir;

/// Network of peers
#[derive(Clone, Debug)]
pub struct Network {
    /// Genesis peer which sends genesis block to everyone
    pub genesis: Peer,
    /// peers
    pub peers: Vec<Peer>,
}

/// Peer structure
#[derive(Clone, Debug)]
pub struct Peer {
    /// id of peer
    pub id: PeerId,
    /// api address
    pub api_address: String,
    /// p2p address
    pub p2p_address: String,
    /// Key pair of peer
    pub key_pair: KeyPair,
}

impl std::cmp::PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl std::cmp::Eq for Peer {}

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const GENESIS_PATH: &str = "tests/genesis.json";

impl Network {
    /// Creates new network with some ofline peers
    pub fn new_with_offline_peers(
        default_configuration: Option<Configuration>,
        n_peers: usize,
        offline_peers: usize,
    ) -> Result<Self> {
        let n_peers = n_peers - 1;
        let genesis = Peer::new()?;
        let peers = (0..n_peers)
            .map(|_| Peer::new())
            .collect::<Result<Vec<_>>>()?;

        let mut configuration =
            default_configuration.unwrap_or(Configuration::from_path(CONFIGURATION_PATH)?);
        configuration.sumeragi_configuration.trusted_peers = peers
            .iter()
            .chain(std::iter::once(&genesis))
            .map(|peer| peer.id.clone())
            .collect();

        {
            let mut configuration = configuration.clone();
            configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
            let _ = genesis.start_with_config(configuration);
        }

        let rng = &mut rand::thread_rng();
        let online_peers = n_peers - offline_peers;

        peers
            .choose_multiple(rng, online_peers)
            .zip(std::iter::repeat_with(|| configuration.clone()))
            .for_each(|(peer, configuration)| {
                let _ = peer.start_with_config(configuration);
            });

        Ok(Self { genesis, peers })
    }

    /// Returns ids of all peers
    pub fn ids(&self) -> impl Iterator<Item = PeerId> + '_ {
        std::iter::once(self.genesis.id.clone())
            .chain(self.peers.iter().map(|peer| peer.id.clone()))
    }

    /// Creates new network from configuration and with that number of peers
    pub fn new(default_configuration: Option<Configuration>, n_peers: usize) -> Result<Self> {
        Self::new_with_offline_peers(default_configuration, n_peers, 0)
    }
}

impl Peer {
    /// Returns per peer config with all addresses, keys, and id setted up
    fn get_config(&self, configuration: Configuration) -> Configuration {
        Configuration {
            sumeragi_configuration: SumeragiConfiguration {
                key_pair: self.key_pair.clone(),
                peer_id: self.id.clone(),
                ..configuration.sumeragi_configuration
            },
            torii_configuration: ToriiConfiguration {
                torii_p2p_url: self.p2p_address.clone(),
                torii_api_url: self.api_address.clone(),
                ..configuration.torii_configuration
            },
            logger_configuration: LoggerConfiguration {
                terminal_color_enabled: true,
                date_time_format: format!("{} %Y-%m-%d %H:%M:%S:%f", self.p2p_address),
                #[cfg(profile = "bench")]
                max_log_level: LevelFilter::Off,
                #[cfg(not(profile = "bench"))]
                max_log_level: LevelFilter::Info,
            },
            public_key: self.key_pair.public_key.clone(),
            private_key: self.key_pair.private_key.clone(),
            ..configuration
        }
    }

    /// Starts peer with config, permissions and temp_directory
    pub fn start_with_config_permissions_dir(
        &self,
        configuration: Configuration,
        permissions: impl Into<PermissionsValidatorBox> + Send + 'static,
        temp_dir: &TempDir,
    ) -> task::JoinHandle<()> {
        let mut configuration = self.get_config(configuration);
        configuration
            .kura_configuration
            .kura_block_store_path(temp_dir.path());
        let join_handle = task::spawn(async move {
            let iroha = Iroha::new(configuration, permissions.into());
            iroha.start().await.expect("Failed to start Iroha.");
            //Prevents temp_dir from clean up untill the end of the tests.
            loop {
                task::yield_now().await;
            }
        });

        thread::sleep(std::time::Duration::from_millis(100));
        join_handle
    }

    /// Starts peer with config and permissions
    pub fn start_with_config_permissions(
        &self,
        configuration: Configuration,
        permissions: impl Into<PermissionsValidatorBox> + Send + 'static,
    ) -> task::JoinHandle<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut configuration = self.get_config(configuration);
        let join_handle = task::spawn(async move {
            let temp_dir = temp_dir;
            configuration
                .kura_configuration
                .kura_block_store_path(temp_dir.path());

            let iroha = Iroha::new(configuration, permissions.into());
            iroha.start().await.expect("Failed to start Iroha.");
            //Prevents temp_dir from clean up untill the end of the tests.
            loop {
                task::yield_now().await;
            }
        });

        thread::sleep(std::time::Duration::from_millis(100));
        join_handle
    }

    /// Starts peer with config
    pub fn start_with_config(&self, configuration: Configuration) -> task::JoinHandle<()> {
        self.start_with_config_permissions(configuration, AllowAll)
    }

    /// Starts peer
    pub fn start(&self) -> Result<task::JoinHandle<()>> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)?;
        Ok(self.start_with_config(configuration))
    }

    /// Creates peer
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate()?;
        let p2p_address = format!(
            "127.0.0.1:{}",
            unique_port::get_unique_free_port().map_err(Error::msg)?
        );
        let api_address = format!(
            "127.0.0.1:{}",
            unique_port::get_unique_free_port().map_err(Error::msg)?
        );
        let id = PeerId {
            address: p2p_address.clone(),
            public_key: key_pair.public_key.clone(),
        };
        Ok(Self {
            id,
            key_pair,
            p2p_address,
            api_address,
        })
    }
}
