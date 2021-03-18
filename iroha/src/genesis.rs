//! This module contains execution Genesis Block logic, and `GenesisBlock` definition.
use self::config::GenesisConfiguration;
use crate::{
    sumeragi::{InitializedNetworkTopology, Sumeragi},
    torii::uri,
    tx::VersionedAcceptedTransaction,
    Identifiable,
};
use async_std::{
    sync::{Arc, RwLock},
    task,
};
use futures::future;
use iroha_crypto::KeyPair;
use iroha_data_model::{account::Account, isi::Instruction, prelude::*};
use iroha_error::{error, Result, WrapErr};
use iroha_network::{Network, Request, Response};
use serde::Deserialize;
use std::{fmt::Debug, fs::File, io::BufReader, path::Path, time::Duration};

/// Time to live for genesis transactions.
const GENESIS_TRANSACTIONS_TTL_MS: u64 = 100_000;

/// `GenesisNetwork` contains initial transactions and genesis setup related parameters.
#[derive(Clone, Debug)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transaction is accepted
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Number of attempts to connect to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_count: u64,
    /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_period_ms: u64,
}

#[derive(Clone, Deserialize, Debug)]
struct RawGenesisBlock {
    pub transactions: Vec<GenesisTransaction>,
}

/// `GenesisTransaction` is a transaction for inisialize settings.
#[derive(Clone, Deserialize, Debug)]
struct GenesisTransaction {
    isi: Vec<Instruction>,
}

impl GenesisTransaction {
    /// Convert `GenesisTransaction` into `AcceptedTransaction` with signature
    pub fn sign_and_accept(
        &self,
        genesis_key_pair: &KeyPair,
        max_instruction_number: usize,
    ) -> Result<VersionedAcceptedTransaction> {
        let transaction = Transaction::new(
            self.isi.clone(),
            <Account as Identifiable>::Id::genesis_account(),
            GENESIS_TRANSACTIONS_TTL_MS,
        )
        .sign(genesis_key_pair)?;
        VersionedAcceptedTransaction::from_transaction(transaction, max_instruction_number)
    }
}

impl GenesisNetwork {
    /// Construct `GenesisNetwork` from configuration.
    ///
    /// # Errors
    /// Fail if genesis block loading fails
    pub fn from_configuration(
        genesis_config: &GenesisConfiguration,
        max_instructions_number: usize,
    ) -> Result<Option<GenesisNetwork>> {
        if let Some(genesis_block_path) = &genesis_config.genesis_block_path {
            let file = File::open(Path::new(genesis_block_path))
                .wrap_err("Failed to open a genesis block file")?;
            let reader = BufReader::new(file);
            let raw_block: RawGenesisBlock = serde_json::from_reader(reader)
                .wrap_err("Failed to deserialize json from reader")?;
            let genesis_key_pair = KeyPair {
                public_key: genesis_config.genesis_account_public_key.clone(),
                private_key: genesis_config
                    .genesis_account_private_key
                    .clone()
                    .ok_or_else(|| error!("genesis account private key is empty"))?,
            };
            Ok(Some(GenesisNetwork {
                transactions: raw_block
                    .transactions
                    .iter()
                    .map(|raw_transaction| {
                        raw_transaction.sign_and_accept(&genesis_key_pair, max_instructions_number)
                    })
                    .filter_map(Result::ok)
                    .collect(),
                wait_for_peers_retry_count: genesis_config.wait_for_peers_retry_count,
                wait_for_peers_retry_period_ms: genesis_config.wait_for_peers_retry_period_ms,
            }))
        } else {
            Ok(None)
        }
    }

    /// Submits genesis transactions.
    ///
    /// # Errors
    /// Returns error if waiting for peers or genesis round itself fails
    pub async fn submit_transactions(&self, sumeragi: Arc<RwLock<Sumeragi>>) -> Result<()> {
        let genesis_topology = {
            let sumeragi = sumeragi.read().await;
            self.wait_for_peers(sumeragi.peer_id.clone(), sumeragi.network_topology.clone())
                .await?
        };
        log::info!("Initializing iroha using the genesis block.");
        sumeragi
            .write()
            .await
            .start_genesis_round(self.transactions.clone(), genesis_topology)
            .await
    }

    /// Waits for a minimum number of `peers` needed for consensus to be online.
    /// Returns [`InitializedNetworkTopology`] with the set A consisting of online peers.
    async fn wait_for_peers(
        &self,
        this_peer_id: PeerId,
        network_topology: InitializedNetworkTopology,
    ) -> Result<InitializedNetworkTopology> {
        log::info!("Waiting for active peers.",);
        for i in 0..self.wait_for_peers_retry_count {
            let (online_peers, offline_peers): (Vec<_>, Vec<_>) =
                future::join_all(network_topology.sorted_peers().iter().cloned().map(
                    |peer| async {
                        let reached = if peer == this_peer_id.clone() {
                            true
                        } else {
                            match Network::send_request_to(
                                &peer.address,
                                Request::new(uri::HEALTH_URI.to_string(), Vec::new()),
                            )
                            .await
                            {
                                Ok(Response::Ok(_)) => true,
                                Ok(Response::InternalError) => {
                                    log::info!(
                                        "Failed to send message - Internal Error on peer: {}.",
                                        &peer.address.as_str()
                                    );
                                    false
                                }
                                Err(_) => {
                                    log::info!(
                                        "Failed to send message - Peer offline: {}.",
                                        &peer.address.as_str(),
                                    );
                                    false
                                }
                            }
                        };
                        (peer, reached)
                    },
                ))
                .await
                .into_iter()
                .partition(|(_, reached)| *reached);
            let set_a_len = network_topology.min_votes_for_commit() as usize;
            if online_peers.len() >= set_a_len {
                let genesis_topology = if network_topology.sorted_peers().len() == 1 {
                    network_topology
                } else {
                    let online_peers: Vec<_> = online_peers
                        .into_iter()
                        .filter(|(peer, _)| peer != &this_peer_id)
                        .collect();
                    let mut set_a = online_peers[..(set_a_len - 1)].to_vec();
                    let set_b: Vec<_> = online_peers[(set_a_len - 1)..]
                        .iter()
                        .cloned()
                        .chain(offline_peers.into_iter())
                        .collect();
                    let leader = this_peer_id.clone();
                    let (proxy_tail, _) = set_a.pop().expect("Failed to get last peer.");
                    let validating_peers: Vec<_> =
                        set_a.into_iter().map(|(peer, _)| peer).collect();
                    let observing_peers: Vec<_> = set_b.into_iter().map(|(peer, _)| peer).collect();
                    InitializedNetworkTopology::from_roles(
                        leader,
                        validating_peers,
                        proxy_tail,
                        observing_peers,
                        network_topology.max_faults(),
                    )?
                };
                log::info!("Waiting for active peers finished.");
                return Ok(genesis_topology);
            }

            let reconnect_in_ms = self.wait_for_peers_retry_period_ms * i;
            log::info!("Retrying to connect in {} ms.", reconnect_in_ms);
            task::sleep(Duration::from_millis(reconnect_in_ms)).await;
        }
        Err(error!("Waiting for peers failed."))
    }
}

/// This module contains all genesis configuration related logic.
pub mod config {
    use iroha_crypto::{PrivateKey, PublicKey};
    use iroha_error::{Result, WrapErr};
    use serde::Deserialize;
    use std::env;

    const GENESIS_ACCOUNT_PUBLIC_KEY: &str = "IROHA_GENESIS_ACCOUNT_PUBLIC_KEY";
    const GENESIS_ACCOUNT_PRIVATE_KEY: &str = "IROHA_GENESIS_ACCOUNT_PRIVATE_KEY";
    const DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT: u64 = 100;
    const DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS: u64 = 500;

    #[derive(Clone, Deserialize, Debug, Default)]
    #[serde(rename_all = "UPPERCASE")]
    /// Configuration of the genesis block and its submission process.
    pub struct GenesisConfiguration {
        /// Genesis account public key, should be supplied to all the peers.
        pub genesis_account_public_key: PublicKey,
        /// Genesis account private key, only needed on the peer that submits the genesis block.
        #[serde(default)]
        pub genesis_account_private_key: Option<PrivateKey>,
        /// Genesis block path. Can be `None` if this peer does not submit the genesis block.
        #[serde(default)]
        pub genesis_block_path: Option<String>,
        /// Number of attempts to connect to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_count")]
        pub wait_for_peers_retry_count: u64,
        /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_period_ms")]
        pub wait_for_peers_retry_period_ms: u64,
    }

    impl GenesisConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        ///
        /// # Errors
        /// Can fail during decoding genesis keypair from env
        pub fn load_environment(&mut self) -> Result<()> {
            if let Ok(genesis_account_public_key) = env::var(GENESIS_ACCOUNT_PUBLIC_KEY) {
                self.genesis_account_public_key =
                    serde_json::from_value(serde_json::json!(genesis_account_public_key))
                        .wrap_err("Failed to parse Public Key of genesis account")?;
            }
            if let Ok(genesis_account_private_key) = env::var(GENESIS_ACCOUNT_PRIVATE_KEY) {
                self.genesis_account_private_key =
                    serde_json::from_str(&genesis_account_private_key)
                        .wrap_err("Failed to parse Private Key of genesis account")?;
            }
            Ok(())
        }
    }

    const fn default_wait_for_peers_retry_count() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT
    }

    const fn default_wait_for_peers_retry_period_ms() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_BLOCK_PATH: &str = "tests/genesis.json";

    #[test]
    fn load_genesis_block() -> Result<()> {
        let genesis_key_pair = KeyPair::generate()?;
        let _genesis_block = GenesisNetwork::from_configuration(
            &GenesisConfiguration {
                genesis_account_public_key: genesis_key_pair.public_key,
                genesis_account_private_key: Some(genesis_key_pair.private_key),
                genesis_block_path: Some(GENESIS_BLOCK_PATH.to_string()),
                ..GenesisConfiguration::default()
            },
            4096,
        )?;
        Ok(())
    }
}
