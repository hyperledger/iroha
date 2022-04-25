//! This module contains execution Genesis Block logic, and `GenesisBlock` definition.
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::new_without_default)]

use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, ops::Deref, path::Path};

use eyre::{eyre, Result, WrapErr};
use iroha_actor::Addr;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{asset::AssetDefinition, prelude::*};
use iroha_schema::prelude::*;
use serde::{Deserialize, Serialize};
use small::SmallVec;
use tokio::{time, time::Duration};

pub use self::config::GenesisConfiguration;
use crate::{
    kura::KuraTrait,
    sumeragi::{
        fault::{FaultInjection, SumeragiWithFault},
        network_topology::{GenesisBuilder as GenesisTopologyBuilder, Topology},
    },
    tx::VersionedAcceptedTransaction,
    wsv::WorldTrait,
    IrohaNetwork,
};

// TODO: 8 is just the optimal value for tests. This number should be
// revised as soon as we have real data, to fix #1855.
type Online = SmallVec<[PeerId; 8]>;
type Offline = SmallVec<[PeerId; 8]>;

/// Time to live for genesis transactions.
const GENESIS_TRANSACTIONS_TTL_MS: u64 = 100_000;

/// Genesis network trait for mocking
#[async_trait::async_trait]
pub trait GenesisNetworkTrait:
    Deref<Target = Vec<VersionedAcceptedTransaction>> + Sync + Send + 'static + Sized + Debug
{
    /// Construct [`GenesisNetwork`] from configuration.
    ///
    /// # Errors
    /// Fails if genesis block is not found or cannot be deserialized.
    fn from_configuration(
        submit_genesis: bool,
        raw_block: RawGenesisBlock,
        genesis_config: &GenesisConfiguration,
        transaction_limits: &TransactionLimits,
    ) -> Result<Option<Self>>;

    /// Waits for a minimum number of [`Peer`]s needed for consensus to be online.
    /// Returns initialized network [`Topology`] with the set A consisting of online peers.
    async fn wait_for_peers(
        &self,
        this_peer_id: PeerId,
        network_topology: Topology,
        network: Addr<IrohaNetwork>,
    ) -> Result<Topology>;

    // FIXME: Having `ctx` reference and `sumaregi` reference here is not ideal.
    // The way it is currently designed, this function is called from sumeragi and then calls sumeragi, while being in an unrelated module.
    // This needs to be restructured.

    /// Submits genesis transactions.
    ///
    /// # Errors
    /// Returns error if waiting for peers or genesis round itself fails
    async fn submit_transactions<K: KuraTrait, W: WorldTrait, F: FaultInjection>(
        &self,
        sumeragi: &mut SumeragiWithFault<Self, K, W, F>,
        network: Addr<IrohaNetwork>,
        ctx: &mut iroha_actor::Context<SumeragiWithFault<Self, K, W, F>>,
    ) -> Result<()> {
        iroha_logger::debug!("Starting submit genesis");
        let genesis_topology = self
            .wait_for_peers(sumeragi.peer_id.clone(), sumeragi.topology.clone(), network)
            .await?;
        time::sleep(Duration::from_millis(self.genesis_submission_delay_ms())).await;
        iroha_logger::info!("Initializing iroha using the genesis block.");
        sumeragi
            .start_genesis_round(self.deref().clone(), genesis_topology, ctx)
            .await
    }

    /// See [`GenesisConfiguration`] docs.
    fn genesis_submission_delay_ms(&self) -> u64;
}

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Clone, Debug)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transaction is accepted
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Number of attempts to connect to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_count: u64,
    /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_period_ms: u64,
    /// Delay before genesis block submission after minimum number of peers were discovered to be online.
    /// Used to ensure that other peers had time to connect to each other.
    pub genesis_submission_delay_ms: u64,
}

impl Deref for GenesisNetwork {
    type Target = Vec<VersionedAcceptedTransaction>;

    fn deref(&self) -> &Self::Target {
        &self.transactions
    }
}

async fn try_get_online_topology(
    this_peer_id: &PeerId,
    network_topology: &Topology,
    network: Addr<IrohaNetwork>,
) -> Result<Topology> {
    let (online_peers, offline_peers) =
        check_peers_status(this_peer_id, network_topology, network).await;
    let set_a_len = network_topology.min_votes_for_commit();
    if online_peers.len() < set_a_len {
        return Err(eyre!("Not enough online peers for consensus."));
    }
    let genesis_topology = if network_topology.sorted_peers().len() == 1 {
        network_topology.clone()
    } else {
        let set_a: HashSet<_> = online_peers[..set_a_len].iter().cloned().collect();
        let set_b: HashSet<_> = online_peers[set_a_len..]
            .iter()
            .cloned()
            .chain(offline_peers.into_iter())
            .collect();
        #[allow(clippy::expect_used)]
        GenesisTopologyBuilder::new()
            .with_leader(this_peer_id.clone())
            .with_set_a(set_a)
            .with_set_b(set_b)
            .build()
            .expect("Preconditions should be already checked.")
    };
    iroha_logger::info!("Waiting for active peers finished.");
    Ok(genesis_topology)
}

/// Checks which [`Peer`]s are online and which are offline
/// Returns `(online, offline)` [`Peer`]s.
async fn check_peers_status(
    this_peer_id: &PeerId,
    network_topology: &Topology,
    network: Addr<IrohaNetwork>,
) -> (Online, Offline) {
    #[allow(clippy::expect_used)]
    let peers = network
        .send(iroha_p2p::network::GetConnectedPeers)
        .await
        .expect("Could not get connected peers from Network!")
        .peers;
    iroha_logger::info!(peer_count = peers.len(), "Peers status");

    let (online, offline): (SmallVec<_>, SmallVec<_>) = network_topology
        .sorted_peers()
        .iter()
        .cloned()
        .partition(|id| peers.contains(&id.public_key) || this_peer_id.public_key == id.public_key);

    (online, offline)
}

#[async_trait::async_trait]
impl GenesisNetworkTrait for GenesisNetwork {
    fn from_configuration(
        submit_genesis: bool,
        raw_block: RawGenesisBlock,
        genesis_config: &GenesisConfiguration,
        tx_limits: &TransactionLimits,
    ) -> Result<Option<GenesisNetwork>> {
        if !submit_genesis {
            iroha_logger::debug!("Not submitting genesis");
            return Ok(None);
        }
        iroha_logger::debug!("Submitting genesis.");
        Ok(Some(GenesisNetwork {
            transactions: raw_block
                .transactions
                .iter()
                .map(|raw_transaction| {
                    let genesis_key_pair = KeyPair::new(
                        genesis_config.account_public_key.clone(),
                        genesis_config
                            .account_private_key
                            .clone()
                            .ok_or_else(|| eyre!("Genesis account private key is empty."))?,
                    );

                    raw_transaction.sign_and_accept(genesis_key_pair, tx_limits)
                })
                .filter_map(Result::ok)
                .collect(),
            wait_for_peers_retry_count: genesis_config.wait_for_peers_retry_count,
            wait_for_peers_retry_period_ms: genesis_config.wait_for_peers_retry_period_ms,
            genesis_submission_delay_ms: genesis_config.genesis_submission_delay_ms,
        }))
    }

    async fn wait_for_peers(
        &self,
        this_peer_id: PeerId,
        network_topology: Topology,
        network: Addr<IrohaNetwork>,
    ) -> Result<Topology> {
        iroha_logger::info!("Waiting for active peers",);
        for i in 0..self.wait_for_peers_retry_count {
            if let Ok(topology) =
                try_get_online_topology(&this_peer_id, &network_topology, network.clone()).await
            {
                iroha_logger::info!("Got topology");
                return Ok(topology);
            }

            let reconnect_in_ms = self.wait_for_peers_retry_period_ms * i;
            iroha_logger::info!("Retrying to connect in {} ms", reconnect_in_ms);
            time::sleep(Duration::from_millis(reconnect_in_ms)).await;
        }
        Err(eyre!("Waiting for peers failed."))
    }

    fn genesis_submission_delay_ms(&self) -> u64 {
        self.genesis_submission_delay_ms
    }
}

/// [`RawGenesisBlock`] is an initial block of the network
#[derive(Clone, Deserialize, Debug, IntoSchema, Default, Serialize)]
pub struct RawGenesisBlock {
    /// Transactions
    pub transactions: SmallVec<[GenesisTransaction; 2]>,
}

impl RawGenesisBlock {
    /// Construct a genesis block from a `.json` file at the specified
    /// path-like object.
    ///
    /// # Errors
    /// If file not found or deserialization from file fails.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Self> {
        let file = File::open(&path).wrap_err(format!("Failed to open {:?}", &path))?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err(format!(
            "Failed to deserialize raw genesis block from {:?}",
            &path
        ))
    }

    /// Create a [`RawGenesisBlock`] with specified [`Domain`] and [`Account`].
    pub fn new(account_name: Name, domain_id: DomainId, public_key: PublicKey) -> Self {
        RawGenesisBlock {
            transactions: SmallVec(smallvec::smallvec![GenesisTransaction::new(
                account_name,
                domain_id,
                public_key,
            )]),
        }
    }
}

/// `GenesisTransaction` is a transaction for initialize settings.
#[derive(Clone, Deserialize, Debug, IntoSchema, Serialize)]
pub struct GenesisTransaction {
    /// Instructions
    pub isi: SmallVec<[Instruction; 8]>,
}

impl GenesisTransaction {
    /// Convert `GenesisTransaction` into `AcceptedTransaction` with signature
    ///
    /// # Errors
    /// Fails if signing fails
    pub fn sign_and_accept(
        &self,
        genesis_key_pair: KeyPair,
        limits: &TransactionLimits,
    ) -> Result<VersionedAcceptedTransaction> {
        let transaction = Transaction::new(
            AccountId::genesis(),
            self.isi.clone().into(),
            GENESIS_TRANSACTIONS_TTL_MS,
        )
        .sign(genesis_key_pair)?;
        VersionedAcceptedTransaction::from_transaction(transaction, limits)
    }

    /// Create a [`GenesisTransaction`] with the specified [`Domain`] and [`Account`].
    pub fn new(account_name: Name, domain_id: DomainId, public_key: PublicKey) -> Self {
        Self {
            isi: SmallVec(smallvec::smallvec![
                RegisterBox::new(Domain::new(domain_id.clone())).into(),
                RegisterBox::new(Account::new(
                    AccountId::new(account_name, domain_id),
                    [public_key],
                ))
                .into()
            ]),
        }
    }
}

/// Module with genesis configuration logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
    use serde::{Deserialize, Serialize};

    const DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT: u64 = 100;
    const DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS: u64 = 500;
    const DEFAULT_GENESIS_SUBMISSION_DELAY_MS: u64 = 1000;

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configurable)]
    #[serde(default)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_GENESIS_")]
    /// Configuration of the genesis block and the process of its submission.
    pub struct GenesisConfiguration {
        /// The genesis account public key, should be supplied to all peers.
        #[config(serde_as_str)]
        pub account_public_key: PublicKey,
        /// Genesis account private key, only needed on the peer that submits the genesis block.
        pub account_private_key: Option<PrivateKey>,
        /// Number of attempts to connect to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_count")]
        pub wait_for_peers_retry_count: u64,
        /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
        #[serde(default = "default_wait_for_peers_retry_period_ms")]
        pub wait_for_peers_retry_period_ms: u64,
        /// Delay before genesis block submission after minimum number of peers were discovered to be online.
        /// Used to ensure that other peers had time to connect to each other.
        #[serde(default = "default_genesis_submission_delay_ms")]
        pub genesis_submission_delay_ms: u64,
    }

    #[allow(clippy::expect_used)]
    impl Default for GenesisConfiguration {
        fn default() -> Self {
            let (public_key, private_key) = Self::placeholder_keypair().into();

            Self {
                account_public_key: public_key,
                account_private_key: Some(private_key),
                wait_for_peers_retry_count: DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT,
                wait_for_peers_retry_period_ms: DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS,
                genesis_submission_delay_ms: DEFAULT_GENESIS_SUBMISSION_DELAY_MS,
            }
        }
    }

    impl GenesisConfiguration {
        /// Key-pair used by default for demo purposes
        #[allow(clippy::expect_used)]
        fn placeholder_keypair() -> KeyPair {
            let public_key =
                "ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
                    .parse()
                    .expect("Public key not in mulithash format");
            let private_key = PrivateKey::from_hex(
                iroha_crypto::Algorithm::Ed25519,
                "d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf"
            ).expect("Private key not hex encoded");

            KeyPair::new(public_key, private_key)
        }
    }

    const fn default_wait_for_peers_retry_count() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_COUNT
    }

    const fn default_wait_for_peers_retry_period_ms() -> u64 {
        DEFAULT_WAIT_FOR_PEERS_RETRY_PERIOD_MS
    }

    const fn default_genesis_submission_delay_ms() -> u64 {
        DEFAULT_GENESIS_SUBMISSION_DELAY_MS
    }
}

/// Builder type for `RawGenesisBlock` that does
/// not perform any correctness checking on the block
/// produced. Use with caution in tests and other things
/// to register domains and accounts.
pub struct RawGenesisBlockBuilder {
    transaction: GenesisTransaction,
}

/// `Domain` subsection of the `RawGenesisBlockBuilder`. Makes
/// it easier to create accounts and assets without needing to
/// provide a `DomainId`.
pub struct RawGenesisDomainBuilder {
    transaction: GenesisTransaction,
    domain_id: DomainId,
}

impl RawGenesisBlockBuilder {
    /// Create a `RawGenesisBlockBuilder`.
    pub fn new() -> Self {
        RawGenesisBlockBuilder {
            transaction: GenesisTransaction {
                isi: iroha_data_model::small::SmallVec::new(),
            },
        }
    }
    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain(mut self, domain_name: Name) -> RawGenesisDomainBuilder {
        let domain_id = DomainId::new(domain_name);
        self.transaction
            .isi
            .push(RegisterBox::new(domain_id.clone()).into());
        RawGenesisDomainBuilder {
            transaction: self.transaction,
            domain_id,
        }
    }
    /// Finish building and produce a `RawGenesisBlock`.
    pub fn build(self) -> RawGenesisBlock {
        RawGenesisBlock {
            transactions: SmallVec(smallvec::smallvec![self.transaction]),
        }
    }
}

impl RawGenesisDomainBuilder {
    /// Finish this domain and return to
    /// genesis block building.
    pub fn finish_domain(self) -> RawGenesisBlockBuilder {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
        }
    }

    /// Add an account to this domain without a public key.
    /// Should only be used for testing.
    #[must_use]
    pub fn with_account_without_public_key(mut self, account_name: Name) -> Self {
        self.transaction
            .isi
            .push(RegisterBox::new(AccountId::new(account_name, self.domain_id.clone())).into());
        self
    }

    /// Add an account to this domain
    #[must_use]
    pub fn with_account(mut self, account_name: Name, public_key: PublicKey) -> Self {
        self.transaction.isi.push(
            RegisterBox::new(Account::new(
                AccountId::new(account_name, self.domain_id.clone()),
                [public_key],
            ))
            .into(),
        );
        self
    }

    /// Add [`AssetDefinition`] to current domain.
    #[must_use]
    pub fn with_asset(mut self, definition: AssetDefinition) -> Self {
        self.transaction
            .isi
            .push(RegisterBox::new(definition).into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_default_genesis_block() -> Result<()> {
        let (public_key, private_key) = KeyPair::generate()?.into();
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        let _genesis_block = GenesisNetwork::from_configuration(
            true,
            RawGenesisBlock::default(),
            &GenesisConfiguration {
                account_public_key: public_key,
                account_private_key: Some(private_key),
                ..GenesisConfiguration::default()
            },
            &tx_limits,
        )?;
        Ok(())
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn genesis_block_builder_example() {
        let public_key = "ed0120204e9593c3ffaf4464a6189233811c297dd4ce73aba167867e4fbd4f8c450acb";
        let mut genesis_builder = RawGenesisBlockBuilder::new();

        genesis_builder = genesis_builder
            .domain("wonderland".parse().unwrap())
            .with_account_without_public_key("alice".parse().unwrap())
            .with_account_without_public_key("bob".parse().unwrap())
            .finish_domain()
            .domain("tulgey_wood".parse().unwrap())
            .with_account_without_public_key("Cheshire_Cat".parse().unwrap())
            .finish_domain()
            .domain("meadow".parse().unwrap())
            .with_account("Mad_Hatter".parse().unwrap(), public_key.parse().unwrap())
            .with_asset(AssetDefinition::big_quantity("hats#meadow".parse().unwrap()).build())
            .finish_domain();

        let finished_genesis_block = genesis_builder.build();
        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[0],
                RegisterBox::new(domain_id.clone()).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[1],
                RegisterBox::new(AccountId::new("alice".parse().unwrap(), domain_id.clone()))
                    .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[2],
                RegisterBox::new(AccountId::new("bob".parse().unwrap(), domain_id)).into()
            );
        }
        {
            let domain_id: DomainId = "tulgey_wood".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[3],
                RegisterBox::new(domain_id.clone()).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[4],
                RegisterBox::new(AccountId::new("Cheshire_Cat".parse().unwrap(), domain_id)).into()
            );
        }
        {
            let domain_id: DomainId = "meadow".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[5],
                RegisterBox::new(domain_id.clone()).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[6],
                RegisterBox::new(Account::new(
                    AccountId::new("Mad_Hatter".parse().unwrap(), domain_id),
                    [public_key.parse().unwrap()],
                ))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[7],
                RegisterBox::new(
                    AssetDefinition::big_quantity("hats#meadow".parse().unwrap()).build()
                )
                .into()
            );
        }
    }
}
