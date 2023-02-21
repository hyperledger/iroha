//! Genesis-related logic and constructs. Contains the `GenesisBlock`,
//! `RawGenesisBlock` and the `RawGenesisBlockBuilder` structures.
#![allow(
    clippy::module_name_repetitions,
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, ops::Deref, path::Path};

use derive_more::Deref;
use eyre::{bail, eyre, Result, WrapErr};
use iroha_actor::Addr;
use iroha_config::genesis::Configuration;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    asset::AssetDefinition,
    prelude::{Metadata, *},
};
use iroha_primitives::small::{smallvec, SmallVec};
use iroha_schema::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::{time, time::Duration};

use crate::{
    sumeragi::network_topology::{GenesisBuilder as GenesisTopologyBuilder, Topology},
    tx::VersionedAcceptedTransaction,
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
        genesis_config: Option<&Configuration>,
        transaction_limits: &TransactionLimits,
    ) -> Result<Option<Self>>;

    /// Waits for a minimum number of [`Peer`]s needed for consensus
    /// to be online.  Returns initialized network [`Topology`] with
    /// the set A consisting of online peers.
    async fn wait_for_peers(
        &self,
        this_peer_id: PeerId,
        network_topology: Topology,
        network: Addr<IrohaNetwork>,
    ) -> Result<Topology>;

    /// See [`Configuration`] docs.
    fn genesis_submission_delay_ms(&self) -> u64;
}

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Clone, Debug, Deref)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transaction is accepted
    #[deref]
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Number of attempts to connect to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_count_limit: u64,
    /// Period in milliseconds in which to retry connecting to peers, while waiting for them to submit genesis.
    pub wait_for_peers_retry_period_ms: u64,
    /// Delay before genesis block submission after minimum number of peers were discovered to be online.
    /// Used to ensure that other peers had time to connect to each other.
    pub genesis_submission_delay_ms: u64,
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
        genesis_config: Option<&Configuration>,
        tx_limits: &TransactionLimits,
    ) -> Result<Option<GenesisNetwork>> {
        if !submit_genesis {
            iroha_logger::debug!("Not submitting genesis");
            return Ok(None);
        }
        iroha_logger::debug!("Submitting genesis.");
        let genesis_config =
            genesis_config.expect("Should be `Some` when `submit_genesis` is true");
        let genesis_key_pair = KeyPair::new(
            genesis_config.account_public_key.clone(),
            genesis_config
                .account_private_key
                .clone()
                .ok_or_else(|| eyre!("Genesis account private key is empty."))?,
        )?;
        let transactions = raw_block
            .transactions
            .iter()
            .map(|raw_transaction| {
                raw_transaction.sign_and_accept(genesis_key_pair.clone(), tx_limits)
            })
            .enumerate()
            .filter_map(|(i, res)| {
                res.map_err(|error| {
                    let error_msg = format!("{error:#}");
                    iroha_logger::error!(error = %error_msg, transaction_num=i, "Genesis transaction failed")
                })
                .ok()
            })
            .collect::<Vec<_>>();
        if transactions.is_empty() {
            bail!("Genesis transaction set contains no valid transactions");
        }
        Ok(Some(GenesisNetwork {
            transactions,
            wait_for_peers_retry_count_limit: genesis_config.wait_for_peers_retry_count_limit,
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
        for i in 0..self.wait_for_peers_retry_count_limit {
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
    const WARN_ON_GENESIS_GTE: u64 = 1024 * 1024 * 1024; // 1Gb

    /// Construct a genesis block from a `.json` file at the specified
    /// path-like object.
    ///
    /// # Errors
    /// If file not found or deserialization from file fails.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Self> {
        let file = File::open(&path).wrap_err(format!("Failed to open {:?}", &path))?;
        let size = file
            .metadata()
            .wrap_err("Unable to access genesis file metadata")?
            .len();
        if size >= Self::WARN_ON_GENESIS_GTE {
            iroha_logger::warn!(%size, threshold = %Self::WARN_ON_GENESIS_GTE, "Genesis is quite large, it will take some time to apply it");
        }
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err(format!(
            "Failed to deserialize raw genesis block from {:?}",
            &path
        ))
    }

    /// Create a [`RawGenesisBlock`] with specified [`Domain`] and [`Account`].
    pub fn new(account_name: Name, domain_id: DomainId, public_key: PublicKey) -> Self {
        RawGenesisBlock {
            transactions: SmallVec(smallvec![GenesisTransaction::new(
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
    /// Convert [`GenesisTransaction`] into [`AcceptedTransaction`] with signature
    ///
    /// # Errors
    /// Fails if signing or accepting fails
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

        VersionedAcceptedTransaction::from_transaction::<true>(transaction, limits)
    }

    /// Create a [`GenesisTransaction`] with the specified [`Domain`] and [`Account`].
    pub fn new(account_name: Name, domain_id: DomainId, public_key: PublicKey) -> Self {
        Self {
            isi: SmallVec(smallvec![
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
#[must_use]
pub struct RawGenesisDomainBuilder {
    transaction: GenesisTransaction,
    domain_id: DomainId,
}

impl RawGenesisBlockBuilder {
    /// Initiate the building process.
    pub fn new() -> Self {
        // Do not add `impl Default`. While it can technically be
        // regarded as a default constructor, this builder should not
        // be used in contexts where `Default::default()` is likely to
        // be called.
        RawGenesisBlockBuilder {
            transaction: GenesisTransaction {
                isi: SmallVec::new(),
            },
        }
    }

    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain(self, domain_name: Name) -> RawGenesisDomainBuilder {
        self.domain_with_metadata(domain_name, Metadata::default())
    }

    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain_with_metadata(
        mut self,
        domain_name: Name,
        metadata: Metadata,
    ) -> RawGenesisDomainBuilder {
        let domain_id = DomainId::new(domain_name);
        let new_domain = Domain::new(domain_id.clone()).with_metadata(metadata);
        self.transaction
            .isi
            .push(Instruction::from(RegisterBox::new(new_domain)));
        RawGenesisDomainBuilder {
            transaction: self.transaction,
            domain_id,
        }
    }

    /// Finish building and produce a `RawGenesisBlock`.
    pub fn build(self) -> RawGenesisBlock {
        RawGenesisBlock {
            transactions: SmallVec(smallvec![self.transaction]),
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
    #[cfg(test)]
    pub fn account_without_public_key(mut self, account_name: Name) -> Self {
        let account_id = AccountId::new(account_name, self.domain_id.clone());
        self.transaction
            .isi
            .push(RegisterBox::new(Account::new(account_id, [])).into());
        self
    }

    /// Add an account to this domain
    pub fn account(self, account_name: Name, public_key: PublicKey) -> Self {
        self.account_with_metadata(account_name, public_key, Metadata::default())
    }

    /// Add an account (having provided `metadata`) to this domain.
    pub fn account_with_metadata(
        mut self,
        account_name: Name,
        public_key: PublicKey,
        metadata: Metadata,
    ) -> Self {
        let account_id = AccountId::new(account_name, self.domain_id.clone());
        let register =
            RegisterBox::new(Account::new(account_id, [public_key]).with_metadata(metadata));
        self.transaction.isi.push(register.into());
        self
    }

    /// Add [`AssetDefinition`] to current domain.
    pub fn asset(mut self, asset_name: Name, asset_value_type: AssetValueType) -> Self {
        let asset_definition_id = AssetDefinitionId::new(asset_name, self.domain_id.clone());
        let asset_definition = match asset_value_type {
            AssetValueType::Quantity => AssetDefinition::quantity(asset_definition_id),
            AssetValueType::BigQuantity => AssetDefinition::big_quantity(asset_definition_id),
            AssetValueType::Fixed => AssetDefinition::fixed(asset_definition_id),
            AssetValueType::Store => AssetDefinition::store(asset_definition_id),
        };
        self.transaction
            .isi
            .push(RegisterBox::new(asset_definition).into());
        self
    }
}

#[cfg(test)]
mod tests {
    use iroha_config::{base::proxy::Builder, genesis::ConfigurationProxy};

    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn load_new_genesis_block() -> Result<()> {
        let (genesis_public_key, genesis_private_key) = KeyPair::generate()?.into();
        let (alice_public_key, _) = KeyPair::generate()?.into();
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        let _genesis_block = GenesisNetwork::from_configuration(
            true,
            RawGenesisBlock::new("alice".parse()?, "wonderland".parse()?, alice_public_key),
            Some(
                &ConfigurationProxy {
                    account_public_key: Some(genesis_public_key),
                    account_private_key: Some(Some(genesis_private_key)),
                    ..ConfigurationProxy::default()
                }
                .build()
                .expect("Default genesis config should build when provided the `public key`"),
            ),
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
            .account_without_public_key("alice".parse().unwrap())
            .account_without_public_key("bob".parse().unwrap())
            .finish_domain()
            .domain("tulgey_wood".parse().unwrap())
            .account_without_public_key("Cheshire_Cat".parse().unwrap())
            .finish_domain()
            .domain("meadow".parse().unwrap())
            .account("Mad_Hatter".parse().unwrap(), public_key.parse().unwrap())
            .asset("hats".parse().unwrap(), AssetValueType::BigQuantity)
            .finish_domain();

        let finished_genesis_block = genesis_builder.build();
        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[0],
                Instruction::from(RegisterBox::new(Domain::new(domain_id.clone())))
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[1],
                RegisterBox::new(Account::new(
                    AccountId::new("alice".parse().unwrap(), domain_id.clone()),
                    []
                ))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[2],
                RegisterBox::new(Account::new(
                    AccountId::new("bob".parse().unwrap(), domain_id),
                    []
                ))
                .into()
            );
        }
        {
            let domain_id: DomainId = "tulgey_wood".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[3],
                Instruction::from(RegisterBox::new(Domain::new(domain_id.clone())))
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[4],
                RegisterBox::new(Account::new(
                    AccountId::new("Cheshire_Cat".parse().unwrap(), domain_id),
                    []
                ))
                .into()
            );
        }
        {
            let domain_id: DomainId = "meadow".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[5],
                Instruction::from(RegisterBox::new(Domain::new(domain_id.clone())))
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
                RegisterBox::new(AssetDefinition::big_quantity(
                    "hats#meadow".parse().unwrap()
                ))
                .into()
            );
        }
    }
}