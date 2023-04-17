//! Genesis-related logic and constructs. Contains the `GenesisBlock`,
//! `RawGenesisBlock` and the `RawGenesisBlockBuilder` structures.
#![allow(
    clippy::module_name_repetitions,
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::{fmt::Debug, fs::File, io::BufReader, ops::Deref, path::Path};

use derive_more::Deref;
use eyre::{bail, eyre, Result, WrapErr};
use iroha_config::genesis::Configuration;
use iroha_crypto::{KeyPair, PublicKey};
#[cfg(not(test))]
use iroha_data_model::validator::Validator;
use iroha_data_model::{
    asset::AssetDefinition,
    prelude::{Metadata, *},
};
use iroha_primitives::small::{smallvec, SmallVec};
use iroha_schema::IntoSchema;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use MockValidator as Validator;

/// Time to live for genesis transactions.
const GENESIS_TRANSACTIONS_TTL_MS: u64 = 100_000;

/// Genesis network trait for mocking
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
}

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Debug, Clone, Deref)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transaction is accepted
    #[deref]
    pub transactions: Vec<VersionedAcceptedTransaction>,
}

impl GenesisNetworkTrait for GenesisNetwork {
    fn from_configuration(
        submit_genesis: bool,
        raw_block: RawGenesisBlock,
        genesis_config: Option<&Configuration>,
        tx_limits: &TransactionLimits,
    ) -> Result<Option<GenesisNetwork>> {
        if !submit_genesis {
            iroha_logger::trace!("Not submitting genesis");
            return Ok(None);
        }
        iroha_logger::trace!("Submitting genesis.");
        let genesis_config =
            genesis_config.expect("Should be `Some` when `submit_genesis` is true");
        let genesis_key_pair = KeyPair::new(
            genesis_config.account_public_key.clone(),
            genesis_config
                .account_private_key
                .clone()
                .ok_or_else(|| eyre!("Genesis account private key is empty."))?,
        )?;
        let transactions_iter = raw_block.transactions.into_iter();
        #[cfg(not(test))]
        let transactions_iter = transactions_iter.chain(std::iter::once(GenesisTransaction {
            isi: SmallVec(smallvec![UpgradeBox::new(raw_block.validator).into()]),
        }));

        let transactions = transactions_iter
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
        Ok(Some(GenesisNetwork { transactions }))
    }
}

/// Mock of [`Validator`](iroha_data_model::validator::Validator) for unit tests
///
/// Aliased to `Validator` when `cfg(test)`.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, IntoSchema)]
#[repr(transparent)]
pub struct MockValidator;

/// [`RawGenesisBlock`] is an initial block of the network
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
pub struct RawGenesisBlock {
    /// Transactions
    pub transactions: SmallVec<[GenesisTransaction; 2]>,
    /// Runtime Validator
    pub validator: Validator,
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
}

/// `GenesisTransaction` is a transaction for initialize settings.
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[serde(transparent)]
#[repr(transparent)]
pub struct GenesisTransaction {
    /// Instructions
    pub isi: SmallVec<[InstructionBox; 8]>,
}

impl GenesisTransaction {
    /// Convert [`GenesisTransaction`] into [`AcceptedTransaction`] with signature
    ///
    /// # Errors
    /// Fails if signing or accepting fails
    pub fn sign_and_accept(
        self,
        genesis_key_pair: KeyPair,
        limits: &TransactionLimits,
    ) -> Result<VersionedAcceptedTransaction> {
        let transaction =
            TransactionBuilder::new(AccountId::genesis(), self.isi, GENESIS_TRANSACTIONS_TTL_MS)
                .sign(genesis_key_pair)?;

        AcceptedTransaction::accept::<true>(transaction, limits)
            .wrap_err("Failed to accept transaction")
            .map(Into::into)
    }
}

/// Builder type for `RawGenesisBlock` that does
/// not perform any correctness checking on the block
/// produced. Use with caution in tests and other things
/// to register domains and accounts.
#[must_use]
pub struct RawGenesisBlockBuilder<S> {
    transaction: GenesisTransaction,
    state: S,
}

/// `Domain` subsection of the `RawGenesisBlockBuilder`. Makes
/// it easier to create accounts and assets without needing to
/// provide a `DomainId`.
#[must_use]
pub struct RawGenesisDomainBuilder<S> {
    transaction: GenesisTransaction,
    domain_id: DomainId,
    state: S,
}

mod validator_state {
    use super::Validator;

    #[cfg_attr(test, derive(Clone, Copy))]
    pub struct Set(pub Validator);

    #[derive(Clone, Copy)]
    pub struct Unset;
}

impl RawGenesisBlockBuilder<validator_state::Unset> {
    /// Initiate the building process.
    pub fn new() -> Self {
        // Do not add `impl Default`. While it can technically be
        // regarded as a default constructor, this builder should not
        // be used in contexts where `Default::default()` is likely to
        // be called.
        Self {
            transaction: GenesisTransaction {
                isi: SmallVec::new(),
            },
            state: validator_state::Unset,
        }
    }

    /// Set the validator.
    pub fn validator(self, validator: Validator) -> RawGenesisBlockBuilder<validator_state::Set> {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
            state: validator_state::Set(validator),
        }
    }
}

impl<S> RawGenesisBlockBuilder<S> {
    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain(self, domain_name: Name) -> RawGenesisDomainBuilder<S> {
        self.domain_with_metadata(domain_name, Metadata::default())
    }

    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain_with_metadata(
        mut self,
        domain_name: Name,
        metadata: Metadata,
    ) -> RawGenesisDomainBuilder<S> {
        let domain_id = DomainId::new(domain_name);
        let new_domain = Domain::new(domain_id.clone()).with_metadata(metadata);
        self.transaction
            .isi
            .push(RegisterBox::new(new_domain).into());
        RawGenesisDomainBuilder {
            transaction: self.transaction,
            domain_id,
            state: self.state,
        }
    }
}

impl RawGenesisBlockBuilder<validator_state::Set> {
    /// Finish building and produce a `RawGenesisBlock`.
    pub fn build(self) -> RawGenesisBlock {
        RawGenesisBlock {
            transactions: SmallVec(smallvec![self.transaction]),
            validator: self.state.0,
        }
    }
}

impl<S> RawGenesisDomainBuilder<S> {
    /// Finish this domain and return to
    /// genesis block building.
    pub fn finish_domain(self) -> RawGenesisBlockBuilder<S> {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
            state: self.state,
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
            RawGenesisBlockBuilder::new()
                .domain("wonderland".parse()?)
                .account("alice".parse()?, alice_public_key)
                .finish_domain()
                .validator(MockValidator)
                .build(),
            Some(
                &ConfigurationProxy {
                    account_public_key: Some(genesis_public_key),
                    account_private_key: Some(Some(genesis_private_key)),
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
        let public_key = "ed0120204E9593C3FFAF4464A6189233811C297DD4CE73ABA167867E4FBD4F8C450ACB";
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

        // In real cases validator should be constructed from a wasm blob
        let finished_genesis_block = genesis_builder.validator(MockValidator).build();
        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[0],
                RegisterBox::new(Domain::new(domain_id.clone())).into()
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
                RegisterBox::new(Domain::new(domain_id.clone())).into()
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
                RegisterBox::new(Domain::new(domain_id.clone())).into()
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
