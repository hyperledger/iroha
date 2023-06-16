//! Genesis-related logic and constructs. Contains the `GenesisBlock`,
//! `RawGenesisBlock` and the `RawGenesisBlockBuilder` structures.
#![allow(
    clippy::module_name_repetitions,
    clippy::new_without_default,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::{
    fmt::Debug,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use derive_more::From;
use eyre::{bail, eyre, ErrReport, Result, WrapErr};
use iroha_config::genesis::Configuration;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    asset::AssetDefinition,
    prelude::{Metadata, *},
    validator::Validator,
};
use iroha_schema::IntoSchema;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// [`DomainId`] of the genesis account.
pub static GENESIS_DOMAIN_ID: Lazy<DomainId> = Lazy::new(|| "genesis".parse().expect("Valid"));

/// [`AccountId`] of the genesis account.
pub static GENESIS_ACCOUNT_ID: Lazy<AccountId> =
    Lazy::new(|| AccountId::new("genesis".parse().expect("Valid"), GENESIS_DOMAIN_ID.clone()));

/// Genesis transaction
#[derive(Debug, Clone)]
pub struct GenesisTransaction(pub VersionedSignedTransaction);

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Debug, Clone)]
pub struct GenesisNetwork {
    /// transactions from `GenesisBlock`, any transacton is accepted
    pub transactions: Vec<GenesisTransaction>,
}

impl GenesisNetwork {
    /// Construct [`GenesisNetwork`] from configuration.
    ///
    /// # Errors
    /// Fails if genesis block is not found or cannot be deserialized.
    pub fn from_configuration(
        raw_block: RawGenesisBlock,
        genesis_config: Option<&Configuration>,
    ) -> Result<GenesisNetwork> {
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
        #[cfg(not(test))]
        let transactions_iter = std::iter::once(GenesisTransactionBuilder {
            isi: vec![UpgradeBox::new(Validator::try_from(raw_block.validator)?).into()],
        })
        .chain(raw_block.transactions.into_iter());

        #[cfg(test)]
        let transactions_iter = raw_block.transactions.into_iter();

        let transactions = transactions_iter
            .map(|raw_transaction| {
                raw_transaction.sign(genesis_key_pair.clone())
            })
            .enumerate()
            .filter_map(|(i, res)| {
                res.map_err(|error| {
                    let error_msg = format!("{error:#}");
                    iroha_logger::error!(error = %error_msg, transaction_num=i, "Genesis transaction failed")
                })
                .ok()
            }).map(GenesisTransaction)
            .collect::<Vec<_>>();
        if transactions.is_empty() {
            bail!("Genesis transaction set contains no valid transactions");
        }
        Ok(GenesisNetwork { transactions })
    }
}

/// [`RawGenesisBlock`] is an initial block of the network
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
pub struct RawGenesisBlock {
    /// Transactions
    pub transactions: Vec<GenesisTransactionBuilder>,
    /// Runtime Validator
    pub validator: ValidatorMode,
}

/// Ways to provide validator either directly as base64 encoded string or as path to wasm file
#[derive(Debug, Clone, From, Deserialize, Serialize, IntoSchema)]
#[serde(untagged)]
pub enum ValidatorMode {
    /// Path to validator wasm file
    // In the first place to initially try to parse path
    Path(ValidatorPath),
    /// Validator encoded as base64 string
    Inline(Validator),
}

impl ValidatorMode {
    fn set_genesis_path(&mut self, genesis_path: impl AsRef<Path>) {
        if let Self::Path(path) = self {
            path.set_genesis_path(genesis_path);
        }
    }
}

impl TryFrom<ValidatorMode> for Validator {
    type Error = ErrReport;

    fn try_from(value: ValidatorMode) -> Result<Self> {
        match value {
            ValidatorMode::Inline(validator) => Ok(validator),
            ValidatorMode::Path(ValidatorPath(relative_validator_path)) => {
                let wasm = fs::read(&relative_validator_path)
                    .wrap_err(format!("Failed to open {:?}", &relative_validator_path))?;
                Ok(Validator::new(WasmSmartContract::from_compiled(wasm)))
            }
        }
    }
}

/// Path to the validator relative to genesis location
///
/// If path is absolute it will be used directly otherwise it will be treated as relative to genesis location.
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[schema(transparent = "String")]
#[serde(transparent)]
#[repr(transparent)]
pub struct ValidatorPath(pub PathBuf);

impl ValidatorPath {
    fn set_genesis_path(&mut self, genesis_path: impl AsRef<Path>) {
        let path_to_validator = genesis_path
            .as_ref()
            .parent()
            .expect("Genesis must be in some directory")
            .join(&self.0);
        self.0 = path_to_validator;
    }
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
        let mut raw_genesis_block: Self = serde_json::from_reader(reader).wrap_err(format!(
            "Failed to deserialize raw genesis block from {:?}",
            &path
        ))?;
        raw_genesis_block.validator.set_genesis_path(path);
        Ok(raw_genesis_block)
    }
}

/// `GenesisTransactionBuilder` is a transaction for initialize settings.
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[serde(transparent)]
#[schema(transparent)]
#[repr(transparent)]
pub struct GenesisTransactionBuilder {
    /// Instructions
    pub isi: Vec<InstructionBox>,
}

impl GenesisTransactionBuilder {
    /// Convert [`GenesisTransactionBuilder`] into [`VersionedSignedTransaction`] with signature
    ///
    /// # Errors
    /// Fails if signing or accepting fails
    pub fn sign(
        self,
        genesis_key_pair: KeyPair,
    ) -> core::result::Result<VersionedSignedTransaction, iroha_crypto::error::Error> {
        TransactionBuilder::new(GENESIS_ACCOUNT_ID.clone())
            .with_instructions(self.isi)
            .sign(genesis_key_pair)
    }
}

/// Builder type for [`RawGenesisBlock`] that does
/// not perform any correctness checking on the block
/// produced. Use with caution in tests and other things
/// to register domains and accounts.
#[must_use]
pub struct RawGenesisBlockBuilder<S> {
    transaction: GenesisTransactionBuilder,
    state: S,
}

/// `Domain` subsection of the [`RawGenesisBlockBuilder`]. Makes
/// it easier to create accounts and assets without needing to
/// provide a `DomainId`.
#[must_use]
pub struct RawGenesisDomainBuilder<S> {
    transaction: GenesisTransactionBuilder,
    domain_id: DomainId,
    state: S,
}

mod validator_state {
    use super::ValidatorMode;

    #[cfg_attr(test, derive(Clone))]
    pub struct Set(pub ValidatorMode);

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
            transaction: GenesisTransactionBuilder { isi: Vec::new() },
            state: validator_state::Unset,
        }
    }

    /// Set the validator.
    pub fn validator(
        self,
        validator: impl Into<ValidatorMode>,
    ) -> RawGenesisBlockBuilder<validator_state::Set> {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
            state: validator_state::Set(validator.into()),
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
            transactions: vec![self.transaction],
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

    fn dummy_validator() -> ValidatorMode {
        ValidatorMode::Path(ValidatorPath("./validator.wasm".into()))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn load_new_genesis_block() -> Result<()> {
        let (genesis_public_key, genesis_private_key) = KeyPair::generate()?.into();
        let (alice_public_key, _) = KeyPair::generate()?.into();
        let _genesis_block = GenesisNetwork::from_configuration(
            RawGenesisBlockBuilder::new()
                .domain("wonderland".parse()?)
                .account("alice".parse()?, alice_public_key)
                .finish_domain()
                .validator(dummy_validator())
                .build(),
            Some(
                &ConfigurationProxy {
                    account_public_key: Some(genesis_public_key),
                    account_private_key: Some(Some(genesis_private_key)),
                }
                .build()
                .expect("Default genesis config should build when provided the `public key`"),
            ),
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
        let finished_genesis_block = genesis_builder.validator(dummy_validator()).build();
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
