//! Genesis-related logic and constructs. Contains the `GenesisBlock`,
//! `RawGenesisBlock` and the `RawGenesisBlockBuilder` structures.
use std::{
    fmt::Debug,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use derive_more::From;
use eyre::{eyre, ErrReport, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    asset::AssetDefinition,
    executor::Executor,
    prelude::{Metadata, *},
    ChainId,
};
use iroha_schema::IntoSchema;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// [`DomainId`] of the genesis account.
pub static GENESIS_DOMAIN_ID: Lazy<DomainId> = Lazy::new(|| "genesis".parse().expect("Valid"));

/// [`AccountId`] of the genesis account.
pub static GENESIS_ACCOUNT_ID: Lazy<AccountId> =
    Lazy::new(|| AccountId::new(GENESIS_DOMAIN_ID.clone(), "genesis".parse().expect("Valid")));

/// Genesis transaction
#[derive(Debug, Clone)]
pub struct GenesisTransaction(pub SignedTransaction);

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Debug, Clone)]
pub struct GenesisNetwork {
    /// Transactions from [`RawGenesisBlock`]. This vector is guaranteed to be non-empty,
    /// unless [`GenesisNetwork::transactions_mut()`] is used.
    transactions: Vec<GenesisTransaction>,
}

impl GenesisNetwork {
    /// Construct [`GenesisNetwork`] from configuration.
    ///
    /// # Errors
    /// - If fails to sign a transaction (which means that the `key_pair` is malformed rather
    ///   than anything else)
    /// - If transactions set is empty
    pub fn new(
        raw_block: RawGenesisBlock,
        chain_id: &ChainId,
        genesis_key_pair: &KeyPair,
    ) -> Result<GenesisNetwork> {
        // First instruction should be Executor upgrade.
        // This makes possible to grant permissions to users in genesis.
        let transactions_iter = std::iter::once(GenesisTransactionBuilder {
            isi: vec![Upgrade::new(
                Executor::try_from(raw_block.executor)
                    .wrap_err("Failed to construct the executor")?,
            )
            .into()],
        })
        .chain(raw_block.transactions);

        let transactions = transactions_iter
            .enumerate()
            .map(|(i, raw_transaction)| {
                raw_transaction
                    // FIXME: fix underlying chain of `.sign` so that it doesn't
                    //        consume the key pair unnecessarily. It might be costly to clone
                    //        the key pair for a large genesis.
                    .sign(chain_id.clone(), genesis_key_pair.clone())
                    .map(GenesisTransaction)
                    .wrap_err_with(|| eyre!("Failed to sign transaction at index {i}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(GenesisNetwork { transactions })
    }

    /// Consume `self` into genesis transactions
    pub fn into_transactions(self) -> Vec<GenesisTransaction> {
        self.transactions
    }
}

/// [`RawGenesisBlock`] is an initial block of the network
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
pub struct RawGenesisBlock {
    /// Transactions
    transactions: Vec<GenesisTransactionBuilder>,
    /// Runtime Executor
    executor: ExecutorMode,
}

impl RawGenesisBlock {
    const WARN_ON_GENESIS_GTE: u64 = 1024 * 1024 * 1024; // 1Gb

    /// Construct a genesis block from a `.json` file at the specified
    /// path-like object.
    ///
    /// # Errors
    /// If file not found or deserialization from file fails.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Self> {
        let file = File::open(&path)
            .wrap_err_with(|| eyre!("Failed to open {}", path.as_ref().display()))?;
        let size = file
            .metadata()
            .wrap_err("Unable to access genesis file metadata")?
            .len();
        if size >= Self::WARN_ON_GENESIS_GTE {
            eprintln!("Genesis is quite large, it will take some time to apply it (size = {}, threshold = {})", size, Self::WARN_ON_GENESIS_GTE);
        }
        let reader = BufReader::new(file);
        let mut raw_genesis_block: Self = serde_json::from_reader(reader)
            .wrap_err_with(|| eyre!("Failed to deserialize raw genesis block from {:?}", &path))?;
        raw_genesis_block.executor.set_genesis_path(path);
        Ok(raw_genesis_block)
    }

    /// Get first transaction
    pub fn first_transaction_mut(&mut self) -> Option<&mut GenesisTransactionBuilder> {
        self.transactions.first_mut()
    }
}

/// Ways to provide executor either directly as base64 encoded string or as path to wasm file
#[derive(Debug, Clone, From, Deserialize, Serialize, IntoSchema)]
#[serde(untagged)]
pub enum ExecutorMode {
    /// Path to executor wasm file
    // In the first place to initially try to parse path
    Path(ExecutorPath),
    /// Executor encoded as base64 string
    Inline(Executor),
}

impl ExecutorMode {
    fn set_genesis_path(&mut self, genesis_path: impl AsRef<Path>) {
        if let Self::Path(path) = self {
            path.set_genesis_path(genesis_path);
        }
    }
}

impl TryFrom<ExecutorMode> for Executor {
    type Error = ErrReport;

    fn try_from(value: ExecutorMode) -> Result<Self> {
        match value {
            ExecutorMode::Inline(executor) => Ok(executor),
            ExecutorMode::Path(ExecutorPath(relative_executor_path)) => {
                let wasm = fs::read(&relative_executor_path)
                    .wrap_err(format!("Failed to open {:?}", &relative_executor_path))?;
                Ok(Executor::new(WasmSmartContract::from_compiled(wasm)))
            }
        }
    }
}

/// Path to the executor relative to genesis location
///
/// If path is absolute it will be used directly otherwise it will be treated as relative to genesis location.
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[schema(transparent = "String")]
#[serde(transparent)]
#[repr(transparent)]
pub struct ExecutorPath(pub PathBuf);

impl ExecutorPath {
    fn set_genesis_path(&mut self, genesis_path: impl AsRef<Path>) {
        let path_to_executor = genesis_path
            .as_ref()
            .parent()
            .expect("Genesis must be in some directory")
            .join(&self.0);
        self.0 = path_to_executor;
    }
}

/// Transaction for initialize settings.
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[serde(transparent)]
#[schema(transparent)]
#[repr(transparent)]
pub struct GenesisTransactionBuilder {
    /// Instructions
    isi: Vec<InstructionBox>,
}

impl GenesisTransactionBuilder {
    /// Convert [`GenesisTransactionBuilder`] into [`SignedTransaction`] with signature.
    ///
    /// # Errors
    /// Fails if signing or accepting fails.
    fn sign(
        self,
        chain_id: ChainId,
        genesis_key_pair: KeyPair,
    ) -> core::result::Result<SignedTransaction, iroha_crypto::error::Error> {
        TransactionBuilder::new(chain_id, GENESIS_ACCOUNT_ID.clone())
            .with_instructions(self.isi)
            .sign(genesis_key_pair)
    }

    /// Add new instruction to the transaction.
    pub fn append_instruction(&mut self, instruction: InstructionBox) {
        self.isi.push(instruction);
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

mod executor_state {
    use super::ExecutorMode;

    #[cfg_attr(test, derive(Clone))]
    pub struct Set(pub ExecutorMode);

    #[derive(Clone, Copy)]
    pub struct Unset;
}

impl Default for RawGenesisBlockBuilder<executor_state::Unset> {
    fn default() -> Self {
        // Do not add `impl Default`. While it can technically be
        // regarded as a default constructor, this builder should not
        // be used in contexts where `Default::default()` is likely to
        // be called.
        Self {
            transaction: GenesisTransactionBuilder { isi: Vec::new() },
            state: executor_state::Unset,
        }
    }
}

impl RawGenesisBlockBuilder<executor_state::Unset> {
    /// Set the executor.
    pub fn executor(
        self,
        executor: impl Into<ExecutorMode>,
    ) -> RawGenesisBlockBuilder<executor_state::Set> {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
            state: executor_state::Set(executor.into()),
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
            .push(Register::domain(new_domain).into());
        RawGenesisDomainBuilder {
            transaction: self.transaction,
            domain_id,
            state: self.state,
        }
    }
}

impl RawGenesisBlockBuilder<executor_state::Set> {
    /// Finish building and produce a `RawGenesisBlock`.
    pub fn build(self) -> RawGenesisBlock {
        RawGenesisBlock {
            transactions: vec![self.transaction],
            executor: self.state.0,
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
    fn account_without_public_key(mut self, account_name: Name) -> Self {
        let account_id = AccountId::new(self.domain_id.clone(), account_name);
        self.transaction
            .isi
            .push(Register::account(Account::new(account_id, [])).into());
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
        let account_id = AccountId::new(self.domain_id.clone(), account_name);
        let register =
            Register::account(Account::new(account_id, [public_key]).with_metadata(metadata));
        self.transaction.isi.push(register.into());
        self
    }

    /// Add [`AssetDefinition`] to current domain.
    pub fn asset(mut self, asset_name: Name, asset_value_type: AssetValueType) -> Self {
        let asset_definition_id = AssetDefinitionId::new(self.domain_id.clone(), asset_name);
        let asset_definition = match asset_value_type {
            AssetValueType::Quantity => AssetDefinition::quantity(asset_definition_id),
            AssetValueType::BigQuantity => AssetDefinition::big_quantity(asset_definition_id),
            AssetValueType::Fixed => AssetDefinition::fixed(asset_definition_id),
            AssetValueType::Store => AssetDefinition::store(asset_definition_id),
        };
        self.transaction
            .isi
            .push(Register::asset_definition(asset_definition).into());
        self
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn dummy_executor() -> ExecutorMode {
        ExecutorMode::Inline(Executor::new(WasmSmartContract::from_compiled(vec![
            1, 2, 3,
        ])))
    }

    #[test]
    fn load_new_genesis_block() -> Result<()> {
        let chain_id = ChainId::new("0");

        let genesis_key_pair = KeyPair::generate()?;
        let (alice_public_key, _) = KeyPair::generate()?.into();

        let _genesis_block = GenesisNetwork::new(
            RawGenesisBlockBuilder::default()
                .domain("wonderland".parse()?)
                .account("alice".parse()?, alice_public_key)
                .finish_domain()
                .executor(dummy_executor())
                .build(),
            &chain_id,
            &genesis_key_pair,
        )?;
        Ok(())
    }

    #[test]
    fn genesis_block_builder_example() {
        let public_key = "ed0120204E9593C3FFAF4464A6189233811C297DD4CE73ABA167867E4FBD4F8C450ACB";
        let mut genesis_builder = RawGenesisBlockBuilder::default();

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

        // In real cases executor should be constructed from a wasm blob
        let finished_genesis_block = genesis_builder.executor(dummy_executor()).build();
        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[0],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[1],
                Register::account(Account::new(
                    AccountId::new(domain_id.clone(), "alice".parse().unwrap()),
                    []
                ))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[2],
                Register::account(Account::new(
                    AccountId::new(domain_id, "bob".parse().unwrap()),
                    []
                ))
                .into()
            );
        }
        {
            let domain_id: DomainId = "tulgey_wood".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[3],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[4],
                Register::account(Account::new(
                    AccountId::new(domain_id, "Cheshire_Cat".parse().unwrap()),
                    []
                ))
                .into()
            );
        }
        {
            let domain_id: DomainId = "meadow".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[5],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[6],
                Register::account(Account::new(
                    AccountId::new(domain_id, "Mad_Hatter".parse().unwrap()),
                    [public_key.parse().unwrap()],
                ))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[7],
                Register::asset_definition(AssetDefinition::big_quantity(
                    "hats#meadow".parse().unwrap()
                ))
                .into()
            );
        }
    }
}
