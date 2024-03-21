//! Genesis-related logic and constructs. Contains the `GenesisBlock`,
//! `RawGenesisBlock` and the `RawGenesisBlockBuilder` structures.
use std::{
    fmt::Debug,
    fs,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use eyre::{eyre, Report, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    asset::{AssetDefinition, AssetValueType},
    executor::Executor,
    isi::InstructionBox,
    prelude::{Metadata, *},
    ChainId,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// [`DomainId`](iroha_data_model::domain::DomainId) of the genesis account.
pub static GENESIS_DOMAIN_ID: Lazy<DomainId> = Lazy::new(|| "genesis".parse().unwrap());

/// Genesis transaction
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct GenesisTransaction(pub SignedTransaction);

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Debug, Clone)]
pub struct GenesisNetwork {
    /// Transactions from [`RawGenesisBlock`]. This vector is guaranteed to be non-empty,
    /// unless [`GenesisNetwork::transactions_mut()`] is used.
    transactions: Vec<GenesisTransaction>,
}

impl GenesisNetwork {
    /// Construct from configuration
    pub fn new(
        raw_block: RawGenesisBlock,
        chain_id: &ChainId,
        genesis_key_pair: &KeyPair,
    ) -> GenesisNetwork {
        // The first instruction should be Executor upgrade.
        // This makes it possible to grant permissions to users in genesis.
        let transactions_iter = std::iter::once(GenesisTransactionBuilder {
            isi: vec![Upgrade::new(raw_block.executor).into()],
        })
        .chain(raw_block.transactions);

        let transactions = transactions_iter
            .map(|raw_transaction| raw_transaction.sign(chain_id.clone(), genesis_key_pair))
            .map(GenesisTransaction)
            .collect();

        GenesisNetwork { transactions }
    }

    /// Transform into genesis transactions
    pub fn into_transactions(self) -> Vec<GenesisTransaction> {
        self.transactions
    }
}

/// The initial block of the network
///
/// Use [`RawGenesisBlockFile`] to read it from a file.
#[derive(Debug, Clone)]
pub struct RawGenesisBlock {
    /// Transactions
    transactions: Vec<GenesisTransactionBuilder>,
    /// The [`Executor`]
    executor: Executor,
}

impl RawGenesisBlock {
    /// Shorthand for [`RawGenesisBlockFile::from_path`]
    ///
    /// # Errors
    /// Refer to the original method
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        RawGenesisBlockFile::from_path(path)?.try_into()
    }
}

/// A (de-)serializable version of [`RawGenesisBlock`].
///
/// The conversion is performed using [`TryFrom`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawGenesisBlockFile {
    /// Transactions
    transactions: Vec<GenesisTransactionBuilder>,
    /// Path to the [`Executor`] file
    executor_file: PathBuf,
}

impl TryFrom<RawGenesisBlockFile> for RawGenesisBlock {
    type Error = Report;

    fn try_from(value: RawGenesisBlockFile) -> Result<Self> {
        let wasm = fs::read(&value.executor_file).wrap_err_with(|| {
            eyre!(
                "failed to read the executor from {}",
                &value.executor_file.display()
            )
        })?;
        Ok(Self {
            transactions: value.transactions,
            executor: Executor::new(WasmSmartContract::from_compiled(wasm)),
        })
    }
}

impl RawGenesisBlockFile {
    const WARN_ON_GENESIS_GTE: u64 = 1024 * 1024 * 1024; // 1Gb

    /// Construct a genesis block from a `.json` file at the specified
    /// path-like object.
    ///
    /// # Errors
    /// If file not found or deserialization from file fails.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(&path)
            .wrap_err_with(|| eyre!("failed to open genesis at {}", path.as_ref().display()))?;
        let size = file
            .metadata()
            .wrap_err("failed to access genesis file metadata")?
            .len();
        if size >= Self::WARN_ON_GENESIS_GTE {
            eprintln!("Genesis is quite large, it will take some time to apply it (size = {}, threshold = {})", size, Self::WARN_ON_GENESIS_GTE);
        }
        let reader = BufReader::new(file);
        let mut value: Self = serde_json::from_reader(reader).wrap_err_with(|| {
            eyre!(
                "failed to deserialize raw genesis block from {}",
                path.as_ref().display()
            )
        })?;
        value.executor_file = path
            .as_ref()
            .parent()
            .expect("genesis must be a file in some directory")
            .join(value.executor_file);
        Ok(value)
    }

    /// Get the first transaction
    pub fn first_transaction_mut(&mut self) -> Option<&mut GenesisTransactionBuilder> {
        self.transactions.first_mut()
    }
}

/// Transaction for initialize settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GenesisTransactionBuilder {
    /// Instructions
    isi: Vec<InstructionBox>,
}

impl GenesisTransactionBuilder {
    /// Convert [`GenesisTransactionBuilder`] into [`SignedTransaction`] with signature.
    #[must_use]
    fn sign(self, chain_id: ChainId, genesis_key_pair: &KeyPair) -> SignedTransaction {
        let genesis_account_id = AccountId::new(
            GENESIS_DOMAIN_ID.clone(),
            genesis_key_pair.public_key().clone(),
        );
        TransactionBuilder::new(chain_id, genesis_account_id)
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

/// States of executor in [`RawGenesisBlockBuilder`]
pub mod executor_state {
    use super::{Executor, PathBuf};

    /// The executor is set directly as a blob
    #[cfg_attr(test, derive(Clone))]
    pub struct SetBlob(pub Executor);

    /// The executor is set as a file path
    #[cfg_attr(test, derive(Clone))]
    pub struct SetPath(pub PathBuf);

    /// The executor isn't set yet
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
    /// Set the executor as a binary blob
    pub fn executor_blob(self, value: Executor) -> RawGenesisBlockBuilder<executor_state::SetBlob> {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
            state: executor_state::SetBlob(value),
        }
    }

    /// Set the executor as a file path
    pub fn executor_file(self, path: PathBuf) -> RawGenesisBlockBuilder<executor_state::SetPath> {
        RawGenesisBlockBuilder {
            transaction: self.transaction,
            state: executor_state::SetPath(path),
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

    /// Add instruction to the end of genesis transaction
    pub fn append_instruction(mut self, instruction: impl Into<InstructionBox>) -> Self {
        self.transaction.append_instruction(instruction.into());
        self
    }
}

impl RawGenesisBlockBuilder<executor_state::SetBlob> {
    /// Finish building and produce a [`RawGenesisBlock`].
    pub fn build(self) -> RawGenesisBlock {
        RawGenesisBlock {
            transactions: vec![self.transaction],
            executor: self.state.0,
        }
    }
}

impl RawGenesisBlockBuilder<executor_state::SetPath> {
    /// Finish building and produce a [`RawGenesisBlockFile`].
    pub fn build(self) -> RawGenesisBlockFile {
        RawGenesisBlockFile {
            transactions: vec![self.transaction],
            executor_file: self.state.0,
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

    /// Add an account to this domain
    pub fn account(self, signatory: PublicKey) -> Self {
        self.account_with_metadata(signatory, Metadata::default())
    }

    /// Add an account (having provided `metadata`) to this domain.
    pub fn account_with_metadata(mut self, signatory: PublicKey, metadata: Metadata) -> Self {
        let account_id = AccountId::new(self.domain_id.clone(), signatory);
        let register = Register::account(Account::new(account_id).with_metadata(metadata));
        self.transaction.isi.push(register.into());
        self
    }

    /// Add [`AssetDefinition`] to current domain.
    pub fn asset(mut self, asset_name: Name, asset_value_type: AssetValueType) -> Self {
        let asset_definition_id = AssetDefinitionId::new(self.domain_id.clone(), asset_name);
        let asset_definition = AssetDefinition::new(asset_definition_id, asset_value_type);
        self.transaction
            .isi
            .push(Register::asset_definition(asset_definition).into());
        self
    }
}

#[cfg(test)]
mod tests {
    use test_samples::{ALICE_KEYPAIR, BOB_KEYPAIR};

    use super::*;

    fn dummy_executor() -> Executor {
        Executor::new(WasmSmartContract::from_compiled(vec![1, 2, 3]))
    }

    #[test]
    fn load_new_genesis_block() -> Result<()> {
        let chain_id = ChainId::from("0");
        let genesis_key_pair = KeyPair::random();
        let (alice_public_key, _) = KeyPair::random().into_parts();

        let _genesis_block = GenesisNetwork::new(
            RawGenesisBlockBuilder::default()
                .domain("wonderland".parse()?)
                .account(alice_public_key)
                .finish_domain()
                .executor_blob(dummy_executor())
                .build(),
            &chain_id,
            &genesis_key_pair,
        );
        Ok(())
    }

    #[test]
    fn genesis_block_builder_example() {
        let public_key: std::collections::HashMap<&'static str, PublicKey> = [
            ("alice", ALICE_KEYPAIR.public_key().clone()),
            ("bob", BOB_KEYPAIR.public_key().clone()),
            ("cheshire_cat", KeyPair::random().into_parts().0),
            ("mad_hatter", KeyPair::random().into_parts().0),
        ]
        .into_iter()
        .collect();
        let mut genesis_builder = RawGenesisBlockBuilder::default();

        genesis_builder = genesis_builder
            .domain("wonderland".parse().unwrap())
            .account(public_key["alice"].clone())
            .account(public_key["bob"].clone())
            .finish_domain()
            .domain("tulgey_wood".parse().unwrap())
            .account(public_key["cheshire_cat"].clone())
            .finish_domain()
            .domain("meadow".parse().unwrap())
            .account(public_key["mad_hatter"].clone())
            .asset(
                "hats".parse().unwrap(),
                AssetValueType::Numeric(NumericSpec::default()),
            )
            .finish_domain();

        // In real cases executor should be constructed from a wasm blob
        let finished_genesis_block = genesis_builder.executor_blob(dummy_executor()).build();
        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                finished_genesis_block.transactions[0].isi[0],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[1],
                Register::account(Account::new(AccountId::new(
                    domain_id.clone(),
                    public_key["alice"].clone()
                ),))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[2],
                Register::account(Account::new(AccountId::new(
                    domain_id,
                    public_key["bob"].clone()
                ),))
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
                Register::account(Account::new(AccountId::new(
                    domain_id,
                    public_key["cheshire_cat"].clone()
                ),))
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
                Register::account(Account::new(AccountId::new(
                    domain_id,
                    public_key["mad_hatter"].clone()
                ),))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[7],
                Register::asset_definition(AssetDefinition::numeric(
                    "hats#meadow".parse().unwrap(),
                ))
                .into()
            );
        }
    }
}
