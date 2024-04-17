//! Genesis-related logic and constructs. Contains the `GenesisBlock`,
//! `RawGenesisBlock` and the `RawGenesisBlockBuilder` structures.
use std::{
    fmt::Debug,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    time::Duration,
};

use eyre::{eyre, Report, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey, SignaturesOf};
use iroha_data_model::{
    asset::{AssetDefinition, AssetValueType},
    executor::Executor,
    prelude::{Metadata, *},
    transaction::TransactionPayload,
    ChainId,
};
use once_cell::sync::Lazy;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// [`DomainId`] of the genesis account.
pub static GENESIS_DOMAIN_ID: Lazy<DomainId> = Lazy::new(|| "genesis".parse().expect("Valid"));

/// [`AccountId`] of the genesis account.
pub static GENESIS_ACCOUNT_ID: Lazy<AccountId> =
    Lazy::new(|| AccountId::new(GENESIS_DOMAIN_ID.clone(), "genesis".parse().expect("Valid")));

/// Genesis transaction
#[derive(Debug, Clone, Decode, Encode)]
#[repr(transparent)]
pub struct GenesisTransaction(pub SignedTransaction);

impl GenesisTransaction {
    /// Construct single genesis transaction with [`Executor`] and transactions unified under a single transaction
    pub fn new_unified(
        raw_block: RawGenesisBlock,
        chain_id: &ChainId,
        genesis_key_pair: &KeyPair,
    ) -> GenesisTransaction {
        Self(raw_block.unify().sign(chain_id.clone(), genesis_key_pair))
    }
}

/// Different errors as a result of parsing hex string for `GenesisSignature`
#[derive(Copy, Clone, Debug, displaydoc::Display)]
pub enum GenesisSignatureParseError {
    ///  Hex string could not be decoded into scale encoded bytes
    HexDecodeError,
    ///  The config has incorrect scale format and cannot be decoded
    ScaleDecodeError,
}

impl std::error::Error for GenesisSignatureParseError {}

/// [`SignedGenesisConfig`] contains data that is used for loading signed genesis from config.
#[derive(Debug, Clone, Decode, Encode)]
pub struct GenesisSignature {
    chain_id: ChainId,
    creation_time: Duration,
    signatures: SignaturesOf<TransactionPayload>,
}

impl GenesisSignature {
    /// Create [`SignedGenesisConfig`] from it's components
    pub fn new(
        chain_id: ChainId,
        creation_time_ms: Duration,
        signatures: SignaturesOf<TransactionPayload>,
    ) -> Self {
        Self {
            chain_id,
            creation_time: creation_time_ms,
            signatures,
        }
    }

    /// Serialize self to hex string
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.encode())
    }

    /// Deserialize [`SignedGenesisConfig`] from hex representation
    /// # Errors
    /// Fails if it cannot either decode hex string or decode scale-encoded bytes
    pub fn from_hex_string<S: AsRef<[u8]>>(hex: &S) -> Result<Self, GenesisSignatureParseError> {
        let decoded_hex =
            hex::decode(hex).map_err(|_| GenesisSignatureParseError::HexDecodeError)?;
        Decode::decode(&mut decoded_hex.as_slice())
            .map_err(|_| GenesisSignatureParseError::ScaleDecodeError)
    }
}

/// [`GenesisNetwork`] contains initial transactions and genesis setup related parameters.
#[derive(Debug, Clone, Decode, Encode)]
pub struct GenesisNetwork {
    /// Transactions from [`RawGenesisBlock`] packed into a single one.
    transaction: GenesisTransaction,
}

impl GenesisNetwork {
    /// Construct from configuration
    pub fn new(
        raw_block: RawGenesisBlock,
        chain_id: &ChainId,
        genesis_key_pair: &KeyPair,
    ) -> GenesisNetwork {
        let unified_transaction =
            GenesisTransaction::new_unified(raw_block, chain_id, genesis_key_pair);

        GenesisNetwork {
            transaction: unified_transaction,
        }
    }

    /// Construct `GenesisSignature` from config
    /// # Errors
    /// Fails if the
    pub fn new_genesis_signature(
        raw_block: RawGenesisBlock,
        chain_id: &ChainId,
        genesis_key_pair: &KeyPair,
    ) -> GenesisSignature {
        let genesis_tx = GenesisTransaction::new_unified(raw_block, chain_id, genesis_key_pair).0;
        GenesisSignature::new(
            genesis_tx.chain_id().clone(),
            genesis_tx.creation_time(),
            genesis_tx.signatures().clone(),
        )
    }

    /// Checks that [`SignedGenesisConfig`] corresponds to [`RawGenesisBlock`] and produces [`GenesisNetwork`] if it does.
    /// # Errors
    /// Fails if [`RawGenesisBlock`] does not correspond to [`SignedGenesisConfig`] and it was unable to verify it's integrity
    pub fn try_parse(
        genesis_block: RawGenesisBlock,
        signature: GenesisSignature,
    ) -> Result<GenesisNetwork> {
        let mut payload_builder =
            TransactionBuilder::new(signature.chain_id, GENESIS_ACCOUNT_ID.clone())
                .with_instructions(genesis_block.unify().isi);
        payload_builder.set_creation_time(signature.creation_time);
        let payload = payload_builder.into_payload();

        let genesis_signed_transaction =
            SignedTransaction::try_from((signature.signatures, payload))
                .map_err(|e| eyre!("{}", e))?;
        Ok(GenesisNetwork {
            transaction: GenesisTransaction(genesis_signed_transaction),
        })
    }

    /// Transform into genesis transactions
    pub fn into_transaction(self) -> GenesisTransaction {
        self.transaction
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

    fn unify(self) -> GenesisTransactionBuilder {
        // Putting executor upgrade as a first instruction
        let mut unified_tx = GenesisTransactionBuilder {
            isi: vec![Upgrade::new(self.executor).into()],
        };
        unified_tx.extend_instructions(self.transactions.iter().flat_map(|v| v.isi.clone()));
        unified_tx
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
        TransactionBuilder::new(chain_id, GENESIS_ACCOUNT_ID.clone())
            .with_instructions(self.isi)
            .sign(genesis_key_pair)
    }

    /// Add new instruction to the transaction.
    pub fn push_instruction(&mut self, instruction: InstructionBox) {
        self.isi.push(instruction);
    }

    /// Add new instructions to the transaction
    pub fn extend_instructions<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = InstructionBox>,
    {
        self.isi.extend(iter)
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

    /// Add an account to this domain with random public key.
    #[cfg(test)]
    fn account_with_random_public_key(mut self, account_name: Name) -> Self {
        let account_id = AccountId::new(self.domain_id.clone(), account_name);
        self.transaction.isi.push(
            Register::account(Account::new(account_id, KeyPair::random().into_parts().0)).into(),
        );
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
            Register::account(Account::new(account_id, public_key).with_metadata(metadata));
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
                .account("alice".parse()?, alice_public_key)
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
        let public_key = "ed0120204E9593C3FFAF4464A6189233811C297DD4CE73ABA167867E4FBD4F8C450ACB";
        let mut genesis_builder = RawGenesisBlockBuilder::default();

        genesis_builder = genesis_builder
            .domain("wonderland".parse().unwrap())
            .account_with_random_public_key("alice".parse().unwrap())
            .account_with_random_public_key("bob".parse().unwrap())
            .finish_domain()
            .domain("tulgey_wood".parse().unwrap())
            .account_with_random_public_key("Cheshire_Cat".parse().unwrap())
            .finish_domain()
            .domain("meadow".parse().unwrap())
            .account("Mad_Hatter".parse().unwrap(), public_key.parse().unwrap())
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
                Register::account(Account::new(
                    AccountId::new(domain_id.clone(), "alice".parse().unwrap()),
                    KeyPair::random().into_parts().0,
                ))
                .into()
            );
            assert_eq!(
                finished_genesis_block.transactions[0].isi[2],
                Register::account(Account::new(
                    AccountId::new(domain_id, "bob".parse().unwrap()),
                    KeyPair::random().into_parts().0,
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
                    KeyPair::random().into_parts().0,
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
                    public_key.parse().unwrap(),
                ))
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
