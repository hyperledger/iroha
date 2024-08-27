//! Genesis-related logic and constructs. Contains the [`GenesisBlock`],
//! [`RawGenesisTransaction`] and the [`GenesisBuilder`] structures.
use std::{
    fmt::Debug,
    fs,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use eyre::{eyre, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    block::SignedBlock, isi::Instruction, parameter::Parameter, peer::Peer, prelude::*,
};
use iroha_schema::IntoSchema;
use once_cell::sync::Lazy;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// [`DomainId`](iroha_data_model::domain::DomainId) of the genesis account.
pub static GENESIS_DOMAIN_ID: Lazy<DomainId> = Lazy::new(|| "genesis".parse().unwrap());

/// Genesis block.
/// First transaction should contain single [`Upgrade`] instruction to set executor.
/// Second transaction should contain all other instructions.
/// If there are no other instructions, second transaction will be omitted.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct GenesisBlock(pub SignedBlock);

/// Format of genesis.json user file.
/// It should be signed, converted to [`GenesisBlock`],
/// and serialized in SCALE format before supplying to Iroha peer.
/// See `kagami genesis sign`.
#[derive(Debug, Clone, Serialize, Deserialize, IntoSchema, Encode, Decode)]
pub struct RawGenesisTransaction {
    /// Unique id of blockchain
    chain: ChainId,
    /// Path to the [`Executor`] file
    executor: ExecutorPath,
    /// Parameters
    #[serde(default)]
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    /// Initial topology
    topology: Vec<PeerId>,
}

/// Path to [`Executor`] file
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[schema(transparent = "String")]
pub struct ExecutorPath(PathBuf);

impl RawGenesisTransaction {
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
            eprintln!("Genesis is quite large, it will take some time to process it (size = {}, threshold = {})", size, Self::WARN_ON_GENESIS_GTE);
        }
        let reader = BufReader::new(file);
        let mut value: Self = serde_json::from_reader(reader).wrap_err_with(|| {
            eyre!(
                "failed to deserialize raw genesis block from {}",
                path.as_ref().display()
            )
        })?;
        value.executor = ExecutorPath(
            path.as_ref()
                .parent()
                .expect("genesis must be a file in some directory")
                .join(value.executor.0),
        );
        Ok(value)
    }

    /// Add new instruction to the genesis block.
    pub fn append_instruction(&mut self, instruction: impl Instruction) {
        self.instructions.push(instruction.into());
    }

    /// Change topology
    #[must_use]
    pub fn with_topology(mut self, topology: Vec<PeerId>) -> Self {
        self.topology = topology;
        self
    }

    /// Build and sign genesis block.
    ///
    /// # Errors
    /// If executor couldn't be read from provided path
    pub fn build_and_sign(self, genesis_key_pair: &KeyPair) -> Result<GenesisBlock> {
        let executor = get_executor(&self.executor.0)?;
        let genesis = build_and_sign_genesis(
            self.instructions,
            executor,
            self.chain,
            genesis_key_pair,
            self.topology,
            self.parameters,
        );
        Ok(genesis)
    }
}

fn build_and_sign_genesis(
    instructions: Vec<InstructionBox>,
    executor: Executor,
    chain_id: ChainId,
    genesis_key_pair: &KeyPair,
    topology: Vec<PeerId>,
    parameters: Vec<Parameter>,
) -> GenesisBlock {
    let transactions = build_transactions(
        instructions,
        executor,
        parameters,
        topology,
        chain_id,
        genesis_key_pair,
    );
    let block = SignedBlock::genesis(transactions, genesis_key_pair.private_key());
    GenesisBlock(block)
}

fn build_transactions(
    instructions: Vec<InstructionBox>,
    executor: Executor,
    parameters: Vec<Parameter>,
    topology: Vec<PeerId>,
    chain_id: ChainId,
    genesis_key_pair: &KeyPair,
) -> Vec<SignedTransaction> {
    let upgrade_isi = Upgrade::new(executor).into();
    let transaction_executor =
        build_transaction(vec![upgrade_isi], chain_id.clone(), genesis_key_pair);
    let mut transactions = vec![transaction_executor];
    if !topology.is_empty() {
        let register_peers = build_transaction(
            topology
                .into_iter()
                .map(Peer::new)
                .map(Register::peer)
                .map(InstructionBox::from)
                .collect(),
            chain_id.clone(),
            genesis_key_pair,
        );
        transactions.push(register_peers)
    }
    if !parameters.is_empty() {
        let parameters = build_transaction(
            parameters
                .into_iter()
                .map(SetParameter::new)
                .map(InstructionBox::from)
                .collect(),
            chain_id.clone(),
            genesis_key_pair,
        );
        transactions.push(parameters);
    }
    if !instructions.is_empty() {
        let transaction_instructions = build_transaction(instructions, chain_id, genesis_key_pair);
        transactions.push(transaction_instructions);
    }
    transactions
}

fn build_transaction(
    instructions: Vec<InstructionBox>,
    chain_id: ChainId,
    genesis_key_pair: &KeyPair,
) -> SignedTransaction {
    let genesis_account_id = AccountId::new(
        GENESIS_DOMAIN_ID.clone(),
        genesis_key_pair.public_key().clone(),
    );
    TransactionBuilder::new(chain_id, genesis_account_id)
        .with_instructions(instructions)
        .sign(genesis_key_pair.private_key())
}

fn get_executor(file: &Path) -> Result<Executor> {
    let wasm = fs::read(file)
        .wrap_err_with(|| eyre!("failed to read the executor from {}", file.display()))?;
    Ok(Executor::new(WasmSmartContract::from_compiled(wasm)))
}

/// Builder type for [`GenesisBlock`]/[`RawGenesisTransaction`]
/// that does not perform any correctness checking on the block produced.
/// Use with caution in tests and other things to register domains and accounts.
#[must_use]
#[derive(Default)]
pub struct GenesisBuilder {
    instructions: Vec<InstructionBox>,
    parameters: Vec<Parameter>,
}

/// `Domain` subsection of the [`GenesisBuilder`]. Makes
/// it easier to create accounts and assets without needing to
/// provide a `DomainId`.
#[must_use]
pub struct GenesisDomainBuilder {
    instructions: Vec<InstructionBox>,
    parameters: Vec<Parameter>,
    domain_id: DomainId,
}

impl GenesisBuilder {
    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain(self, domain_name: Name) -> GenesisDomainBuilder {
        self.domain_with_metadata(domain_name, Metadata::default())
    }

    /// Create a domain and return a domain builder which can
    /// be used to create assets and accounts.
    pub fn domain_with_metadata(
        mut self,
        domain_name: Name,
        metadata: Metadata,
    ) -> GenesisDomainBuilder {
        let domain_id = DomainId::new(domain_name);
        let new_domain = Domain::new(domain_id.clone()).with_metadata(metadata);
        self.instructions.push(Register::domain(new_domain).into());
        GenesisDomainBuilder {
            instructions: self.instructions,
            parameters: self.parameters,
            domain_id,
        }
    }

    /// Add instruction to the end of genesis transaction
    pub fn append_instruction(mut self, instruction: impl Into<InstructionBox>) -> Self {
        self.instructions.push(instruction.into());
        self
    }

    /// Add parameter to the end of parameter list
    pub fn append_parameter(mut self, parameter: Parameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    /// Finish building, sign, and produce a [`GenesisBlock`].
    pub fn build_and_sign(
        self,
        chain_id: ChainId,
        executor_blob: Executor,
        topology: Vec<PeerId>,
        genesis_key_pair: &KeyPair,
    ) -> GenesisBlock {
        build_and_sign_genesis(
            self.instructions,
            executor_blob,
            chain_id,
            genesis_key_pair,
            topology,
            self.parameters,
        )
    }

    /// Finish building and produce a [`RawGenesisTransaction`].
    pub fn build_raw(
        self,
        chain_id: ChainId,
        executor_file: PathBuf,
        topology: Vec<PeerId>,
    ) -> RawGenesisTransaction {
        RawGenesisTransaction {
            instructions: self.instructions,
            executor: ExecutorPath(executor_file),
            parameters: self.parameters,
            chain: chain_id,
            topology,
        }
    }
}

impl GenesisDomainBuilder {
    /// Finish this domain and return to
    /// genesis block building.
    pub fn finish_domain(self) -> GenesisBuilder {
        GenesisBuilder {
            instructions: self.instructions,
            parameters: self.parameters,
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
        self.instructions.push(register.into());
        self
    }

    /// Add [`AssetDefinition`] to current domain.
    pub fn asset(mut self, asset_name: Name, asset_type: AssetType) -> Self {
        let asset_definition_id = AssetDefinitionId::new(self.domain_id.clone(), asset_name);
        let asset_definition = AssetDefinition::new(asset_definition_id, asset_type);
        self.instructions
            .push(Register::asset_definition(asset_definition).into());
        self
    }
}

impl Encode for ExecutorPath {
    fn encode(&self) -> Vec<u8> {
        self.0
            .to_str()
            .expect("path contains not valid UTF-8")
            .encode()
    }
}

impl Decode for ExecutorPath {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> std::result::Result<Self, parity_scale_codec::Error> {
        String::decode(input).map(PathBuf::from).map(ExecutorPath)
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
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
        let genesis_key_pair = KeyPair::random();
        let (alice_public_key, _) = KeyPair::random().into_parts();

        let _genesis_block = GenesisBuilder::default()
            .domain("wonderland".parse()?)
            .account(alice_public_key)
            .finish_domain()
            .build_and_sign(chain_id, dummy_executor(), vec![], &genesis_key_pair);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn genesis_block_builder_example() {
        let public_key: std::collections::HashMap<&'static str, PublicKey> = [
            ("alice", ALICE_KEYPAIR.public_key().clone()),
            ("bob", BOB_KEYPAIR.public_key().clone()),
            ("cheshire_cat", KeyPair::random().into_parts().0),
            ("mad_hatter", KeyPair::random().into_parts().0),
        ]
        .into_iter()
        .collect();
        let mut genesis_builder = GenesisBuilder::default();

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
                AssetType::Numeric(NumericSpec::default()),
            )
            .finish_domain();

        // In real cases executor should be constructed from a wasm blob
        let finished_genesis = genesis_builder.build_and_sign(
            ChainId::from("00000000-0000-0000-0000-000000000000"),
            dummy_executor(),
            vec![],
            &KeyPair::random(),
        );

        let transactions = &finished_genesis.0.transactions().collect::<Vec<_>>();

        // First transaction
        {
            let transaction = transactions[0];
            let instructions = transaction.value.instructions();
            let Executable::Instructions(instructions) = instructions else {
                panic!("Expected instructions");
            };

            assert_eq!(instructions[0], Upgrade::new(dummy_executor()).into());
            assert_eq!(instructions.len(), 1);
        }

        // Second transaction
        let transaction = transactions[1];
        let instructions = transaction.value.instructions();
        let Executable::Instructions(instructions) = instructions else {
            panic!("Expected instructions");
        };

        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                instructions[0],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[1],
                Register::account(Account::new(AccountId::new(
                    domain_id.clone(),
                    public_key["alice"].clone()
                ),))
                .into()
            );
            assert_eq!(
                instructions[2],
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
                instructions[3],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[4],
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
                instructions[5],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[6],
                Register::account(Account::new(AccountId::new(
                    domain_id,
                    public_key["mad_hatter"].clone()
                ),))
                .into()
            );
            assert_eq!(
                instructions[7],
                Register::asset_definition(AssetDefinition::numeric(
                    "hats#meadow".parse().unwrap(),
                ))
                .into()
            );
        }
    }
}
