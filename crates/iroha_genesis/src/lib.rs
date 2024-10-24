//! Genesis-related logic and constructs. Contains the [`GenesisBlock`],
//! [`RawGenesisTransaction`] and the [`GenesisBuilder`] structures.
use std::{
    fmt::Debug,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use eyre::{eyre, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{block::SignedBlock, parameter::Parameter, peer::Peer, prelude::*};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// [`DomainId`](iroha_data_model::domain::DomainId) of the genesis account.
pub static GENESIS_DOMAIN_ID: LazyLock<DomainId> = LazyLock::new(|| "genesis".parse().unwrap());

/// Genesis block.
///
/// First transaction must contain single [`Upgrade`] instruction to set executor.
/// Subsequent transactions can be parameter settings, instructions, topology change, in this order if they exist.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Parameters>,
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

    /// Construct [`RawGenesisTransaction`] from a json file at `json_path`,
    /// resolving relative paths to `json_path`.
    ///
    /// # Errors
    ///
    /// - file not found
    /// - metadata access to the file failed
    /// - deserialization failed
    pub fn from_path(json_path: impl AsRef<Path>) -> Result<Self> {
        let here = json_path
            .as_ref()
            .parent()
            .expect("json file should be in some directory");
        let file = File::open(&json_path).wrap_err_with(|| {
            eyre!("failed to open genesis at {}", json_path.as_ref().display())
        })?;
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
                json_path.as_ref().display()
            )
        })?;

        value.executor.resolve(here);

        Ok(value)
    }

    /// Revert to builder to add modifications.
    pub fn into_builder(self) -> GenesisBuilder {
        let parameters = self
            .parameters
            .map_or(Vec::new(), |parameters| parameters.parameters().collect());

        GenesisBuilder {
            chain: self.chain,
            executor: self.executor,
            instructions: self.instructions,
            parameters,
            topology: self.topology,
        }
    }

    /// Build and sign genesis block.
    ///
    /// # Errors
    ///
    /// Fails if [`RawGenesisTransaction::parse`] fails.
    pub fn build_and_sign(self, genesis_key_pair: &KeyPair) -> Result<GenesisBlock> {
        let chain = self.chain.clone();
        let mut transactions = vec![];
        for instructions in self.parse()? {
            let transaction = build_transaction(instructions, chain.clone(), genesis_key_pair);
            transactions.push(transaction);
        }
        let block = SignedBlock::genesis(transactions, genesis_key_pair.private_key());

        Ok(GenesisBlock(block))
    }

    /// Parse [`RawGenesisTransaction`] to the list of source instructions of the genesis transactions
    ///
    /// # Errors
    ///
    /// Fails if `self.executor` path fails to load [`Executor`].
    fn parse(self) -> Result<Vec<Vec<InstructionBox>>> {
        let mut instructions_list = vec![];

        let upgrade_executor = Upgrade::new(self.executor.try_into()?).into();
        instructions_list.push(vec![upgrade_executor]);

        if let Some(parameters) = self.parameters {
            let instructions = parameters
                .parameters()
                .map(SetParameter::new)
                .map(InstructionBox::from)
                .collect();
            instructions_list.push(instructions);
        }

        if !self.instructions.is_empty() {
            instructions_list.push(self.instructions);
        }

        if !self.topology.is_empty() {
            let instructions = self
                .topology
                .into_iter()
                .map(Peer::new)
                .map(Register::peer)
                .map(InstructionBox::from)
                .collect();
            instructions_list.push(instructions)
        }

        Ok(instructions_list)
    }
}

/// Build a transaction and sign as the genesis account.
fn build_transaction(
    instructions: Vec<InstructionBox>,
    chain: ChainId,
    genesis_key_pair: &KeyPair,
) -> SignedTransaction {
    let genesis_account = AccountId::new(
        GENESIS_DOMAIN_ID.clone(),
        genesis_key_pair.public_key().clone(),
    );

    TransactionBuilder::new(chain, genesis_account)
        .with_instructions(instructions)
        .sign(genesis_key_pair.private_key())
}

/// Builder to build [`RawGenesisTransaction`] and [`GenesisBlock`].
/// No guarantee of validity of the built genesis transactions and block.
#[must_use]
pub struct GenesisBuilder {
    chain: ChainId,
    executor: ExecutorPath,
    instructions: Vec<InstructionBox>,
    parameters: Vec<Parameter>,
    topology: Vec<PeerId>,
}

/// Domain editing mode of the [`GenesisBuilder`] to register accounts and assets under the domain.
#[must_use]
pub struct GenesisDomainBuilder {
    chain: ChainId,
    executor: ExecutorPath,
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    topology: Vec<PeerId>,
    domain_id: DomainId,
}

impl GenesisBuilder {
    /// Construct [`GenesisBuilder`].
    #[expect(clippy::new_without_default)]
    pub fn new(chain: ChainId, executor: ExecutorPath) -> Self {
        Self {
            chain,
            executor,
            parameters: Vec::new(),
            instructions: Vec::new(),
            topology: Vec::new(),
        }
    }

    /// Entry a domain registration and transition to [`GenesisDomainBuilder`].
    pub fn domain(self, domain_name: Name) -> GenesisDomainBuilder {
        self.domain_with_metadata(domain_name, Metadata::default())
    }

    /// Same as [`GenesisBuilder::domain`], but attach a metadata to the domain.
    pub fn domain_with_metadata(
        mut self,
        domain_name: Name,
        metadata: Metadata,
    ) -> GenesisDomainBuilder {
        let domain_id = DomainId::new(domain_name);
        let new_domain = Domain::new(domain_id.clone()).with_metadata(metadata);

        self.instructions.push(Register::domain(new_domain).into());

        GenesisDomainBuilder {
            chain: self.chain,
            executor: self.executor,
            parameters: self.parameters,
            instructions: self.instructions,
            topology: self.topology,
            domain_id,
        }
    }

    /// Entry a parameter setting to the end of entries.
    pub fn append_parameter(mut self, parameter: Parameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    /// Entry a instruction to the end of entries.
    pub fn append_instruction(mut self, instruction: impl Into<InstructionBox>) -> Self {
        self.instructions.push(instruction.into());
        self
    }

    /// Overwrite the initial topology.
    #[must_use]
    pub fn set_topology(mut self, topology: Vec<PeerId>) -> Self {
        self.topology = topology;
        self
    }

    /// Finish building, sign, and produce a [`GenesisBlock`].
    pub fn build_and_sign(self, genesis_key_pair: &KeyPair) -> Result<GenesisBlock> {
        self.build_raw().build_and_sign(genesis_key_pair)
    }

    /// Finish building and produce a [`RawGenesisTransaction`].
    pub fn build_raw(self) -> RawGenesisTransaction {
        let parameters = (!self.parameters.is_empty()).then(|| {
            let mut res = Parameters::default();
            res.extend(self.parameters);
            res
        });

        RawGenesisTransaction {
            chain: self.chain,
            executor: self.executor,
            parameters,
            instructions: self.instructions,
            topology: self.topology,
        }
    }
}

impl GenesisDomainBuilder {
    /// Finish this domain and return to genesis block building.
    pub fn finish_domain(self) -> GenesisBuilder {
        GenesisBuilder {
            chain: self.chain,
            executor: self.executor,
            parameters: self.parameters,
            instructions: self.instructions,
            topology: self.topology,
        }
    }

    /// Add an account to this domain.
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

    /// Add [`AssetDefinition`] to this domain.
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

impl From<PathBuf> for ExecutorPath {
    fn from(value: PathBuf) -> Self {
        Self(value)
    }
}

impl TryFrom<ExecutorPath> for Executor {
    type Error = eyre::Report;

    fn try_from(value: ExecutorPath) -> Result<Self, Self::Error> {
        let wasm = fs::read(&value.0)
            .wrap_err_with(|| eyre!("failed to read the executor from {}", value.0.display()))?;

        Ok(Executor::new(WasmSmartContract::from_compiled(wasm)))
    }
}

impl ExecutorPath {
    /// Resolve `self` to `here/self`,
    /// assuming `self` is an unresolved relative path to `here`.
    /// Must be applied once.
    fn resolve(&mut self, here: impl AsRef<Path>) {
        self.0 = here.as_ref().join(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use iroha_test_samples::{ALICE_KEYPAIR, BOB_KEYPAIR};
    use tempfile::TempDir;

    use super::*;

    fn dummy_executor() -> (TempDir, ExecutorPath) {
        let tmp_dir = TempDir::new().unwrap();
        let wasm = WasmSmartContract::from_compiled(vec![1, 2, 3]);
        let executor_path = tmp_dir.path().join("executor.wasm");
        std::fs::write(&executor_path, wasm).unwrap();

        (tmp_dir, executor_path.into())
    }

    fn test_builder() -> (TempDir, GenesisBuilder) {
        let (tmp_dir, executor_path) = dummy_executor();
        let chain = ChainId::from("00000000-0000-0000-0000-000000000000");
        let builder = GenesisBuilder::new(chain, executor_path);

        (tmp_dir, builder)
    }

    #[test]
    fn load_new_genesis_block() -> Result<()> {
        let genesis_key_pair = KeyPair::random();
        let (alice_public_key, _) = KeyPair::random().into_parts();
        let (_tmp_dir, builder) = test_builder();

        let _genesis_block = builder
            .domain("wonderland".parse()?)
            .account(alice_public_key)
            .finish_domain()
            .build_and_sign(&genesis_key_pair)?;

        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn genesis_block_builder_example() -> Result<()> {
        let public_key: std::collections::HashMap<&'static str, PublicKey> = [
            ("alice", ALICE_KEYPAIR.public_key().clone()),
            ("bob", BOB_KEYPAIR.public_key().clone()),
            ("cheshire_cat", KeyPair::random().into_parts().0),
            ("mad_hatter", KeyPair::random().into_parts().0),
        ]
        .into_iter()
        .collect();
        let (_tmp_dir, mut genesis_builder) = test_builder();
        let executor_path = genesis_builder.executor.clone();

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
        let finished_genesis = genesis_builder.build_and_sign(&KeyPair::random())?;

        let transactions = &finished_genesis.0.transactions().collect::<Vec<_>>();

        // First transaction
        {
            let transaction = transactions[0];
            let instructions = transaction.as_ref().instructions();
            let Executable::Instructions(instructions) = instructions else {
                panic!("Expected instructions");
            };

            assert_eq!(
                instructions[0],
                Upgrade::new(executor_path.try_into()?).into()
            );
            assert_eq!(instructions.len(), 1);
        }

        // Second transaction
        let transaction = transactions[1];
        let instructions = transaction.as_ref().instructions();
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

        Ok(())
    }

    #[test]
    fn genesis_parameters_deserialization() {
        fn test(parameters: &str) {
            let genesis_json = format!(
                r#"{{
                "chain": "0",
                "executor": "./executor.wasm",
                "parameters": {parameters},
                "instructions": [],
                "topology": []
            }}"#
            );

            let _genesis: RawGenesisTransaction =
                serde_json::from_str(&genesis_json).expect("Failed to deserialize");
        }

        // Empty parameters
        test("{}");
        test(
            r#"{"sumeragi": {}, "block": {}, "transaction": {}, "executor": {}, "smart_contract": {}}"#,
        );

        // Inner value missing
        test(r#"{"sumeragi": {"block_time_ms": 2000}}"#);
        test(r#"{"transaction": {"max_instructions": 4096}}"#);
        test(r#"{"executor": {"fuel": 55000000}}"#);
        test(r#"{"smart_contract": {"fuel": 55000000}}"#);
    }
}
