//! Genesis-related logic and constructs. Contains the [`GenesisTransaction`],
//! [`RawGenesisTransaction`] and the [`GenesisTransactionBuilder`] structures.
use std::{
    fmt::Debug,
    fs,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use eyre::{eyre, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::prelude::*;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// [`DomainId`](iroha_data_model::domain::DomainId) of the genesis account.
pub static GENESIS_DOMAIN_ID: Lazy<DomainId> = Lazy::new(|| "genesis".parse().unwrap());

/// Genesis transaction.
/// First instruction should be [`Upgrade`].
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct GenesisTransaction(pub SignedTransaction);

/// Format of genesis.json user file.
/// It should be signed and serialized to [`GenesisTransaction`]
/// in SCALE format before supplying to Iroha peer.
/// See `kagami genesis sign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawGenesisTransaction {
    instructions: Vec<InstructionBox>,
    /// Path to the [`Executor`] file
    executor_file: PathBuf,
    /// Unique id of blockchain
    chain_id: ChainId,
}

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
        value.executor_file = path
            .as_ref()
            .parent()
            .expect("genesis must be a file in some directory")
            .join(value.executor_file);
        Ok(value)
    }

    /// Add new instruction to the genesis block.
    pub fn append_instruction(&mut self, instruction: InstructionBox) {
        self.instructions.push(instruction);
    }

    /// Build and sign genesis transaction.
    ///
    /// # Errors
    /// If executor couldn't be read from provided path
    pub fn build_and_sign(self, genesis_key_pair: &KeyPair) -> Result<GenesisTransaction> {
        let executor = get_executor(&self.executor_file)?;
        let genesis =
            build_and_sign_genesis(self.instructions, executor, self.chain_id, genesis_key_pair);
        Ok(genesis)
    }
}

fn build_and_sign_genesis(
    instructions: Vec<InstructionBox>,
    executor: Executor,
    chain_id: ChainId,
    genesis_key_pair: &KeyPair,
) -> GenesisTransaction {
    let instructions = build_instructions(instructions, executor);
    let genesis_account_id = AccountId::new(
        GENESIS_DOMAIN_ID.clone(),
        genesis_key_pair.public_key().clone(),
    );
    let transaction = TransactionBuilder::new(chain_id, genesis_account_id)
        .with_instructions(instructions)
        .sign(genesis_key_pair.private_key());
    GenesisTransaction(transaction)
}

fn build_instructions(
    instructions: Vec<InstructionBox>,
    executor: Executor,
) -> Vec<InstructionBox> {
    let mut result = vec![Upgrade::new(executor).into()];
    result.extend(instructions);
    result
}

fn get_executor(file: &Path) -> Result<Executor> {
    let wasm = fs::read(file)
        .wrap_err_with(|| eyre!("failed to read the executor from {}", file.display()))?;
    Ok(Executor::new(WasmSmartContract::from_compiled(wasm)))
}

/// Builder type for [`GenesisTransaction`]/[`RawGenesisTransaction`]
/// that does not perform any correctness checking on the block produced.
/// Use with caution in tests and other things to register domains and accounts.
#[must_use]
#[derive(Default)]
pub struct GenesisTransactionBuilder {
    instructions: Vec<InstructionBox>,
}

/// `Domain` subsection of the [`GenesisTransactionBuilder`]. Makes
/// it easier to create accounts and assets without needing to
/// provide a `DomainId`.
#[must_use]
pub struct GenesisDomainBuilder {
    instructions: Vec<InstructionBox>,
    domain_id: DomainId,
}

impl GenesisTransactionBuilder {
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
            domain_id,
        }
    }

    /// Add instruction to the end of genesis transaction
    pub fn append_instruction(mut self, instruction: impl Into<InstructionBox>) -> Self {
        self.instructions.push(instruction.into());
        self
    }
}

impl GenesisTransactionBuilder {
    /// Finish building, sign, and produce a [`GenesisTransaction`].
    pub fn build_and_sign(
        self,
        executor_blob: Executor,
        chain_id: ChainId,
        genesis_key_pair: &KeyPair,
    ) -> GenesisTransaction {
        build_and_sign_genesis(self.instructions, executor_blob, chain_id, genesis_key_pair)
    }

    /// Finish building and produce a [`RawGenesisTransaction`].
    pub fn build_raw(self, executor_file: PathBuf, chain_id: ChainId) -> RawGenesisTransaction {
        RawGenesisTransaction {
            instructions: self.instructions,
            executor_file,
            chain_id,
        }
    }
}

impl GenesisDomainBuilder {
    /// Finish this domain and return to
    /// genesis block building.
    pub fn finish_domain(self) -> GenesisTransactionBuilder {
        GenesisTransactionBuilder {
            instructions: self.instructions,
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
    pub fn asset(mut self, asset_name: Name, asset_value_type: AssetValueType) -> Self {
        let asset_definition_id = AssetDefinitionId::new(self.domain_id.clone(), asset_name);
        let asset_definition = AssetDefinition::new(asset_definition_id, asset_value_type);
        self.instructions
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
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
        let genesis_key_pair = KeyPair::random();
        let (alice_public_key, _) = KeyPair::random().into_parts();

        let _genesis_block = GenesisTransactionBuilder::default()
            .domain("wonderland".parse()?)
            .account(alice_public_key)
            .finish_domain()
            .build_and_sign(dummy_executor(), chain_id, &genesis_key_pair);
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
        let mut genesis_builder = GenesisTransactionBuilder::default();

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
        let finished_genesis = genesis_builder.build_and_sign(
            dummy_executor(),
            ChainId::from("00000000-0000-0000-0000-000000000000"),
            &KeyPair::random(),
        );

        let instructions = finished_genesis.0.instructions();
        let Executable::Instructions(instructions) = instructions else {
            panic!("Expected instructions");
        };
        assert_eq!(instructions[0], Upgrade::new(dummy_executor()).into());
        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                instructions[1],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[2],
                Register::account(Account::new(AccountId::new(
                    domain_id.clone(),
                    public_key["alice"].clone()
                ),))
                .into()
            );
            assert_eq!(
                instructions[3],
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
                instructions[4],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[5],
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
                instructions[6],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[7],
                Register::account(Account::new(AccountId::new(
                    domain_id,
                    public_key["mad_hatter"].clone()
                ),))
                .into()
            );
            assert_eq!(
                instructions[8],
                Register::asset_definition(AssetDefinition::numeric(
                    "hats#meadow".parse().unwrap(),
                ))
                .into()
            );
        }
    }
}
