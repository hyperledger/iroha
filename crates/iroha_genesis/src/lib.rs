//! Genesis-related logic and constructs. Contains the [`GenesisBlock`],
//! [`RawGenesisTransaction`] and the [`GenesisBuilder`] structures.
use std::{
    fmt::Debug,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use derive_more::Constructor;
use eyre::{eyre, Result, WrapErr};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    block::SignedBlock, isi::Instruction, parameter::Parameter, peer::Peer, prelude::*,
};
use iroha_executor_data_model::permission::trigger::{
    CanRegisterAnyTrigger, CanUnregisterAnyTrigger,
};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Domain of the genesis account, technically required for the pre-genesis state
pub static GENESIS_DOMAIN_ID: LazyLock<DomainId> = LazyLock::new(|| "genesis".parse().unwrap());

/// Domain of the system account, implicitly registered in the genesis
pub static SYSTEM_DOMAIN_ID: LazyLock<DomainId> = LazyLock::new(|| "system".parse().unwrap());

/// The root authority for internal operations, implicitly registered in the genesis
// FIXME #5022 deny external access
// kagami crypto --seed "system"
pub static SYSTEM_ACCOUNT_ID: LazyLock<AccountId> = LazyLock::new(|| {
    AccountId::new(
        SYSTEM_DOMAIN_ID.clone(),
        "ed0120D8B64D62FD8E09B9F29FE04D9C63E312EFB1CB29F1BF6AF00EBC263007AE75F7"
            .parse()
            .unwrap(),
    )
});

/// Genesis block.
///
/// First transaction must contain single [`Upgrade`] instruction to set executor.
/// Second transaction must contain all other instructions.
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
    executor: WasmPath,
    /// Parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Parameters>,
    /// Instructions
    instructions: Vec<InstructionBox>,
    /// Triggers whose executable is wasm, not instructions
    wasm_triggers: Vec<GenesisWasmTrigger>,
    /// Initial topology
    topology: Vec<PeerId>,
}

/// Path to `*.wasm` file
#[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
#[schema(transparent = "String")]
pub struct WasmPath(PathBuf);

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
        value.executor = path
            .as_ref()
            .parent()
            .expect("genesis must be a file in some directory")
            .join(value.executor.0)
            .into();

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
        let parameters = self
            .parameters
            .map_or(Vec::new(), |parameters| parameters.parameters().collect());
        let genesis = build_and_sign_genesis(
            self.chain,
            executor,
            parameters,
            self.instructions,
            self.wasm_triggers,
            self.topology,
            genesis_key_pair,
        );
        Ok(genesis)
    }
}

fn build_and_sign_genesis(
    chain_id: ChainId,
    executor: Executor,
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    wasm_triggers: Vec<GenesisWasmTrigger>,
    topology: Vec<PeerId>,
    genesis_key_pair: &KeyPair,
) -> GenesisBlock {
    let transactions = build_transactions(
        chain_id,
        executor,
        parameters,
        instructions,
        wasm_triggers,
        topology,
        genesis_key_pair,
    );
    let block = SignedBlock::genesis(transactions, genesis_key_pair.private_key());
    GenesisBlock(block)
}

fn build_transactions(
    chain_id: ChainId,
    executor: Executor,
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    wasm_triggers: Vec<GenesisWasmTrigger>,
    topology: Vec<PeerId>,
    genesis_key_pair: &KeyPair,
) -> Vec<SignedTransaction> {
    let upgrade_isi = Upgrade::new(executor).into();
    let transaction_executor =
        build_transaction(vec![upgrade_isi], chain_id.clone(), genesis_key_pair);
    let mut transactions = vec![transaction_executor];
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
        let transaction_instructions =
            build_transaction(instructions, chain_id.clone(), genesis_key_pair);
        transactions.push(transaction_instructions);
    }
    if !wasm_triggers.is_empty() {
        let register_wasm_triggers = build_transaction(
            wasm_triggers
                .into_iter()
                .map(Into::into)
                .map(Register::trigger)
                .map(InstructionBox::from)
                .collect(),
            chain_id.clone(),
            genesis_key_pair,
        );
        transactions.push(register_wasm_triggers);
    }
    if !topology.is_empty() {
        let register_peers = build_transaction(
            topology
                .into_iter()
                .map(Peer::new)
                .map(Register::peer)
                .map(InstructionBox::from)
                .collect(),
            chain_id,
            genesis_key_pair,
        );
        transactions.push(register_peers)
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

/// Builder type for [`GenesisBlock`]/[`RawGenesisTransaction`].
///
/// that does not perform any correctness checking on the block produced.
/// Use with caution in tests and other things to register domains and accounts.
#[must_use]
pub struct GenesisBuilder {
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    wasm_triggers: Vec<GenesisWasmTrigger>,
}

/// `Domain` subsection of the [`GenesisBuilder`]. Makes
/// it easier to create accounts and assets without needing to
/// provide a `DomainId`.
#[must_use]
pub struct GenesisDomainBuilder {
    parameters: Vec<Parameter>,
    instructions: Vec<InstructionBox>,
    wasm_triggers: Vec<GenesisWasmTrigger>,
    domain_id: DomainId,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        // Register a trigger that reacts to domain creation (or owner changes) and registers (or replaces) a multisig accounts registry for the domain
        let multisig_domains_initializer = GenesisWasmTrigger::new(
            "multisig_domains".parse().unwrap(),
            GenesisWasmAction::new(
                "../wasm/target/prebuilt/libs/multisig_domains.wasm",
                Repeats::Indefinitely,
                SYSTEM_ACCOUNT_ID.clone(),
                DomainEventFilter::new()
                    .for_events(DomainEventSet::Created | DomainEventSet::OwnerChanged),
            ),
        );
        let instructions = vec![
            Register::domain(Domain::new(SYSTEM_DOMAIN_ID.clone())).into(),
            Register::account(Account::new(SYSTEM_ACCOUNT_ID.clone())).into(),
            // Allow the initializer to register and replace a multisig accounts registry for any domain
            Grant::account_permission(CanRegisterAnyTrigger, SYSTEM_ACCOUNT_ID.clone()).into(),
            Grant::account_permission(CanUnregisterAnyTrigger, SYSTEM_ACCOUNT_ID.clone()).into(),
        ];

        Self {
            parameters: Vec::default(),
            instructions,
            wasm_triggers: vec![multisig_domains_initializer],
        }
    }
}

#[allow(dead_code)]
#[cfg(test)]
const N_DEFAULT_INSTRUCTIONS: usize = 4;

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
            parameters: self.parameters,
            instructions: self.instructions,
            wasm_triggers: self.wasm_triggers,
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

    /// Add wasm trigger to the end of registration list
    pub fn append_wasm_trigger(mut self, wasm_trigger: GenesisWasmTrigger) -> Self {
        self.wasm_triggers.push(wasm_trigger);
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
            chain_id,
            executor_blob,
            self.parameters,
            self.instructions,
            self.wasm_triggers,
            topology,
            genesis_key_pair,
        )
    }

    /// Finish building and produce a [`RawGenesisTransaction`].
    pub fn build_raw(
        self,
        chain_id: ChainId,
        executor_file: impl Into<WasmPath>,
        topology: Vec<PeerId>,
    ) -> RawGenesisTransaction {
        RawGenesisTransaction {
            chain: chain_id,
            executor: executor_file.into(),
            topology,
            parameters: convert_parameters(self.parameters),
            instructions: self.instructions,
            wasm_triggers: self.wasm_triggers,
        }
    }
}

impl GenesisDomainBuilder {
    /// Finish this domain and return to
    /// genesis block building.
    pub fn finish_domain(self) -> GenesisBuilder {
        GenesisBuilder {
            parameters: self.parameters,
            instructions: self.instructions,
            wasm_triggers: self.wasm_triggers,
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

fn convert_parameters(parameters: Vec<Parameter>) -> Option<Parameters> {
    if parameters.is_empty() {
        return None;
    }
    let mut result = Parameters::default();
    for parameter in parameters {
        result.set_parameter(parameter);
    }

    Some(result)
}

impl Encode for WasmPath {
    fn encode(&self) -> Vec<u8> {
        self.0
            .to_str()
            .expect("path contains not valid UTF-8")
            .encode()
    }
}

impl Decode for WasmPath {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> std::result::Result<Self, parity_scale_codec::Error> {
        String::decode(input).map(PathBuf::from).map(WasmPath)
    }
}

impl From<PathBuf> for WasmPath {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

/// Human-readable alternative to [`Trigger`] whose action has wasm executable
#[derive(Debug, Clone, Serialize, Deserialize, IntoSchema, Encode, Decode, Constructor)]
pub struct GenesisWasmTrigger {
    id: TriggerId,
    action: GenesisWasmAction,
}

/// Human-readable alternative to [`Action`] which has wasm executable
#[derive(Debug, Clone, Serialize, Deserialize, IntoSchema, Encode, Decode)]
pub struct GenesisWasmAction {
    /// Path to the wasm crate relative to `defaults/genesis.json`
    executable: WasmPath,
    repeats: Repeats,
    authority: AccountId,
    filter: EventFilterBox,
}

impl GenesisWasmAction {
    /// Construct [`GenesisWasmAction`]
    pub fn new(
        executable: impl Into<PathBuf>,
        repeats: impl Into<Repeats>,
        authority: AccountId,
        filter: impl Into<EventFilterBox>,
    ) -> Self {
        Self {
            executable: executable.into().into(),
            repeats: repeats.into(),
            authority,
            filter: filter.into(),
        }
    }
}

impl From<GenesisWasmTrigger> for Trigger {
    fn from(src: GenesisWasmTrigger) -> Self {
        Trigger::new(src.id, src.action.into())
    }
}

impl From<GenesisWasmAction> for Action {
    fn from(src: GenesisWasmAction) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/")
            .join(src.executable.0)
            .canonicalize()
            .expect("wasm executable path should be correctly specified");
        let executable = load_library_wasm(path);
        Action::new(executable, src.repeats, src.authority, src.filter)
    }
}

fn read_file(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let mut blob = vec![];
    std::fs::File::open(path.as_ref())?.read_to_end(&mut blob)?;
    Ok(blob)
}

fn load_library_wasm(path: impl AsRef<Path>) -> WasmSmartContract {
    match read_file(&path) {
        Err(err) => {
            let name = path.as_ref().file_stem().unwrap().to_str().unwrap();
            let path = path.as_ref().display();
            eprintln!(
                "ERROR: Could not load library WASM `{name}` from `{path}`: {err}\n\
                    There are two possible reasons why:\n\
                    1. You haven't pre-built WASM libraries before building genesis block. Make sure to run `build_wasm.sh` first.\n\
                    2. `{path}` is not a valid path",
            );
            panic!("could not build WASM, see the message above");
        }
        Ok(blob) => WasmSmartContract::from_compiled(blob),
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use iroha_test_samples::{ALICE_KEYPAIR, BOB_KEYPAIR};

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
            // FIXME field `value` of struct `CommittedTransaction` is private
            let instructions = transaction.as_ref().instructions();
            let Executable::Instructions(instructions) = instructions else {
                panic!("Expected instructions");
            };

            assert_eq!(instructions[0], Upgrade::new(dummy_executor()).into());
            assert_eq!(instructions.len(), 1);
        }

        // Second transaction
        let transaction = transactions[1];
        let instructions = transaction.as_ref().instructions();
        let Executable::Instructions(instructions) = instructions else {
            panic!("Expected instructions");
        };
        let offset = N_DEFAULT_INSTRUCTIONS;

        {
            let domain_id: DomainId = "wonderland".parse().unwrap();
            assert_eq!(
                instructions[offset],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[offset + 1],
                Register::account(Account::new(AccountId::new(
                    domain_id.clone(),
                    public_key["alice"].clone()
                ),))
                .into()
            );
            assert_eq!(
                instructions[offset + 2],
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
                instructions[offset + 3],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[offset + 4],
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
                instructions[offset + 5],
                Register::domain(Domain::new(domain_id.clone())).into()
            );
            assert_eq!(
                instructions[offset + 6],
                Register::account(Account::new(AccountId::new(
                    domain_id,
                    public_key["mad_hatter"].clone()
                ),))
                .into()
            );
            assert_eq!(
                instructions[offset + 7],
                Register::asset_definition(AssetDefinition::numeric(
                    "hats#meadow".parse().unwrap(),
                ))
                .into()
            );
        }
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
              "wasm_triggers": [],
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
