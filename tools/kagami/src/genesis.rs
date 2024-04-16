use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{ArgGroup, Parser, Subcommand};
use color_eyre::{
    eyre::{eyre, WrapErr as _},
    Result,
};
use iroha_config::parameters::defaults::chain_wide::{
    DEFAULT_BLOCK_TIME, DEFAULT_COMMIT_TIME, DEFAULT_IDENT_LENGTH_LIMITS, DEFAULT_MAX_TXS,
    DEFAULT_METADATA_LIMITS, DEFAULT_TRANSACTION_LIMITS, DEFAULT_WASM_FUEL_LIMIT,
    DEFAULT_WASM_MAX_MEMORY_BYTES,
};
use iroha_crypto::{KeyPair, PrivateKey};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetValueType},
    metadata::Limits,
    parameter::{default::*, ParametersBuilder},
    prelude::AssetId,
    ChainId,
};
use iroha_genesis::{
    executor_state, GenesisNetwork, RawGenesisBlock, RawGenesisBlockBuilder, RawGenesisBlockFile,
};
use parity_scale_codec::Encode;
use serde_json::json;

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum Args {
    Generate(GenerateArgs),
    Sign(SignArgs),
}

/// Use `Kagami` to generate genesis block
#[derive(Parser, Debug, Clone)]
pub struct GenerateArgs {
    /// Specifies the `executor_file` <PATH> that will be inserted into the genesis JSON as-is.
    #[clap(long, value_name = "PATH")]
    executor_path_in_genesis: PathBuf,
    #[clap(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand, Debug, Clone, Default)]
pub enum Mode {
    /// Generate default genesis
    #[default]
    Default,
    /// Generate synthetic genesis with the specified number of domains, accounts and assets.
    ///
    /// Synthetic mode is useful when we need a semi-realistic genesis for stress-testing
    /// Iroha's startup times as well as being able to just start an Iroha network and have
    /// instructions that represent a typical blockchain after migration.
    Synthetic {
        /// Number of domains in synthetic genesis.
        #[clap(long, default_value_t)]
        domains: u64,
        /// Number of accounts per domains in synthetic genesis.
        /// The total number of accounts would be `domains * assets_per_domain`.
        #[clap(long, default_value_t)]
        accounts_per_domain: u64,
        /// Number of assets per domains in synthetic genesis.
        /// The total number of assets would be `domains * assets_per_domain`.
        #[clap(long, default_value_t)]
        assets_per_domain: u64,
    },
}

impl<T: Write> RunArgs<T> for GenerateArgs {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let Self {
            executor_path_in_genesis,
            mode,
        } = self;

        let builder = RawGenesisBlockBuilder::default().executor_file(executor_path_in_genesis);
        let genesis = match mode.unwrap_or_default() {
            Mode::Default => generate_default(builder),
            Mode::Synthetic {
                domains,
                accounts_per_domain,
                assets_per_domain,
            } => generate_synthetic(builder, domains, accounts_per_domain, assets_per_domain),
        }?;
        writeln!(writer, "{}", serde_json::to_string_pretty(&genesis)?)
            .wrap_err("failed to write serialized genesis to the buffer")
    }
}

#[allow(clippy::too_many_lines)]
pub fn generate_default(
    builder: RawGenesisBlockBuilder<executor_state::SetPath>,
) -> color_eyre::Result<RawGenesisBlockFile> {
    let mut meta = Metadata::new();
    meta.insert_with_limits("key".parse()?, "value".to_owned(), Limits::new(1024, 1024))?;

    let mut genesis = builder
        .domain_with_metadata("wonderland".parse()?, meta.clone())
        .account_with_metadata(
            "alice".parse()?,
            crate::DEFAULT_PUBLIC_KEY.parse()?,
            meta.clone(),
        )
        .account_with_metadata("bob".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?, meta)
        .asset(
            "rose".parse()?,
            AssetValueType::Numeric(NumericSpec::default()),
        )
        .finish_domain()
        .domain("garden_of_live_flowers".parse()?)
        .account("carpenter".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
        .asset(
            "cabbage".parse()?,
            AssetValueType::Numeric(NumericSpec::default()),
        )
        .finish_domain()
        .build();

    let alice_id = AccountId::from_str("alice@wonderland")?;
    let mint = Mint::asset_numeric(
        13u32,
        AssetId::new("rose#wonderland".parse()?, alice_id.clone()),
    );
    let mint_cabbage = Mint::asset_numeric(
        44u32,
        AssetId::new("cabbage#garden_of_live_flowers".parse()?, alice_id.clone()),
    );
    let grant_permission_to_set_parameters = Grant::permission(
        PermissionToken::new("CanSetParameters".parse()?, &json!(null)),
        alice_id.clone(),
    );
    let transfer_domain_ownerhip = Transfer::domain(
        "genesis@genesis".parse()?,
        "wonderland".parse()?,
        alice_id.clone(),
    );
    let register_user_metadata_access = Register::role(
        Role::new("ALICE_METADATA_ACCESS".parse()?)
            .add_permission(PermissionToken::new(
                "CanSetKeyValueInAccount".parse()?,
                &json!({ "account_id": alice_id }),
            ))
            .add_permission(PermissionToken::new(
                "CanRemoveKeyValueInAccount".parse()?,
                &json!({ "account_id": alice_id }),
            )),
    )
    .into();

    let parameter_defaults = ParametersBuilder::new()
        .add_parameter(
            MAX_TRANSACTIONS_IN_BLOCK,
            Numeric::new(DEFAULT_MAX_TXS.get().into(), 0),
        )?
        .add_parameter(BLOCK_TIME, Numeric::new(DEFAULT_BLOCK_TIME.as_millis(), 0))?
        .add_parameter(
            COMMIT_TIME_LIMIT,
            Numeric::new(DEFAULT_COMMIT_TIME.as_millis(), 0),
        )?
        .add_parameter(TRANSACTION_LIMITS, DEFAULT_TRANSACTION_LIMITS)?
        .add_parameter(WSV_DOMAIN_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(
            WSV_ASSET_DEFINITION_METADATA_LIMITS,
            DEFAULT_METADATA_LIMITS,
        )?
        .add_parameter(WSV_ACCOUNT_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(WSV_ASSET_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(WSV_TRIGGER_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(WSV_IDENT_LENGTH_LIMITS, DEFAULT_IDENT_LENGTH_LIMITS)?
        .add_parameter(
            EXECUTOR_FUEL_LIMIT,
            Numeric::new(DEFAULT_WASM_FUEL_LIMIT.into(), 0),
        )?
        .add_parameter(
            EXECUTOR_MAX_MEMORY,
            Numeric::new(DEFAULT_WASM_MAX_MEMORY_BYTES.into(), 0),
        )?
        .add_parameter(
            WASM_FUEL_LIMIT,
            Numeric::new(DEFAULT_WASM_FUEL_LIMIT.into(), 0),
        )?
        .add_parameter(
            WASM_MAX_MEMORY,
            Numeric::new(DEFAULT_WASM_MAX_MEMORY_BYTES.into(), 0),
        )?
        .into_create_parameters();

    let first_tx = genesis
        .first_transaction_mut()
        .expect("At least one transaction is expected");
    for isi in [
        mint.into(),
        mint_cabbage.into(),
        transfer_domain_ownerhip.into(),
        grant_permission_to_set_parameters.into(),
    ]
    .into_iter()
    .chain(parameter_defaults.into_iter())
    .chain(std::iter::once(register_user_metadata_access))
    {
        first_tx.push_instruction(isi);
    }

    Ok(genesis)
}

fn generate_synthetic(
    builder: RawGenesisBlockBuilder<executor_state::SetPath>,
    domains: u64,
    accounts_per_domain: u64,
    assets_per_domain: u64,
) -> color_eyre::Result<RawGenesisBlockFile> {
    // Synthetic genesis is extension of default one
    let mut genesis = generate_default(builder)?;

    let first_transaction = genesis
        .first_transaction_mut()
        .expect("transaction must exist");

    for domain in 0..domains {
        let domain_id: DomainId = format!("domain_{domain}").parse()?;
        first_transaction.push_instruction(Register::domain(Domain::new(domain_id.clone())).into());

        for account in 0..accounts_per_domain {
            let (public_key, _) = iroha_crypto::KeyPair::random().into_parts();
            let account_id: AccountId = format!("account_{account}@{domain_id}").parse()?;
            first_transaction.push_instruction(
                Register::account(Account::new(account_id.clone(), public_key)).into(),
            );
        }

        for asset in 0..assets_per_domain {
            let asset_definition_id: AssetDefinitionId =
                format!("asset_{asset}#{domain_id}").parse()?;
            first_transaction.push_instruction(
                Register::asset_definition(AssetDefinition::new(
                    asset_definition_id,
                    AssetValueType::Numeric(NumericSpec::default()),
                ))
                .into(),
            );
        }
    }

    for domain in 0..domains {
        for account in 0..accounts_per_domain {
            // FIXME: it actually generates (assets_per_domain * accounts_per_domain) assets per domain
            //        https://github.com/hyperledger/iroha/issues/3508
            for asset in 0..assets_per_domain {
                let mint = Mint::asset_numeric(
                    13u32,
                    AssetId::new(
                        format!("asset_{asset}#domain_{domain}").parse()?,
                        format!("account_{account}@domain_{domain}").parse()?,
                    ),
                )
                .into();
                first_transaction.push_instruction(mint);
            }
        }
    }

    Ok(genesis)
}

/// Use `Kagami` to sign genesis block.
#[derive(ClapArgs, Clone, Debug)]
#[command(group = ArgGroup::new("private_key").required(true))]
#[command(group = ArgGroup::new("public_key").required(true))]
#[command(group = ArgGroup::new("format").required(false))]
pub struct SignArgs {
    /// The algorithm of the provided keypair
    #[clap(default_value_t, long, short)]
    algorithm: crypto::AlgorithmArg,
    /// Private key (in hex string format) to sign genesis block
    #[clap(long, group = "private_key")]
    private_key_string: Option<String>,
    /// Path to private key to sign genesis block
    #[clap(long, group = "private_key")]
    private_key_file: Option<PathBuf>,
    /// Public key in multihash format of the corresponding private key
    #[clap(long, group = "public_key")]
    public_key_string: Option<PublicKey>,
    /// Path to public key in multihash format of the corresponding private key
    #[clap(long, group = "public_key")]
    public_key_file: Option<PathBuf>,
    /// Path to json-serialized keypair
    #[clap(long, short, group = "private_key", group = "public_key")]
    keypair_file: Option<PathBuf>,
    /// Unique id of blockchain
    #[clap(long)]
    chain_id: ChainId,
    /// Path to genesis json file
    #[clap(long, short)]
    genesis_file: PathBuf,
    /// Output signed genesis config as a hex string
    #[clap(long, default_value_t = true, group = "format")]
    hex: bool,
    /// Encode signed genesis block with SCALE (it is only supported with file output)
    #[clap(long, default_value_t = false, group = "format")]
    scale: bool,
    /// Path to signed genesis output file (stdout by default)
    #[clap(long, short)]
    out_file: Option<PathBuf>,
}

#[derive(Debug)]
enum KeyStorage<'a> {
    FromFile(Vec<u8>),
    FromCLI(&'a str),
}

fn get_key_raw<'a, P: AsRef<Path>>(
    path: &Option<P>,
    value: &'a Option<String>,
) -> Result<KeyStorage<'a>, std::io::Error> {
    match (path, value) {
        (Some(path_buf), None) => Ok(KeyStorage::FromFile(fs::read(path_buf)?)),
        (None, Some(hex)) => Ok(KeyStorage::FromCLI(hex.as_str())),
        _ => unreachable!("Clap group invariant"),
    }
}

fn read_keypair<P: AsRef<Path>>(path: P) -> Result<KeyPair> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(bytes.as_slice())?)
}

impl SignArgs {
    fn get_private_key(&self) -> Result<PrivateKey> {
        let private_key_bytes = get_key_raw(&self.private_key_file, &self.private_key_string)?;
        match private_key_bytes {
            KeyStorage::FromFile(bytes) => {
                PrivateKey::from_bytes(self.algorithm.0, bytes.as_slice()).wrap_err_with(|| {
                    eyre!(
                        "Failed to parse private key from bytes for algorithm `{}`",
                        self.algorithm
                    )
                })
            }
            KeyStorage::FromCLI(hex) => {
                PrivateKey::from_hex(self.algorithm.0, hex).wrap_err_with(|| {
                    eyre!(
                        "Failed to parse private key from hex for algorithm `{}`",
                        self.algorithm
                    )
                })
            }
        }
    }

    fn get_public_key(&self) -> Result<PublicKey> {
        if let Some(key) = &self.public_key_string {
            return Ok(key.clone());
        }
        let public_key_bytes = get_key_raw(&self.public_key_file, &None)?;
        match public_key_bytes {
            KeyStorage::FromFile(bytes) => {
                PublicKey::from_bytes(self.algorithm.0, bytes.as_slice()).wrap_err_with(|| {
                    eyre!(
                        "Failed to parse public key from bytes for algorithm `{}`",
                        self.algorithm
                    )
                })
            }
            KeyStorage::FromCLI(multihash_string) => PublicKey::from_str(multihash_string)
                .wrap_err_with(|| {
                    eyre!(
                        "Failed to deserialize public key from multihash string for algorithm `{}`",
                        self.algorithm
                    )
                }),
        }
    }
}

impl<T: Write> RunArgs<T> for SignArgs {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let key_pair = if let Some(path) = self.keypair_file {
            read_keypair(path)?
        } else {
            let (public_key, private_key) = (self.get_public_key()?, self.get_private_key()?);
            KeyPair::new(public_key, private_key)?
        };

        let genesis_block = RawGenesisBlock::from_path(&self.genesis_file)?;
        let genesis_signature =
            GenesisNetwork::new_genesis_signature(genesis_block, &self.chain_id, &key_pair);
        let genesis_signature_string = genesis_signature.to_hex_string();

        let encoded_genesis_signature = if self.scale {
            genesis_signature_string.encode()
        } else {
            Vec::default()
        };

        let hex_genesis_config = if self.hex {
            genesis_signature_string
        } else {
            String::default()
        };

        if let Some(path) = self.out_file {
            if self.scale {
                fs::write(&path, encoded_genesis_signature)?;
            } else {
                fs::write(&path, hex_genesis_config)?;
            }

            writeln!(
                writer,
                "Genesis was successfully signed and written to `{}`",
                path.display()
            )?;
        } else if self.scale {
            writeln!(
                writer,
                "SCALE encoded data is not supported for console outputs."
            )?;
        } else {
            writeln!(writer, "{hex_genesis_config}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use iroha_genesis::{GenesisSignature, GenesisTransaction};

    use super::*;
    use crate::crypto::AlgorithmArg;

    const GENESIS_JSON_PATH: &str = "../../configs/swarm/genesis.json";

    fn genesis_signing_works() -> Result<bool> {
        let keypair_config = crypto::Args {
            algorithm: AlgorithmArg::default(),
            private_key: None,
            seed: None,
            json: true,
            compact: false,
        };

        let mut keypair_json = BufWriter::new(Vec::new());
        keypair_config.run(&mut keypair_json)?;
        let keypair: KeyPair = serde_json::from_slice(keypair_json.buffer())?;

        let tmp_keypair_json_file = tempfile::NamedTempFile::new()?;
        fs::write(tmp_keypair_json_file.path(), keypair_json.buffer())?;

        let chain_id = ChainId::from("0123456");
        let crypto_genesis_config = SignArgs {
            algorithm: AlgorithmArg::default(),
            private_key_string: None,
            private_key_file: None,
            public_key_string: None,
            public_key_file: None,
            keypair_file: Some(PathBuf::from(tmp_keypair_json_file.path())),
            chain_id: chain_id.clone(),
            genesis_file: PathBuf::from_str(GENESIS_JSON_PATH)?,
            out_file: None,
            scale: false,
            hex: true,
        };

        let mut genesis_buf_writer = BufWriter::new(Vec::new());

        crypto_genesis_config.run(&mut genesis_buf_writer)?;

        let mut encoded_genesis_signature = genesis_buf_writer.buffer().to_owned();
        encoded_genesis_signature.pop();

        let decoded_signed_genesis_config =
            GenesisSignature::from_hex_string(&encoded_genesis_signature)?;

        let raw_genesis = RawGenesisBlock::from_path(GENESIS_JSON_PATH)?;
        let signed_genesis_manually =
            GenesisTransaction::new_unified(raw_genesis.clone(), &chain_id, &keypair);
        let signed_genesis_from_config =
            &GenesisNetwork::try_parse(raw_genesis, decoded_signed_genesis_config)?
                .into_transaction();

        let cmp = |a: &SignedTransaction, b: &SignedTransaction| {
            a.metadata() == b.metadata()
                && a.authority() == b.authority()
                && a.chain_id() == b.chain_id()
                && a.time_to_live() == b.time_to_live()
                && a.instructions() == b.instructions()
                && a.nonce() == b.nonce()
                && a.signatures() == b.signatures()
        };
        Ok(cmp(
            &signed_genesis_from_config.0,
            &signed_genesis_manually.0,
        ))
    }

    #[test]
    fn test_genesis_signing_works() {
        let result = genesis_signing_works();
        assert!(result.is_ok_and(|result| result));
    }
}
