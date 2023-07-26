use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand};
use iroha_config::{sumeragi::default::*, wasm::default::*, wsv::default::*};
use iroha_data_model::{
    asset::AssetValueType,
    isi::{MintBox, RegisterBox},
    metadata::Limits,
    parameter::{default::*, ParametersBuilder},
    prelude::AssetId,
    validator::Validator,
    IdBox,
};
use iroha_genesis::{RawGenesisBlock, RawGenesisBlockBuilder, ValidatorMode, ValidatorPath};
use serde_json::json;

use super::*;

#[derive(Parser, Debug, Clone)]
#[clap(group = ArgGroup::new("validator").required(true))]
pub struct Args {
    /// If this option provided validator will be inlined in the genesis.
    #[clap(long, group = "validator")]
    inlined_validator: bool,
    /// If this option provided validator won't be included in the genesis and only path to the validator will be included.
    /// Path is either absolute path to validator or relative to genesis location.
    /// Validator can be generated using `kagami validator` command.
    #[clap(long, group = "validator")]
    compiled_validator_path: Option<PathBuf>,
    #[clap(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand, Debug, Clone, Default)]
pub enum Mode {
    /// Generate default genesis
    #[default]
    Default,
    /// Generate synthetic genesis with specified number of domains, accounts and assets.
    ///
    /// Synthetic mode is useful when we need a semi-realistic genesis for stress-testing
    /// Iroha's startup times as well as being able to just start an Iroha network and have
    /// instructions that represent a typical blockchain after migration.
    Synthetic {
        /// Number of domains in synthetic genesis.
        #[clap(long, default_value_t)]
        domains: u64,
        /// Number of accounts per domains in synthetic genesis.
        /// Total number of  accounts would be `domains * assets_per_domain`.
        #[clap(long, default_value_t)]
        accounts_per_domain: u64,
        /// Number of assets per domains in synthetic genesis.
        /// Total number of assets would be `domains * assets_per_domain`.
        #[clap(long, default_value_t)]
        assets_per_domain: u64,
    },
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        if self.inlined_validator {
            eprintln!("WARN: You're using genesis with inlined validator.");
            eprintln!(
                "Consider providing validator in separate file `--compiled-validator-path PATH`."
            );
            eprintln!("Use `--help` to get more information.");
        }
        let validator_path = self.compiled_validator_path;
        let genesis = match self.mode.unwrap_or_default() {
            Mode::Default => generate_default(validator_path),
            Mode::Synthetic {
                domains,
                accounts_per_domain,
                assets_per_domain,
            } => generate_synthetic(
                validator_path,
                domains,
                accounts_per_domain,
                assets_per_domain,
            ),
        }?;
        writeln!(writer, "{}", serde_json::to_string_pretty(&genesis)?)
            .wrap_err("Failed to write serialized genesis to the buffer.")
    }
}

#[allow(clippy::too_many_lines)]
pub fn generate_default(validator_path: Option<PathBuf>) -> color_eyre::Result<RawGenesisBlock> {
    let mut meta = Metadata::new();
    meta.insert_with_limits(
        "key".parse()?,
        "value".to_owned().into(),
        Limits::new(1024, 1024),
    )?;

    let validator = match validator_path {
        Some(validator_path) => ValidatorMode::Path(ValidatorPath(validator_path)),
        None => ValidatorMode::Inline(construct_validator()?),
    };

    let mut genesis = RawGenesisBlockBuilder::new()
            .domain_with_metadata("wonderland".parse()?, meta.clone())
            .account_with_metadata(
                "alice".parse()?,
                crate::DEFAULT_PUBLIC_KEY.parse()?,
                meta.clone(),
            )
            .account_with_metadata("bob".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?, meta) // TODO: This should fail under SS58
            .asset("rose".parse()?, AssetValueType::Quantity)
            .finish_domain()
            .domain("garden_of_live_flowers".parse()?)
            .account("carpenter".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
            .asset("cabbage".parse()?, AssetValueType::Quantity)
            .finish_domain()
            .validator(validator)
            .build();

    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let mint = MintBox::new(
        13_u32.to_value(),
        IdBox::AssetId(AssetId::new("rose#wonderland".parse()?, alice_id.clone())),
    );
    let mint_cabbage = MintBox::new(
        44_u32.to_value(),
        IdBox::AssetId(AssetId::new(
            "cabbage#garden_of_live_flowers".parse()?,
            alice_id.clone(),
        )),
    );
    let grant_permission_to_set_parameters = GrantBox::new(
        PermissionToken::new("CanSetParameters".parse()?, &json!(null)),
        alice_id.clone(),
    );
    let register_user_metadata_access = RegisterBox::new(
        Role::new("ALICE_METADATA_ACCESS".parse()?)
            .add_permission(PermissionToken::new(
                "CanSetKeyValueInUserAccount".parse()?,
                &json!({ "account_id": alice_id }),
            ))
            .add_permission(PermissionToken::new(
                "CanRemoveKeyValueInUserAccount".parse()?,
                &json!({ "account_id": alice_id }),
            )),
    )
    .into();

    let parameter_defaults = ParametersBuilder::new()
        .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, DEFAULT_MAX_TRANSACTIONS_IN_BLOCK)?
        .add_parameter(BLOCK_TIME, DEFAULT_BLOCK_TIME_MS)?
        .add_parameter(COMMIT_TIME_LIMIT, DEFAULT_COMMIT_TIME_LIMIT_MS)?
        .add_parameter(TRANSACTION_LIMITS, DEFAULT_TRANSACTION_LIMITS)?
        .add_parameter(WSV_ASSET_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(
            WSV_ASSET_DEFINITION_METADATA_LIMITS,
            DEFAULT_METADATA_LIMITS.to_value(),
        )?
        .add_parameter(WSV_ACCOUNT_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(WSV_DOMAIN_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
        .add_parameter(WSV_IDENT_LENGTH_LIMITS, DEFAULT_IDENT_LENGTH_LIMITS)?
        .add_parameter(WASM_FUEL_LIMIT, DEFAULT_FUEL_LIMIT)?
        .add_parameter(WASM_MAX_MEMORY, DEFAULT_MAX_MEMORY)?
        .into_create_parameters();

    let first_tx = genesis
        .first_transaction_mut()
        .expect("At least one transaction is expected");
    for isi in [
        mint.into(),
        mint_cabbage.into(),
        grant_permission_to_set_parameters.into(),
        parameter_defaults.into(),
        register_user_metadata_access,
    ] {
        first_tx.append_instruction(isi);
    }

    Ok(genesis)
}

fn construct_validator() -> color_eyre::Result<Validator> {
    let temp_dir = tempfile::tempdir()
        .wrap_err("Failed to generate a tempdir for validator sources")?
        .into_path();
    let path = super::validator::compute_validator_path(temp_dir)?;
    let wasm_blob = super::validator::construct_validator(path)?;
    Ok(Validator::new(WasmSmartContract::from_compiled(wasm_blob)))
}

fn generate_synthetic(
    validator_path: Option<PathBuf>,
    domains: u64,
    accounts_per_domain: u64,
    assets_per_domain: u64,
) -> color_eyre::Result<RawGenesisBlock> {
    let validator = match validator_path {
        Some(validator_path) => ValidatorMode::Path(ValidatorPath(validator_path)),
        None => ValidatorMode::Inline(construct_validator()?),
    };

    // Add default `Domain` and `Account` to still be able to query
    let mut builder = RawGenesisBlockBuilder::new()
        .domain("wonderland".parse()?)
        .account("alice".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
        .finish_domain();

    for domain in 0..domains {
        let mut domain_builder = builder.domain(format!("domain_{domain}").parse()?);

        for account in 0..accounts_per_domain {
            let (public_key, _) = iroha_crypto::KeyPair::generate()?.into();
            domain_builder =
                domain_builder.account(format!("account_{account}").parse()?, public_key);
        }

        for asset in 0..assets_per_domain {
            domain_builder =
                domain_builder.asset(format!("asset_{asset}").parse()?, AssetValueType::Quantity);
        }

        builder = domain_builder.finish_domain();
    }
    let mut genesis = builder.validator(validator).build();

    let first_transaction = genesis
        .first_transaction_mut()
        .expect("At least one transaction is expected");
    for domain in 0..domains {
        for account in 0..accounts_per_domain {
            // FIXME: it actually generates (assets_per_domain * accounts_per_domain) assets per domain
            //        https://github.com/hyperledger/iroha/issues/3508
            for asset in 0..assets_per_domain {
                let mint = MintBox::new(
                    13_u32.to_value(),
                    IdBox::AssetId(AssetId::new(
                        format!("asset_{asset}#domain_{domain}").parse()?,
                        format!("account_{account}@domain_{domain}").parse()?,
                    )),
                )
                .into();
                first_transaction.append_instruction(mint);
            }
        }
    }

    Ok(genesis)
}
