use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use color_eyre::eyre::WrapErr as _;
use iroha_data_model::{isi::InstructionBox, parameter::Parameters, prelude::*};
use iroha_executor_data_model::permission::{
    account::{CanRemoveKeyValueInAccount, CanSetKeyValueInAccount},
    parameter::CanSetParameters,
};
use iroha_genesis::{GenesisBuilder, RawGenesisTransaction, GENESIS_DOMAIN_ID};
use test_samples::{gen_account_in, ALICE_ID, BOB_ID, CARPENTER_ID};

use crate::{Outcome, RunArgs};

/// Generate the genesis block that is used in tests
#[derive(Parser, Debug, Clone)]
pub struct Args {
    /// Specifies the `executor_file` <PATH> that will be inserted into the genesis JSON as-is.
    #[clap(long, value_name = "PATH")]
    executor_path_in_genesis: PathBuf,
    #[clap(long, value_name = "MULTI_HASH")]
    genesis_public_key: PublicKey,
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

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let Self {
            executor_path_in_genesis,
            genesis_public_key,
            mode,
        } = self;

        let builder = GenesisBuilder::default();
        let genesis = match mode.unwrap_or_default() {
            Mode::Default => {
                generate_default(builder, executor_path_in_genesis, genesis_public_key)
            }
            Mode::Synthetic {
                domains,
                accounts_per_domain,
                assets_per_domain,
            } => generate_synthetic(
                builder,
                executor_path_in_genesis,
                genesis_public_key,
                domains,
                accounts_per_domain,
                assets_per_domain,
            ),
        }?;
        writeln!(writer, "{}", serde_json::to_string_pretty(&genesis)?)
            .wrap_err("failed to write serialized genesis to the buffer")
    }
}

#[allow(clippy::too_many_lines)]
pub fn generate_default(
    builder: GenesisBuilder,
    executor_path: PathBuf,
    genesis_public_key: PublicKey,
) -> color_eyre::Result<RawGenesisTransaction> {
    let genesis_account_id = AccountId::new(GENESIS_DOMAIN_ID.clone(), genesis_public_key);
    let mut meta = Metadata::default();
    meta.insert("key".parse()?, JsonString::new("value"));

    let mut builder = builder
        .domain_with_metadata("wonderland".parse()?, meta.clone())
        .account_with_metadata(ALICE_ID.signatory().clone(), meta.clone())
        .account_with_metadata(BOB_ID.signatory().clone(), meta)
        .asset("rose".parse()?, AssetType::Numeric(NumericSpec::default()))
        .finish_domain()
        .domain("garden_of_live_flowers".parse()?)
        .account(CARPENTER_ID.signatory().clone())
        .asset(
            "cabbage".parse()?,
            AssetType::Numeric(NumericSpec::default()),
        )
        .finish_domain();

    let mint = Mint::asset_numeric(
        13u32,
        AssetId::new("rose#wonderland".parse()?, ALICE_ID.clone()),
    );
    let mint_cabbage = Mint::asset_numeric(
        44u32,
        AssetId::new("cabbage#garden_of_live_flowers".parse()?, ALICE_ID.clone()),
    );
    let grant_permission_to_set_parameters =
        Grant::account_permission(CanSetParameters, ALICE_ID.clone());
    let transfer_rose_ownership = Transfer::asset_definition(
        genesis_account_id.clone(),
        "rose#wonderland".parse()?,
        ALICE_ID.clone(),
    );
    let transfer_wonderland_ownership = Transfer::domain(
        genesis_account_id.clone(),
        "wonderland".parse()?,
        ALICE_ID.clone(),
    );
    let register_user_metadata_access: InstructionBox = Register::role(
        Role::new("ALICE_METADATA_ACCESS".parse()?)
            .add_permission(CanSetKeyValueInAccount {
                account: ALICE_ID.clone(),
            })
            .add_permission(CanRemoveKeyValueInAccount {
                account: ALICE_ID.clone(),
            }),
    )
    .into();

    let parameters = Parameters::default();
    let set_parameters = parameters
        .parameters()
        .map(SetParameter)
        .map(InstructionBox::from);

    for isi in [
        mint.into(),
        mint_cabbage.into(),
        transfer_rose_ownership.into(),
        transfer_wonderland_ownership.into(),
        grant_permission_to_set_parameters.into(),
    ]
    .into_iter()
    .chain(std::iter::once(register_user_metadata_access))
    .chain(set_parameters)
    {
        builder = builder.append_instruction(isi);
    }

    // Will be replaced with actual topology either in scripts/test_env.py or in iroha_swarm
    let topology = vec![];
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
    let genesis = builder.build_raw(chain_id, executor_path, topology);
    Ok(genesis)
}

fn generate_synthetic(
    builder: GenesisBuilder,
    executor_path: PathBuf,
    genesis_public_key: PublicKey,
    domains: u64,
    accounts_per_domain: u64,
    assets_per_domain: u64,
) -> color_eyre::Result<RawGenesisTransaction> {
    // Synthetic genesis is extension of default one
    let mut genesis = generate_default(builder, executor_path, genesis_public_key)?;

    for domain in 0..domains {
        let domain_id: DomainId = format!("domain_{domain}").parse()?;
        genesis.append_instruction(Register::domain(Domain::new(domain_id.clone())));

        for _ in 0..accounts_per_domain {
            let (account_id, _account_keypair) = gen_account_in(&domain_id);
            genesis.append_instruction(Register::account(Account::new(account_id.clone())));
        }

        for asset in 0..assets_per_domain {
            let asset_definition_id: AssetDefinitionId =
                format!("asset_{asset}#{domain_id}").parse()?;
            genesis.append_instruction(Register::asset_definition(AssetDefinition::new(
                asset_definition_id,
                AssetType::Numeric(NumericSpec::default()),
            )));
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
                );
                genesis.append_instruction(mint);
            }
        }
    }

    Ok(genesis)
}
